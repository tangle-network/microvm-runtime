//! Firecracker microVM metrics FIFO reader.
//!
//! Firecracker emits one JSON line per `metrics_interval` into a host-side
//! file (typically a named FIFO) configured via the `PUT /metrics` API
//! endpoint. This module spawns a reader thread that opens that path
//! (blocking until the VMM opens the writer end), parses each line, and
//! exposes the most recent decoded snapshot to callers.
//!
//! Spec: <https://github.com/firecracker-microvm/firecracker/blob/main/docs/metrics.md>
//!
//! # Field mapping
//!
//! The crate models the small subset of fields that lifecycle/billing layers
//! care about; the raw JSON document is preserved verbatim in
//! [`VmMetricsSnapshot::raw`] for callers that need richer detail.
//!
//! | Snapshot field            | FC JSON path                                                                                       |
//! |---------------------------|----------------------------------------------------------------------------------------------------|
//! | `timestamp_ms`            | `utc_timestamp_ms`                                                                                 |
//! | `vcpu_usage_us`           | sum of `vcpu.exit_{io_in,io_out,mmio_read,mmio_write}_agg.sum_us` (microseconds of vCPU exit time) |
//! | `memory_used_bytes`       | best-effort from balloon stats; 0 if unavailable                                                   |
//! | `network_rx_bytes`        | `net.rx_bytes_count` (aggregate across all interfaces)                                             |
//! | `network_tx_bytes`        | `net.tx_bytes_count`                                                                               |
//! | `network_rx_packets`      | `net.rx_packets_count`                                                                             |
//! | `network_tx_packets`      | `net.tx_packets_count`                                                                             |
//! | `block_read_bytes`        | `block.read_bytes`                                                                                 |
//! | `block_write_bytes`       | `block.write_bytes`                                                                                |
//!
//! Missing fields default to `0`. Unknown future fields are still available
//! through `raw`.
//!
//! # Shutdown semantics
//!
//! [`MetricsPoller::shutdown`] sets an atomic flag that the reader thread
//! observes between lines. The thread cannot be unblocked while the underlying
//! `read` syscall is parked waiting for the next line, so shutdown effectively
//! takes hold the next time FC writes (default 60s `metrics_interval`, lower
//! values are configurable on the VMM side). [`Drop`] joins with a 200ms
//! timeout and otherwise leaks the parked reader.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{VmRuntimeError, VmRuntimeResult};

/// Configuration for a single VM's metrics reader.
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// FIFO path where FC writes metrics (per-VM).
    /// The adapter generates this; this module reads from it.
    pub fifo_path: PathBuf,
}

/// Decoded subset of one Firecracker metrics line.
///
/// Well-known counters are extracted into typed fields; the full document is
/// retained in [`raw`](Self::raw) so callers can opt in to other fields without
/// requiring a crate update.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VmMetricsSnapshot {
    /// FC `utc_timestamp_ms` field — millis since UNIX epoch when FC flushed.
    pub timestamp_ms: u64,
    /// Sum across all vCPU exit categories of `*_agg.sum_us`, in microseconds.
    /// Approximates aggregate vCPU exit time since boot.
    pub vcpu_usage_us: u64,
    /// Best-effort guest memory in use (0 when FC does not expose it).
    pub memory_used_bytes: u64,
    /// Aggregate received bytes across all network interfaces.
    pub network_rx_bytes: u64,
    /// Aggregate transmitted bytes across all network interfaces.
    pub network_tx_bytes: u64,
    /// Aggregate received packets across all network interfaces.
    pub network_rx_packets: u64,
    /// Aggregate transmitted packets across all network interfaces.
    pub network_tx_packets: u64,
    /// Aggregate bytes read across all block devices.
    pub block_read_bytes: u64,
    /// Aggregate bytes written across all block devices.
    pub block_write_bytes: u64,
    /// Untouched copy of the FC JSON document, for fields not modelled above.
    pub raw: Value,
}

impl VmMetricsSnapshot {
    /// Decode one FC metrics JSON line into a typed snapshot.
    ///
    /// Missing fields default to `0`. Any parse error of the outer JSON is
    /// surfaced; per-field type mismatches are silently coerced to defaults
    /// because FC may evolve sub-schemas over time.
    pub fn from_json_line(line: &str) -> VmRuntimeResult<Self> {
        let raw: Value = serde_json::from_str(line)
            .map_err(|e| VmRuntimeError::Metrics(format!("invalid json line: {e}")))?;
        Ok(Self::from_value(raw))
    }

    fn from_value(raw: Value) -> Self {
        let timestamp_ms = u64_at(&raw, &["utc_timestamp_ms"]);

        let vcpu_usage_us = [
            "exit_io_in_agg",
            "exit_io_out_agg",
            "exit_mmio_read_agg",
            "exit_mmio_write_agg",
        ]
        .iter()
        .map(|bucket| u64_at(&raw, &["vcpu", bucket, "sum_us"]))
        .sum();

        // FC does not expose a direct "memory used" gauge. If a future host
        // tools sidecar pushes one in under `balloon.actual_bytes` or
        // `vmm.memory_used_bytes`, surface it; otherwise 0.
        let memory_used_bytes = first_nonzero_u64(
            &raw,
            &[
                &["vmm", "memory_used_bytes"],
                &["balloon", "actual_bytes"],
                &["balloon", "actual_mib"],
            ],
        );
        // `actual_mib` needs unit conversion if that was the source.
        let memory_used_bytes = if u64_at(&raw, &["balloon", "actual_mib"]) != 0
            && u64_at(&raw, &["vmm", "memory_used_bytes"]) == 0
            && u64_at(&raw, &["balloon", "actual_bytes"]) == 0
        {
            memory_used_bytes.saturating_mul(1024 * 1024)
        } else {
            memory_used_bytes
        };

        let network_rx_bytes = u64_at(&raw, &["net", "rx_bytes_count"]);
        let network_tx_bytes = u64_at(&raw, &["net", "tx_bytes_count"]);
        let network_rx_packets = u64_at(&raw, &["net", "rx_packets_count"]);
        let network_tx_packets = u64_at(&raw, &["net", "tx_packets_count"]);

        let block_read_bytes = u64_at(&raw, &["block", "read_bytes"]);
        let block_write_bytes = u64_at(&raw, &["block", "write_bytes"]);

        Self {
            timestamp_ms,
            vcpu_usage_us,
            memory_used_bytes,
            network_rx_bytes,
            network_tx_bytes,
            network_rx_packets,
            network_tx_packets,
            block_read_bytes,
            block_write_bytes,
            raw,
        }
    }
}

/// Read a `u64` out of nested JSON at the given path, coercing to 0 on any
/// missing key or non-numeric value.
fn u64_at(root: &Value, path: &[&str]) -> u64 {
    let mut cursor = root;
    for segment in path {
        match cursor.get(*segment) {
            Some(next) => cursor = next,
            None => return 0,
        }
    }
    cursor.as_u64().unwrap_or(0)
}

/// Walk `paths` in order and return the first non-zero `u64` found.
fn first_nonzero_u64(root: &Value, paths: &[&[&str]]) -> u64 {
    for path in paths {
        let v = u64_at(root, path);
        if v != 0 {
            return v;
        }
    }
    0
}

type SharedSnapshot = Arc<Mutex<Option<VmMetricsSnapshot>>>;

/// Background reader of one FC metrics FIFO.
///
/// Construction spawns a thread; use [`snapshot`](Self::snapshot) to read the
/// most recent decoded payload and [`shutdown`](Self::shutdown) (or `Drop`) to
/// stop it.
pub struct MetricsPoller {
    snapshot: SharedSnapshot,
    handle: Option<JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
}

impl MetricsPoller {
    /// Spawn a reader thread that opens `config.fifo_path` (blocking until
    /// FC opens the writer end), parses newline-delimited JSON, and updates
    /// the shared snapshot on every successful line.
    ///
    /// Parse errors on a single line are swallowed so that one malformed line
    /// does not poison the poller; the previous snapshot remains valid.
    pub fn start(config: MetricsConfig) -> VmRuntimeResult<Self> {
        let snapshot: SharedSnapshot = Arc::new(Mutex::new(None));
        let shutdown = Arc::new(AtomicBool::new(false));

        let snapshot_thread = Arc::clone(&snapshot);
        let shutdown_thread = Arc::clone(&shutdown);
        let fifo_path = config.fifo_path.clone();

        let handle = thread::Builder::new()
            .name(format!("microvm-metrics:{}", fifo_path.display()))
            .spawn(move || reader_loop(fifo_path, snapshot_thread, shutdown_thread))
            .map_err(|e| VmRuntimeError::Metrics(format!("spawn reader thread: {e}")))?;

        Ok(Self {
            snapshot,
            handle: Some(handle),
            shutdown,
        })
    }

    /// Most recent decoded snapshot, or `None` if no line has been read yet.
    ///
    /// Recovers transparently from a poisoned mutex (a panicking reader thread
    /// is treated as having simply not written anything).
    pub fn snapshot(&self) -> Option<VmMetricsSnapshot> {
        match self.snapshot.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Signal the reader thread to stop and wait briefly for it to exit.
    ///
    /// The thread cannot be interrupted while blocked inside `read`; if it is
    /// parked there, this call returns once the 200ms join timeout elapses and
    /// the thread is detached. The next FC metric flush will unblock it and
    /// it will then observe the shutdown flag and exit on its own.
    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            join_with_timeout(handle, Duration::from_millis(200));
        }
    }
}

impl std::fmt::Debug for MetricsPoller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricsPoller")
            .field("has_snapshot", &self.snapshot().is_some())
            .field("shutdown", &self.shutdown.load(Ordering::Relaxed))
            .finish()
    }
}

impl Drop for MetricsPoller {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn reader_loop(fifo_path: PathBuf, snapshot: SharedSnapshot, shutdown: Arc<AtomicBool>) {
    // Opening a FIFO for read blocks until the writer end is opened by FC.
    // That is the documented and desired behavior; the caller knows the path
    // belongs to a per-VM FIFO and the corresponding VM is being booted.
    let file = match File::open(&fifo_path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let reader = BufReader::new(file);
    for line in reader.lines() {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        let Ok(line) = line else { break };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(snap) = VmMetricsSnapshot::from_json_line(trimmed) {
            store_snapshot(&snapshot, snap);
        }
    }
}

fn store_snapshot(snapshot: &SharedSnapshot, value: VmMetricsSnapshot) {
    let mut guard = match snapshot.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    *guard = Some(value);
}

/// Best-effort join with a wall-clock deadline. On timeout, the thread is
/// detached (leaked) because the standard library offers no way to abort a
/// thread blocked in a syscall.
fn join_with_timeout(handle: JoinHandle<()>, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    // Quick path: if the thread is already gone, join returns immediately.
    // Otherwise poll with short sleeps until we hit the deadline, then leak.
    while Instant::now() < deadline {
        if !handle.is_finished() {
            thread::sleep(Duration::from_millis(10));
            continue;
        }
        let _ = handle.join();
        return;
    }
    // Timeout: leak the handle by dropping it. The OS will reclaim the
    // thread once FC closes the FIFO or writes another line.
    drop(handle);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{Duration, Instant};

    fn sample_full_line() -> String {
        serde_json::json!({
            "utc_timestamp_ms": 1_700_000_000_123u64,
            "vcpu": {
                "exit_io_in": 1,
                "exit_io_out": 2,
                "exit_mmio_read": 3,
                "exit_mmio_write": 4,
                "exit_io_in_agg": { "min_us": 0, "max_us": 9, "sum_us": 100 },
                "exit_io_out_agg": { "min_us": 0, "max_us": 9, "sum_us": 200 },
                "exit_mmio_read_agg": { "min_us": 0, "max_us": 9, "sum_us": 300 },
                "exit_mmio_write_agg": { "min_us": 0, "max_us": 9, "sum_us": 400 },
            },
            "net": {
                "rx_bytes_count": 1024u64,
                "tx_bytes_count": 2048u64,
                "rx_packets_count": 10u64,
                "tx_packets_count": 20u64,
            },
            "block": {
                "read_bytes": 4096u64,
                "write_bytes": 8192u64,
            },
            "balloon": {
                "actual_mib": 256u64,
            },
            "vmm": {
                "device_events": 7u64,
            }
        })
        .to_string()
    }

    #[test]
    fn parses_well_known_fields() {
        let snap = VmMetricsSnapshot::from_json_line(&sample_full_line()).unwrap();
        assert_eq!(snap.timestamp_ms, 1_700_000_000_123);
        assert_eq!(snap.vcpu_usage_us, 100 + 200 + 300 + 400);
        // 256 MiB -> 256 * 1024 * 1024 bytes
        assert_eq!(snap.memory_used_bytes, 256 * 1024 * 1024);
        assert_eq!(snap.network_rx_bytes, 1024);
        assert_eq!(snap.network_tx_bytes, 2048);
        assert_eq!(snap.network_rx_packets, 10);
        assert_eq!(snap.network_tx_packets, 20);
        assert_eq!(snap.block_read_bytes, 4096);
        assert_eq!(snap.block_write_bytes, 8192);
        // Raw doc is preserved verbatim.
        assert_eq!(snap.raw["vmm"]["device_events"].as_u64(), Some(7));
    }

    #[test]
    fn missing_fields_default_to_zero() {
        let snap = VmMetricsSnapshot::from_json_line("{}").unwrap();
        assert_eq!(snap.timestamp_ms, 0);
        assert_eq!(snap.vcpu_usage_us, 0);
        assert_eq!(snap.memory_used_bytes, 0);
        assert_eq!(snap.network_rx_bytes, 0);
        assert_eq!(snap.network_tx_bytes, 0);
        assert_eq!(snap.network_rx_packets, 0);
        assert_eq!(snap.network_tx_packets, 0);
        assert_eq!(snap.block_read_bytes, 0);
        assert_eq!(snap.block_write_bytes, 0);
        assert!(snap.raw.is_object());
    }

    #[test]
    fn partial_payload_keeps_present_fields_drops_missing() {
        let line = serde_json::json!({
            "utc_timestamp_ms": 42u64,
            "net": { "rx_bytes_count": 7u64 }
        })
        .to_string();
        let snap = VmMetricsSnapshot::from_json_line(&line).unwrap();
        assert_eq!(snap.timestamp_ms, 42);
        assert_eq!(snap.network_rx_bytes, 7);
        assert_eq!(snap.network_tx_bytes, 0);
        assert_eq!(snap.vcpu_usage_us, 0);
    }

    #[test]
    fn invalid_json_is_rejected() {
        let err = VmMetricsSnapshot::from_json_line("not json").unwrap_err();
        match err {
            VmRuntimeError::Metrics(msg) => assert!(msg.contains("invalid json line")),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn balloon_actual_bytes_takes_priority_over_mib() {
        let line = serde_json::json!({
            "balloon": { "actual_bytes": 12345u64, "actual_mib": 999u64 }
        })
        .to_string();
        let snap = VmMetricsSnapshot::from_json_line(&line).unwrap();
        assert_eq!(snap.memory_used_bytes, 12345);
    }

    /// End-to-end: write multiple JSON lines into a regular file (acting as a
    /// stand-in for the FIFO) and verify the poller exposes only the latest.
    ///
    /// A regular file is sufficient because `File::open` does not block for
    /// regular files, and we control the writer. The semantics under test —
    /// "reader sees each new line, snapshot reflects the latest" — are
    /// identical to the FIFO case.
    #[test]
    fn poller_updates_snapshot_with_latest_line() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("metrics.fifo");

        // Pre-write two lines so File::open succeeds immediately and the
        // reader has work to do without us racing the open call.
        let first = serde_json::json!({
            "utc_timestamp_ms": 1u64,
            "net": { "rx_bytes_count": 100u64 }
        });
        let second = serde_json::json!({
            "utc_timestamp_ms": 2u64,
            "net": { "rx_bytes_count": 200u64 }
        });
        let mut writer = std::fs::File::create(&path).expect("create");
        writeln!(writer, "{first}").unwrap();
        writeln!(writer, "{second}").unwrap();
        writer.flush().unwrap();
        drop(writer);

        let poller = MetricsPoller::start(MetricsConfig { fifo_path: path }).expect("start");

        let snap = wait_for_snapshot(&poller, Duration::from_secs(2)).expect("snapshot");
        // Reader consumes both lines; only the latest survives.
        assert_eq!(snap.timestamp_ms, 2);
        assert_eq!(snap.network_rx_bytes, 200);

        drop(poller);
    }

    #[test]
    fn poller_snapshot_is_none_until_first_line() {
        // Use a FIFO via a writer thread so File::open blocks until we open
        // the writer end. This mirrors FC's behavior exactly.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("metrics.fifo");
        mkfifo_or_skip(&path);

        let poller = MetricsPoller::start(MetricsConfig {
            fifo_path: path.clone(),
        })
        .expect("start");

        // Reader is still parked on File::open — no snapshot yet.
        assert!(poller.snapshot().is_none());

        // Open writer, send one line, drop writer. Poller should pick it up.
        let writer_path = path.clone();
        let writer = thread::spawn(move || {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&writer_path)
                .expect("open writer");
            writeln!(f, "{}", serde_json::json!({"utc_timestamp_ms": 99u64})).unwrap();
            f.flush().unwrap();
        });

        let snap = wait_for_snapshot(&poller, Duration::from_secs(2)).expect("snapshot");
        assert_eq!(snap.timestamp_ms, 99);

        writer.join().unwrap();
        drop(poller);
    }

    /// Wait up to `timeout` for the poller to publish any snapshot.
    fn wait_for_snapshot(poller: &MetricsPoller, timeout: Duration) -> Option<VmMetricsSnapshot> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(snap) = poller.snapshot() {
                return Some(snap);
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// Create a FIFO at `path`. Linux-only; tests using a real FIFO need this.
    fn mkfifo_or_skip(path: &std::path::Path) {
        #[cfg(unix)]
        {
            use std::ffi::CString;
            let c = CString::new(path.as_os_str().as_encoded_bytes()).expect("cstring");
            // SAFETY: libc::mkfifo with valid C-string path and mode 0o600.
            let rc = unsafe { libc_mkfifo(c.as_ptr(), 0o600) };
            assert_eq!(rc, 0, "mkfifo failed for {}", path.display());
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            panic!("FIFO tests require a unix host");
        }
    }

    // Minimal libc binding so we don't pull in the libc crate for tests.
    #[cfg(unix)]
    unsafe extern "C" {
        #[link_name = "mkfifo"]
        fn libc_mkfifo(path: *const std::ffi::c_char, mode: u32) -> i32;
    }
}
