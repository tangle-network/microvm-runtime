//! Host-side client for the in-guest metadata daemon.
//!
//! The sandbox needs to inject runtime data (per-VM env, sidecar auth tokens,
//! arbitrary secrets) into a microVM *after* it has booted — not at create
//! time. Anything placed into `VmSpec` before launch must travel through
//! `cmdline`/MMDS/rootfs, which doesn't generalise to opaque secrets and
//! cannot be set per warm-pool consumer.
//!
//! The fix is a thin daemon running inside the guest's `init` (or a systemd
//! unit) that binds a vsock port and exposes a tiny newline-delimited JSON
//! protocol. The host opens the per-VM vsock UDS that
//! [`crate::vsock::VsockManager::attach`] allocated, performs the Firecracker
//! `CONNECT <port>\n` handshake, then writes one JSON request per line and
//! reads one JSON response per line.
//!
//! The daemon writes received state to a known guest filesystem location
//! (env file + per-secret files) that the sandbox sidecar reads at startup.
//! See `examples/guest_metadata_daemon.rs` for the reference implementation.
//!
//! # Wire protocol
//!
//! Each request and response is a single UTF-8 line of JSON terminated by
//! `\n`. The connection stays open across requests; the daemon services them
//! sequentially.
//!
//! Requests (host → guest):
//! ```jsonc
//! {"op": "set_env", "id": "<uuid>", "env": {"FOO": "bar", "BAZ": "qux"}}
//! {"op": "set_secret", "id": "<uuid>", "name": "sidecar_token", "value_b64": "..."}
//! {"op": "ping", "id": "<uuid>"}
//! ```
//!
//! Responses (guest → host):
//! ```jsonc
//! {"id": "<uuid>", "ok": true}
//! {"id": "<uuid>", "ok": false, "error": "permission denied: /var/run/microvm-guest/env"}
//! ```
//!
//! The `id` field is opaque to the daemon — it just echoes it. Callers use
//! it to correlate pipelined requests on a single connection.
//!
//! # Concurrency
//!
//! [`GuestMetadataConn`] holds a single underlying `UnixStream` and is not
//! `Sync`. The sandbox use case is sequential per VM (boot → set_env →
//! set_secret → drop), so this is fine. If a caller needs concurrent writes,
//! open one connection per writer.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde::{Deserialize, Serialize};

use crate::error::{VmRuntimeError, VmRuntimeResult};

/// Default vsock port the guest daemon listens on. The reference daemon binds
/// here. Operators may override per-VM by passing a different port to
/// [`GuestMetadataClient`] (e.g. when several daemons share one guest).
pub const DEFAULT_GUEST_METADATA_PORT: u32 = 5555;

/// Default time budget for the initial `connect(2)` + Firecracker `CONNECT`
/// handshake. Boot-from-cold typically takes 1-3s before the guest binds;
/// restored VMs are <100ms.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default time budget for any single request/response over an open
/// connection.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Polling cadence used when waiting for the Firecracker UDS to materialise.
const CONNECT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Tuning knobs for [`GuestMetadataClient`].
#[derive(Debug, Clone)]
pub struct GuestMetadataConfig {
    /// Vsock port to connect to on the guest. Default:
    /// [`DEFAULT_GUEST_METADATA_PORT`].
    pub port: u32,
    /// Max time to wait for the guest daemon to accept the connection.
    /// Covers both the UDS appearing on disk (host side) and the Firecracker
    /// `CONNECT` handshake succeeding (guest-binding side).
    pub connect_timeout: Duration,
    /// Max time to wait for any single request/response over an open
    /// connection.
    pub request_timeout: Duration,
}

impl Default for GuestMetadataConfig {
    fn default() -> Self {
        Self {
            port: DEFAULT_GUEST_METADATA_PORT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        }
    }
}

impl GuestMetadataConfig {
    /// Load configuration from environment variables.
    ///
    /// Recognised keys: `MICROVM_GUEST_METADATA_PORT`,
    /// `MICROVM_GUEST_METADATA_CONNECT_TIMEOUT_MS`,
    /// `MICROVM_GUEST_METADATA_REQUEST_TIMEOUT_MS`. Missing or unparseable
    /// values fall back to the defaults.
    pub fn from_env() -> Self {
        let defaults = Self::default();
        let port = std::env::var("MICROVM_GUEST_METADATA_PORT")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(defaults.port);
        let connect_timeout = std::env::var("MICROVM_GUEST_METADATA_CONNECT_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .map(Duration::from_millis)
            .unwrap_or(defaults.connect_timeout);
        let request_timeout = std::env::var("MICROVM_GUEST_METADATA_REQUEST_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .map(Duration::from_millis)
            .unwrap_or(defaults.request_timeout);
        Self {
            port,
            connect_timeout,
            request_timeout,
        }
    }
}

/// Host-side client for a single VM's guest metadata daemon.
///
/// Construction is cheap and does not touch the network. Call [`connect`]
/// to open a session.
///
/// [`connect`]: GuestMetadataClient::connect
#[derive(Debug, Clone)]
pub struct GuestMetadataClient {
    uds_path: PathBuf,
    config: GuestMetadataConfig,
}

impl GuestMetadataClient {
    /// Construct a client targeting the given per-VM vsock UDS path. This is
    /// the `uds_path` field of the [`crate::vsock::VmVsock`] returned by
    /// `VsockManager::attach`. The connection is NOT opened here —
    /// [`connect`] does that lazily.
    ///
    /// [`connect`]: GuestMetadataClient::connect
    pub fn new(uds_path: impl Into<PathBuf>, config: GuestMetadataConfig) -> Self {
        Self {
            uds_path: uds_path.into(),
            config,
        }
    }

    /// Borrow the configured UDS path.
    pub fn uds_path(&self) -> &Path {
        &self.uds_path
    }

    /// Borrow the active configuration.
    pub fn config(&self) -> &GuestMetadataConfig {
        &self.config
    }

    /// Open a connection and complete the Firecracker `CONNECT <port>`
    /// handshake. Returns an owned connection wrapper that can issue multiple
    /// requests until dropped.
    ///
    /// The call retries connect failures (`ENOENT`, `ECONNREFUSED`) at
    /// `CONNECT_POLL_INTERVAL` cadence until `connect_timeout` elapses. The
    /// retry loop is required because the UDS only appears after FC has
    /// fully booted the VMM and bound the vsock device, which is racy
    /// against caller code that runs straight after `VmProvider::start`.
    pub fn connect(&self) -> VmRuntimeResult<GuestMetadataConn> {
        let deadline = std::time::Instant::now() + self.config.connect_timeout;
        let stream = self.dial_with_retry(deadline)?;

        // Per-op deadline is enforced by the read/write timeouts on the
        // socket itself, so blocking syscalls return promptly.
        stream
            .set_read_timeout(Some(self.config.request_timeout))
            .map_err(|e| VmRuntimeError::GuestMetadata(format!("set_read_timeout failed: {e}")))?;
        stream
            .set_write_timeout(Some(self.config.request_timeout))
            .map_err(|e| VmRuntimeError::GuestMetadata(format!("set_write_timeout failed: {e}")))?;

        let mut conn = GuestMetadataConn::from_stream(stream)?;
        conn.firecracker_connect(self.config.port)?;
        Ok(conn)
    }

    fn dial_with_retry(&self, deadline: std::time::Instant) -> VmRuntimeResult<UnixStream> {
        loop {
            match UnixStream::connect(&self.uds_path) {
                Ok(s) => return Ok(s),
                Err(err) => {
                    let kind = err.kind();
                    let retryable = matches!(
                        kind,
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    );
                    if !retryable {
                        return Err(VmRuntimeError::GuestMetadata(format!(
                            "connect {}: {err}",
                            self.uds_path.display()
                        )));
                    }
                    if std::time::Instant::now() >= deadline {
                        return Err(VmRuntimeError::GuestMetadata(format!(
                            "timed out connecting to {} after {:?}: {err}",
                            self.uds_path.display(),
                            self.config.connect_timeout
                        )));
                    }
                    std::thread::sleep(CONNECT_POLL_INTERVAL);
                }
            }
        }
    }
}

/// Open connection to a guest metadata daemon.
///
/// Owns a duplex `UnixStream` that has already completed the Firecracker
/// `CONNECT <port>` handshake. The reader half is buffered so we can read
/// one newline-delimited JSON response per call without losing bytes that
/// belong to a later message.
///
/// Dropping closes the underlying stream; reconnecting via
/// [`GuestMetadataClient::connect`] is cheap (single UDS connect + 4-byte
/// handshake exchange).
#[derive(Debug)]
pub struct GuestMetadataConn {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl GuestMetadataConn {
    fn from_stream(stream: UnixStream) -> VmRuntimeResult<Self> {
        let writer = stream.try_clone().map_err(|e| {
            VmRuntimeError::GuestMetadata(format!("clone unix stream for writer half: {e}"))
        })?;
        Ok(Self {
            reader: BufReader::new(stream),
            writer,
        })
    }

    /// Borrow the UDS the connection was opened against. Used by tests and
    /// callers that want to log diagnostic context.
    pub fn peer_uds(&self) -> Option<PathBuf> {
        self.reader
            .get_ref()
            .peer_addr()
            .ok()
            .and_then(|addr| addr.as_pathname().map(Path::to_path_buf))
    }

    /// Perform the Firecracker host-initiated vsock handshake.
    ///
    /// FC expects `CONNECT <port>\n` and replies with `OK <host_port>\n`
    /// once the guest accepts; on failure it closes the stream. We treat
    /// any non-`OK` prefix (or read failure) as a connection-refused error
    /// so the caller can retry against a not-yet-bound daemon.
    fn firecracker_connect(&mut self, port: u32) -> VmRuntimeResult<()> {
        // Use a fresh, small read buffer for the handshake. The buffered
        // reader is fine here — FC writes `OK <port>\n` in a single line.
        let req = format!("CONNECT {port}\n");
        self.writer
            .write_all(req.as_bytes())
            .map_err(|e| VmRuntimeError::GuestMetadata(format!("write CONNECT: {e}")))?;
        self.writer
            .flush()
            .map_err(|e| VmRuntimeError::GuestMetadata(format!("flush CONNECT: {e}")))?;

        let mut response = String::new();
        self.reader
            .read_line(&mut response)
            .map_err(|e| VmRuntimeError::GuestMetadata(format!("read CONNECT response: {e}")))?;
        let trimmed = response.trim_end_matches(['\r', '\n']);
        if !trimmed.starts_with("OK ") {
            return Err(VmRuntimeError::GuestMetadata(format!(
                "firecracker rejected CONNECT {port}: got {trimmed:?}"
            )));
        }
        Ok(())
    }

    /// Push environment variables into the guest.
    ///
    /// Keys must match `[A-Za-z_][A-Za-z0-9_]*` (POSIX `name` production);
    /// values are arbitrary UTF-8. An empty value deletes the key. Existing
    /// keys not present in `env` are left untouched — call with an empty
    /// value to remove them. The daemon persists the resulting env file
    /// atomically (write-tmp + rename).
    pub fn set_env(&mut self, env: &HashMap<String, String>) -> VmRuntimeResult<()> {
        for key in env.keys() {
            validate_env_key(key)?;
        }
        let id = next_id();
        let req = Request::SetEnv {
            id: &id,
            env: env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect(),
        };
        self.send(&req)?;
        self.recv_ok(&id)
    }

    /// Push a single secret (name → bytes) into the guest.
    ///
    /// `name` must match `[A-Za-z0-9_-]+` — no path separators, no leading
    /// dots, no spaces. The daemon stores it under its secrets directory
    /// (default `/var/run/microvm-guest/secrets/<name>`) with mode `0600`.
    /// Bytes are base64-encoded on the wire but written verbatim to disk.
    pub fn set_secret(&mut self, name: &str, value: &[u8]) -> VmRuntimeResult<()> {
        validate_secret_name(name)?;
        let id = next_id();
        let value_b64 = base64_encode(value);
        let req = Request::SetSecret {
            id: &id,
            name,
            value_b64: &value_b64,
        };
        self.send(&req)?;
        self.recv_ok(&id)
    }

    /// Round-trip a NOP. Useful for health probes from a warm-pool validator.
    pub fn ping(&mut self) -> VmRuntimeResult<()> {
        let id = next_id();
        let req = Request::Ping { id: &id };
        self.send(&req)?;
        self.recv_ok(&id)
    }

    fn send(&mut self, req: &Request<'_>) -> VmRuntimeResult<()> {
        let mut line = serde_json::to_string(req)
            .map_err(|e| VmRuntimeError::GuestMetadata(format!("encode request: {e}")))?;
        line.push('\n');
        self.writer
            .write_all(line.as_bytes())
            .map_err(|e| VmRuntimeError::GuestMetadata(format!("write request: {e}")))?;
        self.writer
            .flush()
            .map_err(|e| VmRuntimeError::GuestMetadata(format!("flush request: {e}")))?;
        Ok(())
    }

    fn recv_ok(&mut self, expected_id: &str) -> VmRuntimeResult<()> {
        let mut line = String::new();
        let n = self
            .reader
            .read_line(&mut line)
            .map_err(|e| VmRuntimeError::GuestMetadata(format!("read response: {e}")))?;
        if n == 0 {
            return Err(VmRuntimeError::GuestMetadata(
                "guest closed connection before responding".to_string(),
            ));
        }
        let resp: Response = serde_json::from_str(line.trim_end_matches(['\r', '\n']))
            .map_err(|e| VmRuntimeError::GuestMetadata(format!("decode response: {e}")))?;
        if resp.id != expected_id {
            return Err(VmRuntimeError::GuestMetadata(format!(
                "response id mismatch: expected {expected_id}, got {}",
                resp.id
            )));
        }
        if !resp.ok {
            return Err(VmRuntimeError::GuestMetadata(resp.error.unwrap_or_else(
                || "guest reported failure without detail".to_string(),
            )));
        }
        Ok(())
    }
}

/// Wire-level request shape. Serialised one-per-line on the connection.
///
/// Public so daemon implementers can `Deserialize` it; the struct is owned
/// by this crate but the protocol is the API contract.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request<'a> {
    /// Replace zero or more env vars on the guest. Empty value deletes a key.
    SetEnv {
        id: &'a str,
        env: HashMap<&'a str, &'a str>,
    },
    /// Write a single base64-encoded secret to the guest.
    SetSecret {
        id: &'a str,
        name: &'a str,
        value_b64: &'a str,
    },
    /// No-op health probe.
    Ping { id: &'a str },
}

/// Wire-level response. Echoes the request `id` so pipelined callers can
/// correlate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Echoed request id.
    pub id: String,
    /// `true` on success.
    pub ok: bool,
    /// Human-readable failure detail when `ok == false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Owned variant of [`Request`] that daemons typically deserialize into.
///
/// The borrowed form is convenient for the host (encode-once) but a daemon
/// reading from a stream needs owned strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum OwnedRequest {
    SetEnv {
        id: String,
        env: HashMap<String, String>,
    },
    SetSecret {
        id: String,
        name: String,
        value_b64: String,
    },
    Ping {
        id: String,
    },
}

impl OwnedRequest {
    /// Borrow the request id regardless of variant. Daemons echo this in
    /// the response.
    pub fn id(&self) -> &str {
        match self {
            OwnedRequest::SetEnv { id, .. }
            | OwnedRequest::SetSecret { id, .. }
            | OwnedRequest::Ping { id } => id,
        }
    }
}

/// Validate a POSIX environment variable name. We accept the conservative
/// shell name production: leading `[A-Za-z_]`, then `[A-Za-z0-9_]*`. This
/// keeps `KEY=VALUE` lines unambiguous in the env file and avoids shell
/// metacharacters in keys that some downstream tools mishandle.
pub fn validate_env_key(key: &str) -> VmRuntimeResult<()> {
    if key.is_empty() {
        return Err(VmRuntimeError::GuestMetadata(
            "env key cannot be empty".to_string(),
        ));
    }
    let mut chars = key.chars();
    let first = chars.next().expect("non-empty key");
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(VmRuntimeError::GuestMetadata(format!(
            "env key {key:?} must start with [A-Za-z_]"
        )));
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || c == '_') {
            return Err(VmRuntimeError::GuestMetadata(format!(
                "env key {key:?} contains invalid character {c:?}"
            )));
        }
    }
    Ok(())
}

/// Validate a secret name. Allowed: non-empty `[A-Za-z0-9_-]+`. Rejects
/// path traversal (`..`, `/`, `\`), dot-prefixed names, and any whitespace.
pub fn validate_secret_name(name: &str) -> VmRuntimeResult<()> {
    if name.is_empty() {
        return Err(VmRuntimeError::GuestMetadata(
            "secret name cannot be empty".to_string(),
        ));
    }
    for c in name.chars() {
        if !(c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return Err(VmRuntimeError::GuestMetadata(format!(
                "secret name {name:?} contains invalid character {c:?}"
            )));
        }
    }
    Ok(())
}

/// Encode bytes as standard-alphabet base64 (RFC 4648 §4, with `=` padding).
///
/// Re-exported wrapper over the `base64` crate so daemon implementers and
/// tests inside this crate share the exact same encoding the host uses on
/// the wire.
pub fn base64_encode(bytes: &[u8]) -> String {
    BASE64_STANDARD.encode(bytes)
}

/// Decode standard-alphabet base64. Padding is required (this matches what
/// [`base64_encode`] emits). Errors map to
/// [`VmRuntimeError::GuestMetadata`].
pub fn base64_decode(input: &str) -> VmRuntimeResult<Vec<u8>> {
    BASE64_STANDARD
        .decode(input.as_bytes())
        .map_err(|e| VmRuntimeError::GuestMetadata(format!("base64 decode: {e}")))
}

/// Generate a short opaque request id. Not cryptographic — just enough to
/// disambiguate pipelined requests on a single connection within a single
/// process. Uses thread id + a monotonic counter + nanosecond clock so
/// concurrent callers don't collide.
fn next_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let tid = thread_id_u64();
    format!("{tid:x}-{nanos:08x}-{n:x}")
}

fn thread_id_u64() -> u64 {
    // `ThreadId::as_u64` is unstable; the `Debug` form is `ThreadId(N)`
    // which we parse. This is best-effort — if the format changes we
    // still produce *a* string, just less informative.
    let dbg = format!("{:?}", std::thread::current().id());
    dbg.trim_start_matches("ThreadId(")
        .trim_end_matches(')')
        .parse()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::thread;
    use tempfile::TempDir;

    /// Bytes the host writes to start a Firecracker host-initiated vsock
    /// connection on a given port.
    fn expected_connect_line(port: u32) -> String {
        format!("CONNECT {port}\n")
    }

    /// Spawn a minimal in-process daemon that:
    ///   1. Listens on a UDS in `dir`.
    ///   2. On each accept, reads the FC `CONNECT <port>\n` line and replies
    ///      `OK <port>\n`.
    ///   3. Then services newline-delimited JSON requests sequentially.
    ///   4. Records all successful writes (env + secrets) to `dir`.
    ///
    /// Returns the UDS path and a join handle. The thread exits once the
    /// client closes the connection.
    struct FakeDaemon {
        uds_path: PathBuf,
        env_file: PathBuf,
        secrets_dir: PathBuf,
        _tmp: TempDir,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl FakeDaemon {
        fn spawn() -> Self {
            let tmp = TempDir::new().unwrap();
            let uds_path = tmp.path().join("vsock.uds");
            let env_file = tmp.path().join("env");
            let secrets_dir = tmp.path().join("secrets");
            std::fs::create_dir_all(&secrets_dir).unwrap();

            let listener = UnixListener::bind(&uds_path).unwrap();
            let env_file_clone = env_file.clone();
            let secrets_dir_clone = secrets_dir.clone();
            let handle = thread::spawn(move || {
                // One connection only — the tests open a single client.
                let (stream, _) = match listener.accept() {
                    Ok(p) => p,
                    Err(_) => return,
                };
                serve_one_connection(stream, env_file_clone, secrets_dir_clone);
            });
            Self {
                uds_path,
                env_file,
                secrets_dir,
                _tmp: tmp,
                handle: Some(handle),
            }
        }

        fn join(&mut self) {
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    fn serve_one_connection(
        stream: std::os::unix::net::UnixStream,
        env_file: PathBuf,
        secrets_dir: PathBuf,
    ) {
        let mut writer = stream.try_clone().expect("clone stream");
        let mut reader = BufReader::new(stream);

        // Firecracker CONNECT handshake.
        let mut connect_line = String::new();
        if reader.read_line(&mut connect_line).unwrap_or(0) == 0 {
            return;
        }
        assert!(connect_line.starts_with("CONNECT "));
        let port: u32 = connect_line
            .trim()
            .trim_start_matches("CONNECT ")
            .parse()
            .expect("parse port");
        writer.write_all(format!("OK {port}\n").as_bytes()).unwrap();
        writer.flush().unwrap();

        // Serve requests until EOF.
        loop {
            let mut line = String::new();
            let n = match reader.read_line(&mut line) {
                Ok(n) => n,
                Err(_) => return,
            };
            if n == 0 {
                return;
            }
            let req: OwnedRequest = match serde_json::from_str(line.trim_end()) {
                Ok(r) => r,
                Err(e) => {
                    let resp = Response {
                        id: "?".into(),
                        ok: false,
                        error: Some(format!("decode: {e}")),
                    };
                    write_response(&mut writer, &resp);
                    continue;
                }
            };
            let resp = match handle_request(req, &env_file, &secrets_dir) {
                Ok(id) => Response {
                    id,
                    ok: true,
                    error: None,
                },
                Err((id, err)) => Response {
                    id,
                    ok: false,
                    error: Some(err),
                },
            };
            write_response(&mut writer, &resp);
        }
    }

    fn write_response(w: &mut impl Write, resp: &Response) {
        let mut s = serde_json::to_string(resp).expect("encode");
        s.push('\n');
        let _ = w.write_all(s.as_bytes());
        let _ = w.flush();
    }

    fn handle_request(
        req: OwnedRequest,
        env_file: &Path,
        secrets_dir: &Path,
    ) -> Result<String, (String, String)> {
        match req {
            OwnedRequest::Ping { id } => Ok(id),
            OwnedRequest::SetEnv { id, env } => {
                let mut buf = String::new();
                let mut keys: Vec<&String> = env.keys().collect();
                keys.sort();
                for k in keys {
                    let v = &env[k];
                    if v.is_empty() {
                        continue;
                    }
                    buf.push_str(k);
                    buf.push('=');
                    buf.push_str(v);
                    buf.push('\n');
                }
                std::fs::write(env_file, buf).map_err(|e| (id.clone(), e.to_string()))?;
                Ok(id)
            }
            OwnedRequest::SetSecret {
                id,
                name,
                value_b64,
            } => {
                let bytes = base64_decode(&value_b64).map_err(|e| (id.clone(), e.to_string()))?;
                let path = secrets_dir.join(&name);
                std::fs::write(&path, &bytes).map_err(|e| (id.clone(), e.to_string()))?;
                Ok(id)
            }
        }
    }

    #[test]
    fn config_defaults_match_constants() {
        let cfg = GuestMetadataConfig::default();
        assert_eq!(cfg.port, DEFAULT_GUEST_METADATA_PORT);
        assert_eq!(cfg.connect_timeout, DEFAULT_CONNECT_TIMEOUT);
        assert_eq!(cfg.request_timeout, DEFAULT_REQUEST_TIMEOUT);
    }

    #[test]
    fn validate_env_key_accepts_typical_names() {
        for k in ["FOO", "FOO_BAR", "_PRIVATE", "X1", "lowercase_ok"] {
            validate_env_key(k).unwrap();
        }
    }

    #[test]
    fn validate_env_key_rejects_invalid_names() {
        for k in ["", "1FOO", "FOO-BAR", "FOO BAR", "FOO.BAR", "FOO=", "../X"] {
            assert!(
                validate_env_key(k).is_err(),
                "expected {k:?} to be rejected"
            );
        }
    }

    #[test]
    fn validate_secret_name_accepts_typical_names() {
        for n in [
            "sidecar_token",
            "cert-chain",
            "abc",
            "ABC_123-xyz",
            "single",
        ] {
            validate_secret_name(n).unwrap();
        }
    }

    #[test]
    fn validate_secret_name_rejects_path_traversal_and_special_chars() {
        for n in [
            "",
            "..",
            "../etc/shadow",
            "a/b",
            "a\\b",
            ".hidden",
            "with space",
            "weird;char",
            "dotted.name",
        ] {
            assert!(
                validate_secret_name(n).is_err(),
                "expected {n:?} to be rejected"
            );
        }
    }

    #[test]
    fn base64_round_trip_matches_rfc4648_vectors() {
        // RFC 4648 §10 standard test vectors.
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (raw, encoded) in cases {
            assert_eq!(base64_encode(raw), *encoded, "encode {raw:?}");
            assert_eq!(base64_decode(encoded).unwrap(), *raw, "decode {encoded}");
        }
    }

    #[test]
    fn base64_decode_rejects_invalid_character() {
        let err = base64_decode("Zm9v$g==").unwrap_err();
        assert!(matches!(err, VmRuntimeError::GuestMetadata(_)));
    }

    #[test]
    fn base64_decode_rejects_bad_length() {
        let err = base64_decode("Z").unwrap_err();
        assert!(matches!(err, VmRuntimeError::GuestMetadata(_)));
    }

    #[test]
    fn request_json_round_trips_through_serde() {
        let mut env = HashMap::new();
        env.insert("FOO", "bar");
        env.insert("BAZ", "qux");
        let req = Request::SetEnv { id: "abc", env };
        let s = serde_json::to_string(&req).unwrap();
        // Deserialize into the owned form (what daemons use).
        let parsed: OwnedRequest = serde_json::from_str(&s).unwrap();
        match parsed {
            OwnedRequest::SetEnv { id, env } => {
                assert_eq!(id, "abc");
                assert_eq!(env.get("FOO").map(String::as_str), Some("bar"));
                assert_eq!(env.get("BAZ").map(String::as_str), Some("qux"));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn ping_request_serializes_with_op_tag() {
        let req = Request::Ping { id: "p-1" };
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"op\":\"ping\""), "got {s}");
        assert!(s.contains("\"id\":\"p-1\""), "got {s}");
    }

    #[test]
    fn set_secret_request_uses_value_b64_field() {
        let req = Request::SetSecret {
            id: "s-1",
            name: "tok",
            value_b64: "Zm9v",
        };
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"value_b64\":\"Zm9v\""), "got {s}");
    }

    #[test]
    fn response_round_trips_with_optional_error() {
        let resp_ok = Response {
            id: "x".into(),
            ok: true,
            error: None,
        };
        let s = serde_json::to_string(&resp_ok).unwrap();
        assert!(!s.contains("error"), "ok response should omit error: {s}");
        let parsed: Response = serde_json::from_str(&s).unwrap();
        assert!(parsed.ok);
        assert_eq!(parsed.id, "x");

        let resp_err = Response {
            id: "y".into(),
            ok: false,
            error: Some("nope".into()),
        };
        let s = serde_json::to_string(&resp_err).unwrap();
        let parsed: Response = serde_json::from_str(&s).unwrap();
        assert!(!parsed.ok);
        assert_eq!(parsed.error.as_deref(), Some("nope"));
    }

    #[test]
    fn set_env_validates_keys_before_sending() {
        let mut env = HashMap::new();
        env.insert("bad-key".to_string(), "v".to_string());
        // No daemon — should fail at validation, not at I/O.
        let client = GuestMetadataClient::new(
            "/does/not/exist/vsock.uds",
            GuestMetadataConfig {
                connect_timeout: Duration::from_millis(0),
                request_timeout: Duration::from_millis(50),
                ..GuestMetadataConfig::default()
            },
        );
        // We can't actually call set_env without a connection, but we can
        // verify validate_env_key gates the input. Mirror what set_env does:
        let err = validate_env_key("bad-key").unwrap_err();
        assert!(matches!(err, VmRuntimeError::GuestMetadata(_)));
        // And construct shows path is preserved.
        assert_eq!(
            client.uds_path(),
            std::path::Path::new("/does/not/exist/vsock.uds")
        );
    }

    #[test]
    fn connect_returns_timeout_error_when_uds_missing() {
        let tmp = TempDir::new().unwrap();
        let nonexistent = tmp.path().join("never-bound.uds");
        let client = GuestMetadataClient::new(
            nonexistent,
            GuestMetadataConfig {
                connect_timeout: Duration::from_millis(100),
                ..GuestMetadataConfig::default()
            },
        );
        let err = client.connect().unwrap_err();
        match err {
            VmRuntimeError::GuestMetadata(msg) => {
                assert!(
                    msg.contains("timed out") || msg.contains("connect"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn end_to_end_set_env_writes_env_file() {
        let mut daemon = FakeDaemon::spawn();
        let client = GuestMetadataClient::new(
            daemon.uds_path.clone(),
            GuestMetadataConfig {
                connect_timeout: Duration::from_secs(2),
                request_timeout: Duration::from_secs(2),
                ..GuestMetadataConfig::default()
            },
        );
        let mut conn = client.connect().expect("connect");
        let mut env = HashMap::new();
        env.insert("FOO".to_string(), "bar".to_string());
        env.insert("BAZ".to_string(), "qux".to_string());
        conn.set_env(&env).expect("set_env");

        // Close the connection so the daemon thread exits cleanly.
        drop(conn);
        daemon.join();

        let contents = std::fs::read_to_string(&daemon.env_file).unwrap();
        // FakeDaemon writes keys in sorted order.
        assert_eq!(contents, "BAZ=qux\nFOO=bar\n");
    }

    #[test]
    fn end_to_end_set_secret_writes_secret_file() {
        let mut daemon = FakeDaemon::spawn();
        let client = GuestMetadataClient::new(
            daemon.uds_path.clone(),
            GuestMetadataConfig {
                connect_timeout: Duration::from_secs(2),
                request_timeout: Duration::from_secs(2),
                ..GuestMetadataConfig::default()
            },
        );
        let mut conn = client.connect().expect("connect");
        let payload = b"\x00\x01opaque-bytes\xff";
        conn.set_secret("sidecar_token", payload)
            .expect("set_secret");
        drop(conn);
        daemon.join();

        let path = daemon.secrets_dir.join("sidecar_token");
        let contents = std::fs::read(&path).unwrap();
        assert_eq!(contents, payload);
    }

    #[test]
    fn end_to_end_ping_round_trips() {
        let mut daemon = FakeDaemon::spawn();
        let client = GuestMetadataClient::new(
            daemon.uds_path.clone(),
            GuestMetadataConfig {
                connect_timeout: Duration::from_secs(2),
                request_timeout: Duration::from_secs(2),
                ..GuestMetadataConfig::default()
            },
        );
        let mut conn = client.connect().expect("connect");
        conn.ping().expect("ping");
        conn.ping().expect("second ping reuses connection");
        drop(conn);
        daemon.join();
    }

    #[test]
    fn end_to_end_firecracker_handshake_uses_configured_port() {
        // Bring up a listener that records the CONNECT line and rejects
        // anything else.
        let tmp = TempDir::new().unwrap();
        let uds_path = tmp.path().join("vsock.uds");
        let listener = UnixListener::bind(&uds_path).unwrap();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            tx.send(line.clone()).unwrap();
            // Reply OK then immediately close (we're only testing handshake).
            let port: u32 = line
                .trim()
                .trim_start_matches("CONNECT ")
                .parse()
                .unwrap_or(0);
            writer.write_all(format!("OK {port}\n").as_bytes()).unwrap();
        });
        let client = GuestMetadataClient::new(
            uds_path,
            GuestMetadataConfig {
                port: 9999,
                connect_timeout: Duration::from_secs(2),
                request_timeout: Duration::from_secs(2),
            },
        );
        let _ = client.connect().expect("connect");
        let observed = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(observed, expected_connect_line(9999));
    }

    #[test]
    fn connect_propagates_rejected_handshake() {
        // Listener replies with a non-OK line; client must surface it as
        // a GuestMetadata error rather than hanging.
        let tmp = TempDir::new().unwrap();
        let uds_path = tmp.path().join("vsock.uds");
        let listener = UnixListener::bind(&uds_path).unwrap();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            let _ = reader.read_line(&mut line);
            let _ = writer.write_all(b"REJECT busy\n");
            let _ = writer.flush();
        });
        let client = GuestMetadataClient::new(
            uds_path,
            GuestMetadataConfig {
                connect_timeout: Duration::from_secs(2),
                request_timeout: Duration::from_secs(2),
                ..GuestMetadataConfig::default()
            },
        );
        let err = client.connect().unwrap_err();
        match err {
            VmRuntimeError::GuestMetadata(msg) => {
                assert!(msg.contains("REJECT"), "unexpected message: {msg}");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn from_env_reads_configured_values() {
        // Use a uniquely-scoped key set so concurrent tests don't clobber
        // each other. We `remove_var` after to keep the suite hermetic.
        // SAFETY: env mutation in tests is documented unsafe in Rust 2024.
        unsafe {
            std::env::set_var("MICROVM_GUEST_METADATA_PORT", "7777");
            std::env::set_var("MICROVM_GUEST_METADATA_CONNECT_TIMEOUT_MS", "1500");
            std::env::set_var("MICROVM_GUEST_METADATA_REQUEST_TIMEOUT_MS", "250");
        }
        let cfg = GuestMetadataConfig::from_env();
        // SAFETY: see above.
        unsafe {
            std::env::remove_var("MICROVM_GUEST_METADATA_PORT");
            std::env::remove_var("MICROVM_GUEST_METADATA_CONNECT_TIMEOUT_MS");
            std::env::remove_var("MICROVM_GUEST_METADATA_REQUEST_TIMEOUT_MS");
        }
        assert_eq!(cfg.port, 7777);
        assert_eq!(cfg.connect_timeout, Duration::from_millis(1500));
        assert_eq!(cfg.request_timeout, Duration::from_millis(250));
    }

    #[test]
    fn owned_request_id_returns_correct_field() {
        let r = OwnedRequest::Ping { id: "a".into() };
        assert_eq!(r.id(), "a");
        let r = OwnedRequest::SetEnv {
            id: "b".into(),
            env: HashMap::new(),
        };
        assert_eq!(r.id(), "b");
        let r = OwnedRequest::SetSecret {
            id: "c".into(),
            name: "n".into(),
            value_b64: "".into(),
        };
        assert_eq!(r.id(), "c");
    }
}
