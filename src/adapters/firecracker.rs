use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::{
    composer::FirecrackerComposer,
    console::{ConsoleCapture, ConsoleConfig},
    error::{VmRuntimeError, VmRuntimeResult},
    jailer::{self, VmJail},
    model::{
        DriveSpec, NetworkInterface, RateLimiter, SnapshotRef, TokenBucket, VmSpec, VmStatus,
        VmView, VsockSpec,
    },
    provider::{VmProvider, VmQuery},
    shutdown::graceful_shutdown,
    uffd::{UffdConfig, UffdHandler, snapshot_load_mem_backend_uffd},
};

const DEFAULT_FIRECRACKER_BIN: &str = "/usr/local/bin/firecracker";
const DEFAULT_KERNEL_PATH: &str = "/var/lib/firecracker/vmlinux";
const DEFAULT_ROOTFS_PATH: &str = "/var/lib/firecracker/rootfs/default.ext4";
const DEFAULT_BOOT_ARGS: &str =
    "console=ttyS0 reboot=k panic=1 pci=off quiet i8042.nokbd i8042.noaux";
const DEFAULT_API_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_SOCKET_READY_TIMEOUT_MS: u64 = 5_000;

/// First sleep between API-socket readiness probes after spawning FC. The
/// socket is usually ready within a few ms of exec, so the first re-check
/// must come fast — a flat 100 ms poll wasted 50–90 ms of pure idle wait on
/// every VM spawn.
const SOCKET_POLL_INITIAL_INTERVAL: Duration = Duration::from_millis(2);
/// Backoff cap for the readiness poll — the previous flat interval, so a
/// genuinely slow host converges to exactly the old cadence instead of
/// busy-spinning for the whole `socket_ready_timeout`.
const SOCKET_POLL_MAX_INTERVAL: Duration = Duration::from_millis(100);

/// Next sleep in the socket-readiness backoff: double, capped at
/// [`SOCKET_POLL_MAX_INTERVAL`]. From the initial 2 ms: 4, 8, 16, 32, 64,
/// 100, 100, …
fn next_socket_poll_interval(current: Duration) -> Duration {
    (current * 2).min(SOCKET_POLL_MAX_INTERVAL)
}

/// Basename of the per-VM userfaultfd socket used when
/// [`MemBackend::Uffd`] is selected. Jailed VMs get it at the chroot root
/// (FC connects to `/uffd.sock` post-chroot); non-jailed VMs get it in the
/// VM's state dir.
const UFFD_SOCKET_BASENAME: &str = "uffd.sock";

/// Guest-memory backend Firecracker uses on `PUT /snapshot/load`.
///
/// The `Default` impl is [`MemBackend::File`] — the always-works choice for
/// programmatically constructed configs. [`FirecrackerConfig::from_env`]
/// is smarter: with `MICROVM_MEM_BACKEND` unset it probes
/// `/proc/sys/vm/unprivileged_userfaultfd` and picks `Uffd` when the
/// spawned Firecracker will be able to create a userfaultfd.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MemBackend {
    /// FC reads the whole snapshot mem file synchronously before resuming.
    #[default]
    File,
    /// A [`crate::uffd::UffdHandler`] pages guest memory in on demand —
    /// the VM resumes immediately and only touched pages are loaded.
    Uffd,
}

impl std::str::FromStr for MemBackend {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "file" => Ok(Self::File),
            "uffd" => Ok(Self::Uffd),
            other => Err(format!(
                "invalid memory backend '{other}' (expected 'file' or 'uffd')"
            )),
        }
    }
}

/// Sysctl gating `userfaultfd(2)` for processes without CAP_SYS_PTRACE.
const UNPRIVILEGED_USERFAULTFD_SYSCTL: &str = "/proc/sys/vm/unprivileged_userfaultfd";

/// Whether *any* process on this host — including a jailed, privilege-
/// dropped Firecracker — can create a userfaultfd.
///
/// The userfaultfd behind [`MemBackend::Uffd`] is created by the
/// **Firecracker process** (it hands the fd to our handler over the UDS),
/// so probing our own process (a `userfaultfd(2)` attempt here) would
/// over-approximate: this process may hold CAP_SYS_PTRACE while the jailed
/// FC it spawns runs uid-dropped and fails at restore time. The
/// `vm.unprivileged_userfaultfd=1` sysctl is the one signal valid for
/// every FC we spawn. Hosts running FC privileged with the sysctl off can
/// still opt in explicitly via `MICROVM_MEM_BACKEND=uffd`.
///
/// Missing file (kernel without CONFIG_USERFAULTFD, non-Linux) reads as
/// unsupported — fail-safe to the File backend.
fn host_allows_unprivileged_uffd() -> bool {
    fs::read_to_string(UNPRIVILEGED_USERFAULTFD_SYSCTL)
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// Parse `MICROVM_MEM_BACKEND`. An explicit value always wins; an invalid
/// value panics rather than silently running with the wrong backend — a
/// misconfigured operator must find out at startup, not on the first slow
/// restore.
///
/// Absent → auto-detect from `uffd_usable` (the
/// [`host_allows_unprivileged_uffd`] probe, injected for testability):
/// `Uffd` when the host allows it — restores resume in ~ms instead of
/// reading the whole guest-RAM file — else `File` with a one-line warning
/// naming the sysctl that would unlock the fast path.
fn mem_backend_from_env_value(value: Option<&str>, uffd_usable: bool) -> MemBackend {
    match value {
        None if uffd_usable => MemBackend::Uffd,
        None => {
            eprintln!(
                "[microvm-firecracker] MICROVM_MEM_BACKEND unset and \
                 {UNPRIVILEGED_USERFAULTFD_SYSCTL} != 1: using the File memory \
                 backend (snapshot restore reads the entire guest-RAM file \
                 before resume). Set vm.unprivileged_userfaultfd=1 — or \
                 MICROVM_MEM_BACKEND=uffd if firecracker runs with \
                 CAP_SYS_PTRACE — for lazy userfaultfd restores."
            );
            MemBackend::File
        }
        Some(v) => v
            .parse::<MemBackend>()
            .unwrap_or_else(|e| panic!("MICROVM_MEM_BACKEND: {e}")),
    }
}

/// Read one HTTP/1.1 response from `stream` by its framing: headers up to
/// the blank line, then exactly `Content-Length` body bytes (0 when the
/// header is absent — Firecracker's micro_http always sends it on non-empty
/// bodies). Returns the raw bytes (headers + body).
///
/// Reading to EOF is not an option here: Firecracker's API server holds the
/// connection open regardless of `Connection: close`, so an EOF-terminated
/// read blocks until the socket read timeout on every request.
fn read_http_response(stream: &mut UnixStream) -> std::io::Result<Vec<u8>> {
    // Cap header growth so a misbehaving server cannot balloon memory; FC
    // response headers are well under 1 KiB.
    const MAX_HEADER_BYTES: usize = 64 * 1024;

    let mut response: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = find_subslice(&response, b"\r\n\r\n") {
            break pos + 4;
        }
        if response.len() > MAX_HEADER_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "response headers exceed 64 KiB without terminator",
            ));
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before response headers completed",
            ));
        }
        response.extend_from_slice(&chunk[..n]);
    };

    let headers_text = String::from_utf8_lossy(&response[..header_end]);
    if headers_text
        .lines()
        .any(|l| l.to_ascii_lowercase().starts_with("transfer-encoding:"))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "transfer-encoded responses are not supported",
        ));
    }
    let content_length = headers_text
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>())
        })
        .transpose()
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid Content-Length: {e}"),
            )
        })?
        .unwrap_or(0);

    let total = header_end.checked_add(content_length).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "Content-Length overflow")
    })?;
    while response.len() < total {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed mid-body",
            ));
        }
        response.extend_from_slice(&chunk[..n]);
    }
    response.truncate(total);
    Ok(response)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[derive(Debug, Clone)]
struct VmRecord {
    status: VmStatus,
    snapshots: Vec<String>,
    socket_path: PathBuf,
    state_dir: PathBuf,
}

impl VmRecord {
    fn view(&self, vm_id: &str) -> VmView {
        VmView {
            vm_id: vm_id.to_owned(),
            status: self.status,
            snapshots: self.snapshots.clone(),
        }
    }
}

/// Firecracker adapter configuration loaded from environment.
#[derive(Debug, Clone)]
pub struct FirecrackerConfig {
    /// Path to Firecracker binary.
    pub binary_path: PathBuf,
    /// Path to Linux kernel image.
    pub kernel_path: PathBuf,
    /// Path to rootfs image.
    pub rootfs_path: PathBuf,
    /// Kernel boot args passed to Firecracker.
    pub boot_args: String,
    /// Root directory where per-VM API sockets are created.
    pub socket_dir: PathBuf,
    /// Root directory where per-VM state artifacts are written.
    pub state_dir: PathBuf,
    /// VM vCPU count.
    pub vcpu_count: u8,
    /// VM memory in MiB.
    pub mem_size_mib: u32,
    /// Mount rootfs as read-only in guest.
    pub rootfs_read_only: bool,
    /// Timeout for each API call over unix socket.
    pub api_timeout: Duration,
    /// Max wait for Firecracker API socket readiness after process spawn.
    pub socket_ready_timeout: Duration,
    /// Guest-memory backend for snapshot restore. `MICROVM_MEM_BACKEND`
    /// accepts `file` or `uffd`; unset, [`Self::from_env`] auto-detects
    /// (`uffd` when the host permits unprivileged userfaultfd, else `file`
    /// with a warning); an invalid value fails loudly at config load.
    pub mem_backend: MemBackend,
}

impl FirecrackerConfig {
    pub fn from_env() -> Self {
        let binary_path = std::env::var("MICROVM_FIRECRACKER_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_FIRECRACKER_BIN));
        let kernel_path = std::env::var("MICROVM_FIRECRACKER_KERNEL")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_KERNEL_PATH));
        let rootfs_path = std::env::var("MICROVM_FIRECRACKER_ROOTFS")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_ROOTFS_PATH));
        let boot_args = std::env::var("MICROVM_FIRECRACKER_BOOT_ARGS")
            .unwrap_or_else(|_| DEFAULT_BOOT_ARGS.to_string());
        let socket_dir = std::env::var("MICROVM_FIRECRACKER_SOCKET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp/microvm-firecracker/sockets"));
        let state_dir = std::env::var("MICROVM_FIRECRACKER_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp/microvm-firecracker/state"));
        let vcpu_count = std::env::var("MICROVM_FIRECRACKER_VCPU_COUNT")
            .ok()
            .and_then(|v| v.parse::<u8>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(2);
        let mem_size_mib = std::env::var("MICROVM_FIRECRACKER_MEM_MIB")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(1024);
        let rootfs_read_only = std::env::var("MICROVM_FIRECRACKER_ROOTFS_RO")
            .ok()
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "True"))
            .unwrap_or(true);
        let api_timeout = Duration::from_millis(
            std::env::var("MICROVM_FIRECRACKER_API_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|v| *v > 0)
                .unwrap_or(DEFAULT_API_TIMEOUT_MS),
        );
        let socket_ready_timeout = Duration::from_millis(
            std::env::var("MICROVM_FIRECRACKER_SOCKET_READY_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|v| *v > 0)
                .unwrap_or(DEFAULT_SOCKET_READY_TIMEOUT_MS),
        );
        let mem_backend = mem_backend_from_env_value(
            std::env::var("MICROVM_MEM_BACKEND").ok().as_deref(),
            host_allows_unprivileged_uffd(),
        );

        Self {
            binary_path,
            kernel_path,
            rootfs_path,
            boot_args,
            socket_dir,
            state_dir,
            vcpu_count,
            mem_size_mib,
            rootfs_read_only,
            api_timeout,
            socket_ready_timeout,
            mem_backend,
        }
    }
}

/// Where one snapshot's artifacts (vmstate + guest memory) live on the host
/// and how the — possibly chrooted — Firecracker process must address them.
///
/// * Non-jailed: all three views coincide; FC reads/writes the durable paths
///   directly.
/// * Jailed: FC resolves every path inside its chroot, so the API body gets
///   `/<id>.vmstate` / `/<id>.mem` (`fc_*`), which land at `<chroot>/<id>.*`
///   on the host (`staged_*`). Snapshot create moves the staged files to the
///   durable home afterwards (the chroot dies with the VM); restore
///   hard-links the durable files back in beforehand.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SnapshotArtifactPaths {
    /// Durable host home: `<state_dir>/<source_vm>/snapshots/<id>.{vmstate,mem}`.
    durable_vmstate: PathBuf,
    durable_mem: PathBuf,
    /// Paths written into the FC API body — what the FC process resolves.
    fc_vmstate: PathBuf,
    fc_mem: PathBuf,
    /// Host-side view of `fc_*`. Equal to `durable_*` when not jailed.
    staged_vmstate: PathBuf,
    staged_mem: PathBuf,
}

impl SnapshotArtifactPaths {
    /// `true` when the staged (in-chroot) location differs from the durable
    /// home, i.e. the VM is jailed and artifacts must be moved/linked.
    fn is_staged(&self) -> bool {
        self.staged_vmstate != self.durable_vmstate
    }
}

/// Compute [`SnapshotArtifactPaths`] for `snapshot_id` under `snap_dir`
/// (`<state_dir>/<vm>/snapshots`). `chroot` is `Some` when the FC process is
/// jailed. Rejects snapshot ids that could escape the snapshot dir or the
/// chroot — the id becomes a filename on both sides of the boundary.
fn snapshot_artifact_paths(
    snap_dir: &Path,
    snapshot_id: &str,
    chroot: Option<&Path>,
) -> VmRuntimeResult<SnapshotArtifactPaths> {
    if snapshot_id.is_empty()
        || !snapshot_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        || snapshot_id.contains("..")
    {
        return Err(VmRuntimeError::Unsupported(format!(
            "snapshot id '{snapshot_id}' is not a safe filename \
             (allowed: [A-Za-z0-9._-], no '..')"
        )));
    }

    let vmstate_name = format!("{snapshot_id}.vmstate");
    let mem_name = format!("{snapshot_id}.mem");
    let durable_vmstate = snap_dir.join(&vmstate_name);
    let durable_mem = snap_dir.join(&mem_name);

    Ok(match chroot {
        // Jailed FC sees the chroot as `/`, so an artifact staged at
        // `<chroot>/<name>` is addressed as `/<name>` in the API body.
        Some(chroot) => SnapshotArtifactPaths {
            fc_vmstate: PathBuf::from("/").join(&vmstate_name),
            fc_mem: PathBuf::from("/").join(&mem_name),
            staged_vmstate: chroot.join(&vmstate_name),
            staged_mem: chroot.join(&mem_name),
            durable_vmstate,
            durable_mem,
        },
        None => SnapshotArtifactPaths {
            fc_vmstate: durable_vmstate.clone(),
            fc_mem: durable_mem.clone(),
            staged_vmstate: durable_vmstate.clone(),
            staged_mem: durable_mem.clone(),
            durable_vmstate,
            durable_mem,
        },
    })
}

/// Move a Firecracker-written snapshot artifact from its in-chroot staging
/// path to the durable snapshot dir. Prefers `rename` (atomic, same-fs); the
/// chroot base and the state dir can be different mounts, so falls back to a
/// copy + unlink on `EXDEV`.
fn move_into_place(from: &Path, to: &Path) -> VmRuntimeResult<()> {
    match fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(nix::errno::Errno::EXDEV as i32) => {
            fs::copy(from, to).map_err(|e| {
                VmRuntimeError::Unsupported(format!(
                    "failed copying snapshot artifact {} -> {}: {e}",
                    from.display(),
                    to.display()
                ))
            })?;
            let _ = fs::remove_file(from);
            Ok(())
        }
        Err(e) => Err(VmRuntimeError::Unsupported(format!(
            "failed moving snapshot artifact {} -> {}: {e}",
            from.display(),
            to.display()
        ))),
    }
}

/// Build the `PUT /machine-config` body.
///
/// `track_dirty_pages` defaults to **off**: it exists solely to feed diff
/// snapshots, and this adapter only ever issues `snapshot_type: "Full"`
/// creates and `enable_diff_snapshots: false` loads — so the kernel
/// dirty-page bitmap would tax every guest write with no consumer. Set
/// [`crate::model::VmSpec::track_dirty_pages`] to `Some(true)` per-VM when
/// diff snapshots are driven externally.
fn machine_config_body(
    vcpu_count: u8,
    mem_size_mib: u32,
    track_dirty_pages: Option<bool>,
) -> serde_json::Value {
    serde_json::json!({
        "vcpu_count": vcpu_count,
        "mem_size_mib": mem_size_mib,
        "smt": false,
        "track_dirty_pages": track_dirty_pages.unwrap_or(false)
    })
}

/// Build the `PUT /snapshot/load` body. `mem_backend` is either the `File`
/// object pointing at the FC-visible mem path or the `Uffd` object pointing
/// at the FC-visible handler socket (see
/// [`crate::uffd::snapshot_load_mem_backend_uffd`]).
fn build_snapshot_load_body(
    snapshot: &SnapshotRef,
    fc_vmstate: &Path,
    mem_backend: serde_json::Value,
) -> serde_json::Value {
    let mut body = serde_json::json!({
        "snapshot_path": fc_vmstate,
        "mem_backend": mem_backend,
        "enable_diff_snapshots": false,
        "resume_vm": snapshot.resume_immediately,
    });
    if !snapshot.network_overrides.is_empty() {
        let overrides: Vec<_> = snapshot
            .network_overrides
            .iter()
            .map(|iface| {
                let mut entry = serde_json::json!({
                    "iface_id": iface.iface_id,
                    "host_dev_name": iface.host_dev_name,
                });
                if let Some(mac) = &iface.guest_mac {
                    entry["guest_mac"] = serde_json::Value::String(mac.clone());
                }
                entry
            })
            .collect();
        body["network_interfaces"] = serde_json::Value::Array(overrides);
    }
    body
}

/// Firecracker-backed provider surface.
///
/// This adapter manages real Firecracker VMM processes over unix socket API.
///
/// By default it does the minimum: spawn FC, configure via the spec, start. To opt into
/// auto-composition with the lifecycle primitives (network, vsock, firewall, jailer,
/// console capture, graceful shutdown), construct via
/// [`Self::with_composer`] or [`Self::from_env_composed`].
#[derive(Clone)]
pub struct FirecrackerVmProvider {
    pub config: FirecrackerConfig,
    composer: Option<Arc<FirecrackerComposer>>,
    state: Arc<RwLock<HashMap<String, VmRecord>>>,
    processes: Arc<Mutex<HashMap<String, Child>>>,
    #[cfg(feature = "firecracker")]
    consoles: Arc<Mutex<HashMap<String, ConsoleCapture>>>,
    /// Per-VM attachments owned by the composer (TAP, vsock, firewall rules, jail).
    /// Stored opaquely so destroy_vm can release them without re-deriving identifiers.
    composed: Arc<Mutex<HashMap<String, ComposedAttachments>>>,
    /// Live userfaultfd page-fault handlers, one per VM restored with
    /// [`MemBackend::Uffd`]. Each handler must outlive every page fault its
    /// guest will ever raise, so it is held here until `destroy_vm` (drop
    /// triggers an orderly shutdown).
    uffd_handlers: Arc<Mutex<HashMap<String, UffdHandler>>>,
}

#[derive(Default, Clone)]
struct ComposedAttachments {
    network_attached: bool,
    vsock_attached: bool,
    firewall_installed: bool,
    /// `Some(jail)` means FC was spawned under jailer in this chroot. The
    /// `api_socket_on_host` field of the jail is what the HTTP client connects to;
    /// the workspace default `socket_dir/<vm_id>/api.sock` is bypassed.
    jail: Option<crate::jailer::VmJail>,
}

impl std::fmt::Debug for FirecrackerVmProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FirecrackerVmProvider")
            .field("config", &self.config)
            .field("composer", &self.composer.is_some())
            .finish_non_exhaustive()
    }
}

impl FirecrackerVmProvider {
    pub fn new(config: FirecrackerConfig) -> Self {
        Self {
            config,
            composer: None,
            state: Arc::new(RwLock::new(HashMap::new())),
            processes: Arc::new(Mutex::new(HashMap::new())),
            consoles: Arc::new(Mutex::new(HashMap::new())),
            composed: Arc::new(Mutex::new(HashMap::new())),
            uffd_handlers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn from_env() -> Self {
        Self::new(FirecrackerConfig::from_env())
    }

    /// Attach a [`FirecrackerComposer`] so create / destroy automatically invoke the
    /// configured lifecycle primitives.
    pub fn with_composer(mut self, composer: FirecrackerComposer) -> Self {
        self.composer = Some(Arc::new(composer));
        self
    }

    /// Shorthand for `Self::from_env().with_composer(FirecrackerComposer::from_env())`.
    /// Every composition primitive is toggled by `MICROVM_COMPOSE_*` env vars; absent
    /// = enabled.
    pub fn from_env_composed() -> Self {
        Self::from_env().with_composer(FirecrackerComposer::from_env())
    }

    pub fn api_socket_path(&self, vm_id: &str) -> PathBuf {
        self.config
            .socket_dir
            .join(self.safe_vm_id(vm_id))
            .join("api.sock")
    }

    pub fn vm_state_path(&self, vm_id: &str) -> PathBuf {
        self.config.state_dir.join(self.safe_vm_id(vm_id))
    }

    fn safe_vm_id(&self, vm_id: &str) -> String {
        vm_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    }

    fn ensure_prereqs(&self, spec: &VmSpec) -> VmRuntimeResult<()> {
        if !self.config.binary_path.exists() {
            return Err(VmRuntimeError::Unsupported(format!(
                "firecracker binary not found: {}",
                self.config.binary_path.display()
            )));
        }
        // Kernel + rootfs checks are skipped when restoring — the snapshot encodes its own
        // boot source. Cold boot validates the spec-resolved paths (overrides if set, else
        // the workspace default).
        if spec.restore_from.is_none() {
            let kernel = spec.kernel.as_ref().unwrap_or(&self.config.kernel_path);
            if !kernel.exists() {
                return Err(VmRuntimeError::Unsupported(format!(
                    "kernel image not found: {}",
                    kernel.display()
                )));
            }
            let rootfs = spec.rootfs.as_ref().unwrap_or(&self.config.rootfs_path);
            if !rootfs.exists() {
                return Err(VmRuntimeError::Unsupported(format!(
                    "rootfs image not found: {}",
                    rootfs.display()
                )));
            }
        }
        fs::create_dir_all(&self.config.socket_dir).map_err(|e| {
            VmRuntimeError::Unsupported(format!(
                "failed to create socket dir {}: {e}",
                self.config.socket_dir.display()
            ))
        })?;
        fs::create_dir_all(&self.config.state_dir).map_err(|e| {
            VmRuntimeError::Unsupported(format!(
                "failed to create state dir {}: {e}",
                self.config.state_dir.display()
            ))
        })?;
        Ok(())
    }

    fn remove_stale_socket(socket_path: &Path) -> VmRuntimeResult<()> {
        if socket_path.exists() {
            fs::remove_file(socket_path).map_err(|e| {
                VmRuntimeError::Unsupported(format!(
                    "failed to remove stale socket {}: {e}",
                    socket_path.display()
                ))
            })?;
        }
        Ok(())
    }

    /// Spawn FC under the configured launcher.
    ///
    /// `capture_stderr` toggles between piping the child's stderr for
    /// [`ConsoleCapture`] consumption and routing it to `/dev/null` (the historical
    /// default). The composer is responsible for the toggle; bare semantics keep
    /// stderr null so callers who don't want capture don't accidentally retain it.
    ///
    /// `jail` is `Some` when the caller asked the composer to wrap FC in `jailer`.
    /// In that case the FC binary is invoked via `jailer ... -- --api-sock ...`,
    /// landing FC under the chroot. The `socket_path` parameter MUST point at
    /// the post-jail host view of the API socket (`<chroot>/api.sock`) — the
    /// caller is responsible for resolving this from the [`crate::jailer::VmJail`]
    /// returned by `compose_pre_spawn`.
    fn spawn_firecracker_for_compose(
        &self,
        vm_id: &str,
        socket_path: &Path,
        capture_stderr: bool,
        jail: Option<&crate::jailer::VmJail>,
    ) -> VmRuntimeResult<Child> {
        let parent = socket_path.parent().ok_or_else(|| {
            VmRuntimeError::Unsupported(format!(
                "invalid api socket path for vm {vm_id}: {}",
                socket_path.display()
            ))
        })?;
        fs::create_dir_all(parent).map_err(|e| {
            VmRuntimeError::Unsupported(format!(
                "failed to create socket parent {}: {e}",
                parent.display()
            ))
        })?;
        Self::remove_stale_socket(socket_path)?;

        let stderr = if capture_stderr {
            Stdio::piped()
        } else {
            Stdio::null()
        };

        let mut command = match jail {
            Some(j) => {
                let jailer = self
                    .composer
                    .as_ref()
                    .and_then(|c| c.jailer.clone())
                    .ok_or_else(|| {
                        VmRuntimeError::Jailer(format!(
                            "spawn requested jailed mode for vm {vm_id} but no jailer is on the composer"
                        ))
                    })?;
                jailer.build_command(vm_id, j, &self.config.binary_path)?
            }
            None => {
                let mut c = Command::new(&self.config.binary_path);
                c.arg("--api-sock").arg(socket_path);
                c
            }
        };

        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr)
            .spawn()
            .map_err(|e| {
                VmRuntimeError::Unsupported(format!(
                    "failed spawning firecracker for {vm_id} ({}): {e}",
                    self.config.binary_path.display()
                ))
            })
    }

    /// Run composer-side pre-spawn primitives and augment `spec` with the resulting
    /// fields. Returns the augmented spec plus an [`ComposedAttachments`] tracker
    /// for cleanup on destroy.
    fn compose_pre_spawn(
        &self,
        vm_id: &str,
        mut spec: VmSpec,
    ) -> VmRuntimeResult<(VmSpec, ComposedAttachments)> {
        let Some(composer) = self.composer.clone() else {
            return Ok((spec, ComposedAttachments::default()));
        };

        // Restored VMs ignore network_interfaces / vsock from the spec (the snapshot
        // encodes them), so composing per-VM TAP / CID on restore is incorrect.
        // Callers wanting to swap network on restore should populate
        // `SnapshotRef::network_overrides` themselves. The jailer is the exception:
        // it is an isolation boundary, not guest config, so a restored VM must be
        // chrooted exactly like a cold-booted one. The fresh chroot is prepared with
        // the spec-resolved kernel/rootfs/drives so the in-chroot drive paths the
        // snapshot recorded (`/rootfs.ext4`, drive basenames) resolve again, and
        // `load_snapshot` stages the snapshot artifacts into it.
        if spec.restore_from.is_some() {
            let mut attachments = ComposedAttachments::default();
            if let Some(jailer) = composer.jailer.as_ref() {
                let kernel = spec
                    .kernel
                    .clone()
                    .unwrap_or_else(|| self.config.kernel_path.clone());
                let rootfs = spec
                    .rootfs
                    .clone()
                    .unwrap_or_else(|| self.config.rootfs_path.clone());
                let extra: Vec<PathBuf> = spec
                    .extra_drives
                    .iter()
                    .map(|d| d.path_on_host.clone())
                    .collect();
                attachments.jail = Some(jailer.prepare(vm_id, &kernel, &rootfs, &extra)?);
            }
            return Ok((spec, attachments));
        }

        let mut attachments = ComposedAttachments::default();

        if let Some(network) = composer.network.as_ref() {
            network.ensure_host()?;
            let vm_network = network.attach(vm_id)?;
            let guest_mac = vm_network.mac_string();
            spec.network_interfaces.push(NetworkInterface {
                iface_id: "eth0".into(),
                host_dev_name: vm_network.tap_name,
                guest_mac: Some(guest_mac),
                rx_rate_limiter: None,
                tx_rate_limiter: None,
            });
            attachments.network_attached = true;
        }

        if let Some(vsock) = composer.vsock.as_ref() {
            let attachment = vsock.attach(vm_id)?;
            vsock.ensure_uds_parent(&attachment.uds_path)?;
            spec.vsock = Some(VsockSpec {
                cid: attachment.cid,
                uds_path: attachment.uds_path,
            });
            attachments.vsock_attached = true;
        }

        if let Some(firewall) = composer.firewall.as_ref() {
            // Find the TAP name from the network interface the composer just added.
            // If there's no TAP, skip firewall (it'd jump from a non-existent iface).
            if let Some(tap) = spec
                .network_interfaces
                .last()
                .map(|i| i.host_dev_name.clone())
            {
                firewall.install(vm_id, &tap, &[])?;
                attachments.firewall_installed = true;
            }
        }

        // Jailer composition: prepare per-VM chroot with the spec-resolved kernel +
        // rootfs (defaulting to workspace config). The returned VmJail records the
        // post-jail api.sock path on the host so the HTTP client connects to it
        // instead of the workspace-default `socket_dir/<vm_id>/api.sock`.
        if let Some(jailer) = composer.jailer.as_ref() {
            let kernel = spec
                .kernel
                .clone()
                .unwrap_or_else(|| self.config.kernel_path.clone());
            let rootfs = spec
                .rootfs
                .clone()
                .unwrap_or_else(|| self.config.rootfs_path.clone());
            let extra: Vec<PathBuf> = spec
                .extra_drives
                .iter()
                .map(|d| d.path_on_host.clone())
                .collect();
            let jail = jailer.prepare(vm_id, &kernel, &rootfs, &extra)?;
            attachments.jail = Some(jail);
        }

        Ok((spec, attachments))
    }

    /// Release composer-side attachments for `vm_id`. Idempotent — every step is
    /// best-effort and never errors out.
    fn compose_release(&self, vm_id: &str, attachments: &ComposedAttachments) {
        let Some(composer) = self.composer.clone() else {
            return;
        };

        if attachments.firewall_installed
            && let Some(firewall) = composer.firewall.as_ref()
        {
            let _ = firewall.uninstall(vm_id);
        }

        if attachments.vsock_attached
            && let Some(vsock) = composer.vsock.as_ref()
        {
            let _ = vsock.detach(vm_id);
        }

        if attachments.network_attached
            && let Some(network) = composer.network.as_ref()
        {
            let _ = network.detach(vm_id);
        }

        if attachments.jail.is_some()
            && let Some(jailer) = composer.jailer.as_ref()
        {
            let _ = jailer.teardown(vm_id);
        }
    }

    fn wait_for_socket_ready(&self, socket_path: &Path) -> VmRuntimeResult<()> {
        let deadline = Instant::now() + self.config.socket_ready_timeout;
        let mut interval = SOCKET_POLL_INITIAL_INTERVAL;
        while Instant::now() < deadline {
            if socket_path.exists()
                && self
                    .firecracker_request(socket_path, "GET", "/", None)
                    .is_ok()
            {
                return Ok(());
            }
            thread::sleep(interval);
            interval = next_socket_poll_interval(interval);
        }
        Err(VmRuntimeError::Unsupported(format!(
            "firecracker api socket not ready within {:?}: {}",
            self.config.socket_ready_timeout,
            socket_path.display()
        )))
    }

    fn configure_vm(
        &self,
        socket_path: &Path,
        spec: &VmSpec,
        jail: Option<&VmJail>,
    ) -> VmRuntimeResult<()> {
        let jailed = jail.is_some();

        // A jailed FC would bind the vsock UDS inside its chroot while
        // host-side clients dial the recorded host path — the two can never
        // meet without chroot-aware staging in the vsock manager. Refuse up
        // front (before any FC API call) with the remediation instead of
        // surfacing FC's opaque bind failure.
        if jailed && spec.vsock.is_some() {
            return Err(VmRuntimeError::Unsupported(
                "vsock under the jailer is not yet supported: the UDS path cannot \
                 resolve both inside the chroot (for FC) and on the host (for \
                 clients); set MICROVM_COMPOSE_VSOCK=0 or run without the jailer"
                    .into(),
            ));
        }

        let vcpu_count = spec.vcpu_count.unwrap_or(self.config.vcpu_count);
        let mem_size_mib = spec.mem_size_mib.unwrap_or(self.config.mem_size_mib);
        let machine = machine_config_body(vcpu_count, mem_size_mib, spec.track_dirty_pages);
        self.firecracker_request(socket_path, "PUT", "/machine-config", Some(machine))?;

        // A jailed FC resolves every path inside its chroot, where the jailer
        // staged the artifacts under fixed basenames — hand it those, not the
        // host paths they were staged from. These in-chroot paths are also what
        // the snapshot records, so a later restore into a fresh chroot (which
        // stages the same basenames) resolves them again.
        let kernel_path: PathBuf = if jailed {
            PathBuf::from("/").join(jailer::KERNEL_BASENAME)
        } else {
            spec.kernel
                .clone()
                .unwrap_or_else(|| self.config.kernel_path.clone())
        };
        let boot_args = spec.boot_args.as_deref().unwrap_or(&self.config.boot_args);
        let boot = serde_json::json!({
            "kernel_image_path": kernel_path,
            "boot_args": boot_args
        });
        self.firecracker_request(socket_path, "PUT", "/boot-source", Some(boot))?;

        let rootfs_path: PathBuf = if jailed {
            PathBuf::from("/").join(jailer::ROOTFS_BASENAME)
        } else {
            spec.rootfs
                .clone()
                .unwrap_or_else(|| self.config.rootfs_path.clone())
        };
        let rootfs_read_only = spec
            .rootfs_read_only
            .unwrap_or(self.config.rootfs_read_only);
        let mut root_drive = serde_json::json!({
            "drive_id": "rootfs",
            "path_on_host": rootfs_path,
            "is_root_device": true,
            "is_read_only": rootfs_read_only
        });
        if let Some(limiter) = spec.rootfs_rate_limit.as_ref() {
            root_drive["rate_limiter"] = rate_limiter_to_json(limiter);
        }
        self.firecracker_request(socket_path, "PUT", "/drives/rootfs", Some(root_drive))?;

        for iface in &spec.network_interfaces {
            self.put_network_interface(socket_path, iface)?;
        }

        for (idx, drive) in spec.extra_drives.iter().enumerate() {
            if jailed {
                // Same basename derivation as `Jailer::prepare` staged it under.
                let staged = DriveSpec {
                    path_on_host: PathBuf::from("/")
                        .join(jailer::staged_drive_basename(&drive.path_on_host, idx)),
                    ..drive.clone()
                };
                self.put_extra_drive(socket_path, &staged)?;
            } else {
                self.put_extra_drive(socket_path, drive)?;
            }
        }

        if let Some(vsock) = spec.vsock.as_ref() {
            self.put_vsock(socket_path, vsock)?;
        }

        Ok(())
    }

    fn put_extra_drive(&self, socket_path: &Path, drive: &DriveSpec) -> VmRuntimeResult<()> {
        if drive.drive_id == "rootfs" {
            return Err(VmRuntimeError::Unsupported(
                "drive_id 'rootfs' is reserved for the root device".into(),
            ));
        }
        let mut body = serde_json::json!({
            "drive_id": drive.drive_id,
            "path_on_host": drive.path_on_host,
            "is_root_device": false,
            "is_read_only": drive.is_read_only,
        });
        if let Some(limiter) = drive.rate_limiter.as_ref() {
            body["rate_limiter"] = rate_limiter_to_json(limiter);
        }
        let path = format!("/drives/{}", drive.drive_id);
        self.firecracker_request(socket_path, "PUT", &path, Some(body))?;
        Ok(())
    }

    fn put_vsock(&self, socket_path: &Path, vsock: &VsockSpec) -> VmRuntimeResult<()> {
        let body = serde_json::json!({
            "guest_cid": vsock.cid,
            "uds_path": vsock.uds_path,
        });
        self.firecracker_request(socket_path, "PUT", "/vsock", Some(body))?;
        Ok(())
    }

    fn put_network_interface(
        &self,
        socket_path: &Path,
        iface: &NetworkInterface,
    ) -> VmRuntimeResult<()> {
        let mut body = serde_json::json!({
            "iface_id": iface.iface_id,
            "host_dev_name": iface.host_dev_name,
        });
        if let Some(mac) = &iface.guest_mac {
            body["guest_mac"] = serde_json::Value::String(mac.clone());
        }
        if let Some(rx) = &iface.rx_rate_limiter {
            body["rx_rate_limiter"] = rate_limiter_to_json(rx);
        }
        if let Some(tx) = &iface.tx_rate_limiter {
            body["tx_rate_limiter"] = rate_limiter_to_json(tx);
        }
        let path = format!("/network-interfaces/{}", iface.iface_id);
        self.firecracker_request(socket_path, "PUT", &path, Some(body))?;
        Ok(())
    }

    /// The jailer uid/gid snapshot artifacts must be chowned to so the
    /// privilege-dropped FC can open them. Errors when a jail is present but
    /// no jailer is composed — that combination cannot arise from this
    /// adapter and indicates caller-side state corruption.
    fn jailer_identity(&self) -> VmRuntimeResult<(u32, u32)> {
        let jailer = self
            .composer
            .as_ref()
            .and_then(|c| c.jailer.clone())
            .ok_or_else(|| {
                VmRuntimeError::Jailer(
                    "vm has a jail but no jailer is composed on the provider".into(),
                )
            })?;
        Ok((jailer.config().uid, jailer.config().gid))
    }

    /// Restore `target_vm_id` from `snapshot` via `PUT /snapshot/load`.
    ///
    /// Jail-aware: when the target VM runs under the jailer, the durable
    /// snapshot artifacts are hard-linked into its fresh chroot and the API
    /// body references them chroot-relative (a jailed FC resolves every path
    /// inside its chroot — host-absolute paths ENOENT there).
    ///
    /// Returns the [`UffdHandler`] servicing guest page faults when
    /// [`MemBackend::Uffd`] is configured (`None` for the `File` backend).
    /// The caller must hold it for the VM's lifetime.
    fn load_snapshot(
        &self,
        socket_path: &Path,
        snapshot: &SnapshotRef,
        target_vm_id: &str,
        jail: Option<&VmJail>,
    ) -> VmRuntimeResult<Option<UffdHandler>> {
        let snap_dir = self.vm_state_path(&snapshot.vm_id).join("snapshots");
        let paths = snapshot_artifact_paths(
            &snap_dir,
            &snapshot.snapshot_id,
            jail.map(|j| j.chroot_path.as_path()),
        )?;
        if !paths.durable_vmstate.exists() || !paths.durable_mem.exists() {
            return Err(VmRuntimeError::SnapshotNotFound {
                vm_id: snapshot.vm_id.clone(),
                snapshot_id: snapshot.snapshot_id.clone(),
            });
        }

        // Stage what the jailed FC opens itself: always the vmstate; the mem
        // file only for the File backend (with UFFD our handler mmaps the
        // durable mem file host-side and FC never opens it).
        if jail.is_some() {
            let (uid, gid) = self.jailer_identity()?;
            jailer::stage_chroot_file(&paths.durable_vmstate, &paths.staged_vmstate, uid, gid)?;
            if self.config.mem_backend == MemBackend::File {
                jailer::stage_chroot_file(&paths.durable_mem, &paths.staged_mem, uid, gid)?;
            }
        }

        let (mem_backend, uffd_handler) = match self.config.mem_backend {
            MemBackend::File => (
                serde_json::json!({
                    "backend_type": "File",
                    "backend_path": paths.fc_mem,
                }),
                None,
            ),
            MemBackend::Uffd => {
                // FC connects to the handler socket itself, so the socket must
                // resolve from inside the chroot when jailed. The handler runs
                // in this process (not chrooted) and mmaps the durable mem file.
                let (host_socket, fc_socket) = match jail {
                    Some(jail) => (
                        jail.chroot_path.join(UFFD_SOCKET_BASENAME),
                        PathBuf::from("/").join(UFFD_SOCKET_BASENAME),
                    ),
                    None => {
                        let path = self.vm_state_path(target_vm_id).join(UFFD_SOCKET_BASENAME);
                        (path.clone(), path)
                    }
                };
                let handler = UffdHandler::start(UffdConfig {
                    socket_path: host_socket.clone(),
                    mem_file_path: paths.durable_mem.clone(),
                })?;
                if jail.is_some() {
                    // connect(2) needs write permission on the socket file and
                    // the jailed FC runs privilege-dropped. Best-effort like
                    // the artifact chown: FC's connect fails the restore loudly
                    // if permissions actually block.
                    let (uid, gid) = self.jailer_identity()?;
                    if let Err(err) = nix::unistd::chown(
                        &host_socket,
                        Some(nix::unistd::Uid::from_raw(uid)),
                        Some(nix::unistd::Gid::from_raw(gid)),
                    ) {
                        eprintln!(
                            "[microvm-uffd] chown {} to {uid}:{gid} failed ({err}); \
                             the jailed firecracker may be unable to connect",
                            host_socket.display()
                        );
                    }
                }
                (snapshot_load_mem_backend_uffd(&fc_socket), Some(handler))
            }
        };

        let body = build_snapshot_load_body(snapshot, &paths.fc_vmstate, mem_backend);
        match self.firecracker_request(socket_path, "PUT", "/snapshot/load", Some(body)) {
            // Dropping the handler shuts it down; staged hard-links die with
            // the chroot on compose_release.
            Err(err) => Err(err),
            Ok(_) => Ok(uffd_handler),
        }
    }

    fn firecracker_request(
        &self,
        socket_path: &Path,
        method: &str,
        endpoint: &str,
        body: Option<serde_json::Value>,
    ) -> VmRuntimeResult<Option<serde_json::Value>> {
        let mut stream = UnixStream::connect(socket_path).map_err(|e| {
            VmRuntimeError::Unsupported(format!(
                "failed connecting to firecracker socket {}: {e}",
                socket_path.display()
            ))
        })?;

        stream
            .set_read_timeout(Some(self.config.api_timeout))
            .map_err(|e| {
                VmRuntimeError::Unsupported(format!(
                    "failed setting read timeout on {}: {e}",
                    socket_path.display()
                ))
            })?;
        stream
            .set_write_timeout(Some(self.config.api_timeout))
            .map_err(|e| {
                VmRuntimeError::Unsupported(format!(
                    "failed setting write timeout on {}: {e}",
                    socket_path.display()
                ))
            })?;

        let body_str = body.map(|v| v.to_string()).unwrap_or_default();
        let has_body = !body_str.is_empty();
        let request = if has_body {
            format!(
                "{method} {endpoint} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                body_str.len(),
                body_str
            )
        } else {
            format!(
                "{method} {endpoint} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
            )
        };

        stream.write_all(request.as_bytes()).map_err(|e| {
            VmRuntimeError::Unsupported(format!(
                "failed writing firecracker request {method} {endpoint}: {e}"
            ))
        })?;
        stream.flush().map_err(|e| {
            VmRuntimeError::Unsupported(format!(
                "failed flushing firecracker request {method} {endpoint}: {e}"
            ))
        })?;

        // Firecracker's API server keeps the connection alive even when the
        // request says `Connection: close` (measured on v1.6 and v1.12: the
        // response carries `Connection: keep-alive` and the server never
        // half-closes). `read_to_end` therefore never sees EOF and blocks
        // until the read timeout, failing every call — read the response by
        // its framing (headers, then exactly `Content-Length` body bytes)
        // instead of waiting for a close that never comes.
        let response = read_http_response(&mut stream).map_err(|e| {
            VmRuntimeError::Unsupported(format!(
                "failed reading firecracker response {method} {endpoint}: {e}"
            ))
        })?;

        let response_text = String::from_utf8_lossy(&response);
        let (headers, body) = response_text.split_once("\r\n\r\n").unwrap_or_default();
        let status_line = headers.lines().next().unwrap_or_default();
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or(0);

        if !(200..300).contains(&status_code) {
            return Err(VmRuntimeError::Unsupported(format!(
                "firecracker api error {method} {endpoint}: status={status_code}, body={body}"
            )));
        }

        if body.trim().is_empty() {
            return Ok(None);
        }

        let json = serde_json::from_str::<serde_json::Value>(body).map_err(|e| {
            VmRuntimeError::Unsupported(format!(
                "failed parsing firecracker response JSON for {method} {endpoint}: {e}"
            ))
        })?;
        Ok(Some(json))
    }

    fn action_instance_start(&self, socket_path: &Path) -> VmRuntimeResult<()> {
        self.firecracker_request(
            socket_path,
            "PUT",
            "/actions",
            Some(serde_json::json!({ "action_type": "InstanceStart" })),
        )?;
        Ok(())
    }

    fn action_pause(&self, socket_path: &Path) -> VmRuntimeResult<()> {
        self.firecracker_request(
            socket_path,
            "PATCH",
            "/vm",
            Some(serde_json::json!({ "state": "Paused" })),
        )?;
        Ok(())
    }

    fn action_resume(&self, socket_path: &Path) -> VmRuntimeResult<()> {
        self.firecracker_request(
            socket_path,
            "PATCH",
            "/vm",
            Some(serde_json::json!({ "state": "Resumed" })),
        )?;
        Ok(())
    }

    /// Capture a full snapshot via `PUT /snapshot/create`.
    ///
    /// Jail-aware: a jailed FC can only write inside its chroot, so it is
    /// told to write `/<id>.vmstate` + `/<id>.mem` there; the files are then
    /// moved to the durable snapshot dir, which survives the chroot teardown
    /// and feeds every future restore. Non-jailed FC writes the durable
    /// paths directly.
    fn create_snapshot(
        &self,
        socket_path: &Path,
        state_dir: &Path,
        snapshot_id: &str,
        jail: Option<&VmJail>,
    ) -> VmRuntimeResult<()> {
        let snap_dir = state_dir.join("snapshots");
        fs::create_dir_all(&snap_dir).map_err(|e| {
            VmRuntimeError::Unsupported(format!(
                "failed creating snapshot dir {}: {e}",
                snap_dir.display()
            ))
        })?;
        let paths = snapshot_artifact_paths(
            &snap_dir,
            snapshot_id,
            jail.map(|j| j.chroot_path.as_path()),
        )?;

        let result = self
            .firecracker_request(
                socket_path,
                "PUT",
                "/snapshot/create",
                Some(serde_json::json!({
                    "snapshot_type": "Full",
                    "snapshot_path": paths.fc_vmstate,
                    "mem_file_path": paths.fc_mem
                })),
            )
            .and_then(|_| {
                if paths.is_staged() {
                    move_into_place(&paths.staged_vmstate, &paths.durable_vmstate)?;
                    move_into_place(&paths.staged_mem, &paths.durable_mem)?;
                }
                Ok(())
            });

        if result.is_err() {
            // Clean up partials at both the durable home and the in-chroot
            // staging location (the jailed path can fail before the move).
            let _ = fs::remove_file(&paths.durable_vmstate);
            let _ = fs::remove_file(&paths.durable_mem);
            if paths.is_staged() {
                let _ = fs::remove_file(&paths.staged_vmstate);
                let _ = fs::remove_file(&paths.staged_mem);
            }
        }
        result
    }

    fn create_vm_inner(&self, vm_id: &str, spec: &VmSpec) -> VmRuntimeResult<()> {
        self.ensure_prereqs(spec)?;

        {
            let state = self
                .state
                .read()
                .map_err(|_| VmRuntimeError::StatePoisoned)?;
            if state.contains_key(vm_id) {
                return Err(VmRuntimeError::VmAlreadyExists(vm_id.to_owned()));
            }
        }

        // Run composer-side pre-spawn primitives (network/vsock/firewall/jailer)
        // and augment the spec accordingly. Composer is opt-in; bare semantics
        // unchanged when it's None.
        let (effective_spec, attachments) = self.compose_pre_spawn(vm_id, spec.clone())?;

        // When jailer is composed, the API socket lives inside the chroot;
        // the host-side connect path is `<chroot>/<api.sock-basename>`. Otherwise
        // it's the workspace-default `socket_dir/<vm_id>/api.sock`.
        let socket_path = attachments
            .jail
            .as_ref()
            .map(|j| j.api_socket_on_host.clone())
            .unwrap_or_else(|| self.api_socket_path(vm_id));
        let state_dir = self.vm_state_path(vm_id);
        fs::create_dir_all(&state_dir).map_err(|e| {
            self.compose_release(vm_id, &attachments);
            VmRuntimeError::Unsupported(format!(
                "failed creating vm state dir {}: {e}",
                state_dir.display()
            ))
        })?;

        let capture_stderr = self
            .composer
            .as_ref()
            .map(|c| c.capture_console)
            .unwrap_or(false);

        let mut child = match self.spawn_firecracker_for_compose(
            vm_id,
            &socket_path,
            capture_stderr,
            attachments.jail.as_ref(),
        ) {
            Ok(c) => c,
            Err(e) => {
                self.compose_release(vm_id, &attachments);
                return Err(e);
            }
        };
        let restoring = effective_spec.restore_from.is_some();
        let mut uffd_handler: Option<UffdHandler> = None;
        let configure_result = (|| -> VmRuntimeResult<()> {
            self.wait_for_socket_ready(&socket_path)?;
            if let Some(snapshot) = effective_spec.restore_from.as_ref() {
                uffd_handler =
                    self.load_snapshot(&socket_path, snapshot, vm_id, attachments.jail.as_ref())?;
            } else {
                self.configure_vm(&socket_path, &effective_spec, attachments.jail.as_ref())?;
            }
            Ok(())
        })();

        if let Err(err) = configure_result {
            let _ = child.kill();
            let _ = child.wait();
            self.compose_release(vm_id, &attachments);
            return Err(err);
        }

        // If console capture is enabled, attach the drainer to the child's stderr now
        // (stderr was piped during spawn). Captured early so kernel panics during
        // first boot are visible.
        if capture_stderr && let Some(stderr) = child.stderr.take() {
            let capture = ConsoleCapture::attach(stderr, ConsoleConfig::default());
            if let Ok(mut consoles) = self.consoles.lock() {
                consoles.insert(vm_id.to_owned(), capture);
            }
        }

        self.processes
            .lock()
            .map_err(|_| VmRuntimeError::StatePoisoned)?
            .insert(vm_id.to_owned(), child);

        // The UFFD handler must outlive every page fault the restored guest
        // will raise; parked here until destroy_vm (or rename re-keys it).
        if let Some(handler) = uffd_handler {
            self.uffd_handlers
                .lock()
                .map_err(|_| VmRuntimeError::StatePoisoned)?
                .insert(vm_id.to_owned(), handler);
        }

        if attachments.network_attached
            || attachments.vsock_attached
            || attachments.firewall_installed
            || attachments.jail.is_some()
        {
            self.composed
                .lock()
                .map_err(|_| VmRuntimeError::StatePoisoned)?
                .insert(vm_id.to_owned(), attachments);
        }

        // Restored VMs honour the snapshot's `resume_vm` flag — if `resume_immediately`
        // was set, the FC API call already transitioned the VM to Running; otherwise
        // it stays Paused/Stopped until an explicit start_vm.
        let initial_status = match (restoring, spec.restore_from.as_ref()) {
            (true, Some(snap)) if snap.resume_immediately => VmStatus::Running,
            (true, _) => VmStatus::Stopped,
            (false, _) => VmStatus::Created,
        };

        self.state
            .write()
            .map_err(|_| VmRuntimeError::StatePoisoned)?
            .insert(
                vm_id.to_owned(),
                VmRecord {
                    status: initial_status,
                    snapshots: Vec::new(),
                    socket_path,
                    state_dir,
                },
            );

        Ok(())
    }

    fn kill_process(&self, vm_id: &str) -> VmRuntimeResult<()> {
        let child = self
            .processes
            .lock()
            .map_err(|_| VmRuntimeError::StatePoisoned)?
            .remove(vm_id);

        let use_graceful = self
            .composer
            .as_ref()
            .map(|c| c.graceful_shutdown)
            .unwrap_or(false);

        if let Some(mut child) = child {
            if use_graceful && let Some(composer) = self.composer.as_ref() {
                let _ = graceful_shutdown(&mut child, &composer.shutdown_config);
            } else {
                let _ = child.kill();
                let _ = child.wait();
            }
        }

        // Always drop the console capture, regardless of shutdown mode — the FC
        // child is going away either way and the drainer thread should exit on EOF.
        if let Ok(mut consoles) = self.consoles.lock() {
            consoles.remove(vm_id);
        }

        // Drop the UFFD handler (drop = orderly shutdown): the FC process is
        // gone, so no further page faults can arrive.
        if let Ok(mut handlers) = self.uffd_handlers.lock() {
            handlers.remove(vm_id);
        }

        // Release composer-managed attachments (firewall chain, TAP, vsock CID, jail).
        let attachments = self
            .composed
            .lock()
            .map_err(|_| VmRuntimeError::StatePoisoned)?
            .remove(vm_id);
        if let Some(a) = attachments {
            self.compose_release(vm_id, &a);
        }

        Ok(())
    }

    /// Tail captured stderr for a VM. Returns `None` if console capture is disabled or
    /// the VM has no recorded capture. Useful for post-mortem when a VM exits unexpectedly.
    pub fn console_tail(&self, vm_id: &str) -> Option<Vec<String>> {
        self.consoles
            .lock()
            .ok()
            .and_then(|c| c.get(vm_id).map(|cap| cap.tail()))
    }
}

impl VmProvider for FirecrackerVmProvider {
    fn create_vm(&self, vm_id: &str) -> VmRuntimeResult<()> {
        self.create_vm_inner(vm_id, &VmSpec::default())
    }

    fn create_vm_with_spec(&self, vm_id: &str, spec: &VmSpec) -> VmRuntimeResult<()> {
        self.create_vm_inner(vm_id, spec)
    }

    fn start_vm(&self, vm_id: &str) -> VmRuntimeResult<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| VmRuntimeError::StatePoisoned)?;
        let record = state
            .get_mut(vm_id)
            .ok_or_else(|| VmRuntimeError::VmNotFound(vm_id.to_owned()))?;

        match record.status {
            VmStatus::Created => {
                self.action_instance_start(&record.socket_path)?;
                record.status = VmStatus::Running;
                Ok(())
            }
            VmStatus::Stopped => {
                self.action_resume(&record.socket_path)?;
                record.status = VmStatus::Running;
                Ok(())
            }
            other => Err(VmRuntimeError::InvalidTransition {
                vm_id: vm_id.to_owned(),
                from: other.to_string(),
                to: "running",
            }),
        }
    }

    fn stop_vm(&self, vm_id: &str) -> VmRuntimeResult<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| VmRuntimeError::StatePoisoned)?;
        let record = state
            .get_mut(vm_id)
            .ok_or_else(|| VmRuntimeError::VmNotFound(vm_id.to_owned()))?;

        match record.status {
            VmStatus::Running => {
                self.action_pause(&record.socket_path)?;
                record.status = VmStatus::Stopped;
                Ok(())
            }
            other => Err(VmRuntimeError::InvalidTransition {
                vm_id: vm_id.to_owned(),
                from: other.to_string(),
                to: "stopped",
            }),
        }
    }

    fn snapshot_vm(&self, vm_id: &str, snapshot_id: &str) -> VmRuntimeResult<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| VmRuntimeError::StatePoisoned)?;
        let record = state
            .get_mut(vm_id)
            .ok_or_else(|| VmRuntimeError::VmNotFound(vm_id.to_owned()))?;

        if record.status == VmStatus::Destroyed {
            return Err(VmRuntimeError::InvalidTransition {
                vm_id: vm_id.to_owned(),
                from: VmStatus::Destroyed.to_string(),
                to: "snapshot",
            });
        }

        if record
            .snapshots
            .iter()
            .any(|existing| existing == snapshot_id)
        {
            return Err(VmRuntimeError::SnapshotAlreadyExists {
                vm_id: vm_id.to_owned(),
                snapshot_id: snapshot_id.to_owned(),
            });
        }

        // Jailed VMs must be told to write inside their chroot; fetch the jail
        // recorded at create time. Lock order (state → composed) matches
        // destroy_vm's state → processes → composed.
        let jail = self
            .composed
            .lock()
            .map_err(|_| VmRuntimeError::StatePoisoned)?
            .get(vm_id)
            .and_then(|a| a.jail.clone());

        self.create_snapshot(
            &record.socket_path,
            &record.state_dir,
            snapshot_id,
            jail.as_ref(),
        )?;
        record.snapshots.push(snapshot_id.to_owned());
        Ok(())
    }

    fn destroy_vm(&self, vm_id: &str) -> VmRuntimeResult<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| VmRuntimeError::StatePoisoned)?;
        let record = state
            .get_mut(vm_id)
            .ok_or_else(|| VmRuntimeError::VmNotFound(vm_id.to_owned()))?;

        if record.status == VmStatus::Destroyed {
            return Err(VmRuntimeError::InvalidTransition {
                vm_id: vm_id.to_owned(),
                from: VmStatus::Destroyed.to_string(),
                to: "destroyed",
            });
        }

        self.kill_process(vm_id)?;

        let _ = fs::remove_file(&record.socket_path);
        if let Some(parent) = record.socket_path.parent() {
            let _ = fs::remove_dir_all(parent);
        }
        let _ = fs::remove_dir_all(&record.state_dir);

        record.status = VmStatus::Destroyed;
        Ok(())
    }

    /// Re-key a live VM — the warm-pool handoff: a pooled, pre-restored VM
    /// swaps its identifier onto the claiming sandbox id without a
    /// snapshot/load round-trip.
    ///
    /// Moves every piece of per-VM state the adapter lays out by id:
    ///
    /// * the state dir (`state_dir/<id>`, including its `snapshots/`),
    /// * the API-socket holder — `socket_dir/<id>/` when bare, or the jailer
    ///   vm dir (`<chroot_base>/firecracker/<id>/`) when jailed (renaming a
    ///   directory does not disturb the running FC: its open fds, cwd, and
    ///   the bound unix socket follow the inode),
    /// * the in-memory maps (record, process, console capture, composed
    ///   jail, UFFD handler).
    ///
    /// Snapshots taken from the VM move with it: after the rename they are
    /// addressed as `SnapshotRef { vm_id: new_vm_id, .. }`.
    ///
    /// Refused for VMs with composed network/vsock/firewall attachments —
    /// those managers key host resources (TAP, CID, iptables chain) by vm id
    /// and have no rename surface. Warm-pool restores never compose them
    /// (restores swap network via `SnapshotRef::network_overrides`).
    ///
    /// Known residue: a jailed FC process stays in the cgroup named after the
    /// old id; cgroup cleanup was already best-effort on teardown, and the
    /// empty leaf is removable once the process exits.
    fn rename_vm(&self, old_vm_id: &str, new_vm_id: &str) -> VmRuntimeResult<()> {
        if old_vm_id == new_vm_id {
            return Ok(());
        }

        let mut state = self
            .state
            .write()
            .map_err(|_| VmRuntimeError::StatePoisoned)?;
        if state.contains_key(new_vm_id) {
            return Err(VmRuntimeError::VmAlreadyExists(new_vm_id.to_owned()));
        }
        let record = state
            .get(old_vm_id)
            .ok_or_else(|| VmRuntimeError::VmNotFound(old_vm_id.to_owned()))?;
        if record.status == VmStatus::Destroyed {
            return Err(VmRuntimeError::InvalidTransition {
                vm_id: old_vm_id.to_owned(),
                from: VmStatus::Destroyed.to_string(),
                to: "renamed",
            });
        }

        let mut composed = self
            .composed
            .lock()
            .map_err(|_| VmRuntimeError::StatePoisoned)?;
        let jail = match composed.get(old_vm_id) {
            Some(a) if a.network_attached || a.vsock_attached || a.firewall_installed => {
                return Err(VmRuntimeError::Unsupported(format!(
                    "rename_vm('{old_vm_id}' -> '{new_vm_id}'): composed network/vsock/\
                     firewall attachments are keyed by vm id in their host managers and \
                     cannot be re-keyed; warm-pool restores never compose these"
                )));
            }
            Some(a) => a.jail.clone(),
            None => None,
        };

        // Plan the socket-holder move before touching the filesystem so a
        // failure leaves everything in place.
        let old_state_dir = record.state_dir.clone();
        let new_state_dir = self.vm_state_path(new_vm_id);
        let socket_name = record.socket_path.file_name().ok_or_else(|| {
            VmRuntimeError::Unsupported(format!(
                "invalid api socket path for vm {old_vm_id}: {}",
                record.socket_path.display()
            ))
        })?;
        let (old_holder, new_holder, new_socket_path, new_jail) = match jail.as_ref() {
            Some(jail) => {
                // The jailer lays out `<base>/firecracker/<id>/root/`; the vm
                // dir (chroot parent) is the unit that carries the id.
                let old_vm_dir = jail.chroot_path.parent().ok_or_else(|| {
                    VmRuntimeError::Jailer(format!(
                        "jail chroot {} has no parent vm dir",
                        jail.chroot_path.display()
                    ))
                })?;
                let new_vm_dir = old_vm_dir
                    .parent()
                    .ok_or_else(|| {
                        VmRuntimeError::Jailer(format!(
                            "jail vm dir {} has no firecracker base dir",
                            old_vm_dir.display()
                        ))
                    })?
                    .join(jailer::safe_vm_id(new_vm_id));
                let new_chroot = new_vm_dir.join("root");
                let new_socket = new_chroot.join(socket_name);
                let renamed_jail = VmJail {
                    chroot_path: new_chroot,
                    api_socket_in_chroot: jail.api_socket_in_chroot.clone(),
                    api_socket_on_host: new_socket.clone(),
                };
                (
                    old_vm_dir.to_path_buf(),
                    new_vm_dir,
                    new_socket,
                    Some(renamed_jail),
                )
            }
            None => {
                let old_socket_dir = self.config.socket_dir.join(self.safe_vm_id(old_vm_id));
                let new_socket_dir = self.config.socket_dir.join(self.safe_vm_id(new_vm_id));
                let new_socket = new_socket_dir.join(socket_name);
                (old_socket_dir, new_socket_dir, new_socket, None)
            }
        };

        fs::rename(&old_state_dir, &new_state_dir).map_err(|e| {
            VmRuntimeError::Unsupported(format!(
                "rename_vm: failed moving state dir {} -> {}: {e}",
                old_state_dir.display(),
                new_state_dir.display()
            ))
        })?;
        if let Err(e) = fs::rename(&old_holder, &new_holder) {
            // Restore the state dir so the VM stays addressable by the old id.
            let rollback = fs::rename(&new_state_dir, &old_state_dir);
            return Err(VmRuntimeError::Unsupported(format!(
                "rename_vm: failed moving {} -> {}: {e} (state dir rollback: {})",
                old_holder.display(),
                new_holder.display(),
                match rollback {
                    Ok(()) => "ok".to_owned(),
                    Err(re) => format!("FAILED: {re}"),
                }
            )));
        }

        // Filesystem is consistent under the new id — re-key the maps. These
        // are infallible aside from lock poisoning, which is fatal anyway.
        let mut record = state
            .remove(old_vm_id)
            .expect("checked above while holding the state write lock");
        record.state_dir = new_state_dir;
        record.socket_path = new_socket_path;
        state.insert(new_vm_id.to_owned(), record);

        if let Some(mut attachments) = composed.remove(old_vm_id) {
            attachments.jail = new_jail;
            composed.insert(new_vm_id.to_owned(), attachments);
        }
        {
            let mut processes = self
                .processes
                .lock()
                .map_err(|_| VmRuntimeError::StatePoisoned)?;
            if let Some(child) = processes.remove(old_vm_id) {
                processes.insert(new_vm_id.to_owned(), child);
            }
        }
        if let Ok(mut consoles) = self.consoles.lock()
            && let Some(capture) = consoles.remove(old_vm_id)
        {
            consoles.insert(new_vm_id.to_owned(), capture);
        }
        if let Ok(mut handlers) = self.uffd_handlers.lock()
            && let Some(handler) = handlers.remove(old_vm_id)
        {
            handlers.insert(new_vm_id.to_owned(), handler);
        }

        Ok(())
    }
}

impl VmQuery for FirecrackerVmProvider {
    fn list_vms(&self) -> VmRuntimeResult<Vec<VmView>> {
        let state = self
            .state
            .read()
            .map_err(|_| VmRuntimeError::StatePoisoned)?;
        let mut views = state
            .iter()
            .map(|(vm_id, record)| record.view(vm_id))
            .collect::<Vec<_>>();
        views.sort_by(|a, b| a.vm_id.cmp(&b.vm_id));
        Ok(views)
    }

    fn get_vm(&self, vm_id: &str) -> VmRuntimeResult<Option<VmView>> {
        let state = self
            .state
            .read()
            .map_err(|_| VmRuntimeError::StatePoisoned)?;
        Ok(state.get(vm_id).map(|record| record.view(vm_id)))
    }

    fn list_snapshots(&self, vm_id: &str) -> VmRuntimeResult<Option<Vec<String>>> {
        let state = self
            .state
            .read()
            .map_err(|_| VmRuntimeError::StatePoisoned)?;
        Ok(state.get(vm_id).map(|record| record.snapshots.clone()))
    }
}

fn rate_limiter_to_json(limiter: &RateLimiter) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    if let Some(bw) = &limiter.bandwidth {
        obj.insert("bandwidth".into(), token_bucket_to_json(bw));
    }
    if let Some(ops) = &limiter.ops {
        obj.insert("ops".into(), token_bucket_to_json(ops));
    }
    serde_json::Value::Object(obj)
}

fn token_bucket_to_json(bucket: &TokenBucket) -> serde_json::Value {
    serde_json::json!({
        "size": bucket.size,
        "one_time_burst": bucket.one_time_burst.unwrap_or(bucket.size),
        "refill_time": bucket.refill_time_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::composer::FirecrackerComposer;
    use crate::jailer::{Jailer, JailerConfig};
    use crate::model::{RateLimiter, TokenBucket};

    /// Named bug: Firecracker's API server keeps the connection alive even
    /// for `Connection: close` requests, so an EOF-terminated read
    /// (`read_to_end`) blocks until the socket read timeout on every call —
    /// `create_vm` then fails with "api socket not ready" against a
    /// perfectly healthy VMM. The response must be read by its framing.
    #[test]
    fn read_http_response_returns_without_server_close() {
        let (mut client, mut server) = UnixStream::pair().expect("socketpair");
        let response =
            b"HTTP/1.1 200 \r\nServer: Firecracker API\r\nConnection: keep-alive\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"state\":\"a\"}";
        server.write_all(response).expect("write response");
        server.flush().expect("flush");
        // Deliberately NOT closing/dropping `server`: the read must complete
        // on framing alone. The timeout only bounds a regression — with the
        // read_to_end implementation this test hangs here and fails.
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let got = read_http_response(&mut client).expect("framed read completes without EOF");
        assert_eq!(got, response.to_vec());
        drop(server);
    }

    /// Body split across reads with no Content-Length on empty-body
    /// responses (Firecracker's 204-style action replies).
    #[test]
    fn read_http_response_handles_missing_content_length() {
        let (mut client, mut server) = UnixStream::pair().expect("socketpair");
        server
            .write_all(
                b"HTTP/1.1 204 \r\nServer: Firecracker API\r\nConnection: keep-alive\r\n\r\n",
            )
            .expect("write response");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let got = read_http_response(&mut client).expect("headers-only response");
        assert!(got.ends_with(b"\r\n\r\n"));
        drop(server);
    }

    fn test_config(root: &Path) -> FirecrackerConfig {
        FirecrackerConfig {
            binary_path: PathBuf::from("/usr/local/bin/firecracker"),
            kernel_path: root.join("vmlinux"),
            rootfs_path: root.join("rootfs.ext4"),
            boot_args: DEFAULT_BOOT_ARGS.to_string(),
            socket_dir: root.join("sockets"),
            state_dir: root.join("state"),
            vcpu_count: 1,
            mem_size_mib: 128,
            rootfs_read_only: true,
            api_timeout: Duration::from_millis(200),
            socket_ready_timeout: Duration::from_millis(200),
            mem_backend: MemBackend::File,
        }
    }

    /// Provider with one live VM inserted directly (no FC process): state
    /// dir with a `warm` snapshot, socket dir with a stand-in socket file.
    fn seeded_provider(root: &Path, vm_id: &str, status: VmStatus) -> FirecrackerVmProvider {
        let provider = FirecrackerVmProvider::new(test_config(root));
        let state_dir = provider.vm_state_path(vm_id);
        let snap_dir = state_dir.join("snapshots");
        fs::create_dir_all(&snap_dir).unwrap();
        fs::write(snap_dir.join("warm.vmstate"), b"vmstate").unwrap();
        fs::write(snap_dir.join("warm.mem"), b"guest memory").unwrap();
        let socket_dir = provider.config.socket_dir.join(provider.safe_vm_id(vm_id));
        fs::create_dir_all(&socket_dir).unwrap();
        let socket_path = socket_dir.join("api.sock");
        fs::write(&socket_path, b"").unwrap();
        provider.state.write().unwrap().insert(
            vm_id.to_owned(),
            VmRecord {
                status,
                snapshots: vec!["warm".to_owned()],
                socket_path,
                state_dir,
            },
        );
        provider
    }

    fn same_inode(a: &Path, b: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        let (ma, mb) = (fs::metadata(a).unwrap(), fs::metadata(b).unwrap());
        ma.dev() == mb.dev() && ma.ino() == mb.ino()
    }

    // ---- MemBackend option surface ----

    #[test]
    fn mem_backend_parses_file_and_uffd_case_insensitive() {
        assert_eq!("file".parse::<MemBackend>().unwrap(), MemBackend::File);
        assert_eq!("File".parse::<MemBackend>().unwrap(), MemBackend::File);
        assert_eq!("uffd".parse::<MemBackend>().unwrap(), MemBackend::Uffd);
        assert_eq!(" UFFD ".parse::<MemBackend>().unwrap(), MemBackend::Uffd);
        assert!("mmap".parse::<MemBackend>().is_err());
    }

    #[test]
    fn mem_backend_env_absent_resolves_from_uffd_probe() {
        // Probe says the host allows unprivileged userfaultfd → lazy restore.
        assert_eq!(mem_backend_from_env_value(None, true), MemBackend::Uffd);
        // Probe says no → fail-safe to File (with a warning on stderr).
        assert_eq!(mem_backend_from_env_value(None, false), MemBackend::File);
    }

    #[test]
    fn mem_backend_env_explicit_value_beats_probe() {
        // Operator forces uffd on a host the probe rejected (e.g. FC runs
        // with CAP_SYS_PTRACE and the sysctl is off).
        assert_eq!(
            mem_backend_from_env_value(Some("uffd"), false),
            MemBackend::Uffd
        );
        // Operator forces file even though the host could do uffd.
        assert_eq!(
            mem_backend_from_env_value(Some("file"), true),
            MemBackend::File
        );
    }

    #[test]
    fn mem_backend_default_stays_file_for_programmatic_configs() {
        // `Default` must not probe — a hand-built config keeps the
        // always-works backend unless the caller opts in.
        assert_eq!(MemBackend::default(), MemBackend::File);
    }

    #[test]
    #[should_panic(expected = "MICROVM_MEM_BACKEND")]
    fn mem_backend_env_invalid_value_fails_loud() {
        mem_backend_from_env_value(Some("filee"), false);
    }

    // ---- Socket-ready poll backoff ----

    #[test]
    fn socket_poll_backoff_doubles_then_caps_at_old_flat_interval() {
        let mut interval = SOCKET_POLL_INITIAL_INTERVAL;
        let mut schedule = vec![interval];
        for _ in 0..8 {
            interval = next_socket_poll_interval(interval);
            schedule.push(interval);
        }
        let ms: Vec<u64> = schedule.iter().map(|d| d.as_millis() as u64).collect();
        // 2,4,8,16,32,64 then pinned at the 100 ms cap (the old flat poll).
        assert_eq!(ms, vec![2, 4, 8, 16, 32, 64, 100, 100, 100]);
        // The cap is sticky: once reached the interval never moves again.
        assert_eq!(
            next_socket_poll_interval(SOCKET_POLL_MAX_INTERVAL),
            SOCKET_POLL_MAX_INTERVAL
        );
    }

    // ---- Snapshot artifact path model ----

    #[test]
    fn snapshot_paths_non_jailed_coincide_with_durable() {
        let snap_dir = Path::new("/var/state/vm-1/snapshots");
        let p = snapshot_artifact_paths(snap_dir, "warm", None).unwrap();
        assert_eq!(p.durable_vmstate, snap_dir.join("warm.vmstate"));
        assert_eq!(p.durable_mem, snap_dir.join("warm.mem"));
        assert_eq!(p.fc_vmstate, p.durable_vmstate);
        assert_eq!(p.fc_mem, p.durable_mem);
        assert_eq!(p.staged_vmstate, p.durable_vmstate);
        assert!(!p.is_staged());
    }

    #[test]
    fn snapshot_paths_jailed_reference_chroot_relative() {
        let snap_dir = Path::new("/var/state/vm-1/snapshots");
        let chroot = Path::new("/srv/jailer/firecracker/vm-1/root");
        let p = snapshot_artifact_paths(snap_dir, "warm", Some(chroot)).unwrap();
        // The FC API body must get in-chroot absolute paths…
        assert_eq!(p.fc_vmstate, PathBuf::from("/warm.vmstate"));
        assert_eq!(p.fc_mem, PathBuf::from("/warm.mem"));
        // …which live at <chroot>/<name> from the host's view…
        assert_eq!(p.staged_vmstate, chroot.join("warm.vmstate"));
        assert_eq!(p.staged_mem, chroot.join("warm.mem"));
        // …while the durable home stays in the state dir.
        assert_eq!(p.durable_vmstate, snap_dir.join("warm.vmstate"));
        assert!(p.is_staged());
    }

    #[test]
    fn snapshot_paths_reject_unsafe_ids() {
        let snap_dir = Path::new("/var/state/vm-1/snapshots");
        for bad in ["../warm", "a/b", "", "a..b", "wa rm", "warm\0"] {
            let err = snapshot_artifact_paths(snap_dir, bad, None).unwrap_err();
            assert!(
                matches!(err, VmRuntimeError::Unsupported(_)),
                "id {bad:?} must be rejected"
            );
        }
        assert!(snapshot_artifact_paths(snap_dir, "ok-1.v2_x", None).is_ok());
    }

    #[test]
    fn move_into_place_renames_within_same_fs() {
        let tmp = tempfile::tempdir().unwrap();
        let from = tmp.path().join("staged.mem");
        let to = tmp.path().join("durable.mem");
        fs::write(&from, b"pages").unwrap();
        move_into_place(&from, &to).unwrap();
        assert!(!from.exists());
        assert_eq!(fs::read(&to).unwrap(), b"pages");
    }

    // ---- /machine-config body ----

    #[test]
    fn machine_config_defaults_track_dirty_pages_off() {
        // No consumer exists for the dirty bitmap (Full snapshots only), so
        // the unset spec must not pay for it.
        let body = machine_config_body(2, 512, None);
        assert_eq!(body["vcpu_count"], 2);
        assert_eq!(body["mem_size_mib"], 512);
        assert_eq!(body["smt"], false);
        assert_eq!(body["track_dirty_pages"], false);
    }

    #[test]
    fn machine_config_track_dirty_pages_stays_settable() {
        assert_eq!(
            machine_config_body(1, 128, Some(true))["track_dirty_pages"],
            true
        );
        assert_eq!(
            machine_config_body(1, 128, Some(false))["track_dirty_pages"],
            false
        );
    }

    // ---- /snapshot/load body ----

    fn snapshot_ref(resume: bool, overrides: Vec<NetworkInterface>) -> SnapshotRef {
        SnapshotRef {
            vm_id: "vm-src".into(),
            snapshot_id: "warm".into(),
            resume_immediately: resume,
            network_overrides: overrides,
        }
    }

    #[test]
    fn load_body_file_backend_shape() {
        let body = build_snapshot_load_body(
            &snapshot_ref(true, vec![]),
            Path::new("/warm.vmstate"),
            serde_json::json!({ "backend_type": "File", "backend_path": "/warm.mem" }),
        );
        assert_eq!(body["snapshot_path"], "/warm.vmstate");
        assert_eq!(body["mem_backend"]["backend_type"], "File");
        assert_eq!(body["mem_backend"]["backend_path"], "/warm.mem");
        assert_eq!(body["resume_vm"], true);
        assert_eq!(body["enable_diff_snapshots"], false);
        assert!(body.get("network_interfaces").is_none());
    }

    #[test]
    fn load_body_uffd_backend_shape() {
        let body = build_snapshot_load_body(
            &snapshot_ref(false, vec![]),
            Path::new("/warm.vmstate"),
            crate::uffd::snapshot_load_mem_backend_uffd(Path::new("/uffd.sock")),
        );
        assert_eq!(body["mem_backend"]["backend_type"], "Uffd");
        assert_eq!(body["mem_backend"]["backend_path"], "/uffd.sock");
        assert_eq!(body["resume_vm"], false);
    }

    #[test]
    fn load_body_includes_network_overrides() {
        let overrides = vec![NetworkInterface {
            iface_id: "eth0".into(),
            host_dev_name: "tap-new".into(),
            guest_mac: Some("AA:BB:CC:DD:EE:FF".into()),
            rx_rate_limiter: None,
            tx_rate_limiter: None,
        }];
        let body = build_snapshot_load_body(
            &snapshot_ref(true, overrides),
            Path::new("/warm.vmstate"),
            serde_json::json!({ "backend_type": "File", "backend_path": "/warm.mem" }),
        );
        let ifaces = body["network_interfaces"].as_array().unwrap();
        assert_eq!(ifaces.len(), 1);
        assert_eq!(ifaces[0]["host_dev_name"], "tap-new");
        assert_eq!(ifaces[0]["guest_mac"], "AA:BB:CC:DD:EE:FF");
    }

    // ---- Jail-aware restore staging (the 0.4.0-alpha.1 ENOENT bug) ----

    /// The named bug: `load_snapshot` handed a jailed FC host-absolute
    /// snapshot paths, which ENOENT inside the chroot. The fix stages the
    /// durable artifacts into the chroot before the API call. The FC request
    /// itself fails here (no live FC socket), but staging happens first — so
    /// reverting the fix turns the staged-file assertions red.
    #[test]
    fn jailed_restore_stages_snapshot_into_chroot() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = FirecrackerVmProvider::new(test_config(tmp.path())).with_composer(
            FirecrackerComposer {
                jailer: Some(Arc::new(Jailer::new(JailerConfig {
                    chroot_base: tmp.path().join("jail"),
                    ..JailerConfig::default()
                }))),
                ..FirecrackerComposer::bare()
            },
        );
        let snap_dir = provider.vm_state_path("vm-src").join("snapshots");
        fs::create_dir_all(&snap_dir).unwrap();
        fs::write(snap_dir.join("warm.vmstate"), b"vmstate").unwrap();
        fs::write(snap_dir.join("warm.mem"), b"guest memory").unwrap();

        let chroot = tmp.path().join("jail/firecracker/vm-new/root");
        fs::create_dir_all(&chroot).unwrap();
        let jail = VmJail {
            chroot_path: chroot.clone(),
            api_socket_in_chroot: PathBuf::from("/api.sock"),
            api_socket_on_host: chroot.join("api.sock"),
        };

        let err = provider
            .load_snapshot(
                &jail.api_socket_on_host,
                &snapshot_ref(true, vec![]),
                "vm-new",
                Some(&jail),
            )
            .expect_err("no live FC socket — the API call must fail");
        // Failure must be the socket connect, not a path problem.
        assert!(
            matches!(&err, VmRuntimeError::Unsupported(msg) if msg.contains("failed connecting")),
            "unexpected error: {err}"
        );

        // The artifacts were staged into the chroot as hard links before the
        // call, exactly where the chroot-relative body paths resolve to.
        assert!(same_inode(
            &snap_dir.join("warm.vmstate"),
            &chroot.join("warm.vmstate")
        ));
        assert!(same_inode(
            &snap_dir.join("warm.mem"),
            &chroot.join("warm.mem")
        ));
    }

    #[test]
    fn restore_missing_mem_file_is_snapshot_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = FirecrackerVmProvider::new(test_config(tmp.path()));
        let snap_dir = provider.vm_state_path("vm-src").join("snapshots");
        fs::create_dir_all(&snap_dir).unwrap();
        fs::write(snap_dir.join("warm.vmstate"), b"vmstate").unwrap();
        // No warm.mem — must fail as a typed missing-snapshot, not surface
        // later as an opaque FC-side ENOENT.
        let err = provider
            .load_snapshot(
                Path::new("/nonexistent.sock"),
                &snapshot_ref(true, vec![]),
                "vm-new",
                None,
            )
            .unwrap_err();
        assert!(matches!(err, VmRuntimeError::SnapshotNotFound { .. }));
    }

    /// Jailed snapshot create tells FC to write in-chroot; when the API call
    /// fails, any partial staged artifacts must be cleaned out of the chroot.
    #[test]
    fn jailed_snapshot_create_cleans_staged_partials_on_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = FirecrackerVmProvider::new(test_config(tmp.path()));
        let state_dir = provider.vm_state_path("vm-1");
        fs::create_dir_all(&state_dir).unwrap();
        let chroot = tmp.path().join("jail/firecracker/vm-1/root");
        fs::create_dir_all(&chroot).unwrap();
        // Partial artifacts as if FC wrote them before dying.
        fs::write(chroot.join("warm.vmstate"), b"partial").unwrap();
        fs::write(chroot.join("warm.mem"), b"partial").unwrap();
        let jail = VmJail {
            chroot_path: chroot.clone(),
            api_socket_in_chroot: PathBuf::from("/api.sock"),
            api_socket_on_host: chroot.join("api.sock"),
        };

        provider
            .create_snapshot(&jail.api_socket_on_host, &state_dir, "warm", Some(&jail))
            .expect_err("no live FC socket — must fail");

        assert!(!chroot.join("warm.vmstate").exists());
        assert!(!chroot.join("warm.mem").exists());
        assert!(!state_dir.join("snapshots/warm.vmstate").exists());
    }

    /// Non-jailed UFFD restore: the handler socket is created in the target
    /// VM's state dir for the API call and torn down (drop = shutdown) when
    /// the restore fails.
    #[test]
    fn uffd_restore_failure_tears_down_handler_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = test_config(tmp.path());
        config.mem_backend = MemBackend::Uffd;
        let provider = FirecrackerVmProvider::new(config);
        let snap_dir = provider.vm_state_path("vm-src").join("snapshots");
        fs::create_dir_all(&snap_dir).unwrap();
        fs::write(snap_dir.join("warm.vmstate"), b"vmstate").unwrap();
        fs::write(snap_dir.join("warm.mem"), b"guest memory").unwrap();
        fs::create_dir_all(provider.vm_state_path("vm-new")).unwrap();

        let err = provider
            .load_snapshot(
                Path::new("/nonexistent.sock"),
                &snapshot_ref(true, vec![]),
                "vm-new",
                None,
            )
            .expect_err("no live FC socket — the API call must fail");
        assert!(
            matches!(&err, VmRuntimeError::Unsupported(msg) if msg.contains("failed connecting")),
            "unexpected error: {err}"
        );
        // The handler was dropped on failure and removed its socket.
        assert!(
            !provider
                .vm_state_path("vm-new")
                .join(UFFD_SOCKET_BASENAME)
                .exists()
        );
    }

    // ---- rename_vm (warm-pool handoff) ----

    #[test]
    fn rename_moves_state_and_socket_dirs_and_rekeys_record() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = seeded_provider(tmp.path(), "pool-1", VmStatus::Running);

        provider.rename_vm("pool-1", "sandbox-9").expect("rename");

        // Old identity fully gone…
        assert!(provider.get_vm("pool-1").unwrap().is_none());
        assert!(!provider.vm_state_path("pool-1").exists());
        assert!(!tmp.path().join("sockets/pool-1").exists());
        // …new identity fully addressable, snapshots moved with the VM.
        let view = provider.get_vm("sandbox-9").unwrap().expect("renamed vm");
        assert_eq!(view.status, VmStatus::Running);
        assert_eq!(view.snapshots, vec!["warm".to_owned()]);
        let new_state_dir = provider.vm_state_path("sandbox-9");
        assert!(new_state_dir.join("snapshots/warm.vmstate").exists());
        let record = provider.state.read().unwrap();
        let record = record.get("sandbox-9").unwrap();
        assert_eq!(record.state_dir, new_state_dir);
        assert_eq!(
            record.socket_path,
            tmp.path().join("sockets/sandbox-9/api.sock")
        );
        assert!(record.socket_path.exists());
    }

    #[test]
    fn rename_rejects_unknown_missing_and_duplicate_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = seeded_provider(tmp.path(), "pool-1", VmStatus::Running);

        assert!(matches!(
            provider.rename_vm("ghost", "x").unwrap_err(),
            VmRuntimeError::VmNotFound(_)
        ));

        let state_dir = provider.vm_state_path("other");
        fs::create_dir_all(&state_dir).unwrap();
        provider.state.write().unwrap().insert(
            "other".into(),
            VmRecord {
                status: VmStatus::Running,
                snapshots: vec![],
                socket_path: tmp.path().join("sockets/other/api.sock"),
                state_dir,
            },
        );
        assert!(matches!(
            provider.rename_vm("pool-1", "other").unwrap_err(),
            VmRuntimeError::VmAlreadyExists(_)
        ));
    }

    #[test]
    fn rename_rejects_destroyed_vm() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = seeded_provider(tmp.path(), "pool-1", VmStatus::Destroyed);
        assert!(matches!(
            provider.rename_vm("pool-1", "sandbox-9").unwrap_err(),
            VmRuntimeError::InvalidTransition { to: "renamed", .. }
        ));
    }

    #[test]
    fn rename_to_same_id_is_a_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = seeded_provider(tmp.path(), "pool-1", VmStatus::Running);
        provider.rename_vm("pool-1", "pool-1").expect("noop");
        assert!(provider.get_vm("pool-1").unwrap().is_some());
    }

    #[test]
    fn rename_refuses_composed_network_attachments() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = seeded_provider(tmp.path(), "pool-1", VmStatus::Running);
        provider.composed.lock().unwrap().insert(
            "pool-1".into(),
            ComposedAttachments {
                network_attached: true,
                ..ComposedAttachments::default()
            },
        );
        let err = provider.rename_vm("pool-1", "sandbox-9").unwrap_err();
        assert!(matches!(err, VmRuntimeError::Unsupported(_)), "{err}");
        // Nothing moved.
        assert!(provider.get_vm("pool-1").unwrap().is_some());
        assert!(provider.vm_state_path("pool-1").exists());
    }

    #[test]
    fn rename_rekeys_jailed_chroot_and_jail_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = seeded_provider(tmp.path(), "pool-1", VmStatus::Running);
        let old_chroot = tmp.path().join("jail/firecracker/pool-1/root");
        fs::create_dir_all(&old_chroot).unwrap();
        let socket_path = old_chroot.join("api.sock");
        fs::write(&socket_path, b"").unwrap();
        provider
            .state
            .write()
            .unwrap()
            .get_mut("pool-1")
            .unwrap()
            .socket_path = socket_path;
        provider.composed.lock().unwrap().insert(
            "pool-1".into(),
            ComposedAttachments {
                jail: Some(VmJail {
                    chroot_path: old_chroot.clone(),
                    api_socket_in_chroot: PathBuf::from("/api.sock"),
                    api_socket_on_host: old_chroot.join("api.sock"),
                }),
                ..ComposedAttachments::default()
            },
        );

        provider.rename_vm("pool-1", "sandbox-9").expect("rename");

        let new_chroot = tmp.path().join("jail/firecracker/sandbox-9/root");
        assert!(!tmp.path().join("jail/firecracker/pool-1").exists());
        assert!(new_chroot.join("api.sock").exists());
        let composed = provider.composed.lock().unwrap();
        assert!(composed.get("pool-1").is_none());
        let jail = composed.get("sandbox-9").unwrap().jail.as_ref().unwrap();
        assert_eq!(jail.chroot_path, new_chroot);
        assert_eq!(jail.api_socket_on_host, new_chroot.join("api.sock"));
        assert_eq!(jail.api_socket_in_chroot, PathBuf::from("/api.sock"));
        let state = provider.state.read().unwrap();
        assert_eq!(
            state.get("sandbox-9").unwrap().socket_path,
            new_chroot.join("api.sock")
        );
    }

    #[test]
    fn rename_rolls_back_state_dir_when_socket_move_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = seeded_provider(tmp.path(), "pool-1", VmStatus::Running);
        // Sabotage the socket-holder move: the socket dir is gone.
        fs::remove_dir_all(tmp.path().join("sockets/pool-1")).unwrap();

        let err = provider.rename_vm("pool-1", "sandbox-9").unwrap_err();
        assert!(matches!(err, VmRuntimeError::Unsupported(_)), "{err}");
        // The state dir was rolled back — the VM is still addressable under
        // the old id and untouched under the new one.
        assert!(provider.vm_state_path("pool-1").exists());
        assert!(!provider.vm_state_path("sandbox-9").exists());
        assert!(provider.get_vm("pool-1").unwrap().is_some());
        assert!(provider.get_vm("sandbox-9").unwrap().is_none());
    }

    // ---- Jail-aware cold-boot config ----

    /// Composed vsock + jailer is refused up front: the UDS path cannot
    /// resolve both inside the chroot (for FC) and on the host (for clients).
    #[test]
    fn configure_vm_refuses_vsock_under_jailer() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = FirecrackerVmProvider::new(test_config(tmp.path()));
        let chroot = tmp.path().join("jail/firecracker/vm-1/root");
        let jail = VmJail {
            chroot_path: chroot.clone(),
            api_socket_in_chroot: PathBuf::from("/api.sock"),
            api_socket_on_host: chroot.join("api.sock"),
        };
        let spec = VmSpec {
            vsock: Some(VsockSpec {
                cid: 3,
                uds_path: tmp.path().join("vsock.sock"),
            }),
            ..VmSpec::default()
        };
        // Refusal happens before any FC API call — no live socket needed.
        let err = provider
            .configure_vm(Path::new("/nonexistent.sock"), &spec, Some(&jail))
            .unwrap_err();
        assert!(
            matches!(&err, VmRuntimeError::Unsupported(msg) if msg.contains("vsock under the jailer")),
            "unexpected error: {err}"
        );
    }

    /// Full jailed cold-boot → snapshot → restore → rename cycle against a
    /// real Firecracker + jailer. Not run in CI (needs root + /dev/kvm).
    ///
    /// ```sh
    /// sudo -E \
    ///   MICROVM_FIRECRACKER_BIN=/usr/local/bin/firecracker \
    ///   MICROVM_JAILER_BIN=/usr/local/bin/jailer \
    ///   MICROVM_FIRECRACKER_KERNEL=/var/lib/firecracker/vmlinux \
    ///   MICROVM_FIRECRACKER_ROOTFS=/var/lib/firecracker/rootfs/default.ext4 \
    ///   cargo test --features firecracker -- --ignored jailed_snapshot_restore
    /// ```
    #[test]
    #[ignore = "requires root, /dev/kvm, firecracker + jailer binaries, kernel + rootfs images"]
    fn jailed_snapshot_restore_and_rename_e2e() {
        let provider = FirecrackerVmProvider::from_env().with_composer(FirecrackerComposer {
            jailer: Some(Arc::new(Jailer::from_env())),
            ..FirecrackerComposer::bare()
        });

        provider.create_vm("e2e-src").expect("jailed cold boot");
        provider.start_vm("e2e-src").expect("start");
        thread::sleep(Duration::from_secs(2));
        provider.stop_vm("e2e-src").expect("pause");
        provider
            .snapshot_vm("e2e-src", "warm")
            .expect("snapshot written in-chroot then moved to the durable dir");
        let snap_dir = provider.vm_state_path("e2e-src").join("snapshots");
        assert!(snap_dir.join("warm.vmstate").exists());
        assert!(snap_dir.join("warm.mem").exists());

        // Restore while the source's state dir (the durable snapshot home)
        // still exists — destroy_vm deletes it.
        let spec = VmSpec {
            restore_from: Some(SnapshotRef {
                vm_id: "e2e-src".into(),
                snapshot_id: "warm".into(),
                resume_immediately: true,
                network_overrides: vec![],
            }),
            ..VmSpec::default()
        };
        provider
            .create_vm_with_spec("e2e-pool", &spec)
            .expect("jailed restore from the durable snapshot");

        provider
            .rename_vm("e2e-pool", "e2e-claimed")
            .expect("warm-pool handoff rename");
        assert!(provider.get_vm("e2e-claimed").unwrap().is_some());
        assert!(provider.get_vm("e2e-pool").unwrap().is_none());

        provider.destroy_vm("e2e-claimed").expect("destroy renamed");
        provider.destroy_vm("e2e-src").expect("destroy source");
    }

    #[test]
    fn token_bucket_default_burst_equals_size() {
        let json = token_bucket_to_json(&TokenBucket {
            size: 1_048_576,
            one_time_burst: None,
            refill_time_ms: 1_000,
        });
        assert_eq!(json["size"], 1_048_576);
        assert_eq!(json["one_time_burst"], 1_048_576);
        assert_eq!(json["refill_time"], 1_000);
    }

    #[test]
    fn token_bucket_explicit_burst_respected() {
        let json = token_bucket_to_json(&TokenBucket {
            size: 1_048_576,
            one_time_burst: Some(2_097_152),
            refill_time_ms: 500,
        });
        assert_eq!(json["one_time_burst"], 2_097_152);
    }

    #[test]
    fn rate_limiter_serialises_both_buckets() {
        let json = rate_limiter_to_json(&RateLimiter {
            bandwidth: Some(TokenBucket {
                size: 10_000,
                one_time_burst: None,
                refill_time_ms: 100,
            }),
            ops: Some(TokenBucket {
                size: 50,
                one_time_burst: None,
                refill_time_ms: 100,
            }),
        });
        assert!(json.get("bandwidth").is_some());
        assert!(json.get("ops").is_some());
        assert_eq!(json["bandwidth"]["size"], 10_000);
        assert_eq!(json["ops"]["size"], 50);
    }

    #[test]
    fn rate_limiter_empty_serialises_to_empty_object() {
        let json = rate_limiter_to_json(&RateLimiter {
            bandwidth: None,
            ops: None,
        });
        assert!(json.is_object());
        assert!(json.as_object().unwrap().is_empty());
    }
}
