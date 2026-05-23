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
    model::{
        DriveSpec, NetworkInterface, RateLimiter, SnapshotRef, TokenBucket, VmSpec, VmStatus,
        VmView, VsockSpec,
    },
    provider::{VmProvider, VmQuery},
    shutdown::graceful_shutdown,
};

const DEFAULT_FIRECRACKER_BIN: &str = "/usr/local/bin/firecracker";
const DEFAULT_KERNEL_PATH: &str = "/var/lib/firecracker/vmlinux";
const DEFAULT_ROOTFS_PATH: &str = "/var/lib/firecracker/rootfs/default.ext4";
const DEFAULT_BOOT_ARGS: &str =
    "console=ttyS0 reboot=k panic=1 pci=off quiet i8042.nokbd i8042.noaux";
const DEFAULT_API_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_SOCKET_READY_TIMEOUT_MS: u64 = 5_000;

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
        }
    }
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
}

#[derive(Default)]
struct ComposedAttachments {
    network_attached: bool,
    vsock_attached: bool,
    firewall_installed: bool,
    jail_prepared: bool,
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
    fn spawn_firecracker_for_compose(
        &self,
        vm_id: &str,
        socket_path: &Path,
        capture_stderr: bool,
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

        Command::new(&self.config.binary_path)
            .arg("--api-sock")
            .arg(socket_path)
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
        // The composer is a no-op when restoring; callers wanting to swap network on
        // restore should populate `SnapshotRef::network_overrides` themselves.
        if spec.restore_from.is_some() {
            return Ok((spec, ComposedAttachments::default()));
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

        // Jailer composition is gated on the spawn_firecracker rewrite that wires
        // the chroot'd API socket back to the host. Tracked for the next milestone;
        // for now the composer flag is accepted but produces no action.
        if composer.jailer.is_some() {
            attachments.jail_prepared = false;
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

        if attachments.jail_prepared
            && let Some(jailer) = composer.jailer.as_ref()
        {
            let _ = jailer.teardown(vm_id);
        }
    }

    fn wait_for_socket_ready(&self, socket_path: &Path) -> VmRuntimeResult<()> {
        let deadline = Instant::now() + self.config.socket_ready_timeout;
        while Instant::now() < deadline {
            if socket_path.exists()
                && self
                    .firecracker_request(socket_path, "GET", "/", None)
                    .is_ok()
            {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }
        Err(VmRuntimeError::Unsupported(format!(
            "firecracker api socket not ready within {:?}: {}",
            self.config.socket_ready_timeout,
            socket_path.display()
        )))
    }

    fn configure_vm(&self, socket_path: &Path, spec: &VmSpec) -> VmRuntimeResult<()> {
        let vcpu_count = spec.vcpu_count.unwrap_or(self.config.vcpu_count);
        let mem_size_mib = spec.mem_size_mib.unwrap_or(self.config.mem_size_mib);
        let track_dirty_pages = spec.track_dirty_pages.unwrap_or(true);
        let machine = serde_json::json!({
            "vcpu_count": vcpu_count,
            "mem_size_mib": mem_size_mib,
            "smt": false,
            "track_dirty_pages": track_dirty_pages
        });
        self.firecracker_request(socket_path, "PUT", "/machine-config", Some(machine))?;

        let kernel_path = spec.kernel.as_ref().unwrap_or(&self.config.kernel_path);
        let boot_args = spec.boot_args.as_deref().unwrap_or(&self.config.boot_args);
        let boot = serde_json::json!({
            "kernel_image_path": kernel_path,
            "boot_args": boot_args
        });
        self.firecracker_request(socket_path, "PUT", "/boot-source", Some(boot))?;

        let rootfs_path = spec.rootfs.as_ref().unwrap_or(&self.config.rootfs_path);
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

        for drive in &spec.extra_drives {
            self.put_extra_drive(socket_path, drive)?;
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

    fn load_snapshot(&self, socket_path: &Path, snapshot: &SnapshotRef) -> VmRuntimeResult<()> {
        let source_state_dir = self.vm_state_path(&snapshot.vm_id);
        let snap_dir = source_state_dir.join("snapshots");
        let vmstate_path = snap_dir.join(format!("{}.vmstate", snapshot.snapshot_id));
        let mem_path = snap_dir.join(format!("{}.mem", snapshot.snapshot_id));
        if !vmstate_path.exists() {
            return Err(VmRuntimeError::SnapshotNotFound {
                vm_id: snapshot.vm_id.clone(),
                snapshot_id: snapshot.snapshot_id.clone(),
            });
        }

        let mut body = serde_json::json!({
            "snapshot_path": vmstate_path,
            "mem_backend": {
                "backend_type": "File",
                "backend_path": mem_path,
            },
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

        self.firecracker_request(socket_path, "PUT", "/snapshot/load", Some(body))?;
        Ok(())
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

        let mut response = Vec::new();
        stream.read_to_end(&mut response).map_err(|e| {
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

    fn create_snapshot(
        &self,
        socket_path: &Path,
        state_dir: &Path,
        snapshot_id: &str,
    ) -> VmRuntimeResult<()> {
        let snap_dir = state_dir.join("snapshots");
        fs::create_dir_all(&snap_dir).map_err(|e| {
            VmRuntimeError::Unsupported(format!(
                "failed creating snapshot dir {}: {e}",
                snap_dir.display()
            ))
        })?;
        let vmstate_path = snap_dir.join(format!("{snapshot_id}.vmstate"));
        let mem_path = snap_dir.join(format!("{snapshot_id}.mem"));

        self.firecracker_request(
            socket_path,
            "PUT",
            "/snapshot/create",
            Some(serde_json::json!({
                "snapshot_type": "Full",
                "snapshot_path": vmstate_path,
                "mem_file_path": mem_path
            })),
        )?;
        Ok(())
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

        // Run composer-side pre-spawn primitives (network/vsock/firewall) and
        // augment the spec accordingly. Composer is opt-in; bare semantics
        // unchanged when it's None.
        let (effective_spec, attachments) = self.compose_pre_spawn(vm_id, spec.clone())?;

        let socket_path = self.api_socket_path(vm_id);
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

        let mut child =
            match self.spawn_firecracker_for_compose(vm_id, &socket_path, capture_stderr) {
                Ok(c) => c,
                Err(e) => {
                    self.compose_release(vm_id, &attachments);
                    return Err(e);
                }
            };
        let restoring = effective_spec.restore_from.is_some();
        let configure_result = (|| -> VmRuntimeResult<()> {
            self.wait_for_socket_ready(&socket_path)?;
            if let Some(snapshot) = effective_spec.restore_from.as_ref() {
                self.load_snapshot(&socket_path, snapshot)?;
            } else {
                self.configure_vm(&socket_path, &effective_spec)?;
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

        if attachments.network_attached
            || attachments.vsock_attached
            || attachments.firewall_installed
            || attachments.jail_prepared
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

        self.create_snapshot(&record.socket_path, &record.state_dir, snapshot_id)?;
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
    use crate::model::{RateLimiter, TokenBucket};

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
