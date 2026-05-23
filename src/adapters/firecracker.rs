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
    error::{VmRuntimeError, VmRuntimeResult},
    model::{VmStatus, VmView},
    provider::{VmProvider, VmQuery},
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
#[derive(Clone)]
pub struct FirecrackerVmProvider {
    pub config: FirecrackerConfig,
    state: Arc<RwLock<HashMap<String, VmRecord>>>,
    processes: Arc<Mutex<HashMap<String, Child>>>,
}

impl std::fmt::Debug for FirecrackerVmProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FirecrackerVmProvider")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl FirecrackerVmProvider {
    pub fn new(config: FirecrackerConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(HashMap::new())),
            processes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn from_env() -> Self {
        Self::new(FirecrackerConfig::from_env())
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

    fn ensure_prereqs(&self) -> VmRuntimeResult<()> {
        if !self.config.binary_path.exists() {
            return Err(VmRuntimeError::Unsupported(format!(
                "firecracker binary not found: {}",
                self.config.binary_path.display()
            )));
        }
        if !self.config.kernel_path.exists() {
            return Err(VmRuntimeError::Unsupported(format!(
                "kernel image not found: {}",
                self.config.kernel_path.display()
            )));
        }
        if !self.config.rootfs_path.exists() {
            return Err(VmRuntimeError::Unsupported(format!(
                "rootfs image not found: {}",
                self.config.rootfs_path.display()
            )));
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

    fn spawn_firecracker(&self, vm_id: &str, socket_path: &Path) -> VmRuntimeResult<Child> {
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

        Command::new(&self.config.binary_path)
            .arg("--api-sock")
            .arg(socket_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                VmRuntimeError::Unsupported(format!(
                    "failed spawning firecracker for {vm_id} ({}): {e}",
                    self.config.binary_path.display()
                ))
            })
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

    fn configure_vm(&self, socket_path: &Path) -> VmRuntimeResult<()> {
        let machine = serde_json::json!({
            "vcpu_count": self.config.vcpu_count,
            "mem_size_mib": self.config.mem_size_mib,
            "smt": false,
            "track_dirty_pages": true
        });
        self.firecracker_request(socket_path, "PUT", "/machine-config", Some(machine))?;

        let boot = serde_json::json!({
            "kernel_image_path": self.config.kernel_path,
            "boot_args": self.config.boot_args
        });
        self.firecracker_request(socket_path, "PUT", "/boot-source", Some(boot))?;

        let root_drive = serde_json::json!({
            "drive_id": "rootfs",
            "path_on_host": self.config.rootfs_path,
            "is_root_device": true,
            "is_read_only": self.config.rootfs_read_only
        });
        self.firecracker_request(socket_path, "PUT", "/drives/rootfs", Some(root_drive))?;
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

    fn kill_process(&self, vm_id: &str) -> VmRuntimeResult<()> {
        let child = self
            .processes
            .lock()
            .map_err(|_| VmRuntimeError::StatePoisoned)?
            .remove(vm_id);

        if let Some(mut child) = child {
            let _ = child.kill();
            let _ = child.wait();
        }
        Ok(())
    }
}

impl VmProvider for FirecrackerVmProvider {
    fn create_vm(&self, vm_id: &str) -> VmRuntimeResult<()> {
        self.ensure_prereqs()?;

        {
            let state = self
                .state
                .read()
                .map_err(|_| VmRuntimeError::StatePoisoned)?;
            if state.contains_key(vm_id) {
                return Err(VmRuntimeError::VmAlreadyExists(vm_id.to_owned()));
            }
        }

        let socket_path = self.api_socket_path(vm_id);
        let state_dir = self.vm_state_path(vm_id);
        fs::create_dir_all(&state_dir).map_err(|e| {
            VmRuntimeError::Unsupported(format!(
                "failed creating vm state dir {}: {e}",
                state_dir.display()
            ))
        })?;

        let mut child = self.spawn_firecracker(vm_id, &socket_path)?;
        let create_result = (|| -> VmRuntimeResult<()> {
            self.wait_for_socket_ready(&socket_path)?;
            self.configure_vm(&socket_path)?;
            Ok(())
        })();

        if let Err(err) = create_result {
            let _ = child.kill();
            let _ = child.wait();
            return Err(err);
        }

        self.processes
            .lock()
            .map_err(|_| VmRuntimeError::StatePoisoned)?
            .insert(vm_id.to_owned(), child);

        self.state
            .write()
            .map_err(|_| VmRuntimeError::StatePoisoned)?
            .insert(
                vm_id.to_owned(),
                VmRecord {
                    status: VmStatus::Created,
                    snapshots: Vec::new(),
                    socket_path,
                    state_dir,
                },
            );

        Ok(())
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
