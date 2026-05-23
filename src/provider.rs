use crate::{error::VmRuntimeResult, model::VmView};

/// State-changing operations on microVMs, executed by lifecycle jobs.
pub trait VmProvider: Send + Sync + 'static {
    /// Provision a new microVM. Fails if `vm_id` is already in use.
    fn create_vm(&self, vm_id: &str) -> VmRuntimeResult<()>;

    /// Start a created or stopped microVM. Fails if already running or destroyed.
    fn start_vm(&self, vm_id: &str) -> VmRuntimeResult<()>;

    /// Stop a running microVM. Fails if not currently running.
    fn stop_vm(&self, vm_id: &str) -> VmRuntimeResult<()>;

    /// Capture the state of a microVM as a named snapshot.
    /// Fails if the VM is destroyed or the snapshot name already exists.
    fn snapshot_vm(&self, vm_id: &str, snapshot_id: &str) -> VmRuntimeResult<()>;

    /// Tear down a microVM. Terminal state — cannot be restarted.
    fn destroy_vm(&self, vm_id: &str) -> VmRuntimeResult<()>;
}

/// Read-only queries against microVM state, used by query surfaces.
pub trait VmQuery: Send + Sync + 'static {
    /// Return all known VMs, sorted by identifier.
    fn list_vms(&self) -> VmRuntimeResult<Vec<VmView>>;

    /// Return a single VM by identifier, or `None` if it does not exist.
    fn get_vm(&self, vm_id: &str) -> VmRuntimeResult<Option<VmView>>;

    /// Return the snapshot names for a VM, or `None` if the VM does not exist.
    fn list_snapshots(&self, vm_id: &str) -> VmRuntimeResult<Option<Vec<String>>>;
}

/// Unified trait object used by runners and query services.
pub trait VmRuntime: VmProvider + VmQuery {}

impl<T> VmRuntime for T where T: VmProvider + VmQuery {}
