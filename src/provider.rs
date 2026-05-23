use crate::error::{VmRuntimeError, VmRuntimeResult};
use crate::model::{VmSpec, VmView};

/// State-changing operations on microVMs, executed by lifecycle jobs.
pub trait VmProvider: Send + Sync + 'static {
    /// Provision a new microVM with workspace defaults. Fails if `vm_id` is already in use.
    fn create_vm(&self, vm_id: &str) -> VmRuntimeResult<()>;

    /// Provision a new microVM with per-VM configuration overrides.
    ///
    /// If `spec.restore_from` is set, the VM boots from the referenced snapshot via
    /// `PUT /snapshot/load` instead of cold-booting; the rest of the spec's cold-boot
    /// fields are ignored except for any [`crate::model::SnapshotRef::network_overrides`].
    ///
    /// Default implementation delegates to [`create_vm`](Self::create_vm) and ignores
    /// the spec — adequate for simple providers (e.g. the in-memory test adapter) where
    /// the spec has no semantics. Real adapters should override.
    fn create_vm_with_spec(&self, vm_id: &str, _spec: &VmSpec) -> VmRuntimeResult<()> {
        self.create_vm(vm_id)
    }

    /// Start a created or stopped microVM. Fails if already running or destroyed.
    fn start_vm(&self, vm_id: &str) -> VmRuntimeResult<()>;

    /// Stop a running microVM. Fails if not currently running.
    fn stop_vm(&self, vm_id: &str) -> VmRuntimeResult<()>;

    /// Capture the state of a microVM as a named snapshot.
    /// Fails if the VM is destroyed or the snapshot name already exists.
    fn snapshot_vm(&self, vm_id: &str, snapshot_id: &str) -> VmRuntimeResult<()>;

    /// Tear down a microVM. Terminal state — cannot be restarted.
    fn destroy_vm(&self, vm_id: &str) -> VmRuntimeResult<()>;

    /// Rename a VM. Used for warm-pool handoff: a pre-restored VM that swaps its identifier
    /// onto a new tenant request without going through a full snapshot/load round-trip.
    ///
    /// Default implementation returns [`VmRuntimeError::Unsupported`]. Providers that support
    /// pooled VMs should override.
    fn rename_vm(&self, _old_vm_id: &str, _new_vm_id: &str) -> VmRuntimeResult<()> {
        Err(VmRuntimeError::Unsupported(
            "rename_vm is not implemented by this provider".into(),
        ))
    }
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
