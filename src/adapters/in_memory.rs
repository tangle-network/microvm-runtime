use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use crate::{
    error::{VmRuntimeError, VmRuntimeResult},
    model::{VmStatus, VmView},
    provider::{VmProvider, VmQuery},
};

/// In-memory VM provider for development and testing.
///
/// Replace with a hypervisor-backed adapter (e.g. Firecracker, Cloud Hypervisor)
/// for production use.
#[derive(Debug, Clone, Default)]
pub struct InMemoryVmProvider {
    state: Arc<RwLock<HashMap<String, VmRecord>>>,
}

#[derive(Debug, Clone)]
struct VmRecord {
    status: VmStatus,
    snapshots: Vec<String>,
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

impl VmProvider for InMemoryVmProvider {
    fn create_vm(&self, vm_id: &str) -> VmRuntimeResult<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| VmRuntimeError::StatePoisoned)?;

        if state.contains_key(vm_id) {
            return Err(VmRuntimeError::VmAlreadyExists(vm_id.to_owned()));
        }

        state.insert(
            vm_id.to_owned(),
            VmRecord {
                status: VmStatus::Created,
                snapshots: Vec::new(),
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
            VmStatus::Created | VmStatus::Stopped => {
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

        record.status = VmStatus::Destroyed;
        Ok(())
    }
}

impl VmQuery for InMemoryVmProvider {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_lifecycle() {
        let provider = InMemoryVmProvider::default();

        provider.create_vm("vm-a").expect("create");
        provider.start_vm("vm-a").expect("start");
        provider.snapshot_vm("vm-a", "snap-1").expect("snapshot");
        provider.stop_vm("vm-a").expect("stop");
        provider.destroy_vm("vm-a").expect("destroy");

        let vm = provider.get_vm("vm-a").expect("query").expect("vm exists");

        assert_eq!(vm.status, VmStatus::Destroyed);
        assert_eq!(vm.snapshots, vec!["snap-1".to_owned()]);
    }
}
