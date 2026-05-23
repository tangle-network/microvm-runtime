use std::fmt;

use serde::Serialize;

/// Current lifecycle state of a microVM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VmStatus {
    /// Provisioned but not yet started.
    Created,
    /// Actively running.
    Running,
    /// Gracefully stopped; can be restarted.
    Stopped,
    /// Torn down; terminal state.
    Destroyed,
}

impl fmt::Display for VmStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Created => f.write_str("created"),
            Self::Running => f.write_str("running"),
            Self::Stopped => f.write_str("stopped"),
            Self::Destroyed => f.write_str("destroyed"),
        }
    }
}

/// Read-only snapshot of a microVM's current state.
#[derive(Debug, Clone, Serialize)]
pub struct VmView {
    /// Unique identifier for this microVM.
    pub vm_id: String,
    /// Current lifecycle status.
    pub status: VmStatus,
    /// Names of snapshots captured for this VM, in creation order.
    pub snapshots: Vec<String>,
}
