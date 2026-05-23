use std::fmt;
use std::path::PathBuf;

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

/// Per-VM configuration override. Every field is optional; `None` falls back to the
/// provider's workspace-level default (e.g. [`FirecrackerConfig`](crate::adapters::firecracker::FirecrackerConfig)).
///
/// Use [`VmSpec::default`] for cold boot with workspace defaults, or set
/// [`VmSpec::restore_from`] to restore from a snapshot instead of cold-booting.
///
/// To do a warm-pool handoff — a pre-restored VM that swaps its TAP and IP onto a
/// new tenant — set [`VmSpec::restore_from`] with [`SnapshotRef::network_overrides`]
/// populated. Firecracker 1.10+ supports this; 1.6 rejects it.
#[derive(Debug, Clone, Default)]
pub struct VmSpec {
    /// Kernel image path. None = use workspace default.
    pub kernel: Option<PathBuf>,
    /// Rootfs image path. None = use workspace default.
    pub rootfs: Option<PathBuf>,
    /// Mount rootfs read-only. None = use workspace default.
    pub rootfs_read_only: Option<bool>,
    /// vCPU count override.
    pub vcpu_count: Option<u8>,
    /// Memory size in MiB override.
    pub mem_size_mib: Option<u32>,
    /// Kernel command-line override.
    pub boot_args: Option<String>,
    /// Rate limit applied to the rootfs drive.
    pub rootfs_rate_limit: Option<RateLimiter>,
    /// Network interfaces to attach pre-boot. Firecracker requires these to be configured
    /// before `InstanceStart`. Empty by default — the VM has no network unless explicitly set.
    pub network_interfaces: Vec<NetworkInterface>,
    /// If set, the VM boots from a snapshot via `PUT /snapshot/load` instead of cold-booting.
    /// The spec's `kernel`, `rootfs`, `vcpu_count`, `mem_size_mib`, `boot_args`, and
    /// `network_interfaces` are ignored when restoring (the snapshot encodes its own machine
    /// config). Use [`SnapshotRef::network_overrides`] to swap network interfaces on restore.
    pub restore_from: Option<SnapshotRef>,
    /// Track dirty pages during execution — required to later capture diff snapshots.
    /// None = enabled (FC's safer default for snapshot-friendly workloads).
    pub track_dirty_pages: Option<bool>,
}

/// Firecracker `RateLimiter` config, applicable to drives and network interfaces.
///
/// At least one of `bandwidth` / `ops` should be set; setting both is allowed.
/// See <https://github.com/firecracker-microvm/firecracker/blob/main/docs/api_requests/patch-rate-limiter.md>.
#[derive(Debug, Clone, Default)]
pub struct RateLimiter {
    /// Bandwidth token bucket (units = bytes).
    pub bandwidth: Option<TokenBucket>,
    /// Operations token bucket (units = IO ops).
    pub ops: Option<TokenBucket>,
}

/// Token bucket parameters. Caller specifies `refill_time_ms`; serialization translates
/// to Firecracker's `refill_time` (also in ms — but we keep the suffix explicit on our side
/// to avoid the "is this seconds?" question).
#[derive(Debug, Clone)]
pub struct TokenBucket {
    /// Bucket size (bytes for bandwidth, ops for ops).
    pub size: u64,
    /// Optional one-time burst capacity used at start. Defaults to `size` if `None`.
    pub one_time_burst: Option<u64>,
    /// Refill period in milliseconds.
    pub refill_time_ms: u64,
}

/// Network interface attached to a VM.
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    /// Identifier used by FC for this interface (e.g. `"eth0"`).
    pub iface_id: String,
    /// Host-side TAP device name (e.g. `"tap-abcd1234"`).
    pub host_dev_name: String,
    /// Guest-visible MAC address. None = let Firecracker assign one.
    pub guest_mac: Option<String>,
    /// Rate limit applied to received traffic on this NIC.
    pub rx_rate_limiter: Option<RateLimiter>,
    /// Rate limit applied to transmitted traffic on this NIC.
    pub tx_rate_limiter: Option<RateLimiter>,
}

/// Reference to a snapshot used to restore a VM.
#[derive(Debug, Clone)]
pub struct SnapshotRef {
    /// VM the snapshot was taken from.
    pub vm_id: String,
    /// Snapshot name.
    pub snapshot_id: String,
    /// If true, transition straight to `Running` after restore (Firecracker's `resume_vm` flag).
    /// If false, the VM is restored in Paused state and needs an explicit `start_vm`.
    pub resume_immediately: bool,
    /// If non-empty, replace the snapshot's recorded network interfaces with these on load.
    /// Use this for warm-pool handoff: a pre-restored VM swaps its TAP/MAC to a new tenant
    /// without a full re-boot. Firecracker 1.10+ required; earlier versions reject the field.
    pub network_overrides: Vec<NetworkInterface>,
}
