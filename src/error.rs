use thiserror::Error;

/// Convenience alias used throughout runtime providers.
pub type VmRuntimeResult<T> = Result<T, VmRuntimeError>;

/// Errors that can occur during microVM lifecycle or query operations.
#[derive(Debug, Error)]
pub enum VmRuntimeError {
    /// Attempted to create a VM with an identifier that is already in use.
    #[error("vm '{0}' already exists")]
    VmAlreadyExists(String),

    /// Referenced a VM identifier that does not exist.
    #[error("vm '{0}' not found")]
    VmNotFound(String),

    /// A lifecycle transition was requested that is not valid from the current state.
    #[error("invalid vm transition for '{vm_id}': {from} -> {to}")]
    InvalidTransition {
        vm_id: String,
        from: String,
        to: &'static str,
    },

    /// Attempted to create a snapshot with an identifier that already exists on the VM.
    #[error("snapshot '{snapshot_id}' already exists for vm '{vm_id}'")]
    SnapshotAlreadyExists { vm_id: String, snapshot_id: String },

    /// Attempted to restore from a snapshot that does not exist on disk.
    #[error("snapshot '{snapshot_id}' not found for vm '{vm_id}'")]
    SnapshotNotFound { vm_id: String, snapshot_id: String },

    /// Internal lock was poisoned by a panicking thread.
    #[error("provider state lock poisoned")]
    StatePoisoned,

    /// Backend is not supported in the current build/config.
    #[error("backend unsupported: {0}")]
    Unsupported(String),

    /// Metrics poller failed to open, parse, or read the FC metrics FIFO.
    #[error("metrics: {0}")]
    Metrics(String),

    /// Graceful shutdown of a child process failed (signal delivery, wait, or
    /// escalation step).
    #[error("shutdown failed: {0}")]
    Shutdown(String),

    /// Host egress firewall (iptables) setup or teardown failed, or input
    /// validation rejected a rule before any iptables call was made.
    #[error("firewall error: {0}")]
    Firewall(String),

    /// Jailer chroot preparation, command construction, or teardown failed.
    #[error("jailer error: {0}")]
    Jailer(String),

    /// Network configuration is malformed (bad CIDR, prefix out of range, etc).
    #[error("network config invalid: {0}")]
    NetworkConfig(String),

    /// Host network setup or teardown failed (bridge/NAT/forward/TAP).
    #[error("network setup failed: {0}")]
    NetworkSetup(String),

    /// Rootfs catalog discovery, per-VM clone, or SHA-256 integrity check
    /// failed (missing template, stamp mismatch, hash mismatch, I/O error).
    #[error("rootfs: {0}")]
    Rootfs(String),

    /// Userfaultfd page-fault handler failed to bind, hand-shake, or service
    /// page faults. The variant is intentionally a free-form message because
    /// the failure modes range from libc errno values to JSON parse errors on
    /// the region-mapping payload Firecracker sends with the fd.
    #[error("uffd error: {0}")]
    Uffd(String),

    /// Communication with the in-guest metadata daemon failed (UDS connect,
    /// Firecracker `CONNECT` handshake, JSON encode/decode, request timeout,
    /// or guest-reported failure).
    #[error("guest metadata: {0}")]
    GuestMetadata(String),
}
