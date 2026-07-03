//! Shared microVM runtime contracts and provider adapters.
//!
//! This crate is infrastructure-layer (`L0`) surface area. Product blueprints
//! should consume it indirectly through runtime adapters (`L1`).

pub mod adapters;
#[cfg(feature = "firecracker")]
pub mod composer;
#[cfg(feature = "firecracker")]
pub mod console;
pub mod error;
#[cfg(feature = "firecracker")]
pub mod firewall;
#[cfg(feature = "firecracker")]
pub mod guest_metadata;
#[cfg(feature = "firecracker")]
pub mod jailer;
#[cfg(feature = "firecracker")]
pub mod metrics;
pub mod model;
#[cfg(feature = "firecracker")]
pub mod network;
pub mod provider;
#[cfg(feature = "firecracker")]
pub mod rootfs;
#[cfg(feature = "firecracker")]
pub mod shutdown;
#[cfg(feature = "firecracker")]
pub mod uffd;
#[cfg(feature = "firecracker")]
pub mod vsock;

#[cfg(feature = "firecracker")]
pub use adapters::firecracker::{FirecrackerConfig, FirecrackerVmProvider, MemBackend};
pub use adapters::in_memory::InMemoryVmProvider;
#[cfg(feature = "firecracker")]
pub use composer::FirecrackerComposer;
#[cfg(feature = "firecracker")]
pub use console::{ConsoleCapture, ConsoleConfig};
pub use error::{VmRuntimeError, VmRuntimeResult};
#[cfg(feature = "firecracker")]
pub use firewall::{EgressRule, Firewall, FirewallConfig, VmEgressRules};
#[cfg(feature = "firecracker")]
pub use guest_metadata::{
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_GUEST_METADATA_PORT, DEFAULT_REQUEST_TIMEOUT,
    GuestMetadataClient, GuestMetadataConfig, GuestMetadataConn, OwnedRequest, Request, Response,
};
#[cfg(feature = "firecracker")]
pub use jailer::{Jailer, JailerConfig, VmJail};
#[cfg(feature = "firecracker")]
pub use metrics::{MetricsConfig, MetricsPoller, VmMetricsSnapshot};
pub use model::{
    DriveSpec, NetworkInterface, RateLimiter, SnapshotRef, TokenBucket, VmSpec, VmStatus, VmView,
    VsockSpec,
};
#[cfg(feature = "firecracker")]
pub use network::{Ipv4Net, NetworkConfig, NetworkManager, VmNetwork};
pub use provider::{VmProvider, VmQuery, VmRuntime};
#[cfg(feature = "firecracker")]
pub use rootfs::{RootfsConfig, RootfsRegistry, StackInfo, VmRootfs};
#[cfg(feature = "firecracker")]
pub use shutdown::{ShutdownConfig, ShutdownOutcome, graceful_shutdown};
#[cfg(feature = "firecracker")]
pub use uffd::{UffdConfig, UffdHandler, snapshot_load_mem_backend_uffd};
#[cfg(feature = "firecracker")]
pub use vsock::{VmVsock, VsockConfig, VsockManager};
