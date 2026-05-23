//! Shared microVM runtime contracts and provider adapters.
//!
//! This crate is infrastructure-layer (`L0`) surface area. Product blueprints
//! should consume it indirectly through runtime adapters (`L1`).

pub mod adapters;
#[cfg(feature = "firecracker")]
pub mod console;
pub mod error;
#[cfg(feature = "firecracker")]
pub mod metrics;
pub mod model;
pub mod provider;
#[cfg(feature = "firecracker")]
pub mod shutdown;
#[cfg(feature = "firecracker")]
pub mod vsock;

#[cfg(feature = "firecracker")]
pub use adapters::firecracker::{FirecrackerConfig, FirecrackerVmProvider};
pub use adapters::in_memory::InMemoryVmProvider;
#[cfg(feature = "firecracker")]
pub use console::{ConsoleCapture, ConsoleConfig};
pub use error::{VmRuntimeError, VmRuntimeResult};
#[cfg(feature = "firecracker")]
pub use metrics::{MetricsConfig, MetricsPoller, VmMetricsSnapshot};
pub use model::{VmStatus, VmView};
pub use provider::{VmProvider, VmQuery, VmRuntime};
#[cfg(feature = "firecracker")]
pub use shutdown::{ShutdownConfig, ShutdownOutcome, graceful_shutdown};
#[cfg(feature = "firecracker")]
pub use vsock::{VmVsock, VsockConfig, VsockManager};
