//! Shared microVM runtime contracts and provider adapters.
//!
//! This crate is infrastructure-layer (`L0`) surface area. Product blueprints
//! should consume it indirectly through runtime adapters (`L1`).

pub mod adapters;
pub mod error;
#[cfg(feature = "firecracker")]
pub mod metrics;
pub mod model;
pub mod provider;

#[cfg(feature = "firecracker")]
pub use adapters::firecracker::{FirecrackerConfig, FirecrackerVmProvider};
pub use adapters::in_memory::InMemoryVmProvider;
pub use error::{VmRuntimeError, VmRuntimeResult};
#[cfg(feature = "firecracker")]
pub use metrics::{MetricsConfig, MetricsPoller, VmMetricsSnapshot};
pub use model::{VmStatus, VmView};
pub use provider::{VmProvider, VmQuery, VmRuntime};
