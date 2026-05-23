//! Auto-composition of [`FirecrackerVmProvider`](crate::FirecrackerVmProvider) with the per-VM lifecycle modules.
//!
//! By default the Firecracker adapter is bare: callers pass a [`crate::model::VmSpec`]
//! with whatever fields they want and the adapter writes them into the FC API. Networking,
//! vsock setup, firewall installation, jailer wrapping, console-tail capture, and graceful
//! shutdown are all opt-in primitives that callers compose themselves.
//!
//! For decentralized operators who want the "give me a working VM" experience, this module
//! provides [`FirecrackerComposer`] — a bundle of managers that the provider invokes
//! automatically in `create_vm_with_spec` and `destroy_vm`. Set the composer fields you
//! want active; leave the rest as `None`.
//!
//! ```no_run
//! use microvm_runtime::{FirecrackerComposer, FirecrackerVmProvider};
//! // Pull everything from env vars:
//! let composer = FirecrackerComposer::from_env();
//! let provider = FirecrackerVmProvider::from_env().with_composer(composer);
//! // Now `provider.create_vm("vm-1")` lights up network + vsock + firewall + jailer
//! // + console capture + graceful destroy, all in one call.
//! ```

use std::sync::Arc;

use crate::{
    firewall::Firewall, jailer::Jailer, network::NetworkManager, shutdown::ShutdownConfig,
    vsock::VsockManager,
};

/// Toggle-bag of lifecycle primitives. Each field is independent; mix and match.
///
/// Construction patterns:
/// - [`Self::bare`] — all `None` / `false`. Equivalent to no composer (adapter does
///   the minimum: spawn + configure + start). Use this if you want to compose primitives
///   manually outside the provider.
/// - [`Self::from_env`] — reads `MICROVM_COMPOSE_*` env vars to gate each primitive.
///   Defaults: every primitive ON when its toggle env var is absent. Set
///   `MICROVM_COMPOSE_NETWORK=0` to disable.
/// - [`Self::all`] — every primitive ON with defaults sourced from each manager's own
///   `from_env` constructor.
#[derive(Clone)]
pub struct FirecrackerComposer {
    /// Host network manager (TAP/bridge/NAT). When `Some`, `ensure_host` runs at
    /// construction-time of the composer and each VM gets a TAP attached pre-boot.
    pub network: Option<Arc<NetworkManager>>,
    /// Vsock CID + UDS allocator. When `Some`, each VM gets a CID + UDS pair set up
    /// pre-boot; the parent directory is created before snapshot/load.
    pub vsock: Option<Arc<VsockManager>>,
    /// Per-VM iptables FORWARD chain installer. When `Some`, an empty-allowlist chain
    /// is installed (no egress permitted) — callers should call `install` themselves
    /// later if they want a custom allowlist. Always uninstalled on `destroy_vm`.
    ///
    /// The default empty allowlist is intentionally restrictive: silent default-allow
    /// would mean every composed VM gets unrestricted egress on day one.
    pub firewall: Option<Arc<Firewall>>,
    /// Jailer wrapper. When `Some`, FC spawns under jailer with chroot + cgroup v2 +
    /// seccomp + UID/GID drop. The chroot is prepared per VM and torn down on destroy.
    pub jailer: Option<Arc<Jailer>>,
    /// When `true`, the FC subprocess's stderr is piped into a per-VM
    /// [`crate::console::ConsoleCapture`] for post-mortem diagnostics. Without this the
    /// stderr goes to `/dev/null`; kernel panics are invisible.
    pub capture_console: bool,
    /// When `true`, `destroy_vm` uses [`crate::shutdown::graceful_shutdown`] instead of
    /// `Child::kill` — sends SIGTERM, waits up to `shutdown_config.grace_period`, then
    /// escalates to SIGKILL if the FC process hasn't exited.
    pub graceful_shutdown: bool,
    /// Tuning for graceful shutdown. Ignored if `graceful_shutdown` is `false`.
    pub shutdown_config: ShutdownConfig,
}

impl Default for FirecrackerComposer {
    fn default() -> Self {
        Self::bare()
    }
}

impl std::fmt::Debug for FirecrackerComposer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FirecrackerComposer")
            .field("network", &self.network.is_some())
            .field("vsock", &self.vsock.is_some())
            .field("firewall", &self.firewall.is_some())
            .field("jailer", &self.jailer.is_some())
            .field("capture_console", &self.capture_console)
            .field("graceful_shutdown", &self.graceful_shutdown)
            .finish()
    }
}

impl FirecrackerComposer {
    /// All primitives disabled. Use when you want to compose manually.
    pub fn bare() -> Self {
        Self {
            network: None,
            vsock: None,
            firewall: None,
            jailer: None,
            capture_console: false,
            graceful_shutdown: false,
            shutdown_config: ShutdownConfig::default(),
        }
    }

    /// All primitives enabled with defaults from each manager's `from_env` constructor.
    pub fn all() -> Self {
        Self {
            network: Some(Arc::new(NetworkManager::from_env())),
            vsock: Some(Arc::new(VsockManager::from_env())),
            firewall: Some(Arc::new(Firewall::from_env())),
            jailer: Some(Arc::new(Jailer::from_env())),
            capture_console: true,
            graceful_shutdown: true,
            shutdown_config: ShutdownConfig::default(),
        }
    }

    /// Read each toggle from `MICROVM_COMPOSE_<NAME>` env vars; `0` or `false`
    /// disables, anything else (or absent) enables. Underlying manager configs are
    /// pulled from their own env vars.
    pub fn from_env() -> Self {
        Self {
            network: opt_in("MICROVM_COMPOSE_NETWORK")
                .then(|| Arc::new(NetworkManager::from_env())),
            vsock: opt_in("MICROVM_COMPOSE_VSOCK").then(|| Arc::new(VsockManager::from_env())),
            firewall: opt_in("MICROVM_COMPOSE_FIREWALL").then(|| Arc::new(Firewall::from_env())),
            jailer: opt_in("MICROVM_COMPOSE_JAILER").then(|| Arc::new(Jailer::from_env())),
            capture_console: opt_in("MICROVM_COMPOSE_CONSOLE"),
            graceful_shutdown: opt_in("MICROVM_COMPOSE_GRACEFUL_SHUTDOWN"),
            shutdown_config: ShutdownConfig::default(),
        }
    }
}

fn opt_in(var: &str) -> bool {
    match std::env::var(var) {
        Ok(v) => !matches!(v.trim(), "0" | "false" | "FALSE" | "False" | "no" | "NO"),
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_is_all_off() {
        let c = FirecrackerComposer::bare();
        assert!(c.network.is_none());
        assert!(c.vsock.is_none());
        assert!(c.firewall.is_none());
        assert!(c.jailer.is_none());
        assert!(!c.capture_console);
        assert!(!c.graceful_shutdown);
    }

    #[test]
    fn opt_in_default_is_true() {
        let name = "MICROVM_COMPOSE_TEST_DEFAULT_ON";
        unsafe { std::env::remove_var(name) };
        assert!(opt_in(name));
    }

    #[test]
    fn opt_in_explicit_zero_is_false() {
        let name = "MICROVM_COMPOSE_TEST_ZERO";
        unsafe { std::env::set_var(name, "0") };
        assert!(!opt_in(name));
        unsafe { std::env::remove_var(name) };
    }

    #[test]
    fn opt_in_false_word_is_false() {
        let name = "MICROVM_COMPOSE_TEST_FALSE";
        unsafe { std::env::set_var(name, "false") };
        assert!(!opt_in(name));
        unsafe { std::env::set_var(name, "FALSE") };
        assert!(!opt_in(name));
        unsafe { std::env::remove_var(name) };
    }

    #[test]
    fn opt_in_any_other_value_is_true() {
        let name = "MICROVM_COMPOSE_TEST_TRUE";
        unsafe { std::env::set_var(name, "1") };
        assert!(opt_in(name));
        unsafe { std::env::set_var(name, "yes") };
        assert!(opt_in(name));
        unsafe { std::env::set_var(name, "") };
        // Empty is still "set" → opt-in defaults to true since empty doesn't match "0"/"false".
        assert!(opt_in(name));
        unsafe { std::env::remove_var(name) };
    }
}
