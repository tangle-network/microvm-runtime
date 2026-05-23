//! Host networking for Firecracker VMs.
//!
//! The driver in `adapters::firecracker` spawns VMs but has no notion of
//! network: this module fills that gap. Public surface is [`NetworkConfig`],
//! [`NetworkManager`], and [`VmNetwork`]. Wiring the manager into the
//! Firecracker adapter is the caller's job — this module exposes a clean,
//! adapter-agnostic API.
//!
//! Topology produced:
//!
//! ```text
//!  guest eth0  <-->  host TAP (tap-<hash>)  <-->  bridge (fcbr0)  <-->  NAT  <-->  egress iface
//!                                                      |
//!                                                      gateway (.1 of subnet)
//! ```
//!
//! All host-side mutations shell out to `ip(8)` and `iptables(8)`; this keeps
//! the dependency tree small (no rtnetlink) and makes the operations
//! identical to what an operator would run by hand for debugging.

mod alloc;
mod host;
mod ipv4_net;

use std::net::Ipv4Addr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{VmRuntimeError, VmRuntimeResult};

pub use ipv4_net::Ipv4Net;

use host::{Runner, SystemRunner};

const DEFAULT_BRIDGE: &str = "fcbr0";
const DEFAULT_SUBNET: &str = "172.30.0.0/24";
const DEFAULT_EGRESS: &str = "eth0";
const DEFAULT_MTU: u32 = 1500;

const ENV_BRIDGE: &str = "MICROVM_NETWORK_BRIDGE";
const ENV_SUBNET: &str = "MICROVM_NETWORK_SUBNET";
const ENV_EGRESS: &str = "MICROVM_NETWORK_EGRESS";
const ENV_MTU: &str = "MICROVM_NETWORK_MTU";

/// Configuration for [`NetworkManager`]. Mirrors the `FirecrackerConfig::from_env`
/// style so deployments can wire both managers from the same env block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Host bridge name to attach VMs to (default `"fcbr0"`).
    pub bridge_name: String,
    /// CIDR for VM IP allocation, e.g. `"172.30.0.0/24"`. The first host
    /// address (`.1`) is reserved as gateway; broadcast is reserved by
    /// convention. Must be at least `/30`.
    pub vm_subnet: Ipv4Net,
    /// Host interface to NAT through (default `"eth0"`).
    pub host_egress_iface: String,
    /// MTU passed to TAP devices on creation.
    pub mtu: u32,
}

impl NetworkConfig {
    /// Build a [`NetworkConfig`] with bounded defaults. Will return an error
    /// if `subnet` is malformed or too small.
    pub fn new(
        bridge_name: impl Into<String>,
        subnet: &str,
        host_egress_iface: impl Into<String>,
        mtu: u32,
    ) -> VmRuntimeResult<Self> {
        let vm_subnet = Ipv4Net::from_str(subnet)?;
        validate_subnet(vm_subnet)?;
        Ok(Self {
            bridge_name: bridge_name.into(),
            vm_subnet,
            host_egress_iface: host_egress_iface.into(),
            mtu,
        })
    }

    /// Load configuration from environment, falling back to defaults:
    ///
    /// | env var                     | default          |
    /// |-----------------------------|------------------|
    /// | `MICROVM_NETWORK_BRIDGE`    | `fcbr0`          |
    /// | `MICROVM_NETWORK_SUBNET`    | `172.30.0.0/24`  |
    /// | `MICROVM_NETWORK_EGRESS`    | `eth0`           |
    /// | `MICROVM_NETWORK_MTU`       | `1500`           |
    ///
    /// Unparseable / malformed values silently fall back to the default,
    /// matching `FirecrackerConfig::from_env`. Use [`NetworkConfig::new`]
    /// if you want fail-fast validation.
    pub fn from_env() -> Self {
        let bridge_name = std::env::var(ENV_BRIDGE).unwrap_or_else(|_| DEFAULT_BRIDGE.to_string());
        let vm_subnet = std::env::var(ENV_SUBNET)
            .ok()
            .and_then(|s| Ipv4Net::from_str(&s).ok())
            .filter(|net| net.num_addresses() >= 4)
            .unwrap_or_else(|| {
                Ipv4Net::from_str(DEFAULT_SUBNET).expect("DEFAULT_SUBNET is statically valid")
            });
        let host_egress_iface =
            std::env::var(ENV_EGRESS).unwrap_or_else(|_| DEFAULT_EGRESS.to_string());
        let mtu = std::env::var(ENV_MTU)
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_MTU);
        Self {
            bridge_name,
            vm_subnet,
            host_egress_iface,
            mtu,
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        // Defaults are statically valid; unwrap is sound.
        Self::new(DEFAULT_BRIDGE, DEFAULT_SUBNET, DEFAULT_EGRESS, DEFAULT_MTU)
            .expect("default NetworkConfig is statically valid")
    }
}

fn validate_subnet(subnet: Ipv4Net) -> VmRuntimeResult<()> {
    if subnet.num_addresses() < 4 {
        return Err(VmRuntimeError::NetworkConfig(format!(
            "subnet {subnet} is too small: need /30 or larger"
        )));
    }
    Ok(())
}

/// Per-VM network attachment returned by [`NetworkManager::attach`].
///
/// Fields map directly onto Firecracker's `/network-interfaces/<id>` body
/// and the kernel `ip=` boot argument:
///
/// ```text
/// ip=<guest_ip>::<gateway_ip>:<netmask>::eth0:off
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct VmNetwork {
    /// Host-side TAP interface name (e.g. `"tap-abcd1234"`). 15-byte safe.
    pub tap_name: String,
    /// IPv4 address inside [`NetworkConfig::vm_subnet`].
    pub guest_ip: Ipv4Addr,
    /// Locally-administered unicast MAC.
    pub guest_mac: [u8; 6],
    /// Gateway address (first host address of the subnet).
    pub gateway_ip: Ipv4Addr,
    /// Netmask for the subnet (e.g. `255.255.255.0` for `/24`).
    pub netmask: Ipv4Addr,
}

impl VmNetwork {
    /// `"02:ab:cd:ef:01:23"` rendering of [`Self::guest_mac`].
    pub fn mac_string(&self) -> String {
        alloc::format_mac(self.guest_mac)
    }

    /// Kernel command-line `ip=` fragment for this attachment, identical in
    /// shape to what the reference TS driver emits.
    pub fn kernel_ip_arg(&self) -> String {
        format!(
            "ip={}::{}:{}::eth0:off",
            self.guest_ip, self.gateway_ip, self.netmask
        )
    }
}

/// Host network manager.
///
/// State is intentionally minimal: a [`NetworkConfig`] plus a private
/// command runner for shelling out. The host's actual state (bridge
/// presence, iptables rules, TAP devices) is the source of truth; this
/// struct does not cache it. That keeps `attach` / `detach` race-free
/// across processes — the kernel is the lock.
pub struct NetworkManager {
    config: NetworkConfig,
    runner: Box<dyn Runner>,
}

impl std::fmt::Debug for NetworkManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkManager")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl NetworkManager {
    pub fn new(config: NetworkConfig) -> Self {
        Self {
            config,
            runner: Box::new(SystemRunner),
        }
    }

    /// Mirror of `FirecrackerConfig::from_env`.
    pub fn from_env() -> Self {
        Self::new(NetworkConfig::from_env())
    }

    pub fn config(&self) -> &NetworkConfig {
        &self.config
    }

    /// Idempotent host setup: bridge, NAT rule, FORWARD ACCEPT pair.
    ///
    /// Safe to call once per host — repeat calls are no-ops because each
    /// step checks before insert (`iptables -C`, `ip link show`, etc.).
    pub fn ensure_host(&self) -> VmRuntimeResult<()> {
        let gateway = alloc::gateway_for(self.config.vm_subnet)?;
        let gateway_cidr = format!("{}/{}", gateway, self.config.vm_subnet.prefix());
        host::ensure_bridge(
            self.runner.as_ref(),
            &self.config.bridge_name,
            &gateway_cidr,
        )?;
        host::ensure_nat(
            self.runner.as_ref(),
            &self.config.vm_subnet.to_string(),
            &self.config.host_egress_iface,
        )?;
        host::ensure_forward(
            self.runner.as_ref(),
            &self.config.bridge_name,
            &self.config.host_egress_iface,
        )?;
        Ok(())
    }

    /// Create the TAP for `vm_id`, attach it to the host bridge, and return
    /// the addressing details Firecracker needs to configure
    /// `/network-interfaces/eth0`.
    ///
    /// `vm_id` may be any string; it is hashed to derive the (15-byte safe)
    /// TAP name and the deterministic guest IP/MAC. The same `vm_id` always
    /// yields the same triple.
    pub fn attach(&self, vm_id: &str) -> VmRuntimeResult<VmNetwork> {
        if vm_id.is_empty() {
            return Err(VmRuntimeError::NetworkConfig(
                "vm_id must be non-empty".into(),
            ));
        }
        let tap_name = alloc::tap_name_for(vm_id);
        let guest_ip = alloc::allocate_guest_ip(vm_id, self.config.vm_subnet)?;
        let guest_mac = alloc::allocate_guest_mac(vm_id);
        let gateway_ip = alloc::gateway_for(self.config.vm_subnet)?;
        let netmask = self.config.vm_subnet.netmask();

        host::create_tap(
            self.runner.as_ref(),
            &tap_name,
            &self.config.bridge_name,
            self.config.mtu,
        )?;

        Ok(VmNetwork {
            tap_name,
            guest_ip,
            guest_mac,
            gateway_ip,
            netmask,
        })
    }

    /// Tear down the TAP for `vm_id`. Idempotent: already-removed is OK.
    /// Does not release any iptables state — there is none per-VM in Phase 1.
    pub fn detach(&self, vm_id: &str) -> VmRuntimeResult<()> {
        if vm_id.is_empty() {
            return Err(VmRuntimeError::NetworkConfig(
                "vm_id must be non-empty".into(),
            ));
        }
        let tap_name = alloc::tap_name_for(vm_id);
        host::delete_tap(self.runner.as_ref(), &tap_name)
    }
}

#[cfg(test)]
impl NetworkManager {
    /// Test-only constructor that injects a custom runner. Lives behind
    /// `#[cfg(test)]` so the public surface stays clean.
    fn with_runner(config: NetworkConfig, runner: Box<dyn Runner>) -> Self {
        Self { config, runner }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct ScriptedRunner {
        log: Mutex<Vec<Vec<String>>>,
        outcomes: Mutex<Vec<(i32, String, String)>>,
    }

    impl ScriptedRunner {
        fn new(outcomes: Vec<(i32, &str, &str)>) -> Self {
            Self {
                log: Mutex::new(Vec::new()),
                outcomes: Mutex::new(
                    outcomes
                        .into_iter()
                        .map(|(s, o, e)| (s, o.to_string(), e.to_string()))
                        .collect(),
                ),
            }
        }
        #[allow(dead_code)]
        fn calls(&self) -> Vec<Vec<String>> {
            self.log.lock().unwrap().clone()
        }
    }

    impl Runner for ScriptedRunner {
        fn run(&self, program: &str, args: &[&str]) -> VmRuntimeResult<host::CommandOutcome> {
            let mut rec = vec![program.to_string()];
            rec.extend(args.iter().map(|s| s.to_string()));
            self.log.lock().unwrap().push(rec);
            let mut outs = self.outcomes.lock().unwrap();
            if outs.is_empty() {
                Ok(host::CommandOutcome {
                    status: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            } else {
                let (status, stdout, stderr) = outs.remove(0);
                Ok(host::CommandOutcome {
                    status,
                    stdout,
                    stderr,
                })
            }
        }
    }

    fn default_config() -> NetworkConfig {
        NetworkConfig::new("fcbr-test", "172.30.0.0/24", "ethX", 1500).unwrap()
    }

    #[test]
    fn default_config_is_valid() {
        let cfg = NetworkConfig::default();
        assert_eq!(cfg.bridge_name, "fcbr0");
        assert_eq!(cfg.host_egress_iface, "eth0");
        assert_eq!(cfg.mtu, 1500);
        assert_eq!(cfg.vm_subnet.to_string(), "172.30.0.0/24");
    }

    #[test]
    fn rejects_too_small_subnet() {
        let err = NetworkConfig::new("br", "10.0.0.0/31", "eth0", 1500).unwrap_err();
        assert!(matches!(err, VmRuntimeError::NetworkConfig(_)));
    }

    #[test]
    fn rejects_malformed_subnet() {
        let err = NetworkConfig::new("br", "not-a-cidr", "eth0", 1500).unwrap_err();
        assert!(matches!(err, VmRuntimeError::NetworkConfig(_)));
    }

    #[test]
    fn from_env_uses_defaults_when_unset() {
        // Clear envs to make this test independent.
        let keys = [ENV_BRIDGE, ENV_SUBNET, ENV_EGRESS, ENV_MTU];
        // SAFETY: tests in this crate run in a single-thread test runner; we
        // do not spawn observers concurrently.
        for k in keys {
            unsafe { std::env::remove_var(k) };
        }
        let cfg = NetworkConfig::from_env();
        assert_eq!(cfg.bridge_name, "fcbr0");
        assert_eq!(cfg.vm_subnet.to_string(), "172.30.0.0/24");
        assert_eq!(cfg.host_egress_iface, "eth0");
        assert_eq!(cfg.mtu, 1500);
    }

    #[test]
    fn vm_network_kernel_ip_arg_shape() {
        let net = VmNetwork {
            tap_name: "tap-deadbeef".into(),
            guest_ip: Ipv4Addr::new(172, 30, 0, 42),
            guest_mac: [0x02, 0xab, 0xcd, 0xef, 0x01, 0x23],
            gateway_ip: Ipv4Addr::new(172, 30, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
        };
        assert_eq!(
            net.kernel_ip_arg(),
            "ip=172.30.0.42::172.30.0.1:255.255.255.0::eth0:off"
        );
        assert_eq!(net.mac_string(), "02:ab:cd:ef:01:23");
    }

    #[test]
    fn attach_is_deterministic_and_in_subnet() {
        // Bridge present, MTU set, master set, link up
        let r = ScriptedRunner::new(vec![(0, "", ""), (0, "", ""), (0, "", ""), (0, "", "")]);
        let mgr = NetworkManager::with_runner(default_config(), Box::new(r));
        let a = mgr.attach("vm-determinism").unwrap();

        let r2 = ScriptedRunner::new(vec![(0, "", ""), (0, "", ""), (0, "", ""), (0, "", "")]);
        let mgr2 = NetworkManager::with_runner(default_config(), Box::new(r2));
        let b = mgr2.attach("vm-determinism").unwrap();

        assert_eq!(a.tap_name, b.tap_name);
        assert_eq!(a.guest_ip, b.guest_ip);
        assert_eq!(a.guest_mac, b.guest_mac);
        assert_eq!(a.gateway_ip, Ipv4Addr::new(172, 30, 0, 1));
        assert_eq!(a.netmask, Ipv4Addr::new(255, 255, 255, 0));
        assert!(a.tap_name.starts_with("tap-"));
        assert!(a.tap_name.len() <= 15);
        // Locally-administered unicast.
        assert_eq!(a.guest_mac[0] & 0x03, 0x02);
        // Allocated host address must not be .0, .1, or .255.
        assert_ne!(a.guest_ip, Ipv4Addr::new(172, 30, 0, 0));
        assert_ne!(a.guest_ip, Ipv4Addr::new(172, 30, 0, 1));
        assert_ne!(a.guest_ip, Ipv4Addr::new(172, 30, 0, 255));
    }

    #[test]
    fn attach_rejects_empty_vm_id() {
        let mgr =
            NetworkManager::with_runner(default_config(), Box::new(ScriptedRunner::default()));
        assert!(matches!(
            mgr.attach("").unwrap_err(),
            VmRuntimeError::NetworkConfig(_)
        ));
    }

    #[test]
    fn detach_rejects_empty_vm_id() {
        let mgr =
            NetworkManager::with_runner(default_config(), Box::new(ScriptedRunner::default()));
        assert!(matches!(
            mgr.detach("").unwrap_err(),
            VmRuntimeError::NetworkConfig(_)
        ));
    }

    #[test]
    fn ensure_host_runs_full_sequence() {
        // 1. ip link show <bridge> → fail (missing)
        // 2. ip link add name <bridge> type bridge → ok
        // 3. ip -4 addr show dev <bridge> → ok (empty)
        // 4. ip addr add <cidr> dev <bridge> → ok
        // 5. ip link set dev <bridge> up → ok
        // 6. iptables -t nat -C ... → fail
        // 7. iptables -t nat -A ... → ok
        // 8. iptables -C FORWARD -i br -o egress -j ACCEPT → fail
        // 9. iptables -A FORWARD -i br -o egress -j ACCEPT → ok
        // 10. iptables -C FORWARD -i egress -o br -j ACCEPT → fail
        // 11. iptables -A FORWARD -i egress -o br -j ACCEPT → ok
        let r = ScriptedRunner::new(vec![
            (1, "", "Device not found"),
            (0, "", ""),
            (0, "", ""),
            (0, "", ""),
            (0, "", ""),
            (1, "", "No such rule"),
            (0, "", ""),
            (1, "", "No such rule"),
            (0, "", ""),
            (1, "", "No such rule"),
            (0, "", ""),
        ]);
        let mgr = NetworkManager::with_runner(default_config(), Box::new(r));
        mgr.ensure_host().unwrap();
    }

    #[test]
    fn ensure_host_is_idempotent_when_everything_present() {
        // 1. ip link show ok
        // 2. ip -4 addr show ok (contains gateway cidr)
        // 3. ip link set up ok
        // 4. iptables -t nat -C ok
        // 5. iptables -C FORWARD ... ok
        // 6. iptables -C FORWARD ... ok
        let r = ScriptedRunner::new(vec![
            (0, "", ""),
            (
                0,
                "inet 172.30.0.1/24 brd 172.30.0.255 scope global fcbr-test",
                "",
            ),
            (0, "", ""),
            (0, "", ""),
            (0, "", ""),
            (0, "", ""),
        ]);
        let mgr = NetworkManager::with_runner(default_config(), Box::new(r));
        mgr.ensure_host().unwrap();
    }

    #[test]
    fn attach_then_detach_drives_expected_commands() {
        // attach: ip link show (fail), ip tuntap add (ok), ip link set mtu (ok),
        //         ip link set master (ok), ip link set up (ok)
        // detach: ip link show (ok), ip link set nomaster (ok),
        //         ip link set down (ok), ip link delete (ok)
        let r = ScriptedRunner::new(vec![
            (1, "", "Device does not exist"),
            (0, "", ""),
            (0, "", ""),
            (0, "", ""),
            (0, "", ""),
            (0, "", ""),
            (0, "", ""),
            (0, "", ""),
            (0, "", ""),
        ]);
        let mgr = NetworkManager::with_runner(default_config(), Box::new(r));
        let net = mgr.attach("vm-flow").unwrap();
        mgr.detach("vm-flow").unwrap();
        assert_eq!(net.tap_name, alloc::tap_name_for("vm-flow"));
    }

    // Integration tests against the real kernel. Require root + NET_ADMIN
    // and a host with `ip(8)` and `iptables(8)`. Run with:
    //
    //     sudo -E cargo +1.91 test --all-features -- --ignored network_integration
    //
    // These create and tear down a uniquely-named bridge / TAP per test run;
    // a manual cleanup script: `ip link delete fcbr-it-microvm; ip link
    // delete tap-<hash>` if a test panics mid-flight.
    #[test]
    #[ignore = "requires root + NET_ADMIN; run with --ignored network_integration"]
    fn network_integration_ensure_attach_detach() {
        let cfg = NetworkConfig::new("fcbr-it-microvm", "172.31.99.0/24", "lo", 1500).unwrap();
        let mgr = NetworkManager::new(cfg);
        mgr.ensure_host().expect("ensure_host");
        let net = mgr.attach("it-vm-1").expect("attach");
        assert!(net.tap_name.starts_with("tap-"));
        mgr.detach("it-vm-1").expect("detach");
        // detach is idempotent
        mgr.detach("it-vm-1").expect("detach idempotent");
    }
}
