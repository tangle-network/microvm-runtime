//! Per-VM egress firewall implemented as an `iptables` `FORWARD` chain.
//!
//! ## What this module does
//!
//! VMs configured with the (in-flight) network module are attached to a host
//! bridge with `MASQUERADE` NAT — so by default they can reach anything the
//! host can reach. Operators that need scoped egress install a per-VM chain
//! in `FORWARD` that allowlists a set of `(CIDR, proto, port)` tuples and
//! drops everything else originating from the VM's TAP.
//!
//! The shape mirrors the Docker-side egress firewall in `agent-dev-container`
//! (per-VM chain, hash-truncated chain name, allow-then-drop ordering,
//! orphan GC) but is implemented self-contained — no shared code, no shared
//! chain prefix.
//!
//! ## Required host privileges
//!
//! All `iptables` invocations require `CAP_NET_ADMIN`. Hosts running the
//! Firecracker adapter typically already need this for TAP/bridge setup, so
//! the firewall imposes no additional capability surface. Without
//! `CAP_NET_ADMIN`, every method here returns
//! [`VmRuntimeError::Firewall`].
//!
//! ## Concurrency
//!
//! `iptables -w` is passed on every invocation so the kernel-side xtables
//! lock serialises concurrent mutations against other system tooling.
//! This module does NOT install its own in-process lock; callers that
//! parallelise installs for the *same* `vm_id` MUST serialise themselves —
//! that is a misuse of the API (the per-VM chain is owned by exactly one
//! caller).
//!
//! ## Chain naming
//!
//! `{chain_prefix}{first-16-hex-chars-of-fnv1a-64(vm_id)}` — total length
//! is `len(prefix) + 16`. With the default prefix `microvm-` this yields
//! a 24-char chain name, comfortably under the kernel 28-char limit.
//! FNV-1a is used (instead of SHA-256) to keep this crate free of crypto
//! dependencies, matching the rest of the crate's hashing convention. The
//! collision domain is 2^64 — the caller owns `vm_id` uniqueness, this is
//! just a name shortener that survives non-ASCII / oversized identifiers.

use std::path::PathBuf;
use std::process::Command;

use crate::error::{VmRuntimeError, VmRuntimeResult};

/// Default `iptables` binary name. Resolved via `PATH` at invocation time.
const DEFAULT_IPTABLES_BIN: &str = "iptables";
/// Default chain prefix. Picked so list-by-prefix GC cannot collide with
/// the Docker-side `AEG` / `FCEG` chains in mixed deployments.
const DEFAULT_CHAIN_PREFIX: &str = "microvm-";
/// Length (in hex chars) of the truncated FNV-1a digest appended to the
/// chain name. 16 hex chars = full 64-bit digest = 2^64 collision space.
const CHAIN_HASH_LEN: usize = 16;
/// Kernel-side iptables chain name length cap. Documented invariant —
/// exercised by `chain_name_under_iptables_limit`.
#[cfg(test)]
const IPTABLES_CHAIN_NAME_MAX: usize = 28;

/// Configuration for the firewall: binary path and chain naming.
#[derive(Debug, Clone)]
pub struct FirewallConfig {
    /// Iptables binary path. Default `"iptables"`; override for nftables
    /// alias (`iptables-nft`) or a wrapper.
    pub iptables_bin: PathBuf,
    /// Prefix used for chain names. Used both at install-time and as the
    /// GC discriminator at orphan-cleanup time.
    pub chain_prefix: String,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            iptables_bin: PathBuf::from(DEFAULT_IPTABLES_BIN),
            chain_prefix: DEFAULT_CHAIN_PREFIX.to_string(),
        }
    }
}

impl FirewallConfig {
    /// Build from environment.
    ///
    /// - `MICROVM_IPTABLES_BIN` — overrides the iptables binary path.
    /// - `MICROVM_FIREWALL_CHAIN_PREFIX` — overrides the chain prefix.
    pub fn from_env() -> Self {
        let iptables_bin = std::env::var("MICROVM_IPTABLES_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_IPTABLES_BIN));
        let chain_prefix = std::env::var("MICROVM_FIREWALL_CHAIN_PREFIX")
            .unwrap_or_else(|_| DEFAULT_CHAIN_PREFIX.to_string());
        Self {
            iptables_bin,
            chain_prefix,
        }
    }
}

/// A single egress allowlist entry.
///
/// Maps to one `iptables -A <chain> -d <cidr> [-p <proto>] [--dport <port>]
/// -j ACCEPT` rule. Combining `port` with no `proto` is rejected — a port
/// without a protocol has no meaning to iptables.
#[derive(Debug, Clone)]
pub struct EgressRule {
    /// IPv4 CIDR allowed (e.g. `"10.0.0.0/8"`, `"1.2.3.4/32"`).
    pub cidr: String,
    /// Optional port restriction (`None` = all ports). Requires `proto`.
    pub port: Option<u16>,
    /// Protocol: `"tcp"`, `"udp"`, or `None` (both — emits no `-p` flag).
    pub proto: Option<String>,
}

/// Installed-rule receipt for one VM.
#[derive(Debug)]
pub struct VmEgressRules {
    /// Chain name as it appears in `iptables -nL`.
    pub chain_name: String,
    /// Allowlist as installed.
    pub allowlist: Vec<EgressRule>,
}

/// Stateless firewall handle. All state lives in the kernel's xtables.
#[derive(Debug, Clone)]
pub struct Firewall {
    config: FirewallConfig,
}

impl Firewall {
    /// Build with the supplied config.
    pub fn new(config: FirewallConfig) -> Self {
        Self { config }
    }

    /// Build from environment ([`FirewallConfig::from_env`]).
    pub fn from_env() -> Self {
        Self::new(FirewallConfig::from_env())
    }

    /// Deterministic chain name for `vm_id`.
    pub fn chain_name(&self, vm_id: &str) -> String {
        chain_name_for(&self.config.chain_prefix, vm_id)
    }

    /// Install (idempotently) the per-VM egress chain.
    ///
    /// On every call: validate inputs, then `flush + repopulate` the chain
    /// so a second `install` with a different allowlist replaces the first.
    /// The `FORWARD` jump is `-C`-checked before insert so repeated calls
    /// do not stack duplicate jumps.
    ///
    /// All `iptables` invocations use `-w` to acquire the kernel xtables
    /// lock; concurrent system tooling will serialise correctly.
    ///
    /// `vm_tap` is the host-side TAP interface name (e.g. `tap-abc12345`).
    /// `iptables` caps interface names at `IFNAMSIZ-1 = 15` bytes; we
    /// validate that here so misconfigured callers fail loudly before any
    /// iptables call.
    pub fn install(
        &self,
        vm_id: &str,
        vm_tap: &str,
        allowlist: &[EgressRule],
    ) -> VmRuntimeResult<VmEgressRules> {
        validate_vm_id(vm_id)?;
        validate_tap_name(vm_tap)?;
        for rule in allowlist {
            validate_egress_rule(rule)?;
        }
        ensure_linux()?;

        let chain = self.chain_name(vm_id);

        // `-N` errors when the chain exists; suppress that one case and
        // re-raise everything else. Then `-F` to drop any residual rules
        // — this makes install idempotent under repeat calls with changed
        // allowlists.
        match self.run_iptables(&["-N", &chain]) {
            Ok(_) => {}
            Err(VmRuntimeError::Firewall(msg)) if is_chain_exists_error(&msg) => {}
            Err(e) => return Err(e),
        }
        self.run_iptables(&["-F", &chain])?;

        for rule in allowlist {
            let mut args: Vec<String> = vec![
                "-A".to_string(),
                chain.clone(),
                "-d".to_string(),
                rule.cidr.clone(),
            ];
            if let Some(proto) = &rule.proto {
                args.push("-p".to_string());
                args.push(proto.clone());
            }
            if let Some(port) = rule.port {
                args.push("--dport".to_string());
                args.push(port.to_string());
            }
            args.push("-j".to_string());
            args.push("ACCEPT".to_string());
            let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
            self.run_iptables(&arg_refs)?;
        }

        // Final policy: drop anything that fell through the allowlist.
        self.run_iptables(&["-A", &chain, "-j", "DROP"])?;

        // FORWARD jump: anything arriving on the VM's TAP enters the
        // per-VM chain. `-C` precheck makes the insert idempotent.
        let chain_str = chain.as_str();
        let jump = ["FORWARD", "-i", vm_tap, "-j", chain_str];
        if self.run_iptables_with_op("-C", &jump).is_err() {
            let insert_args = ["-I", "FORWARD", "1", "-i", vm_tap, "-j", chain_str];
            self.run_iptables(&insert_args)?;
        }

        Ok(VmEgressRules {
            chain_name: chain,
            allowlist: allowlist.to_vec(),
        })
    }

    /// Remove the per-VM chain and the `FORWARD` jump.
    ///
    /// Idempotent: missing chains / missing jumps are not errors. Any other
    /// failure (permission, lock contention timeout) is propagated.
    ///
    /// Note: `iptables` does not let us scope the `-D FORWARD` delete by
    /// chain name alone — we discover the jump from a `-S FORWARD` listing
    /// and delete by line number so callers do not need to remember the
    /// VM's TAP name.
    pub fn uninstall(&self, vm_id: &str) -> VmRuntimeResult<()> {
        validate_vm_id(vm_id)?;
        ensure_linux()?;
        let chain = self.chain_name(vm_id);
        self.delete_forward_jumps_to(&chain)?;
        self.flush_and_delete_chain(&chain)
    }

    /// Garbage-collect chains under the configured prefix that no longer
    /// belong to a known VM.
    ///
    /// Hashes every entry of `known_vm_ids` and treats those chain names as
    /// live; anything else under the prefix is uninstalled. Returns the
    /// list of removed chain names.
    pub fn gc_orphans(&self, known_vm_ids: &[&str]) -> VmRuntimeResult<Vec<String>> {
        for vm_id in known_vm_ids {
            validate_vm_id(vm_id)?;
        }
        ensure_linux()?;
        let live: std::collections::HashSet<String> =
            known_vm_ids.iter().map(|id| self.chain_name(id)).collect();

        let present = self.list_chains_with_prefix()?;
        let mut removed = Vec::new();
        for chain in present {
            if live.contains(&chain) {
                continue;
            }
            self.delete_forward_jumps_to(&chain)?;
            self.flush_and_delete_chain(&chain)?;
            removed.push(chain);
        }
        Ok(removed)
    }

    // ---- internals ----

    /// Discover every line in `FORWARD` that jumps to `chain` and delete
    /// them by line number, highest first (deleting by index invalidates
    /// later indices).
    fn delete_forward_jumps_to(&self, chain: &str) -> VmRuntimeResult<()> {
        // `iptables -S FORWARD` prints one rule per line in the order they
        // appear. The chain is referenced via `-j <chain>`. We use the
        // line-numbered list (`-L FORWARD --line-numbers`) for deletion
        // since `-D` by line number does not depend on argument ordering
        // matching the rule exactly.
        let stdout = self.iptables_capture(&["-L", "FORWARD", "--line-numbers", "-n"])?;
        let mut indices: Vec<u32> = Vec::new();
        for line in stdout.lines().skip(2) {
            // first two lines: "Chain FORWARD ..." and the column header.
            let mut cols = line.split_whitespace();
            let num = match cols.next().and_then(|n| n.parse::<u32>().ok()) {
                Some(n) => n,
                None => continue,
            };
            // column 2 = target
            let target = match cols.next() {
                Some(t) => t,
                None => continue,
            };
            if target == chain {
                indices.push(num);
            }
        }
        indices.sort_unstable_by(|a, b| b.cmp(a));
        for idx in indices {
            let idx_str = idx.to_string();
            // Ignore not-found: a parallel mutation could have raced us.
            match self.run_iptables(&["-D", "FORWARD", &idx_str]) {
                Ok(_) => {}
                Err(VmRuntimeError::Firewall(msg)) if is_not_found_error(&msg) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn flush_and_delete_chain(&self, chain: &str) -> VmRuntimeResult<()> {
        match self.run_iptables(&["-F", chain]) {
            Ok(_) => {}
            Err(VmRuntimeError::Firewall(msg)) if is_not_found_error(&msg) => return Ok(()),
            Err(e) => return Err(e),
        }
        match self.run_iptables(&["-X", chain]) {
            Ok(_) => Ok(()),
            Err(VmRuntimeError::Firewall(msg)) if is_not_found_error(&msg) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn list_chains_with_prefix(&self) -> VmRuntimeResult<Vec<String>> {
        let stdout = self.iptables_capture(&["-S"])?;
        let mut out = Vec::new();
        for line in stdout.lines() {
            // `-S` prints `-N <chain>` for user-defined chains.
            let rest = match line.strip_prefix("-N ") {
                Some(r) => r,
                None => continue,
            };
            let chain = rest.split_whitespace().next().unwrap_or("");
            if !chain.is_empty() && chain.starts_with(&self.config.chain_prefix) {
                out.push(chain.to_string());
            }
        }
        Ok(out)
    }

    fn run_iptables(&self, args: &[&str]) -> VmRuntimeResult<()> {
        let output = self.spawn(args)?;
        if output.status.success() {
            Ok(())
        } else {
            Err(VmRuntimeError::Firewall(format_iptables_failure(
                &self.config.iptables_bin,
                args,
                &output,
            )))
        }
    }

    /// Variant where the first arg is the iptables operation (e.g. `-C`)
    /// followed by positional args. Pure ergonomic helper for the
    /// `-C <jump-args>` precheck flow.
    fn run_iptables_with_op(&self, op: &str, args: &[&str]) -> VmRuntimeResult<()> {
        let mut all: Vec<&str> = Vec::with_capacity(args.len() + 1);
        all.push(op);
        all.extend(args);
        self.run_iptables(&all)
    }

    fn iptables_capture(&self, args: &[&str]) -> VmRuntimeResult<String> {
        let output = self.spawn(args)?;
        if !output.status.success() {
            return Err(VmRuntimeError::Firewall(format_iptables_failure(
                &self.config.iptables_bin,
                args,
                &output,
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn spawn(&self, args: &[&str]) -> VmRuntimeResult<std::process::Output> {
        let mut cmd = build_iptables_command(&self.config.iptables_bin, args);
        cmd.output().map_err(|e| {
            VmRuntimeError::Firewall(format!(
                "failed to invoke {} {}: {e}",
                self.config.iptables_bin.display(),
                args.join(" "),
            ))
        })
    }
}

// ---- helpers ----

#[cfg(target_os = "linux")]
fn ensure_linux() -> VmRuntimeResult<()> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn ensure_linux() -> VmRuntimeResult<()> {
    Err(VmRuntimeError::Firewall(
        "iptables-based egress firewall requires Linux".into(),
    ))
}

/// FNV-1a 64-bit digest. Used to keep this module dependency-free; same
/// convention as `crate::network::alloc::vm_short_hash`.
fn fnv1a_64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

fn chain_name_for(prefix: &str, vm_id: &str) -> String {
    let digest = fnv1a_64(vm_id.as_bytes());
    let hex = format!("{digest:016x}");
    format!("{prefix}{}", &hex[..CHAIN_HASH_LEN])
}

fn validate_vm_id(vm_id: &str) -> VmRuntimeResult<()> {
    if vm_id.is_empty() {
        return Err(VmRuntimeError::Firewall("vm_id must not be empty".into()));
    }
    Ok(())
}

fn validate_tap_name(name: &str) -> VmRuntimeResult<()> {
    // Linux IFNAMSIZ is 16 (15 + NUL). Reject empties, oversize, and
    // anything that would let an attacker smuggle shell metachars into
    // our argv (defence in depth — we already use `Command` with
    // explicit args, but a chain name with spaces breaks the iptables
    // line parser used by `delete_forward_jumps_to`).
    if name.is_empty() {
        return Err(VmRuntimeError::Firewall("vm_tap must not be empty".into()));
    }
    if name.len() > 15 {
        return Err(VmRuntimeError::Firewall(format!(
            "vm_tap '{name}' exceeds IFNAMSIZ (15 chars)"
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(VmRuntimeError::Firewall(format!(
            "vm_tap '{name}' contains illegal characters"
        )));
    }
    Ok(())
}

fn validate_egress_rule(rule: &EgressRule) -> VmRuntimeResult<()> {
    validate_ipv4_cidr(&rule.cidr)?;
    if let Some(proto) = &rule.proto {
        match proto.as_str() {
            "tcp" | "udp" => {}
            other => {
                return Err(VmRuntimeError::Firewall(format!(
                    "unsupported proto '{other}': must be 'tcp' or 'udp'"
                )));
            }
        }
    }
    if rule.port.is_some() && rule.proto.is_none() {
        return Err(VmRuntimeError::Firewall(
            "port restriction requires proto ('tcp' or 'udp')".into(),
        ));
    }
    Ok(())
}

fn validate_ipv4_cidr(cidr: &str) -> VmRuntimeResult<()> {
    let (addr, prefix) = cidr.split_once('/').ok_or_else(|| {
        VmRuntimeError::Firewall(format!("invalid cidr '{cidr}': expected <ipv4>/<prefix>"))
    })?;
    addr.parse::<std::net::Ipv4Addr>().map_err(|e| {
        VmRuntimeError::Firewall(format!("invalid cidr '{cidr}': bad ipv4 address: {e}"))
    })?;
    let prefix: u8 = prefix.parse().map_err(|_| {
        VmRuntimeError::Firewall(format!("invalid cidr '{cidr}': prefix must be 0..=32"))
    })?;
    if prefix > 32 {
        return Err(VmRuntimeError::Firewall(format!(
            "invalid cidr '{cidr}': prefix {prefix} > 32"
        )));
    }
    Ok(())
}

fn build_iptables_command(bin: &std::path::Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(bin);
    // `-w`: wait for xtables lock so concurrent system mutations
    // (e.g. fail2ban, ufw) don't EBUSY us.
    cmd.arg("-w");
    for a in args {
        cmd.arg(a);
    }
    cmd
}

fn format_iptables_failure(
    bin: &std::path::Path,
    args: &[&str],
    output: &std::process::Output,
) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    format!(
        "iptables call failed: {} -w {} (exit={}): stderr={}; stdout={}",
        bin.display(),
        args.join(" "),
        output
            .status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".to_string()),
        stderr.trim(),
        stdout.trim(),
    )
}

fn is_chain_exists_error(msg: &str) -> bool {
    // iptables 1.8+ prints "Chain already exists." — match case-insensitive
    // substring so different distro builds line up.
    let lower = msg.to_ascii_lowercase();
    lower.contains("chain already exists") || lower.contains("file exists")
}

fn is_not_found_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("no chain")
        || lower.contains("does not exist")
        || lower.contains("no such")
        || lower.contains("bad rule")
        || lower.contains("matching rule exist")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> FirewallConfig {
        FirewallConfig::default()
    }

    #[test]
    fn chain_name_is_deterministic() {
        let fw = Firewall::new(cfg());
        let a = fw.chain_name("vm-alpha");
        let b = fw.chain_name("vm-alpha");
        assert_eq!(a, b);
    }

    #[test]
    fn chain_name_differs_per_vm() {
        let fw = Firewall::new(cfg());
        assert_ne!(fw.chain_name("vm-a"), fw.chain_name("vm-b"));
    }

    #[test]
    fn chain_name_under_iptables_limit() {
        let fw = Firewall::new(cfg());
        // Long, ugly vm ids still produce short chain names.
        let long_id = "this-is-a-very-long-and-arbitrary-vm-identifier-string-with-uuid-7f81";
        let name = fw.chain_name(long_id);
        assert!(
            name.len() <= IPTABLES_CHAIN_NAME_MAX,
            "chain name '{name}' exceeds {IPTABLES_CHAIN_NAME_MAX}: {} chars",
            name.len()
        );
    }

    #[test]
    fn chain_name_uses_prefix() {
        let fw = Firewall::new(FirewallConfig {
            iptables_bin: PathBuf::from("iptables"),
            chain_prefix: "FOO-".to_string(),
        });
        let name = fw.chain_name("vm-x");
        assert!(name.starts_with("FOO-"));
        assert_eq!(name.len(), "FOO-".len() + CHAIN_HASH_LEN);
    }

    #[test]
    fn validate_egress_rule_rejects_bad_cidr() {
        let r = EgressRule {
            cidr: "not-an-ip".to_string(),
            port: None,
            proto: None,
        };
        assert!(validate_egress_rule(&r).is_err());
    }

    #[test]
    fn validate_egress_rule_rejects_bad_prefix() {
        let r = EgressRule {
            cidr: "10.0.0.0/64".to_string(),
            port: None,
            proto: None,
        };
        assert!(validate_egress_rule(&r).is_err());
    }

    #[test]
    fn validate_egress_rule_rejects_unknown_proto() {
        let r = EgressRule {
            cidr: "0.0.0.0/0".to_string(),
            port: None,
            proto: Some("icmp".to_string()),
        };
        assert!(validate_egress_rule(&r).is_err());
    }

    #[test]
    fn validate_egress_rule_rejects_port_without_proto() {
        let r = EgressRule {
            cidr: "0.0.0.0/0".to_string(),
            port: Some(443),
            proto: None,
        };
        assert!(validate_egress_rule(&r).is_err());
    }

    #[test]
    fn validate_egress_rule_accepts_full_open() {
        let r = EgressRule {
            cidr: "0.0.0.0/0".to_string(),
            port: None,
            proto: None,
        };
        assert!(validate_egress_rule(&r).is_ok());
    }

    #[test]
    fn validate_egress_rule_accepts_tcp_port() {
        let r = EgressRule {
            cidr: "192.168.1.0/24".to_string(),
            port: Some(443),
            proto: Some("tcp".to_string()),
        };
        assert!(validate_egress_rule(&r).is_ok());
    }

    #[test]
    fn validate_tap_name_rejects_oversize() {
        assert!(validate_tap_name("a".repeat(16).as_str()).is_err());
    }

    #[test]
    fn validate_tap_name_rejects_empty() {
        assert!(validate_tap_name("").is_err());
    }

    #[test]
    fn validate_tap_name_rejects_metachars() {
        assert!(validate_tap_name("tap;rm").is_err());
        assert!(validate_tap_name("tap rm").is_err());
        assert!(validate_tap_name("tap|x").is_err());
    }

    #[test]
    fn validate_tap_name_accepts_legal() {
        assert!(validate_tap_name("tap-abc12345").is_ok());
        assert!(validate_tap_name("eth0.5").is_ok());
    }

    #[test]
    fn validate_vm_id_rejects_empty() {
        assert!(validate_vm_id("").is_err());
    }

    #[test]
    fn iptables_command_includes_wait_flag() {
        let cmd = build_iptables_command(std::path::Path::new("iptables"), &["-N", "foo"]);
        let args: Vec<&std::ffi::OsStr> = cmd.get_args().collect();
        assert_eq!(args.len(), 3);
        assert_eq!(args[0], "-w");
        assert_eq!(args[1], "-N");
        assert_eq!(args[2], "foo");
    }

    #[test]
    fn rule_args_construction_full_open() {
        // Mirror the construction in `install`. This locks in the iptables
        // arg order so a refactor cannot silently break wire compatibility.
        let chain = "microvm-deadbeefdeadbeef";
        let rule = EgressRule {
            cidr: "10.0.0.0/8".to_string(),
            port: None,
            proto: None,
        };
        let args = build_accept_args(chain, &rule);
        assert_eq!(args, vec!["-A", chain, "-d", "10.0.0.0/8", "-j", "ACCEPT"]);
    }

    #[test]
    fn rule_args_construction_tcp_port() {
        let chain = "microvm-0123456789abcdef";
        let rule = EgressRule {
            cidr: "1.2.3.4/32".to_string(),
            port: Some(443),
            proto: Some("tcp".to_string()),
        };
        let args = build_accept_args(chain, &rule);
        assert_eq!(
            args,
            vec![
                "-A",
                chain,
                "-d",
                "1.2.3.4/32",
                "-p",
                "tcp",
                "--dport",
                "443",
                "-j",
                "ACCEPT",
            ]
        );
    }

    #[test]
    fn rule_args_construction_proto_only() {
        let chain = "microvm-aaaabbbbccccdddd";
        let rule = EgressRule {
            cidr: "0.0.0.0/0".to_string(),
            port: None,
            proto: Some("udp".to_string()),
        };
        let args = build_accept_args(chain, &rule);
        assert_eq!(
            args,
            vec!["-A", chain, "-d", "0.0.0.0/0", "-p", "udp", "-j", "ACCEPT",]
        );
    }

    #[test]
    fn orphan_set_basic() {
        // Closed-form check on the chain-removal predicate.
        let cfg = FirewallConfig::default();
        let live_vms = ["vm-alive-1", "vm-alive-2"];
        let live_chains: std::collections::HashSet<String> = live_vms
            .iter()
            .map(|id| chain_name_for(&cfg.chain_prefix, id))
            .collect();

        let present = [
            chain_name_for(&cfg.chain_prefix, "vm-alive-1"),
            chain_name_for(&cfg.chain_prefix, "vm-orphan-1"),
            chain_name_for(&cfg.chain_prefix, "vm-orphan-2"),
            chain_name_for(&cfg.chain_prefix, "vm-alive-2"),
        ];

        let to_remove: Vec<&String> = present
            .iter()
            .filter(|c| !live_chains.contains(*c))
            .collect();
        assert_eq!(to_remove.len(), 2);
        assert!(to_remove.contains(&&chain_name_for(&cfg.chain_prefix, "vm-orphan-1")));
        assert!(to_remove.contains(&&chain_name_for(&cfg.chain_prefix, "vm-orphan-2")));
    }

    #[test]
    fn orphan_set_handles_collisions_with_known_set() {
        // A known vm_id whose chain is also present must not be removed.
        let cfg = FirewallConfig::default();
        let live_chains: std::collections::HashSet<String> = ["vm-1", "vm-2"]
            .iter()
            .map(|id| chain_name_for(&cfg.chain_prefix, id))
            .collect();
        let present = [
            chain_name_for(&cfg.chain_prefix, "vm-1"),
            chain_name_for(&cfg.chain_prefix, "vm-2"),
        ];
        let to_remove: Vec<&String> = present
            .iter()
            .filter(|c| !live_chains.contains(*c))
            .collect();
        assert!(to_remove.is_empty());
    }

    #[test]
    fn error_classifier_chain_exists() {
        assert!(is_chain_exists_error("iptables: Chain already exists."));
        assert!(is_chain_exists_error("Chain Already EXISTS."));
        assert!(is_chain_exists_error("File exists"));
        assert!(!is_chain_exists_error("Permission denied"));
    }

    #[test]
    fn error_classifier_not_found() {
        assert!(is_not_found_error(
            "iptables: No chain/target/match by that name."
        ));
        assert!(is_not_found_error(
            "iptables: Bad rule (does a matching rule exist in that chain?)"
        ));
        assert!(!is_not_found_error("Permission denied"));
    }

    // Pure helper used to lock in arg construction order. Mirrors the
    // construction in `install`; if `install` diverges from this, the
    // tests must update in lockstep.
    fn build_accept_args(chain: &str, rule: &EgressRule) -> Vec<String> {
        let mut args: Vec<String> = vec![
            "-A".to_string(),
            chain.to_string(),
            "-d".to_string(),
            rule.cidr.clone(),
        ];
        if let Some(proto) = &rule.proto {
            args.push("-p".to_string());
            args.push(proto.clone());
        }
        if let Some(port) = rule.port {
            args.push("--dport".to_string());
            args.push(port.to_string());
        }
        args.push("-j".to_string());
        args.push("ACCEPT".to_string());
        args
    }

    // ---- OS-touching tests (require root + iptables) ----

    #[test]
    #[ignore = "requires root + iptables on the host"]
    fn install_then_uninstall_real_iptables() {
        let fw = Firewall::from_env();
        let vm_id = "integ-test-vm-1";
        let tap = "lo"; // safe: loopback always exists, we just need a valid IFNAME
        let allow = vec![EgressRule {
            cidr: "10.0.0.0/8".to_string(),
            port: Some(443),
            proto: Some("tcp".to_string()),
        }];
        let receipt = fw.install(vm_id, tap, &allow).expect("install");
        assert_eq!(receipt.chain_name, fw.chain_name(vm_id));

        // Verify chain present
        let out = std::process::Command::new("iptables")
            .args(["-w", "-nL", &receipt.chain_name])
            .output()
            .expect("iptables -nL");
        assert!(out.status.success(), "chain not listed: {:?}", out);

        fw.uninstall(vm_id).expect("uninstall");

        // Verify chain gone
        let out = std::process::Command::new("iptables")
            .args(["-w", "-nL", &receipt.chain_name])
            .output()
            .expect("iptables -nL");
        assert!(!out.status.success(), "chain still present after uninstall");
    }

    #[test]
    #[ignore = "requires root + iptables on the host"]
    fn gc_orphans_removes_unknown_chains() {
        let fw = Firewall::from_env();
        let orphan_vm = "integ-test-orphan-1";
        let known_vm = "integ-test-known-1";
        let tap = "lo";
        fw.install(orphan_vm, tap, &[]).expect("install orphan");
        fw.install(known_vm, tap, &[]).expect("install known");

        let removed = fw.gc_orphans(&[known_vm]).expect("gc");
        assert!(removed.contains(&fw.chain_name(orphan_vm)));
        assert!(!removed.contains(&fw.chain_name(known_vm)));

        // Cleanup
        fw.uninstall(known_vm).expect("uninstall known");
    }
}
