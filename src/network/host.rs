use std::ffi::OsStr;
use std::process::{Command, Output};

use crate::error::{VmRuntimeError, VmRuntimeResult};

/// Outcome of a host shell-out.
#[derive(Debug)]
pub(crate) struct CommandOutcome {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl From<Output> for CommandOutcome {
    fn from(o: Output) -> Self {
        Self {
            status: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        }
    }
}

impl CommandOutcome {
    pub(crate) fn is_success(&self) -> bool {
        self.status == 0
    }
}

/// `Runner` is the seam between the network manager and the host.
///
/// Production code uses [`SystemRunner`] which invokes real `ip`/`iptables`
/// binaries. Tests can substitute a fake to assert command shape without
/// touching the kernel.
pub(crate) trait Runner: Send + Sync {
    fn run(&self, program: &str, args: &[&str]) -> VmRuntimeResult<CommandOutcome>;
}

#[derive(Debug, Default)]
pub(crate) struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, program: &str, args: &[&str]) -> VmRuntimeResult<CommandOutcome> {
        let os_args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
        let output = Command::new(program).args(&os_args).output().map_err(|e| {
            VmRuntimeError::NetworkSetup(format!(
                "failed to spawn `{program} {}`: {e}",
                args.join(" ")
            ))
        })?;
        Ok(CommandOutcome::from(output))
    }
}

/// Map a non-zero command exit to a `NetworkSetup` error, capturing stdout
/// and stderr for diagnosability. Returns `Ok(outcome)` on success.
pub(crate) fn require_success(
    program: &str,
    args: &[&str],
    outcome: CommandOutcome,
) -> VmRuntimeResult<CommandOutcome> {
    if outcome.is_success() {
        return Ok(outcome);
    }
    Err(VmRuntimeError::NetworkSetup(format!(
        "`{program} {}` exited with status {} (stdout={:?}, stderr={:?})",
        args.join(" "),
        outcome.status,
        outcome.stdout.trim(),
        outcome.stderr.trim(),
    )))
}

/// Idempotently bring up the host bridge with the given gateway address and prefix.
pub(crate) fn ensure_bridge(
    runner: &dyn Runner,
    bridge: &str,
    gateway_cidr: &str,
) -> VmRuntimeResult<()> {
    let show = runner.run("ip", &["link", "show", "dev", bridge])?;
    if !show.is_success() {
        let args = ["link", "add", "name", bridge, "type", "bridge"];
        let out = runner.run("ip", &args)?;
        require_success("ip", &args, out)?;
    }

    let addr_show_args = ["-4", "addr", "show", "dev", bridge];
    let addr_show = runner.run("ip", &addr_show_args)?;
    if !addr_show.is_success() {
        return Err(VmRuntimeError::NetworkSetup(format!(
            "`ip {}` exited with status {} (stderr={:?})",
            addr_show_args.join(" "),
            addr_show.status,
            addr_show.stderr.trim(),
        )));
    }
    if !addr_show.stdout.contains(gateway_cidr) {
        let args = ["addr", "add", gateway_cidr, "dev", bridge];
        let out = runner.run("ip", &args)?;
        // Treat "File exists" / EEXIST as success — another caller raced us.
        if !out.is_success() && !is_already_exists(&out.stderr) {
            return Err(VmRuntimeError::NetworkSetup(format!(
                "`ip addr add {gateway_cidr} dev {bridge}` exited with status {} (stderr={:?})",
                out.status,
                out.stderr.trim(),
            )));
        }
    }

    let up_args = ["link", "set", "dev", bridge, "up"];
    let out = runner.run("ip", &up_args)?;
    require_success("ip", &up_args, out)?;
    Ok(())
}

/// Install `iptables -t nat -A POSTROUTING -s <subnet> -o <egress> -j MASQUERADE`
/// if not already present.
pub(crate) fn ensure_nat(runner: &dyn Runner, subnet: &str, egress: &str) -> VmRuntimeResult<()> {
    let check = [
        "-t",
        "nat",
        "-C",
        "POSTROUTING",
        "-s",
        subnet,
        "-o",
        egress,
        "-j",
        "MASQUERADE",
    ];
    if runner.run("iptables", &check)?.is_success() {
        return Ok(());
    }
    let add = [
        "-t",
        "nat",
        "-A",
        "POSTROUTING",
        "-s",
        subnet,
        "-o",
        egress,
        "-j",
        "MASQUERADE",
    ];
    let out = runner.run("iptables", &add)?;
    require_success("iptables", &add, out)?;
    Ok(())
}

/// Install bidirectional FORWARD ACCEPT between `bridge` and `egress`. Idempotent.
pub(crate) fn ensure_forward(
    runner: &dyn Runner,
    bridge: &str,
    egress: &str,
) -> VmRuntimeResult<()> {
    let pairs: [[&str; 6]; 2] = [
        ["FORWARD", "-i", bridge, "-o", egress, "-j"],
        ["FORWARD", "-i", egress, "-o", bridge, "-j"],
    ];
    // Established/related reverse direction is included via the second rule
    // pair (egress -> bridge) because we want any tenant-initiated flow to
    // get replies regardless of conntrack state — Firecracker VMs do their
    // own per-VM filtering at the guest level, and Phase 2 will add
    // per-tenant egress chains.
    for prefix in pairs {
        let check: [&str; 7] = [
            prefix[0], prefix[1], prefix[2], prefix[3], prefix[4], prefix[5], "ACCEPT",
        ];
        let mut check_args = vec!["-C"];
        check_args.extend(check.iter().copied());
        if runner.run("iptables", &check_args)?.is_success() {
            continue;
        }
        let mut add_args = vec!["-A"];
        add_args.extend(check.iter().copied());
        let out = runner.run("iptables", &add_args)?;
        require_success("iptables", &add_args, out)?;
    }
    Ok(())
}

/// Create a TAP device, configure MTU, bring it up, and attach to `bridge`.
/// Idempotent on "already exists" — reuses the device.
pub(crate) fn create_tap(
    runner: &dyn Runner,
    tap: &str,
    bridge: &str,
    mtu: u32,
) -> VmRuntimeResult<()> {
    let show = runner.run("ip", &["link", "show", "dev", tap])?;
    if !show.is_success() {
        let args = ["tuntap", "add", "dev", tap, "mode", "tap"];
        let out = runner.run("ip", &args)?;
        if !out.is_success() && !is_already_exists(&out.stderr) {
            return Err(VmRuntimeError::NetworkSetup(format!(
                "`ip tuntap add dev {tap} mode tap` exited with status {} (stderr={:?})",
                out.status,
                out.stderr.trim(),
            )));
        }
    }

    let mtu_str = mtu.to_string();
    let mtu_args = ["link", "set", "dev", tap, "mtu", &mtu_str];
    let out = runner.run("ip", &mtu_args)?;
    require_success("ip", &mtu_args, out)?;

    let master_args = ["link", "set", "dev", tap, "master", bridge];
    let out = runner.run("ip", &master_args)?;
    require_success("ip", &master_args, out)?;

    let up_args = ["link", "set", "dev", tap, "up"];
    let out = runner.run("ip", &up_args)?;
    require_success("ip", &up_args, out)?;
    Ok(())
}

/// Delete a TAP device. Idempotent — missing device is success.
pub(crate) fn delete_tap(runner: &dyn Runner, tap: &str) -> VmRuntimeResult<()> {
    let show = runner.run("ip", &["link", "show", "dev", tap])?;
    if !show.is_success() {
        return Ok(());
    }
    let _ = runner.run("ip", &["link", "set", "dev", tap, "nomaster"])?;
    let _ = runner.run("ip", &["link", "set", "dev", tap, "down"])?;
    let del_args = ["link", "delete", "dev", tap];
    let out = runner.run("ip", &del_args)?;
    if out.is_success() || is_no_such_device(&out.stderr) {
        return Ok(());
    }
    let tuntap_args = ["tuntap", "del", "dev", tap, "mode", "tap"];
    let out2 = runner.run("ip", &tuntap_args)?;
    if out2.is_success() || is_no_such_device(&out2.stderr) {
        return Ok(());
    }
    Err(VmRuntimeError::NetworkSetup(format!(
        "failed to delete tap `{tap}`: link-del stderr={:?}, tuntap-del stderr={:?}",
        out.stderr.trim(),
        out2.stderr.trim(),
    )))
}

fn is_already_exists(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    s.contains("file exists") || s.contains("already exists") || s.contains("exists")
}

fn is_no_such_device(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    s.contains("does not exist") || s.contains("cannot find") || s.contains("no such")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeRunner {
        calls: Mutex<Vec<Vec<String>>>,
        scripted: Mutex<Vec<CommandOutcome>>,
    }

    impl FakeRunner {
        fn with_script(outcomes: Vec<CommandOutcome>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                scripted: Mutex::new(outcomes),
            }
        }
        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl Runner for FakeRunner {
        fn run(&self, program: &str, args: &[&str]) -> VmRuntimeResult<CommandOutcome> {
            let mut record = vec![program.to_string()];
            record.extend(args.iter().map(|s| s.to_string()));
            self.calls.lock().unwrap().push(record);
            let mut scripted = self.scripted.lock().unwrap();
            if scripted.is_empty() {
                Ok(CommandOutcome {
                    status: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            } else {
                Ok(scripted.remove(0))
            }
        }
    }

    fn ok() -> CommandOutcome {
        CommandOutcome {
            status: 0,
            stdout: String::new(),
            stderr: String::new(),
        }
    }
    fn fail(stderr: &str) -> CommandOutcome {
        CommandOutcome {
            status: 1,
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }

    #[test]
    fn require_success_captures_streams() {
        let outcome = CommandOutcome {
            status: 2,
            stdout: "boom-out".into(),
            stderr: "boom-err".into(),
        };
        let err = require_success("ip", &["link"], outcome).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("status 2"), "msg={msg}");
        assert!(msg.contains("boom-out"), "msg={msg}");
        assert!(msg.contains("boom-err"), "msg={msg}");
    }

    #[test]
    fn ensure_bridge_creates_when_missing() {
        // Scripted: show=fail (missing) → add (ok) → addr show (ok, empty) → addr add (ok) → up (ok)
        let runner = FakeRunner::with_script(vec![fail("not found"), ok(), ok(), ok(), ok()]);
        ensure_bridge(&runner, "fcbr0", "172.30.0.1/24").unwrap();
        let calls = runner.calls();
        assert_eq!(calls[0][1], "link");
        assert_eq!(calls[1][1..3], ["link", "add"]);
        assert!(calls[1].contains(&"fcbr0".to_string()));
        assert!(calls[3].contains(&"172.30.0.1/24".to_string()));
        assert_eq!(
            calls.last().unwrap()[1..],
            ["link", "set", "dev", "fcbr0", "up"]
        );
    }

    #[test]
    fn ensure_bridge_skips_create_when_present() {
        // show=ok (exists) → addr show ok with gateway present → up (ok)
        let runner = FakeRunner::with_script(vec![
            ok(),
            CommandOutcome {
                status: 0,
                stdout: "inet 172.30.0.1/24 ...".into(),
                stderr: String::new(),
            },
            ok(),
        ]);
        ensure_bridge(&runner, "fcbr0", "172.30.0.1/24").unwrap();
        let calls = runner.calls();
        assert_eq!(calls.len(), 3, "expected exactly 3 calls, got {calls:?}");
        assert!(
            !calls
                .iter()
                .any(|c| c.contains(&"add".to_string()) && c.contains(&"bridge".to_string()))
        );
    }

    #[test]
    fn ensure_nat_skips_when_present() {
        let runner = FakeRunner::with_script(vec![ok()]);
        ensure_nat(&runner, "172.30.0.0/24", "eth0").unwrap();
        assert_eq!(runner.calls().len(), 1);
        assert_eq!(runner.calls()[0][0], "iptables");
        assert!(runner.calls()[0].contains(&"-C".to_string()));
    }

    #[test]
    fn ensure_nat_inserts_when_missing() {
        let runner = FakeRunner::with_script(vec![fail("does not exist"), ok()]);
        ensure_nat(&runner, "172.30.0.0/24", "eth0").unwrap();
        let calls = runner.calls();
        assert_eq!(calls.len(), 2);
        assert!(calls[1].contains(&"-A".to_string()));
        assert!(calls[1].contains(&"MASQUERADE".to_string()));
    }

    #[test]
    fn ensure_forward_inserts_both_directions() {
        let runner = FakeRunner::with_script(vec![fail("missing"), ok(), fail("missing"), ok()]);
        ensure_forward(&runner, "fcbr0", "eth0").unwrap();
        let calls = runner.calls();
        assert_eq!(calls.len(), 4);
        assert!(calls[1].contains(&"-A".to_string()));
        assert!(calls[3].contains(&"-A".to_string()));
    }

    #[test]
    fn create_tap_skips_create_when_present() {
        let runner = FakeRunner::with_script(vec![ok(), ok(), ok(), ok()]);
        create_tap(&runner, "tap-abc", "fcbr0", 1500).unwrap();
        let calls = runner.calls();
        // show, set mtu, set master, set up
        assert_eq!(calls.len(), 4);
        assert!(!calls.iter().any(|c| c.contains(&"tuntap".to_string())));
        assert!(calls[1].contains(&"mtu".to_string()));
        assert!(calls[1].contains(&"1500".to_string()));
    }

    #[test]
    fn create_tap_creates_when_missing() {
        let runner = FakeRunner::with_script(vec![fail("missing"), ok(), ok(), ok(), ok()]);
        create_tap(&runner, "tap-abc", "fcbr0", 1500).unwrap();
        let calls = runner.calls();
        assert_eq!(calls.len(), 5);
        assert!(calls[1].contains(&"tuntap".to_string()));
        assert!(calls[1].contains(&"add".to_string()));
    }

    #[test]
    fn delete_tap_is_noop_when_missing() {
        let runner = FakeRunner::with_script(vec![fail("no such device")]);
        delete_tap(&runner, "tap-gone").unwrap();
        assert_eq!(runner.calls().len(), 1);
    }

    #[test]
    fn delete_tap_uses_link_delete_first() {
        let runner = FakeRunner::with_script(vec![ok(), ok(), ok(), ok()]);
        delete_tap(&runner, "tap-abc").unwrap();
        let calls = runner.calls();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[3][1..], ["link", "delete", "dev", "tap-abc"]);
    }

    #[test]
    fn delete_tap_falls_back_to_tuntap_del() {
        let runner = FakeRunner::with_script(vec![
            ok(),
            ok(),
            ok(),
            fail("operation not supported"),
            ok(),
        ]);
        delete_tap(&runner, "tap-abc").unwrap();
        let calls = runner.calls();
        assert_eq!(calls.len(), 5);
        assert!(calls[4].contains(&"tuntap".to_string()));
        assert!(calls[4].contains(&"del".to_string()));
    }

    #[test]
    fn delete_tap_surfaces_unexpected_error() {
        let runner = FakeRunner::with_script(vec![
            ok(),
            ok(),
            ok(),
            fail("permission denied"),
            fail("permission denied"),
        ]);
        let err = delete_tap(&runner, "tap-abc").unwrap_err();
        assert!(err.to_string().contains("permission denied"));
    }
}
