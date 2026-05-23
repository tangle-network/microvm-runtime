//! Graceful process shutdown with SIGTERM → poll → SIGKILL escalation.
//!
//! VM teardown via [`std::process::Child::kill`] sends `SIGKILL`, which gives
//! the guest no opportunity to flush state or finalize work. [`graceful_shutdown`]
//! sends `SIGTERM`, polls for exit up to a configurable grace window, and only
//! escalates to `SIGKILL` if the process refuses to exit in time. The child is
//! always reaped before this function returns.

use std::process::Child;
use std::thread;
use std::time::{Duration, Instant};

use crate::error::{VmRuntimeError, VmRuntimeResult};

/// Tunables for [`graceful_shutdown`].
#[derive(Debug, Clone, Copy)]
pub struct ShutdownConfig {
    /// How long to wait for graceful exit after SIGTERM before SIGKILL.
    pub grace_period: Duration,
    /// How often to poll `try_wait()` during the grace window.
    pub poll_interval: Duration,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            grace_period: Duration::from_millis(2_000),
            poll_interval: Duration::from_millis(50),
        }
    }
}

/// Outcome of a [`graceful_shutdown`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownOutcome {
    /// Process exited within the grace window after SIGTERM.
    Graceful,
    /// Process did not respond to SIGTERM; SIGKILL was issued.
    Forced,
    /// Process was already exited at call time.
    AlreadyExited,
}

/// Send `SIGTERM`, poll for exit up to `config.grace_period`, escalate to
/// `SIGKILL` on timeout. Always reaps the child (calls `wait()`) before
/// returning so callers cannot leak zombies.
///
/// Returns [`VmRuntimeError::Unsupported`] on non-Linux targets: there is no
/// portable way to deliver `SIGTERM` to a child via `std`, and the firecracker
/// adapter — the only production caller — only runs on Linux anyway.
pub fn graceful_shutdown(
    child: &mut Child,
    config: &ShutdownConfig,
) -> VmRuntimeResult<ShutdownOutcome> {
    // 1. Already-exited fast path. `try_wait` reaps the child on `Ok(Some(_))`.
    if child
        .try_wait()
        .map_err(|e| VmRuntimeError::Shutdown(format!("try_wait failed: {e}")))?
        .is_some()
    {
        return Ok(ShutdownOutcome::AlreadyExited);
    }

    // 2. SIGTERM. Linux-only — see function docs for rationale.
    #[cfg(target_os = "linux")]
    {
        send_sigterm(child)?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = child;
        return Err(VmRuntimeError::Unsupported(
            "graceful_shutdown requires linux for SIGTERM delivery".to_owned(),
        ));
    }

    // 3. Poll loop until grace_period elapses.
    #[cfg(target_os = "linux")]
    {
        let deadline = Instant::now() + config.grace_period;
        loop {
            if child
                .try_wait()
                .map_err(|e| VmRuntimeError::Shutdown(format!("try_wait failed: {e}")))?
                .is_some()
            {
                return Ok(ShutdownOutcome::Graceful);
            }
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let remaining = deadline.saturating_duration_since(now);
            thread::sleep(config.poll_interval.min(remaining));
        }

        // 4. Escalate to SIGKILL and reap.
        child
            .kill()
            .map_err(|e| VmRuntimeError::Shutdown(format!("SIGKILL failed: {e}")))?;
        child
            .wait()
            .map_err(|e| VmRuntimeError::Shutdown(format!("wait after SIGKILL failed: {e}")))?;
        Ok(ShutdownOutcome::Forced)
    }
}

#[cfg(target_os = "linux")]
fn send_sigterm(child: &Child) -> VmRuntimeResult<()> {
    // `child.id()` is `u32`; the kernel takes a signed pid. PIDs always fit in
    // `i32` on Linux (kernel.pid_max ceiling is < 2^22), so the cast is safe.
    let pid = child.id() as i32;
    // SAFETY: `libc::kill` is an FFI call with no Rust-side aliasing concerns;
    // it only inspects `pid` and `signum`. Non-zero return ⇒ failure, real
    // reason in `errno`.
    let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
    if rc != 0 {
        let errno = std::io::Error::last_os_error();
        return Err(VmRuntimeError::Shutdown(format!(
            "SIGTERM to pid {pid} failed: {errno}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command};

    /// RAII guard that force-kills + reaps a child on drop. Prevents zombies
    /// when an assertion fires mid-test.
    struct ChildGuard(Option<Child>);

    impl ChildGuard {
        fn new(child: Child) -> Self {
            Self(Some(child))
        }

        fn as_mut(&mut self) -> &mut Child {
            self.0.as_mut().expect("child taken")
        }

        fn into_inner(mut self) -> Child {
            self.0.take().expect("child taken")
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    fn spawn_sh(script: &str) -> Child {
        Command::new("sh")
            .arg("-c")
            .arg(script)
            .spawn()
            .expect("spawn sh")
    }

    fn fast_config() -> ShutdownConfig {
        ShutdownConfig {
            grace_period: Duration::from_millis(200),
            poll_interval: Duration::from_millis(10),
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn graceful_exit_on_sigterm() {
        // Traps SIGTERM and exits cleanly. graceful_shutdown should observe
        // exit during the poll loop, well before the grace window elapses.
        //
        // `sleep` is backgrounded and `wait`ed so the shell sits in an
        // interruptible syscall — dash (and most POSIX shells) defer trap
        // execution until the current foreground command returns, and `sleep`
        // is not interrupted by signals delivered to its parent.
        let mut guard = ChildGuard::new(spawn_sh(r#"trap "exit 0" TERM; sleep 10 & wait"#));
        // Give the shell a moment to install its trap before we signal.
        thread::sleep(Duration::from_millis(50));

        let start = Instant::now();
        let outcome = graceful_shutdown(guard.as_mut(), &fast_config()).expect("shutdown");
        let elapsed = start.elapsed();

        assert_eq!(outcome, ShutdownOutcome::Graceful);
        assert!(
            elapsed < Duration::from_millis(200),
            "graceful exit should finish before grace_period (took {elapsed:?})"
        );

        // Confirm reaped: a second try_wait must report the recorded exit
        // status without OS error.
        let mut child = guard.into_inner();
        let post = child.try_wait().expect("try_wait after reap");
        assert!(post.is_some(), "child must be reaped by graceful_shutdown");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn forced_kill_when_sigterm_ignored() {
        // Ignores SIGTERM entirely (`trap "" TERM` clears the default handler).
        // graceful_shutdown must escalate to SIGKILL after grace_period.
        let mut guard = ChildGuard::new(spawn_sh(r#"trap "" TERM; sleep 10"#));
        thread::sleep(Duration::from_millis(50));

        let cfg = fast_config();
        let start = Instant::now();
        let outcome = graceful_shutdown(guard.as_mut(), &cfg).expect("shutdown");
        let elapsed = start.elapsed();

        assert_eq!(outcome, ShutdownOutcome::Forced);
        assert!(
            elapsed >= cfg.grace_period,
            "forced kill should respect grace_period (took {elapsed:?})"
        );
        // Generous upper bound to stay stable under CI load.
        assert!(
            elapsed < cfg.grace_period + Duration::from_secs(2),
            "forced kill should not hang well past grace_period (took {elapsed:?})"
        );

        let mut child = guard.into_inner();
        let post = child.try_wait().expect("try_wait after reap");
        assert!(post.is_some(), "child must be reaped after SIGKILL");
    }

    #[test]
    fn already_exited_returns_already_exited() {
        // `true` exits immediately with status 0.
        let mut guard = ChildGuard::new(Command::new("true").spawn().expect("spawn true"));
        // Give the kernel time to deliver SIGCHLD so try_wait observes the exit.
        thread::sleep(Duration::from_millis(100));

        let outcome = graceful_shutdown(guard.as_mut(), &fast_config()).expect("shutdown");
        assert_eq!(outcome, ShutdownOutcome::AlreadyExited);
    }

    #[test]
    fn default_config_values() {
        let cfg = ShutdownConfig::default();
        assert_eq!(cfg.grace_period, Duration::from_millis(2_000));
        assert_eq!(cfg.poll_interval, Duration::from_millis(50));
    }
}
