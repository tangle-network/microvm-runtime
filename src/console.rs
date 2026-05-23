//! Bounded ring-buffer capture for a child process's stderr.
//!
//! Firecracker is spawned as a subprocess and, when a guest kernel panics or
//! `init` fails, the only signal the operator has is whatever Firecracker
//! emits on stderr before exiting. Piping that to `Stdio::null()` discards
//! the diagnostic. This module retains a bounded tail of the last `max_lines`
//! lines so callers can read it post-mortem.
//!
//! The capture is intentionally independent of the Firecracker adapter so it
//! can be wired in by callers that pipe stderr themselves. A drainer thread
//! reads `ChildStderr` line-by-line and pushes into a `VecDeque` behind a
//! `Mutex`; the lock scope is just push + evict so `tail()` is non-blocking
//! against the I/O loop.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader};
use std::process::ChildStderr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Suffix appended to lines that exceeded `max_line_bytes`.
const TRUNCATION_MARKER: &str = "…[truncated]";

/// Best-effort wait applied by `Drop` before leaking the drainer thread.
const SHUTDOWN_JOIN_BUDGET: Duration = Duration::from_millis(200);

/// Polling cadence for `Drop`'s bounded join wait.
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Tuning knobs for [`ConsoleCapture`].
#[derive(Debug, Clone)]
pub struct ConsoleConfig {
    /// Maximum number of lines retained in the ring buffer. Oldest lines are
    /// evicted when this limit is exceeded.
    pub max_lines: usize,
    /// Maximum bytes per retained line. Longer lines are truncated and
    /// suffixed with `…[truncated]`. Truncation is applied at the byte
    /// boundary of the last valid UTF-8 character at or before the limit.
    pub max_line_bytes: usize,
}

impl Default for ConsoleConfig {
    fn default() -> Self {
        Self {
            max_lines: 200,
            max_line_bytes: 4096,
        }
    }
}

/// Captures a bounded tail of a child process's stderr lines.
///
/// A background thread owns the [`ChildStderr`] handle and drains it line by
/// line. The captured tail survives the child process: once the reader sees
/// EOF the drainer thread exits but the in-memory ring buffer is preserved
/// until the [`ConsoleCapture`] itself is dropped.
#[derive(Debug)]
pub struct ConsoleCapture {
    buffer: Arc<Mutex<VecDeque<String>>>,
    shutdown: Arc<AtomicBool>,
    drainer: Option<JoinHandle<()>>,
}

impl ConsoleCapture {
    /// Spawn a drainer thread reading `stderr` into a bounded ring buffer.
    ///
    /// The thread exits cleanly when `stderr` hits EOF (e.g. the child exits)
    /// or when [`ConsoleCapture::shutdown`] is invoked. After EOF, the ring
    /// buffer remains readable via [`ConsoleCapture::tail`].
    pub fn attach(stderr: ChildStderr, config: ConsoleConfig) -> Self {
        let buffer = Arc::new(Mutex::new(VecDeque::with_capacity(config.max_lines.min(
            // Avoid reserving an absurd amount up front if a caller passes a
            // pathological `max_lines`. 256 is more than enough for the
            // common case and we can grow if needed.
            256,
        ))));
        let shutdown = Arc::new(AtomicBool::new(false));

        let buffer_for_thread = Arc::clone(&buffer);
        let shutdown_for_thread = Arc::clone(&shutdown);
        let max_lines = config.max_lines;
        let max_line_bytes = config.max_line_bytes;

        let drainer = thread::Builder::new()
            .name("microvm-console-drainer".into())
            .spawn(move || {
                drain_loop(
                    BufReader::new(stderr),
                    buffer_for_thread,
                    shutdown_for_thread,
                    max_lines,
                    max_line_bytes,
                );
            })
            // Thread spawn can fail under extreme resource exhaustion. We
            // surface this by leaving the buffer empty and the join handle
            // absent so `tail()` works and `shutdown()` is a no-op. This
            // matches the "fail-open on capture" posture documented for
            // diagnostic-only paths: losing the tail must never break VM
            // boot.
            .ok();

        Self {
            buffer,
            shutdown,
            drainer,
        }
    }

    /// Return a snapshot of the ring buffer, oldest line first.
    ///
    /// Cloning is performed under the buffer lock; the lock is released
    /// before returning. Callers can invoke this concurrently with the
    /// drainer thread without blocking it for longer than a clone.
    pub fn tail(&self) -> Vec<String> {
        let guard = match self.buffer.lock() {
            Ok(guard) => guard,
            // A panic in any path holding the buffer lock (only the drainer
            // and `tail` itself touch it) shouldn't lose us the captured
            // diagnostic. Recover the inner state and return it.
            Err(poison) => poison.into_inner(),
        };
        guard.iter().cloned().collect()
    }

    /// Request the drainer thread to stop and best-effort join it.
    ///
    /// The thread observes the shutdown flag between line reads. If it is
    /// currently blocked inside a `read()` call (waiting for the child to
    /// emit more output) it will not observe the flag until the read
    /// completes; in that case the bounded join in `Drop` will time out and
    /// the thread is leaked. That is preferable to hanging the caller.
    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.drainer.take()
            && join_with_deadline(handle, SHUTDOWN_JOIN_BUDGET).is_err()
        {
            // Thread is still blocked in I/O; the spec calls for leaking it.
        }
    }
}

impl Drop for ConsoleCapture {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Block until `handle` finishes or `deadline` elapses.
///
/// On success returns `Ok(())`. On timeout returns `Err(handle)` so the
/// caller can choose to leak or retry (we leak — the spec is explicit).
fn join_with_deadline(handle: JoinHandle<()>, budget: Duration) -> Result<(), JoinHandle<()>> {
    let deadline = Instant::now() + budget;
    loop {
        if handle.is_finished() {
            // Discard the thread's panic payload, if any — we are in a Drop
            // path and propagating would abort the process.
            let _ = handle.join();
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(handle);
        }
        thread::sleep(SHUTDOWN_POLL_INTERVAL);
    }
}

fn drain_loop<R: BufRead>(
    mut reader: R,
    buffer: Arc<Mutex<VecDeque<String>>>,
    shutdown: Arc<AtomicBool>,
    max_lines: usize,
    max_line_bytes: usize,
) {
    let mut line = String::new();
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return;
        }
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => return, // EOF
            Ok(_) => {
                // `read_line` retains the trailing `\n` (and possibly `\r`).
                // Strip it so consumers don't see double newlines when they
                // render the tail.
                trim_trailing_newline(&mut line);
                let to_push = enforce_line_limit(&line, max_line_bytes);
                push_with_eviction(&buffer, to_push, max_lines);
            }
            Err(_) => return, // unrecoverable read error → end capture
        }
    }
}

fn trim_trailing_newline(line: &mut String) {
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
}

/// Apply the per-line byte cap, truncating on a UTF-8 boundary and appending
/// the marker so consumers can distinguish a truncated line from a long-but-
/// intact one.
fn enforce_line_limit(line: &str, max_line_bytes: usize) -> String {
    if line.len() <= max_line_bytes {
        return line.to_owned();
    }
    // `max_line_bytes` may fall mid-codepoint; walk back to the nearest
    // char boundary so the resulting string is valid UTF-8.
    let mut cut = max_line_bytes;
    while cut > 0 && !line.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut out = String::with_capacity(cut + TRUNCATION_MARKER.len());
    out.push_str(&line[..cut]);
    out.push_str(TRUNCATION_MARKER);
    out
}

fn push_with_eviction(buffer: &Mutex<VecDeque<String>>, line: String, max_lines: usize) {
    let mut guard = match buffer.lock() {
        Ok(guard) => guard,
        Err(poison) => poison.into_inner(),
    };
    if max_lines == 0 {
        // Caller explicitly disabled retention; still drain stderr (so the
        // child doesn't block on a full pipe) but don't store anything.
        return;
    }
    guard.push_back(line);
    while guard.len() > max_lines {
        guard.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    /// Spawn `sh -c <script>` with stderr piped, return the `ChildStderr`
    /// handle and a function that blocks until the child exits.
    fn sh_stderr(script: &str) -> ChildStderr {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sh");
        let stderr = child.stderr.take().expect("piped stderr");
        // Detach the child reaper: we don't care about exit status, and the
        // OS will reap once stderr is fully drained.
        thread::spawn(move || {
            let _ = child.wait();
        });
        stderr
    }

    /// Wait until `predicate` returns true or `deadline` elapses. Returns
    /// the final tail snapshot regardless.
    fn wait_for_tail<F>(capture: &ConsoleCapture, deadline: Duration, predicate: F) -> Vec<String>
    where
        F: Fn(&[String]) -> bool,
    {
        let start = Instant::now();
        loop {
            let snapshot = capture.tail();
            if predicate(&snapshot) {
                return snapshot;
            }
            if start.elapsed() >= deadline {
                return snapshot;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn tail_returns_lines_in_chronological_order() {
        let stderr = sh_stderr("printf 'a\\nb\\nc\\n' 1>&2");
        let capture = ConsoleCapture::attach(stderr, ConsoleConfig::default());
        let tail = wait_for_tail(&capture, Duration::from_secs(2), |t| t.len() >= 3);
        assert_eq!(
            tail,
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
    }

    #[test]
    fn oldest_line_is_evicted_when_capacity_exceeded() {
        let stderr = sh_stderr("printf '1\\n2\\n3\\n4\\n5\\n' 1>&2");
        let capture = ConsoleCapture::attach(
            stderr,
            ConsoleConfig {
                max_lines: 2,
                max_line_bytes: 4096,
            },
        );
        let tail = wait_for_tail(&capture, Duration::from_secs(2), |t| {
            t.last().map(|s| s == "5").unwrap_or(false)
        });
        assert_eq!(tail, vec!["4".to_string(), "5".to_string()]);
    }

    #[test]
    fn long_line_is_truncated_with_suffix() {
        // 50 'x' chars on stderr; we cap at 10 bytes per line. Use a
        // POSIX-portable construction (no brace expansion — `sh` is `dash`
        // on Debian-likes and won't expand `{1..50}`).
        let stderr =
            sh_stderr("printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\\n' 1>&2");
        let capture = ConsoleCapture::attach(
            stderr,
            ConsoleConfig {
                max_lines: 16,
                max_line_bytes: 10,
            },
        );
        let tail = wait_for_tail(&capture, Duration::from_secs(2), |t| !t.is_empty());
        assert_eq!(tail.len(), 1);
        let line = &tail[0];
        assert!(line.ends_with(TRUNCATION_MARKER), "line was {line:?}");
        assert_eq!(&line[..10], "xxxxxxxxxx");
        assert_eq!(line.len(), 10 + TRUNCATION_MARKER.len());
    }

    #[test]
    fn truncation_respects_utf8_boundary() {
        // '€' is 3 bytes (E2 82 AC). Place it so the cap falls inside it.
        // We feed: 9 ASCII bytes, then '€', then more — cap at 10. The cut
        // must land at byte 9, not 10 (which would be mid-codepoint).
        let stderr = sh_stderr("printf '123456789€XYZ\\n' 1>&2");
        let capture = ConsoleCapture::attach(
            stderr,
            ConsoleConfig {
                max_lines: 4,
                max_line_bytes: 10,
            },
        );
        let tail = wait_for_tail(&capture, Duration::from_secs(2), |t| !t.is_empty());
        assert_eq!(tail.len(), 1);
        let line = &tail[0];
        assert!(line.ends_with(TRUNCATION_MARKER));
        // The kept prefix must be valid UTF-8. The first 9 ASCII chars fit
        // under 10 bytes; '€' would push us to 12, so the cut walks back
        // to 9.
        assert_eq!(&line[..9], "123456789");
        assert!(!line[..line.len() - TRUNCATION_MARKER.len()].contains('€'));
    }

    #[test]
    fn tail_survives_process_exit() {
        let stderr = sh_stderr("printf 'panic: kernel\\nrebooting\\n' 1>&2");
        let capture = ConsoleCapture::attach(stderr, ConsoleConfig::default());
        // Wait for both lines; the producer is a one-shot `sh` that exits
        // immediately, so EOF arrives almost instantly.
        let tail = wait_for_tail(&capture, Duration::from_secs(2), |t| t.len() >= 2);
        assert_eq!(
            tail,
            vec!["panic: kernel".to_string(), "rebooting".to_string()]
        );
        // Sleep past any drainer wind-down and re-read; should be identical.
        thread::sleep(Duration::from_millis(50));
        assert_eq!(capture.tail(), tail);
    }

    #[test]
    fn shutdown_then_tail_does_not_panic() {
        let stderr = sh_stderr("printf 'one\\ntwo\\n' 1>&2");
        let mut capture = ConsoleCapture::attach(stderr, ConsoleConfig::default());
        let _ = wait_for_tail(&capture, Duration::from_secs(2), |t| t.len() >= 2);
        capture.shutdown();
        let tail = capture.tail();
        assert!(tail.contains(&"one".to_string()));
        assert!(tail.contains(&"two".to_string()));
        // Calling shutdown twice must be safe (idempotent).
        capture.shutdown();
    }

    #[test]
    fn drop_does_not_deadlock_when_thread_is_mid_read() {
        // `sh -c 'sleep 5'` produces no output and stays open for 5s. The
        // drainer thread will be blocked inside `read_line`. Dropping the
        // capture must return within the 200ms budget plus slack.
        let stderr = sh_stderr("sleep 5");
        let capture = ConsoleCapture::attach(stderr, ConsoleConfig::default());
        // Give the drainer a moment to actually enter the blocked read.
        thread::sleep(Duration::from_millis(20));
        let start = Instant::now();
        drop(capture);
        // 200ms budget + generous slack for CI jitter.
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(1000),
            "drop took too long: {elapsed:?}"
        );
    }

    #[test]
    fn empty_lines_are_retained() {
        let stderr = sh_stderr("printf 'a\\n\\nb\\n' 1>&2");
        let capture = ConsoleCapture::attach(stderr, ConsoleConfig::default());
        let tail = wait_for_tail(&capture, Duration::from_secs(2), |t| t.len() >= 3);
        assert_eq!(tail, vec!["a".to_string(), String::new(), "b".to_string()]);
    }

    #[test]
    fn crlf_line_endings_are_stripped() {
        let stderr = sh_stderr("printf 'win\\r\\nlin\\n' 1>&2");
        let capture = ConsoleCapture::attach(stderr, ConsoleConfig::default());
        let tail = wait_for_tail(&capture, Duration::from_secs(2), |t| t.len() >= 2);
        assert_eq!(tail, vec!["win".to_string(), "lin".to_string()]);
    }

    #[test]
    fn max_lines_zero_drains_without_storing() {
        let stderr = sh_stderr("printf 'a\\nb\\nc\\n' 1>&2");
        let capture = ConsoleCapture::attach(
            stderr,
            ConsoleConfig {
                max_lines: 0,
                max_line_bytes: 4096,
            },
        );
        // Give the drainer enough time to consume all three lines and hit
        // EOF. With `max_lines: 0` the buffer should remain empty.
        thread::sleep(Duration::from_millis(100));
        assert!(capture.tail().is_empty());
    }

    #[test]
    fn poisoned_buffer_lock_still_returns_tail() {
        // Simulate a panic while holding the buffer lock by poisoning it
        // directly, then read the tail through the public API.
        let stderr = sh_stderr("printf 'survivor\\n' 1>&2");
        let capture = ConsoleCapture::attach(stderr, ConsoleConfig::default());
        wait_for_tail(&capture, Duration::from_secs(2), |t| !t.is_empty());
        // Poison the mutex by panicking inside a lock guard.
        let buffer = Arc::clone(&capture.buffer);
        let _ = thread::spawn(move || {
            let _guard = buffer.lock().expect("lock");
            panic!("intentional poison");
        })
        .join();
        // tail() must still return the survivor line, recovered from the
        // poisoned guard.
        let tail = capture.tail();
        assert!(tail.contains(&"survivor".to_string()), "tail was {tail:?}");
    }
}
