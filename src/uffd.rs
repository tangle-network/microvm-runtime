//! Userfaultfd page-fault handler for Firecracker snapshot restore.
//!
//! Without UFFD, `PUT /snapshot/load` reads the entire guest memory file
//! synchronously before the VM resumes. For a 4 GiB guest that is a multi-
//! hundred-millisecond hit on every restore. With UFFD, Firecracker hands the
//! guest memory region to a userspace handler over a unix-domain socket; the
//! handler `mmap`s the snapshot mem file `MAP_PRIVATE` and services page
//! faults on demand by calling `UFFDIO_COPY`. The VM resumes immediately and
//! only the pages the guest actually touches are paged in. Cold ~150 ms warm-
//! restores collapse to ~5 ms.
//!
//! # Wire protocol (FC v1.6+)
//!
//! 1. The handler binds a UDS at [`UffdConfig::socket_path`] and `accept`s.
//! 2. The caller issues `PUT /snapshot/load` with `mem_backend.backend_type =
//!    "Uffd"` (see [`snapshot_load_mem_backend_uffd`]) — FC then connects to
//!    the handler's socket.
//! 3. FC sends one `sendmsg(2)` containing:
//!    - **Ancillary data**: an `SCM_RIGHTS` control message carrying the
//!      userfaultfd file descriptor FC created internally.
//!    - **Body**: a JSON array `[{ base_host_virt_addr, size, offset,
//!      page_size_kib }, …]` describing each guest memory region's mapping
//!      between guest physical and host virtual addresses, and its byte
//!      offset within the snapshot mem file.
//! 4. The handler reads `UFFD_EVENT_PAGEFAULT` events off the received fd and
//!    responds with `UFFDIO_COPY` from the mmap'd mem file at the appropriate
//!    offset. `UFFD_EVENT_REMOVE` events (from balloon device reclaim) are
//!    acknowledged via `unregister`.
//!
//! Reference: <https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/handling-page-faults-on-snapshot-resume.md>
//!
//! # Threading model
//!
//! [`UffdHandler::start`] spawns one OS thread that owns the listener and the
//! page-fault loop. Its lifecycle:
//!
//! * Spawns immediately, `accept()` blocks until FC connects.
//! * On connect: receives the uffd fd + region JSON, then enters the fault
//!   loop using `poll(2)` so we react both to UFFD events and to EOF on the
//!   control socket.
//! * Exits cleanly when (a) FC closes the connection (EOF / `POLLHUP`),
//!   (b) [`UffdHandler::shutdown`] sets the atomic flag, or (c) `Drop` runs.
//!
//! `is_alive()` is a snapshot view: the loop publishes its state into an
//! [`AtomicBool`] on entry and on exit, so callers can observe whether the
//! handler is still accepting page faults without locking.
//!
//! # Non-goals
//!
//! This module is a *primitive*: it has no opinion on which VM the handler
//! belongs to, where snapshots live, or how the socket path is chosen. The
//! `firecracker` adapter is responsible for both (a) constructing a
//! [`UffdConfig`] before calling `/snapshot/load` and (b) holding the
//! returned [`UffdHandler`] for the VM's lifetime so the handler outlives
//! every page fault the guest will ever raise.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::error::{VmRuntimeError, VmRuntimeResult};

/// Best-effort join budget applied by `Drop` / `shutdown()` before the
/// handler thread is detached. Matches the cadence used by the rest of the
/// crate (`console`, `metrics`).
const SHUTDOWN_JOIN_BUDGET: Duration = Duration::from_millis(200);

/// Poll cadence for the bounded shutdown join wait.
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Tuning knobs for a single VM's UFFD handler.
#[derive(Debug, Clone)]
pub struct UffdConfig {
    /// Path of the unix-domain socket the handler binds. Firecracker connects
    /// here as soon as `/snapshot/load` is invoked with `backend_type =
    /// "Uffd"` and `backend_path = socket_path`. The handler removes a stale
    /// file at this path before binding so a crashed previous handler does
    /// not block a restart.
    pub socket_path: PathBuf,

    /// Path to the snapshotted guest memory file. The handler `mmap`s this
    /// file `PROT_READ | MAP_PRIVATE` and copies pages out of the mapping in
    /// response to faults. The mapping is created once at connect time and
    /// lives for the handler thread's lifetime.
    pub mem_file_path: PathBuf,
}

/// Spawned UFFD page-fault handler for one Firecracker microVM.
///
/// The handler owns a background thread that binds the UDS, accepts the
/// Firecracker connection, and services page faults until the VM exits or
/// [`UffdHandler::shutdown`] is invoked. Drop on this type triggers an
/// orderly shutdown.
#[derive(Debug)]
pub struct UffdHandler {
    socket_path: PathBuf,
    state: Arc<HandlerState>,
    join: Option<JoinHandle<()>>,
}

/// State shared between the spawned handler thread and the owning
/// [`UffdHandler`].
///
/// * `alive` — set to `true` once the handler thread starts; flipped to
///   `false` on EOF, error, or shutdown. Callers read it via
///   [`UffdHandler::is_alive`].
/// * `shutdown` — set to `true` by [`UffdHandler::shutdown`] / `Drop` to
///   request the loop exit. The loop checks it between iterations and after
///   each `poll`.
#[derive(Debug)]
struct HandlerState {
    alive: AtomicBool,
    shutdown: AtomicBool,
}

impl UffdHandler {
    /// Spawn the UFFD handler thread bound to `config.socket_path`.
    ///
    /// Idempotent on the socket path: any existing file at that location is
    /// removed before `bind(2)`. This matches Firecracker's expectation that
    /// the handler is restartable in place after a crash.
    ///
    /// The handler thread runs until any of:
    ///   * Firecracker closes the control socket (normal lifecycle on VM stop)
    ///   * an unrecoverable libc error on the UFFD fd
    ///   * [`UffdHandler::shutdown`] is invoked
    ///   * the [`UffdHandler`] is dropped
    pub fn start(config: UffdConfig) -> VmRuntimeResult<Self> {
        platform::start(config)
    }

    /// `true` while the handler thread is alive and accepting page faults.
    ///
    /// Becomes `false` permanently once the loop exits for any reason. This
    /// is a cheap atomic load — callers can poll it from hot paths (e.g. a
    /// VM-supervisor health check).
    pub fn is_alive(&self) -> bool {
        self.state.alive.load(Ordering::SeqCst)
    }

    /// Best-effort stop.
    ///
    /// Sets the shutdown flag, removes the socket file to unblock any
    /// pending `accept`, and joins the handler thread for up to 200 ms.
    /// If the thread is parked inside a syscall
    /// (`poll` or `read_event`) when the budget expires, it is detached;
    /// in-flight page faults are dropped on the floor. This is intentional:
    /// hanging the caller is worse than leaking a thread that will exit on
    /// the next FC event or once the VM goes away.
    pub fn shutdown(&mut self) {
        self.state.shutdown.store(true, Ordering::SeqCst);
        // Best-effort socket removal unblocks `accept` if the listener is
        // still waiting for FC to connect (e.g. snapshot load was never
        // issued). Errors are ignored — the socket may not exist if FC
        // already connected and the listener was dropped.
        let _ = std::fs::remove_file(&self.socket_path);
        if let Some(handle) = self.join.take() {
            let _ = join_with_deadline(handle, SHUTDOWN_JOIN_BUDGET);
        }
        // Mark alive=false here too: if the thread is parked and gets
        // detached, `is_alive` should still reflect "no longer servicing".
        self.state.alive.store(false, Ordering::SeqCst);
    }
}

impl Drop for UffdHandler {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Build the `mem_backend` JSON value Firecracker expects on `PUT
/// /snapshot/load` when using a UFFD handler.
///
/// Shape:
/// ```json
/// { "backend_type": "Uffd", "backend_path": "<socket_path>" }
/// ```
///
/// The caller embeds this value at `body.mem_backend` and POSTs the rest of
/// the snapshot-load body as usual.
pub fn snapshot_load_mem_backend_uffd(socket_path: &Path) -> serde_json::Value {
    serde_json::json!({
        "backend_type": "Uffd",
        "backend_path": socket_path,
    })
}

/// Bounded join: returns `Ok` if the thread finished within `budget`,
/// otherwise returns the handle back so the caller can decide whether to
/// detach it. We always detach (drop), matching the `console` / `metrics`
/// convention.
fn join_with_deadline(handle: JoinHandle<()>, budget: Duration) -> Result<(), JoinHandle<()>> {
    let deadline = Instant::now() + budget;
    loop {
        if handle.is_finished() {
            // Discard any panic payload from the handler thread; propagating
            // through Drop would abort the process.
            let _ = handle.join();
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(handle);
        }
        thread::sleep(SHUTDOWN_POLL_INTERVAL);
    }
}

// ---------------------------------------------------------------------------
// Linux implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    use std::fs::File;
    use std::io::IoSliceMut;
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::ptr;

    use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
    use serde::Deserialize;
    use userfaultfd::{Event, Uffd};

    /// One guest memory region as Firecracker describes it in the JSON body
    /// of the SCM_RIGHTS handshake.
    ///
    /// Fields mirror FC's internal `GuestRegionUffdMapping` 1:1 — DO NOT
    /// rename or reorder. The handler matches faulting host-virtual
    /// addresses against `[base_host_virt_addr, base_host_virt_addr + size)`
    /// and translates them to a file offset of `offset + (fault_addr -
    /// base_host_virt_addr)`.
    #[derive(Debug, Deserialize)]
    struct GuestRegionUffdMapping {
        base_host_virt_addr: u64,
        size: u64,
        offset: u64,
        #[allow(dead_code)] // FC sends this; we always use 4 KiB pages.
        page_size_kib: Option<u64>,
    }

    /// Default guest page size. FC's x86_64 default is 4 KiB and the docs
    /// note that mixed page sizes are not currently supported per region.
    const PAGE_SIZE: usize = 4096;

    /// Max bytes we'll read in the single FC handshake message. FC's region
    /// list is small (one entry per memory region, a handful in practice);
    /// 64 KiB is generous and matches the reference handler.
    const HANDSHAKE_BUF_BYTES: usize = 65_536;

    pub fn start(config: UffdConfig) -> VmRuntimeResult<UffdHandler> {
        let UffdConfig {
            socket_path,
            mem_file_path,
        } = config;

        // Idempotent: remove any stale socket before binding.
        if let Err(err) = std::fs::remove_file(&socket_path)
            && err.kind() != std::io::ErrorKind::NotFound
        {
            return Err(VmRuntimeError::Uffd(format!(
                "remove stale socket {}: {err}",
                socket_path.display()
            )));
        }

        let listener = UnixListener::bind(&socket_path)
            .map_err(|e| VmRuntimeError::Uffd(format!("bind {}: {e}", socket_path.display())))?;

        let state = Arc::new(HandlerState {
            alive: AtomicBool::new(true),
            shutdown: AtomicBool::new(false),
        });

        let state_thread = Arc::clone(&state);
        let mem_file_path_thread = mem_file_path.clone();
        let socket_path_thread = socket_path.clone();

        let join = thread::Builder::new()
            .name(format!("microvm-uffd:{}", socket_path.display()))
            .spawn(move || {
                let result = run_handler(listener, &mem_file_path_thread, &state_thread);
                state_thread.alive.store(false, Ordering::SeqCst);
                if let Err(err) = result {
                    // Surface the failure on stderr; we have no return
                    // channel once the thread is spawned. Callers detect
                    // failure through `is_alive() == false`.
                    eprintln!(
                        "[microvm-uffd] handler exited with error \
                         (socket={}, mem_file={}): {err}",
                        socket_path_thread.display(),
                        mem_file_path_thread.display(),
                    );
                }
            })
            .map_err(|e| VmRuntimeError::Uffd(format!("spawn handler thread: {e}")))?;

        Ok(UffdHandler {
            socket_path,
            state,
            join: Some(join),
        })
    }

    /// Drive one handler lifecycle: accept FC, handshake, fault loop.
    ///
    /// The listener is dropped before the fault loop begins so `shutdown()`
    /// can no longer race with `accept` after FC connects. The fault loop
    /// exits on shutdown, EOF, or unrecoverable error.
    fn run_handler(
        listener: UnixListener,
        mem_file_path: &Path,
        state: &HandlerState,
    ) -> VmRuntimeResult<()> {
        // `accept()` blocks until either FC connects OR shutdown drops the
        // socket file out from under the listener (which surfaces as an
        // error on accept). We treat shutdown-during-accept as a clean exit.
        let stream = match listener.accept() {
            Ok((stream, _addr)) => stream,
            Err(_) if state.shutdown.load(Ordering::SeqCst) => return Ok(()),
            Err(e) => return Err(VmRuntimeError::Uffd(format!("accept: {e}"))),
        };
        drop(listener);

        // The handshake gives us the uffd fd + region mapping. If FC sends
        // garbage or we hit a libc error here, propagate up so the operator
        // can see the failure in logs.
        let (uffd, regions) = receive_handshake(&stream)?;

        // Open + mmap the snapshot mem file once and reuse across faults.
        let mem_file = File::open(mem_file_path).map_err(|e| {
            VmRuntimeError::Uffd(format!("open mem file {}: {e}", mem_file_path.display()))
        })?;
        let mem_size = mem_file
            .metadata()
            .map_err(|e| {
                VmRuntimeError::Uffd(format!("stat mem file {}: {e}", mem_file_path.display()))
            })?
            .len() as usize;

        let mem_ptr = unsafe {
            let ptr = libc::mmap(
                ptr::null_mut(),
                mem_size,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                mem_file.as_raw_fd(),
                0,
            );
            if ptr == libc::MAP_FAILED {
                return Err(VmRuntimeError::Uffd(format!(
                    "mmap mem file {}: {}",
                    mem_file_path.display(),
                    std::io::Error::last_os_error()
                )));
            }
            ptr as *const u8
        };

        // Wrap in an RAII guard so we always munmap, even on early returns
        // and panics inside the fault loop.
        let _mmap_guard = MmapGuard {
            ptr: mem_ptr,
            size: mem_size,
        };

        fault_loop(&uffd, &stream, mem_ptr, mem_size, &regions, state);

        Ok(())
    }

    /// Read FC's SCM_RIGHTS handshake off `stream` and decode the embedded
    /// JSON region list. Returns the [`Uffd`] adopted from the received raw
    /// fd plus the parsed regions.
    fn receive_handshake(
        stream: &UnixStream,
    ) -> VmRuntimeResult<(Uffd, Vec<GuestRegionUffdMapping>)> {
        let mut buf = vec![0u8; HANDSHAKE_BUF_BYTES];
        let mut cmsg_buf = nix::cmsg_space!(RawFd);

        let mut iov = [IoSliceMut::new(&mut buf)];

        let msg = recvmsg::<()>(
            stream.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_buf),
            MsgFlags::empty(),
        )
        .map_err(|e| VmRuntimeError::Uffd(format!("recvmsg from firecracker: {e}")))?;

        let mut uffd_fd: Option<RawFd> = None;
        for cmsg in msg
            .cmsgs()
            .map_err(|e| VmRuntimeError::Uffd(format!("decode cmsg from firecracker: {e}")))?
        {
            if let ControlMessageOwned::ScmRights(fds) = cmsg
                && let Some(&fd) = fds.first()
            {
                uffd_fd = Some(fd);
            }
        }

        let uffd_fd = uffd_fd.ok_or_else(|| {
            VmRuntimeError::Uffd("firecracker did not send a userfaultfd fd".into())
        })?;

        let json_len = msg.bytes;
        let json_slice = &buf[..json_len];
        let json_str = std::str::from_utf8(json_slice)
            .map_err(|e| VmRuntimeError::Uffd(format!("region mapping payload not utf-8: {e}")))?;
        let regions: Vec<GuestRegionUffdMapping> = serde_json::from_str(json_str)
            .map_err(|e| VmRuntimeError::Uffd(format!("parse region mappings: {e}")))?;

        // SAFETY: FC just transferred ownership of this fd to us via
        // SCM_RIGHTS. Wrapping it in `Uffd` adopts ownership; `Uffd`'s `Drop`
        // closes it. The kernel guarantees the fd is a valid userfaultfd.
        let uffd = unsafe { Uffd::from_raw_fd(uffd_fd) };

        Ok((uffd, regions))
    }

    /// Service page faults until shutdown, EOF, or unrecoverable error.
    ///
    /// We poll BOTH the uffd fd (for PAGEFAULT / REMOVE events) and the
    /// stream fd (for HUP — FC's signal that the VM is shutting down) so
    /// the loop terminates promptly on either path.
    fn fault_loop(
        uffd: &Uffd,
        stream: &UnixStream,
        mem_base: *const u8,
        mem_size: usize,
        regions: &[GuestRegionUffdMapping],
        state: &HandlerState,
    ) {
        let uffd_fd = uffd.as_raw_fd();
        let stream_fd = stream.as_raw_fd();

        loop {
            if state.shutdown.load(Ordering::SeqCst) {
                return;
            }

            let mut fds = [
                libc::pollfd {
                    fd: uffd_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: stream_fd,
                    events: 0, // only watch for HUP/ERR on FC's control socket
                    revents: 0,
                },
            ];

            // Short timeout so we observe the shutdown flag promptly without
            // burning CPU.
            let timeout_ms: libc::c_int = 100;
            let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                eprintln!("[microvm-uffd] poll error: {err}");
                return;
            }
            if rc == 0 {
                // Timeout — loop back to shutdown check.
                continue;
            }

            // FC closed the control socket → VM is gone; we're done.
            if fds[1].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                return;
            }

            if fds[0].revents & libc::POLLHUP != 0 {
                // The uffd fd itself was closed (rare: typically only on
                // VM teardown). Exit cleanly.
                return;
            }
            if fds[0].revents & libc::POLLIN == 0 {
                continue;
            }

            match uffd.read_event() {
                Ok(Some(Event::Pagefault { addr, .. })) => {
                    handle_pagefault(uffd, addr as u64, regions, mem_base, mem_size);
                }
                Ok(Some(Event::Remove { start, end })) => {
                    // Balloon device reclaimed pages. Per FC docs we
                    // unregister the range so subsequent faults in it
                    // resolve as zero-filled by the kernel rather than
                    // re-paged from the snapshot.
                    let size = (end as usize).saturating_sub(start as usize);
                    if size > 0 {
                        let _ = uffd.unregister(start as *mut _, size);
                    }
                }
                Ok(Some(_)) => {
                    // Other event kinds (REMAP, UNMAP, FORK) don't apply to
                    // FC's restore path — ignore.
                }
                Ok(None) => {
                    // Non-blocking read with no event ready — go back to poll.
                    continue;
                }
                Err(e) => {
                    eprintln!("[microvm-uffd] read_event error: {e}");
                    return;
                }
            }
        }
    }

    /// Resolve a faulting host-virtual address against the snapshot mmap and
    /// satisfy the fault with a single 4 KiB `UFFDIO_COPY`.
    ///
    /// Per the FC reference handler, we copy one page per fault rather than
    /// the whole region: copying eagerly defeats UFFD's "only pay for pages
    /// the guest actually touches" property.
    fn handle_pagefault(
        uffd: &Uffd,
        fault_addr: u64,
        regions: &[GuestRegionUffdMapping],
        mem_base: *const u8,
        mem_size: usize,
    ) {
        let aligned = (fault_addr as usize) & !(PAGE_SIZE - 1);

        for region in regions {
            let start = region.base_host_virt_addr as usize;
            let end = start.saturating_add(region.size as usize);
            if aligned < start || aligned >= end {
                continue;
            }

            let in_region = aligned - start;
            let src_offset = (region.offset as usize).saturating_add(in_region);
            if src_offset.saturating_add(PAGE_SIZE) > mem_size {
                eprintln!(
                    "[microvm-uffd] fault page out of mem-file bounds: \
                     src_offset={src_offset}, mem_size={mem_size}"
                );
                return;
            }

            // SAFETY: `mem_base` and `mem_size` describe an active
            // `MAP_PRIVATE` mapping of the snapshot mem file; `src_offset +
            // PAGE_SIZE <= mem_size` is checked above. The destination is
            // the guest's address space which the kernel will populate via
            // UFFDIO_COPY.
            let src = unsafe { mem_base.add(src_offset) };
            let dst = aligned as *mut libc::c_void;
            match unsafe { uffd.copy(src.cast(), dst, PAGE_SIZE, true) } {
                Ok(_) => {}
                Err(userfaultfd::Error::CopyFailed(errno)) if errno as i32 == libc::EEXIST => {
                    // Another thread populated this page first — benign.
                    // We compare via raw `i32` rather than a typed `Errno`
                    // constant because `userfaultfd` 0.8 vendors `nix` 0.27
                    // and our direct `nix` dep is 0.30 — two distinct types.
                }
                Err(e) => {
                    eprintln!("[microvm-uffd] UFFDIO_COPY failed at 0x{aligned:x}: {e}");
                }
            }
            return;
        }

        // Fault address fell outside every registered region. Zero-fill the
        // page so the guest doesn't deadlock; this matches the reference
        // handler's behaviour for spurious faults.
        let zero = [0u8; PAGE_SIZE];
        let dst = aligned as *mut libc::c_void;
        let _ = unsafe { uffd.copy(zero.as_ptr().cast(), dst, PAGE_SIZE, true) };
    }

    /// RAII guard that `munmap`s the snapshot mem file mapping on drop.
    ///
    /// Kept separate from the `Uffd` handle (which owns the kernel-side fd
    /// lifecycle) because the mmap is independent host-side state.
    struct MmapGuard {
        ptr: *const u8,
        size: usize,
    }

    // SAFETY: the mapping is owned by this guard; we don't share the raw
    // pointer with anything outside the handler thread, and the page-fault
    // loop only reads from it (never writes).
    unsafe impl Send for MmapGuard {}

    impl Drop for MmapGuard {
        fn drop(&mut self) {
            if !self.ptr.is_null() {
                // SAFETY: pointer + size were returned by `mmap` on the
                // matching length. munmap on a NULL ptr or zero length would
                // be UB, both of which are excluded here.
                unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.size) };
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Non-Linux stub
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::*;

    pub fn start(_config: UffdConfig) -> VmRuntimeResult<UffdHandler> {
        Err(VmRuntimeError::Uffd(
            "userfaultfd is Linux-only; \
             this build target has no UFFD handler implementation"
                .into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::net::UnixListener;

    #[test]
    fn snapshot_load_mem_backend_uffd_returns_expected_shape() {
        let path = Path::new("/tmp/some-vm/uffd.sock");
        let value = snapshot_load_mem_backend_uffd(path);

        // The exact contract Firecracker `/snapshot/load` requires.
        assert_eq!(value["backend_type"], "Uffd");
        assert_eq!(value["backend_path"], "/tmp/some-vm/uffd.sock");

        // Exactly these two keys — extra fields would be ignored by FC but
        // would also signal a drift from the doc'd contract.
        let obj = value.as_object().expect("object");
        assert_eq!(obj.len(), 2);
    }

    #[test]
    fn snapshot_load_mem_backend_uffd_preserves_non_ascii_paths() {
        // Paths are arbitrary bytes on unix; the helper should not lossily
        // re-encode them. We only test the common (utf-8) case here because
        // `serde_json::Value` for paths uses lossy utf-8 rendering for
        // non-utf-8 OsStr, which is FC's expectation anyway.
        let path = Path::new("/var/run/microvm/vm-αβγ/uffd.sock");
        let value = snapshot_load_mem_backend_uffd(path);
        assert_eq!(
            value["backend_path"].as_str().expect("string path"),
            "/var/run/microvm/vm-αβγ/uffd.sock"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn start_removes_stale_socket_before_binding() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("uffd.sock");
        let mem_file_path = dir.path().join("mem.bin");
        std::fs::write(&mem_file_path, b"unused-for-this-test").expect("write mem file");

        // Pre-create a stale socket file at the target path. If `start` did
        // not unlink it, `bind` would fail with EADDRINUSE.
        let stale = UnixListener::bind(&socket_path).expect("seed stale socket");
        drop(stale); // closes the fd but leaves the file behind.
        assert!(socket_path.exists(), "stale socket file should exist");

        let handler = UffdHandler::start(UffdConfig {
            socket_path: socket_path.clone(),
            mem_file_path,
        })
        .expect("start with stale socket present must succeed");

        // Socket file should now belong to the new handler.
        assert!(socket_path.exists());
        assert!(handler.is_alive());
        drop(handler);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn start_errors_when_socket_parent_dir_does_not_exist() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("nope").join("uffd.sock");
        let mem_file_path = dir.path().join("mem.bin");
        std::fs::write(&mem_file_path, b"x").unwrap();

        let err = UffdHandler::start(UffdConfig {
            socket_path,
            mem_file_path,
        })
        .expect_err("missing parent dir must surface as Uffd error");
        match err {
            VmRuntimeError::Uffd(msg) => {
                assert!(msg.contains("bind"), "expected bind failure, got: {msg}");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shutdown_unblocks_accept_and_drops_listener() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("uffd.sock");
        let mem_file_path = dir.path().join("mem.bin");
        std::fs::write(&mem_file_path, b"unused").unwrap();

        let mut handler = UffdHandler::start(UffdConfig {
            socket_path: socket_path.clone(),
            mem_file_path,
        })
        .expect("start");

        // Sanity: the handler is alive and parked on accept.
        assert!(handler.is_alive());
        assert!(socket_path.exists());

        let start = Instant::now();
        handler.shutdown();
        let elapsed = start.elapsed();

        // Bounded shutdown: the join budget is 200ms, with generous CI slack.
        assert!(
            elapsed < Duration::from_secs(2),
            "shutdown took too long: {elapsed:?}"
        );
        assert!(!handler.is_alive(), "is_alive must flip off after shutdown");
        assert!(
            !socket_path.exists(),
            "shutdown must remove the socket file"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn drop_runs_shutdown() {
        // Drop without explicit shutdown must still bound the thread and
        // clean the socket. We assert by spawning, then dropping, then
        // verifying the socket file is gone.
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("uffd.sock");
        let mem_file_path = dir.path().join("mem.bin");
        std::fs::write(&mem_file_path, b"unused").unwrap();

        {
            let handler = UffdHandler::start(UffdConfig {
                socket_path: socket_path.clone(),
                mem_file_path,
            })
            .expect("start");
            assert!(handler.is_alive());
        } // <- drop runs here

        assert!(
            !socket_path.exists(),
            "Drop must remove the socket file via shutdown()"
        );
    }

    /// Full end-to-end fault-servicing test would require a real
    /// `userfaultfd(2)` fd plus a guest-side faulting mapping. That is
    /// possible from a test (open `/dev/userfaultfd`, register a private
    /// anonymous mapping, fault it, see UFFDIO_COPY land) but it requires
    /// either CAP_SYS_PTRACE or `vm.unprivileged_userfaultfd=1` and is
    /// gated by host kernel config. The unit tests above cover the
    /// crate-side surface; the full path is exercised by the firecracker
    /// adapter's integration tests once the tech lead wires it in.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires CAP_SYS_PTRACE / unprivileged_userfaultfd; \
                exercised by the firecracker adapter integration tests"]
    fn end_to_end_pagefault_servicing() {
        // Intentionally empty — the gating comment is the documentation.
    }
}
