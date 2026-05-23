//! Firecracker jailer wrapper.
//!
//! Firecracker's stock spawn path runs the VMM as the parent's UID with no
//! filesystem, namespace, or syscall isolation. A guest escape compromises the
//! host outright. This module wraps spawn through Firecracker's official
//! `jailer` binary, which enforces:
//!
//! * **Chroot**: the VMM sees only `<chroot_base>/firecracker/<vm_id>/root/`.
//! * **UID/GID drop**: the VMM runs as a non-root user post-setup.
//! * **cgroup v2 (or v1) limits**: CPU/memory/PIDs constrained at the kernel
//!   level via a parent slice (`microvm.slice` by default).
//! * **Default seccomp filter**: jailer applies Firecracker's built-in seccomp
//!   allowlist with no opt-out from us (we never pass `--no-seccomp`).
//! * **PID/mount namespaces**: via `--new-pid-ns` and chroot's pivot semantics.
//!
//! # Chroot directory layout
//!
//! ```text
//! <chroot_base>/
//! └── firecracker/
//!     └── <vm_id>/
//!         ├── firecracker.pid       (written by jailer)
//!         └── root/                 (the new `/` for the VMM)
//!             ├── firecracker       (copied/hardlinked by jailer itself)
//!             ├── api.sock          (created by FC once running)
//!             ├── vmlinux           (hardlink of kernel, from prepare())
//!             ├── rootfs.ext4       (hardlink of rootfs, from prepare())
//!             ├── drive-0.ext4 …    (extra drives, from prepare())
//!             └── dev/
//!                 ├── kvm           (c 10 232, from prepare())
//!                 └── net/tun       (c 10 200, from prepare())
//! ```
//!
//! `<vm_id>` is sanitised exactly like
//! [`crate::adapters::firecracker`]'s internal `safe_vm_id`: non-alphanumeric
//! characters other than `-` / `_` collapse to `_`.
//!
//! # Required host capabilities
//!
//! * `CAP_MKNOD` — to create `/dev/kvm` and `/dev/net/tun` inside the chroot.
//! * `CAP_CHOWN` — to chown the chroot tree to the unprivileged uid/gid.
//! * `CAP_SYS_ADMIN` — for cgroup hierarchy creation when the parent slice is
//!   not pre-created by systemd/admin.
//! * The `jailer` binary itself must be invoked by root (or appropriately
//!   setuid'd / file-capability'd); it drops to the configured uid/gid before
//!   `execve`'ing Firecracker.
//!
//! In practice the calling process either is root, or has these caps via
//! ambient capability sets. Failures from `mknod`/`chown` surface as
//! [`VmRuntimeError::Jailer`] with the offending path embedded for triage.

use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use nix::sys::stat::{Mode, SFlag, mknod};
use nix::unistd::{Gid, Uid, chown};

use crate::error::{VmRuntimeError, VmRuntimeResult};

const DEFAULT_JAILER_BIN: &str = "/usr/bin/jailer";
const DEFAULT_CHROOT_BASE: &str = "/srv/jailer";
const DEFAULT_CGROUP_PARENT: &str = "microvm.slice";
const DEFAULT_UID: u32 = 123;
const DEFAULT_GID: u32 = 100;

const KERNEL_BASENAME: &str = "vmlinux";
const ROOTFS_BASENAME: &str = "rootfs.ext4";
const API_SOCKET_BASENAME: &str = "api.sock";

// `dev` major:minor pairs. These are stable Linux ABI:
//   /dev/kvm        c 10 232
//   /dev/net/tun    c 10 200
const KVM_MAJOR: u64 = 10;
const KVM_MINOR: u64 = 232;
const TUN_MAJOR: u64 = 10;
const TUN_MINOR: u64 = 200;

/// Configuration for [`Jailer`].
#[derive(Debug, Clone)]
pub struct JailerConfig {
    /// Path to the `jailer` binary (default `/usr/bin/jailer` or via `MICROVM_JAILER_BIN`).
    pub jailer_bin: PathBuf,
    /// UID to drop privileges to (default 123 — matches Firecracker docs convention).
    pub uid: u32,
    /// GID to drop privileges to (default 100).
    pub gid: u32,
    /// Chroot base directory. Per-VM chroots created under `<base>/firecracker/<vm_id>/root/`.
    pub chroot_base: PathBuf,
    /// cgroup v2 parent slice (default `microvm.slice`).
    pub cgroup_parent: String,
    /// Whether to use the new cgroup v2 controllers (true) vs legacy v1 (false).
    pub cgroup_v2: bool,
    /// Optional NUMA node binding for the jailed FC process.
    pub numa_node: Option<u32>,
}

impl Default for JailerConfig {
    fn default() -> Self {
        Self {
            jailer_bin: PathBuf::from(DEFAULT_JAILER_BIN),
            uid: DEFAULT_UID,
            gid: DEFAULT_GID,
            chroot_base: PathBuf::from(DEFAULT_CHROOT_BASE),
            cgroup_parent: DEFAULT_CGROUP_PARENT.to_string(),
            cgroup_v2: true,
            numa_node: None,
        }
    }
}

impl JailerConfig {
    /// Build a [`JailerConfig`] from environment variables, falling back to
    /// the documented defaults. Recognised vars:
    ///
    /// * `MICROVM_JAILER_BIN`
    /// * `MICROVM_JAILER_UID`
    /// * `MICROVM_JAILER_GID`
    /// * `MICROVM_JAILER_CHROOT_BASE`
    /// * `MICROVM_JAILER_CGROUP_PARENT`
    /// * `MICROVM_JAILER_CGROUP_VERSION` (`1` or `2`; defaults to `2`)
    /// * `MICROVM_JAILER_NUMA_NODE`
    pub fn from_env() -> Self {
        let default = Self::default();
        Self {
            jailer_bin: std::env::var("MICROVM_JAILER_BIN")
                .map(PathBuf::from)
                .unwrap_or(default.jailer_bin),
            uid: std::env::var("MICROVM_JAILER_UID")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(default.uid),
            gid: std::env::var("MICROVM_JAILER_GID")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(default.gid),
            chroot_base: std::env::var("MICROVM_JAILER_CHROOT_BASE")
                .map(PathBuf::from)
                .unwrap_or(default.chroot_base),
            cgroup_parent: std::env::var("MICROVM_JAILER_CGROUP_PARENT")
                .unwrap_or(default.cgroup_parent),
            cgroup_v2: std::env::var("MICROVM_JAILER_CGROUP_VERSION")
                .ok()
                .map(|v| v.trim() != "1")
                .unwrap_or(default.cgroup_v2),
            numa_node: std::env::var("MICROVM_JAILER_NUMA_NODE")
                .ok()
                .and_then(|v| v.parse::<u32>().ok()),
        }
    }
}

/// Paths describing a prepared chroot for one VM.
///
/// Returned by [`Jailer::prepare`]; consumed by [`Jailer::build_command`] and
/// by the HTTP client that talks to the Firecracker API socket (the socket
/// path is the *host* view — the path the calling process must `connect(2)`).
#[derive(Debug, Clone)]
pub struct VmJail {
    /// The host-side path to the chroot root directory (the guest's `/`).
    pub chroot_path: PathBuf,
    /// API socket path **inside** the chroot — the value passed as
    /// `--api-sock` to Firecracker after `--`.
    pub api_socket_in_chroot: PathBuf,
    /// API socket path on the host — the value the HTTP client `connect(2)`s
    /// to (`<chroot_path>/<api_socket_basename>`).
    pub api_socket_on_host: PathBuf,
}

/// Driver around Firecracker's `jailer` binary.
#[derive(Debug, Clone)]
pub struct Jailer {
    config: JailerConfig,
}

impl Jailer {
    /// Construct a [`Jailer`] from an explicit configuration.
    pub fn new(config: JailerConfig) -> Self {
        Self { config }
    }

    /// Convenience shortcut for `Self::new(JailerConfig::from_env())`.
    pub fn from_env() -> Self {
        Self::new(JailerConfig::from_env())
    }

    /// Borrow the underlying configuration (useful for callers that already
    /// know the chroot base layout — e.g. an adapter that wants to derive
    /// post-jail paths without holding a `VmJail`).
    pub fn config(&self) -> &JailerConfig {
        &self.config
    }

    /// Compute the per-VM chroot directory `<chroot_base>/firecracker/<vm_id>/root/`.
    pub fn chroot_for(&self, vm_id: &str) -> PathBuf {
        self.config
            .chroot_base
            .join("firecracker")
            .join(safe_vm_id(vm_id))
            .join("root")
    }

    /// Prepare a chroot for `vm_id`. Idempotent — safe to call repeatedly for
    /// the same VM. On the second call, existing artifacts are verified and
    /// reused rather than re-created.
    ///
    /// `kernel`, `rootfs`, and each entry of `extra_drives` must exist on the
    /// host. They are hardlinked into the chroot when possible (same
    /// filesystem) and fall back to a byte-for-byte copy on `EXDEV`.
    ///
    /// Device nodes `/dev/kvm` and `/dev/net/tun` are created inside the
    /// chroot via `mknod(2)`. If the caller lacks `CAP_MKNOD`, the call
    /// returns [`VmRuntimeError::Jailer`] with a clear message.
    pub fn prepare(
        &self,
        vm_id: &str,
        kernel: &Path,
        rootfs: &Path,
        extra_drives: &[PathBuf],
    ) -> VmRuntimeResult<VmJail> {
        let safe_id = safe_vm_id(vm_id);
        if safe_id.is_empty() {
            return Err(VmRuntimeError::Jailer(format!(
                "vm id '{vm_id}' is empty after sanitisation"
            )));
        }

        let chroot_path = self
            .config
            .chroot_base
            .join("firecracker")
            .join(&safe_id)
            .join("root");

        if !kernel.exists() {
            return Err(VmRuntimeError::Jailer(format!(
                "kernel image not found: {}",
                kernel.display()
            )));
        }
        if !rootfs.exists() {
            return Err(VmRuntimeError::Jailer(format!(
                "rootfs image not found: {}",
                rootfs.display()
            )));
        }
        for drive in extra_drives {
            if !drive.exists() {
                return Err(VmRuntimeError::Jailer(format!(
                    "extra drive not found: {}",
                    drive.display()
                )));
            }
        }

        create_dir_all(&chroot_path)?;
        create_dir_all(&chroot_path.join("dev"))?;
        create_dir_all(&chroot_path.join("dev").join("net"))?;

        link_or_copy(kernel, &chroot_path.join(KERNEL_BASENAME))?;
        link_or_copy(rootfs, &chroot_path.join(ROOTFS_BASENAME))?;
        for (idx, drive) in extra_drives.iter().enumerate() {
            let basename = drive
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| format!("drive-{idx}.img"));
            link_or_copy(drive, &chroot_path.join(basename))?;
        }

        ensure_char_device(&chroot_path.join("dev").join("kvm"), KVM_MAJOR, KVM_MINOR)?;
        ensure_char_device(
            &chroot_path.join("dev").join("net").join("tun"),
            TUN_MAJOR,
            TUN_MINOR,
        )?;

        chown_tree(&chroot_path, self.config.uid, self.config.gid)?;

        Ok(VmJail {
            chroot_path: chroot_path.clone(),
            api_socket_in_chroot: PathBuf::from("/").join(API_SOCKET_BASENAME),
            api_socket_on_host: chroot_path.join(API_SOCKET_BASENAME),
        })
    }

    /// Build the `Command` that spawns `jailer` wrapping Firecracker.
    ///
    /// The caller is responsible for `.spawn()` and for wiring stdio (e.g.
    /// piping stderr into a console capture). This keeps process supervision
    /// — pid tracking, kill/wait, restart policy — outside this module.
    pub fn build_command(
        &self,
        vm_id: &str,
        jail: &VmJail,
        firecracker_bin: &Path,
    ) -> VmRuntimeResult<Command> {
        let safe_id = safe_vm_id(vm_id);
        if safe_id.is_empty() {
            return Err(VmRuntimeError::Jailer(format!(
                "vm id '{vm_id}' is empty after sanitisation"
            )));
        }
        if !firecracker_bin.is_absolute() {
            return Err(VmRuntimeError::Jailer(format!(
                "firecracker binary must be an absolute path: {}",
                firecracker_bin.display()
            )));
        }

        let expected_chroot = self
            .config
            .chroot_base
            .join("firecracker")
            .join(&safe_id)
            .join("root");
        if jail.chroot_path != expected_chroot {
            return Err(VmRuntimeError::Jailer(format!(
                "jail chroot {} does not match expected {} for vm '{vm_id}'",
                jail.chroot_path.display(),
                expected_chroot.display()
            )));
        }

        let mut cmd = Command::new(&self.config.jailer_bin);
        cmd.arg("--id")
            .arg(&safe_id)
            .arg("--exec-file")
            .arg(firecracker_bin)
            .arg("--uid")
            .arg(self.config.uid.to_string())
            .arg("--gid")
            .arg(self.config.gid.to_string())
            .arg("--chroot-base-dir")
            .arg(&self.config.chroot_base);

        // cgroup configuration. v2 is the modern unified hierarchy and is
        // what we ship by default; v1 is supported for hosts that haven't
        // migrated yet.
        cmd.arg("--cgroup-version")
            .arg(if self.config.cgroup_v2 { "2" } else { "1" })
            .arg("--parent-cgroup")
            .arg(&self.config.cgroup_parent);

        if let Some(node) = self.config.numa_node {
            cmd.arg("--numa-node").arg(node.to_string());
        }

        // Spawn FC in a fresh PID namespace so the only PID 1 the guest can
        // signal is itself. Jailer also applies the default seccomp filter
        // (no opt-out flag passed — we never want `--no-seccomp`).
        cmd.arg("--new-pid-ns");

        // Separator. Everything after this is forwarded verbatim to FC.
        cmd.arg("--");

        // Firecracker arguments. The api socket path is *inside* the chroot —
        // we hand the host-relative path as `/api.sock` so FC's bind sees it
        // at `<chroot>/api.sock`, which is also `jail.api_socket_on_host`.
        cmd.arg("--api-sock").arg(&jail.api_socket_in_chroot);

        Ok(cmd)
    }

    /// Tear down the chroot and best-effort the cgroup for `vm_id`. Safe to
    /// call even if `prepare` was never invoked (no-op in that case).
    pub fn teardown(&self, vm_id: &str) -> VmRuntimeResult<()> {
        let safe_id = safe_vm_id(vm_id);
        if safe_id.is_empty() {
            return Err(VmRuntimeError::Jailer(format!(
                "vm id '{vm_id}' is empty after sanitisation"
            )));
        }

        let vm_dir = self.config.chroot_base.join("firecracker").join(&safe_id);
        if vm_dir.exists() {
            fs::remove_dir_all(&vm_dir).map_err(|e| {
                VmRuntimeError::Jailer(format!("failed removing chroot {}: {e}", vm_dir.display()))
            })?;
        }

        // Best-effort cgroup cleanup. cgroup v2 supports plain `rmdir` once
        // the leaf has no procs left; v1 wants the legacy mount point. We
        // ignore failures here — a process may still be wrapping up and the
        // kernel will reap the empty cgroup itself.
        let cgroup_path = PathBuf::from("/sys/fs/cgroup")
            .join(&self.config.cgroup_parent)
            .join(&safe_id);
        let _ = fs::remove_dir(&cgroup_path);

        Ok(())
    }
}

/// Sanitise a VM id for use as a directory/cgroup name. Mirrors
/// `crate::adapters::firecracker::FirecrackerVmProvider::safe_vm_id`: anything
/// outside `[A-Za-z0-9_-]` collapses to `_`.
pub fn safe_vm_id(vm_id: &str) -> String {
    vm_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn create_dir_all(path: &Path) -> VmRuntimeResult<()> {
    fs::create_dir_all(path).map_err(|e| {
        VmRuntimeError::Jailer(format!("failed creating directory {}: {e}", path.display()))
    })
}

/// Hardlink `src` to `dst`. On `EXDEV` (cross-device link) fall back to a
/// byte copy. If `dst` already points to the same inode as `src`, this is a
/// no-op — the second call to `prepare()` for the same VM short-circuits.
fn link_or_copy(src: &Path, dst: &Path) -> VmRuntimeResult<()> {
    if dst.exists() {
        if same_inode(src, dst).unwrap_or(false) {
            return Ok(());
        }
        // A stale artifact from a previous, distinct source. Replace.
        fs::remove_file(dst).map_err(|e| {
            VmRuntimeError::Jailer(format!(
                "failed removing stale chroot artifact {}: {e}",
                dst.display()
            ))
        })?;
    }
    match fs::hard_link(src, dst) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc_exdev()) => {
            fs::copy(src, dst).map(|_| ()).map_err(|e| {
                VmRuntimeError::Jailer(format!(
                    "failed copying {} -> {}: {e}",
                    src.display(),
                    dst.display()
                ))
            })?;
            Ok(())
        }
        Err(e) => Err(VmRuntimeError::Jailer(format!(
            "failed hardlinking {} -> {}: {e}",
            src.display(),
            dst.display()
        ))),
    }
}

fn same_inode(a: &Path, b: &Path) -> io::Result<bool> {
    let ma = fs::metadata(a)?;
    let mb = fs::metadata(b)?;
    Ok(ma.dev() == mb.dev() && ma.ino() == mb.ino())
}

#[inline]
fn libc_exdev() -> i32 {
    // `EXDEV` is 18 on Linux; we avoid pulling `libc` in directly by going
    // through `nix`'s re-exported errno constant.
    nix::errno::Errno::EXDEV as i32
}

/// Create a character device node at `path` with the given major/minor. If a
/// node already exists at the path with matching type and device number, the
/// call is a no-op. Surfaces `EPERM` / `EACCES` with a hint about
/// `CAP_MKNOD`.
fn ensure_char_device(path: &Path, major: u64, minor: u64) -> VmRuntimeResult<()> {
    if path.exists() {
        // Validate it's the expected device. If something else is sitting at
        // the path (e.g. a regular file), refuse to proceed silently — that's
        // a sign the chroot got corrupted out-of-band.
        let md = fs::metadata(path).map_err(|e| {
            VmRuntimeError::Jailer(format!(
                "failed stat'ing existing chroot node {}: {e}",
                path.display()
            ))
        })?;
        let file_type = md.file_type();
        if !file_type.is_char_device() {
            return Err(VmRuntimeError::Jailer(format!(
                "chroot path {} exists but is not a character device",
                path.display()
            )));
        }
        let rdev = md.rdev();
        let expected = makedev(major, minor);
        if rdev != expected {
            return Err(VmRuntimeError::Jailer(format!(
                "chroot device {} has rdev {rdev:#x}, expected {expected:#x}",
                path.display()
            )));
        }
        return Ok(());
    }

    // Mode 0600 — the unprivileged FC user inside the chroot needs RW access;
    // chown_tree() below moves ownership to that user.
    let mode = Mode::S_IRUSR | Mode::S_IWUSR;
    let dev = makedev(major, minor);
    match mknod(path, SFlag::S_IFCHR, mode, dev) {
        Ok(()) => Ok(()),
        // Race: another caller created the same node between our `exists`
        // check and the `mknod`. Treat as success.
        Err(nix::errno::Errno::EEXIST) => Ok(()),
        Err(nix::errno::Errno::EPERM) | Err(nix::errno::Errno::EACCES) => {
            Err(VmRuntimeError::Jailer(format!(
                "mknod({}, c {major} {minor}) denied — process needs CAP_MKNOD",
                path.display()
            )))
        }
        Err(e) => Err(VmRuntimeError::Jailer(format!(
            "mknod({}, c {major} {minor}) failed: {e}",
            path.display()
        ))),
    }
}

/// Linux `makedev(3)`: encode major/minor into the kernel's 64-bit dev_t.
/// Mirrors the glibc encoding used by `mknod(1)`.
fn makedev(major: u64, minor: u64) -> u64 {
    ((major & 0xffff_f000) << 32)
        | ((major & 0x0000_0fff) << 8)
        | ((minor & 0xffff_ff00) << 12)
        | (minor & 0x0000_00ff)
}

/// Recursively chown `root` and every descendant to `uid:gid`. Errors are
/// reported with the offending path. Used to hand the chroot tree to the
/// unprivileged user that the jailer will drop to.
fn chown_tree(root: &Path, uid: u32, gid: u32) -> VmRuntimeResult<()> {
    let owner = Some(Uid::from_raw(uid));
    let group = Some(Gid::from_raw(gid));
    chown(root, owner, group).map_err(|e| {
        VmRuntimeError::Jailer(format!(
            "chown {} to {uid}:{gid} failed: {e}",
            root.display()
        ))
    })?;

    let entries = fs::read_dir(root).map_err(|e| {
        VmRuntimeError::Jailer(format!("failed reading chroot dir {}: {e}", root.display()))
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| {
            VmRuntimeError::Jailer(format!(
                "failed iterating chroot dir {}: {e}",
                root.display()
            ))
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|e| {
            VmRuntimeError::Jailer(format!("failed stat'ing {}: {e}", path.display()))
        })?;
        if file_type.is_dir() {
            chown_tree(&path, uid, gid)?;
        } else {
            chown(&path, owner, group).map_err(|e| {
                VmRuntimeError::Jailer(format!(
                    "chown {} to {uid}:{gid} failed: {e}",
                    path.display()
                ))
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(base: &Path) -> JailerConfig {
        JailerConfig {
            jailer_bin: PathBuf::from("/usr/bin/jailer"),
            uid: 123,
            gid: 100,
            chroot_base: base.to_path_buf(),
            cgroup_parent: "microvm.slice".to_string(),
            cgroup_v2: true,
            numa_node: None,
        }
    }

    #[test]
    fn safe_vm_id_matches_adapter_convention() {
        assert_eq!(safe_vm_id("vm-1_a"), "vm-1_a");
        assert_eq!(safe_vm_id("vm/with/slash"), "vm_with_slash");
        assert_eq!(safe_vm_id("../etc/passwd"), "___etc_passwd");
        assert_eq!(safe_vm_id("ünicode"), "_nicode");
        assert_eq!(safe_vm_id("ok123"), "ok123");
    }

    #[test]
    fn chroot_path_computation() {
        let j = Jailer::new(cfg(Path::new("/srv/jailer")));
        assert_eq!(
            j.chroot_for("vm-1"),
            PathBuf::from("/srv/jailer/firecracker/vm-1/root")
        );
        assert_eq!(
            j.chroot_for("../etc"),
            PathBuf::from("/srv/jailer/firecracker/___etc/root")
        );
    }

    #[test]
    fn build_command_basic_args_in_expected_order() {
        let j = Jailer::new(cfg(Path::new("/srv/jailer")));
        let jail = VmJail {
            chroot_path: PathBuf::from("/srv/jailer/firecracker/vm-1/root"),
            api_socket_in_chroot: PathBuf::from("/api.sock"),
            api_socket_on_host: PathBuf::from("/srv/jailer/firecracker/vm-1/root/api.sock"),
        };
        let cmd = j
            .build_command("vm-1", &jail, Path::new("/usr/bin/firecracker"))
            .expect("command builds");
        assert_eq!(cmd.get_program(), "/usr/bin/jailer");
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            vec![
                "--id".to_string(),
                "vm-1".to_string(),
                "--exec-file".to_string(),
                "/usr/bin/firecracker".to_string(),
                "--uid".to_string(),
                "123".to_string(),
                "--gid".to_string(),
                "100".to_string(),
                "--chroot-base-dir".to_string(),
                "/srv/jailer".to_string(),
                "--cgroup-version".to_string(),
                "2".to_string(),
                "--parent-cgroup".to_string(),
                "microvm.slice".to_string(),
                "--new-pid-ns".to_string(),
                "--".to_string(),
                "--api-sock".to_string(),
                "/api.sock".to_string(),
            ]
        );
    }

    #[test]
    fn build_command_cgroup_v1_flag() {
        let mut c = cfg(Path::new("/srv/jailer"));
        c.cgroup_v2 = false;
        let j = Jailer::new(c);
        let jail = VmJail {
            chroot_path: PathBuf::from("/srv/jailer/firecracker/vm-1/root"),
            api_socket_in_chroot: PathBuf::from("/api.sock"),
            api_socket_on_host: PathBuf::from("/srv/jailer/firecracker/vm-1/root/api.sock"),
        };
        let cmd = j
            .build_command("vm-1", &jail, Path::new("/usr/bin/firecracker"))
            .expect("command builds");
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let i = args.iter().position(|s| s == "--cgroup-version").unwrap();
        assert_eq!(args[i + 1], "1");
    }

    #[test]
    fn build_command_includes_numa_when_configured() {
        let mut c = cfg(Path::new("/srv/jailer"));
        c.numa_node = Some(3);
        let j = Jailer::new(c);
        let jail = VmJail {
            chroot_path: PathBuf::from("/srv/jailer/firecracker/vm-1/root"),
            api_socket_in_chroot: PathBuf::from("/api.sock"),
            api_socket_on_host: PathBuf::from("/srv/jailer/firecracker/vm-1/root/api.sock"),
        };
        let cmd = j
            .build_command("vm-1", &jail, Path::new("/usr/bin/firecracker"))
            .expect("command builds");
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let i = args.iter().position(|s| s == "--numa-node").unwrap();
        assert_eq!(args[i + 1], "3");
        // Must appear before the `--` separator.
        let sep = args.iter().position(|s| s == "--").unwrap();
        assert!(i < sep);
    }

    #[test]
    fn build_command_sanitises_vm_id() {
        let j = Jailer::new(cfg(Path::new("/srv/jailer")));
        let jail = VmJail {
            chroot_path: PathBuf::from("/srv/jailer/firecracker/___etc/root"),
            api_socket_in_chroot: PathBuf::from("/api.sock"),
            api_socket_on_host: PathBuf::from("/srv/jailer/firecracker/___etc/root/api.sock"),
        };
        let cmd = j
            .build_command("../etc", &jail, Path::new("/usr/bin/firecracker"))
            .expect("command builds");
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let i = args.iter().position(|s| s == "--id").unwrap();
        assert_eq!(args[i + 1], "___etc");
    }

    #[test]
    fn build_command_rejects_relative_firecracker_bin() {
        let j = Jailer::new(cfg(Path::new("/srv/jailer")));
        let jail = VmJail {
            chroot_path: PathBuf::from("/srv/jailer/firecracker/vm-1/root"),
            api_socket_in_chroot: PathBuf::from("/api.sock"),
            api_socket_on_host: PathBuf::from("/srv/jailer/firecracker/vm-1/root/api.sock"),
        };
        let err = j
            .build_command("vm-1", &jail, Path::new("firecracker"))
            .unwrap_err();
        match err {
            VmRuntimeError::Jailer(msg) => assert!(msg.contains("absolute"), "{msg}"),
            other => panic!("expected Jailer error, got {other:?}"),
        }
    }

    #[test]
    fn build_command_rejects_chroot_mismatch() {
        let j = Jailer::new(cfg(Path::new("/srv/jailer")));
        let jail = VmJail {
            chroot_path: PathBuf::from("/srv/jailer/firecracker/other/root"),
            api_socket_in_chroot: PathBuf::from("/api.sock"),
            api_socket_on_host: PathBuf::from("/srv/jailer/firecracker/other/root/api.sock"),
        };
        let err = j
            .build_command("vm-1", &jail, Path::new("/usr/bin/firecracker"))
            .unwrap_err();
        assert!(matches!(err, VmRuntimeError::Jailer(_)));
    }

    #[test]
    fn teardown_is_idempotent_without_prepare() {
        let tmp = tempfile::tempdir().unwrap();
        let j = Jailer::new(cfg(tmp.path()));
        j.teardown("vm-1").expect("teardown ok");
        j.teardown("vm-1").expect("teardown ok");
    }

    #[test]
    fn teardown_removes_chroot_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let j = Jailer::new(cfg(tmp.path()));
        let vm_dir = tmp.path().join("firecracker").join("vm-1");
        fs::create_dir_all(vm_dir.join("root").join("dev")).unwrap();
        fs::write(vm_dir.join("root").join("vmlinux"), b"fake").unwrap();
        assert!(vm_dir.exists());
        j.teardown("vm-1").expect("teardown ok");
        assert!(!vm_dir.exists());
    }

    #[test]
    fn makedev_matches_glibc_for_kvm_and_tun() {
        // Cross-checked against `mknod -m 0600 /dev/kvm c 10 232`.
        //   major=10  -> (10 & 0xfff) << 8 = 0xa00
        //   minor=232 -> 232 & 0xff       = 0xe8
        //   high bits zero.
        //   => 0xa00 | 0xe8 = 0xae8 = 2792
        assert_eq!(makedev(10, 232), 0xae8);
        // TUN 10:200 -> 0xa00 | 0xc8 = 0xac8 = 2760
        assert_eq!(makedev(10, 200), 0xac8);
    }

    // -------- OS-touching tests below --------
    //
    // Require `CAP_MKNOD` + `CAP_CHOWN`; run as root via:
    //   sudo -E env "PATH=$PATH" cargo test --features firecracker -- --ignored

    #[test]
    #[ignore = "requires root: CAP_MKNOD + CAP_CHOWN"]
    fn prepare_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = tmp.path().join("vmlinux.src");
        let rootfs = tmp.path().join("rootfs.src");
        fs::write(&kernel, b"fake kernel").unwrap();
        fs::write(&rootfs, b"fake rootfs").unwrap();

        let j = Jailer::new(cfg(tmp.path()));
        let jail1 = j.prepare("vm-1", &kernel, &rootfs, &[]).expect("prepare 1");
        let jail2 = j.prepare("vm-1", &kernel, &rootfs, &[]).expect("prepare 2");
        assert_eq!(jail1.chroot_path, jail2.chroot_path);
        let kvm = jail1.chroot_path.join("dev/kvm");
        let tun = jail1.chroot_path.join("dev/net/tun");
        assert!(fs::metadata(&kvm).unwrap().file_type().is_char_device());
        assert!(fs::metadata(&tun).unwrap().file_type().is_char_device());
    }
}
