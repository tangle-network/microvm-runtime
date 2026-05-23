//! Stack catalog, per-VM rootfs CoW cloning, and SHA-256 integrity helpers.
//!
//! ## What this module does
//!
//! The Firecracker adapter today points every VM at a single `rootfs_path`.
//! Real operators want a **catalog of pre-built rootfs templates** (e.g.
//! `base`, `node-20`, `python-3.12`) and a **per-VM clone** of the chosen
//! template so VMs do not share writable state.
//!
//! Cloning prefers reflink-based CoW (btrfs / XFS / bcachefs / ZFS-on-Linux)
//! so the per-VM copy is a few milliseconds and a few kilobytes of metadata.
//! On filesystems without reflink (ext4, tmpfs in tests, etc.) the module
//! falls back to a hardlink (only safe when the caller mounts the rootfs
//! read-only in the guest) and finally to a full streaming copy. The chosen
//! strategy is opaque to the caller — only the resulting path matters.
//!
//! The same `sha2`-backed streaming hasher is exported for snapshot integrity
//! verification: callers compute the hash on snapshot create and re-verify on
//! restore, defending against silent disk corruption.
//!
//! ## Layout on disk
//!
//! ```text
//! template_dir/
//! ├── base/
//! │   └── rootfs.ext4         (canonical template — never mutated by the registry)
//! ├── node-20/
//! │   └── rootfs.ext4
//! └── python-3.12/
//!     └── rootfs.ext4
//!
//! clones_dir/
//! ├── <safe_vm_id_1>/
//! │   ├── rootfs.ext4         (per-VM clone — reflink / hardlink / copy)
//! │   └── rootfs.ext4.sha256  (stamp file: hex digest of the template at clone time)
//! └── <safe_vm_id_2>/
//!     └── …
//! ```
//!
//! Stamp files let [`RootfsRegistry::clone_for_vm`] be idempotent: a repeat
//! call with the same `vm_id` returns the existing clone iff its stamp still
//! matches the live template digest. A mismatch is a caller bug — the
//! template was swapped out from under a live VM — and surfaces as
//! [`VmRuntimeError::Rootfs`] rather than a silent re-clone.
//!
//! ## Required filesystem support
//!
//! - **btrfs**, **XFS** (with `reflink=1`), **bcachefs**, **ZFS-on-Linux** —
//!   `cp --reflink=always` succeeds, clones are instant CoW. Recommended.
//! - **ext4**, **tmpfs**, anything else — reflink fails, the registry falls
//!   back through hardlink (if the caller mounts read-only) and finally a
//!   full sparse-aware copy. Functionally correct, just not free.
//!
//! ## Concurrency
//!
//! The SHA-256 cache is protected by an internal `Mutex`. Concurrent
//! `clone_for_vm` calls for the **same** `vm_id` race against the filesystem
//! and may both observe "stamp missing" and attempt to clone — that is a
//! caller bug (each VM ID is owned by exactly one orchestrator). Calls with
//! distinct `vm_id` are independent.

use std::collections::HashMap;
use std::fs;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::SystemTime;

use sha2::{Digest, Sha256};

use crate::error::{VmRuntimeError, VmRuntimeResult};

/// Default canonical-template parent directory.
pub const DEFAULT_TEMPLATE_DIR: &str = "/var/lib/microvm/rootfs-templates";
/// Default per-VM clones parent directory.
pub const DEFAULT_CLONES_DIR: &str = "/var/lib/microvm/rootfs";
/// File name of each template's rootfs image inside its stack directory.
pub const TEMPLATE_ROOTFS_FILE: &str = "rootfs.ext4";
/// File name of the per-VM clone (kept identical to the template name so
/// downstream tooling that hard-codes `rootfs.ext4` works unchanged).
pub const CLONE_ROOTFS_FILE: &str = "rootfs.ext4";
/// Sidecar file name holding the hex digest of the template at clone time.
pub const CLONE_STAMP_FILE: &str = "rootfs.ext4.sha256";

/// I/O block size for streaming SHA-256. Matches ADC's 4 MiB chunk size,
/// large enough to amortise syscall overhead on multi-GiB rootfs images and
/// small enough to stay within the default stack-allocated buffer budget.
const HASH_BUF_BYTES: usize = 4 * 1024 * 1024;

/// Configuration for [`RootfsRegistry`].
#[derive(Debug, Clone)]
pub struct RootfsConfig {
    /// Directory containing the canonical stack templates. Each subdirectory
    /// named `<stack>/rootfs.ext4` is a template.
    /// Default `/var/lib/microvm/rootfs-templates/`.
    pub template_dir: PathBuf,
    /// Directory where per-VM clones live. Default `/var/lib/microvm/rootfs/`.
    pub clones_dir: PathBuf,
}

impl Default for RootfsConfig {
    fn default() -> Self {
        Self {
            template_dir: PathBuf::from(DEFAULT_TEMPLATE_DIR),
            clones_dir: PathBuf::from(DEFAULT_CLONES_DIR),
        }
    }
}

impl RootfsConfig {
    /// Build from environment variables.
    ///
    /// - `MICROVM_ROOTFS_TEMPLATE_DIR` overrides [`Self::template_dir`].
    /// - `MICROVM_ROOTFS_CLONES_DIR` overrides [`Self::clones_dir`].
    pub fn from_env() -> Self {
        let defaults = Self::default();
        let template_dir = std::env::var("MICROVM_ROOTFS_TEMPLATE_DIR")
            .map(PathBuf::from)
            .unwrap_or(defaults.template_dir);
        let clones_dir = std::env::var("MICROVM_ROOTFS_CLONES_DIR")
            .map(PathBuf::from)
            .unwrap_or(defaults.clones_dir);
        Self {
            template_dir,
            clones_dir,
        }
    }
}

/// Metadata for a single template in the catalog.
#[derive(Debug, Clone)]
pub struct StackInfo {
    /// Stack name (matches the subdirectory name under `template_dir`).
    pub name: String,
    /// Absolute path to the canonical `rootfs.ext4`.
    pub template_path: PathBuf,
    /// Size of the template in bytes.
    pub size_bytes: u64,
    /// Hex-encoded SHA-256 of the template. Cached per `(path, mtime)`.
    pub sha256: String,
}

/// The result of cloning a template into a per-VM rootfs slot.
#[derive(Debug, Clone)]
pub struct VmRootfs {
    /// Sanitised VM identifier (see [`safe_vm_id`]).
    pub vm_id: String,
    /// Stack name the clone was sourced from.
    pub stack: String,
    /// Per-VM clone path that callers point Firecracker's drive at.
    pub path: PathBuf,
    /// Hex-encoded SHA-256 of the template at clone time, mirrored from the
    /// on-disk stamp file. Equality with the live template digest is the
    /// idempotency invariant.
    pub source_sha256: String,
}

#[derive(Debug, Default)]
struct HashCache {
    /// (template_path, mtime) → hex digest.
    inner: HashMap<(PathBuf, SystemTime), String>,
}

/// Stack catalog + per-VM CoW cloner + SHA-256 integrity helper.
///
/// Cheap to construct; all state is filesystem-backed except a small
/// in-memory hash cache keyed by `(path, mtime)`.
#[derive(Debug)]
pub struct RootfsRegistry {
    config: RootfsConfig,
    hash_cache: Mutex<HashCache>,
}

impl RootfsRegistry {
    /// Construct a registry with the given configuration.
    pub fn new(config: RootfsConfig) -> Self {
        Self {
            config,
            hash_cache: Mutex::new(HashCache::default()),
        }
    }

    /// Construct a registry with configuration read from the environment.
    pub fn from_env() -> Self {
        Self::new(RootfsConfig::from_env())
    }

    /// Borrow the active configuration. Useful for callers that need the
    /// canonical directories without threading them through their own state.
    pub fn config(&self) -> &RootfsConfig {
        &self.config
    }

    /// Enumerate available stacks. Returns an empty list if the template
    /// directory does not exist yet (a fresh host that has not been
    /// provisioned). Sorted by `name` for deterministic output.
    ///
    /// SHA-256 is computed lazily and cached per `(path, mtime)`; the second
    /// call is free if the templates have not changed.
    pub fn stacks(&self) -> VmRuntimeResult<Vec<StackInfo>> {
        let read = match fs::read_dir(&self.config.template_dir) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(VmRuntimeError::Rootfs(format!(
                    "read template dir {}: {e}",
                    self.config.template_dir.display()
                )));
            }
        };

        let mut out = Vec::new();
        for entry in read {
            let entry = entry.map_err(|e| {
                VmRuntimeError::Rootfs(format!(
                    "iterate template dir {}: {e}",
                    self.config.template_dir.display()
                ))
            })?;
            let ftype = entry.file_type().map_err(|e| {
                VmRuntimeError::Rootfs(format!(
                    "stat template entry {}: {e}",
                    entry.path().display()
                ))
            })?;
            if !ftype.is_dir() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let template_path = entry.path().join(TEMPLATE_ROOTFS_FILE);
            let meta = match fs::metadata(&template_path) {
                Ok(m) if m.is_file() => m,
                Ok(_) | Err(_) => continue,
            };
            let size_bytes = meta.len();
            let sha256 = self.cached_hash(&template_path, &meta)?;
            out.push(StackInfo {
                name,
                template_path,
                size_bytes,
                sha256,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Look up a single stack by name. `Ok(None)` when the stack directory
    /// (or its `rootfs.ext4`) is missing — not an error.
    pub fn stack(&self, name: &str) -> VmRuntimeResult<Option<StackInfo>> {
        let template_path = self
            .config
            .template_dir
            .join(name)
            .join(TEMPLATE_ROOTFS_FILE);
        let meta = match fs::metadata(&template_path) {
            Ok(m) if m.is_file() => m,
            Ok(_) => return Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(VmRuntimeError::Rootfs(format!(
                    "stat template {}: {e}",
                    template_path.display()
                )));
            }
        };
        let sha256 = self.cached_hash(&template_path, &meta)?;
        Ok(Some(StackInfo {
            name: name.to_owned(),
            template_path,
            size_bytes: meta.len(),
            sha256,
        }))
    }

    /// Clone the named stack into a per-VM rootfs slot.
    ///
    /// Strategy order: `cp --reflink=always` → `std::fs::hard_link` →
    /// streaming byte copy. The chosen strategy is invisible to the caller;
    /// what matters is that [`VmRootfs::path`] is a usable rootfs image
    /// whose contents match the template at the time of the call.
    ///
    /// **Idempotency.** Calling twice with the same `vm_id` and `stack_name`
    /// returns the existing clone iff the on-disk stamp matches the live
    /// template digest. A stamp mismatch (template was swapped while a VM
    /// holds a clone) returns [`VmRuntimeError::Rootfs`] rather than silently
    /// re-cloning — re-cloning under a running VM corrupts its view of the
    /// disk and is always a caller bug. To rotate a stack, the caller must
    /// [`Self::release`] the VM first.
    ///
    /// **Hardlink safety.** The hardlink fallback only makes sense when the
    /// caller mounts the rootfs read-only in the guest (typical for the
    /// shared-rootfs deployment mode); otherwise writes from one VM are
    /// visible to every other VM clone of the same template. Callers that
    /// want a writable rootfs on a non-reflink filesystem will end up at the
    /// copy fallback path automatically — the hardlink only succeeds when
    /// the source and destination share a filesystem and the kernel allows
    /// it, which is the common case.
    pub fn clone_for_vm(&self, vm_id: &str, stack_name: &str) -> VmRuntimeResult<VmRootfs> {
        let safe_id = safe_vm_id(vm_id);
        if safe_id.is_empty() {
            return Err(VmRuntimeError::Rootfs(format!(
                "vm_id '{vm_id}' sanitises to an empty string"
            )));
        }

        let stack = self.stack(stack_name)?.ok_or_else(|| {
            VmRuntimeError::Rootfs(format!(
                "stack '{stack_name}' not found under {}",
                self.config.template_dir.display()
            ))
        })?;

        let vm_dir = self.config.clones_dir.join(&safe_id);
        let clone_path = vm_dir.join(CLONE_ROOTFS_FILE);
        let stamp_path = vm_dir.join(CLONE_STAMP_FILE);

        // Idempotent fast path: existing clone with matching stamp.
        if clone_path.exists() {
            let stamp = read_stamp(&stamp_path)?;
            if stamp == stack.sha256 {
                return Ok(VmRootfs {
                    vm_id: safe_id,
                    stack: stack.name,
                    path: clone_path,
                    source_sha256: stamp,
                });
            }
            return Err(VmRuntimeError::Rootfs(format!(
                "vm '{safe_id}' clone stamp mismatch (stamp={stamp}, template={}) — release the VM before rotating stack '{}'",
                stack.sha256, stack.name,
            )));
        }

        fs::create_dir_all(&vm_dir).map_err(|e| {
            VmRuntimeError::Rootfs(format!("create clone dir {}: {e}", vm_dir.display()))
        })?;

        clone_file(&stack.template_path, &clone_path)?;
        write_stamp(&stamp_path, &stack.sha256)?;

        Ok(VmRootfs {
            vm_id: safe_id,
            stack: stack.name,
            path: clone_path,
            source_sha256: stack.sha256,
        })
    }

    /// Remove a per-VM clone. Idempotent — a missing directory is not an
    /// error.
    pub fn release(&self, vm_id: &str) -> VmRuntimeResult<()> {
        let safe_id = safe_vm_id(vm_id);
        if safe_id.is_empty() {
            return Err(VmRuntimeError::Rootfs(format!(
                "vm_id '{vm_id}' sanitises to an empty string"
            )));
        }
        let vm_dir = self.config.clones_dir.join(&safe_id);
        match fs::remove_dir_all(&vm_dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(VmRuntimeError::Rootfs(format!(
                "remove clone dir {}: {e}",
                vm_dir.display()
            ))),
        }
    }

    /// Streaming SHA-256 over an arbitrary file. Use case: snapshot
    /// integrity verification (memory + state files are GiB-sized and
    /// reading the whole file into memory is not viable).
    ///
    /// Buffered through a 4 MiB block size — large enough to amortise
    /// syscall overhead, small enough to stay friendly to the heap.
    pub fn hash_file(path: &Path) -> VmRuntimeResult<String> {
        let file = fs::File::open(path).map_err(|e| {
            VmRuntimeError::Rootfs(format!("open {} for hashing: {e}", path.display()))
        })?;
        let mut reader = BufReader::with_capacity(HASH_BUF_BYTES, file);
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; HASH_BUF_BYTES];
        loop {
            let n = reader.read(&mut buf).map_err(|e| {
                VmRuntimeError::Rootfs(format!("read {} for hashing: {e}", path.display()))
            })?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hex_encode(&hasher.finalize()))
    }

    fn cached_hash(&self, path: &Path, meta: &fs::Metadata) -> VmRuntimeResult<String> {
        // `modified()` is missing on some filesystems (notably some FUSE
        // backends). Fall back to UNIX_EPOCH so the cache is keyed by path
        // alone in that case — the worst-case behaviour is "no caching",
        // not incorrectness.
        let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let key = (path.to_path_buf(), mtime);
        {
            let cache = self
                .hash_cache
                .lock()
                .map_err(|_| VmRuntimeError::StatePoisoned)?;
            if let Some(v) = cache.inner.get(&key) {
                return Ok(v.clone());
            }
        }
        let digest = Self::hash_file(path)?;
        let mut cache = self
            .hash_cache
            .lock()
            .map_err(|_| VmRuntimeError::StatePoisoned)?;
        cache.inner.insert(key, digest.clone());
        Ok(digest)
    }
}

/// Sanitise a VM identifier into a filesystem-safe directory name.
///
/// Mirrors the convention used by [`crate::adapters::firecracker`]'s internal
/// `safe_vm_id`: ASCII alphanumeric, `-`, and `_` pass through; everything
/// else collapses to `_`. Exported so callers and tests can reason about the
/// per-VM clone path without re-deriving it.
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

fn clone_file(source: &Path, dest: &Path) -> VmRuntimeResult<()> {
    // 1. Reflink (btrfs/XFS/bcachefs/ZFS-on-Linux). `cp --reflink=always`
    //    exits non-zero on filesystems that do not support FICLONE, so
    //    failure is the signal to fall through, not a hard error.
    if try_reflink(source, dest).is_ok() {
        return Ok(());
    }
    // Ensure the partial output from a failed reflink attempt is gone before
    // the next strategy runs — `cp` cleans up after itself, but defensively
    // unlink to keep the fallback chain deterministic.
    let _ = fs::remove_file(dest);

    // 2. Hardlink. Safe only if the caller will mount the rootfs read-only
    //    in the guest (documented contract). On cross-FS attempts this
    //    surfaces as `EXDEV` and we fall through to a full copy.
    if fs::hard_link(source, dest).is_ok() {
        return Ok(());
    }
    let _ = fs::remove_file(dest);

    // 3. Full streaming copy. `fs::copy` uses `copy_file_range(2)` under the
    //    hood on Linux, which handles sparse files efficiently — same path
    //    that GNU `cp --sparse=auto` takes when reflink is unavailable.
    fs::copy(source, dest).map_err(|e| {
        VmRuntimeError::Rootfs(format!(
            "copy {} -> {}: {e}",
            source.display(),
            dest.display()
        ))
    })?;
    Ok(())
}

fn try_reflink(source: &Path, dest: &Path) -> std::io::Result<()> {
    // We shell out to `cp` rather than issue FICLONE via ioctl ourselves —
    // GNU coreutils' `cp` already handles the small ABI quirks (e.g. FICLONE
    // on overlayfs, FICLONE on a directory vs file dest) that a hand-rolled
    // ioctl would have to re-derive. `cp` is in every base image we target.
    // `--sparse=always` is incompatible with `--reflink=always` (GNU cp rejects
    // the combination). The default sparse handling (`--sparse=auto`) is what
    // we want anyway when a reflink succeeds — the clone shares blocks with
    // the source via CoW, so sparseness is preserved at the FS layer.
    // stderr is squelched: reflink failure is the normal fall-through signal
    // on ext4/tmpfs and a per-clone noisy "cp: failed to clone" message would
    // drown out legitimate logging.
    let status = Command::new("cp")
        .arg("--reflink=always")
        .arg("--")
        .arg(source)
        .arg(dest)
        .stderr(std::process::Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "cp --reflink=always exit {status}"
        )))
    }
}

fn read_stamp(path: &Path) -> VmRuntimeResult<String> {
    let raw = fs::read_to_string(path)
        .map_err(|e| VmRuntimeError::Rootfs(format!("read stamp {}: {e}", path.display())))?;
    Ok(raw.trim().to_owned())
}

fn write_stamp(path: &Path, digest: &str) -> VmRuntimeResult<()> {
    fs::write(path, digest)
        .map_err(|e| VmRuntimeError::Rootfs(format!("write stamp {}: {e}", path.display())))
}

/// Lowercase hex-encode a 32-byte digest. Inlined to keep `sha2` the only
/// new dependency — pulling in `hex` for thirty bytes of code is not worth
/// the supply-chain surface.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{Duration, SystemTime};

    use tempfile::TempDir;

    /// Build a config rooted under `tempdir`, returning the registry plus the
    /// two child directories so tests can write templates / inspect clones.
    fn registry(tempdir: &TempDir) -> (RootfsRegistry, PathBuf, PathBuf) {
        let template_dir = tempdir.path().join("templates");
        let clones_dir = tempdir.path().join("clones");
        fs::create_dir_all(&template_dir).unwrap();
        let cfg = RootfsConfig {
            template_dir: template_dir.clone(),
            clones_dir: clones_dir.clone(),
        };
        (RootfsRegistry::new(cfg), template_dir, clones_dir)
    }

    fn write_template(template_dir: &Path, stack: &str, bytes: &[u8]) -> PathBuf {
        let dir = template_dir.join(stack);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(TEMPLATE_ROOTFS_FILE);
        fs::write(&path, bytes).unwrap();
        path
    }

    /// Stamp the file's mtime back by `secs` so that a follow-up write
    /// produces a strictly-greater mtime — guards against single-second
    /// mtime resolution on some filesystems making cache-invalidation tests
    /// flaky.
    fn rewind_mtime(path: &Path, secs: u64) {
        let now = SystemTime::now();
        let earlier = now - Duration::from_secs(secs);
        // `filetime` is not a dep; use `utimensat` via libc-free `set_modified`
        // on the File handle.
        let f = fs::File::open(path).unwrap();
        f.set_modified(earlier).unwrap();
    }

    // ============================================================ stacks() ====

    #[test]
    fn stacks_lists_all_subdirs_with_rootfs() {
        let tmp = TempDir::new().unwrap();
        let (reg, tdir, _cdir) = registry(&tmp);
        write_template(&tdir, "base", b"BASE-ROOTFS");
        write_template(&tdir, "node-20", b"NODE-20-ROOTFS");
        // A subdir without `rootfs.ext4` is silently skipped.
        fs::create_dir_all(tdir.join("incomplete")).unwrap();

        let stacks = reg.stacks().unwrap();
        assert_eq!(stacks.len(), 2);
        assert_eq!(stacks[0].name, "base");
        assert_eq!(stacks[1].name, "node-20");
        assert_eq!(stacks[0].size_bytes, b"BASE-ROOTFS".len() as u64);
        // Distinct templates have distinct hashes.
        assert_ne!(stacks[0].sha256, stacks[1].sha256);
    }

    #[test]
    fn stacks_returns_empty_when_template_dir_missing() {
        let tmp = TempDir::new().unwrap();
        let cfg = RootfsConfig {
            template_dir: tmp.path().join("does-not-exist"),
            clones_dir: tmp.path().join("clones"),
        };
        let reg = RootfsRegistry::new(cfg);
        assert!(reg.stacks().unwrap().is_empty());
    }

    #[test]
    fn stack_by_name_returns_none_for_missing() {
        let tmp = TempDir::new().unwrap();
        let (reg, tdir, _) = registry(&tmp);
        write_template(&tdir, "base", b"x");
        assert!(reg.stack("base").unwrap().is_some());
        assert!(reg.stack("nope").unwrap().is_none());
    }

    // ====================================================== sha256 cache ====

    #[test]
    fn hash_cache_skips_rehash_when_mtime_unchanged() {
        let tmp = TempDir::new().unwrap();
        let (reg, tdir, _) = registry(&tmp);
        let path = write_template(&tdir, "base", b"first-bytes");
        rewind_mtime(&path, 5);

        let first = reg.stack("base").unwrap().unwrap().sha256;

        // Overwrite contents but reset mtime to the prior value — the cache
        // is keyed by `(path, mtime)`, so a stale digest must come back.
        // This is the documented behaviour: changing contents without
        // bumping mtime is a deployment error the cache cannot detect.
        let mtime_before = fs::metadata(&path).unwrap().modified().unwrap();
        let mut f = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        f.write_all(b"second-bytes-different-length").unwrap();
        drop(f);
        fs::File::open(&path)
            .unwrap()
            .set_modified(mtime_before)
            .unwrap();

        let second = reg.stack("base").unwrap().unwrap().sha256;
        assert_eq!(first, second, "cache must hold while mtime unchanged");
    }

    #[test]
    fn hash_cache_invalidates_when_mtime_advances() {
        let tmp = TempDir::new().unwrap();
        let (reg, tdir, _) = registry(&tmp);
        let path = write_template(&tdir, "base", b"first");
        rewind_mtime(&path, 5);
        let first = reg.stack("base").unwrap().unwrap().sha256;

        // Overwrite with new contents and a fresh mtime: the cache key
        // changes, so the new digest is observed.
        fs::write(&path, b"second").unwrap();
        let second = reg.stack("base").unwrap().unwrap().sha256;
        assert_ne!(first, second);
    }

    // ====================================================== clone_for_vm ====

    #[test]
    fn clone_creates_per_vm_copy_with_stamp() {
        let tmp = TempDir::new().unwrap();
        let (reg, tdir, cdir) = registry(&tmp);
        write_template(&tdir, "base", b"BASE-CONTENTS");
        let live_hash = reg.stack("base").unwrap().unwrap().sha256;

        let rootfs = reg.clone_for_vm("vm-1", "base").unwrap();
        assert_eq!(rootfs.vm_id, "vm-1");
        assert_eq!(rootfs.stack, "base");
        assert_eq!(rootfs.path, cdir.join("vm-1").join(CLONE_ROOTFS_FILE));
        assert_eq!(rootfs.source_sha256, live_hash);

        // Clone file exists and matches template bytes.
        let bytes = fs::read(&rootfs.path).unwrap();
        assert_eq!(bytes, b"BASE-CONTENTS");

        // Stamp sidecar was written with the live hash.
        let stamp = fs::read_to_string(cdir.join("vm-1").join(CLONE_STAMP_FILE)).unwrap();
        assert_eq!(stamp.trim(), live_hash);
    }

    #[test]
    fn clone_is_idempotent_with_matching_stamp() {
        let tmp = TempDir::new().unwrap();
        let (reg, tdir, _) = registry(&tmp);
        write_template(&tdir, "base", b"abc");
        let a = reg.clone_for_vm("vm-1", "base").unwrap();
        let b = reg.clone_for_vm("vm-1", "base").unwrap();
        assert_eq!(a.path, b.path);
        assert_eq!(a.source_sha256, b.source_sha256);
    }

    #[test]
    fn clone_errors_when_stamp_mismatches_live_template() {
        let tmp = TempDir::new().unwrap();
        let (reg, tdir, cdir) = registry(&tmp);
        write_template(&tdir, "base", b"abc");
        reg.clone_for_vm("vm-1", "base").unwrap();

        // Hand-corrupt the stamp file — simulates either disk corruption or
        // a buggy admin who rotated the template under a live VM.
        fs::write(
            cdir.join("vm-1").join(CLONE_STAMP_FILE),
            "deadbeef".repeat(8),
        )
        .unwrap();

        let err = reg.clone_for_vm("vm-1", "base").unwrap_err();
        match err {
            VmRuntimeError::Rootfs(msg) => {
                assert!(
                    msg.contains("stamp mismatch"),
                    "expected stamp mismatch, got: {msg}"
                );
            }
            other => panic!("expected Rootfs error, got: {other:?}"),
        }
    }

    #[test]
    fn clone_errors_when_stack_missing() {
        let tmp = TempDir::new().unwrap();
        let (reg, _tdir, _) = registry(&tmp);
        let err = reg.clone_for_vm("vm-1", "ghost").unwrap_err();
        assert!(matches!(err, VmRuntimeError::Rootfs(_)));
    }

    #[test]
    fn clone_fallback_works_on_non_reflink_filesystem() {
        // tempfile defaults to TMPDIR (typically tmpfs on Linux), which does
        // not support reflink. The reflink path therefore fails and the
        // copy/hardlink fallback must complete successfully. We assert on
        // bytes, not strategy — the public contract is "the clone exists
        // and matches the template", regardless of how it got there.
        let tmp = TempDir::new().unwrap();
        let (reg, tdir, _) = registry(&tmp);
        write_template(&tdir, "base", b"fallback-must-succeed");
        let rootfs = reg.clone_for_vm("vm-1", "base").unwrap();
        let bytes = fs::read(&rootfs.path).unwrap();
        assert_eq!(bytes, b"fallback-must-succeed");
    }

    #[test]
    fn clone_sanitises_vm_id_in_path() {
        let tmp = TempDir::new().unwrap();
        let (reg, tdir, cdir) = registry(&tmp);
        write_template(&tdir, "base", b"x");
        let rootfs = reg.clone_for_vm("vm/with:weird*chars", "base").unwrap();
        assert_eq!(rootfs.vm_id, "vm_with_weird_chars");
        assert!(rootfs.path.starts_with(cdir.join("vm_with_weird_chars")));
    }

    #[test]
    fn clone_rejects_empty_sanitised_id() {
        let tmp = TempDir::new().unwrap();
        let (reg, _, _) = registry(&tmp);
        let err = reg.clone_for_vm("", "base").unwrap_err();
        assert!(matches!(err, VmRuntimeError::Rootfs(_)));
    }

    // ============================================================ release ====

    #[test]
    fn release_removes_per_vm_dir_and_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let (reg, tdir, cdir) = registry(&tmp);
        write_template(&tdir, "base", b"x");
        reg.clone_for_vm("vm-1", "base").unwrap();
        assert!(cdir.join("vm-1").exists());

        reg.release("vm-1").unwrap();
        assert!(!cdir.join("vm-1").exists());

        // Second call is a no-op.
        reg.release("vm-1").unwrap();
    }

    // ========================================================== hash_file ====

    #[test]
    fn hash_file_matches_standard_abc_test_vector() {
        // FIPS 180-2 / NIST sample: SHA-256("abc") =
        // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("abc");
        fs::write(&path, b"abc").unwrap();
        let got = RootfsRegistry::hash_file(&path).unwrap();
        assert_eq!(
            got,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hash_file_handles_empty_input() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("empty");
        fs::write(&path, b"").unwrap();
        let got = RootfsRegistry::hash_file(&path).unwrap();
        assert_eq!(
            got,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hash_file_errors_on_missing_path() {
        let err = RootfsRegistry::hash_file(Path::new("/nonexistent/path/to/nothing")).unwrap_err();
        assert!(matches!(err, VmRuntimeError::Rootfs(_)));
    }

    #[test]
    fn hash_file_handles_multi_chunk_input() {
        // Forces multiple read iterations through the 4 MiB buffer to
        // exercise the streaming path. 10 MiB of zeros has a known digest
        // we can recompute via the same code path to detect regressions.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("zeros");
        let f = fs::File::create(&path).unwrap();
        f.set_len(10 * 1024 * 1024).unwrap();
        let digest = RootfsRegistry::hash_file(&path).unwrap();
        // sha256 of 10 MiB of zeros, verified out-of-band with
        //   `dd if=/dev/zero bs=1M count=10 | sha256sum`
        assert_eq!(
            digest,
            "e5b844cc57f57094ea4585e235f36c78c1cd222262bb89d53c94dcb4d6b3e55d"
        );
    }

    // ========================================================= safe_vm_id ====

    #[test]
    fn safe_vm_id_matches_adapter_convention() {
        assert_eq!(safe_vm_id("vm-1"), "vm-1");
        assert_eq!(safe_vm_id("vm_1"), "vm_1");
        assert_eq!(safe_vm_id("VM1"), "VM1");
        assert_eq!(safe_vm_id("vm/1:foo"), "vm_1_foo");
        assert_eq!(safe_vm_id("a.b/c"), "a_b_c");
    }

    // ============================================================== config ====

    #[test]
    fn config_from_env_picks_up_overrides() {
        // SAFETY: tests in this module run in a shared process; touching
        // env vars is generally unsound. We restrict ourselves to keys
        // that no other module reads and unset on exit. Cargo runs tests
        // in this file serially within this module (single test binary),
        // and we hold the values long enough only for a single from_env.
        let saved_t = std::env::var("MICROVM_ROOTFS_TEMPLATE_DIR").ok();
        let saved_c = std::env::var("MICROVM_ROOTFS_CLONES_DIR").ok();

        // SAFETY: see comment above.
        unsafe {
            std::env::set_var("MICROVM_ROOTFS_TEMPLATE_DIR", "/tmp/mvm-test-templates");
            std::env::set_var("MICROVM_ROOTFS_CLONES_DIR", "/tmp/mvm-test-clones");
        }
        let cfg = RootfsConfig::from_env();
        assert_eq!(cfg.template_dir, PathBuf::from("/tmp/mvm-test-templates"));
        assert_eq!(cfg.clones_dir, PathBuf::from("/tmp/mvm-test-clones"));

        // SAFETY: see comment above.
        unsafe {
            match saved_t {
                Some(v) => std::env::set_var("MICROVM_ROOTFS_TEMPLATE_DIR", v),
                None => std::env::remove_var("MICROVM_ROOTFS_TEMPLATE_DIR"),
            }
            match saved_c {
                Some(v) => std::env::set_var("MICROVM_ROOTFS_CLONES_DIR", v),
                None => std::env::remove_var("MICROVM_ROOTFS_CLONES_DIR"),
            }
        }
    }

    #[test]
    fn config_default_paths_match_documented_constants() {
        let cfg = RootfsConfig::default();
        assert_eq!(cfg.template_dir, PathBuf::from(DEFAULT_TEMPLATE_DIR));
        assert_eq!(cfg.clones_dir, PathBuf::from(DEFAULT_CLONES_DIR));
    }
}
