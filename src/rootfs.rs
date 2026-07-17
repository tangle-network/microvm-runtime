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
//! ## Per-VM disk sizing
//!
//! [`RootfsRegistry::clone_for_vm_with_size`] extends the clone path with an
//! ext4 resize step so the per-VM image can be larger than the template. The
//! sequence is `fallocate` (grow the backing file) → `resize2fs` (grow the
//! filesystem to fill it) → write a sidecar `<path>.size` stamp recording the
//! committed size. The size stamp is independent of the SHA-256 stamp — the
//! latter still tracks the source template digest. Resize-down is rejected:
//! shrinking an image risks data loss for any state the guest wrote, and
//! growing under a live VM is not safe to redo with a different target.
//! Re-calling with a matching size stamp is a no-op; a mismatching size is
//! a hard error for the same reason a SHA-256 stamp mismatch is.
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
use std::sync::{Mutex, Once};
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
/// Sidecar file name holding the decimal byte count of the per-VM image after
/// any resize. Absent when the image was not resized (clone equals template).
pub const CLONE_SIZE_STAMP_FILE: &str = "rootfs.ext4.size";

/// Environment variable used by tests (and, optionally, exotic hosts where
/// `resize2fs` is installed under a non-default name) to override the
/// resize2fs binary path. Read by [`RootfsConfig::from_env`]; production
/// callers building config explicitly should pass the path via
/// [`RootfsConfig::resize2fs_bin`] instead.
const RESIZE2FS_BIN_ENV: &str = "MICROVM_RESIZE2FS_BIN";

/// Default name of the resize2fs binary searched on `PATH`. Lifted into a
/// constant so the env-override layer and the default config both reference
/// the same string and stay in sync.
pub const DEFAULT_RESIZE2FS_BIN: &str = "resize2fs";

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
    /// Path (or PATH-resolvable name) of the `resize2fs` binary used by
    /// [`RootfsRegistry::clone_for_vm_with_size`]. Default
    /// [`DEFAULT_RESIZE2FS_BIN`]. Override for test doubles or non-standard
    /// install locations (e.g. a stripped-down container that ships
    /// `resize2fs` under `/sbin/resize2fs`).
    pub resize2fs_bin: PathBuf,
}

impl Default for RootfsConfig {
    fn default() -> Self {
        Self {
            template_dir: PathBuf::from(DEFAULT_TEMPLATE_DIR),
            clones_dir: PathBuf::from(DEFAULT_CLONES_DIR),
            resize2fs_bin: PathBuf::from(DEFAULT_RESIZE2FS_BIN),
        }
    }
}

impl RootfsConfig {
    /// Build from environment variables.
    ///
    /// - `MICROVM_ROOTFS_TEMPLATE_DIR` overrides [`Self::template_dir`].
    /// - `MICROVM_ROOTFS_CLONES_DIR` overrides [`Self::clones_dir`].
    /// - `MICROVM_RESIZE2FS_BIN` overrides [`Self::resize2fs_bin`].
    pub fn from_env() -> Self {
        let defaults = Self::default();
        let template_dir = std::env::var("MICROVM_ROOTFS_TEMPLATE_DIR")
            .map(PathBuf::from)
            .unwrap_or(defaults.template_dir);
        let clones_dir = std::env::var("MICROVM_ROOTFS_CLONES_DIR")
            .map(PathBuf::from)
            .unwrap_or(defaults.clones_dir);
        let resize2fs_bin = std::env::var(RESIZE2FS_BIN_ENV)
            .map(PathBuf::from)
            .unwrap_or(defaults.resize2fs_bin);
        Self {
            template_dir,
            clones_dir,
            resize2fs_bin,
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
    /// Final size of the per-VM image after any resize. For unresized clones
    /// (returned by [`RootfsRegistry::clone_for_vm`] or by
    /// [`RootfsRegistry::clone_for_vm_with_size`] with `target_bytes` equal
    /// to the source template size) this equals the source template size.
    pub size_bytes: u64,
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
        self.clone_for_vm_inner(vm_id, stack_name, CloneMode::SharedOk)
    }

    fn clone_for_vm_inner(
        &self,
        vm_id: &str,
        stack_name: &str,
        mode: CloneMode,
    ) -> VmRuntimeResult<VmRootfs> {
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
                let size_bytes = current_size_bytes(&clone_path)?;
                return Ok(VmRootfs {
                    vm_id: safe_id,
                    stack: stack.name,
                    path: clone_path,
                    source_sha256: stamp,
                    size_bytes,
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

        clone_file_with_mode(&stack.template_path, &clone_path, mode)?;
        write_stamp(&stamp_path, &stack.sha256)?;

        Ok(VmRootfs {
            vm_id: safe_id,
            stack: stack.name,
            path: clone_path,
            source_sha256: stack.sha256,
            size_bytes: stack.size_bytes,
        })
    }

    /// Same as [`Self::clone_for_vm`] but also resizes the per-VM image to
    /// `target_bytes`.
    ///
    /// The resize sequence (when `target_bytes > source_bytes`) is:
    /// 1. Clone the template into the per-VM slot (reuses [`Self::clone_for_vm`]
    ///    semantics, including its SHA-256 stamp idempotency check).
    /// 2. `fallocate` the clone file up to `target_bytes`.
    /// 3. `resize2fs <path>` to expand the ext4 filesystem into the new space.
    /// 4. Write `<path>.size` (decimal `target_bytes`) so subsequent calls
    ///    can detect both "already resized to this size" (idempotent no-op)
    ///    and "previously resized to a different size" (hard error).
    ///
    /// When `target_bytes == source_bytes` the resize step is skipped
    /// entirely — no `fallocate`, no `resize2fs`, no `.size` stamp.
    ///
    /// Resize-down (`target_bytes < source_bytes`) is rejected with
    /// [`VmRuntimeError::Rootfs`]; shrinking an ext4 image risks losing data
    /// the guest already wrote and the on-disk clone is not touched.
    ///
    /// Re-calling with a different `target_bytes` against an existing clone
    /// is a hard error for the same reason a SHA-256 stamp mismatch is — a
    /// live VM holds a view of the disk's size and changing it underneath
    /// would corrupt that view.
    pub fn clone_for_vm_with_size(
        &self,
        vm_id: &str,
        stack_name: &str,
        target_bytes: u64,
    ) -> VmRuntimeResult<VmRootfs> {
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

        // Validate the target up front, before touching the filesystem. This
        // way a reject-shrink never leaves a half-built per-VM directory.
        if target_bytes < stack.size_bytes {
            return Err(VmRuntimeError::Rootfs(format!(
                "resize-down would lose data: target {target_bytes} < source {} for stack '{}'",
                stack.size_bytes, stack.name,
            )));
        }

        let vm_dir = self.config.clones_dir.join(&safe_id);
        let size_stamp_path = vm_dir.join(CLONE_SIZE_STAMP_FILE);

        // If a prior call resized this slot, refuse to change the size. We
        // check BEFORE calling `clone_for_vm` so a mismatch never re-stats
        // the clone path or re-reads the sha stamp redundantly.
        if size_stamp_path.exists() {
            let recorded = read_size_stamp(&size_stamp_path)?;
            if recorded != target_bytes {
                return Err(VmRuntimeError::Rootfs(format!(
                    "vm '{safe_id}' size stamp mismatch (stamp={recorded}, requested={target_bytes}) — release the VM before resizing"
                )));
            }
        }

        // If a resize is required, force an independent clone (no hardlink
        // fallback) so the subsequent fallocate/resize2fs does not mutate
        // the shared template inode. When `target_bytes == stack.size_bytes`
        // a hardlinked clone is fine — we will not write to it.
        let clone_mode = if target_bytes == stack.size_bytes {
            CloneMode::SharedOk
        } else {
            CloneMode::Independent
        };
        let mut rootfs = self.clone_for_vm_inner(vm_id, stack_name, clone_mode)?;

        // Fast path: no resize requested.
        if target_bytes == stack.size_bytes {
            // If the slot already had a `.size` stamp recording the same
            // value (idempotent re-entry where target == source), surface
            // it through `size_bytes` for callers that care.
            if size_stamp_path.exists() {
                rootfs.size_bytes = read_size_stamp(&size_stamp_path)?;
            }
            return Ok(rootfs);
        }

        // Idempotent fast path: clone already resized to exactly this size.
        if size_stamp_path.exists() {
            // Stamp matches (we checked above), nothing more to do — the
            // clone file is already at the right size and the filesystem
            // was expanded on the prior call. Re-running resize2fs is
            // safe but wasteful; skip it.
            rootfs.size_bytes = target_bytes;
            return Ok(rootfs);
        }

        // Defensive: if the per-VM clone is hardlinked to the template (e.g.
        // a prior `clone_for_vm` call landed on the hardlink fallback before
        // resize was wired in), break the link before extending it. Otherwise
        // `set_len` would grow the template through the shared inode and
        // corrupt every other VM cloning from the same stack. Compare device
        // + inode rather than `nlink > 1` because the latter is also true
        // when the user has hardlinked the file for an unrelated reason; we
        // only care if the hardlink target IS the template.
        ensure_independent_inode(&stack.template_path, &rootfs.path)?;

        // First-time resize for this slot. Use the configured resize2fs
        // binary so tests (and exotic hosts) do not need to mutate process
        // env vars to swap in a different binary.
        resize_ext4_image_with_bin(&rootfs.path, target_bytes, &self.config.resize2fs_bin)?;
        write_size_stamp(&size_stamp_path, target_bytes)?;
        rootfs.size_bytes = target_bytes;
        Ok(rootfs)
    }

    /// Resize an ext4 image file to `target_bytes`.
    ///
    /// Internal logic shared by [`Self::clone_for_vm_with_size`]. Public so
    /// callers building images outside the registry can use the same resize
    /// semantics: refuse to shrink, grow the backing file via
    /// [`std::fs::File::set_len`], then run `resize2fs` against it.
    ///
    /// `resize2fs` is shelled out (no in-process ext4 manipulation). The
    /// default binary is `resize2fs` on `PATH`; the `MICROVM_RESIZE2FS_BIN`
    /// environment variable, if set, overrides it. Callers that want
    /// deterministic injection (e.g. tests, or producers running inside a
    /// minimal container with `resize2fs` at a non-standard path) should set
    /// [`RootfsConfig::resize2fs_bin`] and go through
    /// [`Self::clone_for_vm_with_size`] instead — `clone_for_vm_with_size`
    /// uses the configured binary without touching process env.
    pub fn resize_ext4_image(path: &Path, target_bytes: u64) -> VmRuntimeResult<()> {
        let bin = std::env::var(RESIZE2FS_BIN_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_RESIZE2FS_BIN));
        resize_ext4_image_with_bin(path, target_bytes, &bin)
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

/// Internal: extend `path` to `target_bytes` and run `resize2fs_bin` to grow
/// the ext4 filesystem. Refuses to shrink. No-op when the file is already at
/// the requested size.
fn resize_ext4_image_with_bin(
    path: &Path,
    target_bytes: u64,
    resize2fs_bin: &Path,
) -> VmRuntimeResult<()> {
    let meta = fs::metadata(path).map_err(|e| {
        VmRuntimeError::Rootfs(format!("stat image {} for resize: {e}", path.display()))
    })?;
    let current = meta.len();

    if target_bytes < current {
        return Err(VmRuntimeError::Rootfs(format!(
            "resize-down would lose data: target {target_bytes} < current {current} for {}",
            path.display(),
        )));
    }
    if target_bytes == current {
        // Caller-driven idempotency: same target as current size is a no-op.
        // We deliberately do not run resize2fs here — the file hasn't grown,
        // so the filesystem has nothing to do.
        return Ok(());
    }

    // 1. Grow the backing file. `File::set_len` is the portable wrapper
    //    around `ftruncate(2)`; on filesystems that support sparse files
    //    (ext4, XFS, btrfs, tmpfs) the new bytes are unallocated until
    //    written, so this is O(1) and uses no real disk until resize2fs
    //    (or the guest) starts touching pages.
    {
        let f = fs::OpenOptions::new().write(true).open(path).map_err(|e| {
            VmRuntimeError::Rootfs(format!("open image {} for resize: {e}", path.display()))
        })?;
        f.set_len(target_bytes).map_err(|e| {
            VmRuntimeError::Rootfs(format!(
                "extend image {} to {target_bytes} bytes: {e}",
                path.display(),
            ))
        })?;
    }

    // 2. Grow the ext4 filesystem to fill the new file size. `-f` forces a
    //    resize even when the kernel has not seen a recent fsck — fresh
    //    template images are typically clean, but the flag keeps the
    //    contract forgiving against corner cases like a template that was
    //    last touched on a different kernel.
    let output = Command::new(resize2fs_bin)
        .arg("-f")
        .arg("--")
        .arg(path)
        .output()
        .map_err(|e| {
            VmRuntimeError::Rootfs(format!(
                "spawn {} on {}: {e}",
                resize2fs_bin.display(),
                path.display(),
            ))
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(VmRuntimeError::Rootfs(format!(
            "{} {} exit {}: {}",
            resize2fs_bin.display(),
            path.display(),
            output.status,
            stderr.trim(),
        )));
    }
    Ok(())
}

/// Whether the caller intends to write to `dest`.
///
/// - `SharedOk`: the caller will mount the clone read-only in the guest, so a
///   hardlink that shares the inode with `source` is acceptable. This is the
///   default and is what [`RootfsRegistry::clone_for_vm`] uses.
/// - `Independent`: the caller will write to `dest` (e.g. resize, sparse
///   extend). Hardlink fallback is skipped because mutating the clone would
///   also mutate the source template. Only reflink (true CoW) or a real copy
///   are acceptable.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum CloneMode {
    SharedOk,
    Independent,
}

/// Which rung of the reflink → hardlink → copy ladder a clone landed on.
/// Surfaced so callers/tests can observe the effective clone cost — a
/// `FullCopy` means every VM pays a whole-image byte copy.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum CloneStrategy {
    Reflink,
    Hardlink,
    FullCopy,
}

/// One-shot latch for the full-copy warning: a fleet of VMs on a
/// non-reflink filesystem would otherwise emit one line per clone.
static FULL_COPY_WARNING: Once = Once::new();

fn clone_file_with_mode(
    source: &Path,
    dest: &Path,
    mode: CloneMode,
) -> VmRuntimeResult<CloneStrategy> {
    // 1. Reflink (btrfs/XFS/bcachefs/ZFS-on-Linux). `cp --reflink=always`
    //    exits non-zero on filesystems that do not support FICLONE, so
    //    failure is the signal to fall through, not a hard error.
    if try_reflink(source, dest).is_ok() {
        return Ok(CloneStrategy::Reflink);
    }
    // Ensure the partial output from a failed reflink attempt is gone before
    // the next strategy runs — `cp` cleans up after itself, but defensively
    // unlink to keep the fallback chain deterministic.
    let _ = fs::remove_file(dest);

    // 2. Hardlink. Safe only when the caller mounts the rootfs read-only in
    //    the guest. Callers that will write to the clone (resize, sparse
    //    extend) must skip this step or risk mutating the source template
    //    through the shared inode.
    if mode == CloneMode::SharedOk {
        if fs::hard_link(source, dest).is_ok() {
            return Ok(CloneStrategy::Hardlink);
        }
        let _ = fs::remove_file(dest);
    }

    // Landing here means every clone of a multi-GB rootfs is a full byte
    // copy — operationally fine, but slow enough (seconds per VM) that it
    // must not stay silent. Warn once per process; the remediation is a
    // reflink-capable filesystem, not a code change.
    FULL_COPY_WARNING.call_once(|| {
        eprintln!(
            "[microvm-rootfs] cloning {} by full byte copy: the filesystem \
             supports no reflink (and hardlink sharing does not apply). Every \
             VM clone copies the entire image; host the rootfs dirs on btrfs \
             or XFS (reflink=1) for instant CoW clones. Warned once — later \
             clones stay on this path silently.",
            source.display()
        );
    });

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
    Ok(CloneStrategy::FullCopy)
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

fn read_size_stamp(path: &Path) -> VmRuntimeResult<u64> {
    let raw = fs::read_to_string(path)
        .map_err(|e| VmRuntimeError::Rootfs(format!("read size stamp {}: {e}", path.display())))?;
    raw.trim().parse::<u64>().map_err(|e| {
        VmRuntimeError::Rootfs(format!(
            "parse size stamp {} (contents={:?}): {e}",
            path.display(),
            raw,
        ))
    })
}

fn write_size_stamp(path: &Path, target_bytes: u64) -> VmRuntimeResult<()> {
    fs::write(path, target_bytes.to_string())
        .map_err(|e| VmRuntimeError::Rootfs(format!("write size stamp {}: {e}", path.display())))
}

fn current_size_bytes(path: &Path) -> VmRuntimeResult<u64> {
    fs::metadata(path)
        .map(|m| m.len())
        .map_err(|e| VmRuntimeError::Rootfs(format!("stat {} for size: {e}", path.display())))
}

/// Ensure `clone` does not share an inode with `source`. If it does (the
/// hardlink fallback was used during a prior clone), replace `clone` with an
/// independent copy of its current contents so subsequent writes to `clone`
/// no longer mutate `source`.
fn ensure_independent_inode(source: &Path, clone: &Path) -> VmRuntimeResult<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let src_meta = fs::metadata(source).map_err(|e| {
            VmRuntimeError::Rootfs(format!("stat source {} for inode: {e}", source.display()))
        })?;
        let clone_meta = fs::metadata(clone).map_err(|e| {
            VmRuntimeError::Rootfs(format!("stat clone {} for inode: {e}", clone.display()))
        })?;
        if src_meta.dev() != clone_meta.dev() || src_meta.ino() != clone_meta.ino() {
            return Ok(());
        }

        // Inode is shared. Materialise an independent copy in a sibling
        // temp file, then atomically replace the clone. Going through a
        // temp file ensures we never leave the per-VM slot in a
        // half-broken state if the copy aborts mid-stream.
        let tmp = clone.with_extension("ext4.unlinkme");
        // Pre-clean any stale temp from a prior aborted run.
        let _ = fs::remove_file(&tmp);
        fs::copy(clone, &tmp).map_err(|e| {
            VmRuntimeError::Rootfs(format!(
                "break hardlink via copy {} -> {}: {e}",
                clone.display(),
                tmp.display(),
            ))
        })?;
        fs::rename(&tmp, clone).map_err(|e| {
            // Clean up the temp so a retry doesn't trip the pre-clean.
            let _ = fs::remove_file(&tmp);
            VmRuntimeError::Rootfs(format!(
                "rename {} -> {}: {e}",
                tmp.display(),
                clone.display(),
            ))
        })?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        // The `firecracker` feature is Linux-only in practice; on other hosts
        // we leave the clone in place. This keeps the helper compilable
        // under `cargo check --target` cross-builds and tests that may run
        // on a non-Linux developer machine.
        let _ = (source, clone);
    }
    Ok(())
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
    /// `resize2fs_bin` defaults to `/bin/true` so tests exercise the
    /// fallocate path without needing `e2fsprogs` installed; tests that need
    /// the real or a different binary should construct via
    /// [`registry_with_resize_bin`].
    fn registry(tempdir: &TempDir) -> (RootfsRegistry, PathBuf, PathBuf) {
        registry_with_resize_bin(tempdir, PathBuf::from("true"))
    }

    fn registry_with_resize_bin(
        tempdir: &TempDir,
        resize2fs_bin: PathBuf,
    ) -> (RootfsRegistry, PathBuf, PathBuf) {
        let template_dir = tempdir.path().join("templates");
        let clones_dir = tempdir.path().join("clones");
        fs::create_dir_all(&template_dir).unwrap();
        let cfg = RootfsConfig {
            template_dir: template_dir.clone(),
            clones_dir: clones_dir.clone(),
            resize2fs_bin,
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
            resize2fs_bin: PathBuf::from(DEFAULT_RESIZE2FS_BIN),
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
        // Unresized clones report the template size.
        assert_eq!(rootfs.size_bytes, b"BASE-CONTENTS".len() as u64);

        // Clone file exists and matches template bytes.
        let bytes = fs::read(&rootfs.path).unwrap();
        assert_eq!(bytes, b"BASE-CONTENTS");

        // Stamp sidecar was written with the live hash.
        let stamp = fs::read_to_string(cdir.join("vm-1").join(CLONE_STAMP_FILE)).unwrap();
        assert_eq!(stamp.trim(), live_hash);

        // No size stamp is written by the plain clone path.
        assert!(!cdir.join("vm-1").join(CLONE_SIZE_STAMP_FILE).exists());
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
        let saved_r = std::env::var(RESIZE2FS_BIN_ENV).ok();

        // SAFETY: see comment above.
        unsafe {
            std::env::set_var("MICROVM_ROOTFS_TEMPLATE_DIR", "/tmp/mvm-test-templates");
            std::env::set_var("MICROVM_ROOTFS_CLONES_DIR", "/tmp/mvm-test-clones");
            std::env::set_var(RESIZE2FS_BIN_ENV, "/tmp/mvm-test-resize2fs");
        }
        let cfg = RootfsConfig::from_env();
        assert_eq!(cfg.template_dir, PathBuf::from("/tmp/mvm-test-templates"));
        assert_eq!(cfg.clones_dir, PathBuf::from("/tmp/mvm-test-clones"));
        assert_eq!(cfg.resize2fs_bin, PathBuf::from("/tmp/mvm-test-resize2fs"));

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
            match saved_r {
                Some(v) => std::env::set_var(RESIZE2FS_BIN_ENV, v),
                None => std::env::remove_var(RESIZE2FS_BIN_ENV),
            }
        }
    }

    #[test]
    fn config_default_paths_match_documented_constants() {
        let cfg = RootfsConfig::default();
        assert_eq!(cfg.template_dir, PathBuf::from(DEFAULT_TEMPLATE_DIR));
        assert_eq!(cfg.clones_dir, PathBuf::from(DEFAULT_CLONES_DIR));
        assert_eq!(cfg.resize2fs_bin, PathBuf::from(DEFAULT_RESIZE2FS_BIN));
    }

    // ===================================================== clone strategy ====

    #[test]
    fn shared_clone_never_lands_on_full_copy_within_one_fs() {
        // Source and dest share a tempdir (one filesystem), so even without
        // reflink support the hardlink rung must catch a SharedOk clone —
        // FullCopy here would mean the ladder is broken.
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("template.ext4");
        let dst = tmp.path().join("clone.ext4");
        fs::write(&src, b"rootfs-bytes").unwrap();
        let strategy = clone_file_with_mode(&src, &dst, CloneMode::SharedOk).unwrap();
        assert_ne!(strategy, CloneStrategy::FullCopy, "got {strategy:?}");
        assert_eq!(fs::read(&dst).unwrap(), b"rootfs-bytes");
    }

    #[test]
    fn independent_clone_never_shares_the_source_inode() {
        // Independent mode must skip the hardlink rung: it lands on reflink
        // (new inode, CoW) or a full copy (new inode), never inode sharing.
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("template.ext4");
        let dst = tmp.path().join("clone.ext4");
        fs::write(&src, b"rootfs-bytes").unwrap();
        let strategy = clone_file_with_mode(&src, &dst, CloneMode::Independent).unwrap();
        assert_ne!(strategy, CloneStrategy::Hardlink);
        use std::os::unix::fs::MetadataExt;
        let (s, d) = (fs::metadata(&src).unwrap(), fs::metadata(&dst).unwrap());
        assert_ne!(s.ino(), d.ino(), "independent clone shares the inode");
        assert_eq!(fs::read(&dst).unwrap(), b"rootfs-bytes");
    }

    // ============================================== clone_for_vm_with_size ====

    fn template_bytes(n: usize) -> Vec<u8> {
        // Non-zero pattern so a successful fallocate-extend can be told apart
        // from "the file was always this big and full of zeros".
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn clone_with_size_equal_to_source_is_no_op_fast_path() {
        // Use a deliberately broken resize2fs binary: if the code shells out
        // at all the command spawn fails and the test fails. This catches
        // regressions where the equal-size short-circuit is skipped.
        let tmp = TempDir::new().unwrap();
        let (reg, tdir, cdir) =
            registry_with_resize_bin(&tmp, PathBuf::from("/nonexistent-resize2fs-bin"));
        let src = template_bytes(4096);
        write_template(&tdir, "base", &src);

        let target = src.len() as u64;
        let rootfs = reg.clone_for_vm_with_size("vm-1", "base", target).unwrap();
        assert_eq!(rootfs.size_bytes, target);
        // No size stamp because the resize step was skipped entirely.
        assert!(!cdir.join("vm-1").join(CLONE_SIZE_STAMP_FILE).exists());
        // Clone content equals template.
        assert_eq!(fs::read(&rootfs.path).unwrap(), src);
    }

    #[test]
    fn clone_with_size_smaller_than_source_errors_and_leaves_image_untouched() {
        let tmp = TempDir::new().unwrap();
        let (reg, tdir, cdir) = registry(&tmp);
        let src = template_bytes(8192);
        write_template(&tdir, "base", &src);

        let err = reg
            .clone_for_vm_with_size("vm-1", "base", 4096)
            .unwrap_err();
        match err {
            VmRuntimeError::Rootfs(msg) => assert!(
                msg.contains("resize-down would lose data"),
                "expected shrink message, got: {msg}"
            ),
            other => panic!("expected Rootfs error, got: {other:?}"),
        }
        // No per-VM directory should have been created — validation runs
        // before any filesystem mutation.
        assert!(!cdir.join("vm-1").exists());
    }

    #[test]
    fn clone_with_size_grows_image_and_writes_size_stamp() {
        let tmp = TempDir::new().unwrap();
        let (reg, tdir, cdir) = registry(&tmp);
        let src = template_bytes(4096);
        write_template(&tdir, "base", &src);
        // Capture template inode so we can verify the resize did NOT mutate
        // it (which would happen if the hardlink fallback leaked through to
        // the writable resize path).
        let template_path = tdir.join("base").join(TEMPLATE_ROOTFS_FILE);
        let template_len_before = fs::metadata(&template_path).unwrap().len();

        let target = (src.len() * 4) as u64;
        let rootfs = reg.clone_for_vm_with_size("vm-1", "base", target).unwrap();
        assert_eq!(rootfs.size_bytes, target);

        // Backing file grew to target via fallocate.
        assert_eq!(fs::metadata(&rootfs.path).unwrap().len(), target);
        // Template was NOT mutated. This is the key invariant: writes to
        // the per-VM clone must not bleed back into the canonical template.
        assert_eq!(
            fs::metadata(&template_path).unwrap().len(),
            template_len_before,
        );
        // Size stamp records the committed target.
        let stamp = fs::read_to_string(cdir.join("vm-1").join(CLONE_SIZE_STAMP_FILE)).unwrap();
        assert_eq!(stamp.trim().parse::<u64>().unwrap(), target);
        // Original template bytes are still at the head of the clone.
        let read = fs::read(&rootfs.path).unwrap();
        assert_eq!(&read[..src.len()], &src[..]);
        // Extension region is zero-filled by `set_len` (sparse semantics).
        assert!(read[src.len()..].iter().all(|&b| b == 0));
    }

    #[test]
    fn clone_with_size_breaks_pre_existing_hardlink_before_resize() {
        // Simulates the migration case: a VM was cloned with `clone_for_vm`
        // first (landing on the hardlink fallback because tmpfs has no
        // reflink), then later resized via `clone_for_vm_with_size`. The
        // resize must break the hardlink so the template is not mutated.
        let tmp = TempDir::new().unwrap();
        let (reg, tdir, _cdir) = registry(&tmp);
        let src = template_bytes(4096);
        write_template(&tdir, "base", &src);
        let template_path = tdir.join("base").join(TEMPLATE_ROOTFS_FILE);

        // First clone uses SharedOk → hardlink on tmpfs.
        let first = reg.clone_for_vm("vm-1", "base").unwrap();
        {
            use std::os::unix::fs::MetadataExt;
            let t = fs::metadata(&template_path).unwrap();
            let c = fs::metadata(&first.path).unwrap();
            assert_eq!(t.ino(), c.ino(), "test pre-condition: hardlinked clone");
        }

        // Now resize. The resize must break the hardlink and grow the
        // clone, leaving the template at its original size.
        let target = (src.len() * 2) as u64;
        let resized = reg.clone_for_vm_with_size("vm-1", "base", target).unwrap();
        assert_eq!(fs::metadata(&resized.path).unwrap().len(), target);
        assert_eq!(
            fs::metadata(&template_path).unwrap().len(),
            src.len() as u64,
            "template must not grow when a hardlinked clone is resized",
        );
        // Inodes should differ now.
        {
            use std::os::unix::fs::MetadataExt;
            let t = fs::metadata(&template_path).unwrap();
            let c = fs::metadata(&resized.path).unwrap();
            assert_ne!(t.ino(), c.ino(), "resize must break the hardlink");
        }
    }

    #[test]
    fn clone_with_size_is_idempotent_and_does_not_rewrite_size_stamp() {
        let tmp = TempDir::new().unwrap();
        let (reg, tdir, cdir) = registry(&tmp);
        let src = template_bytes(4096);
        write_template(&tdir, "base", &src);

        let target = (src.len() * 2) as u64;
        let first = reg.clone_for_vm_with_size("vm-1", "base", target).unwrap();
        let stamp_path = cdir.join("vm-1").join(CLONE_SIZE_STAMP_FILE);
        let first_mtime = fs::metadata(&stamp_path).unwrap().modified().unwrap();

        // Backdate the stamp's mtime so any rewrite on the second call
        // would produce a strictly-greater mtime. Without this guard the
        // assertion below would be flaky on filesystems with 1-second
        // mtime resolution.
        let backdated = first_mtime - Duration::from_secs(5);
        fs::File::open(&stamp_path)
            .unwrap()
            .set_modified(backdated)
            .unwrap();

        let second = reg.clone_for_vm_with_size("vm-1", "base", target).unwrap();
        assert_eq!(first.size_bytes, second.size_bytes);
        assert_eq!(first.path, second.path);

        let second_mtime = fs::metadata(&stamp_path).unwrap().modified().unwrap();
        assert_eq!(
            backdated, second_mtime,
            "second call must not rewrite the size stamp"
        );
    }

    #[test]
    fn clone_with_size_rejects_different_target_on_second_call() {
        let tmp = TempDir::new().unwrap();
        let (reg, tdir, cdir) = registry(&tmp);
        let src = template_bytes(4096);
        write_template(&tdir, "base", &src);

        let first_target = (src.len() * 2) as u64;
        reg.clone_for_vm_with_size("vm-1", "base", first_target)
            .unwrap();

        // Snapshot mtime + bytes of the clone image so we can assert the
        // failed call doesn't mutate it.
        let clone_path = cdir.join("vm-1").join(CLONE_ROOTFS_FILE);
        let before_meta = fs::metadata(&clone_path).unwrap();
        let before_len = before_meta.len();
        let before_mtime = before_meta.modified().unwrap();

        let second_target = (src.len() * 3) as u64;
        let err = reg
            .clone_for_vm_with_size("vm-1", "base", second_target)
            .unwrap_err();
        match err {
            VmRuntimeError::Rootfs(msg) => assert!(
                msg.contains("size stamp mismatch"),
                "expected size stamp mismatch, got: {msg}"
            ),
            other => panic!("expected Rootfs error, got: {other:?}"),
        }

        let after_meta = fs::metadata(&clone_path).unwrap();
        assert_eq!(before_len, after_meta.len());
        assert_eq!(before_mtime, after_meta.modified().unwrap());
    }

    #[test]
    fn clone_with_size_then_equal_to_source_passes_through_recorded_size() {
        // A slot resized previously (size_stamp at 8192) gets a follow-up
        // call with `target_bytes == source_bytes` (4096). The check must
        // reject because the existing stamp (8192) does not match the
        // requested (4096), and the per-VM clone must not be touched.
        let tmp = TempDir::new().unwrap();
        let (reg, tdir, _cdir) = registry(&tmp);
        let src = template_bytes(4096);
        write_template(&tdir, "base", &src);

        reg.clone_for_vm_with_size("vm-1", "base", 8192).unwrap();
        let err = reg
            .clone_for_vm_with_size("vm-1", "base", src.len() as u64)
            .unwrap_err();
        match err {
            VmRuntimeError::Rootfs(msg) => assert!(
                msg.contains("size stamp mismatch"),
                "expected size stamp mismatch, got: {msg}"
            ),
            other => panic!("expected Rootfs error, got: {other:?}"),
        }
    }

    // ============================================== resize_ext4_image ====

    #[test]
    fn resize_ext4_image_with_bin_rejects_target_less_than_current() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("img.ext4");
        fs::write(&path, vec![0u8; 8192]).unwrap();
        let err = resize_ext4_image_with_bin(&path, 4096, Path::new("true")).unwrap_err();
        match err {
            VmRuntimeError::Rootfs(msg) => assert!(
                msg.contains("resize-down would lose data"),
                "expected shrink message, got: {msg}"
            ),
            other => panic!("expected Rootfs error, got: {other:?}"),
        }
        // The file size is unchanged.
        assert_eq!(fs::metadata(&path).unwrap().len(), 8192);
    }

    #[test]
    fn resize_ext4_image_with_bin_target_equal_to_current_is_no_op() {
        // Bin set to /nonexistent: if the code shells out at all the test
        // fails. The function must short-circuit when target == current.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("img.ext4");
        let payload = template_bytes(4096);
        fs::write(&path, &payload).unwrap();
        resize_ext4_image_with_bin(&path, 4096, Path::new("/nonexistent-resize2fs-bin")).unwrap();
        assert_eq!(fs::read(&path).unwrap(), payload);
    }

    #[test]
    fn resize_ext4_image_with_bin_extends_file_via_set_len() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("img.ext4");
        let payload = template_bytes(4096);
        fs::write(&path, &payload).unwrap();
        resize_ext4_image_with_bin(&path, 16384, Path::new("true")).unwrap();
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.len(), 16384);
        let bytes = fs::read(&path).unwrap();
        assert_eq!(&bytes[..payload.len()], &payload[..]);
        assert!(bytes[payload.len()..].iter().all(|&b| b == 0));
    }

    #[test]
    fn resize_ext4_image_with_bin_surfaces_resize2fs_failure() {
        // `false` exits non-zero — exercises the non-success branch.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("img.ext4");
        fs::write(&path, vec![0u8; 4096]).unwrap();
        let err = resize_ext4_image_with_bin(&path, 8192, Path::new("false")).unwrap_err();
        match err {
            VmRuntimeError::Rootfs(msg) => assert!(
                msg.contains("exit"),
                "expected non-zero exit message, got: {msg}"
            ),
            other => panic!("expected Rootfs error, got: {other:?}"),
        }
        // Even on resize2fs failure, the file was already grown by set_len
        // — there is no rollback path. Document this contract via the
        // assertion so a future refactor that adds rollback is forced to
        // update the test.
        assert_eq!(fs::metadata(&path).unwrap().len(), 8192);
    }

    #[test]
    fn resize_ext4_image_with_bin_surfaces_spawn_failure() {
        // Non-existent binary: the spawn itself fails, distinct from a
        // non-zero exit. The error message must still surface.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("img.ext4");
        fs::write(&path, vec![0u8; 4096]).unwrap();
        let err = resize_ext4_image_with_bin(&path, 8192, Path::new("/nonexistent-resize2fs"))
            .unwrap_err();
        match err {
            VmRuntimeError::Rootfs(msg) => assert!(
                msg.contains("spawn"),
                "expected spawn failure message, got: {msg}"
            ),
            other => panic!("expected Rootfs error, got: {other:?}"),
        }
    }

    // ============================================== integration: real ext4 ====

    /// Requires `e2fsprogs` installed (`resize2fs` on PATH) and a real ext4
    /// image to operate on. Builds the image with `mke2fs -t ext4` against a
    /// sparse 4 MiB file, resizes to 8 MiB, and verifies the filesystem
    /// reports the new size via `dumpe2fs`. Run with
    /// `cargo test --features firecracker -- --ignored`.
    #[test]
    #[ignore = "requires e2fsprogs (mke2fs + resize2fs + dumpe2fs) on PATH"]
    fn resize_ext4_image_integration_with_real_ext4() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("img.ext4");
        // 4 MiB sparse file.
        let initial: u64 = 4 * 1024 * 1024;
        let target: u64 = 8 * 1024 * 1024;
        {
            let f = fs::File::create(&path).unwrap();
            f.set_len(initial).unwrap();
        }
        let mke2fs = Command::new("mke2fs")
            .arg("-q")
            .arg("-t")
            .arg("ext4")
            .arg("-F")
            .arg(&path)
            .output()
            .expect("mke2fs not on PATH — install e2fsprogs");
        assert!(
            mke2fs.status.success(),
            "mke2fs failed: {}",
            String::from_utf8_lossy(&mke2fs.stderr),
        );
        RootfsRegistry::resize_ext4_image(&path, target).expect("resize2fs failed");
        assert_eq!(fs::metadata(&path).unwrap().len(), target);

        let dump = Command::new("dumpe2fs")
            .arg("-h")
            .arg(&path)
            .output()
            .expect("dumpe2fs not on PATH");
        assert!(dump.status.success());
        let stdout = String::from_utf8_lossy(&dump.stdout);
        // The "Block count" line in `dumpe2fs -h` reflects the resized FS.
        // ext4 default block size is 4 KiB → 8 MiB / 4 KiB = 2048 blocks.
        let blocks_line = stdout
            .lines()
            .find(|l| l.starts_with("Block count:"))
            .expect("Block count missing from dumpe2fs output");
        let blocks: u64 = blocks_line
            .split_whitespace()
            .last()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(blocks, target / 4096);
    }
}
