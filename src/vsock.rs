//! Per-VM virtio-vsock CID and UDS path management for the Firecracker adapter.
//!
//! Firecracker exposes vsock to a guest as a virtio device whose host endpoint
//! is a unix-domain socket. Two host-side resources need lifecycle management
//! around that: a 32-bit context id (CID) that uniquely identifies the guest
//! on the host's vsock plane, and a UDS path that the operator (and tools
//! talking to it) connect to.
//!
//! This module owns both:
//!
//! - CIDs are allocated deterministically from `vm_id` (stable hash → range
//!   offset). Collisions linear-probe the free space. Allocations are tracked
//!   so `detach` can release them.
//! - UDS paths mirror the adapter's per-VM directory convention
//!   (`socket_dir/<safe_vm_id>/vsock.uds`).
//!
//! ## Firecracker v1.6 snapshot-restore parent-dir race
//!
//! `PUT /snapshot/load` re-binds the vsock UDS at the path encoded in the
//! snapshot file. If the parent directory of that path has been cleaned up
//! between snapshot-create and snapshot-load (e.g. seed VM teardown removed
//! its state dir), Firecracker's `VsockUnixBackend::UnixBind` fails with
//! `NotFound` and the restore aborts. `ensure_uds_parent` re-creates the
//! parent directory before the load call to short-circuit that race.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::{fs, io};

use crate::error::{VmRuntimeError, VmRuntimeResult};

/// Default parent directory for per-VM vsock UDS sockets.
pub const DEFAULT_SOCKET_DIR: &str = "/var/run/microvm/vsocks";
/// CIDs 0, 1, 2 are reserved (VMADDR_CID_HYPERVISOR/LOCAL/HOST).
pub const DEFAULT_FIRST_CID: u32 = 3;
/// 0xFFFFFFFF is `VMADDR_CID_ANY`; allocate up to but not including it.
pub const DEFAULT_LAST_CID: u32 = 0xFFFF_FFFE;

/// Configuration for [`VsockManager`].
#[derive(Debug, Clone)]
pub struct VsockConfig {
    /// Parent dir for per-VM vsock UDS sockets (default "/var/run/microvm/vsocks").
    pub socket_dir: PathBuf,
    /// First CID to allocate (default 3 — CIDs 0/1/2 are reserved).
    pub first_cid: u32,
    /// Last CID inclusive (default 0xFFFFFFFE).
    pub last_cid: u32,
}

impl Default for VsockConfig {
    fn default() -> Self {
        Self {
            socket_dir: PathBuf::from(DEFAULT_SOCKET_DIR),
            first_cid: DEFAULT_FIRST_CID,
            last_cid: DEFAULT_LAST_CID,
        }
    }
}

impl VsockConfig {
    /// Load configuration from environment variables.
    ///
    /// Recognised keys: `MICROVM_VSOCK_DIR`, `MICROVM_VSOCK_FIRST_CID`,
    /// `MICROVM_VSOCK_LAST_CID`. Missing or unparseable values fall back to
    /// the defaults.
    pub fn from_env() -> Self {
        let defaults = Self::default();
        let socket_dir = std::env::var("MICROVM_VSOCK_DIR")
            .map(PathBuf::from)
            .unwrap_or(defaults.socket_dir);
        let first_cid = std::env::var("MICROVM_VSOCK_FIRST_CID")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(defaults.first_cid);
        let last_cid = std::env::var("MICROVM_VSOCK_LAST_CID")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(defaults.last_cid);
        Self {
            socket_dir,
            first_cid,
            last_cid,
        }
    }
}

/// Per-VM vsock binding (CID + host-side UDS path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmVsock {
    /// Guest context id on the host vsock plane.
    pub cid: u32,
    /// Host-side UDS path Firecracker will bind for this VM.
    pub uds_path: PathBuf,
}

/// Allocator + path-manager for per-VM vsock state.
#[derive(Debug)]
pub struct VsockManager {
    config: VsockConfig,
    // vm_id -> CID. Owning the map gives idempotent `attach` (same vm_id
    // returns the same allocation) and `detach` (frees the slot for reuse)
    // while letting us check CID-in-use cheaply during collision probing.
    allocations: Mutex<HashMap<String, u32>>,
}

impl VsockManager {
    pub fn new(config: VsockConfig) -> Self {
        Self {
            config,
            allocations: Mutex::new(HashMap::new()),
        }
    }

    pub fn from_env() -> Self {
        Self::new(VsockConfig::from_env())
    }

    /// Borrow the active configuration.
    pub fn config(&self) -> &VsockConfig {
        &self.config
    }

    /// Allocate (or look up) a CID and UDS path for `vm_id`.
    ///
    /// Idempotent: calling twice with the same `vm_id` returns the same
    /// `VmVsock` and does not double-allocate. The UDS parent directory is
    /// created on every call so callers can rely on it existing afterwards
    /// — required for the Firecracker v1.6 snapshot-restore parent-dir race.
    pub fn attach(&self, vm_id: &str) -> VmRuntimeResult<VmVsock> {
        let mut allocations = self
            .allocations
            .lock()
            .map_err(|_| VmRuntimeError::StatePoisoned)?;

        let cid = match allocations.get(vm_id) {
            Some(existing) => *existing,
            None => {
                let used: std::collections::HashSet<u32> = allocations.values().copied().collect();
                let cid = find_free_cid(vm_id, self.config.first_cid, self.config.last_cid, &used)?;
                allocations.insert(vm_id.to_owned(), cid);
                cid
            }
        };

        let uds_path = self.uds_path_for(vm_id);
        ensure_parent_dir(&uds_path)?;
        Ok(VmVsock { cid, uds_path })
    }

    /// Free the CID for `vm_id` and remove the UDS socket file.
    ///
    /// Idempotent: removing a non-existent allocation or socket file is not
    /// an error. The parent directory is left in place — other VMs may share
    /// it under the same `socket_dir`.
    pub fn detach(&self, vm_id: &str) -> VmRuntimeResult<()> {
        let mut allocations = self
            .allocations
            .lock()
            .map_err(|_| VmRuntimeError::StatePoisoned)?;
        allocations.remove(vm_id);
        drop(allocations);

        let uds_path = self.uds_path_for(vm_id);
        match fs::remove_file(&uds_path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(VmRuntimeError::Unsupported(format!(
                "failed to remove vsock uds {}: {err}",
                uds_path.display()
            ))),
        }
    }

    /// Idempotently re-create the parent directory of `uds_path`.
    ///
    /// Firecracker v1.6 bakes the vsock UDS path verbatim into snapshot state.
    /// On `PUT /snapshot/load` the VMM calls `bind(2)` against that exact path
    /// before the caller has any opportunity to materialise it. If the seed
    /// VM's teardown removed the path's parent directory (witnessed on warm-
    /// pool restore where the seed's state dir is `rm -rf`'d), bind fails
    /// with `UnixBind(NotFound)` and the restore aborts. Call this before
    /// every `/snapshot/load` to make the load deterministic across hosts
    /// regardless of what cleaned up the original parent.
    pub fn ensure_uds_parent(&self, uds_path: &Path) -> VmRuntimeResult<()> {
        ensure_parent_dir(uds_path)
    }

    /// Compute the canonical UDS path for `vm_id` without allocating a CID.
    pub fn uds_path_for(&self, vm_id: &str) -> PathBuf {
        self.config
            .socket_dir
            .join(safe_vm_id(vm_id))
            .join("vsock.uds")
    }
}

/// Sanitize a vm_id to the same `[a-zA-Z0-9_-]` charset the Firecracker
/// adapter uses for per-VM directory names. Kept private — callers should
/// use [`VsockManager::uds_path_for`] which applies it internally.
fn safe_vm_id(vm_id: &str) -> String {
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

fn ensure_parent_dir(path: &Path) -> VmRuntimeResult<()> {
    let parent = path.parent().ok_or_else(|| {
        VmRuntimeError::Unsupported(format!(
            "vsock uds path has no parent directory: {}",
            path.display()
        ))
    })?;
    fs::create_dir_all(parent).map_err(|e| {
        VmRuntimeError::Unsupported(format!(
            "failed to create vsock uds parent {}: {e}",
            parent.display()
        ))
    })
}

/// Hash `vm_id` into `[first, last]` and linear-probe past any CIDs already
/// in `used`. Returns `Unsupported` if the range is empty or exhausted.
fn find_free_cid(
    vm_id: &str,
    first: u32,
    last: u32,
    used: &std::collections::HashSet<u32>,
) -> VmRuntimeResult<u32> {
    if first > last {
        return Err(VmRuntimeError::Unsupported(format!(
            "vsock cid range is empty: first={first}, last={last}"
        )));
    }
    let span = u64::from(last - first) + 1;
    let capacity = usize::try_from(span).unwrap_or(usize::MAX);
    if used.len() >= capacity {
        return Err(VmRuntimeError::Unsupported(format!(
            "vsock cid range exhausted: first={first}, last={last}"
        )));
    }

    let mut hasher = DefaultHasher::new();
    vm_id.hash(&mut hasher);
    let h = hasher.finish();
    let offset = u32::try_from(h % span).unwrap_or(0);
    let start = first.saturating_add(offset);

    let mut candidate = start;
    loop {
        if !used.contains(&candidate) {
            return Ok(candidate);
        }
        candidate = if candidate == last {
            first
        } else {
            candidate + 1
        };
        if candidate == start {
            return Err(VmRuntimeError::Unsupported(format!(
                "vsock cid range exhausted: first={first}, last={last}"
            )));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use tempfile::TempDir;

    fn manager_in(dir: &TempDir) -> VsockManager {
        VsockManager::new(VsockConfig {
            socket_dir: dir.path().to_path_buf(),
            first_cid: DEFAULT_FIRST_CID,
            last_cid: DEFAULT_LAST_CID,
        })
    }

    #[test]
    fn defaults_are_sane() {
        let cfg = VsockConfig::default();
        assert_eq!(cfg.first_cid, 3);
        assert_eq!(cfg.last_cid, 0xFFFF_FFFE);
        assert_eq!(cfg.socket_dir, PathBuf::from(DEFAULT_SOCKET_DIR));
    }

    #[test]
    fn cid_is_deterministic_across_managers() {
        let tmp = TempDir::new().unwrap();
        let m1 = manager_in(&tmp);
        let m2 = manager_in(&tmp);
        let a = m1.attach("vm-deterministic").unwrap();
        let b = m2.attach("vm-deterministic").unwrap();
        assert_eq!(a.cid, b.cid);
        assert_eq!(a.uds_path, b.uds_path);
    }

    #[test]
    fn attach_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let mgr = manager_in(&tmp);
        let first = mgr.attach("vm-x").unwrap();
        let second = mgr.attach("vm-x").unwrap();
        let third = mgr.attach("vm-x").unwrap();
        assert_eq!(first, second);
        assert_eq!(second, third);
        let allocations = mgr.allocations.lock().unwrap();
        assert_eq!(allocations.len(), 1);
    }

    #[test]
    fn distinct_vm_ids_get_distinct_cids() {
        let tmp = TempDir::new().unwrap();
        let mgr = manager_in(&tmp);
        let a = mgr.attach("alpha").unwrap();
        let b = mgr.attach("beta").unwrap();
        let c = mgr.attach("gamma").unwrap();
        let set: HashSet<u32> = [a.cid, b.cid, c.cid].into_iter().collect();
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn cid_collision_linear_probes() {
        // Force-collide by squeezing the range to two slots: every vm_id
        // hashes into {3, 4}. After two attaches the third must fail with
        // range exhausted, and the first two must not collide.
        let tmp = TempDir::new().unwrap();
        let mgr = VsockManager::new(VsockConfig {
            socket_dir: tmp.path().to_path_buf(),
            first_cid: 3,
            last_cid: 4,
        });
        let a = mgr.attach("vm-a").unwrap();
        let b = mgr.attach("vm-b").unwrap();
        assert_ne!(a.cid, b.cid);
        let exhausted = mgr.attach("vm-c");
        assert!(
            matches!(exhausted, Err(VmRuntimeError::Unsupported(ref msg)) if msg.contains("exhausted"))
        );
    }

    #[test]
    fn detach_releases_cid_for_future_allocation() {
        let tmp = TempDir::new().unwrap();
        let mgr = VsockManager::new(VsockConfig {
            socket_dir: tmp.path().to_path_buf(),
            first_cid: 3,
            last_cid: 4,
        });
        let _a = mgr.attach("vm-a").unwrap();
        let _b = mgr.attach("vm-b").unwrap();
        assert!(mgr.attach("vm-c").is_err());
        mgr.detach("vm-a").unwrap();
        // Now there is room again.
        let c = mgr.attach("vm-c").unwrap();
        assert!(c.cid == 3 || c.cid == 4);
    }

    #[test]
    fn detach_is_idempotent_when_unknown() {
        let tmp = TempDir::new().unwrap();
        let mgr = manager_in(&tmp);
        mgr.detach("never-attached").unwrap();
        mgr.detach("never-attached").unwrap();
    }

    #[test]
    fn detach_removes_socket_file_but_leaves_parent_dir() {
        let tmp = TempDir::new().unwrap();
        let mgr = manager_in(&tmp);
        let vm = mgr.attach("vm-cleanup").unwrap();
        std::fs::write(&vm.uds_path, b"").unwrap();
        assert!(vm.uds_path.exists());
        mgr.detach("vm-cleanup").unwrap();
        assert!(!vm.uds_path.exists());
        assert!(vm.uds_path.parent().unwrap().exists());
    }

    #[test]
    fn safe_vm_id_strips_unsafe_chars() {
        assert_eq!(safe_vm_id("a/b/c"), "a_b_c");
        assert_eq!(safe_vm_id("normal-id_42"), "normal-id_42");
        assert_eq!(safe_vm_id("../etc/passwd"), "___etc_passwd");
        assert_eq!(safe_vm_id("with space"), "with_space");
    }

    #[test]
    fn uds_path_uses_sanitised_vm_id() {
        let tmp = TempDir::new().unwrap();
        let mgr = manager_in(&tmp);
        let path = mgr.uds_path_for("a/b/c");
        assert_eq!(path, tmp.path().join("a_b_c").join("vsock.uds"));
    }

    #[test]
    fn ensure_uds_parent_creates_missing_dirs() {
        let tmp = TempDir::new().unwrap();
        let mgr = manager_in(&tmp);
        let deep = tmp.path().join("a").join("b").join("c").join("vsock.uds");
        assert!(!deep.parent().unwrap().exists());
        mgr.ensure_uds_parent(&deep).unwrap();
        assert!(deep.parent().unwrap().exists());
    }

    #[test]
    fn ensure_uds_parent_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let mgr = manager_in(&tmp);
        let p = tmp.path().join("a").join("vsock.uds");
        mgr.ensure_uds_parent(&p).unwrap();
        mgr.ensure_uds_parent(&p).unwrap();
        mgr.ensure_uds_parent(&p).unwrap();
        assert!(p.parent().unwrap().exists());
    }

    #[test]
    fn ensure_uds_parent_simulates_fc_v16_restore_race() {
        // Reproduce the FC v1.6 bug: an `attach` creates the parent, an
        // outside process cleans it up (mimicking seed VM teardown), then
        // `ensure_uds_parent` recovers it before the would-be /snapshot/load.
        let tmp = TempDir::new().unwrap();
        let mgr = manager_in(&tmp);
        let vm = mgr.attach("seed").unwrap();
        let parent = vm.uds_path.parent().unwrap();
        assert!(parent.exists());
        std::fs::remove_dir_all(parent).unwrap();
        assert!(!parent.exists());
        mgr.ensure_uds_parent(&vm.uds_path).unwrap();
        assert!(parent.exists());
    }

    #[test]
    fn attach_creates_parent_dir() {
        let tmp = TempDir::new().unwrap();
        let mgr = manager_in(&tmp);
        let vm = mgr.attach("vm-fresh").unwrap();
        assert!(vm.uds_path.parent().unwrap().exists());
        // The socket file itself should NOT be created by attach — Firecracker
        // binds it on /vsock PUT.
        assert!(!vm.uds_path.exists());
    }

    #[test]
    fn cid_range_validation() {
        let tmp = TempDir::new().unwrap();
        let mgr = VsockManager::new(VsockConfig {
            socket_dir: tmp.path().to_path_buf(),
            first_cid: 100,
            last_cid: 50,
        });
        let err = mgr.attach("vm").unwrap_err();
        assert!(matches!(err, VmRuntimeError::Unsupported(_)));
    }

    #[test]
    fn cid_lands_inside_configured_range() {
        let tmp = TempDir::new().unwrap();
        let mgr = VsockManager::new(VsockConfig {
            socket_dir: tmp.path().to_path_buf(),
            first_cid: 100,
            last_cid: 200,
        });
        for i in 0..50 {
            let vm = mgr.attach(&format!("vm-{i}")).unwrap();
            assert!(
                vm.cid >= 100 && vm.cid <= 200,
                "cid {} outside [100, 200]",
                vm.cid
            );
        }
    }

    #[test]
    fn linear_probe_when_hash_collides_directly() {
        // Allocate every CID in a tiny range; each new vm_id must find the
        // remaining slot via probing rather than landing on a used CID.
        let tmp = TempDir::new().unwrap();
        let mgr = VsockManager::new(VsockConfig {
            socket_dir: tmp.path().to_path_buf(),
            first_cid: 10,
            last_cid: 13,
        });
        let mut seen = HashSet::new();
        for i in 0..4 {
            let vm = mgr.attach(&format!("probe-{i}")).unwrap();
            assert!(seen.insert(vm.cid), "duplicate CID {}", vm.cid);
        }
        assert_eq!(seen, HashSet::from([10, 11, 12, 13]));
    }
}
