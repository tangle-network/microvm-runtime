use std::net::Ipv4Addr;

use crate::error::{VmRuntimeError, VmRuntimeResult};
use crate::network::ipv4_net::Ipv4Net;

/// TAP interface names are kernel-capped at 15 bytes. `tap-` prefix (4) plus
/// the first 8 hex chars of the FNV-1a digest of the VM id fits in 12.
pub const TAP_NAME_PREFIX: &str = "tap-";
pub const TAP_HASH_LEN: usize = 8;

/// Deterministic short identifier derived from `vm_id`.
///
/// Uses FNV-1a (64-bit) so the digest is stable across releases without
/// pulling a crypto dependency. The output is hex-encoded and truncated to
/// [`TAP_HASH_LEN`] characters. Collision domain is 2^32 — the caller owns
/// VM id uniqueness, this is just a name shortener.
pub fn vm_short_hash(vm_id: &str) -> String {
    let digest = fnv1a_64(vm_id.as_bytes());
    let hex = format!("{digest:016x}");
    hex[..TAP_HASH_LEN].to_string()
}

pub fn tap_name_for(vm_id: &str) -> String {
    format!("{TAP_NAME_PREFIX}{}", vm_short_hash(vm_id))
}

/// Deterministically allocate a guest IP for `vm_id` inside `subnet`.
///
/// Strategy: take a 64-bit FNV-1a digest of `vm_id`, map it into the host
/// range `[2, num_addresses - 1)` (skipping network=.0, gateway=.1, and
/// broadcast=.last). Allocation is pure — the same `(vm_id, subnet)` always
/// yields the same address. Collisions happen iff `vm_id`s collide modulo
/// the usable host count; that is the caller's problem to avoid.
pub fn allocate_guest_ip(vm_id: &str, subnet: Ipv4Net) -> VmRuntimeResult<Ipv4Addr> {
    let total = subnet.num_addresses();
    if total < 4 {
        return Err(VmRuntimeError::NetworkConfig(format!(
            "subnet {subnet} too small: need /30 or larger (got {total} addresses)"
        )));
    }
    let usable = total - 3; // exclude .0, .1, broadcast
    let digest = fnv1a_64(vm_id.as_bytes());
    let offset = (digest % usable) as u32 + 2;
    subnet.nth(offset).ok_or_else(|| {
        VmRuntimeError::NetworkConfig(format!(
            "computed offset {offset} out of range for subnet {subnet}"
        ))
    })
}

/// Gateway is conventionally the first host address — `subnet.network + 1`.
pub fn gateway_for(subnet: Ipv4Net) -> VmRuntimeResult<Ipv4Addr> {
    subnet.nth(1).ok_or_else(|| {
        VmRuntimeError::NetworkConfig(format!("subnet {subnet} has no usable host address"))
    })
}

/// Build a locally-administered, unicast MAC deterministically from `vm_id`.
///
/// Bits set on byte 0: locally-administered (`0x02`), unicast (`& !0x01`).
/// The remaining 46 bits come from FNV-1a of `vm_id`.
pub fn allocate_guest_mac(vm_id: &str) -> [u8; 6] {
    let digest = fnv1a_64(vm_id.as_bytes());
    let mut mac = [0u8; 6];
    mac[0] = 0x02; // locally administered, unicast
    mac[1] = ((digest >> 32) & 0xff) as u8;
    mac[2] = ((digest >> 24) & 0xff) as u8;
    mac[3] = ((digest >> 16) & 0xff) as u8;
    mac[4] = ((digest >> 8) & 0xff) as u8;
    mac[5] = (digest & 0xff) as u8;
    mac
}

pub fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_matches_reference_vectors() {
        // Canonical FNV-1a 64-bit test vectors.
        assert_eq!(fnv1a_64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a_64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a_64(b"foobar"), 0x8594_4171_f739_67e8);
        assert_eq!(fnv1a_64(b"hello"), 0xa430_d846_80aa_bd0b);
    }

    #[test]
    fn vm_short_hash_is_deterministic() {
        let a = vm_short_hash("vm-abc-123");
        let b = vm_short_hash("vm-abc-123");
        assert_eq!(a, b);
        assert_eq!(a.len(), TAP_HASH_LEN);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn tap_name_fits_kernel_limit() {
        let name = tap_name_for("very-long-vm-identifier-1234567890");
        assert!(name.len() <= 15, "tap '{name}' must be <= 15 bytes");
        assert!(name.starts_with("tap-"));
    }

    #[test]
    fn tap_name_changes_with_vm_id() {
        assert_ne!(tap_name_for("a"), tap_name_for("b"));
    }

    #[test]
    fn ip_allocation_is_deterministic() {
        let subnet: Ipv4Net = "172.30.0.0/24".parse().unwrap();
        let first = allocate_guest_ip("vm-1", subnet).unwrap();
        let second = allocate_guest_ip("vm-1", subnet).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn ip_allocation_skips_reserved() {
        let subnet: Ipv4Net = "172.30.0.0/24".parse().unwrap();
        let gateway = gateway_for(subnet).unwrap();
        let broadcast = subnet.broadcast();
        let network = subnet.network();
        for i in 0..256u32 {
            let id = format!("vm-{i}");
            let ip = allocate_guest_ip(&id, subnet).unwrap();
            assert!(subnet.contains(ip), "{ip} outside {subnet}");
            assert_ne!(ip, network, "must skip network address");
            assert_ne!(ip, gateway, "must skip gateway");
            assert_ne!(ip, broadcast, "must skip broadcast");
        }
    }

    #[test]
    fn ip_allocation_rejects_too_small_subnet() {
        let subnet: Ipv4Net = "10.0.0.0/31".parse().unwrap();
        assert!(allocate_guest_ip("vm-x", subnet).is_err());
    }

    #[test]
    fn mac_is_locally_administered_unicast() {
        let mac = allocate_guest_mac("anything");
        assert_eq!(mac[0] & 0x02, 0x02, "locally-administered bit not set");
        assert_eq!(
            mac[0] & 0x01,
            0x00,
            "unicast bit not set (multicast forbidden)"
        );
    }

    #[test]
    fn mac_is_deterministic() {
        assert_eq!(allocate_guest_mac("vm-1"), allocate_guest_mac("vm-1"));
        assert_ne!(allocate_guest_mac("vm-1"), allocate_guest_mac("vm-2"));
    }

    #[test]
    fn mac_format_is_canonical() {
        let mac = [0x02, 0xab, 0xcd, 0xef, 0x01, 0x23];
        assert_eq!(format_mac(mac), "02:ab:cd:ef:01:23");
    }

    #[test]
    fn gateway_is_first_host_address() {
        let subnet: Ipv4Net = "172.30.0.0/24".parse().unwrap();
        assert_eq!(gateway_for(subnet).unwrap(), Ipv4Addr::new(172, 30, 0, 1));
    }
}
