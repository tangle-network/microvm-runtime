use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::VmRuntimeError;

/// Minimal IPv4 CIDR representation.
///
/// Kept in-crate to avoid pulling `ipnet`. Stores the canonical network
/// address (host bits zeroed) plus a `/prefix` in `0..=32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Net {
    network: Ipv4Addr,
    prefix: u8,
}

impl Ipv4Net {
    pub fn new(addr: Ipv4Addr, prefix: u8) -> Result<Self, VmRuntimeError> {
        if prefix > 32 {
            return Err(VmRuntimeError::NetworkConfig(format!(
                "invalid prefix /{prefix}, must be 0..=32"
            )));
        }
        let mask = prefix_to_mask(prefix);
        let network = Ipv4Addr::from(u32::from(addr) & mask);
        Ok(Self { network, prefix })
    }

    pub fn network(&self) -> Ipv4Addr {
        self.network
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn netmask(&self) -> Ipv4Addr {
        Ipv4Addr::from(prefix_to_mask(self.prefix))
    }

    /// Total number of addresses in the block (including network + broadcast).
    pub fn num_addresses(&self) -> u64 {
        1u64 << (32 - u32::from(self.prefix))
    }

    /// Broadcast address — last address in the block.
    pub fn broadcast(&self) -> Ipv4Addr {
        let net = u32::from(self.network);
        let hostbits = 32 - u32::from(self.prefix);
        // For /32 there are no host bits and "broadcast" coincides with the network address.
        let bcast = if hostbits == 32 {
            u32::MAX
        } else {
            net | ((1u32 << hostbits) - 1)
        };
        Ipv4Addr::from(bcast)
    }

    /// `true` if `addr` is inside this block.
    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        let mask = prefix_to_mask(self.prefix);
        (u32::from(addr) & mask) == u32::from(self.network)
    }

    /// `network + offset`. Returns `None` if `offset` exceeds the block.
    pub fn nth(&self, offset: u32) -> Option<Ipv4Addr> {
        let hostbits = 32u32 - u32::from(self.prefix);
        let cap = if hostbits == 32 {
            u32::MAX
        } else {
            (1u32 << hostbits) - 1
        };
        if offset > cap {
            return None;
        }
        Some(Ipv4Addr::from(u32::from(self.network).wrapping_add(offset)))
    }
}

impl fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

impl FromStr for Ipv4Net {
    type Err = VmRuntimeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, prefix) = s.split_once('/').ok_or_else(|| {
            VmRuntimeError::NetworkConfig(format!("missing '/prefix' in cidr '{s}'"))
        })?;
        let addr = Ipv4Addr::from_str(addr.trim()).map_err(|e| {
            VmRuntimeError::NetworkConfig(format!("invalid ipv4 '{addr}' in cidr '{s}': {e}"))
        })?;
        let prefix: u8 = prefix.trim().parse().map_err(|e| {
            VmRuntimeError::NetworkConfig(format!("invalid prefix '{prefix}' in cidr '{s}': {e}"))
        })?;
        Self::new(addr, prefix)
    }
}

impl Serialize for Ipv4Net {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Ipv4Net {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <String as Deserialize>::deserialize(deserializer)?;
        Ipv4Net::from_str(&s).map_err(serde::de::Error::custom)
    }
}

fn prefix_to_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_cidr() {
        let net: Ipv4Net = "172.30.0.0/24".parse().unwrap();
        assert_eq!(net.network(), Ipv4Addr::new(172, 30, 0, 0));
        assert_eq!(net.prefix(), 24);
        assert_eq!(net.netmask(), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(net.broadcast(), Ipv4Addr::new(172, 30, 0, 255));
        assert_eq!(net.num_addresses(), 256);
    }

    #[test]
    fn zeroes_host_bits() {
        let net: Ipv4Net = "172.30.0.42/24".parse().unwrap();
        assert_eq!(net.network(), Ipv4Addr::new(172, 30, 0, 0));
    }

    #[test]
    fn rejects_bad_prefix() {
        assert!("10.0.0.0/33".parse::<Ipv4Net>().is_err());
        assert!("not-a-cidr".parse::<Ipv4Net>().is_err());
        assert!("10.0.0.0".parse::<Ipv4Net>().is_err());
        assert!("10.0.0.0/abc".parse::<Ipv4Net>().is_err());
    }

    #[test]
    fn contains_matches_subnet() {
        let net: Ipv4Net = "10.0.0.0/8".parse().unwrap();
        assert!(net.contains(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(net.contains(Ipv4Addr::new(10, 255, 255, 254)));
        assert!(!net.contains(Ipv4Addr::new(11, 0, 0, 1)));
    }

    #[test]
    fn nth_addresses() {
        let net: Ipv4Net = "172.30.0.0/24".parse().unwrap();
        assert_eq!(net.nth(0), Some(Ipv4Addr::new(172, 30, 0, 0)));
        assert_eq!(net.nth(1), Some(Ipv4Addr::new(172, 30, 0, 1)));
        assert_eq!(net.nth(255), Some(Ipv4Addr::new(172, 30, 0, 255)));
        assert_eq!(net.nth(256), None);
    }

    #[test]
    fn slash_32_is_single_host() {
        let net: Ipv4Net = "192.168.1.5/32".parse().unwrap();
        assert_eq!(net.num_addresses(), 1);
        assert_eq!(net.network(), Ipv4Addr::new(192, 168, 1, 5));
        assert_eq!(net.nth(0), Some(Ipv4Addr::new(192, 168, 1, 5)));
        assert_eq!(net.nth(1), None);
    }

    #[test]
    fn slash_0_covers_everything() {
        let net: Ipv4Net = "0.0.0.0/0".parse().unwrap();
        assert_eq!(net.num_addresses(), 1u64 << 32);
        assert!(net.contains(Ipv4Addr::new(1, 2, 3, 4)));
        assert!(net.contains(Ipv4Addr::new(255, 255, 255, 255)));
    }

    #[test]
    fn display_round_trips() {
        let net: Ipv4Net = "172.30.0.0/24".parse().unwrap();
        assert_eq!(net.to_string(), "172.30.0.0/24");
    }

    #[test]
    fn serde_round_trips() {
        let net: Ipv4Net = "192.168.42.0/24".parse().unwrap();
        let json = serde_json::to_string(&net).unwrap();
        assert_eq!(json, "\"192.168.42.0/24\"");
        let back: Ipv4Net = serde_json::from_str(&json).unwrap();
        assert_eq!(back, net);
    }
}
