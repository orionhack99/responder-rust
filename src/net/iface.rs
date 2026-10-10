//! Interface enumeration and resolution.
//!
//! Uses `pnet_datalink` for a portable list of interfaces with their MAC and IP addresses.
//! The special selection `ALL` expands to every non-loopback, up interface.

use std::net::{IpAddr, Ipv4Addr};

use pnet::datalink;

/// A resolved interface with the addresses we need for poisoning.
#[derive(Clone, Debug)]
pub struct IfaceInfo {
    pub name: String,
    pub mac: Option<String>,
    pub ips: Vec<IpAddr>,
}

impl IfaceInfo {
    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        self.ips.iter().find_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            _ => None,
        })
    }

    pub fn ipv6(&self) -> Option<&IpAddr> {
        self.ips.iter().find(|ip| matches!(ip, IpAddr::V6(_)))
    }
}

/// Enumerate all interfaces currently known to the OS.
pub fn list() -> Vec<IfaceInfo> {
    datalink::interfaces()
        .into_iter()
        .map(|i| IfaceInfo {
            name: i.name,
            mac: i.mac.map(|m| m.to_string()),
            ips: i.ips.into_iter().map(|n| n.ip()).collect(),
        })
        .collect()
}

/// Find a single interface by exact name.
pub fn find(selection: &str) -> Option<IfaceInfo> {
    list().into_iter().find(|i| i.name == selection)
}

/// Resolve a selection into one or more interfaces. `ALL` returns every usable interface.
pub fn resolve(selection: &str) -> anyhow::Result<Vec<IfaceInfo>> {
    let all = list();
    if selection.eq_ignore_ascii_case("ALL") {
        let chosen: Vec<IfaceInfo> = all
            .into_iter()
            .filter(|i| i.name != "lo" && i.ipv4().is_some())
            .collect();
        if chosen.is_empty() {
            anyhow::bail!("no usable interfaces found for ALL");
        }
        return Ok(chosen);
    }
    match all.into_iter().find(|i| i.name == selection) {
        Some(i) => Ok(vec![i]),
        None => {
            let names: Vec<String> = list().into_iter().map(|i| i.name).collect();
            anyhow::bail!(
                "interface {selection:?} not found; available: {}",
                names.join(", ")
            )
        }
    }
}

/// The primary IPv4 address of an interface (first v4 address).
pub fn primary_ipv4(iface: &IfaceInfo) -> Option<Ipv4Addr> {
    iface.ipv4()
}
