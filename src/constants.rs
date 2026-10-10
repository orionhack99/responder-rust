//! Protocol constants: ports, multicast groups and the service enumeration shared by the
//! poisoners, rogue servers and the CLI/config layer.

use std::net::{Ipv4Addr, Ipv6Addr};

// --- Poisoner / infrastructure ports -------------------------------------------------------

pub const LLMNR_PORT: u16 = 5355;
pub const MDNS_PORT: u16 = 5353;
pub const NBTNS_PORT: u16 = 137;
pub const DNS_PORT: u16 = 53;
pub const DHCP_PORT: u16 = 67;
pub const DHCP_CLIENT_PORT: u16 = 68;
pub const DHCPV6_PORT: u16 = 547;
pub const DHCPV6_CLIENT_PORT: u16 = 546;

// --- Multicast groups ----------------------------------------------------------------------

/// LLMNR IPv4 multicast group (RFC 4795).
pub const LLMNR_MCAST_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 252);
/// LLMNR IPv6 multicast group (RFC 4795).
pub const LLMNR_MCAST_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 0x0003);
/// mDNS IPv4 multicast group (RFC 6762).
pub const MDNS_MCAST_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// mDNS IPv6 multicast group (RFC 6762).
pub const MDNS_MCAST_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb);
/// NetBIOS-NS broadcast sent to the IPv4 broadcast address.
pub const BROADCAST_V4: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 255);

/// The default answer TTL used in poison responses (seconds).
pub const DEFAULT_TTL: u32 = 31;

/// Fixed NTLM server challenge used to keep captured NetNTLMv2 hashes crackable and
/// consistent with the reference tool.
pub const CAPTURE_CHALLENGE_HEX: &str = "1122334455667788";

// --- Service enumeration -------------------------------------------------------------------

/// Every service the toolkit can expose or poison. The string forms match the file-name
/// protocol labels used in `logs/`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Service {
    Llmnr,
    NbtNs,
    Mdns,
    Dns,
    Dhcp,
    Dhcpv6,
    Smb,
    Http,
    Https,
    Wpad,
    Ftp,
    Pop3,
    Smtp,
    Imap,
    Imaps,
    Mssql,
    Ldap,
    Ldaps,
    Kerberos,
    Rdp,
    Winrm,
    Winrms,
    Dcerpc,
}

impl Service {
    /// Canonical name used in logs and configuration.
    pub fn as_str(&self) -> &'static str {
        match self {
            Service::Llmnr => "LLMNR",
            Service::NbtNs => "NBT-NS",
            Service::Mdns => "MDNS",
            Service::Dns => "DNS",
            Service::Dhcp => "DHCP",
            Service::Dhcpv6 => "DHCPv6",
            Service::Smb => "SMB",
            Service::Http => "HTTP",
            Service::Https => "HTTPS",
            Service::Wpad => "WPAD",
            Service::Ftp => "FTP",
            Service::Pop3 => "POP",
            Service::Smtp => "SMTP",
            Service::Imap => "IMAP",
            Service::Imaps => "IMAPS",
            Service::Mssql => "MSSQL",
            Service::Ldap => "LDAP",
            Service::Ldaps => "LDAPS",
            Service::Kerberos => "Kerberos",
            Service::Rdp => "RDP",
            Service::Winrm => "WinRM",
            Service::Winrms => "WinRMS",
            Service::Dcerpc => "DCERPC",
        }
    }

    /// Default TCP/UDP ports. Poisoners bind UDP; the rest are TCP.
    pub fn default_ports(&self) -> &'static [u16] {
        match self {
            Service::Llmnr => &[LLMNR_PORT],
            Service::NbtNs => &[NBTNS_PORT],
            Service::Mdns => &[MDNS_PORT],
            Service::Dns => &[DNS_PORT],
            Service::Dhcp => &[DHCP_PORT],
            Service::Dhcpv6 => &[DHCPV6_PORT],
            Service::Smb => &[445, 139],
            Service::Http | Service::Wpad => &[80],
            Service::Https => &[443],
            Service::Ftp => &[21],
            Service::Pop3 => &[110],
            Service::Smtp => &[25, 587],
            Service::Imap => &[143],
            Service::Imaps => &[993],
            Service::Mssql => &[1433],
            Service::Ldap => &[389],
            Service::Ldaps => &[636],
            Service::Kerberos => &[88],
            Service::Rdp => &[3389],
            Service::Winrm => &[5985],
            Service::Winrms => &[5986],
            Service::Dcerpc => &[135],
        }
    }

    /// True for the raw L2/L3 poisoners (as opposed to the rogue auth servers).
    pub fn is_poisoner(&self) -> bool {
        matches!(
            self,
            Service::Llmnr
                | Service::NbtNs
                | Service::Mdns
                | Service::Dns
                | Service::Dhcp
                | Service::Dhcpv6
        )
    }

    /// The set of services enabled by default (all of them).
    pub fn all() -> &'static [Service] {
        &[
            Service::Llmnr,
            Service::NbtNs,
            Service::Mdns,
            Service::Dns,
            Service::Dhcp,
            Service::Dhcpv6,
            Service::Smb,
            Service::Http,
            Service::Https,
            Service::Wpad,
            Service::Ftp,
            Service::Pop3,
            Service::Smtp,
            Service::Imap,
            Service::Imaps,
            Service::Mssql,
            Service::Ldap,
            Service::Ldaps,
            Service::Kerberos,
            Service::Rdp,
            Service::Winrm,
            Service::Winrms,
            Service::Dcerpc,
        ]
    }
}
