//! Command-line interface. The option letters/long names are part of the compatibility
//! contract (`contracts/cli.md`) and are intentionally stable.

use clap::Parser;

/// LLMNR/NBT-NS/mDNS poisoner and rogue authentication servers.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "responder",
    version,
    about = "Responder-compatible LLMNR/NBT-NS/mDNS poisoner and rogue auth server",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Network interface to operate on (`ALL` expands to every usable interface).
    #[arg(short = 'I', long = "interface", value_name = "IFACE")]
    pub interface: Option<String>,

    /// Analyze mode: observe name resolution without responding.
    #[arg(short = 'A', long = "analyze")]
    pub analyze: bool,

    /// Start the rogue WPAD proxy server.
    #[arg(short = 'w', long = "wpad")]
    pub wpad: bool,

    /// Force authentication on `wpad.dat` retrieval.
    #[arg(short = 'F', long = "ForceWpadAuth")]
    pub force_wpad_auth: bool,

    /// Force authentication for the rogue proxy.
    #[arg(short = 'P', long = "ProxyAuth")]
    pub proxy_auth: bool,

    /// Enable DHCP broadcast responses with WPAD injection.
    #[arg(short = 'd', long = "DHCP")]
    pub dhcp: bool,

    /// Inject the DNS server in the DHCP response instead of WPAD.
    #[arg(short = 'D', long = "DHCP-DNS")]
    pub dhcp_dns: bool,

    /// Enable DHCPv6 poisoning.
    #[arg(long = "dhcpv6")]
    pub dhcpv6: bool,

    /// Poison answers with this external IPv4 address.
    #[arg(short = 'e', long = "externalip", value_name = "IPv4")]
    pub external_ip: Option<std::net::Ipv4Addr>,

    /// Poison answers with this external IPv6 address.
    #[arg(short = '6', long = "externalip6", value_name = "IPv6")]
    pub external_ip6: Option<std::net::Ipv6Addr>,

    /// Local IP to use (required on macOS).
    #[arg(short = 'i', long = "ip", value_name = "IPv4")]
    pub local_ip: Option<std::net::Ipv4Addr>,

    /// Return HTTP Basic auth instead of NTLM.
    #[arg(short = 'b', long = "basic")]
    pub basic: bool,

    /// Force LM hashing downgrade.
    #[arg(long = "lm")]
    pub lm: bool,

    /// Force Extended Security (NTLMSSP) downgrade.
    #[arg(long = "disable-ess")]
    pub disable_ess: bool,

    /// Upstream HTTP proxy for the rogue WPAD server.
    #[arg(short = 'u', long = "upstream-proxy", value_name = "HOST:PORT")]
    pub upstream_proxy: Option<String>,

    /// TTL for poisoned answers (hex, or `random`).
    #[arg(short = 't', long = "ttl", value_name = "HEX|random")]
    pub ttl: Option<String>,

    /// Canonical name used in LLMNR answers.
    #[arg(short = 'N', long = "AnswerName", value_name = "NAME")]
    pub answer_name: Option<String>,

    /// Return STATUS_LOGON_FAILURE (optionally an explicit code).
    #[arg(
        short = 'E',
        long = "ErrorCode",
        value_name = "CODE",
        num_args = 0..=1,
        default_missing_value = "STATUS_LOGON_FAILURE"
    )]
    pub error_code: Option<String>,

    /// Increase verbosity (repeatable).
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Suppress poisoner output while still reporting captures.
    #[arg(short = 'Q', long = "quiet")]
    pub quiet: bool,

    /// Path to the configuration file (defaults to `Responder.conf`).
    #[arg(long = "config", value_name = "FILE", default_value = "Responder.conf")]
    pub config: String,
}

impl Cli {
    pub fn parse_args() -> Self {
        Cli::parse()
    }
}
