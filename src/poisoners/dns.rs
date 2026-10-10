//! Rogue DNS server (UDP + TCP port 53). Answers in-scope queries with our address.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use hickory_proto::op::{Message, MessageType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::capture::CaptureSink;
use crate::capture::model::Protocol;
use crate::logger::Logger;

use super::{PoisonConfig, dns_response, domain_allowed, nxdomain, query_event};

/// A synthesized response body plus the decoded `(name, type)` questions it answers.
type Decoded = (Vec<u8>, Vec<(String, String)>);

fn handle(cfg: &PoisonConfig, data: &[u8]) -> Option<Decoded> {
    let msg = Message::from_vec(data).ok()?;
    if msg.metadata.message_type != MessageType::Query {
        return None;
    }
    let mut names = Vec::new();
    let mut allowed = false;
    for q in &msg.queries {
        let name = q.name().to_utf8();
        if domain_allowed(&name, &cfg.domains) {
            allowed = true;
        }
        names.push((name, format!("{:?}", q.query_type())));
    }
    let resp = if allowed {
        dns_response(&msg, cfg)
    } else {
        nxdomain(&msg)
    };
    resp.to_vec().ok().map(|b| (b, names))
}

/// Run both the UDP and TCP DNS services.
pub async fn run(
    bind_ip: Ipv4Addr,
    cfg: Arc<PoisonConfig>,
    sink: CaptureSink,
    logger: Arc<Logger>,
    tcp: bool,
) -> anyhow::Result<()> {
    let udp = super::bind_udp(
        SocketAddr::from((bind_ip, crate::constants::DNS_PORT)),
        true,
        None,
    )?;
    logger.info("DNS server listening on 53/udp");
    if tcp {
        let tcp_bind = SocketAddr::from((bind_ip, crate::constants::DNS_PORT));
        let cfg2 = cfg.clone();
        let sink2 = sink.clone();
        let logger2 = logger.clone();
        tokio::spawn(async move {
            if let Err(e) = run_tcp(tcp_bind, cfg2, sink2, logger2).await {
                tracing::warn!("dns tcp listener stopped: {e}");
            }
        });
    }
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, src) = udp.recv_from(&mut buf).await?;
        let Some((resp, names)) = handle(&cfg, &buf[..n]) else {
            continue;
        };
        if src.ip() == std::net::IpAddr::V4(cfg.answer_ipv4) {
            continue;
        }
        for (name, rtype) in names {
            sink.query(query_event(
                Protocol::Dns,
                src.ip(),
                &name,
                &rtype,
                !cfg.analyze,
                cfg.analyze,
            ));
        }
        if !cfg.analyze {
            let _ = udp.send_to(&resp, src).await;
        }
    }
}

async fn run_tcp(
    bind: SocketAddr,
    cfg: Arc<PoisonConfig>,
    sink: CaptureSink,
    logger: Arc<Logger>,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(bind).await?;
    logger.info("DNS server listening on 53/tcp");
    loop {
        let (mut stream, peer) = listener.accept().await?;
        let cfg = cfg.clone();
        let sink = sink.clone();
        tokio::spawn(async move {
            let mut len_buf = [0u8; 2];
            if stream.read_exact(&mut len_buf).await.is_err() {
                return;
            }
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut data = vec![0u8; len];
            if stream.read_exact(&mut data).await.is_err() {
                return;
            }
            if let Some((resp, names)) = handle(&cfg, &data) {
                for (name, rtype) in names {
                    sink.query(query_event(
                        Protocol::Dns,
                        peer.ip(),
                        &name,
                        &rtype,
                        !cfg.analyze,
                        cfg.analyze,
                    ));
                }
                if !cfg.analyze && resp.len() < 65536 {
                    let mut out = (resp.len() as u16).to_be_bytes().to_vec();
                    out.extend_from_slice(&resp);
                    let _ = stream.write_all(&out).await;
                }
            }
        });
    }
}
