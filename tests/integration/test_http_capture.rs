//! Integration test: the rogue HTTP server captures Basic and NTLM credentials.

#[path = "../common/mod.rs"]
mod common;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

use responder::capture::model::{ArtifactType, Protocol};
use responder::servers::http;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn drive(request: &str, ctx: std::sync::Arc<responder::servers::ServerContext>) -> String {
    let (mut client, server) = tokio::io::duplex(8192);
    let peer = common::peer();
    let task = tokio::spawn(async move {
        let _ = http::serve_conn(server, peer, ctx, Protocol::Http).await;
    });
    client.write_all(request.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    client.read_to_end(&mut out).await.unwrap();
    task.await.unwrap();
    String::from_utf8_lossy(&out).to_string()
}

#[tokio::test]
async fn captures_basic_cleartext() {
    let td = common::TempDir::new("http-basic");
    let (ctx, mut rx) = common::make_ctx(&td);

    let creds = B64.encode("alice:s3cr3t");
    let req = format!("GET / HTTP/1.1\r\nHost: responder\r\nAuthorization: Basic {creds}\r\n\r\n");
    let resp = drive(&req, ctx).await;
    assert!(resp.starts_with("HTTP/1.1 401 Unauthorized"));

    let art = common::recv_artifact(&mut rx, 5).await.expect("captured");
    assert_eq!(art.artifact_type, ArtifactType::Cleartext);
    assert_eq!(art.protocol, Protocol::Http);
    assert_eq!(art.formatted, "alice:s3cr3t");
}

#[tokio::test]
async fn offers_ntlm_challenge() {
    let td = common::TempDir::new("http-ntlm");
    let (ctx, _rx) = common::make_ctx(&td);

    let token = B64.encode(common::ntlm_type1());
    let req = format!("GET / HTTP/1.1\r\nHost: responder\r\nAuthorization: NTLM {token}\r\n\r\n");
    let resp = drive(&req, ctx).await;
    assert!(resp.contains("WWW-Authenticate: NTLM"), "resp was: {resp}");
}

#[tokio::test]
async fn captures_ntlmv2() {
    let td = common::TempDir::new("http-ntlm2");
    let (ctx, mut rx) = common::make_ctx(&td);

    let proof: Vec<u8> = (0u8..16).collect();
    let mut nt = proof;
    nt.extend_from_slice(&[0x11; 16]);
    let token = B64.encode(common::ntlm_type3("bob", "CORP", &nt));
    let req = format!("GET / HTTP/1.1\r\nHost: responder\r\nAuthorization: NTLM {token}\r\n\r\n");
    let _ = drive(&req, ctx).await;

    let art = common::recv_artifact(&mut rx, 5).await.expect("captured");
    assert_eq!(art.artifact_type, ArtifactType::NetNtlmV2);
    assert!(art.formatted.starts_with("bob::CORP:1122334455667788:"));
}
