//! Integration tests for the cleartext/challenge-response mail services (FTP, POP3, SMTP).

#[path = "../common/mod.rs"]
mod common;

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

use responder::capture::model::{ArtifactType, Protocol};
use responder::servers::{ftp, pop3, smtp};

use tokio::io::AsyncWriteExt;

async fn spawn_ftp(ctx: Arc<responder::servers::ServerContext>, s: tokio::io::DuplexStream) {
    let _ = ftp::handle_stream(s, common::peer(), ctx).await;
}
async fn spawn_pop3(ctx: Arc<responder::servers::ServerContext>, s: tokio::io::DuplexStream) {
    let _ = pop3::handle_stream(s, common::peer(), ctx).await;
}
async fn spawn_smtp(ctx: Arc<responder::servers::ServerContext>, s: tokio::io::DuplexStream) {
    let _ = smtp::handle_stream(s, common::peer(), ctx).await;
}

#[tokio::test]
async fn ftp_captures_cleartext() {
    let td = common::TempDir::new("ftp");
    let (ctx, mut rx) = common::make_ctx(&td);
    let (mut client, server) = tokio::io::duplex(4096);
    tokio::spawn(spawn_ftp(ctx, server));

    client
        .write_all(b"USER alice\r\nPASS s3cr3t\r\n")
        .await
        .unwrap();

    let art = common::recv_artifact(&mut rx, 5).await.expect("captured");
    assert_eq!(art.protocol, Protocol::Ftp);
    assert_eq!(art.artifact_type, ArtifactType::Cleartext);
    assert_eq!(art.formatted, "alice:s3cr3t");
}

#[tokio::test]
async fn pop3_captures_cleartext_and_apop() {
    let td = common::TempDir::new("pop3");
    let (ctx, mut rx) = common::make_ctx(&td);
    let (mut client, server) = tokio::io::duplex(4096);
    tokio::spawn(spawn_pop3(ctx, server));

    client
        .write_all(b"USER bob\r\nPASS hunter2\r\n")
        .await
        .unwrap();
    let art = common::recv_artifact(&mut rx, 5).await.expect("captured");
    assert_eq!(art.protocol, Protocol::Pop3);
    assert_eq!(art.formatted, "bob:hunter2");

    client
        .write_all(b"APOP carol c4c9334bac560ecc979e58001b3e22fb\r\n")
        .await
        .unwrap();
    let art = common::recv_artifact(&mut rx, 5).await.expect("captured");
    assert_eq!(art.artifact_type, ArtifactType::Apop);
    assert!(art.formatted.starts_with("carol:"));
}

#[tokio::test]
async fn smtp_captures_auth_plain() {
    let td = common::TempDir::new("smtp");
    let (ctx, mut rx) = common::make_ctx(&td);
    let (mut client, server) = tokio::io::duplex(4096);
    tokio::spawn(spawn_smtp(ctx, server));

    let creds = B64.encode("\0alice\0s3cr3t");
    client
        .write_all(format!("EHLO test\r\nAUTH PLAIN {creds}\r\n").as_bytes())
        .await
        .unwrap();

    let art = common::recv_artifact(&mut rx, 5).await.expect("captured");
    assert_eq!(art.protocol, Protocol::Smtp);
    assert_eq!(art.artifact_type, ArtifactType::Cleartext);
    assert_eq!(art.formatted, "alice:s3cr3t");
}
