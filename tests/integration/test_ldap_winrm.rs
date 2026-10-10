//! Integration tests for the rogue LDAP simple-bind capture and the WinRM auth handler.

#[path = "../common/mod.rs"]
mod common;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

use responder::capture::model::{ArtifactType, Protocol};
use responder::protocols::ber;
use responder::servers::{http, ldap};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn tlv(tag: u8, val: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend_from_slice(&ber::encode_len(val.len()));
    v.extend_from_slice(val);
    v
}

fn ldap_simple_bind(message_id: u8, dn: &str, password: &str) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(&tlv(0x02, &[0x03])); // version 3
    inner.extend_from_slice(&tlv(0x04, dn.as_bytes())); // name
    inner.extend_from_slice(&tlv(0x80, password.as_bytes())); // [0] simple
    let bind_request = tlv(0x60, &inner); // [APPLICATION 0]

    let mut msg = Vec::new();
    msg.extend_from_slice(&tlv(0x02, &[message_id]));
    msg.extend_from_slice(&bind_request);
    tlv(0x30, &msg)
}

#[tokio::test]
async fn ldap_captures_simple_bind() {
    let td = common::TempDir::new("ldap");
    let (ctx, mut rx) = common::make_ctx(&td);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(ldap::serve(listener, ctx, false));

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(&ldap_simple_bind(1, "cn=admin,dc=corp", "s3cr3t"))
        .await
        .unwrap();

    let art = common::recv_artifact(&mut rx, 5).await.expect("captured");
    assert_eq!(art.protocol, Protocol::Ldap);
    assert_eq!(art.artifact_type, ArtifactType::Cleartext);
    assert_eq!(art.formatted, "cn=admin,dc=corp:s3cr3t");

    // The server answers with an LDAP BindResponse (invalidCredentials = 49).
    let mut buf = [0u8; 32];
    let n = stream.read(&mut buf).await.unwrap();
    assert!(n > 0);
    assert_eq!(buf[0], 0x30);
    assert!(buf.contains(&0x31) || buf.contains(&0x49));
}

#[tokio::test]
async fn winrm_offers_ntlm_and_captures() {
    let td = common::TempDir::new("winrm");
    let (ctx, mut rx) = common::make_ctx(&td);

    // Stage 1: NEGOTIATE token -> 401 with a server challenge.
    let (mut client, server) = tokio::io::duplex(8192);
    let peer = common::peer();
    let ctx1 = ctx.clone();
    let task = tokio::spawn(async move {
        let _ = http::serve_conn(server, peer, ctx1, Protocol::Winrm).await;
    });
    let token = B64.encode(common::ntlm_type1());
    let req =
        format!("POST /wsman HTTP/1.1\r\nHost: responder\r\nAuthorization: NTLM {token}\r\n\r\n");
    client.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    client.read_to_end(&mut out).await.unwrap();
    task.await.unwrap();
    assert!(
        String::from_utf8_lossy(&out).contains("WWW-Authenticate: NTLM"),
        "resp was: {}",
        String::from_utf8_lossy(&out)
    );

    // Stage 2: AUTHENTICATE token -> NetNTLMv2 capture on the same context/sink.
    let (mut client2, server2) = tokio::io::duplex(8192);
    let peer = common::peer();
    let task2 = tokio::spawn(async move {
        let _ = http::serve_conn(server2, peer, ctx, Protocol::Winrm).await;
    });
    let mut nt: Vec<u8> = (0u8..16).collect();
    nt.extend_from_slice(&[0x11; 16]);
    let token3 = B64.encode(common::ntlm_type3("dave", "CORP", &nt));
    let req3 =
        format!("POST /wsman HTTP/1.1\r\nHost: responder\r\nAuthorization: NTLM {token3}\r\n\r\n");
    client2.write_all(req3.as_bytes()).await.unwrap();
    let mut out3 = Vec::new();
    client2.read_to_end(&mut out3).await.unwrap();
    task2.await.unwrap();

    let art = common::recv_artifact(&mut rx, 5).await.expect("captured");
    assert_eq!(art.protocol, Protocol::Winrm);
    assert_eq!(art.artifact_type, ArtifactType::NetNtlmV2);
    assert!(art.formatted.starts_with("dave::CORP:1122334455667788:"));
    assert!(String::from_utf8_lossy(&out3).starts_with("HTTP/1.1 401"));
}
