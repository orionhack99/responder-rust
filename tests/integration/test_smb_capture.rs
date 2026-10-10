//! Integration test: the rogue SMB server drives NEGOTIATE/SESSION_SETUP and captures a
//! crackable NetNTLMv2 hash from an NTLMSSP AUTHENTICATE message.

#[path = "../common/mod.rs"]
mod common;

use responder::capture::model::{ArtifactType, Protocol};
use responder::protocols::smb;
use responder::servers::smb::serve;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn send_session_setup(stream: &mut TcpStream, token: &[u8]) {
    let mut body = vec![0u8; 24];
    body[12..14].copy_from_slice(&(64u16 + 24).to_le_bytes());
    body[14..16].copy_from_slice(&(token.len() as u16).to_le_bytes());

    let mut full = common::smb2_header(smb::CMD_SESSION_SETUP);
    full.extend_from_slice(&body);
    full.extend_from_slice(token);

    stream
        .write_all(&common::netbios_frame(&full))
        .await
        .unwrap();
}

async fn read_status(stream: &mut TcpStream) -> u32 {
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await.unwrap();
    let len = ((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | hdr[3] as usize;
    let mut msg = vec![0u8; len];
    stream.read_exact(&mut msg).await.unwrap();
    u32::from_le_bytes(msg[8..12].try_into().unwrap())
}

#[tokio::test]
async fn smb_negotiate_and_capture() {
    let td = common::TempDir::new("smb");
    let (ctx, mut rx) = common::make_ctx(&td);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, ctx));

    let mut stream = TcpStream::connect(addr).await.unwrap();

    // NEGOTIATE
    let negotiate = common::smb2_header(smb::CMD_NEGOTIATE);
    stream
        .write_all(&common::netbios_frame(&negotiate))
        .await
        .unwrap();
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await.unwrap();
    let len = ((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | hdr[3] as usize;
    let mut resp = vec![0u8; len];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[0..4], [0xFE, b'S', b'M', b'B']);

    // SESSION_SETUP stage 1 (NEGOTIATE token) => MORE_PROCESSING_REQUIRED
    send_session_setup(&mut stream, &common::ntlm_type1()).await;
    assert_eq!(
        read_status(&mut stream).await,
        smb::STATUS_MORE_PROCESSING_REQUIRED
    );

    // SESSION_SETUP stage 2 (AUTHENTICATE, NTLMv2) => capture + LOGON_FAILURE
    let proof: Vec<u8> = (0u8..16).collect();
    let mut nt = proof.clone();
    nt.extend_from_slice(&[0xaa; 16]);
    let t3 = common::ntlm_type3("alice", "CORP", &nt);
    send_session_setup(&mut stream, &t3).await;
    assert_eq!(read_status(&mut stream).await, smb::STATUS_LOGON_FAILURE);

    let art = common::recv_artifact(&mut rx, 5).await.expect("captured");
    assert_eq!(art.protocol, Protocol::Smb);
    assert_eq!(art.artifact_type, ArtifactType::NetNtlmV2);
    assert!(art.formatted.starts_with("alice::CORP:1122334455667788:"));
    assert_eq!(art.client.to_string(), "127.0.0.1");
}
