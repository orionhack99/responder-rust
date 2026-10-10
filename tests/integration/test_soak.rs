//! Soak test: many concurrent SMB sessions are handled without dropped captures (SC-006).

#[path = "../common/mod.rs"]
mod common;

use responder::protocols::smb;
use responder::servers::smb::serve;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const SESSIONS: usize = 50;

async fn one_session(addr: std::net::SocketAddr, user: String) {
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

    // SESSION_SETUP with AUTHENTICATE
    let mut nt: Vec<u8> = (0u8..16).collect();
    nt.extend_from_slice(&[0xab; 16]);
    let token = common::ntlm_type3(&user, "CORP", &nt);
    let mut body = vec![0u8; 24];
    body[12..14].copy_from_slice(&(64u16 + 24).to_le_bytes());
    body[14..16].copy_from_slice(&(token.len() as u16).to_le_bytes());
    let mut full = common::smb2_header(smb::CMD_SESSION_SETUP);
    full.extend_from_slice(&body);
    full.extend_from_slice(&token);
    stream
        .write_all(&common::netbios_frame(&full))
        .await
        .unwrap();

    // Read the LOGON_FAILURE response then drop the connection.
    stream.read_exact(&mut hdr).await.unwrap();
    let len = ((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | hdr[3] as usize;
    let mut resp = vec![0u8; len];
    stream.read_exact(&mut resp).await.unwrap();
    let status = u32::from_le_bytes(resp[8..12].try_into().unwrap());
    assert_eq!(status, smb::STATUS_LOGON_FAILURE);
}

#[tokio::test]
async fn fifty_concurrent_smb_captures() {
    let td = common::TempDir::new("soak");
    let (ctx, mut rx) = common::make_ctx(&td);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, ctx));

    let mut handles = Vec::new();
    for i in 0..SESSIONS {
        handles.push(tokio::spawn(one_session(addr, format!("user{i}"))));
    }
    for h in handles {
        h.await.unwrap();
    }

    let mut seen = std::collections::HashSet::new();
    for _ in 0..SESSIONS {
        let art = common::recv_artifact(&mut rx, 5).await.expect("capture");
        seen.insert(art.formatted);
    }
    assert_eq!(
        seen.len(),
        SESSIONS,
        "every session produced a distinct capture"
    );
}
