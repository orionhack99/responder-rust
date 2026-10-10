//! Shared helpers for the unit/integration/contract test targets.
//!
//! Included into each test file with `#[path = "../common/mod.rs"] mod common;`.

#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio::sync::mpsc;

use responder::capture::model::{CaptureArtifact, RunConfiguration};
use responder::capture::{CaptureEvent, CaptureSink};
use responder::cli::Cli;
use responder::config::{Settings, resolve};
use responder::logger::Logger;
use responder::servers::ServerContext;

/// A self-cleaning temporary directory (no external `tempfile` dependency).
pub struct TempDir {
    pub path: PathBuf,
}

impl TempDir {
    pub fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!(
            "responder-test-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        TempDir { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A default `RunConfiguration` (interface selection does not need to exist for these tests).
pub fn base_config() -> RunConfiguration {
    let cli = Cli::try_parse_from(["responder", "-I", "lo"]).unwrap();
    resolve(&cli, &Settings::default()).unwrap()
}

/// Build a `ServerContext` wired to a fresh capture channel rooted at `td`.
pub fn make_ctx(td: &TempDir) -> (Arc<ServerContext>, mpsc::Receiver<CaptureEvent>) {
    let logger = Arc::new(Logger::new(td.path.join("logs"), true, false, true).unwrap());
    let (tx, rx) = mpsc::channel(256);
    let ctx = Arc::new(ServerContext::new(
        base_config(),
        CaptureSink::new(tx),
        logger,
        Ipv4Addr::new(127, 0, 0, 1),
    ));
    (ctx, rx)
}

/// Await the next captured artifact, or `None` on timeout.
pub async fn recv_artifact(
    rx: &mut mpsc::Receiver<CaptureEvent>,
    secs: u64,
) -> Option<CaptureArtifact> {
    loop {
        match tokio::time::timeout(Duration::from_secs(secs), rx.recv()).await {
            Ok(Some(CaptureEvent::Artifact(a))) => return Some(*a),
            Ok(Some(CaptureEvent::Query(_))) => continue,
            Ok(None) | Err(_) => return None,
        }
    }
}

/// Await the next query observation, or `None` on timeout.
pub async fn recv_query(
    rx: &mut mpsc::Receiver<CaptureEvent>,
    secs: u64,
) -> Option<responder::capture::model::PoisonedQuery> {
    loop {
        match tokio::time::timeout(Duration::from_secs(secs), rx.recv()).await {
            Ok(Some(CaptureEvent::Query(q))) => return Some(*q),
            Ok(Some(CaptureEvent::Artifact(_))) => continue,
            Ok(None) | Err(_) => return None,
        }
    }
}

/// Build an NTLMSSP Type 1 (NEGOTIATE) message.
pub fn ntlm_type1() -> Vec<u8> {
    let mut b = vec![0u8; 32];
    b[0..8].copy_from_slice(b"NTLMSSP\0");
    b[8..12].copy_from_slice(&1u32.to_le_bytes());
    b[12..16].copy_from_slice(&0x0000_8207u32.to_le_bytes());
    b
}

/// Build an NTLMSSP Type 3 (AUTHENTICATE) message carrying `nt` as the NT response and the
/// supplied `domain`/`user` (ANSI encoded). When `nt` is longer than 24 bytes the parser treats
/// it as an NTLMv2 response (16-byte proof + blob).
pub fn ntlm_type3(user: &str, domain: &str, nt: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 64];
    buf[0..8].copy_from_slice(b"NTLMSSP\0");
    buf[8..12].copy_from_slice(&3u32.to_le_bytes());

    let mut payload = Vec::new();
    let put = |buf: &mut Vec<u8>, payload: &mut Vec<u8>, field: usize, data: &[u8]| {
        let start = 64 + payload.len();
        buf[field..field + 2].copy_from_slice(&(data.len() as u16).to_le_bytes());
        buf[field + 2..field + 4].copy_from_slice(&(data.len() as u16).to_le_bytes());
        buf[field + 4..field + 8].copy_from_slice(&(start as u32).to_le_bytes());
        payload.extend_from_slice(data);
    };
    put(&mut buf, &mut payload, 20, nt);
    put(&mut buf, &mut payload, 28, domain.as_bytes());
    put(&mut buf, &mut payload, 36, user.as_bytes());
    // flags = 0 => ANSI (not Unicode).
    buf[60..64].copy_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&payload);
    buf
}

/// Wrap `payload` in the NetBIOS session-service frame.
pub fn netbios_frame(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.push(0x00);
    out.extend_from_slice(&len.to_be_bytes()[1..4]);
    out.extend_from_slice(payload);
    out
}

/// Build a 64-byte SMB2 header for `command`.
pub fn smb2_header(command: u16) -> Vec<u8> {
    let mut h = vec![0u8; 64];
    h[0..4].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
    h[4..6].copy_from_slice(&64u16.to_le_bytes());
    h[12..14].copy_from_slice(&command.to_le_bytes());
    h
}

/// A loopback peer address for handler-level tests.
pub fn peer() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 49152)
}
