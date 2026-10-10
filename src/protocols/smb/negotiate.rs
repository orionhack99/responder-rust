//! SMB2 NEGOTIATE handling.

use super::{Header, STATUS_SUCCESS};

/// SMB 2.0.2 — simple, widely supported and uses direct NTLMSSP in SESSION_SETUP.
pub const DIALECT_2_0_2: u16 = 0x0202;

fn now_filetime() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    (secs + 11_644_473_600) * 10_000_000
}

/// Build the NEGOTIATE response body (without the 64-byte SMB2 header).
pub fn build_response(server_guid: &[u8; 16]) -> Vec<u8> {
    let mut body = Vec::with_capacity(64);
    body.extend_from_slice(&65u16.to_le_bytes()); // StructureSize (per spec)
    body.extend_from_slice(&0u16.to_le_bytes()); // SecurityMode: signing not required
    body.extend_from_slice(&DIALECT_2_0_2.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes()); // NegotiateContextCount
    body.extend_from_slice(server_guid);
    body.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    body.extend_from_slice(&0x0010_0000u32.to_le_bytes()); // MaxTransactSize
    body.extend_from_slice(&0x0010_0000u32.to_le_bytes()); // MaxReadSize
    body.extend_from_slice(&0x0010_0000u32.to_le_bytes()); // MaxWriteSize
    body.extend_from_slice(&now_filetime().to_le_bytes()); // SystemTime
    body.extend_from_slice(&0u64.to_le_bytes()); // ServerStartTime
    body.extend_from_slice(&128u16.to_le_bytes()); // SecurityBufferOffset
    body.extend_from_slice(&0u16.to_le_bytes()); // SecurityBufferLength
    body.extend_from_slice(&0u32.to_le_bytes()); // NegotiateContextOffset
    body
}

/// Build the full NEGOTIATE response (header + body).
pub fn respond(req: &Header, server_guid: &[u8; 16]) -> Vec<u8> {
    let mut h = *req;
    h.status = STATUS_SUCCESS;
    let mut out = Vec::new();
    h.write(&mut out);
    out.extend_from_slice(&build_response(server_guid));
    out
}
