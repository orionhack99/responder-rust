//! SMB2 SESSION_SETUP handling (NTLMSSP token framing).

use super::Header;

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

/// Extract the security buffer token from a SESSION_SETUP request. Offsets are relative to the
/// start of the SMB2 header, so `full` must include the 64-byte header.
pub fn parse_security_buffer(full: &[u8]) -> Option<Vec<u8>> {
    if full.len() < 64 + 24 {
        return None;
    }
    let body = &full[64..];
    // StructureSize(2) Flags(1) SecurityMode(1) Capabilities(4) Channel(4)
    // SecurityBufferOffset(2) SecurityBufferLength(2) PreviousSessionId(8)
    let off = u16le(body, 12) as usize;
    let len = u16le(body, 14) as usize;
    let end = off.checked_add(len)?;
    full.get(off..end).map(|s| s.to_vec())
}

/// Build a SESSION_SETUP response with an optional NTLMSSP token.
pub fn respond(req: &Header, status: u32, session_id: u64, token: &[u8]) -> Vec<u8> {
    let mut h = *req;
    h.status = status;
    h.session_id = session_id;
    let mut out = Vec::new();
    h.write(&mut out);
    let sb_off = 64u16 + 8u16;
    out.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
    out.extend_from_slice(&0u16.to_le_bytes()); // SessionFlags
    out.extend_from_slice(&sb_off.to_le_bytes());
    out.extend_from_slice(&(token.len() as u16).to_le_bytes());
    out.extend_from_slice(token);
    out
}
