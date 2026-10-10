//! Minimal SMB2 server-side codec used by the rogue SMB service. Only the subset needed to
//! drive a client through NEGOTIATE + SESSION_SETUP (NTLMSSP) and capture the AUTHENTICATE
//! message is implemented.

pub mod negotiate;
pub mod session;

use crate::protocols::ntlm;

/// SMB2 protocol id (`\xFESMB`).
pub const SMB2_PROTOCOL_ID: [u8; 4] = [0xFE, b'S', b'M', b'B'];
/// SMB1 protocol id (`\xFFSMB`).
pub const SMB1_PROTOCOL_ID: [u8; 4] = [0xFF, b'S', b'M', b'B'];

pub const CMD_NEGOTIATE: u16 = 0x0000;
pub const CMD_SESSION_SETUP: u16 = 0x0001;
pub const CMD_TREE_CONNECT: u16 = 0x0003;
pub const CMD_CREATE: u16 = 0x0005;

pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
pub const STATUS_LOGON_FAILURE: u32 = 0xC000_006D;
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;

/// A decoded SMB2 header.
#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub command: u16,
    pub status: u32,
    pub flags: u32,
    pub next_command: u32,
    pub message_id: u64,
    pub process_id: u32,
    pub tree_id: u32,
    pub session_id: u64,
}

impl Header {
    pub fn parse(buf: &[u8]) -> Option<Header> {
        if buf.len() < 64 || buf[0..4] != SMB2_PROTOCOL_ID {
            return None;
        }
        let u16_at = |o: usize| u16::from_le_bytes([buf[o], buf[o + 1]]);
        let u32_at = |o: usize| u32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]);
        let u64_at = |o: usize| {
            u64::from_le_bytes([
                buf[o],
                buf[o + 1],
                buf[o + 2],
                buf[o + 3],
                buf[o + 4],
                buf[o + 5],
                buf[o + 6],
                buf[o + 7],
            ])
        };
        Some(Header {
            command: u16_at(12),
            status: u32_at(8),
            flags: u32_at(16),
            next_command: u32_at(20),
            message_id: u64_at(24),
            process_id: u32_at(32),
            tree_id: u32_at(36),
            session_id: u64_at(40),
        })
    }

    /// Serialize a 64-byte response header taking status/ids from `self`.
    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&SMB2_PROTOCOL_ID);
        out.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
        out.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
        out.extend_from_slice(&self.status.to_le_bytes());
        out.extend_from_slice(&self.command.to_le_bytes());
        out.extend_from_slice(&32u16.to_le_bytes()); // Credit granted
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.next_command.to_le_bytes());
        out.extend_from_slice(&self.message_id.to_le_bytes());
        out.extend_from_slice(&self.process_id.to_le_bytes());
        out.extend_from_slice(&self.tree_id.to_le_bytes());
        out.extend_from_slice(&self.session_id.to_le_bytes());
        out.extend_from_slice(&[0u8; 16]); // Signature
    }
}

/// Wrap an SMB payload in the NetBIOS session-service frame (message type 0).
pub fn netbios_frame(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.push(0x00);
    out.extend_from_slice(&len.to_be_bytes()[1..4]);
    out.extend_from_slice(payload);
    out
}

/// Read one NetBIOS-framed SMB message from a byte buffer, returning the payload and the number
/// of bytes consumed (including the 4-byte header).
pub fn read_netbios(buf: &[u8]) -> Option<(Vec<u8>, usize)> {
    if buf.len() < 4 {
        return None;
    }
    let len = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | buf[3] as usize;
    if buf.len() < 4 + len {
        return None;
    }
    Some((buf[4..4 + len].to_vec(), 4 + len))
}

/// Determine the type of an NTLMSSP token inside a security buffer (some messages wrap the
/// token in a SPNEGO/GSS-API envelope).
pub fn extract_ntlmssp(buf: &[u8]) -> Option<Vec<u8>> {
    if ntlm::message_type(buf).is_some() {
        return Some(buf.to_vec());
    }
    // SPNEGO wraps the NTLMSSP token after the "NTLMSSP\0" signature somewhere in the blob.
    let needle = b"NTLMSSP\0";
    buf.windows(needle.len())
        .position(|w| w == needle)
        .map(|p| buf[p..].to_vec())
}
