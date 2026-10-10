//! Minimal DCE/RPC (connection-oriented, over TCP) codec for the rogue endpoint-mapper
//! service. Handles the bind/auth handshake that carries an NTLMSSP token.

pub const VERSION: u8 = 5;

pub const PTYPE_REQUEST: u8 = 0;
pub const PTYPE_RESPONSE: u8 = 2;
pub const PTYPE_BIND: u8 = 11;
pub const PTYPE_BIND_ACK: u8 = 12;
pub const PTYPE_AUTH3: u8 = 16;

pub const AUTH_TYPE_NTLM: u8 = 0x0a;
pub const AUTH_LEVEL_PKT_PRIVACY: u8 = 6;

/// A decoded DCE/RPC PDU header + optional auth trailer.
#[derive(Clone, Debug)]
pub struct Pdu {
    pub ptype: u8,
    pub flags: u8,
    pub frag_len: u16,
    pub auth_len: u16,
    pub call_id: u32,
    /// `(auth_type, auth_level, auth_context_id, auth_value)` when present.
    pub auth: Option<(u8, u8, u32, Vec<u8>)>,
}

impl Pdu {
    pub fn parse(buf: &[u8]) -> Option<Pdu> {
        if buf.len() < 16 || buf[0] != VERSION {
            return None;
        }
        let ptype = buf[1];
        let flags = buf[2];
        let frag_len = u16::from_le_bytes([buf[8], buf[9]]);
        let auth_len = u16::from_le_bytes([buf[10], buf[11]]);
        let call_id = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);

        let auth = if auth_len >= 8 {
            let frag = (frag_len as usize).min(buf.len());
            let start = frag.checked_sub(auth_len as usize)?;
            let a = &buf[start..start + auth_len as usize];
            if a.len() >= 8 {
                let auth_type = a[0];
                let auth_level = a[1];
                let auth_context_id = u32::from_le_bytes([a[4], a[5], a[6], a[7]]);
                Some((auth_type, auth_level, auth_context_id, a[8..].to_vec()))
            } else {
                None
            }
        } else {
            None
        };
        Some(Pdu {
            ptype,
            flags,
            frag_len,
            auth_len,
            call_id,
            auth,
        })
    }
}

/// Build the DCE/RPC auth trailer bytes (auth_type/level/pad/context + token + padding).
fn auth_trailer(auth_type: u8, auth_level: u8, context_id: u32, token: &[u8]) -> Vec<u8> {
    let pad = (4 - (token.len() % 4)) % 4;
    let mut out = Vec::with_capacity(8 + token.len() + pad);
    out.push(auth_type);
    out.push(auth_level);
    out.push(pad as u8);
    out.push(0);
    out.extend_from_slice(&context_id.to_le_bytes());
    out.extend_from_slice(token);
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

/// Build a BIND_ACK PDU. When `token` is present an NTLM auth trailer is appended.
pub fn bind_ack(call_id: u32, token: Option<&[u8]>) -> Vec<u8> {
    let sec_addr = b"\\PIPE\\epmapper";
    let mut body = Vec::new();
    body.extend_from_slice(&5840u16.to_le_bytes()); // max_xmit_frag
    body.extend_from_slice(&5840u16.to_le_bytes()); // max_recv_frag
    body.extend_from_slice(&0u32.to_le_bytes()); // assoc_group
    body.extend_from_slice(&(sec_addr.len() as u16).to_le_bytes());
    body.extend_from_slice(sec_addr);
    while (16 + 8 + body.len()) % 4 != 0 {
        body.push(0);
    }

    let auth = token.map(|t| auth_trailer(AUTH_TYPE_NTLM, AUTH_LEVEL_PKT_PRIVACY, 1, t));
    let auth_len = auth.as_ref().map(|a| a.len() as u16).unwrap_or(0);
    let total = 16 + 8 + body.len() + auth_len as usize;

    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&[VERSION, PTYPE_BIND_ACK, 0x03, 0x10]);
    out.extend_from_slice(&(total as u16).to_le_bytes());
    out.extend_from_slice(&auth_len.to_le_bytes());
    out.extend_from_slice(&call_id.to_le_bytes());
    out.extend_from_slice(&body);
    if let Some(a) = auth {
        out.extend_from_slice(&a);
    }
    out
}

/// Build an AUTH3 PDU echoing the negotiated auth level.
pub fn auth3(call_id: u32) -> Vec<u8> {
    let trailer = auth_trailer(AUTH_TYPE_NTLM, AUTH_LEVEL_PKT_PRIVACY, 1, &[]);
    let total = 16 + trailer.len();
    let mut out = vec![VERSION, PTYPE_AUTH3, 0x00, 0x10];
    out.extend_from_slice(&(total as u16).to_le_bytes());
    out.extend_from_slice(&(trailer.len() as u16).to_le_bytes());
    out.extend_from_slice(&call_id.to_le_bytes());
    out.extend_from_slice(&trailer);
    out
}
