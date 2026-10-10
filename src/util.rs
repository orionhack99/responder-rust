//! Small, dependency-light helpers used across protocols and the capture model.

use std::net::IpAddr;

/// Lower-case hex encode.
pub fn hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Hex decode; accepts upper/lower case and an odd leading nibble-free string only.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let nib = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut i = 0;
    while i < bytes.len() {
        out.push((nib(bytes[i])? << 4) | nib(bytes[i + 1])?);
        i += 2;
    }
    Some(out)
}

/// Encode a string to UTF-16LE (used by NTLM and NetBIOS wire formats).
pub fn utf16le(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

/// Decode UTF-16LE bytes, ignoring a trailing odd byte.
pub fn from_utf16le(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// `MD5(data)` as a lower-case hex string (used for dedup keys and challenge-response).
pub fn md5_hex(data: &[u8]) -> String {
    hex(&md5::compute(data).0)
}

/// `HMAC-MD5(key, data)` built manually on top of the `md5` crate (no extra dependency).
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..16].copy_from_slice(&md5::compute(key).0);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = ipad.to_vec();
    inner.extend_from_slice(data);
    let inner_hash = md5::compute(&inner).0;
    let mut outer = opad.to_vec();
    outer.extend_from_slice(&inner_hash);
    md5::compute(&outer).0
}

/// Parse an `IpAddr` from a possibly-bracketed literal.
pub fn parse_ip(s: &str) -> Option<IpAddr> {
    let t = s.trim();
    let t = t
        .strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .unwrap_or(t);
    t.parse().ok()
}

/// True when `text` is a valid dotted-quad or bracketed IPv6 literal.
pub fn is_ip_literal(text: &str) -> bool {
    parse_ip(text).is_some()
}

/// Strip a trailing NUL and any trailing dot from an iface/host name.
pub fn trim_name(s: &str) -> String {
    s.trim_end_matches('\0').trim_end_matches('.').to_string()
}

/// Return the printable ASCII form of a byte slice (drops non-printables) — used when logging
/// cleartext credentials that may contain stray control bytes.
pub fn printable(data: &[u8]) -> String {
    data.iter()
        .filter(|&&b| (0x20..0x7f).contains(&b))
        .map(|&b| b as char)
        .collect()
}
