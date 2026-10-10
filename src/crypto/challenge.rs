//! Challenge-response helpers for the cleartext/digest protocols (POP3 APOP, SMTP/IMAP
//! CRAM-MD5 and DIGEST-MD5). Built on MD5 + the local HMAC-MD5 so no extra dependency is
//! required.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use crate::util;

/// POP3 APOP: `MD5(challenge <> password)` rendered as 16 bytes.
pub fn apop_digest(challenge: &str, password: &str) -> Vec<u8> {
    let mut input = challenge.as_bytes().to_vec();
    input.extend_from_slice(password.as_bytes());
    md5::compute(&input).0.to_vec()
}

/// Verify an APOP digest captured from a client.
pub fn apop_verify(challenge: &str, password: &str, digest_hex: &str) -> bool {
    util::hex(&apop_digest(challenge, password)) == digest_hex.to_ascii_lowercase()
}

/// CRAM-MD5 client response body: `user <hex(HMAC-MD5(challenge, password))>`.
pub fn cram_md5_response(challenge: &[u8], user: &str, password: &str) -> String {
    let mac = util::hmac_md5(password.as_bytes(), challenge);
    format!("{user} {}", util::hex(&mac))
}

/// Parse a CRAM-MD5 response (`user hexmac`) into `(user, mac_hex)`.
pub fn parse_cram_md5(resp: &str) -> Option<(String, String)> {
    let mut parts = resp.split_whitespace();
    let user = parts.next()?.to_string();
    let mac = parts.next()?.to_string();
    Some((user, mac))
}

/// Encode a CRAM-MD5 challenge for the `+ ` prompt line.
pub fn cram_md5_challenge(token: &[u8]) -> String {
    B64.encode(token)
}

/// A parsed DIGEST-MD5 response (subset of the directives we care about).
#[derive(Clone, Debug, Default)]
pub struct DigestMd5 {
    pub username: Option<String>,
    pub realm: Option<String>,
    pub nonce: Option<String>,
    pub cnonce: Option<String>,
    pub response: Option<String>,
    pub digest_uri: Option<String>,
}

impl DigestMd5 {
    /// One-line capture representation: `user:response`.
    pub fn capture_line(&self) -> Option<String> {
        Some(format!(
            "{}:{}",
            self.username.clone().unwrap_or_default(),
            self.response.clone()?
        ))
    }
}

/// Parse a DIGEST-MD5 client response: a comma-separated list of `key=value` directives,
/// where values may be quoted.
pub fn parse_digest_md5(resp: &str) -> DigestMd5 {
    let mut d = DigestMd5::default();
    for part in split_directives(resp) {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim().trim_matches('"').to_string();
        match key.as_str() {
            "username" => d.username = Some(val),
            "realm" => d.realm = Some(val),
            "nonce" => d.nonce = Some(val),
            "cnonce" => d.cnonce = Some(val),
            "response" => d.response = Some(val),
            "digest-uri" => d.digest_uri = Some(val),
            _ => {}
        }
    }
    d
}

/// Split a DIGEST-MD5 directive list on commas that are not inside quotes.
fn split_directives(resp: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    for c in resp.chars() {
        if escaped {
            cur.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quotes => escaped = true,
            '"' => {
                in_quotes = !in_quotes;
                cur.push(c);
            }
            ',' if !in_quotes => {
                out.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

/// Build the server DIGEST-MD5 challenge directive list.
pub fn digest_md5_challenge(realm: &str, nonce: &str) -> String {
    format!("realm=\"{realm}\",nonce=\"{nonce}\",qop=\"auth\",charset=utf-8,algorithm=md5-sess")
}
