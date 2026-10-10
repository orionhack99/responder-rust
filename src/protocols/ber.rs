//! Minimal BER/DER codec plus LDAP BindRequest parsing for the rogue LDAP service.

/// Encode a BER length (definite form).
pub fn encode_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let mut bytes = Vec::new();
        let mut v = len;
        while v > 0 {
            bytes.push((v & 0xff) as u8);
            v >>= 8;
        }
        bytes.reverse();
        let mut out = vec![0x80 | bytes.len() as u8];
        out.extend_from_slice(&bytes);
        out
    }
}

/// Parse one TLV; returns `(tag, value, bytes_consumed)`.
pub fn parse_tlv(buf: &[u8]) -> Option<(u8, &[u8], usize)> {
    if buf.is_empty() {
        return None;
    }
    let tag = buf[0];
    if buf.len() < 2 {
        return None;
    }
    let first = buf[1];
    let (len, hdr) = if first & 0x80 == 0 {
        (first as usize, 2usize)
    } else {
        let n = (first & 0x7f) as usize;
        if buf.len() < 2 + n || n == 0 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | buf[2 + i] as usize;
        }
        (len, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    if buf.len() < end {
        return None;
    }
    Some((tag, &buf[hdr..end], end))
}

/// A parsed LDAP BindRequest.
#[derive(Clone, Debug, Default)]
pub struct BindOp {
    pub message_id: i64,
    pub dn: String,
    /// Present for simple authentication.
    pub simple: Option<Vec<u8>>,
    /// SASL mechanism (context tag 3), if used.
    pub sasl_mech: Option<String>,
    /// SASL credentials.
    pub sasl_creds: Option<Vec<u8>>,
}

fn parse_integer(v: &[u8]) -> i64 {
    let mut n: i64 = 0;
    for &b in v {
        n = (n << 8) | b as i64;
    }
    n
}

/// Parse an LDAPMessage (SEQUENCE { messageID, bindRequest[APPLICATION 0] }).
pub fn parse_bind(msg: &[u8]) -> Option<BindOp> {
    let (tag, seq, _) = parse_tlv(msg)?;
    if tag != 0x30 {
        return None;
    }
    let (_t, id_bytes, used) = parse_tlv(seq)?;
    let message_id = parse_integer(id_bytes);
    let rest = &seq[used..];
    let (bind_tag, bind_val, _) = parse_tlv(rest)?;
    if bind_tag != 0x60 {
        // Not an application-0 BindRequest.
        return None;
    }
    let (_t, version, used_v) = parse_tlv(bind_val)?;
    let _ = version;
    let (_t, dn_bytes, used_dn) = parse_tlv(&bind_val[used_v..])?;
    let dn = String::from_utf8_lossy(dn_bytes).to_string();
    let auth_rest = &bind_val[used_v + used_dn..];
    let (auth_tag, auth_val, _) = parse_tlv(auth_rest)?;
    let mut op = BindOp {
        message_id,
        dn,
        ..Default::default()
    };
    match auth_tag {
        0x80 => op.simple = Some(auth_val.to_vec()), // [0] simple password
        0xa3 => {
            // [3] SASL: mechanism OCTET STRING, optional credentials OCTET STRING
            let (_m, mech, used_m) = parse_tlv(auth_val)?;
            op.sasl_mech = Some(String::from_utf8_lossy(mech).to_string());
            if let Some((_c, creds, _)) = parse_tlv(&auth_val[used_m..]) {
                op.sasl_creds = Some(creds.to_vec());
            }
        }
        _ => {}
    }
    Some(op)
}

/// Build a BindResponse LDAPMessage with the given result code and optional server credentials
/// (used for SASL continuation carrying an NTLMSSP challenge).
pub fn build_bind_response(
    message_id: i64,
    result_code: u8,
    server_creds: Option<&[u8]>,
) -> Vec<u8> {
    let mut bind = Vec::new();
    bind.extend_from_slice(&[0x0a, 0x01, result_code]); // resultCode ENUMERATED
    bind.extend_from_slice(&[0x04, 0x00]); // matchedDN
    bind.extend_from_slice(&[0x04, 0x00]); // diagnosticMessage
    if let Some(creds) = server_creds {
        // [7] serverSaslCreds
        bind.push(0x87);
        bind.extend_from_slice(&encode_len(creds.len()));
        bind.extend_from_slice(creds);
    }
    let mut inner = vec![0x61];
    inner.extend_from_slice(&encode_len(bind.len()));
    inner.extend_from_slice(&bind);

    let mut msg = Vec::new();
    // INTEGER messageID
    msg.push(0x02);
    let id_bytes = message_id.to_be_bytes();
    let start = id_bytes.iter().position(|&b| b != 0).unwrap_or(7);
    msg.extend_from_slice(&encode_len(id_bytes.len() - start));
    msg.extend_from_slice(&id_bytes[start..]);
    msg.extend_from_slice(&inner);

    let mut out = vec![0x30];
    out.extend_from_slice(&encode_len(msg.len()));
    out.extend_from_slice(&msg);
    out
}
