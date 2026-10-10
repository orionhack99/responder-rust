//! Minimal TDS (MSSQL) codec: packet framing, PRELOGIN and LOGIN7 credential extraction.

/// A TDS packet header (8 bytes).
#[derive(Clone, Copy, Debug)]
pub struct TdsHeader {
    pub packet_type: u8,
    pub status: u8,
    pub length: u16,
    pub spid: u16,
    pub packet_id: u8,
    pub window: u8,
}

impl TdsHeader {
    pub fn parse(buf: &[u8]) -> Option<TdsHeader> {
        if buf.len() < 8 {
            return None;
        }
        Some(TdsHeader {
            packet_type: buf[0],
            status: buf[1],
            length: u16::from_be_bytes([buf[2], buf[3]]),
            spid: u16::from_be_bytes([buf[4], buf[5]]),
            packet_id: buf[6],
            window: buf[7],
        })
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.push(self.packet_type);
        out.push(self.status);
        out.extend_from_slice(&self.length.to_be_bytes());
        out.extend_from_slice(&self.spid.to_be_bytes());
        out.push(self.packet_id);
        out.push(self.window);
    }
}

pub const PKT_LOGIN7: u8 = 0x10;
pub const PKT_PRELOGIN: u8 = 0x12;
pub const PKT_RESPONSE: u8 = 0x04;
pub const PKT_SSPI: u8 = 0x11;

/// Wrap a payload in a TDS packet.
pub fn frame(packet_type: u8, payload: &[u8]) -> Vec<u8> {
    let hdr = TdsHeader {
        packet_type,
        status: 0x01, // EOM
        length: (payload.len() + 8) as u16,
        spid: 0,
        packet_id: 1,
        window: 0,
    };
    let mut out = Vec::with_capacity(payload.len() + 8);
    hdr.write(&mut out);
    out.extend_from_slice(payload);
    out
}

/// Credentials extracted from a LOGIN7 packet.
#[derive(Clone, Debug, Default)]
pub struct Login7 {
    pub username: Option<String>,
    pub password: Option<String>,
    /// Raw NTLMSSP token when SSPI (Windows auth) is used.
    pub ntlmssp: Option<Vec<u8>>,
}

fn utf16le_at(buf: &[u8], offset: usize, cch: usize, f_byte: bool) -> String {
    if f_byte {
        // Single-byte charset: length is in bytes; approximate as ASCII.
        let end = (offset + cch).min(buf.len());
        crate::util::printable(&buf[offset.min(buf.len())..end])
    } else {
        let end = (offset + cch * 2).min(buf.len());
        crate::util::from_utf16le(&buf[offset.min(buf.len())..end])
    }
}

/// Parse a LOGIN7 payload (without the 8-byte TDS header).
pub fn parse_login7(buf: &[u8]) -> Login7 {
    // Fixed header is at least 86 bytes: length(4) TDSVersion(4) PacketSize(4) ClientProgVer(4)
    // ClientPid(4) ConnectionID(4) OptionFlags1(1) OptionFlags2(1) TypeFlags(1) OptionFlags3(1)
    // ClientTimeZone(4) ClientLCID(4) then offset/length pairs of cch (2) + offset (2).
    let mut login = Login7::default();
    if buf.len() < 86 {
        return login;
    }
    let flags2 = buf[29];
    let f_byte_order = flags2 & 0x01 == 0; // fByteOrder: 0 = little-endian char fields
    let read_pair = |base: usize| -> (usize, usize) {
        let cch = u16::from_le_bytes([buf[base], buf[base + 1]]) as usize;
        let off = u16::from_le_bytes([buf[base + 2], buf[base + 3]]) as usize;
        (cch, off)
    };
    // ClientName(36) UserName(40) Password(44) AppName(48) ServerName(52) ...
    let (_cch_cn, _off_cn) = read_pair(36);
    let (cch_user, off_user) = read_pair(40);
    let (cch_pass, off_pass) = read_pair(44);
    if off_user != 0 && cch_user != 0 {
        login.username = Some(utf16le_at(buf, off_user, cch_user, f_byte_order));
    }
    if off_pass != 0 && cch_pass != 0 {
        // Password bytes are XOR 0xA5 then nibble-swapped (obfuscation).
        let raw = &buf[off_pass.min(buf.len())..(off_pass + cch_pass * 2).min(buf.len())];
        let decoded: Vec<u8> = raw.iter().map(|b| b ^ 0xA5).collect();
        let swapped = swap_nibbles(&decoded);
        login.password = Some(crate::util::from_utf16le(&swapped));
    }
    // Try to find an embedded NTLMSSP token (SSPI) anywhere in the packet.
    if let Some(pos) = buf.windows(8).position(|w| w == b"NTLMSSP\0") {
        login.ntlmssp = Some(buf[pos..].to_vec());
    }
    login
}

/// Reverse the nibble swap TDS applies to the XOR-obfuscated password.
fn swap_nibbles(data: &[u8]) -> Vec<u8> {
    data.iter().map(|b| b.rotate_right(4)).collect()
}
