//! Unit tests for the shared encoding/decoding helpers in `util.rs`.

use responder::util;

#[test]
fn hex_roundtrip() {
    let data = [0x00u8, 0x0f, 0xa5, 0xff];
    let encoded = util::hex(&data);
    assert_eq!(encoded, "000fa5ff");
    assert_eq!(util::unhex(&encoded).unwrap(), data);
    assert_eq!(util::unhex("000FA5FF").unwrap(), data);
}

#[test]
fn unhex_rejects_odd_and_invalid() {
    assert!(util::unhex("abc").is_none());
    assert!(util::unhex("zz").is_none());
    assert_eq!(util::unhex("").unwrap(), Vec::<u8>::new());
}

#[test]
fn utf16le_roundtrip() {
    let bytes = util::utf16le("héllo");
    assert_eq!(&bytes[0..2], &[b'h', 0]);
    assert_eq!(util::from_utf16le(&bytes), "héllo");
}

#[test]
fn hmac_md5_rfc2202_vector() {
    // RFC 2202 test case 1: key = 0x0b x16, data = "Hi There".
    let key = [0x0bu8; 16];
    let mac = util::hmac_md5(&key, b"Hi There");
    assert_eq!(util::hex(&mac), "9294727a3638bb1c13f48ef8158bfc9d");
}

#[test]
fn hmac_md5_long_key_is_hashed() {
    // RFC 2202 test case 6: 80-byte 0xaa key, data = "Test Using Larger Than Block-Size Key - Hash Key First".
    let key = [0xaau8; 80];
    let mac = util::hmac_md5(
        &key,
        b"Test Using Larger Than Block-Size Key - Hash Key First",
    );
    assert_eq!(util::hex(&mac), "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd");
}

#[test]
fn md5_hex_known() {
    assert_eq!(util::md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
}

#[test]
fn printable_drops_control_bytes() {
    assert_eq!(util::printable(b"pass\x00word\x01"), "password");
}

#[test]
fn parse_ip_and_literals() {
    assert!(util::is_ip_literal("10.0.0.1"));
    assert!(util::is_ip_literal("[fe80::1]"));
    assert!(!util::is_ip_literal("not-an-ip"));
    assert_eq!(
        util::parse_ip("192.168.1.20").unwrap().to_string(),
        "192.168.1.20"
    );
}

#[test]
fn trim_name_strips_nul_and_dot() {
    assert_eq!(util::trim_name("HOST\0"), "HOST");
    assert_eq!(util::trim_name("host."), "host");
}
