//! Unit tests for APOP / CRAM-MD5 / DIGEST-MD5 helpers.

use responder::crypto::challenge;

#[test]
fn apop_rfc1939_vector() {
    let challenge = "<1896.697170952@dbc.mtview.ca.us>";
    let digest = challenge::apop_digest(challenge, "tanstaaf");
    assert_eq!(
        responder::util::hex(&digest),
        "c4c9334bac560ecc979e58001b3e22fb"
    );
    assert!(challenge::apop_verify(
        challenge,
        "tanstaaf",
        "c4c9334bac560ecc979e58001b3e22fb"
    ));
    assert!(!challenge::apop_verify(challenge, "wrong", "c4c9"));
}

#[test]
fn cram_md5_rfc2195_vector() {
    let challenge = b"<1896.697170952@postoffice.reston.mci.net>";
    let resp = challenge::cram_md5_response(challenge, "tim", "tanstaaftanstaaf");
    assert_eq!(resp, "tim b913a602c7eda7a495b4e6e7334d3890");
    let (user, mac) = challenge::parse_cram_md5(&resp).unwrap();
    assert_eq!(user, "tim");
    assert_eq!(mac, "b913a602c7eda7a495b4e6e7334d3890");
}

#[test]
fn cram_md5_challenge_is_base64() {
    assert_eq!(challenge::cram_md5_challenge(b"abc"), "YWJj");
}

#[test]
fn digest_md5_parses_quoted_directives() {
    let raw = r#"username="alice",realm="corp.local",nonce="OA6MG9tEQGm2hh",cnonce="OA6MHXh6VqTrRk",response=3b60a04dfa1f4c36f7e0e75b1ed2eef1,digest-uri="imap/corp.local""#;
    let d = challenge::parse_digest_md5(raw);
    assert_eq!(d.username.as_deref(), Some("alice"));
    assert_eq!(d.realm.as_deref(), Some("corp.local"));
    assert_eq!(d.cnonce.as_deref(), Some("OA6MHXh6VqTrRk"));
    assert_eq!(d.digest_uri.as_deref(), Some("imap/corp.local"));
    assert_eq!(
        d.capture_line().as_deref(),
        Some("alice:3b60a04dfa1f4c36f7e0e75b1ed2eef1")
    );
}

#[test]
fn digest_md5_tolerates_commas_in_quotes() {
    let raw = r#"username="bob",realm="a,b",nonce="n",response=deadbeef"#;
    let d = challenge::parse_digest_md5(raw);
    assert_eq!(d.username.as_deref(), Some("bob"));
    assert_eq!(d.realm.as_deref(), Some("a,b"));
}

#[test]
fn server_digest_challenge_shape() {
    let c = challenge::digest_md5_challenge("corp.local", "abc123");
    assert!(c.contains(r#"realm="corp.local""#));
    assert!(c.contains(r#"nonce="abc123""#));
    assert!(c.contains("qop=\"auth\""));
}
