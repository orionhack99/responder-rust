//! Unit tests for the NTLMSSP server helpers in `protocols/ntlm.rs`.

#[path = "../common/mod.rs"]
mod common;

use responder::protocols::ntlm;

fn flags_at(msg: &[u8]) -> u32 {
    u32::from_le_bytes(msg[20..24].try_into().unwrap())
}

#[test]
fn capture_challenge_is_fixed() {
    assert_eq!(
        ntlm::capture_challenge(),
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
    );
}

#[test]
fn challenge_is_a_type2_message() {
    let msg = ntlm::build_default_challenge("RESPONDER", false, false);
    assert_eq!(ntlm::message_type(&msg), Some(2));
    assert!(flags_at(&msg) & ntlmssp::flags::NEGOTIATE_TARGET_INFO != 0);
    assert!(flags_at(&msg) & ntlmssp::flags::NEGOTIATE_EXTENDED_SESSIONSECURITY != 0);
}

#[test]
fn lm_downgrade_clears_ntlmv2_flags() {
    let msg = ntlm::build_default_challenge("RESPONDER", true, false);
    let f = flags_at(&msg);
    assert_eq!(f & ntlmssp::flags::NEGOTIATE_TARGET_INFO, 0);
    assert_eq!(f & ntlmssp::flags::NEGOTIATE_EXTENDED_SESSIONSECURITY, 0);
}

#[test]
fn disable_ess_only_clears_ess() {
    let msg = ntlm::build_default_challenge("RESPONDER", false, true);
    let f = flags_at(&msg);
    assert_eq!(f & ntlmssp::flags::NEGOTIATE_EXTENDED_SESSIONSECURITY, 0);
    assert!(f & ntlmssp::flags::NEGOTIATE_TARGET_INFO != 0);
}

#[test]
fn message_type_detects_types() {
    assert_eq!(ntlm::message_type(&common::ntlm_type1()), Some(1));
    let t3 = common::ntlm_type3("u", "d", &[0u8; 24]);
    assert_eq!(ntlm::message_type(&t3), Some(3));
    assert_eq!(ntlm::message_type(b"not ntlm"), None);
}

#[test]
fn parse_type3_v2_extracts_proof_and_blob() {
    let challenge = ntlm::capture_challenge();
    let proof: Vec<u8> = (0u8..16).collect();
    let blob: Vec<u8> = (100u8..116).collect();
    let mut nt = proof.clone();
    nt.extend_from_slice(&blob);

    let t3 = common::ntlm_type3("alice", "CORP", &nt);
    let net = ntlm::parse_type3(&t3, &challenge).expect("parsed");
    assert_eq!(net.user, "alice");
    assert_eq!(net.domain, "CORP");
    assert_eq!(net.nt_proof_str, proof);
    assert_eq!(net.blob.as_deref(), Some(blob.as_slice()));
    assert!(net.is_v2());

    let line = ntlm::to_hashcat(&net);
    assert!(line.starts_with("alice::CORP:1122334455667788:"));
    assert_eq!(line.matches(':').count(), 5);
}

#[test]
fn parse_type3_v1_has_no_blob() {
    let challenge = ntlm::capture_challenge();
    let nt = [0xabu8; 24];
    let t3 = common::ntlm_type3("bob", "CORP", &nt);
    let net = ntlm::parse_type3(&t3, &challenge).expect("parsed");
    assert_eq!(net.user, "bob");
    assert!(!net.is_v2());
    assert!(net.blob.is_none());
    assert_eq!(net.nt_proof_str, nt);
}

#[test]
fn parse_type3_rejects_short_nt() {
    let challenge = ntlm::capture_challenge();
    let t3 = common::ntlm_type3("x", "y", &[0u8; 8]);
    assert!(ntlm::parse_type3(&t3, &challenge).is_none());
}
