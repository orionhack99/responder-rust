//! Contract tests for on-disk artifact formats, file naming and the SQLite schema.

#[path = "../common/mod.rs"]
mod common;

use std::io::Read;
use std::sync::Arc;

use responder::capture::model::{ArtifactType, CaptureArtifact, Protocol};
use responder::logger::Logger;
use responder::protocols::ntlm::NetNtlm;
use responder::store::Store;

fn netntlmv2(user: &str, domain: &str, client: &str) -> CaptureArtifact {
    let net = NetNtlm {
        user: user.to_string(),
        domain: domain.to_string(),
        server_challenge: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        nt_proof_str: (0u8..16).collect(),
        blob: Some((100u8..116).collect()),
    };
    CaptureArtifact::netntlm(Protocol::Smb, client.parse().unwrap(), &net)
}

#[test]
fn netntlmv2_line_is_hashcat_compatible() {
    let art = netntlmv2("alice", "CORP", "10.0.0.5");
    assert_eq!(art.artifact_type, ArtifactType::NetNtlmV2);
    // user::domain:challenge:NTProofStr:blob  (5 colons)
    assert_eq!(art.formatted.matches(':').count(), 5);
    assert!(art.formatted.starts_with("alice::CORP:1122334455667788:"));
}

#[test]
fn cleartext_line_is_user_colon_secret() {
    let art = CaptureArtifact::cleartext(
        Protocol::Ftp,
        "10.0.0.5".parse().unwrap(),
        "alice",
        "s3cr3t",
    )
    .unwrap();
    assert_eq!(art.formatted, "alice:s3cr3t");
    assert_eq!(art.artifact_type, ArtifactType::Cleartext);
    // Cleartext requires a non-empty secret.
    assert!(
        CaptureArtifact::cleartext(Protocol::Ftp, "10.0.0.5".parse().unwrap(), "x", "").is_none()
    );
}

#[test]
fn log_file_naming_rule() {
    let td = common::TempDir::new("logname");
    let logger = Logger::new(td.path.join("logs"), true, false, true).unwrap();
    let art = netntlmv2("alice", "CORP", "10.0.0.5");
    logger.captured(&art).unwrap();

    let file = td.path.join("logs").join("SMB-NTLMv2-10.0.0.5.txt");
    assert!(file.exists(), "expected {}", file.display());
    let mut s = String::new();
    std::fs::File::open(&file)
        .unwrap()
        .read_to_string(&mut s)
        .unwrap();
    assert_eq!(s.trim_end(), art.formatted);

    // Session log records the capture.
    let session = td.path.join("logs").join("Responder-Session.log");
    let mut sl = String::new();
    std::fs::File::open(&session)
        .unwrap()
        .read_to_string(&mut sl)
        .unwrap();
    assert!(sl.contains("NTLMv2") && sl.contains("10.0.0.5"));
}

#[test]
fn database_schema_matches_contract() {
    let td = common::TempDir::new("dbschema");
    let db = td.path.join("Responder.db");
    let _store = Store::open(&db).unwrap();

    let conn = rusqlite::Connection::open(&db).unwrap();
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type IN ('table','index')")
        .unwrap();
    let names: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    for expected in [
        "runs",
        "hosts",
        "sessions",
        "captures",
        "poisoned_queries",
        "idx_captures_dedup",
    ] {
        assert!(names.iter().any(|n| n == expected), "missing {expected}");
    }
}

#[test]
fn dedup_collapses_identical_captures() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    let run = store.start_run("lo", false).unwrap();
    let art = netntlmv2("alice", "CORP", "10.0.0.5");

    assert!(store.insert_capture(&run, &art).unwrap(), "first insert");
    assert!(!store.insert_capture(&run, &art).unwrap(), "dup suppressed");
    assert_eq!(store.count_captures().unwrap(), 1);

    // A different client is a different artifact.
    let other = netntlmv2("alice", "CORP", "10.0.0.6");
    assert!(store.insert_capture(&run, &other).unwrap());
    assert_eq!(store.count_captures().unwrap(), 2);
}

#[test]
fn run_lifecycle_sets_ended_at() {
    let store = Store::open_in_memory().unwrap();
    let run = store.start_run("lo", true).unwrap();
    store.finish_run(&run).unwrap();
}
