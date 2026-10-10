//! Integration test: review/export over the capture store, including dedup behavior.

use std::sync::Arc;

use responder::capture::model::{CaptureArtifact, Protocol};
use responder::protocols::ntlm::NetNtlm;
use responder::report;
use responder::store::Store;

fn netntlmv2(user: &str, client: &str) -> CaptureArtifact {
    let net = NetNtlm {
        user: user.to_string(),
        domain: "CORP".to_string(),
        server_challenge: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        nt_proof_str: (0u8..16).collect(),
        blob: Some((1u8..17).collect()),
    };
    CaptureArtifact::netntlm(Protocol::Smb, client.parse().unwrap(), &net)
}

#[test]
fn list_filter_and_export() {
    let store = Arc::new(Store::open_in_memory().unwrap());
    let run = store.start_run("lo", false).unwrap();

    let smb = netntlmv2("alice", "10.0.0.5");
    let ftp = CaptureArtifact::cleartext(Protocol::Ftp, "10.0.0.5".parse().unwrap(), "bob", "pw")
        .unwrap();
    assert!(store.insert_capture(&run, &smb).unwrap());
    assert!(store.insert_capture(&run, &ftp).unwrap());
    // Duplicate of smb is collapsed.
    assert!(!store.insert_capture(&run, &smb).unwrap());

    assert_eq!(store.count_captures().unwrap(), 2);
    assert_eq!(store.list_captures(None, None).unwrap().len(), 2);
    assert_eq!(store.list_captures(Some("SMB"), None).unwrap().len(), 1);
    assert_eq!(
        store.list_captures(None, Some("10.0.0.5")).unwrap().len(),
        2
    );
    assert_eq!(
        store
            .list_captures(Some("FTP"), Some("10.0.0.5"))
            .unwrap()
            .len(),
        1
    );

    let hashes = report::dump_hashes(&store).unwrap();
    assert_eq!(hashes.len(), 2);
    assert!(hashes.iter().any(|h| h.starts_with("alice::CORP:")));
    assert!(hashes.iter().any(|h| h == "bob:pw"));

    let reviewed = report::review(&store, Some("SMB"), None).unwrap();
    assert_eq!(reviewed.len(), 1);
    assert!(reviewed[0].contains("alice"));
}
