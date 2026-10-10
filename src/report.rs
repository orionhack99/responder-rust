//! Startup summary and offline artifact review/export helpers.

use anyhow::Result;

use crate::servers::BindOutcome;
use crate::store::Store;

/// Count `(listening, failed)` services.
pub fn summarize(outcomes: &[BindOutcome]) -> (usize, usize) {
    let ok = outcomes.iter().filter(|o| o.ok).count();
    (ok, outcomes.len() - ok)
}

/// Render the multi-line startup summary shown once services are launched.
pub fn format_summary(interface: &str, analyze: bool, outcomes: &[BindOutcome]) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "Responder is running on interface {interface}{}\n",
        if analyze { " (analyze mode)" } else { "" }
    ));
    for o in outcomes {
        let status = if o.ok { "listening" } else { "FAILED" };
        let err = o
            .error
            .as_ref()
            .map(|e| format!(" — {e}"))
            .unwrap_or_default();
        s.push_str(&format!("  {:<8} {}{}\n", o.service.as_str(), status, err));
    }
    s
}

/// List captured artifacts, optionally filtered by protocol/client (review mode).
pub fn review(store: &Store, protocol: Option<&str>, client: Option<&str>) -> Result<Vec<String>> {
    Ok(store
        .list_captures(protocol, client)?
        .into_iter()
        .map(|a| {
            format!(
                "[{}] {}-{} from {}: {}",
                a.timestamp.to_rfc3339(),
                a.protocol.as_str(),
                a.artifact_type.file_suffix(),
                a.client,
                a.formatted
            )
        })
        .collect())
}

/// Dump every captured hash line (one per line), suitable for `hashcat`.
pub fn dump_hashes(store: &Store) -> Result<Vec<String>> {
    store.dump_hashes()
}
