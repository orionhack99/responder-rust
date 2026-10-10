//! SQLite persistence for runs, hosts, captures and poisoned queries.
//!
//! The schema mirrors `contracts/output-artifacts.md`. `captures.dedup_hash` has a UNIQUE index
//! so exact repeats collapse while distinct artifacts are preserved. The database is ordinary
//! SQLite and is fully inspectable with the `sqlite3` CLI.

use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{Connection, params};

use crate::capture::model::{CaptureArtifact, PoisonedQuery};
use crate::util;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS runs (
  run_id      TEXT PRIMARY KEY,
  started_at  TEXT NOT NULL,
  ended_at    TEXT,
  interface   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
  addr         TEXT PRIMARY KEY,
  hostname     TEXT,
  domain       TEXT,
  netbios_name TEXT,
  llmnr_name   TEXT,
  mdns_name    TEXT,
  first_seen   TEXT NOT NULL,
  last_seen    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  session_id     TEXT PRIMARY KEY,
  run_id         TEXT NOT NULL REFERENCES runs(run_id),
  service        TEXT,
  client_addr    TEXT,
  started_at     TEXT NOT NULL,
  ended_at       TEXT,
  artifact_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS captures (
  id            TEXT PRIMARY KEY,
  run_id        TEXT NOT NULL,
  session_id    TEXT,
  protocol      TEXT NOT NULL,
  artifact_type TEXT NOT NULL,
  client_addr   TEXT NOT NULL,
  timestamp     TEXT NOT NULL,
  username      TEXT,
  domain        TEXT,
  challenge     BLOB,
  response      BLOB,
  blob          BLOB,
  secret        TEXT,
  raw           BLOB,
  formatted     TEXT NOT NULL,
  dedup_hash    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_captures_protocol ON captures(protocol);
CREATE INDEX IF NOT EXISTS idx_captures_type ON captures(artifact_type);
CREATE INDEX IF NOT EXISTS idx_captures_client ON captures(client_addr);
CREATE UNIQUE INDEX IF NOT EXISTS idx_captures_dedup ON captures(dedup_hash);

CREATE TABLE IF NOT EXISTS poisoned_queries (
  id                    TEXT PRIMARY KEY,
  run_id                TEXT NOT NULL,
  protocol              TEXT NOT NULL,
  queried_name          TEXT NOT NULL,
  client_addr           TEXT NOT NULL,
  timestamp             TEXT NOT NULL,
  answered              INTEGER NOT NULL,
  answer_addr           TEXT,
  record_type           TEXT,
  domain_filter_matched INTEGER,
  mode                  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_queries_client ON poisoned_queries(client_addr);
"#;

/// A unique id derived from the current time plus a random suffix (no external uuid dep).
pub fn new_id() -> String {
    let now = Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let rand = rand::random::<u64>();
    util::md5_hex(format!("{now}-{rand}").as_bytes())
}

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    /// Open (creating if needed) the capture database.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path.as_ref())
            .with_context(|| format!("opening sqlite db {}", path.as_ref().display()))?;
        conn.execute_batch(SCHEMA).context("creating schema")?;
        Ok(Store {
            conn: Mutex::new(conn),
        })
    }

    /// Open an in-memory database (used by tests).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Store {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("store mutex poisoned")
    }

    /// Insert a new run row and return its id.
    pub fn start_run(&self, interface: &str, _analyze: bool) -> Result<String> {
        let id = new_id();
        self.lock().execute(
            "INSERT INTO runs (run_id, started_at, interface) VALUES (?1, ?2, ?3)",
            params![id, Utc::now().to_rfc3339(), interface],
        )?;
        Ok(id)
    }

    /// Finalize a run row.
    pub fn finish_run(&self, run_id: &str) -> Result<()> {
        self.lock().execute(
            "UPDATE runs SET ended_at = ?1 WHERE run_id = ?2",
            params![Utc::now().to_rfc3339(), run_id],
        )?;
        Ok(())
    }

    /// Upsert a client host row.
    pub fn upsert_host(&self, addr: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        self.lock().execute(
            "INSERT INTO hosts (addr, first_seen, last_seen) VALUES (?1, ?2, ?2)
             ON CONFLICT(addr) DO UPDATE SET last_seen = ?2",
            params![addr, now],
        )?;
        Ok(())
    }

    /// Persist a capture; identical `dedup_hash` rows are ignored. Returns true when a new row
    /// was written.
    pub fn insert_capture(&self, run_id: &str, art: &CaptureArtifact) -> Result<bool> {
        let client = art.client.to_string();
        self.upsert_host(&client)?;
        let challenge = art.challenge.as_ref().and_then(|h| util::unhex(h));
        let response = art.response.as_ref().and_then(|h| util::unhex(h));
        let blob = art.blob.as_ref().and_then(|h| util::unhex(h));
        let n = self.lock().execute(
            "INSERT OR IGNORE INTO captures
                (id, run_id, session_id, protocol, artifact_type, client_addr, timestamp,
                 username, domain, challenge, response, blob, secret, raw, formatted, dedup_hash)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
            params![
                new_id(),
                run_id,
                Option::<String>::None,
                art.protocol.as_str(),
                art.artifact_type.file_suffix(),
                client,
                art.timestamp.to_rfc3339(),
                art.username,
                art.domain,
                challenge,
                response,
                blob,
                art.secret,
                art.raw,
                art.formatted,
                art.dedup_hash,
            ],
        )?;
        Ok(n > 0)
    }

    /// Persist a poisoned query observation.
    pub fn insert_query(
        &self,
        run_id: &str,
        q: &PoisonedQuery,
        answer_addr: Option<&str>,
    ) -> Result<()> {
        self.lock().execute(
            "INSERT INTO poisoned_queries
                (id, run_id, protocol, queried_name, client_addr, timestamp, answered,
                 answer_addr, record_type, domain_filter_matched, mode)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                new_id(),
                run_id,
                q.protocol.as_str(),
                q.name,
                q.client.to_string(),
                q.timestamp.to_rfc3339(),
                q.answered as i64,
                answer_addr,
                q.record_type,
                Option::<i64>::None,
                if q.analysis_only { "analyze" } else { "poison" },
            ],
        )?;
        Ok(())
    }

    pub fn count_captures(&self) -> Result<i64> {
        let conn = self.lock();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM captures", [], |r| r.get(0))?;
        Ok(n)
    }

    /// List captures optionally filtered by protocol and/or client.
    pub fn list_captures(
        &self,
        protocol: Option<&str>,
        client: Option<&str>,
    ) -> Result<Vec<CaptureArtifact>> {
        let conn = self.lock();
        let mut sql = String::from(
            "SELECT protocol, artifact_type, client_addr, timestamp, username, domain,
                    hex(challenge), hex(response), hex(blob), secret, formatted, dedup_hash
             FROM captures WHERE 1=1",
        );
        if protocol.is_some() {
            sql.push_str(" AND protocol = ?1");
        }
        if client.is_some() {
            if protocol.is_some() {
                sql.push_str(" AND client_addr = ?2");
            } else {
                sql.push_str(" AND client_addr = ?1");
            }
        }
        sql.push_str(" ORDER BY rowid");

        let mut stmt = conn.prepare(&sql)?;
        let map = |row: &rusqlite::Row<'_>| -> rusqlite::Result<CaptureArtifact> {
            let protocol: String = row.get(0)?;
            let art_type: String = row.get(1)?;
            let client: String = row.get(2)?;
            let ts: String = row.get(3)?;
            Ok(CaptureArtifact {
                protocol: protocol_from_str(&protocol),
                artifact_type: artifact_from_str(&art_type),
                client: client
                    .parse()
                    .unwrap_or(std::net::IpAddr::V4([0, 0, 0, 0].into())),
                timestamp: chrono::DateTime::parse_from_rfc3339(&ts)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                username: row.get(4)?,
                domain: row.get(5)?,
                challenge: row.get(6)?,
                response: row.get(7)?,
                blob: row.get(8)?,
                secret: row.get(9)?,
                raw: None,
                formatted: row.get(10)?,
                dedup_hash: row.get(11)?,
            })
        };

        let rows = match (protocol, client) {
            (Some(p), Some(c)) => stmt
                .query_map(params![p, c], map)?
                .collect::<Result<Vec<_>, _>>()?,
            (Some(p), None) => stmt
                .query_map(params![p], map)?
                .collect::<Result<Vec<_>, _>>()?,
            (None, Some(c)) => stmt
                .query_map(params![c], map)?
                .collect::<Result<Vec<_>, _>>()?,
            (None, None) => stmt.query_map([], map)?.collect::<Result<Vec<_>, _>>()?,
        };
        Ok(rows)
    }

    /// Export every captured `formatted` line, one per line (DumpHash equivalent).
    pub fn dump_hashes(&self) -> Result<Vec<String>> {
        let list = self.list_captures(None, None)?;
        Ok(list.into_iter().map(|a| a.formatted).collect())
    }
}

fn protocol_from_str(s: &str) -> crate::capture::model::Protocol {
    use crate::capture::model::Protocol::*;
    match s {
        "LLMNR" => Llmnr,
        "NBT-NS" => NbtNs,
        "MDNS" => Mdns,
        "SMB" => Smb,
        "HTTP" => Http,
        "HTTPS" => Https,
        "WPAD" => Wpad,
        "FTP" => Ftp,
        "POP" => Pop3,
        "SMTP" => Smtp,
        "IMAP" => Imap,
        "IMAPS" => Imaps,
        "MSSQL" => Mssql,
        "LDAP" => Ldap,
        "LDAPS" => Ldaps,
        "Kerberos" => Kerberos,
        "DNS" => Dns,
        "RDP" => Rdp,
        "WinRM" => Winrm,
        "WinRMS" => Winrms,
        "DCERPC" => Dcerpc,
        _ => Dns,
    }
}

fn artifact_from_str(s: &str) -> crate::capture::model::ArtifactType {
    use crate::capture::model::ArtifactType::*;
    match s {
        "NTLMv1" => NetNtlmV1,
        "NTLMv2" => NetNtlmV2,
        "Cleartext" => Cleartext,
        "CRAM-MD5" => CramMd5,
        "DIGEST-MD5" => DigestMd5,
        "APOP" => Apop,
        "ASREP" => AsRep,
        _ => Digest,
    }
}
