//! Capture logging: per-protocol artifact files, an optional session log and console output.
//!
//! File naming follows `contracts/output-artifacts.md`:
//! `<PROTOCOL>-<ARTIFACT>-<client-ip>.txt`, opened in append mode so repeated runs accumulate.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::capture::model::{CaptureArtifact, PoisonedQuery};

pub struct Logger {
    dir: PathBuf,
    console: bool,
    verbose: bool,
    quiet: bool,
    session: Mutex<Option<File>>,
}

impl Logger {
    /// Create a logger rooted at `dir`. When `session_log` is true a `Responder-Session.log`
    /// is opened for appending.
    pub fn new(
        dir: impl AsRef<Path>,
        session_log: bool,
        verbose: bool,
        quiet: bool,
    ) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        let session = if session_log {
            let path = dir.as_ref().join("Responder-Session.log");
            Some(OpenOptions::new().create(true).append(true).open(path)?)
        } else {
            None
        };
        Ok(Logger {
            dir: dir.as_ref().to_path_buf(),
            console: !quiet,
            verbose,
            quiet,
            session: Mutex::new(session),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Informational console line.
    pub fn info(&self, msg: &str) {
        if self.console {
            println!("[+] {msg}");
        }
    }

    /// Warning/error console line (still shown unless fully quiet).
    pub fn warn(&self, msg: &str) {
        if !self.quiet {
            eprintln!("[!] {msg}");
        }
    }

    /// Verbose-only console line.
    pub fn trace(&self, msg: &str) {
        if self.verbose && self.console {
            println!("[*] {msg}");
        }
    }

    fn session_write(&self, line: &str) {
        if let Ok(mut guard) = self.session.lock()
            && let Some(f) = guard.as_mut()
        {
            let _ = writeln!(f, "{line}");
        }
    }

    /// Persist a captured artifact to its per-protocol file and the session log.
    pub fn captured(&self, art: &CaptureArtifact) -> std::io::Result<()> {
        let fname = format!(
            "{}-{}-{}.txt",
            art.protocol.as_str(),
            art.artifact_type.file_suffix(),
            art.client
        );
        let path = self.dir.join(fname);
        let mut f = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(f, "{}", art.formatted)?;

        self.session_write(&format!(
            "[{}] {} {} captured from {}: {}",
            art.timestamp.to_rfc3339(),
            art.protocol.as_str(),
            art.artifact_type.file_suffix(),
            art.client,
            art.formatted
        ));
        if self.console {
            println!(
                "[+] {} {} captured from {}: {}",
                art.protocol.as_str(),
                art.artifact_type.file_suffix(),
                art.client,
                art.formatted
            );
        }
        Ok(())
    }

    /// Record a poisoned (or observed) query.
    pub fn poisoned(&self, q: &PoisonedQuery) {
        if self.quiet && !self.verbose {
            return;
        }
        let line = format!(
            "[{}] {} query from {}: {} {} answered={}",
            q.timestamp.to_rfc3339(),
            q.protocol.as_str(),
            q.client,
            q.name,
            q.record_type,
            q.answered
        );
        self.session_write(&line);
        if self.verbose && self.console {
            println!("[*] {line}");
        }
    }
}
