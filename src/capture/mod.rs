//! Capture pipeline: servers/poisoners hand artifacts and query observations to a single
//! writer task through a bounded channel, guaranteeing non-interleaved files and DB writes.

pub mod model;

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::logger::Logger;
use crate::store::Store;

use self::model::{CaptureArtifact, PoisonedQuery};

/// Events handled by the capture writer.
#[derive(Debug)]
pub enum CaptureEvent {
    Artifact(Box<CaptureArtifact>),
    Query(Box<PoisonedQuery>),
}

/// Cheap, cloneable handle used by every rogue service to emit captures.
#[derive(Clone)]
pub struct CaptureSink {
    tx: mpsc::Sender<CaptureEvent>,
}

impl CaptureSink {
    pub fn new(tx: mpsc::Sender<CaptureEvent>) -> Self {
        CaptureSink { tx }
    }

    /// Emit an artifact without blocking (drops on a full channel rather than stalling a
    /// service handler).
    pub fn artifact(&self, art: CaptureArtifact) {
        let _ = self.tx.try_send(CaptureEvent::Artifact(Box::new(art)));
    }

    /// Emit a query observation without blocking.
    pub fn query(&self, q: PoisonedQuery) {
        let _ = self.tx.try_send(CaptureEvent::Query(Box::new(q)));
    }
}

/// Spawn the single writer task. Returns the sink and the task handle.
pub fn spawn_writer(
    logger: Arc<Logger>,
    store: Arc<Store>,
    run_id: String,
    buffer: usize,
) -> (CaptureSink, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel::<CaptureEvent>(buffer);
    let handle = tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            match ev {
                CaptureEvent::Artifact(art) => {
                    if let Err(e) = logger.captured(&art) {
                        logger.warn(&format!("failed to write capture log: {e}"));
                    }
                    if let Err(e) = store.insert_capture(&run_id, &art) {
                        logger.warn(&format!("failed to persist capture: {e}"));
                    }
                }
                CaptureEvent::Query(q) => {
                    logger.poisoned(&q);
                    if let Err(e) = store.insert_query(&run_id, &q, None) {
                        logger.warn(&format!("failed to persist query: {e}"));
                    }
                }
            }
        }
    });
    (CaptureSink::new(tx), handle)
}
