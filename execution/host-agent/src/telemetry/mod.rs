//! Observability (contract §24, boundary B16). It owns emission and correlation, and no decision.
//!
//! Three classes of information, three reliabilities (§24.1):
//!
//! * **Committed state** — durable and authoritative. It is *read* through the API (§10.6); nothing
//!   here is needed to learn it (OB-4).
//! * **Security evidence** (confinement posture, network verdict, restore oracle) — obtained, or the
//!   operation fails closed at the call site (PA-3). It never passes through this module.
//! * **Diagnostic telemetry** (this module's events and counters) — best effort. A full disk or a
//!   dead log file increments a counter and **never** changes an operation's outcome (OB-6).

pub mod events;
pub mod metrics;

pub use events::{Event, EventDraft, EventIdentity, EventSink};
pub use metrics::Metrics;

use std::{path::Path, sync::Arc};

/// Bundle handed to the coordinator.
#[derive(Debug, Clone)]
pub struct Telemetry {
    pub events: Arc<EventSink>,
    pub metrics: Arc<Metrics>,
}

impl Telemetry {
    pub fn open(dir: &Path) -> Self {
        let metrics = Arc::new(Metrics::default());
        Self { events: Arc::new(EventSink::open(dir, Arc::clone(&metrics))), metrics }
    }

    /// No file sink (tests).
    pub fn memory() -> Self {
        let metrics = Arc::new(Metrics::default());
        Self { events: Arc::new(EventSink::memory(Arc::clone(&metrics))), metrics }
    }
}
