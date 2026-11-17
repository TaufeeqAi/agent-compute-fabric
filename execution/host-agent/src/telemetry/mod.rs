//! BND-11 — Telemetry and evidence plumbing (spec §23).
//!
//! Three classes, three failure behaviours:
//! * `REQUIRED_EXECUTION_EVIDENCE` (output, exit status) — failure to capture is surfaced on the
//!   result as `evidence_status != COMPLETE`; it never silently disappears.
//! * `SECURITY_EVIDENCE` (posture, network verdict) — failure to obtain it **fails closed** at the
//!   call site (see `FirecrackerBackend::launch_vmm`).
//! * `DIAGNOSTIC_TELEMETRY` (this module's event log and counters) — best effort. A full disk or a
//!   dead log file increments a counter and **never** changes lifecycle truth.

pub mod events;
pub mod metrics;

pub use events::{Event, EventSink};
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
