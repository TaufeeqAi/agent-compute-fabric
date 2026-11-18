//! Structured events (contract §24): diagnostic telemetry. May be lost; never an authority (OB-4).
//!
//! * OB-5 — every event carries a strictly increasing sequence number within its activation. An
//!   event that describes a committed change also carries that change's commit sequence. A consumer
//!   detects loss from a gap and resynchronises by listing; the host counts the events it dropped.
//! * OB-6 — a telemetry failure changes no operation outcome: `emit` returns nothing and cannot fail.
//! * OB-7 — no secret material, credential, signed decision, execution output or privileged host
//!   path is ever placed in an event. Failures are described by class and side-effect marker, not by
//!   their message.

use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::metrics::Metrics;
use crate::store::OperationRecord;

pub const EVENT_SCHEMA_VERSION: u32 = 2;

/// Who is emitting: constant for one activation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventIdentity {
    pub host_id: String,
    pub lineage: String,
    pub activation_epoch: u64,
}

/// The event envelope (`execution/contracts/event-schema.json`). Field set: §24.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Event {
    pub schema_version: u32,
    pub host_id: String,
    /// Store lineage: qualifies `commit_seq`.
    pub lineage: String,
    pub activation_epoch: u64,
    /// Strictly increasing within the activation. A gap means events were lost.
    pub seq: u64,
    /// Commit sequence of the committed change this event describes, if it describes one.
    pub commit_seq: Option<u64>,
    /// Wall-clock timestamp (a label, never an ordering).
    pub timestamp: String,
    pub kind: String,
    pub request_id: Option<String>,
    pub operation_id: Option<String>,
    pub sandbox_id: Option<String>,
    pub generation: Option<u64>,
    pub peer_id: Option<String>,
    pub owner_scope: Option<String>,
    pub operation_type: Option<String>,
    pub step: Option<String>,
    pub outcome: Option<String>,
    pub failure_class: Option<String>,
    pub side_effect: Option<String>,
    pub attempt: Option<u32>,
    pub latency_ms: Option<u64>,
    /// Small structured detail. Never output, secrets or host paths (OB-7).
    pub detail: serde_json::Value,
}

/// An event before the sink stamps identity and sequence on it.
#[derive(Debug, Clone)]
pub struct EventDraft {
    event: Event,
}

fn enum_label<T: Serialize>(v: &T) -> Option<String> {
    serde_json::to_value(v).ok().and_then(|v| v.as_str().map(str::to_owned))
}

impl EventDraft {
    pub fn new(timestamp: &str, kind: &str) -> Self {
        Self {
            event: Event {
                schema_version: EVENT_SCHEMA_VERSION,
                host_id: String::new(),
                lineage: String::new(),
                activation_epoch: 0,
                seq: 0,
                commit_seq: None,
                timestamp: timestamp.to_owned(),
                kind: kind.to_owned(),
                request_id: None,
                operation_id: None,
                sandbox_id: None,
                generation: None,
                peer_id: None,
                owner_scope: None,
                operation_type: None,
                step: None,
                outcome: None,
                failure_class: None,
                side_effect: None,
                attempt: None,
                latency_ms: None,
                detail: serde_json::Value::Null,
            },
        }
    }

    /// Fill every field an operation record determines. `commit_seq` is the record's revision.
    #[must_use]
    pub fn operation(mut self, op: &OperationRecord) -> Self {
        let e = &mut self.event;
        e.operation_id = Some(op.operation_id.to_string());
        e.operation_type = Some(op.operation_type.name().to_owned());
        e.peer_id = Some(op.tags.peer_id.to_string());
        e.owner_scope = Some(op.tags.owner_scope.to_string());
        e.step = op.step.clone();
        e.outcome = enum_label(&op.state);
        if let Some((sbx, generation)) = &op.sandbox {
            e.sandbox_id = Some(sbx.to_string());
            e.generation = Some(generation.0);
        }
        if let Some(f) = &op.failure {
            e.failure_class = enum_label(&f.class);
            e.side_effect = enum_label(&f.side_effect);
        }
        if op.revision > 0 {
            e.commit_seq = Some(op.revision);
        }
        self
    }

    #[must_use]
    pub fn sandbox(mut self, sandbox_id: &str, generation: Option<u64>) -> Self {
        self.event.sandbox_id = Some(sandbox_id.to_owned());
        self.event.generation = generation;
        self
    }

    #[must_use]
    pub fn commit_seq(mut self, seq: u64) -> Self {
        self.event.commit_seq = Some(seq);
        self
    }

    #[must_use]
    pub fn attempt(mut self, attempt: u32) -> Self {
        self.event.attempt = Some(attempt);
        self
    }

    #[must_use]
    pub fn latency_ms(mut self, ms: u64) -> Self {
        self.event.latency_ms = Some(ms);
        self
    }

    #[must_use]
    pub fn detail(mut self, detail: serde_json::Value) -> Self {
        self.event.detail = detail;
        self
    }
}

#[derive(Debug)]
pub struct EventSink {
    identity: Mutex<EventIdentity>,
    seq: AtomicU64,
    file: Mutex<Option<File>>,
    /// Always kept (bounded) so tests and diagnostics can read recent history.
    recent: Mutex<std::collections::VecDeque<Event>>,
    metrics: Arc<Metrics>,
}

const RECENT_CAP: usize = 512;

impl EventSink {
    pub fn open(dir: &Path, metrics: Arc<Metrics>) -> Self {
        let file = std::fs::create_dir_all(dir)
            .and_then(|()| OpenOptions::new().create(true).append(true).mode(0o600).open(dir.join("events.jsonl")))
            .ok();
        Self { identity: Mutex::default(), seq: AtomicU64::new(0), file: Mutex::new(file), recent: Mutex::default(), metrics }
    }

    pub fn memory(metrics: Arc<Metrics>) -> Self {
        Self { identity: Mutex::default(), seq: AtomicU64::new(0), file: Mutex::new(None), recent: Mutex::default(), metrics }
    }

    /// Set once the store is open and the activation has its epoch.
    pub fn set_identity(&self, identity: EventIdentity) {
        if let Ok(mut i) = self.identity.lock() {
            *i = identity;
        }
    }

    pub fn emit(&self, draft: EventDraft) {
        let mut ev = draft.event;
        if let Ok(i) = self.identity.lock() {
            ev.host_id.clone_from(&i.host_id);
            ev.lineage.clone_from(&i.lineage);
            ev.activation_epoch = i.activation_epoch;
        }
        // The sequence is consumed whether or not the write succeeds: that is what makes a lost
        // event visible as a gap.
        ev.seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        if let Ok(mut f) = self.file.lock()
            && let Some(file) = f.as_mut()
        {
            let ok = serde_json::to_vec(&ev).is_ok_and(|mut line| {
                line.push(b'\n');
                file.write_all(&line).is_ok()
            });
            if !ok {
                // Diagnostic only: count it, never propagate it (OB-6).
                self.metrics.incr("events_dropped", 1);
            }
        }
        if let Ok(mut r) = self.recent.lock() {
            if r.len() >= RECENT_CAP {
                r.pop_front();
            }
            r.push_back(ev);
        }
    }

    /// An event with no operation behind it.
    pub fn emit_simple(&self, timestamp: &str, kind: &str, detail: serde_json::Value) {
        self.emit(EventDraft::new(timestamp, kind).detail(detail));
    }

    pub fn recent(&self) -> Vec<Event> {
        self.recent.lock().map(|r| r.iter().cloned().collect()).unwrap_or_default()
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn break_file_for_test(&self) {
        if let Ok(mut f) = self.file.lock() {
            *f = File::open("/dev/null").ok();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sink() -> (EventSink, Arc<Metrics>) {
        let m = Arc::new(Metrics::default());
        let s = EventSink::memory(Arc::clone(&m));
        s.set_identity(EventIdentity { host_id: "h1".into(), lineage: "lin".into(), activation_epoch: 4 });
        (s, m)
    }

    #[test]
    fn sequence_is_strictly_increasing_within_the_activation_and_history_is_bounded() {
        let (s, _) = sink();
        for i in 0..(RECENT_CAP + 10) {
            s.emit_simple("t", "k", serde_json::json!({ "i": i }));
        }
        let r = s.recent();
        assert_eq!(r.len(), RECENT_CAP);
        assert!(r.windows(2).all(|w| w[1].seq == w[0].seq + 1));
        assert_eq!(r.last().map(|e| e.seq), Some((RECENT_CAP + 10) as u64));
        assert!(
            r.iter()
                .all(|e| e.host_id == "h1" && e.lineage == "lin" && e.activation_epoch == 4 && e.schema_version == EVENT_SCHEMA_VERSION)
        );
    }

    #[test]
    fn a_dropped_event_is_counted_leaves_a_gap_in_the_log_and_fails_nobody() {
        let d = tempfile::tempdir().unwrap();
        let m = Arc::new(Metrics::default());
        let s = EventSink::open(d.path(), Arc::clone(&m));
        s.emit_simple("t", "first", serde_json::json!({}));
        let good = s.file.lock().unwrap().take();
        s.break_file_for_test(); // every write now fails
        s.emit_simple("t", "lost", serde_json::json!({}));
        *s.file.lock().unwrap() = good;
        s.emit_simple("t", "third", serde_json::json!({}));
        assert_eq!(m.get("events_dropped"), 1, "the loss is counted");
        let text = std::fs::read_to_string(d.path().join("events.jsonl")).unwrap();
        let seqs: Vec<u64> = text.lines().map(|l| serde_json::from_str::<Event>(l).unwrap().seq).collect();
        assert_eq!(seqs, vec![1, 3], "the consumer sees the gap");
        assert_eq!(s.recent().len(), 3, "and the in-memory history still works");
    }

    #[test]
    fn an_operation_event_carries_the_required_fields_and_no_failure_message() {
        let (s, _) = sink();
        let mut op = crate::store::journal::tests::op("op-aaaaaaaa", true);
        op.revision = 17;
        op.step = Some("launch".into());
        op.state = crate::domain::OperationState::Failed;
        op.failure = Some(crate::domain::FailureInfo::new(
            crate::error::FailureClass::DependencyUnavailable,
            "cannot open /var/lib/acf/secret-path",
            crate::error::SideEffect::Possible,
        ));
        s.emit(EventDraft::new("t", "operation.finished").operation(&op).attempt(2).latency_ms(40));
        let e = s.recent().pop().unwrap();
        assert_eq!(e.commit_seq, Some(17), "an event about a committed change names the commit");
        assert_eq!((e.operation_type.as_deref(), e.outcome.as_deref()), (Some("sandbox.create"), Some("FAILED")));
        assert_eq!((e.failure_class.as_deref(), e.side_effect.as_deref()), (Some("DEPENDENCY_UNAVAILABLE"), Some("POSSIBLE")));
        assert_eq!(
            (e.peer_id.as_deref(), e.owner_scope.as_deref(), e.attempt, e.latency_ms),
            (Some("peer-1"), Some("scope-a"), Some(2), Some(40))
        );
        let text = serde_json::to_string(&e).unwrap();
        assert!(!text.contains("secret-path"), "failure messages (and the paths in them) stay out of telemetry (OB-7)");
    }

    #[test]
    fn events_are_appended_as_json_lines_with_the_schema_field_set() {
        let d = tempfile::tempdir().unwrap();
        let s = EventSink::open(d.path(), Arc::new(Metrics::default()));
        s.emit(EventDraft::new("t", "sandbox.destroyed").sandbox("sbx-1", Some(2)).commit_seq(9));
        let text = std::fs::read_to_string(d.path().join("events.jsonl")).unwrap();
        let v: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        // §24.2, transcribed.
        for field in [
            "host_id",
            "lineage",
            "request_id",
            "operation_id",
            "sandbox_id",
            "generation",
            "peer_id",
            "owner_scope",
            "operation_type",
            "step",
            "outcome",
            "failure_class",
            "side_effect",
            "attempt",
            "commit_seq",
            "schema_version",
            "timestamp",
            "latency_ms",
        ] {
            assert!(v.get(field).is_some(), "event is missing `{field}`");
        }
        assert_eq!((v["kind"].as_str(), v["seq"].as_u64(), v["commit_seq"].as_u64()), (Some("sandbox.destroyed"), Some(1), Some(9)));
    }
}
