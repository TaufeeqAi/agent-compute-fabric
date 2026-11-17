//! Structured lifecycle events.
//!
//! Every event has a **host-wide monotonically increasing sequence number** (spec §23.6) and,
//! where applicable, an operation id, so a consumer can order events from one operation without
//! trusting wall-clock timestamps.

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

use serde::{Deserialize, Serialize};

use super::metrics::Metrics;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    pub at: String,
    pub kind: String,
    pub operation_id: Option<String>,
    pub resource: Option<String>,
    pub detail: serde_json::Value,
}

#[derive(Debug)]
pub struct EventSink {
    seq: AtomicU64,
    file: Mutex<Option<File>>,
    /// Always kept (bounded) so `host.events` and tests can read recent history.
    recent: Mutex<std::collections::VecDeque<Event>>,
    metrics: Arc<Metrics>,
}

const RECENT_CAP: usize = 512;

impl EventSink {
    pub fn open(dir: &Path, metrics: Arc<Metrics>) -> Self {
        let file = std::fs::create_dir_all(dir)
            .and_then(|()| OpenOptions::new().create(true).append(true).mode(0o600).open(dir.join("events.jsonl")))
            .ok();
        Self { seq: AtomicU64::new(0), file: Mutex::new(file), recent: Mutex::default(), metrics }
    }

    pub fn memory(metrics: Arc<Metrics>) -> Self {
        Self { seq: AtomicU64::new(0), file: Mutex::new(None), recent: Mutex::default(), metrics }
    }

    pub fn emit(&self, at: &str, kind: &str, operation_id: Option<&str>, resource: Option<&str>, detail: serde_json::Value) {
        let ev = Event {
            seq: self.seq.fetch_add(1, Ordering::SeqCst) + 1,
            at: at.to_owned(),
            kind: kind.to_owned(),
            operation_id: operation_id.map(str::to_owned),
            resource: resource.map(str::to_owned),
            detail,
        };
        if let Ok(mut f) = self.file.lock()
            && let Some(file) = f.as_mut()
        {
            let ok = serde_json::to_vec(&ev).is_ok_and(|mut line| {
                line.push(b'\n');
                file.write_all(&line).is_ok()
            });
            if !ok {
                // Diagnostic only: count it, never propagate it.
                self.metrics.incr("telemetry_write_failures", 1);
            }
        }
        if let Ok(mut r) = self.recent.lock() {
            if r.len() >= RECENT_CAP {
                r.pop_front();
            }
            r.push_back(ev);
        }
    }

    pub fn recent(&self) -> Vec<Event> {
        self.recent.lock().map(|r| r.iter().cloned().collect()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_is_strictly_increasing_and_history_is_bounded() {
        let m = Arc::new(Metrics::default());
        let s = EventSink::memory(Arc::clone(&m));
        for i in 0..(RECENT_CAP + 10) {
            s.emit("t", "k", Some("op-1"), None, serde_json::json!({ "i": i }));
        }
        let r = s.recent();
        assert_eq!(r.len(), RECENT_CAP);
        assert!(r.windows(2).all(|w| w[1].seq == w[0].seq + 1));
        assert_eq!(r.last().map(|e| e.seq), Some((RECENT_CAP + 10) as u64));
    }

    #[test]
    fn a_dead_log_file_degrades_telemetry_without_failing_the_caller() {
        let d = tempfile::tempdir().unwrap();
        let m = Arc::new(Metrics::default());
        let s = EventSink::open(d.path(), Arc::clone(&m));
        // Replace the sink's file with a read-only handle so every write fails.
        *s.file.lock().unwrap() = Some(File::open("/dev/null").unwrap());
        s.emit("t", "k", None, None, serde_json::json!({}));
        assert_eq!(m.get("telemetry_write_failures"), 1, "the failure is counted…");
        assert_eq!(s.recent().len(), 1, "…and the in-memory history still works");
    }

    #[test]
    fn events_are_appended_as_json_lines() {
        let d = tempfile::tempdir().unwrap();
        let s = EventSink::open(d.path(), Arc::new(Metrics::default()));
        s.emit("t", "sandbox.created", Some("op-1"), Some("sbx-1"), serde_json::json!({"a": 1}));
        let text = std::fs::read_to_string(d.path().join("events.jsonl")).unwrap();
        let ev: Event = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!((ev.kind.as_str(), ev.seq), ("sandbox.created", 1));
    }
}
