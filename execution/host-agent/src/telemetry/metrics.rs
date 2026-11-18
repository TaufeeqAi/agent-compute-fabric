//! Process-local counters and gauges (contract §24.3), rendered as JSON by `host.metrics`.
//!
//! OB-8: a metric label never contains a sandbox, operation or snapshot id, or any caller-supplied
//! string. Labels here are closed vocabularies (states, classes, operation types), and the registry
//! enforces it: a label value outside a small character set is recorded as `invalid`, and the number
//! of series is bounded, so no input can make the registry grow without limit.

use std::{collections::BTreeMap, sync::Mutex};

/// Most distinct series the registry holds. Beyond it, new series are counted and not created.
pub const MAX_SERIES: usize = 512;
const MAX_LABEL_BYTES: usize = 48;

#[derive(Debug, Default)]
pub struct Metrics {
    counters: Mutex<BTreeMap<String, u64>>,
    gauges: Mutex<BTreeMap<String, i64>>,
}

/// A label value is a word from a closed vocabulary: letters, digits, `_` and `.` only. Ids contain
/// `-`, and caller strings may contain anything, so neither can pass.
fn label_value(v: &str) -> &str {
    let ok = (1..=MAX_LABEL_BYTES).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.');
    if ok { v } else { "invalid" }
}

impl Metrics {
    pub fn incr(&self, name: &str, by: u64) {
        if let Ok(mut c) = self.counters.lock() {
            if !c.contains_key(name) && c.len() >= MAX_SERIES {
                *c.entry("metrics_series_dropped".to_owned()).or_insert(0) += 1;
                return;
            }
            *c.entry(name.to_owned()).or_insert(0) += by;
        }
    }

    /// `name{label="value"}` — flat string keys keep this dependency-free.
    pub fn incr_labelled(&self, name: &str, label: &str, value: &str, by: u64) {
        self.incr(&format!("{name}{{{label}=\"{}\"}}", label_value(value)), by);
    }

    pub fn set_gauge(&self, name: &str, v: i64) {
        if let Ok(mut g) = self.gauges.lock()
            && (g.contains_key(name) || g.len() < MAX_SERIES)
        {
            g.insert(name.to_owned(), v);
        }
    }

    pub fn get(&self, name: &str) -> u64 {
        self.counters.lock().ok().and_then(|c| c.get(name).copied()).unwrap_or(0)
    }

    pub fn gauge(&self, name: &str) -> Option<i64> {
        self.gauges.lock().ok().and_then(|g| g.get(name).copied())
    }

    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "counters": self.counters.lock().map(|c| c.clone()).unwrap_or_default(),
            "gauges": self.gauges.lock().map(|g| g.clone()).unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate_and_labels_are_distinct_series() {
        let m = Metrics::default();
        m.incr("a", 2);
        m.incr("a", 3);
        m.incr_labelled("ops", "state", "SUCCEEDED", 1);
        m.incr_labelled("ops", "state", "FAILED", 4);
        m.incr_labelled("ops", "type", "sandbox.create", 1);
        m.set_gauge("live", 7);
        assert_eq!(m.get("a"), 5);
        assert_eq!(m.get("ops{state=\"FAILED\"}"), 4);
        assert_eq!(m.get("ops{type=\"sandbox.create\"}"), 1);
        assert_eq!(m.snapshot()["gauges"]["live"], 7);
    }

    #[test]
    fn ids_and_caller_strings_can_never_become_label_values() {
        let m = Metrics::default();
        for hostile in
            ["sbx-00000000000000000000000000000001", "op-12345678", "team a", "x\"} evil{y=\"z", "", &"l".repeat(MAX_LABEL_BYTES + 1)]
        {
            m.incr_labelled("ops", "state", hostile, 1);
        }
        assert_eq!(m.get("ops{state=\"invalid\"}"), 6, "every one of them collapsed into a single series");
        assert_eq!(m.snapshot()["counters"].as_object().unwrap().len(), 1);
    }

    #[test]
    fn the_number_of_series_is_bounded() {
        let m = Metrics::default();
        for i in 0..(MAX_SERIES + 50) {
            m.incr(&format!("series_{i}"), 1);
            m.set_gauge(&format!("gauge_{i}"), 1);
        }
        let snap = m.snapshot();
        assert!(snap["counters"].as_object().unwrap().len() <= MAX_SERIES + 1);
        assert_eq!(snap["gauges"].as_object().unwrap().len(), MAX_SERIES);
        assert!(m.get("metrics_series_dropped") >= 49);
    }
}
