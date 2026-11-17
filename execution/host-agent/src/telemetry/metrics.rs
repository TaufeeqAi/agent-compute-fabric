//! Process-local counters/gauges (spec §23.5). Deliberately tiny: a labelled counter map that can
//! be rendered as JSON for `host.metrics`. No exporter dependency in Phase 1.

use std::{collections::BTreeMap, sync::Mutex};

#[derive(Debug, Default)]
pub struct Metrics {
    counters: Mutex<BTreeMap<String, u64>>,
    gauges: Mutex<BTreeMap<String, i64>>,
}

impl Metrics {
    pub fn incr(&self, name: &str, by: u64) {
        if let Ok(mut c) = self.counters.lock() {
            *c.entry(name.to_owned()).or_insert(0) += by;
        }
    }

    /// `name{label="value"}` — flat string keys keep this dependency-free.
    pub fn incr_labelled(&self, name: &str, label: &str, value: &str, by: u64) {
        self.incr(&format!("{name}{{{label}=\"{value}\"}}"), by);
    }

    pub fn set_gauge(&self, name: &str, v: i64) {
        if let Ok(mut g) = self.gauges.lock() {
            g.insert(name.to_owned(), v);
        }
    }

    pub fn get(&self, name: &str) -> u64 {
        self.counters.lock().ok().and_then(|c| c.get(name).copied()).unwrap_or(0)
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
        m.incr_labelled("ops", "status", "SUCCEEDED", 1);
        m.incr_labelled("ops", "status", "FAILED", 4);
        m.set_gauge("live", 7);
        assert_eq!(m.get("a"), 5);
        assert_eq!(m.get("ops{status=\"FAILED\"}"), 4);
        assert_eq!(m.snapshot()["gauges"]["live"], 7);
    }
}
