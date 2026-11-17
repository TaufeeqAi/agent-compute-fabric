//! Canonical request fingerprint (spec §12.2, DELTA-003).
//!
//! **Included**: the operation type and the *semantic* request body (what would be done, to what).
//! **Excluded** (volatile / transport): `operation_id`, `retry`, client deadlines and timestamps —
//! they are stripped by the caller before this function sees the body.
//! **Normalisation**: object keys sorted by byte order; no insignificant whitespace; members whose
//! value is `null` are dropped (so `{"name":null}` fingerprints like `{}`); arrays keep order;
//! non-integer numbers are rejected (floats have no canonical form); strings are hashed as the
//! exact UTF-8 bytes.
//! **Hash**: SHA-256 over `"acf-fp/1\0" || op_type || "\0" || canonical_json`.

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    domain::{OperationType, RequestFingerprint},
    error::{AcfError, Result},
};

pub const FINGERPRINT_SCHEMA_VERSION: u32 = 1;
const DOMAIN_TAG: &str = "acf-fp/1";

fn canonical(v: &Value, out: &mut String) -> Result<()> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if n.is_f64() {
                return Err(AcfError::validation("floating-point numbers are not allowed in operation requests"));
            }
            out.push_str(&n.to_string());
        }
        Value::String(s) => out.push_str(&serde_json::to_string(s)?),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(x, out)?;
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.iter().filter(|(_, v)| !v.is_null()).map(|(k, _)| k).collect();
            keys.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k)?);
                out.push(':');
                if let Some(val) = m.get(*k) {
                    canonical(val, out)?;
                }
            }
            out.push('}');
        }
    }
    Ok(())
}

pub fn fingerprint(op: OperationType, body: &Value) -> Result<RequestFingerprint> {
    let mut canon = String::new();
    canonical(body, &mut canon)?;
    let op_name = serde_json::to_value(op)?.as_str().unwrap_or_default().to_owned();
    let mut h = Sha256::new();
    h.update(DOMAIN_TAG.as_bytes());
    h.update([0]);
    h.update(op_name.as_bytes());
    h.update([0]);
    h.update(canon.as_bytes());
    Ok(RequestFingerprint { schema_version: FINGERPRINT_SCHEMA_VERSION, algorithm: "sha256".to_owned(), digest: hex::encode(h.finalize()) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn fp(op: OperationType, v: Value) -> String {
        fingerprint(op, &v).unwrap().digest
    }

    #[test]
    fn key_order_and_whitespace_do_not_matter() {
        let a: Value = serde_json::from_str(r#"{"b":1,"a":{"y":2,"x":[3,1]}}"#).unwrap();
        let b: Value = serde_json::from_str("{ \"a\" : { \"x\" : [3, 1], \"y\": 2 }, \"b\": 1 }").unwrap();
        assert_eq!(fp(OperationType::Exec, a), fp(OperationType::Exec, b));
    }

    #[test]
    fn null_members_are_equivalent_to_absent_ones() {
        assert_eq!(fp(OperationType::SandboxCreate, json!({"name": null, "cpu": 2})), fp(OperationType::SandboxCreate, json!({"cpu": 2})));
    }

    #[test]
    fn semantic_differences_change_the_fingerprint() {
        let base = fp(OperationType::Exec, json!({"argv": ["a", "b"]}));
        assert_ne!(base, fp(OperationType::Exec, json!({"argv": ["b", "a"]})), "array order is significant");
        assert_ne!(base, fp(OperationType::Exec, json!({"argv": ["a", "b "]})), "string bytes are significant");
        assert_ne!(base, fp(OperationType::SandboxDestroy, json!({"argv": ["a", "b"]})), "operation type is bound in");
    }

    #[test]
    fn floats_are_rejected_not_silently_normalised() {
        assert!(fingerprint(OperationType::Exec, &json!({"x": 1.5})).is_err());
    }

    #[test]
    fn digest_is_stable_across_releases() {
        // Golden value computed by an INDEPENDENT implementation (Python `json.dumps(sort_keys=True,
        // separators=(",", ":"))` + hashlib) — see docs/CONTRACT_COMPLIANCE.md. Changing the
        // canonical form is a *breaking* contract change (bump the schema version), so this test
        // must fail loudly if it ever drifts.
        assert_eq!(
            fp(OperationType::SandboxDestroy, json!({"sandbox_id": "sbx-00000000000000000000000000000000", "generation": 1})),
            "1c74278e5341f6853d57d902265c533b98a728b1c4eaa0e8b8405ef34261b66e"
        );
    }

    proptest! {
        #[test]
        fn permuting_object_keys_never_changes_the_digest(keys in proptest::collection::btree_set("[a-z]{1,6}", 1..8), seed in any::<u64>()) {
            let keys: Vec<String> = keys.into_iter().collect();
            let mut shuffled = keys.clone();
            shuffled.rotate_left((seed % keys.len() as u64) as usize);
            let build = |ks: &[String]| {
                let mut m = serde_json::Map::new();
                for (i, k) in ks.iter().enumerate() { m.insert(k.clone(), json!(i as u64)); }
                Value::Object(m)
            };
            // values must follow keys, so build from (key -> index in the sorted list)
            let by_sorted = |ks: &[String]| {
                let mut m = serde_json::Map::new();
                for k in ks { m.insert(k.clone(), json!(keys.iter().position(|x| x == k).unwrap() as u64)); }
                Value::Object(m)
            };
            let _ = build;
            prop_assert_eq!(fp(OperationType::Exec, by_sorted(&keys)), fp(OperationType::Exec, by_sorted(&shuffled)));
        }
    }
}
