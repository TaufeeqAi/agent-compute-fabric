//! The request envelope (contract §10.2) and the checks that need nothing but the request itself.
//!
//! The envelope is decoded in two steps so that every part of it is strict: the envelope struct
//! denies unknown fields, and `method` + `params` are then decoded into a typed [`Command`] whose
//! parameter structs deny unknown fields too. An unknown field, an unknown method or a value outside
//! its bound is refused with `INVALID_REQUEST` before anything is recorded (API-3).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::command::Command;
use crate::{
    clock::parse_rfc3339_utc_ms,
    domain::{MAX_ON_BEHALF_OF_BYTES, MAX_REQUEST_ID_BYTES, Method, OwnerScope, validate_label},
    error::{AcfError, Result},
    ids::OperationId,
};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    /// Protocol identifier with a major version, e.g. `acf.host/2`.
    pub protocol: String,
    /// Caller correlation; echoed; never an identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Caller-generated idempotency identity. Required for every granting, containment and
    /// operator method (INV-005).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
    /// "I already submitted this operation." If the host has no record the answer is `NOT_FOUND`;
    /// the request is never treated as new.
    #[serde(default)]
    pub retry: bool,
    /// When the caller first issued the request: `YYYY-MM-DDTHH:MM:SS[.fff]Z`. Required wherever
    /// `operation_id` is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
    /// Opaque owner scope (AU-7). Stored and compared for equality; never interpreted.
    pub owner_scope: OwnerScope,
    /// Opaque label; recorded and never compared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
    /// Reserved for a signed decision (AU-11). A host that does not advertise `signed_decision`
    /// refuses any request that carries it. It never ignores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<serde_json::Value>,
    /// How long the caller is willing to wait for the operation to end before the host answers with
    /// its current state (API-6). Capped at `wait_max`; absent means `wait_max`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_ms: Option<u64>,
    /// One of the methods of §10.3.
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

/// A request whose shape is valid: every field typed, bounded and known.
#[derive(Debug, Clone)]
pub struct ValidatedRequest {
    pub request_id: Option<String>,
    pub operation_id: Option<OperationId>,
    pub retry: bool,
    pub issued_at: Option<String>,
    /// `issued_at` as milliseconds since the epoch.
    pub issued_at_ms: Option<i64>,
    pub owner_scope: OwnerScope,
    pub on_behalf_of: Option<String>,
    pub wait_ms: Option<u64>,
    pub command: Command,
}

impl RequestEnvelope {
    /// Shape validation (PA-1, the "schema validation" stage). Performs no I/O and consults no state,
    /// so the edge can run it without any privilege and the core can run it again (PD-2).
    ///
    /// The protocol check is separate ([`super::protocol_supported`]) because a major mismatch has
    /// its own class.
    pub fn validate(self) -> Result<ValidatedRequest> {
        if let Some(id) = &self.request_id {
            validate_label("request_id", id, MAX_REQUEST_ID_BYTES)?;
        }
        if let Some(o) = &self.on_behalf_of {
            validate_label("on_behalf_of", o, MAX_ON_BEHALF_OF_BYTES)?;
        }
        if self.authority.is_some() {
            // AU-11 / T-AUTH-08: never ignored.
            return Err(AcfError::validation(
                "`authority` carries a signed decision, and this host does not advertise the `signed_decision` feature",
            ));
        }
        let method = Method::parse(&self.method).ok_or_else(|| AcfError::validation("unknown method"))?;
        let command = Command::decode(method, self.params)?;
        let issued_at_ms = match &self.issued_at {
            Some(t) => Some(
                parse_rfc3339_utc_ms(t)
                    .ok_or_else(|| AcfError::validation("issued_at must be UTC in the form YYYY-MM-DDTHH:MM:SS[.fff]Z"))?,
            ),
            None => None,
        };
        if method.requires_operation() {
            if self.operation_id.is_none() {
                return Err(AcfError::validation(format!("`{method}` requires an operation_id")));
            }
            if issued_at_ms.is_none() {
                return Err(AcfError::validation(format!("`{method}` requires issued_at")));
            }
        } else if self.retry {
            return Err(AcfError::validation(format!("`{method}` is a read: `retry` has no meaning for it")));
        }
        Ok(ValidatedRequest {
            request_id: self.request_id,
            operation_id: self.operation_id,
            retry: self.retry,
            issued_at: self.issued_at,
            issued_at_ms,
            owner_scope: self.owner_scope,
            on_behalf_of: self.on_behalf_of,
            wait_ms: self.wait_ms,
            command,
        })
    }
}

/// §11.4: `issued_at` older than `acceptance_horizon`, or later than now by more than
/// `clock_skew_tolerance`, is refused with `EXPIRED_REQUEST`. Pure, so it is tested at the edges.
pub fn within_acceptance_horizon(issued_at_ms: i64, now_ms: i64, horizon_ms: u64, skew_ms: u64) -> bool {
    let age = now_ms.saturating_sub(issued_at_ms);
    let horizon = i64::try_from(horizon_ms).unwrap_or(i64::MAX);
    let skew = i64::try_from(skew_ms).unwrap_or(i64::MAX);
    age <= horizon && age >= -skew
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::FailureClass;

    fn env(json: &str) -> std::result::Result<RequestEnvelope, serde_json::Error> {
        serde_json::from_str(json)
    }

    const SBX: &str = "sbx-00000000000000000000000000000000";

    fn destroy(extra: &str) -> String {
        format!(
            r#"{{"protocol":"acf.host/2","owner_scope":"team-a","operation_id":"op-12345678","issued_at":"2026-11-18T10:00:00Z",
                "method":"sandbox.destroy","params":{{"sandbox_id":"{SBX}","expected_generation":3}}{extra}}}"#
        )
    }

    #[test]
    fn the_envelope_fields_are_exactly_the_contract_table_plus_the_wait_bound() {
        // §10.2, transcribed. `wait_ms` is the caller's `wait` bound of API-6.
        let schema = serde_json::to_value(schemars::schema_for!(RequestEnvelope)).unwrap();
        let mut fields: Vec<&str> = schema["properties"].as_object().unwrap().keys().map(String::as_str).collect();
        fields.sort_unstable();
        assert_eq!(
            fields,
            [
                "authority",
                "issued_at",
                "method",
                "on_behalf_of",
                "operation_id",
                "owner_scope",
                "params",
                "protocol",
                "request_id",
                "retry",
                "wait_ms"
            ]
        );
        let mut required: Vec<&str> = schema["required"].as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
        required.sort_unstable();
        assert_eq!(required, ["method", "owner_scope", "protocol"]);
        assert_eq!(schema["additionalProperties"], serde_json::json!(false), "unknown envelope fields are refused");
    }

    #[test]
    fn unknown_fields_and_unknown_methods_are_refused() {
        assert!(env(&destroy(r#","sneaky":1"#)).is_err(), "an unknown envelope field");
        let unknown = env(r#"{"protocol":"acf.host/2","owner_scope":"a","method":"rm.rf","params":{}}"#).unwrap().validate().unwrap_err();
        assert_eq!(unknown.class, FailureClass::InvalidRequest);
        let params = env(&destroy("").replace(r#""expected_generation":3"#, r#""expected_generation":3,"force":true"#)).unwrap().validate();
        assert_eq!(params.unwrap_err().class, FailureClass::InvalidRequest, "params are strict too");
        assert!(env(&destroy("")).unwrap().validate().is_ok());
    }

    #[test]
    fn a_mutation_cannot_be_expressed_with_a_name() {
        let by_name = env(r#"{"protocol":"acf.host/2","owner_scope":"a","operation_id":"op-12345678","issued_at":"2026-11-18T10:00:00Z",
                "method":"sandbox.destroy","params":{"sandbox":"baseline"}}"#)
        .unwrap()
        .validate();
        assert_eq!(by_name.unwrap_err().class, FailureClass::InvalidRequest);
    }

    #[test]
    fn every_method_that_records_an_operation_requires_an_id_and_issued_at() {
        let no_id = env(&destroy("").replace(r#""operation_id":"op-12345678","#, "")).unwrap().validate().unwrap_err();
        assert_eq!(no_id.class, FailureClass::InvalidRequest);
        assert!(no_id.message.contains("operation_id"), "{}", no_id.message);
        let no_time = env(&destroy("").replace(r#""issued_at":"2026-11-18T10:00:00Z","#, "")).unwrap().validate().unwrap_err();
        assert!(no_time.message.contains("issued_at"), "{}", no_time.message);
        let bad_time = env(&destroy("").replace("2026-11-18T10:00:00Z", "2026-11-18T10:00:00+01:00")).unwrap().validate().unwrap_err();
        assert_eq!(bad_time.class, FailureClass::InvalidRequest);
        // a read needs neither
        let read = env(r#"{"protocol":"acf.host/2","owner_scope":"a","method":"sandbox.list"}"#).unwrap().validate().unwrap();
        assert!(read.operation_id.is_none() && read.issued_at_ms.is_none());
    }

    #[test]
    fn a_request_carrying_a_signed_decision_is_refused_never_ignored() {
        let e = env(&destroy(r#","authority":{"decision":"…","signature":"…"}"#)).unwrap().validate().unwrap_err();
        assert_eq!(e.class, FailureClass::InvalidRequest);
        assert!(e.message.contains("signed_decision"), "{}", e.message);
        assert!(env(&destroy(r#","authority":null"#)).unwrap().validate().is_ok(), "null is absent");
    }

    #[test]
    fn caller_labels_are_bounded_before_they_can_be_recorded_or_logged() {
        for bad in [r#","request_id":"has space""#, r#","on_behalf_of":"line\nbreak""#] {
            let e = env(&destroy(bad)).unwrap().validate().unwrap_err();
            assert_eq!(e.class, FailureClass::InvalidRequest, "{bad}");
        }
        let long = format!(r#","request_id":"{}""#, "r".repeat(MAX_REQUEST_ID_BYTES + 1));
        assert!(env(&destroy(&long)).unwrap().validate().is_err());
        assert!(env(&destroy("").replace("team-a", "team a")).is_err(), "owner_scope is validated while decoding");
        let oversized_scope = "s".repeat(crate::domain::MAX_OWNER_SCOPE_BYTES + 1);
        assert!(env(&destroy("").replace("team-a", &oversized_scope)).is_err());
    }

    #[test]
    fn acceptance_horizon_edges() {
        let now = 1_000_000_000i64;
        let (horizon, skew) = (300_000u64, 30_000u64);
        assert!(within_acceptance_horizon(now, now, horizon, skew));
        assert!(within_acceptance_horizon(now - 300_000, now, horizon, skew), "exactly the horizon is accepted");
        assert!(!within_acceptance_horizon(now - 300_001, now, horizon, skew), "one millisecond older is not");
        assert!(within_acceptance_horizon(now + 30_000, now, horizon, skew), "a clock slightly ahead is tolerated");
        assert!(!within_acceptance_horizon(now + 30_001, now, horizon, skew), "a request from the future is refused");
        assert!(!within_acceptance_horizon(i64::MIN, now, horizon, skew), "no overflow at the extremes");
        assert!(!within_acceptance_horizon(i64::MAX, now, horizon, skew));
    }
}
