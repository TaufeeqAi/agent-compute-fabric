//! Network intent (contract §20). The intent is what a caller asks for and what the host records;
//! it is immutable for the life of a generation (NW-3) and there is no fallback to a broader mode.
//!
//! The vocabulary has exactly two modes. Adding a third is a contract change that ships with its
//! own adversarial tests (§20.1).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The mode vocabulary. Any other word is refused with `UNSUPPORTED` before the request is decoded
/// any further (§20.1, `api::command`): a mode this host does not know is a capability it does not
/// offer. A known mode that the backend does not support is `UNSUPPORTED` too, and one that the
/// safety profile does not list is `SAFETY_CONTROL_DENIED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// No network device exists in the guest.
    None,
    /// Outbound TCP to listed destinations only, through the host's resolver and relay.
    Allowlist,
}

/// One inclusive port range. `from` and `to` are 1..=65535 and `from <= to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PortRange {
    pub from: u16,
    pub to: u16,
}

/// AL-1: the destination is an exact DNS name or an IPv4 network.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum AllowDestination {
    /// An exact DNS name: permits TLS whose server name equals it, to an address the host resolver
    /// returned for it (AL-4).
    Name(String),
    /// An IPv4 network in CIDR form: permits TCP to its addresses (AL-5).
    Network(String),
}

/// AL-1: a destination and a non-empty set of ports.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AllowEntry {
    pub destination: AllowDestination,
    pub ports: Vec<PortRange>,
}

/// What connectivity a sandbox is given. Recorded on the generation; never widened afterwards.
///
/// Wire form: `{"mode": "none"}` or `{"mode": "allowlist", "entries": [...]}`. Decoding goes through
/// [`IntentWire`], because a derived tagged enum would silently accept extra fields beside
/// `"mode": "none"` — and a field that narrows what a sandbox may do must never be ignored (VR-2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields, try_from = "IntentWire")]
pub enum NetworkIntent {
    None,
    Allowlist { entries: Vec<AllowEntry> },
}

/// The published schema states the same strictness the decoder enforces.
impl JsonSchema for NetworkIntent {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "NetworkIntent".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let entry = generator.subschema_for::<AllowEntry>();
        schemars::json_schema!({
            "description": "What connectivity a sandbox is given. Recorded on the generation; never widened afterwards.",
            "oneOf": [
                {
                    "description": "No network device exists in the guest.",
                    "type": "object",
                    "properties": { "mode": { "type": "string", "const": "none" } },
                    "required": ["mode"],
                    "additionalProperties": false
                },
                {
                    "description": "Outbound TCP to listed destinations only, through the host's resolver and relay.",
                    "type": "object",
                    "properties": { "mode": { "type": "string", "const": "allowlist" }, "entries": { "type": "array", "items": entry } },
                    "required": ["mode", "entries"],
                    "additionalProperties": false
                }
            ]
        })
    }
}

/// The strict decoding form of [`NetworkIntent`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentWire {
    mode: NetworkMode,
    entries: Option<Vec<AllowEntry>>,
}

impl TryFrom<IntentWire> for NetworkIntent {
    type Error = &'static str;

    fn try_from(w: IntentWire) -> Result<Self, Self::Error> {
        match (w.mode, w.entries) {
            (NetworkMode::None, None) => Ok(NetworkIntent::None),
            (NetworkMode::None, Some(_)) => Err("network mode `none` takes no `entries`"),
            (NetworkMode::Allowlist, Some(entries)) => Ok(NetworkIntent::Allowlist { entries }),
            (NetworkMode::Allowlist, None) => Err("network mode `allowlist` requires `entries`"),
        }
    }
}

impl NetworkIntent {
    pub fn mode(&self) -> NetworkMode {
        match self {
            NetworkIntent::None => NetworkMode::None,
            NetworkIntent::Allowlist { .. } => NetworkMode::Allowlist,
        }
    }

    pub fn entries(&self) -> &[AllowEntry] {
        match self {
            NetworkIntent::None => &[],
            NetworkIntent::Allowlist { entries } => entries,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wire_form_is_tagged_and_strict() {
        let none: NetworkIntent = serde_json::from_str(r#"{"mode":"none"}"#).unwrap();
        assert_eq!(none.mode(), NetworkMode::None);
        let allow: NetworkIntent = serde_json::from_str(
            r#"{"mode":"allowlist","entries":[{"destination":{"name":"pypi.org"},"ports":[{"from":443,"to":443}]},
                {"destination":{"network":"198.51.100.0/24"},"ports":[{"from":5432,"to":5433}]}]}"#,
        )
        .unwrap();
        assert_eq!(allow.mode(), NetworkMode::Allowlist);
        assert_eq!(allow.entries().len(), 2);
        for bad in [
            r#"{"mode":"open"}"#,
            r#"{"mode":"restricted"}"#,
            r#"{"mode":"none","entries":[]}"#,
            r#"{"mode":"none","allow_all":true}"#,
            r#"{"mode":"allowlist","entries":[],"fallback":"open"}"#,
            r#"{"entries":[]}"#,
            r#"{"mode":"allowlist","entries":[{"destination":{"name":"a.example"},"ports":[],"note":"x"}]}"#,
            r#"{"mode":"allowlist","entries":[{"destination":{"url":"https://a.example"},"ports":[]}]}"#,
            r#"{"mode":"allowlist"}"#,
        ] {
            assert!(serde_json::from_str::<NetworkIntent>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_mode_vocabulary_has_exactly_two_words() {
        assert_eq!(serde_json::from_str::<NetworkMode>("\"none\"").unwrap(), NetworkMode::None);
        assert_eq!(serde_json::from_str::<NetworkMode>("\"allowlist\"").unwrap(), NetworkMode::Allowlist);
        for other in ["\"restricted\"", "\"open\"", "\"host\"", "\"bridge\""] {
            assert!(serde_json::from_str::<NetworkMode>(other).is_err(), "{other}");
        }
    }
}
