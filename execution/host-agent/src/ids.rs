//! Typed identifiers (contract §8). Every id is validated on construction **and** on
//! deserialization, so a malformed id can never reach path construction or a jailer argv.
//!
//! This is a security property, not a style choice: persisted metadata never supplies a
//! filesystem path (contract ID-5, ST-1). Paths are *derived* from these validated ids, and the
//! charset (`[a-z0-9-]`, fixed length) makes `..`, `/` and NUL unrepresentable.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AcfError, Result};

/// 128 bits from the kernel CSPRNG, hex-encoded: ownership nonces and the store lineage.
pub fn random_token() -> Result<String> {
    use std::io::Read;
    let mut b = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .map_err(|e| AcfError::internal(format!("cannot read /dev/urandom: {e}")))?;
    Ok(hex::encode(b))
}

fn is_lower_hex32(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

macro_rules! prefixed_id {
    ($(#[$m:meta])* $name:ident, $prefix:literal) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub const PREFIX: &'static str = $prefix;

            /// Time-ordered (UUIDv7) so ids sort by creation; unguessable enough that another
            /// local process cannot predict a jail id.
            pub fn generate() -> Self {
                Self(format!("{}{}", $prefix, Uuid::now_v7().simple()))
            }

            pub fn parse(s: &str) -> Result<Self> {
                match s.strip_prefix($prefix) {
                    Some(rest) if is_lower_hex32(rest) => Ok(Self(s.to_owned())),
                    _ => Err(AcfError::validation(format!(
                        "invalid {}: expected `{}` followed by 32 lowercase hex characters",
                        stringify!($name), $prefix
                    ))),
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = AcfError;
            fn try_from(s: String) -> Result<Self> {
                Self::parse(&s)
            }
        }
        impl From<$name> for String {
            fn from(v: $name) -> String {
                v.0
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                stringify!($name).into()
            }
            fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
                schemars::json_schema!({
                    "type": "string",
                    "pattern": concat!("^", $prefix, "[0-9a-f]{32}$")
                })
            }
        }
    };
}

prefixed_id!(
    /// Identity of a sandbox across all of its generations.
    SandboxId,
    "sbx-"
);
prefixed_id!(RunId, "run-");
prefixed_id!(SnapshotId, "snp-");
prefixed_id!(ArtifactId, "art-");
prefixed_id!(RecoveryId, "rec-");
prefixed_id!(EventId, "evt-");

/// Client-supplied (so the client can resolve a lost response). Charset is deliberately the
/// jailer-safe `[A-Za-z0-9-]`, 8..=64 chars; we never use it in a path without re-validating.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OperationId(String);

impl OperationId {
    pub fn generate() -> Self {
        Self(format!("op-{}", Uuid::now_v7().simple()))
    }

    pub fn parse(s: &str) -> Result<Self> {
        if (8..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            Ok(Self(s.to_owned()))
        } else {
            Err(AcfError::validation("invalid OperationId: expected 8..=64 chars of [A-Za-z0-9-]"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for OperationId {
    type Error = AcfError;
    fn try_from(s: String) -> Result<Self> {
        Self::parse(&s)
    }
}
impl From<OperationId> for String {
    fn from(v: OperationId) -> String {
        v.0
    }
}
impl fmt::Display for OperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl JsonSchema for OperationId {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "OperationId".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({"type": "string", "pattern": "^[A-Za-z0-9-]{8,64}$"})
    }
}

/// Monotonic per-sandbox incarnation counter (contract ID-1). Starts at 1; never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct Generation(pub u64);

impl Generation {
    pub const FIRST: Generation = Generation(1);

    #[must_use]
    pub fn next(self) -> Generation {
        Generation(self.0.saturating_add(1))
    }
}

impl fmt::Display for Generation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A sandbox incarnation. Destructive operations require *this*, never a name (contract ID-5).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct SandboxRef {
    pub sandbox_id: SandboxId,
    pub generation: Generation,
}

impl SandboxRef {
    /// The jailer `--id`: alphanumerics + hyphens, <= 64 chars (4 + 32 + 2 + <=20 = <= 58).
    pub fn jail_id(&self) -> String {
        format!("{}-g{}", self.sandbox_id, self.generation)
    }
}

impl fmt::Display for SandboxRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.sandbox_id, self.generation)
    }
}

/// Validate a human-facing alias (sandbox/snapshot names). Aliases are never identity.
pub fn validate_alias(name: &str) -> Result<()> {
    let ok = (1..=63).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        && !name.starts_with('.');
    if ok { Ok(()) } else { Err(AcfError::validation("alias must be 1..=63 chars of [A-Za-z0-9._-] and not start with '.'")) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn generated_ids_roundtrip_through_serde_and_parse() {
        let id = SandboxId::generate();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(serde_json::from_str::<SandboxId>(&json).unwrap(), id);
        assert_eq!(SandboxId::parse(id.as_str()).unwrap(), id);
    }

    #[test]
    fn jail_id_satisfies_jailer_constraints() {
        let r = SandboxRef { sandbox_id: SandboxId::generate(), generation: Generation(u64::MAX) };
        let j = r.jail_id();
        assert!(j.len() <= 64, "{j}");
        assert!(j.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    }

    #[test]
    fn path_traversal_and_wrong_prefix_are_unrepresentable() {
        for bad in [
            "sbx-../../etc/passwd",
            "sbx-",
            "run-00000000000000000000000000000000",
            "sbx-ABCDEF00000000000000000000000000",
            "sbx-0000000000000000000000000000000/",
            "../sbx-00000000000000000000000000000000",
        ] {
            assert!(SandboxId::parse(bad).is_err(), "{bad}");
        }
        assert!(serde_json::from_str::<SandboxId>("\"sbx-../x\"").is_err(), "deserialisation must validate too");
    }

    proptest! {
        #[test]
        fn no_string_with_a_separator_or_dot_is_ever_accepted(s in ".{0,80}") {
            if s.contains('/') || s.contains("..") || s.contains('\0') {
                prop_assert!(SandboxId::parse(&s).is_err());
                prop_assert!(OperationId::parse(&s).is_err());
            }
        }
    }

    #[test]
    fn operation_id_rules() {
        assert!(OperationId::parse("op-12345").is_ok());
        assert!(OperationId::parse("short").is_err());
        assert!(OperationId::parse("has space 1234").is_err());
        assert!(OperationId::parse(&"a".repeat(65)).is_err());
    }

    #[test]
    fn alias_rules() {
        assert!(validate_alias("baseline").is_ok());
        assert!(validate_alias("v1.2_final-3").is_ok());
        for bad in ["", ".hidden", "a/b", "has space", &"x".repeat(64)] {
            assert!(validate_alias(bad).is_err(), "{bad}");
        }
    }
}
