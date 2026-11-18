//! Authority vocabulary (contract §9): who is asking, in which role, on whose behalf.
//!
//! * A **peer** is an enrolled caller of this host (AU-2). Its id comes from trusted configuration,
//!   never from the request, and it is what durable records hold (AU-6). A peer is *not* a tenant
//!   (INV-015).
//! * An **owner scope** is an opaque label the peer attaches to everything it creates (AU-7). The
//!   host stores it and compares it for equality. It never interprets it.
//! * **Tags** are the pair `(peer_id, owner_scope)` stamped on every sandbox, snapshot and operation
//!   (AU-8). A `caller` sees only records whose tags equal its own; everything else is `NOT_FOUND`
//!   (AU-9), so a record's existence is never revealed across scopes.
//!
//! Every type here validates on construction **and** on deserialization: these strings are written
//! to durable records and to telemetry, so their length and character set are bounded first (OB-8).

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{AcfError, Result};

/// Longest enrolled peer id.
pub const MAX_PEER_ID_BYTES: usize = 64;
/// Longest owner scope a request may carry (§30, identifier length bounds).
pub const MAX_OWNER_SCOPE_BYTES: usize = 128;
/// Longest `on_behalf_of` label a request may carry.
pub const MAX_ON_BEHALF_OF_BYTES: usize = 256;
/// Longest `request_id` a request may carry (it is echoed, so it is bounded).
pub const MAX_REQUEST_ID_BYTES: usize = 128;

/// The character set of every caller-supplied label: visible, unambiguous in a log line, and free
/// of quoting, whitespace and path metacharacters that matter to a shell or a terminal.
fn label_byte_ok(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':' | b'/' | b'@' | b'=' | b'+')
}

/// Validate an opaque caller-supplied label (`on_behalf_of`, `request_id`).
pub fn validate_label(what: &str, value: &str, max: usize) -> Result<()> {
    if value.is_empty() || value.len() > max || !value.bytes().all(label_byte_ok) {
        return Err(AcfError::validation(format!("{what} must be 1..={max} characters of [A-Za-z0-9._:/@=+-]")));
    }
    Ok(())
}

macro_rules! bounded_label {
    ($(#[$m:meta])* $name:ident, $what:literal, $max:expr) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn parse(s: &str) -> Result<Self> {
                validate_label($what, s, $max)?;
                Ok(Self(s.to_owned()))
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
                    "minLength": 1,
                    "maxLength": $max,
                    "pattern": "^[A-Za-z0-9._:/@=+-]+$"
                })
            }
        }
    };
}

bounded_label!(
    /// The enrolled identity of a caller of this host. Allocated in trusted configuration.
    PeerId,
    "peer_id",
    MAX_PEER_ID_BYTES
);
bounded_label!(
    /// Opaque owner scope. Compared for equality, never interpreted (AU-7).
    OwnerScope,
    "owner_scope",
    MAX_OWNER_SCOPE_BYTES
);

impl PeerId {
    /// The peer id under which operations the host issues itself are recorded when the sandbox they
    /// act on has no tags (never the case for records written by this version; kept total).
    pub fn host() -> Self {
        Self("host".to_owned())
    }
}

/// The closed role set (§9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// `host.info` and `host.metrics` only.
    Observer,
    /// Every granting, containment and read method, on records carrying its own tags.
    Caller,
    /// Everything a caller may call, on any record, plus the operator methods.
    Operator,
}

/// `(peer_id, owner_scope)` of the request that created a record (AU-8).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Tags {
    pub peer_id: PeerId,
    pub owner_scope: OwnerScope,
}

impl fmt::Display for Tags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.peer_id, self.owner_scope)
    }
}

/// Who caused an operation: an enrolled peer, or the host acting on an observation (OP-24).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Issuer {
    Peer,
    Host,
}

/// How the peer reached the host. Diagnostic only: authority never depends on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// Mutual TLS on the network endpoint.
    Mtls,
    /// Operating-system peer credentials on the local endpoint.
    Local,
}

/// The authority context of one request: the form `DelegatedAuthority` takes in this contract
/// revision (AU-10). It is the enrolled peer's own statement; the host enforces consistency between
/// scopes and cannot verify that a peer is entitled to the scope it names (accepted risk AR-1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AuthorityContext {
    pub peer_id: PeerId,
    pub role: Role,
    pub owner_scope: OwnerScope,
    /// Recorded, never compared (AU-7).
    pub on_behalf_of: Option<String>,
}

impl AuthorityContext {
    pub fn tags(&self) -> Tags {
        Tags { peer_id: self.peer_id.clone(), owner_scope: self.owner_scope.clone() }
    }

    /// AU-9 / §9.2: an operator acts on any record; a caller only on records with its own tags.
    pub fn may_access(&self, tags: &Tags) -> bool {
        match self.role {
            Role::Operator => true,
            Role::Caller => self.peer_id == tags.peer_id && self.owner_scope == tags.owner_scope,
            Role::Observer => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ctx(peer: &str, role: Role, scope: &str) -> AuthorityContext {
        AuthorityContext { peer_id: PeerId::parse(peer).unwrap(), role, owner_scope: OwnerScope::parse(scope).unwrap(), on_behalf_of: None }
    }

    #[test]
    fn labels_are_bounded_and_restricted_to_a_safe_character_set() {
        assert!(OwnerScope::parse("team-a/project_1:prod@eu=1+x").is_ok());
        for bad in ["", "has space", "quote\"", "new\nline", "back\\slash", "semi;colon", "tab\t", "ünïcode", "a,b"] {
            assert!(OwnerScope::parse(bad).is_err(), "{bad:?}");
            assert!(PeerId::parse(bad).is_err(), "{bad:?}");
        }
        assert!(OwnerScope::parse(&"s".repeat(MAX_OWNER_SCOPE_BYTES)).is_ok());
        assert!(OwnerScope::parse(&"s".repeat(MAX_OWNER_SCOPE_BYTES + 1)).is_err());
        assert!(PeerId::parse(&"p".repeat(MAX_PEER_ID_BYTES + 1)).is_err());
        assert!(serde_json::from_str::<OwnerScope>("\"a b\"").is_err(), "deserialization validates too");
    }

    #[test]
    fn a_caller_reaches_only_its_own_tags_and_an_operator_reaches_everything() {
        let mine = Tags { peer_id: PeerId::parse("cli-1").unwrap(), owner_scope: OwnerScope::parse("team-a").unwrap() };
        assert!(ctx("cli-1", Role::Caller, "team-a").may_access(&mine));
        assert!(!ctx("cli-1", Role::Caller, "team-b").may_access(&mine), "a different owner scope is another world");
        assert!(!ctx("cli-2", Role::Caller, "team-a").may_access(&mine), "a different peer is another world, even with the same scope");
        assert!(ctx("ops", Role::Operator, "anything").may_access(&mine));
        assert!(!ctx("cli-1", Role::Observer, "team-a").may_access(&mine), "an observer reaches no record at all");
    }

    proptest! {
        #[test]
        fn no_label_with_whitespace_control_or_quoting_is_ever_accepted(s in ".{0,160}") {
            let risky = s.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '\\' | '`' | '$' | ';' | '|' | '&' | '<' | '>'));
            if risky {
                prop_assert!(OwnerScope::parse(&s).is_err());
                prop_assert!(validate_label("x", &s, 256).is_err());
            }
        }
    }
}
