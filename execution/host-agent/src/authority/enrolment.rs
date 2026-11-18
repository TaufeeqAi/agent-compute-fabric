//! Enrolment (contract §9.1): which authenticated peers have authority on this host, and in which role.
//!
//! * AU-2 — an authenticated peer has authority **only** if it matches an entry here. A credential
//!   that chains to a trusted anchor but is not enrolled has none: the connection is closed before
//!   any request is read.
//! * AU-6 — records store the enrolled `peer_id`, never the credential. Rotating a certificate is
//!   an enrolment change and touches no record.
//! * The enrolment file is trusted configuration (TI-1). The core loads it through the trusted-file
//!   rule and hands the parsed table to the edge; the edge never reads a file.
//!
//! A matcher names a credential exactly. There is no pattern, no wildcard and no "any certificate
//! from this authority" entry: authority is granted to a named peer or not at all.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    domain::{PeerId, Role},
    error::{AcfError, Result},
};

pub const ENROLMENT_SCHEMA_VERSION: u32 = 1;
/// More peers than this in one host's enrolment is a configuration error, not a scale target.
pub const MAX_ENROLLED_PEERS: usize = 256;

/// How an enrolled peer proves who it is.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CredentialMatcher {
    /// Network endpoint: lower-case hex SHA-256 of the DER encoding of the client's leaf certificate.
    CertificateSha256(String),
    /// Network endpoint: lower-case hex SHA-256 of the leaf certificate's DER SubjectPublicKeyInfo.
    /// Survives re-issuance of the certificate for the same key.
    SpkiSha256(String),
    /// Local endpoint: the uid the kernel reports for the connecting process.
    LocalUid(u32),
    /// Local endpoint: the primary gid the kernel reports for the connecting process.
    LocalGid(u32),
}

impl CredentialMatcher {
    pub fn is_network(&self) -> bool {
        matches!(self, Self::CertificateSha256(_) | Self::SpkiSha256(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnrolmentEntry {
    pub peer_id: PeerId,
    pub role: Role,
    #[serde(rename = "match")]
    pub matcher: CredentialMatcher,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnrolmentDoc {
    pub schema_version: u32,
    pub peers: Vec<EnrolmentEntry>,
}

/// A validated enrolment table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrolment {
    doc: EnrolmentDoc,
    digest: String,
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Enrolment {
    /// Parse **and validate**. `digest` is the sha256 hex of exactly `bytes`.
    pub fn parse(bytes: &[u8], digest: String) -> Result<Self> {
        let text = std::str::from_utf8(bytes).map_err(|_| AcfError::corrupt("enrolment file is not valid UTF-8"))?;
        let doc: EnrolmentDoc = serde_saphyr::from_str(text).map_err(|e| AcfError::corrupt(format!("enrolment YAML rejected: {e}")))?;
        Self::from_doc(doc, digest)
    }

    pub fn from_doc(doc: EnrolmentDoc, digest: String) -> Result<Self> {
        if doc.schema_version != ENROLMENT_SCHEMA_VERSION {
            return Err(AcfError::incompatible(format!(
                "enrolment schema_version {} is not supported (expected {ENROLMENT_SCHEMA_VERSION})",
                doc.schema_version
            )));
        }
        if doc.peers.len() > MAX_ENROLLED_PEERS {
            return Err(AcfError::corrupt(format!(
                "enrolment lists {} peers; at most {MAX_ENROLLED_PEERS} are supported",
                doc.peers.len()
            )));
        }
        for (i, e) in doc.peers.iter().enumerate() {
            if let CredentialMatcher::CertificateSha256(h) | CredentialMatcher::SpkiSha256(h) = &e.matcher
                && !is_sha256_hex(h)
            {
                return Err(AcfError::corrupt(format!(
                    "enrolment entry `{}`: a fingerprint must be 64 lower-case hex characters",
                    e.peer_id
                )));
            }
            // One credential names one peer, and one peer id has one role: an ambiguous table could
            // grant a credential a role its operator did not intend.
            for other in &doc.peers[..i] {
                if other.matcher == e.matcher {
                    return Err(AcfError::corrupt(format!(
                        "enrolment entries `{}` and `{}` name the same credential",
                        other.peer_id, e.peer_id
                    )));
                }
                if other.peer_id == e.peer_id && other.role != e.role {
                    return Err(AcfError::corrupt(format!("enrolment peer `{}` is listed with two different roles", e.peer_id)));
                }
            }
        }
        Ok(Self { doc, digest })
    }

    /// An empty table: nobody has authority. The host still runs (it can be reached once a peer is enrolled).
    pub fn empty() -> Self {
        Self { doc: EnrolmentDoc { schema_version: ENROLMENT_SCHEMA_VERSION, peers: Vec::new() }, digest: String::new() }
    }

    pub fn doc(&self) -> &EnrolmentDoc {
        &self.doc
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn has_network_peers(&self) -> bool {
        self.doc.peers.iter().any(|e| e.matcher.is_network())
    }

    /// The entry a client certificate matches. `spki_sha256` is `None` if the key could not be extracted.
    pub fn match_mtls(&self, certificate_sha256: &str, spki_sha256: Option<&str>) -> Option<&EnrolmentEntry> {
        self.doc.peers.iter().find(|e| match &e.matcher {
            CredentialMatcher::CertificateSha256(h) => h == certificate_sha256,
            CredentialMatcher::SpkiSha256(h) => Some(h.as_str()) == spki_sha256,
            _ => false,
        })
    }

    /// The entry a local caller matches. A uid entry is more specific than a gid entry and wins.
    pub fn match_local(&self, uid: u32, gid: u32) -> Option<&EnrolmentEntry> {
        let by = |want: CredentialMatcher| self.doc.peers.iter().find(|e| e.matcher == want);
        by(CredentialMatcher::LocalUid(uid)).or_else(|| by(CredentialMatcher::LocalGid(gid)))
    }

    /// Is `(peer_id, role)` enrolled? The core checks this for every command the edge relays (PD-2):
    /// a removed entry stops working at once, whatever an open connection believes (AU-5).
    pub fn grants(&self, peer_id: &PeerId, role: Role) -> bool {
        self.doc.peers.iter().any(|e| e.peer_id == *peer_id && e.role == role)
    }
}

#[cfg(any(test, feature = "testing"))]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test doubles may fail loudly; never compiled into release builds"
)]
pub mod test_support {
    use super::*;

    /// The calling user as `operator`, plus one caller and one observer enrolled by gid/uid that never match.
    pub fn local(uid: u32) -> Enrolment {
        let yaml =
            format!("schema_version: 1\npeers:\n  - peer_id: test-operator\n    role: operator\n    match: {{ local_uid: {uid} }}\n");
        Enrolment::parse(yaml.as_bytes(), "e".repeat(64)).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::FailureClass;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn table() -> Enrolment {
        let yaml = format!(
            r#"
schema_version: 1
peers:
  - peer_id: gateway-1
    role: caller
    match: {{ certificate_sha256: "{A}" }}
  - peer_id: ops-laptop
    role: operator
    match: {{ spki_sha256: "{B}" }}
  - peer_id: local-root
    role: operator
    match: {{ local_uid: 0 }}
  - peer_id: local-callers
    role: caller
    match: {{ local_gid: 990 }}
  - peer_id: metrics
    role: observer
    match: {{ local_uid: 65534 }}
"#
        );
        Enrolment::parse(yaml.as_bytes(), "d".repeat(64)).unwrap()
    }

    #[test]
    fn a_credential_matches_only_its_own_entry() {
        let t = table();
        assert_eq!(t.match_mtls(A, None).map(|e| (e.peer_id.as_str(), e.role)), Some(("gateway-1", Role::Caller)));
        assert_eq!(t.match_mtls("c".repeat(64).as_str(), Some(B)).map(|e| e.peer_id.as_str()), Some("ops-laptop"));
        assert!(t.match_mtls(B, None).is_none(), "a certificate fingerprint does not match an SPKI entry");
        assert!(t.match_mtls(&"c".repeat(64), Some(&"c".repeat(64))).is_none(), "a chain-valid but unenrolled peer has no authority");
        assert!(t.has_network_peers());
    }

    #[test]
    fn local_callers_match_by_uid_before_gid_and_unknown_callers_match_nothing() {
        let t = table();
        assert_eq!(t.match_local(0, 990).map(|e| e.peer_id.as_str()), Some("local-root"), "uid is more specific than gid");
        assert_eq!(t.match_local(1000, 990).map(|e| (e.peer_id.as_str(), e.role)), Some(("local-callers", Role::Caller)));
        assert!(t.match_local(1000, 1000).is_none());
        assert!(Enrolment::empty().match_local(0, 0).is_none(), "an empty enrolment grants nobody, not even root");
    }

    #[test]
    fn the_core_can_verify_a_relayed_identity() {
        let t = table();
        let peer = |s: &str| PeerId::parse(s).unwrap();
        assert!(t.grants(&peer("gateway-1"), Role::Caller));
        assert!(!t.grants(&peer("gateway-1"), Role::Operator), "an edge cannot promote a peer");
        assert!(!t.grants(&peer("ghost"), Role::Caller));
    }

    #[test]
    fn ambiguous_or_malformed_tables_are_refused() {
        let dup_cred = format!(
            "schema_version: 1\npeers:\n  - {{peer_id: a, role: caller, match: {{certificate_sha256: \"{A}\"}}}}\n  - {{peer_id: b, role: operator, match: {{certificate_sha256: \"{A}\"}}}}\n"
        );
        assert!(Enrolment::parse(dup_cred.as_bytes(), "d".into()).is_err(), "one credential, two peers");
        let two_roles = "schema_version: 1\npeers:\n  - {peer_id: a, role: caller, match: {local_uid: 1}}\n  - {peer_id: a, role: operator, match: {local_uid: 2}}\n";
        assert!(Enrolment::parse(two_roles.as_bytes(), "d".into()).is_err(), "one peer, two roles");
        let short = "schema_version: 1\npeers:\n  - {peer_id: a, role: caller, match: {certificate_sha256: \"abc\"}}\n";
        assert!(Enrolment::parse(short.as_bytes(), "d".into()).is_err());
        let upper = format!(
            "schema_version: 1\npeers:\n  - {{peer_id: a, role: caller, match: {{certificate_sha256: \"{}\"}}}}\n",
            A.to_uppercase()
        );
        assert!(Enrolment::parse(upper.as_bytes(), "d".into()).is_err(), "one spelling per fingerprint");
        let wildcard = "schema_version: 1\npeers:\n  - {peer_id: a, role: caller, match: {any_certificate: true}}\n";
        assert!(Enrolment::parse(wildcard.as_bytes(), "d".into()).is_err(), "there is no wildcard matcher");
        let unknown = "schema_version: 1\npeers: []\nallow_all: true\n";
        assert!(Enrolment::parse(unknown.as_bytes(), "d".into()).is_err());
        let role = "schema_version: 1\npeers:\n  - {peer_id: a, role: admin, match: {local_uid: 1}}\n";
        assert!(Enrolment::parse(role.as_bytes(), "d".into()).is_err(), "roles are a closed set");
        let v9 = "schema_version: 9\npeers: []\n";
        assert_eq!(Enrolment::parse(v9.as_bytes(), "d".into()).unwrap_err().class, FailureClass::IncompatibleRuntime);
    }

    #[test]
    fn the_same_peer_may_have_several_credentials_in_one_role() {
        let y = format!(
            "schema_version: 1\npeers:\n  - {{peer_id: gw, role: caller, match: {{certificate_sha256: \"{A}\"}}}}\n  - {{peer_id: gw, role: caller, match: {{certificate_sha256: \"{B}\"}}}}\n"
        );
        let t = Enrolment::parse(y.as_bytes(), "d".into()).unwrap();
        assert_eq!(t.match_mtls(B, None).map(|e| e.peer_id.as_str()), Some("gw"), "rotation: both certificates are the same peer");
    }
}
