//! CLI ⇄ host-agent wire protocol (spec §24): length-delimited JSON frames over a Unix socket.
//!
//! * **Versioned and strict.** `protocol` must equal [`PROTOCOL`]; every request type denies
//!   unknown fields, so version skew fails loudly instead of being reinterpreted (§24.3).
//! * **Ids, not names, for anything destructive.** Names are accepted only by read-only lookups;
//!   mutating requests carry `(sandbox_id, expected_generation)` (§12.5).
//! * **Transport is a replaceable mechanism.** The semantic content is the typed envelope; Phase 2
//!   can carry the same bodies over mTLS HTTP without touching handlers (§3.3).

pub mod request;
pub mod response;

pub use request::*;
pub use response::*;

/// Semantic protocol identifier. A change that is not backward compatible bumps the major.
pub const PROTOCOL: &str = "acf.host/1";

/// Largest response frame the host will ever send (and the CLI's default receive limit).
pub const MAX_RESPONSE_FRAME: usize = 64 * 1024 * 1024;

/// Room reserved in a response for everything that is *not* captured output: ids, metrics, resource
/// evidence, artifact references, notes, and JSON escaping.
pub const RESPONSE_METADATA_SLACK: usize = 1024 * 1024;

/// The most captured output (stdout + stderr, raw bytes) a single response can carry. Output travels
/// base64-encoded (4 bytes of text per 3 of data), so a run that stays under the policy ceilings must
/// still fit in one frame: otherwise it would succeed and its result could never be delivered. Policy
/// validation enforces this, so the guarantee does not depend on anyone choosing sensible numbers.
pub const MAX_RESULT_OUTPUT_BYTES: u64 = ((MAX_RESPONSE_FRAME - RESPONSE_METADATA_SLACK) / 4 * 3) as u64;

const _: () = assert!(
    (MAX_RESULT_OUTPUT_BYTES as usize).div_ceil(3) * 4 + RESPONSE_METADATA_SLACK <= MAX_RESPONSE_FRAME,
    "the output budget must leave room for the response metadata",
);
