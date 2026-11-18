//! Authority (contract §9, boundaries B03 and B04): who may ask, in which role, on which records,
//! and what the host's own safety profile permits — plus the integrity of the files those answers
//! come from. Nothing here touches a sandbox, and nothing here decides business policy (INV-003).
//!
//! ```text
//! credential ──enrolment──► (peer_id, role)            edge authenticates; core re-checks
//! request    ──role table──► method allowed?            AUTHORIZATION_DENIED
//! record     ──tags────────► same peer and scope?       NOT_FOUND
//! request    ──profile─────► within the safety floor?   SAFETY_CONTROL_DENIED
//! ```

pub mod enrolment;
pub mod profile;
pub mod trusted_file;

pub use enrolment::{CredentialMatcher, Enrolment, EnrolmentDoc, EnrolmentEntry};
pub use profile::{ProfileDoc, SafetyProfile};
