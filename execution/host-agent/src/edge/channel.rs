//! The edge ↔ core channel (contract §17.3: a host-only control surface).
//!
//! One stream, created by the core as a socket pair and inherited by the edge. Length-delimited JSON
//! frames in both directions, multiplexed by a request id the edge chooses. Nothing a guest or a
//! peer can reach terminates here.
//!
//! What crosses it is deliberately small: a *validated* request with the peer's enrolled identity
//! and role, and the answer. The core trusts the edge for that identity and role and for nothing
//! else (PD-2); it validates the request again.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::tls::TlsMaterial;
use crate::{
    api::{RequestEnvelope, ResponseEnvelope},
    authority::EnrolmentDoc,
    coordinator::PeerContext,
};

/// Largest control frame (the init message and enrolment updates).
pub const MAX_CONTROL_FRAME: usize = 4 * 1024 * 1024;
/// Room for the peer context and framing around a request or a response.
pub const CHANNEL_SLACK: usize = 16 * 1024;

/// Pre-authentication limits (PA-2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EdgeLimits {
    pub max_connections: usize,
    pub max_connections_per_source: usize,
    pub max_request_bytes: usize,
    pub handshake_deadline_ms: u64,
    pub idle_timeout_ms: u64,
    /// How long the edge waits for the core's answer before it gives the connection up as lost.
    pub response_deadline_ms: u64,
}

/// The first frame the core sends: everything the edge needs, so it opens nothing by name.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EdgeInit {
    pub limits: EdgeLimits,
    pub enrolment: EnrolmentDoc,
    /// Present when the network endpoint is to be served.
    pub tls: Option<TlsMaterial>,
    /// Which listeners follow as descriptors, in this order: local, then network.
    pub local: bool,
    pub network: bool,
}

/// Counters since the edge's last report. The core adds them to its metrics (§24.3: "refusals
/// before authentication").
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EdgeStats {
    pub accepted: u64,
    /// Dropped at `max_connections`.
    pub shed: u64,
    /// Dropped at the per-source cap.
    pub per_source_refused: u64,
    /// TLS handshakes that failed or ran out of time.
    pub handshake_failures: u64,
    /// Authenticated at the transport but not enrolled, or no peer credentials.
    pub auth_denied: u64,
    /// Frames that were not a valid request.
    pub invalid_requests: u64,
    pub relayed: u64,
    /// Requests for an operation that the core did not answer in time. The peer was given no answer
    /// and resolves the operation by its id.
    #[serde(default)]
    pub unanswered: u64,
}

impl EdgeStats {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Everything the edge refused before a peer had authenticated.
    pub fn refused_before_authentication(&self) -> u64 {
        self.shed + self.per_source_refused + self.handshake_failures + self.auth_denied
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum EdgeMessage {
    Request { id: u64, peer: PeerContext, envelope: Box<RequestEnvelope> },
    Stats { stats: EdgeStats },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum CoreMessage {
    Response {
        id: u64,
        response: Box<ResponseEnvelope>,
    },
    /// The enrolment table changed (AU-5). Connections whose peer is no longer enrolled are closed.
    Enrolment {
        doc: EnrolmentDoc,
    },
    Shutdown,
}
