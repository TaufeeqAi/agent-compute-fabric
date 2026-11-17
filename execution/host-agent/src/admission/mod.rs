//! BND-02 — Admission: who may ask (auth), what they may ask for (policy), and integrity of the
//! files those answers come from (trusted_file). Nothing here touches a sandbox.

pub mod auth;
pub mod policy;
pub mod trusted_file;

pub use auth::{Authorizer, PeerCred};
pub use policy::{EffectivePolicy, PolicyDoc};
