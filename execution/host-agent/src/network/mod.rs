//! BND-07 — Network manager. Phase 1 supports exactly one mode, `none` (spec §18.6–18.7).
//!
//! `network=none` is enforced in **three independent layers**, and evidence says which held:
//!
//! 1. **Structure (authoritative).** The Firecracker machine config contains *no* network
//!    interface, so the guest has no NIC to bring up. There is nothing to misconfigure.
//! 2. **Containment.** The VMM process itself runs in a freshly created, *empty* network
//!    namespace (loopback only), so even a compromised VMM has no route anywhere.
//! 3. **Corroboration.** The guest agent reports its own interfaces and attempts a few egress
//!    connections. A guest can lie, so this can only *add* a violation, never remove one.

pub mod netns;
pub mod verify;

pub use netns::Netns;
pub use verify::{NetworkEvidence, NetworkStatus, evaluate_none};
