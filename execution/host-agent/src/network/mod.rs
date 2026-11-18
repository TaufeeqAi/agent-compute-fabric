//! Network (contract §20, boundary B12): what each mode *means*.
//!
//! * `none` is enforced in **three independent layers**, and the evidence says which held:
//!   1. **Structure (authoritative).** The machine configuration contains *no* network interface,
//!      so the guest has no device to bring up.
//!   2. **Containment.** The VMM itself runs in a freshly created, *empty* network namespace.
//!   3. **Corroboration.** The guest agent reports its own interfaces and attempts a few egress
//!      connections. A guest can lie, so this can only *add* a violation, never remove one.
//! * `allowlist` gives the guest one device on an isolated segment inside its own namespace. Nothing
//!   is routed out of that namespace: the only way out is the guest-traffic role (`acf-traffic`),
//!   an unprivileged process that answers DNS for listed names only and relays TCP to listed
//!   destinations only. If it stops, there is no connectivity (NW-1).
//!
//! The plumbing (namespaces, the device, the packet filter) is the backend's. This module holds the
//! intent rules, the guest segment, the verdict on `none`, and the launch of the guest-traffic role.

pub mod intent;
pub mod traffic;
pub mod verify;

pub use intent::{GuestSegment, validate_allowlist};
pub use verify::{NetworkEvidence, NetworkStatus, evaluate_allowlist, evaluate_none};
