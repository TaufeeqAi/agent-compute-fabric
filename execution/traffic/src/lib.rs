//! The guest-traffic domain: the one unprivileged place where bytes sent by a sandbox are parsed.
//!
//! # What it is
//!
//! In network mode `allowlist` a sandbox has one network device, on an isolated host-side segment inside its
//! own network namespace, and that namespace has no route out. The privileged core opens two sockets inside
//! the namespace and hands them to this role, which runs in the host's namespace as an unprivileged process:
//!
//! * a UDP socket on the gateway address, port 53 - served by [`resolver`];
//! * a TCP listener that the namespace's packet filter redirects every guest TCP connection to - served by
//!   [`relay`].
//!
//! Those two sockets are the sandbox's whole connectivity. [`role::run`] serves them until it is told to stop
//! or fails, and returning closes both: a dead, stopped or crashed role means no connectivity, never more.
//!
//! # Rules (execution-plane contract 1.2.0)
//!
//! * **PD-3** - code that parses guest-originated traffic runs without host-mutation capability, and its
//!   failure yields no connectivity. This crate spawns no process, opens no file, and touches no namespace,
//!   route or packet filter; it only uses the two sockets it is given and the outbound sockets it creates.
//! * **NW-1** - deny by construction: lost or corrupt filtering state yields no connectivity. Bindings live in
//!   memory only, an unknown destination is denied, and every failure path closes the guest connection.
//! * **NW-4 / AL-6** - loopback, link-local (metadata addresses included), multicast, broadcast, reserved
//!   ranges, the host's own addresses and other sandboxes are denied whatever the allowlist says; private
//!   ranges are denied unless the profile enables them and a network entry names them.
//! * **AL-1** - an entry is an exact DNS name or an IPv4 network plus a non-empty set of ports; every table
//!   is bounded.
//! * **AL-2** - whatever no entry matches is denied. Only DNS over UDP to the resolver and redirected TCP
//!   ever reach this crate, and it forwards nothing else. IPv4 only.
//! * **AL-3** - the resolver answers only for allowlisted names, refuses every other name without contacting
//!   an upstream, and returns address records only.
//! * **AL-4** - a name entry permits a TLS connection whose server name equals the entry, to an address the
//!   resolver returned for that name to this sandbox within the binding lifetime, on a listed port.
//! * **AL-5** - a network entry permits TCP to its addresses and ports.
//!
//! # Threat model
//!
//! The guest is hostile and controls every byte this crate reads: DNS datagrams, TCP segmentation and TLS
//! record framing. The upstream resolver is not trusted to return safe addresses (DNS rebinding). The crate
//! therefore keeps to four habits: parsers are hand-written, strict and total (no `unsafe`, no panics, no
//! recursion, no length trusted beyond the bytes received); every buffer, table, task count and wait has a
//! named bound; decisions are pure functions in [`policy`], tested row by row, with the I/O loops unable to
//! widen them; and guest-supplied bytes never reach a log or a metric label.
//!
//! What it does not defend against is by design: a TLS server name is the guest's claim, so two sites that
//! share one allowlisted address can both be reached; the contract accepts this for name entries.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod dns;
pub mod policy;
mod reader;
pub mod relay;
pub mod resolver;
pub mod role;
pub mod sni;

pub use policy::{Allowlist, Bindings, DenyContext, DenyReason, DnsName, Ipv4Net, PolicyError, Verdict};
pub use role::{RoleConfig, RoleError, Shared, StatsSnapshot, run, run_with};
