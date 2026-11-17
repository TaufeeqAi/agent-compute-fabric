//! Host side of the guest-agent channel (spec §18.8, §20.5). The transport is abstracted behind
//! [`GuestConnector`] so the *same* client code is exercised in production over Firecracker's
//! vsock UDS and in tests over a plain Unix socket against the real agent.

pub mod client;
pub mod connector;

pub use client::{GuestClient, GuestHello, VmBackstop, enforce_bounds};
pub use connector::{BoxedStream, GuestConnector, UdsTarget, UnixConnector, VsockUdsConnector};
