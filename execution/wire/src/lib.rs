//! Wire contracts shared between the privileged host-agent and the in-VM guest agent.
//!
//! Two things live here and nothing else:
//!
//! * [`frame`] — a deliberately tiny length-delimited framing layer with a **mandatory
//!   maximum frame size**. The guest is untrusted, so the host must be able to bound the
//!   memory a single read can cost *before* allocating (contract GP-2).
//! * [`guest`] — the versioned request/response vocabulary spoken over AF_VSOCK.
//!
//! The crate is `std`-only by default so the static guest binary stays small.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod frame;
pub mod guest;

pub use frame::{FrameError, MAX_FRAME_HARD_CAP};
