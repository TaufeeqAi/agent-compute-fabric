//! The local control surface (spec §16.1, §24): one Unix-domain socket speaking length-delimited
//! JSON frames. It is the **only** way into the host agent.
//!
//! Security properties (each has a test):
//! * the socket is created `0600` under a restrictive umask and *then* opened to the configured
//!   mode/group, so there is no window where it is world-accessible;
//! * identity is the kernel's `SO_PEERCRED`, never anything in the request; no credentials ⇒ denied;
//! * every frame is size-bounded *before* allocation; connections and idle time are bounded;
//! * a stale socket file is replaced only if it is a socket nobody is listening on.

pub mod dispatch;
pub mod ipc;

pub use ipc::{Server, bind_socket};
