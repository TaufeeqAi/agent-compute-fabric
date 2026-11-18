//! The edge (contract §6.1 PD-1, §9.1, §17.4; boundaries B01 and B04): every ingress endpoint of the
//! host, and nothing else.
//!
//! Two endpoint kinds (AU-1), one pipeline (SEC-012):
//!
//! * the **network endpoint** — mutual TLS 1.3, trust anchors listed explicitly, client certificate
//!   mandatory, authority only for an enrolled certificate;
//! * the **local endpoint** — a Unix socket, authority only for an enrolled uid or gid as the kernel
//!   reports it.
//!
//! The edge runs **without any capability needed for host mutation** (INV-025). It never opens a
//! file by name: the core hands it its listeners and its configuration over the channel it was
//! started with. It reads bytes from peers; the core never does (T-SEC-01).
//!
//! Security properties (each has a test):
//! * the local socket is created `0600` and *then* opened to the configured mode and group, so there
//!   is no window in which it is more accessible than intended;
//! * identity is the kernel's peer credentials or the TLS client certificate, never anything in a
//!   request; no credentials ⇒ refused; valid but not enrolled ⇒ refused, before any request is read;
//! * every frame is size-bounded *before* allocation; connections, per-source connections, handshake
//!   time and idle time are bounded;
//! * a stale socket file is replaced only if it is a socket nobody is listening on.

pub mod channel;
pub mod local;
pub mod serve;
pub mod tls;

pub use channel::{CoreMessage, EdgeInit, EdgeLimits, EdgeMessage, EdgeStats};
pub use local::bind_socket;
pub use serve::{EdgeListeners, receive_init, role_main, run, send_init};
pub use tls::TlsMaterial;
