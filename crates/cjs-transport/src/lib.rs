//! Resumable, end-to-end encrypted transport for ClawdJumpServer.
//!
//! ```text
//!   app (yamux)  <->  SessionIo (byte stream)
//!                       |  chunks <= 65519 bytes
//!                     Core: seq/ack, retransmit buffer, Noise (nonce = seq)
//!                       |
//!               WebSocket link  |  HTTP long-poll link (fallback)
//! ```
//!
//! * The client always dials out. It pins the server's static Noise key
//!   (Noise IK), so a TLS-intercepting proxy can neither read nor forge the
//!   session; at most it can drop traffic.
//! * Every segment is a Noise transport message whose nonce is its sequence
//!   number. Segments are kept until acknowledged, so a broken link is
//!   re-attached (`Resume`) and unacknowledged segments are re-sent verbatim
//!   without losing or duplicating stream data.
//! * Control data outside Noise messages (acks, close, resume, HTTP
//!   batches) is MAC'd with keys derived from the Noise handshake hash
//!   (see `mac`). Anything unauthenticated can at most drop a link: a
//!   forged close or ack is ignored and the session is resumed.
//! * Re-attaching proves possession of the resume key with a MAC over
//!   (sid, kind, counter, timestamp, H(data)); the key itself never crosses
//!   the wire, and counters make captured requests unreplayable.
#![forbid(unsafe_code)]

pub mod client;
mod core;
mod handshake;
mod io;
pub mod keys;
mod link;
mod mac;
pub mod profile;
pub mod server;
pub mod tls;

pub use crate::core::SessionHandle;
pub use crate::io::SessionIo;
pub use client::{connect, new_hello, ClientConfig, ClientConn, TransportMode};
pub use keys::StaticKeypair;
pub use server::{
    peer_addr, Accepted, Authenticator, HandshakeLimit, TransportServer, TransportServerConfig,
};

/// How long a session survives without any attached link.
pub const SESSION_GRACE: std::time::Duration = std::time::Duration::from_secs(90);
/// Longest time the server parks an HTTP `rx` request.
pub const LONG_POLL: std::time::Duration = std::time::Duration::from_secs(25);
