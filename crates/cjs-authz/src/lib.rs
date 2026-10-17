//! Authorization for ClawdJumpServer.
//!
//! * [`model`]: roles, grants, full-access requests.
//! * [`net`]: host/port rules for forwarding and egress, SSRF guard.
//! * [`pdp`]: the policy decision point (default deny).
//! * [`capability`]: Ed25519-signed capability tokens that devices verify
//!   independently of the server.
#![forbid(unsafe_code)]

pub mod capability;
pub mod model;
pub mod net;
pub mod pdp;

pub use model::*;
pub use pdp::{decide, AccessRequest, Decision};
