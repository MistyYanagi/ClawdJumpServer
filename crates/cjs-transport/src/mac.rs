//! Authentication of transport control data that travels outside Noise
//! transport messages: acknowledgements, session close, resume requests
//! and HTTP batches.
//!
//! Three 32-byte keys are derived from the Noise handshake hash, which
//! only the two Noise parties know:
//!
//! * `resume`: proves possession of the session (client requests); it is
//!   never sent, only used to MAC `(sid, kind, ctr, ts, H(data))`, where
//!   `ctr` strictly increases per kind (replay protection) and `ts` must be
//!   within the handshake clock skew;
//! * `c2s` / `s2c`: MAC control messages per direction, so a message cannot
//!   be reflected back to its sender.
use cjs_proto::{encode, Mac};
use serde::Serialize;
use subtle::ConstantTimeEq;

const CTX_RESUME: &str = "clawdjumpserver transport v2 resume key";
const CTX_C2S: &str = "clawdjumpserver transport v2 client-to-server control key";
const CTX_S2C: &str = "clawdjumpserver transport v2 server-to-client control key";

#[derive(Clone)]
pub(crate) struct CtlKeys {
    pub resume: [u8; 32],
    /// MACs what this side sends.
    pub send: [u8; 32],
    /// Verifies what the peer sends.
    pub recv: [u8; 32],
}

impl CtlKeys {
    pub(crate) fn derive(handshake_hash: &[u8], initiator: bool) -> Self {
        let resume = blake3::derive_key(CTX_RESUME, handshake_hash);
        let c2s = blake3::derive_key(CTX_C2S, handshake_hash);
        let s2c = blake3::derive_key(CTX_S2C, handshake_hash);
        let (send, recv) = if initiator { (c2s, s2c) } else { (s2c, c2s) };
        Self { resume, send, recv }
    }
}

pub(crate) fn tag<T: Serialize + ?Sized>(key: &[u8; 32], label: &str, v: &T) -> Mac {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(label.as_bytes());
    h.update(&[0]);
    h.update(&encode(&v));
    *h.finalize().as_bytes()
}

pub(crate) fn check<T: Serialize + ?Sized>(key: &[u8; 32], label: &str, v: &T, mac: &[u8]) -> bool {
    check_raw(&tag(key, label, v), mac)
}

/// Constant-time comparison of an expected MAC with a received one.
pub(crate) fn check_raw(want: &Mac, got: &[u8]) -> bool {
    got.len() == 32 && bool::from(want.ct_eq(got))
}

/// MAC of an authenticated client request (resume or HTTP call).
pub(crate) fn request_tag(key: &[u8; 32], sid: &str, kind: &str, ctr: u64, ts: i64, data: &[u8]) -> Mac {
    let h = blake3::hash(data);
    tag(key, "request", &(sid, kind, ctr, ts, h.as_bytes()))
}

pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `<ctr>.<ts>.<hex mac>` header value.
pub(crate) fn auth_header(key: &[u8; 32], sid: &str, kind: &str, ctr: u64, data: &[u8]) -> String {
    let ts = now_unix();
    format!(
        "{ctr}.{ts}.{}",
        hex::encode(request_tag(key, sid, kind, ctr, ts, data))
    )
}

pub(crate) fn parse_auth_header(v: &str) -> Option<(u64, i64, Vec<u8>)> {
    let mut it = v.splitn(3, '.');
    let ctr = it.next()?.parse().ok()?;
    let ts = it.next()?.parse().ok()?;
    let mac = hex::decode(it.next()?).ok()?;
    Some((ctr, ts, mac))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directions_differ_and_match() {
        let c = CtlKeys::derive(b"hash", true);
        let s = CtlKeys::derive(b"hash", false);
        assert_eq!(c.send, s.recv);
        assert_eq!(c.recv, s.send);
        assert_ne!(c.send, c.recv);
        assert_eq!(c.resume, s.resume);
        let t = tag(&c.send, "ack", &5u64);
        assert!(check(&s.recv, "ack", &5u64, &t));
        assert!(!check(&s.recv, "ack", &6u64, &t));
        assert!(!check(&s.recv, "close", &5u64, &t));
        assert!(!check(&s.send, "ack", &5u64, &t), "reflection");
        assert!(!check(&s.recv, "ack", &5u64, &t[..31]));
    }

    #[test]
    fn header_roundtrip() {
        let k = [3u8; 32];
        let h = auth_header(&k, "sid", "tx", 7, b"body");
        let (ctr, ts, mac) = parse_auth_header(&h).unwrap();
        assert_eq!(ctr, 7);
        assert_eq!(mac, request_tag(&k, "sid", "tx", 7, ts, b"body"));
        assert_ne!(mac, request_tag(&k, "sid", "rx", 7, ts, b"body"));
        assert!(parse_auth_header("x.y.z").is_none());
    }
}
