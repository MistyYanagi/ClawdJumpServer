//! Capability tokens. The server signs one per device stream after its
//! policy decision; the device verifies it again before doing anything.
use std::collections::HashMap;
use std::sync::Mutex;

use cjs_proto::{decode, encode, Action, Capability, ErrorCode, OpenRequest, ProtoError, SignedCapability};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

const DOMAIN: &[u8] = b"cjs-cap-v2";
pub const CAP_VERSION: u8 = 2;
/// Lifetime of a capability token: it only has to survive the open.
pub const CAP_TTL_SECS: i64 = 60;
const SKEW: i64 = 60;

pub fn sign(key: &SigningKey, cap: &Capability) -> SignedCapability {
    let body = encode(cap);
    let mut msg = DOMAIN.to_vec();
    msg.extend_from_slice(&body);
    SignedCapability {
        body,
        sig: key.sign(&msg).to_bytes().to_vec(),
    }
}

/// Hash binding a capability to one request (postcard encoding of the
/// request exactly as the device receives it).
pub fn request_hash(req: &OpenRequest) -> [u8; 32] {
    *blake3::Hasher::new_derive_key("ClawdJumpServer capability request v2")
        .update(&encode(req))
        .finalize()
        .as_bytes()
}

pub fn new_id() -> [u8; 16] {
    use rand::RngCore;
    let mut id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut id);
    id
}

fn deny(m: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::Forbidden, m)
}

/// Device-side verifier with replay protection.
pub struct CapVerifier {
    key: VerifyingKey,
    device_id: String,
    seen: Mutex<HashMap<[u8; 16], i64>>,
}

impl std::fmt::Debug for CapVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapVerifier")
            .field("device", &self.device_id)
            .finish()
    }
}

impl CapVerifier {
    pub fn new(key: VerifyingKey, device_id: impl Into<String>) -> Self {
        Self {
            key,
            device_id: device_id.into(),
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Verify `signed` for request `req` arriving on stream `stream` of
    /// connection `connection_id`. Returns the capability on success.
    pub fn verify(
        &self,
        signed: &SignedCapability,
        req: &OpenRequest,
        connection_id: &str,
        stream: u32,
        now: i64,
    ) -> Result<Capability, ProtoError> {
        let sig = ed25519_dalek::Signature::from_slice(&signed.sig)
            .map_err(|_| deny("malformed capability signature"))?;
        let mut msg = DOMAIN.to_vec();
        msg.extend_from_slice(&signed.body);
        self.key
            .verify(&msg, &sig)
            .map_err(|_| deny("capability signature invalid"))?;
        let cap: Capability = decode(&signed.body)?;
        if cap.version != CAP_VERSION {
            return Err(deny("unsupported capability version"));
        }
        if cap.device != self.device_id {
            return Err(deny("capability issued for another device"));
        }
        if cap.connection != connection_id {
            return Err(deny("capability bound to another connection"));
        }
        if cap.stream != stream {
            return Err(deny("capability bound to another stream"));
        }
        if now > cap.expires_at || now + SKEW < cap.issued_at || cap.expires_at - cap.issued_at > CAP_TTL_SECS
        {
            return Err(ProtoError::new(ErrorCode::Expired, "capability expired"));
        }
        let want: Option<Action> = req.action();
        if want != Some(cap.action) {
            return Err(deny("capability does not cover this action"));
        }
        if req.net_target() != cap.target {
            return Err(deny("capability does not cover this network target"));
        }
        if request_hash(req) != cap.req_hash {
            return Err(deny("capability was issued for a different request"));
        }
        if !cap.full_access && cap.action != Action::Egress && cap.roots.is_empty() {
            return Err(deny("capability has no project roots"));
        }
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        seen.retain(|_, exp| *exp >= now - SKEW);
        if seen.insert(cap.id, cap.expires_at).is_some() {
            return Err(ProtoError::new(ErrorCode::Replay, "capability replayed"));
        }
        Ok(cap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (SigningKey, CapVerifier, Capability, OpenRequest) {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let v = CapVerifier::new(key.verifying_key(), "d1");
        let req = OpenRequest::Exec {
            device: String::new(),
            argv: vec!["ls".into()],
            cwd: None,
            env: vec![],
            timeout_secs: None,
        };
        let cap = Capability {
            version: CAP_VERSION,
            id: new_id(),
            principal: "a1".into(),
            device: "d1".into(),
            action: Action::Exec,
            roots: vec!["/work".into()],
            full_access: false,
            issued_at: 1000,
            expires_at: 1000 + CAP_TTL_SECS,
            stream: 1,
            connection: "c1".into(),
            target: None,
            session: "s1".into(),
            net_rules: None,
            req_hash: request_hash(&req),
        };
        (key, v, cap, req)
    }

    #[test]
    fn valid_once() {
        let (k, v, cap, req) = setup();
        let s = sign(&k, &cap);
        assert!(v.verify(&s, &req, "c1", 1, 1010).is_ok());
        assert_eq!(
            v.verify(&s, &req, "c1", 1, 1011).unwrap_err().code,
            ErrorCode::Replay
        );
    }

    #[test]
    fn forged_and_out_of_scope_rejected() {
        let (k, v, cap, req) = setup();
        // Forged by another key.
        let other = SigningKey::generate(&mut rand::rngs::OsRng);
        assert!(v.verify(&sign(&other, &cap), &req, "c1", 1, 1010).is_err());
        // Tampered body.
        let mut s = sign(&k, &cap);
        let mut c2 = cap.clone();
        c2.full_access = true;
        s.body = encode(&c2);
        assert!(v.verify(&s, &req, "c1", 1, 1010).is_err());
        // Wrong device, connection, action, expiry.
        let mut c = cap.clone();
        c.device = "d2".into();
        assert!(v.verify(&sign(&k, &c), &req, "c1", 1, 1010).is_err());
        assert!(v.verify(&sign(&k, &cap), &req, "c2", 1, 1010).is_err());
        let mut c = cap.clone();
        c.id = new_id();
        c.action = Action::Shell;
        assert!(v.verify(&sign(&k, &c), &req, "c1", 1, 1010).is_err());
        let mut c = cap.clone();
        c.id = new_id();
        assert_eq!(
            v.verify(&sign(&k, &c), &req, "c1", 1, 2000).unwrap_err().code,
            ErrorCode::Expired
        );
        let mut c = cap;
        c.id = new_id();
        c.expires_at = c.issued_at + 3600;
        assert!(
            v.verify(&sign(&k, &c), &req, "c1", 1, 1010).is_err(),
            "overlong ttl"
        );
    }

    #[test]
    fn stream_bound() {
        let (k, v, cap, req) = setup();
        assert!(v.verify(&sign(&k, &cap), &req, "c1", 2, 1010).is_err());
    }

    #[test]
    fn net_target_bound() {
        let (k, v, mut cap, _) = setup();
        cap.action = Action::ForwardLocal;
        cap.target = Some("127.0.0.1:8080".into());
        let ok = OpenRequest::ForwardL {
            device: String::new(),
            host: "127.0.0.1".into(),
            port: 8080,
        };
        let bad = OpenRequest::ForwardL {
            device: String::new(),
            host: "127.0.0.1".into(),
            port: 22,
        };
        cap.req_hash = request_hash(&ok);
        assert!(v.verify(&sign(&k, &cap), &bad, "c1", 1, 1010).is_err());
        cap.id = new_id();
        assert!(v.verify(&sign(&k, &cap), &ok, "c1", 1, 1010).is_ok());
    }

    #[test]
    fn request_bound() {
        let (k, v, cap, _) = setup();
        let other = OpenRequest::Exec {
            device: String::new(),
            argv: vec!["rm".into(), "-rf".into(), ".".into()],
            cwd: None,
            env: vec![],
            timeout_secs: None,
        };
        let e = v.verify(&sign(&k, &cap), &other, "c1", 1, 1010).unwrap_err();
        assert_eq!(e.code, ErrorCode::Forbidden);
    }
}
