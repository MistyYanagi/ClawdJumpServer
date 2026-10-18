//! Noise IK handshake helpers.
use cjs_proto::{
    decode, encode, ErrorCode, HandshakeReply, Hello, ProtoError, Welcome, NOISE_MAX_MSG, NOISE_PARAMS,
};

use crate::mac::CtlKeys;

fn perr(e: snow::Error) -> ProtoError {
    ProtoError::new(ErrorCode::Unauthenticated, format!("noise: {e}"))
}

pub(crate) struct ClientHs {
    hs: snow::HandshakeState,
}

/// Prologue binds the protocol name so cross-protocol replays fail.
const PROLOGUE: &[u8] = b"clawdjumpserver/v2";

impl ClientHs {
    pub(crate) fn start(
        local_private: &[u8; 32],
        server_public: &[u8; 32],
        hello: &Hello,
    ) -> Result<(Self, Vec<u8>), ProtoError> {
        let mut hs = snow::Builder::new(NOISE_PARAMS.parse().expect("params"))
            .local_private_key(local_private)
            .map_err(perr)?
            .remote_public_key(server_public)
            .map_err(perr)?
            .prologue(PROLOGUE)
            .map_err(perr)?
            .build_initiator()
            .map_err(perr)?;
        let mut buf = vec![0u8; NOISE_MAX_MSG];
        let n = hs.write_message(&encode(hello), &mut buf).map_err(perr)?;
        buf.truncate(n);
        Ok((Self { hs }, buf))
    }

    pub(crate) fn finish(
        mut self,
        msg2: &[u8],
    ) -> Result<(snow::StatelessTransportState, Welcome, CtlKeys), ProtoError> {
        let mut buf = vec![0u8; NOISE_MAX_MSG];
        let n = self.hs.read_message(msg2, &mut buf).map_err(|_| {
            ProtoError::new(
                ErrorCode::Unauthenticated,
                "server failed to prove its key (wrong server key or interception)",
            )
        })?;
        let reply: HandshakeReply = decode(&buf[..n])?;
        let welcome = match reply {
            HandshakeReply::Welcome(w) => w,
            HandshakeReply::Rejected(e) => return Err(e),
        };
        let keys = CtlKeys::derive(self.hs.get_handshake_hash(), true);
        let ts = self.hs.into_stateless_transport_mode().map_err(perr)?;
        Ok((ts, welcome, keys))
    }
}

pub(crate) struct ServerHsOutcome {
    pub msg2: Vec<u8>,
    /// `None` when the client was rejected (msg2 then carries the reason).
    pub session: Option<(snow::StatelessTransportState, Welcome, Hello, [u8; 32], CtlKeys)>,
    pub rejection: Option<ProtoError>,
}

/// Run the responder side. `auth` decides the reply.
pub(crate) fn respond(
    local_private: &[u8; 32],
    msg1: &[u8],
    auth: impl FnOnce(&[u8; 32], &Hello) -> Result<Welcome, ProtoError>,
) -> Result<ServerHsOutcome, ProtoError> {
    let mut hs = snow::Builder::new(NOISE_PARAMS.parse().expect("params"))
        .local_private_key(local_private)
        .map_err(perr)?
        .prologue(PROLOGUE)
        .map_err(perr)?
        .build_responder()
        .map_err(perr)?;
    let mut buf = vec![0u8; NOISE_MAX_MSG];
    // A failure here means the client did not encrypt to our key or sent
    // garbage; there is nothing to reply with.
    let n = hs.read_message(msg1, &mut buf).map_err(perr)?;
    let hello: Hello = decode(&buf[..n])?;
    let mut client_key = [0u8; 32];
    client_key.copy_from_slice(hs.get_remote_static().ok_or_else(|| perr(snow::Error::Input))?);
    let decision = auth(&client_key, &hello);
    let reply = match &decision {
        Ok(w) => HandshakeReply::Welcome(w.clone()),
        Err(e) => HandshakeReply::Rejected(e.clone()),
    };
    let mut out = vec![0u8; NOISE_MAX_MSG];
    let n = hs.write_message(&encode(&reply), &mut out).map_err(perr)?;
    out.truncate(n);
    match decision {
        Ok(w) => {
            let keys = CtlKeys::derive(hs.get_handshake_hash(), false);
            let ts = hs.into_stateless_transport_mode().map_err(perr)?;
            Ok(ServerHsOutcome {
                msg2: out,
                session: Some((ts, w, hello, client_key, keys)),
                rejection: None,
            })
        }
        Err(e) => Ok(ServerHsOutcome {
            msg2: out,
            session: None,
            rejection: Some(e),
        }),
    }
}
