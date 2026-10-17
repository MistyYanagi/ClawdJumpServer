//! The session core: sequence numbers, acknowledgements, the retransmit
//! buffer and Noise encryption with explicit nonces.
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use cjs_proto::{ErrorCode, ProtoError, MAX_FRAME_PLAINTEXT, NOISE_MAX_MSG};
use tokio::sync::{mpsc, watch};

/// Unacknowledged bytes we buffer before applying backpressure.
const MAX_UNACKED: usize = 8 * 1024 * 1024;

struct State {
    next_seq: u64,
    out: VecDeque<(u64, Vec<u8>)>,
    out_bytes: usize,
    acked: u64,
    recv_next: u64,
    closed: Option<ProtoError>,
    in_tx: Option<mpsc::UnboundedSender<Bytes>>,
}

pub(crate) struct Core {
    st: Mutex<State>,
    ver: watch::Sender<u64>,
    noise: snow::StatelessTransportState,
}

impl Core {
    pub(crate) fn new(noise: snow::StatelessTransportState) -> (Arc<Core>, mpsc::UnboundedReceiver<Bytes>) {
        let (in_tx, in_rx) = mpsc::unbounded_channel();
        let core = Core {
            st: Mutex::new(State {
                next_seq: 1,
                out: VecDeque::new(),
                out_bytes: 0,
                acked: 0,
                recv_next: 1,
                closed: None,
                in_tx: Some(in_tx),
            }),
            ver: watch::channel(0).0,
            noise,
        };
        (Arc::new(core), in_rx)
    }

    fn bump(&self) {
        self.ver.send_modify(|v| *v = v.wrapping_add(1));
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<u64> {
        self.ver.subscribe()
    }

    /// Encrypt and queue one plaintext chunk (<= MAX_FRAME_PLAINTEXT).
    pub(crate) async fn send(&self, pt: &[u8]) -> Result<(), ProtoError> {
        debug_assert!(pt.len() <= MAX_FRAME_PLAINTEXT);
        let mut ver = self.subscribe();
        loop {
            {
                let mut st = self.st.lock().unwrap();
                if let Some(e) = &st.closed {
                    return Err(e.clone());
                }
                if st.out_bytes < MAX_UNACKED {
                    let seq = st.next_seq;
                    let mut ct = vec![0u8; pt.len() + 16];
                    let n = self
                        .noise
                        .write_message(seq, pt, &mut ct)
                        .map_err(|e| ProtoError::new(ErrorCode::Internal, format!("encrypt: {e}")))?;
                    ct.truncate(n);
                    st.out_bytes += ct.len();
                    st.out.push_back((seq, ct));
                    st.next_seq += 1;
                    drop(st);
                    self.bump();
                    return Ok(());
                }
            }
            if ver.changed().await.is_err() {
                return Err(ProtoError::new(ErrorCode::Io, "session gone"));
            }
        }
    }

    /// Peer acknowledged everything up to and including `n`.
    pub(crate) fn ack(&self, n: u64) -> Result<(), ProtoError> {
        let mut st = self.st.lock().unwrap();
        if n >= st.next_seq {
            return Err(ProtoError::new(ErrorCode::Protocol, "ack beyond sent data"));
        }
        if n <= st.acked {
            return Ok(());
        }
        while let Some((seq, d)) = st.out.front() {
            if *seq > n {
                break;
            }
            st.out_bytes -= d.len();
            st.out.pop_front();
        }
        st.acked = n;
        drop(st);
        self.bump();
        Ok(())
    }

    pub(crate) fn acked(&self) -> u64 {
        self.st.lock().unwrap().acked
    }

    /// Handle an incoming segment.
    pub(crate) fn receive(&self, seq: u64, ct: &[u8]) -> Result<(), ProtoError> {
        let mut st = self.st.lock().unwrap();
        if st.closed.is_some() {
            return Ok(());
        }
        if seq < st.recv_next {
            return Ok(()); // duplicate after a resend
        }
        if seq > st.recv_next {
            return Err(ProtoError::new(ErrorCode::Protocol, "segment gap"));
        }
        if ct.len() > NOISE_MAX_MSG {
            return Err(ProtoError::new(ErrorCode::Protocol, "segment too large"));
        }
        let mut pt = vec![0u8; ct.len()];
        let n = self
            .noise
            .read_message(seq, ct, &mut pt)
            .map_err(|_| ProtoError::new(ErrorCode::Protocol, "segment failed authentication"))?;
        pt.truncate(n);
        st.recv_next += 1;
        if let Some(tx) = &st.in_tx {
            let _ = tx.send(Bytes::from(pt));
        }
        drop(st);
        self.bump();
        Ok(())
    }

    /// Highest segment received in order.
    pub(crate) fn recv_ack(&self) -> u64 {
        self.st.lock().unwrap().recv_next - 1
    }

    pub(crate) fn segs_after(&self, after: u64, max_bytes: usize) -> Vec<(u64, Vec<u8>)> {
        let st = self.st.lock().unwrap();
        let mut out = Vec::new();
        let mut total = 0;
        for (seq, d) in st.out.iter() {
            if *seq <= after {
                continue;
            }
            if total > 0 && total + d.len() > max_bytes {
                break;
            }
            total += d.len();
            out.push((*seq, d.clone()));
        }
        out
    }

    pub(crate) fn has_unacked(&self) -> bool {
        !self.st.lock().unwrap().out.is_empty()
    }

    pub(crate) fn close(&self, err: ProtoError) {
        let mut st = self.st.lock().unwrap();
        if st.closed.is_none() {
            st.closed = Some(err);
            st.in_tx = None;
        }
        drop(st);
        self.bump();
    }

    pub(crate) fn closed(&self) -> Option<ProtoError> {
        self.st.lock().unwrap().closed.clone()
    }

    /// Wait (bounded) until all sent data was acknowledged, then close.
    pub(crate) async fn finish(&self, err: ProtoError) {
        let mut ver = self.subscribe();
        let wait = async {
            while self.has_unacked() && self.closed().is_none() {
                if ver.changed().await.is_err() {
                    break;
                }
            }
        };
        let _ = tokio::time::timeout(Duration::from_secs(5), wait).await;
        self.close(err);
    }

    pub(crate) async fn wait_closed(&self) -> ProtoError {
        let mut ver = self.subscribe();
        loop {
            if let Some(e) = self.closed() {
                return e;
            }
            if ver.changed().await.is_err() {
                return ProtoError::new(ErrorCode::Io, "session gone");
            }
        }
    }
}

/// External control over a session: used to cut a session immediately (for
/// example when the account behind it is disabled).
#[derive(Clone)]
pub struct SessionHandle(pub(crate) Arc<Core>);

impl std::fmt::Debug for SessionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionHandle")
    }
}

impl SessionHandle {
    pub fn close(&self, err: ProtoError) {
        self.0.close(err)
    }

    pub fn is_closed(&self) -> bool {
        self.0.closed().is_some()
    }

    pub async fn closed(&self) -> ProtoError {
        self.0.wait_closed().await
    }
}
