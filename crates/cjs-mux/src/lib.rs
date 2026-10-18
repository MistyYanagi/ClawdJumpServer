//! Stream multiplexing for ClawdJumpServer.
//!
//! We use [yamux](https://github.com/libp2p/rust-yamux) (libp2p's
//! implementation) for multiplexing: it gives per-stream credit-based flow
//! control with auto-tuned receive windows, half-close and stream limits.
//! This crate wraps a yamux connection in a driver task and adds the small
//! framing layer every ClawdJumpServer stream uses on top of it:
//! length-prefixed postcard messages.
#![forbid(unsafe_code)]

use std::future::poll_fn;
use std::task::Poll;

use cjs_proto::{ErrorCode, ProtoError, MAX_STREAM_MSG};
use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

/// A multiplexed stream with tokio I/O traits.
pub type MuxStream = Compat<yamux::Stream>;

pub use yamux::Mode;

/// Maximum concurrent streams per connection.
pub const MAX_STREAMS: usize = 128;

/// Receive buffer budget of one connection, all streams together. yamux
/// guarantees every stream its 256 KiB minimum window (128 * 256 KiB =
/// 32 MiB); the remaining 16 MiB is shared by streams whose window
/// auto-tunes upwards, so one bulk stream can grow to about 16 MiB while a
/// peer can never make us buffer more than this per connection.
pub const MAX_CONNECTION_RECEIVE_WINDOW: usize = 48 * 1024 * 1024;

fn config() -> yamux::Config {
    let mut c = yamux::Config::default();
    // Order matters: yamux asserts window >= streams * 256 KiB on each set.
    c.set_max_num_streams(MAX_STREAMS);
    c.set_max_connection_receive_window(Some(MAX_CONNECTION_RECEIVE_WINDOW));
    c
}

/// Handle used to open outbound streams. Cheap to clone. The connection is
/// closed once every handle and the inbound receiver are dropped, or when
/// [`MuxHandle::close`] is called.
#[derive(Clone)]
pub struct MuxHandle {
    tx: mpsc::Sender<Cmd>,
}

impl std::fmt::Debug for MuxHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MuxHandle")
    }
}

enum Cmd {
    Open(oneshot::Sender<Result<MuxStream, ProtoError>>),
    Close,
}

fn closed_err() -> ProtoError {
    ProtoError::new(ErrorCode::Io, "connection closed")
}

impl MuxHandle {
    /// Open a new outbound stream.
    pub async fn open(&self) -> Result<MuxStream, ProtoError> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(Cmd::Open(tx)).await.map_err(|_| closed_err())?;
        rx.await.map_err(|_| closed_err())?
    }

    /// Gracefully close the connection.
    pub async fn close(&self) {
        let _ = self.tx.send(Cmd::Close).await;
    }

    /// True once the driver task has exited.
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }

    /// Resolves when the driver task has exited.
    pub async fn closed(&self) {
        self.tx.closed().await
    }
}

/// Run a yamux connection over `io`. Returns the handle for outbound
/// streams, the receiver of inbound streams, and the driver task (which
/// finishes when the connection ends).
pub fn spawn<T>(
    io: T,
    mode: Mode,
) -> (
    MuxHandle,
    mpsc::UnboundedReceiver<MuxStream>,
    tokio::task::JoinHandle<Result<(), ProtoError>>,
)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Cmd>(64);
    let (in_tx, in_rx) = mpsc::unbounded_channel();
    let mut conn = yamux::Connection::new(io.compat(), config(), mode);
    let task = tokio::spawn(async move {
        let mut pending: Option<oneshot::Sender<Result<MuxStream, ProtoError>>> = None;
        let mut closing = false;
        let res = poll_fn(|cx| {
            if closing {
                return match conn.poll_close(cx) {
                    Poll::Ready(r) => {
                        Poll::Ready(r.map_err(|e| ProtoError::new(ErrorCode::Io, e.to_string())))
                    }
                    Poll::Pending => Poll::Pending,
                };
            }
            // Outbound opens: one at a time, in request order.
            loop {
                if let Some(waiter) = pending.take() {
                    match conn.poll_new_outbound(cx) {
                        Poll::Ready(r) => {
                            let r = r
                                .map(|s| s.compat())
                                .map_err(|e| ProtoError::new(ErrorCode::LimitExceeded, e.to_string()));
                            let _ = waiter.send(r);
                            continue;
                        }
                        Poll::Pending => {
                            pending = Some(waiter);
                            break;
                        }
                    }
                }
                match cmd_rx.poll_recv(cx) {
                    Poll::Ready(Some(Cmd::Open(w))) => pending = Some(w),
                    Poll::Ready(Some(Cmd::Close)) | Poll::Ready(None) if in_tx.is_closed() => {
                        closing = true;
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    Poll::Ready(Some(Cmd::Close)) => {
                        closing = true;
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    // All handles dropped but inbound still consumed: keep running.
                    Poll::Ready(None) | Poll::Pending => break,
                }
            }
            // Inbound streams; this also drives all I/O of the connection.
            loop {
                match conn.poll_next_inbound(cx) {
                    Poll::Ready(Some(Ok(s))) => {
                        // If nobody listens for inbound streams, drop it (resets).
                        let _ = in_tx.send(s.compat());
                    }
                    Poll::Ready(Some(Err(e))) => {
                        return Poll::Ready(Err(ProtoError::new(ErrorCode::Io, e.to_string())));
                    }
                    Poll::Ready(None) => return Poll::Ready(Ok(())),
                    Poll::Pending => return Poll::Pending,
                }
            }
        })
        .await;
        if let Some(w) = pending.take() {
            let _ = w.send(Err(closed_err()));
        }
        tracing::debug!(?res, "mux connection ended");
        res
    });
    (MuxHandle { tx: cmd_tx }, in_rx, task)
}

/// Unwrap a [`MuxStream`] back into the raw futures-io yamux stream.
pub fn into_inner(s: MuxStream) -> yamux::Stream {
    s.into_inner()
}

/// Convert a raw yamux stream into a [`MuxStream`].
pub fn from_inner(s: yamux::Stream) -> MuxStream {
    s.compat()
}

// ---------------------------------------------------------------------------
// Message framing
// ---------------------------------------------------------------------------

/// Write one length-prefixed postcard message.
pub async fn write_msg<W, T>(w: &mut W, msg: &T) -> Result<(), ProtoError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = cjs_proto::encode(msg);
    write_raw_msg(w, &body).await
}

/// Write one length-prefixed raw message.
pub async fn write_raw_msg<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8]) -> Result<(), ProtoError> {
    if body.len() > MAX_STREAM_MSG {
        return Err(ProtoError::new(ErrorCode::LimitExceeded, "message too large"));
    }
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
    buf.extend_from_slice(body);
    w.write_all(&buf).await.map_err(io_err)?;
    w.flush().await.map_err(io_err)
}

/// Read one raw length-prefixed message. `Ok(None)` on clean EOF at a
/// message boundary.
pub async fn read_raw_msg<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>, ProtoError> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(io_err(e)),
    }
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_STREAM_MSG {
        return Err(ProtoError::new(ErrorCode::LimitExceeded, "message too large"));
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).await.map_err(io_err)?;
    Ok(Some(body))
}

/// Read one length-prefixed postcard message.
pub async fn read_msg<R, T>(r: &mut R) -> Result<Option<T>, ProtoError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    match read_raw_msg(r).await? {
        Some(b) => cjs_proto::decode(&b).map(Some),
        None => Ok(None),
    }
}

/// Read a message that must be present.
pub async fn expect_msg<R, T>(r: &mut R) -> Result<T, ProtoError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    read_msg(r)
        .await?
        .ok_or_else(|| ProtoError::new(ErrorCode::Protocol, "stream ended unexpectedly"))
}

pub fn io_err(e: std::io::Error) -> ProtoError {
    ProtoError::new(ErrorCode::Io, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn many_parallel_streams_over_one_pipe() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (client, _cin, _ct) = spawn(a, Mode::Client);
        let (_server, mut sin, _st) = spawn(b, Mode::Server);
        // Echo server.
        tokio::spawn(async move {
            while let Some(mut s) = sin.recv().await {
                tokio::spawn(async move {
                    while let Ok(Some(m)) = read_raw_msg(&mut s).await {
                        write_raw_msg(&mut s, &m).await.unwrap();
                    }
                    let _ = s.shutdown().await;
                });
            }
        });
        let mut tasks = Vec::new();
        for i in 0..50u32 {
            let c = client.clone();
            tasks.push(tokio::spawn(async move {
                let mut s = c.open().await.unwrap();
                for j in 0..20u32 {
                    let payload = vec![(i ^ j) as u8; 1000 + (j as usize * 100)];
                    write_raw_msg(&mut s, &payload).await.unwrap();
                    let back = read_raw_msg(&mut s).await.unwrap().unwrap();
                    assert_eq!(back, payload);
                }
                s.shutdown().await.unwrap();
                assert!(read_raw_msg(&mut s).await.unwrap().is_none());
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
    }

    #[tokio::test]
    async fn bulk_transfer_respects_backpressure() {
        let (a, b) = tokio::io::duplex(16 * 1024);
        let (client, _cin, _ct) = spawn(a, Mode::Client);
        let (_server, mut sin, _st) = spawn(b, Mode::Server);
        let reader = tokio::spawn(async move {
            let mut s = sin.recv().await.unwrap();
            let mut total = 0usize;
            let mut buf = vec![0u8; 8192];
            loop {
                let n = s.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                total += n;
                // Slow consumer.
                if total % (512 * 1024) < 8192 {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            }
            total
        });
        let mut s = client.open().await.unwrap();
        let chunk = vec![7u8; 64 * 1024];
        for _ in 0..128 {
            s.write_all(&chunk).await.unwrap();
        }
        s.shutdown().await.unwrap();
        assert_eq!(reader.await.unwrap(), 128 * 64 * 1024);
    }

    #[test]
    fn limits_are_bounded() {
        // Constructing the config runs yamux's own consistency assertions.
        let _ = config();
        assert!(MAX_STREAMS <= 128);
        assert!(MAX_CONNECTION_RECEIVE_WINDOW <= 64 * 1024 * 1024);
        assert!(MAX_CONNECTION_RECEIVE_WINDOW >= MAX_STREAMS * yamux::DEFAULT_CREDIT as usize);
    }

    #[tokio::test]
    async fn stream_count_is_capped() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (client, _cin, _ct) = spawn(a, Mode::Client);
        let (_server, mut sin, _st) = spawn(b, Mode::Server);
        tokio::spawn(async move {
            let mut keep = Vec::new();
            while let Some(s) = sin.recv().await {
                keep.push(s);
            }
        });
        let mut open = Vec::new();
        for _ in 0..MAX_STREAMS {
            let mut s = client.open().await.unwrap();
            // Make the stream known to the peer.
            s.write_all(b"x").await.unwrap();
            open.push(s);
        }
        assert!(
            client.open().await.is_err(),
            "more than MAX_STREAMS concurrent streams"
        );
    }

    #[tokio::test]
    async fn open_fails_after_peer_gone() {
        let (a, b) = tokio::io::duplex(1024);
        let (client, _cin, ct) = spawn(a, Mode::Client);
        drop(b);
        let _ = ct.await;
        assert!(client.open().await.is_err());
    }
}
