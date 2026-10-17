//! Byte-stream view of a session (tokio `AsyncRead` + `AsyncWrite`).
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use bytes::{Buf, Bytes};
use cjs_proto::{ErrorCode, ProtoError, MAX_FRAME_PLAINTEXT};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

use crate::core::{Core, SessionHandle};

pub struct SessionIo {
    rx: mpsc::UnboundedReceiver<Bytes>,
    cur: Bytes,
    tx: PollSender<Bytes>,
    handle: SessionHandle,
}

impl std::fmt::Debug for SessionIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionIo")
    }
}

impl SessionIo {
    pub(crate) fn new(core: Arc<Core>, rx: mpsc::UnboundedReceiver<Bytes>) -> Self {
        let (tx, mut wrx) = mpsc::channel::<Bytes>(32);
        let c = core.clone();
        tokio::spawn(async move {
            while let Some(b) = wrx.recv().await {
                for chunk in b.chunks(MAX_FRAME_PLAINTEXT) {
                    if c.send(chunk).await.is_err() {
                        return;
                    }
                }
            }
            // Writer shut down or dropped: graceful end of session.
            c.finish(ProtoError::new(ErrorCode::Cancelled, "session closed"))
                .await;
        });
        Self {
            rx,
            cur: Bytes::new(),
            tx: PollSender::new(tx),
            handle: SessionHandle(core),
        }
    }

    pub fn handle(&self) -> SessionHandle {
        self.handle.clone()
    }
}

impl AsyncRead for SessionIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.cur.is_empty() {
                let n = self.cur.len().min(buf.remaining());
                buf.put_slice(&self.cur[..n]);
                self.cur.advance(n);
                return Poll::Ready(Ok(()));
            }
            match ready!(self.rx.poll_recv(cx)) {
                Some(b) => self.cur = b,
                None => return Poll::Ready(Ok(())), // EOF
            }
        }
    }
}

impl AsyncWrite for SessionIo {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if let Some(e) = self.handle.0.closed() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e.to_string())));
        }
        if ready!(self.tx.poll_reserve(cx)).is_err() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let n = buf.len().min(256 * 1024);
        if self.tx.send_item(Bytes::copy_from_slice(&buf[..n])).is_err() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.tx.close();
        Poll::Ready(Ok(()))
    }
}
