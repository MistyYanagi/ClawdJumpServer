//! Pumping a session over one message link (a WebSocket). Used by both the
//! client and the server.
use std::sync::Arc;
use std::time::{Duration, Instant};

use cjs_proto::WireMsg;
use futures::{Sink, SinkExt, Stream, StreamExt};
use tokio::sync::watch;

use crate::core::Core;

/// Link considered dead after this long without hearing from the peer.
pub(crate) const LINK_IDLE: Duration = Duration::from_secs(40);
const KEEPALIVE: Duration = Duration::from_secs(10);
const ACK_EVERY: u64 = 16;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LinkEnd {
    /// The session itself ended.
    Closed,
    /// The link broke; the session may be resumed.
    Lost,
    /// Another link took over the session.
    Superseded,
}

pub(crate) async fn run_link<S, R>(
    core: Arc<Core>,
    mut sink: S,
    mut stream: R,
    peer_ack: u64,
    mut superseded: watch::Receiver<u64>,
) -> LinkEnd
where
    S: Sink<WireMsg> + Unpin,
    R: Stream<Item = WireMsg> + Unpin,
{
    // `peer_ack` was authenticated by the resume exchange.
    if let Err(e) = core.ack(peer_ack) {
        core.close(e.clone());
        let _ = sink.send(core.close_msg(e)).await;
        return LinkEnd::Closed;
    }
    let my_gen = *superseded.borrow_and_update();
    let last_rx = std::sync::Mutex::new(Instant::now());

    // Reader and writer run concurrently so neither side can deadlock on
    // full socket buffers.
    let reader = async {
        loop {
            let Some(m) = stream.next().await else {
                return LinkEnd::Lost;
            };
            // Anything that is not authenticated only ends this link (the
            // session is then resumed); it can never close the session.
            match m {
                WireMsg::Seg { seq, data } => {
                    if let Err(e) = core.receive(seq, &data) {
                        tracing::warn!(err = %e, "rejected segment; dropping link");
                        return LinkEnd::Lost;
                    }
                }
                WireMsg::Ack { n, mac } => {
                    if !core.check_ack(n, &mac) {
                        tracing::warn!("unauthenticated ack; dropping link");
                        return LinkEnd::Lost;
                    }
                    if let Err(e) = core.ack(n) {
                        core.close(e);
                        return LinkEnd::Closed;
                    }
                }
                WireMsg::Close { err, mac } => {
                    if !core.check_close(&err, &mac) {
                        tracing::warn!(err = %err, "unauthenticated close ignored; dropping link");
                        return LinkEnd::Lost;
                    }
                    core.close(err);
                    return LinkEnd::Closed;
                }
                _ => {
                    tracing::warn!("unexpected message on link; dropping link");
                    return LinkEnd::Lost;
                }
            }
            *last_rx.lock().unwrap() = Instant::now();
        }
    };

    let writer = async {
        let mut sent = peer_ack;
        let mut ver = core.subscribe();
        let mut last_ack_sent = u64::MAX;
        let mut last_tx = Instant::now();
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            if let Some(e) = core.closed() {
                let _ = sink.send(core.close_msg(e)).await;
                return LinkEnd::Closed;
            }
            let mut wrote = false;
            let a = core.recv_ack();
            if last_ack_sent == u64::MAX || a >= last_ack_sent.saturating_add(ACK_EVERY) {
                if sink.feed(core.ack_msg(a)).await.is_err() {
                    return LinkEnd::Lost;
                }
                last_ack_sent = a;
                wrote = true;
            }
            for (seq, data) in core.segs_after(sent, 256 * 1024) {
                if sink.feed(WireMsg::Seg { seq, data }).await.is_err() {
                    return LinkEnd::Lost;
                }
                sent = seq;
                wrote = true;
            }
            if wrote {
                if sink.flush().await.is_err() {
                    return LinkEnd::Lost;
                }
                last_tx = Instant::now();
                continue;
            }
            tokio::select! {
                r = ver.changed() => {
                    if r.is_err() { return LinkEnd::Closed; }
                }
                r = superseded.changed() => {
                    if r.is_err() || *superseded.borrow() != my_gen {
                        return LinkEnd::Superseded;
                    }
                }
                _ = tick.tick() => {
                    let a = core.recv_ack();
                    if a != last_ack_sent || last_tx.elapsed() >= KEEPALIVE {
                        if sink.send(core.ack_msg(a)).await.is_err() { return LinkEnd::Lost; }
                        last_ack_sent = a;
                        last_tx = Instant::now();
                    }
                    if last_rx.lock().unwrap().elapsed() > LINK_IDLE {
                        return LinkEnd::Lost;
                    }
                }
            }
        }
    };

    tokio::select! {
        e = reader => {
            if e == LinkEnd::Closed {
                // Tell the peer why, best effort.
                if let Some(err) = core.closed() {
                    let _ = sink.send(core.close_msg(err)).await;
                }
            }
            e
        }
        e = writer => e,
    }
}
