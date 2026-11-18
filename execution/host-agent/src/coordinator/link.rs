//! The core's side of the edge ↔ core channel.
//!
//! The core reads **validated commands** from the edge — never bytes from a peer (PD-2, T-SEC-01) —
//! and answers them. Each request runs in its own task, so one slow operation does not delay
//! another caller's answer; the edge's connection limit bounds how many can be in flight.

use std::sync::Arc;

use acf_wire::frame::aio;
use tokio::{net::UnixStream, sync::mpsc};
use tokio_util::sync::CancellationToken;

use super::Host;
use crate::{
    api::MAX_RESPONSE_FRAME,
    edge::{
        CoreMessage, EdgeMessage, EdgeStats,
        channel::{CHANNEL_SLACK, MAX_CONTROL_FRAME},
    },
};

impl Host {
    /// §24.3: what the edge refused before authentication is a standing-risk measurement.
    fn record_edge_stats(&self, s: &EdgeStats) {
        let m = &self.telemetry.metrics;
        m.incr("edge_connections_accepted", s.accepted);
        m.incr("connections_shed", s.shed + s.per_source_refused);
        m.incr("handshake_failures", s.handshake_failures);
        m.incr("auth_denied", s.auth_denied);
        m.incr("refusals_before_authentication", s.refused_before_authentication());
        m.incr("invalid_requests", s.invalid_requests);
        m.incr("requests_relayed", s.relayed);
        m.incr("responses_lost_at_edge", s.unanswered);
    }

    /// Serve the edge until `shutdown`, or until the edge goes away. Also pushes enrolment changes
    /// to the edge (AU-5): `enrolment_changed` yields each time the core installed a new table.
    pub async fn serve_edge(self: Arc<Self>, channel: UnixStream, mut enrolment_changed: mpsc::Receiver<()>, shutdown: CancellationToken) {
        let (mut from_edge, mut to_edge) = channel.into_split();
        let (answers, mut outbox) = mpsc::channel::<CoreMessage>(self.cfg.edge.max_connections.max(1) * 2);
        let writer = tokio::spawn(async move {
            while let Some(msg) = outbox.recv().await {
                let last = matches!(msg, CoreMessage::Shutdown);
                if aio::send_json(&mut to_edge, &msg, MAX_RESPONSE_FRAME + CHANNEL_SLACK).await.is_err() || last {
                    break;
                }
            }
        });
        let max_request = self.cfg.edge.max_request_bytes.max(MAX_CONTROL_FRAME) + CHANNEL_SLACK;
        loop {
            let msg = tokio::select! {
                () = shutdown.cancelled() => break,
                Some(()) = enrolment_changed.recv() => {
                    let _ = answers.send(CoreMessage::Enrolment { doc: self.enrolment().doc().clone() }).await;
                    continue;
                }
                m = aio::recv_json::<_, EdgeMessage>(&mut from_edge, max_request) => m,
            };
            match msg {
                Ok(EdgeMessage::Request { id, peer, envelope }) => {
                    let (me, answers) = (Arc::clone(&self), answers.clone());
                    tokio::spawn(async move {
                        let response = me.handle(&peer, *envelope).await;
                        let _ = answers.send(CoreMessage::Response { id, response: Box::new(response) }).await;
                    });
                }
                Ok(EdgeMessage::Stats { stats }) => self.record_edge_stats(&stats),
                Err(e) => {
                    if !shutdown.is_cancelled() {
                        tracing::error!(error = %e, "the edge channel closed; no ingress endpoint is being served");
                        self.telemetry.metrics.incr("edge_channel_lost", 1);
                    }
                    break;
                }
            }
        }
        let _ = answers.send(CoreMessage::Shutdown).await;
        drop(answers);
        let _ = writer.await;
    }
}
