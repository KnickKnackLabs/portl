use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use iroh::endpoint::Connection;
use tracing::{instrument, warn};

use crate::AgentState;
use crate::audit;
use crate::meta_handler;
use crate::pipeline::{AcceptanceInput, AcceptanceOutcome, evaluate_offer};
use crate::session::Session;
use crate::session_handler;
use crate::shell_handler;
use crate::stream_io::read_postcard_prefix;
use crate::tcp_handler;
use crate::udp_handler::{self, UdpConnectionContext};

const MAX_OFFER_BYTES: usize = 64 * 1024;
const MAX_META_STREAMS: u32 = 64;
const MAX_PREAMBLE_BYTES: usize = 8 * 1024;

#[allow(clippy::too_many_lines)]
#[instrument(skip_all, fields(remote = %connection.remote_id().fmt_short()))]
pub(crate) async fn serve_connection(connection: Connection, state: Arc<AgentState>) -> Result<()> {
    connection.set_max_concurrent_bi_streams(MAX_META_STREAMS.into());

    let (mut send, mut recv) = connection
        .accept_bi()
        .await
        .context("accept offer stream")?;
    let offer_bytes = recv
        .read_to_end(MAX_OFFER_BYTES)
        .await
        .context("read offer stream")?;
    let source_id = remote_node_id(&connection);

    let outcome = match postcard::from_bytes::<portl_proto::ticket_v1::TicketOffer>(&offer_bytes) {
        Ok(offer) => {
            let revocations = state
                .revocations
                .read()
                .map_err(|_| anyhow!("revocations lock poisoned"))?;
            let trust_roots = state
                .trust_roots
                .read()
                .map_err(|_| anyhow!("trust roots lock poisoned"))?;
            evaluate_offer(&AcceptanceInput {
                offer: &offer,
                source_id,
                trust_roots: &trust_roots,
                revocations: &revocations,
                now: unix_now_secs()?,
                rate_limit: &state.rate_limit,
                mode: &state.mode,
            })
        }
        Err(_) => AcceptanceOutcome::Rejected {
            reason: portl_proto::ticket_v1::AckReason::BadSignature,
        },
    };

    let maybe_session = match &outcome {
        AcceptanceOutcome::Accepted {
            peer_token,
            caps,
            ticket_id,
            ticket_chain_ids,
            bearer,
        } => {
            let ack = portl_proto::ticket_v1::TicketAck {
                ok: true,
                reason: None,
                peer_token: Some(*peer_token),
                effective_caps: Some((**caps).clone()),
                server_time: unix_now_secs()?,
            };
            let bytes = postcard::to_stdvec(&ack).context("encode accepted ack")?;
            send.write_all(&bytes).await.context("write accepted ack")?;
            send.finish().context("finish accepted ack")?;
            let session = Session {
                peer_token: *peer_token,
                caps: (**caps).clone(),
                ticket_id: *ticket_id,
                ticket_chain_ids: ticket_chain_ids.clone(),
                caller_endpoint_id: source_id,
                bearer: bearer.clone(),
            };
            audit::ticket_accepted(&session);
            if source_id != state.self_endpoint_id {
                state
                    .network_watchdog
                    .record_inbound_handshake(SystemTime::now());
            }
            state.metrics.tickets_accepted.inc();
            // Track this connection in the registry so
            // `/status/connections` (and the derived
            // `portl_active_connections` gauge) reflect reality.
            // Keyed by `(eid, stable_id)` so N concurrent connections
            // from the same peer coexist.
            Some(session)
        }
        AcceptanceOutcome::Rejected { reason } => {
            state
                .metrics
                .tickets_rejected_total
                .get_or_create(&crate::metrics::AckReasonLabel {
                    reason: format!("{reason:?}"),
                })
                .inc();
            let ack = portl_proto::ticket_v1::TicketAck {
                ok: false,
                reason: Some(reason.clone()),
                peer_token: None,
                effective_caps: None,
                server_time: unix_now_secs()?,
            };
            let bytes = postcard::to_stdvec(&ack).context("encode rejected ack")?;
            send.write_all(&bytes).await.context("write rejected ack")?;
            send.finish().context("finish rejected ack")?;
            None
        }
    };

    let Some(session) = maybe_session else {
        connection.closed().await;
        return Ok(());
    };

    let udp_context = Arc::new(UdpConnectionContext::new(state.udp_registry.clone()));
    let conn_key = state.connections.insert(source_id, connection.clone());
    let _conn_registry_guard = ConnectionRegistryGuard {
        connections: state.connections.clone(),
        key: conn_key,
    };

    loop {
        let (send, recv) = match connection.accept_bi().await {
            Ok(streams) => streams,
            Err(err) => {
                warn!(?err, "stopping authenticated stream loop");
                return Ok(());
            }
        };

        let connection = connection.clone();
        let session = session.clone();
        let state = Arc::clone(&state);
        let udp_context = Arc::clone(&udp_context);
        tokio::spawn(async move {
            match read_postcard_prefix::<portl_proto::wire::StreamPreamble>(
                recv,
                MAX_PREAMBLE_BYTES,
            )
            .await
            {
                Ok((preamble, recv)) => {
                    let result = match preamble.alpn.as_str() {
                        value
                            if value
                                == String::from_utf8_lossy(portl_proto::meta_v1::ALPN_META_V1) =>
                        {
                            meta_handler::serve_stream(
                                connection, session, state, send, recv, preamble,
                            )
                            .await
                        }
                        value
                            if value
                                == String::from_utf8_lossy(
                                    portl_proto::shell_v1::ALPN_SHELL_V1,
                                ) =>
                        {
                            if let Err(error) = crate::alpn_allowed_in_mode(&state.mode, value) {
                                connection.close(0x1004u32.into(), error.as_bytes());
                                Ok(())
                            } else {
                                state.metrics.shell_sessions_opened.inc();
                                shell_handler::serve_stream(
                                    connection, session, state, send, recv, preamble,
                                )
                                .await
                            }
                        }
                        value
                            if value
                                == String::from_utf8_lossy(
                                    portl_proto::session_v1::ALPN_SESSION_V1,
                                ) =>
                        {
                            if let Err(error) = crate::alpn_allowed_in_mode(&state.mode, value) {
                                connection.close(0x1004u32.into(), error.as_bytes());
                                Ok(())
                            } else {
                                session_handler::serve_stream(
                                    connection, session, state, send, recv, preamble,
                                )
                                .await
                            }
                        }
                        value
                            if value
                                == String::from_utf8_lossy(portl_proto::tcp_v1::ALPN_TCP_V1) =>
                        {
                            state.metrics.tcp_streams_opened.inc();
                            match &state.mode {
                                crate::AgentMode::Listener => {
                                    tcp_handler::serve_stream(
                                        connection, session, state, send, recv, preamble,
                                    )
                                    .await
                                }
                                crate::AgentMode::Gateway { .. } => {
                                    crate::gateway::serve_stream(
                                        connection, session, state, send, recv, preamble,
                                    )
                                    .await
                                }
                            }
                        }
                        value
                            if value
                                == String::from_utf8_lossy(portl_proto::udp_v1::ALPN_UDP_V1) =>
                        {
                            if let Err(error) = crate::alpn_allowed_in_mode(&state.mode, value) {
                                connection.close(0x1004u32.into(), error.as_bytes());
                                Ok(())
                            } else {
                                state.metrics.udp_sessions_opened.inc();
                                udp_handler::serve_stream(
                                    connection,
                                    session,
                                    state,
                                    send,
                                    recv,
                                    preamble,
                                    udp_context,
                                )
                                .await
                            }
                        }
                        _ => {
                            connection.close(0x1003u32.into(), b"version mismatch");
                            Ok(())
                        }
                    };
                    if let Err(err) = result {
                        tracing::debug!(%err, "authenticated stream error");
                    }
                }
                Err(err) => tracing::debug!(%err, "failed to parse stream preamble"),
            }
        });
    }
}

fn unix_now_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs())
}

/// Drop the per-connection entry from `ConnectionRegistry` when the
/// authenticated stream loop exits, regardless of whether it exited
/// cleanly or via an error. The `active_connections` gauge is
/// derived from `registry.len()` at scrape time, so no manual
/// accounting is needed here.
struct ConnectionRegistryGuard {
    connections: crate::conn_registry::ConnectionRegistry,
    key: crate::conn_registry::ConnKey,
}

impl Drop for ConnectionRegistryGuard {
    fn drop(&mut self) {
        self.connections.remove(&self.key);
    }
}

fn remote_node_id(connection: &Connection) -> [u8; 32] {
    *connection.remote_id().as_bytes()
}
