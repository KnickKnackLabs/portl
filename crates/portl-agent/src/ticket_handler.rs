use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use iroh::endpoint::Connection;
use tracing::{instrument, warn};

use crate::AgentState;
use crate::audit;
use crate::meta_handler;
use crate::pipeline::{AcceptanceInput, AcceptanceOutcome, evaluate_offer};
use crate::session::Session;
use crate::shell_handler;
use crate::stream_io::read_postcard_prefix;
use crate::tcp_handler;

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
        Ok(offer) => evaluate_offer(&AcceptanceInput {
            offer: &offer,
            source_id,
            trust_roots: &state.trust_roots,
            revocations: &state.revocations,
            now: unix_now_secs()?,
            rate_limit: &state.rate_limit,
        }),
        Err(_) => AcceptanceOutcome::Rejected {
            reason: portl_proto::ticket_v1::AckReason::BadSignature,
        },
    };

    let maybe_session = match &outcome {
        AcceptanceOutcome::Accepted {
            peer_token,
            caps,
            ticket_id,
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
                caller_endpoint_id: source_id,
            };
            audit::ticket_accepted(&session);
            Some(session)
        }
        AcceptanceOutcome::Rejected { reason } => {
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
                            shell_handler::serve_stream(
                                connection, session, state, send, recv, preamble,
                            )
                            .await
                        }
                        value
                            if value
                                == String::from_utf8_lossy(portl_proto::tcp_v1::ALPN_TCP_V1) =>
                        {
                            tcp_handler::serve_stream(
                                connection, session, state, send, recv, preamble,
                            )
                            .await
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

fn remote_node_id(connection: &Connection) -> [u8; 32] {
    *connection.remote_id().as_bytes()
}
