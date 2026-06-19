use std::time::Instant;

use anyhow::{Context, Result, bail};
use iroh::endpoint::Connection;

use crate::endpoint::Endpoint;
use crate::id::Identity;
use crate::ticket::hash::{client_nonce_log_hash, ticket_id};
use crate::ticket::offer::compute_pop_sig;
use crate::ticket::schema::{Capabilities, PortlTicket};
use crate::wire::{AckReason, TicketAck, TicketOffer};

const MAX_ACK_BYTES: usize = 64 * 1024;

fn elapsed_millis_u64(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSession {
    pub peer_token: [u8; 16],
    pub effective_caps: Capabilities,
    pub server_time: u64,
    pub client_nonce_hash: [u8; 16],
    pub supported_alpns: Vec<String>,
}

impl PeerSession {
    #[must_use]
    pub fn supports_alpn(&self, alpn: &[u8]) -> bool {
        let alpn = String::from_utf8_lossy(alpn);
        self.supported_alpns
            .iter()
            .any(|candidate| candidate == alpn.as_ref())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketHandshakeError {
    pub reason: Option<AckReason>,
}

impl std::fmt::Display for TicketHandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.reason {
            Some(reason) => write!(f, "ticket handshake rejected: {reason:?}"),
            None => write!(f, "ticket handshake rejected"),
        }
    }
}

impl std::error::Error for TicketHandshakeError {}

fn log_ticket_handshake_start(endpoint_id: &str, ticket_id_hex: &str, chain_len: usize) {
    tracing::info!(
        event = "portl.ticket_handshake.start",
        endpoint = %endpoint_id,
        chain_len,
    );
    tracing::info!(
        target: crate::transport_telemetry::TARGET,
        event = "transport.ticket_handshake.start",
        schema_version = crate::transport_telemetry::SCHEMA_VERSION,
        role = "cli",
        process_id = std::process::id(),
        endpoint = %endpoint_id,
        ticket_id = %ticket_id_hex,
        chain_len,
    );
}

fn log_ticket_handshake_connected(
    endpoint_id: &str,
    ticket_id_hex: &str,
    connection: &Connection,
    started: Instant,
) {
    tracing::info!(
        event = "portl.ticket_handshake.connected",
        remote = %connection.remote_id().fmt_short(),
        duration_ms = elapsed_millis_u64(started),
    );
    tracing::info!(
        target: crate::transport_telemetry::TARGET,
        event = "transport.ticket_handshake.connected",
        schema_version = crate::transport_telemetry::SCHEMA_VERSION,
        role = "cli",
        process_id = std::process::id(),
        endpoint = %endpoint_id,
        remote = %connection.remote_id().fmt_short(),
        ticket_id = %ticket_id_hex,
        duration_ms = elapsed_millis_u64(started),
    );
}

fn log_ticket_handshake_ack(
    endpoint_id: &str,
    ticket_id_hex: &str,
    client_nonce_hash_hex: &str,
    connection: &Connection,
    started: Instant,
    ack: &TicketAck,
) {
    tracing::info!(
        event = "portl.ticket_handshake.ack",
        ok = ack.ok,
        reason = ?ack.reason,
        duration_ms = elapsed_millis_u64(started),
    );
    tracing::info!(
        target: crate::transport_telemetry::TARGET,
        event = "transport.ticket_handshake.ack",
        schema_version = crate::transport_telemetry::SCHEMA_VERSION,
        role = "cli",
        process_id = std::process::id(),
        endpoint = %endpoint_id,
        remote = %connection.remote_id().fmt_short(),
        ticket_id = %ticket_id_hex,
        client_nonce_hash = %client_nonce_hash_hex,
        ok = ack.ok,
        reason = ?ack.reason,
        duration_ms = elapsed_millis_u64(started),
    );
}

fn log_ticket_handshake_rejected(
    endpoint_id: &str,
    ticket_id_hex: &str,
    client_nonce_hash_hex: &str,
    connection: &Connection,
    started: Instant,
    ack: &TicketAck,
) {
    tracing::warn!(
        event = "portl.ticket_handshake.rejected",
        reason = ?ack.reason,
        duration_ms = elapsed_millis_u64(started),
    );
    tracing::warn!(
        target: crate::transport_telemetry::TARGET,
        event = "transport.ticket_handshake.rejected",
        schema_version = crate::transport_telemetry::SCHEMA_VERSION,
        role = "cli",
        process_id = std::process::id(),
        endpoint = %endpoint_id,
        remote = %connection.remote_id().fmt_short(),
        ticket_id = %ticket_id_hex,
        client_nonce_hash = %client_nonce_hash_hex,
        reason = ?ack.reason,
        duration_ms = elapsed_millis_u64(started),
    );
}

pub async fn open_ticket_v1(
    endpoint: &Endpoint,
    ticket: &PortlTicket,
    chain: &[PortlTicket],
    identity: &Identity,
) -> Result<(Connection, PeerSession)> {
    // NOTE: we used to `await endpoint.inner().online()` here to
    // ensure a relay was connected before dialing. That call has an
    // iroh 0.98.x bug (see crash on `Endpoint::online` /
    // `endpoint.rs:1291`): when `any()` on the home-relay-status
    // Flatten iterator short-circuits, dropping the underlying
    // `Vec<Option<(RelayUrl, HomeRelayStatus)>>` aborts the process
    // with `malloc: pointer being freed was not allocated` on
    // macOS. `Endpoint::connect()` already picks a relay on its own
    // if one isn't yet connected, so skipping the pre-wait costs us
    // only a tiny bit of first-dial latency in exchange for not
    // crashing the CLI. Drop this workaround once we move to an
    // iroh release that fixes the `online()` drop path.
    let started = Instant::now();
    let endpoint_id = hex::encode(ticket.addr.id.as_bytes());
    let ticket_id_bytes = ticket_id(&ticket.sig);
    let ticket_id_hex = hex::encode(ticket_id_bytes);
    log_ticket_handshake_start(&endpoint_id, &ticket_id_hex, chain.len());
    tracing::debug!(
        endpoint = %endpoint_id,
        "connecting ticket/v1"
    );
    let connection = endpoint
        .inner()
        .connect(ticket.addr.clone(), portl_alpn::ALPN_TICKET_V1)
        .await
        .context("connect ticket/v1")?;
    log_ticket_handshake_connected(&endpoint_id, &ticket_id_hex, &connection, started);
    tracing::debug!(remote = %connection.remote_id().fmt_short(), "connected ticket/v1");
    let (mut send, mut recv) = connection.open_bi().await.context("open ticket stream")?;

    let client_nonce = rand::random::<[u8; 16]>();
    let client_nonce_hash = client_nonce_log_hash(&client_nonce);
    let client_nonce_hash_hex = hex::encode(client_nonce_hash);
    let proof = ticket
        .body
        .to
        .map(|_| compute_pop_sig(identity.signing_key(), &ticket_id_bytes, &client_nonce));
    let offer = TicketOffer {
        ticket: crate::ticket::encode(ticket).context("encode terminal ticket")?,
        chain: chain
            .iter()
            .map(|ticket| crate::ticket::encode(ticket).context("encode chain ticket"))
            .collect::<Result<Vec<_>>>()?,
        proof,
        client_nonce,
    };

    let offer_bytes = postcard::to_stdvec(&offer).context("encode ticket offer")?;
    send.write_all(&offer_bytes).await.context("write offer")?;
    send.finish().context("finish offer")?;

    tracing::debug!(offer_bytes = offer_bytes.len(), "sent ticket offer");
    let ack_bytes = recv.read_to_end(MAX_ACK_BYTES).await.context("read ack")?;
    let ack: TicketAck = postcard::from_bytes(&ack_bytes).context("decode ticket ack")?;
    log_ticket_handshake_ack(
        &endpoint_id,
        &ticket_id_hex,
        &client_nonce_hash_hex,
        &connection,
        started,
        &ack,
    );
    tracing::debug!(ok = ack.ok, reason = ?ack.reason, "received ticket ack");
    if !ack.ok {
        log_ticket_handshake_rejected(
            &endpoint_id,
            &ticket_id_hex,
            &client_nonce_hash_hex,
            &connection,
            started,
            &ack,
        );
        return Err(TicketHandshakeError { reason: ack.reason }.into());
    }

    let peer_token = ack
        .peer_token
        .context("missing peer_token in accepted ack")?;
    let effective_caps = ack
        .effective_caps
        .context("missing effective_caps in accepted ack")?;
    if ack.reason.is_some() {
        bail!("accepted ack unexpectedly carried a rejection reason");
    }

    Ok((
        connection,
        PeerSession {
            peer_token,
            effective_caps,
            server_time: ack.server_time,
            client_nonce_hash,
            supported_alpns: Vec::new(),
        },
    ))
}

mod portl_alpn {
    pub const ALPN_TICKET_V1: &[u8] = b"portl/ticket/v1";
}
