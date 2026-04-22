//! Resolve a `peer` argument (as seen by `portl shell`, `exec`, `tcp`,
//! and `udp`) to a `PortlTicket` ready for handshake. v0.3.0 put this
//! behind a two-store lookup (`peers.json`, `tickets.json`) plus a raw
//! `endpoint_id` fallback for one-off dials. The old alias-store /
//! raw-ticket fallback surface is gone — tickets that aren't saved
//! locally have to be parsed via `ticket save <label> <string>` first.
//!
//! Resolution cascade (first match wins, each prints `using …` to
//! stderr so routing is always observable):
//!
//! 1. `<name>` matches a peer with `they_accept_from_me=true`
//!    (outbound / mutual / self) → mint a short-lived fresh ticket
//!    against that endpoint's address.
//! 2. `<name>` matches a ticket in the ticket store, unexpired →
//!    return the saved ticket as-is.
//! 3. `<name>` matches a peer with inbound-only relationship →
//!    hard error naming the asymmetry and the fix.
//! 4. `<name>` is 32-byte hex → mint a fresh ticket against that
//!    endpoint. Ephemeral dial path.
//! 5. `<name>` parses as a raw ticket string (`portl…`) → use it
//!    directly. This covers the bearer-ticket flow: a third party
//!    mints a ticket for you and you paste the whole string.
//! 6. Otherwise: hard error listing possible sources.
//!
//! Call sites: `shell::run`, `exec::run`, `tcp::run`, `udp::run`,
//! `status::run`.
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use iroh::address_lookup::AddressLookupFailed;
use iroh::endpoint::Connection;
use iroh_base::{EndpointAddr, EndpointId};
use iroh_tickets::Ticket;
use n0_future::StreamExt;
use portl_core::endpoint::Endpoint;
use portl_core::id::{Identity, store};
use portl_core::net::{PeerSession, open_ticket_v1};
use portl_core::peer_store::PeerStore;
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::{Capabilities, PortlTicket};
use portl_core::ticket_store::TicketStore;

pub(crate) struct ConnectedPeer {
    pub(crate) endpoint: iroh::Endpoint,
    pub(crate) connection: Connection,
    pub(crate) session: PeerSession,
}

pub(crate) fn resolve_identity_path(explicit: Option<&Path>) -> PathBuf {
    explicit
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os("PORTL_IDENTITY_KEY").map(PathBuf::from))
        .unwrap_or_else(store::default_path)
}

pub(crate) async fn connect_peer(peer: &str, caps: Capabilities) -> Result<ConnectedPeer> {
    let identity_path = resolve_identity_path(None);
    let identity = store::load(&identity_path).context("load local identity")?;
    let endpoint = bind_client_endpoint(&identity).await?;
    connect_peer_with_endpoint(peer, caps, &identity, &endpoint).await
}

pub(crate) async fn bind_client_endpoint(identity: &Identity) -> Result<iroh::Endpoint> {
    portl_agent::endpoint::bind(&portl_agent::AgentConfig::default(), identity)
        .await
        .context("bind client endpoint")
}

pub(crate) async fn connect_peer_with_endpoint(
    peer: &str,
    caps: Capabilities,
    identity: &Identity,
    endpoint: &iroh::Endpoint,
) -> Result<ConnectedPeer> {
    let endpoint_wrapper = Endpoint::from(endpoint.clone());
    let ticket = resolve_peer_ticket(peer, identity, endpoint, caps).await?;
    let (connection, session) = open_ticket_v1(&endpoint_wrapper, &ticket, &[], identity)
        .await
        .context("run ticket handshake")?;
    Ok(ConnectedPeer {
        endpoint: endpoint.clone(),
        connection,
        session,
    })
}

/// Run the v0.3.0 resolution cascade. Emits `using <source>` to
/// stderr on success so routing is auditable without a separate
/// `--explain` flag.
pub(crate) async fn resolve_peer_ticket(
    peer: &str,
    identity: &Identity,
    endpoint: &iroh::Endpoint,
    caps: Capabilities,
) -> Result<PortlTicket> {
    let peers = PeerStore::load(&PeerStore::default_path()).context("load peer store")?;
    let tickets = TicketStore::load(&TicketStore::default_path()).context("load ticket store")?;

    // 1) Peer store: outbound-capable entries get a fresh mint.
    if let Some(entry) = peers.get_by_label(peer) {
        if entry.last_hold_at.is_some() {
            bail!(
                "peer '{peer}' is currently held; resume it with `portl peer resume {peer}` \
                 before dialing"
            );
        }
        if entry.they_accept_from_me {
            eprintln!("using peer \"{peer}\"");
            let eid = entry.endpoint_id_bytes()?;
            let endpoint_id =
                EndpointId::from_bytes(&eid).context("peer endpoint_id is not a valid iroh id")?;
            let addr = resolve_endpoint_addr(endpoint, endpoint_id).await?;
            return mint_fresh(identity, addr, caps);
        }
        // Entry exists but is inbound-only: hard error with the fix.
        bail!(
            "peer '{peer}' is inbound-only — they accept from us, but we don't have \
             outbound authority to mint into them. Ask the peer to run \
             `portl ticket issue <caps> --ttl <dur> --to {our_eid}` and paste the ticket \
             back; then save it with `portl ticket save {peer} <ticket-string>`.",
            our_eid = hex::encode(identity.verifying_key())
        );
    }
    // 2) Ticket store: saved, unexpired ticket.
    if let Some(entry) = tickets.get(peer) {
        let now = unix_now()?;
        if entry.expires_at <= now {
            bail!(
                "ticket '{peer}' expired {ago}s ago; remove it with \
                 `portl ticket rm {peer}` or issue a new one",
                ago = now - entry.expires_at
            );
        }
        eprintln!("using ticket \"{peer}\"");
        let ticket = <PortlTicket as Ticket>::deserialize(&entry.ticket_string)
            .map_err(|err| anyhow!("stored ticket '{peer}' is malformed: {err}"))?;
        return Ok(ticket);
    }
    // 3) Raw endpoint_id (64 hex chars). Ephemeral one-off dial.
    if let Ok(endpoint_id) = parse_endpoint_id(peer) {
        eprintln!(
            "using raw endpoint \"{short}\"",
            short = &peer[..16.min(peer.len())]
        );
        let addr = resolve_endpoint_addr(endpoint, endpoint_id).await?;
        return mint_fresh(identity, addr, caps);
    }
    // 4) Raw ticket string (bearer-ticket flow: someone minted a
    //    ticket for you and you're pasting it as-is).
    if let Ok(ticket) = <PortlTicket as Ticket>::deserialize(peer) {
        eprintln!("using inline ticket");
        return Ok(ticket);
    }

    bail!(
        "unknown peer or ticket name '{peer}'. Options:\n  \
         - `portl peer ls` to see stored peers\n  \
         - `portl ticket ls` to see saved tickets\n  \
         - pass a 64-char hex endpoint_id for a one-off dial\n  \
         - pass a `portl…` ticket string directly\n  \
         - `portl peer add-unsafe-raw <endpoint_id> --label {peer} …` to pin"
    );
}

fn mint_fresh(identity: &Identity, addr: EndpointAddr, caps: Capabilities) -> Result<PortlTicket> {
    let now = unix_now()?;
    mint_root(identity.signing_key(), addr, caps, now, now + 300, None)
        .context("mint ephemeral peer ticket")
}

fn unix_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs())
}

async fn resolve_endpoint_addr(
    endpoint: &iroh::Endpoint,
    endpoint_id: EndpointId,
) -> Result<EndpointAddr> {
    let mut stream = endpoint
        .address_lookup()
        .context("access address lookup")?
        .resolve(endpoint_id);
    while let Some(item) = stream.next().await {
        match item {
            Ok(Ok(item)) => return Ok(item.into_endpoint_addr()),
            Ok(Err(_)) => {}
            Err(AddressLookupFailed::NoServiceConfigured { .. }) => {
                bail!("no discovery services configured")
            }
            Err(AddressLookupFailed::NoResults { errors, .. }) => {
                let detail = errors
                    .into_iter()
                    .map(|err| err.to_string())
                    .collect::<Vec<_>>()
                    .join("; ");
                bail!("discovery failed: {detail}")
            }
            Err(err) => return Err(anyhow!(err)),
        }
    }

    bail!("discovery returned no addresses")
}

fn parse_endpoint_id(spec: &str) -> Result<EndpointId> {
    let bytes = hex::decode(spec).context("endpoint id must be hex or a portl ticket URI")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("endpoint id must be exactly 32 bytes"))?;
    EndpointId::from_bytes(&bytes).context("invalid endpoint id")
}
