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
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::{Capabilities, PortlTicket};

use crate::alias_store::AliasStore;

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

pub(crate) async fn resolve_peer_ticket(
    peer: &str,
    identity: &Identity,
    endpoint: &iroh::Endpoint,
    caps: Capabilities,
) -> Result<PortlTicket> {
    if let Ok(ticket) = <PortlTicket as Ticket>::deserialize(peer) {
        return Ok(ticket);
    }

    if let Some(alias) = AliasStore::default().get(peer)? {
        if let Some(spec) = AliasStore::default().get_spec(peer)?
            && let Some(ticket_path) = spec.ticket_file_path
        {
            let raw = std::fs::read_to_string(&ticket_path)
                .with_context(|| format!("read stored ticket {}", ticket_path.display()))?;
            return <PortlTicket as Ticket>::deserialize(raw.trim())
                .map_err(|err| anyhow!("parse stored ticket {}: {err}", ticket_path.display()));
        }
        let endpoint_id = parse_endpoint_id(&alias.endpoint_id)?;
        let addr = resolve_endpoint_addr(endpoint, endpoint_id).await?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before unix epoch")?
            .as_secs();
        return mint_root(identity.signing_key(), addr, caps, now, now + 300, None)
            .context("mint ephemeral peer ticket");
    }

    let endpoint_id = parse_endpoint_id(peer)?;
    let addr = resolve_endpoint_addr(endpoint, endpoint_id).await?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs();
    mint_root(identity.signing_key(), addr, caps, now, now + 300, None)
        .context("mint ephemeral peer ticket")
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
