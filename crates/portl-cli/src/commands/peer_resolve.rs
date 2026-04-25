//! Resolve a `peer` argument to a `PortlTicket` ready for handshake.
//!
//! Single resolution cascade shared by every command that takes a
//! `<peer>` argument (`shell`, `exec`, `tcp`, `udp`, `forward`,
//! `status`, `docker run`, …). Each step prints `using …` to stderr
//! so routing is always observable. First match wins:
//!
//! 1. **Inline ticket** — `peer` deserializes as a full `portl…`
//!    ticket string. Used as-is (optionally force-relay-ed).
//! 2. **Label → `peers.json`** — a paired peer with
//!    `they_accept_from_me=true` mints a short-lived fresh ticket
//!    against that endpoint. Inbound-only or held peers return a
//!    specific error naming the fix.
//! 3. **Label → `tickets.json`** — a saved, unexpired ticket is
//!    returned as-is.
//! 4. **Label → `aliases.json`** — a container-adapter alias either
//!    points to a stored ticket file or supplies a bare
//!    `endpoint_id` to mint against.
//! 5. **Endpoint-id token** — full 64-char hex or middle-elided
//!    `PPPP…SSSS` (via `crate::eid::resolve`) mints an ephemeral
//!    ticket against that endpoint.
//! 6. Otherwise: hard error listing possible sources.
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
use tracing::debug;

use crate::alias_store::AliasStore;

/// Which store a `resolve_peer` call matched in. Surfaced in
/// `ResolvedPeer.source` for callers that want to report it, and
/// used internally to shape the "using …" stderr message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerSource {
    /// Full `portl…` ticket string pasted as the argument.
    Inline,
    /// Label hit in `peers.json`; ticket minted against the stored
    /// `endpoint_id`.
    PeerStore,
    /// Label hit in `tickets.json`; the saved ticket was returned.
    TicketStore,
    /// Label hit in `aliases.json` and pointed to an on-disk ticket
    /// file.
    AliasStoreTicket,
    /// Label hit in `aliases.json` with only an `endpoint_id`;
    /// ticket minted against it.
    AliasStoreEid,
    /// `peer` parsed as a raw `endpoint_id` (full hex or elided form).
    RawEid,
}

/// Resolution output. `discovery` describes how the address was
/// located ("cached" for inline tickets, "stored-ticket" for any
/// label→stored-ticket hit, or the iroh discovery provenance like
/// "dns" / "pkarr" / "mdns" / "relay" for ephemeral mints).
pub(crate) struct ResolvedPeer {
    pub(crate) ticket: PortlTicket,
    /// Which store/form the argument resolved against. Kept so
    /// future callers (e.g. `peer ls --expand`) can reason about
    /// provenance without reparsing.
    #[allow(dead_code)]
    pub(crate) source: PeerSource,
    pub(crate) discovery: String,
}

/// Options to `resolve_peer`. Kept tiny on purpose — anything
/// command-specific (e.g. the auditor-friendly stderr line) happens
/// at the call site, not in here.
pub(crate) struct ResolveOpts<'a> {
    /// Capabilities baked into any ephemeral ticket this call mints.
    /// Ignored for `Inline` / `TicketStore` / `AliasStoreTicket`
    /// paths, since those return a pre-existing ticket.
    pub(crate) caps: Capabilities,
    /// Force the resolved ticket's address to the peer's relay URL
    /// only, dropping direct-UDP candidates. Useful when the direct
    /// path is known-broken (NAT, captive portal) and you want to
    /// pin the session to the relay.
    pub(crate) force_relay: bool,
    pub(crate) identity: &'a Identity,
    pub(crate) endpoint: &'a iroh::Endpoint,
}

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
    match connect_peer_with_endpoint(peer, caps, &identity, &endpoint).await {
        Ok(connected) => Ok(connected),
        Err(err) => {
            close_client_endpoint(endpoint, "connect failure").await;
            Err(err)
        }
    }
}

pub(crate) async fn close_connected(connected: ConnectedPeer, reason: &'static [u8]) {
    connected.connection.close(0u32.into(), reason);
    close_client_endpoint(connected.endpoint, "connected peer").await;
}

pub(crate) async fn close_client_endpoint(endpoint: iroh::Endpoint, context: &'static str) {
    if tokio::time::timeout(Duration::from_secs(5), endpoint.close())
        .await
        .is_err()
    {
        debug!(context, "timed out closing CLI endpoint");
    }
}

pub(crate) async fn bind_client_endpoint(identity: &Identity) -> Result<iroh::Endpoint> {
    crate::client_endpoint::bind_client_endpoint(identity).await
}

pub(crate) async fn connect_peer_with_endpoint(
    peer: &str,
    caps: Capabilities,
    identity: &Identity,
    endpoint: &iroh::Endpoint,
) -> Result<ConnectedPeer> {
    let endpoint_wrapper = Endpoint::from(endpoint.clone());
    let resolved = resolve_peer(
        peer,
        &ResolveOpts {
            caps,
            force_relay: false,
            identity,
            endpoint,
        },
    )
    .await?;
    let (connection, session) = open_ticket_v1(&endpoint_wrapper, &resolved.ticket, &[], identity)
        .await
        .context("run ticket handshake")?;
    Ok(ConnectedPeer {
        endpoint: endpoint.clone(),
        connection,
        session,
    })
}

/// Unified resolution cascade. See module docs for the order. Emits
/// a single `using …` line to stderr on success, naming the source.
#[allow(clippy::too_many_lines)]
pub(crate) async fn resolve_peer(peer: &str, opts: &ResolveOpts<'_>) -> Result<ResolvedPeer> {
    // 1) Inline `portl…` ticket pasted as the arg. Check first so
    //    paste-a-ticket workflows work even when a label happens to
    //    collide (unlikely: tickets start with `portl`).
    if let Ok(ticket) = <PortlTicket as Ticket>::deserialize(peer) {
        if ticket.body.parent.is_some() {
            bail!(
                "delegated tickets not yet supported by this command; use the root ticket \
                 or pass --chain"
            );
        }
        eprintln!("using inline ticket");
        return Ok(ResolvedPeer {
            ticket: maybe_force_relay_ticket(ticket, opts.force_relay)?,
            source: PeerSource::Inline,
            discovery: "cached".to_owned(),
        });
    }

    // Load the name-keyed stores once. Each lookup is cheap after
    // load; no file IO in the hot path.
    let peers = PeerStore::load(&PeerStore::default_path()).context("load peer store")?;
    let tickets = TicketStore::load(&TicketStore::default_path()).context("load ticket store")?;
    let aliases = AliasStore::default();

    // 2) Label → peer store.
    //
    // Held peers hard-error (the user explicitly held them — do not
    // surprise-dial via a stale ticket).
    //
    // Outbound-capable peers mint a fresh ephemeral ticket with the
    // caller's caps — the ergonomic common case.
    //
    // Inbound-only peers *fall through* to the ticket / alias stores
    // before bailing: our own error message for this case instructs
    // users to `portl ticket save <peer> …`, so looking up the saved
    // ticket under the same label is exactly the flow we documented.
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
            let (addr, provenance) =
                resolve_endpoint_addr(opts.endpoint, endpoint_id, opts.force_relay).await?;
            let ticket = mint_fresh(opts.identity, addr, opts.caps.clone())?;
            return Ok(ResolvedPeer {
                ticket,
                source: PeerSource::PeerStore,
                discovery: normalize_discovery_source(&provenance),
            });
        }
        // Inbound-only: intentionally drop through. If no saved
        // ticket / alias matches, the final bail! reports the
        // inbound-only diagnosis with the same fix as before.
    }

    // 3) Label → ticket store.
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
        return Ok(ResolvedPeer {
            ticket: maybe_force_relay_ticket(ticket, opts.force_relay)?,
            source: PeerSource::TicketStore,
            discovery: "stored-ticket".to_owned(),
        });
    }

    // 4) Label → alias store. Container adapters register aliases
    //    pointing to either a saved ticket file or a bare
    //    endpoint_id.
    if let Some(alias) = aliases.get(peer)? {
        if let Some(spec) = aliases.get_spec(peer)?
            && let Some(ticket_path) = spec.ticket_file_path
        {
            let raw = std::fs::read_to_string(&ticket_path)
                .with_context(|| format!("read stored ticket {}", ticket_path.display()))?;
            let ticket = <PortlTicket as Ticket>::deserialize(raw.trim())
                .map_err(|err| anyhow!("parse stored ticket {}: {err}", ticket_path.display()))?;
            eprintln!("using alias \"{peer}\" (stored ticket)");
            return Ok(ResolvedPeer {
                ticket: maybe_force_relay_ticket(ticket, opts.force_relay)?,
                source: PeerSource::AliasStoreTicket,
                discovery: "stored-ticket".to_owned(),
            });
        }
        let endpoint_id = crate::eid::resolve(&alias.endpoint_id, None, None)
            .context("alias endpoint_id is not valid hex")?;
        let (addr, provenance) =
            resolve_endpoint_addr(opts.endpoint, endpoint_id, opts.force_relay).await?;
        eprintln!("using alias \"{peer}\"");
        let ticket = mint_fresh(opts.identity, addr, opts.caps.clone())?;
        return Ok(ResolvedPeer {
            ticket,
            source: PeerSource::AliasStoreEid,
            discovery: normalize_discovery_source(&provenance),
        });
    }

    // 5) Endpoint-id token: full 64-char hex or middle-elided form.
    if let Ok(endpoint_id) = crate::eid::resolve(peer, Some(&peers), Some(&tickets)) {
        let short = crate::eid::format_short(&hex::encode(endpoint_id.as_bytes()));
        eprintln!("using endpoint \"{short}\"");
        let (addr, provenance) =
            resolve_endpoint_addr(opts.endpoint, endpoint_id, opts.force_relay).await?;
        let ticket = mint_fresh(opts.identity, addr, opts.caps.clone())?;
        return Ok(ResolvedPeer {
            ticket,
            source: PeerSource::RawEid,
            discovery: normalize_discovery_source(&provenance),
        });
    }

    // If we reached this point and the peer store had an entry that
    // was just inbound-only, give the same inbound-only diagnosis as
    // before — it's more actionable than the generic "unknown peer"
    // message when the user genuinely has a paired-but-inbound peer.
    if peers
        .get_by_label(peer)
        .is_some_and(|e| !e.they_accept_from_me)
    {
        bail!(
            "peer '{peer}' is inbound-only — they accept from us, but we don't have \
             outbound authority to mint into them, and no ticket / alias named \
             '{peer}' is stored locally. Ask the peer to run \
             `portl ticket issue <caps> --ttl <dur> --to {our_eid}` and paste the \
             ticket back; then save it with `portl ticket save {peer} <ticket-string>`.",
            our_eid = hex::encode(opts.identity.verifying_key())
        );
    }

    bail!(
        "unknown peer or ticket name '{peer}'. Options:\n  \
         - `portl peer ls` to see stored peers\n  \
         - `portl ticket ls` to see saved tickets\n  \
         - pass a 64-char hex endpoint_id (or elided `PPPP…SSSS` form)\n  \
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

/// Run iroh's address discovery for `endpoint_id` and return the
/// first usable `EndpointAddr`, plus its provenance string ("dns",
/// "pkarr", "mdns", "relay", …) for surfacing to users.
///
/// When `force_relay` is true, the returned addr is rewritten to
/// the peer's relay URL only (direct-UDP candidates dropped). This
/// errors clearly if the peer has no relay address configured.
pub(crate) async fn resolve_endpoint_addr(
    endpoint: &iroh::Endpoint,
    endpoint_id: EndpointId,
    force_relay: bool,
) -> Result<(EndpointAddr, String)> {
    if force_relay && relay_discovery_disabled() {
        bail!(
            "PORTL_DISCOVERY=none disables relay discovery and DNS lookups; unset it or \
             pass a ticket with a relay address"
        );
    }
    let mut stream = endpoint
        .address_lookup()
        .context("access address lookup")?
        .resolve(endpoint_id);
    while let Some(item) = stream.next().await {
        match item {
            Ok(Ok(item)) => {
                let provenance = item.provenance().to_owned();
                let addr = item.into_endpoint_addr();
                let addr = maybe_force_relay_addr(endpoint_id, addr, force_relay)?;
                return Ok((addr, provenance));
            }
            Ok(Err(_)) => {}
            Err(AddressLookupFailed::NoServiceConfigured { .. }) => {
                if force_relay {
                    bail!(
                        "no discovery services configured for relay probing; unset \
                         PORTL_DISCOVERY=none or pass a ticket with a relay address"
                    );
                }
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

fn maybe_force_relay_ticket(mut ticket: PortlTicket, force_relay: bool) -> Result<PortlTicket> {
    if force_relay {
        ticket.addr = relay_only_addr(ticket.addr.id, &ticket.addr)?;
    }
    Ok(ticket)
}

fn maybe_force_relay_addr(
    endpoint_id: EndpointId,
    addr: EndpointAddr,
    force_relay: bool,
) -> Result<EndpointAddr> {
    if force_relay {
        return relay_only_addr(endpoint_id, &addr);
    }
    Ok(addr)
}

fn relay_only_addr(endpoint_id: EndpointId, addr: &EndpointAddr) -> Result<EndpointAddr> {
    let relay_url = addr.relay_urls().next().cloned().context(
        "peer does not advertise a relay address; rerun without --relay or use a ticket \
         with relay information",
    )?;
    Ok(EndpointAddr::new(endpoint_id).with_relay_url(relay_url))
}

fn relay_discovery_disabled() -> bool {
    matches!(std::env::var("PORTL_DISCOVERY"), Ok(value) if value.trim() == "none")
}

/// Map iroh's discovery-source slug to the portl-canonical name
/// surfaced by `portl status <peer>` output. Keeps "local" as the
/// user-facing term for mDNS.
pub(crate) fn normalize_discovery_source(source: &str) -> String {
    match source {
        "mdns" => "local".to_owned(),
        other => other.to_owned(),
    }
}
