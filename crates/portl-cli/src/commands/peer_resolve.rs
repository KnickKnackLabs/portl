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
use iroh_base::{EndpointAddr, EndpointId, TransportAddr};
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
            let configured_relay_hints = configured_relay_hints();
            let (addr, provenance) = resolve_endpoint_addr_with_relay_hints(
                opts.endpoint,
                endpoint_id,
                entry.relay_hint.as_deref(),
                &configured_relay_hints,
                opts.force_relay,
            )
            .await?;
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
        let configured_relay_hints = configured_relay_hints();
        let (addr, provenance) = resolve_endpoint_addr_with_relay_hints(
            opts.endpoint,
            endpoint_id,
            None,
            &configured_relay_hints,
            opts.force_relay,
        )
        .await?;
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
        let configured_relay_hints = configured_relay_hints();
        let (addr, provenance) = resolve_endpoint_addr_with_relay_hints(
            opts.endpoint,
            endpoint_id,
            None,
            &configured_relay_hints,
            opts.force_relay,
        )
        .await?;
        let ticket = mint_fresh(opts.identity, addr, opts.caps.clone())?;
        return Ok(ResolvedPeer {
            ticket,
            source: PeerSource::RawEid,
            discovery: normalize_discovery_source(&provenance),
        });
    }

    // 6) Unique hostname shorthand → peer store. Checked after exact
    //    ticket/alias/raw endpoint matches so shorthand never steals
    //    an explicit saved credential label.
    if let Some(peer_label) = resolve_peer_store_shorthand(&peers, peer)?
        && let Some(entry) = peers.get_by_label(&peer_label)
    {
        if entry.last_hold_at.is_some() {
            bail!(
                "peer '{peer_label}' is currently held; resume it with `portl peer resume {peer_label}` \
                 before dialing"
            );
        }
        if entry.they_accept_from_me {
            eprintln!("using peer \"{peer_label}\"");
            let eid = entry.endpoint_id_bytes()?;
            let endpoint_id =
                EndpointId::from_bytes(&eid).context("peer endpoint_id is not a valid iroh id")?;
            let configured_relay_hints = configured_relay_hints();
            let (addr, provenance) = resolve_endpoint_addr_with_relay_hints(
                opts.endpoint,
                endpoint_id,
                entry.relay_hint.as_deref(),
                &configured_relay_hints,
                opts.force_relay,
            )
            .await?;
            let ticket = mint_fresh(opts.identity, addr, opts.caps.clone())?;
            return Ok(ResolvedPeer {
                ticket,
                source: PeerSource::PeerStore,
                discovery: normalize_discovery_source(&provenance),
            });
        }
        bail!(
            "peer '{peer_label}' is inbound-only — they accept from us, but we don't have \
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

fn resolve_peer_store_shorthand(peers: &PeerStore, peer: &str) -> Result<Option<String>> {
    let mut matches = peers
        .iter()
        .filter(|entry| label_hostname(&entry.label).as_deref() == Some(peer))
        .map(|entry| entry.label.clone())
        .collect::<Vec<_>>();
    matches.sort();
    matches.dedup();

    match matches.as_slice() {
        [] => Ok(None),
        [only] => Ok(Some(only.clone())),
        many => {
            let labels = many
                .iter()
                .map(|label| format!("  {label}"))
                .collect::<Vec<_>>()
                .join("\n");
            anyhow::bail!("ambiguous peer shorthand '{peer}'\n\nMatches:\n{labels}")
        }
    }
}

fn label_hostname(label: &str) -> Option<String> {
    let (host, suffix) = label.rsplit_once('-')?;
    (suffix.len() == 4 && suffix.chars().all(|ch| ch.is_ascii_hexdigit())).then(|| host.to_owned())
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

/// Run iroh's address discovery for `endpoint_id` and return as soon as
/// the first usable `EndpointAddr` appears, plus its provenance string
/// ("dns", "pkarr", "mdns", "relay", …) for surfacing to users.
///
/// Discovery streams are not treated as finite enumerations: local/mDNS
/// discovery can keep probing after DNS/PKARR has already yielded a viable
/// relay. Callers that know static relay hints should merge them around this
/// helper rather than waiting for the stream to exhaust.
///
/// When `force_relay` is true, the returned addr is rewritten to
/// the peer's relay URL only (direct-UDP candidates dropped). This
/// errors clearly if the peer has no relay address configured.
pub(crate) async fn resolve_endpoint_addr_with_relay_hints(
    endpoint: &iroh::Endpoint,
    endpoint_id: EndpointId,
    relay_hint: Option<&str>,
    configured_relay_hints: &[String],
    force_relay: bool,
) -> Result<(EndpointAddr, String)> {
    if let Some(fallback) = relay_fallback_addr(endpoint_id, relay_hint, configured_relay_hints)? {
        return Ok(fallback);
    }

    match resolve_endpoint_addr(endpoint, endpoint_id, force_relay).await {
        Ok((addr, provenance)) => {
            let addr = if force_relay {
                addr
            } else {
                add_relay_hints(addr, relay_hint, configured_relay_hints)?
            };
            Ok((addr, provenance))
        }
        Err(discovery_err) => {
            if let Some(fallback) =
                relay_fallback_addr(endpoint_id, relay_hint, configured_relay_hints)?
            {
                return Ok(fallback);
            }
            Err(discovery_err)
        }
    }
}

fn configured_relay_hints() -> Vec<String> {
    crate::client_endpoint::load_client_config()
        .map(|cfg| {
            cfg.discovery
                .relays
                .into_iter()
                .map(|relay| relay.to_string())
                .collect()
        })
        .unwrap_or_default()
}

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
    let mut saw_empty_addr = false;
    let mut stream = endpoint
        .address_lookup()
        .context("access address lookup")?
        .resolve(endpoint_id);
    while let Some(item) = stream.next().await {
        match item {
            Ok(Ok(item)) => {
                let provenance = item.provenance().to_owned();
                let addr = item.into_endpoint_addr();
                if !is_usable_endpoint_addr(&addr) {
                    saw_empty_addr = true;
                    continue;
                }
                let addr = maybe_force_relay_addr(endpoint_id, addr, force_relay)?;
                return Ok((addr, normalize_discovery_source(&provenance)));
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

    if saw_empty_addr {
        bail!("discovery returned no usable addresses")
    }
    bail!("discovery returned no addresses")
}

fn relay_fallback_addr(
    endpoint_id: EndpointId,
    relay_hint: Option<&str>,
    configured_relay_hints: &[String],
) -> Result<Option<(EndpointAddr, String)>> {
    let addr = add_relay_hints(
        EndpointAddr::new(endpoint_id),
        relay_hint,
        configured_relay_hints,
    )?;
    if addr.is_empty() {
        return Ok(None);
    }
    let provenance = match (relay_hint.is_some(), configured_relay_hints.is_empty()) {
        (true, false) => "stored+configured-relay",
        (true, true) => "stored-relay",
        (false, false) => "configured-relay",
        (false, true) => "relay",
    };
    Ok(Some((addr, provenance.to_owned())))
}

fn add_relay_hints(
    mut addr: EndpointAddr,
    relay_hint: Option<&str>,
    configured_relay_hints: &[String],
) -> Result<EndpointAddr> {
    for relay_hint in relay_hint
        .into_iter()
        .chain(configured_relay_hints.iter().map(String::as_str))
    {
        let relay_url = relay_hint
            .parse()
            .with_context(|| format!("parse relay URL {relay_hint:?}"))?;
        addr = addr.with_relay_url(relay_url);
    }
    Ok(addr)
}

fn is_usable_endpoint_addr(addr: &EndpointAddr) -> bool {
    !addr.is_empty()
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
    let relays = addr
        .relay_urls()
        .cloned()
        .map(TransportAddr::Relay)
        .collect::<Vec<_>>();
    if relays.is_empty() {
        anyhow::bail!(
            "peer does not advertise a relay address; rerun without --relay or use a ticket \
         with relay information"
        );
    }
    Ok(EndpointAddr::from_parts(endpoint_id, relays))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn peer_entry(label: &str) -> portl_core::peer_store::PeerEntry {
        portl_core::peer_store::PeerEntry {
            label: label.to_owned(),
            endpoint_id_hex: hex::encode(endpoint_id().as_bytes()),
            accepts_from_them: true,
            they_accept_from_me: true,
            since: 1_000,
            origin: portl_core::peer_store::PeerOrigin::Paired,
            last_hold_at: None,
            is_self: false,
            relay_hint: None,
            schema_version: 2,
        }
    }

    fn endpoint_id() -> EndpointId {
        let bytes = hex::decode("bba9659180ddc99df3295c488914d244055017c3bda5938340252961e98eb265")
            .expect("valid hex");
        let bytes: [u8; 32] = bytes.try_into().expect("32 byte endpoint id");
        EndpointId::from_bytes(&bytes).expect("valid endpoint id")
    }

    #[test]
    fn peer_store_label_accepts_unique_hostname_shorthand() {
        let mut peers = PeerStore::new();
        peers.insert_or_update(peer_entry("max-b265")).unwrap();

        let resolved = resolve_peer_store_shorthand(&peers, "max").unwrap();

        assert_eq!(resolved.as_deref(), Some("max-b265"));
    }

    #[test]
    fn peer_store_label_rejects_ambiguous_hostname_shorthand() {
        let mut peers = PeerStore::new();
        let mut first = peer_entry("max-b265");
        first.endpoint_id_hex = hex::encode(endpoint_id().as_bytes());
        peers.insert_or_update(first).unwrap();
        let mut second = peer_entry("max-7310");
        second.endpoint_id_hex =
            "d65f9e656607519c4c28f52ddd9ecb71c0598492656ff8ce21b5079526e57310".to_owned();
        peers.insert_or_update(second).unwrap();

        let err = resolve_peer_store_shorthand(&peers, "max").unwrap_err();

        assert!(err.to_string().contains("ambiguous peer shorthand 'max'"));
    }

    #[test]
    fn empty_endpoint_addr_is_not_usable_for_ticket_minting() {
        let addr = EndpointAddr::new(endpoint_id());
        assert!(!is_usable_endpoint_addr(&addr));
    }

    #[test]
    fn static_relay_hints_are_added_to_discovered_addr() {
        let endpoint_id = endpoint_id();
        let discovered = EndpointAddr::new(endpoint_id)
            .with_relay_url("https://discovered.example/".parse().unwrap());
        let configured = vec!["https://configured.example/".to_owned()];

        let addr = add_relay_hints(discovered, Some("https://stored.example/"), &configured)
            .expect("valid relay hints");

        assert_eq!(
            relay_urls(&addr),
            vec![
                "https://configured.example/",
                "https://discovered.example/",
                "https://stored.example/",
            ]
        );
    }

    #[test]
    fn stored_and_configured_relay_hints_are_aggregated() {
        let endpoint_id = endpoint_id();
        let configured = vec![
            "https://configured-a.example/".to_owned(),
            "https://configured-b.example/".to_owned(),
        ];
        let (addr, provenance) = relay_fallback_addr(
            endpoint_id,
            Some("https://stored-relay.example/"),
            &configured,
        )
        .expect("valid relay hints")
        .expect("fallback exists");

        assert!(is_usable_endpoint_addr(&addr));
        assert_eq!(addr.id, endpoint_id);
        assert_eq!(provenance, "stored+configured-relay");
        let relays = relay_urls(&addr);
        assert_eq!(
            relays,
            vec![
                "https://configured-a.example/",
                "https://configured-b.example/",
                "https://stored-relay.example/",
            ]
        );
    }

    #[test]
    fn configured_relay_hint_recovers_legacy_peer_without_stored_hint() {
        let endpoint_id = endpoint_id();
        let configured = vec!["https://configured-relay.example/".to_owned()];
        let (addr, provenance) = relay_fallback_addr(endpoint_id, None, &configured)
            .expect("valid relay hint")
            .expect("fallback exists");

        assert!(is_usable_endpoint_addr(&addr));
        assert_eq!(provenance, "configured-relay");
        assert_eq!(relay_urls(&addr), vec!["https://configured-relay.example/"]);
    }

    fn relay_urls(addr: &EndpointAddr) -> Vec<String> {
        addr.relay_urls().map(ToString::to_string).collect()
    }
}
