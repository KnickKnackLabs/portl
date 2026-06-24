//! Resolve a user-facing Portl target into a ticket.
//!
//! This is the non-CLI subset of the target cascade used by embedders:
//! raw ticket strings, outbound-capable peers, saved tickets, and raw
//! endpoint ids. CLI-only adapter aliases stay in `portl-cli`.

use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use iroh_base::{EndpointAddr, EndpointId};
use iroh_tickets::Ticket;

use crate::id::Identity;
use crate::peer_store::{PeerEntry, PeerStore};
use crate::ticket::mint::mint_root;
use crate::ticket::schema::{Capabilities, EnvPolicy, PortlTicket, ShellCaps};
use crate::ticket_store::TicketStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetSource {
    InlineTicket,
    PeerStore,
    TicketStore,
    RawEndpointId,
}

pub struct ResolveTargetOptions<'a> {
    pub identity: &'a Identity,
    pub caps: Capabilities,
    pub peer_store_path: &'a Path,
    pub ticket_store_path: &'a Path,
    pub now_unix: u64,
    pub ephemeral_ttl_secs: u64,
}

#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    pub ticket: PortlTicket,
    pub ticket_string: String,
    pub source: TargetSource,
    pub expires_at: u64,
}

pub fn interactive_shell_caps() -> Capabilities {
    Capabilities {
        presence: 0b0000_0001,
        shell: Some(ShellCaps {
            user_allowlist: None,
            pty_allowed: true,
            exec_allowed: true,
            command_allowlist: None,
            env_policy: EnvPolicy::Merge { allow: None },
        }),
        tcp: None,
        udp: None,
        fs: None,
        vpn: None,
        meta: None,
        unix: None,
    }
}

pub fn resolve_target(target: &str, options: ResolveTargetOptions<'_>) -> Result<ResolvedTarget> {
    let target = target.trim();
    if target.is_empty() {
        bail!("Portl target is empty");
    }

    if let Ok(ticket) = <PortlTicket as Ticket>::decode_string(target) {
        reject_expired(target, ticket.body.not_after, options.now_unix)?;
        return Ok(resolved_ticket(
            ticket,
            target.to_owned(),
            TargetSource::InlineTicket,
        ));
    }

    let peers = PeerStore::load(options.peer_store_path).context("load peer store")?;
    let tickets = TicketStore::load(options.ticket_store_path).context("load ticket store")?;
    let peer_entry = peers.get_by_label(target).cloned();

    if let Some(entry) = &peer_entry {
        if entry.last_hold_at.is_some() {
            bail!("peer '{target}' is currently held; resume it before dialing");
        }
        if entry.they_accept_from_me {
            let ticket = mint_peer_ticket(entry, &options)?;
            let ticket_string = ticket.encode_string();
            return Ok(resolved_ticket(
                ticket,
                ticket_string,
                TargetSource::PeerStore,
            ));
        }
    }

    if let Some(entry) = tickets.get(target) {
        reject_expired(target, entry.expires_at, options.now_unix)?;
        let ticket = <PortlTicket as Ticket>::decode_string(&entry.ticket_string)
            .map_err(|err| anyhow!("stored ticket '{target}' is malformed: {err}"))?;
        reject_expired(target, ticket.body.not_after, options.now_unix)?;
        return Ok(resolved_ticket(
            ticket,
            entry.ticket_string.clone(),
            TargetSource::TicketStore,
        ));
    }

    if peer_entry.is_some() {
        bail!(
            "peer '{target}' is inbound-only; ask the peer to accept an outbound invite or issue a ticket"
        );
    }

    if let Some(endpoint_id) = parse_endpoint_id(target)? {
        let ticket = mint_root(
            options.identity.signing_key(),
            EndpointAddr::new(endpoint_id),
            options.caps,
            options.now_unix,
            options.now_unix + options.ephemeral_ttl_secs,
            Some(options.identity.verifying_key()),
        )
        .context("mint endpoint ticket")?;
        let ticket_string = ticket.encode_string();
        return Ok(resolved_ticket(
            ticket,
            ticket_string,
            TargetSource::RawEndpointId,
        ));
    }

    bail!(
        "unknown Portl target '{target}'; use an accepted peer label, saved ticket label, raw ticket, or endpoint id"
    );
}

fn mint_peer_ticket(entry: &PeerEntry, options: &ResolveTargetOptions<'_>) -> Result<PortlTicket> {
    let endpoint_id = endpoint_id_from_hex(&entry.endpoint_id_hex)
        .with_context(|| format!("peer '{}' endpoint_id is invalid", entry.label))?;
    let mut addr = EndpointAddr::new(endpoint_id);
    if let Some(relay_hint) = entry.relay_hint.as_deref() {
        let relay_url = relay_hint
            .parse()
            .with_context(|| format!("peer '{}' relay hint is invalid", entry.label))?;
        addr = addr.with_relay_url(relay_url);
    }
    mint_root(
        options.identity.signing_key(),
        addr,
        options.caps.clone(),
        options.now_unix,
        options.now_unix + options.ephemeral_ttl_secs,
        Some(options.identity.verifying_key()),
    )
    .context("mint peer ticket")
}

fn resolved_ticket(
    ticket: PortlTicket,
    ticket_string: String,
    source: TargetSource,
) -> ResolvedTarget {
    ResolvedTarget {
        expires_at: ticket.body.not_after,
        ticket,
        ticket_string,
        source,
    }
}

fn reject_expired(label: &str, expires_at: u64, now_unix: u64) -> Result<()> {
    if expires_at <= now_unix {
        bail!(
            "Portl target '{label}' expired {ago}s ago",
            ago = now_unix - expires_at
        );
    }
    Ok(())
}

fn parse_endpoint_id(target: &str) -> Result<Option<EndpointId>> {
    if target.len() != 64 || !target.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Ok(None);
    }
    endpoint_id_from_hex(target).map(Some)
}

fn endpoint_id_from_hex(value: &str) -> Result<EndpointId> {
    let bytes = hex::decode(value).context("decode endpoint id")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("endpoint id is not 32 bytes"))?;
    EndpointId::from_bytes(&bytes).context("endpoint id is not a valid iroh id")
}
