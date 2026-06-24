//! Session-share ticket import helpers shared by CLI and embedders.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use iroh_tickets::Ticket;

use crate::peer_store::PeerStore;
use crate::rendezvous::exchange::{ExchangePayload, PortlExchangeEnvelopeV1};
use crate::store_index::label_in_use;
use crate::target_resolve::interactive_shell_caps;
use crate::ticket::canonical::{canonical_check_ticket, resolved_issuer};
use crate::ticket::schema::{Capabilities, PortlTicket};
use crate::ticket::sign::verify_body;
use crate::ticket_store::{SessionShareMetadata, TicketEntry, TicketStore};

#[derive(Debug, Clone, Copy)]
pub struct ImportSessionShareOptions<'a> {
    pub label: Option<&'a str>,
    pub recipient_endpoint_id_hex: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedSessionShare {
    pub label: String,
    pub endpoint_id_hex: String,
    pub expires_at: u64,
    pub saved_at: u64,
}

/// Capabilities baked into session-share root tickets.
///
/// These mirror interactive session attach caps so accepted session shares can
/// be saved and later attached through the normal ticket target path.
pub fn session_share_caps() -> Capabilities {
    interactive_shell_caps()
}

pub fn import_session_share_envelope_json(
    envelope_json: &str,
    options: ImportSessionShareOptions<'_>,
    peers_path: &Path,
    tickets_path: &Path,
) -> Result<ImportedSessionShare> {
    let envelope: PortlExchangeEnvelopeV1 =
        serde_json::from_str(envelope_json).context("parse session share envelope JSON")?;
    import_session_share_envelope(&envelope, options, peers_path, tickets_path)
}

#[allow(clippy::too_many_lines)]
pub fn import_session_share_envelope(
    envelope: &PortlExchangeEnvelopeV1,
    options: ImportSessionShareOptions<'_>,
    peers_path: &Path,
    tickets_path: &Path,
) -> Result<ImportedSessionShare> {
    envelope
        .validate()
        .map_err(|err| anyhow!("invalid exchange envelope: {err}"))?;
    let now = unix_now()?;
    if let Some(not_after) = envelope.not_after_unix
        && not_after <= now
    {
        bail!("session share expired; ask the sender to run `portl session share` again");
    }
    let ExchangePayload::SessionShare(share) = &envelope.payload;
    if share.access_not_after_unix <= now {
        bail!("session share access expired; ask the sender to mint a fresh share");
    }

    let ticket = <PortlTicket as Ticket>::decode_string(&share.ticket)
        .map_err(|err| anyhow!("parse embedded session ticket: {err}"))?;
    canonical_check_ticket(&ticket)
        .map_err(|err| anyhow!("invalid embedded session ticket: {err}"))?;
    verify_body(&resolved_issuer(&ticket), &ticket.body, &ticket.sig)
        .map_err(|err| anyhow!("embedded session ticket signature failed: {err}"))?;
    if ticket.v != 1
        || ticket.body.parent.is_some()
        || ticket.body.bearer.is_some()
        || ticket.body.caps != session_share_caps()
    {
        bail!("embedded session ticket is not a session-share ticket");
    }

    let endpoint_id_hex = hex::encode(ticket.addr.id.as_bytes());
    if !endpoint_id_hex.eq_ignore_ascii_case(&share.target_endpoint_id_hex) {
        bail!("embedded session ticket target did not match share envelope");
    }
    if ticket.body.not_after > share.access_not_after_unix {
        bail!("embedded session ticket outlives share access window");
    }
    if ticket.body.not_after <= now {
        bail!("embedded session ticket has already expired");
    }
    if let Some(expected) = options.recipient_endpoint_id_hex {
        let Some(holder) = ticket.body.to else {
            bail!("embedded session ticket is not bound to this recipient");
        };
        let holder = hex::encode(holder);
        if !holder.eq_ignore_ascii_case(expected) {
            bail!("embedded session ticket is bound to a different recipient");
        }
    }

    let label = options.label.map_or_else(
        || share.import_label(),
        |label| {
            let trimmed = label.trim();
            if trimmed.is_empty() {
                String::new()
            } else {
                trimmed.to_owned()
            }
        },
    );
    if label.trim().is_empty() {
        bail!("session share label is empty; pass --label <name>");
    }

    let peers = PeerStore::load(peers_path)?;
    let mut tickets = TicketStore::load(tickets_path)?;
    if peers.get_by_label(&label).is_some() {
        bail!(
            "label '{label}' is already in use by a peer; pass --label <name> or choose another label"
        );
    }

    if let Some(existing) = tickets.get(&label).cloned() {
        if !existing
            .endpoint_id_hex
            .eq_ignore_ascii_case(&endpoint_id_hex)
        {
            bail!(
                "label '{label}' is already in use by a ticket for a different endpoint; pass --label <name> or remove the existing label first"
            );
        }
        if existing.expires_at >= ticket.body.not_after {
            bail!(
                "ticket '{label}' already exists for this endpoint and expires later or at the same time; keeping the existing ticket"
            );
        }
        tickets.remove(&label);
    } else if let Some(store) = label_in_use(&label, &peers, &tickets) {
        bail!(
            "label '{label}' is already in use by a {store}; pass --label <name> or remove the existing label first"
        );
    }

    tickets.insert(
        label.clone(),
        TicketEntry {
            endpoint_id_hex: endpoint_id_hex.clone(),
            ticket_string: share.ticket.clone(),
            expires_at: ticket.body.not_after,
            saved_at: now,
            session_share: Some(SessionShareMetadata {
                friendly_name: share.friendly_name.clone(),
                provider_session: share.provider_session.clone(),
                provider: share.provider.clone(),
                origin_label_hint: share.origin_label_hint.clone(),
                target_label_hint: share.target_label_hint.clone(),
            }),
        },
    )?;
    tickets.save(tickets_path)?;

    Ok(ImportedSessionShare {
        label,
        endpoint_id_hex,
        expires_at: ticket.body.not_after,
        saved_at: now,
    })
}

fn unix_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs())
}
