//! `portl ticket save <label> <ticket-string>` — parse a ticket
//! string (typically minted by a remote peer and pasted to us),
//! extract its `endpoint_id` and expiry, and write it under a label
//! to `tickets.json`. From then on, `portl shell <label>` uses it
//! via the resolve cascade.
//!
//! Parsing at save-time (rather than at use-time) catches typos
//! early and lets `portl ticket ls` show the expiry column without
//! re-parsing every row.

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use iroh_tickets::Ticket;
use portl_core::peer_store::PeerStore;
use portl_core::ticket::schema::PortlTicket;
use portl_core::ticket_store::{TicketEntry, TicketStore};

pub fn run(label: &str, ticket_string: Option<&str>) -> Result<ExitCode> {
    if label.trim().starts_with("PORTLINV-")
        || ticket_string.is_some_and(|s| s.trim().starts_with("PORTLINV-"))
    {
        let invite = ticket_string.unwrap_or(label);
        bail!(
            "this looks like an invite code, not a ticket.\n       To redeem it and pair with the inviter:\n         portl accept {invite}"
        );
    }
    let Some(ticket_string) = ticket_string else {
        bail!("missing ticket string. Usage: portl ticket save <label> <ticket>");
    };
    let ticket = <PortlTicket as Ticket>::deserialize(ticket_string)
        .map_err(|err| anyhow!("parse ticket: {err}"))?;
    // Pull endpoint_id and `not_after` directly from the ticket —
    // `addr.endpoint_id` is the terminal target, `body.not_after`
    // is the signed expiry.
    let endpoint_id_hex = hex::encode(ticket.addr.id.as_bytes());
    let expires_at = ticket.body.not_after;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();
    if expires_at <= now {
        bail!(
            "ticket expired {ago}s ago; refusing to save (run `portl ticket issue …` \
             to mint a fresh one)",
            ago = now - expires_at
        );
    }

    let tickets_path = TicketStore::default_path();
    let mut tickets = TicketStore::load(&tickets_path)?;
    let peers = PeerStore::load(&PeerStore::default_path())?;

    // Cross-store label uniqueness check — same label in peers and
    // tickets is a route-ambiguity footgun.
    if let Some(store) = portl_core::store_index::label_in_use(label, &peers, &tickets) {
        bail!(
            "label '{label}' is already in use by a {store}; \
             pick another label or remove the existing one first"
        );
    }

    tickets.insert(
        label.to_owned(),
        TicketEntry {
            endpoint_id_hex,
            ticket_string: ticket_string.to_owned(),
            expires_at,
            saved_at: now,
        },
    )?;
    tickets.save(&tickets_path)?;
    let ttl_secs = expires_at - now;
    println!("saved ticket '{label}' (expires in {ttl_secs}s)");
    Ok(ExitCode::SUCCESS)
}
