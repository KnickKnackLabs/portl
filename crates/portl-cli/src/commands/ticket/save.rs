//! `portl ticket save [label] <ticket-string>` — save a ticket for
//! reuse through the target-resolution cascade.
//!
//! The core helper owns validation, label selection, renewal, and
//! persistence so the CLI and embedders follow the same rules.

use std::process::ExitCode;

use anyhow::{Result, bail};
use portl_core::peer_store::PeerStore;
use portl_core::ticket_save::save_ticket;
use portl_core::ticket_store::TicketStore;

pub fn run(label: &str, ticket_string: Option<&str>) -> Result<ExitCode> {
    if label.trim().starts_with("PORTLINV-")
        || ticket_string.is_some_and(|s| s.trim().starts_with("PORTLINV-"))
    {
        let invite = ticket_string.unwrap_or(label);
        bail!(
            "this looks like an invite code, not a ticket.\n       To redeem it and pair with the inviter:\n         portl accept {invite}"
        );
    }
    let (explicit_label, ticket_string) = match ticket_string {
        Some(ticket_string) => (Some(label), ticket_string),
        None => (None, label),
    };
    let saved = save_ticket(
        explicit_label,
        ticket_string,
        &PeerStore::default_path(),
        &TicketStore::default_path(),
    )?;
    let ttl_secs = saved.expires_at - saved.saved_at;
    println!("saved ticket '{}' (expires in {ttl_secs}s)", saved.label);
    Ok(ExitCode::SUCCESS)
}
