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
use portl_core::ticket::schema::{Capabilities, PortlTicket};
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
    let (explicit_label, ticket_string) = match ticket_string {
        Some(ticket_string) => (Some(label), ticket_string),
        None => (None, label),
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

    let label = explicit_label
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| auto_ticket_label(&endpoint_id_hex, &ticket.body.caps, &peers));

    if peers.get_by_label(&label).is_some() {
        bail!(
            "label '{label}' is already in use by a peer; pick another label or remove the existing one first"
        );
    }
    if let Some(existing) = tickets.get(&label).cloned() {
        if !existing
            .endpoint_id_hex
            .eq_ignore_ascii_case(&endpoint_id_hex)
        {
            bail!(
                "label '{label}' is already in use by a ticket for a different endpoint; pick another label or remove it first"
            );
        }
        if existing.expires_at >= expires_at {
            bail!(
                "ticket '{label}' already exists for this endpoint and expires later or at the same time; keeping the existing ticket"
            );
        }
        tickets.remove(&label);
    }

    tickets.insert(
        label.clone(),
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

fn auto_ticket_label(endpoint_id_hex: &str, caps: &Capabilities, peers: &PeerStore) -> String {
    let machine = peers
        .iter()
        .find(|peer| peer.endpoint_id_hex.eq_ignore_ascii_case(endpoint_id_hex))
        .map(|peer| peer.label.as_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| portl_core::labels::machine_label(None, endpoint_id_hex));
    portl_core::labels::ticket_label(&machine, &cap_summary(caps))
}

fn cap_summary(caps: &Capabilities) -> String {
    let mut parts = Vec::new();
    if let Some(shell) = &caps.shell {
        parts.push(if shell.pty_allowed { "shell" } else { "exec" });
    }
    if caps.tcp.as_ref().is_some_and(|rules| !rules.is_empty()) {
        parts.push("tcp");
    }
    if caps.udp.as_ref().is_some_and(|rules| !rules.is_empty()) {
        parts.push("udp");
    }
    if caps.meta.is_some() {
        parts.push("meta");
    }
    if parts.is_empty() || parts.len() > 2 {
        "access".to_owned()
    } else {
        parts.join("-")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portl_core::ticket::schema::{Capabilities, EnvPolicy, MetaCaps, ShellCaps};

    #[test]
    fn auto_label_uses_peer_machine_and_ticket_caps() {
        let mut peers = PeerStore::new();
        let endpoint_id_hex = hex::encode([0xabu8; 32]);
        peers
            .insert_or_update(portl_core::peer_store::PeerEntry {
                label: "max-b265".to_owned(),
                endpoint_id_hex: endpoint_id_hex.clone(),
                accepts_from_them: true,
                they_accept_from_me: true,
                since: 0,
                origin: portl_core::peer_store::PeerOrigin::Paired,
                last_hold_at: None,
                is_self: false,
                relay_hint: None,
                schema_version: 2,
            })
            .unwrap();

        assert_eq!(
            auto_ticket_label(&endpoint_id_hex, &shell_caps(), &peers),
            "max-b265-ticket-shell"
        );
    }

    #[test]
    fn auto_label_falls_back_to_endpoint_machine_label() {
        let peers = PeerStore::new();
        let endpoint_id_hex = "bba96591b265";
        assert_eq!(
            auto_ticket_label(endpoint_id_hex, &meta_caps(), &peers),
            "host-b265-ticket-meta"
        );
    }

    fn shell_caps() -> Capabilities {
        Capabilities {
            presence: 1,
            shell: Some(ShellCaps {
                user_allowlist: None,
                pty_allowed: true,
                exec_allowed: true,
                command_allowlist: None,
                env_policy: EnvPolicy::Deny,
            }),
            tcp: None,
            udp: None,
            fs: None,
            vpn: None,
            meta: None,
        }
    }

    fn meta_caps() -> Capabilities {
        Capabilities {
            presence: 0b0010_0000,
            shell: None,
            tcp: None,
            udp: None,
            fs: None,
            vpn: None,
            meta: Some(MetaCaps {
                ping: true,
                info: true,
            }),
        }
    }
}
