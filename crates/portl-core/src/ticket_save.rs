//! Store helper for saving parsed Portl tickets under reusable labels.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use iroh_tickets::Ticket;

use crate::peer_store::PeerStore;
use crate::ticket::schema::{Capabilities, PortlTicket};
use crate::ticket_store::{TicketEntry, TicketStore};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedTicket {
    pub label: String,
    pub endpoint_id_hex: String,
    pub expires_at: u64,
    pub saved_at: u64,
}

pub fn save_ticket(
    label: Option<&str>,
    ticket_string: &str,
    peers_path: &Path,
    tickets_path: &Path,
) -> Result<SavedTicket> {
    save_ticket_at(label, ticket_string, peers_path, tickets_path, unix_now()?)
}

pub fn save_ticket_at(
    label: Option<&str>,
    ticket_string: &str,
    peers_path: &Path,
    tickets_path: &Path,
    now: u64,
) -> Result<SavedTicket> {
    let ticket = <PortlTicket as Ticket>::decode_string(ticket_string)
        .map_err(|err| anyhow!("parse ticket: {err}"))?;
    let endpoint_id_hex = hex::encode(ticket.addr.id.as_bytes());
    let expires_at = ticket.body.not_after;
    if expires_at <= now {
        bail!(
            "ticket expired {ago}s ago; refusing to save (run `portl ticket issue …` \
             to mint a fresh one)",
            ago = now - expires_at
        );
    }

    let peers = PeerStore::load(peers_path)?;
    let mut tickets = TicketStore::load(tickets_path)?;
    let label = label.map_or_else(
        || auto_ticket_label(&endpoint_id_hex, &ticket.body.caps, &peers),
        |label| label.trim().to_owned(),
    );
    if label.is_empty() {
        bail!("ticket label is empty");
    }

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
            endpoint_id_hex: endpoint_id_hex.clone(),
            ticket_string: ticket_string.to_owned(),
            expires_at,
            saved_at: now,
            session_share: None,
        },
    )?;
    tickets.save(tickets_path)?;

    Ok(SavedTicket {
        label,
        endpoint_id_hex,
        expires_at,
        saved_at: now,
    })
}

fn auto_ticket_label(endpoint_id_hex: &str, caps: &Capabilities, peers: &PeerStore) -> String {
    let machine = peers
        .iter()
        .find(|peer| peer.endpoint_id_hex.eq_ignore_ascii_case(endpoint_id_hex))
        .map(|peer| peer.label.as_str())
        .map_or_else(
            || crate::labels::machine_label(None, endpoint_id_hex),
            ToOwned::to_owned,
        );
    crate::labels::ticket_label(&machine, &cap_summary(caps))
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

fn unix_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_store::{PeerEntry, PeerOrigin};
    use crate::ticket::schema::{EnvPolicy, MetaCaps, ShellCaps};

    #[test]
    fn auto_label_uses_peer_machine_and_ticket_caps() {
        let mut peers = PeerStore::new();
        let endpoint_id_hex = hex::encode([0xabu8; 32]);
        peers
            .insert_or_update(PeerEntry {
                label: "max-b265".to_owned(),
                endpoint_id_hex: endpoint_id_hex.clone(),
                accepts_from_them: true,
                they_accept_from_me: true,
                since: 0,
                origin: PeerOrigin::Paired,
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
            unix: None,
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
            unix: None,
        }
    }
}
