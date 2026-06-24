//! Shared acceptor-side peer-store update for pairing invite consumers.

use std::path::Path;

use anyhow::{Context, Result};

use crate::pair_code::InviteCode;
use crate::peer_store::{PeerEntry, PeerOrigin, PeerStore};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedPeer {
    pub label: String,
    pub endpoint_id_hex: String,
    pub relationship: String,
}

#[derive(Debug, Clone)]
pub struct SaveAcceptedPeerOptions<'a> {
    pub responder_self_label: Option<&'a str>,
    pub responder_relay_hint: Option<String>,
    pub now_unix: u64,
}

pub fn save_accepted_peer(
    invite: &InviteCode,
    options: SaveAcceptedPeerOptions<'_>,
    peers_path: &Path,
) -> Result<AcceptedPeer> {
    let inviter_eid_hex = hex::encode(invite.inviter_eid);
    let mut peers = PeerStore::load(peers_path)?;
    let label = choose_local_label(&peers, options.responder_self_label, &inviter_eid_hex);
    let (accepts_from_them, they_accept_from_me) =
        invite.initiator.relationship().acceptor_peer_flags();

    peers
        .insert_or_update(PeerEntry {
            label: label.clone(),
            endpoint_id_hex: inviter_eid_hex.clone(),
            accepts_from_them,
            they_accept_from_me,
            since: options.now_unix,
            origin: PeerOrigin::Paired,
            last_hold_at: None,
            is_self: false,
            relay_hint: options.responder_relay_hint,
            schema_version: 2,
        })
        .context("insert paired peer locally")?;
    peers.save(peers_path).context("save peer store")?;

    Ok(AcceptedPeer {
        label,
        endpoint_id_hex: inviter_eid_hex,
        relationship: acceptor_relationship_sentence(options.responder_self_label, invite),
    })
}

fn choose_local_label(
    peers: &PeerStore,
    responder_self_label: Option<&str>,
    inviter_eid_hex: &str,
) -> String {
    let candidate =
        responder_self_label.unwrap_or(&inviter_eid_hex[..8.min(inviter_eid_hex.len())]);
    if !peers.iter().any(|entry| entry.label == candidate) {
        return candidate.to_owned();
    }
    format!(
        "{candidate}-{suffix}",
        suffix = &inviter_eid_hex[..4.min(inviter_eid_hex.len())]
    )
}

fn acceptor_relationship_sentence(
    responder_self_label: Option<&str>,
    invite: &InviteCode,
) -> String {
    let label = responder_self_label.unwrap_or("peer");
    match invite.initiator {
        crate::pair_code::InitiatorMode::Mutual => {
            format!("{label} and you can reach each other.")
        }
        crate::pair_code::InitiatorMode::Me => {
            format!("{label} can reach you; you cannot reach {label}.")
        }
        crate::pair_code::InitiatorMode::Them => {
            format!("you can reach {label}; {label} cannot reach you.")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pair_code::{InitiatorMode, InviteCode};
    use tempfile::TempDir;

    #[test]
    fn save_accepted_peer_records_inviter_relationship() {
        let temp = TempDir::new().unwrap();
        let peers_path = temp.path().join("peers.json");
        let invite = InviteCode::new([7u8; 32], [9u8; 16], 4_000, InitiatorMode::Them, None);

        let accepted = save_accepted_peer(
            &invite,
            SaveAcceptedPeerOptions {
                responder_self_label: Some("devbox"),
                responder_relay_hint: Some("https://relay.example/".to_owned()),
                now_unix: 1_000,
            },
            &peers_path,
        )
        .unwrap();

        assert_eq!(accepted.label, "devbox");
        assert_eq!(
            accepted.relationship,
            "you can reach devbox; devbox cannot reach you."
        );

        let peers = PeerStore::load(&peers_path).unwrap();
        let entry = peers.get_by_label("devbox").unwrap();
        assert_eq!(entry.endpoint_id_hex, hex::encode([7u8; 32]));
        assert!(!entry.accepts_from_them);
        assert!(entry.they_accept_from_me);
        assert_eq!(entry.relay_hint.as_deref(), Some("https://relay.example/"));
    }
}
