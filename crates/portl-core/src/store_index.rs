//! Cross-store uniqueness helpers. Labels must be globally unique
//! across `peers.json` and `tickets.json` — `shell <name>` / `tcp <name>`
//! resolve through both stores and an ambiguous label would be a
//! silent route-change footgun.

use crate::peer_store::PeerStore;
use crate::ticket_store::TicketStore;

/// Which store claims the label, if any. Returned as `&'static str`
/// so call sites can embed it in error messages without allocation.
pub fn label_in_use(label: &str, peers: &PeerStore, tickets: &TicketStore) -> Option<&'static str> {
    if peers.get_by_label(label).is_some() {
        return Some("peer");
    }
    if tickets.get(label).is_some() {
        return Some("ticket");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_store::{PeerEntry, PeerOrigin};
    use crate::ticket_store::TicketEntry;

    #[test]
    fn reports_which_store_owns_a_label() {
        let mut peers = PeerStore::new();
        peers
            .insert_or_update(PeerEntry {
                label: "max".into(),
                endpoint_id_hex: hex::encode([1; 32]),
                accepts_from_them: true,
                they_accept_from_me: true,
                since: 0,
                origin: PeerOrigin::Raw,
                last_hold_at: None,
                is_self: false,
                relay_hint: None,
                schema_version: 2,
            })
            .unwrap();
        let mut tickets = TicketStore::new();
        tickets
            .insert(
                "daily".into(),
                TicketEntry {
                    endpoint_id_hex: hex::encode([2; 32]),
                    ticket_string: "portl...".into(),
                    expires_at: 2_000_000,
                    saved_at: 1_000_000,
                },
            )
            .unwrap();
        assert_eq!(label_in_use("max", &peers, &tickets), Some("peer"));
        assert_eq!(label_in_use("daily", &peers, &tickets), Some("ticket"));
        assert_eq!(label_in_use("missing", &peers, &tickets), None);
    }
}
