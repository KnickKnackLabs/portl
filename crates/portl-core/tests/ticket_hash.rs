//! M1 Task 4 — domain-separated ticket-id helpers.

use portl_core::ticket::hash::{parent_ticket_id, ticket_id};

#[test]
fn ticket_id_and_parent_ticket_id_are_domain_separated() {
    let sig = [0x5au8; 64];
    assert_ne!(ticket_id(&sig), parent_ticket_id(&sig));
}

#[test]
fn ticket_ids_are_16_bytes() {
    let id = ticket_id(&[0u8; 64]);
    let parent = parent_ticket_id(&[0u8; 64]);
    assert_eq!(id.len(), 16);
    assert_eq!(parent.len(), 16);
}

#[test]
fn ticket_id_golden_for_zero_signature() {
    assert_eq!(
        hex::encode(ticket_id(&[0u8; 64])),
        "0dcb29ad5fb8fc9656c8c77eae288bae"
    );
}

#[test]
fn parent_ticket_id_golden_for_zero_signature() {
    assert_eq!(
        hex::encode(parent_ticket_id(&[0u8; 64])),
        "dc03a3c334a8d9e7d1f8f24c9da0cfdc"
    );
}
