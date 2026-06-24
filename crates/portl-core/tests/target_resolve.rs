use ed25519_dalek::SigningKey;
use iroh_base::{EndpointAddr, EndpointId};
use iroh_tickets::Ticket;
use portl_core::id::Identity;
use portl_core::peer_store::{PeerEntry, PeerOrigin, PeerStore};
use portl_core::target_resolve::{
    ResolveTargetOptions, TargetSource, interactive_shell_caps, resolve_target,
};
use portl_core::ticket::mint::mint_root;
use portl_core::ticket_store::{TicketEntry, TicketStore};
use tempfile::TempDir;

const NOW: u64 = 1_700_000_000;

fn identity(byte: u8) -> Identity {
    Identity::from_signing_key(SigningKey::from_bytes(&[byte; 32]))
}

fn paths(dir: &TempDir) -> (std::path::PathBuf, std::path::PathBuf) {
    (
        dir.path().join("peers.json"),
        dir.path().join("tickets.json"),
    )
}

fn options<'a>(
    identity: &'a Identity,
    peer_store_path: &'a std::path::Path,
    ticket_store_path: &'a std::path::Path,
) -> ResolveTargetOptions<'a> {
    ResolveTargetOptions {
        identity,
        caps: interactive_shell_caps(),
        peer_store_path,
        ticket_store_path,
        now_unix: NOW,
        ephemeral_ttl_secs: 300,
    }
}

#[test]
fn peer_label_mints_fresh_identity_bound_ticket() {
    let dir = TempDir::new().unwrap();
    let (peer_path, ticket_path) = paths(&dir);
    let local = identity(1);
    let remote = identity(2);
    let endpoint_id_hex = hex::encode(remote.endpoint_id().as_bytes());

    let mut peers = PeerStore::new();
    peers
        .insert_or_update(PeerEntry {
            label: "devbox".to_owned(),
            endpoint_id_hex: endpoint_id_hex.clone(),
            accepts_from_them: false,
            they_accept_from_me: true,
            since: NOW - 60,
            origin: PeerOrigin::Paired,
            last_hold_at: None,
            is_self: false,
            relay_hint: Some("https://relay.example.invalid".to_owned()),
            schema_version: 2,
        })
        .unwrap();
    peers.save(&peer_path).unwrap();

    let resolved = resolve_target("devbox", options(&local, &peer_path, &ticket_path)).unwrap();

    assert_eq!(resolved.source, TargetSource::PeerStore);
    assert_eq!(resolved.ticket.addr.id, remote.endpoint_id());
    assert_eq!(
        hex::encode(resolved.ticket.addr.id.as_bytes()),
        endpoint_id_hex
    );
    assert_eq!(resolved.ticket.body.to, Some(local.verifying_key()));
    assert_eq!(resolved.ticket.body.not_before, NOW);
    assert_eq!(resolved.ticket.body.not_after, NOW + 300);
    assert_eq!(resolved.expires_at, NOW + 300);
}

#[test]
fn saved_ticket_label_returns_stored_unexpired_ticket() {
    let dir = TempDir::new().unwrap();
    let (peer_path, ticket_path) = paths(&dir);
    let local = identity(3);
    let issuer = identity(4);
    let remote = identity(5);
    let ticket = mint_root(
        issuer.signing_key(),
        EndpointAddr::new(remote.endpoint_id()),
        interactive_shell_caps(),
        NOW - 10,
        NOW + 3_600,
        Some(local.verifying_key()),
    )
    .unwrap();
    let ticket_string = ticket.encode_string();

    let mut tickets = TicketStore::new();
    tickets
        .insert(
            "shared-session".to_owned(),
            TicketEntry {
                endpoint_id_hex: hex::encode(remote.endpoint_id().as_bytes()),
                ticket_string: ticket_string.clone(),
                expires_at: NOW + 3_600,
                saved_at: NOW - 5,
                session_share: None,
            },
        )
        .unwrap();
    tickets.save(&ticket_path).unwrap();

    let resolved =
        resolve_target("shared-session", options(&local, &peer_path, &ticket_path)).unwrap();

    assert_eq!(resolved.source, TargetSource::TicketStore);
    assert_eq!(resolved.ticket, ticket);
    assert_eq!(resolved.ticket_string, ticket_string);
    assert_eq!(resolved.expires_at, NOW + 3_600);
}

#[test]
fn expired_saved_ticket_label_is_rejected() {
    let dir = TempDir::new().unwrap();
    let (peer_path, ticket_path) = paths(&dir);
    let local = identity(6);
    let issuer = identity(7);
    let remote = identity(8);
    let ticket = mint_root(
        issuer.signing_key(),
        EndpointAddr::new(remote.endpoint_id()),
        interactive_shell_caps(),
        NOW - 100,
        NOW - 1,
        Some(local.verifying_key()),
    )
    .unwrap();

    let mut tickets = TicketStore::new();
    tickets
        .insert(
            "old-share".to_owned(),
            TicketEntry {
                endpoint_id_hex: hex::encode(remote.endpoint_id().as_bytes()),
                ticket_string: ticket.encode_string(),
                expires_at: NOW - 1,
                saved_at: NOW - 100,
                session_share: None,
            },
        )
        .unwrap();
    tickets.save(&ticket_path).unwrap();

    let err = resolve_target("old-share", options(&local, &peer_path, &ticket_path)).unwrap_err();

    assert!(err.to_string().contains("expired"), "{err}");
}

#[test]
fn inbound_only_peer_without_saved_ticket_is_rejected() {
    let dir = TempDir::new().unwrap();
    let (peer_path, ticket_path) = paths(&dir);
    let local = identity(9);
    let remote = identity(10);

    let mut peers = PeerStore::new();
    peers
        .insert_or_update(PeerEntry {
            label: "inbound-only".to_owned(),
            endpoint_id_hex: hex::encode(remote.endpoint_id().as_bytes()),
            accepts_from_them: true,
            they_accept_from_me: false,
            since: NOW - 60,
            origin: PeerOrigin::Paired,
            last_hold_at: None,
            is_self: false,
            relay_hint: None,
            schema_version: 2,
        })
        .unwrap();
    peers.save(&peer_path).unwrap();

    let err =
        resolve_target("inbound-only", options(&local, &peer_path, &ticket_path)).unwrap_err();

    assert!(err.to_string().contains("inbound-only"), "{err}");
}

#[test]
fn raw_endpoint_id_mints_fresh_ticket() {
    let dir = TempDir::new().unwrap();
    let (peer_path, ticket_path) = paths(&dir);
    let local = identity(11);
    let remote = identity(12);
    let endpoint_id = remote.endpoint_id();
    let endpoint_id_hex = hex::encode(endpoint_id.as_bytes());

    let resolved =
        resolve_target(&endpoint_id_hex, options(&local, &peer_path, &ticket_path)).unwrap();

    assert_eq!(resolved.source, TargetSource::RawEndpointId);
    assert_eq!(
        resolved.ticket.addr.id,
        EndpointId::from_bytes(endpoint_id.as_bytes()).unwrap()
    );
    assert_eq!(resolved.ticket.body.to, Some(local.verifying_key()));
    assert_eq!(resolved.expires_at, NOW + 300);
}
