use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use assert_cmd::cargo::CommandCargoExt;
use ed25519_dalek::SigningKey;
use iroh::EndpointAddr;
use iroh_tickets::Ticket;
use portl_core::id::Identity;
use portl_core::pair_accept::{SaveAcceptedPeerOptions, save_accepted_peer};
use portl_core::pair_code::{InitiatorMode, InviteCode};
use portl_core::target_resolve::interactive_shell_caps;
use portl_core::ticket::mint::mint_root;
use portl_core::ticket_store::TicketStore;

fn expires_at() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3_600
}

fn identity(byte: u8) -> Identity {
    Identity::from_signing_key(SigningKey::from_bytes(&[byte; 32]))
}

fn ticket(issuer: &Identity, expires: u64) -> String {
    mint_root(
        issuer.signing_key(),
        EndpointAddr::new(issuer.endpoint_id()),
        interactive_shell_caps(),
        expires.saturating_sub(7_200),
        expires,
        Some(issuer.verifying_key()),
    )
    .unwrap()
    .encode_string()
}

fn save(home: &Path, args: &[&str]) -> Output {
    Command::cargo_bin("portl")
        .unwrap()
        .env("PORTL_HOME", home)
        .args(["ticket", "save"])
        .args(args)
        .output()
        .unwrap()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn ticket_save_normalizes_labels_and_rejects_empty_labels() {
    let dir = tempfile::tempdir().unwrap();
    let ticket = ticket(&identity(1), expires_at());
    let output = save(dir.path(), &["  work  ", &ticket]);
    assert_success(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("saved ticket 'work'"));
    let path = dir.path().join("data/tickets.json");
    let stored = TicketStore::load(&path).unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored.get("work").unwrap().ticket_string, ticket);

    let before = fs::read(&path).unwrap();
    for label in ["", "   "] {
        let output = save(dir.path(), &[label, &ticket]);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("ticket label is empty"));
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}

#[test]
fn ticket_save_only_renews_with_later_access_for_the_same_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    let issuer = identity(2);
    let expires = expires_at();
    let original = ticket(&issuer, expires);
    assert_success(&save(dir.path(), &["work", &original]));
    let path = dir.path().join("data/tickets.json");
    let before = fs::read(&path).unwrap();

    for (candidate, message) in [
        (original, "expires later or at the same time"),
        (
            ticket(&issuer, expires - 1),
            "expires later or at the same time",
        ),
        (ticket(&identity(3), expires + 1), "different endpoint"),
        (ticket(&issuer, 1), "ticket expired"),
        ("not-a-ticket".to_owned(), "parse ticket"),
    ] {
        let output = save(dir.path(), &["work", &candidate]);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(message));
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    let renewed = ticket(&issuer, expires + 1);
    assert_success(&save(dir.path(), &["work", &renewed]));
    let stored = TicketStore::load(&path).unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored.get("work").unwrap().ticket_string, renewed);
    assert_eq!(stored.get("work").unwrap().expires_at, expires + 1);
}

#[test]
fn ticket_save_uses_peer_name_without_overwriting_peer_labels() {
    let dir = tempfile::tempdir().unwrap();
    let issuer = identity(4);
    let expires = expires_at();
    let peers_path = dir.path().join("data/peers.json");
    save_accepted_peer(
        &InviteCode::new(
            issuer.verifying_key(),
            rand::random(),
            expires,
            InitiatorMode::Them,
            None,
        ),
        SaveAcceptedPeerOptions {
            responder_self_label: Some("devbox"),
            responder_relay_hint: None,
            now_unix: 1,
        },
        &peers_path,
    )
    .unwrap();
    let peers_before = fs::read(&peers_path).unwrap();
    let ticket = ticket(&issuer, expires);
    let output = save(dir.path(), &[&ticket]);
    assert_success(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("saved ticket 'devbox-ticket-shell'"));
    let path = dir.path().join("data/tickets.json");
    let stored = TicketStore::load(&path).unwrap();
    assert_eq!(
        stored.get("devbox-ticket-shell").unwrap().ticket_string,
        ticket
    );

    let before = fs::read(&path).unwrap();
    let output = save(dir.path(), &["devbox", &ticket]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already in use by a peer"));
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(fs::read(&peers_path).unwrap(), peers_before);
}
