//! M1 Task 8 — proof-of-possession for `to`-bound tickets.

use ed25519_dalek::SigningKey;
use iroh_base::{EndpointAddr, EndpointId};
use portl_core::ticket::hash::ticket_id;
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::offer::{compute_pop_sig, validate_ticket_proof, verify_pop};
use portl_core::ticket::schema::{Capabilities, EnvPolicy, ShellCaps};

fn endpoint_addr_from_key(sk: &SigningKey) -> EndpointAddr {
    EndpointAddr::new(EndpointId::from_bytes(&sk.verifying_key().to_bytes()).unwrap())
}

fn shell_caps() -> Capabilities {
    Capabilities {
        presence: 0b0000_0001,
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

#[test]
fn correct_holder_passes() {
    let issuer = SigningKey::from_bytes(&[41u8; 32]);
    let holder = SigningKey::from_bytes(&[42u8; 32]);
    let ticket = mint_root(
        &issuer,
        endpoint_addr_from_key(&issuer),
        shell_caps(),
        1_000,
        4_600,
        Some(holder.verifying_key().to_bytes()),
    )
    .unwrap();
    let nonce = [7u8; 16];
    let id = ticket_id(&ticket.sig);
    let proof = compute_pop_sig(&holder, &id, &nonce);

    verify_pop(&holder.verifying_key().to_bytes(), &id, &nonce, &proof).unwrap();
    validate_ticket_proof(&ticket, &nonce, Some(&proof)).unwrap();
}

#[test]
fn wrong_holder_fails() {
    let issuer = SigningKey::from_bytes(&[43u8; 32]);
    let holder = SigningKey::from_bytes(&[44u8; 32]);
    let wrong = SigningKey::from_bytes(&[45u8; 32]);
    let ticket = mint_root(
        &issuer,
        endpoint_addr_from_key(&issuer),
        shell_caps(),
        1_000,
        4_600,
        Some(holder.verifying_key().to_bytes()),
    )
    .unwrap();
    let nonce = [8u8; 16];
    let id = ticket_id(&ticket.sig);
    let proof = compute_pop_sig(&wrong, &id, &nonce);

    assert!(verify_pop(&holder.verifying_key().to_bytes(), &id, &nonce, &proof).is_err());
    assert!(validate_ticket_proof(&ticket, &nonce, Some(&proof)).is_err());
}

#[test]
fn wrong_nonce_fails() {
    let issuer = SigningKey::from_bytes(&[46u8; 32]);
    let holder = SigningKey::from_bytes(&[47u8; 32]);
    let ticket = mint_root(
        &issuer,
        endpoint_addr_from_key(&issuer),
        shell_caps(),
        1_000,
        4_600,
        Some(holder.verifying_key().to_bytes()),
    )
    .unwrap();
    let nonce = [9u8; 16];
    let wrong_nonce = [10u8; 16];
    let id = ticket_id(&ticket.sig);
    let proof = compute_pop_sig(&holder, &id, &nonce);

    assert!(
        verify_pop(
            &holder.verifying_key().to_bytes(),
            &id,
            &wrong_nonce,
            &proof
        )
        .is_err()
    );
    assert!(validate_ticket_proof(&ticket, &wrong_nonce, Some(&proof)).is_err());
}

#[test]
fn missing_proof_when_to_is_set_fails() {
    let issuer = SigningKey::from_bytes(&[48u8; 32]);
    let holder = SigningKey::from_bytes(&[49u8; 32]);
    let ticket = mint_root(
        &issuer,
        endpoint_addr_from_key(&issuer),
        shell_caps(),
        1_000,
        4_600,
        Some(holder.verifying_key().to_bytes()),
    )
    .unwrap();

    assert!(validate_ticket_proof(&ticket, &[11u8; 16], None).is_err());
}

#[test]
fn bearer_ticket_ignores_proof() {
    let issuer = SigningKey::from_bytes(&[50u8; 32]);
    let holder = SigningKey::from_bytes(&[51u8; 32]);
    let ticket = mint_root(
        &issuer,
        endpoint_addr_from_key(&issuer),
        shell_caps(),
        1_000,
        4_600,
        None,
    )
    .unwrap();
    let nonce = [12u8; 16];
    let proof = compute_pop_sig(&holder, &ticket_id(&ticket.sig), &nonce);

    validate_ticket_proof(&ticket, &nonce, None).unwrap();
    validate_ticket_proof(&ticket, &nonce, Some(&proof)).unwrap();
}
