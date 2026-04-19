//! M1 Task 5 — minting root and delegated tickets.

use ed25519_dalek::SigningKey;
use iroh_base::{EndpointAddr, EndpointId};
use portl_core::ticket::canonical::resolved_issuer;
use portl_core::ticket::hash::parent_ticket_id;
use portl_core::ticket::schema::{Capabilities, Delegation, EnvPolicy, PortRule, ShellCaps};
use portl_core::ticket::sign::verify_body;
use portl_core::ticket::{mint::mint_delegated, mint::mint_root, verify::MAX_DELEGATION_DEPTH};

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

fn shell_and_tcp_caps() -> Capabilities {
    Capabilities {
        presence: 0b0000_0011,
        shell: Some(ShellCaps {
            user_allowlist: None,
            pty_allowed: true,
            exec_allowed: true,
            command_allowlist: None,
            env_policy: EnvPolicy::Deny,
        }),
        tcp: Some(vec![PortRule {
            host_glob: "127.0.0.1".into(),
            port_min: 22,
            port_max: 22,
        }]),
        udp: None,
        fs: None,
        vpn: None,
        meta: None,
    }
}

#[test]
fn mint_root_self_signed_elides_issuer() {
    let sk = SigningKey::from_bytes(&[21u8; 32]);
    let addr = endpoint_addr_from_key(&sk);
    let ticket = mint_root(&sk, addr, shell_caps(), 1_000, 4_600, None).expect("mint root");
    assert_eq!(ticket.body.issuer, None);
    verify_body(&resolved_issuer(&ticket), &ticket.body, &ticket.sig).expect("verify");
}

#[test]
fn mint_root_operator_issued_sets_explicit_issuer() {
    let signer = SigningKey::from_bytes(&[22u8; 32]);
    let target = SigningKey::from_bytes(&[23u8; 32]);
    let addr = endpoint_addr_from_key(&target);
    let ticket = mint_root(&signer, addr, shell_caps(), 1_000, 4_600, None).expect("mint root");
    assert_eq!(ticket.body.issuer, Some(signer.verifying_key().to_bytes()));
    verify_body(&resolved_issuer(&ticket), &ticket.body, &ticket.sig).expect("verify");
}

#[test]
fn mint_delegated_narrows_caps() {
    let signer = SigningKey::from_bytes(&[24u8; 32]);
    let parent = mint_root(
        &signer,
        endpoint_addr_from_key(&signer),
        shell_and_tcp_caps(),
        1_000,
        4_600,
        None,
    )
    .expect("parent root");

    let child =
        mint_delegated(&signer, &parent, shell_caps(), 1_100, 4_500, None).expect("mint delegated");

    assert_eq!(child.body.caps, shell_caps());
    assert_eq!(
        child.body.parent,
        Some(Delegation {
            parent_ticket_id: parent_ticket_id(&parent.sig),
            depth_remaining: MAX_DELEGATION_DEPTH - 1,
        })
    );
}

#[test]
fn mint_delegated_preserves_addr() {
    let signer = SigningKey::from_bytes(&[25u8; 32]);
    let parent = mint_root(
        &signer,
        endpoint_addr_from_key(&signer),
        shell_and_tcp_caps(),
        1_000,
        4_600,
        None,
    )
    .expect("parent root");

    let child =
        mint_delegated(&signer, &parent, shell_caps(), 1_100, 4_500, None).expect("mint delegated");

    assert_eq!(child.addr, parent.addr);
    verify_body(&resolved_issuer(&child), &child.body, &child.sig).expect("verify");
}

#[test]
fn mint_delegated_rejects_widening_caps() {
    let signer = SigningKey::from_bytes(&[26u8; 32]);
    let parent = mint_root(
        &signer,
        endpoint_addr_from_key(&signer),
        shell_caps(),
        1_000,
        4_600,
        None,
    )
    .expect("parent root");

    assert!(mint_delegated(&signer, &parent, shell_and_tcp_caps(), 1_100, 4_500, None).is_err());
}

#[test]
fn mint_root_rejects_ttl_out_of_bounds() {
    let signer = SigningKey::from_bytes(&[27u8; 32]);
    assert!(
        mint_root(
            &signer,
            endpoint_addr_from_key(&signer),
            shell_caps(),
            0,
            366 * 86_400,
            None,
        )
        .is_err()
    );
}

#[test]
fn mint_delegated_rejects_window_outside_parent() {
    let signer = SigningKey::from_bytes(&[28u8; 32]);
    let parent = mint_root(
        &signer,
        endpoint_addr_from_key(&signer),
        shell_caps(),
        1_000,
        4_600,
        None,
    )
    .expect("parent root");

    assert!(mint_delegated(&signer, &parent, shell_caps(), 999, 4_500, None).is_err());
    assert!(mint_delegated(&signer, &parent, shell_caps(), 1_100, 4_601, None).is_err());
}
