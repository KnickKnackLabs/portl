//! M1 Task 6 — delegation-chain verification.

use std::collections::HashSet;

use ed25519_dalek::SigningKey;
use iroh_base::{EndpointAddr, EndpointId};
use portl_core::error::PortlError;
use portl_core::ticket::hash::parent_ticket_id;
use portl_core::ticket::mint::{mint_delegated, mint_root};
use portl_core::ticket::schema::{
    Capabilities, Delegation, EnvPolicy, PortRule, PortlBody, PortlTicket, ShellCaps,
};
use portl_core::ticket::sign::sign_body;
use portl_core::ticket::verify::{MAX_DELEGATION_DEPTH, TrustRoots, verify_chain};

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

fn trust_root_for(sk: &SigningKey) -> TrustRoots {
    TrustRoots(HashSet::from([sk.verifying_key().to_bytes()]))
}

fn forge_child(
    signer: &SigningKey,
    parent: &PortlTicket,
    caps: Capabilities,
    not_before: u64,
    not_after: u64,
    depth_remaining: u8,
) -> PortlTicket {
    let body = PortlBody {
        caps,
        target: parent.body.target,
        alpns_extra: vec![],
        not_before,
        not_after,
        issuer: if signer.verifying_key().to_bytes() == *parent.addr.id.as_bytes() {
            None
        } else {
            Some(signer.verifying_key().to_bytes())
        },
        parent: Some(Delegation {
            parent_ticket_id: parent_ticket_id(&parent.sig),
            depth_remaining,
        }),
        nonce: [9u8; 8],
        bearer: None,
        to: None,
    };
    let sig = sign_body(signer, &body).unwrap();
    PortlTicket {
        v: 1,
        addr: parent.addr.clone(),
        body,
        sig,
    }
}

#[test]
fn verify_chain_accepts_root_only() {
    let signer = SigningKey::from_bytes(&[31u8; 32]);
    let root = mint_root(
        &signer,
        endpoint_addr_from_key(&signer),
        shell_caps(),
        1_000,
        4_600,
        None,
    )
    .unwrap();

    let caps = verify_chain(&root, &[], &trust_root_for(&signer), 1_000).expect("verify root");
    assert_eq!(caps, shell_caps());
}

#[test]
fn verify_chain_accepts_three_hop_chain() {
    let signer = SigningKey::from_bytes(&[32u8; 32]);
    let root = mint_root(
        &signer,
        endpoint_addr_from_key(&signer),
        shell_and_tcp_caps(),
        1_000,
        4_600,
        None,
    )
    .unwrap();
    let child1 = mint_delegated(&signer, &root, shell_caps(), 1_100, 4_500, None).unwrap();
    let child2 = mint_delegated(&signer, &child1, shell_caps(), 1_200, 4_400, None).unwrap();
    let child3 = mint_delegated(&signer, &child2, shell_caps(), 1_300, 4_300, None).unwrap();

    let caps = verify_chain(
        &child3,
        &[root, child1, child2],
        &trust_root_for(&signer),
        1_350,
    )
    .expect("verify chain");
    assert_eq!(caps, shell_caps());
}

#[test]
fn verify_chain_rejects_broken_hop_2_signature() {
    let signer = SigningKey::from_bytes(&[33u8; 32]);
    let root = mint_root(
        &signer,
        endpoint_addr_from_key(&signer),
        shell_caps(),
        1_000,
        4_600,
        None,
    )
    .unwrap();
    let child1 = mint_delegated(&signer, &root, shell_caps(), 1_100, 4_500, None).unwrap();
    let mut child2 = mint_delegated(&signer, &child1, shell_caps(), 1_200, 4_400, None).unwrap();
    child2.sig[0] ^= 0x01;

    assert!(verify_chain(&child2, &[root, child1], &trust_root_for(&signer), 1_250).is_err());
}

#[test]
fn verify_chain_rejects_nine_hops() {
    let signer = SigningKey::from_bytes(&[34u8; 32]);
    let root = mint_root(
        &signer,
        endpoint_addr_from_key(&signer),
        shell_caps(),
        1_000,
        4_600,
        None,
    )
    .unwrap();

    let mut tickets = vec![root.clone()];
    let mut parent = root;
    for depth in (0..MAX_DELEGATION_DEPTH).rev() {
        let child = forge_child(&signer, &parent, shell_caps(), 1_100, 4_500, depth);
        tickets.push(child.clone());
        parent = child;
    }
    let terminal = forge_child(&signer, &parent, shell_caps(), 1_200, 4_400, 0);

    assert!(verify_chain(&terminal, &tickets, &trust_root_for(&signer), 1_300).is_err());
}

#[test]
fn verify_chain_rejects_mismatched_endpoint_ids() {
    let signer = SigningKey::from_bytes(&[35u8; 32]);
    let root = mint_root(
        &signer,
        endpoint_addr_from_key(&signer),
        shell_caps(),
        1_000,
        4_600,
        None,
    )
    .unwrap();
    let mut child = mint_delegated(&signer, &root, shell_caps(), 1_100, 4_500, None).unwrap();
    let other = SigningKey::from_bytes(&[36u8; 32]);
    child.addr = endpoint_addr_from_key(&other);

    assert!(verify_chain(&child, &[root], &trust_root_for(&signer), 1_200).is_err());
}

#[test]
fn verify_chain_rejects_unknown_root() {
    let signer = SigningKey::from_bytes(&[37u8; 32]);
    let root = mint_root(
        &signer,
        endpoint_addr_from_key(&signer),
        shell_caps(),
        1_000,
        4_600,
        None,
    )
    .unwrap();

    assert!(verify_chain(&root, &[], &TrustRoots(HashSet::new()), 1_200).is_err());
}

#[test]
fn verify_chain_rejects_widening_caps_in_chain() {
    let signer = SigningKey::from_bytes(&[38u8; 32]);
    let root = mint_root(
        &signer,
        endpoint_addr_from_key(&signer),
        shell_caps(),
        1_000,
        4_600,
        None,
    )
    .unwrap();
    let widened = forge_child(
        &signer,
        &root,
        shell_and_tcp_caps(),
        1_100,
        4_500,
        MAX_DELEGATION_DEPTH - 1,
    );

    assert!(verify_chain(&widened, &[root], &trust_root_for(&signer), 1_200).is_err());
}

#[test]
fn verify_chain_honors_clock_skew_boundaries() {
    let signer = SigningKey::from_bytes(&[39u8; 32]);
    let root = mint_root(
        &signer,
        endpoint_addr_from_key(&signer),
        shell_caps(),
        1_000,
        4_600,
        None,
    )
    .unwrap();

    assert!(verify_chain(&root, &[], &trust_root_for(&signer), 939).is_err());
    assert!(verify_chain(&root, &[], &trust_root_for(&signer), 940).is_ok());
    assert!(verify_chain(&root, &[], &trust_root_for(&signer), 4_599).is_ok());
    assert!(verify_chain(&root, &[], &trust_root_for(&signer), 4_600).is_err());
}

#[test]
fn verify_rejects_forged_target_on_operator_issued_ticket() {
    let operator = SigningKey::from_bytes(&[41u8; 32]);
    let target = SigningKey::from_bytes(&[42u8; 32]);
    let mut ticket = mint_root(
        &operator,
        endpoint_addr_from_key(&target),
        shell_caps(),
        1_000,
        4_600,
        None,
    )
    .unwrap();
    let forged = SigningKey::from_bytes(&[43u8; 32]);
    ticket.addr = endpoint_addr_from_key(&forged);

    let err = verify_chain(&ticket, &[], &trust_root_for(&operator), 1_200).unwrap_err();
    assert!(matches!(
        err,
        PortlError::Canonical("body.target does not match addr.endpoint_id")
    ));
}

#[test]
fn verify_rejects_child_whose_resolved_issuer_mismatches_parent_key() {
    let operator = SigningKey::from_bytes(&[44u8; 32]);
    let target = SigningKey::from_bytes(&[45u8; 32]);
    let pivot = SigningKey::from_bytes(&[46u8; 32]);
    let root = mint_root(
        &operator,
        endpoint_addr_from_key(&target),
        shell_caps(),
        1_000,
        4_600,
        None,
    )
    .unwrap();
    let body = PortlBody {
        caps: shell_caps(),
        target: root.body.target,
        alpns_extra: vec![],
        not_before: 1_100,
        not_after: 4_500,
        issuer: Some(pivot.verifying_key().to_bytes()),
        parent: Some(Delegation {
            parent_ticket_id: parent_ticket_id(&root.sig),
            depth_remaining: MAX_DELEGATION_DEPTH - 1,
        }),
        nonce: [47u8; 8],
        bearer: None,
        to: None,
    };
    let sig = sign_body(&operator, &body).unwrap();
    let child = PortlTicket {
        v: 1,
        addr: root.addr.clone(),
        body,
        sig,
    };

    let err = verify_chain(&child, &[root], &trust_root_for(&operator), 1_200).unwrap_err();
    assert!(matches!(
        err,
        PortlError::Chain("child issuer does not match parent authority")
    ));
}

#[test]
fn verify_rejects_child_introducing_bearer() {
    let signer = SigningKey::from_bytes(&[47u8; 32]);
    let root = mint_root(
        &signer,
        endpoint_addr_from_key(&signer),
        shell_caps(),
        1_000,
        4_600,
        None,
    )
    .unwrap();
    let mut child = mint_delegated(&signer, &root, shell_caps(), 1_100, 4_500, None).unwrap();
    child.body.bearer = Some(b"slicer-token".to_vec());
    child.sig = sign_body(&signer, &child.body).unwrap();

    let err = verify_chain(&child, &[root], &trust_root_for(&signer), 1_200).unwrap_err();
    assert!(matches!(
        err,
        PortlError::Chain("child introduces bearer not present in parent")
    ));
}

#[test]
fn verify_chain_verifies_before_hashing_parent_signature() {
    let signer = SigningKey::from_bytes(&[40u8; 32]);
    let root = mint_root(
        &signer,
        endpoint_addr_from_key(&signer),
        shell_caps(),
        1_000,
        4_600,
        None,
    )
    .unwrap();
    let mut forged_parent = root;
    forged_parent.sig[0] ^= 0x80;

    let child = forge_child(
        &signer,
        &forged_parent,
        shell_caps(),
        1_100,
        4_500,
        MAX_DELEGATION_DEPTH - 1,
    );

    assert!(verify_chain(&child, &[forged_parent], &trust_root_for(&signer), 1_200).is_err());
}
