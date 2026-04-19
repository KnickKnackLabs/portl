//! M1 Task 1: verify the ticket schema types compile and compose as
//! described in `docs/design/030-tickets.md §2`.
//!
//! This is the very first ticket-related test; it only exercises
//! type construction. Canonicalisation, codec, and verification
//! tests live in their own files (M1 Task 2+).

use iroh_base::{EndpointAddr, EndpointId};
use portl_core::ticket::schema::{Capabilities, EnvPolicy, PortlBody, PortlTicket, ShellCaps};

fn dummy_endpoint_id() -> EndpointId {
    // Deterministic ed25519 key so the test is reproducible.
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0u8; 32]);
    EndpointId::from_bytes(&sk.verifying_key().to_bytes()).expect("valid endpoint id")
}

#[test]
fn can_construct_minimal_self_signed_root_ticket() {
    let ticket = PortlTicket {
        v: 1,
        addr: EndpointAddr::new(dummy_endpoint_id()),
        body: PortlBody {
            caps: Capabilities {
                presence: 0b0000_0001,
                shell: Some(ShellCaps {
                    user_allowlist: None,
                    pty_allowed: true,
                    exec_allowed: false,
                    command_allowlist: None,
                    env_policy: EnvPolicy::Deny,
                }),
                tcp: None,
                udp: None,
                fs: None,
                vpn: None,
                meta: None,
            },
            alpns_extra: vec![],
            not_before: 0,
            not_after: 3600,
            issuer: None,
            parent: None,
            nonce: [1u8; 8],
            bearer: None,
            to: None,
        },
        sig: [0u8; 64],
    };

    assert_eq!(ticket.v, 1);
    assert_eq!(ticket.body.caps.presence, 0b0000_0001);
    assert!(ticket.body.caps.shell.is_some());
    assert!(ticket.body.parent.is_none());
    assert!(ticket.body.issuer.is_none());
}

#[test]
fn all_capability_bodies_are_optional_at_construction() {
    // Regression sentinel: every field under Capabilities is Option<..>
    // so presence-bit enforcement (§2.2 rule 2) has something to elide.
    let caps = Capabilities {
        presence: 0,
        shell: None,
        tcp: None,
        udp: None,
        fs: None,
        vpn: None,
        meta: None,
    };
    assert_eq!(caps.presence, 0);
}
