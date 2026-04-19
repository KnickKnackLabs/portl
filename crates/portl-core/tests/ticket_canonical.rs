//! M1 Task 2 — canonical-form rejection matrix per
//! `docs/design/030-tickets.md §2.2`.
//!
//! Eleven cases cover every rule the verifier enforces before a
//! signature is even checked. `canonical_check(body)` returns
//! `Ok(())` on a canonical body and `Err(PortlError::Canonical(_))`
//! otherwise. `resolved_issuer(ticket)` implements rule 1's key
//! resolution.

use iroh_base::{EndpointAddr, EndpointId};
use portl_core::error::PortlError;
use portl_core::ticket::canonical::{canonical_check, canonical_check_ticket, resolved_issuer};
use portl_core::ticket::schema::{
    Capabilities, EnvPolicy, PortRule, PortlBody, PortlTicket, ShellCaps,
};

// ---------- fixtures ----------

fn addr_from_seed(seed: u8) -> EndpointAddr {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    EndpointAddr::new(EndpointId::from_bytes(&sk.verifying_key().to_bytes()).unwrap())
}

fn canonical_body() -> PortlBody {
    let addr = addr_from_seed(7);
    PortlBody {
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
        target: *addr.id.as_bytes(),
        alpns_extra: vec![],
        not_before: 1_000,
        not_after: 2_000,
        issuer: None,
        parent: None,
        nonce: [1u8; 8],
        bearer: None,
        to: None,
    }
}

fn assert_canonical_err(body: &PortlBody) {
    let err = canonical_check(body).unwrap_err();
    assert!(
        matches!(err, PortlError::Canonical(_)),
        "expected Canonical error, got {err:?}"
    );
}

// ---------- rule 1: issuer elision ----------

#[test]
fn rejects_issuer_equal_to_addr_endpoint_id() {
    let addr = addr_from_seed(7);
    let bad_ticket = PortlTicket {
        v: 1,
        addr: addr.clone(),
        body: PortlBody {
            issuer: Some(*addr.id.as_bytes()),
            ..canonical_body()
        },
        sig: [0u8; 64],
    };
    let err = canonical_check_ticket(&bad_ticket).unwrap_err();
    assert!(
        matches!(err, PortlError::Canonical(_)),
        "expected Canonical, got {err:?}"
    );
    // resolved_issuer on an *elided* ticket still returns addr.endpoint_id.
    let good_ticket = PortlTicket {
        v: 1,
        addr: addr.clone(),
        body: canonical_body(),
        sig: [0u8; 64],
    };
    assert_eq!(resolved_issuer(&good_ticket), *addr.id.as_bytes());
}

#[test]
fn resolved_issuer_returns_explicit_key_when_different_from_addr() {
    let addr = addr_from_seed(7);
    let other = [9u8; 32];
    let ticket = PortlTicket {
        v: 1,
        addr,
        body: PortlBody {
            issuer: Some(other),
            ..canonical_body()
        },
        sig: [0u8; 64],
    };
    assert_eq!(resolved_issuer(&ticket), other);
}

// ---------- rule 2: presence bitmap ----------

#[test]
fn rejects_target_mismatch_with_addr_endpoint_id() {
    let mut body = canonical_body();
    body.target = [8u8; 32];
    let ticket = PortlTicket {
        v: 1,
        addr: addr_from_seed(7),
        body,
        sig: [0u8; 64],
    };
    let err = canonical_check_ticket(&ticket).unwrap_err();
    assert!(matches!(err, PortlError::Canonical(_)));
}

#[test]
fn rejects_presence_bit_set_but_body_none() {
    let mut body = canonical_body();
    body.caps.shell = None; // bit 0 still set
    assert_canonical_err(&body);
}

#[test]
fn rejects_presence_bit_clear_but_body_some() {
    let mut body = canonical_body();
    body.caps.presence = 0b0000_0000; // shell still Some
    assert_canonical_err(&body);
}

// ---------- rule 3: sorted + dedup vecs ----------

#[test]
fn rejects_unsorted_port_rules() {
    let rules = vec![
        PortRule {
            host_glob: "b.example".into(),
            port_min: 80,
            port_max: 80,
        },
        PortRule {
            host_glob: "a.example".into(),
            port_min: 80,
            port_max: 80,
        },
    ];
    let mut body = canonical_body();
    body.caps.presence = 0b0000_0011;
    body.caps.tcp = Some(rules);
    assert_canonical_err(&body);
}

#[test]
fn rejects_duplicate_port_rules() {
    let rule = PortRule {
        host_glob: "a.example".into(),
        port_min: 22,
        port_max: 22,
    };
    let mut body = canonical_body();
    body.caps.presence = 0b0000_0011;
    body.caps.tcp = Some(vec![rule.clone(), rule]);
    assert_canonical_err(&body);
}

#[test]
fn rejects_unsorted_alpns_extra_even_though_field_must_be_empty_in_v01() {
    // v0.1 requires alpns_extra to be empty; canonical_check
    // enforces that directly (any non-empty value is rejected).
    let mut body = canonical_body();
    body.alpns_extra = vec!["z".into(), "a".into()];
    assert_canonical_err(&body);
}

// ---------- rule 4: timestamps / nonce ----------

#[test]
fn rejects_not_after_equal_to_not_before() {
    let mut body = canonical_body();
    body.not_before = 1_000;
    body.not_after = 1_000;
    assert_canonical_err(&body);
}

#[test]
fn rejects_not_after_before_not_before() {
    let mut body = canonical_body();
    body.not_before = 2_000;
    body.not_after = 1_000;
    assert_canonical_err(&body);
}

#[test]
fn rejects_ttl_exceeds_365_days() {
    let mut body = canonical_body();
    body.not_before = 0;
    body.not_after = 366 * 86_400;
    assert_canonical_err(&body);
}

#[test]
fn rejects_zero_nonce() {
    let mut body = canonical_body();
    body.nonce = [0u8; 8];
    assert_canonical_err(&body);
}

// ---------- accept path ----------

#[test]
fn accepts_canonical_body() {
    canonical_check(&canonical_body()).expect("canonical body must pass");
}

#[test]
fn accepts_body_with_sorted_unique_port_rules() {
    let rules = vec![
        PortRule {
            host_glob: "a.example".into(),
            port_min: 22,
            port_max: 22,
        },
        PortRule {
            host_glob: "b.example".into(),
            port_min: 80,
            port_max: 80,
        },
    ];
    let mut body = canonical_body();
    body.caps.presence = 0b0000_0011;
    body.caps.tcp = Some(rules);
    canonical_check(&body).expect("sorted unique rules must pass");
}
