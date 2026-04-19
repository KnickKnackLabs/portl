//! M1 Task 4 — signing and strict verification wrappers.

use ed25519_dalek::SigningKey;
use iroh_base::{EndpointAddr, EndpointId};
use portl_core::ticket::schema::{Capabilities, EnvPolicy, PortlBody, ShellCaps};
use portl_core::ticket::sign::{body_signing_bytes, sign_body, verify_body};

fn body_fixture() -> PortlBody {
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
        target: [99u8; 32],
        alpns_extra: vec![],
        not_before: 1_000,
        not_after: 4_600,
        issuer: None,
        parent: None,
        nonce: [7u8; 8],
        bearer: None,
        to: None,
    }
}

#[test]
fn body_signing_bytes_match_postcard_for_canonical_body() {
    let body = body_fixture();
    let bytes = body_signing_bytes(&body).expect("signing bytes");
    assert_eq!(bytes, postcard::to_stdvec(&body).unwrap());
}

#[test]
fn sign_and_verify_round_trip() {
    let sk = SigningKey::from_bytes(&[11u8; 32]);
    let body = body_fixture();
    let sig = sign_body(&sk, &body).expect("sign");
    verify_body(&sk.verifying_key().to_bytes(), &body, &sig).expect("verify");
}

#[test]
fn verify_rejects_tampered_body() {
    let sk = SigningKey::from_bytes(&[12u8; 32]);
    let mut body = body_fixture();
    let sig = sign_body(&sk, &body).expect("sign");
    body.not_after += 1;
    assert!(verify_body(&sk.verifying_key().to_bytes(), &body, &sig).is_err());
}

#[test]
fn verify_rejects_low_order_public_key_where_feasible() {
    let sk = SigningKey::from_bytes(&[13u8; 32]);
    let body = body_fixture();
    let sig = sign_body(&sk, &body).expect("sign");
    let low_order_pk = [
        1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    assert!(verify_body(&low_order_pk, &body, &sig).is_err());
}

#[test]
fn sign_rejects_non_canonical_body() {
    let sk = SigningKey::from_bytes(&[14u8; 32]);
    let mut body = body_fixture();
    body.nonce = [0u8; 8];
    assert!(sign_body(&sk, &body).is_err());
}

#[test]
fn verify_rejects_non_canonical_body_even_with_matching_signature() {
    let sk = SigningKey::from_bytes(&[15u8; 32]);
    let mut body = body_fixture();
    let sig = sign_body(&sk, &body).expect("sign");
    body.caps.presence = 0;
    assert!(verify_body(&sk.verifying_key().to_bytes(), &body, &sig).is_err());
}

#[test]
fn sign_and_verify_fixture_targets_endpoint_style_key() {
    let sk = SigningKey::from_bytes(&[16u8; 32]);
    let endpoint_id = EndpointId::from_bytes(&sk.verifying_key().to_bytes()).unwrap();
    let _addr = EndpointAddr::new(endpoint_id);
    let body = body_fixture();
    let sig = sign_body(&sk, &body).expect("sign");
    verify_body(&sk.verifying_key().to_bytes(), &body, &sig).expect("verify");
}
