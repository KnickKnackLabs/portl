use iroh_base::{EndpointAddr, EndpointId};
use portl_core::error::PortlError;
use portl_core::ticket::canonical::canonical_check_ticket;
use portl_core::ticket::master::{extract_bearer, mint_master};
use portl_core::ticket::schema::{Capabilities, PortRule};

fn addr_from_seed(seed: u8) -> EndpointAddr {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    EndpointAddr::new(EndpointId::from_bytes(&sk.verifying_key().to_bytes()).unwrap())
}

fn tcp_caps(port: u16) -> Capabilities {
    Capabilities {
        presence: 0b0000_0010,
        shell: None,
        tcp: Some(vec![PortRule {
            host_glob: "127.0.0.1".to_owned(),
            port_min: port,
            port_max: port,
        }]),
        udp: None,
        fs: None,
        vpn: None,
        meta: None,
    }
}

#[test]
fn master_ticket_roundtrips_bearer_extraction() {
    let issuer = ed25519_dalek::SigningKey::from_bytes(&[61u8; 32]);
    let ticket = mint_master(
        &issuer,
        addr_from_seed(62),
        tcp_caps(8080),
        b"slicer-token".to_vec(),
        600,
        Some([7u8; 32]),
    )
    .expect("mint master ticket");

    assert_eq!(extract_bearer(&ticket), Some(&b"slicer-token"[..]));
    canonical_check_ticket(&ticket).expect("master ticket stays canonical");
}

#[test]
fn canonical_rejects_empty_bearer_bytes() {
    let issuer = ed25519_dalek::SigningKey::from_bytes(&[63u8; 32]);
    let mut ticket = mint_master(
        &issuer,
        addr_from_seed(64),
        tcp_caps(8080),
        b"ok".to_vec(),
        600,
        None,
    )
    .expect("mint master ticket");
    ticket.body.bearer = Some(Vec::new());

    let err = canonical_check_ticket(&ticket).expect_err("empty bearer must be rejected");
    assert!(matches!(err, PortlError::Canonical(_)));
}

#[test]
fn mint_master_rejects_empty_bearer() {
    let issuer = ed25519_dalek::SigningKey::from_bytes(&[65u8; 32]);
    let err = mint_master(
        &issuer,
        addr_from_seed(66),
        tcp_caps(8080),
        Vec::new(),
        60,
        None,
    )
    .expect_err("empty bearer must fail");
    assert!(err.to_string().contains("non-empty"));
}
