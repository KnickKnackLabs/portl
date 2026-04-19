//! M1 Task 3 — postcard codec roundtrip + `iroh_tickets::Ticket`
//! integration. Canonical-form enforcement is already covered in
//! `ticket_canonical.rs`; here we only exercise the codec surface.

use ed25519_dalek::{Signer, SigningKey};
use iroh_base::{EndpointAddr, EndpointId};
use portl_core::ticket::{
    canonical::canonical_check_ticket,
    codec::{decode, encode},
    schema::{Capabilities, EnvPolicy, PortlBody, PortlTicket, ShellCaps},
};

fn fixture_signed_root() -> PortlTicket {
    let sk = SigningKey::from_bytes(&[42u8; 32]);
    let vk = sk.verifying_key().to_bytes();
    let addr = EndpointAddr::new(EndpointId::from_bytes(&vk).unwrap());
    let body = PortlBody {
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
        not_before: 1_000,
        not_after: 1_000 + 3600,
        issuer: None,
        parent: None,
        nonce: [7u8; 8],
        bearer: None,
        to: None,
    };
    // sign the encoded body; caller of `encode` will enforce that the
    // signed bytes are what postcard round-trips.
    let body_bytes = postcard::to_stdvec(&body).unwrap();
    let sig = sk.sign(&body_bytes).to_bytes();
    let ticket = PortlTicket {
        v: 1,
        addr,
        body,
        sig,
    };
    canonical_check_ticket(&ticket).expect("fixture must be canonical");
    ticket
}

#[test]
fn roundtrip_postcard_ok() {
    let t = fixture_signed_root();
    let bytes = encode(&t).expect("encode");
    let back = decode(&bytes).expect("decode");
    assert_eq!(t, back);
}

#[test]
fn decode_rejects_garbage() {
    let err = decode(&[0xff, 0xff, 0xff, 0xff]);
    assert!(err.is_err(), "garbage must be rejected");
}

#[test]
fn decode_rejects_body_with_non_canonical_presence_bitmap() {
    let mut t = fixture_signed_root();
    // Flip presence to claim tcp is present while leaving tcp == None.
    t.body.caps.presence = 0b0000_0011;
    let bytes = postcard::to_stdvec(&t).unwrap();
    let err = decode(&bytes).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("canonical") || msg.contains("presence"),
        "expected canonical/presence error, got {msg}"
    );
}

#[test]
fn iroh_tickets_display_starts_with_portl_prefix() {
    use iroh_tickets::Ticket;
    let t = fixture_signed_root();
    let s = t.serialize();
    assert!(
        s.starts_with(<PortlTicket as Ticket>::KIND),
        "iroh_tickets Display should emit KIND prefix; got {s}"
    );
}

#[test]
fn iroh_tickets_parse_roundtrip() {
    use iroh_tickets::Ticket;
    let t = fixture_signed_root();
    let s = t.serialize();
    let back = PortlTicket::deserialize(&s).expect("deserialize");
    assert_eq!(t, back);
}
