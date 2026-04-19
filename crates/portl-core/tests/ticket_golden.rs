//! M1 Task 9 — golden postcard bytes for a deterministic ticket.

use ed25519_dalek::SigningKey;
use iroh_base::{EndpointAddr, EndpointId};
use portl_core::ticket::codec::encode;
use portl_core::ticket::schema::{Capabilities, EnvPolicy, PortlBody, PortlTicket, ShellCaps};
use portl_core::ticket::sign::sign_body;

const EXPECTED_HEX: &str = "01197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d6100010100010100000000000000197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d6100e807f823000042424242424242420000d81a17ed8a29c0e61cb919746eab0f049618c43c40a4e77f2d642b91207e77b8795154cf227d914aadeb67b29703f093876a69633ee3046f9151ff9095d6a80a";

fn fixture() -> PortlTicket {
    let sk = SigningKey::from_bytes(&[42u8; 32]);
    let addr = EndpointAddr::new(EndpointId::from_bytes(&sk.verifying_key().to_bytes()).unwrap());
    let body = PortlBody {
        caps: Capabilities {
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
        },
        target: *addr.id.as_bytes(),
        alpns_extra: vec![],
        not_before: 1_000,
        not_after: 4_600,
        issuer: None,
        parent: None,
        nonce: [0x42u8; 8],
        bearer: None,
        to: None,
    };
    let sig = sign_body(&sk, &body).unwrap();
    PortlTicket {
        v: 1,
        addr,
        body,
        sig,
    }
}

#[test]
fn root_fixture_matches_expected_hex() {
    let actual = encode(&fixture()).unwrap();
    let actual_hex = hex::encode(&actual);
    assert_eq!(actual_hex, EXPECTED_HEX, "actual hex: {actual_hex}");
}
