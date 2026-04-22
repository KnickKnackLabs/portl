//! `ticket_misc`: merged small ticket_* integration test files.
//! Merged per `TEST_BUILD_TUNING.md` to cut the number of nextest
//! binaries. Each former top-level file is preserved verbatim under
//! a `mod` with the same name so tests keep their fully-qualified
//! test ids unchanged (e.g. `ticket_hash::foo` still exists, just as
//! `ticket_misc::ticket_hash::foo` now).

mod ticket_hash {
    //! M1 Task 4 — domain-separated ticket-id helpers.

    use portl_core::ticket::hash::{parent_ticket_id, ticket_id};

    #[test]
    fn ticket_id_and_parent_ticket_id_are_domain_separated() {
        let sig = [0x5au8; 64];
        assert_ne!(ticket_id(&sig), parent_ticket_id(&sig));
    }

    #[test]
    fn ticket_ids_are_16_bytes() {
        let id = ticket_id(&[0u8; 64]);
        let parent = parent_ticket_id(&[0u8; 64]);
        assert_eq!(id.len(), 16);
        assert_eq!(parent.len(), 16);
    }

    #[test]
    fn ticket_id_golden_for_zero_signature() {
        assert_eq!(
            hex::encode(ticket_id(&[0u8; 64])),
            "0dcb29ad5fb8fc9656c8c77eae288bae"
        );
    }

    #[test]
    fn parent_ticket_id_golden_for_zero_signature() {
        assert_eq!(
            hex::encode(parent_ticket_id(&[0u8; 64])),
            "dc03a3c334a8d9e7d1f8f24c9da0cfdc"
        );
    }
}

mod ticket_golden {
    //! M1 Task 9 — golden postcard bytes for a deterministic ticket.

    use ed25519_dalek::SigningKey;
    use iroh_base::{EndpointAddr, EndpointId};
    use portl_core::ticket::codec::encode;
    use portl_core::ticket::schema::{Capabilities, EnvPolicy, PortlBody, PortlTicket, ShellCaps};
    use portl_core::ticket::sign::sign_body;

    const EXPECTED_HEX: &str = "01197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d6100010100010100000000000000197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d6100e807f823000042424242424242420000d81a17ed8a29c0e61cb919746eab0f049618c43c40a4e77f2d642b91207e77b8795154cf227d914aadeb67b29703f093876a69633ee3046f9151ff9095d6a80a";

    fn fixture() -> PortlTicket {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let addr =
            EndpointAddr::new(EndpointId::from_bytes(&sk.verifying_key().to_bytes()).unwrap());
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
}

mod ticket_schema {
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
        let addr = EndpointAddr::new(dummy_endpoint_id());
        let ticket = PortlTicket {
            v: 1,
            addr: addr.clone(),
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
                target: *addr.id.as_bytes(),
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
}

mod ticket_master {
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
            [7u8; 32],
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
            [8u8; 32],
        )
        .expect("mint master ticket");
        ticket.body.bearer = Some(Vec::new());

        let err = canonical_check_ticket(&ticket).expect_err("empty bearer must be rejected");
        assert!(matches!(err, PortlError::Canonical(_)));
    }

    #[test]
    fn mint_master_requires_to() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[65u8; 32]);
        let ticket = mint_master(
            &issuer,
            addr_from_seed(66),
            tcp_caps(8080),
            b"token".to_vec(),
            60,
            [0xabu8; 32],
        )
        .expect("master ticket should require a concrete holder binding");
        assert_eq!(ticket.body.to, Some([0xabu8; 32]));
    }

    #[test]
    fn mint_master_rejects_empty_bearer() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[67u8; 32]);
        let err = mint_master(
            &issuer,
            addr_from_seed(68),
            tcp_caps(8080),
            Vec::new(),
            60,
            [9u8; 32],
        )
        .expect_err("empty bearer must fail");
        assert!(err.to_string().contains("non-empty"));
    }
}

mod ticket_sign {
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
            1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
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
}
