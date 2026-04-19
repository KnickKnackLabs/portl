//! M1 Task 7 — property tests for ticket invariants.

use std::collections::HashSet;

use ed25519_dalek::SigningKey;
use iroh_base::{EndpointAddr, EndpointId};
use portl_core::caps::is_narrowing;
use portl_core::ticket::canonical::canonical_check;
use portl_core::ticket::hash::parent_ticket_id;
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::{
    Capabilities, Delegation, EnvPolicy, PortRule, PortlBody, PortlTicket, ShellCaps,
};
use portl_core::ticket::sign::sign_body;
use portl_core::ticket::verify::{MAX_DELEGATION_DEPTH, TrustRoots, verify_chain};
use proptest::prelude::*;

fn endpoint_addr_from_key(sk: &SigningKey) -> EndpointAddr {
    EndpointAddr::new(EndpointId::from_bytes(&sk.verifying_key().to_bytes()).unwrap())
}

fn trust_root_for(sk: &SigningKey) -> TrustRoots {
    TrustRoots(HashSet::from([sk.verifying_key().to_bytes()]))
}

fn shell_caps(pty_allowed: bool, exec_allowed: bool) -> ShellCaps {
    ShellCaps {
        user_allowlist: None,
        pty_allowed,
        exec_allowed,
        command_allowlist: None,
        env_policy: EnvPolicy::Deny,
    }
}

fn make_caps(
    has_shell: bool,
    pty_allowed: bool,
    exec_allowed: bool,
    tcp_max: Option<u16>,
) -> Capabilities {
    let shell = has_shell.then(|| shell_caps(pty_allowed, exec_allowed));
    let tcp = tcp_max.map(|port_max| {
        vec![PortRule {
            host_glob: "127.0.0.1".into(),
            port_min: 1,
            port_max,
        }]
    });
    let presence = u8::from(shell.is_some()) | (u8::from(tcp.is_some()) << 1);
    Capabilities {
        presence,
        shell,
        tcp,
        udp: None,
        fs: None,
        vpn: None,
        meta: None,
    }
}

fn narrow_caps(parent: &Capabilities, tighten: bool) -> Capabilities {
    let parent_shell = parent.shell.as_ref();
    let shell = parent_shell.map(|shell| ShellCaps {
        user_allowlist: None,
        pty_allowed: if tighten { false } else { shell.pty_allowed },
        exec_allowed: if tighten { false } else { shell.exec_allowed },
        command_allowlist: None,
        env_policy: EnvPolicy::Deny,
    });
    let tcp = parent.tcp.as_ref().map(|rules| {
        let rule = &rules[0];
        let port_max = if tighten {
            rule.port_max.saturating_sub(1).max(rule.port_min)
        } else {
            rule.port_max
        };
        vec![PortRule {
            host_glob: rule.host_glob.clone(),
            port_min: rule.port_min,
            port_max,
        }]
    });
    let presence = u8::from(shell.is_some()) | (u8::from(tcp.is_some()) << 1);
    Capabilities {
        presence,
        shell,
        tcp,
        udp: None,
        fs: None,
        vpn: None,
        meta: None,
    }
}

fn forge_child(
    signer: &SigningKey,
    parent: &PortlTicket,
    not_before: u64,
    not_after: u64,
    depth_remaining: u8,
) -> PortlTicket {
    let caps = parent.body.caps.clone();
    let body = PortlBody {
        caps,
        alpns_extra: vec![],
        not_before,
        not_after,
        issuer: None,
        parent: Some(Delegation {
            parent_ticket_id: parent_ticket_id(&parent.sig),
            depth_remaining,
        }),
        nonce: [depth_remaining.saturating_add(1); 8],
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

prop_compose! {
    fn arb_capabilities()
        (
            has_shell in any::<bool>(),
            pty_allowed in any::<bool>(),
            exec_allowed in any::<bool>(),
            tcp_max in prop::option::of(1u16..1000u16),
        ) -> Capabilities {
            make_caps(has_shell, pty_allowed, exec_allowed, tcp_max)
        }
}

prop_compose! {
    fn arb_body()
        (
            caps in arb_capabilities(),
            not_before in 0u64..10_000u64,
            delta in 1u64..(400 * 86_400u64),
            nonce in any::<[u8; 8]>().prop_filter("nonce must be non-zero", |n| *n != [0u8; 8]),
        ) -> PortlBody {
            PortlBody {
                caps,
                alpns_extra: vec![],
                not_before,
                not_after: not_before + delta,
                issuer: None,
                parent: None,
                nonce,
                bearer: None,
                to: None,
            }
        }
}

prop_compose! {
    fn arb_ticket_chain(depth: usize)
        (seed in any::<u8>()) -> (PortlTicket, Vec<PortlTicket>, TrustRoots) {
            let signer = SigningKey::from_bytes(&[seed.max(1); 32]);
            let root = mint_root(
                &signer,
                endpoint_addr_from_key(&signer),
                make_caps(true, true, true, Some(1000)),
                1_000,
                4_600,
                None,
            ).unwrap();
            let roots = trust_root_for(&signer);
            let mut chain = vec![root.clone()];
            let mut parent = root;
            for i in 0..depth {
                let depth_remaining =
                    MAX_DELEGATION_DEPTH.saturating_sub(u8::try_from(i).unwrap() + 1);
                let child = forge_child(&signer, &parent, 1_100, 4_500, depth_remaining);
                chain.push(child.clone());
                parent = child;
            }
            let terminal = chain.pop().unwrap();
            (terminal, chain, roots)
        }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, .. ProptestConfig::default() })]

    #[test]
    fn narrowing_is_monotone(parent in arb_capabilities(), tighten_child in any::<bool>(), tighten_grandchild in any::<bool>()) {
        let child = narrow_caps(&parent, tighten_child);
        let grandchild = narrow_caps(&child, tighten_grandchild);
        prop_assert!(is_narrowing(&parent, &child));
        prop_assert!(is_narrowing(&child, &grandchild));
        prop_assert!(is_narrowing(&parent, &grandchild));
    }

    #[test]
    fn ttl_respects_365_day_bound(body in arb_body()) {
        let ttl = body.not_after - body.not_before;
        let accepted = canonical_check(&body).is_ok();
        prop_assert_eq!(accepted, ttl <= 365 * 86_400);
    }

    #[test]
    fn delegation_depth_never_exceeds_max(
        depth_and_chain in (0usize..12usize)
            .prop_flat_map(|depth| arb_ticket_chain(depth).prop_map(move |chain| (depth, chain)))
    ) {
        let (depth, (terminal, chain, roots)) = depth_and_chain;
        let accepted = verify_chain(&terminal, &chain, &roots, 1_200).is_ok();
        prop_assert_eq!(accepted, depth <= usize::from(MAX_DELEGATION_DEPTH));
    }

    #[test]
    fn clock_skew_tolerance_is_60s(skew in -120i64..120i64) {
        let signer = SigningKey::from_bytes(&[91u8; 32]);
        let root = mint_root(
            &signer,
            endpoint_addr_from_key(&signer),
            make_caps(true, true, true, None),
            1_000,
            4_600,
            None,
        ).unwrap();
        let now = if skew.is_negative() {
            1_000u64.saturating_sub(skew.unsigned_abs())
        } else {
            1_000u64 + u64::try_from(skew).unwrap()
        };
        let accepted = verify_chain(&root, &[], &trust_root_for(&signer), now).is_ok();
        let expected = now + 60 >= 1_000 && now < 4_600;
        prop_assert_eq!(accepted, expected);
    }
}
