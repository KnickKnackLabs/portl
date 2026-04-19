use std::collections::HashSet;
use std::time::{Duration, Instant};

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use ed25519_dalek::SigningKey;
use iroh_base::{EndpointAddr, EndpointId};
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::{Capabilities, EnvPolicy, ShellCaps};
use portl_core::ticket::verify::{TrustRoots, verify_chain};

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

fn endpoint_addr_from_key(sk: &SigningKey) -> EndpointAddr {
    EndpointAddr::new(EndpointId::from_bytes(&sk.verifying_key().to_bytes()).unwrap())
}

fn trust_roots(sk: &SigningKey) -> TrustRoots {
    TrustRoots(HashSet::from([sk.verifying_key().to_bytes()]))
}

fn bench_mint_root(c: &mut Criterion) {
    let sk = SigningKey::from_bytes(&[61u8; 32]);
    let addr = endpoint_addr_from_key(&sk);
    let caps = shell_caps();

    c.bench_function("mint_root", |b| {
        b.iter(|| {
            black_box(
                mint_root(
                    black_box(&sk),
                    black_box(addr.clone()),
                    black_box(caps.clone()),
                    black_box(1_000),
                    black_box(4_600),
                    black_box(None),
                )
                .unwrap(),
            )
        });
    });
}

fn bench_verify_root(c: &mut Criterion) {
    let sk = SigningKey::from_bytes(&[62u8; 32]);
    let ticket = mint_root(
        &sk,
        endpoint_addr_from_key(&sk),
        shell_caps(),
        1_000,
        4_600,
        None,
    )
    .unwrap();
    let roots = trust_roots(&sk);

    c.bench_function("verify_root", |b| {
        b.iter(|| {
            black_box(
                verify_chain(
                    black_box(&ticket),
                    black_box(&[]),
                    black_box(&roots),
                    black_box(1_100),
                )
                .unwrap(),
            )
        });
    });
}

fn bench_mint_then_verify_10k(c: &mut Criterion) {
    let mut group = c.benchmark_group("mint_then_verify");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(5));

    let sk = SigningKey::from_bytes(&[63u8; 32]);
    let addr = endpoint_addr_from_key(&sk);
    let caps = shell_caps();
    let roots = trust_roots(&sk);

    group.bench_function("mint_then_verify_10k", |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                for _ in 0..10_000 {
                    let ticket =
                        mint_root(&sk, addr.clone(), caps.clone(), 1_000, 4_600, None).unwrap();
                    verify_chain(&ticket, &[], &roots, 1_100).unwrap();
                }
            }
            start.elapsed()
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_mint_root,
    bench_verify_root,
    bench_mint_then_verify_10k
);
criterion_main!(benches);
