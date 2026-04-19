# 11 — Workspace layout

Single Cargo workspace, single repo, all in one place until v0.1 ships
and stable APIs freeze.

## 1. Filesystem layout

```
portl/
├── Cargo.toml                     [workspace]
├── Cargo.lock
├── rust-toolchain.toml            stable pinned (≥ 1.85 for edition 2024)
├── rustfmt.toml
├── clippy.toml
├── deny.toml                      cargo-deny config
├── justfile                       common tasks
├── .github/
│   └── workflows/
│       ├── ci.yml                 check + test + clippy + rustfmt
│       ├── release.yml            static musl builds on tag
│       └── docs.yml               mdbook → gh-pages
├── README.md
├── CHANGELOG.md
├── LICENSE-APACHE
├── LICENSE-MIT
│
├── docs/
│   └── design/                     this doc set (markdown)
│       ├── README.md               landing / index
│       ├── 01-goals.md
│       ├── 02-architecture.md
│       ├── 03-tickets.md
│       ├── 04-protocols.md
│       ├── 05-bootstrap.md
│       ├── 06-docker.md
│       ├── 06a-slicer.md
│       ├── 07-security.md
│       ├── 08-cli.md
│       ├── 09-config.md
│       ├── 10-walkthroughs.md
│       ├── 11-workspace.md
│       ├── 12-roadmap.md
│       ├── 13-open-questions.md
│       └── future/                 deferred design artifacts
│           ├── 14-transport-abstraction.md
│           └── 15-loom-analysis.md
│
├── crates/
│   ├── portl-core/                     # sessions, tickets, caps, traits,
│   │   ├── Cargo.toml                  #   concrete iroh wrapper, test helpers
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── ticket/
│   │       │   ├── mod.rs
│   │       │   ├── schema.rs           # PortlTicket + PortlBody
│   │       │   ├── codec.rs            # postcard + base32,
│   │       │   │                       #   impl iroh_tickets::Ticket
│   │       │   ├── canonical.rs        # issuer elision, vec sorting,
│   │       │   │                       #   re-encode-reject verifier
│   │       │   ├── hash.rs             # ticket_id + parent_ticket_id
│   │       │   │                       #   domain-separated SHA-256
│   │       │   ├── sign.rs             # ed25519_verify_strict
│   │       │   └── verify.rs           # chain walk, verify-before-hash
│   │       ├── caps.rs
│   │       ├── session.rs
│   │       ├── endpoint.rs             # thin newtype over iroh::Endpoint
│   │       ├── discovery.rs            # configure DNS/Pkarr/Local/DHT
│   │       ├── policy.rs
│   │       ├── revocation.rs           # store + GC
│   │       ├── bootstrap.rs            # trait + TargetSpec
│   │       ├── alpn.rs                 # canonical ALPN names
│   │       ├── audit.rs
│   │       ├── metrics.rs              # Prometheus text exporter
│   │       ├── test_util.rs            # pair(), in-proc Endpoint wiring
│   │       └── error.rs
│   │
│   ├── portl-proto/                    # all ALPNs in one crate for v0.1
│   │   ├── Cargo.toml                  #   (split later if any grows > ~1k LoC)
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── ticket.rs               # ticket/v1 handshake
│   │       ├── meta.rs                 # meta/v1
│   │       ├── shell/
│   │       │   ├── mod.rs
│   │       │   ├── client.rs
│   │       │   ├── server.rs
│   │       │   ├── pty.rs
│   │       │   └── streams.rs          # multi-sub-stream framing
│   │       ├── tcp.rs
│   │       ├── udp.rs                  # QUIC datagrams + session linger
│   │       └── vpn/                    # feature-gated, Linux + macOS TUN
│   │           ├── mod.rs
│   │           ├── ula.rs
│   │           ├── client.rs
│   │           └── server.rs
│   │
│   └── portl-cli/                      binary (single multicall)
│       └── src/
│           ├── main.rs                  # argv[0] dispatch:
│           │                            #   portl-agent → prepend "agent"
│           ├── cli.rs                   # clap root; `agent` subtree lives
│           │                            #   in commands/agent/
│           ├── commands/
│           │   ├── id.rs
│           │   ├── ticket.rs           # import/list/show/rm (was login/logout)
│           │   ├── mint_root.rs        # `portl mint-root`
│           │   ├── status.rs
│           │   ├── doctor.rs
│           │   ├── shell.rs
│           │   ├── exec.rs
│           │   ├── tcp.rs
│           │   ├── udp.rs
│           │   ├── vpn.rs
│           │   ├── share.rs
│           │   ├── revoke.rs
│           │   └── agent/              # target-side subcommands
│           │       ├── mod.rs
│           │       ├── run.rs           # `portl agent run`
│           │       ├── enroll.rs        # `portl agent enroll`
│           │       ├── identity.rs
│           │       ├── policy.rs
│           │       ├── sessions.rs
│           │       ├── service.rs       # serve loop
│           │       └── gateway.rs       # `--mode gateway`
│           ├── adapters.rs             discover + dispatch adapter subcommands
│           └── config.rs
│
├── adapters/
│   ├── docker-portl/                      M4 reference adapter
│   │   ├── Cargo.toml
│   │   ├── images/
│   │   │   └── Dockerfile.reference       <80 MiB agent image
│   │   └── src/
│   │       ├── main.rs                    binary: portl-docker-adapter
│   │       ├── bootstrapper.rs             bollard-backed Bootstrapper impl
│   │       ├── agent_toml.rs               render config from defaults+flags
│   │       ├── networking.rs               bridge|host|user-defined dispatch
│   │       └── subcommands.rs              `portl docker container …` tree
│   │
│   ├── slicer-portl/                      M5 adapter (gateway-capable)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs                    binary: portl-slicer-adapter
│   │       ├── bootstrapper.rs
│   │       ├── userdata.rs                templated install script
│   │       └── subcommands.rs
│   │
│   └── manual-portl/                      reference adapter (prints instructions)
│       ├── Cargo.toml
│       └── src/main.rs
│
├── extras/                               post-v0.1 work (optional crates)
│   └── portl-relay/                       thin wrapper on iroh-relay (only
│       ├── Cargo.toml                      #   if iroh-relay isn't usable as-is)
│       └── src/main.rs
│
├── examples/
│   └── hello-peers/                       two peers, one tcp forward
│       └── src/main.rs
│
└── tests/
    ├── integration/
    │   ├── ticket_roundtrip.rs
    │   ├── cap_intersection.rs
    │   ├── delegation_chain.rs
    │   ├── revocation.rs
    │   ├── shell_e2e.rs
    │   ├── tcp_e2e.rs
    │   ├── udp_e2e.rs
    │   └── docker_e2e.rs              M4; spins up 2 containers
    └── fuzz/
        ├── ticket_decoder/
        └── frame_parsers/
```

## 2. Workspace Cargo.toml

```toml
[workspace]
resolver = "2"
members = [
    "crates/portl-core",
    "crates/portl-proto",
    "crates/portl-cli",
    "adapters/docker-portl",
    "adapters/slicer-portl",
    "adapters/manual-portl",
    # extras/portl-relay is added when (if) iroh-relay can't be used directly
]

[workspace.package]
version      = "0.0.1"
edition      = "2024"
license      = "Apache-2.0 OR MIT"
repository   = "https://github.com/KnickKnackLabs/portl"
authors      = ["KnickKnackLabs and portl contributors"]
rust-version = "1.85"    # 2024 edition baseline

[workspace.dependencies]
# transport
iroh             = "0.x"
iroh-base        = "0.x"         # EndpointAddr, TransportAddr types
iroh-tickets     = "0.x"         # Ticket trait + KIND plumbing
quinn            = "0.x"
tokio            = { version = "1", features = ["full"] }
bytes            = "1"
futures-util     = "0.3"

# crypto
ed25519-dalek    = { version = "2", features = ["rand_core"] }
sha2             = "0.10"

# encoding
serde            = { version = "1", features = ["derive"] }
postcard         = { version = "1", features = ["use-std"] }
base32           = "0.5"
age              = "0.10"

# CLI
clap             = { version = "4", features = ["derive", "env", "wrap_help"] }
anyhow           = "1"
thiserror        = "2"

# obs
tracing          = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }

# local state
rusqlite         = { version = "0.32", features = ["bundled"] }
directories      = "5"

# specific modules
portable-pty     = "0.8"    # shell
socket2          = "0.5"    # udp
tun              = { version = "0.7", optional = true }

# adapters
bollard          = "0.17"   # docker API (docker-portl)
reqwest          = { version = "0.12", default-features = false,
                     features = ["rustls-tls", "json"] }  # slicer-portl
```

## 3. Justfile (task runner)

```make
default: check

check:
    cargo check --workspace --all-features

test:
    cargo nextest run --workspace

lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-features --all-targets -- -D warnings

fmt:
    cargo fmt --all

deny:
    cargo deny check

docs:
    mdbook build docs

release-check:
    cargo build --release --workspace
    cargo test  --release --workspace

release:
    # kicks off GH Actions workflow
    gh workflow run release.yml

agent-local:
    cargo run -p portl-cli -- agent run --config dev/agent.toml

cli:
    cargo run -p portl-cli -- {{ARGS}}
```

## 4. CI outline

`.github/workflows/ci.yml` runs on every PR:

```
jobs:
  check:
    - cargo check --workspace --all-features
  lint:
    - cargo fmt --all -- --check
    - cargo clippy --workspace --all-features --all-targets -- -D warnings
  test:
    matrix: [ubuntu-latest, macos-latest]
    - cargo nextest run --workspace
  deny:
    - cargo deny check
  docs:
    - mdbook build docs
```

## 5. Feature flags

```
portl-core             (no non-default features)
portl-proto            (default)   shell, tcp, udp, meta, ticket
                       (opt-in)    fs (post-v0.1), vpn (stretch)
portl-cli              (default)   all of the above; builds the single
                                   multicall binary (client + agent
                                   subtree). The `vpn` feature is
                                   opt-in because it requires TUN
                                   privileges at the agent side and
                                   a `tun` dep at build time.
```

## 6. Release artifacts

On `git tag v*`, GH Actions produces:

```
portl-<version>-aarch64-apple-darwin.tar.gz
portl-<version>-x86_64-apple-darwin.tar.gz
portl-<version>-aarch64-unknown-linux-musl.tar.gz
portl-<version>-x86_64-unknown-linux-musl.tar.gz

portl-docker-adapter-<version>-*.tar.gz
portl-slicer-adapter-<version>-*.tar.gz
portl-relay-<version>-*.tar.gz

ghcr.io/knickknacklabs/portl-agent:<version>   # reference image (M5+)

SHA256SUMS (signed by the release key)
```

Each `portl-<version>-<target>.tar.gz` contains:

```
bin/portl                        # the multicall binary
bin/portl-agent                  # symlink → portl (argv[0] dispatch)
share/systemd/portl-agent.service
share/man/*                      # generated from clap
LICENSE-APACHE
LICENSE-MIT
README.md
```

macOS tarballs omit `share/systemd/` (launchd plist ships post-v0.1
as a separate `share/launchd/com.portl.agent.plist` artifact).

## 7. Publishing to crates.io

Not until v0.1.0 (after M7). Order:

```
1.  portl-core
2.  portl-proto
3.  portl-cli               # the multicall binary
4.  docker-portl
5.  slicer-portl
6.  portl-relay (optional)
```

Separate repos split only if / when adapters want their own velocity.
Individual protocol crates may be split out of `portl-proto` post-v0.1
if any of them grows beyond ~1000 LoC.

## 8. Binaries produced

```
portl               multicall binary                  (both sides)
                      • `portl …`        client surface
                      • `portl agent …`  target-side agent
                      • argv[0] = `portl-agent` → dispatches as
                        `portl agent …` (symlink installed by
                        packagers)
portl-docker-adapter  dynamic subcommand plugin (M4)   (operator laptop)
portl-slicer-adapter  dynamic subcommand plugin (M5)   (operator laptop)
portl-relay         relay server (optional)             (public-IP VPS)
```

Post-v0.1 candidates — not shipped at v0.1:

```
portl-socks5        SOCKS5 gateway (stretch, post-v0.1)
portl-dns           *.portl.local DNS stub (bundled into portl-cli
                    if/when VPN mode ships)
```

## 9. What lives where (decision map)

| Concern | Crate / module | Notes |
| --- | --- | --- |
| Ticket parsing/signing | `portl-core::ticket` | no I/O |
| Iroh Endpoint wrapper | `portl-core::endpoint` | concrete; no generic-over-T |
| Discovery config | `portl-core::discovery` | DNS/Pkarr/Local/DHT toggles |
| ALPN multiplex | `portl-core::session` | dispatches to `portl-proto` |
| Policy evaluation | `portl-core::policy` | no network |
| Revocation store + GC | `portl-core::revocation` | `REVOCATION_LINGER` rule |
| Bootstrapper trait | `portl-core::bootstrap` | adapters depend on this |
| Metrics exporter | `portl-core::metrics` | Prometheus text |
| Ticket/v1 handshake | `portl-proto::ticket` | canonical wire in `04 §1` |
| `meta/v1` | `portl-proto::meta` | |
| PTY handling | `portl-proto::shell::pty` | `portable-pty` |
| `tcp/v1` | `portl-proto::tcp` | tokio streams |
| `udp/v1` | `portl-proto::udp` | iroh datagrams + linger |
| `vpn/v1` (opt-in feature) | `portl-proto::vpn` | `tun` crate, OS-specific |
| Agent serve loop | `portl-cli::commands::agent::service` | runs ticket/v1 + dispatches ALPNs |
| Gateway mode | `portl-cli::commands::agent::gateway` | bearer injection for master tix |
| Docker API client      | `docker-portl` | bollard; M4 reference adapter |
| Slicer HTTP API client | `slicer-portl` | reqwest + bearer injection |
| Client state on disk | `portl-cli::config` | tickets + sqlite |
| Relay (optional) | `portl-relay` | iroh-relay thin wrapper |

## 10. External dependency posture

- Minimise transitive deps. Every dep reviewed in `deny.toml`.
- No `openssl-sys`; use `rustls` via iroh.
- `rusqlite` over `sqlx` for simplicity; pulls in `libsqlite3-sys`
  bundled.
- `clap` with `derive` — worth the compile-time cost for consistent CLIs.
- `postcard` for ticket bodies (matches iroh-tickets); no CBOR.
- `iroh-tickets` for the `Ticket` trait + KIND-prefixed base32
  envelope. `iroh-base` for `EndpointAddr`.
- `ed25519-dalek` v2 with `fips-compliance-vec` checked off (not a
  project requirement yet). `verify_strict` is mandatory in the
  ticket verifier path.
