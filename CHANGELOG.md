# Changelog

All notable changes land here. This project follows
[Semantic Versioning](https://semver.org/) from v0.1.0 onward.

## 0.1.0 — 2026-04-20

First end-to-end release. The v0.1 feature set spans milestones M0
through M7 of the roadmap.

### Added

- **Ticket schema v1** — postcard-encoded, ed25519-signed,
  canonical-form enforced at mint and verify. Supports up to 8
  delegation hops with monotone cap narrowing.
- **`portl id new/show/export/import`** — operator identity management
  with XDG-compliant storage, mode 0600, and age-encrypted export.
- **`portl mint-root`** — operator-issued and self-signed root
  tickets with `--to` holder binding and `--depth` delegation knob.
- **`portl/ticket/v1`** — handshake + session setup ALPN with 8-step
  acceptance pipeline (rate limit → postcard → canonical → chain →
  narrow → revocation → ttl/skew → proof). Per-node-id token bucket
  (1 offer / 5 s steady, burst 10).
- **`portl/meta/v1`** — ping, info, and `PublishRevocations`
  distribution over authenticated sessions.
- **`portl/shell/v1`** — PTY and exec modes with six sub-streams
  (stdin, stdout, stderr, signal, resize, exit). Env policy
  enforcement (deny / merge / replace) with minimal-login-env base.
  Supplementary-group drop on `--user` switch via `pre_exec` +
  `setgroups(&[])`.
- **`portl/tcp/v1`** — one stream per forwarded connection with
  `copy_bidirectional` FIN propagation.
- **`portl/udp/v1`** — QUIC-datagram UDP forwarding with 60 s session
  linger, per-source `src_tag` isolation, CLI reconnect supervisor,
  `MAX_SESSIONS_PER_CONNECTION = 16`, LRU `src_tag` eviction.
- **Docker adapter** (`adapters/docker-portl`) — provisions an
  ephemeral container with bind-mounted ed25519 secret and the
  portl multicall binary. `portl docker container {add,list,rm,
  rebuild,logs}` and a reference multi-arch-ready Dockerfile.
- **Slicer adapter** (`adapters/slicer-portl`) — provisions a Slicer
  VM with a systemd `portl-agent.service`. Includes `portl agent run
  --mode gateway` for bridging the Slicer HTTP API via master
  tickets, with per-connection bearer injection.
- **Master tickets** — `mint_master` requires holder binding (`to`);
  empty bearer bytes rejected; bearer widening in delegation chains
  rejected.
- **Revocations** — unified JSONL format with `REVOCATION_LINGER_SECS
  = 7 days` GC, a background GC task, and distribution via
  `portl revocations publish`.
- **Prometheus metrics** — OpenMetrics over a local unix socket at
  `$PORTL_HOME/metrics.sock` (mode 0600).
- **`portl doctor`** — local diagnostics (clock sanity, identity
  load + permissions, UDP ephemeral bind, ticket expiry scan).
- **GitHub Actions** — `ci-e2e.yml` builds and exercises a full
  add → exec → shell → tcp → rm cycle on every push. The
  `release.yml` workflow publishes musl linux binaries and
  macOS-native binaries as `.tar.zst` (zstd -19) artifacts per
  tag, cross-compiled via `cargo-zigbuild` on a single Ubuntu
  runner.
- **Static Linux builds.** Release tarballs target
  `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`,
  yielding fully statically linked binaries that drop into
  Alpine, distroless, BusyBox, CentOS 7 and every modern glibc
  distro without additional runtime dependencies.

### Notes

- Release-mode macOS host client crash tracked in
  `scratch/m4-known-issues.md`. Debug builds, Linux clients, and the
  full workspace test suite are unaffected.
- Full PTY `--user` drop requires a follow-up in v0.2; the current
  handler rejects with an actionable error.
- Relay operators rely on upstream `iroh-relay` for v0.1.0; no
  separate `portl-relay` crate.

### Design documents

The authoritative design set lives under `docs/design/`:

- [010-goals.md](docs/design/010-goals.md)
- [020-architecture.md](docs/design/020-architecture.md)
- [030-tickets.md](docs/design/030-tickets.md)
- [040-protocols.md](docs/design/040-protocols.md)
- [050-bootstrap.md](docs/design/050-bootstrap.md)
- [060-docker.md](docs/design/060-docker.md)
- [065-slicer.md](docs/design/065-slicer.md)
- [070-security.md](docs/design/070-security.md)
- [080-cli.md](docs/design/080-cli.md)
- [090-config.md](docs/design/090-config.md)
- [100-walkthroughs.md](docs/design/100-walkthroughs.md)
- [110-workspace.md](docs/design/110-workspace.md)
- [120-roadmap.md](docs/design/120-roadmap.md)
- [130-open-questions.md](docs/design/130-open-questions.md)
