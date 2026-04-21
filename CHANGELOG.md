# Changelog

All notable changes land here. This project follows
[Semantic Versioning](https://semver.org/) from v0.1.0 onward.

## 0.1.1 — 2026-04-21

Safety-net patch release. Non-breaking at the CLI / config / env
surface; the audit JSONL schema changes (pre-1.0, no consumers).

Full scope and invariants:
[`docs/specs/150-v0.1.1-safety-net.md`](docs/specs/150-v0.1.1-safety-net.md).

### Added

- **Resource limits on every shell / exec spawn.** Applied in
  `pre_exec` before `execve`:
  `RLIMIT_NOFILE=4096`, `RLIMIT_CORE=0`, `RLIMIT_CPU=86_400s`,
  `RLIMIT_FSIZE=10 GiB`. Linux additionally gets
  `RLIMIT_NPROC=512` (per-uid fork-bomb containment). macOS does
  not (`RLIMIT_NPROC` is per-process on Darwin and can't bound a
  fork-bomb at the agent's uid level); see spec 150 §3.1 for the
  platform caveat.
- **`audit.shell_reject` record.** Emitted exactly once when a
  session is rejected before spawn (`caps_denied`, `argv_empty`,
  `uid_lookup_failed`, `user_switch_refused`, `path_probe_failed`,
  `pty_allocation_failed`). Rejections do **not** also emit
  `shell_start` or `shell_exit`. Reason strings are dispatched from
  a typed `SpawnReject` enum, not from request-shape heuristics.
- **`session_id` (UUIDv4) in shell records.** Every accepted
  session emits one `shell_start` and one `shell_exit` with the
  same `session_id`, allowing consumers to correlate start and
  exit without timestamp heuristics.
- **`pid`, `mode`, `exit_code`, `duration_ms`** fields on the
  shell records (see spec 150 §3.2 for the full schema).

### Changed

- **Release profile uses `panic = "abort"`.** Any panic in any
  async task terminates the process via `SIGABRT`; the supervisor
  can detect the non-zero exit and restart. Latent panic sites
  were triaged first: `meta_handler.rs` and `ticket_handler.rs`
  RwLock-poison handlers were rewritten to propagate errors
  instead of panicking; three infallible sites were documented
  with `SAFETY(panic)` comments.
- **PTY spawn path rewritten.** Drops the `portable_pty`
  dependency and uses a direct `CommandExt::pre_exec` hook that
  runs `openpty(3)` + `setsid` + `ioctl(TIOCSCTTY)` + `dup2` +
  `apply_rlimits` inline. The master fd is marked `FD_CLOEXEC`
  before spawn so the forked child cannot inherit it (which would
  otherwise suppress slave-side `SIGHUP` when the parent closes
  master). Unlocks the unified rlimit contract across PTY and
  exec paths.
- **`audit.shell_spawn` renamed to `audit.shell_start`** for
  symmetry with `shell_exit`. Hard cutover; v0.1.1 emits
  `shell_start` only, never `shell_spawn`. Audit JSONL is pre-1.0
  and has no external consumers.
- **Field names in all shell audit records** changed from
  `ticket_id_hex` / `caller_endpoint_id_hex` to `ticket_id` /
  `caller_endpoint_id` (spec compliance; the `_hex` suffix was
  never part of the contract and implied an encoding guarantee
  the records did not enforce at the schema level).

### Fixed

- **PTY master fd was inherited by spawned children.** Caught in
  the M1+M2 roundtable review; fixed by setting `FD_CLOEXEC` on
  master before `Command::spawn` so the fork does not duplicate
  the handle into the child's fd table. Without this, the master
  side's open-count stayed > 0 from the child's inherited handle
  and the slave side missed `SIGHUP` when the parent closed
  master.

### Infrastructure

- Clippy tightened (`clippy::cargo` + selected `restriction` /
  `nursery` picks; `dbg_macro = deny`). CI gate unchanged
  (`-D warnings`).
- Nextest config + cargo aliases (`cargo nt`) for faster local
  test iteration.
- Per-test-binary watchdog at
  `crates/portl-agent/tests/common/mod.rs` aborts the process
  after 30 s (`PORTL_TEST_WATCHDOG_SECS` override) so a hung
  integration test can't wedge CI.
- `sccache` wired into `.cargo/config.toml` as the `rustc-wrapper`
  for cross-branch rustc output caching.

### Deferred to v0.1.2

- Alias store migration from `aliases.sqlite` to `aliases.json`
  (spec 160).
- `rusqlite` removal from the workspace (spec 160 §3.4).

### Deferred to v0.2.0

- Full CLI / env / config cleanup (spec 140 Parts A+B+D).
- Session-lifecycle hardening: pgroup kill on disconnect, PTY
  drain with timeout, revocations-kill-live-sessions, slow-task
  detection, revocations.jsonl ceiling, graceful shutdown
  (spec 140 Part C items not in v0.1.1).

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
