# Changelog

All notable changes land here. This project follows
[Semantic Versioning](https://semver.org/) from v0.1.0 onward.

## 0.2.2 — 2026-04-21

Post-v0.2 cleanup release. No new user-facing features; pure
simplification, dead-code removal, and retirement of v0.2.0
transition scaffolding.

### Removed

- **`portl agent *`, `portl id *`, and `portl mint-root` helpful-error
  shims.** These printed a migration pointer to the v0.2.0 spec and
  exited non-zero. After v0.2.1, they are gone; users hitting those
  paths get clap's default unrecognized-subcommand error. Scripts
  that still pipe through them will fail with a different error
  message but the same non-zero exit.
- **v0.1 `revocations.json` migration path.** The agent no longer
  converts a bare-JSON-array `revocations.json` to `revocations.jsonl`
  at startup. Any site still on v0.1 on-disk state must run a v0.2.0
  agent once (which performs the migration) before upgrading here.
- **`portl-agent` `reqwest` direct dep.** Already trimmed in v0.2.1
  but the `.github/workflows` and `autoresearch.ideas.md` still
  referenced it; updated to reflect the shipped A+B gateway isolation.

### Changed

- **`commands/docker.rs` split into submodules.** 2145-line file
  becomes `commands/docker/{mod,types,host_ops,docker_ops,run,bake,aliases}.rs`.
  No behavior change; public surface identical.
- **`commands/install.rs` split into submodules.** 576-line file
  becomes `commands/install/{mod,detect,resolve,render,apply}.rs`.
  No behavior change; public surface identical.
- **`src/shell_handler.rs` split into submodules.** 1955-line file
  becomes `src/shell_handler/{mod,pumps,reject,spawn,exec_capture,pty_master,env,user,shutdown}.rs`.
  No behavior change; public surface identical.
- **Agent-mode error message.** The pty `--user` rejection no
  longer says "in v0.1"; it just describes the current behavior.
- **Retired v0.1.1 / v0.1.2 / v0.2.0 implementation plans.** Per
  the stated `docs/plans/README.md` policy, these task-level
  recipes are removed now that their features shipped. The
  shipped contracts live in the specs and CHANGELOG.

### Internal

- Dropped unused `#[allow(dead_code)]` on `AgentState`; every
  field is referenced.
- Fixed two alias-store test fixtures that still named the
  on-disk file `aliases.sqlite` instead of `aliases.json`.
- Refreshed predictive doc comments ("v0.2 may add PAM env")
  that never actually shipped.

## 0.2.1 — 2026-04-21

Gateway-isolation and dependency-hygiene patch release. No user-facing
CLI changes; focus is on making `AgentMode` a first-class trust
boundary and removing vestigial dependencies from `portl-agent`.

### Changed

- **Agent-mode contract enforced at handshake.** `AcceptanceInput`
  now carries the agent mode and `evaluate_offer` rejects tickets
  whose bearer shape does not match the mode: listener mode refuses
  master tickets, gateway mode requires one. Previously this was
  only checked inside `gateway::serve_stream` on the `tcp/v1` path,
  after the handshake had already succeeded.
- **Gateway-mode ALPN dispatch is narrowed.** Gateway agents now
  only serve `meta/v1` and `tcp/v1` streams. Incoming `shell/v1`
  and `udp/v1` streams are closed at dispatch with an explicit
  reason, closing the defense-in-depth gap where a gateway build
  still linked shell/udp handlers.

### Removed

- **`reqwest` direct dependency from `portl-agent`.** It was only
  used as a URL parser inside `parse_gateway_mode`. Replaced with
  `url::Url`, which was already pulled in transitively. No runtime
  or feature change.
- **Ignored wiremock-backed gateway integration test.** The
  aspirational end-to-end header-injection test was permanently
  `#[ignore]`'d due to iroh in-process endpoint timing; deleted.
  The `wiremock` dev-dependency is dropped from `portl-agent`.
  Header-injection coverage remains in `src/gateway.rs` unit tests
  against `tokio::io::duplex`.

## 0.2.0 — 2026-04-21

Operability release. This is the first intentionally breaking
release in the project: the CLI surface collapses, `agent.toml`
is replaced by a fixed env-var contract, `portl docker run`
becomes the default container workflow, and the unattended-runtime
safety invariants from spec 140 ship together.

Headline operator flow: `portl init && portl docker run <image>`.

Full scope and invariants:
[`docs/specs/140-v0.2-operability.md`](docs/specs/140-v0.2-operability.md).

### Added

- **`portl init` and `portl install [TARGET]`.** `init` creates an
  identity if needed, runs `doctor`, and prints the first-mint
  cookbook. `install` now targets `systemd`, `launchd`, `openrc`,
  or `dockerfile`, with autodetect, dry-run, detect-only, and
  `--apply` flows.
- **`portl docker run` orchestrate mode.** The Docker adapter now
  injects `portl-agent` into an existing container at runtime via
  `docker create`/`start` + binary upload + `docker exec -d`, then
  prints a holder-bound ticket. `attach`, `detach`, and `bake`
  join the Docker surface.
- **`portl-gateway` multicall entrypoint.** Gateway mode is now a
  dedicated daemon entrypoint (`portl-gateway <upstream-url>`) and
  a top-level `portl gateway` command.
- **Runtime safety invariants from spec 140 §13.**
  - Process-group teardown escalator: `SIGHUP` → 5 s → `SIGTERM`
    → 5 s → `SIGKILL` on session drop.
  - Async PTY drain with a 30 s force-close cap.
  - Live-session cancellation on ticket revocation.
  - `slow_task` watchdog around agent `spawn_blocking` call sites.
  - `revocations.jsonl` size ceiling with fail-closed semantics.
  - Graceful agent shutdown that stops accepting, reaps live
    sessions, fsyncs `shell_exit`, and exits non-zero on survivors.

### Changed

- **CLI surface collapsed.** The supported top-level commands are
  now: `init`, `doctor`, `status`, `shell`, `exec`, `tcp`, `udp`,
  `mint`, `revoke`, `install`, `docker`, `slicer`, `gateway`.
  `mint-root` became `mint`; `revocations publish` folded into
  `revoke --publish`; `docker container ...` collapsed into
  `docker run/list/rm/attach/detach/bake`; `slicer container ...`
  collapsed into `slicer run/list/rm`.
- **`portl agent *` removed.** The daemon is now invoked as the
  multicall entrypoint `portl-agent`. The v0.2.x binary keeps a
  one-release deprecation shim: `portl agent ...` prints a clear
  notice and exits with status 2.
- **`portl doctor` is strictly local.** The hard-coded relay TCP
  probe moved out of doctor and into `portl status --relay`.
- **Agent configuration is env-only.** `agent.toml` and
  `PORTL_AGENT_CONFIG` are gone. The daemon reads `PORTL_HOME`,
  `PORTL_IDENTITY_SECRET_HEX`, `PORTL_TRUST_ROOTS`,
  `PORTL_LISTEN_ADDR`, `PORTL_DISCOVERY`, `PORTL_METRICS`,
  `PORTL_REVOCATIONS_PATH`, `PORTL_RATE_LIMIT`,
  `PORTL_UDP_SESSION_LINGER_SECS`, and `PORTL_MODE`.
- **Release tarballs now ship three entrypoints** via symlinks to
  the same ELF: `portl`, `portl-agent`, and `portl-gateway`.

### Removed

- **`agent.toml` / TOML parsing.** The `toml` crate leaves the
  workspace.
- **Old CLI namespaces and commands:** `id new/show/export/import`,
  `mint-root`, `docker image generate`, `docker image build`,
  `docker container rebuild`, `docker container logs`, and the
  `portl agent` subcommand tree.

### Infrastructure

- **Release and CI gating continue through the consolidated
  `ci.yml` flow.** `release-build` remains gated on the full test /
  clippy / fmt / deny / docker-smoke matrix before publishing.
- **Docker asset resolution now supports `--from-release <tag>`.**
  Foreign-arch orchestrate flows can download the correct release
  tarball, verify the `.sha256` sidecar, and inject the matching
  `portl-agent` binary.

### Notes

- The full internal extraction of gateway code out of
  `portl-agent` into its own crate was intentionally deferred to a
  follow-up release. The user-visible `portl-gateway` surface
  ships in v0.2.0; the binary-size / direct-dep cleanup is tracked
  separately.
- v0.2.0 is still ticket-schema v1 / ALPN v1. Existing v0.1
  tickets and identities remain valid.

## 0.1.2 — 2026-04-21

Alias-isolation patch release. Non-breaking at the CLI / config /
env surface. The on-disk alias store changes format; no migration
(pre-1.0, no external users). This release exists specifically to
isolate the `rusqlite`-bundled dependency as the suspected cause
of the macOS release-mode host-client SIGABRT recorded in v0.1.0.

Full scope and invariants:
[`docs/specs/160-v0.1.2-alias-isolation.md`](docs/specs/160-v0.1.2-alias-isolation.md).

### Changed

- **Alias-store backend**: `aliases.sqlite` (rusqlite, bundled) is
  replaced by `aliases.json` (`serde_json` + `fd-lock`). Writers
  take an exclusive advisory lock on a companion `aliases.json.lock`
  file for the full read-modify-write-rename cycle; readers take a
  shared lock on the same companion file. Atomic durability is
  provided by temp-file fsync + rename + parent-directory fsync.
- Public API of `crate::alias_store` (`AliasStore`, `AliasRecord`,
  `StoredSpec`, `default_db_path`, `now_unix_secs`) is preserved
  byte-for-byte; every caller under `crates/portl-cli/src/commands/`
  is source-compatible.
- **File permissions hardened**: `aliases.json` and
  `aliases.json.lock` are created with mode `0600` on Unix so that
  hex-encoded `endpoint_id` and `root_ticket_id` values are not
  world-readable. The v0.1.1 SQLite file inherited the process
  umask (typically `0644`).
- **Schema-version gate**: the JSON file carries
  `"version": <u32>` at the top level. Readers reject files whose
  version exceeds the current version (1) with a clear error,
  preventing silent downgrade of newer state when rolling back for
  a bisect. Unknown fields inside each alias entry are
  round-tripped (preserved via `#[serde(flatten)]`) so a v0.1.2
  binary can safely read and re-save a v0.1.3 file without losing
  added fields.
- **Endpoint-id uniqueness preserved**: `save()` rejects a record
  whose `endpoint_id` is already claimed by a different alias,
  matching the `UNIQUE INDEX idx_aliases_endpoint_id` constraint
  that v0.1.1 enforced at the SQLite layer.

### Removed

- `rusqlite` and `libsqlite3-sys` leave the workspace entirely.
  Expected binary-size delta vs v0.1.1 (release, zstd -19):
  approximately 1.5-2 MiB smaller per tarball. Cold-build time
  drops comparably; the `cc` build script for `libsqlite3-sys` was
  the single longest-running step in the v0.1.1 release build.
- **No migration from `aliases.sqlite`.** A stray SQLite file left
  over from v0.1.1 is silently ignored. Operators recreate aliases
  with `portl ticket accept … --save-as` (pre-1.0 stance; see
  `docs/specs/160-v0.1.2-alias-isolation.md §3.3`).

### Infrastructure

- **New `dep-guard` CI job** (`.github/workflows/ci.yml`) fails
  the build if `rusqlite` or `libsqlite3-sys` re-enter the
  workspace dependency tree. Added to the `release-build` `needs:`
  list so tag-triggered releases cannot ship with SQLite reintroduced.
- Nextest profile `ci` gains a per-test override for
  `alias_store::tests::many_writers_converge_to_full_set` — the
  1,000-save durability test is intentionally fsync-heavy, so it
  gets a 90 s slow-timeout with `terminate-after = 3` and one
  retry to absorb disk-contention noise on shared runners.

### Forensic note

This release is the clean bisect target for the macOS release-mode
host-client SIGABRT recorded in v0.1.0. Outcome (confirmed /
falsified) will be captured in
`scratch/2026-0X-XX-v0.1.2-mac-bisect.md` after the 50×raw-ticket
and 50×alias-resolved acceptance loops run against vn3 from a
macOS arm64 release build. Protocol: spec 160 §4.3.

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
- **UDP forwarder starved its own ingress socket under QUIC
  congestion.** The single `upstream_loop` task interleaved
  `local_socket.recv_from` with `connection.send_datagram_wait`
  — while QUIC was backpressuring, nothing drained the kernel's
  UDP rx queue and packets dropped silently. Split into reader +
  QUIC-sender futures joined by `tokio::select!`, with a bounded
  mpsc (cap 256) between them. Queue-full drops the newest
  datagram (matches UDP best-effort semantics) instead of
  propagating the stall back to the kernel.
- **`tokio::sync::Mutex` on purely-synchronous HashMap state.**
  `SrcTagTable` and the forward handle's `session_id` were wrapped
  in async-aware mutexes but the lock never crossed an `.await`
  point — all that got us was scheduling overhead per packet.
  Swapped to `std::sync::Mutex`; `LocalUdpForwardHandle::session_id`
  and `::bind` are no longer `async`.
- **`udp_src_tag_lru_eviction` could hang indefinitely on any
  single dropped datagram.** `remote.recv_from` was unwrapped
  with no timeout, so one QUIC-level drop (explicitly allowed by
  the transport) turned the 1,025-iteration sweep into an
  unbounded hang that only nextest's SIGKILL could break.
  Wrapped each `recv_from` in `tokio::time::timeout(1 s)` so a
  drop fails fast with the src_tag index.

### Infrastructure

- **Release workflow merged into `ci.yml`.** Previously
  `release.yml` built and published on `v*` tag pushes
  independently of CI, so a tag could ship binaries from a
  commit that failed tests. The `release-build` (matrix, 4
  targets) and `release-publish` jobs now live in `ci.yml`
  gated on `needs: [test, clippy, fmt, deny, docker-smoke]`
  and `if: startsWith(github.ref, 'refs/tags/v')`. Release
  artifacts can no longer ship unless every CI job passes on
  the exact tagged commit.
- **Ingress UDP socket `SO_RCVBUF` tuned to 1 MiB.** Best-effort
  via `socket2`; silently clamps to `net.core.rmem_max` (Linux)
  or `kern.ipc.maxsockbuf` (macOS) without error. Complements
  the forwarder reader/sender decouple under heavy CPU
  contention (e.g. shared CI runners).
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
  VM with a systemd `portl-agent.service`. Includes `portl-gateway`
  for bridging the Slicer HTTP API via master
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
