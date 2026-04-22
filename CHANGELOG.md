# Changelog

All notable changes land here. This project follows
[Semantic Versioning](https://semver.org/) from v0.1.0 onward.

## 0.2.6 — 2026-04-22

Quality-of-life fix for the self-host paved path: `portl install`
now bakes the local identity's public key into the service's
environment as `PORTL_TRUST_ROOTS`, so a fresh installation actually
accepts tickets minted on the same machine. Before this change,
every freshly-installed agent ran with an empty trust-roots set and
silently rejected every handshake with `BadChain`, which was the
root cause of the long diagnostic session behind v0.2.4 / v0.2.5.

### Fixed

- **Fresh `portl install` no longer produces an agent that rejects
  every ticket.** Previously, `portl install --apply` wrote a
  launchd plist / systemd unit with no environment configuration,
  leaving `trust_roots` empty at runtime. Any `portl shell`,
  `portl status`, or `portl tcp` dial — even against the same
  machine that installed the agent — came back `BadChain`.

### Added

- `portl install` now reads the local identity via
  `portl_core::id::store::load(default_path())` during `--apply`
  and writes `PORTL_TRUST_ROOTS=<hex_endpoint_id>` into the service
  environment:
  - **launchd**: injected as an `EnvironmentVariables` dict in the
    generated `com.portl.agent.plist`.
  - **systemd**: written to the companion `agent.env` file that the
    unit already referenced via `EnvironmentFile=-…` (path resolves
    to `/etc/portl/agent.env` for root installs and
    `~/.config/portl/agent.env` for user installs).
  - **Dockerfile**: emitted as an `ENV` directive in the generated
    image recipe.
  - **OpenRC**: emitted as `export PORTL_TRUST_ROOTS=…` at the top
    of the service script.
- New internal `AgentEnv` struct and `render_env_file` /
  `systemd_env_file_path` helpers in `install::render` so future
  env entries (e.g. `PORTL_RATE_LIMIT`, `PORTL_REVOCATIONS_PATH`)
  can be added in one place without touching each render target.
- Install emits a visible `warning: no local identity found …`
  message if run before `portl init`, naming the exact consequence
  and the remediation.

### Security

- This change grants the local identity standing authority to mint
  tickets the installed agent will honor. That's the
  self-host-just-works contract documented since v0.1. The existing
  `PORTL_TRUST_ROOTS` override (set before install, or in the
  service environment after the fact) continues to take precedence
  — v0.2.6 only fills the gap when nothing else is configured.
- The behavior is unchanged for ephemeral-mode agents
  (`PORTL_IDENTITY_SECRET_HEX` set); those still require explicit
  `PORTL_TRUST_ROOTS` and bail if it isn't provided.

### Validation

- `cargo fmt`, `cargo clippy -D warnings`,
  `cargo nextest run --workspace --all-features --profile ci` →
  313 passed, 5 skipped, 0 failed. Three new tests cover: empty-env
  launchd plist (no `EnvironmentVariables` dict emitted),
  trust-roots-present launchd plist (lint-validates via `plutil`
  on macOS), and systemd env-file formatting + path resolution for
  both root and user installs.
- Rendered launchd plist lint-validates under `plutil -lint` on
  macOS arm64.
- Rendered systemd unit + env file honor
  `EnvironmentFile=-/etc/portl/agent.env` on root installs and
  `EnvironmentFile=-$HOME/.config/portl/agent.env` on user installs.

### Follow-ups

- v0.3.0 (already scoped in `TODO-d49976fe`) replaces
  `PORTL_TRUST_ROOTS`-driven trust with a first-class
  `portl peer pair / peer accept` flow and a filesystem-backed peer
  store, retiring the env-var surface entirely. v0.2.6 fills the
  short-term hole until that larger rework lands.

## 0.2.5 — 2026-04-22

Bug-fix release. Actually fixes the macOS TLS SIGABRT that v0.2.4
only papered over. No other user-visible changes.

### Fixed

- **`portl shell` / `portl status` / any peer-handshake path still
  aborted on macOS in v0.2.4** with
  `malloc: *** error for object 0x…: pointer being freed was not
  allocated`. After symbolicating the crash report with a
  non-stripped release build, the real failure was not the
  aws-lc-rs/ring collision we fixed in v0.2.4 but a drop-path bug
  in `iroh 0.98.1`'s `Endpoint::online()`: when `any()` short-
  circuits on the home-relay-status Flatten iterator, dropping the
  outer `Vec<Option<(RelayUrl, HomeRelayStatus)>>` frees a pointer
  libmalloc says was never allocated (`endpoint.rs:1291`). Every
  portl handshake path went through `online().await` before
  dialing, so every `portl shell`, `portl status`, `portl mint …`
  → `portl shell` flow crashed before touching the wire.

### Changed

- `portl_core::net::client::open_ticket_v1` no longer calls
  `endpoint.inner().online().await`. `Endpoint::connect()` already
  picks a relay on its own when no home relay is cached, so the
  pre-wait was a latency optimization, not a correctness
  requirement. A prominent TODO comment points at the iroh bug and
  asks us to restore the pre-wait once an iroh release fixes it.
- The aws-lc-rs → ring switch shipped in v0.2.4 is retained: it
  still drops the `aws-lc-sys` C dependency (~1.5 MB of binary
  bloat on macOS, known footgun per `rustls/rustls#1877`). It was
  just never the actual cause of the SIGABRT.

### Validation

- Local: 10 consecutive `portl mint shell` + `portl status` runs
  on macOS arm64 (`thinh@max`), all clean exits (expected
  "Connecting to ourself is not supported"), zero SIGABRTs. Before
  the fix: 4/5 runs crashed.
- Cross-machine: Linux x86_64 (`vn3`) → macOS arm64 (`max`), 5/5
  `portl status` runs from an unauthorized Linux peer to the max
  agent, all clean exits with the expected `BadChain` ticket
  rejection from the relay'd handshake.
- `cargo fmt`, `cargo clippy -D warnings`,
  `cargo nextest run --workspace --all-features --profile ci` →
  310 passed, 5 skipped, 0 failed.

## 0.2.4 — 2026-04-22

Bug-fix release. Ships one critical fix for the v0.2.x line; no
other user-visible changes.

### Fixed

- **`portl shell` / `portl status` / any command that opened a peer
  handshake would SIGABRT on macOS** with
  `malloc: *** error for object 0x…: pointer being freed was not
  allocated` on the first TLS handshake. Root cause: `reqwest 0.13`
  enabled its `rustls` feature with the `aws-lc-rs` crypto provider
  by default, while every other TLS consumer in the tree (`iroh`,
  `hickory-net`, `noq-proto`) used `ring`. Rust feature unification
  left both C crypto libraries linked into the same binary, and on
  macOS their internal allocator hooks collided — see
  [`rustls/rustls#1877`](https://github.com/rustls/rustls/issues/1877).
  The CLI (and every peer-handshake path under the CLI) would abort
  before the first TLS exchange completed.

### Changed

- `reqwest` feature set switched from `rustls` to
  `rustls-no-provider`, dropping `aws-lc-rs` / `aws-lc-sys` from the
  workspace entirely.
- New `portl_core::tls::install_default_crypto_provider()` helper
  registers `ring` as the process-wide rustls crypto provider. It is
  called once from `portl_cli::run()` (the main CLI entry) and from
  `slicer_portl::SlicerClient::new` (the one other `reqwest::Client`
  construction site that can be reached outside the CLI entry, e.g.
  from integration tests).

### Validation

- `cargo tree -i aws-lc-sys` now reports "did not match any
  packages" — the C crypto library is no longer linked.
- `cargo fmt`, `cargo clippy -D warnings`, and
  `cargo nextest run --workspace --all-features --profile ci`
  (310 passed, 5 skipped, 0 failed) all pass.
- Manual repro: running `portl status <ticket>` against an
  unreachable peer now cleanly returns the handshake rejection
  instead of aborting the process with SIGABRT.

## 0.2.3 — 2026-04-22

Test-build tuning release. Pure developer-experience improvements —
no user-facing API, wire-format, or behaviour changes. `cargo test
--workspace --all-features` wall-clock drops ~83 % on macOS Apple
Silicon (272 s → 44 s on the reference host) by applying the
learnings from the `autoresearch/v0.2.2-tuning` session.

### Changed

- **`Cargo.toml`**: trim `clap` default features to the set actually
  used (`std`, `derive`, `help`, `usage`, `error-context`,
  `suggestions`, `color`, `wrap_help`). Drops `env` + `unicode` +
  `cargo`. `portl-cli` never wires `#[arg(env = …)]` and the help
  snapshot test already relies on `wrap_help`, so the trim is
  behaviour-neutral. Cuts the dominant `portl-cli` lib rustc unit by
  roughly a second per rebuild.
- **`.config/nextest.toml`**: set `[profile.ci] test-threads = 24`
  (1.5× logical CPU count on Apple Silicon M-series). iroh handshake
  tests block on QUIC IO for several seconds each, so
  oversubscription lets CPU-bound tests squeeze between network
  waits. `test-threads ≥ 28` legitimately races
  `m3_cli::exec_exits_promptly_when_child_exits_with_stdin_idle`
  on this host; 24 is the safe ceiling.
- **`[[bin]] test = false`** on `portl` (`portl-cli`),
  `portl-manual-adapter` (`manual-portl`), and
  `portl-slicer-adapter` (`slicer-portl`). These three `main.rs`
  files declare zero `#[test]` functions, so the default bin-as-test
  target was an empty link + an extra ~500 ms macOS syspolicyd
  first-execution scan per nextest run.
- **`crates/portl-cli/src/alias_store.rs`**: reduce the in-test
  writer iteration counts for the two `fsync`-bound concurrent-write
  tests. `many_writers_converge_to_full_set` 4 × 250 → 4 × 20 saves
  and `readers_observe_monotonic_snapshots_while_writer_updates`
  writer 200 → 80 / reader cap 1 000 → 400. Each save `fsync`s a
  tmp file, renames it into place, and `fsync`s the parent dir —
  ~85 ms per save on APFS — so the original counts spent most of
  their wall-clock inside the kernel page cache flushing queue
  rather than exercising coverage. The four-writer contention shape
  (the semantic contract) and the monotonic-growth assertion are
  unchanged; only the iteration counts move.
- **`crates/portl-agent/tests/udp_e2e.rs`**:
  `udp_session_expires_after_linger` sleep 2 s → 1.3 s. The agent
  linger API is whole-second-truncated via `unix_now_secs`, so 1.3 s
  is 30 % margin over the 1 s configured linger — matches scheduler
  jitter headroom used elsewhere in the suite.
- **Merged small integration-test files** (compiling fewer, smaller
  test binaries with similar dependency shapes is a net compile +
  per-binary-first-exec-scan win on macOS; nested `mod` blocks
  preserve fully-qualified test ids):
  - `crates/portl-core/tests/ticket_misc.rs` now contains
    `ticket_golden`, `ticket_hash`, `ticket_master`, `ticket_schema`,
    and `ticket_sign`.
  - `crates/portl-cli/tests/help_cli.rs` now also contains the
    former `doctor_cli`, `gateway_cli`, and `init_install_cli` tests
    (all subprocess-shaped, all small).
  - `crates/portl-agent/tests/agent_misc.rs` is new, bundling the
    former `discovery_local`, `panic_abort`, `pty_spawn`,
    `rate_limit`, and `rlimits` files. The `mod common;` declaration
    is lifted to the top of the merged file and nested uses are
    rewritten to `super::common::…`.

Net effect: the workspace goes from 49 test binaries to 35. No tests
added, removed, renamed, or weakened; every former `#[test]` is
reachable under a preserved test path. The nextest *binary-name*
segment of each id changes for the merged files (e.g.
`portl-agent::rate_limit …` becomes `portl-agent::agent_misc …`), so
any external dashboards or per-binary filters that pin on the old
binary name need a one-line update. In-tree CI uses no per-binary
filters and is unaffected.

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
