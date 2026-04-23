# Changelog

All notable changes land here. This project follows
[Semantic Versioning](https://semver.org/) from v0.1.0 onward.

## Unreleased

## 0.3.4.1 — 2026-04-24

Observability correctness + CLI resolution unification. The
v0.3.2 live-connection registry had a keying bug that hid live
connections; the v0.3.0 peer-resolution cascade had drifted into
two copies with different behaviour. This release fixes both and
consolidates endpoint-id display/parsing across the CLI.

### Agent — live-connection registry

- `ConnectionRegistry` is now keyed by `(peer_eid, stable_id)`
  instead of `peer_eid` alone. Two concurrent QUIC connections
  from the same peer no longer collapse into a single row, and
  the first connection to close no longer wipes the row for
  other live connections.
- The registry stores an `iroh::endpoint::Connection` per row;
  `snapshot()` derives `path`, `rtt_micros`, `bytes_rx`, and
  `bytes_tx` live from iroh at query time. The previously
  dead `set_rtt` / `set_path` / `add_bytes` APIs are gone; the
  `portl status` dashboard fields that were hard-coded to
  `unknown` / `—` / `0B` now report real values.
- `ConnectionSnapshot` gains `connection_id: u64` so concurrent
  connections from the same peer are distinguishable in output.
- `portl_active_connections` and `portl_active_udp_sessions`
  Prometheus gauges are derived from the corresponding
  registry's `len()` at scrape time instead of being manually
  incremented/decremented. No more gauge-vs-registry drift.
- `ConnectionGaugeGuard` renamed to `ConnectionRegistryGuard`
  and keys on the full `ConnKey`, removing only its own row.
- `StatusSource` trait gains `active_connection_count()` and
  `active_udp_session_count()` for the derived-gauge sync.

### CLI — unified peer resolution

- Single `peer_resolve::resolve_peer(peer, opts)` replaces the
  two drifting copies in `peer_resolve` (used by `shell`,
  `exec`, `tcp`, `udp`, `forward`, `docker run`) and
  `status::resolve_peer` (used by `portl status <peer>`).
- Unified cascade (first match wins, prints `using …` to
  stderr):
  1. Inline `portl…` ticket string.
  2. Label → `peers.json`.
  3. Label → `tickets.json`.
  4. Label → `aliases.json` (container adapters; stored ticket
     file or bare endpoint_id).
  5. Endpoint-id token (full 64-hex or middle-elided
     `PPPP…SSSS`).
- Inbound-only paired peers now fall through from step 2 to
  steps 3/4/5 before bailing. The prior behaviour instructed
  users to `portl ticket save <peer> …` but then refused to use
  that ticket under the same label — fixed.
- Held peers still hard-error (unchanged: holding is an
  explicit "don't dial" signal).
- `--relay` (previously status-only, via `force_relay`) is now
  supported uniformly through `ResolveOpts` — any caller can
  opt in.
- Deleted as duplicates: `status::resolve_peer`,
  `status::resolve_endpoint_addr`,
  `status::maybe_force_relay_*`,
  `status::relay_only_addr`,
  `status::relay_discovery_disabled`,
  `status::parse_endpoint_id`,
  `status::normalize_discovery_source`,
  `peer_resolve::resolve_peer_ticket`,
  `peer_resolve::parse_endpoint_id`.

### CLI — endpoint-id display & parse

- New `crate::eid` module owns `format_short` (canonical
  `PPPPPPPP…SSSS`, 8-hex prefix + 4-hex suffix) and `resolve`
  (full 64-hex, or middle-elided form matched against peer ∪
  ticket stores).
- `resolve` requires the `…` character for the short form;
  bare hex prefixes are rejected to prevent a mistyped label
  that happens to be hex-ish from silently matching. Ambiguous
  short forms error with the candidates listed.
- Switched to `format_short` in user-facing tabular output:
  `portl status` dashboard per-connection rows, `portl peer ls`,
  `portl ticket ls`, `portl peer unlink` confirmation,
  `portl peer pair` confirmation, `portl install --apply` self-row
  message. Full hex retained in copy-paste targets (`portl whoami`,
  `portl status <peer>` `endpoint:` line) and error messages that
  embed a command the user runs.
- `portl shell <elided>` / `portl status <elided>` / `portl tcp
  <elided>` etc. now all accept the elided form.

### Metrics

- `portl_active_connections` and `portl_active_udp_sessions`
  gauges are now correct by construction (derived from the live
  registries at scrape time), resolving a long-standing
  divergence where the gauge could stick above the registry
  count after a hung `accept_bi` loop.
- `portl_active_udp_sessions` is no longer a permanent zero —
  previously registered but never incremented.

## 0.3.4 — 2026-04-23

Peer pairing handshake. Completes the v0.3.0 deferral: three new
verbs replace the copy-paste-endpoint-id workflow, peer entries
gain `relay_hint`, and new ALPN `portl/pair/v1` lands on the
agent's existing iroh listener. Workspace bumped to `0.3.4`.

### CLI

- `portl peer invite [--ttl 1h] [--for <label>]` — issue a
  single-use invite code (`PORTLINV-…`) + write it to
  `$PORTL_HOME/pending_invites.json`. Default TTL 1h; supports
  bare seconds or shorthand (`s`/`m`/`h`/`d`).
- `portl peer invite --list` — tabulate pending invites with
  nonce prefix, `for_label` hint, and expiry.
- `portl peer invite --revoke <nonce-prefix>` — delete a pending
  invite. Ambiguous prefix fails clean.
- `portl peer pair <code>` — decode the invite, dial the inviter,
  and establish mutual trust. Both sides end up with matching
  peer entries (`PeerOrigin::Paired`).
- `portl peer accept <code>` — same dial, but one-way: caller
  gains `PeerOrigin::Accepted` inbound from the inviter, no
  outbound privilege back. Matches the "remote support / IoT"
  use case.
- All three JSON-aware where it makes sense (invite issue + list).

### Protocol

- New ALPN `portl/pair/v1`, added to the agent's `set_alpns` list
  alongside `portl/ticket/v1`.
- Wire types live in `portl-proto::pair_v1`: `PairRequest`,
  `PairResponse`, `PairResult { Ok, NonceExpired, NonceUnknown,
  AlreadyPaired { existing_label }, PolicyRejected(msg) }`,
  `PairMode { Pair, Accept }`. Postcard-encoded with u32 LE
  length prefix.
- Invite code format: base32 (RFC-4648, no pad) of `{version:1,
  inviter_eid:32, nonce:16, not_after:u64_le, relay_hint_len:1,
  relay_hint:variable}`, prefixed `PORTLINV-`. ~80 chars at
  typical relay-hint lengths.

### Stores

- New `$PORTL_HOME/pending_invites.json` tracked by
  `portl-core::pair_store::PairStore`. Same atomic-write pattern
  as `peer_store`. Missing file = no pending invites.
- `PeerEntry` gained `relay_hint: Option<String>` and
  `schema_version: u8` fields. Backward-compatible: v1 entries
  load with `relay_hint: None, schema_version: 1`; next save
  writes schema v2. No file migration needed.
- Caller's `endpoint_id` is read from the QUIC TLS peer cert,
  never from wire content — the wire format can't spoof identity.

### Agent

- New `crates/portl-agent/src/pair_handler.rs`:
    1. Read one postcard `PairRequest` from an accepted bi-stream.
    2. Validate the nonce against `pending_invites.json`
       (exists + not expired).
    3. Insert/update the caller in `peers.json` with the right
       `(accepts_from_them, they_accept_from_me)` tuple per
       `PairMode`. `Pair` → `(true, true)`; `Accept` →
       `(true, false)`.
    4. Consume the nonce (remove from `pending_invites.json`).
    5. Reply with `PairResponse::Ok` including the server's own
       `relay_hint` (from `RelayStatus`) and its `self` label.
- `AlreadyPaired` is idempotent: nonce still consumed, existing
  label returned verbatim, caller gets told to `peer ls`.
- Label-collision fallback: `<candidate>-<4-hex-of-eid>`.

### Security

- Nonces are 128-bit from `OsRng`; single-use; default 1h TTL;
  revocable.
- Invite codes are *not* secrets — they bind to a single inviter
  eid, have a short TTL, and are single-use. Leaked codes give
  an attacker at most one pair attempt against a single agent
  in a short window.
- No transitive trust: a pairs-with-B does not imply A-reaches-C
  via B.

### Version bump

Workspace `Cargo.toml` bumped to `0.3.4` (ends the diverge-from-tag
pattern for minor releases; `portl --version` now reports `0.3.4`
on all v0.3.4 artifacts).

### Tests & quality

400 tests pass (was 371 in v0.3.3.2), clippy clean under
`--all-features -D warnings`, fmt clean. 29 new tests cover:
invite code roundtrip (5), pair store ops (7), pair wire types
(4), TTL parsing (4), and end-to-end `handle_pair` paths
(5: happy path, accept mode, unknown/expired nonce, already-
paired idempotency).

### Out of scope (deferred)

- Agent-side reload task for `pending_invites.json` (today the
  pair handler reads the file per-request, which is already
  reload-on-every-call; a polling task would be redundant).
- Caller-side relay-hint propagation (the `caller_relay_hint`
  field in PairRequest is always `None` today; picking it up
  from the caller's own `RelayServerConfig` is v0.3.4.1).
- `portl peer ls` RELAY_HINT column (field is persisted; display
  column lands with v0.3.4.1 when the full relay-hint story
  is wired through `peer_resolve`).
- Integration test dialing through a live relay — iroh-relay's
  client + pair ALPN e2e still blocked by same harness gap
  as v0.3.3.2.

## 0.3.3.2 — 2026-04-23

Relay HTTPS + rejection metrics. Operators can now serve the
embedded iroh-relay over TLS using a standard PEM cert + key
pair. ACME and install-time plist/unit integration still deferred
to v0.3.3.3. Workspace `Cargo.toml` stays at `0.3.3` (4-component
SemVer isn't legal).

### Agent

- New `RelayTlsConfig { https_bind, cert_path, key_path }`. Wired
  up from `PORTL_RELAY_CERT` + `PORTL_RELAY_KEY` (both required
  together; setting one without the other fails at startup).
  `PORTL_RELAY_HTTPS_BIND` defaults to `0.0.0.0:443`, inheriting
  the HTTP bind IP when left at the default.
- Cert chain + private key loaded from PEM once at startup via
  `rustls-pemfile`. Fails cleanly on missing file, unreadable
  file, empty file, or zero-PEM-block content. Process-global
  rustls crypto provider initialized lazily (ring, matching the
  workspace's v0.2.4 no-aws-lc-rs convention).
- iroh-relay's `CertConfig::Manual` variant receives the cert
  chain; `rustls::ServerConfig::builder().with_single_cert(...)`
  builds the TLS server config. QUIC address discovery is not
  enabled (`QuicConfig = None`).
- `RelayStatus` gains `https_addr`. `/status/relay` and the
  dashboard surface it alongside `http_addr`.
- New metrics:
    - `portl_relay_accepts_total` — counter, every allowed
      authorization decision.
    - `portl_relay_rejects_total{reason}` — counter by reason;
      only `not_in_peer_store` fires in this release.

### CLI

- No CLI changes in this release; relay is still env-configured.
  Install-time wiring lands in v0.3.3.3.

### Out of scope (still deferred to v0.3.3.3)

- Let's Encrypt / ACME onboarding (`--relay-acme-email`).
- `portl install --apply --with-relay` plist / unit emission.
- Cert mtime reload (operator-provided cert rotation requires
  agent restart today).
- True integration test against a live iroh-relay client
  (iroh-relay's client isn't easy to spin up outside
  `iroh::Endpoint`; deferred to v0.3.4 when the pair protocol
  gives us a natural client-side harness).

### Tests & quality

371 tests pass (was 367 in v0.3.3.1); clippy clean under
`--all-features -D warnings`. The 4 new tests exercise PEM
cert/key loading (empty file, missing file, garbage input).

## 0.3.3.1 — 2026-04-23

Observability polish. No agent-side changes; this release is all
CLI ergonomics: the `--json` rollout promised in the v0.3.2
"deferred" list, plus `doctor --verbose` / `peer ls --active`.
Workspace `Cargo.toml` stays at `0.3.3` — SemVer doesn't accept
4-component versions, and the 4-component tag pattern matches
the earlier `v0.3.0.1` / `v0.3.1.x` precedent (tag = release,
workspace = parent minor). `portl --version` still reports
`0.3.3` on these binaries; the release artifact names include
the full tag.

### CLI

- `portl doctor` default output now hides passing checks (prints
  a `(N passing checks hidden — use --verbose to show)` footer
  instead). `portl doctor --verbose` restores the full table.
  `portl init` forces `--verbose` internally so onboarding shows
  every green check explicitly.
- `portl doctor --json` emits the structured `{schema,kind,checks}`
  envelope. Exit code still tracks fail presence.
- `portl whoami --json` adds the structured view. `--eid` still
  takes precedence (scripts that already consume the bare hex
  don't break).
- `portl peer ls --json` emits the structured view.
- `portl peer ls --active` overlays an agent IPC call against
  `/status/connections` and adds a `LIVE` column. Graceful
  degradation when the agent isn't running (shows all peers as
  inactive; no hard error).
- `portl ticket ls --json` emits the structured view (incl.
  `expires_at` / `expires_in_secs` / `expired`).

### Tests & quality

367 tests pass, clippy clean under `--all-features -D warnings`,
fmt clean. Help snapshots regenerated for doctor + whoami.

## 0.3.3 — 2026-04-23

Embedded relay (preview MVP). The agent can now optionally serve as
an iroh-relay for its peers, in-process, gated by the same peer
store that authorizes ticket handshakes. HTTP-only in this release;
HTTPS + ACME deferred to v0.3.3.1. Workspace version bumped to
`0.3.3` (ending the "workspace stays at parent" precedent — minor
releases now track the tag so `portl --version` matches reality).

### Agent

- New `crates/portl-agent/src/relay.rs` wraps `iroh_relay::server`
  and gates accept by consulting `state.trust_roots`. Because the
  trust set is reloaded live by `spawn_peer_store_reload_task`,
  relay access tracks `peers.json` edits without restart.
- Three policy tiers exposed via `PORTL_RELAY_POLICY`:
    - `open`        — `AccessConfig::Everyone`
    - `peers-only`  — endpoint must be in `trust_roots` (default)
    - `pairs-only`  — same as `peers-only` in v0.3.3; full
      enforcement waits on the v0.3.4 pair protocol. Falling back
      is reported as `pairs_only_pending_v034: true` in the JSON
      and called out in the human dashboard.
- Configuration via env vars only in this preview:
    - `PORTL_RELAY_ENABLE` (`0`/`1`, default `0`)
    - `PORTL_RELAY_BIND` (default `0.0.0.0:3340`)
    - `PORTL_RELAY_HOSTNAME` (default = bind IP)
    - `PORTL_RELAY_POLICY` (`open`/`peers-only`/`pairs-only`)
- The relay shares one process / one identity / one
  `tokio::Runtime` with the existing portl-protocol UDP listener.
  Drop of `RelayHandle` aborts the supervisor.
- New `/status/relay` IPC route on `metrics.sock` (JSON, schema v1
  envelope). The relay snapshot is also folded into the top-level
  `/status` response.

### CLI

- `portl status` (no args) now shows a `relay:` section when the
  agent has the embedded relay enabled. Hidden when disabled to
  keep the output uncluttered for the common single-host case.
- `--json` output of `portl status` includes the new `relay`
  field. Schema bump deferred until v0.4 — the addition is
  non-breaking and consumers that ignore unknown fields keep
  working.

### Out of scope (deferred to v0.3.3.1 within the same spec)

- HTTPS / ACME / operator-provided cert paths.
- `portl install --apply --with-relay` plist/unit emission.
- Per-policy / per-reason rejection counters in OpenMetrics.
- `portl status relay` focused subsection (the dashboard fold-in
  covers the operator workflow today; the dedicated route exists
  on the agent side via `/status/relay` for future use).

### Tests & quality

367 tests pass (was 361 in v0.3.2); clippy clean under
`--all-features -D warnings`. The relay listener is not exercised
by the unit tests (depends on a free TCP port and live iroh-relay
spawn); covered by manual smoke testing with a two-endpoint
loopback locally. Integration tests land alongside HTTPS in
v0.3.3.1.

## 0.3.2 — 2026-04-23

Observability dashboard. No wire or schema changes; additive new
HTTP routes on `metrics.sock` and a new `portl status` dashboard
mode. Workspace version stays `0.3.1` per the v0.3.0.1 /
v0.3.1.1 / v0.3.1.2 / v0.3.1.3 / v0.3.1.4 precedent.

### Agent

- New per-peer `ConnectionRegistry` tracks path kind
  (direct-udp / relay / mixed / unknown), RTT, rx/tx bytes, and
  up-since-unix. Populated and drained by `ticket_handler` in
  lockstep with the existing `active_connections` gauge.
- `metrics.sock` gained path-based HTTP dispatch. Existing
  `OpenMetrics` is served on `GET /` (and `GET /metrics` as an
  alias); three new JSON routes land alongside:
    - `GET /status` — agent info + connections + network
    - `GET /status/connections` — connections list only
    - `GET /status/network` — discovery config + relay URLs
  Unknown paths return `404` with a structured JSON error
  envelope (`{schema, kind:"error", error:{code,message}}`).
- Shared JSON envelope with `schema: 1` and a `kind` tag so
  future additions can coexist on the same socket without
  version sniffing.

### CLI

- `portl status` gained an optional `<peer>` arg. With no args,
  prints a local dashboard by hitting the new `/status` route
  over the agent's UDS. With `<peer>`, runs the existing
  ticket-handshake reachability probe unchanged.
- `portl status --json` pretty-prints the `/status` JSON.
- `portl status --watch <SECS>` re-renders the dashboard every
  N seconds (1..=3600). On a TTY it uses an ANSI clear + redraw;
  non-TTY callers see `--- tick N ---` separators instead.
  Ctrl+C exits clean. `--watch` is rejected with `--json`.
- New internal `agent_ipc` module wraps the UDS HTTP client so
  follow-up verbs can share one parser.

### Deferred to v0.3.3 (additive, within the same spec)

- Focused subsections (`status agent`, `status peers`, etc.).
- `--json` rollout on `doctor`, `peer ls`, `ticket ls`, `whoami`.
- `portl peer ls --active` runtime overlay.
- `doctor --verbose` (default hides passing checks).

### Tests & quality

361 tests pass (was 343 in v0.3.1.4); clippy clean under
`--all-features -D warnings`. No new unsafe; no new heavy deps
(RFC3339 formatting uses an inline `civil_from_days`
implementation rather than pulling in `chrono` or `time`).

## 0.3.1.4 — 2026-04-23

Hand-editable config file and multi-relay support. No wire
changes; existing env-var configuration continues to work with
identical precedence above portl.toml and below CLI flags.
Workspace version stays `0.3.1`.

### portl.toml

- New `$PORTL_HOME/portl.toml` (optional). Schema is
  `schema = 1`; unknown fields are tolerated for forward-compat.
  Sections:
    - `[agent]` — `listen_addr`
    - `[agent.discovery]` — `dns`, `pkarr`, `local`, `relays`
    - `[agent.rate_limit]` — `rps`, `burst`
    - `[agent.udp]` — `session_linger_secs`
    - `[cli]` — reserved for future CLI-local settings
- Precedence remains CLI flags > env vars > portl.toml >
  compiled defaults.
- New `portl config` verb with four subcommands:
    - `portl config show` — effective merged config
    - `portl config path` — resolved file location
    - `portl config default` — print a template (no write)
    - `portl config validate [PATH]` — parse without applying
- No auto-creation: the file is only read when it exists.
  `portl config default > ~/.local/share/portl/portl.toml`
  bootstraps it explicitly.

### Multi-relay

- `DiscoveryConfig.relays: Vec<RelayUrl>` replaces the old
  `Option<RelayUrl>`. Empty list disables relay; any entries
  form an explicit relay set passed to iroh's `RelayMode::custom`.
- `PORTL_DISCOVERY` grammar extended:
    - `relay` (bare) — n0 defaults
    - `relay:<url>` — append a custom URL
    - `disabled` — no relay
  The env token and the `[agent.discovery].relays = [...]`
  TOML list accept the same `"default"` alias and dedupe.

### Tests & quality

343 tests pass (was 329); clippy clean; shellcheck clean
on `install.sh`.

## 0.3.1.3 — 2026-04-23

CI / release pipeline cleanup. No binary or CLI changes; workspace
version stays `0.3.1` per the v0.3.0.1 / v0.3.1.1 / v0.3.1.2
precedent.

### CI / release pipeline

- Release workflow split out of CI. `.github/workflows/ci.yml`
  now fires on main pushes and PRs only; tag pushes (`v*`) trigger
  a dedicated `.github/workflows/release.yml` that gates on CI
  being green for the tagged SHA via a parallel
  `fountainhead/action-wait-for-check` matrix (one leg per required
  check — `cargo test`, `rustfmt`, `clippy`, `cargo deny`,
  `dep-guard`, `docker integration smoke` — with `fail-fast: true`
  so any red check cancels the rest immediately). Net effect: one
  CI run + one Release run per tagged release, instead of the
  previous duplicated CI matrix when a tag pointed at a commit
  already on main.
- GitHub release notes now contain only the CHANGELOG section for
  the released version (extracted from the matching
  `## <version> — <date>` heading) instead of the full
  CHANGELOG.md. Release publish fails fast with an actionable
  error if no matching section exists for the tag, so tagging
  without a CHANGELOG entry becomes a hard fail rather than a
  silent "entire history dumped as release body".

## 0.3.1.2 — 2026-04-23

Two additive fixes driven by gaps hit during v0.3.1 self-host
testing. No CLI / wire / schema changes beyond the additive flag
surface; workspace version stays `0.3.1` per the v0.3.0.1 /
v0.3.1.1 precedent.

### Relay / discovery

- `PORTL_DISCOVERY` now accepts an operator-provided relay URL via
  `relay:<url>` or `relay=<url>`. Previously the bare `relay`
  token meant "use the iroh default n0 relay" and any URL suffix
  was rejected as an unsupported backend, leaving self-hosted
  relay operators without a way to point agents at their own
  server. URLs are parsed through `iroh::RelayUrl::from_str`, so
  malformed values surface a clear error instead of a generic
  "unsupported PORTL_DISCOVERY backend".

  ```
  PORTL_DISCOVERY=dns,pkarr,local,relay:https://relay.mynet.com
  ```

### Doctor

- `portl doctor --fix` auto-remediates the duplicate-service drift
  that the v0.3.1 doctor started warning about (both user
  LaunchAgent + system LaunchDaemon loaded on macOS, or both
  user + system systemd units active on Linux — they fight over
  UDP binds). Strategy: keep the user lane (what
  `portl install --apply` writes by default for non-root
  invocations); tear down the system lane via
  `sudo launchctl bootout system/com.portl.agent` /
  `sudo systemctl disable --now portl-agent.service` plus unit
  file removal.
- `--yes` is required when stdin is non-TTY (scripting contexts).
- No-drift state is a clean no-op.

## 0.3.1.1 — 2026-04-23

Hotfix for a P0 install regression in v0.3.1: a fresh install
ended with a 0-byte `portl` binary.

### Container / install

- `portl install --apply` no longer truncates the portl binary to
  0 bytes on reinstall. Two compounding bugs caused the regression:
  `install.sh` created `portl-agent` + `portl-gateway` as symlinks
  to `portl`, and `portl install --apply` then called
  `std::fs::copy(current_exe, "…/portl-agent")`, which opens dst
  with `O_WRONLY|O_CREAT|O_TRUNC` *before* reading src. The open
  followed the symlink and truncated `portl` itself, so the
  subsequent read returned 0 bytes.
- Double fix, defense in depth:
  - `install.sh` now uses `install -m 0755` to create real copies
    of the multicall entrypoints (~10 MB each; trivially cheap).
    Eliminates the footgun class for the install.sh code path.
  - `portl install --apply` gains `install_binary_safely()`:
    canonicalizes src and dst, short-circuits on same-inode
    (handles idempotent re-apply and symlink-to-self), and
    unlinks dst before the copy — breaks any inode identity
    *before* dst is opened for writing, so even a symlink
    introduced between canonicalization and open can't truncate
    src.

## 0.3.1 — 2026-04-23

Ergonomics release. Three P0 container-bootstrap regressions from
v0.3.0 + three categories of UX polish driven by live self-host
testing.

### Container bootstrap

- `portl init` now seeds the peer-store self-row automatically. v0.3.0
  put this in `portl install --apply`, which refuses to run inside a
  container (launchd / systemd aren't available), leaving container
  operators with an empty peer store and `BadChain` on every ticket.
  Idempotent on re-run.
- `portl install --apply` in container mode seeds peers and prints a
  next-step hint (`portl-agent &`) instead of refusing outright. The
  service-install path still refuses (correctly).
- `portl init` prints a container-aware "next step" hint pointing at
  `portl-agent &` when a container is detected.

### Capability discoverability

- `portl ticket issue --help` now includes a full capability grammar
  + four examples covering common cases (shell, tcp port range,
  meta-only, all wildcard).
- `portl ticket issue --list-caps` prints the full capability
  reference — suitable for `grep`/paging.
- Invalid cap specs now emit an error listing valid caps + pointing
  at `--list-caps` for the full reference.
- Help text for `--ttl` and `--to` explains units and bearer
  semantics.

### Doctor drift detection

- `[…] package:` line — detects mise / homebrew / nix installs and
  surfaces upgrade hints for each.
- `[…] binaries:` line — walks `$PATH` for portl / portl-agent
  copies and warns on version drift (catches the common "upgraded
  CLI but running agent is stale" state).
- `[…] service:` line — launchd (macOS) / systemd (Linux) drift
  detection: warns when both user and system services are loaded
  (they fight over UDP binds), when no service is loaded,
  pointing at `portl install --apply` or `portl-agent &` as the
  remedy.

### CLI ergonomics

- `portl whoami --eid` prints just the 64-char endpoint_id hex —
  saves the `awk` dance common in scripts.

## 0.3.0 — 2026-04-22

Major rework of the trust and credential surface. v0.3.0 retires
the hidden `PORTL_TRUST_ROOTS` env var and replaces it with a
first-class two-store model (peers + tickets) backed by JSON files
on disk, reloaded live by the agent.

This is a **breaking release**. Nothing is preserved from v0.2.x
on the env var / alias side (intentional; nothing had shipped yet
under the v0.2 vocabulary that justified carrying a compat layer).

### Added

- **`portl peer`** subcommand (replaces the hidden
  `PORTL_TRUST_ROOTS` env surface):
  - `portl peer ls` — tabulate peer entries (label, endpoint,
    relationship, origin).
  - `portl peer unlink <label>` — remove a peer. Refuses to unlink
    the self-row to preserve the self-host contract.
  - `portl peer add-unsafe-raw <endpoint_hex> --label <name>
    {--mutual|--inbound|--outbound} [--yes]` — direct escape
    hatch for pinning a peer by raw endpoint_id. Requires the
    user to retype the full endpoint_id at a confirmation prompt
    (unless `--yes`) because it grants root-equivalent authority.
- **`portl ticket`** subcommand:
  - `portl ticket issue` — replaces the top-level `portl mint`.
    Identical args and behavior.
  - `portl ticket save <label> <string>` — parse a ticket string,
    bind its endpoint_id + expiry, and write it to the local
    ticket store under a user-chosen label. Subsequent
    `portl shell <label>` (etc.) resolve through the saved ticket.
  - `portl ticket ls` / `rm` / `prune` — manage the store.
  - `portl ticket revoke` — replaces the top-level `portl revoke`.
- **`portl whoami`** — two-line output (label + endpoint_id) for
  copy-paste sharing of the local identity.
- **Peer store** (`crates/portl-core/src/peer_store.rs`):
  atomic-write JSON at `$CONFIG_DIR/peers.json`. Carries label,
  endpoint_id, `(accepts_from_them, they_accept_from_me)` booleans
  so relationships can be inbound / outbound / mutual / held,
  `origin` (self / paired / accepted / raw), and `since`. Provides
  `trust_roots()` which filters held entries.
- **Ticket store** (`crates/portl-core/src/ticket_store.rs`):
  atomic-write JSON at `$CONFIG_DIR/tickets.json`. Parses endpoint
  and `not_after` at save time so `portl ticket ls` is O(n) in
  display time, and `prune` can bulk-remove expired entries.
- **Cross-store label uniqueness** (`store_index::label_in_use`):
  creating a peer or ticket with a name already used by the other
  store hard-errors to prevent silent route ambiguity.
- **Agent-side live reload**: the agent loads `peers.json` at
  startup, then polls every 500ms in a background task and swaps
  the in-memory `TrustRoots` set when the file changes. `portl
  peer add-unsafe-raw` takes effect without a service restart.
- **`portl install --apply`** now seeds the peer store with a
  self-row (`label=self`, `is_self=true`, `origin=self`, mutual).
  This fixes the "BadChain on fresh install" class of errors at
  the source: the agent starts with a non-empty trust set.
- **`portl doctor`** gains two lines:
  - `peers: N total (S self, M mutual, I inbound, O outbound, H held)`
  - `tickets-saved: N saved (soonest expires in …)`

### Removed

- **`PORTL_TRUST_ROOTS` env var** entirely. The agent no longer
  reads it. Trust configuration is the peer store and only the
  peer store.
- **`portl mint`** top-level command — moved to `portl ticket issue`.
- **`portl revoke`** top-level command — moved to `portl ticket revoke`.
- The `trust roots required when ephemeral secret set` startup
  check in `AgentConfig::from_env` (was tied to the env var).
  Ephemeral agents now have the same peer-store-backed policy.
- `mint-root` alias (was hidden; removed from parser).
- v0.2.6's `AgentEnv` plumbing + `PORTL_TRUST_ROOTS=<hex>` env
  injection in `portl install --apply` rendered plists / unit
  files. Install no longer writes env files for trust purposes
  (it still leaves `EnvironmentFile=-…` in the systemd unit for
  operators who want to set `PORTL_RATE_LIMIT`, etc.).

### Changed

- **Resolution cascade** in `shell` / `exec` / `tcp` / `udp` /
  `status`: the old alias-store + raw-ticket-string fallback is
  gone. The new cascade (printed on success as `using <source>`
  to stderr):
  1. peer entry with `they_accept_from_me=true` → mint fresh
     5-minute ticket and dial.
  2. saved ticket, unexpired → use it.
  3. peer entry with `they_accept_from_me=false` → hard error
     naming the asymmetry and the fix.
  4. raw 64-char hex endpoint_id → mint fresh, dial. One-off.
  5. otherwise → hard error listing possible sources.
- `AgentConfig.trust_roots` is now populated from `peers.json`
  via `PeerStore::trust_roots()`. Added `AgentConfig.peers_path`
  so the reload task knows where to re-read from.
- `AgentState.trust_roots` is now `RwLock<TrustRoots>` (was
  plain `TrustRoots`). The ticket handler takes a read lock
  during acceptance evaluation; the reload task takes a write
  lock on change.

### Migration

There is no compat path from v0.2.x. Anyone who was running a
v0.2.x install should:

1. `portl install --apply` again (seeds the new peer store with
   the self-row).
2. For each remote peer they want mutual trust with:
   - `portl whoami` on both sides to collect endpoint_ids.
   - `portl peer add-unsafe-raw <their_eid> --label <name> --mutual`
     on both sides.
3. `portl shell <name>` works as in v0.2.x, but now routed
   through the peer store.

Saved tickets (if any) can be imported with
`portl ticket save <label> <ticket-string>`.

### Follow-ups (v0.3.1+)

- `portl peer invite` + `peer pair` + `peer accept` — network
  pairing handshake over a new `portl/pair/v1` ALPN, so users
  don't need to paste endpoint_ids between machines to pair.
  Deferred because `peer add-unsafe-raw` covers the immediate
  self-host use case.
- `portl peer hold` / `resume` for temporary suspension.
- `portl peer rename` for relabel-without-unlink.

### Validation

- `cargo fmt`, `cargo clippy -D warnings`,
  `cargo nextest run --workspace --all-features --profile ci` →
  314 passed, 5 skipped, 0 failed.
- Manual smoke: `PORTL_HOME=/tmp/portl-test portl install
  dockerfile --apply --output /tmp/portl-test-out --yes`
  produces a peers.json with a self-row; `portl peer ls` renders
  it; `portl peer add-unsafe-raw` adds a mutual peer; `portl
  doctor` reports the expected counts.
- Help snapshot regenerated for the new CLI surface (wrap_help
  still honored; help output still wraps cleanly).

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
