# Agent Network Watchdog Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a lightweight built-in `portl-agent` watchdog that detects stale network endpoints, refreshes them automatically, surfaces health in status/doctor, and keeps target-mode JSON status machine-readable.

**Architecture:** Introduce a small watchdog module that owns health state, probe/backoff policy, and an abstract probe/refresh interface for tests. Wire it into `AgentState`, status schema, metrics IPC, and doctor output first; then integrate a production watchdog task that can rebuild the agent's Iroh endpoint when repeated self-probes fail.

**Tech Stack:** Rust 1.93, tokio, iroh endpoints, `cargo nextest`, existing Portl status/metrics IPC.

---

## File map

- Create `crates/portl-agent/src/network_watchdog.rs`: health snapshot, config, policy transitions, fake-probe test hooks, and production watchdog loop.
- Modify `crates/portl-agent/src/lib.rs`: add the module, add `network_watchdog` field to `AgentState`, record inbound handshakes, and spawn/cancel watchdog task.
- Modify `crates/portl-agent/src/status_schema.rs`: add `network_health` to `StatusResponse` and a `NetworkHealthInfo` schema struct.
- Modify `crates/portl-agent/src/metrics.rs`: extend `StatusSource` and include network health in `/status`.
- Modify `crates/portl-agent/src/config.rs` and `config_file.rs`: parse watchdog env/config knobs.
- Modify `crates/portl-cli/src/commands/doctor.rs`: render network watchdog health.
- Modify `crates/portl-cli/src/commands/status.rs`: make target `--json` emit only JSON and preserve human diagnostics on stderr.
- Test with `cargo nextest`; do not use `cargo test`.

## Task 1: Add watchdog health state and policy tests

**Files:**
- Create: `crates/portl-agent/src/network_watchdog.rs`
- Modify: `crates/portl-agent/src/lib.rs`

- [ ] **Step 1: Write failing unit tests**

Create `crates/portl-agent/src/network_watchdog.rs` with tests for inbound reset, failure threshold, refresh success, and refresh failure. Expected missing implementation names: `NetworkWatchdogHealth`, `WatchdogConfig`, `WatchdogState`.

- [ ] **Step 2: Verify RED**

Run:

```bash
RUSTUP_TOOLCHAIN=1.93.0 cargo nextest run -p portl-agent -E 'kind(lib) & test(network_watchdog::tests::)'
```

Expected: compile failure because watchdog types are not implemented.

- [ ] **Step 3: Implement health state**

Add `pub mod network_watchdog;` to `crates/portl-agent/src/lib.rs`. Implement in `network_watchdog.rs`:

- `WatchdogState::{Disabled, Ok, Degraded, Refreshing, Failed}` with snake_case serde.
- `WatchdogConfig { enabled, interval, timeout, failures_before_refresh }`, defaulting to enabled, 5m interval, 5s timeout, 3 failures.
- `NetworkHealthSnapshot` with endpoint generation, timestamps, failure count, refresh count, and last refresh error.
- `NetworkWatchdogHealth` wrapping an `Arc<RwLock<Inner>>` and methods:
  - `new(now)`
  - `disabled(now)`
  - `record_inbound_handshake(now)`
  - `record_probe_success(now)`
  - `record_probe_failure(now) -> ProbeFailureAction`
  - `record_endpoint_refresh_success(now)`
  - `record_endpoint_refresh_failure(now, error)`
  - `snapshot(now)`
- `ProbeFailureAction::should_refresh(&WatchdogConfig)`.

- [ ] **Step 4: Verify GREEN**

Run:

```bash
RUSTUP_TOOLCHAIN=1.93.0 cargo fmt --all
RUSTUP_TOOLCHAIN=1.93.0 cargo nextest run -p portl-agent -E 'kind(lib) & test(network_watchdog::tests::)'
```

Expected: watchdog unit tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/portl-agent/src/lib.rs crates/portl-agent/src/network_watchdog.rs
git commit -m "Add agent network watchdog state"
```

## Task 2: Surface network health through status IPC and doctor

**Files:**
- Modify: `crates/portl-agent/src/status_schema.rs`
- Modify: `crates/portl-agent/src/metrics.rs`
- Modify: `crates/portl-agent/src/lib.rs`
- Modify: `crates/portl-cli/src/commands/doctor.rs`

- [ ] **Step 1: Write failing schema and doctor tests**

Add a `status_response_includes_network_health` test in `status_schema.rs` that constructs `StatusResponse::new(...)` with a `NetworkHealthInfo` and asserts serialized JSON contains `network_health.state == "ok"`. Add a focused doctor test that renders a degraded network endpoint check as `warn`.

- [ ] **Step 2: Verify RED**

Run:

```bash
RUSTUP_TOOLCHAIN=1.93.0 cargo nextest run -p portl-agent -p portl-cli -E 'kind(lib) & (test(status_response_includes_network_health) | test(network_endpoint))'
```

Expected: compile/test failure until network health status plumbing exists.

- [ ] **Step 3: Add status schema and source plumbing**

Add `NetworkHealthInfo` to `status_schema.rs`, implement `From<network_watchdog::NetworkHealthSnapshot>`, add `network_health` to `StatusResponse`, and add a `network_health` parameter to `StatusResponse::new`.

Add `fn network_health(&self) -> NetworkHealthInfo` to `metrics::StatusSource`. Update `/status` rendering to pass `s.network_health()`.

Add `network_watchdog: NetworkWatchdogHealth` to `AgentState`, initialize it in `run_with_shutdown`, and implement `StatusSource::network_health` with `self.network_watchdog.snapshot(SystemTime::now()).into()`.

- [ ] **Step 4: Render doctor health check**

In `doctor.rs`, render a `network endpoint` check from agent status JSON:

- `ok` for `state == ok`
- `warn` for `degraded` or `refreshing`
- `fail` for `failed`
- `warn` for `disabled` while a managed agent is loaded

Include endpoint generation, consecutive failures, refresh count, and last refresh error in detail text.

- [ ] **Step 5: Verify and commit**

Run:

```bash
RUSTUP_TOOLCHAIN=1.93.0 cargo fmt --all
RUSTUP_TOOLCHAIN=1.93.0 cargo nextest run -p portl-agent -p portl-cli -E 'kind(lib) & (test(status_response_includes_network_health) | test(network_endpoint))'
```

Commit:

```bash
git add crates/portl-agent/src/status_schema.rs crates/portl-agent/src/metrics.rs crates/portl-agent/src/lib.rs crates/portl-cli/src/commands/doctor.rs
git commit -m "Expose agent network watchdog health"
```

## Task 3: Make target status JSON machine-readable

**Files:**
- Modify: `crates/portl-cli/src/commands/status.rs`
- Test: `crates/portl-cli/tests/status_cli.rs` or module tests in `status.rs`

- [ ] **Step 1: Write failing test**

Add a pure renderer test proving target-mode JSON emits one parseable JSON object that includes endpoint, path, discovery, relationship, remote agent version, uptime, hostname, and OS, and does not contain the human `endpoint:` prefix.

- [ ] **Step 2: Verify RED**

Run:

```bash
RUSTUP_TOOLCHAIN=1.93.0 cargo nextest run -p portl-cli -E 'kind(lib) & test(target_status_json_emits_single_json_object_without_human_prefix)'
```

- [ ] **Step 3: Implement probe report rendering**

Refactor target status so the async probe returns a `ProbeReport` instead of printing inside `run_with_endpoint`. Human mode calls the existing `print_status`; JSON mode prints only `serde_json::to_string(&report_json)`. Keep peer resolution messages on stderr.

- [ ] **Step 4: Verify and commit**

Run:

```bash
RUSTUP_TOOLCHAIN=1.93.0 cargo fmt --all
RUSTUP_TOOLCHAIN=1.93.0 cargo nextest run -p portl-cli -E 'kind(lib) & test(target_status_json_emits_single_json_object_without_human_prefix)'
portl status vn3 --json >/tmp/status.json 2>/tmp/status.err
jq . /tmp/status.json >/dev/null
```

Commit:

```bash
git add crates/portl-cli/src/commands/status.rs crates/portl-cli/tests/status_cli.rs
git commit -m "Emit clean JSON for target status probes"
```

## Task 4: Add watchdog config parsing

**Files:**
- Modify: `crates/portl-agent/src/config.rs`
- Modify: `crates/portl-agent/src/config_file.rs`
- Modify: `docs/ENV.md`

- [ ] **Step 1: Write failing config tests**

Add env-isolated tests proving defaults and overrides:

- default enabled in listener/agent mode
- `PORTL_AGENT_WATCHDOG=off` disables
- `PORTL_AGENT_WATCHDOG_INTERVAL=30s`
- `PORTL_AGENT_WATCHDOG_TIMEOUT=2s`
- `PORTL_AGENT_WATCHDOG_FAILURES=2`

- [ ] **Step 2: Verify RED**

Run:

```bash
RUSTUP_TOOLCHAIN=1.93.0 cargo nextest run -p portl-agent -E 'kind(lib) & test(config::tests::watchdog_env)'
```

- [ ] **Step 3: Implement parsing and docs**

Add `watchdog: WatchdogConfig` to `AgentConfig`. Parse the env vars with existing duration parsing style and minimum `failures_before_refresh = 1`. Add optional config-file fields only if they fit existing `[agent]` config patterns cleanly; otherwise document that the first release supports env knobs only.

Update `docs/ENV.md` with all watchdog env vars and defaults.

- [ ] **Step 4: Verify and commit**

Run:

```bash
RUSTUP_TOOLCHAIN=1.93.0 cargo fmt --all
RUSTUP_TOOLCHAIN=1.93.0 cargo nextest run -p portl-agent -E 'kind(lib) & test(config::tests::watchdog_env)'
```

Commit:

```bash
git add crates/portl-agent/src/config.rs crates/portl-agent/src/config_file.rs docs/ENV.md
git commit -m "Add agent watchdog configuration"
```

## Task 5: Wire inbound tracking and watchdog loop

**Files:**
- Modify: `crates/portl-agent/src/lib.rs`
- Modify: `crates/portl-agent/src/network_watchdog.rs`
- Possibly modify: `crates/portl-agent/src/ticket_handler.rs`

- [ ] **Step 1: Write fakeable loop tests**

Add tests for `apply_probe_outcome(config, health, now, outcome)`:

- success records `last_self_probe_ok_at` and resets failures
- three failures request refresh
- refresh success resets failures and increments generation

- [ ] **Step 2: Verify RED**

Run:

```bash
RUSTUP_TOOLCHAIN=1.93.0 cargo nextest run -p portl-agent -E 'kind(lib) & test(network_watchdog::tests::watchdog_)'
```

- [ ] **Step 3: Implement loop core**

Add `ProbeOutcome::{Success, Failure(String)}` and `apply_probe_outcome(...) -> bool` to keep the threshold/backoff logic unit-testable without networking.

- [ ] **Step 4: Record inbound handshakes**

In `lib.rs`, after `incoming.await` succeeds and before spawning ticket/pair handlers, call `state.network_watchdog.record_inbound_handshake(SystemTime::now())`.

- [ ] **Step 5: Implement production self-probe and recovery**

Spawn a watchdog task in `run_with_shutdown` when enabled. The task wakes on jittered interval, skips probing if inbound traffic is recent, performs a lightweight self-probe with `cfg.timeout`, and applies the outcome.

If three consecutive failures occur, prefer in-place endpoint recreation if it can be isolated behind a narrow network subsystem boundary. If in-place recreation is too invasive for the first implementation, use the approved service-manager-backed fallback: record failure, log clearly, and exit with a nonzero code so launchd/systemd restarts the agent. Do not exit on the first or second failure.

- [ ] **Step 6: Verify and commit**

Run:

```bash
RUSTUP_TOOLCHAIN=1.93.0 cargo fmt --all
RUSTUP_TOOLCHAIN=1.93.0 cargo nextest run -p portl-agent -E 'kind(lib) & test(network_watchdog::tests::)'
RUSTUP_TOOLCHAIN=1.93.0 cargo nextest run -p portl-agent -E 'binary(=session_e2e) & test(session_list_aggregates_available_providers_and_resolves_unique_attach)'
```

Commit:

```bash
git add crates/portl-agent/src/lib.rs crates/portl-agent/src/network_watchdog.rs crates/portl-agent/src/ticket_handler.rs
git commit -m "Run agent network watchdog"
```

## Task 6: Verification, review, OrbStack, and release

- [ ] **Step 1: Full local verification**

Run:

```bash
RUSTUP_TOOLCHAIN=1.93.0 cargo fmt --all
git diff --check
RUSTUP_TOOLCHAIN=1.93.0 cargo nextest run --profile ci --workspace --lib --bins --tests
RUSTUP_TOOLCHAIN=1.93.0 cargo clippy --workspace --all-targets -- -D warnings
cargo deny --all-features check
RUSTUP_TOOLCHAIN=1.93.0 cargo nextest run --profile ci -p portl-cli --features ghostty-vt-static -E 'binary(=ghostty_smoke)'
```

- [ ] **Step 2: Post-implementation roundtable review**

Run `/roundtable-review` if available. If unavailable, dispatch three reviewer subagents with models `openai/gpt-5.4`, `anthropic/claude-opus-4-7`, and `google/gemini-3.1-pro-preview`, asking for Critical/High/Medium issues in watchdog design, endpoint refresh behavior, status JSON compatibility, CPU/network overhead, and service-manager restart safety.

- [ ] **Step 3: Address High and Medium review items**

For each valid High/Medium item, write a failing test or reproduction first, fix it, and rerun the smallest relevant verification. Commit review fixes separately.

- [ ] **Step 4: OrbStack validation**

Run existing Linux/Ghostty validation scripts:

```bash
scratch/ghostty-musl-smoke.sh x86_64-unknown-linux-musl
scratch/ghostty-musl-smoke.sh aarch64-unknown-linux-musl
scratch/ghostty-provider-e2e.sh x86_64-unknown-linux-musl
scratch/ghostty-provider-e2e.sh aarch64-unknown-linux-musl
```

Add a watchdog smoke in an OrbStack Linux environment: install the built binary, start agent with a short watchdog interval, confirm `portl status --json` shows `network_health.state == "ok"`, and confirm `portl doctor --verbose` reports network endpoint health.

- [ ] **Step 5: Release patch**

Use `/skill:portl-release` workflow:

```bash
git status --short --branch
git log --oneline --decorate -5
git describe --tags --abbrev=0
```

Draft/update `CHANGELOG.md`, run release prep/verify, commit, push main, wait for CI, tag, and watch the release publish.
