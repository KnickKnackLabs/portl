---
name: portl-testing
description: Use when writing, updating, or running Portl tests, especially Rust nextest filters, iroh endpoint helpers, tmux/session provider tests, or avoiding cargo test.
---

# Portl Testing

## Overview

Portl tests should be scoped with `cargo nextest` filtersets and should avoid real iroh DNS/relay setup unless the test explicitly validates discovery or relay behavior.

## Core Rules

- Do not use `cargo test`; use `cargo nextest run` or `cargo nextest list`.
- Prefer `-E` filtersets over positional test names for precise scoping.
- Always narrow by binary kind/name when possible so nextest does not discover/run unrelated binaries.
- For in-process endpoint tests, use `portl_core::test_util::{endpoint, pair}`.
- Do not call `portl_core::endpoint::Endpoint::bind()` from tests unless the production `presets::N0` behavior itself is under test.
- Use `DiscoveryConfig::in_process()` for agent tests that do not need real discovery.

## Nextest Filter Patterns

List before running when unsure:

```bash
cargo nextest list -p portl-agent -E 'binary(=session_e2e)' --message-format oneline
```

Common scoped runs:

```bash
# One library unit test
cargo nextest run -p portl-agent \
  -E 'kind(lib) & test(tmux_viewport_snapshot_restores_cursor_for_live_deltas)'

# All tests under one Rust module in the library test binary
cargo nextest run -p portl-agent \
  -E 'kind(lib) & test(session_handler::provider::tests::)'

# One integration-test binary
cargo nextest run -p portl-core -E 'binary(=endpoint)'

# Selected tests inside one integration-test binary
cargo nextest run -p portl-agent \
  -E 'binary(=session_e2e) & (test(session_list_aggregates_available_providers_and_resolves_unique_attach) + test(session_tmux_provider_attaches_with_control_mode))'
```

`test(...)` defaults to contains matching. Use `test(=full::path::name)` only when exact matching matters.

## Iroh Endpoint Testing

Use local-only helpers:

```rust
let endpoint = portl_core::test_util::endpoint().await?;
let (client, server) = portl_core::test_util::pair().await?;
```

These helpers use iroh `presets::Minimal`, disable relays, avoid default DNS/PKARR publication, and install a loopback DNS resolver so tests do not hang in platform DNS setup.

Use production `Endpoint::bind()` only for tests whose purpose is to validate production endpoint defaults.

## Tmux / Session Provider Testing

- Prefer focused unit tests for tmux control parsing and snapshot rendering.
- For tmux session e2e tests, scope to `binary(=session_e2e)`.
- Snapshot/live-output bugs usually require cursor-position assertions, not just byte-for-byte captured text.
- Fake provider scripts must model both `display-message` and `capture-pane` when testing viewport snapshots.

## Formatting and Verification

- Run `cargo fmt` after Rust edits.
- If unrelated untracked broken files block formatting, inspect with `git status --short`; do not silently fix unrelated tracked changes.
- Use fresh nextest output before claiming tests pass.

## Common Mistakes

- Running `cargo nextest run -p portl-agent some_name` without `kind(lib)` or `binary(...)`; this can still discover unrelated binaries.
- Using real iroh DNS/relay setup for tests that only need local peer-to-peer behavior.
- Treating nextest timeout as a code failure before sampling/listing; verify whether it is stuck in setup, discovery, or the code under test.
- Updating fake tmux output expectations without updating the fake command argument handling.
