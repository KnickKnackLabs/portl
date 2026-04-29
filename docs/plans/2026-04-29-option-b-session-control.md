# Option B Session Control Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement viewport-first, live-output-aware, coalescing session control for zmx first, then tmux B1+B2, and release a new minor Portl version.

**Architecture:** zmx owns provider-native terminal state and emits semantic control frames for viewport snapshots, live output, and history chunks while retaining legacy direct `zmx attach` behavior. Portl consumes those semantic frames through the existing zmx-control process boundary, maps render frames to the attach stdout stream, and preserves critical stdin/resize/cancel separation. tmux follows with equivalent Portl-side snapshot/live/history/coalescing using tmux `-CC`, `%output`, and `capture-pane`.

**Tech Stack:** Zig zmx control protocol, Rust Portl `portl/session/v1`, iroh streams, tmux `-CC`, Cargo tests, Zig tests, Bats tests, OrbStack Docker validation, mise Portl release tasks.

---

## File Map

### zmx worktree: `/Users/thinh/.config/superpowers/worktrees/zmx/option-b-control`

- `src/ipc.zig` — add stable semantic tags for the zmx control bridge: control init, viewport snapshot, live output, history chunks/end.
- `src/util.zig` — split terminal serialization into viewport-only, history/all, and legacy restore helpers.
- `src/main.zig` — classify direct terminal vs control clients, emit semantic frames for control clients, chunk history, coalesce slow control-client live output into latest viewport snapshots, and update control probe features.
- `test/session.bats` — integration coverage for control viewport-first, live output tags, and command-on-create startup output.

### Portl worktree: `/Users/thinh/.config/superpowers/worktrees/portl/option-b-session-control`

- `crates/portl-agent/src/session_handler/mod.rs` — consume zmx semantic tags, continue legacy tag support, and update fake zmx control tests.
- `crates/portl-agent/src/session_handler/tmux_control.rs` — later B1+B2 tmux snapshot/live/coalescing support.
- `crates/portl-agent/src/session_handler/provider.rs` — update provider feature advertisement and tmux capture helpers.
- `crates/portl-core/src/wire/session.rs` — add provider feature constants only if needed; avoid breaking `portl/session/v1` unless tests prove a new wire stream is necessary.
- `crates/portl-agent/tests/session_e2e.rs` — regression tests for zmx semantic frames and tmux B1/B2 behavior.
- `CHANGELOG.md`, version manifests, README — release prep updates through `mise run release:prep`.

---

## Task 1: zmx semantic control tags and serialization tests

**Files:**
- Modify: `/Users/thinh/.config/superpowers/worktrees/zmx/option-b-control/src/ipc.zig`
- Modify: `/Users/thinh/.config/superpowers/worktrees/zmx/option-b-control/src/util.zig`
- Modify: `/Users/thinh/.config/superpowers/worktrees/zmx/option-b-control/src/main.zig`

- [ ] **Step 1: Write failing zmx tests for new semantic tags and viewport serialization**

Add tests that expect:

```zig
try std.testing.expectEqual(@as(u8, 14), @intFromEnum(ipc.Tag.ViewportSnapshot));
try std.testing.expectEqual(@as(u8, 15), @intFromEnum(ipc.Tag.LiveOutput));
try std.testing.expectEqual(@as(u8, 16), @intFromEnum(ipc.Tag.HistoryChunk));
try std.testing.expectEqual(@as(u8, 17), @intFromEnum(ipc.Tag.HistoryEnd));
try std.testing.expectEqual(@as(u8, 18), @intFromEnum(ipc.Tag.ControlInit));
```

Add a viewport serialization unit test that fills scrollback and asserts `serializeViewportSnapshot()` contains the visible marker but omits an old scrollback marker.

- [ ] **Step 2: Run the zmx tests and verify RED**

Run:

```bash
cd /Users/thinh/.config/superpowers/worktrees/zmx/option-b-control
zig build test
```

Expected: fail because tags/helpers do not exist.

- [ ] **Step 3: Implement semantic tags and split serialization helpers**

Add tags to `ipc.Tag` without changing existing values:

```zig
ViewportSnapshot = 14,
LiveOutput = 15,
HistoryChunk = 16,
HistoryEnd = 17,
ControlInit = 18,
```

Add helpers:

```zig
pub fn serializeViewportSnapshot(alloc: std.mem.Allocator, term: *ghostty_vt.Terminal) ?[]const u8
pub fn serializeTerminalHistory(alloc: std.mem.Allocator, term: *ghostty_vt.Terminal, format: HistoryFormat) ?[]const u8
```

Keep `serializeTerminalState()` as the legacy direct-attach restore helper.

- [ ] **Step 4: Run zmx tests and verify GREEN**

Run:

```bash
cd /Users/thinh/.config/superpowers/worktrees/zmx/option-b-control
zig build test
```

Expected: pass.

---

## Task 2: zmx control clients emit viewport/live/history frames

**Files:**
- Modify: `/Users/thinh/.config/superpowers/worktrees/zmx/option-b-control/src/main.zig`
- Modify: `/Users/thinh/.config/superpowers/worktrees/zmx/option-b-control/test/session.bats`

- [ ] **Step 1: Write failing integration tests**

Add Bats coverage that:

1. seeds a session with output,
2. attaches through `zmx control --rows 24 --cols 80`,
3. decodes the binary stream with `od`,
4. asserts a frame beginning with tag `0e` (`ViewportSnapshot`) appears before tag `0f` (`LiveOutput`),
5. asserts command-on-create still emits startup output.

- [ ] **Step 2: Run the Bats test and verify RED**

Run:

```bash
cd /Users/thinh/.config/superpowers/worktrees/zmx/option-b-control
zig build
bats test/session.bats --filter 'control:'
```

Expected: fail because control clients still receive legacy `.Output` frames.

- [ ] **Step 3: Implement control client classification**

Add:

```zig
const ClientKind = enum { terminal, control };
```

Extend `Client` with `kind: ClientKind = .terminal`.

Make `controlLoop()` send `.ControlInit` with `ipc.Resize` payload instead of `.Init`. Keep direct `clientLoop()` unchanged.

Add `Daemon.handleControlInit()` that sets `client.kind = .control`, resizes the PTY/terminal state, releases command-on-create child start, and queues `.ViewportSnapshot` using `serializeViewportSnapshot()` when state exists.

- [ ] **Step 4: Emit semantic frames**

In PTY output fanout:

```zig
const tag: ipc.Tag = if (client.kind == .control) .LiveOutput else .Output;
```

Forward `.ViewportSnapshot`, `.LiveOutput`, `.HistoryChunk`, and `.HistoryEnd` from `controlLoop()` stdout.

Chunk `.History` responses for control clients as `.HistoryChunk` + `.HistoryEnd`; keep legacy `.History` for terminal/direct clients.

- [ ] **Step 5: Run zmx control tests and verify GREEN**

Run:

```bash
cd /Users/thinh/.config/superpowers/worktrees/zmx/option-b-control
zig fmt src/ipc.zig src/util.zig src/main.zig
zig build test
zig build
bats test/session.bats --filter 'control:'
```

Expected: pass.

---

## Task 3: zmx B2 coalescing for slow control clients

**Files:**
- Modify: `/Users/thinh/.config/superpowers/worktrees/zmx/option-b-control/src/main.zig`
- Modify: `/Users/thinh/.config/superpowers/worktrees/zmx/option-b-control/src/util.zig` if snapshot throttling helpers are needed.

- [ ] **Step 1: Write failing unit/integration tests for control-client queue coalescing**

Add a testable helper that takes a control client write buffer length and decides whether to replace queued live output with a viewport snapshot. The failing test asserts that a control client above the cap drops stale queued live data and queues one `.ViewportSnapshot` frame.

- [ ] **Step 2: Run zmx tests and verify RED**

Run:

```bash
cd /Users/thinh/.config/superpowers/worktrees/zmx/option-b-control
zig build test
```

Expected: fail because coalescing helper does not exist.

- [ ] **Step 3: Implement bounded control render queues**

Use an initial cap of `1 * 1024 * 1024` bytes for control-client render backlog. When a control client is over cap, clear stale queued render frames and queue a fresh `.ViewportSnapshot`. Do not apply this policy to direct terminal clients.

- [ ] **Step 4: Run zmx tests and verify GREEN**

Run:

```bash
cd /Users/thinh/.config/superpowers/worktrees/zmx/option-b-control
zig fmt src/main.zig src/util.zig src/ipc.zig
zig build test
```

Expected: pass.

---

## Task 4: Portl consumes zmx semantic frames

**Files:**
- Modify: `/Users/thinh/.config/superpowers/worktrees/portl/option-b-session-control/crates/portl-agent/src/session_handler/mod.rs`
- Modify: `/Users/thinh/.config/superpowers/worktrees/portl/option-b-session-control/crates/portl-agent/tests/session_e2e.rs`

- [ ] **Step 1: Write failing Portl tests for zmx semantic frames**

Update the fake zmx control helper to emit:

```text
tag 14: viewport:dev\n
tag 15: live:dev\n
```

Assert `open_session_attach()` stdout is `viewport:dev\nlive:dev\n` and legacy tag `1` remains accepted.

- [ ] **Step 2: Run Portl test and verify RED**

Run:

```bash
cd /Users/thinh/.config/superpowers/worktrees/portl/option-b-session-control
cargo test -p portl-agent --test session_e2e session_attach_prefers_zmx_control_when_probe_succeeds
```

Expected: fail because Portl currently forwards only zmx control tag `1`.

- [ ] **Step 3: Implement zmx semantic tag decoding**

Add local constants for zmx control tags:

```rust
const ZMX_TAG_OUTPUT: u8 = 1;
const ZMX_TAG_VIEWPORT_SNAPSHOT: u8 = 14;
const ZMX_TAG_LIVE_OUTPUT: u8 = 15;
```

Forward all three to stdout. Ignore history chunk/end for attach until Portl has an interactive scrollback UI.

- [ ] **Step 4: Run Portl tests and verify GREEN**

Run:

```bash
cd /Users/thinh/.config/superpowers/worktrees/portl/option-b-session-control
cargo fmt --all
cargo test -p portl-agent --test session_e2e session_attach_prefers_zmx_control_when_probe_succeeds
```

Expected: pass.

---

## Task 5: Commit and push zmx Option B

**Files:** zmx worktree only.

- [ ] **Step 1: Verify zmx before commit**

Run:

```bash
cd /Users/thinh/.config/superpowers/worktrees/zmx/option-b-control
zig fmt --check src/ipc.zig src/util.zig src/main.zig
zig build test
zig build
bats test/session.bats --filter 'control:'
git status --short
```

- [ ] **Step 2: Commit zmx changes**

Commit subject:

```text
Add semantic control frames
```

- [ ] **Step 3: Push zmx branch**

Run:

```bash
git push -u kkl option-b-control
```

---

## Task 6: tmux B1+B2 Portl support

**Files:**
- Modify: `/Users/thinh/.config/superpowers/worktrees/portl/option-b-session-control/crates/portl-agent/src/session_handler/tmux_control.rs`
- Modify: `/Users/thinh/.config/superpowers/worktrees/portl/option-b-session-control/crates/portl-agent/src/session_handler/provider.rs`
- Modify: `/Users/thinh/.config/superpowers/worktrees/portl/option-b-session-control/crates/portl-agent/tests/session_e2e.rs`

- [ ] **Step 1: Write failing tmux tests for viewport before live output**

Extend fake tmux to emit a capture-pane result and `%output`. Assert attach stdout starts with the captured viewport before later live output.

- [ ] **Step 2: Run tmux test and verify RED**

Run:

```bash
cd /Users/thinh/.config/superpowers/worktrees/portl/option-b-session-control
cargo test -p portl-agent --test session_e2e session_tmux_provider_attaches_with_control_mode
```

Expected: fail because current tmux adapter forwards only `%output`.

- [ ] **Step 3: Implement tmux B1 viewport-first attach**

Before pumping `%output`, capture the selected pane visible region using `capture-pane -p -e -S 0 -E -1 -t <session>` or the smallest stable equivalent in tests, enqueue it to stdout, then stream `%output`.

- [ ] **Step 4: Implement tmux B2 coalescing**

When tmux output queue backlog exceeds the render cap, pause/drop stale `%output` for that Portl client and enqueue a fresh capture-pane viewport snapshot. Keep input/resize commands serviced before output in the `tokio::select!` loop.

- [ ] **Step 5: Run Portl tmux tests and verify GREEN**

Run:

```bash
cd /Users/thinh/.config/superpowers/worktrees/portl/option-b-session-control
cargo fmt --all
cargo test -p portl-agent --test session_e2e session_tmux_provider_attaches_with_control_mode
```

Expected: pass.

---

## Task 7: OrbStack Docker validation

**Files:**
- Create or modify scratch validation scripts only under `/Users/thinh/.config/superpowers/worktrees/portl/option-b-session-control/scratch/` if needed.

- [ ] **Step 1: Build local binaries**

Run:

```bash
cd /Users/thinh/.config/superpowers/worktrees/zmx/option-b-control
zig build -Doptimize=ReleaseSafe
cd /Users/thinh/.config/superpowers/worktrees/portl/option-b-session-control
cargo build --workspace
```

- [ ] **Step 2: Validate in OrbStack Docker containers**

Use OrbStack-backed Docker to run Linux container smoke checks for provider discovery, zmx control probe, attach viewport-first behavior, and tmux attach viewport-first behavior. Keep scripts under `scratch/` if a repeatable harness is needed.

- [ ] **Step 3: Run full focused local verification**

Run:

```bash
cd /Users/thinh/.config/superpowers/worktrees/portl/option-b-session-control
cargo test -p portl-agent --test session_e2e session_
cargo test -p portl-cli
cargo test -p portl-core
cargo clippy -p portl-agent -p portl-cli -p portl-core --all-targets -- -D warnings
```

Expected: pass.

---

## Task 8: Portl minor release

**Files:**
- Modify through release tasks: Portl manifests, README, CHANGELOG, release metadata.

- [ ] **Step 1: Use portl-release workflow**

Inspect state, choose next minor version from current `v0.6.8`, prepare a user-facing changelog, and run release prep.

- [ ] **Step 2: Verify release locally**

Run:

```bash
cd /Users/thinh/.config/superpowers/worktrees/portl/option-b-session-control
mise run release:verify -- VERSION --local
```

- [ ] **Step 3: Commit and push Portl release branch/main as appropriate**

Follow the release skill exactly for commit, push, CI watch, tag, and release watch.

- [ ] **Step 4: Signal loop success**

Only after zmx branch is pushed, Portl release is tagged/published or the release workflow completes according to `portl-release`, and all verification evidence is fresh, call `signal_loop_success`.

---

## Self-Review

- Spec coverage: zmx B1/B2, Portl zmx consumption, tmux B1/B2, Docker validation, release workflow are covered.
- Placeholder scan: No TBD/TODO placeholders remain; Docker validation is intentionally described as a repeatable smoke task because the exact container image depends on local OrbStack availability.
- Type consistency: zmx tag names and Portl constants use the same numeric mapping. tmux work remains Portl-only because tmux is external.
