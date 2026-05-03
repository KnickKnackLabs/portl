# 230 — Native Session Provider and Terminal Engine

> Status: **proposed follow-on**. This spec extends the session-control
> direction in `210-session-control-lanes.md` with a Portl-owned native
> persistent-session provider. The native provider should prove the
> viewport-first, priority-input, and latest-screen coalescing UX without
> depending on zmx or tmux as the session authority.

## 1. Summary

Portl currently relies on external terminal-session providers:

- zmx for the optimized one-session/one-surface path,
- tmux `-CC` for compatibility control mode,
- raw PTY shell for one-shot non-persistent sessions.

Those providers are useful, but they force Portl's best interactive UX
to depend on provider-specific control protocols. A native provider lets
Portl own the session manager, terminal model, lane scheduler, and
backpressure policy directly:

```text
PTY child process
  -> native Portl session provider
    -> pinned Rust terminal engine
      -> ViewportSnapshot / LiveOutput / HistoryChunk
        -> priority-aware Portl session lanes
          -> CLI, TUI, or agent consumer
```

The native provider should not be just a Rust PTY wrapper. A PTY wrapper
can spawn a shell and replay bytes, but it cannot know the active
viewport, cursor, scrollback, alternate screen, or latest visible state.
The native provider therefore needs a real VT terminal engine. The first
implementation should use a small `portl-vt` crate that pins and wraps a
specific terminal-engine dependency. Based on current inspection,
`alacritty_terminal` is the preferred first engine because it is much
lighter and more embeddable than WezTerm's full terminal core. WezTerm
remains a valuable future comparison for higher-fidelity features.

## 2. Relationship to existing specs

- `200-persistent-sessions.md` defines the provider-backed persistent
  session baseline.
- `210-session-control-lanes.md` defines the provider-neutral event model,
  priority classes, zmx-control, and tmux `-CC` direction.
- `220-local-first-session-sharing.md` defines the workspace/share UX that
  can sit above any provider.
- This spec defines a **native provider implementation strategy** for the
  control semantics from spec 210. It does not replace zmx or tmux; it
  adds a Portl-owned provider that can become the preferred local-first
  provider once proven.

This is a deliberate pivot from spec 200's early non-goal of maintaining
a virtual terminal emulator in Portl. That non-goal was correct for the
v0.4.0 external-provider baseline. The Option B UX from spec 210 now
requires provider-owned terminal state: viewport-first attach and
latest-screen coalescing cannot be implemented with PTY bytes alone.
Rather than writing a bespoke emulator, Portl should wrap a pinned
terminal-engine crate behind `portl-vt` and keep zmx/tmux as fallback
providers. `libghostty-vt` remains proven by zmx, but Rust-native
integration starts with Alacritty to avoid Zig FFI and release-packaging
complexity.

In the workspace model from spec 220, native sessions are a local provider
binding. A local workspace can bind to `native` first, then later be
shared through the same session-share/ticket flow as zmx or tmux-backed
sessions.

## 3. Motivation

The current zmx-control and tmux `-CC` integrations expose useful control
paths, but both still have limits:

- zmx uses `ghostty-vt` internally and can become viewport-first, but Portl
  must wait for zmx protocol features to expose distinct viewport, live,
  and history lanes.
- tmux can approximate viewport-first behavior with `capture-pane` and
  `%output`, but its semantics are tmux-shaped and less faithful for some
  terminal state.
- local Portl sessions currently shell out to `zmx attach`, bypassing
  Portl's optimized lanes.
- large output floods can still make a normal stdout-attached terminal
  appear stuck, even if input transport is technically separate.

A native provider lets Portl implement the intended UX directly:

1. show the current viewport before scrollback/history,
2. keep input, resize, and cancel ahead of render/bulk work,
3. coalesce live render output under flood to fresh viewport snapshots,
4. keep full history available through explicit history APIs,
5. bound per-session and per-client memory without depending on a third
   party provider's queue policy.

## 4. Goals

1. **Portl-owned persistent sessions.** Create, attach, detach, list,
   run-on-create, history, resize, cancel, and kill without zmx/tmux.
2. **Real terminal-state model.** Track a VT grid, scrollback, cursor,
   modes, alternate screen, and dirty/sequence state using a pinned engine.
3. **Viewport-first attach.** A reconnecting client sees the active
   visible terminal before any history backfill.
4. **Priority interactivity.** Input, Ctrl-C/cancel, detach, and resize
   must not wait behind history or large render queues.
5. **Latest-screen coalescing.** During live output floods, clients may
   receive fresh viewport snapshots instead of every intermediate byte.
6. **Explicit history access.** Full scrollback and raw transcript data are
   available through history/chunk APIs, not forced into the live terminal
   stdout stream.
7. **Small first engine surface.** Hide terminal-engine details behind a
   Portl trait so Alacritty, WezTerm, or another engine can be swapped or
   compared later.
8. **Reproducible dependency management.** Pin the engine version or git
   revision inside `portl-vt`; avoid leaking engine APIs through Portl's
   public session provider.
9. **Keep zmx/tmux fallback.** Existing external providers remain supported
   and useful, especially while native provider durability is maturing.

## 5. Non-goals

- Perfect terminal fidelity in the first native slice.
- Building a GUI terminal emulator.
- Making native sessions survive all agent restarts in the first slice.
- Replacing zmx or tmux immediately.
- Transparent background insertion into a user's local terminal scrollback.
  Ordinary terminals do not provide a portable API for appending history to
  scrollback without affecting the visible stream.
- Preserving byte-for-byte live rendering during output floods while also
  guaranteeing immediate latest-viewport rendering. Interactive mode should
  prefer responsiveness; lossless output belongs in history/transcript APIs
  or an explicit lossless mode.

## 6. Terminology

This spec uses three related but distinct output products:

- **Live output** is the current attach render stream for an attached
  client. In interactive mode it may be coalesced under flood.
- **History** is terminal scrollback or rendered history derived from the
  terminal engine's grid. It is rangeable and can be chunked.
- **Raw transcript** is the original PTY byte stream. It is useful for
  debugging/export, but it is not the same as terminal scrollback.

Interactive attach is not an automatic lossless replay of all historical
PTY bytes. It prioritizes current viewport correctness and input
responsiveness. Portl can deliver input to the PTY promptly, but it cannot
force a foreground program to read that input or visibly respond.

## 7. Terminal engine decision

### 7.1 Engine abstraction

Introduce an internal crate such as `crates/portl-vt`:

```rust
pub trait TerminalEngine {
    fn advance_bytes(&mut self, bytes: &[u8]);
    fn resize(&mut self, rows: u16, cols: u16);

    fn current_seq(&self) -> u64;
    fn is_alt_screen(&self) -> bool;

    fn viewport_snapshot(&self) -> ViewportSnapshot;
    fn history_chunk(&self, request: HistoryRequest) -> HistoryChunk;
}
```

The native provider depends on `portl-vt`, not on the underlying engine.
Engine-specific types stay private to the adapter.

### 7.2 Alacritty first

Use `alacritty_terminal` first, pinned exactly or to a specific git
revision:

```toml
alacritty_terminal = { version = "=0.26.0", default-features = false }
```

If a crates.io release is unsuitable, use a git revision:

```toml
alacritty_terminal = {
  git = "https://github.com/alacritty/alacritty",
  rev = "<sha>",
  package = "alacritty_terminal",
  default-features = false,
}
```

Rationale:

- it is explicitly packaged as a terminal-emulator library,
- it provides `Term`, grid, scrollback, alternate screen, cursor, modes,
  damage tracking, and parser integration,
- it is relatively lightweight for Portl's release and cross-build story,
- it avoids Zig FFI and a large workspace dependency stack.

Current source inspection suggests roughly 28 unique normal dependencies
with default features disabled and roughly 39 with defaults, far smaller
than WezTerm's full terminal core.

Alacritty's crate is still an internal-ish project surface rather than a
formal long-term embedders API. Phase 1 must validate the exact crates.io
version or git revision, record the selected pin, and keep a git-revision
fallback if the crates.io release shape does not expose the needed APIs.

### 7.3 WezTerm as a future comparison

WezTerm's relevant engine is `wezterm-term`, not `termwiz` alone.
`termwiz` provides surfaces, changes, rendering helpers, input helpers,
and parsing pieces; `wezterm-term` is the full VT model with
`Terminal::advance_bytes`.

WezTerm is attractive for high fidelity:

- rich terminal attributes,
- images/sixel/iTerm2 image support,
- OSC 8 hyperlinks,
- bidi support,
- stable row indexes and dirty-row tracking.

It is not the first choice because its dependency graph is much larger
and more coupled to WezTerm workspace crates. Current source inspection
suggests the full `wezterm-term` tree is an order of magnitude larger
than `alacritty_terminal`. Keep the `TerminalEngine` trait narrow enough
to allow a later `WezTermEngine` experiment without rewriting the native
provider.

## 8. Native provider architecture

### 8.1 Components

```text
portl-agent
  SessionProvider::Native
    NativeSessionRegistry
      NativeSession
        PTY child/process group
        TerminalEngine
        optional raw transcript ring/log
        per-session event sequence
        attached NativeClient records
        resource limits and audit hooks
```

`NativeSession` owns the PTY and terminal model. Attached clients are
views onto that model with independent scheduling/backpressure state.

### 8.2 First process model

The first slice may run native sessions inside `portl-agent`.

Pros:

- smallest implementation,
- reuses existing Portl PTY code,
- simplest deployment and testing,
- enough to prove Option B UX.

Cons:

- sessions may not survive agent restart or upgrade,
- a provider bug shares failure domain with the agent.

For the in-agent slice, native sessions are explicitly lost on agent
restart. The provider must use a process group for each PTY child and
must attempt clean teardown on normal agent shutdown: detach/close PTY,
send SIGHUP or SIGTERM, then SIGKILL after a bounded grace period. If the
agent crashes, the expected behavior is that PTY closure ends the child;
any orphan-risk findings from testing must be fixed before native becomes
the default local provider.

A later slice may split the provider into a local `portl-sessiond` that
owns PTYs and terminal models while `portl-agent` handles tickets and
remote transport. Splitting is required before native sessions become the
default local-first provider if restart/upgrade durability is a release
goal.

### 8.3 Existing code reuse

Reuse or adapt existing Portl primitives:

- PTY spawn/resize/read/write from `shell_handler::spawn` and
  `shell_handler::pty_master`,
- process-group signaling from shell shutdown helpers,
- target environment/cwd handling from `TargetProcessContext`,
- audit start/exit events,
- session caps enforcement and ticket authorization.

The native provider should not use `zmx attach` or `tmux -CC` internally.

### 8.4 Engine ownership

Each `NativeSession` should own its terminal engine in one actor/task.
PTY reads, client commands, history requests, and snapshot timers enter
that task through bounded channels. The task advances the engine, creates
snapshots/chunks, then hands owned payloads to per-client queues. It must
not hold an engine mutex while awaiting network writes or slow client
queues.

This actor model avoids data races between `advance_bytes` and
`viewport_snapshot`, keeps network backpressure from stalling PTY reads,
and gives one place to enforce queue bounds and coalescing transitions.

## 9. Session-control semantics

### 9.1 Events

The native provider emits the same conceptual events as spec 210. For the
first slice, a native session has one selected surface. The adapter should
synthesize a stable `SurfaceId(0)` and emit or map:

```rust
enum NativeSessionEvent {
    ProviderReady { generation: u64 },
    SurfaceCreated { surface_id: SurfaceId, rows: u16, cols: u16 },
    SurfaceResized { surface_id: SurfaceId, rows: u16, cols: u16 },
    SurfaceClosed { surface_id: SurfaceId },
    ViewportSnapshot(ViewportSnapshot),
    LiveOutput(LiveOutput),
    HistoryChunk(HistoryChunk),
    ProviderError(ProviderError),
}
```

`generation` increments when a native session is killed/recreated or when
provider state is lost. Clients with stale generation data must request a
fresh viewport snapshot rather than attempting resume.

`ViewportSnapshot` is a rendering of the active visible terminal. It is
not the entire scrollback. It carries an explicit encoding, initially VT
bytes for CLI attach and optionally structured cells for future UI clients.

`LiveOutput` may carry raw bytes while the client is keeping up, but the
provider is allowed to stop sending every live byte to a slow/flooded
interactive client and replace stale output with a fresh viewport
snapshot.

`HistoryChunk` is demand-driven or idle-priority bulk data. It must not
block input, cancel, resize, or fresh viewport snapshots. By default it
carries rendered terminal scrollback/history, not raw PTY transcript
bytes. Raw transcript export, if implemented, is a separate format or API
mode with its own authorization and byte limits.

### 9.2 Attach ordering

An attach must begin with current state, not history replay:

1. `ProviderReady` with session generation,
2. `SurfaceCreated` or current surface metadata,
3. initial `ViewportSnapshot`,
4. then `LiveOutput` and subsequent snapshots,
5. optional `HistoryChunk` only after the initial viewport and only on
   request or idle/backfill policy.

No history chunk and no queued live-render event may overtake the initial
viewport snapshot for a newly attached client.

### 9.3 Commands

The provider accepts:

```rust
enum NativeSessionCommand {
    Input(Vec<u8>),
    Paste(Vec<u8>),
    Cancel(CancelKind),
    Resize { rows: u16, cols: u16 },
    RequestViewport,
    RequestHistory(HistoryRequest),
    Detach,
    Kill,
}
```

The first cancel implementation may inject Ctrl-C (`0x03`) into the PTY.
If process-group SIGINT is supported for native sessions, advertise it as
an explicit feature such as `native_cancel.v1`.

### 9.4 Resize arbitration

Only one attached client controls PTY size at a time. The first native
slice should use a simple driver policy:

- the active driver controls resize,
- observers do not resize the PTY,
- if no driver exists, the first interactive attach becomes driver,
- driver handoff happens only after explicit input/role promotion,
- resize events are coalesced to the latest driver size.

This mirrors spec 210's driver/observer direction and avoids
last-writer-wins resize fights between multiple terminals.

## 10. Output and coalescing policy

### 10.1 Normal streaming

When the client is keeping up, stream live PTY bytes or minimal render
updates normally. The terminal engine is updated with every PTY output
chunk regardless of what is sent to the client.

### 10.2 Flood mode

When a client's render queue exceeds configured thresholds, switch that
client into coalesced latest-screen mode:

1. continue reading PTY output,
2. continue advancing the terminal engine,
3. stop queuing all intermediate live output to that client,
4. periodically send the latest `ViewportSnapshot`,
5. keep input, cancel, resize, and detach on critical paths,
6. resume normal streaming after a quiet period and low backlog.

Client-visible contract:

- a coalesced client may miss intermediate `LiveOutput`,
- a newer `ViewportSnapshot` supersedes older queued render output,
- leaving flood mode does not require replaying dropped live bytes,
- full output remains available only through explicit history/transcript
  APIs and configured retention.

This is the intended behavior for cases such as:

```bash
cat huge-100mb-file
```

In interactive mode, Portl should prefer a fresh bottom-most viewport over
lossless live rendering. The full output can remain available through raw
transcript/history APIs. If a user explicitly wants byte-for-byte live
rendering into their local terminal scrollback, they should choose a
lossless mode that may sacrifice responsiveness.

### 10.3 Application caveat

Portl can prioritize delivery of `abc` to the PTY during a flood, but it
cannot force the foreground application to read that input or render it.
If `cat` is the foreground process, it may ignore stdin until it exits or
is interrupted. For shells, editors, REPLs, and TUIs with an active input
area, priority input plus fresh viewport snapshots should produce the
desired UX.

## 11. Snapshot and history rendering

### 11.1 Viewport snapshots

The first Alacritty-backed adapter should render viewport snapshots from
terminal cells to VT bytes for the user's local terminal:

1. reset or normalize attributes,
2. clear visible screen,
3. draw visible cells with SGR styling,
4. restore cursor position and visibility,
5. restore relevant terminal modes when safe.

This serializer is Portl-owned. It should be tested against real terminal
traces and kept separate from the engine adapter so future engines can
reuse it where practical.

The serializer is also a security boundary. It must suppress or
conservatively handle host-integration sequences that should not be
replayed blindly into a client terminal, including OSC 52 clipboard
operations, downloads, unsafe hyperlinks/actions, terminal image payloads,
focus/mouse modes when inappropriate, and transient synchronized-output
state. If a sequence is needed for correct rendering, document and test
why it is safe to emit.

Snapshot VT output should minimize bloat by emitting SGR changes only
when cell attributes change, not by resetting styling per cell.

### 11.2 History chunks

History chunks should support at least:

- plain text for `portl session history`,
- styled VT or structured cell data for future UI clients,
- bounded byte/row ranges,
- cancellation and per-client limits.

The first interactive CLI attach should not automatically dump all
history into stdout. History backfill may be opt-in, idle-only, or future
UI-driven.

### 11.3 Raw transcript

Terminal scrollback and raw transcript are different data products.
Terminal scrollback is the engine's visible/logical grid history. A raw
transcript is the original PTY byte stream. The native provider may keep a
bounded raw transcript ring or file for debugging/export, but interactive
rendering should be driven by terminal state.

## 12. Provider discovery and features

Add a native provider report when enabled:

```json
{
  "name": "native",
  "available": true,
  "tier": "native",
  "features": [
    "viewport_snapshot.v1",
    "live_output.v1",
    "history_chunks.v1",
    "priority_input.v1",
    "slow_client_coalesce.v1",
    "adapter_sequence.v1"
  ]
}
```

Initial capabilities:

- persistent: true,
- multi_attach: true,
- create_on_attach: true,
- attach_command: true,
- run: optional in first slice,
- history: true,
- terminal_state_restore: true,
- external_direct_attach: false.

Provider selection remains explicit or default-driven. zmx and tmux stay
available fallbacks.

## 13. Resource limits and safety

The native provider must bound resources from the first slice:

- max sessions,
- max clients per session,
- max scrollback rows or bytes per session,
- max raw transcript bytes if transcript logging is enabled,
- max per-client render queue bytes,
- max history request bytes/chunks,
- idle session timeout if configured,
- kill/cleanup behavior on provider or PTY failure.

Slow clients are normal. A slow observer must not degrade an active
driver. The provider should drop/coalesce stale render data for that
client rather than allowing unbounded queue growth.

## 14. Security and authorization

Portl tickets remain the authorization layer. Native sessions should obey
existing shell/session caps and later role-specific caps:

- attach/read-only/input/cancel/history/kill,
- provider allowlist,
- session allowlist,
- max history bytes,
- max attach duration.

The native provider should run target processes with the same environment,
cwd, and user-switch rules as the existing shell/session paths. Provider
state should not persist sensitive ticket material.

Native provider state should live under the same Portl state conventions
as other session work. If an environment override is exposed, prefer the
existing future-facing name from spec 200, `PORTL_SESSION_DIR`, for native
session state, transcript rings, and crash-recovery metadata.

Clipboard, OSC 52, downloads, hyperlinks, terminal images, and other
host-integration features should default to conservative behavior. If the
engine can parse them, Portl still decides whether to honor, ignore,
audit, or expose them to clients.

## 15. Build and dependency management

The terminal engine dependency should be isolated in `portl-vt`.

Benefits:

- provider code does not depend on engine internals,
- engine upgrades happen in one crate,
- exact pins make behavior reproducible,
- incremental builds avoid rebuilding the engine when only provider logic
  changes,
- feature flags can keep native provider builds optional while the feature
  is experimental.

Suggested feature shape:

```toml
[features]
native-session-provider = ["dep:portl-vt"]

[dependencies]
portl-vt = { path = "../portl-vt", optional = true }
```

Clean release builds still compile the engine. Choosing Alacritty keeps
that first-time cost and dependency surface small compared with WezTerm.

## 16. Phased rollout

### Phase 1 — engine wrapper prototype

- Add `portl-vt` behind a feature flag.
- Pin `alacritty_terminal` with default features disabled.
- Feed recorded PTY traces into the engine.
- Extract visible cells, cursor, alt-screen state, and plain history.
- Build a minimal viewport-to-VT serializer.

### Phase 2 — in-agent native provider

- Add `native` provider discovery.
- Create/list/attach/kill native sessions inside `portl-agent`.
- Reuse existing PTY spawn/resize/input/cancel plumbing.
- Attach viewport-first.
- Keep zmx/tmux fallback unchanged.

### Phase 3 — coalescing scheduler

- Add per-client critical/render/bulk queues.
- Implement render queue thresholds.
- Switch flooded clients to latest-screen snapshots.
- Keep history chunks demand-driven and cancellable.
- Add telemetry for queue drops, coalescing, snapshot rate, and input
  latency.

### Phase 4 — durability and UX hardening

- Decide whether to split a `portl-sessiond` process.
- Add restart/upgrade behavior.
- Add local-first defaults if native provider proves stable.
- Add lossless attach/history/export modes.
- Compare Alacritty against WezTerm for fidelity gaps.

## 17. Testing and benchmarks

Required test categories:

1. **Trace replay tests.** Feed known PTY traces into `portl-vt` and assert
   viewport text/cursor/alt-screen outcomes.
2. **Snapshot rendering tests.** Serialize viewport snapshots and replay
   them into a terminal model to verify visible equivalence.
3. **History tests.** Validate plain and styled history chunks, bounds, and
   cancellation.
4. **Flood tests.** Run `cat`/synthetic 100MB output and verify queue bounds,
   coalescing, and latest viewport freshness.
5. **Interactive latency tests.** During output backfill/flood, measure p95
   input forwarding and first visible response when the foreground app reads
   input.
6. **Compatibility smoke tests.** Shell prompt, vim/nvim, less, htop/top,
   common REPLs, and Pi-agent sessions.
7. **Resource tests.** Enforce max sessions, max clients, max history, and
   slow-client queue caps.

The first performance target should be modest and measurable, for example:

- viewport snapshot visible before history on attach,
- no unbounded queue growth under 100MB output,
- p95 input forwarding under flood within one RTT plus small processing
  budget when the PTY is writable,
- active client remains responsive while a slow observer is coalesced.

## 18. Acceptance criteria

The first native provider slice is accepted when:

1. `portl session providers` can report a `native` provider with honest
   feature flags.
2. A native session can be created, attached, detached, reattached, listed,
   and killed.
3. Reattach renders the active viewport before history.
4. Input, Ctrl-C/cancel, and resize are not queued behind history work.
5. A large output flood does not create unbounded per-client queues.
6. Under flood, interactive attach can coalesce to latest viewport snapshots.
7. Full history remains available through explicit history APIs.
8. zmx and tmux providers continue to work unchanged.
9. Native provider can be disabled at compile time or runtime while
   experimental.
10. The engine dependency is isolated behind `portl-vt` and pinned.
11. The selected Alacritty crate version or git revision is validated and
+    recorded, including a fallback if crates.io packaging is unsuitable.
12. Multi-attach resize arbitration follows the driver policy.
13. Snapshot serialization filters unsafe host-integration sequences.

## 19. Open questions

1. Should the first native provider be enabled by default for local-only
   sessions, or remain opt-in until durability is proven?
2. What is the minimum styled snapshot format for the CLI: VT bytes, cell
   records, or both?
3. Should raw transcript logging be on by default, off by default, or only
   available for explicit recording sessions?
4. How much history should interactive attach fetch automatically, if any?
5. What coalescing thresholds produce the best UX for Pi-agent sessions?
6. When should `portl-sessiond` replace in-agent session ownership?
7. Which terminal features should Portl intentionally ignore for security,
   even if the engine parses them?
8. What fidelity gaps would justify a WezTerm-backed engine experiment?
