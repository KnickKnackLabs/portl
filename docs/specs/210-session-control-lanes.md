# 210 — Remote Session Control, Provider Tiers, and Iroh Lanes

> Status: **draft**. This is follow-on design work for the persistent
> session foundation shipped in v0.4.0 and specified in
> `200-persistent-sessions.md`. That foundation adds `portl session`,
> `portl/session/v1`, provider discovery, and the initial zmx CLI
> bridge. This spec describes the next layer: viewport-aware session
> control, provider capability tiers, and an iroh-native lane scheduler
> for responsive remote terminal sharing.

## 1. Summary

Persistent sessions make remote terminal workspaces reconnectable. The
next problem is making them feel responsive over real networks, while
supporting richer sharing and provider-native terminal state.

The central idea is:

```text
provider-native session state
  -> Portl session-control events
    -> prioritized iroh/QUIC lanes
      -> local terminal / UI / agent consumer
```

Portl should own a provider-neutral session-control model instead of
shaping the product around any one provider's protocol. Providers map
their native concepts into Portl concepts:

| Provider | Native shape | Portl mapping |
| --- | --- | --- |
| zmx control | one persistent PTY with ghostty-vt state | one session, one surface |
| tmux `-CC` | sessions/windows/panes/control events | panes become surfaces |
| Zellij | sessions/tabs/panes/render subscriptions | panes become surfaces |
| native | Portl-owned session manager | direct implementation |

The first optimized provider should be a zmx control-mode fork or
branch, because zmx already keeps terminal state with `ghostty-vt` and
has the simplest one-session/one-surface model. The first compatibility
provider should be tmux `-CC`, because it is the most mature existing
external control protocol. Zellij is promising for rich workspace
support but should remain experimental until its external/headless API
is stable enough. Kitty is valuable protocol and UX inspiration, but it
is not a good persistent-session provider today.

## 2. Motivation

Raw remote terminal streams couple unrelated work together:

- user input and cancellation can wait behind bulk output,
- resize events can be delayed by scrollback transfer,
- reconnects can replay history before the current screen appears,
- slow observers can degrade the active user's experience,
- clients cannot resume from a known terminal-state sequence,
- providers expose different primitives and failure modes.

SSH multiplexing and terminal multiplexers improve parts of this, but a
single ordered TCP transport still has head-of-line behavior under
packet loss, and most terminal providers expose a byte stream rather
than a prioritized state-synchronization model.

portl already uses iroh/QUIC. That lets us design the session layer as
multiple semantic lanes, with application-level scheduling on top:

1. accept user input, cancel, and resize first,
2. show the active viewport as soon as possible,
3. stream live output without waiting for scrollback,
4. backfill history in low-priority chunks,
5. adapt to direct vs relayed paths, RTT, loss, and slow clients.

## 3. Goals

1. **Own the Portl session-control model.** Avoid leaking tmux, zmx,
   or Zellij-specific terminology into the wire model where a generic
   concept is enough.
2. **Make attach viewport-first.** A reconnecting user should see the
   active screen before scrollback/history backfill.
3. **Separate interactivity from bulk transfer.** Input, cancellation,
   resize, and control messages must not wait behind history or large
   snapshots.
4. **Support provider tiers honestly.** Providers differ. Discovery and
   errors should report whether a provider is a PTY bridge, a control
   provider, or scheduler-native.
5. **Use iroh deliberately.** QUIC streams and datagrams should support
   semantic lanes, not just tunnel an SSH-like byte stream.
6. **Keep direct provider use working.** `zmx attach`, `tmux attach`,
   and `zellij attach` remain useful outside portl.
7. **Enable sharing roles.** The model should support active drivers,
   read-only observers, agent consumers, and future collaborative
   features.
8. **Preserve provider fallback.** Optimized control providers should
   gracefully fall back to the v0.4.0 CLI bridge when unavailable.

## 4. Non-goals

- Replacing the v0.4.0 `portl session` CLI surface.
- Making zmx pretend to speak tmux `-CC`.
- Requiring tmux, Zellij, or Kitty for the optimized zmx path.
- Building a native Portl terminal emulator in the first follow-on
  phase.
- Guaranteeing identical terminal semantics across providers.
- Using QUIC datagrams for authoritative terminal output, input, or
  cancellation.
- Rewriting provider internals in the first spec slice.

## 5. Baseline from spec 200 / v0.4.0

`200-persistent-sessions.md` establishes the baseline:

- `portl session` command group,
- `portl/session/v1` protocol,
- provider discovery,
- zmx as the first persistent provider,
- CLI bridge mapping to `zmx attach`, `zmx run`, `zmx history`, etc.,
- Docker/Slicer provisioning hooks,
- persistent-session vocabulary in user-facing errors.

That baseline remains valid and should stay as the fallback path. This
spec does not remove the v0.4.0 zmx CLI bridge. It defines what an
optimized provider can expose above that bridge.

## 6. Portl session-control model

The model is provider-neutral and surface-oriented.

### 6.1 Session

A session is a named persistent workspace on a target. The provider owns
the target-side lifetime; portl owns remote authorization, transport,
and client-side presentation.

Conceptual fields:

```rust
struct SessionRef {
    provider: String,
    session_name: String,
    generation: Option<u64>,
}
```

`generation` is optional provider state used to detect stale client
caches after a provider restart, kill/recreate, or incompatible upgrade.

### 6.2 Surface

A surface is a renderable terminal surface within a session.

Examples:

- zmx: the session's single PTY surface,
- tmux: a pane,
- Zellij: a pane,
- native: a Portl-managed PTY surface.

Use `surface_id` rather than `pane_id` in Portl APIs:

```rust
struct SurfaceRef {
    session: SessionRef,
    surface_id: String,
    title: Option<String>,
    rows: u16,
    cols: u16,
}
```

### 6.3 Events

Provider adapters emit events into a common model:

```rust
enum SessionEvent {
    ProviderReady(ProviderReady),
    SurfaceCreated(SurfaceRef),
    SurfaceClosed(SurfaceRef),
    SurfaceFocused(SurfaceRef),
    ViewportSnapshot(ViewportSnapshot),
    LiveOutput(LiveOutput),
    HistoryChunk(HistoryChunk),
    FlowControl(FlowControlEvent),
    ProviderError(ProviderError),
}
```

Important payloads:

```rust
struct ViewportSnapshot {
    surface: SurfaceRef,
    seq: Option<u64>,
    encoding: TerminalEncoding,
    bytes: Vec<u8>,
}

struct LiveOutput {
    surface: SurfaceRef,
    seq: Option<u64>,
    bytes: Vec<u8>,
}

struct HistoryChunk {
    surface: SurfaceRef,
    request_id: u64,
    index: u64,
    final_chunk: bool,
    encoding: HistoryEncoding,
    bytes: Vec<u8>,
}
```

`seq` is optional because not every provider can produce a reliable
surface sequence initially. Optimized providers should implement it.

### 6.4 Commands

Clients send commands into the same model:

```rust
enum SessionCommand {
    Attach(AttachRequest),
    Input { surface: SurfaceRef, bytes: Vec<u8> },
    Paste { surface: SurfaceRef, bytes: Vec<u8> },
    Cancel { surface: SurfaceRef, kind: CancelKind },
    Resize { surface: SurfaceRef, rows: u16, cols: u16 },
    RequestViewport { surface: SurfaceRef },
    RequestHistory(HistoryRequest),
    Pause { surface: SurfaceRef, lane: LaneKind },
    Resume { surface: SurfaceRef, lane: LaneKind },
    Detach { session: SessionRef },
}
```

`Cancel` should not be modeled only as input byte `0x03`. Providers may
map it to Ctrl-C, SIGINT, a process-group signal, or a provider-native
interrupt, depending on capability and policy.

## 7. Iroh lane scheduler

### 7.1 Lanes

The session transport should be lane-aware even when a provider is not.

Suggested lanes:

| Lane | Direction | Priority | Contents |
| --- | --- | ---: | --- |
| control | both | highest | hello, attach ack, errors, detach, caps |
| input | client → target | highest | keystrokes, paste metadata, priority input |
| cancel | client → target | highest | interrupt, suspend, kill request |
| resize | client → target | highest | latest-wins terminal geometry |
| viewport | target → client | high | active viewport snapshot / refresh |
| live | target → client | normal/high | live output or provider updates |
| history | target → client | low | scrollback/history chunks |
| telemetry | both | low/lossy | RTT hints, presence, typing state, pointer hints |

The implementation may use separate QUIC streams, stream preambles, or
multiple connections for some lanes. The invariant is semantic: urgent
commands are not queued behind bulk data by Portl.

### 7.2 Scheduling policy

Application scheduling is required even with QUIC. Streams share
congestion control and local socket buffers. Portl should therefore:

- always service input/cancel/resize before history,
- coalesce resize to the latest value,
- send viewport snapshots before history backfill,
- pause history when live output or input is active,
- bound per-lane queues,
- drop/coalesce stale viewport updates for slow observers,
- use credit-based transfer for history,
- avoid writing large history bursts into QUIC faster than the client
  can consume them.

### 7.3 Datagrams

iroh/QUIC datagrams are useful for lossy/latest-wins hints, not
authoritative terminal state.

Good datagram candidates:

- path/RTT telemetry,
- typing or presence hints,
- pointer/hover locations for collaborative sessions,
- speculative resize hints,
- "new viewport available" invalidations.

Do not use datagrams for:

- keystrokes,
- cancellation,
- live terminal output,
- history chunks,
- final resize authority.

### 7.4 Bulk isolation

If history, artifacts, or file transfers are large enough to harm
interactive latency, Portl may open a separate iroh connection for bulk
lanes. This is not an MVP requirement; start with app-level scheduling
on one connection and measure.

## 8. Provider tiers

Provider discovery should report a tier and explicit capabilities.

### 8.1 Tier 1 — PTY bridge

The provider exposes attach/detach through a terminal byte stream.

Examples:

- current zmx CLI bridge (`zmx attach`),
- raw one-shot shell,
- basic `tmux attach` or `zellij attach` bridge.

Capabilities:

- persistent attach if provider supports it,
- provider-native detach/reconnect,
- optional history command,
- no structured viewport/live/history separation,
- no provider-level lane scheduling.

Tier 1 remains the compatibility fallback.

### 8.2 Tier 2 — control provider

The provider exposes structured control events and commands.

Examples:

- zmx control mode,
- tmux `-CC`,
- future Zellij headless/control API.

Capabilities:

- surface identity,
- viewport snapshot or capture,
- live output event stream,
- targeted input,
- targeted resize,
- history request,
- provider events/errors,
- optional flow control.

Tier 2 providers are enough to map into Portl's lane scheduler.

### 8.3 Tier 3 — scheduler-native provider

The provider is designed around Portl's session-control semantics.

Examples:

- future native Portl provider,
- advanced `portl-zmx`,
- upstream provider with explicit Portl-compatible session-control.

Capabilities:

- sequence-numbered viewport/live output,
- chunked history with cursors and credits,
- explicit priority input/cancel,
- slow-client coalescing,
- latest-snapshot recovery,
- multi-client roles,
- resumable attach from sequence or generation,
- path-aware scheduling hints.

### 8.4 Provider report shape

Extend provider discovery conceptually:

```json
{
  "name": "zmx",
  "available": true,
  "tier": "control",
  "path": "/usr/local/bin/zmx",
  "capabilities": {
    "persistent": true,
    "multi_attach": true,
    "viewport_snapshot": true,
    "live_output": true,
    "history_chunks": true,
    "priority_input": true,
    "cancel": true,
    "resize": true,
    "sequence_resume": false,
    "direct_human_attach": true
  }
}
```

## 9. zmx-control provider

### 9.1 Role

zmx is the best first optimized provider because it already has:

- one named persistent PTY per session,
- attach/detach and multi-client support,
- a per-session Unix socket,
- `ghostty-vt` terminal state,
- reattach restore,
- history output,
- simple direct human use.

The current v0.4.0 Portl provider shells out to `zmx attach` and sees a
PTY byte stream. A zmx-control provider should instead expose the pieces
zmx already computes as structured events.

### 9.2 Fork/control-mode approach

The practical next step is a small `portl-zmx` branch or fork designed
to be upstreamable. It should add a headless/control command such as:

```bash
zmx control --protocol portl-v1 <session>
```

Portl should treat this process protocol as the supported integration
surface, rather than depending long-term on zmx's current private Unix
socket IPC.

Layering:

```text
portl-agent
  <-> zmx control --protocol portl-v1
    <-> zmx private per-session socket
      <-> zmx daemon / PTY / ghostty-vt
```

### 9.3 Required zmx changes

Additive changes only:

1. split `serializeTerminalState` into reusable helpers:
   - active viewport,
   - scrollback/history,
   - combined legacy restore;
2. add version/capability handshake;
3. add viewport snapshot response;
4. separate live output from restore output;
5. add sequence numbers;
6. add chunked history responses;
7. add explicit cancel / priority input semantics.

Do not change vanilla `zmx attach`, existing tag numbers, socket naming,
or direct provider usability.

### 9.4 zmx-control attach flow

```text
portl-agent -> zmx control: Hello { requested_caps }
zmx control -> portl-agent: HelloAck { accepted_caps, zmx_version }
portl-agent -> zmx control: Attach { session, rows, cols }
zmx control -> portl-agent: ViewportSnapshot { seq, bytes }
zmx control -> portl-agent: LiveOutput { seq, bytes }
```

History is requested separately:

```text
portl-agent -> zmx control: HistoryRequest { request_id, range, format, credit }
zmx control -> portl-agent: HistoryChunk { request_id, index, final, bytes }
```

### 9.5 zmx-control fallback

If `zmx control` is unavailable, Portl falls back to the v0.4.0 zmx CLI
bridge:

```text
zmx found, control protocol unavailable; using PTY bridge
```

## 10. tmux `-CC` provider

### 10.1 Role

tmux `-CC` is the best compatibility control provider. It is mature,
documented, and already designed for external terminal UI clients.

Useful primitives:

- control-mode command/response blocks,
- `%output` / `%extended-output`,
- pane/window/session notifications,
- `capture-pane` for visible and history ranges,
- `refresh-client -C` for size,
- `refresh-client -A` pause/on/off/continue flow control,
- `send-keys` for input and Ctrl-C.

### 10.2 Mapping

| Portl concept | tmux mapping |
| --- | --- |
| Session | tmux session |
| Surface | tmux pane |
| LiveOutput | `%output` / `%extended-output` |
| ViewportSnapshot | `capture-pane` visible range |
| HistoryChunk | `capture-pane` history ranges |
| Input | `send-keys` or control client input |
| Cancel | `send-keys C-c` |
| Resize | `refresh-client -C` |
| FlowControl | `refresh-client -A pause/on/off/continue` |

### 10.3 Caveats

tmux is mature but not Portl-native:

- protocol is tmux-shaped,
- panes/windows/layouts leak into provider behavior,
- terminal output follows tmux/screen semantics,
- viewport-first is assembled through `capture-pane`, not a native
  snapshot event,
- cancel is usually key injection, not an explicit provider interrupt.

Do not make zmx speak tmux `-CC`. Instead, implement a tmux adapter that
maps real tmux control mode into Portl events.

## 11. Zellij provider

Zellij is promising but should be experimental after zmx-control and
tmux `-CC`.

Relevant capabilities:

- real client/server architecture,
- protobuf-framed local IPC,
- sessions/tabs/panes,
- CLI actions for pane input/control,
- read-only watcher clients,
- web sharing,
- pane render subscription:
  - initial viewport,
  - optional initial scrollback,
  - later viewport updates.

Promising mapping:

| Portl concept | Zellij mapping |
| --- | --- |
| Session | Zellij session |
| Surface | Zellij pane |
| ViewportSnapshot | initial `PaneRenderUpdate` viewport |
| LiveOutput | subsequent viewport updates |
| HistoryChunk | initial scrollback / dump-screen / plugin API |
| Input | pane-targeted write/paste/send-keys actions |
| Cancel | Ctrl-C write or internal/plugin SIGINT |

Caveats:

- no stable tmux-like external control protocol,
- updates are whole viewport snapshots, not append/diff streams,
- no sequence/resume model,
- no paginated history cursor,
- no explicit lane-aware flow control,
- direct protobuf IPC is internal-version-coupled.

Recommended path:

1. Prototype read-only support with `zellij subscribe --format json`.
2. Map panes to Portl surfaces.
3. Pursue direct IPC or upstream headless/control API only if Zellij
   becomes strategically important.

## 12. Kitty decision

Kitty is not a primary session provider for this work.

Kitty is a terminal emulator with a strong remote-control API, not a
detached PTY/session server. It can list windows, fetch screen text,
fetch scrollback, inject text, signal child processes, and expose a
secure control socket. It does not expose persistent attach/detach,
multi-client terminal sharing, live output subscriptions, history
cursors, or provider-level sequence/resume.

Use Kitty as inspiration for:

- socket/env discovery (`KITTY_LISTEN_ON`-style UX),
- command envelopes,
- async request ids and cancellation,
- streaming upload/download ids,
- authz and remote-control passwords,
- shell-integration-aware command output ranges,
- graphics and advanced terminal capability handling.

Do not build a Kitty provider in the first session-control phase.

## 13. Backpressure and slow clients

Optimized providers and Portl's scheduler should treat slow clients as
normal.

Policy:

- input/cancel/resize queues are tiny and high priority,
- history transfer is credit-based,
- viewport updates may be coalesced for observers,
- stale live-output chunks may be replaced by a fresh viewport snapshot
  when a client falls too far behind,
- active driver traffic should not be slowed by read-only observers,
- provider adapters should bound memory per client/lane.

For Tier 2 providers that cannot coalesce internally, Portl should still
avoid writing low-priority data while high-priority data is pending.

## 14. Resume and sequence numbers

Tier 3 providers should support resume:

```text
client reconnects with { session, surface, generation, last_seq }
provider either:
  - resumes live output after last_seq, or
  - sends a fresh ViewportSnapshot with a new seq
```

Tier 2 providers may lack this. Portl should handle missing resume by
requesting a fresh viewport snapshot or provider-native capture.

Sequence numbers are per surface, not global across all sessions.

## 15. Sharing roles

The model should allow multiple client roles:

| Role | Capabilities |
| --- | --- |
| driver | input, cancel, resize, viewport/live/history |
| observer | viewport/live/history, no input |
| navigator | observer plus pointer/annotation hints |
| agent | viewport/live/history summaries, optional controlled input |
| history-only | history requests only |

Ticket caps should eventually distinguish these roles. Initial
implementations may gate all attach/share behavior through existing
session attach permission.

## 16. Security and authorization

Portl remains the cross-boundary authorization layer.

Provider-local sockets and permissions protect local direct use, but
they do not replace Portl tickets. Session caps should eventually cover:

- provider allowlist,
- session allowlist,
- surface allowlist if provider supports it,
- attach/read-only/input/cancel/history/kill permissions,
- sharing role,
- max history bytes,
- max attach duration.

Provider commands should not inherit sensitive Portl environment unless
explicitly required. Optimized control providers should be local-only on
the target; Portl carries remote access over iroh.

## 17. Phased rollout

### Phase 1 — spec and model

- Add this spec.
- Update `200-persistent-sessions.md` to mark the v0.4.0 baseline and
  point here for follow-on work.
- Define provider tier/capability names used by discovery.

### Phase 2 — zmx-control prototype

- Create a zmx fork/branch with `zmx control --protocol portl-v1`.
- Add active viewport serialization without changing vanilla attach.
- Emit viewport snapshot and live output separately.
- Integrate Portl provider fallback: control if available, CLI bridge
  otherwise.

### Phase 3 — Portl lane scheduler

- Add lane-aware attach plumbing.
- Prioritize control/input/cancel/resize.
- Backfill history on a low-priority lane.
- Add queue bounds and resize coalescing.

### Phase 4 — tmux `-CC` adapter

- Implement tmux control-mode provider adapter.
- Map panes to surfaces.
- Use `capture-pane` for viewport/history.
- Use tmux flow-control commands where possible.

### Phase 5 — history, cancel, sharing

- Add zmx history chunks and credits.
- Add explicit cancel/priority input.
- Add read-only observer behavior and slow-client coalescing.

### Phase 6 — experimental providers

- Prototype read-only Zellij provider.
- Reassess Kitty as client integration/inspiration only.
- Consider native Portl provider if zmx/tmux limitations dominate.

## 18. Acceptance criteria

The first optimized slice is accepted when:

1. Provider discovery distinguishes PTY-bridge and control providers.
2. A zmx-control target attaches viewport-first without breaking direct
   `zmx attach`.
3. Portl falls back to the v0.4.0 zmx CLI bridge when control is
   unavailable.
4. Input and resize remain responsive while history backfill is active.
5. History transfer is separated from live output at Portl's scheduler
   boundary.
6. A tmux `-CC` adapter can map at least one tmux pane to a Portl
   surface with live output and visible-pane capture.
7. Errors and provider reports expose missing capabilities clearly.
8. Existing `portl exec` and one-shot `portl shell` behavior is
   unchanged.

## 19. Open questions

1. Should the first zmx-control protocol be named `portl-v1`,
   `zmx-control/v1`, or something upstream-neutral?
2. Should Portl maintain a temporary `portl-zmx` fork, or keep all zmx
   work on a branch intended for immediate upstream submission?
3. How much history should be fetched automatically on attach before the
   user scrolls?
4. Should large history/artifact transfer use a separate iroh connection
   or only app-level scheduling on one connection?
5. What is the minimum useful cancel semantic: Ctrl-C injection,
   priority queue insertion, queue clearing, or SIGINT to process group?
6. Should read-only observers receive raw live output, coalesced
   viewport snapshots, or both?
7. When should a native Portl provider be reconsidered?
