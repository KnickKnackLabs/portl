# Ghostty Attach v2 Design

Date: 2026-05-07

## Summary

Native Ghostty session attach should stop treating scrollback, current viewport
state, live output, input, resize, and control as one effective byte stream.
Attach v2 introduces semantic lanes for Ghostty-backed sessions so Portl can show
the current terminal quickly, preserve a bounded amount of recent context, and
recover from resize/redraw storms without closing the attach stream.

The first implementation is v2-only for native Ghostty sessions. zmx and tmux
continue to use the existing attach path.

## Current Problem

The current Ghostty attach path sends a capped raw history tail as the initial
snapshot, then collapses that snapshot and all future live output into stdout.
For long-running TUIs, the raw snapshot can hit the current 2 MiB cap. On slow
or high-latency remote paths, that initial replay can backpressure the output
pipeline before the user reaches the current TUI and can type.

The same failure appears during resize storms. A TUI redraw can generate a large
live-output burst; if the output path falls behind, the bounded Ghostty
subscriber queue can fill. Today that closes the attach stream, and the client
interprets stdout ending before an exit frame as a disconnect.

Benchmarks from live Ghostty sessions confirmed that both sampled sessions hit
the 2 MiB attach snapshot cap. Full history cannot currently be fetched through
the helper as one frame because it can exceed the 4 MiB helper frame limit.

## Goals

- Make initial attach and reconnect interactive quickly.
- Separate current viewport restore from scrollback/history transfer.
- Keep input, resize, detach, reload, and resync controls responsive under heavy
  output.
- Treat backpressure as a recoverable semantic condition, not as EOF.
- Make resize/redraw recovery low-latency by using the latest viewport as the
  authoritative state.
- Support explicit full reload when the user asks for it.
- Compress large protocol payloads with a simple default policy.
- Preserve current zmx/tmux behavior.

## Non-Goals

- No history viewer or `Ctrl-\\ l` load mode in the first implementation.
- No automatic insertion of older scrollback above an already-live terminal
  view; normal terminals do not provide a safe portable API for that.
- No user-facing zstd tuning knobs in the first implementation.
- No required custom zstd dictionary in the first implementation, though the
  protocol reserves a dictionary identifier.

## User Experience

### Fast Resync Profile

Initial attach, automatic reconnect, resize recovery, and output-backpressure
recovery use the same fast-resync profile:

1. Collect bounded context bytes.
2. Render the latest current viewport snapshot.
3. Enter live mode.

The bounded context collection stops when the first of these conditions is true:

- `prelude_max_wait_ms` elapsed.
- `prelude_max_bytes` decoded/renderable terminal bytes are available.
- The provider reports that no more bounded context is available.

Defaults:

```text
prelude_max_wait_ms = 200
prelude_max_bytes = 512 KiB
```

These are OR caps. If the byte cap is reached in 40 ms, Portl renders
immediately instead of waiting for the remainder of the 200 ms budget. If only a
small amount of context arrives by 200 ms, Portl renders that small amount and
then renders the current viewport.

The byte cap applies to decoded/renderable terminal bytes, not compressed bytes.
Rendering should trim to safe boundaries, preferably complete rows and complete
escape sequences.

### Live Mode

Live mode forwards input, resize, detach/control commands, and healthy live
output. Large live-output bursts can be compressed, but small output stays
uncompressed for latency.

If live output falls behind, Portl should prefer semantic recovery over faithful
delivery of every stale byte:

```text
backpressure or stale redraw risk
→ pause low-priority work
→ coalesce/drop stale output when safe
→ request latest viewport
→ redraw viewport
→ resume live mode
```

The final viewport snapshot is authoritative after any sequence gap.

### Control Mode

`Ctrl-\\` opens the attach control prompt. For Ghostty v2, the prompt should
include:

```text
d   detach
r   reload full retained history + latest viewport
^\\  send literal Ctrl-\\
Esc cancel control prompt
```

Existing conditional actions, such as paste cancellation, may still appear when
relevant.

### Explicit Reload Profile

`Ctrl-\\ r` is a deliberate full reload. It is not bounded by the fast-resync
prelude caps.

Reload flow:

1. Enter reload mode and show progress.
2. Stream the provider's full retained Ghostty history in chunks.
3. Render chunks as they arrive.
4. Render the latest viewport snapshot.
5. Resume live mode from a clean sequence boundary.

Reload still uses chunking and backpressure; it never sends one giant frame and
never requires buffering all history in memory before rendering. `Esc` during
reload cancels remaining history replay, requests the latest viewport, and
resumes live mode.

Live output must not be visually interleaved with history replay during reload.
The client should buffer, coalesce, or discard stale live output behind a
sequence boundary, then finish reload with a latest viewport snapshot.

Progress examples:

```text
▌ Portl › max/ghostty/dev · reloading 2.4 MiB · Esc cancel
▌ Portl › max/ghostty/dev · reloading 2.4 / 12.1 MiB · 20% · Esc cancel
```

## Protocol Planes

Ghostty attach v2 separates six semantic planes:

```text
control      detach, heartbeat, reload, cancel, resync, backpressure, exit/error
input        ordered stdin bytes and paste flow
resize       latest-wins PTY size updates
viewport     current visible terminal state; latest generation wins
live output  ordered PTY output while healthy; recoverable by resync
history      bounded prelude and explicit reload chunks
```

The existing remote attach already uses separate QUIC streams for several
directions. Attach v2 should preserve that separation and add an application
scheduler so control, input, resize, and viewport messages are never blocked by
history or stale redraw data.

Priority order:

```text
1. detach, exit, error, heartbeat, cancel reload, resync/backpressure control
2. stdin/input flow and latest resize
3. current viewport snapshots
4. healthy live output
5. bounded prelude / explicit reload history chunks
```

Resize events, viewport snapshots, duplicate resync requests, and duplicate
backpressure notices are latest-wins or coalesced. Stdin bytes, healthy live
output, reload chunks within one reload, and exit events remain ordered.

Application priority must also respect QUIC connection-level flow control. The
history/reload plane must have a small outstanding-byte budget and must pause
when control, input, viewport, or live-output recovery is pending.

## Protocol Identity, Ordering, and Barriers

Attach v2 needs explicit identifiers so old work cannot race with new work:

```text
attach_id      unique per attach/reconnect instance
reload_id      unique per explicit reload within one attach_id
resize_id      monotonic latest-wins resize counter
live_seq       monotonic byte/message boundary after provider VT ingestion
view_generation monotonic viewport snapshot generation
```

All v2 messages are scoped by `attach_id`, either explicitly in the frame or by
the stream opened for that attach. The client ignores messages for any stale
`attach_id`.

`LiveOutput` uses a sequence range, not just an opaque counter:

```text
LiveOutput { attach_id, start_seq, end_seq, payload }
```

`ViewportSnapshot` is a sequence barrier:

```text
ViewportSnapshot {
  attach_id,
  generation,
  covers_live_seq,
  cols,
  rows,
  resize_id,
  payload,
}
```

The snapshot means: the provider terminal state has applied all PTY output up to
`covers_live_seq`. After applying the snapshot, the client discards any buffered
live output with `end_seq <= covers_live_seq` and resumes from the first live
output after that boundary. Stale snapshots with an older generation, stale
`attach_id`, or non-current `resize_id` are ignored unless the client explicitly
requested that older size.

The provider must assign `live_seq` and produce viewport snapshots from one
serialized terminal-state actor. PTY output ingestion, resize application,
terminal `vt_write`, history appends, snapshot generation, and sequence
assignment must be ordered through that actor. Expensive snapshot encoding or
compression may run off the actor, but it must operate on a copied/minimized
snapshot plus its recorded `covers_live_seq`.

## State Machine

The client and server should model attach v2 as explicit states:

```text
Opening
FastResync
Live
Reloading
Detached
Exited
Failed
```

State rules:

- `Opening` waits for `AttachReady` and the fast-resync viewport.
- `FastResync` collects bounded context until the OR caps fire, then renders an
  authoritative viewport and enters `Live`.
- `Live` forwards input/control and renders healthy live output.
- `Reloading` streams full retained history for a `reload_id`, suppresses visual
  interleaving of live output, and exits through a latest viewport barrier.
- `Detached`, `Exited`, and `Failed` are terminal states for that `attach_id`.

Precedence rules:

- `Detach` cancels reload/history/resync work and closes the attach without
  killing the persistent session.
- `Exit` cancels reload/history/resync work and is terminal for the process.
- Provider/helper crash is `Error` if the control lane survives; otherwise it is
  a transport failure.
- `CancelReload` is idempotent. If it races with `ReloadDone`, the client treats
  the reload as cancelled once it has sent `CancelReload`, ignores later chunks
  or done frames for that `reload_id`, requests a latest viewport, and resumes
  live mode.
- Late chunks, snapshots, or live output after `Detached`, `Exited`, or `Failed`
  are ignored.

Input and high-priority controls remain active during `Reloading`. Plain stdin
is forwarded to the remote PTY, but live output is not rendered during history
replay; the final viewport barrier makes the visible screen current. `Esc` while
the reload UI is active is a Portl reload-cancel command and must not leak to
the PTY.

## Wire and Helper Stream Mapping

Ghostty attach v2 should be requested with an explicit versioned operation, such
as `SessionOp::AttachV2` or an equivalent `attach_version = 2` request field. An
old client must not accidentally interpret v2 framed payloads as raw stdout. If
a client requests the old Ghostty attach path against a v2-only Ghostty agent,
the agent should reject with a clear capability error; zmx/tmux attach remains
unchanged.

Remote QUIC mapping should use separate framed streams by priority class:

```text
v2_control   bidirectional, high priority; no bulk payloads
v2_input     client→server ordered stdin frames
v2_resize    client→server latest-wins resize frames
v2_signal    client→server signal frames
v2_viewport  server→client viewport snapshots
v2_live      server→client live output ranges
v2_history   server→client prelude/reload history chunks
```

`Exit`, `Error`, `BackpressureNotice`, `ResyncRequired`, `ReloadStarted`,
`ReloadCancelled`, `ReloadDone`, and heartbeat frames travel on `v2_control` so
they are not queued behind the saturated live/history data lane. Viewport
snapshots have their own stream so a recovery snapshot is not blocked by stale
history chunks. Cross-stream ordering is expressed with `attach_id`, `live_seq`,
`covers_live_seq`, `generation`, `reload_id`, and `resize_id`.

The local Ghostty helper IPC needs the same priority model. Full history
streaming must not fill the helper command queue or block PTY reads. Detach,
kill, resize, input, and viewport-resync commands need independent
high-priority channels or a framed helper scheduler that can always service
control before history/live bulk writes.

## Message Model

The concrete Rust types can live in `portl-proto` or `portl-core` wire modules,
but the semantic message set should resemble:

Server to client:

```text
AttachReady { attach_id, provider/session metadata, codec capabilities }
Heartbeat { attach_id, sent_at }
PreludeChunk { attach_id, seq, progress, payload }
ViewportSnapshot { attach_id, generation, covers_live_seq, cols, rows, resize_id, payload }
LiveOutput { attach_id, start_seq, end_seq, payload }
ReloadStarted { attach_id, reload_id, total_bytes: Option<u64> }
ReloadChunk { attach_id, reload_id, seq, progress, payload }
ReloadDone { attach_id, reload_id, final_generation }
ReloadCancelled { attach_id, reload_id }
BackpressureNotice { attach_id, reason, from_seq }
ResyncRequired { attach_id, reason, from_seq }
Exit { attach_id, code }
Error { attach_id, message, recoverable }
```

Client to server:

```text
Input { attach_id, bytes }
Resize { attach_id, resize_id, cols, rows }
Signal { attach_id, sig }
Detach { attach_id }
HeartbeatAck { attach_id, sent_at }
Reload { attach_id, reload_id }
CancelReload { attach_id, reload_id }
RequestViewport { attach_id, reason, resize_id }
```

Progress should be explicit:

```text
Progress {
  loaded_bytes,
  total_bytes: Option<u64>,
  retained_history_truncated: bool,
  complete: bool,
}
```

EOF should mean exit, detach, or transport failure. It must not be used as the
normal representation of output backpressure.

## Backpressure and Flow Control

Backpressure notices must not travel on the same congested data lane that caused
the pressure. When a live/history queue crosses its high-water mark, the server
should:

1. Stop or pause low-priority history/reload sends for that attach.
2. Mark a live sequence gap if stale live bytes will be dropped.
3. Send `BackpressureNotice` or `ResyncRequired` on `v2_control`.
4. Proactively enqueue a latest viewport snapshot on `v2_viewport` when doing so
   is cheaper than waiting for a client `RequestViewport` round trip.
5. Resume live mode only after the viewport barrier is applied.

Per-plane queues must be bounded and have plane-specific overflow behavior:

```text
control   never drop terminal events; close/fail attach if control cannot send
input     ordered and bounded; backpressure local paste/input UI if needed
resize    keep only latest resize_id
viewport  keep only latest generation per requested size
live      ordered while healthy; on overflow mark sequence gap and resync
history   pause/drop outstanding chunks; reload can be cancelled/retried
```

Suggested initial limits should be conservative and measurable:

- maximum uncompressed payload per frame,
- maximum compressed payload per frame,
- maximum outstanding history/reload bytes per attach,
- maximum live queue bytes before resync,
- maximum simultaneous reloads per session/client,
- maximum viewport requests per time window.

## Payload Compression

Large payload-bearing messages use a shared payload envelope:

```text
Payload {
  codec: none | zstd,
  dictionary_id: none | static-terminal-v1 | future,
  uncompressed_len,
  compressed_len,
  bytes,
}
```

Initial compression policy is internal and minimal:

```text
zstd_level = 3
compress_if_over = 16 KiB
dictionary_id = none
```

Apply compression to:

- prelude chunks,
- reload/history chunks,
- large viewport snapshots,
- large live-output bursts.

Do not compress:

- input,
- resize,
- detach,
- signal,
- heartbeat/control messages,
- small live output.

The wire envelope reserves `dictionary_id` for a future built-in terminal/TUI
dictionary. Benchmarks showed plain zstd already provides strong compression on
real attach snapshots, while rough custom dictionary gains were modest.

History and reload chunks should be independently decodable. Use a target chunk
size around 64 KiB or 128 KiB uncompressed so reload can stream progress,
cancel cleanly, and stay within frame and memory limits. Smaller chunks are
acceptable on high-latency or constrained paths if they reduce connection-level
flow-control pressure.

Compression and decompression must be resource bounded:

- `compressed_len` must equal the actual payload length.
- `uncompressed_len` must be capped per message and verified after decode.
- Unknown `dictionary_id` values are rejected unless negotiated.
- zstd decode must use a hard output limit to prevent decompression bombs.
- Large compression work should run off the provider terminal-state actor.
- Live-output compression must not block the hot PTY read path; if compression
  would add latency during a burst, send raw live data, coalesce, or resync.

## Viewport Snapshot and Rendering

The helper should use libghostty-vt terminal/render-state APIs to build a
semantic viewport snapshot instead of replaying raw history to restore the
current screen. Snapshot extraction must happen at a known `covers_live_seq`
barrier from the serialized provider terminal-state actor.

A viewport snapshot should include:

```text
cols/rows
rows of cells/graphemes
style/color data
cursor visibility, position, and visual style
active screen indicator
selected terminal/input modes
title/pwd metadata when available
generation and live sequence info
```

The client renders the snapshot to ANSI for the user's local terminal. The first
implementation should prioritize visually correct current content and usable
input over perfect serialization of every Ghostty internal state. Missing edge
cases should be recoverable through another viewport resync.

Terminal safety rules:

- Fast prelude should be provider-produced safe render output where practical,
  not arbitrary raw escape replay.
- Explicit reload may stream retained history, but side-effecting controls such
  as OSC 52 clipboard writes, device queries, DCS/APC/PM payloads, and stale
  title/mode changes should be filtered or rendered through a sanitizer where
  possible.
- If the session is currently on the alternate screen, fast prelude should be
  minimal or omitted unless the provider can produce safe main-screen context
  without switching local terminal modes.
- The client must restore local terminal modes on detach/exit/failure,
  including mouse tracking, bracketed paste, cursor visibility, and control bar
  styling.
- Partial UTF-8, CSI/OSC escape sequences, combining marks, emoji ZWJ
  sequences, and wide cells must not be split when trimming prelude or framing
  sanitized render output.

Initial rendering order:

```text
bounded prelude, if any
→ clear/reset enough local state to avoid leftovers
→ render current viewport rows
→ restore cursor/modes where possible
→ enter live mode
```

Explicit reload rendering order:

```text
full retained history chunks
→ latest viewport snapshot
→ enter live mode
```

## Resize and Redraw Storms

Resize recovery should be optimized for latency and treated like a mini attach.

On resize:

1. Send latest resize with a monotonic `resize_id`; intermediate sizes can be
   coalesced.
2. Let live output stream while healthy.
3. If redraw output creates pressure, enter fast-resync profile.
4. Collect bounded post-resize context using the same 200 ms / 512 KiB OR caps.
5. Render a viewport snapshot matching the latest `resize_id` and local terminal
   size.
6. Resume live mode from a clean sequence boundary.

The latest viewport is authoritative. Portl should not get stuck trying to
deliver obsolete intermediate redraw bytes.

A resize snapshot captured immediately after `TIOCSWINSZ` may precede the TUI's
redraw. Resize recovery should therefore wait for the earliest of first
post-resize output, the fast-resync wait cap, the byte cap, or provider
exhaustion before taking the final viewport snapshot. If the local terminal size
changes again during resync/reload, stale viewport requests for the old size are
cancelled or ignored.

## Configuration

Only two user-facing knobs are required initially:

```text
PORTL_ATTACH_PRELUDE_MAX_WAIT_MS = 200
PORTL_ATTACH_PRELUDE_MAX_BYTES = 524288
```

Compression remains internal. If future metrics justify exposing compression
controls, they should be added as advanced/debug configuration rather than part
of the default UX.

## Terminal History Semantics

The provider's retained history may mutate while reload is running. Reload uses
a fixed retained-history range captured at reload start. New live output after
that boundary is handled by live sequencing and the final viewport barrier, not
by extending the reload range indefinitely.

Full retained history means the provider's retained cap, not unlimited process
history. If older history was already evicted, progress should set
`retained_history_truncated = true` so diagnostics can explain why a reload did
not include everything since session creation.

Current raw helper history paths that copy the whole `VecDeque` into a `String`
are not acceptable for v2 reload. History must be streamed as bytes or
sanitized rows without one full-buffer allocation.

## Metrics and Diagnostics

Add counters/timings that make the UX tunable:

```text
attach_v2_prelude_wait_ms
attach_v2_prelude_decoded_bytes
attach_v2_prelude_timeout_total
attach_v2_prelude_byte_cap_total
attach_v2_viewport_render_ms
attach_v2_reload_decoded_bytes
attach_v2_reload_cancel_total
attach_v2_reload_complete_total
attach_v2_resync_total{reason}
attach_v2_live_compressed_bytes
attach_v2_live_raw_bytes
attach_v2_backpressure_total
attach_v2_sequence_gap_total
attach_v2_stale_message_dropped_total
attach_v2_snapshot_stale_total
attach_v2_queue_depth{plane}
attach_v2_bytes_in_flight{plane}
attach_v2_control_latency_ms
attach_v2_compress_ms{plane}
attach_v2_decompress_ms{plane}
attach_v2_viewport_generation_lag
```

The attach flight recorder should include:

- prelude cap reason,
- viewport generation,
- reload start/cancel/complete,
- resync reason,
- compression stats summary,
- selected path/RTT when available,
- queue depth and in-flight bytes when resync/backpressure fires,
- stale message drops by attach/reload/generation mismatch.

## Testing Plan

Focused unit tests:

- Fast prelude exits on wait cap.
- Fast prelude exits on byte cap.
- Prelude trimming preserves safe render boundaries.
- Compression envelope uses `none` for small payloads and zstd for large
  payloads.
- Compression envelope validates uncompressed/compressed lengths and dictionary
  identifiers.
- Viewport renderer round-trips simple rows, styles, and cursor state.
- Multiple resize events collapse to final size.
- Reload cancellation stops history chunks and renders a viewport.
- Stale `attach_id`, `reload_id`, `resize_id`, and viewport generations are
  ignored.
- Viewport/live sequence barriers discard covered live output and preserve newer
  output.
- Compression decode rejects invalid lengths, unknown dictionaries, and
  decompression outputs above the configured cap.

Integration-style tests:

- A large retained-history Ghostty attach becomes interactive without replaying
  full history first.
- A slow stdout consumer does not disconnect the attach.
- A resize redraw storm triggers fast resync rather than a reconnect loop.
- `Ctrl-\\ r` streams full retained history in chunks with progress and finishes
  with a latest viewport.
- Ghostty v2 EOF means exit/detach/transport failure, not normal backpressure.
- zmx/tmux attach behavior remains unchanged.
- Backpressure notice is delivered on the high-priority control lane even when
  live/history data queues are full.
- Detach and exit while reload chunks are in flight cancel the reload and ignore
  stale chunks.
- Reconnect overlap ignores messages from an old `attach_id`.
- Alternate screen, bracketed paste, mouse mode, split ANSI, split UTF-8,
  combining marks, emoji ZWJ sequences, and wide cells are covered by rendering
  tests.
- Provider/helper crash reports `Error` when possible and otherwise becomes a
  transport failure without being confused with normal backpressure.

## Acceptance Criteria

- Attaching to long-running Pi-agent Ghostty sessions does not replay the full
  current 2 MiB v1 snapshot before interactivity.
- Resizing a busy TUI no longer causes the attach stream to disconnect under
  normal backpressure.
- `Ctrl-\\ r` can stream full retained history without a single oversized frame
  and can be cancelled with `Esc`.
- Current viewport appears quickly after attach, reconnect, and resize recovery.
- Live input/control remains responsive while history or large output is in
  progress.
- zmx and tmux session attach behavior is unchanged.
- Stale messages from prior attach/reload/resync epochs cannot modify the active
  viewport.
- Control and detach remain responsive while live/history queues are saturated.
- Malformed compressed payloads and oversized decompressed payloads are rejected
  without unbounded memory growth.
