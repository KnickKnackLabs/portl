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

Ghostty attach v2 separates five semantic planes:

```text
control      resize, detach, signal, heartbeat, resync, reload, overflow notices
input        stdin bytes and paste flow
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
1. detach, signal, resize, heartbeat, cancel reload, resync control
2. stdin/input flow
3. current viewport snapshots
4. healthy live output
5. bounded prelude / explicit reload history chunks
```

Resize events, viewport snapshots, and duplicate resync requests are
latest-wins. Stdin bytes, healthy live output, reload chunks within one reload,
and exit events remain ordered.

## Message Model

The concrete Rust types can live in `portl-proto` or `portl-core` wire modules,
but the semantic message set should resemble:

Server to client:

```text
AttachReady { provider/session metadata }
PreludeChunk { seq, payload }
ViewportSnapshot { generation, live_seq, payload }
LiveOutput { seq, payload }
ReloadChunk { seq, progress, payload }
ReloadDone { final_generation }
BackpressureNotice { reason }
ResyncRequired { reason }
Exit { code }
Error { message }
```

Client to server:

```text
Input { bytes }
Resize { cols, rows }
Signal { sig }
Detach
Reload
CancelReload
RequestViewport { reason }
```

EOF should mean exit, detach, or transport failure. It must not be used as the
normal representation of output backpressure.

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
cancel cleanly, and stay within frame and memory limits.

## Viewport Snapshot and Rendering

The helper should use libghostty-vt terminal/render-state APIs to build a
semantic viewport snapshot instead of replaying raw history to restore the
current screen.

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

1. Send latest resize; intermediate sizes can be coalesced.
2. Let live output stream while healthy.
3. If redraw output creates pressure, enter fast-resync profile.
4. Collect bounded post-resize context using the same 200 ms / 512 KiB OR caps.
5. Render latest viewport snapshot.
6. Resume live mode from a clean sequence boundary.

The latest viewport is authoritative. Portl should not get stuck trying to
deliver obsolete intermediate redraw bytes.

## Configuration

Only two user-facing knobs are required initially:

```text
PORTL_ATTACH_PRELUDE_MAX_WAIT_MS = 200
PORTL_ATTACH_PRELUDE_MAX_BYTES = 524288
```

Compression remains internal. If future metrics justify exposing compression
controls, they should be added as advanced/debug configuration rather than part
of the default UX.

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
```

The attach flight recorder should include:

- prelude cap reason,
- viewport generation,
- reload start/cancel/complete,
- resync reason,
- compression stats summary,
- selected path/RTT when available.

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

Integration-style tests:

- A large retained-history Ghostty attach becomes interactive without replaying
  full history first.
- A slow stdout consumer does not disconnect the attach.
- A resize redraw storm triggers fast resync rather than a reconnect loop.
- `Ctrl-\\ r` streams full retained history in chunks with progress and finishes
  with a latest viewport.
- Ghostty v2 EOF means exit/detach/transport failure, not normal backpressure.
- zmx/tmux attach behavior remains unchanged.

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

