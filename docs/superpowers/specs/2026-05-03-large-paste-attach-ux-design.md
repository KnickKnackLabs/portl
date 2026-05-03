# Large Paste Attach UX and Flow Control Design

## Context

Portl attach sessions currently forward terminal input as raw stdin chunks. A
large `Cmd+V` paste can make a remote attach look frozen because Portl has no
paste-specific flow control, progress UI, or cancellation path. The risk is
especially visible for Ghostty-backed remote sessions.

The current Ghostty helper also has provider-side failure modes:

- The helper handles PTY reads and PTY writes in one `tokio::select!` loop.
  When it awaits `write_pty_all()` for large input, it stops reading PTY
  output. If the child echoes/redraws enough output to fill the PTY output
  buffer, the child can stop reading input and the helper can deadlock.
- The helper command channel and attach subscriber output channels are
  unbounded, so a large paste or slow client can accumulate unbounded memory.
- Attach snapshots are built from history up to 64 MiB, but Ghostty IPC frames
  are capped at 4 MiB, so a large-output session can make later attaches fail.

This design fixes the underlying full-duplex/backpressure problem and adds a
progressive UI so large paste handling is visible and cancellable.

## Goals

- Keep remote attach responsive during large paste bursts.
- Prevent unbounded input/output buffering in Portl and the Ghostty helper.
- Show a floating paste status bar when a paste is large or backpressured.
- Let users cancel pending paste input without interrupting, killing, or
  detaching the remote session.
- Preserve terminal/application behavior, including bracketed paste when the
  terminal/application already uses it.

## Non-goals

- Do not use OSC 52 for paste handling. OSC 52 is primarily clipboard
  set/query behavior, not how `Cmd+V` input normally reaches a TTY.
- Do not use platform clipboard APIs. Portl should remain terminal-driven,
  cross-platform, and avoid reading clipboard contents directly.
- Do not make cancel send `Ctrl+C`, SIGINT, kill the process, or detach the
  session. Those remain separate user actions.

## User-facing behavior

Portl enters paste-progress mode when either of these conditions is true:

1. A large, fast input burst is detected locally.
2. Input forwarding becomes backpressured or queued.

The floating bar starts minimal:

```text
Portl › pasting 1.4 MiB · Esc cancel
```

If the paste remains backpressured or stalled past a short threshold, the bar
expands with operational detail:

```text
Portl › paste 1.4 MiB · 512 KiB queued · ghostty backpressure · Esc cancel
```

While paste-progress mode is active:

- `Esc` cancels pending paste input.
- `Ctrl+\` control mode exposes `c cancel paste`.
- Cancellation drops only bytes that Portl has not delivered yet.
- Bytes already delivered to the remote session are not recalled.
- Portl shows a short confirmation such as:

```text
Portl › cancelled 824 KiB pending paste
```

The bar disappears once pending input drains or cancellation completes.

## Architecture

Introduce an attach input pump between terminal stdin and provider stdin:

```text
local terminal
  → local attach input pump
  → remote session stdin stream
  → remote agent bounded input queue
  → provider adapter
  → provider PTY/socket
```

For Ghostty, the provider adapter continues through the helper:

```text
agent Ghostty adapter
  → bounded helper command channel
  → Ghostty helper full-duplex PTY pump
  → shell/app PTY
```

The central invariant is that no layer should accept unbounded paste data
faster than the next layer can process it.

## Local attach input pump

The local attach input pump owns large-paste state. It tracks:

- bytes read from local stdin,
- bytes accepted by the current sink,
- bytes still pending in Portl,
- whether a write is currently delayed or backpressured,
- whether bracketed paste is active,
- whether paste-progress mode is active.

It drives `AttachDisplay` updates independently of normal remote output as much
as possible. The status bar should continue updating while input writes are
backpressured.

The pump should avoid reading unbounded local paste data into memory. When the
current sink is backpressured, local reading should slow down or stop rather
than accumulating an unlimited pending queue.

## Cancellation semantics

Cancel means: drop pending Portl input only.

Cancellation may discard:

- bytes already read by Portl but not yet written to the remote stream,
- bytes queued in Portl-owned bounded queues,
- provider-helper input queued by Portl where the provider can safely drop it.

Cancellation must not:

- send terminal `Ctrl+C`,
- send SIGINT,
- kill the provider process,
- detach the attach session,
- attempt to recall bytes already delivered to the remote program.

If the provider has no safe way to drop bytes already accepted into its queue,
the provider should report them as delivered rather than pending.

## Bracketed paste handling

Portl should opportunistically detect bracketed paste markers:

- begin: `ESC [ 200 ~`,
- end: `ESC [ 201 ~`.

When markers are present, Portl enters paste-progress mode immediately at the
begin marker and treats the end marker as a natural paste boundary. Portl should
forward bracketed-paste markers transparently during normal operation so the
remote shell/editor sees the same input it would see locally.

Portl should not unilaterally enable bracketed paste by sending `?2004h`; the
remote application owns that terminal-mode choice.

If cancellation occurs after Portl has forwarded an opening bracketed-paste
marker, Portl should send the closing `ESC[201~` marker if needed so the remote
application is not left in bracketed-paste state. Pending payload bytes are
dropped according to the normal cancellation semantics.

If no bracketed-paste markers are present, Portl falls back to the hybrid
large-burst/backpressure detector.

## Ghostty provider changes

The Ghostty helper must not call `write_pty_all()` inline from the main helper
loop for large input. Instead it should use a full-duplex PTY pump:

- enqueue input into a bounded pending buffer,
- read PTY output whenever the PTY is readable,
- write only the bytes the PTY accepts when writable,
- keep partial-write state and return to the event loop after each write,
- process resize/kill/history commands without unbounded input growth.

The helper command channel should become bounded for input-bearing commands, or
input should be routed through a bounded queue separate from lightweight control
commands. Large paste data must backpressure toward the remote agent/local CLI
instead of accumulating in the helper.

Attach subscriber output queues should also be bounded. A slow attach client
should not be able to accumulate unlimited output. The first implementation can
disconnect slow subscribers when their bounded queue remains full.

Attach snapshots must stay within Ghostty IPC frame limits. Either cap the
initial snapshot below `MAX_FRAME_BYTES` or send large history as multiple
output frames after the attach acknowledgement.

## Provider-agnostic behavior

The same flow-control principle applies to all PTY-backed paths:

- `portl shell`, via `pty_master_task`,
- remote tmux control attach, via `pump_tmux_cc_pty`,
- zmx fallback attach, via the generic PTY shell path,
- Ghostty helper PTY handling.

zmx-control already separates stdin writing from stdout/stderr reading and is
less exposed to the same PTY starvation bug, but it should still participate in
bounded queue/backpressure behavior where applicable.

## Error handling

- If the provider stdin closes during paste, clear the paste bar and follow the
  existing stdin-close path.
- If a bounded queue remains full long enough to affect user experience, show
  backpressure in the status bar rather than silently buffering.
- If pending input is cancelled, show the amount dropped.
- If a slow Ghostty subscriber cannot keep up, disconnect that subscriber rather
  than growing memory without bound.
- If the Ghostty snapshot would exceed the IPC frame limit, cap or chunk it;
  attach should not fail only because history grew large.

## Testing strategy

### Local input pump tests

- A large fast burst triggers paste-progress mode.
- Backpressure triggers paste-progress mode even for smaller input.
- `Esc` cancels only pending bytes.
- Already-delivered bytes are not treated as cancelled.
- The status bar expands after the stall threshold.
- Bracketed-paste begin/end markers enter and exit paste mode.
- Cancelling mid-bracketed-paste emits a closing marker if an opening marker was
  already forwarded.

### PTY full-duplex tests

- A PTY child such as `/bin/cat` echoes large input without deadlocking.
- Output continues to drain while input remains pending.
- Partial writes resume correctly after the PTY becomes writable again.
- Closing or cancelling pending input does not kill the session.

### Ghostty helper tests

- Large input through `GhosttyClient::attach()` to `/bin/cat` remains observable
  and does not time out.
- Helper input queues are bounded and apply backpressure.
- Slow attach subscribers do not grow unbounded output queues.
- Large history does not make subsequent attach fail due to the 4 MiB frame
  limit.

## Rollout plan

Implement incrementally:

1. Fix PTY full-duplex/backpressure in shared PTY and Ghostty helper paths.
2. Add local paste-progress state, floating bar, and cancel semantics.
3. Add opportunistic bracketed-paste detection.
4. Add Ghostty bounded queues and snapshot capping/chunking.
5. Add provider/status details to the progressive bar where useful.

Each step should include regression tests before broadening the behavior.
