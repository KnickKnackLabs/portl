# Session Attach Automatic Reconnect Design

## Status

Approved for implementation planning.

## Context

Remote `portl session attach` currently opens one QUIC connection, starts a
provider attach through `open_session_attach`, and bridges local terminal I/O
through `bridge_attach`. If that connection or one of its streams drops, the
client exits with an error even though persistent providers such as zmx and tmux
can be manually reattached.

The first reconnect slice should make remote persistent session attach feel
resilient without changing the session wire protocol or provider contracts.
Protocol-level resume with generation and sequence numbers remains future work
covered by `docs/specs/210-session-control-lanes.md`.

## Goals

1. Automatically reattach remote persistent sessions after unexpected transport
   drops.
2. Make fast reconnects feel seamless by buffering local input and resize state
   during a short transparent resumption window.
3. Show the retry status bar only after transparent resumption is visibly
   failing.
4. Preserve clear detach semantics: stopping reconnect leaves the provider
   session running.
5. Use bounded, jittered exponential backoff so reconnect is resilient without
   hanging forever.
6. Avoid wire/schema changes in the first implementation slice.

## Non-goals

- Resume from provider-native sequence numbers.
- Guarantee lossless terminal output across a dropped transport.
- Add agent-side client attach state or new `/status` schema fields in the first
  slice.
- Apply reconnect behavior to one-shot `portl shell` or `portl exec`.
- Buffer unbounded paste/input while disconnected.

## User experience

### Normal fast drop

When a transport drop resolves quickly, Portl should keep raw mode active,
buffer local input briefly, reconnect immediately, flush the buffered input, and
continue without drawing a reconnect bar. The user may notice a short pause but
should not see an alarming disconnect message.

### Visible reconnect

If transparent resumption exceeds the grace window or starts applying backoff,
Portl shows a bottom status bar:

```text
▌ Portl › dev/tmux/work · disconnected · retry 3 in 1.8s · 12 bytes buffered · Enter retry now · d detach · Ctrl-C quit
```

Controls while this bar is visible:

- `Enter`: skip the current backoff delay and retry immediately.
- `d`: detach locally and stop reconnecting. The provider session keeps running.
- `Ctrl-C`: local quit fallback. The provider session keeps running.

The bar must lead with `d detach` rather than `Ctrl-C cancel` so users do not
infer that Portl will interrupt or kill the remote session.

### Reattach success

If the reconnect bar was visible, show a short success state, then clear it:

```text
▌ Portl › dev/tmux/work · reattached · flushed 12 bytes
```

If reconnect completed within the transparent window, no success bar is needed.

### Stop messages

If the user presses `d` during reconnect:

```text
portl: detached from session "dev/tmux/work"

The session is still running. To reconnect, run:
  portl attach dev/tmux/work
```

If the user presses `Ctrl-C` during reconnect:

```text
portl: stopped reconnecting to session "dev/tmux/work"

The session is still running. To reconnect, run:
  portl attach dev/tmux/work
```

## Architecture

Add a remote attach reconnect runner around the existing remote attach flow:

```text
remote_session_attach_with_reconnect
  resolves target/provider/session once
  owns raw mode, AttachDisplay, reconnect policy, and buffered local input
  loops over connect_peer -> open_session_attach -> run_attach_once

run_attach_once
  owns one ConnectedPeer and one SessionClient
  bridges stdout/stderr/exit and the current remote input sink
  returns Exited, Detached, or Disconnected
```

The first implementation should keep this CLI-owned. The target agent already
keeps the persistent provider session alive independently of any single client
connection, so the client can reattach by opening a new session attach with the
same target, provider, session name, user, cwd, argv, and terminal size.

## Attach lifecycle results

Represent attach completion explicitly instead of treating every task result as
an exit code:

```rust
enum AttachEnd {
    Exited(i32),
    Detached,
    Disconnected(anyhow::Error),
}
```

`Exited` stops the reconnect loop and returns the provider exit code.
`Detached` stops the reconnect loop and prints the standard detach message.
`Disconnected` enters transparent resumption or visible reconnect depending on
retry state.

Do not reconnect after:

- user detach,
- normal provider/session exit frame,
- authorization or capability rejection,
- provider not found/unavailable errors from `open_session_attach`,
- local non-interactive stdin EOF.

Reconnect after:

- QUIC connection loss,
- remote stdout/stderr/exit read failures,
- attach substream failure before a clean exit frame,
- connection close that cannot be classified as a normal session exit.

## Transparent resumption

On unexpected disconnect, enter a transparent phase before showing UI:

- Keep raw mode active.
- Keep the local stdin reader alive.
- Buffer stdin bytes up to a bounded limit.
- Coalesce resizes and keep only the latest terminal size.
- Retry immediately, then with very short jittered delays.
- If reattach succeeds inside the grace window, flush buffered input and the
  latest resize, then continue without drawing the reconnect bar.

Recommended defaults:

- transparent grace window: `1.5s`,
- immediate attempts before visible backoff: `2`,
- transparent retry delays:
  - attempt 1: immediate,
  - attempt 2: `150-300ms` jitter,
  - attempt 3: `500-800ms` jitter if still within the grace window.

The transparent phase ends and the visible bar appears when any of these happen:

- the grace window expires,
- buffered input reaches the configured limit,
- the retry policy enters regular exponential backoff,
- the reconnect error is persistent enough to be user-actionable.

## Buffering policy

Buffer only data the user produced while Portl was disconnected:

1. stdin bytes,
2. latest terminal resize,
3. local reconnect controls once the visible reconnect bar is shown.

Recommended stdin limit for the first slice: `256 KiB`.

When the buffer reaches the limit:

- transition to visible reconnect state,
- stop reading additional local stdin until reattached or detached,
- show the buffered byte count in the bar,
- do not silently drop bytes.

Resize events should be coalesced. Only send the latest known dimensions after
reattach.

Large paste remains bounded by the same buffer. A future enhancement may add a
paste-specific larger limit or explicit paste-spooling policy, but the first
slice should avoid unbounded memory growth.

## Backoff policy

Use bounded exponential backoff with jitter after transparent resumption fails.

Recommended defaults:

- base delay: `500ms`,
- maximum delay: `10s`,
- maximum reconnect elapsed time: `2m`,
- jitter: full jitter in `[0, capped_delay]`,
- reset attempt count after a successful attach lasts at least `30s`.

The visible backoff wait races:

```text
timer completes  -> scheduled retry
Enter            -> immediate retry
d                -> detach and stop reconnecting
Ctrl-C           -> local quit and stop reconnecting
```

## Status bar integration

The reconnect bar should use the existing `AttachDisplay` machinery so output is
gated while the bar is drawn and flushed when the bar clears.

The current attach-control bar and paste-progress bar remain connected-state UI.
The reconnect bar is a degradation indicator shown only after transparent
resumption fails.

Priority between bars:

1. reconnect/backoff bar while disconnected,
2. paste progress while connected and paste is active,
3. attach control mode while connected and `Ctrl-\` was pressed.

When disconnected, no bytes should be sent to the remote sink because there is no
live sink. Local keys are either buffered input during transparent resumption or
interpreted as reconnect controls once the visible bar is active.

## Error handling

Reconnect failures should be concise in the bar and detailed in debug logs.
User-facing text should distinguish local reconnect control from remote session
control.

If the bounded retry budget expires, clear raw mode and print:

```text
portl: could not reconnect to session "dev/tmux/work" after 2m

The session may still be running. To reconnect, run:
  portl attach dev/tmux/work
```

If a later attach attempt receives a provider/session-not-found style error, stop
retrying and print the provider error. That means the persistent session may have
been killed or the provider state changed; retrying the same request is unlikely
to help.

## Configuration surface

Automatic reconnect is enabled by default for remote `portl session attach`.

The first implementation should prefer constants over a large CLI surface. If a
small override is needed, add only these controls:

- `--no-reconnect` for debugging or strict fail-fast behavior,
- `PORTL_SESSION_RECONNECT=off` as an environment override.

Detailed tuning knobs for grace, buffer size, and max elapsed can wait until real
usage shows the defaults are wrong.

## Testing strategy

Unit tests:

- backoff delay caps and jitter range,
- retry budget expiration,
- visible-state transitions after grace expiration,
- Enter skips backoff,
- `d` and `Ctrl-C` both stop reconnecting without marking remote exit,
- input buffer limit transitions to visible reconnect and stops additional
  reads,
- resize coalescing keeps only the latest size.

Integration-style tests where practical:

- remote attach reconnects after forced QUIC connection close,
- user input typed during a short disconnect is delivered after reattach,
- normal provider exit does not reconnect,
- explicit detach does not reconnect,
- provider-not-found/session-not-found errors do not retry,
- status bar strings fit narrow terminal widths.

Manual smoke tests:

- attach to a zmx or tmux session, kill the client network path briefly, confirm
  transparent resume,
- hold the target unreachable beyond the grace window, confirm retry bar,
- press Enter during backoff, confirm immediate retry,
- press `d` during backoff, confirm detach message and session survives,
- press Ctrl-C during backoff, confirm local quit message and session survives.

## Rollout

1. Refactor remote attach into an explicit one-shot attach result.
2. Add reconnect policy and retry loop without transparent buffering.
3. Add transparent input/resize buffering.
4. Add visible reconnect bar with Enter/`d`/Ctrl-C controls.
5. Add integration tests and manual smoke coverage.

This order keeps each step testable while preserving the approved final UX.
