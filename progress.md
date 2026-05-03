## Summary
The implementation successfully resolves the terminal-query staleness bugs caused by `zmx control` mimicking full terminal attachments. By shifting from a sticky, global `has_terminal_client` to a dynamically scanned `responds_to_terminal_queries` per client, the daemon correctly auto-responds to terminal queries when no real terminal is attached. The addition of DSR/CPR responses robustly preempts future shell hangs, and the implementation is clean, well-tested, and maintainable.

## Key observations
- **Correctness**: The replacement of a sticky boolean with a per-client property (`responds_to_terminal_queries`) correctly handles attach/detach cycles without leaving the daemon in an unresponsive state.
- **DSR/CPR Addition**: Adding `ESC[5n` and `ESC[6n` is well-justified. It proactively solves similar blocking waits in shells/TUIs. Leveraging `ghostty-vt`'s internal state to provide real 1-indexed coordinates (`cursor.y + 1`, `cursor.x + 1`) is an elegant solution.
- **Split Query Handling**: The local `pending` buffer logic in `respondToTerminalQueries` is an excellent, minimal implementation. It retains only strict query prefixes, avoiding memory bloat or complex parsers while gracefully recovering queries split across PTY reads. It naturally drops false prefixes on subsequent reads.
- **Performance**: Scanning clients per PTY read (`hasTerminalQueryResponder()`) is O(N), which is perfectly acceptable given the small number of connected clients. It avoids synchronization bugs entirely.
- **Test Coverage**: The Bats integration tests and the Python probe script provide excellent coverage of standard queries, split payloads, and the detached sticky-state fix. 

## Recommendation
Approve the implementation. The code is surgically minimal, handles all edge cases identified (including the split chunks and sticky state), and fits cleanly into the existing architecture. The `respondToDeviceAttributes` wrapper preserves compatibility nicely.

## Tradeoffs and risks
- **O(N) Client Scan**: Calling `hasTerminalQueryResponder` on every PTY read is a slight overhead compared to tracking a discrete count, but heavily favors correctness and simplicity over negligible micro-optimization.
- **DSR/CPR Scope**: While slightly outside the initial DA problem, adding them makes the terminal-mocking more complete and prevents an entire class of query-based hangs. The risk is extremely low since they are standard VT queries with well-defined responses.

---

## Review — Task 5 (commit afc0365: Show cancellable paste progress)

### What's correct
- **Struct design**: `PasteConfig` / `PasteState` / `BracketedPasteScanner` are cleanly separated and easy to reason about in isolation.
- **Burst detection math** (`observe_read`): window reset + accumulation + threshold check is correct.
- **`should_show_detail` guard**: Correctly delays UI noise for short bursts using `detail_after`.
- **Bar message format**: Unicode vs ASCII fallback handled consistently; clear_bar on `pending == 0` is correct.
- **`attach_control.rs` render_bar change**: `paste_cancellable` is threaded through cleanly; existing tests updated; new test `compact_bar_shows_cancel_paste_when_paste_active` is correct.
- **Cross-chunk bracketed paste scanner**: tail-overlap logic (`keep = max(BEGIN.len, END.len) - 1`) is correct and the test validates a split across chunks properly.
- **`cancel_pending` return value**: returning the dropped byte count is good for future logging.
- **Double-cancel via CancelPaste branch**: `cancel_pending()` is correctly called by the caller after `run_attach_control_mode` returns `CancelPaste` (not duplicated inside the control loop).

---

### Issues

#### CRITICAL — `observe_queued` unconditionally sets `active = true`, breaking Esc and the control bar hint for all sessions

`observe_queued` is called on **every** chunk forwarded to `send_stdin`, not only during a detected paste burst:

```rust
// session.rs
paste.observe_queued(read);   // ← sets active = true on first keypress
…
sink.send_stdin(chunk).await?;
paste.observe_sent(read);
```

```rust
fn observe_queued(&mut self, bytes: usize) {
    self.pending_bytes += bytes;
    self.active = true;          // ← activates unconditionally
    self.active_since.get_or_insert_with(Instant::now);
}
```

And `active` is **never set back to `false`** anywhere — `cancel_pending`, `observe_sent`, `set_backpressured(false)` all leave `active` as-is. Consequences:

1. **Esc swallowed from the first keypress onward.** After the user types a single character, `paste.is_active() == true` permanently. The guard `if paste.is_active() && chunk == b"\x1b"` then intercepts *every* bare `\x1b` read. In raw mode, escape sequences (arrow keys, function keys, `^[` prefix of multi-byte escapes) can arrive as a standalone `\x1b` read followed by the rest — OS/tty buffering does not guarantee atomicity. Under moderate load this silently eats arrow keys after the first keystroke.

2. **Control bar always shows "c cancel paste" after any typing.** The hint should only appear during an active paste burst, but it is shown from the first `^\ ` invocation onward because `paste.is_active()` stays true.

**Preferred fix**: Remove `self.active = true` from `observe_queued`. `active` should be set only by `observe_read` (burst threshold), `set_backpressured(true)`, or a dedicated `activate()` call triggered by `BracketedPasteEvent::Begin`. Add deactivation: `cancel_pending` (and ideally `observe_sent` when `pending_bytes` reaches 0) should set `self.active = false` and clear `active_since`.

---

#### HIGH — `BracketedPasteEvent::Begin` arm calls `set_backpressured(false)` instead of activating paste mode

```rust
match bracketed.scan(chunk) {
    BracketedPasteEvent::Begin => paste.set_backpressured(false),   // ← wrong
    BracketedPasteEvent::End | BracketedPasteEvent::None => {}
}
```

`set_backpressured(false)` only clears the `backpressured` flag — it does not set `active = true` (because its `if value { ... }` branch is skipped). So bracketed paste completely fails to activate paste mode. The intent is clearly the opposite: Begin should activate the paste state. If the CRITICAL fix above removes `observe_queued`'s side effect, this becomes the sole activation path for bracketed paste and the bug becomes user-visible.

**Preferred fix**: Replace `paste.set_backpressured(false)` with `paste.activate(now)` (or equivalent) when `BracketedPasteEvent::Begin` is received. On `End`, deactivate (or let `observe_sent` drain to zero trigger deactivation).

---

#### MEDIUM — `cancel_pending` does not reset `active` or `active_since`

After a paste is cancelled, `active` remains `true` and `active_since` still points to the original start time. The bar clears because `update_paste_bar` calls `clear_bar()` when `pending == 0`, but:

- The control bar hint "c cancel paste" continues to appear on all subsequent `^\ ` presses.
- The Esc-swallow guard continues to be armed.

**Preferred fix**: `cancel_pending` should also set `self.active = false; self.active_since = None;`.

---

#### MEDIUM — Scanner ignores current `in_paste` state when dispatching Begin vs. End

```rust
let event = if combined.windows(BEGIN.len()).any(|w| w == BEGIN) {
    …Begin…
} else if combined.windows(END.len()).any(|w| w == END) {
    …End…
}
```

If a chunk contains both `\x1b[200~` and `\x1b[201~` (e.g. an empty bracketed paste `\x1b[200~\x1b[201~` delivered atomically), `Begin` fires and `End` is missed. The following chunk has no tail that covers `\x1b[201~`, so the paste is never closed; `in_paste` stays `true` indefinitely.

Additionally, if already `in_paste == true`, the scanner should prioritise looking for `END`. Checking `BEGIN` first when already in a paste can produce a spurious extra `Begin` if a malformed stream sends a second `\x1b[200~`.

**Preferred fix**: Branch on `self.in_paste` first to select which sequence to search for, and handle the both-sequences case by scanning for End after Begin within the same combined buffer.

---

#### MINOR — `PasteConfig::default()` shadows the `Default` trait without implementing it

```rust
impl PasteConfig {
    fn default() -> Self { … }
}
```

This defines a freestanding `fn default()` rather than implementing `std::default::Default`. Code using `PasteConfig::default()` compiles, but `Default::default()` or struct-update syntax (`..Default::default()`) would not work, and clippy will warn (`should_implement_trait`). Either add `#[derive(Default)]` (with field defaults) or `impl Default for PasteConfig`.

---

#### MINOR — Esc-cancel hint in the paste bar does not mention `^\ c`

`update_paste_bar` formats: `"… | Esc cancel"`. But Esc is not the primary documented cancel path — `^\ c` is. Both should be shown (matching the control bar that correctly shows "c cancel paste"), or at minimum the bar should say `"Esc or ^\\ c to cancel"`.

---

### Test coverage gaps

- No test that `observe_queued` **does not** prematurely activate paste state (would catch the CRITICAL bug above if it existed).
- No test for `cancel_pending` resetting `active` (would catch the MEDIUM deactivation bug).
- No test for `BracketedPasteEvent::Begin` activating paste mode (would catch the HIGH bracket bug).
- No test for the both-BEGIN-and-END-in-one-chunk scanner edge case.
- No test for `should_show_detail` timing boundary (`detail_after`).
- `in_bracketed_paste` accessor is gated `#[cfg_attr(not(test), allow(dead_code))]` — this suggests the accessor is only used in tests, meaning the scanner's state is never actually consumed in production logic (bracketed detection activates paste through the `observe_queued` side-effect path rather than through `in_paste`).

---

### Note

The bar-clearing path (`clear_bar()` when `pending == 0` in `update_paste_bar`) is correct and would keep the screen clean once all bytes drain, but relies on `update_paste_bar` being called post-send — which it is. The backpressure heuristic (100 ms threshold) is reasonable for a first iteration.

---

## Verdict: CHANGES_REQUESTED

The CRITICAL `observe_queued`/`active` bug causes Esc to be silently consumed after the first keypress in any session, breaking arrow keys and normal Esc usage for the entire session lifetime. The HIGH bracket-paste activation bug means the feature does not work for the bracketed-paste detection path at all. Both must be fixed before merge.
