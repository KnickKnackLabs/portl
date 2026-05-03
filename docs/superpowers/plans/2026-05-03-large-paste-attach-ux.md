# Large Paste Attach UX Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make large interactive pastes in Portl attach sessions visible, backpressured, and cancellable, with Ghostty-specific deadlock and queue fixes.

**Architecture:** Add bounded/full-duplex PTY input pumping so writes cannot starve reads, then layer a provider-agnostic local paste state machine and floating status UI on top. Ghostty helper input/output queues become bounded, snapshots are capped, and bracketed-paste markers are detected opportunistically while preserving remote application state.

**Tech Stack:** Rust 2024, Tokio async I/O, nix `AsyncFd` PTYs, cargo-nextest, Portl `AttachDisplay`, Portl session/Ghostty provider modules.

---

## File structure

- Modify `crates/portl-agent/src/shell_handler/pty_master.rs`
  - Add a reusable `PendingPtyWrite` queue for bounded, partial PTY writes.
  - Refactor `pty_master_task()` so PTY output reads continue while input is pending.
  - Add unit tests for queue accounting and cancellation semantics that do not require a real PTY.
- Modify `crates/portl-agent/src/session_handler/tmux_control.rs`
  - Reuse `PendingPtyWrite` for tmux control PTY writes after encoding input as tmux commands.
  - Add/extend tests for pending tmux writes and detach handling.
- Modify `crates/portl-agent/src/session_handler/ghostty.rs`
  - Use bounded helper command/input channels.
  - Replace inline `write_pty_all()` in `run_helper()` with full-duplex pending writes.
  - Bound subscriber output queues and disconnect slow subscribers.
  - Cap attach snapshots under `MAX_FRAME_BYTES`.
  - Add Ghostty helper tests for large input and large history attach.
- Modify `crates/portl-cli/src/commands/session.rs`
  - Add `PasteState`, bracketed-paste scanner, and an attach input pump around stdin forwarding.
  - Show progressive floating status via existing `AttachDisplay`.
  - Let `Esc` cancel pending paste input while paste mode is active.
  - Add `Ctrl+\` then `c` cancel-paste control action.
  - Add unit tests for paste state and bracketed paste behavior.
- Modify `crates/portl-core/src/attach_control.rs`
  - Extend status/control bar rendering helpers if needed for cancel-paste text.
  - Add rendering tests if the visible text changes.

## Task 1: Add bounded pending PTY write primitive

**Files:**
- Modify: `crates/portl-agent/src/shell_handler/pty_master.rs`

- [ ] **Step 1: Add failing unit tests for pending write accounting**

Add these tests in `crates/portl-agent/src/shell_handler/pty_master.rs` under the existing test module:

```rust
#[test]
fn pending_pty_write_tracks_bytes_and_partial_progress() {
    let mut pending = PendingPtyWrite::new(16);

    assert_eq!(pending.pending_bytes(), 0);
    assert!(pending.push(b"abcdef".to_vec()).is_ok());
    assert!(pending.push(b"gh".to_vec()).is_ok());
    assert_eq!(pending.pending_bytes(), 8);
    assert_eq!(pending.front_chunk(), Some(&b"abcdef"[..]));

    pending.consume(2);
    assert_eq!(pending.front_chunk(), Some(&b"cdef"[..]));
    assert_eq!(pending.pending_bytes(), 6);

    pending.consume(4);
    assert_eq!(pending.front_chunk(), Some(&b"gh"[..]));
    pending.consume(2);
    assert!(pending.is_empty());
    assert_eq!(pending.pending_bytes(), 0);
}

#[test]
fn pending_pty_write_rejects_over_capacity_and_clears() {
    let mut pending = PendingPtyWrite::new(8);

    assert!(pending.push(b"12345678".to_vec()).is_ok());
    let err = pending.push(b"9".to_vec()).expect_err("queue should be full");
    assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
    assert_eq!(pending.clear(), 8);
    assert!(pending.is_empty());
}
```

- [ ] **Step 2: Run the tests and verify they fail**

Run:

```bash
cargo nextest run -p portl-agent -E 'kind(lib) & (test(pending_pty_write_tracks_bytes_and_partial_progress) + test(pending_pty_write_rejects_over_capacity_and_clears))'
```

Expected: compile failure because `PendingPtyWrite` does not exist.

- [ ] **Step 3: Implement `PendingPtyWrite`**

Add this near the top of `pty_master.rs`, after imports:

```rust
#[cfg(unix)]
pub(crate) const DEFAULT_PTY_INPUT_QUEUE_BYTES: usize = 1024 * 1024;

#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct PendingPtyWrite {
    chunks: std::collections::VecDeque<Vec<u8>>,
    front_offset: usize,
    pending_bytes: usize,
    max_bytes: usize,
}

#[cfg(unix)]
impl PendingPtyWrite {
    pub(crate) fn new(max_bytes: usize) -> Self {
        Self {
            chunks: std::collections::VecDeque::new(),
            front_offset: 0,
            pending_bytes: 0,
            max_bytes,
        }
    }

    pub(crate) fn push(&mut self, bytes: Vec<u8>) -> std::io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        if self.pending_bytes.saturating_add(bytes.len()) > self.max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "pty input queue is full",
            ));
        }
        self.pending_bytes += bytes.len();
        self.chunks.push_back(bytes);
        Ok(())
    }

    pub(crate) fn front_chunk(&self) -> Option<&[u8]> {
        self.chunks
            .front()
            .map(|chunk| &chunk[self.front_offset..])
            .filter(|chunk| !chunk.is_empty())
    }

    pub(crate) fn consume(&mut self, mut written: usize) {
        written = written.min(self.pending_bytes);
        self.pending_bytes -= written;
        while written > 0 {
            let Some(front) = self.chunks.front() else {
                self.front_offset = 0;
                return;
            };
            let remaining_front = front.len() - self.front_offset;
            if written < remaining_front {
                self.front_offset += written;
                return;
            }
            written -= remaining_front;
            self.chunks.pop_front();
            self.front_offset = 0;
        }
    }

    pub(crate) fn clear(&mut self) -> usize {
        let dropped = self.pending_bytes;
        self.chunks.clear();
        self.front_offset = 0;
        self.pending_bytes = 0;
        dropped
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pending_bytes == 0
    }

    pub(crate) fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }
}
```

- [ ] **Step 4: Run the tests and verify they pass**

Run the same nextest command from Step 2. Expected: both tests pass.

- [ ] **Step 5: Commit Task 1**

```bash
git add crates/portl-agent/src/shell_handler/pty_master.rs
git commit -m "Add bounded PTY input queue" -m "Introduce a reusable pending PTY write buffer with byte accounting and capacity checks so later attach pumps can avoid unbounded paste buffering."
```

## Task 2: Refactor generic PTY pump to stay full-duplex

**Files:**
- Modify: `crates/portl-agent/src/shell_handler/pty_master.rs`

- [ ] **Step 1: Add a regression test for large echoing PTY input**

Add this test in `pty_master.rs` test module:

```rust
#[cfg(unix)]
#[tokio::test]
async fn pty_master_echoes_large_input_without_deadlock() {
    let mut harness = spawn_pty_task_harness(&["-c", "cat"], Duration::from_secs(2));
    let input = vec![b'x'; 256 * 1024];

    harness
        .stdin_tx
        .send(crate::shell_registry::StdinMessage::Data(input.clone()))
        .await
        .expect("send large input");

    let mut observed = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while observed.len() < input.len() {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .expect("timed out waiting for echoed input");
        let chunk = tokio::time::timeout(remaining, harness.stdout_rx.recv())
            .await
            .expect("wait for pty output")
            .expect("pty output channel open");
        observed.extend_from_slice(&chunk);
    }

    assert!(observed.windows(4096).any(|window| window == &input[..4096]));
    harness
        .pty_tx
        .send(PtyCommand::Close { force: true })
        .expect("queue pty close");
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(harness.child_pid),
        nix::sys::signal::Signal::SIGKILL,
    );
}
```

Make `stdin_tx` visible in `PtyTaskHarness` by adding this field:

```rust
stdin_tx: mpsc::Sender<StdinMessage>,
```

and populate it in `spawn_pty_task_harness()`.

- [ ] **Step 2: Run the regression test**

Run:

```bash
cargo nextest run -p portl-agent -E 'kind(lib) & test(pty_master_echoes_large_input_without_deadlock)'
```

Expected before the refactor: the test may time out or fail to compile until the harness exposes `stdin_tx`.

- [ ] **Step 3: Refactor `pty_master_task()` to use pending writes**

Replace direct `write_pty_all()` calls in `pty_master_task()` with a pending queue. The main shape should be:

```rust
let mut pending_input = PendingPtyWrite::new(DEFAULT_PTY_INPUT_QUEUE_BYTES);

tokio::select! {
    biased;
    Some(cmd) = pty_rx.recv() => { /* existing resize/close behavior */ }
    Some(message) = stdin_rx.recv(), if stdin_open && drain_deadline.is_none() => {
        match message {
            StdinMessage::Data(bytes) => pending_input.push(bytes).context("queue pty stdin")?,
            StdinMessage::Close => stdin_open = false,
        }
    }
    () = wait_pty_writable(&master), if !pending_input.is_empty() && drain_deadline.is_none() => {
        write_one_pending_pty_chunk(&master, &mut pending_input)
            .await
            .context("write queued pty stdin")?;
    }
    () = drain_sleep => return Ok(()),
    chunk = read_pty_chunk(&master, &mut read_buf) => { /* existing output path */ }
    else => return Ok(()),
}
```

Add helpers in `pty_master.rs`:

```rust
#[cfg(unix)]
async fn wait_pty_writable(master: &AsyncFd<OwnedFd>) -> std::io::Result<()> {
    let mut guard = master.writable().await?;
    guard.clear_ready();
    Ok(())
}

#[cfg(unix)]
pub(crate) async fn write_one_pending_pty_chunk(
    master: &AsyncFd<OwnedFd>,
    pending: &mut PendingPtyWrite,
) -> std::io::Result<()> {
    let Some(bytes) = pending.front_chunk() else {
        return Ok(());
    };
    let mut guard = master.writable().await?;
    match nix::unistd::write(master.get_ref(), bytes) {
        Ok(0) => Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "pty write returned zero bytes",
        )),
        Ok(written) => {
            pending.consume(written);
            Ok(())
        }
        Err(nix::errno::Errno::EAGAIN) => {
            guard.clear_ready();
            Ok(())
        }
        Err(err) => Err(std::io::Error::from(err)),
    }
}
```

- [ ] **Step 4: Run focused PTY tests**

Run:

```bash
cargo nextest run -p portl-agent -E 'kind(lib) & test(pty_master_)'
```

Expected: all `pty_master_` tests pass.

- [ ] **Step 5: Commit Task 2**

```bash
git add crates/portl-agent/src/shell_handler/pty_master.rs
git commit -m "Keep PTY input pumping full duplex" -m "Queue PTY stdin writes and write them opportunistically so large pastes cannot starve PTY output reads."
```

## Task 3: Apply full-duplex PTY writes to tmux control attach

**Files:**
- Modify: `crates/portl-agent/src/session_handler/tmux_control.rs`

- [ ] **Step 1: Add/update test coverage for queued tmux input**

Add a unit test that validates tmux input is encoded before queuing:

```rust
#[test]
fn tmux_pending_input_queues_encoded_send_keys_command() {
    let mut pending = crate::shell_handler::pty_master::PendingPtyWrite::new(1024);
    pending
        .push(tmux_cc::send_keys_command(b"hello"))
        .expect("queue tmux command");
    let queued = pending.front_chunk().expect("queued command");
    assert!(String::from_utf8_lossy(queued).contains("send-keys"));
}
```

- [ ] **Step 2: Run the tmux-control test**

Run:

```bash
cargo nextest run -p portl-agent -E 'kind(lib) & test(tmux_pending_input_queues_encoded_send_keys_command)'
```

Expected: compile failure until `PendingPtyWrite` is visible from `tmux_control.rs`.

- [ ] **Step 3: Refactor `pump_tmux_cc_pty()`**

Import the shared helpers:

```rust
use crate::shell_handler::pty_master::{
    DEFAULT_PTY_INPUT_QUEUE_BYTES, PendingPtyWrite, read_pty_chunk, set_nonblocking,
    write_one_pending_pty_chunk, write_pty_all,
};
```

Create `let mut pending_input = PendingPtyWrite::new(DEFAULT_PTY_INPUT_QUEUE_BYTES);` and replace direct `write_pty_all(&master, &tmux_cc::send_keys_command(&data)).await` with:

```rust
pending_input
    .push(tmux_cc::send_keys_command(&data))
    .context("queue tmux -CC input")?;
```

Add a writable branch before the read branch:

```rust
() = async {
    write_one_pending_pty_chunk(&master, &mut pending_input).await
}, if !pending_input.is_empty() && drain_deadline.is_none() => {
    // helper already wrote one chunk or observed EAGAIN
}
```

Keep detach and resize commands using `write_pty_all()` because they are small control commands that must be sent immediately.

- [ ] **Step 4: Run tmux control tests**

Run:

```bash
cargo nextest run -p portl-agent -E 'kind(lib) & test(session_handler::tmux_control::tests::)'
```

Expected: pass.

- [ ] **Step 5: Commit Task 3**

```bash
git add crates/portl-agent/src/session_handler/tmux_control.rs
git commit -m "Queue tmux attach input writes" -m "Route tmux control-mode stdin through the shared pending PTY write queue so large pastes do not block output decoding."
```

## Task 4: Fix Ghostty helper backpressure and snapshot limits

**Files:**
- Modify: `crates/portl-agent/src/session_handler/ghostty.rs`

- [ ] **Step 1: Add Ghostty regression tests**

Add tests to the existing Ghostty test module:

```rust
#[tokio::test]
async fn helper_attach_handles_large_echoing_input() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let registry = GhosttyRegistry::with_roots(temp.path().join("run"), temp.path().join("state"));
    let paths = registry.paths_for("large-cat");
    let helper = GhosttyHelperConfig::for_test("large-cat", paths.clone(), vec!["/bin/cat".to_owned()]);
    let task = spawn_helper_thread(helper);
    wait_for_socket(&paths.socket_path, Duration::from_secs(2)).await?;

    let mut attach = GhosttyClient::connect(paths.socket_path.clone()).await?.attach(80, 24).await?;
    let input = vec![b'a'; 256 * 1024];
    attach.input(input).await?;
    let output = attach.read_until_contains("aaaaaaaaaaaaaaaa", Duration::from_secs(5)).await?;
    assert!(output.contains("aaaaaaaaaaaaaaaa"));

    GhosttyClient::connect(paths.socket_path.clone()).await?.kill().await?;
    task.join().expect("helper thread").context("helper result")?;
    Ok(())
}

#[test]
fn capped_snapshot_stays_below_frame_limit() {
    let mut history = VecDeque::new();
    append_bounded(&mut history, &vec![b'x'; MAX_FRAME_BYTES + 1024]);
    let snapshot = capped_attach_snapshot(&history);
    assert!(snapshot.len() < MAX_FRAME_BYTES);
    assert!(snapshot.iter().all(|byte| *byte == b'x'));
}
```

- [ ] **Step 2: Run Ghostty tests**

Run:

```bash
cargo nextest run -p portl-agent --features ghostty-vt -E 'kind(lib) & (test(helper_attach_handles_large_echoing_input) + test(capped_snapshot_stays_below_frame_limit))'
```

Expected: compile failure for `capped_attach_snapshot`; large input may fail or time out before the implementation.

- [ ] **Step 3: Add bounded constants and capped snapshot helper**

Add near Ghostty constants:

```rust
#[cfg(unix)]
const GHOSTTY_HELPER_COMMANDS: usize = 64;
#[cfg(unix)]
const GHOSTTY_SUBSCRIBER_BUFFER: usize = 64;
#[cfg(unix)]
const MAX_ATTACH_SNAPSHOT_BYTES: usize = MAX_FRAME_BYTES / 2;
```

Add helper:

```rust
#[cfg(unix)]
fn capped_attach_snapshot(history: &VecDeque<u8>) -> Vec<u8> {
    let len = history.len().min(MAX_ATTACH_SNAPSHOT_BYTES);
    history.iter().skip(history.len().saturating_sub(len)).copied().collect()
}
```

Use it in `HelperCommand::Subscribe` instead of collecting the full history.

- [ ] **Step 4: Bound helper command and subscriber channels**

Change helper command channel from unbounded to bounded:

```rust
let (cmd_tx, mut cmd_rx) = mpsc::channel(GHOSTTY_HELPER_COMMANDS);
```

Change all `tx.send(...)` calls in `handle_client()` to `tx.send(...).await` and keep the same error mapping:

```rust
tx.send(HelperCommand::Input(bytes))
    .await
    .map_err(|_| anyhow!("ghostty helper stopped"))?;
```

Change `HelperCommand::Subscribe` reply type to return `mpsc::Receiver<Vec<u8>>`. In subscribe handling, create bounded subscriber channels:

```rust
let (tx, rx) = mpsc::channel(GHOSTTY_SUBSCRIBER_BUFFER);
subscribers.push(tx);
let snapshot = capped_attach_snapshot(&history);
```

Update `broadcast` to drop slow subscribers with `try_send`:

```rust
fn broadcast(subscribers: &mut Vec<mpsc::Sender<Vec<u8>>>, bytes: &[u8]) {
    subscribers.retain(|subscriber| subscriber.try_send(bytes.to_vec()).is_ok());
}
```

- [ ] **Step 5: Refactor Ghostty helper PTY writes**

In `run_helper()`, import/use:

```rust
use crate::shell_handler::pty_master::{
    DEFAULT_PTY_INPUT_QUEUE_BYTES, PendingPtyWrite, write_one_pending_pty_chunk,
};
```

Create `let mut pending_input = PendingPtyWrite::new(DEFAULT_PTY_INPUT_QUEUE_BYTES);` before the loop.

Replace:

```rust
HelperCommand::Input(bytes) => {
    crate::shell_handler::pty_master::write_pty_all(&master, &bytes).await.context("write ghostty pty input")?;
}
```

with:

```rust
HelperCommand::Input(bytes) => {
    pending_input.push(bytes).context("queue ghostty pty input")?;
}
```

Add a writable branch in the helper loop:

```rust
() = async {
    write_one_pending_pty_chunk(&master, &mut pending_input).await
}, if !pending_input.is_empty() => {}
```

- [ ] **Step 6: Run Ghostty focused tests**

Run:

```bash
cargo nextest run -p portl-agent --features ghostty-vt -E 'kind(lib) & test(session_handler::ghostty::tests::)'
```

Expected: pass.

- [ ] **Step 7: Commit Task 4**

```bash
git add crates/portl-agent/src/session_handler/ghostty.rs
git commit -m "Backpressure Ghostty helper input" -m "Make Ghostty helper queues bounded, cap attach snapshots, and keep PTY output draining while large input is pending."
```

## Task 5: Add local paste state, UI, and cancellation

**Files:**
- Modify: `crates/portl-cli/src/commands/session.rs`
- Modify: `crates/portl-core/src/attach_control.rs` if bar text helpers need adjustment

- [ ] **Step 1: Add paste state tests**

Add tests in `session.rs` test module:

```rust
#[test]
fn paste_state_enters_on_large_burst_and_cancels_pending() {
    let mut state = PasteState::new(PasteConfig::for_test(16, Duration::from_secs(1)));
    state.observe_read(32, Instant::now());
    assert!(state.is_active());
    state.observe_queued(32);
    assert_eq!(state.pending_bytes(), 32);
    assert_eq!(state.cancel_pending(), 32);
    assert_eq!(state.pending_bytes(), 0);
}

#[test]
fn bracketed_paste_scanner_detects_begin_and_end_across_chunks() {
    let mut scanner = BracketedPasteScanner::default();
    assert_eq!(scanner.scan(b"abc\x1b[200"), BracketedPasteEvent::None);
    assert_eq!(scanner.scan(b"~payload"), BracketedPasteEvent::Begin);
    assert!(scanner.in_bracketed_paste());
    assert_eq!(scanner.scan(b"more\x1b[201~"), BracketedPasteEvent::End);
    assert!(!scanner.in_bracketed_paste());
}
```

- [ ] **Step 2: Run paste state tests**

Run:

```bash
cargo nextest run -p portl-cli -E 'kind(lib) & (test(paste_state_enters_on_large_burst_and_cancels_pending) + test(bracketed_paste_scanner_detects_begin_and_end_across_chunks))'
```

Expected: compile failure because paste types do not exist.

- [ ] **Step 3: Add paste state types**

Add near stdin-loop types in `session.rs`:

```rust
#[derive(Debug, Clone, Copy)]
struct PasteConfig {
    burst_threshold_bytes: usize,
    burst_window: Duration,
    detail_after: Duration,
}

impl PasteConfig {
    fn default() -> Self {
        Self {
            burst_threshold_bytes: 64 * 1024,
            burst_window: Duration::from_millis(250),
            detail_after: Duration::from_secs(2),
        }
    }

    #[cfg(test)]
    fn for_test(burst_threshold_bytes: usize, burst_window: Duration) -> Self {
        Self { burst_threshold_bytes, burst_window, detail_after: Duration::from_millis(10) }
    }
}

#[derive(Debug)]
struct PasteState {
    config: PasteConfig,
    active: bool,
    burst_start: Option<Instant>,
    burst_bytes: usize,
    read_bytes: usize,
    sent_bytes: usize,
    pending_bytes: usize,
    backpressured: bool,
    active_since: Option<Instant>,
}

impl PasteState {
    fn new(config: PasteConfig) -> Self { /* initialize fields to zero/false/None */ }
    fn is_active(&self) -> bool { self.active }
    fn pending_bytes(&self) -> usize { self.pending_bytes }
    fn observe_read(&mut self, bytes: usize, now: Instant) { /* update burst and activate */ }
    fn observe_sent(&mut self, bytes: usize) { self.sent_bytes += bytes; self.pending_bytes = self.pending_bytes.saturating_sub(bytes); }
    fn observe_queued(&mut self, bytes: usize) { self.pending_bytes += bytes; self.active = true; self.active_since.get_or_insert_with(Instant::now); }
    fn set_backpressured(&mut self, value: bool) { self.backpressured = value; if value { self.active = true; self.active_since.get_or_insert_with(Instant::now); } }
    fn cancel_pending(&mut self) -> usize { let dropped = self.pending_bytes; self.pending_bytes = 0; self.backpressured = false; dropped }
    fn should_show_detail(&self, now: Instant) -> bool { self.active_since.is_some_and(|started| now.duration_since(started) >= self.config.detail_after) }
}
```

Implement `new()` and `observe_read()` fully, with burst activation when bytes in the current burst exceed `burst_threshold_bytes` within `burst_window`.

- [ ] **Step 4: Add bracketed-paste scanner**

Add:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BracketedPasteEvent { None, Begin, End }

#[derive(Debug, Default)]
struct BracketedPasteScanner {
    tail: Vec<u8>,
    in_paste: bool,
}

impl BracketedPasteScanner {
    fn in_bracketed_paste(&self) -> bool { self.in_paste }
    fn scan(&mut self, bytes: &[u8]) -> BracketedPasteEvent {
        const BEGIN: &[u8] = b"\x1b[200~";
        const END: &[u8] = b"\x1b[201~";
        let mut combined = self.tail.clone();
        combined.extend_from_slice(bytes);
        let event = if combined.windows(BEGIN.len()).any(|w| w == BEGIN) {
            self.in_paste = true;
            BracketedPasteEvent::Begin
        } else if combined.windows(END.len()).any(|w| w == END) {
            self.in_paste = false;
            BracketedPasteEvent::End
        } else {
            BracketedPasteEvent::None
        };
        let keep = BEGIN.len().max(END.len()).saturating_sub(1);
        self.tail = combined[combined.len().saturating_sub(keep)..].to_vec();
        event
    }
}
```

- [ ] **Step 5: Integrate state into `stdin_loop()`**

Inside `stdin_loop()`, instantiate:

```rust
let mut paste = PasteState::new(PasteConfig::default());
let mut bracketed = BracketedPasteScanner::default();
```

On each read:

```rust
let now = Instant::now();
paste.observe_read(read, now);
match bracketed.scan(chunk) {
    BracketedPasteEvent::Begin => paste.set_backpressured(false),
    BracketedPasteEvent::End => {}
    BracketedPasteEvent::None => {}
}
```

When `paste.is_active()` and `chunk == b"\x1b"`, call `paste.cancel_pending()`, update the bar, and do not forward that `Esc` byte.

Before sending a normal chunk, call `paste.observe_queued(chunk.len())`; after `send_stdin` succeeds, call `paste.observe_sent(chunk.len())`. If the send takes longer than a small threshold, mark backpressure:

```rust
let send_started = Instant::now();
let send_result = sink.send_stdin(chunk).await;
paste.set_backpressured(send_started.elapsed() >= Duration::from_millis(100));
```

Render/clear the paste bar with helper functions that call `ui.display.set_bar(...)` and `ui.display.clear_bar().await`.

- [ ] **Step 6: Add cancel-paste to control mode**

Extend `AttachControlOutcome`:

```rust
enum AttachControlOutcome {
    Continue,
    Detached,
    CancelPaste,
}
```

In `run_attach_control_mode()`, when command is `b"c"`, return `CancelPaste`. In `stdin_loop()`, handle it by dropping pending paste input and continuing.

Update bar text to include `c cancel paste` when paste mode is active.

- [ ] **Step 7: Run CLI focused tests**

Run:

```bash
cargo nextest run -p portl-cli -E 'kind(lib) & (test(paste_state_) + test(bracketed_paste_))'
```

Expected: pass.

- [ ] **Step 8: Commit Task 5**

```bash
git add crates/portl-cli/src/commands/session.rs crates/portl-core/src/attach_control.rs
git commit -m "Show cancellable paste progress" -m "Detect large or bracketed paste input, show progressive attach status, and let users drop pending Portl input without interrupting the remote session."
```

## Task 6: Validate focused behavior and OrbStack smoke path

**Files:**
- Modify only if tests reveal bugs.

- [ ] **Step 1: Format**

Run:

```bash
cargo fmt --all
```

Expected: no errors.

- [ ] **Step 2: Run focused nextest suites**

Run:

```bash
cargo nextest run -p portl-agent -E 'kind(lib) & (test(pty_master_) + test(session_handler::tmux_control::tests::))'
cargo nextest run -p portl-agent --features ghostty-vt -E 'kind(lib) & test(session_handler::ghostty::tests::)'
cargo nextest run -p portl-cli -E 'kind(lib) & (test(paste_state_) + test(bracketed_paste_) + test(attach_control_bar_))'
```

Expected: pass.

- [ ] **Step 3: Run project local verification**

Run:

```bash
cargo nextest run -p portl-cli -E 'kind(lib)'
cargo nextest run -p portl-core -E 'kind(lib)'
cargo nextest run -p portl-agent -E 'kind(lib)'
cargo clippy -p portl-cli -p portl-agent -p portl-core --all-targets --all-features -- -D warnings
```

Expected: pass.

- [ ] **Step 4: Validate through OrbStack**

Run the repository's Docker/OrbStack smoke path. If no dedicated task exists, use Docker against the OrbStack engine:

```bash
docker info | grep -i orbstack
docker build -f adapters/docker-portl/Dockerfile -t portl-large-paste-test .
docker run --rm portl-large-paste-test portl --version
```

Expected: Docker reports OrbStack, image builds, and `portl --version` exits successfully.

- [ ] **Step 5: Commit any validation fixes**

If validation required code fixes, commit them with a focused message. If no fixes were needed, do not create an empty commit.

## Task 7: Parallel post-implementation review

**Files:**
- No direct edits unless reviewers find issues.

- [ ] **Step 1: Dispatch parallel reviewers**

Ask reviewers to inspect the diff from the branch base to HEAD with these focuses:

1. Ghostty/helper deadlock and memory bounds.
2. Local paste UX/cancellation/bracketed-paste correctness.
3. PTY/tmux regression and test coverage.

- [ ] **Step 2: Triage feedback**

Classify each issue as Critical, High, Medium, Low, or Not a bug. Fix Critical/High/Medium issues before merging. Document Low issues in `scratch/large-paste-followups.md` if not fixed.

- [ ] **Step 3: Commit review fixes**

Commit each logical fix separately, for example:

```bash
git add crates/portl-agent/src/shell_handler/pty_master.rs \
  crates/portl-agent/src/session_handler/tmux_control.rs \
  crates/portl-agent/src/session_handler/ghostty.rs \
  crates/portl-cli/src/commands/session.rs \
  crates/portl-core/src/attach_control.rs
git commit -m "Fix paste cancellation edge case" -m "Address review feedback by ensuring pending bracketed paste is closed before dropping queued payload bytes."
```

## Task 8: Merge, release, and tag patch version

**Files:**
- Modify: `CHANGELOG.md`
- Modify version files touched by `mise run release:prep`

- [ ] **Step 1: Merge worktree branch back to main**

From the main checkout, ensure unrelated changes are not mixed into the merge. Merge only the completed feature branch:

```bash
git checkout main
git merge --no-ff large-paste-attach-ux
```

- [ ] **Step 2: Prepare patch release**

Use the `portl-release` skill. Starting from `v0.8.1`, the expected patch version is `0.8.2` unless another release already exists.

Run:

```bash
git status --short --branch
git log --oneline --decorate -5
git describe --tags --abbrev=0
```

- [ ] **Step 3: Update changelog with user-facing notes**

Add an Unreleased entry or run:

```bash
mise run release:changelog:draft -- 0.8.2
```

Rewrite notes into user-facing bullets mentioning:

- Large interactive pastes in attach sessions now show progress and can be cancelled before pending input is delivered.
- Ghostty-backed sessions are more robust under large paste/output backpressure.
- Bracketed paste is preserved and used as a paste detection signal when present.

- [ ] **Step 4: Run release prep and verification**

Run:

```bash
mise run release:prep -- 0.8.2
mise run release:verify -- 0.8.2 --local
```

Expected: verification passes.

- [ ] **Step 5: Commit release bump**

```bash
git add -A
git commit -m "Release v0.8.2" -m "Bump Portl to v0.8.2 after adding cancellable large-paste attach flow control and Ghostty backpressure fixes."
```

- [ ] **Step 6: Push, watch CI, tag, and watch release**

Run:

```bash
git push origin main
mise run release:watch -- 0.8.2 --ci-only
mise run release:tag -- 0.8.2
mise run release:watch -- 0.8.2
```

Expected: CI and release workflows succeed.
