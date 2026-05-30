# Portl Herdr Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an end-to-end `portl attach TARGET/herdr[/SESSION]` path that launches local `herdr client`, bootstraps remote `herdr remote-client-bridge`, and routes Herdr protocol frames over Portl/Iroh lanes.

**Architecture:** Reuse `portl/session/v1` authentication and attach setup, add a Herdr provider and Herdr-specific session substreams, and keep Herdr UI/server lifecycle inside the Herdr CLI. Portl owns only target resolution, temporary local Unix socket, remote bridge spawn, frame parsing/classification, and lane routing.

**Tech Stack:** Rust 2024, tokio Unix sockets/processes, iroh streams, postcard for Portl session frames, bincode v2 serde for Herdr frames, cargo nextest filtersets.

---

## File Structure

- Modify `Cargo.toml`: add workspace `bincode = { version = "2", features = ["serde"] }`.
- Modify `crates/portl-core/Cargo.toml`: depend on workspace `bincode`.
- Create `crates/portl-core/src/herdr_wire.rs`: Herdr v11 frame structs, frame reader/writer helpers, and lane classifier.
- Modify `crates/portl-core/src/lib.rs`: expose `herdr_wire`.
- Modify `crates/portl-core/src/wire/session.rs`: add Herdr stream kinds and provider capabilities.
- Create `crates/portl-core/src/net/herdr_client.rs`: open Herdr attach, Herdr substreams, and local-side bridge helpers usable by the CLI.
- Modify `crates/portl-core/src/net/mod.rs`: export Herdr client helpers.
- Modify `crates/portl-agent/src/session_handler/provider.rs`: add `HerdrProvider` discovery, probe, list, capabilities, and tests.
- Create `crates/portl-agent/src/session_handler/herdr.rs`: remote Herdr attach process lifecycle, registry entry, frame pumps, and substream handlers.
- Modify `crates/portl-agent/src/session_handler/mod.rs`: select Herdr provider, serve Herdr attach, dispatch Herdr substreams.
- Modify `crates/portl-agent/src/lib.rs`: add Herdr attach registry state if needed.
- Modify `crates/portl-agent/src/config.rs`: add `herdr` to provider values and `PORTL_HERDR_PATH` handling.
- Modify `crates/portl-cli/src/commands/session.rs`: parse Herdr shorthand refs and run local Herdr attach path instead of Portl terminal attach path.
- Modify `crates/portl-cli/src/lib.rs`: help text includes Herdr provider and `PORTL_HERDR_PATH`.
- Modify `crates/portl-agent/tests/session_e2e.rs`: fake Herdr bridge integration tests.

## Task 1: Add Herdr wire model and classifier

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/portl-core/Cargo.toml`
- Create: `crates/portl-core/src/herdr_wire.rs`
- Modify: `crates/portl-core/src/lib.rs`

- [ ] **Step 1: Write failing classifier/framing tests**

Add `crates/portl-core/src/herdr_wire.rs` with tests first. The initial file should compile-fail or test-fail because implementation is absent; include these tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_client_messages_into_priority_lanes() {
        assert_eq!(client_lane(&ClientMessage::Hello {
            version: HERDR_PROTOCOL_VERSION,
            cols: 80,
            rows: 24,
            cell_width_px: 0,
            cell_height_px: 0,
            requested_encoding: RenderEncoding::SemanticFrame,
            keybindings: ClientKeybindings::Server,
        }), ClientLane::Control);
        assert_eq!(client_lane(&ClientMessage::Input { data: b"x".to_vec() }), ClientLane::Input);
        assert_eq!(client_lane(&ClientMessage::Resize {
            cols: 100,
            rows: 40,
            cell_width_px: 0,
            cell_height_px: 0,
        }), ClientLane::Resize);
        assert_eq!(client_lane(&ClientMessage::ClipboardImage {
            extension: "png".to_owned(),
            data: vec![1, 2, 3],
        }), ClientLane::Bulk);
        assert_eq!(client_lane(&ClientMessage::Detach), ClientLane::Control);
    }

    #[test]
    fn classifies_server_messages_into_priority_lanes() {
        assert_eq!(server_lane(&ServerMessage::Welcome {
            version: HERDR_PROTOCOL_VERSION,
            encoding: RenderEncoding::SemanticFrame,
            error: None,
        }), ServerLane::Control);
        assert_eq!(server_lane(&ServerMessage::Frame(FrameData::empty_for_test(80, 24))), ServerLane::Render);
        assert_eq!(server_lane(&ServerMessage::Terminal(TerminalFrame {
            seq: 1,
            width: 80,
            height: 24,
            full: true,
            bytes: b"redraw".to_vec(),
        })), ServerLane::Render);
        assert_eq!(server_lane(&ServerMessage::Graphics { bytes: vec![1, 2] }), ServerLane::Bulk);
        assert_eq!(server_lane(&ServerMessage::Clipboard { data: "abc".to_owned() }), ServerLane::Bulk);
        assert_eq!(server_lane(&ServerMessage::MouseCapture { enabled: true }), ServerLane::Control);
    }

    #[test]
    fn raw_frame_roundtrips_with_bincode_v2_length_prefix() {
        let msg = ClientMessage::Input { data: b"hello".to_vec() };
        let raw = RawHerdrFrame::encode_client(&msg).expect("encode");
        assert_eq!(raw.direction(), FrameDirection::ClientToServer);
        assert_eq!(raw.client_lane().expect("lane"), ClientLane::Input);
        assert_eq!(raw.decode_client().expect("decode"), msg);
    }

    #[test]
    fn oversized_frame_is_rejected_before_allocation() {
        let bytes = ((MAX_FRAME_SIZE as u32) + 1).to_le_bytes().to_vec();
        let err = RawHerdrFrame::decode_client_from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, HerdrFrameError::Oversized { .. }));
    }
}
```

- [ ] **Step 2: Run tests and verify RED**

Run:

```bash
cargo nextest run -p portl-core -E 'kind(lib) & test(herdr_wire::tests::)'
```

Expected: FAIL/compile error because Herdr wire types and helpers are not implemented yet.

- [ ] **Step 3: Add minimal Herdr v11 model**

Implement `crates/portl-core/src/herdr_wire.rs` with:

```rust
pub const HERDR_PROTOCOL_VERSION: u32 = 11;
pub const MAX_FRAME_SIZE: usize = 2 * 1024 * 1024;
pub const MAX_GRAPHICS_FRAME_SIZE: usize = 32 * 1024 * 1024;
pub const MAX_CLIPBOARD_IMAGE_PAYLOAD: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameDirection { ClientToServer, ServerToClient }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientLane { Control, Input, Resize, Bulk }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerLane { Control, Render, Bulk }
```

Copy the Herdr v11 wire structs/enums needed for serde decode/classification:

```rust
RenderEncoding, ClientKeybindings, ClientMessage, AttachScrollDirection,
AttachScrollSource, CellData, CursorState, FrameData, TerminalFrame,
NotifyKind, ServerMessage
```

Add `FrameData::empty_for_test(width, height)` behind `#[cfg(test)]`.

Implement `RawHerdrFrame` as full framed bytes, preserving original bytes:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHerdrFrame {
    direction: FrameDirection,
    framed: Vec<u8>,
}
```

Methods:

```rust
encode_client, encode_server, decode_client, decode_server,
decode_client_from_bytes, decode_server_from_bytes, framed_bytes,
client_lane, server_lane, direction
```

- [ ] **Step 4: Add dependencies and export module**

Add to workspace `Cargo.toml`:

```toml
bincode = { version = "2", features = ["serde"] }
```

Add to `crates/portl-core/Cargo.toml`:

```toml
bincode.workspace = true
```

Add to `crates/portl-core/src/lib.rs`:

```rust
pub mod herdr_wire;
```

- [ ] **Step 5: Run GREEN**

Run:

```bash
cargo nextest run -p portl-core -E 'kind(lib) & test(herdr_wire::tests::)'
```

Expected: PASS.

- [ ] **Step 6: Commit**

Commit message:

```bash
git add Cargo.toml Cargo.lock crates/portl-core/Cargo.toml crates/portl-core/src/lib.rs crates/portl-core/src/herdr_wire.rs
git commit -m "Add Herdr wire frame classifier" -m "Add a minimal Herdr protocol v11 model to classify length-prefixed bincode frames into Portl transport lanes without reimplementing Herdr rendering or UI behavior."
```

## Task 2: Extend Portl session wire for Herdr lanes

**Files:**
- Modify: `crates/portl-core/src/wire/session.rs`
- Modify: `crates/portl-core/src/net/session_client.rs`

- [ ] **Step 1: Write failing session wire tests**

In `crates/portl-core/src/wire/session.rs`, add tests:

```rust
#[test]
fn herdr_capabilities_match_external_protocol_provider_contract() {
    assert_eq!(ProviderCapabilities::herdr(), ProviderCapabilities {
        persistent: true,
        multi_attach: true,
        create_on_attach: true,
        attach_command: true,
        run: false,
        detached_run: false,
        history: false,
        tail: false,
        kill: false,
        terminal_state_restore: true,
        external_direct_attach: true,
        exact_argv_spawn: false,
    });
}

#[test]
fn herdr_stream_kinds_roundtrip_via_postcard() {
    let kinds = [
        SessionStreamKind::HerdrClientControl,
        SessionStreamKind::HerdrClientInput,
        SessionStreamKind::HerdrClientResize,
        SessionStreamKind::HerdrClientBulk,
        SessionStreamKind::HerdrServerControl,
        SessionStreamKind::HerdrServerRender,
        SessionStreamKind::HerdrServerBulk,
    ];
    for kind in kinds {
        let tail = SessionSubTail { session_id: [9; 16], kind };
        let encoded = postcard::to_stdvec(&tail).expect("encode");
        let decoded: SessionSubTail = postcard::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, tail);
    }
}
```

- [ ] **Step 2: Verify RED**

Run:

```bash
cargo nextest run -p portl-core -E 'kind(lib) & test(herdr_)'
```

Expected: FAIL because `ProviderCapabilities::herdr` and Herdr stream kinds do not exist.

- [ ] **Step 3: Implement minimal session wire additions**

Add `ProviderCapabilities::herdr()` and stream kinds:

```rust
HerdrClientControl,
HerdrClientInput,
HerdrClientResize,
HerdrClientBulk,
HerdrServerControl,
HerdrServerRender,
HerdrServerBulk,
```

Update any exhaustive matches in `session_client.rs` to treat Herdr kinds as non-V1/non-V2 generic substreams until Task 5 adds Herdr-specific open helpers.

- [ ] **Step 4: Run GREEN**

Run:

```bash
cargo nextest run -p portl-core -E 'kind(lib) & test(herdr_)'
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/portl-core/src/wire/session.rs crates/portl-core/src/net/session_client.rs
git commit -m "Add Herdr session stream lanes" -m "Extend the session wire protocol with Herdr-specific lane identifiers and provider capabilities so the attach provider can route Herdr frames without overloading the existing terminal attach streams."
```

## Task 3: Add Herdr provider discovery and listing

**Files:**
- Modify: `crates/portl-agent/src/config.rs`
- Modify: `crates/portl-agent/src/session_handler/provider.rs`
- Modify: `crates/portl-cli/src/commands/session.rs`
- Modify: `crates/portl-cli/src/lib.rs`

- [ ] **Step 1: Write failing provider tests**

In `provider.rs` tests, add fake Herdr tests:

```rust
#[tokio::test]
async fn herdr_provider_maps_session_list_json() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let fake = temp.path().join("herdr");
    fs::write(&fake, r#"#!/bin/sh
printf '%s\n' "$@" >> "$PORTL_FAKE_HERDR_LOG"
case "$1" in
  --version) echo "herdr 0.6.4" ;;
  session)
    if [ "$2" = "list" ] && [ "$3" = "--json" ]; then
      printf '{"sessions":[{"name":"default","default":true,"running":true,"socket_path":"/tmp/herdr.sock","session_dir":"/tmp/herdr"},{"name":"ops","default":false,"running":false,"socket_path":"/tmp/ops.sock","session_dir":"/tmp/ops"}]}'
    fi
    ;;
esac
"#)?;
    let mut perms = fs::metadata(&fake)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&fake, perms)?;
    let log = temp.path().join("log");
    let provider = HerdrProvider::with_path(fake).with_env("PORTL_FAKE_HERDR_LOG", &log);

    let status = provider.probe().await?;
    assert!(status.available);
    assert_eq!(status.tier.as_deref(), Some("protocol-aware"));
    assert!(status.features.contains(&"herdr_wire.v1".to_owned()));
    let sessions = provider.list_detailed().await?;
    assert_eq!(sessions.iter().map(|s| (&s.provider, &s.name)).collect::<Vec<_>>(), vec![(&"herdr".to_owned(), &"default".to_owned()), (&"herdr".to_owned(), &"ops".to_owned())]);
    Ok(())
}
```

Add CLI provider capability test in `session.rs` near `provider_capabilities` tests if present:

```rust
#[test]
fn provider_capabilities_include_herdr() {
    assert_eq!(provider_capabilities("herdr"), ProviderCapabilities::herdr());
}
```

- [ ] **Step 2: Verify RED**

Run:

```bash
cargo nextest run -p portl-agent -E 'kind(lib) & test(herdr_provider_)'
cargo nextest run -p portl-cli -E 'kind(lib) & test(provider_capabilities_include_herdr)'
```

Expected: FAIL because `HerdrProvider` and provider normalization do not exist.

- [ ] **Step 3: Implement `HerdrProvider`**

Add to `provider.rs` a provider parallel to `ZmxProvider`/`TmuxProvider`:

```rust
#[derive(Debug, Clone)]
pub(crate) struct HerdrProvider {
    path: Option<PathBuf>,
    env: Vec<(String, String)>,
    target_home: Option<PathBuf>,
}
```

Methods:

```rust
new(path: Option<PathBuf>)
with_target_home(target_home: Option<PathBuf>)
with_path(path: PathBuf) #[cfg(test)]
with_env(key: &str, value: &Path) #[cfg(test)]
probe() -> ProviderStatus
list_detailed() -> Vec<SessionInfo>
bridge_command(session: &str, cwd: Option<&str>, workload_env: Option<&[(String, String)]>) -> Result<Command>
path_discovery() -> ProviderPathDiscovery
resolve_path() -> Option<PathBuf>
```

Use `PORTL_HERDR_PATH` before generic discovery when set. Parse `herdr session list --json` response shape `{ "sessions": [...] }`, where each item has at least `name`.

- [ ] **Step 4: Register provider in reports and config**

Update provider report to include Herdr after Ghostty and before zmx/tmux. Update config constants:

```rust
pub const SESSION_PROVIDER_HERDR: &str = "herdr";
pub const SESSION_PROVIDER_HELP_VALUES: &str = "default, ghostty, herdr, zmx, tmux";
```

Update normalize helpers and CLI `provider_capabilities`.

- [ ] **Step 5: Run GREEN**

Run:

```bash
cargo nextest run -p portl-agent -E 'kind(lib) & test(herdr_provider_)'
cargo nextest run -p portl-cli -E 'kind(lib) & test(provider_capabilities_include_herdr)'
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/portl-agent/src/config.rs crates/portl-agent/src/session_handler/provider.rs crates/portl-cli/src/commands/session.rs crates/portl-cli/src/lib.rs
git commit -m "Add Herdr session provider discovery" -m "Register Herdr as a persistent-session provider and discover sessions through the Herdr CLI while keeping attach implementation separate."
```

## Task 4: Resolve Herdr attach shorthands

**Files:**
- Modify: `crates/portl-cli/src/commands/session.rs`

- [ ] **Step 1: Write failing reference-resolution tests**

Add tests near existing `resolve_session_ref_with_stores` tests:

```rust
#[test]
fn target_provider_ref_defaults_herdr_session_name() -> Result<()> {
    let stores = SessionRefTestStores::with_peer("vn3");
    let resolved = resolve_session_ref_with_stores(Some("vn3/herdr"), None, None, &stores.peers, &stores.tickets, &stores.aliases)?;
    assert_eq!(resolved.target, "vn3");
    assert_eq!(resolved.provider.as_deref(), Some("herdr"));
    assert_eq!(resolved.session, "default");
    Ok(())
}

#[test]
fn env_target_provider_ref_defaults_herdr_session_name() -> Result<()> {
    let stores = SessionRefTestStores::with_peer("vn3");
    let resolved = resolve_session_ref_with_stores(Some("herdr"), None, Some("vn3"), &stores.peers, &stores.tickets, &stores.aliases)?;
    assert_eq!(resolved.target, "vn3");
    assert_eq!(resolved.provider.as_deref(), Some("herdr"));
    assert_eq!(resolved.session, "default");
    Ok(())
}

#[test]
fn one_part_herdr_without_target_remains_session_name() -> Result<()> {
    let stores = SessionRefTestStores::empty();
    let resolved = resolve_session_ref_with_stores(Some("herdr"), None, None, &stores.peers, &stores.tickets, &stores.aliases)?;
    assert_eq!(resolved.provider, None);
    assert_eq!(resolved.session, "herdr");
    Ok(())
}
```

Use existing test store helpers if they exist; otherwise add minimal helper constructors in the test module.

- [ ] **Step 2: Verify RED**

Run:

```bash
cargo nextest run -p portl-cli -E 'kind(lib) & test(herdr_session_name)'
```

Expected: FAIL because `vn3/herdr` still parses as target/session, not target/provider/default.

- [ ] **Step 3: Implement shorthand resolution**

Add helper:

```rust
fn known_session_provider_name(value: &str) -> bool {
    matches!(normalize_session_provider_alias(value).as_str(), "ghostty" | "herdr" | "zmx" | "tmux" | "raw")
}
```

Update `split_session_ref` and `resolve_session_ref_with_stores` so:

- `[host, provider]` with known provider becomes `(Some(host), Some(provider), Some("default"))`.
- `[session]` with env/flag target and known provider becomes provider/default.
- `[session]` without env/flag target stays unchanged.

- [ ] **Step 4: Run GREEN**

Run:

```bash
cargo nextest run -p portl-cli -E 'kind(lib) & test(herdr_session_name)'
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/portl-cli/src/commands/session.rs
git commit -m "Resolve Herdr attach shorthands" -m "Teach session reference parsing to interpret TARGET/herdr and PORTL_TARGET=... portl attach herdr as Herdr default-session attaches without stealing ordinary one-part local session names."
```

## Task 5: Implement remote Herdr attach registry and substream pumps

**Files:**
- Create: `crates/portl-agent/src/session_handler/herdr.rs`
- Modify: `crates/portl-agent/src/session_handler/mod.rs`
- Modify: `crates/portl-agent/src/lib.rs`

- [ ] **Step 1: Write failing remote attach unit tests**

In new `herdr.rs`, add tests for process argv/env planning and resize coalescing:

```rust
#[test]
fn default_session_does_not_set_herdr_session_env() {
    let env = bridge_env_for_session("default");
    assert!(!env.iter().any(|(k, _)| k == "HERDR_SESSION"));
}

#[test]
fn named_session_sets_herdr_session_env() {
    let env = bridge_env_for_session("ops");
    assert!(env.contains(&("HERDR_SESSION".to_owned(), "ops".to_owned())));
}

#[tokio::test]
async fn resize_coalescer_emits_latest_resize() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let coalescer = ResizeCoalescer::new(tx);
    coalescer.send(RawHerdrFrame::encode_client(&ClientMessage::Resize { cols: 80, rows: 24, cell_width_px: 0, cell_height_px: 0 }).unwrap()).await.unwrap();
    coalescer.send(RawHerdrFrame::encode_client(&ClientMessage::Resize { cols: 120, rows: 40, cell_width_px: 0, cell_height_px: 0 }).unwrap()).await.unwrap();
    let latest = rx.recv().await.unwrap();
    let decoded = latest.decode_client().unwrap();
    assert!(matches!(decoded, ClientMessage::Resize { cols: 120, rows: 40, .. }));
}
```

- [ ] **Step 2: Verify RED**

Run:

```bash
cargo nextest run -p portl-agent -E 'kind(lib) & test(session_handler::herdr::tests::)'
```

Expected: FAIL because the module does not exist.

- [ ] **Step 3: Implement remote Herdr attach structures**

Create `HerdrAttach` with:

```rust
pub(crate) struct HerdrAttach {
    pub(crate) session_id: [u8; 16],
    client_control_tx: mpsc::Sender<RawHerdrFrame>,
    client_input_tx: mpsc::Sender<RawHerdrFrame>,
    client_resize_tx: mpsc::Sender<RawHerdrFrame>,
    client_bulk_tx: mpsc::Sender<RawHerdrFrame>,
    server_control_rx: AsyncMutex<Option<mpsc::Receiver<RawHerdrFrame>>>,
    server_render_rx: AsyncMutex<Option<mpsc::Receiver<RawHerdrFrame>>>,
    server_bulk_rx: AsyncMutex<Option<mpsc::Receiver<RawHerdrFrame>>>,
    exit_rx: watch::Receiver<Option<i32>>,
}
```

Implement:

```rust
spawn_herdr_bridge_process(session, provider, req, context) -> Result<Arc<HerdrAttach>, SessionReason>
pump_client_lane_to_bridge(rx, child_stdin)
pump_bridge_stdout_to_server_lanes(child_stdout, control_tx, render_tx, bulk_tx)
pump_herdr_client_frames(recv, attach, kind)
pump_herdr_server_frames(send, receiver)
```

Use a single writer task for remote bridge stdin to preserve ordered writes among control/input/resize/bulk after lane scheduling decisions. The first milestone priority loop should always service control before input before resize before bulk when multiple lanes are ready.

- [ ] **Step 4: Register Herdr attach in session handler**

Add `pub(crate) mod herdr;`. Add a Herdr registry to `AgentState`, parallel to other registries if needed:

```rust
pub herdr_attach_registry: dashmap::DashMap<[u8; 16], Arc<session_handler::herdr::HerdrAttach>>,
```

In `serve_attach`, if selected provider is Herdr, call `serve_herdr_attach(...)` and return.

In `serve_substream`, dispatch Herdr stream kinds to `herdr::serve_substream` before falling through to `shell_registry`.

- [ ] **Step 5: Run GREEN**

Run:

```bash
cargo nextest run -p portl-agent -E 'kind(lib) & test(session_handler::herdr::tests::)'
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/portl-agent/src/session_handler/herdr.rs crates/portl-agent/src/session_handler/mod.rs crates/portl-agent/src/lib.rs
git commit -m "Add remote Herdr attach bridge" -m "Spawn Herdr's remote-client-bridge as a fixed provider command and expose Herdr-specific session substreams for control, input, resize, render, and bulk traffic."
```

## Task 6: Implement local Herdr attach client path

**Files:**
- Create: `crates/portl-core/src/net/herdr_client.rs`
- Modify: `crates/portl-core/src/net/mod.rs`
- Modify: `crates/portl-cli/src/commands/session.rs`

- [ ] **Step 1: Write failing local bridge tests**

In `herdr_client.rs`, add tests using `tokio::io::duplex` or local Unix sockets:

```rust
#[tokio::test]
async fn first_client_frame_must_be_hello() {
    let input = RawHerdrFrame::encode_client(&ClientMessage::Input { data: b"oops".to_vec() }).unwrap();
    let err = validate_first_client_frame(&input).unwrap_err();
    assert!(err.to_string().contains("expected Herdr Hello"));
}

#[tokio::test]
async fn first_server_frame_must_be_welcome() {
    let frame = RawHerdrFrame::encode_server(&ServerMessage::Notify { kind: NotifyKind::Toast, message: "later".to_owned() }).unwrap();
    let err = validate_first_server_frame(&frame).unwrap_err();
    assert!(err.to_string().contains("expected Herdr Welcome"));
}
```

In CLI tests, add a test that local Herdr path chooses external client bridge:

```rust
#[test]
fn remote_attach_session_detects_herdr_provider() {
    assert!(is_herdr_provider(Some("herdr")));
    assert!(!is_herdr_provider(Some("zmx")));
    assert!(!is_herdr_provider(None));
}
```

- [ ] **Step 2: Verify RED**

Run:

```bash
cargo nextest run -p portl-core -E 'kind(lib) & test(herdr_client::tests::)'
cargo nextest run -p portl-cli -E 'kind(lib) & test(remote_attach_session_detects_herdr_provider)'
```

Expected: FAIL because local Herdr client helpers do not exist.

- [ ] **Step 3: Implement `HerdrSessionClient` open helper**

Add `open_herdr_attach_checked` that mirrors `open_session_attach_checked` but opens Herdr stream kinds:

```rust
pub struct HerdrSessionClient {
    pub provider: String,
    pub session_id: [u8; 16],
    pub control_send: SendStream,
    pub control_recv: BufferedRecv,
    pub client_control: SendStream,
    pub client_input: SendStream,
    pub client_resize: SendStream,
    pub client_bulk: SendStream,
    pub server_control: BufferedRecv,
    pub server_render: BufferedRecv,
    pub server_bulk: BufferedRecv,
}
```

Open control attach with `provider = Some("herdr")`, then open the seven Herdr substreams.

- [ ] **Step 4: Implement CLI local socket and process path**

In `session.rs`, when resolved provider is `Some("herdr")`, call a new `remote_herdr_attach(...)` path instead of `bridge_attach(...)`.

Implement local steps:

```text
resolve local Herdr binary from PORTL_HERDR_PATH or PATH
create temp Unix listener with 0600 permissions
spawn `herdr client` with HERDR_CLIENT_SOCKET_PATH, HERDR_REATTACH_COMMAND, HERDR_REMOTE_KEYBINDINGS default local
accept one UnixStream
bridge local Herdr frames to HerdrSessionClient lanes
wait for local Herdr process exit and remote stream completion
remove socket path
```

Use tokio `UnixListener` and `tokio::process::Command`.

- [ ] **Step 5: Run GREEN**

Run:

```bash
cargo nextest run -p portl-core -E 'kind(lib) & test(herdr_client::tests::)'
cargo nextest run -p portl-cli -E 'kind(lib) & test(remote_attach_session_detects_herdr_provider)'
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/portl-core/src/net/herdr_client.rs crates/portl-core/src/net/mod.rs crates/portl-cli/src/commands/session.rs
git commit -m "Launch local Herdr client for attach" -m "Add the local half of Herdr attach: a temporary Unix socket, local Herdr client invocation, handshake validation, and Herdr lane streams over an authenticated Portl session."
```

## Task 7: Add fake Herdr end-to-end session test

**Files:**
- Modify: `crates/portl-agent/tests/session_e2e.rs`

- [ ] **Step 1: Write failing fake bridge integration test**

Add a fake Herdr binary helper that supports:

```text
--version
session list --json
remote-client-bridge
```

The fake `remote-client-bridge` should read one Herdr `ClientMessage::Hello`, write `ServerMessage::Welcome`, read input frames, and log them to a temp file. Use a small Rust helper in the test process if shell/Python bincode generation is impractical; the test can spawn `current_exe()` with an env flag for fake Herdr mode.

Test behavior:

```rust
#[tokio::test]
async fn session_herdr_provider_bridges_hello_welcome_and_input_lanes() -> Result<()> {
    // start agent with fake herdr provider path
    // open ticket/session
    // open Herdr attach provider
    // write encoded Hello to client_control
    // assert Welcome arrives on server_control
    // write Input on client_input
    // assert fake remote bridge log contains that input
    // shutdown cleanly
}
```

- [ ] **Step 2: Verify RED**

Run:

```bash
cargo nextest run -p portl-agent -E 'binary(=session_e2e) & test(session_herdr_provider_bridges_hello_welcome_and_input_lanes)'
```

Expected: FAIL until remote and local Herdr attach pieces are wired correctly.

- [ ] **Step 3: Implement test helpers and fix integration gaps**

Use `portl_core::test_util::pair()` and `DiscoveryConfig::in_process()` as existing tests do. Ensure fake Herdr path is provided to the agent through `PORTL_HERDR_PATH` or provider-path config. Keep the test local-only; do not contact real Iroh DNS/relay.

- [ ] **Step 4: Run GREEN**

Run:

```bash
cargo nextest run -p portl-agent -E 'binary(=session_e2e) & test(session_herdr_provider_bridges_hello_welcome_and_input_lanes)'
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/portl-agent/tests/session_e2e.rs
git commit -m "Test Herdr provider attach bridge" -m "Cover the Herdr provider over in-process Portl endpoints with a fake Herdr bridge that verifies Hello, Welcome, and input traffic cross the protocol-aware lanes."
```

## Task 8: Run formatting and focused verification

**Files:**
- All changed Rust files

- [ ] **Step 1: Format**

Run:

```bash
cargo fmt
```

Expected: no output or formatting changes only in files touched by this plan.

- [ ] **Step 2: Run focused test suite**

Run:

```bash
cargo nextest run -p portl-core -E 'kind(lib) & (test(herdr_wire::tests::) + test(herdr_client::tests::) + test(herdr_))'
cargo nextest run -p portl-agent -E 'kind(lib) & (test(session_handler::herdr::tests::) + test(herdr_provider_))'
cargo nextest run -p portl-agent -E 'binary(=session_e2e) & (test(session_herdr_provider_bridges_hello_welcome_and_input_lanes) + test(session_zmx_provider_maps_core_ops_over_session_protocol))'
cargo nextest run -p portl-cli -E 'kind(lib) & (test(herdr_session_name) + test(remote_attach_session_detects_herdr_provider) + test(provider_capabilities_include_herdr))'
```

Expected: all pass.

- [ ] **Step 3: Commit any formatting-only changes**

If `cargo fmt` changed files after prior commits:

```bash
git add <formatted files>
git commit -m "Format Herdr provider implementation" -m "Apply rustfmt to the Herdr provider changes after the focused verification pass."
```

If there are no changes, skip this commit.

## Task 9: Post-implementation roundtable review and fixes

**Files:**
- Review-dependent

- [ ] **Step 1: Run `/roundtable-review`**

Run the project's review prompt/template against the branch diff. If `/roundtable-review` is available as a prompt template, use:

```bash
/roundtable-review
```

or the Pi prompt-template equivalent with this scope:

```text
Review the Herdr provider implementation on branch feature/herdr-provider against docs/superpowers/specs/2026-05-30-portl-herdr-provider-design.md. Identify correctness, safety, compatibility, test coverage, and UX issues. Prioritize Critical, High, Medium, Low.
```

- [ ] **Step 2: Triage review findings**

Create a checklist in the session notes for every Critical, High, and Medium finding. Low findings may be deferred unless cheap and safe.

- [ ] **Step 3: Fix Critical/High/Medium findings with tests first**

For each finding:

1. Add or update a failing test that reproduces the issue.
2. Run the focused nextest filter and verify RED.
3. Implement the fix.
4. Run the focused nextest filter and verify GREEN.
5. Commit with a message naming the issue.

- [ ] **Step 4: Re-run review if substantial fixes landed**

If any High issue required non-trivial changes, run a second review focused on the changed files.

## Task 10: Real vn3 end-to-end validation

**Files:**
- No required source edits unless validation finds bugs

- [ ] **Step 1: Build local Portl CLI**

Run:

```bash
cargo build -p portl-cli
```

Expected: build succeeds.

- [ ] **Step 2: Ensure target uses compatible Portl agent**

Install or run the built Portl agent on `vn3` according to existing Portl install/dev workflow. Verify:

```bash
portl status vn3 --count 1 --timeout 5s
```

Expected: status succeeds and reports the new build or a compatible dev agent.

- [ ] **Step 3: Verify remote Herdr provider**

Run:

```bash
portl session providers vn3 --json
portl ls vn3/herdr --json
```

Expected: provider list includes available `herdr`; `ls` includes `default`.

- [ ] **Step 4: Manual interactive attach smoke test**

Run:

```bash
portl attach vn3/herdr
```

Inside Herdr, validate basic controls:

```text
create a new tab
create/switch workspace or space
send text command into a pane, e.g. `printf portl-herdr-e2e && echo`
observe output
detach/exit cleanly
```

Record the exact controls used and observed results in `scratch/herdr-e2e-YYYYMMDD.md`.

- [ ] **Step 5: Cross-validate over SSH**

Use SSH to inspect the remote Herdr instance:

```bash
ssh vn3 '~/.local/bin/herdr session list --json'
ssh vn3 '~/.local/bin/herdr status server --json'
```

Expected: the session touched by Portl is visible and healthy. If Herdr exposes API state for tabs/workspaces/panes, query it and record evidence; otherwise record terminal-observed evidence plus server/session health.

## Task 11: Version bump and release minting

**Files:**
- Version files discovered by the release skill
- Changelog/release files discovered by the release skill

- [ ] **Step 1: Use Portl release skill**

Invoke the `portl-release` skill before changing versions. Follow its release validation workflow.

- [ ] **Step 2: Bump minor version**

Current version is `0.9.0`; bump to `0.10.0` unless the release skill or repository policy indicates a different next minor.

- [ ] **Step 3: Update release notes/changelog**

Document:

```text
- Added protocol-aware Herdr session provider.
- Added `portl attach TARGET/herdr[/SESSION]` support.
- Added Herdr frame lane routing over Portl/Iroh.
```

- [ ] **Step 4: Run release validation**

Run the exact checks required by `portl-release`. Also run the focused Herdr provider nextest suite from Task 8.

- [ ] **Step 5: Mint `$portl-release`**

Use the repository's release minting command from the release skill. Record the produced release artifact/tag/identifier in the final report.

## Completion Audit Checklist

Before marking the goal complete, produce evidence for every row:

| Requirement | Evidence required |
| --- | --- |
| Fully working `portl attach vn3/herdr` | Real command transcript and observed Herdr UI interaction |
| Provider syntax works | Tests and manual commands for `vn3/herdr`, `vn3/herdr/default`, and `PORTL_TARGET=vn3 portl attach herdr` |
| Protocol-aware bridge | Code links and tests showing Herdr frame decode/classification and multiple lane streams |
| Local Herdr CLI only | Code showing local `herdr client` launched with `HERDR_CLIENT_SOCKET_PATH` |
| Remote bootstrap uses Herdr CLI | Code showing fixed `herdr remote-client-bridge` spawn |
| Roundtable review done | Review output path/transcript and checklist |
| High/Medium issues addressed | Commit/test evidence per issue |
| Real vn3 controls validated | Scratch note with controls used and SSH cross-validation output |
| Minor version bumped | Diff evidence for version files |
| `$portl-release` minted | Release command output/artifact/tag |
| Tests green | Fresh nextest and release validation output |

Only call `update_goal(status="complete")` after this checklist has concrete evidence for every requirement.
