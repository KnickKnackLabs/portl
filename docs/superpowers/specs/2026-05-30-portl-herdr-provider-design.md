# Portl Herdr Provider Design

Date: 2026-05-30

## Summary

Add a first-class `herdr` persistent-session provider to Portl. The provider
lets users attach to a Herdr session on a remote Portl peer with normal session
syntax:

```bash
portl attach vn3/herdr/default
portl attach vn3/herdr
PORTL_TARGET=vn3 portl attach herdr
```

Portl remains responsible for target resolution, ticket authentication, Iroh
connectivity, a local temporary Unix socket, protocol-aware frame routing, and
invoking the local `herdr client`. Herdr remains responsible for its own server
lifecycle, socket discovery, config, rendering, terminal setup, and UI logic.

The remote side uses Herdr's existing public bootstrap command:

```bash
herdr remote-client-bridge
```

This avoids duplicating Herdr session-directory or server-startup logic inside
Portl. Portl parses Herdr's length-prefixed bincode protocol around that bridge
so that future optimizations can use separate Iroh streams for input, resize,
render, control, and bulk payloads.

## Current Problem

Herdr's built-in `--remote` path is SSH-specific in lifecycle/bootstrap code,
even though the underlying interactive client protocol is transport-agnostic:

```text
[u32 little-endian length][bincode ClientMessage/ServerMessage]
```

Portl already provides authenticated peer-to-peer Iroh connectivity and remote
process execution. A simple byte bridge would work, but it would collapse Herdr
input, resize, render, graphics, clipboard, and shutdown/control events into one
ordered stream. That forfeits the latency benefits available from Iroh streams.

The desired integration is a provider, not a separate one-off command, so Herdr
sessions fit existing Portl session workflows beside zmx, tmux, and Ghostty.

## Goals

- Add `herdr` as a Portl session provider.
- Support `portl attach TARGET/herdr/SESSION` for remote Herdr sessions.
- Treat `TARGET/herdr` as `TARGET/herdr/default`.
- Treat `PORTL_TARGET=vn3 portl attach herdr` as
  `portl attach vn3/herdr/default`.
- Require a local Herdr CLI and launch it as `herdr client`.
- Create a local temporary Unix socket and pass it to local Herdr with
  `HERDR_CLIENT_SOCKET_PATH`.
- Bootstrap the target with remote `herdr remote-client-bridge` rather than
  reimplementing Herdr server startup or socket discovery.
- Parse Herdr client/server frames in Portl and classify them by lane.
- Preserve correct handshake behavior and safe message ordering.
- Keep Herdr's local configuration, terminal handling, keybindings, sounds,
  notifications, clipboard handling, and rendering in the Herdr client.
- Keep the first implementation conservative: protocol-aware lanes and resize
  coalescing first; aggressive render dropping only after the bridge is stable.

## Non-Goals

- Do not implement a Herdr UI renderer in Portl.
- Do not implement Herdr server startup logic or Herdr config-dir discovery in
  Portl.
- Do not modify Herdr for the first milestone.
- Do not add a new ticket capability in the first milestone.
- Do not support `portl run ...` or `portl history ...` for Herdr in the first
  milestone.
- Do not drop semantic render frames in the first milestone. The bridge should
  be structured so latest-frame-wins can be added later.
- Do not support Windows named pipes in the first milestone; Herdr's current
  client socket is Unix-domain-socket based.

## User Experience

### Attach syntax

Canonical remote attach:

```bash
portl attach vn3/herdr/default
```

Default-session shorthand:

```bash
portl attach vn3/herdr
```

Environment-target shorthand:

```bash
PORTL_TARGET=vn3 portl attach herdr
```

The environment-target shorthand only receives the special interpretation when
the single path component is a known provider name. Otherwise existing
one-component session behavior is preserved.

### Runtime output

Before handing the terminal to Herdr, Portl should print the same style of
attach notice used by existing providers:

```text
portl: attaching to session "vn3/herdr/default"
```

After that, the local Herdr client owns the terminal. Portl should not enable
its own raw-mode attach bridge for Herdr.

### Local Herdr invocation

Portl creates a local temporary Unix socket, listens on it, and spawns:

```bash
HERDR_CLIENT_SOCKET_PATH=/tmp/portl-herdr-...sock \
HERDR_REATTACH_COMMAND='portl attach vn3/herdr/default' \
HERDR_REMOTE_KEYBINDINGS=local \
herdr client
```

If `HERDR_REMOTE_KEYBINDINGS` is already set in the user's environment, Portl
respects it. Otherwise Portl sets `local`, matching Herdr's current `--remote`
default.

Portl does not force `HERDR_RENDER_ENCODING`. Local Herdr currently defaults to
semantic frames, which is the desired mode for future frame coalescing. If the
user explicitly sets `HERDR_RENDER_ENCODING=terminal-ansi`, Portl still bridges
correctly but cannot apply semantic latest-frame-wins optimizations.

### Remote Herdr invocation

The remote agent starts the bridge process with the selected session applied to
Herdr's normal session mechanism:

```bash
# default session
herdr remote-client-bridge

# named session
HERDR_SESSION=<session> herdr remote-client-bridge
```

For the default session, Portl leaves `HERDR_SESSION` unset so Herdr uses its
native default-session behavior.

Remote `--cwd` and `--user` from `portl attach` apply to this bootstrap process
using the same target-process handling as other session providers.

## Architecture

High-level flow:

```text
User terminal
    │
    │ portl attach vn3/herdr/default
    ▼
Portl CLI
    │ resolve target, connect ticket, open Herdr attach
    │ create local Unix socket
    │ spawn local `herdr client`
    ▼
local herdr client
    │ Herdr wire frames over Unix socket
    ▼
Portl local Herdr proxy
    │ classify ClientMessage frames by lane
    │ route over Portl/Iroh session substreams
    ▼
remote Portl agent Herdr proxy
    │ merge client lanes into remote bridge stdin
    │ classify remote bridge stdout ServerMessage frames
    ▼
remote `herdr remote-client-bridge`
    │ connects to remote Herdr client socket
    ▼
remote Herdr server/session
```

The provider has two layers:

1. Provider discovery and session operations integrated into the existing
   Portl session provider system.
2. A Herdr-specific attach bridge that bypasses Portl's terminal renderer and
   instead launches the local Herdr client against a Portl-owned local socket.

## Provider Discovery and Capabilities

Add `herdr` to the supported session provider names and aliases. The first
implementation should accept the canonical name `herdr`; no short alias is
required.

Remote provider discovery uses the existing provider-path discovery pattern for
the `herdr` binary:

```text
PORTL_HERDR_PATH, when set in the agent environment
configured provider path, when it names Herdr
stable system paths
target home: ~/.local/bin, ~/bin, ~/.cargo/bin, mise shims
```

Local Herdr invocation resolves the binary with:

```text
PORTL_HERDR_PATH, when set in the CLI environment
PATH lookup for `herdr`
```

Availability is determined by running `herdr --version` or an equally cheap
local command. Provider status should report:

```text
name: herdr
tier: protocol-aware
features: herdr_wire.v1, priority_lanes.v1, remote_client_bridge.v1
```

Capabilities:

```text
persistent              true
multi_attach            true
create_on_attach        true
attach_command          true
run                     false
detached_run            false
history                 false
tail                    false
kill                    false in the first milestone
terminal_state_restore  true, handled by local Herdr
external_direct_attach  true
exact_argv_spawn        false
```

Listing Herdr sessions should use Herdr's public CLI:

```bash
herdr session list --json
```

The provider maps each returned session to `SessionInfo { provider: "herdr" }`.
If Herdr is available but session listing fails, provider discovery can still
report Herdr as available while `portl ls .../herdr` returns the command error.

## Session Reference Resolution

Existing Portl syntax already supports:

```text
SESSION
HOST/SESSION
HOST/PROVIDER/SESSION
```

This design adds one provider-shorthand case:

```text
HOST/herdr
```

When the second component is a known provider name and no explicit session is
present, resolve it as:

```text
HOST/herdr/default
```

For one-component refs, when `PORTL_TARGET` or `--target` supplies the target
and the component is a known provider name, resolve it as:

```text
target = PORTL_TARGET or --target
provider = component
session = default
```

Without `PORTL_TARGET` or `--target`, one-component refs keep their existing
meaning so a local session named `herdr` is not stolen by the provider
shorthand.

Examples:

```text
portl attach vn3/herdr              → target vn3, provider herdr, session default
PORTL_TARGET=vn3 portl attach herdr → target vn3, provider herdr, session default
portl attach herdr                  → unchanged: session herdr, provider auto
portl attach dev                    → unchanged: session dev, provider auto
```

This rule applies to known provider names only, so ordinary sessions named
`dev`, `dotfiles`, or `frontend` keep their current meaning.

## Herdr Wire Compatibility

Portl needs a minimal copy of Herdr protocol version 11 message types so it can
deserialize and classify frames. The copy should live in Portl protocol code and
be explicitly version-named, for example:

```text
portl-core/src/herdr_wire/v11.rs
```

Constants:

```text
HERDR_PROTOCOL_VERSION = 11
MAX_FRAME_SIZE = 2 MiB
MAX_GRAPHICS_FRAME_SIZE = 32 MiB
MAX_CLIPBOARD_IMAGE_PAYLOAD = 16 MiB
```

Portl preserves Herdr's outer framing exactly:

```text
[u32 little-endian payload length][bincode v2 serde payload]
```

If Portl cannot decode a Herdr frame, the attach fails clearly rather than
silently forwarding partially parsed data. That is safer for a protocol-aware
transport than degrading to raw bytes after state has diverged.

## Portl Session Wire Extensions

Use the existing `portl/session/v1` authenticated connection and extend
`SessionStreamKind` with Herdr-specific substream kinds instead of introducing a
second top-level ALPN in the first milestone. This keeps Herdr aligned with
existing provider attach and ticket capability enforcement.

New stream kinds:

```text
HerdrClientControl
HerdrClientInput
HerdrClientResize
HerdrClientBulk
HerdrServerControl
HerdrServerRender
HerdrServerBulk
```

The control attach request remains a session attach request:

```text
SessionOp::Attach
provider = Some("herdr")
session_name = Some("default" or named session)
```

When the remote agent accepts a Herdr attach, it spawns the remote bridge,
creates a Herdr attach registry entry keyed by the returned `session_id`, and
returns a normal `SessionAck` with:

```text
provider = Some("herdr")
session_id = Some(...)
```

The local Portl Herdr client then opens the Herdr substreams for that
`session_id`.

## Frame Classification

Client-to-server lanes:

```text
ClientControl:
  Hello
  Detach
  AttachTerminal

ClientInput:
  Input
  AttachScroll

ClientResize:
  Resize, latest value wins while backlog exists

ClientBulk:
  ClipboardImage
```

Server-to-client lanes:

```text
ServerControl:
  Welcome
  ServerShutdown
  Notify
  ReloadSoundConfig
  MouseCapture

ServerRender:
  Frame
  Terminal

ServerBulk:
  Graphics
  Clipboard
```

Handshake is special-cased:

```text
local Herdr Hello must reach the remote bridge before any other client frame
remote Welcome must reach the local Herdr client before any other server frame
```

After handshake, lanes may progress independently within these safety rules:

- Input must preserve order relative to other input frames.
- Resize may be coalesced because only the latest terminal size matters.
- Detach and shutdown may overtake queued render or bulk payloads.
- Render frames preserve order in the first milestone.
- Bulk frames preserve order within the bulk lane.
- TerminalAnsi render mode is forwarded in order and is never dropped.

Semantic render frames make later latest-frame-wins optimization possible, but
the first milestone deliberately does not drop render frames.

## Local Socket Lifecycle

Portl creates a unique temporary socket path short enough for Unix-domain socket
limits:

```text
$TMPDIR/portl-herdr-<pid>-<random>.sock
```

Lifecycle:

1. Remove stale path if it exists and is not live.
2. Bind listener with owner-only permissions.
3. Spawn local `herdr client` with `HERDR_CLIENT_SOCKET_PATH` set to the socket.
4. Accept exactly one local client connection for the attach.
5. Bridge frames until local Herdr exits, remote bridge exits, or the connection
   closes.
6. Remove the temporary socket path on exit.

If the local Herdr client exits before connecting, Portl reports the process
exit status and captured startup stderr where practical.

## Remote Process Lifecycle

The remote agent uses normal target-process handling to spawn Herdr:

```text
argv = [herdr_path, "remote-client-bridge"]
stdin = piped
stdout = piped
stderr = captured/forwarded as provider diagnostics
cwd = requested --cwd, if supplied
user = requested --user, if supplied
env = target workload env plus HERDR_SESSION for named sessions
```

The remote process is not a PTY. It is a clean stdin/stdout byte stream, matching
Herdr's existing bridge contract.

If the remote bridge exits, Portl closes the Herdr lanes and lets the local Herdr
client display the server disconnect/error path. If the local Herdr client exits
first, Portl sends detach/EOF to the remote process and reaps it.

## Error Handling

Local Herdr missing:

```text
portl: herdr provider requires a local `herdr` executable; set PORTL_HERDR_PATH or install Herdr
```

Remote Herdr missing:

```text
portl: target vn3 does not have an available Herdr provider
```

Remote bridge startup failure:

```text
portl: failed to start remote Herdr bridge for vn3/herdr/default: <stderr or spawn error>
```

Protocol decode failure:

```text
portl: Herdr protocol decode failed; local and remote Herdr versions may be incompatible
```

Version mismatch reported by Herdr itself should pass through to local Herdr via
the normal `Welcome { error }` path whenever the frame can be decoded.

## Security and Capabilities

The first milestone uses existing session/shell capability enforcement because
the remote agent must spawn `herdr remote-client-bridge`. It does not add a new
ticket capability.

The Herdr provider should narrow what it spawns:

```text
resolved herdr binary + fixed argv ["remote-client-bridge"]
```

It should not pass arbitrary user argv to the remote Herdr bridge. It should not
open arbitrary remote Unix sockets. The only remote socket access is performed
inside Herdr's own bridge command.

Audit events should record:

```text
provider = herdr
session = default or named session
operation = attach
target user/cwd when supplied
```

## Testing Plan

Unit tests:

- Session ref parsing resolves `TARGET/herdr` to default session.
- `PORTL_TARGET=vn3 portl attach herdr` resolves to provider `herdr`, session
  `default`.
- Ordinary one-part session refs remain unchanged.
- Herdr provider discovery finds a fake `herdr` binary in the same search
  locations used by other providers.
- Herdr provider maps `herdr session list --json` output to `SessionInfo`.
- Herdr frame classifier maps every `ClientMessage` and `ServerMessage` variant
  to the expected lane.
- Resize coalescer keeps only the latest resize under backlog.
- Framing rejects oversized and malformed Herdr frames.

Integration tests using local in-process Portl endpoints:

- Fake remote `herdr remote-client-bridge` exchanges a Hello/Welcome pair and a
  small render frame through the provider.
- Local fake Herdr client connects to Portl's temp socket and receives the
  remote fake server's Welcome before any later frames.
- Input frames sent by the fake local client arrive at the fake remote bridge in
  order.
- Rapid resize frames arrive at the remote bridge as the latest resize, not a
  stale queue.
- Remote bridge process failure produces a rejected attach with useful error
  text.

Manual validation:

```bash
portl attach vn3/herdr/default
portl attach vn3/herdr
PORTL_TARGET=vn3 portl attach herdr
HERDR_RENDER_ENCODING=terminal-ansi portl attach vn3/herdr/default
```

Per project testing rules, Rust verification should use focused
`cargo nextest run` filtersets rather than `cargo test`.

## Rollout

Milestone 1:

- Provider discovery/listing.
- Session-ref resolution shorthands.
- Local Unix socket lifecycle.
- Remote Herdr bridge spawn.
- Protocol-aware lanes with conservative ordering.
- Resize coalescing.
- Manual validation against `vn3`.

Milestone 2:

- Metrics for lane counts, dropped/coalesced resizes, attach duration, and
  bridge exit reasons.
- Better local/remote Herdr path overrides if real-world installs require them.

Milestone 3:

- Semantic `Frame` latest-frame-wins under render backlog.
- Optional lane scheduling knobs if default prioritization needs tuning.
- Consider a dedicated Herdr ticket capability if the provider becomes a stable
  public feature.

## First Milestone Decisions

These choices are intentionally fixed for the first milestone:

- Remote bootstrap uses `herdr remote-client-bridge`.
- Local attach uses `herdr client` with `HERDR_CLIENT_SOCKET_PATH`.
- Portl does not force `HERDR_RENDER_ENCODING`.
- Default Herdr session is represented as Portl session name `default`, but
  remote `HERDR_SESSION` is unset for that default.
- Herdr render frames are not dropped until a later milestone.
