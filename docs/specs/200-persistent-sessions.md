# 200 — Persistent Sessions and Providers

> Status: **baseline shipped in v0.4.0**. This document now records the
> implemented persistent-sessions baseline and preserves target-design
> intent where useful. v0.4.0 shipped `portl/session/v1`, top-level
> `portl session`, zmx CLI bridging, raw discovery metadata,
> Docker/Slicer `--session-provider zmx` provisioning, ticket presets,
> and ShellCaps-backed authorization with session-vocabulary errors.
> Dedicated `SessionCaps`, additional providers, provider-native APIs,
> and viewport-aware/session-control lanes are follow-on work. The
> viewport/session-control follow-on belongs in
> `docs/specs/210-session-control-lanes.md`.

## 1. Summary

As of v0.4.0, portl has three terminal-adjacent primitives. Before this
release it had two:

- `portl shell <target>` opens a one-shot remote PTY and dies when the
  client disconnects.
- `portl exec <target> -- <argv>...` runs a non-PTY command with
  separate stdin/stdout/stderr and script-friendly exit-code behavior.

v0.4.0 added the third primitive:

- `portl session ...` manages persistent terminal workspaces on a
  target.

The key mental model is:

```text
peer    = where / who
ticket  = permission
session = persistent terminal workspace
provider = how the target keeps the session alive
```

The shipped provider is `zmx`, because it already solves the hard human
terminal problems: attach/detach, multiple clients, history, and
terminal-state restoration via Ghostty's virtual terminal machinery.
The portl design must not become zmx-specific: `tmux`, `zellij`, and a
future native provider remain possible providers behind the same
capability-gated interface.

Viewport-aware attach behavior, explicit session-control lanes, and
richer active-session control are intentionally outside this baseline;
track that work in `docs/specs/210-session-control-lanes.md`.

Adapters such as Docker and Slicer may provision session providers so
portl-managed targets work out of the box. The `session` command itself
stays target-neutral and uses the same `<target>` resolution cascade as
`shell`, `exec`, `tcp`, and `udp`.

## 2. Goals

1. **Make persistent shells feel native.** A user should be able to run
   `portl session attach dev` after provisioning a target and get a
   reconnectable terminal workspace.
2. **Keep the vocabulary simple.** First-time users should understand
   that peers identify targets, tickets grant permission, and sessions
   are named terminal workspaces.
3. **Keep `exec` script-safe.** Persistent sessions do not replace
   non-PTY `exec`.
4. **Avoid maintaining a virtual terminal emulator in portl.** Use
   mature providers for terminal-state restoration. zmx is first;
   libghostty-backed native support is future work.
5. **Let external tools remain external.** If a target uses zmx, tmux,
   or zellij, users should still be able to interact with that provider
   directly outside portl.
6. **Preserve portl's trust model.** Provider availability never
   grants authorization. Tickets still gate every cross-boundary
   operation.
7. **Make Docker/Slicer seamless.** Adapters can install or advertise a
   provider at provisioning time, then `portl session attach <alias>`
   just works.
8. **Expose provider differences honestly.** The interface is
   capability-based; not every provider supports history, run, exact
   argv, or terminal-state restore.

## 3. Non-goals

- Replacing `portl exec` with shell injection into a persistent
  terminal.
- Collapsing `shell`, `exec`, and `session` into one overloaded verb.
- Requiring zmx for all portl installations.
- Silently installing session providers on arbitrary manual hosts.
- Providing identical semantics across zmx, tmux, zellij, and native
  providers.
- Maintaining a bespoke VT emulator in portl.
- Deep provider-native API integrations in the first cut. zmx starts as
  an external-provider bridge; richer IPC integration can follow.

## 4. Conceptual model

### 4.1 Peer / target

A peer is a known remote identity. A target is any string the resolver
can turn into a connection:

1. inline `portl...` ticket,
2. peer label from `peers.json`,
3. saved ticket label from `tickets.json`,
4. Docker/Slicer alias from `aliases.json`,
5. raw endpoint id.

`portl session` uses the same target resolver as the existing connect
verbs. The first positional remains the target:

```bash
portl session attach dev
portl session attach portlq...
portl session attach 0123abcd...
```

### 4.2 Ticket

A ticket is a signed permission slip. Users in the happy path do not
need to mint tickets manually: when a paired peer allows outbound
access, portl mints a short-lived action ticket as it does for
`shell`, `exec`, `tcp`, and `udp`.

Advanced users can still save or issue tickets explicitly:

```bash
portl ticket save customer portlq...
portl session attach customer
```

If the ticket does not permit persistent-session operations, the error
must say that directly. It should not leak implementation language such
as "shell cap denied".

### 4.3 Session

A session is a named persistent terminal workspace on a target:

```bash
portl session attach dev          # target=dev, session defaults to dev
portl session attach dev frontend # target=dev, session=frontend
```

The default session name is:

1. the target label when the resolver matched a label or adapter alias,
2. `default` for inline tickets or raw endpoint ids,
3. user-overridden by the optional `[session]` argument.

This makes direct provider use intuitive. If `dev` uses zmx, then
`portl session attach dev` should map to a zmx session named `dev` by
default.

### 4.4 Provider

A provider is the target-side mechanism that keeps terminal sessions
alive. Implemented and planned providers:

| Provider | v0.4.0 status | Role |
| --- | --- | --- |
| `zmx` | implemented | First persistent provider. Uses zmx commands on the target. |
| `raw` | discovery-only metadata | Current one-shot PTY behavior; advertised so the user can see that no persistent provider is available, but not used as a silent fallback for persistent operations. |
| `tmux` | future | External multiplexer provider. |
| `zellij` | future | External multiplexer provider. |
| `native` | future | Portl-owned persistent manager, likely backed by libghostty-vt bindings if terminal-state restoration is required. |

Provider support is capability-discovered, not assumed. v0.4.0 reports
`zmx` and `raw`; it does not report `tmux`, `zellij`, or `native` yet.

## 5. CLI surface

### 5.1 New command group

v0.4.0 adds a top-level command group:

```text
portl session <subcommand>
```

This command lives in the **Connect** help group from
`190-cli-ergonomics.md`. `ticket` remains the advanced
**Permissions** namespace; `session` is the user-facing terminal
workspace namespace.

Shipped v0.4.0 subcommands:

```bash
portl session attach <target> [session] [--provider PROVIDER] [--user USER] [--cwd CWD] [-- <cmd>...]
portl session providers <target> [--json]
portl session ls <target> [--provider PROVIDER] [--json]
portl session run <target> [session] [--provider PROVIDER] -- <cmd>...
portl session history <target> [session] [--provider PROVIDER] [--format plain|vt|html]
portl session kill <target> [session] [--provider PROVIDER]
```

`attach` is the primary happy-path command. It attaches to the named
session, creating it if the provider supports create-on-attach. The CLI
exposes `--format plain|vt|html` for `history`, but v0.4.0 accepts only
`plain`; `vt` and `html` fail locally before opening a session request.

Examples:

```bash
portl session attach dev
portl session attach dev frontend
portl session attach dev --provider zmx
portl session attach dev -- zellij a
portl session run dev frontend -- make test
portl session history dev frontend | tail -100
portl session kill dev frontend
```

### 5.2 Relationship to existing verbs

Keep the three verbs distinct:

```bash
portl shell dev              # one-shot interactive PTY
portl session attach dev     # persistent terminal workspace
portl exec dev -- uname -a   # non-PTY script-friendly command
```

`shell` should remain useful when no persistent provider exists, when a
user wants no target-side session state, or when provider behavior is
not desired.

`exec` remains exact-argv, non-PTY, and separate from provider command
injection.

### 5.3 Provider selection

v0.4.0 provider selection is intentionally narrower than the full
target design:

1. If `--provider zmx` is set, the target must have zmx available.
2. If `--provider raw` is set for a persistent operation, the request
   fails with a provider capability error.
3. If any other `--provider` is set, the request fails as unsupported
   by the target.
4. If `--provider` is omitted, the target-side handler selects zmx when
   zmx is available. If zmx is unavailable, persistent operations fail
   rather than silently opening a non-persistent shell.
5. `portl session providers` always returns discovery metadata and may
   report `raw` as available even when no persistent provider exists.

Alias metadata and `PORTL_SESSION_PROVIDER` are recorded/validated for
adapter provisioning, but the v0.4.0 session command does not yet use
alias metadata to choose among multiple providers. There is only one
persistent provider implementation, and `PORTL_SESSION_PROVIDER_PATH`
only influences where the target-side zmx CLI is found.

### 5.4 Provider discovery

`portl session providers <target>` reports target-side availability and
capabilities:

```text
PROVIDER  AVAILABLE  DEFAULT  NOTES
zmx       yes        yes      /usr/local/bin/zmx
raw       yes        no       one-shot PTY fallback
```

JSON shape:

```json
{
  "default_provider": "zmx",
  "providers": [
    {
      "name": "zmx",
      "available": true,
      "path": "/usr/local/bin/zmx",
      "notes": "zmx 0.1.0",
      "capabilities": {
        "persistent": true,
        "multi_attach": true,
        "create_on_attach": true,
        "attach_command": true,
        "run": true,
        "detached_run": false,
        "history": true,
        "tail": false,
        "kill": true,
        "terminal_state_restore": true,
        "external_direct_attach": true,
        "exact_argv_spawn": false
      }
    },
    {
      "name": "raw",
      "available": true,
      "path": null,
      "notes": "one-shot PTY fallback",
      "capabilities": {
        "persistent": false,
        "multi_attach": false,
        "create_on_attach": false,
        "attach_command": false,
        "run": false,
        "detached_run": false,
        "history": false,
        "tail": false,
        "kill": false,
        "terminal_state_restore": false,
        "external_direct_attach": false,
        "exact_argv_spawn": false
      }
    }
  ]
}
```

## 6. Provider interface

The provider interface is intentionally small and capability-based. In
v0.4.0, the code implements this as a concrete `ZmxProvider` helper plus
wire-level `ProviderCapabilities`; the trait below remains the
multi-provider target shape rather than shipped Rust API.

Conceptual Rust shape:

```rust
trait SessionProvider {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> ProviderCapabilities;

    async fn probe(&self) -> Result<ProviderStatus>;
    async fn attach(&self, req: AttachRequest) -> Result<AttachHandle>;
    async fn list(&self, req: ListRequest) -> Result<Vec<SessionInfo>>;
    async fn run(&self, req: RunRequest) -> Result<RunResult>;
    async fn history(&self, req: HistoryRequest) -> Result<HistoryOutput>;
    async fn kill(&self, req: KillRequest) -> Result<()>;
}
```

Capabilities are explicit:

```rust
struct ProviderCapabilities {
    persistent: bool,
    multi_attach: bool,
    create_on_attach: bool,
    attach_command: bool,
    run: bool,
    detached_run: bool,
    history: bool,
    tail: bool,
    kill: bool,
    terminal_state_restore: bool,
    external_direct_attach: bool,
    exact_argv_spawn: bool,
}
```

Do not normalize away real provider differences. If a provider does not
support history, `portl session history` returns a clear provider
capability error. If a provider's `run` is shell injection rather than
exact argv, document it and keep `portl exec` as the exact-argv
primitive. The v0.4.0 zmx bridge sets `exact_argv_spawn = false` for
this reason.

## 7. zmx provider

### 7.1 Integration level

The first zmx implementation shells out to the target-side `zmx` CLI.
This gives a fast vertical slice and preserves direct zmx usability.

v0.4.0 mapping:

| portl operation | zmx command |
| --- | --- |
| `providers` | resolve explicit `PORTL_SESSION_PROVIDER_PATH` or search `/usr/local/bin`, `/usr/bin`, `/bin`; then `zmx version` |
| `attach <session>` | `zmx attach <session>` |
| `attach <session> -- <cmd>...` | `zmx attach <session> <cmd>...` |
| `ls` | `zmx list` |
| `run <session> -- <cmd>...` | `zmx run <session> <cmd>...` |
| `history <session>` | `zmx history <session>` |
| `kill <session>` | `zmx kill <session>` |

The provider command environment is cleared and rebuilt with a safe
`PATH` so provider subprocesses do not inherit portl secrets such as
identity material. Later, portl may speak zmx's Unix-socket IPC directly
for richer status and errors. That remains future work.

### 7.2 Direct zmx use

Do not hide zmx. When portl attaches to a zmx-backed session, the
v0.4.0 CLI prints a small pre-raw-mode hint:

```text
portl: using session provider target default
portl: attaching to session "dev"
```

When `--provider zmx` is supplied, the first line names `zmx` instead of
`target default`.

Where appropriate, setup commands can also print:

```text
Inside the target, you can also run: zmx attach dev
```

Session names should remain human-readable and provider-native unless
the user opts into a prefix.

## 8. Ticket and capability model

### 8.1 v0.4.0 gate

The shipped v0.4.0 implementation gates all session operations with
existing `ShellCaps`:

- attach/create require PTY shell permission,
- run through provider requires PTY shell permission,
- interactive attach is spawned through the existing shell handler and
  honors its user/cwd checks,
- non-interactive provider operations (`providers`, `ls`, `run`,
  `history`, `kill`) run the zmx CLI with a sanitized provider
  environment; they do not yet have dedicated per-operation session
  caps or provider-specific user/cwd switching.

User-facing errors already use session vocabulary:

```text
ticket does not allow persistent sessions
```

not:

```text
shell cap denied
```

### 8.2 Target explicit session caps

Longer term, add a dedicated capability body. Conceptual schema:

```rust
pub struct SessionCaps {
    pub providers_allowed: Option<Vec<String>>,
    pub user_allowlist: Option<Vec<String>>,
    pub session_name_allowlist: Option<Vec<String>>,
    pub create_allowed: bool,
    pub attach_allowed: bool,
    pub list_allowed: bool,
    pub history_allowed: bool,
    pub run_allowed: bool,
    pub kill_allowed: bool,
    pub max_session_ttl_secs: Option<u64>,
    pub max_idle_secs: Option<u64>,
}
```

This body is distinct from `ShellCaps` because the operations are
different. Reading history and killing sessions are not equivalent to
opening an interactive PTY.

### 8.3 Presets

Ticket UX offers friendly presets:

```bash
portl ticket issue session --ttl 1d
portl ticket issue shell --ttl 1d
portl ticket issue exec --ttl 1d
portl ticket issue dev --ttl 7d
```

v0.4.0 meanings:

| Preset | Meaning |
| --- | --- |
| `shell` | full shell access in the current grammar: PTY shell plus exec |
| `exec` | non-PTY exec only; does not grant shell/session |
| `session` | persistent-session preset encoded as full ShellCaps in v0.4.0, so it is not isolated from `shell` until dedicated SessionCaps exist |
| `dev` | alias for `all` in v0.4.0 |

Advanced session-specific cap syntax can follow later. Presets are the
onboarding path.

## 9. Enforcement layers

Keep authorization and implementation separate.

### 9.1 CLI

The CLI:

- parses the command,
- resolves the target,
- asks for the caps needed by the operation,
- prints friendly provenance/provider/session messages,
- bridges the local terminal for interactive attach.

The CLI does not trust alias metadata for authorization and does not
assume provider availability without remote confirmation.

### 9.2 Resolver

The resolver remains target-focused:

```text
input:  "dev"
output: ticket / endpoint connection material
```

It should not know provider internals. It only receives the requested
capabilities for the operation, as it already does for shell/exec/tcp.

### 9.3 Ticket handshake

The ticket handshake remains the trust boundary. It checks validity,
time window, chain, holder proof, revocation, and requested caps.

### 9.4 Session protocol handler

The target-side `session` handler enforces the v0.4.0 baseline:

- session access via existing `ShellCaps`, including user/cwd policy as
  interpreted by shell authorization,
- requested provider is either omitted or `zmx`,
- `raw` is discovery-only and reports unsupported persistent
  capabilities,
- zmx is available before persistent operations run,
- required operation inputs exist, such as session name and run argv.

Dedicated provider allowlists, session-name allowlists, per-operation
session caps, and multi-provider capability dispatch are future work.

### 9.5 Provider

The provider maps authorized session operations to zmx/tmux/zellij or a
native manager. Provider-local permissions may still apply, but they do
not replace portl authorization.

## 10. Wire protocol direction

v0.4.0 adds a separate ALPN rather than overloading `portl/shell/v1`:

```text
portl/session/v1
```

The protocol needs both control-style operations and interactive attach.
Conceptual operation enum:

```rust
enum SessionOp {
    Providers,
    List,
    Attach,
    Run,
    History,
    Kill,
}
```

Conceptual request:

```rust
struct SessionReq {
    op: SessionOp,
    provider: Option<String>,
    session_name: Option<String>,
    user: Option<String>,
    cwd: Option<String>,
    argv: Option<Vec<String>>,
    pty: Option<PtyCfg>,
}
```

For interactive attach, the client and agent bridge byte streams in the
same broad shape as shell/v1. The provider is responsible for terminal
state and persistence; portl is responsible for auth, transport, and
stream bridging.

## 11. Docker and Slicer integration

Adapters provision targets. v0.4.0 Docker and Slicer surfaces accept
`--session-provider zmx`, can make zmx available for managed targets,
and record provider metadata in `aliases.json`. `portl session` remains
target-neutral and confirms provider availability with the target-side
agent.

### 11.1 Docker bake

Best path for reliable Docker targets:

```bash
portl docker bake ubuntu:24.04 --session-provider zmx --tag ubuntu-portl-zmx
portl docker run ubuntu-portl-zmx --name dev
portl session attach dev
```

The generated image includes `portl-agent` and provider env/config. If
`PORTL_ZMX_BINARY` is set, the bake context copies that zmx binary to
`/usr/local/bin/zmx` and sets `PORTL_SESSION_PROVIDER_PATH`; otherwise
the Dockerfile requires the base image to already provide `zmx`.

### 11.2 Docker runtime injection

Convenience path for demos and arbitrary images:

```bash
portl docker run ubuntu:24.04 --name dev --session-provider zmx
portl docker attach existing --session-provider zmx
```

The adapter copies a target-appropriate zmx binary when
`PORTL_ZMX_BINARY` is set; otherwise it verifies that `zmx` already
exists in the container. It records provider metadata in `aliases.json`
and sets agent/provider env where possible.

This path is convenient but less deterministic than bake: minimal
images, cross-architecture binaries, glibc/musl compatibility, and
restricted networks may all matter.

### 11.3 Slicer

Slicer supports provider installation metadata in userdata:

```bash
portl slicer run dev-image --session-provider zmx
portl session attach <vm-alias>
```

The userdata request carries `session_provider: "zmx"` when requested,
and the local alias metadata records the provider. The exact target-side
installation behavior is owned by the Slicer adapter/userdata path.

### 11.4 Manual hosts

Do not silently mutate manual hosts. If a provider is missing:

```text
error: zmx is not installed on dev

Try:
  portl shell dev

Or install zmx explicitly on the target.
```

A future explicit command may exist:

```bash
portl session install-provider dev zmx
```

but it must be explicit and auditable.

## 12. Alias and config metadata

Alias metadata records provider expectations in v0.4.0:

```rust
pub struct StoredSpec {
    // existing fields...
    pub session_provider: Option<String>,
    pub session_provider_install: Option<SessionProviderInstall>,
}

pub struct SessionProviderInstall {
    pub provider: String,
    pub version: Option<String>,
    pub path: Option<PathBuf>,
    pub installed_by_portl: bool,
}
```

Agent config/env includes:

```text
PORTL_SESSION_PROVIDER=zmx
PORTL_SESSION_PROVIDER_PATH=/usr/local/bin/zmx
```

A future native/session-manager provider may add state-directory config
such as `PORTL_SESSION_DIR`, but v0.4.0 does not implement it.

`PORTL_SESSION_PROVIDER` is parsed/validated as `zmx` but is not yet a
multi-provider selection mechanism. `PORTL_SESSION_PROVIDER_PATH` is the
path the zmx bridge uses before falling back to safe-path discovery.
Provider-specific env must preserve direct-provider usability. For zmx,
be careful with `ZMX_DIR`: a private portl-owned socket directory is
good for Docker isolation but may make direct `zmx attach` harder on
manual/user hosts.

Suggested defaults:

| Target type | Provider state directory |
| --- | --- |
| Docker-managed container | portl-managed directory, e.g. `/var/lib/portl/zmx` |
| Slicer VM running as a service | portl-managed unless a target user is configured |
| User-level/manual agent | provider default, e.g. zmx's normal runtime dir |

## 13. Revocation and lifecycle

Persistent external sessions are target resources, not purely portl
objects. The default rule:

> Revocation prevents new access immediately. Killing existing
> provider sessions is explicit unless portl owns the target lifecycle.

Implications:

- A revoked ticket cannot attach, run, read history, list, or kill.
- Existing zmx/tmux/zellij sessions may continue on the target because
  users can access them outside portl.
- Docker/Slicer teardown kills sessions by destroying or stopping the
  target.
- A future native provider may support stricter kill-on-revoke because
  portl owns the session manager.

If stricter behavior is needed later, make it explicit in session caps
or provider policy rather than surprising users.

## 14. Audit

v0.4.0 adds audit events distinct from existing `shell_start` /
`shell_exit` for the shipped operations, and the target model leaves
room for future lifecycle events:

```text
audit.session_providers
audit.session_attach
audit.session_detach     # future explicit lifecycle/control event
audit.session_create     # future explicit lifecycle/control event
audit.session_run
audit.session_history
audit.session_kill
audit.session_reject
```

Implemented common fields:

```text
ticket_id
caller_endpoint_id
provider
session_name
operation
session_user
session_cwd
session_argv0
reason
```

`target_endpoint_id` and richer lifecycle state can be added later if
needed.

Preserve the current audit principle: do not log secrets or full argv
vectors by default.

## 15. Error messages

Errors must teach the model. v0.4.0 implements session-vocabulary
client errors for capability denial, unsupported providers,
unavailable zmx, unsupported raw capabilities, missing session names,
missing run argv, provider spawn failure, and internal errors. The more
context-rich examples below remain the target UX direction for follow-on
polish.

Unknown target:

```text
error: unknown target "dev"

A target can be a peer, saved ticket, docker/slicer alias, inline ticket,
or endpoint id.

Try:
  portl peer ls
  portl ticket ls
  portl docker ls
  portl slicer ls
```

No provider:

```text
using alias "dev" (docker)
error: dev does not have a persistent session provider

Available:
  raw shell: yes
  zmx: no
  tmux: no
  zellij: no

Try:
  portl shell dev

Or enable zmx for this Docker target:
  portl docker attach dev --session-provider zmx
```

Ticket lacks permission:

```text
using ticket "customer"
error: ticket "customer" does not allow persistent sessions

This command needs:
  session.attach

Try:
  portl shell customer

Or ask the issuer for a ticket with session access.
```

Provider not allowed:

```text
error: ticket allows persistent sessions, but not provider "tmux"

Allowed providers:
  zmx
```

Operation not allowed:

```text
error: ticket allows attaching to sessions, but not killing them

This command needs:
  session.kill
```

## 16. Top-level help impact

With `session` shipped, the help grouping treats `ticket` as advanced
permissions and `session` as a connection verb:

```text
Setup
  init, doctor, install, config, whoami

Trust
  invite, accept, peer

Connect
  status, shell, session, exec, tcp, udp

Permissions
  ticket

Integrations
  docker, slicer, gateway
```

Top-level examples:

```text
Connect to a target:
  portl shell dev              # one-shot interactive shell
  portl session attach dev     # persistent shell session
  portl exec dev -- uname -a   # script-friendly command
```

## 17. Phased rollout

### Phase 1 — UX and protocol skeleton (shipped in v0.4.0)

- Added `portl session` command surface.
- Added `portl/session/v1` request/response structs.
- Added provider discovery.
- Implemented `raw` provider metadata as a non-persistent fallback for
  discovery only, not as silent fallback for persistent commands.

### Phase 2 — zmx vertical slice (shipped in v0.4.0)

- Implemented zmx provider via external CLI.
- Supported `attach`, `providers`, `ls`, `run`, `history`, and `kill`.
- Gated with existing shell caps while preserving session vocabulary in
  errors.
- Added audit events.

### Phase 3 — adapter provisioning (baseline shipped in v0.4.0)

- Added `--session-provider zmx` to Docker run/attach/bake.
- Added `--session-provider zmx` to Slicer run/userdata.
- Stored provider metadata in alias specs.
- Surface provider status in `status`, `docker ls`, or `slicer ls`
  once the discovery flow is stable. v0.4.0 records Docker/Slicer alias
  metadata and includes Docker `session_provider` in JSON listing, but
  broad status/list surfacing remains follow-on.

### Phase 4 — explicit session caps (future)

- Add `SessionCaps` to ticket schema.
- Move the friendly `session` preset from ShellCaps encoding to
  dedicated SessionCaps semantics.
- Update resolver/requested caps for every session operation.

### Phase 5 — additional providers (future)

- Add tmux provider if command mapping is reliable.
- Add zellij provider after an API spike.
- Consider native provider only if external providers cannot satisfy
  core use cases.

### Phase 6 — session-control lanes (future, spec 210)

- Define viewport-aware attach/control behavior in
  `docs/specs/210-session-control-lanes.md`.
- Define any explicit control lanes for resize, detach, tail/follow,
  active attach state, or richer provider-native status there rather
  than expanding this baseline spec.

## 18. Acceptance criteria

The v0.4.0 baseline feature slice is accepted when:

1. `portl session providers <target>` works for a target with and
   without zmx.
2. `portl session attach <target>` attaches to a zmx-backed session and
   reconnects after client disconnect.
3. `portl session attach <target> -- <cmd>...` creates/attaches via zmx
   and starts the command.
4. `portl session ls`, `run`, `history`, and `kill` map to zmx and fail
   clearly when unsupported.
5. `portl exec` behavior is unchanged.
6. `portl shell` behavior is unchanged except for separately-approved
   ergonomic improvements.
7. Docker or Slicer can provision a target with zmx such that the next
   command is `portl session attach <alias>`.
8. Errors use persistent-session vocabulary for permission, provider,
   missing-input, and provider-spawn failures. Naming every target
   source and next command remains follow-on polish.
9. Audit records distinguish session operations from one-shot shell
   operations.

These criteria are satisfied for the baseline shipped in v0.4.0, with
criterion 8 intentionally scoped to the implemented error vocabulary.

## 19. Resolved baseline decisions and follow-on questions

Resolved in v0.4.0:

1. `portl session attach <target>` requires a persistent provider;
   `raw` is discovery-only and is not a silent fallback.
2. Default session names remain human-readable: target label/alias when
   available, otherwise `default` for inline tickets and raw endpoint
   ids.
3. The friendly `session` ticket preset exists and is encoded as
   ShellCaps until dedicated SessionCaps are added.
4. Manual hosts are not silently mutated; missing zmx errors direct the
   user toward `portl shell` or explicit zmx installation.

Still future:

1. How much provider installation should `portl session install-provider`
   eventually support on manual hosts?
2. Should Slicer default to zmx once the provider path is proven?
3. Which viewport-aware/session-control behaviors belong in the next
   layer? Answer in `docs/specs/210-session-control-lanes.md`, not in
   this baseline spec.
