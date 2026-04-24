# 200 — Persistent Sessions and Providers

> Status: **implemented in v0.4.0 as an MVP slice**. The shipped
> implementation adds `portl/session/v1`, top-level `portl session`,
> zmx CLI bridging, raw discovery fallback, Docker/Slicer provider
> hints, and ShellCaps-based authorization with session-vocabulary
> errors. Dedicated `SessionCaps`, richer provider-native APIs, and
> additional providers remain future work described by this target
> design.

## 1. Summary

portl currently has two terminal-adjacent primitives:

- `portl shell <target>` opens a one-shot remote PTY and dies when the
  client disconnects.
- `portl exec <target> -- <argv>...` runs a non-PTY command with
  separate stdin/stdout/stderr and script-friendly exit-code behavior.

This spec adds a third primitive:

- `portl session ...` manages persistent terminal workspaces on a
  target.

The key mental model is:

```text
peer    = where / who
ticket  = permission
session = persistent terminal workspace
provider = how the target keeps the session alive
```

The first provider is `zmx`, because it already solves the hard human
terminal problems: attach/detach, multiple clients, history, and
terminal-state restoration via Ghostty's virtual terminal machinery.
The portl design must not become zmx-specific: `tmux`, `zellij`, and a
future native provider remain possible providers behind the same
capability-gated interface.

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
alive. Initial providers:

| Provider | Role |
| --- | --- |
| `raw` | Current one-shot PTY behavior; non-persistent fallback. |
| `zmx` | First persistent provider. Uses zmx commands on the target. |
| `tmux` | Future external multiplexer provider. |
| `zellij` | Future external multiplexer provider. |
| `native` | Future portl-owned persistent manager, likely backed by libghostty-vt bindings if terminal-state restoration is required. |

Provider support is capability-discovered, not assumed.

## 5. CLI surface

### 5.1 New command group

Add a top-level command group:

```text
portl session <subcommand>
```

This command lives in the **Connect** help group from
`190-cli-ergonomics.md`. `ticket` remains the advanced
**Permissions** namespace; `session` is the user-facing terminal
workspace namespace.

Initial subcommands:

```bash
portl session attach <target> [session] [--provider PROVIDER] [--user USER] [--cwd CWD] [-- <cmd>...]
portl session providers <target> [--json]
portl session ls <target> [--provider PROVIDER] [--json]
portl session run <target> [session] [--provider PROVIDER] -- <cmd>...
portl session history <target> [session] [--provider PROVIDER] [--format plain|vt|html]
portl session kill <target> [session] [--provider PROVIDER]
```

`attach` is the primary happy-path command. It attaches to the named
session, creating it if the provider supports create-on-attach.

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

Provider selection is deterministic:

1. If `--provider` is set, use that provider or return an actionable
   error.
2. Else if alias metadata names a preferred provider, use it if
   available.
3. Else if remote agent config names a preferred provider, use it if
   available.
4. Else choose the best available provider by default order:
   `zmx`, `tmux`, `zellij`, `native`, `raw`.
5. If the requested operation requires persistence and only `raw` is
   available, error rather than silently opening a non-persistent shell.

### 5.4 Provider discovery

`portl session providers <target>` reports target-side availability and
capabilities:

```text
PROVIDER  AVAILABLE  DEFAULT  NOTES
zmx       yes        yes      /usr/local/bin/zmx
tmux      no         no       not found
zellij    no         no       not found
raw       yes        no       one-shot PTY fallback
```

JSON shape:

```json
{
  "target": "dev",
  "default_provider": "zmx",
  "providers": [
    {
      "name": "zmx",
      "available": true,
      "path": "/usr/local/bin/zmx",
      "capabilities": {
        "persistent": true,
        "multi_attach": true,
        "history": true,
        "run": true,
        "terminal_state_restore": true,
        "external_direct_attach": true
      }
    }
  ]
}
```

## 6. Provider interface

The internal provider abstraction is intentionally small and
capability-based.

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
primitive.

## 7. zmx provider

### 7.1 Integration level

The first zmx implementation shells out to the target-side `zmx` CLI.
This gives a fast vertical slice and preserves direct zmx usability.

Initial mapping:

| portl operation | zmx command |
| --- | --- |
| `providers` | `command -v zmx`, `zmx version` |
| `attach <session>` | `zmx attach <session>` |
| `attach <session> -- <cmd>...` | `zmx attach <session> <cmd>...` |
| `ls` | `zmx list` |
| `run <session> -- <cmd>...` | `zmx run <session> <cmd>...` |
| `history <session>` | `zmx history <session>` |
| `kill <session>` | `zmx kill <session>` |

Later, portl may speak zmx's Unix-socket IPC directly for richer
status and errors. That is an optimization, not the first design.

### 7.2 Direct zmx use

Do not hide zmx. If portl attaches to a zmx-backed session, the CLI may
print a pre-raw-mode hint:

```text
portl: using alias "dev" (docker)
portl: using session provider zmx
portl: attaching to session "dev" as root
```

Where appropriate, setup commands can also print:

```text
Inside the target, you can also run: zmx attach dev
```

Session names should remain human-readable and provider-native unless
the user opts into a prefix.

## 8. Ticket and capability model

### 8.1 MVP gate

The first implementation may gate session operations with existing
`ShellCaps`:

- attach/create require PTY shell permission,
- run through provider requires PTY shell permission,
- provider command execution is still subject to env/user policy where
  possible.

However, user-facing errors should already use session vocabulary:

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

Ticket UX should offer friendly presets:

```bash
portl ticket issue --caps session --ttl 1d
portl ticket issue --caps shell --ttl 1d
portl ticket issue --caps exec --ttl 1d
portl ticket issue --caps dev --ttl 7d
```

Suggested meanings:

| Preset | Meaning |
| --- | --- |
| `shell` | one-shot PTY shell only |
| `exec` | non-PTY exec only |
| `session` | persistent session attach/create/run/history, no kill by default |
| `dev` | shell + exec + session + localhost TCP/UDP conveniences |

Advanced cap syntax can follow later. Presets are the onboarding path.

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

The target-side `session` handler enforces:

- operation allowed by ticket caps,
- provider allowed by ticket caps,
- user allowed by ticket caps,
- session name allowed by ticket caps,
- provider is available,
- provider supports the requested operation.

### 9.5 Provider

The provider maps authorized session operations to zmx/tmux/zellij or a
native manager. Provider-local permissions may still apply, but they do
not replace portl authorization.

## 10. Wire protocol direction

Add a separate ALPN rather than overloading `portl/shell/v1`:

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

Adapters provision targets. They can also make providers available and
record expected provider metadata. `portl session` remains
target-neutral.

### 11.1 Docker bake

Best path for reliable Docker targets:

```bash
portl docker bake ubuntu:24.04 --session-provider zmx --tag ubuntu-portl-zmx
portl docker run ubuntu-portl-zmx --name dev
portl session attach dev
```

The generated image includes `portl-agent`, `zmx`, and default provider
env/config.

### 11.2 Docker runtime injection

Convenience path for demos and arbitrary images:

```bash
portl docker run ubuntu:24.04 --name dev --session-provider zmx
portl docker attach existing --session-provider zmx
```

The adapter copies a target-appropriate zmx binary alongside
`portl-agent`, records provider metadata in `aliases.json`, and sets
agent/provider env where possible.

This path is convenient but less deterministic than bake: minimal
images, cross-architecture binaries, glibc/musl compatibility, and
restricted networks may all matter.

### 11.3 Slicer

Slicer should support provider installation in userdata:

```bash
portl slicer run dev-image --session-provider zmx
portl session attach <vm-alias>
```

The userdata installs portl, installs zmx when requested, and writes a
provider default into `/etc/portl/agent.env` or future config.

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

Alias metadata may record provider expectations:

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

Agent config/env may eventually include:

```text
PORTL_SESSION_PROVIDER=zmx
PORTL_SESSION_PROVIDER_PATH=/usr/local/bin/zmx
PORTL_SESSION_DIR=/var/lib/portl/sessions
```

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

Add audit events distinct from existing `shell_start` / `shell_exit`:

```text
audit.session_providers
audit.session_attach
audit.session_detach
audit.session_create
audit.session_run
audit.session_history
audit.session_kill
audit.session_reject
```

Common fields:

```text
ticket_id
caller_endpoint_id
target_endpoint_id
provider
session_name
operation
user
cwd
argv0
reason
```

Preserve the current audit principle: do not log secrets or full argv
vectors by default.

## 15. Error messages

Errors must teach the model.

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

Once `session` exists, the help grouping should treat `ticket` as
advanced permissions and `session` as a connection verb:

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

### Phase 1 — UX and protocol skeleton

- Add `portl session` command surface.
- Add `portl/session/v1` request/response structs.
- Add provider discovery.
- Implement `raw` provider as a non-persistent fallback for discovery
  only, not as silent fallback for persistent commands.

### Phase 2 — zmx vertical slice

- Implement zmx provider via external CLI.
- Support `attach`, `providers`, `ls`, `run`, `history`, and `kill`.
- Gate with existing shell caps initially while preserving session
  vocabulary in errors.
- Add audit events.

### Phase 3 — adapter provisioning

- Add `--session-provider zmx` to Docker run/attach/bake.
- Add `--session-provider zmx` to Slicer run/userdata.
- Store provider metadata in alias specs.
- Surface provider status in `status`, `docker ls`, or `slicer ls`
  once the discovery flow is stable.

### Phase 4 — explicit session caps

- Add `SessionCaps` to ticket schema.
- Add friendly cap presets.
- Update resolver/requested caps for every session operation.

### Phase 5 — additional providers

- Add tmux provider if command mapping is reliable.
- Add zellij provider after an API spike.
- Consider native provider only if external providers cannot satisfy
  core use cases.

## 18. Acceptance criteria

The first complete feature slice is accepted when:

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
8. Errors name the relevant target source, permission, provider, and
   next command.
9. Audit records distinguish session operations from one-shot shell
   operations.

## 19. Open questions

1. Should `portl session attach <target>` require zmx/persistence, or
   may it attach through `raw` with an explicit warning? This spec
   recommends erroring when persistence was requested and only `raw` is
   available.
2. Should zmx session names be prefixed by default on Docker/Slicer
   targets, e.g. `portl-dev`, or should direct human names win? This
   spec recommends human names, with opt-in prefixing later.
3. Should `session.run` be included in the friendly `session` ticket
   preset? zmx supports it, but it is shell injection rather than
   exact-argv execution. This spec recommends including it but making
   docs point users to `exec` for exact argv.
4. How much provider installation should `portl session install-provider`
   eventually support on manual hosts? This spec keeps manual mutation
   explicit and out of the MVP.
5. Should Slicer default to zmx once the provider path is proven? This
   spec allows that as a later adapter policy, not a protocol rule.
