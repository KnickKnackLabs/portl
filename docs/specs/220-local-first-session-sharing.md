# 220 — Local-First Sessions, Workspace Sharing, and Short Codes

> Status: **proposed follow-on** after `210-session-control-lanes.md`.
> This spec revisits the session ergonomics shipped in v0.4.0/v0.5.0
> and designs a local-first workflow where `portl session` is the
> default way to start a reusable terminal workspace, then share it
> later through short online codes or long offline tokens. It does not
> replace the provider-control work in spec 210; it builds a portable
> workspace and exchange layer above it.

## 1. Summary

Portl's current session surface is remote-first:

```bash
portl shell <TARGET>                  # one-shot PTY
portl session attach <TARGET> [NAME]  # persistent remote provider session
```

That works technically, but it makes persistent sessions feel like an
advanced remote-management feature. The next UX step should make
sessions feel like the natural starting point:

```bash
portl session        # create/attach a local generated workspace
portl session dev    # create/attach local workspace "dev"
portl session share dev
portl join PORTL-S-2-nebula-involve
```

The key design move is to separate three concepts:

```text
workspace = Portl's stable, portable identity for a terminal workspace
binding   = where/how that workspace is backed today (local zmx, remote tmux, Docker, ...)
exchange  = how workspace/ticket/peer metadata is handed to another user
```

Friendly names stay human. Portl stores stable hidden workspace IDs and
short conflict handles so a local `dev`, a remote `dev@shared-box`, and
an imported `dev#7k3p` can coexist without forcing ugly provider names.

Short online codes are generic Portl exchange codes:

```text
PORTL-S-2-nebula-involve
```

They are provider-agnostic in the visible UX. The first backend may be
Magic Wormhole's public rendezvous server, but backend selection belongs
in Portl config. A future Portl mailbox or self-hosted backend should be
able to carry the same Portl exchange envelope without changing the
normal code shape.

Long offline tokens remain available for asynchronous copy/paste:

```text
PORTL-SHARE1-...
```

They contain the same session-share envelope directly instead of
transporting it through a rendezvous backend.

## 2. Relationship to existing specs

- `200-persistent-sessions.md` defines the shipped provider-backed
  session baseline: `portl/session/v1`, `portl session attach`, zmx,
  Docker/Slicer provider provisioning, and provider-native names.
- `210-session-control-lanes.md` defines the v0.5.0 optimized provider
  slice: zmx-control, tmux `-CC`, provider tiers, and viewport/live
  control semantics.
- This spec adds a **Portl workspace registry and exchange layer** above
  those providers. It keeps the explicit remote provider commands and
  does not remove `portl shell` or `portl exec`.

## 3. Goals

1. **Make `portl session` local-first.** A newcomer should be able to
   run `portl session` or `portl session dev` without already thinking
   about targets, tickets, or providers.
2. **Make sharing feel like a follow-on action.** Start locally, then
   run `portl session share dev` when someone else should join.
3. **Keep names friendly.** Use `dev` normally; show `dev@shared-box` or
   `dev#7k3p` only when a conflict exists.
4. **Use stable hidden identity.** Workspaces need globally unique IDs
   so friendly-name collisions do not confuse imports or future sync.
5. **Model multiple bindings from day one.** A workspace may later have
   local, remote, Docker/Slicer, and synced metadata bindings, with one
   default active binding in the initial UX.
6. **Use one exchange envelope across transports.** Short codes,
   offline tokens, QR codes, and future mailboxes should all carry the
   same typed Portl payloads.
7. **Generalize short codes.** The short-code layer should carry session
   shares, ticket shares, peer invites, and peer/endpoint cards.
8. **Keep authority in Portl tickets.** Metadata and workspace identity
   never grant terminal access by themselves.
9. **Keep rendezvous out of the hot path.** Short-code services are used
   only for share/join setup. Later session attach uses normal Portl/Iroh
   transport.

## 4. Non-goals

- Removing `portl shell`, `portl exec`, or explicit remote
  `portl session attach <TARGET> [SESSION]`.
- Making provider-native zmx/tmux session names globally unique.
- Building a permanent URL-shortener service that stores authority-bearing
  tickets under short keys.
- Requiring Magic Wormhole as the only possible short-code backend.
- Requiring Iroh Docs metadata sync in the first implementation slice.
- Making metadata-document access equivalent to terminal/session access.

## 5. Core model

### 5.1 Workspace

A workspace is Portl's stable identity for a reusable terminal workspace.

Conceptual schema:

```rust
struct WorkspaceRecord {
    id: WorkspaceId,             // globally unique, hidden by default
    friendly_name: String,       // "dev"
    conflict_handle: String,     // short stable handle, e.g. "7k3p"
    created_at_unix: u64,
    updated_at_unix: u64,
    default_binding: BindingId,
    bindings: Vec<WorkspaceBinding>,
    imported_from: Option<ImportSource>,
}
```

The initial storage can be a local JSON file under `$PORTL_HOME`, for
example:

```text
$PORTL_HOME/workspaces.json
```

The on-disk format should include a schema version so a later redb/SQLite
or Iroh Docs-backed store can migrate it.

### 5.2 Friendly refs

Common case:

```text
dev
```

Qualified forms when needed:

```text
dev@thinh-mac    # origin/target qualifier
dev#7k3p         # conflict handle qualifier
ws_...           # hidden stable ID, accepted for scripting/debugging
```

Friendly names are local aliases, not global authority. The stable
workspace ID is the only globally unique identity.

### 5.3 Binding

A binding tells Portl where/how to attach the workspace.

```rust
struct WorkspaceBinding {
    id: BindingId,
    kind: BindingKind,
    target: BindingTarget,
    provider: Option<String>,
    provider_session: String,
    provider_features: Vec<String>,
    role_hint: Option<ShareRole>,
    last_seen_unix: Option<u64>,
}

enum BindingKind {
    LocalProvider,
    RemoteTarget,
    DockerTarget,
    SlicerTarget,
    ImportedShare,
    MetadataSynced,
}
```

Initial UX should use one default binding. The data model still allows
multiple bindings so later imports and metadata sync do not force a
schema break.

### 5.4 Local attach path

Local-first `portl session` should not depend on Iroh self-connecting to
the local agent. Earlier validation showed self-connect is unsupported in
the current Iroh path. Local attach should use a local provider path or a
local agent IPC path:

```text
portl session dev
  -> resolve/create local workspace "dev"
  -> resolve default local provider (zmx preferred, tmux fallback)
  -> attach/create provider session "dev"
```

Remote sharing still uses normal Portl ticket/session protocols.

## 6. CLI surface

### 6.1 Local-first happy path

```bash
portl session
portl session dev
```

Behavior:

- no argument: generate a friendly local workspace name, create registry
  entry, attach/create local provider session;
- one non-subcommand argument: resolve/create local workspace by friendly
  name, attach default binding;
- if the name is ambiguous, print choices and ask for a qualifier or fail
  with actionable guidance in non-TTY mode.

Generated names should be memorable slugs, not provider IDs:

```text
quiet-lab
amber-fox
swift-river
```

### 6.2 Existing explicit remote commands

Keep the existing remote provider surface:

```bash
portl session attach <TARGET> [SESSION] [--provider PROVIDER] [--user USER] [--cwd CWD] [-- <ARGV>...]
portl session providers <TARGET> [--json]
portl session ls <TARGET> [--provider PROVIDER] [--json]
portl session run <TARGET> [SESSION] [--provider PROVIDER] -- <ARGV>...
portl session history <TARGET> [SESSION] [--provider PROVIDER]
portl session kill <TARGET> [SESSION] [--provider PROVIDER]
```

These remain useful for direct target/provider management and for
backward compatibility.

### 6.3 Sharing and joining

```bash
portl session share [WORKSPACE]
portl session share [WORKSPACE] --offline
portl session join <CODE_OR_TOKEN>
portl join <CODE_OR_TOKEN>
```

`portl join` is the generic newcomer command: if someone sends you a
Portl thing, run `portl join <thing>`. It dispatches by prefix or by
short-code rendezvous payload kind.

Inputs it should understand:

```text
PORTL-S-*       short online exchange code
PORTL-SHARE1-*  long offline session/workspace share
PORTLINV-*      existing peer invite
portl...        existing Portl ticket
PORTL-PEER1-*   future peer/endpoint card
```

Specific commands can remain aliases for clarity:

```bash
portl accept PORTLINV-...
portl ticket save LABEL portl...
portl session join PORTL-S-...
```

## 7. Exchange envelope

Short codes and offline tokens carry typed Portl exchange envelopes.

```rust
struct PortlExchangeEnvelopeV1 {
    schema: String,              // "portl.exchange.v1"
    kind: ExchangeKind,
    created_at_unix: u64,
    not_after_unix: Option<u64>, // envelope/import TTL, not access TTL
    sender: SenderHint,
    payload: ExchangePayload,
}

enum ExchangePayload {
    SessionShare(SessionShareEnvelopeV1),
    TicketShare(TicketShareEnvelopeV1),
    PeerInvite(PeerInviteEnvelopeV1),
    PeerCard(PeerCardEnvelopeV1),
    MetadataDoc(MetadataDocEnvelopeV1),
}
```

The envelope is transport-independent. Magic Wormhole, a future Portl
mailbox, offline tokens, QR codes, and files can all carry it.

## 8. Session-share payload

```rust
struct SessionShareEnvelopeV1 {
    workspace: WorkspaceRefV1,
    target: EndpointCardV1,
    binding: SessionBindingV1,
    access: AccessGrantV1,
    metadata: Option<MetadataDocEnvelopeV1>,
}

struct WorkspaceRefV1 {
    workspace_id: String,
    friendly_name: String,
    conflict_handle: String,
    origin_label_hint: Option<String>,
}

struct EndpointCardV1 {
    endpoint_id: EndpointId,
    endpoint_addr: EndpointAddr,
    label_hint: Option<String>,
    relay_urls: Vec<RelayUrl>,
    direct_addrs_included: bool,
}

struct SessionBindingV1 {
    provider: Option<String>,
    provider_session: String,
    provider_features: Vec<String>,
    role_hint: Option<ShareRole>,
}

struct AccessGrantV1 {
    ticket: Vec<u8>,
    chain: Vec<Vec<u8>>,
    ticket_id: [u8; 16],
    access_not_after_unix: u64,
}
```

### 8.1 Endpoint details

Iroh's `EndpointAddr` already contains the important dialing details:

```rust
struct EndpointAddr {
    id: EndpointId,
    addrs: BTreeSet<TransportAddr>,
}

enum TransportAddr {
    Relay(RelayUrl),
    Ip(SocketAddr),
    Custom(CustomAddr),
}
```

The long offline envelope should include at least:

- endpoint ID;
- current home relay URL, if known;
- enough canonical Portl ticket bytes to authorize the operation.

Direct IP socket addresses are useful but may leak private topology.
The default offline token should include relay information and may omit
direct addresses unless the user passes an explicit flag such as
`--include-direct-addrs`.

### 8.2 Authority validation

The Portl ticket is authoritative. Duplicated target fields in the
envelope are for UX and diagnostics only.

Import must verify:

```text
envelope.target.endpoint_id == ticket.body.target == ticket.addr.id
```

If these disagree, reject the envelope. Metadata/doc tickets never grant
terminal access.

## 9. Other exchange payloads and overlap

### 9.1 Ticket share

Existing long form:

```text
portl...
```

Short exchange:

```bash
portl ticket share dev-access
portl join PORTL-S-4-panda-lantern
```

Payload:

```rust
struct TicketShareEnvelopeV1 {
    ticket: Vec<u8>,
    chain: Vec<Vec<u8>>,
    ticket_id: [u8; 16],
    label_hint: Option<String>,
    save_as_hint: Option<String>,
}
```

This transfers the ticket, not merely a ticket ID. A ticket ID is useful
for display/revocation but is not enough to grant access.

### 9.2 Peer invite

Existing long form:

```text
PORTLINV-...
```

Short exchange:

```bash
portl invite --short
portl join PORTL-S-8-river-copper
```

First implementation can transport the existing invite code:

```rust
struct PeerInviteEnvelopeV1 {
    invite_code: String,
    label_hint: Option<String>,
}
```

Recipient flow:

```text
receive envelope -> extract PORTLINV -> run existing accept flow
```

This keeps peer pairing semantics separate from session sharing.

### 9.3 Peer/endpoint card

An endpoint card shares identity and dialing hints without granting
terminal access.

```rust
struct PeerCardEnvelopeV1 {
    endpoint: EndpointCardV1,
    display_name: Option<String>,
    fingerprint_words: Option<String>,
}
```

This can support future identity-only sharing:

```bash
portl peer share-card
portl join PORTL-S-6-orbit-silver
```

### 9.4 Session share versus ticket

A `PortlTicket` already contains endpoint ID, endpoint address hints,
capabilities, validity, issuer/signature, optional holder binding, and
delegation parent reference. `SessionShareEnvelopeV1` adds workspace
identity, friendly names, conflict handles, provider/session binding,
display hints, optional metadata sync, and ticket chain material.

Do not duplicate ticket authority in session metadata.

## 10. Short-code rendezvous

Visible short codes are provider-agnostic:

```text
PORTL-S-2-nebula-involve
```

They mean "short online Portl exchange code", not "Magic Wormhole code"
or "Portl mailbox code".

Backend selection is configuration-driven:

```toml
[rendezvous]
default = "magic-wormhole"
fallbacks = []

[[rendezvous.backends]]
name = "magic-wormhole"
kind = "magic-wormhole"
url = "ws://relay.magic-wormhole.io:4000/v1"
```

Future config:

```toml
[rendezvous]
default = "portl-mailbox"
fallbacks = ["magic-wormhole"]

[[rendezvous.backends]]
name = "portl-mailbox"
kind = "portl-mailbox"
url = "https://rendezvous.portl.dev"

[[rendezvous.backends]]
name = "magic-wormhole"
kind = "magic-wormhole"
url = "ws://relay.magic-wormhole.io:4000/v1"
compat = true
```

Do not blindly probe every possible backend. Try the configured default,
then explicit fallbacks. Add advanced override later:

```bash
portl join --rendezvous my-mailbox PORTL-S-...
```

Internal namespacing still matters:

```text
Magic Wormhole AppID: portl.exchange.v1
Portl mailbox ALPN/API: portl/rendezvous/v1
Envelope schema: portl.exchange.v1
```

### 10.1 Magic Wormhole as first backend

The scratch POC showed Magic Wormhole can exchange a full long Iroh
gossip bootstrap ticket locally and cross-machine. For Portl, the
transported payload should be `PortlExchangeEnvelopeV1`.

The `magic-wormhole` Rust crate exposes the needed core APIs with
default features disabled:

```toml
magic-wormhole = { version = "0.8", default-features = false }
```

This uses the rendezvous mailbox, SPAKE2/PAKE, key derivation, and
encrypted peer messages without the file-transfer/transit/forwarding
features. Before making it a required production dependency, review:

- EUPL-1.2 license compatibility with Portl's MIT license;
- dependency footprint and async-runtime integration;
- public relay availability and self-hosted relay options.

If license or production-suitability concerns block the dependency,
keep the same envelope and backend abstraction and implement a Portl
mailbox backend instead.

## 11. Security and lifecycle

Separate lifetimes:

```text
rendezvous TTL = how long a short code can be joined
envelope TTL   = how long an offline/import envelope should be accepted
access TTL     = how long the embedded Portl ticket grants access
workspace ID   = stable identity, not authority
```

Short online exchanges should be one-time by default. The sharer should
mint recipient-bound tickets where possible after learning the recipient
endpoint ID during rendezvous. If the exchange payload leaks afterward,
proof-of-possession should prevent use by a third party.

The rendezvous service must never be in the terminal hot path and should
never be treated as an authority store.

Bad model:

```text
PORTL-ABCD -> central server stores reusable Portl ticket
```

Good model:

```text
PORTL-S-* -> one-time PAKE rendezvous -> encrypted envelope -> native object imported
```

## 12. Newcomer onboarding after implementation

The logical guide should start with the session-first mental model:

```text
1. Install Portl and initialize identity.
2. Start a local session workspace.
3. Keep working normally.
4. Share the workspace when someone else needs to join.
5. Recipient runs one `portl join` command.
6. Both sides can return to the workspace by name later.
```

Minimal guide:

```bash
# One-time setup on your machine.
portl init
portl doctor

# Start a local persistent workspace.
portl session dev

# Share it when ready.
portl session share dev
# Share code: PORTL-S-2-nebula-involve

# On the other machine.
portl init
portl join PORTL-S-2-nebula-involve

# Later, reconnect by name.
portl session dev@alice-laptop
```

The guide should introduce long/offline links only after the short online
path:

```bash
portl session share dev --offline
# PORTL-SHARE1-...
```

Explain the difference:

```text
Short code: both sides online, easiest to read aloud, expires quickly.
Offline token: long, copyable later, contains full bootstrap/access payload.
Peer pairing: durable relationship for repeated access.
```

## 13. Example: local zmx-backed workspace

### Sharer

Install and verify a provider:

```bash
portl init
portl doctor
zmx control --probe
```

Start a local workspace:

```bash
portl session dev
```

Expected behavior:

```text
portl: created workspace "dev" (ws_..., handle 7k3p)
portl: using local provider zmx
portl: attaching to local zmx session "dev"
```

Share with someone online:

```bash
portl session share dev
```

Expected output:

```text
Share code: PORTL-S-2-nebula-involve
Expires:    10m
Recipient:  portl join PORTL-S-2-nebula-involve
```

Portl builds a session-share envelope containing:

- workspace `dev` / `ws_...` / conflict handle;
- local machine endpoint ID;
- current `EndpointAddr` including relay URL if known;
- provider binding `zmx:dev`;
- recipient-bound Portl session ticket if the recipient identity is
  known during rendezvous, or a bounded bearer ticket in the first slice;
- optional future metadata doc ticket.

### Recipient

One-time setup:

```bash
portl init
```

Join:

```bash
portl join PORTL-S-2-nebula-involve
```

Expected behavior:

```text
portl: receiving session share from alice-laptop
portl: imported workspace "dev" as "dev@alice-laptop"
portl: connecting to alice-laptop
portl: attaching to zmx session "dev"
```

Later reconnect:

```bash
portl session dev@alice-laptop
```

If there is no local conflict, Portl may also allow:

```bash
portl session dev
```

If the share was created as observer/read-only in a future role model,
the recipient can attach but cannot send terminal input.

## 14. Example: Docker-backed workspace

Docker-backed sessions should use the same workspace model. The Docker
adapter creates a target alias and provisions a provider inside the
container.

### Sharer

Create a Docker target with a session provider:

```bash
portl docker run debian:stable-slim --name app --session-provider zmx --watch
```

Or attach an existing container:

```bash
portl docker attach --session-provider zmx app
```

Start a workspace bound to that Docker target:

```bash
portl session attach app dev
```

Optionally import that explicit remote/provider session into the local
workspace registry:

```bash
portl session import app dev --as app-dev
```

Then use the local-first name:

```bash
portl session app-dev
```

Share it:

```bash
portl session share app-dev
```

Expected output:

```text
Share code: PORTL-S-6-orbit-silver
Recipient:  portl join PORTL-S-6-orbit-silver
```

The envelope contains:

- workspace `app-dev` / `ws_...`;
- target endpoint ID for the Docker target's agent;
- `EndpointAddr` with relay URL if known;
- adapter/target hint `app`;
- provider binding such as `zmx:dev` or `tmux:dev`;
- bounded Portl ticket granting session access to that target.

### Recipient

The recipient does not need Docker locally. They need Portl and the code:

```bash
portl init
portl join PORTL-S-6-orbit-silver
```

Expected behavior:

```text
portl: receiving session share from alice-laptop
portl: imported workspace "app-dev"
portl: connecting to Docker target "app"
portl: attaching to zmx session "dev"
```

Later reconnect:

```bash
portl session app-dev
```

or, if ambiguous:

```bash
portl session app-dev@alice-laptop
```

## 15. Implementation phases

### Phase 1 — Local workspace registry

- Add workspace registry storage.
- Add local-first `portl session` and `portl session <NAME>`.
- Resolve local providers without Iroh self-connect.
- Keep explicit remote commands unchanged.

### Phase 2 — Workspace refs and import

- Add conflict handles and qualified refs.
- Add `portl session import <TARGET> [SESSION] --as <NAME>` for turning
  explicit remote/provider sessions into local workspace records.
- Add `portl session ls` mode for local workspace registry, while keeping
  provider session listing explicit.

### Phase 3 — Exchange envelope and offline tokens

- Define `PortlExchangeEnvelopeV1` and `SessionShareEnvelopeV1`.
- Add `PORTL-SHARE1-*` encode/decode.
- Add import validation for embedded tickets and endpoint consistency.

### Phase 4 — Short-code backend

- Add rendezvous backend abstraction.
- Add Magic Wormhole backend behind an optional feature or after license
  review.
- Add provider-agnostic `PORTL-S-*` user-visible codes.
- Add `portl join` generic dispatcher.

### Phase 5 — Real session access and roles

- Mint recipient-bound session tickets during rendezvous when possible.
- Add read-only/observer roles if provider/session-control lanes can
  enforce them.
- Add progress states and separate timeouts for rendezvous, envelope
  exchange, and session attach.

### Phase 6 — Metadata sync and Portl mailbox

- Add optional Iroh Docs metadata sync for workspace registries.
- Add Portl mailbox rendezvous backend if Magic Wormhole is unsuitable as
  a default production dependency.
- Seed rendezvous and metadata defaults from `portl init` / config.

## 16. Open questions

1. **Magic Wormhole dependency policy:** Is EUPL-1.2 acceptable for a
   default Portl dependency, or should it remain optional/prototype-only?
2. **Default direct-address privacy:** Should offline tokens include direct
   IP addresses by default, or only relay URLs unless explicitly requested?
3. **Generated name style:** Which wordlist/slug format should `portl
   session` use when no name is provided?
4. **Recipient-bound first slice:** Should initial short-code sharing wait
   to mint a `to`-bound ticket after rendezvous, or ship bearer tickets
   with short access TTL first?
5. **`portl session ls` split:** Should local workspace listing become the
   default `portl session ls`, moving provider listing to `portl session
   provider ls <TARGET>`, or should a new `portl workspace ls` exist?

These questions should be answered in the implementation plan before code
changes begin.
