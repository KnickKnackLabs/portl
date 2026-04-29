# 230 — Session Provider Ergonomics

## Purpose

Make persistent session discovery and resumption provider-aware by default.
The configured default provider should decide where Portl creates new
sessions; it should not hide existing sessions in other detected providers.

## Current Behavior

- `portl status` reports all detected session providers: `zmx`, `tmux`, and
  the built-in raw fallback.
- Local `portl session providers` reports only the local `zmx` provider.
- Providerless `session ls`, `session attach`, `session history`, and
  `session kill` select a single provider, preferring `zmx` whenever it is
  available.
- `tmux` attach and history commands target the session name only, leaving
  window/pane selection implicit.
- Exiting a Portl tmux attachment can be ambiguous for users because tmux
  control mode does not expose the same explicit detach UX as `zmx attach`.

## Desired Behavior

### Provider Selection

Provider selection precedence is:

1. `--provider`
2. `PORTL_SESSION_PROVIDER`
3. providerless aggregate lookup for existing-session operations
4. configured/default provider only when creating a new session

`PORTL_SESSION_PROVIDER` acts like an implicit `--provider` for session
operations. It limits `ls`, `attach`, `history`, and `kill` to that provider,
and it selects the creation provider for `run` or create-on-attach flows.
An explicit `--provider` always wins over the environment variable.

### Provider Reporting

`portl session providers` should match the provider discovery semantics used
by `portl status`:

- show `zmx` when detected,
- show `tmux` when detected,
- show `raw` as a built-in fallback,
- keep the `DEFAULT` column, but define it as the provider used for new
  session creation.

### Aggregate Listing

`portl session ls` without an explicit or environment provider filter queries
all available persistent providers with list support.

Human output becomes provider-aware:

```text
PROVIDER  SESSION
zmx       dev
tmux      scratch
```

JSON output should return structured entries with at least:

```json
[{ "provider": "zmx", "name": "dev" }]
```

When a provider filter is set, list only that provider and preserve a simple
provider-specific view where practical.

### Aggregate Resolution

Providerless `attach`, `history`, and `kill` resolve the requested session
name across all available persistent providers.

- If exactly one provider has the session, use that provider.
- If multiple providers have the session, fail with a clear message listing
  the matching providers and asking the user to rerun with `--provider` or
  `PORTL_SESSION_PROVIDER`.
- If no provider has the session and the operation can create the session
  (`attach` with create-on-attach or `run`), use the configured/default
  creation provider.
- If no provider has the session and the operation requires an existing
  session (`history`, `kill`), return a not-found error.

`raw` is not included in aggregate lookup because it has no persistent
session list.

## Tmux Window and Pane Targets

Portl should use native tmux target-pane syntax:

```text
session:window.pane
```

Examples:

```text
portl session attach dev:0.1
portl session attach max/dev:editor.0
```

The `host/session` separator remains `/`; everything after the session name
belongs to the provider-specific session selector. For tmux, the selector is
parsed as a tmux target pane and passed to commands with `-t`.

When attaching to an unqualified tmux session that has multiple windows or
panes, Portl should print a short stderr summary before attaching:

```text
portl: available tmux panes for dev:
  dev:0.0  window=0 pane=0 active
  dev:0.1  window=0 pane=1
  dev:1.0  window=1 pane=0
portl: attaching to dev:0.0
```

The default target should be tmux's active/default pane, not an arbitrary
first pane. Scripts can avoid this message and ambiguity by specifying a
target pane explicitly.

## Tmux Detach Escape

Portl tmux attach should mimic `zmx attach`'s detach escape. While attached
to a tmux session, `Ctrl+\` should detach the Portl client instead of sending
the byte to the pane or killing the session.

Detection should match zmx behavior:

- raw `Ctrl+\` byte `0x1c`, and
- kitty keyboard protocol CSI-u forms for backslash with only the Ctrl
  intentional modifier, including press and repeat events, excluding release
  events and Ctrl+Shift/Ctrl+Alt variants.

On detection, the tmux control pump should send `detach-client` to tmux
control mode and close the Portl attach bridge cleanly. Normal terminal EOF
or connection close should also detach the control client, not kill the tmux
session or pane.

## Protocol and Compatibility

The current `SessionAck.sessions: Option<Vec<String>>` shape is ambiguous for
aggregate provider listing. Add a provider-aware list shape while retaining
compatibility for simple provider-specific lists. The agent can populate both
where possible during the transition:

- `sessions`: provider-specific names for older/simple callers,
- `session_entries`: aggregate provider/name records for provider-aware
  callers.

This is an internal Portl wire protocol change between matching CLI/agent
versions. Tests should cover postcard round trips for the new field.

## Testing

- Unit-test provider precedence: `--provider` beats `PORTL_SESSION_PROVIDER`,
  which beats default creation provider.
- Unit-test aggregate list formatting and JSON output.
- E2E-test remote providerless list returning sessions from both fake `zmx`
  and fake `tmux` providers.
- E2E-test providerless attach resolution:
  - unique match attaches to the matching provider,
  - duplicate match returns a clear ambiguity error,
  - no match falls back to default provider for create-on-attach.
- Unit-test tmux target parsing for `session`, `session:window`,
  `session:window.pane`, and `host/session:window.pane`.
- Unit-test tmux pane listing/active target selection from `tmux list-panes`.
- Unit-test raw and kitty `Ctrl+\` detach detection, including non-detach
  variants.
- E2E-test tmux control attach emits a detach command on `Ctrl+\` and does
  not send that input to the pane.
