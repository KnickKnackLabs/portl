# portl

> **p**eer-to-peer **o**verlay for **r**emote **t**argets with
> **l**imited capability tickets

Portl lets you share a machine, VM, or container over a peer-to-peer
transport without opening inbound ports or relying on a central account
system. The main workflow is a **persistent terminal session**: start a
named workspace on a target, detach, and let another device or
collaborator attach to the same workspace later.

Portl is built on [iroh](https://iroh.computer). Discovery uses iroh's
DNS, Pkarr, mDNS, and optional Mainline DHT support; relay fallback is
used for NAT traversal when direct paths are unavailable.

## Status

**v0.8.2** — local-first session-share UX patch. Portl has persistent
terminal sessions via `portl/session/v1`, provider discovery,
zmx-control support, tmux `-CC` compatibility, `PORTL-S-*` short codes
for importing shared session access through `portl accept`, and stable
host-suffixed labels for paired machines and saved access.
The current CLI vocabulary is:

```text
target   = something Portl can dial: peer label, adapter alias, ticket, or endpoint_id
peer     = a saved trust-store entry from `portl peer ls`
ticket   = a bounded permission token
session  = a named persistent terminal workspace on a target
provider = how the target keeps sessions alive, currently zmx or tmux
```

Run `portl --help` for the grouped command map.

## Install

### One-liner

```bash
# install or upgrade; preserves the current client/agent mode
curl -fsSL \
  https://raw.githubusercontent.com/KnickKnackLabs/portl/main/install.sh \
  | bash

# install or upgrade and make this machine shareable
curl -fsSL \
  https://raw.githubusercontent.com/KnickKnackLabs/portl/main/install.sh \
  | PORTL_AGENT=1 bash
```

The installer is idempotent. Re-run it to upgrade; by default it preserves
whether this machine was already configured as a client or agent. Set
`PORTL_VERSION=0.8.2` to pin a release. Use `--agent=off` to disable the
service, or `--uninstall` to remove binaries and service while keeping
`$PORTL_HOME`. By default, Portl stores local state under `~/.portl` on
all operating systems (`config/`, `data/`, `state/`, and `run/` subdirs).
Release artifacts cover macOS and Linux on arm64 / x86_64.

Daemon lifecycle commands live on `portl-agent`:

```bash
portl-agent status          # service + process + IPC status
portl-agent status --json   # script-friendly status
portl-agent up              # install/enable/start service
portl-agent restart         # restart installed service
portl-agent down            # stop/disable service, keeping state
```

### Package managers and source

```bash
# mise
mise use -g github:KnickKnackLabs/portl@0.8.2
# mise only shims `portl`; run install.sh with PORTL_AGENT=1 if this machine should be shared.

# cargo
cargo install --git https://github.com/KnickKnackLabs/portl --locked portl

# source checkout
git clone https://github.com/KnickKnackLabs/portl
cd portl
cargo install --path crates/portl-cli
```

## Quickstart: share this machine

On the machine you want to share:

```bash
# Install the daemon if you did not use install.sh --agent.
portl install --apply --yes

# Create your local identity and run diagnostics.
portl init
portl doctor

# Optional local checks for persistent-session providers.
tmux -V              # compatibility provider
zmx control --probe  # optimized provider, when zmx is installed
```

For persistent sessions, install at least one provider on the shared
machine:

- **tmux** works as the compatibility provider via `tmux -CC`.
- **zmx** is the optimized provider when its `zmx-control/v1` path is
  available.

After another device has a peer label or ticket for this machine, it can
ask Portl which providers are available:

```bash
portl session providers <shared-machine-label>
```

If no persistent provider is available, `portl shell` and `portl exec`
still work, but `portl session attach` will not provide a reconnectable
workspace.

### Pair another device or collaborator

On the shared machine:

```bash
portl invite --ttl 1h --for shared-box
```

On the other device:

```bash
portl accept PORTLINV-...
portl attach pair --target shared-box
```

The session name (`pair` above) is the rendezvous point. Anyone with
permission to the target can attach to the same named session. For repeated
work on one machine, set a default target:

```bash
PORTL_TARGET=shared-box portl attach pair
```

Detach by closing the local terminal; the provider session stays alive.
Destroy it explicitly when finished:

```bash
portl ls --target shared-box
portl kill pair --target shared-box
```

### Share a session with a short code

When the recipient should get short-lived session access without a full
pairing, keep a sender command running and send them the printed
`PORTL-S-*` code:

```bash
portl session share pair --target shared-box --label shared-box --ttl 10m --access-ttl 2h
# prints PORTL-S-...
```

On the recipient machine:

```bash
portl accept PORTL-S-...
portl attach shared-box/pair
```

`portl accept` saves the imported access as a local ticket label. Pass
`--label <name>` while accepting if the suggested label conflicts. The
sender stays online only for the rendezvous; the saved ticket controls
how long access remains valid.

### Share with a ticket instead of pairing

For short-lived access, mint a bounded ticket on the shared machine:

```bash
portl ticket issue session --ttl 2h
```

Send the printed `portl...` ticket string. The recipient can attach
directly:

```bash
portl attach pair --target 'portl...'
```

Or save it under a local label first:

```bash
portl ticket save shared-box 'portl...'
portl attach pair --target shared-box
```

Use `portl ticket issue dev --ttl 2h` for a broader development ticket
that also includes shell, exec, TCP/UDP, and metadata conveniences.

## Quickstart: Docker target

Docker and Slicer adapters create target aliases that use the same
`<TARGET>` argument as peers and tickets.

```bash
portl init

# Spin up a container target and save its ticket under the alias `demo`.
portl docker run alpine:3.20 --name demo

# One-shot commands.
portl exec demo -- echo "it works"
portl shell demo

# Persistent session, when the target has zmx or tmux.
portl session providers demo
portl session attach demo dev

# TCP / UDP forwards.
portl tcp demo -L 127.0.0.1:18080:127.0.0.1:80
portl udp demo -L 60000:127.0.0.1:60000

portl docker rm demo --force
```

To require zmx provisioning for a Docker target:

```bash
PORTL_ZMX_BINARY=/path/to/zmx \
  portl docker run alpine:3.20 --name dev --session-provider zmx
```

## CLI map

Top-level help is grouped by task:

```text
Setup        init, doctor, install, config, whoami
Trust        peer, invite
Pairing      accept
Connect      status, shell, session, exec, tcp, udp
Permissions  ticket
Integrations docker, slicer, gateway
Utility      completions, man, help
```

Connection commands use `<TARGET>` because they accept any value that
resolves through Portl's connection cascade: inline ticket, peer label,
saved ticket, adapter alias, then endpoint id. Commands under
`portl peer ...` use peer vocabulary because they operate on the local
peer store specifically.

## Protocols

- `portl/ticket/v1` — ticket handshake and capability validation.
- `portl/meta/v1` — ping, info, and revocation publication.
- `portl/shell/v1` — one-shot PTY shell and exact-argv exec.
- `portl/session/v1` — persistent terminal sessions via providers.
- `portl/tcp/v1` — one stream per forwarded TCP connection.
- `portl/udp/v1` — QUIC-datagram UDP with session linger for roaming
  clients such as mosh.

Full wire details live in [`docs/specs/040-protocols.md`](docs/specs/040-protocols.md),
with the shipped persistent-session baseline in
[`docs/specs/200-persistent-sessions.md`](docs/specs/200-persistent-sessions.md)
and the v0.5.0 control-provider work in
[`docs/specs/210-session-control-lanes.md`](docs/specs/210-session-control-lanes.md).

## Adapters and providers

- **Docker** — `portl docker run/attach` provisions a container target
  with a `portl-agent` and saved alias.
- **Slicer** — `portl slicer run` provisions a Slicer VM and can route
  through `portl-gateway`.
- **zmx** — optimized persistent-session provider when
  `zmx-control/v1` is available; falls back to legacy attach behavior
  where needed.
- **tmux** — compatibility persistent-session provider via PTY-backed
  `tmux -CC`.

## Diagnostics

```bash
portl doctor
portl status
portl status <TARGET>
portl session providers <TARGET>
```

The agent exposes OpenMetrics on `$PORTL_HOME/run/metrics.sock` when the
local service is running:

```bash
curl --unix-socket "${PORTL_HOME:-$HOME/.portl}/run/metrics.sock" http://metrics/
```

## Design docs

Start with [`docs/specs/README.md`](docs/specs/README.md). The numbered
specs are a mix of live design references and historical release records;
the index marks which is which.

## Contributing

Single-branch development on `main`. MIT licensed. Copyright
"KnickKnackLabs and portl contributors". Open an issue or discussion
before starting a large change.

## License

[MIT](LICENSE-MIT).
