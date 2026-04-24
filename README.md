# portl

> **p**eer-to-peer **o**verlay for **r**emote **t**argets with
> **l**imited capability tickets

Decentralized, capability-ticket-based overlay for reaching remote
targets (VMs, containers, hosts, devices) over a p2p substrate. Built on
[iroh](https://iroh.computer) — no mandatory control plane, no central
account system. Peer discovery uses iroh's built-in DNS, Pkarr, mDNS,
and (opt-in) Mainline DHT services.

## Status

**v0.2.0** — operability release. The operator flow is now `portl init`
followed by `portl docker run <image>` or `portl slicer run <image>`.
Runtime orchestration, install targets, local revocation propagation,
and the collapsed CLI surface are all in place.

## Install

### One-liner (recommended)

```bash
# client-only (just the CLI binaries)
curl -fsSL https://raw.githubusercontent.com/KnickKnackLabs/portl/main/install.sh | bash

# install + enable the portl-agent service (launchd on macOS, systemd on Linux)
curl -fsSL https://raw.githubusercontent.com/KnickKnackLabs/portl/main/install.sh | bash -s -- --agent

# pin a version
curl -fsSL https://raw.githubusercontent.com/KnickKnackLabs/portl/main/install.sh | bash -s -- --version 0.3.0

# toggle back to client-only (removes service, keeps binaries + identity)
curl -fsSL https://raw.githubusercontent.com/KnickKnackLabs/portl/main/install.sh | bash -s -- --client-only --yes

# fully uninstall (keeps $PORTL_HOME)
curl -fsSL https://raw.githubusercontent.com/KnickKnackLabs/portl/main/install.sh | bash -s -- --uninstall --yes
```

The installer is idempotent — re-run it any time to upgrade, switch
between client-only and agent modes, or pin a specific version.
Works in Docker containers (service install is auto-skipped).
Supports darwin arm64 / x86_64 and linux-musl arm64 / x86_64.

### From a package manager

```bash
# mise
mise use -g github:KnickKnackLabs/portl@0.3.0
# (mise only shims `portl`; if you want the agent, run `install.sh --agent`
#  afterwards or symlink `portl-agent` into ~/.local/bin manually)

# cargo
cargo install --git https://github.com/KnickKnackLabs/portl --locked portl
```

### From source

```bash
git clone https://github.com/KnickKnackLabs/portl
cd portl
cargo install --path crates/portl-cli
```

## Quickstart (Docker adapter)

```bash
# One-time setup (created automatically by install.sh if run for the first time):
portl init

# Spin up an ephemeral container + mint a ticket:
portl docker run alpine:3.20 --name demo

# Run an exact-argv, non-PTY command:
portl exec demo -- echo "it works"

# Persistent terminal sessions are available on zmx-enabled targets:
#   PORTL_ZMX_BINARY=/path/to/zmx portl docker run alpine:3.20 --name dev --session-provider zmx
#   portl session providers dev
#   portl session attach dev

# Forward a TCP port (local 18080 -> container 80):
portl tcp demo -L 127.0.0.1:18080:127.0.0.1:80

# Forward UDP (mosh-roaming-aware):
portl udp demo -L 60000:127.0.0.1:60000

# Diagnostics:
portl doctor

# Tear down:
portl docker rm demo --force
```

From `portl docker run` to a working shell is typically under 3
seconds on a warm image; 10 seconds on first pull.

## Ticket model

Every remote session is gated by a postcard-encoded
`portl` ticket (see
[`docs/specs/030-tickets.md`](docs/specs/030-tickets.md)). Tickets
are ed25519-signed, narrow-by-construction, and support up to 8 hops
of delegation. The in-session pipeline does postcard canonical-form
enforcement, strict `verify_strict` signature check, re-encode
invariant, revocation lookup, and `SKEW_TOLERANCE = ±60s` time-window
enforcement before any protocol stream is dispatched.

A typical ticket grants "shell + tcp on 127.0.0.1 + udp on 127.0.0.1"
for 30 days; delegate variants narrow further.

## Protocols (v0.1)

- `portl/ticket/v1` — ticket handshake + session setup.
- `portl/meta/v1` — ping, info, `PublishRevocations`.
- `portl/shell/v1` — one-shot PTY shell or exact-argv exec with 6 sub-streams per session.
- `portl/session/v1` — persistent terminal sessions via target-side providers such as zmx.
- `portl/tcp/v1` — one stream per forwarded TCP connection.
- `portl/udp/v1` — QUIC-datagram UDP with 60 s session linger for
  roaming-aware apps like mosh.

Full wire spec at
[`docs/specs/040-protocols.md`](docs/specs/040-protocols.md).

## Adapters

- **`docker-portl`** — provisions an ephemeral container with the
  `portl` multicall binary and an injected per-container ed25519
  secret. Works against `dockerd` or OrbStack. Add `--session-provider zmx`
  to require/configure persistent sessions; set `PORTL_ZMX_BINARY` to copy
  a zmx binary into arbitrary images. See
  [`docs/specs/140-v0.2-operability.md`](docs/specs/140-v0.2-operability.md).
- **`slicer-portl`** — provisions a Slicer VM with a systemd
  `portl-agent.service`, plus a gateway mode for bridging the Slicer
  HTTP API via master tickets. See
  [`docs/specs/065-slicer.md`](docs/specs/065-slicer.md).

## Metrics + diagnostics

The running agent exposes OpenMetrics on a local unix socket at
`$PORTL_HOME/metrics.sock` (mode 0600). Scrape with:

```bash
curl --unix-socket $PORTL_HOME/metrics.sock http://metrics/
```

Counters cover ticket accept/reject rates (with reason labels)
and stream opens per ALPN.

`portl doctor` runs a local diagnostic sweep: wall-clock sanity,
identity file + permissions, UDP ephemeral bind, and ticket-expiry
scan across the alias store.

## Operator install

Release artifacts are published for four targets on every tag:

- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-musl`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

Linux builds are fully statically linked (musl), so a single
`portl` binary drops into Alpine, distroless, BusyBox, CentOS 7 and
every modern glibc distro without additional runtime dependencies.
macOS builds link only against always-present system frameworks.

Install from a tag:

```sh
VER=v0.2.0
TARGET=x86_64-unknown-linux-musl      # pick your target
curl -L -o portl.tar.zst \
  https://github.com/KnickKnackLabs/portl/releases/download/$VER/portl-$VER-$TARGET.tar.zst
tar --zstd -xf portl.tar.zst
sudo install -m 0755 portl-$VER-$TARGET/portl /usr/local/bin/portl
sudo ln -sf portl /usr/local/bin/portl-agent
```

Tarballs are `zstd -19` compressed (~7 MiB each). Any `tar` built on
top of GNU tar 1.31+ or bsdtar with libarchive can extract them; if
you see `unrecognized option --zstd`, install the `zstd` package.

Use `portl install dockerfile --output ./portl-image`
to emit a service Dockerfile and matching `portl-agent` binary for
container-only deployments.

## Design docs

Everything under [`docs/specs/`](docs/specs/). Start with
[`docs/specs/README.md`](docs/specs/README.md) for the full reading
order; the numbered prefixes (`010`, `020`, `030`, ...) encode the
intended traversal.

## Contributing

Single-branch development on `main`. MIT licensed. Copyright
"KnickKnackLabs and portl contributors". Open an issue or discussion
before starting a large change.

## License

[MIT](LICENSE-MIT).
