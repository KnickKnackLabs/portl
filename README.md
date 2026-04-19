# portl

> **p**eer-to-peer **o**verlay for **r**emote **t**argets with
> **l**imited capability tickets

Decentralized, capability-ticket-based overlay for reaching remote
targets (VMs, containers, hosts, devices) over a p2p substrate. Built on
[iroh](https://iroh.computer) — no mandatory control plane, no central
account system. Peer discovery uses iroh's built-in DNS, Pkarr, mDNS,
and (opt-in) Mainline DHT services.

## Status

**v0.1.0** — first end-to-end release. Ticket-based authentication,
shell/tcp/udp forwarding, reference adapters for Docker and Slicer, a
local `portl doctor`, and on-socket Prometheus metrics are all in
place. The quickstart below works on macOS (with OrbStack or Docker
Desktop) and Linux.

## Quickstart (Docker adapter)

```bash
# Install from source:
git clone https://github.com/KnickKnackLabs/portl
cd portl
cargo install --path crates/portl-cli

# One-time setup:
portl id new

# Spin up an ephemeral container + mint a ticket:
portl docker container add demo

# Open a shell:
portl exec demo -- echo "it works"

# Forward a TCP port (local 18080 -> container 80):
portl tcp demo -L 127.0.0.1:18080:127.0.0.1:80

# Forward UDP (mosh-roaming-aware):
portl udp demo -L 60000:127.0.0.1:60000

# Diagnostics:
portl doctor

# Tear down:
portl docker container rm demo --force
```

From `portl docker container add` to a working shell is typically
under 3 seconds on a warm image; 10 seconds on first pull.

## Ticket model

Every remote session is gated by a postcard-encoded
`portl` ticket (see
[`docs/design/030-tickets.md`](docs/design/030-tickets.md)). Tickets
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
- `portl/shell/v1` — PTY or exec with 6 sub-streams per session.
- `portl/tcp/v1` — one stream per forwarded TCP connection.
- `portl/udp/v1` — QUIC-datagram UDP with 60 s session linger for
  roaming-aware apps like mosh.

Full wire spec at
[`docs/design/040-protocols.md`](docs/design/040-protocols.md).

## Adapters

- **`docker-portl`** — provisions an ephemeral container with the
  `portl` multicall binary and an injected per-container ed25519
  secret. Works against `dockerd` or OrbStack. See
  [`docs/design/060-docker.md`](docs/design/060-docker.md).
- **`slicer-portl`** — provisions a Slicer VM with a systemd
  `portl-agent.service`, plus a gateway mode for bridging the Slicer
  HTTP API via master tickets. See
  [`docs/design/065-slicer.md`](docs/design/065-slicer.md).

## Metrics + diagnostics

The running agent exposes OpenMetrics on a local unix socket at
`$PORTL_HOME/metrics.sock` (mode 0600). Scrape with:

```bash
curl --unix-socket $PORTL_HOME/metrics.sock http://metrics/
```

Counters cover ticket accept/reject rates (with reason labels)
and stream opens per ALPN. Byte-counter series are scheduled for
v0.2.

`portl doctor` runs a local diagnostic sweep: wall-clock sanity,
identity file + permissions, UDP ephemeral bind, and ticket-expiry
scan across the alias store.

## Operator install

Release artifacts are published for `linux/amd64`, `linux/arm64`,
`darwin/amd64`, `darwin/arm64` on each tag. Binaries are static
enough to drop into a minimal image. See
[`docs/design/060-docker.md §13`](docs/design/060-docker.md) for the
reference Dockerfile.

## Design docs

Everything under [`docs/design/`](docs/design/). Start with
[`docs/design/README.md`](docs/design/README.md) for the full reading
order; the numbered prefixes (`010`, `020`, `030`, ...) encode the
intended traversal.

## Contributing

Single-branch development on `main`. MIT licensed. Copyright
"KnickKnackLabs and portl contributors". Open an issue or discussion
before starting a large change.

## License

[MIT](LICENSE-MIT).
