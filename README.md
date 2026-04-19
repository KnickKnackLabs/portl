# portl

> **p**eer-to-peer **o**verlay for **r**emote **t**argets with
> **l**imited capability tickets

Decentralized, capability-ticket-based overlay for reaching remote
targets (VMs, containers, hosts, devices) over a p2p substrate. Built on
[iroh](https://iroh.computer) — no mandatory control plane, no central
account system. Peer discovery uses iroh's built-in DNS, Pkarr, mDNS,
and (opt-in) Mainline DHT services.

## Status

**Pre-scaffold.** This repository currently contains design documentation
only. Implementation is about to start.

- Full design doc set → [`docs/design/`](docs/design/)
- Short version → [`docs/design/010-goals.md`](docs/design/010-goals.md)
- Architecture → [`docs/design/020-architecture.md`](docs/design/020-architecture.md)
- Roadmap → [`docs/design/120-roadmap.md`](docs/design/120-roadmap.md)

The design is complete enough to start on M0 (workspace scaffold +
`portl-core` skeleton + in-process test helpers). See the roadmap for
what ships when.

## What portl is for

- **General**: any workflow where you want to hand someone a signed
  bearer URL that grants narrow, time-bounded access to a specific
  capability (shell, TCP/UDP forward, file transfer, or small VPN) on a
  target, with no central account system required.
- **Reference adapter (M4)**: Docker. Provisions a container, injects
  an agent identity, mints a ticket. Runs on any developer laptop or
  CI runner.
- **Primary personal use case (M5)**: [slicer](https://slicer.sh) VMs
  on a developer's Mac, reached without port-forwarding or tailnet.

The threat model (see
[`docs/design/070-security.md`](docs/design/070-security.md)) is
*"possession of the ticket is the authorisation"*. Revocation exists;
accounts do not.

## Quickstart (M4, approximate)

```bash
# On the target host (a laptop, a server, or a container):
portl agent run --config /etc/portl/agent.toml

# On your laptop, provision a docker container target:
portl docker container add demo-1
# → prints a portl<…> ticket URI

# Use it:
portl shell demo-1
portl tcp demo-1 -L 127.0.0.1:3000:127.0.0.1:3000 -N
```

See [`docs/design/060-docker.md`](docs/design/060-docker.md) for full
adapter details, [`docs/design/065-slicer.md`](docs/design/065-slicer.md)
for slicer adapter (M5).

## What portl is NOT

- Not a replacement for Tailscale or a general mesh VPN. You *can* run
  portl as a dumb substrate over an existing tailnet, but portl itself
  doesn't aspire to be the coordination plane.
- Not a SaaS. No mandatory control plane. You can run the reference
  setup entirely without talking to any server controlled by a third
  party.
- Not tied to any one orchestrator. Docker is the M4 reference adapter
  and slicer is the M5 adapter; both ship in v0.1. The design treats
  adapters as the extensibility point (see
  [`docs/design/050-bootstrap.md`](docs/design/050-bootstrap.md)).

## License

Licensed under the [MIT license](LICENSE-MIT). See `LICENSE-MIT` for
the full text.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you shall be licensed under
the MIT license, without any additional terms or conditions.
