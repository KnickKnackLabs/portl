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
- Short version → [`docs/design/01-goals.md`](docs/design/01-goals.md)
- Architecture → [`docs/design/02-architecture.md`](docs/design/02-architecture.md)
- Roadmap → [`docs/design/12-roadmap.md`](docs/design/12-roadmap.md)

The design is complete enough to start on M0 (workspace scaffold +
`portl-core` skeleton + in-process test helpers). See the roadmap for
what ships when.

## What portl is for

- **Primary**: reaching [slicer](https://slicer.sh) VMs on a developer's
  laptop from that same laptop, without TCP port forwarding.
- **General**: any workflow where you want to hand someone a signed
  bearer URL that grants narrow, time-bounded access to a specific
  capability (shell, TCP/UDP forward, file transfer, or small VPN) on a
  target, with no central account system required.

The threat model (see
[`docs/design/07-security.md`](docs/design/07-security.md)) is
*"possession of the ticket is the authorisation"*. Revocation exists;
accounts do not.

## What portl is NOT

- Not a replacement for Tailscale or a general mesh VPN. You *can* run
  portl as a dumb substrate over an existing tailnet, but portl itself
  doesn't aspire to be the coordination plane.
- Not a SaaS. No mandatory control plane. You can run the reference
  setup entirely without talking to any server controlled by a third
  party.
- Not tied to slicer. Slicer is the first adapter; the design treats
  adapters as the extensibility point (see
  [`docs/design/05-bootstrap.md`](docs/design/05-bootstrap.md)).

## License

Dual-licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT license](LICENSE-MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms
or conditions.
