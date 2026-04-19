# portl

> A decentralized, capability-addressed peer-to-peer overlay.
> Hand someone a URL-shaped capability and they can shell / tcp / udp / vpn
> into a specific peer you control — without a coordinator, without a VPN
> provider, without opening an inbound port.

## One-picture summary

```
 ┌────────── operator machine(s) ──────────┐        ┌───────── target host ─────────┐
 │                                         │        │                               │
 │  identity.key  (ed25519)                │        │  portl agent run              │
 │  ~/.config/portl/tickets/*.ticket       │        │    secret /var/lib/portl/key  │
 │                                         │        │    policy /etc/portl/agent.* │
 │  ┌────────────┐                         │        │    (same binary as client)    │
 │  │   portl    │  (client CLI)           │◄──────►│  ALPNs                        │
 │  └─────┬──────┘                         │  QUIC  │    ticket/v1  meta/v1         │
 │        │                                │ (iroh) │    shell/v1  tcp/v1           │
 │        │   uses portl-core directly     │        │    udp/v1                     │
 │        │   for embedders                │        │    vpn/v1     (optional)      │
 │        │   (slicer-portl, docker-portl…)│        │    fs/v1      (v0.2)          │
 └─────────────────────────────────────────┘        └───────────────────────────────┘

                  ┌────── shared infra (all self-hostable) ─────────┐
                  │                                                  │
                  │  iroh discovery:  DNS / Pkarr / Local(mDNS)      │
                  │    default: n0's dns.iroh.link                   │
                  │    self-host: iroh-dns-server                    │
                  │                                                  │
                  │  iroh relay:  for NAT traversal fallback         │
                  │    default: iroh-run relays                      │
                  │    self-host: portl-relay (thin wrapper)         │
                  └──────────────────────────────────────────────────┘
```

## What this document set is

A complete design doc for `portl` before any code is written. Each file is
self-contained and cross-references the others. The intent is to settle
enough architecture that scaffolding the workspace is a mechanical
translation of what's written here.

## Terminology note: `node_id` vs `endpoint_id`

These two terms refer to the same thing: the ed25519 public key that
uniquely identifies a peer on the overlay. `endpoint_id` is iroh's
current name (≥ 0.33); `node_id` is iroh's previous name and the term
historically used in portl prose. The ticket schema (`03-tickets.md §2`)
uses `endpoint_id` to match iroh's type names; most diagrams and English
prose still use `node_id`. Treat them as synonymous.

## Index

| # | File | What's in it |
| --- | --- | --- |
| — | `README.md` | This file. High-level map. |
| 01 | `01-goals.md` | Goals, non-goals, positioning, prior art. |
| 02 | `02-architecture.md` | Components, data flow, state machines. Many diagrams. |
| 03 | `03-tickets.md` | Ticket URI format, postcard schema, delegation, revocation. |
| 04 | `04-protocols.md` | Every ALPN with framing and sequence diagrams. |
| 05 | `05-bootstrap.md` | `Bootstrapper` trait, adapter pattern, lifecycle. |
| 06 | `06-slicer.md` | The slicer adapter end-to-end. |
| 07 | `07-security.md` | Threat model, trust, key custody, failure modes. |
| 08 | `08-cli.md` | Exhaustive CLI reference: `portl` (operator), `portl agent` (target-side), adapters. |
| 09 | `09-config.md` | Config file formats, on-disk layout, directories, keys. |
| 10 | `10-walkthroughs.md` | End-to-end example flows with diagrams. |
| 11 | `11-workspace.md` | Cargo workspace layout, crate boundaries, dependencies. |
| 12 | `12-roadmap.md` | Milestones M0–M9 with exit criteria. |
| 13 | `13-open-questions.md` | Decisions the author wants confirmed before scaffolding. |

Design artifacts for deferred/post-v0.1 work (in `future/`):

- [`future/14-transport-abstraction.md`](future/14-transport-abstraction.md) — `OverlayTransport` trait design. Deferred: iroh's `Discovery` plugins (DNS, Pkarr, Local/mDNS, DHT) cover our v0.1 needs; a full transport trait gets designed when a second genuine data plane (WebRTC, Loom/AWDL) is demanded.
- [`future/15-loom-analysis.md`](future/15-loom-analysis.md) — Loom / AWDL deep dive. Deferred alongside the transport trait; preserved for future reference.

## One-minute pitch

- **Identity is a public key.** Node IDs are ed25519 pubkeys; no accounts, no
  coordinator.
- **Capabilities are tickets.** A ticket is a signed, URL-shaped blob that
  names a peer and the operations allowed against it. You hand someone a
  ticket; they can do what it says, and only that.
- **Transport is iroh/QUIC.** Hole-punched direct paths where possible,
  self-hostable relay fallback. UDP-native; datagrams in QUIC cover UDP
  apps (mosh, DNS, game netcode).
- **Discovery is iroh's.** DNS, Pkarr, and Local (mDNS) are all on by
  default; peers on the same LAN find each other with zero
  infrastructure. DHT is opt-in.
- **Protocols are ALPNs.** `shell/v1`, `tcp/v1`, `udp/v1` ship at v0.1;
  `fs/v1` is v0.2; `vpn/v1` is a feature-gated stretch. Each a small,
  separately-reviewable module.
- **Bootstrap is pluggable.** Slicer is one `Bootstrapper` among many
  (cloud-init, docker, nixos, manual).
- **One binary.** `portl` is a single multicall binary that serves
  both operator and target roles: `portl shell foo` on your laptop,
  `portl agent run` on the target. Packagers ship a
  `/usr/bin/portl-agent` symlink so argv[0] dispatch preserves
  legacy systemd units. `--mode gateway` covers the earlier
  "portl-gw" role. Everything else is libraries.

## Reading order

If you only read three documents, read **01-goals**, **02-architecture**,
and **10-walkthroughs**. The rest fills in the shapes.

If you care about the long-range transport story (WebRTC, Loom/AWDL,
running over Tailscale, SSH-as-transport), the artifact reading is
**future/14-transport-abstraction** and **future/15-loom-analysis** —
both deferred from v0.1. For v0.1's one-data-plane-with-pluggable-
discovery story, **02-architecture** and **09-config** are the truth.

If you're reviewing: the live decision points are in **13-open-questions**.
