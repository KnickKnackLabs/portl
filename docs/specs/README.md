# portl

> A decentralized, capability-addressed peer-to-peer overlay.
> Hand someone a URL-shaped capability and they can shell / tcp / udp / vpn
> into a specific peer you control — without a coordinator, without a VPN
> provider, without opening an inbound port.

## One-picture summary

```
 ┌────────── operator machine(s) ──────────┐        ┌───────── target host ─────────┐
 │                                         │        │                               │
│  identity.key  (ed25519)                │        │  portl-agent                  │
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

A mix of **live specs** and **historical design records**. The v0.1
canon docs (`010`–`130`) capture the project as originally designed;
`140`, `150`, and `160` record the shipped post-v0.1 release work.
Where a v0.1 doc's user-facing surface is now stale, it is preserved as
history and should be read together with the newer superseding spec.

## Terminology note: `node_id` vs `endpoint_id`

These two terms refer to the same thing: the ed25519 public key that
uniquely identifies a peer on the overlay. `endpoint_id` is iroh's
current name (≥ 0.33); `node_id` is iroh's previous name and the term
historically used in portl prose. The ticket schema (`030-tickets.md §2`)
uses `endpoint_id` to match iroh's type names; most diagrams and English
prose still use `node_id`. Treat them as synonymous.

## Index

| #   | File | What's in it |
| --- | --- | --- |
| —   | `README.md` | This file. High-level map. |
| 010 | `010-goals.md` | Goals, non-goals, positioning, prior art. |
| 020 | `020-architecture.md` | Components, data flow, state machines. Many diagrams. |
| 030 | `030-tickets.md` | Ticket URI format, postcard schema, delegation, revocation. |
| 040 | `040-protocols.md` | Every ALPN with framing and sequence diagrams. |
| 050 | `050-bootstrap.md` | `Bootstrapper` trait, adapter pattern, lifecycle. |
| 060 | `060-docker.md` | The Docker adapter (M4 reference implementation). |
| 065 | `065-slicer.md` | The slicer adapter end-to-end (M5). |
| 070 | `070-security.md` | Threat model, trust, key custody, failure modes. |
| 080 | `080-cli.md` | **Historical v0.1 CLI reference.** Superseded for shipped behavior by `140-v0.2-operability.md §4` and the current `--help` output. |
| 090 | `090-config.md` | **Historical v0.1 config/layout doc.** Superseded for shipped behavior by `140-v0.2-operability.md §8-§9`. |
| 100 | `100-walkthroughs.md` | End-to-end example flows with diagrams. Early walkthroughs use v0.1 command names; read with `140` for the shipped v0.2 surface. |
| 110 | `110-workspace.md` | Workspace layout and repo structure. Some command-tree examples are historical v0.1; the live CLI surface is in `140`. |
| 120 | `120-roadmap.md` | Historical milestone plan and release sequence record. Read as shipped history, not forward roadmap. |
| 130 | `130-open-questions.md` | Historical design questions. Many are resolved; use as decision provenance rather than an active to-do list. |
| 140 | `140-v0.2-operability.md` | **v0.2.0 design spec.** Live reference for the shipped CLI/config/runtime surface; supersedes parts of 060/080/090 on ship. |
| 150 | `150-v0.1.1-safety-net.md` | **v0.1.1 design spec.** Three non-breaking runtime-stability items shipped ahead of v0.2. |
| 160 | `160-v0.1.2-alias-isolation.md` | **v0.1.2 design spec.** Forensic experiment: isolate rusqlite removal to test the macOS release-mode crash hypothesis. |
| 165 | `165-v0.3.2-observability.md` | **v0.3.2 design spec.** Targeted diagnostics and observability polish for peer/ticket/status/connect operations. |
| 170 | `170-v0.3.3-relay.md` | **v0.3.3 design spec.** Relay configuration, diagnostics, and reachability improvements. |
| 180 | `180-v0.3.4-peer-pairing.md` | **Historical shipped spec.** Peer pairing via invite/pair/accept; superseded by the CLI vocabulary direction in `190`. |
| 190 | `190-cli-ergonomics.md` | **Implemented in v0.3.6.** CLI friction-reduction release: help text, examples, actionable errors, command grouping, completions, selected surface cleanup. |
| 200 | `200-persistent-sessions.md` | **Baseline shipped in v0.4.0.** Persistent terminal sessions via a provider interface, with zmx first and Docker/Slicer provisioning hooks. |
| 210 | `210-session-control-lanes.md` | **v0.5.0 implementation slice shipped.** zmx-control and tmux `-CC` provider tiers landed; broader viewport/lane scheduling remains follow-on. |

## Specs vs plans — where does what go

This directory holds **specs**: architectural decisions and per-release design docs. Specs answer *what & why*. They are durable: someone reading them a year later should understand what was decided and why. They do not contain TDD step lists, exact commit messages, or implementation timelines.

Implementation recipes live in [`../plans/`](../plans/). A plan answers *how*: bite-sized TDD tasks, exact file paths, exact code to write, exact commands to run. Plans retire when the feature ships — their content graduates to the `CHANGELOG.md`.

This split matches the Superpowers `brainstorming` → `writing-plans` flow, adapted to keep portl's 3-digit numbering convention instead of date-prefixed filenames.

Quick reference:

| Question | Look here |
| --- | --- |
| Why does the agent use env vars instead of a TOML file? | spec |
| What exact test should I write to verify setrlimit inheritance? | plan |
| What are the v0.2 CLI invariants? | spec |
| In what order should the v0.1.1 commits land? | plan |
| Did this ship? | `CHANGELOG.md` |

Design artifacts for deferred/post-v0.1 work (in `future/`):

- [`future/140-transport-abstraction.md`](future/140-transport-abstraction.md) — `OverlayTransport` trait design. Deferred: iroh's `Discovery` plugins (DNS, Pkarr, Local/mDNS, DHT) cover our v0.1 needs; a full transport trait gets designed when a second genuine data plane (WebRTC, Loom/AWDL) is demanded.
- [`future/150-loom-analysis.md`](future/150-loom-analysis.md) — Loom / AWDL deep dive. Deferred alongside the transport trait; preserved for future reference.

## Numbering convention

Filenames use a **3-digit prefix** (`NNN-slug.md`) with **canon docs
on multiples of 10** (`010`, `020`, `030`, …). This leaves 9 free
slots between every pair of canon docs.

- **Inserting a new doc between two existing ones**: pick any
  non-multiple-of-10 in the gap (`065` went between `060-docker.md`
  and `070-security.md` this way when the slicer adapter slid to
  M5). Prefer the midpoint first (e.g. `015` between `010` and
  `020`), then `011`/`019`, etc.
- **Inserting at either end**: go below `010` (`005`, `001`) or
  past `130` (`140`, `150`). The `future/` subdirectory uses the
  same number line, reserving `≥ 140` for deferred design
  artifacts.
- **Reordering canon**: rare. When needed, renumber only within
  the affected region, not the whole tree. Cross-references can
  be updated with a single `sed` pass plus a grep check that no
  old prefixes survive.
- **Superseding**: mark the old doc's frontmatter with
  `Status: superseded by NNN-slug.md`, and either leave it in
  place or move to `archive/`. Do not reuse its number.

The number itself has no semantic meaning beyond ordering —
don't overload it with thematic ranges ("20s are protocols, 30s
are adapters"). That temptation trades one renumbering crisis
(insertion) for a harder one (re-theming).

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
- **Protocols are ALPNs.** `ticket/v1`, `meta/v1`, `shell/v1`,
  `session/v1`, `tcp/v1`, and `udp/v1` are small, separately
  reviewable protocol modules.
- **Sessions are named workspaces.** A command like
  `portl session attach <TARGET> <SESSION>` reconnects to
  provider-backed terminal state. zmx-control is the optimized path;
  tmux `-CC` is the compatibility path.
- **Bootstrap is pluggable.** Docker and Slicer create target aliases;
  manual hosts can run the same agent and provider tools.
- **One multicall binary, three entrypoints.** `portl` is the operator
  CLI; `portl-agent` is the daemon entrypoint; `portl-gateway` is
  the gateway daemon entrypoint.

## Reading order

For the current user-facing surface, read **190-cli-ergonomics**,
**200-persistent-sessions**, and **210-session-control-lanes** after the
root `README.md`. These capture the modern `<TARGET>` vocabulary,
persistent-session model, and provider-tier work.

For architectural background, read **010-goals**, **020-architecture**,
and **030-tickets**. **100-walkthroughs** is still useful, but some early
flows use historical v0.1 command names; compare with `portl --help` and
the v0.2+ release specs.

If you care about the long-range transport story (WebRTC, Loom/AWDL,
running over Tailscale, SSH-as-transport), the artifact reading is
**future/140-transport-abstraction** and **future/150-loom-analysis** —
both deferred from v0.1.

Historical decision logs such as **120-roadmap** and
**130-open-questions** are provenance, not the active roadmap.
