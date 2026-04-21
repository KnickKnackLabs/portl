# 13 — Open questions / decisions needed
+
+> **Historical decision log.** Most items in this file are resolved
+> by the shipped v0.1.x / v0.2.0 work. Keep reading it as design
+> provenance, not as a live unresolved-questions queue.
+
+These are the places where this doc deliberately stops short and asks for
+explicit confirmation before code shape locks in.

Each item lists: the choice, the options, the current lean, and the cost
of getting it wrong.

---

## Q1. `shell/v1` stdio multiplexing  ✅ *resolved*

Decision: **(a) Separate QUIC sub-streams** per kind (stdin, stdout,
stderr, resize, signal, exit), all carrying the same `session_id` in
their `StreamPreamble`. See `040-protocols.md §3.2`.

Why: QUIC's built-in per-stream flow control is exactly what we want
for tty data. Choice (b) was simpler in frame-count terms but collapsed
three independent flow-control problems into one, re-creating the same
head-of-line blocking QUIC was designed to avoid (a flooded stdout can
block a resize or SIGINT).

The per-session stream-open cost (~5 extra streams per shell) is
trivial; QUIC scales to thousands of streams per connection.

---

## Q2. Ticket TTL cap on delegated tickets

Do we refuse to mint a delegated ticket whose `not_after` exceeds its
parent's?

Lean: **yes, strict**. Makes the delegation lattice monotone and
reasoning about "when does this stop working" trivial.

Alternative: allow; enforce at verify time only.

Cost of change: none if we relax later; painful if we want to tighten
later.

---

## Q3. Default discovery services

What does `portl-agent run` publish to by default?

Iroh exposes four discovery services. v0.1 defaults:

- **DNS** (iroh's `dns.iroh.link` by default, self-hostable): **on**.
- **Pkarr** (signed records, served via DNS): **on**.
- **Local/mDNS** (multicast on attached LANs): **on** — this is what
  makes LAN peers findable with zero infrastructure.
- **DHT** (BitTorrent Mainline): **off** — opt-in via
  `[discovery] dht = true`.

Rationale: the three "on" defaults cover the common cases (internet +
LAN) and each can be disabled for privacy (`[discovery] dns = false`,
etc.). DHT adds a layer of gossip where "this node exists" is a real
privacy signal even if the attacker can't connect, so we leave it
opt-in.

See `090-config.md` for config keys.

---

## Q4. Where does `portl-agent enroll` get its bootstrap ticket?

Options:

- **File path argument only**: `portl-agent enroll --bootstrap-ticket /path`
- **Also env var**: `PORTL_BOOTSTRAP_TICKET`
- **Also stdin**: `... --bootstrap-ticket -`
- **Adapter-provided well-known path**: e.g. `/run/portl/bootstrap.ticket`

Lean: **file path + stdin for v1**; adapters can write the path and pass
it. Env var feels error-prone (leaks in `ps`).

---

## Q5. Infinite-TTL tickets?

Do we forbid tickets with `not_after` set to max(u64)?

Lean: **forbid in v1**. Allow arbitrarily long TTL (e.g. 10 years) but
never "forever". Forces rotation thinking. Makes revocation simpler
(bounded size of the revocation set).

Cost of tightening later: existing tickets with infinite TTL break — bad.

Cost of loosening later: trivial; just remove the check.

---

## Q6. Adapter subcommand namespacing

Two options:

- **(A) Scoped**: `portl slicer vm add ...` (adapter as first positional)
- **(B) Flagged**: `portl vm add --via slicer ...`

Lean: **(A)**. Scoped reads better, matches `kubectl <verb> <noun>`
families, keeps adapters' flag sets separate. Price: less uniformity
across adapters (each adapter can have whatever subcommands it wants).

---

## Q7. License — RESOLVED

**Decision: MIT only.**

Rationale: maximally permissive, single-file license text, minimal
friction for both consumers and contributors. No CLA. Chosen over
`Apache-2.0 OR MIT` because a single license keeps `LICENSE` files,
`Cargo.toml` metadata, and contributor language simpler at this
scale.

---

## Q8. Relay discovery fallback order

When a ticket has no relay hints, what do we try?

Lean:

```
1. pkarr / DHT if enabled
2. config.toml relay_fallbacks
3. built-in last-ditch relay list (n0 community)
```

Question: include #3 or not? Arguments for: better UX for first-time
users. Arguments against: trusted-path ambiguity; some operators want
zero contact with non-self-hosted infra.

Lean: **include, behind a flag that's on by default, documented**, so
users can disable with `[discovery] builtin_relays = false`.

---

## Q9. Binary distribution

Options:

- **(A) `cargo install` + GH binary releases only** (musl for Linux,
  native for macOS).
- **(B) Also homebrew tap.**
- **(C) Also apt repo / nix flake / AUR.**

Lean: **(A) for v0.1**, (B) for v0.2, (C) driven by demand. Static musl
binaries from GH Actions are Good Enough for a long time.

---

## Q10. SDK embedding API shape

What does "10-line embed" look like? Draft:

```rust
use portl_sdk::{Endpoint, Ticket};

let ticket: Ticket = std::env::var("TICKET")?.parse()?;
let endpoint = Endpoint::builder()
    .identity(Endpoint::load_or_generate("~/.my-app/portl.key")?)
    .build().await?;

let peer = endpoint.connect(&ticket).await?;
let mut stream = peer.open_tcp("127.0.0.1", 22).await?;
// stream is tokio::io::AsyncRead + AsyncWrite
```

Question: should `Endpoint::builder()` default to the same discovery /
relay config that `portl-cli` uses, or be minimal?

Lean: **opinionated defaults** (same as CLI defaults), with ergonomic
overrides. Embedders who want surgical control can escape to
`portl-core` directly.

---

## Q11. Ticket signing key vs identity key

Currently: operator has one `identity.key` used for everything (signing
tickets, proof-of-possession, encrypting backups).

Alternative: separate **signing key** from **device key**. Each machine
the operator uses gets a device key; signing key is on hardware.

Lean: **one key for v1**; plan to separate in v0.2+ once the rest is
stable.

---

## Q12. Minimum iroh version

Iroh's public API is still evolving. What do we pin to?

Lean: **latest stable release at M2 freeze**, then update in sync with
upstream's minor bumps. Don't chase main. Document minimum in README.

---

## Q13. Telemetry

Zero by default; no phone-home. Confirm?

Lean: **confirmed**. Even anonymous crash reporting is out unless
explicitly opt-in. `portl doctor` produces a text report the user can
paste manually.

---

## Q14. Naming subcommand convention

Variants in this document:

- `portl vm list`   (operating on VM-shaped peers)
- `portl list`      (operating on local tickets)

The `vm` namespace makes sense for adapter subcommands
(`portl slicer vm …`), but for operator-local commands (listing tickets
you hold), do we want `portl list` or `portl tickets list`?

Lean: **`portl list`** for tickets (fewer keystrokes, matches `git log`,
`kubectl get`). Adapter subcommands keep `vm` for orchestrator objects.

---

## Q15. Revocation propagation model

Three models for keeping agents current on revocations:

- **(A) Pull**: agent polls a well-known HTTP endpoint (e.g. the operator's
  gist) every N minutes.
- **(B) Push**: operator `meta/v1 PublishRevocations` to each agent they
  know about.
- **(C) Both**: agents pull + accept pushes.

Lean: **(B) only in v1**, **(C) in v2**. Pull requires hosting; push is
self-contained.

Trade-off: push doesn't reach agents whose node-id's operator isn't
actively running the CLI.

---

## Q16. Audit log format

Structured JSONL vs human-readable vs journald's native format?

Lean: **JSONL when sink=file**, journald structured fields when
sink=journald. Both at once via dual-sink if needed.

---

## Questions to answer **before scaffolding**

1. **Q6 subcommand namespacing** — scoped like `portl slicer ...` ok?
   (affects CLI module layout)
2. **Q14 `portl list` naming** — confirm top-level `portl list` lists
   tickets? (affects commands/ skeleton)

Everything else can be decided as we build, or left to RFC after v0.1.

---

## Resolved decisions (post-roundtable review)

The design went through a formal roundtable review
([`future/140-transport-abstraction.md`](future/140-transport-abstraction.md)
documents the branch we didn't take). These decisions are settled:

- **Transport abstraction in v0.1**: **no**. Iroh is the single data
  plane; a thin newtype wrapper in `portl-core::endpoint` keeps iroh
  imports out of protocol crates. When a genuine alternate data plane
  (WebRTC, Loom/AWDL) is demanded, the `OverlayTransport` trait gets
  designed then, informed by what that second plane actually needs.
  See `020-architecture.md §11`.
- **Ticket schema version**: **v1** with `node_id` + `relays[]`
  (iroh's `NodeAddr` shape). See `030-tickets.md §2`. Bumps to v2 when
  the first wire-format change lands.
- **Bonjour-style LAN discovery**: iroh's built-in **Local discovery**
  (mDNS-based) is turned on by default. No separate `portl-overlay-
  bonjour` crate needed; the work is a config flag on the iroh
  endpoint. See `090-config.md` `[discovery]` section.
- **Proof-of-possession**: `to`-bound tickets require a signature with
  domain separation; bearer-style tickets carry no extra handshake
  turn. Iroh QUIC TLS already binds node identity, so no mutual
  challenge-response in `ticket/v1`. See `030-tickets.md §9`.
- **Delegation chain encoding**: parent ticket bytes travel on the
  wire inside `TicketOffer.chain`, not embedded in the URI. URIs stay
  bounded at ~400–500 chars regardless of delegation depth. See
  `030-tickets.md §3` and `040-protocols.md §1`.
- **URI encoding**: kind-prefixed base32-lowercase, matching
  iroh-tickets (`portl<base32>`, no separator, no checksum). Gives
  us parseability in `ticket.iroh.computer` and reuses
  `iroh_base::EndpointAddr` for dialing info. Postcard-encoded body.
  See `030-tickets.md §11`.
- **Ticket schema compression**: three mechanical wins taken after
  roundtable review — elide `issuer` for self-signed roots; replace
  `parent_sig` with `parent_ticket_id: [u8; 16]` (domain-separated
  SHA-256); elide `parent_issuer`. Plus drop redundant `alpns` field
  (derive from `Capabilities`) and use a presence bitmap for
  `Capabilities`. Net effect: ~30% smaller tickets for the common
  cases. See `030-tickets.md §12`.
- **Connection migration**: explicit non-goal for v0.1. Sessions drop
  on transport change; reconnect via same ticket. `tmux attach` is
  the documented mitigation for long-running work.
- **`fs/v1`**: **deferred to post-v0.1** (M8). Workaround for v0.1 is
  `portl sh peer 'tar c DIR' | tar x`.
- **M0 workspace scope**: trimmed to 4 active crates (`portl-core`,
  `portl-proto`, `portl-cli`, `slicer-portl`, `manual-portl`;
  `portl-relay` added only if iroh-relay upstream can't be used
  directly). `portl-cli` produces a single multicall binary that
  serves both the operator (`portl …`) and agent (`portl agent …`)
  roles, with a packager-installed `portl-agent` symlink for
  argv[0] dispatch. Individual protocol crates split back out of
  `portl-proto` post-v0.1 if any grows beyond ~1 kLoC.
- **Binary shape**: **one multicall binary, not two.** Client and
  agent share ~90% of their code (iroh, rustls, tokio, ed25519,
  postcard, rusqlite, tracing, clap, `portl-core`, `portl-proto`);
  a merged binary is ~17–19 MB vs ~27 MB for two separate ones, and
  it eliminates client/agent version skew by construction. The
  `portl-agent` symlink preserves existing systemd units and
  operator muscle memory.
- **Clock skew**: ±60 s tolerance on `not_before`; strict on
  `not_after`. See `070-security.md §4.11`.
- **Revocation GC**: `REVOCATION_LINGER = 7 days past original ticket
  not_after`. See `070-security.md §4.12`.
- **Loom backend**: deferred indefinitely (community-driven). AWDL
  cannot reach the primary Mac→Linux-VM use case; iroh Local
  discovery + iroh QUIC cover what Loom would cover for that topology.
  Analysis preserved at `future/150-loom-analysis.md`.

## New questions introduced by the revision

- **Default iroh `dns.iroh.link` vs self-hosted DNS**: operators who
  never want to talk to n0.computer infrastructure need a quick
  `portl-agent run --discovery self` that turns DNS off and leaves
  only Local + Pkarr. Should we ship that flag, or just document the
  config override?
- **`iroh::discovery` churn**: iroh is pre-1.0 and the Discovery API
  has shifted at least twice in 2024–25. `portl-core::discovery`
  should wrap iroh's type so we can absorb API changes in one place.
- **First alternate data plane**: when the first real WebRTC or Loom
  contributor appears, do we accept the code in-tree (behind a
  feature flag) or require a separate repo? No answer yet; revisit
  when the situation is concrete.
