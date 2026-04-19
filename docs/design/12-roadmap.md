# 12 — Roadmap

## 1. Milestones

```
  M0 ─ scaffold (workspace, iroh Endpoint wrapper, CI)
         │
  M1 ─ identity + tickets v1 (node_id + relays[])
         │
  M2 ─ handshake (ticket/v1 + meta/v1) over iroh
         │
  M3 ─ shell + tcp
         │
  M4 ─ slicer adapter (primary portl use case usable)
         │
         ▼  v0.1-pre (internal dogfooding)

  M5 ─ udp (mosh-quality roaming)
  M6 ─ polish (revocation GC, doctor, metrics, docs)
         │
         ▼  v0.1.0 release

  ─── post-v0.1 ───
  M7 ─ fs/v1
  M8 ─ vpn mode (stretch)
  M9 ─ publish to crates.io ─────────► v0.2.0

  Future (demand-driven, not on critical path):
     Alternate data planes (WebRTC, Loom/AWDL) — `OverlayTransport`
         design landed then; see `future/14-transport-abstraction.md`
     Tailscale passthrough — if `tailscale-rs` stabilises
     SSH-as-transport
     Post-quantum hybrid signatures
```

## 2. Milestone detail

### M0 — scaffold

Exit:

- Workspace compiles (`cargo check --workspace`).
- All crates (`portl-core`, `portl-proto`, `portl-cli`,
  `slicer-portl`, `manual-portl`) have `fn main`/`pub fn` stubs.
- `portl-cli` builds as a single multicall binary; `portl agent run`
  dispatches into the agent subtree, and argv[0] == `portl-agent`
  prepends `agent` before clap parsing.
- `portl-core::endpoint` is a thin newtype over `iroh::Endpoint`.
- `portl-core::test_util::pair()` returns two wired-in-process Endpoints
  (replaces the pre-review `portl-overlay-loopback` crate).
- CI green: `cargo check + cargo test + clippy + rustfmt + cargo-deny`.
- `docs/design/` with this document set committed.
- Reproducible dev environment (`rust-toolchain.toml` pinned).

Non-goals: no real functionality yet.

### M1 — identity and tickets

Exit:

- `portl id new/show/export/import` works.
- Ticket codec roundtrip: `mint → encode (postcard + base32) → decode → verify`.
- Chain carrying tested: a 3-hop delegation encodes via separate
  `Bytes` blobs in `TicketOffer.chain`, not embedded in the URI.
- Proof-of-possession: `to`-bound ticket requires `proof` with domain-
  separated signature (see `03-tickets.md §9`).
- Property tests: monotone narrowing, TTL bounds, delegation depth,
  clock-skew tolerance.
- No network code yet — verification runs against in-memory fixtures.

Tests:

- Ticket schema stability test (golden bytes).
- 10 000-ticket mint-then-verify benchmark (< 5 s).

### M2 — handshake + discovery

Exit:

- `portl-agent run` binds an `iroh::Endpoint` with DNS, Pkarr, **and
  Local (mDNS)** discovery enabled by default.
- `portl` opens a `ticket/v1` stream, handshake succeeds.
- `portl status <peer>` reports direct-vs-relay, RTT, and which
  discovery service located the peer (DNS/Pkarr/Local/DHT).
- Two machines on the same LAN find each other without any relay or
  DNS hit (Local discovery only).
- Two machines across NAT complete `ticket/v1 + meta/v1` using
  DNS/Pkarr + relay.

Tests:

- Ticket acceptance matrix: valid, expired, revoked, bad-sig,
  wrong-root, bad-proof, wrong-`to`.
- Pre-auth rate-limit gate rejects a CPU-flood attacker before
  ed25519 verify (see `07-security.md §4.10`).
- Direct + relay paths exercised in CI via container networking.
- LAN-only path exercised in CI via a docker bridge network with
  no outbound route.

### M3 — shell + tcp

Exit:

- `portl shell <peer>` → PTY with colour, resize, clean exit.
- `portl exec <peer> -- cmd` → stdio correct, exit code returned.
- `portl tcp <peer> -L …:…:…:…` forwards; TCP EOF propagates.
- Audit records written to journald.

Tests:

- Resize mid-session.
- Large file streamed through `tcp/v1` (no data corruption,
  backpressure correct).
- `portl exec` with non-zero exit correctly reported.

### M4 — slicer adapter

Exit:

- Base OCI image fork with `portl` installed and
  `portl-agent.service` enabled.
- `portl slicer login <master>` works.
- `portl slicer vm add sbox` creates + registers + prints ticket.
- `portl shell <vm>` uses the per-VM ticket, bypasses slicer daemon.
- `portl slicer vm delete <vm>` revokes + deprovisions.

Tests:

- Full round trip: add → shell → cp → delete, no orphaned secrets.
- Master ticket rotation: old master refused after rotation.

### v0.1-pre — internal dogfooding

Tag, but no release. Use against real VMs for a week. Collect:

- Pain points in CLI UX
- Reconnection edge cases
- Missing error messages
- Diagnostic gaps

### M5 — udp

Exit:

- `portl udp <peer> -L ...` carries mosh traffic end-to-end.
- UDP session survives a QUIC reconnect within `UDP_SESSION_LINGER`
  (mosh keeps its session across a Wi-Fi switch).
- Mosh across NAT via relay works.

Tests:

- DNS over UDP works under latency loss.
- Mosh continues across a forced QUIC teardown + reconnect.

### M6 — polish

Exit:

- `portl revoke` + `portl revocations publish` works end-to-end.
- Revocation GC enforced (per `07-security.md §4.12`).
- `portl doctor` diagnoses: clock skew, discovery config, listener
  bind, relay reachability, ticket expiry.
- Agent exposes Prometheus metrics on the local unix socket.
- README quickstart reproducible by a stranger.
- `portl-relay` packaged (if we need it beyond iroh-relay upstream);
  documented how to self-host.
- v0.1.0 tagged; GH release artifacts.

---

### M7 — `fs/v1`

Exit:

- `portl cp` (fs/v1) handles files up to 10 GiB.
- Symlink, sparse-file, and cross-OS-permission corner cases tested.
- Throughput within 50% of native scp over equivalent path.

### M8 — VPN mode (stretch)

Exit:

- `vpn/v1` implemented in `portl-proto::vpn` (feature-gated).
- Linux + macOS TUN support.
- `portl vpn up <peer>` + local DNS stub for `*.portl.local`.
- `mosh <peer>.portl.local` works end-to-end without `portl udp -L`.

### M9 — publish

Exit:

- Crates published in dep-order to crates.io.
- Slicer adapter split to its own repo
  (`KnickKnackLabs/slicer-portl`) if adapter velocity has diverged.
- Blog post / README published.
- v0.2.0 tagged.

---

## 3. Rough calendar at hobby pace

```
 week   milestone                     cumulative toward v0.1
 ────   ──────────────                ─────────────────────
  1     M0 scaffold                      5%
  2     M1 identity + tickets v1        15%
  3     M2 handshake + discovery        30%
  4     M3 shell                        40%
  5     M3 tcp                          50%
  6-7   M4 slicer adapter               65%
  8     v0.1-pre dogfooding             —
  9-10  M5 udp (mosh roaming)           80%
 11     M6 polish + metrics             95%
 12     v0.1.0 release                 100%
 ─── post-v0.1 ───
 13-14  M7 fs/v1
 15-17  M8 vpn mode (stretch)
 18+    M9 publish → v0.2.0
```

Adjust for life. Plan is that M4 is usable even if M5+ slips. Budget
for at least one iroh API migration between M2 and M6 (iroh is
pre-1.0 and has had breaking changes in nearly every minor release
during 2024–25).

## 4. Explicit non-milestones

Features that will not have dedicated milestones in this plan:

- Web UI
- Mobile clients
- Windows agent
- HSM / Secure Enclave integration
- Post-quantum migration
- Multi-hop routing / real mesh topology
- Pluggable alternate data planes (OverlayTransport trait); see
  `future/14-transport-abstraction.md`
- Bonjour backend (iroh's Local discovery covers our LAN case)

These might happen later, but not along the critical path.

## 5. Measurable success criteria

For each milestone, a concrete demo/recording is filed:

- M2: short clip showing `portl status` going "direct" in < 1 s on a
  typical NAT; second clip showing two LAN peers finding each other
  with no external network.
- M3: `portl shell + portl tcp` in action.
- M4: full `portl slicer vm add → shell → delete` cycle.
- M5: mosh across the internet to a slicer VM, surviving a Wi-Fi
  switch.
- M6: ticket revoked mid-session, follow-up attempt rejected within
  1 s.
- M8: `mosh <peer>.portl.local` works with `portl vpn up` and nothing
  else.

These are the benchmarks for whether a milestone "shipped."

## 6. What "done" looks like for v0.1.0

A stranger can follow README.md, install binaries from a GH release,
join two machines, mint a ticket, use `shell/tcp/udp`, share it, revoke
it — all without consulting the author. Everything else is polish.
