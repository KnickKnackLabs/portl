# 12 — Roadmap

## 1. Milestones

```
  M0 ─ scaffold (workspace, iroh Endpoint wrapper, CI)
         │
  M1 ─ identity + tickets v1 (EndpointAddr + caps)
         │
  M2 ─ handshake (ticket/v1 + meta/v1) over iroh
         │
  M3 ─ shell + tcp
         │
  M4 ─ docker adapter (reference Bootstrapper + CI e2e)
         │
         ▼  v0.1-pre (external-friendly dogfooding)

  M5 ─ slicer adapter (gateway mode + master tickets)
  M6 ─ udp (mosh-quality roaming)
  M7 ─ polish (revocation GC, doctor, metrics, docs)
         │
         ▼  v0.1.0 release

  ─── post-v0.1 ───
  v0.1.x patch line ─ shell-handler stability (rlimits, pgroup
                      kill on disconnect, revoke kills live
                      sessions, session-start audit, stdout
                      drain timeout).

  v0.2.0 ─ "The Big Cleanup" — breaking simplification.
           Full plan: `140-v0.2-cleanup.md`.
           Headline: `portl init` + `portl docker run <image>`
           = shelled in, in two commands.

  v0.3+ ─ demand-driven, not committed:
     fs/v1
     vpn mode
     publish to crates.io
     Alternate data planes (WebRTC, Loom/AWDL) — `OverlayTransport`
         design landed then; see `future/140-transport-abstraction.md`
     Tailscale passthrough — if `tailscale-rs` stabilises
     SSH-as-transport
     Post-quantum hybrid signatures
```

The v0.1.0 release shipped on 2026-04-20. The post-v0.1 plan
diverged from the pre-release roadmap after operator feedback:
fs/v1 is pushed out in favour of a shape-cleanup release (v0.2)
that uses the only window we'll ever have to break CLI and
env-var shapes without maintenance burden. See
`140-v0.2-cleanup.md`.

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
- `docs/specs/` with this document set committed.
- Reproducible dev environment (`rust-toolchain.toml` pinned).

Non-goals: no real functionality yet.

### M1 — identity and tickets

Exit:

- `portl id new/show/export/import` works.
- Ticket codec roundtrip: `mint → encode (postcard + base32) → decode → verify`.
- Chain carrying tested: a 3-hop delegation encodes via separate
  `Bytes` blobs in `TicketOffer.chain`, not embedded in the URI.
- Proof-of-possession: `to`-bound ticket requires `proof` with domain-
  separated signature (see `030-tickets.md §9`).
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
  ed25519 verify (see `070-security.md §4.10`).
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

### M4 — docker adapter (reference Bootstrapper + CI e2e)

Exit:

- `adapters/docker-portl/` crate implements the `Bootstrapper` trait
  against `dockerd` via `bollard`.
- `portl docker container add <name>` provisions, registers, mints a
  root ticket, and prints the URI. See `060-docker.md`.
- `portl docker container {list,rm,rebuild,logs}` all work.
- Reference `Dockerfile` at `adapters/docker-portl/images/` builds
  a <80 MiB image containing the multicall binary.
- GH Actions `ci-e2e.yml` workflow brings up two ephemeral
  containers on an `ubuntu-latest` runner and exercises
  ticket/v1 + shell/v1 + tcp/v1 + delegation + revocation.
- Agent runs correctly as PID 1 (SIGTERM graceful shutdown, SIGCHLD
  reaping).
- Zero license / proprietary gates: anyone with `docker` can run
  the README quickstart.

Tests:

- `docker compose` with 3 agents; full mesh shell + tcp forward.
- Signal handling: container SIGTERM → agent closes QUIC cleanly
  within 10 s.
- Rootless dockerd: adapter works without privileged socket.
- macOS Docker Desktop `bridge` mode: hole-punch out succeeds,
  relay fallback works for inbound.
- Ephemeral container cycle: add → shell → rm → add (same name)
  produces a new endpoint_id; old tickets correctly rejected.

### v0.1-pre — external-friendly dogfooding

Tag, but no release. At this point the quickstart is:

```
brew install portl          # or apt / direct download
portl id new
portl docker container add demo-1
portl shell demo-1
```

Dogfood against docker for a week. Also dogfood on slicer via the
`manual-portl` adapter (print-the-instructions flow) to surface
anything docker happens to hide.

Collect:

- Pain points in CLI UX
- Reconnection edge cases
- Missing error messages
- Diagnostic gaps
- Surface gaps that M5's slicer-portl will need to fill

### M5 — slicer adapter

Exit:

- `adapters/slicer-portl/` crate implements `Bootstrapper` against
  the slicer HTTP API.
- Base OCI image fork with `portl` installed and
  `portl-agent.service` enabled.
- `portl slicer login <master>` works.
- `portl slicer vm add sbox` creates + registers + prints ticket.
- `portl shell <vm>` uses the per-VM ticket, bypasses slicer daemon.
- `portl slicer vm delete <vm>` revokes + deprovisions.
- `portl agent run --mode gateway` implemented; master-ticket
  bearer injection against the slicer HTTP API works.
- Published `ghcr.io/knickknacklabs/portl-agent:<version>` image
  (shared with docker-portl).

Tests:

- Full round trip: add → shell → cp → delete, no orphaned secrets.
- Master ticket rotation: old master refused after rotation.
- Gateway mode: master-ticket-held slicer API calls proxy
  correctly; non-bearer traffic is rejected at the gateway.

### M6 — udp

Exit:

- `portl udp <peer> -L ...` carries mosh traffic end-to-end.
- UDP session survives a QUIC reconnect within `UDP_SESSION_LINGER`
  (mosh keeps its session across a Wi-Fi switch).
- Mosh across NAT via relay works.

Tests:

- DNS over UDP works under latency loss.
- Mosh continues across a forced QUIC teardown + reconnect.

### M7 — polish

Exit:

- `portl revoke` + `portl revocations publish` works end-to-end.
- Revocation GC enforced (per `070-security.md §4.12`).
- `portl doctor` diagnoses: clock skew, discovery config, listener
  bind, relay reachability, ticket expiry.
- Agent exposes Prometheus metrics on the local unix socket.
- README quickstart reproducible by a stranger (uses docker-portl).
- `portl-relay` packaged (if we need it beyond iroh-relay upstream);
  documented how to self-host.
- v0.1.0 tagged; GH release artifacts.

---

### M8 — `fs/v1`

Exit:

- `portl cp` (fs/v1) handles files up to 10 GiB.
- Symlink, sparse-file, and cross-OS-permission corner cases tested.
- Throughput within 50% of native scp over equivalent path.

### M9 — VPN mode (stretch)

Exit:

- `vpn/v1` implemented in `portl-proto::vpn` (feature-gated).
- Linux + macOS TUN support.
- `portl vpn up <peer>` + local DNS stub for `*.portl.local`.
- `mosh <peer>.portl.local` works end-to-end without `portl udp -L`.

### M10 — publish

Exit:

- Crates published in dep-order to crates.io.
- Adapter crates split to their own repos
  (`KnickKnackLabs/slicer-portl`, `KnickKnackLabs/docker-portl`)
  if adapter velocity has diverged.
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
  6     M4 docker adapter (+ CI e2e)    65%
  7     v0.1-pre dogfooding             —
  8-9   M5 slicer adapter               78%
 10-11  M6 udp (mosh roaming)           88%
 12     M7 polish + metrics             98%
 13     v0.1.0 release                 100%
 ─── post-v0.1 ───
 14-15  M8 fs/v1
 16-18  M9 vpn mode (stretch)
 19+    M10 publish → v0.2.0
```

Adjust for life. Plan is that M4 (docker adapter) is usable even if
M5+ slips — external contributors and CI already get a working
system without any slicer dependency. Budget for at least one iroh
API migration between M2 and M7 (iroh is pre-1.0 and has had
breaking changes in nearly every minor release during 2024–25).

## 4. Explicit non-milestones

Features that will not have dedicated milestones in this plan:

- Web UI
- Mobile clients
- Windows agent
- HSM / Secure Enclave integration
- Post-quantum migration
- Multi-hop routing / real mesh topology
- Pluggable alternate data planes (OverlayTransport trait); see
  `future/140-transport-abstraction.md`
- Bonjour backend (iroh's Local discovery covers our LAN case)

These might happen later, but not along the critical path.

## 5. Measurable success criteria

For each milestone, a concrete demo/recording is filed:

- M2: short clip showing `portl status` going "direct" in < 1 s on a
  typical NAT; second clip showing two LAN peers finding each other
  with no external network.
- M3: `portl shell + portl tcp` in action.
- M4: quickstart recording — stranger clones repo, runs `docker
  compose up`, pastes a ticket, gets a shell into a container.
  CI e2e workflow running green on every PR.
- M5: full `portl slicer vm add → shell → delete` cycle.
- M6: mosh across the internet to a container or slicer VM,
  surviving a Wi-Fi switch.
- M7: ticket revoked mid-session, follow-up attempt rejected within
  1 s.
- M9: `mosh <peer>.portl.local` works with `portl vpn up` and nothing
  else.

These are the benchmarks for whether a milestone "shipped."

## 6. What "done" looks like for v0.1.0

A stranger can follow README.md, install binaries from a GH release,
join two machines, mint a ticket, use `shell/tcp/udp`, share it, revoke
it — all without consulting the author. Everything else is polish.
