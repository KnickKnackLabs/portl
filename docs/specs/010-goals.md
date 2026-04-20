# 01 — Goals, Non-Goals, Positioning

## 1. What portl is

A userspace framework for reaching peers over iroh/QUIC using **signed
capability tickets**. Ships as:

- A Rust library (`portl-core`) plus a combined protocol crate
  (`portl-proto`).
- One multicall binary: `portl`. The same executable serves the
  operator side (`portl shell …`) and the target side (`portl agent
  run …`), with an installed `portl-agent` symlink for argv[0]
  dispatch so legacy systemd units keep working. Opt-in `--mode
  gateway` replaces the earlier "portl-gw" sketch.
- A growing set of adapter crates that plug arbitrary orchestrators into
  the bootstrap pipeline.

## 2. Goals (v1)

1. **Public-key-addressed peers.** Every target has an ed25519 node-id. No
   centrally-assigned usernames, IPs, or accounts.
2. **Signed capability tickets as the unit of sharing.** Everything you ever
   paste or send is a ticket: a self-describing, URI-shaped capability with
   explicit allowed ALPNs, port globs, and a TTL.
3. **NAT-traversal across the public internet.** iroh hole-punches; when that
   fails, a self-hostable relay carries bytes without being able to read
   them.
4. **A small useful protocol set over one transport.** v0.1 ships
   `shell/v1`, `tcp/v1`, `udp/v1`, plus the mandatory `ticket/v1`
   and `meta/v1` handshake ALPNs. `fs/v1` is deferred to v0.2; VPN
   mode (`vpn/v1`) is a feature-gated stretch.
5. **Embeddability.** `portl-core` must be callable from other Rust
   programs. Binaries are thin wrappers.
6. **Bootstrap-agnostic.** Docker is the M4 reference adapter, slicer
   ships at M5 — both exercise the `Bootstrapper` trait from
   different angles, and neither is a dependency of the core. Other
   adapters must be straightforward to write.
7. **Revocable.** Tickets have a ticket-id; agents honour a revocation list.
   Delegated tickets can be revoked from either end of the chain.
8. **Observable.** Direct-vs-relay path, peer liveness, per-session audit
   records. "Why is this slow" is answerable without a packet capture.

## 3. Stretch goals (v1.x, feature-gated)

- **`vpn/v1` protocol** with cross-platform TUN driver. Deterministic ULA
  per peer derived from the node-id hash.
- **Local DNS stub** serving `<alias>.portl.local` → peer ULA. Lets apps
  reach peers by name without any coordinator.
- **SOCKS5 fallback** for the common case where a full VPN is overkill.
- **pkarr/DHT-based discovery** so tickets can omit relay hints and still
  resolve when the peer's network moves.

## 4. Non-goals (v1, possibly ever)

- **Full VPN replacement for WireGuard / Tailscale at line-rate.** portl is
  userspace and optimises for "reach anything across any NAT," not for
  saturating 10 GbE.
- **Windows agent.** Client likely works; agent support is post-v1.
- **Web UI, hosted dashboard, SaaS control plane.** Decentralised by design.
- **SSO / OIDC / SAML integration.** Bring your own trust roots; portl only
  knows about public keys.
- **Full SSH compatibility.** No agent forwarding, no SFTP. If you need
  those, run openssh inside the target and tunnel TCP to :22.
- **Byzantine-fault-tolerant consensus between peers.** Tickets are the only
  multi-party object and they're strictly additive (sign-only, no group
  protocol).

## 5. Positioning vs prior art

```
                 central      p2p     cap-based    embeddable     decentralised
                 control      QUIC    tickets      as library     by default
  WireGuard         —          —         —            partial        yes
  Tailscale         yes        —         —            (tsnet)        no
  Nebula            lighthouse —         —            partial        partial
  Yggdrasil         —          —         —            no             yes
  iroh (core)       —          yes       —            yes            yes
  iroh-ssh          —          yes       —            no             yes
  dumbpipe          —          yes       partial      no             yes
  portl             —          yes       yes          yes            yes
```

In one sentence: *portl sits where iroh is "just the transport" and things
like Tailscale are "full coordinator product."* It adds a capability model
and protocol suite on top of iroh without adding a control plane.

## 6. Who is this for

- Operators who run a small fleet of Linux hosts / VMs / containers and want
  ergonomic, secure remote access without depending on a commercial
  coordinator.
- Tool builders who want to embed p2p capability-shaped access in their
  product (slicer is the motivating example).
- Homelab / self-hosting enthusiasts for whom "run a VPS with a relay" is
  acceptable infrastructure and "sign up for an account somewhere" is not.

## 7. Deliberate simplifications

- **One canonical data plane (iroh/QUIC).** No pluggable `OverlayTransport`
  trait at v0.1. Iroh's own pluggable `Discovery` (DNS, Pkarr,
  Local/mDNS, DHT) covers LAN + internet peer-finding. When a genuine
  alternate data plane (WebRTC, Loom/AWDL) becomes necessary, the
  abstraction gets designed then, informed by what that plane actually
  needs. Draft kept at `future/140-transport-abstraction.md`.
- **One identity primitive (ed25519).** No post-quantum story in v0.1.
  Upgrade path: bump ticket version, rotate keys, republish.
- **One ticket schema version (v1).** iroh `EndpointAddr` for dialing,
  postcard for serialization, kind-prefixed base32 wire format
  (matches iroh-tickets; see `030-tickets.md §11`). Bumps to v2 on
  the first breaking change.
- **Postcard, not Protobuf/JSON/CBOR.** Smaller tickets, deterministic
  encoding, matches iroh's own ticket format.
- **Files on disk for state, not a DB.** The address book is SQLite but
  tickets are one-per-file. Easy to inspect, grep, diff, back up.
- **No plugin system at runtime.** Adapters are separate binaries /
  subcommands registered at build time. Keeps the security story simple.

## 8. Success criteria for v0.1

The project is useful when:

1. Two laptops running `portl agent run` can shell and port-forward to
   each other across the public internet using only a ticket exchanged
   via any out-of-band channel.
2. `portl docker container add demo-1` provisions a container on any
   dev laptop or CI runner and the operator can `portl shell demo-1`
   from their own machine with no port-forwarding. (M4)
3. `portl slicer vm add sbox` provisions a VM such that the operator's
   laptop can `portl shell <vm>` directly, without the slicer daemon
   being in the hot path. (M5)
4. `portl share <peer> --caps shell,tcp:22 --ttl 24h --to <friend>`
   produces a ticket that gives the friend exactly that access and
   nothing else.
5. Revoking a ticket takes effect on the agent within one session.

Stretch for v0.2:

6. `mosh` via `portl udp -L`.
7. `vpn` mode with `ping <peer>.portl.local`.
