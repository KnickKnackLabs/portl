> **Deferred design artifact.**
>
> This document was written during the pre-v0.1 design phase, when portl
> briefly planned a pluggable `OverlayTransport` trait at the core layer.
> That direction was **abandoned** after a design review showed that:
>
> 1. Iroh already owns the data plane (QUIC + hole-punch + relay) and
>    exposes its own pluggable `Discovery` trait (DNS, Pkarr, Local/mDNS,
>    DHT). "LAN discovery via Bonjour" is an iroh config flag, not a
>    separate backend.
> 2. Non-iroh data planes worth supporting (WebRTC for browsers,
>    Loom/AWDL for Apple-proximity) are far enough off that designing an
>    abstraction for them now would be guessing.
>
> v0.1 therefore ships iroh as the sole data plane, with iroh's own
> `Discovery` plugins (including Local/mDNS) used to cover LAN +
> internet peers. This document is retained as an artifact for the day
> a second, genuine data plane is demanded.

---

# 14 — Transport abstraction

> portl's distinctive pieces — tickets, capabilities, policy, protocols —
> live at the application layer and are transport-agnostic. The iroh
> dependency is deliberately isolated to a thin layer so we can swap it,
> supplement it, or federate across multiple transports at once.

## 1. Why pluggable transports

A single transport is a single failure mode, a single trust assumption,
and a single performance envelope. Users reasonably want:

- **iroh** for the default: decentralised, public-key-addressed, global.
- **Tailscale** when they already live on a tailnet and don't want to run
  an iroh relay.
- **LAN / Bonjour** for airgapped or same-network direct paths.
- **AWDL / Loom** for the "two Apple devices with no router" scenario.
- **SSH** as a tunnel when they already have an SSH session to a machine
  and want portl streams over it.
- **Loopback** (in-process) for tests.

The architecture was drafted with this in mind: ticket signing, capability
intersection, protocol framing, and audit are all unaware of transport.
Only the byte-shoveling layer changes.

This doc defines the trait, the capability-matching model, and the
multi-transport dial semantics.

## 2. The `OverlayTransport` trait

```rust
// crates/portl-overlay/src/lib.rs

pub trait OverlayTransport: Send + Sync + 'static {
    type PeerAddress: Clone + Send + Sync + std::fmt::Debug;
    type Endpoint:    OverlayEndpoint<PeerAddress = Self::PeerAddress>;
    type Identity;

    /// Short stable name: "iroh", "tailscale", "bonjour", "loom", ...
    fn name(&self) -> &'static str;

    fn capabilities(&self) -> TransportCapabilities;

    fn bind(&self, id: Self::Identity, cfg: EndpointCfg)
        -> impl Future<Output = Result<Self::Endpoint>>;
}

pub trait OverlayEndpoint: Send + Sync + 'static {
    type PeerAddress;
    type Connection: OverlayConnection<PeerAddress = Self::PeerAddress>;

    fn local_address(&self) -> Self::PeerAddress;

    fn accept(&self)
        -> impl Future<Output = Result<Self::Connection>>;

    fn connect(&self, addr: Self::PeerAddress)
        -> impl Future<Output = Result<Self::Connection>>;
}

pub trait OverlayConnection: Send + Sync + 'static {
    type PeerAddress;
    type Stream:  tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send;

    fn open_stream(&self, label: &str)
        -> impl Future<Output = Result<Self::Stream>>;

    fn accept_stream(&self)
        -> impl Future<Output = Result<(String, Self::Stream)>>;

    fn send_datagram(&self, data: Bytes)
        -> impl Future<Output = Result<()>>;

    fn recv_datagram(&self)
        -> impl Future<Output = Result<Bytes>>;

    fn peer_address(&self) -> &Self::PeerAddress;
    fn max_datagram_size(&self) -> usize;
    fn path_info(&self) -> PathInfo;
}
```

Small enough to review end-to-end, large enough that mapping iroh,
Tailscale, Bonjour, Loom, or a loopback onto it is straightforward.

## 3. Capability declarations

Transports advertise what they can and cannot do. Protocols declare what
they need. A small matcher function pairs them.

```rust
pub struct TransportCapabilities {
    pub streams:           StreamSupport,
    pub datagrams:         DatagramSupport,
    pub typical_bps:       u64,
    pub typical_rtt_ms:    u32,
    pub reliability:       Reliability,
    pub cost_class:        CostClass,
    pub duty_cycle_pct:    Option<f32>,   // Some(1.0) for EU LoRa, etc.
    pub discovery:         DiscoveryModel,
    pub range:             Range,
    pub multiplexing:      Multiplexing,
}

pub enum StreamSupport {
    None,                       // no stream primitive
    OneAtATime,                 // single stream per connection
    MultiplexedNative,          // transport has first-class streams (QUIC)
    MultiplexedApp,             // we synthesise via yamux or similar
}

pub enum DatagramSupport {
    None,
    BestEffort { max_size: usize },
    Reliable   { max_size: usize },   // very rare; e.g. message-oriented
                                      //   protocols with ack
}

pub enum Reliability    { Reliable, BestEffort, HighLoss }
pub enum CostClass      { Free, Metered, RateLimited }
pub enum DiscoveryModel { DirectAddress, Scan, Coordinator, Broadcast, Signalled }
pub enum Range          { Global, Lan, Proximity, LineOfSight }
pub enum Multiplexing   { Native, AppLevel, OneStream }
```

Protocols declare what they need:

```rust
pub trait ProtocolService: Send + Sync {
    const ALPN: &'static str;
    fn requirements() -> ProtocolRequirements;
}

pub struct ProtocolRequirements {
    pub needs_streams:      bool,
    pub needs_datagrams:    bool,
    pub min_bps:            u64,
    pub max_rtt_ms:         u32,
    pub min_datagram_size:  Option<usize>,
    pub interactive:        bool,   // PTYs, shells → latency essential
}
```

## 4. Matching algorithm

```
      ┌────────────────── ProtocolRequirements ──────────────────┐
      │  needs_streams?   needs_datagrams?                        │
      │  min_bps, max_rtt_ms, min_datagram_size, interactive      │
      └───────────────────────────────┬───────────────────────────┘
                                      │
                                      ▼
      ┌────────────────── TransportCapabilities ─────────────────┐
      │  for each transport known to the client, evaluate:       │
      │                                                          │
      │   1. If needs_streams: caps.streams != None ?            │
      │   2. If needs_datagrams: caps.datagrams != None ?        │
      │   3. typical_bps >= min_bps ?                            │
      │   4. typical_rtt_ms <= max_rtt_ms ?                      │
      │   5. max_datagram_size >= min_datagram_size ?            │
      │   6. if interactive: rtt + duty_cycle acceptable ?       │
      └───────────────────────────────┬───────────────────────────┘
                                      │
                                      ▼
      [candidate transports] ranked by:
          a) direct over relayed
          b) Lan/Proximity over Global
          c) Free over Metered
          d) lower RTT
          e) higher bandwidth
```

The matcher is pure; it runs client-side at dial time and agent-side at
accept time to reject protocol requests that the chosen transport can't
satisfy.

## 5. Multi-transport peers (tickets as address bundles)

A peer publishes all the ways it can be reached. A ticket is one of those
bundles.

```
Ticket for claude-1
────────────────────
  peer_key  : a1b2c3…                   (portl identity; invariant)
  transports:
     [0] IrohHint      { node_id: a1b2c3…, relays: [...] }
     [1] BonjourHint   { service: _portl._tcp, name: claude-1.local }
     [2] TailscaleHint { ip: 100.64.0.8, port: 42000 }
     [3] LoomHint      { service: _portl._tcp, bonjour_name: claude-1 }
     [4] SshHint       { host: claude-1.example.org, port: 22,
                         user: ubuntu }
  alpns     : [shell/v1, tcp/v1, udp/v1, fs/v1]
  caps      : {...}
  ttl, sig, …
```

The client picks at dial time — none of this affects the ticket's caps or
identity.

## 6. Dial sequence (parallel-dial with stagger)

```
  t=0ms     filter transports by protocol requirements
              → [bonjour, loom, iroh]     (tailscale excluded; cost=metered,
                                          user preference off)

  t=0ms     rank by preference
              → [loom (Proximity, direct), bonjour (LAN), iroh (Global)]

  t=0ms     start dialing loom
  t=300ms   start dialing bonjour (if loom not yet connected)
  t=600ms   start dialing iroh

  t=??ms    first successful ticket/v1 handshake WINS
            - cancel slower outstanding dials
            - keep one as hot-standby for migration? (v2)
            - report path info to status UI

  commit:   use winning connection for all subsequent streams/datagrams
            (until it breaks; reconnect uses same logic)
```

Stagger avoids hammering all transports simultaneously (especially
important for metered / rate-limited ones). Values are configurable in
`config.toml`.

## 7. Asymmetric topologies

A peer need not listen on or dial from all transports.

```
agent inside a slicer VM:
  LISTENS on iroh
  LISTENS on bonjour (if LAN-visible)
  does not dial outbound anywhere

client on operator laptop:
  DIALS iroh + bonjour + tailscale (+ loom on Apple)
  LISTENS on nothing

gateway on the slicer host:
  LISTENS on iroh (public)
  LISTENS on tailscale (tailnet-visible)
  LISTENS on bonjour (office LAN)
  DIALS the local slicer HTTP API via TCP to 127.0.0.1
```

Each transport is independent. The ticket lists the ones the peer
advertises; the client evaluates which are reachable from its side.

## 8. Identity proof-of-possession (for non-cryptographic transports)

iroh's QUIC TLS handshake cryptographically proves the peer holds
`node_id`'s private key. Tailscale, Bonjour, Loom, SSH-as-transport, and
loopback do not — the transport proves "connected to whoever lives at
100.64.0.8" or "paired with this Bonjour name," which is weaker.

To close the gap uniformly, the portl `ticket/v1` handshake always
includes a mutual challenge-response:

```
client  → agent:  TicketOffer {
                     ticket,
                     client_nonce,
                     op_sig = sign(op_key, client_nonce || transport_addr)
                         // present iff ticket is `to`-bound
                  }

agent   → client: TicketAck   {
                     ok,
                     peer_token,
                     agent_nonce,
                     agent_sig = sign(agent_secret,
                                      agent_nonce || client_nonce || ticket_id),
                     effective_caps
                  }

both verify each other's signature against keys named in the ticket.
```

For iroh this is redundant (TLS already binds the identity); we still run
it for uniformity. The cost is ~one ed25519 verify per side, tens of
microseconds.

## 9. Transport fit matrix

```
┌────────────── TRANSPORT ↔ PROTOCOL FIT ──────────────┐

Transport     meta   shell   tcp    udp    fs     vpn    notes
─────────────────────────────────────────────────────────────────────
iroh          ✓      ✓       ✓      ✓      ✓      ✓      reference
loopback      ✓      ✓       ✓      ✓      ✓      ✓      tests only
tailscale     ✓      ✓       ✓      ✓      ✓      ✓*     *via yamux + udp
bonjour       ✓      ✓       ✓      ✗      ✓      ✗      LAN-only; no dgrams
loom          ✓      ✓       ✓      ✗      ✓      ✗      AWDL; Apple-only
ssh           ✓      ✓       ✓      ✗      ✓      ✗      if SSH supported by host
bt-classic    ✓      slow    ✓      ✗      —      ✗      RFCOMM one stream
bt-le         ping   ✗       ✗      ✗      ✗      ✗      tiny payloads only
webrtc        ✓      ✓       ✓      ✓      ✓      ✓      browser clients
lorawan       ping   ✗       ✗      ✗      ✗      ✗      heartbeat/revoke
─────────────────────────────────────────────────────────────────────

✓ = supported
✗ = not supported or impractical
ping = only meta/v1 ping + revocation push fit
```

Notes:
- **bonjour / loom / ssh lose udp/v1 and vpn/v1** because they don't
  expose a native datagram primitive. `udp/v1` could be emulated over a
  reliable stream at cost of UDP's semantics; that's a per-ALPN policy
  call.
- **tailscale** needs app-level multiplexing (yamux) because it only
  exposes raw TCP sockets. Our transport crate does this transparently.
- **ssh** is interesting: if a user has OpenSSH to a host, they can run
  portl streams over an SSH channel without any other transport. Useful
  for pre-portl fleets; sketched as `portl-overlay-ssh`.

## 10. Architecture: how the transport abstraction plugs in

```
┌────────────────── portl-cli / portl-agent / portl-sdk ──────────────┐
│                                                                      │
│   protocols: portl-proto-shell, -forward, -fs, -tunnel              │
│       │                                                              │
│       │ each generic over T: OverlayTransport                        │
│       ▼                                                              │
│   portl-core: sessions, tickets, caps, policy, audit                 │
│       │                                                              │
│       │ depends on                                                   │
│       ▼                                                              │
│   portl-overlay (trait crate)                                        │
│       │                                                              │
│       │ impls registered via one of:                                 │
│       ▼                                                              │
│   ┌────────────────────────────────────────────────────────────┐    │
│   │  portl-overlay-iroh      (Rust, default)                    │    │
│   │  portl-overlay-loopback  (Rust, tests)                      │    │
│   │  portl-overlay-bonjour   (Rust, LAN; v0.2)                  │    │
│   │  portl-overlay-tailscale (Rust, tailscale-rs; v0.3 experim.)│    │
│   │  portl-overlay-ssh       (Rust, ssh fwd; future)            │    │
│   │  portl-overlay-loom      (Swift FFI; deferred)              │    │
│   │  portl-overlay-webrtc    (Rust, webrtc-rs; future)          │    │
│   └────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘
```

Each backend is its own crate, feature-gated in `portl-agent` and
`portl-cli`. Shipping binaries include iroh + loopback by default;
end-users enable others with `--features overlay-bonjour,overlay-loom` at
install time, or download pre-built binaries with the right combination.

## 11. Connection migration (explicit non-goal for v1)

Moving a live session from one transport to another while keeping the
logical session alive is technically possible (QUIC connection migration
does it within one transport; cross-transport is strictly harder). It
requires:

- Transport-agnostic session IDs.
- Stream resumption tokens.
- Re-running `ticket/v1` on the new path and attaching to the existing
  `peer_token`.

For v1, **sessions simply drop on transport failure.** Mitigations:

- Use `--bootstrap "tmux attach"` for shell sessions so the in-target
  tmux survives client reconnects.
- `portl-proto-*` each document their "connection dropped" semantics.
- Reconnection uses the same dial logic and attaches fresh.

Revisit in v2 if demand materialises.

## 12. What each transport looks like mapped onto the trait

### iroh (reference backend)

```
PeerAddress  = iroh::NodeAddr { node_id, relays }
Identity     = iroh::SecretKey
Endpoint     = iroh::Endpoint
Connection   = iroh::Connection

open_stream(label)   → connection.open_bi() with ALPN = label
accept_stream()      → connection.accept_bi() → (alpn, bi)
send_datagram(b)     → connection.send_datagram(b)
recv_datagram()      → connection.read_datagram()
max_datagram_size    → PMTU-aware, ~1200 bytes
path_info            → direct vs relay, RTT, bytes
```

### loopback (tests)

```
PeerAddress  = a tokio::sync::mpsc handle
Connection   = pair of channels

Everything in-process; instant; no real transport. Used exclusively for
unit + integration tests. Zero external deps.
```

### bonjour / LAN-QUIC (v0.2)

```
PeerAddress  = (resolved IP, port)  from Bonjour TXT records
Identity     = ed25519 SecretKey (portl's own, shared with iroh backend)
Endpoint     = mDNS browser + advertise + quinn-over-UDP listener
Connection   = quinn QUIC connection over LAN UDP

Discovery    = mDNS / DNS-SD (`_portl._tcp`)
Range        = LAN only
Multiplex    = native (QUIC streams + datagrams, same as iroh backend)

Note: full QUIC semantics, minus iroh's discovery/relay plumbing. This is
essentially iroh without the internet; pure Rust; works on linux/macOS/
windows.
```

### tailscale (v0.3, experimental)

```
PeerAddress  = (tailnet Ipv4Addr, base port)
Identity     = TailscaleAuthKey + hostname
Endpoint     = tailscale::Device with our yamux-over-TCP listener on base port
Connection   = one TCP conn + yamux; one UDP socket for datagrams

open_stream(label) → yamux.open() + write 2-byte label header
accept_stream()    → yamux.accept() + read 2-byte label header
send_datagram(b)   → udp.send_to(peer_ip:ds_port, b)
recv_datagram()    → udp.recv_from on shared socket; demux by peer + session

Note: tailscale-rs is still experimental; this backend is gated on
upstream maturity. Direct NAT traversal not yet implemented upstream
(DERP-only as of this writing).
```

### loom / AWDL (deferred, see 15-loom-analysis.md)

```
PeerAddress  = LoomPeerRef (UUID + Bonjour name)
Identity     = LoomIdentityManager handle
Endpoint     = LoomNode via Swift FFI bridge
Connection   = LoomAuthenticatedSession

open_stream(label) → LoomMultiplexedStream with protocol label
datagrams         → NOT SUPPORTED; only reliable streams.

Strictly Apple-to-Apple (AWDL peer-to-peer Wi-Fi).
Requires Swift sidecar dylib + entitlements.
Deferred to v0.4+.
```

### ssh (future)

```
PeerAddress  = (hostname, port, user)
Identity     = an ssh private key (operator-chosen)
Endpoint     = spawns an openssh control socket on demand
Connection   = an ssh channel; multiplexed via yamux OR via separate
               direct-tcpip forwards per stream

datagrams    → NOT SUPPORTED

Use case: "I already have SSH to this host; let me drive portl over it."
Great for retrofitting portl onto existing fleets.
```

## 13. Agent capabilities advertisement

Agents publish their capability self-description via `meta/v1 Info`:

```
MetaResp::Info {
    agent_version: Text,
    supported_alpns: Array<Text>,
    transports: Array<{
        name: Text,
        caps: TransportCapabilities,
        reachable: Array<PeerAddress>,
    }>,
    uptime_s, hostname, os, tags,
}
```

`portl status <peer>` can then show not just "direct/relay" but which
transport is actually carrying bytes, and which alternatives the agent
advertises but aren't currently in use.

## 14. Hybrid scenarios (what this unlocks)

Three examples of scenarios a single-transport design can't handle:

**Fleet attached via multiple overlays.**

```
  slicer host in homelab:
    - iroh (public)
    - tailscale (work tailnet)
    - bonjour (office LAN)
  operator at the office: bonjour wins (sub-ms)
  operator at home:        iroh wins
  operator on holiday:     iroh via relay wins
  same ticket; same caps; no reconfiguration.
```

**Demo mode with no internet.**

```
  two Apple laptops in a conference room, no router:
    loom/AWDL wins
  add a Linux colleague on the same room WiFi:
    bonjour wins (works cross-OS)
```

**SSH-bridged legacy server.**

```
  a VPS that only exposes SSH:
    portl-overlay-ssh tunnels portl streams through the SSH channel.
  operator gets `portl shell` + `portl tcp` + `portl cp` UX on a machine
  that isn't yet running portl-agent natively.
```

## 15. Schema alignment: ticket v2

The v1 ticket had `node_id` + `relays` (iroh-shaped). The v2 ticket
generalises to `peer_key` + `transports: [TransportHint]`:

```
TransportHint = one of:

  IrohHint      { node_id: [u8;32], relays: [RelayUrl] }
  BonjourHint   { service: Text, name: Text }
  TailscaleHint { ip: Ipv4Addr, base_port: u16,
                  coordinator: Text, hostname: Text }
  LoomHint      { service: Text, bonjour_name: Text }
  SshHint       { host: Text, port: u16, user: Text,
                  host_fingerprint: [u8;32] }
  LoopbackHint  { name: Text }            // tests
  WebRtcHint    { signaling_url: Text }   // future
```

See `03-tickets.md §2` for the full v2 schema.

## 16. What we commit to in v1 — crate-by-crate status

**Tier 1 — fully implemented before v0.1 release.**

| Crate | Impl status | Milestone | Notes |
| --- | --- | --- | --- |
| `portl-overlay` (trait crate) | full | M0 | trait + capability types + matcher |
| `portl-overlay-loopback` | full | M0 | tokio-channel pair; used by every integration test; canonical minimal impl |
| `portl-overlay-iroh` | full | M2 | reference backend; default feature of agent + CLI |

**Tier 2 — in-repo stub at M0, promoted to full impl during the v0.1 cycle.**

| Crate | Impl status | Milestone | Notes |
| --- | --- | --- | --- |
| `portl-overlay-bonjour` | stub (returns `Unimplemented`) at M0; full at M7 | M0 → M7 | pure Rust mDNS + LAN QUIC; validates that the trait handles a second non-iroh backend before the v0.1 API freezes |

**Tier 3 — README placeholder only in initial workspace (no crate).**

Each of these gets a `extras/<name>/README.md` that explains the
intended design, constraints, and prerequisites. No `Cargo.toml`, no
`lib.rs`, no empty stubs — nothing that pretends to compile today. A
future PR promotes the placeholder into a real crate.

| Placeholder | Why not now |
| --- | --- |
| `portl-overlay-tailscale` | upstream `tailscale-rs` is still labelled unstable/insecure, DERP-only, no direct connections; revisit when 1.0 lands |
| `portl-overlay-loom` | requires Swift FFI, codesigning, entitlements, and is Apple-only; primary Mac→Linux-VM portl use case can't benefit from AWDL anyway (see 15-loom-analysis.md) |
| `portl-overlay-ssh` | valuable for retrofit scenarios but not on the v0.1 critical path; contributors welcome |
| `portl-overlay-webrtc` | for browser clients; no signal yet that anyone wants this |

**Why this split.**

Shipping `iroh` + `loopback` is enough to prove the system end-to-end.
Shipping `bonjour` alongside before v0.1 is what proves the **abstraction
itself works** — otherwise we only know iroh fits its own interface. Any
backend beyond that is feature work that can happen post-v0.1 without
reshaping the trait.

Not shipping stubs for Tier 3 avoids two hazards:
- users `cargo add portl-overlay-loom` and file bug reports when nothing
  works,
- the workspace grows crates that drift, accumulate technical debt, and
  still don't do anything.

When a Tier 3 backend actually gets built, it lands as a full crate with
a real implementation in one PR.

## 17. Open questions (transport-specific)

- Precise header format for synthesised ALPN in non-native-mux
  transports (2-byte length + UTF-8 label vs CBOR preamble vs fixed-port
  mapping).
- Which datagrams strategy for transports with no native datagrams: (a)
  refuse `udp/v1` at the matcher, (b) emulate via reliable messages,
  (c) side-channel UDP socket alongside the main transport.
- How eagerly to cancel "losing" parallel dials — cancel on winner, keep
  for 5s as warm standby, or always drop.

These live in `13-open-questions.md`.
