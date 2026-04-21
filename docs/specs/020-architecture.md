# 02 — Architecture
+
+> **Historical architecture note.** This document preserves the
+> original v0.1 architecture vocabulary and diagrams. The shipped
+> v0.2.0 user-facing surface differs in three important ways:
+> `portl-agent` replaces `portl agent run`, `portl-gateway`
+> replaces gateway mode on the main CLI, and `agent.toml` is
+> replaced by env-only configuration. See
+> [`140-v0.2-operability.md`](140-v0.2-operability.md) for the live
+> surface.

## 1. Component inventory

```
┌──────────────────────── client host ────────────────────────┐
│                                                             │
│   portl-cli (binary)  ──┐                                   │
│                         │  links                             │
│   portl-core (crate) ───┤  sessions, tickets, discovery,     │
│                         │  iroh::Endpoint wrapper, audit     │
│   portl-proto (crate) ──┘  ticket/meta/shell/tcp/udp + vpn   │
│                                                              │
│   ~/.config/portl/                                           │
│     identity.key         operator signing key                │
│     tickets/*.ticket     one per known peer                  │
│     state/peers.sqlite   address book + path history         │
│                                                              │
└──────────────────────────────────────────────────────────────┘
                     ▲
                     │ QUIC streams + datagrams, one persistent
                     │ connection per peer, ALPN multiplex
                     │
                     ▼
┌──────────────────────── target host ────────────────────────┐
│                                                              │
│   portl agent run       ─┐ (the same `portl` binary,         │
│                          │  invoked as `portl agent run`     │
│                          │  or via the `portl-agent` symlink)│
│                          │                                   │
│   portl-core             │  links same core + protocols      │
│   portl-proto            │                                   │
│                                                              │
│   /var/lib/portl/secret   agent ed25519 private key          │
│   /etc/portl/agent.toml   policy + trust roots               │
│   journald / audit log    per-session records                │
│   /run/portl/metrics.sock prometheus text-format scrape      │
│                                                              │
│   optional: TUN iface "portl0"   (portl/vpn/v1 enabled)      │
│                                                              │
└──────────────────────────────────────────────────────────────┘
                     ▲
                     │ when hole-punch fails
                     ▼
┌─────────── self-hosted or public relay infra ──────────────┐
│   portl-relay (thin wrapper over iroh-relay / DERP)         │
│   pkarr publisher (optional — DHT discovery)                │
└──────────────────────────────────────────────────────────────┘
```

## 2. Actor / trust model

Three kinds of keypair exist; never mixed.

```
┌──────────────┐        mints             ┌──────────────┐
│  operator    │  ─── signs tickets ───▶  │    ticket    │
│  key (Ka)    │                          │  (bytes)     │
└──────────────┘                          └──────┬───────┘
                                                 │ paste / send
                                                 ▼
                                          ┌──────────────┐
                                          │   another    │
                                          │   operator   │
                                          └──────┬───────┘
                                                 │ presents
                                                 ▼
┌──────────────┐      accepts if         ┌──────────────┐
│   target     │ ◀── chain → trust.root  │   agent      │
│   key (Kv)   │         valid &         │  (runs in    │
└──────────────┘         caps fit policy │   target)    │
                                         └──────┬───────┘
                                                │
                                         opens ALPNs
                                         per caps
```

| Key | Held by | Written once to | Purpose |
| --- | --- | --- | --- |
| Operator identity (Ka) | the human | `~/.config/portl/identity.key` | signs issued/delegated tickets |
| Target identity (Kv) | the target's agent | `/var/lib/portl/secret` | the node-id a ticket points at |
| Relay identity (Kr) | the relay operator | wherever the relay stores it | stable relay address to pin |

## 3. Connection lifecycle

```
client                        relay?                       agent
  │                              │                            │
  │──── iroh::connect(node_id) ──┼──► (hole-punch attempt) ──►│
  │                              │◄── (direct path found) ────│
  │◄─── 0-RTT/1-RTT QUIC up ─────┴────────────────────────────┤
  │                                                           │
  │   open stream ALPN=portl/ticket/v1                              │
  │──────────────────────────────────────────────────────────►│
  │   send CBOR TicketOffer { ticket_bytes }                  │
  │                                                           │
  │                                          verify sig chain │
  │                                          check TTL, revoke│
  │                                          intersect caps   │
  │                                                           │
  │◄── CBOR TicketAck { ok, peer_token, effective_caps } ─────│
  │                                                           │
  │   open stream ALPN=portl/shell/v1  (carrying peer_token)        │
  │──────────────────────────────────────────────────────────►│
  │   ShellReq { pty, argv, env }                             │
  │◄── ShellAck { ok }                                        │
  │   ════════════════ duplex bytes ═══════════════════       │
  │                                                           │
  │   open stream ALPN=portl/tcp/v1                                 │
  │──────────────────────────────────────────────────────────►│
  │   TcpReq { host:"127.0.0.1", port: 22 }                   │
  │◄── TcpAck { ok }                                          │
  │   ════════════════ duplex bytes ═══════════════════       │
  │                                                           │
  │   …additional streams & datagrams multiplexed…            │
```

Key decision: **one iroh `Connection` per (operator, peer) pair; all
protocols multiplex over it.** New streams are cheap; new connections incur
a handshake + discovery and should be avoided per-operation.

## 4. Capability evaluation pipeline (agent side)

Order is deliberate: cheap checks first, expensive crypto last. This
blunts CPU-exhaustion attacks that would otherwise spam ed25519
verifies.

```
   incoming QUIC handshake attempt
            │
            ▼
     ┌──────────────┐
     │ per-src-IP    │── exceeded ──▶ reject pre-accept (429)
     │ rate gate     │
     └──────┬───────┘
            ▼
     ┌──────────────┐
     │ QUIC retry   │── bad token ──▶ address validation
     │ (quinn)      │
     └──────┬───────┘
            ▼
     incoming ticket bytes
            │
            ▼
     ┌─────────────┐
     │ decode CBOR │─── malformed ──▶ reject (ProtoError)
     └──────┬──────┘
            ▼
     ┌──────────────┐
     │ per-node-id   │── exceeded ──▶ reject (RateLimited)
     │ offer rate    │
     └──────┬───────┘
            ▼
     ┌──────────────┐
     │ walk chain   │── bad link ───▶ reject (BadChain)
     │ + verify sig │── bad sig  ───▶ reject (BadSignature)
     │ at each hop  │
     └──────┬───────┘
            ▼
     ┌─────────────┐
     │ TTL window  │─── expired ─────▶ reject (Expired)
     │ ± skew      │── premature ────▶ reject (NotYetValid)
     └──────┬──────┘
            ▼
     ┌─────────────┐
     │ revocation  │─── revoked ─────▶ reject (Revoked)
     │ set lookup  │
     └──────┬──────┘
            ▼
     ┌─────────────┐
     │ issuer in   │─── unknown ─────▶ reject (BadChain)
     │ trust.roots │    root
     └──────┬──────┘
            ▼
     ┌──────────────────┐
     │ proof-of-possess.│── bad ──▶ reject (ProofInvalid)
     │ iff ticket.to    │── absent ▶ reject (ProofMissing)
     │ verify sig       │
     └──────┬───────────┘
            ▼
     ┌──────────────────┐
     │ intersect caps   │─── empty ───▶ reject (CapDenied)
     │ with local policy│
     └──────┬───────────┘
            ▼
     effective caps (Set<Alpn × PortRule × …>)
            │
            ▼
     attach to connection,
     cache under peer_token
            │
            ▼
     route further streams
     through these caps
```

Every reject emits an audit record with a typed `AckReason` (see
`040-protocols.md §1`). Rate-limit metrics are enumerated in
`070-security.md §4.10`; per-source-per-reason counters prevent the
agent from becoming a free oracle about `trust.roots`.

## 5. Stream multiplex / per-protocol dispatch

```
                            ┌──── ALPN = portl/ticket/v1 ───── TicketService
                            │
                            ├──── ALPN = portl/meta/v1 ─────── MetaService
                            │                           (ping, info,
                            │                            revocation push)
                            │
   QUIC Connection  ────────┼──── ALPN = portl/shell/v1 ────── ShellService
   (one per peer)           │                           (1 stream/session,
                            │                            with PTY)
                            │
                            ├──── ALPN = portl/tcp/v1 ──────── TcpService
                            │                           (1 stream per
                            │                            forwarded conn)
                            │
                            ├──── ALPN = portl/udp/v1 ──────── UdpService
                            │                           (1 control stream +
                            │                            N QUIC datagrams)
                            │
                            ├──── ALPN = portl/fs/v1 ────────  FsService
                            │
                            └──── ALPN = portl/vpn/v1 ──────── VpnService
                                                        (1 control stream +
                                                         raw IP datagrams)
```

## 6. Agent state machine

```
         (process start)
                │
                ▼
       ┌─────────────────┐
       │   LOADING        │  read identity.key, config, policy
       └────┬────┬────────┘
            │    │
   key ok?  │    │   missing / unreadable key
     yes    │    │
            ▼    ▼
       ┌─────┐   ┌──────────────┐
       │BIND │   │ ENROLL_WAIT  │  awaits bootstrap ticket
       └──┬──┘   │              │    (provisioned via adapter)
          │      └──────┬───────┘
          │             │ enroll --bootstrap-ticket <uri>
          │             ▼
          │      ┌──────────────┐
          │      │ PROVISIONED  │  write key, restart
          │      └──────┬───────┘
          │             │
          │◄────────────┘
          ▼
       ┌──────────┐
       │  READY   │  accepting connections
       └─────┬────┘
             │ SIGTERM / shutdown
             ▼
       ┌──────────┐
       │ DRAINING │  finish in-flight sessions
       └─────┬────┘
             │
             ▼
       ┌──────────┐
       │ STOPPED  │
       └──────────┘
```

## 7. Connection establishment: direct vs relayed

```
                   client                                agent
                     │                                     │
                     │  holepunch frame │
    ┌──────────┐     │  via discovery   │  ┌──────────┐    │
    │ CGNAT?   │─────┤                   ├──│ CGNAT?   │────┤
    └────┬─────┘     │                   │  └────┬─────┘    │
         │ no        │                   │       │ no       │
         ▼           ▼                   ▼       ▼          ▼
     ┌───────────────────────────────────────────────────┐
     │      iroh endpoint with multiple path attempts     │
     │                                                    │
     │   ┌──────────────┐   ┌──────────────────────────┐  │
     │   │  direct UDP  │   │  relay-forwarded QUIC    │  │
     │   │   5-tuple    │   │  (portl-relay / DERP)    │  │
     │   └──────┬───────┘   └───────────┬──────────────┘  │
     │          │                       │                 │
     │          ▼                       ▼                 │
     │   selected path chosen by latency + stability      │
     │   (path may upgrade direct→relay or vice versa)    │
     └──────────────────────┬─────────────────────────────┘
                            │
                            ▼
                     QUIC Connection live
```

`portl status <peer>` shows the current path, RTT, and transitions.

## 8. Data-plane topology for different use cases

### 8.1 TCP forward (`portl tcp peer -L 3000:127.0.0.1:3000`)

```
  app on client ──▶ 127.0.0.1:3000 (local listener)
                    │
                    │ accept()
                    ▼
               portl-cli ── open QUIC stream (portl/tcp/v1) ──▶ agent
                                                           │
                                                           │ connect()
                                                           ▼
                                                    127.0.0.1:3000 (remote)
                                                           │
                                                           ▼
                                                   dev server on target
```

### 8.2 UDP forward (`portl udp peer -L 60000:60000`)

```
  app on client ──▶ UDP 127.0.0.1:60000 (local bind)
                    │
                    │ recv sendto()
                    ▼
               portl-cli ── wrap as datagram(session,src_tag,payload) ──▶ agent
                                                                          │
                                                                          │ sendto()
                                                                          ▼
                                                                  UDP 127.0.0.1:60000
                                                                          │
                                                                          ▼
                                                                  mosh-server / coturn / etc
```

### 8.3 VPN mode (`portl vpn up peer1 peer2`)

```
  client machine                                           target VM (peer1)

 +--------------------+                                   +--------------------+
 |  app:              |                                   |  listener:         |
 |   mosh, curl,      |                                   |   sshd, http, ...  |
 |   ping, anything   |                                   |                    |
 +---------+----------+                                   +---------+----------+
           │ IP packet to fd7a:…:peer1::1                           │
           ▼                                                        ▼
 +--------------------+                                   +--------------------+
 | kernel route:      |                                   | kernel route:      |
 |  fd7a::/32 → tun   |                                   |  fd7a::/32 → tun   |
 +---------+----------+                                   +---------+----------+
           │                                                        │
           ▼                                                        │
 +--------------------+  QUIC datagrams (portl/vpn/v1)     +────────┴───────────+
 | portl vpn driver   │◄──────────────────────────────────►│ portl-agent vpn    │
 +--------------------+                                   +--------------------+
```

## 9. Memory / threading model

- One `tokio::runtime::Runtime` per process.
- One `iroh::Endpoint` per process, bound to one identity key.
- One task per incoming connection; spawns sub-tasks per stream.
- Backpressure inherited from QUIC streams; UDP datagrams have a bounded
  queue per session (drops on overflow; mosh/DNS self-pace fine).
- Zero-copy where `tokio_util::bytes` allows.

## 10. Extension surfaces

Places the architecture anticipates extension without surgery:

| Extension point | How you plug in | Example |
| --- | --- | --- |
| New protocol | new crate implementing `ProtocolService` trait; register an ALPN | `portl-proto-vnc`, `portl-proto-mqtt` |
| New orchestrator | new crate implementing `Bootstrapper` | `cloud-init-portl`, `docker-portl` |
| Discovery backend | implement `Discovery` trait | pkarr, DNS, static, mDNS |
| Policy store | implement `PolicyStore` trait | file-based, Consul, Vault |
| Audit sink | implement `AuditSink` trait | journald, file, S3, Kafka |

## 11. Discovery and data plane

portl has **one data plane**: iroh QUIC (direct UDP with hole-punching,
falling back to a self-hostable relay). There is no pluggable
`OverlayTransport` trait at v0.1; iroh is the transport, used
concretely in `portl-core` behind a thin newtype wrapper so imports
don't bleed into protocol crates.

What *is* pluggable is **discovery** — how a peer is located given its
`node_id`. Iroh itself provides a `Discovery` trait with four built-in
services; portl's job is to opt in to the ones we want:

| Discovery service | What it does | Default in portl |
| --- | --- | --- |
| DNS (iroh-dns) | Looks up `node_id` via DNS (default origin `dns.iroh.link`, self-hostable). | **enabled** |
| Pkarr | Signed packets published to a Pkarr relay; default `iroh-dns` is the same server. | **enabled** |
| Local (mDNS) | Multicast on the LAN. Resolves `node_id` → direct addrs without any server. | **enabled** |
| DHT | BitTorrent Mainline DHT. Fully decentralized, slower. | opt-in |

The important consequence: **LAN peers find each other with zero
infrastructure** — no Bonjour backend, no separate "portl-overlay"
crate, just iroh's Local discovery. Internet peers find each other via
DNS/Pkarr (and the operator can self-host their own `iroh-dns-server`
if they want to remove the n0.computer default).

```
   peer A                                             peer B
   ───────                                            ───────

   portl-agent                                        portl-agent
        │                                                  │
        │  iroh::Endpoint                                  │  iroh::Endpoint
        │    discovery:                                    │    discovery:
        │      • DNS                                       │      • DNS
        │      • Pkarr                                     │      • Pkarr
        │      • Local (mDNS)                              │      • Local (mDNS)
        │                                                  │
        │  publishes its NodeAddr:                         │
        │    - to pkarr (→ DNS)                            │
        │    - via mDNS on attached LANs                   │
        │                                                  │
        │  resolves peer B's node_id:                      │
        │    - mDNS first if same L2                       │
        │    - else DNS                                    │
        │                                                  │
        └───────── QUIC direct ────────────────────────────┘
                    (falls back through iroh-relay when
                     NAT/firewall prevents direct path)
```

### 11.1 Escape hatch for genuine alternate data planes

Some future use cases *are* genuine alternate data planes and can't be
served by "iroh + more discovery." Specifically:

- **WebRTC** for browser peers — iroh isn't browser-native yet.
- **Loom/AWDL** for Apple-proximity — Network.framework owns those
  socket types; iroh can't drive them.
- **Heavily constrained embedded** — LoRa, BLE, etc.

None are v0.1. When the first one is demanded, we design the
`OverlayTransport` trait informed by what the second data plane
actually looks like, instead of guessing. A draft of that future
abstraction lives at `future/140-transport-abstraction.md` — retained
as a design artifact, not a commitment.

### 11.2 What this means for tickets (03) and walkthroughs (10)

- Tickets carry `node_id` + `relays[]` (iroh's `NodeAddr` shape).
  No `transports[]` array, no `TransportHint` union.
- Reachability varies at runtime based on which discovery services
  succeed; tickets do not encode "try Bonjour first."
- The same ticket works on the office LAN (via mDNS) and from a café
  (via DNS + relay fallback) without re-issuing.
