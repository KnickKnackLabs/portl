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

# 15 — Loom analysis (and why we defer integration)

> Loom is a Swift package for peer-to-peer networking between Apple
> devices: https://github.com/EthanLipnik/Loom . Its headline claim is
> "Apple device-to-device features without building a networking stack
> from scratch," and in particular it works between two Apple devices
> that are physically close *even with no router present*. This doc
> dissects that claim, maps Loom's architecture against portl's, and
> explains why we bake support for a Loom-style transport into the
> design but defer shipping `portl-overlay-loom` for now.

## 1. What Loom actually is (four layers, one brand)

```
┌────────────────────────────────────────────────────────────────────┐
│ LoomKit          SwiftUI runtime: LoomContainer / LoomContext /    │
│                   @LoomQuery; mirrors SwiftData's mental model.    │
│                   App-facing; not relevant to portl.                │
├────────────────────────────────────────────────────────────────────┤
│ LoomShell        Shell-session protocol over Loom + OpenSSH        │
│                   fallback when Loom-native can't reach. Parallel  │
│                   to `portl-proto-shell`.                          │
├────────────────────────────────────────────────────────────────────┤
│ LoomCloudKit     Opt-in CloudKit-backed peer directory + trust.    │
│                   Apple-account-anchored. Not relevant to portl.   │
├────────────────────────────────────────────────────────────────────┤
│ Loom (core)      LoomNode, LoomDiscovery, LoomAuthenticatedSession, │
│                   LoomIdentityManager, LoomTrustStore,             │
│                   LoomConnectionCoordinator, LoomTransferEngine,   │
│                   LoomOverlayDirectory. THE INTERESTING LAYER.     │
└────────────────────────────────────────────────────────────────────┘
```

Everything under "Loom (core)" is Apple's own stack: **Bonjour** for
discovery, **`Network.framework`** for sockets + TLS, **TLS 1.3** for
encryption. Loom doesn't reimplement transport plumbing; it adds
identity, trust, signaling, and a coherent session abstraction on top.

## 2. The "no router needed" claim — what's actually happening

The magic knob in `LoomNetworkConfiguration`:

```swift
LoomNetworkConfiguration(serviceType: "_myapp._tcp", enablePeerToPeer: true)
```

When `enablePeerToPeer: true`, Apple's networking stack enables
**peer-to-peer discovery and transport** in three stacked layers:

```
Layer           Substrate                         Visible to app
────────────────────────────────────────────────────────────────────
Discovery       mDNS over AWDL + infrastructure   Bonjour service
                WiFi + Bluetooth LE beacons       records

Transport       AWDL (802.11 ad-hoc) primary;     NWConnection /
                infrastructure WiFi fallback;     TCP streams on
                Bluetooth LE for very small       the peer
                payloads

Security        TLS 1.3 negotiated over           TLS handshake
                whatever underlying link          works regardless
                                                  of carrier
```

**AWDL (Apple Wireless Direct Link)** is the interesting bit. It's
Apple's proprietary 802.11-based protocol — the same thing AirDrop,
Continuity, Sidecar, Universal Clipboard, and AirPlay peer-to-peer
mode all ride on. It creates a parallel wireless network on a second
virtual interface (`awdl0` on macOS) that coexists with regular WiFi.

```
┌─────────────────────── AWDL direct path ─────────────────────┐
│                                                              │
│   MacBook A                             MacBook B            │
│   ┌────────┐                            ┌────────┐           │
│   │ Loom   │                            │ Loom   │           │
│   │ app    │                            │ app    │           │
│   └────┬───┘                            └────┬───┘           │
│        ▼                                     ▼               │
│   NWConnection                         NWConnection          │
│   over TCP+TLS                         over TCP+TLS          │
│        │                                     │               │
│        ▼                                     ▼               │
│   ┌─────────┐  ──────── AWDL link ────►  ┌─────────┐         │
│   │  awdl0  │  (802.11 direct,           │  awdl0  │         │
│   │         │   2.4/5/6 GHz,             │         │         │
│   │         │   infrastructure-less,     │         │         │
│   │         │   time-slotted)            │         │         │
│   └─────────┘  ◄─────────────────────    └─────────┘         │
│                                                              │
│   no router, no internet, no DHCP, no shared SSID            │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 2.1 Real capabilities of AWDL

From Apple's own AirDrop documentation + community reverse-engineering
work (notably **OWL**, the open-source AWDL reimplementation from TU
Darmstadt):

| Property | Value |
| --- | --- |
| Range indoors | ~30 m |
| Range line-of-sight | ~100 m |
| Throughput | 100s of Mbps sustained; AirDrop hits 50–150 MB/s between modern devices |
| Latency | single-digit ms when direct |
| WiFi coexistence | time-slotted; does not kick you off your AP |
| Cross-device support | Apple-to-Apple only (Mac, iPhone, iPad, Apple TV, Vision Pro) |

### 2.2 The "only Apple devices" asterisk

AWDL is **exclusively Apple-to-Apple**:

- A Linux laptop cannot see AWDL traffic at all. Its WiFi driver doesn't
  know the protocol.
- An Android phone, same story.
- A slicer VM running on a Mac: the VM is on an internal virtualised
  network (AVF NAT `192.168.64.0/24`). AWDL binds to `awdl0` on the
  host, not to any interface visible to the VM.

There is an **open-source AWDL implementation called OWL** (Open
Wireless Link) from the Secure Mobile Networking Lab at TU Darmstadt.
It can make Linux machines join AWDL in principle, but:

- requires a specific WiFi chipset put into monitor mode,
- is a research project (not production),
- is effectively unmaintained,
- needs kernel/driver cooperation that isn't standard anywhere.

**OWL is not a realistic path for production portl.**

## 3. Loom core architecture, annotated

```
                    ┌──────────────────────────────────┐
                    │        LoomNode                   │
                    │   composition root:               │
                    │   owns discovery + sessions +     │
                    │   identity + trust                │
                    └─────┬────────────────────────┬────┘
                          │                        │
                          ▼                        ▼
                ┌─────────────────┐      ┌──────────────────┐
                │  LoomDiscovery  │      │ LoomIdentity-    │
                │  Bonjour browse │      │ Manager          │
                │  + advertise    │      │ ed25519 device   │
                │  over AWDL/WiFi │      │ key in Keychain  │
                └────────┬────────┘      └─────────┬────────┘
                         │ LoomPeer list           │ signs Hello
                         ▼                         │
                ┌─────────────────┐                │
                │ LoomConnection- │                │
                │ Coordinator     │                │
                │ parallel-dial   │                │
                │ candidates      │                │
                └────────┬────────┘                │
                         │                         │
                         ▼                         ▼
                ┌─────────────────────────────────────┐
                │  LoomSession                         │
                │  raw NWConnection + TLS              │
                └────────────────┬────────────────────┘
                                 │ mutual Hello exchange
                                 ▼
                ┌─────────────────────────────────────┐
                │  LoomAuthenticatedSession            │
                │  identity verified by LoomIdentityMgr│
                │  trust policy from LoomTrustStore    │
                │  gives multiplexed streams           │
                └────────┬────────────────────────────┘
                         ▼
                ┌─────────────────────────────────────┐
                │  LoomMultiplexedStream               │
                │  logical bidi streams over one       │
                │  authenticated session               │
                └─────────────────────────────────────┘

 Side modules:
   LoomTrustStore             persists trusted devices
   LoomTrustProvider          app-provided policy hook
   LoomOverlayDirectory       Tailscale/VPN seed list
   LoomRemoteSignalingClient  WebSocket signaling (YOU host it)
   LoomSTUNProbe              NAT type detection
   LoomBootstrapControlServer Wake-on-LAN + SSH unlock for recovery
   LoomTransferEngine         resumable bulk file transfer
```

## 4. Mapping Loom's concepts onto portl's

| portl concept | Loom equivalent | Notes |
| --- | --- | --- |
| `portl-core::transport` | `LoomNode` + `NWConnection` | |
| `portl-core::session` | `LoomAuthenticatedSession` | |
| ALPN + stream multiplex | `LoomMultiplexedStream` | labels ≈ ALPN |
| ALPN `shell/v1` | `LoomNativeShellSession` | direct parallel |
| ticket (v2) | `LoomPeerAdvertisement` + signed `LoomSessionHello` | Loom's equivalent is less capability-shaped |
| operator identity key | `LoomIdentityManager` device key | |
| `trust.roots` | `LoomTrustProvider` + `LoomTrustStore` | |
| relay fallback | *no Loom equivalent* | Loom's remote story is signaling-only |
| `portl-relay` | *none in Loom* | |
| capability-ticket model | **not present in Loom** | biggest architectural gap |
| adapter-based target provisioning | *not present* | Loom doesn't create targets |

## 5. The most important architectural difference: capabilities

**Loom trust is device-shaped. portl trust is capability-shaped.**

Loom: "this other MacBook is the one I paired with; my app may let it
do anything my app policy allows trusted devices to do."

portl: "this bearer may shell into this specific VM for the next 24
hours and nothing else."

These are complementary — not redundant. If we layered portl tickets on
top of Loom sessions, the stack would be:

```
  Loom layer   :  proves two authenticated devices are connected
                  and bytes flow securely between them
                                │
                                ▼
  portl layer  :  ticket/v1 handshake proves the bytes are
                  authorised to do a narrow, signed set of
                  operations for a bounded time
```

Loom makes no claim at all about capabilities. That layering is natural.

## 6. Loom's remote story — it's not a full mesh

Loom's "off-LAN" support is intentionally limited.

**`LoomOverlayDirectory`.** Explicit from their docs: *"we do not talk
to the Tailscale admin API, Headscale, or your inventory service for
you."* You feed it a list of hostnames/IPs you already trust; Loom
probes each for a Loom-speaking peer; found ones are treated as direct
connectivity. A thin convention over existing VPNs.

**`LoomRemoteSignalingClient`.** A WebSocket-based signaling service
**that you build and host yourself.** Their docs include a page titled
"Build a Signaling Service." The service is introducer-only: it helps
two off-LAN peers exchange candidates via STUN probes and attempt a
direct QUIC connection. **No relay, no data plane.**

**There is no Loom relay.** If hole-punch fails, you're out of luck.
Loom's recommended recovery in that case is to *wake the remote peer
up* (Wake-on-LAN, SSH bootstrap) rather than carry bytes for them.

```
                   ┌────────── Loom remote story ────────────┐
                   │                                         │
                   │   self-hosted signaling (WebSocket)     │
                   │     |                                    │
                   │     | exchange SDP-like candidates       │
                   │     ▼                                    │
                   │   peers attempt direct NWConnection      │
                   │     │                                    │
                   │     ├─ success: ok!                      │
                   │     └─ fail: sorry (no relay)            │
                   │                                         │
                   └─────────────────────────────────────────┘

              vs.

                   ┌────────── iroh remote story ────────────┐
                   │                                         │
                   │   node-id discovery via pkarr/DNS/DHT    │
                   │     │                                    │
                   │     ▼                                    │
                   │   peers attempt direct QUIC              │
                   │     │                                    │
                   │     ├─ success: ok                       │
                   │     └─ fail: DERP-style relay carries    │
                   │              ciphertext between peers    │
                   │                                         │
                   └─────────────────────────────────────────┘
```

So Loom as a transport gives us exceptional **proximity** capability
and nothing for **long-distance**; iroh is the other way around. They
are complements.

## 7. What the AWDL property buys portl, concretely

Scenarios and their outcomes with a hypothetical `portl-overlay-loom`:

| Scenario | Works? | Why |
| --- | --- | --- |
| Two Macs on the same café WiFi | ✓✓ excellent | AWDL + mDNS, sub-ms |
| Two Macs on café WiFi with client isolation | ✓ | AWDL bypasses AP |
| Two Macs in a car, no WiFi at all | ✓ | pure AWDL |
| Two Macs in a hotel w/ captive portal, not signed in | ✓ | AWDL ignores captive portal |
| Mac ↔ iPhone, same room, no WiFi | ✓ | AWDL both sides |
| Mac ↔ Apple TV for demo | ✓ | AWDL |
| Mac ↔ Linux laptop | ✗ | Linux cannot join AWDL |
| **Mac host ↔ slicer VM (primary portl use case)** | ✗ | VM has no AWDL interface |
| Two Macs on different continents | ✗ | AWDL is proximity-only |

**The Mac-host-to-slicer-VM row is the important one.** It's the
primary workflow portl serves today, and AWDL can't help. The slicer VM
lives on virtio-net inside AVF NAT; it has no `awdl0` device.

This is the single biggest reason to defer Loom: our main user cannot
actually use it.

## 8. Three integration options, honestly costed

### Option A — ignore Loom; build `portl-overlay-bonjour` instead

Pure-Rust LAN transport using mDNS discovery and quinn-over-UDP for
streams + datagrams. Works on macOS + Linux + Windows. No AWDL; loses
the "no router needed on Apple devices" property.

- Effort: medium (~2 weeks).
- Coverage: 80% of Loom's non-AWDL value, on all three OSes.
- Cost: zero Swift dependency.
- Already planned: yes, M7 in the roadmap.

### Option B — ship `portl-overlay-loom` via Swift FFI

Rust crate wrapping Loom with `swift-rs` or `swift-bridge`. Ships
alongside a Swift `libportl_loom_bridge.dylib` that links Loom and
exposes a small C ABI.

- Effort: high (~4–6 weeks). Most of it is non-code:
  - Swift toolchain in CI (xcodebuild, codesign).
  - Info.plist entitlements (`NSBonjourServices`,
    `NSLocalNetworkUsageDescription`, multicast entitlement for App
    Store distribution).
  - Bundling + code-signing the dylib alongside the Rust binary.
  - Apple Developer account for the multicast entitlement.
  - Ongoing maintenance against Loom's API evolution.
- Coverage: only where Loom helps (Apple ↔ Apple proximity).
- Cost: permanent dependency on a Swift package + a one-maintainer
  upstream.

### Option C — roll our own AWDL in Rust using OWL

Bind to a monitor-mode WiFi interface, implement AWDL frames, handle
channel sequencing ourselves.

- Effort: astronomical.
- Coverage: limited WiFi chipsets, root, unstable.
- Cost: not serious engineering.

**Don't do C.** The real choice is A vs A+B.

## 9. Decision: defer Loom, ship Bonjour

Based on the above:

1. Most portl users are Mac host → Linux VM; AWDL cannot reach the VM.
2. `portl-overlay-bonjour` (pure Rust) covers the LAN use case cross-OS
   at a fraction of the cost.
3. If Loom-quality AWDL becomes critical later, the transport trait
   absorbs it cleanly — no retrofit needed.

Therefore:

- **In the v0.1 workspace**: `extras/portl-overlay-loom/README.md`
  placeholder only. No Rust crate. Explicitly documents why.
- **Roadmap**: Loom integration is post-v0.1 at earliest, and probably
  won't happen unless an Apple-focused contributor drives it. The core
  portl team maintains Bonjour + iroh; a Loom backend is community work.
- **Docs**: this file records the evaluation so the decision is
  legible.

## 10. Design patterns we steal from Loom anyway

Several Loom design choices map cleanly onto portl regardless of
whether we integrate their transport. Worth adopting deliberately:

### 10.1 `LoomPeerAdvertisement`-style Bonjour TXT records

When we ship `portl-overlay-bonjour`, the advertisement format should
carry the peer_key pubkey + supported ALPNs + basic capability flags in
TXT records. Loom's shape is a good template; we reuse the field names
verbatim where sensible.

### 10.2 `LoomConnectionCoordinator` parallel-dial semantics

"Collect candidates from discovery + signaling + overlay directory;
parallel-dial with stagger; first-handshake wins; report a
`ConnectionFailure` if all lose." Already in our design (see 14 §6);
borrow the exact vocabulary: `ConnectionPlan`, `ConnectionTarget`,
`ConnectionFailure`.

### 10.3 `LoomOverlayDirectory` convention for existing VPNs

"If you already run Tailscale/WireGuard/custom, portl can treat
reachable hosts on it as direct connectivity." That's what our
TailscaleHint transport does, philosophically — just using an existing
mesh as a dumb layer-3 substrate. Loom's seed-file convention is a
cleaner user affordance than requiring it in the ticket.

### 10.4 Three-way `LoomHandshakeTrustStatus`

Loom's handshake surfaces trust state explicitly as
`trusted | unknown | blocked`, so clients can render UI. Our current
`TicketAck.ok: bool` loses information. Upgrade:

```
TicketAck {
    result:   TicketResult,   // Accepted | NeedsApproval | Denied(reason)
    ...
}
enum TicketResult {
    Accepted,
    NeedsApproval { approval_id: Bytes(16) },   // future: interactive trust
    Denied { reason: Text },
}
```

Cheap upgrade. Enables future "approve this new connection on my phone"
flows without reshaping the handshake.

### 10.5 `LoomBootstrapControlServer` for recovery

Their "Wake-on-LAN + SSH unlock + control channel for emergency
recovery" pattern is great for out-of-band management. portl doesn't
have an equivalent and probably should, especially for the slicer
restart / VM recovery use case. Candidate for post-v0.1.

### 10.6 SSH as a fallback transport (`LoomShellConnector`)

Loom's shell connector prefers Loom-native and falls back to OpenSSH
when both sides have credentials. We defined an optional
`portl-overlay-ssh` (Tier 3 placeholder) inspired directly by this
pattern. Lets portl piggyback on existing SSH infrastructure without
requiring a portl-agent to be reachable any other way.

## 11. Reading list

If someone picks up the Loom backend as community work, these are the
references they'll need:

- Loom repo: https://github.com/EthanLipnik/Loom
- Loom DocC: https://ethanlipnik.github.io/Loom/documentation/loom/
- LoomShell DocC: https://ethanlipnik.github.io/Loom/documentation/loomshell/
- Apple Network.framework: https://developer.apple.com/documentation/network
- Apple Bonjour / `NSBonjourServices`: https://developer.apple.com/documentation/bundleresources/information_property_list/bonjour
- AWDL academic analysis (Stute et al., USENIX): https://owlink.org/
- Swift FFI crates:
  - `swift-bridge` https://github.com/chinedufn/swift-bridge
  - `swift-rs`     https://github.com/Brendonovich/swift-rs
- MultipeerConnectivity (what Loom is an alternative to):
  https://developer.apple.com/documentation/multipeerconnectivity

## 12. Decision record

**Decision.** Defer `portl-overlay-loom` as a placeholder-only
community deliverable. Ship `portl-overlay-bonjour` for LAN coverage
instead.

**Rationale.** (1) Primary portl use case is Mac host → Linux VM,
which AWDL cannot reach. (2) Pure-Rust Bonjour gets 80% of Loom's
non-AWDL value for 20% of the cost, works cross-OS. (3) The transport
trait admits a future Loom backend cleanly if demand materialises.

**Reconsider when.** A contributor with Apple-ecosystem expertise
volunteers to maintain the Swift sidecar, OR a concrete use case
emerges where Mac ↔ Mac AWDL is load-bearing (e.g. a portl-based
AirDrop replacement, offline collaboration demo, conference
deployment).

**Non-overlap.** This decision is independent of whether we ship
`portl-overlay-tailscale`. They target different scenarios: tailscale
for operator-owned mesh, loom for proximity-Apple. Both could
coexist; neither is a prerequisite of the other.
