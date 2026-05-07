# Session-scoped `.portl` hostnames and network mode

Date: 2026-05-07
Status: revised design draft after roundtable review

## Summary

Portl should make an attached session feel like a temporary machine on the
local network. When a user attaches to a session, Portl publishes a local
hostname for that attachment:

```text
<session>.<machine>.portl
```

For example:

```bash
portl attach session-a --target max-ab11

ping session-a.max-ab11.portl
curl http://session-a.max-ab11.portl:8055/foo
curl https://session-a.max-ab11.portl:8055/foo
ssh session-a.max-ab11.portl
```

The hostname is active only while Portl has an active attachment record for
that session. A saved ticket or paired peer grants permission material, but it
does not by itself publish a routable network surface.

The first implementation should be an explicit opt-in network install:

```bash
portl network doctor
portl install --network --dry-run
portl install --network --apply --yes
```

Once the model is proven, normal `portl install --apply` can try network mode
by default when installing `portl-agent`, and fall back based on preflight
results.

This design supersedes the older v0.1-era `portl/vpn/v1` stretch goal as the
primary path for machine-like hostnames. `vpn/v1` remains a possible future
raw-IP peer VPN, but it should not be the first implementation path for
session-scoped `.portl` hostnames.

## Goals

1. **Make attached sessions reachable by normal tools.** `ping`, `curl`,
   browsers, SSH, databases, mosh, and other TCP/UDP tools should work against
   `<session>.<machine>.portl` when network mode is installed.
2. **Tie reachability to active user intent.** Only currently attached sessions
   publish `.portl` hostnames by default.
3. **Reuse existing Portl data planes.** Transparent TCP and UDP should reuse
   `portl/tcp/v1` and `portl/udp/v1` rather than inventing a separate VPN data
   plane.
4. **Support literal ping.** `/sbin/ping session-a.max-ab11.portl` should work
   in full network mode, using a Portl overlay health response rather than
   requiring remote-kernel ICMP.
5. **Keep HTTPS understandable.** Portl may provide a local HTTPS front door for
   HTTP(S) development workflows, but should not universally terminate TLS.
6. **Preserve Portl's trust model.** Iroh endpoint identity and Portl tickets
   decide remote access. Local CA trust only helps local browser/curl clients
   trust Portl-managed HTTPS front doors.
7. **Provide a useful locked-down fallback.** If system network integration is
   unavailable, users can still create explicit localhost forwards.

## Non-goals

- Building a full raw-IP VPN in the first version, including the older
  `portl/vpn/v1` TUN-on-both-ends stretch goal.
- Publishing hostnames for every saved peer or ticket without an active
  attachment.
- Making Portl a universal TLS MITM/proxy.
- Replacing existing explicit `portl tcp` and `portl udp` commands.
- Requiring the local Portl CA for secure Portl transport. Iroh already secures
  the Portl-to-Portl leg.
- Guaranteeing that ping responses come from the remote operating system's ICMP
  stack.

## User mental model

The product model should be simple:

```text
Saved ticket
  = permission material, not active network exposure

portl attach
  = active user intent

Published hostname
  = routable .portl name for the active attachment
```

Internal code can call this an attachment lease, but normal UX should use
"published hostname" and "network mode".

```text
portl attach session-a --target max-ab11
        |
        v
creates/joins persistent session
        |
        v
publishes local hostname:
  session-a.max-ab11.portl
        |
        v
normal tools can use it while attached
```

When the foreground attach exits, the published hostname expires or is removed.
A future background mode can keep the same lease alive without a terminal UI:

```bash
portl attach session-a --target max-ab11 --background
```

## Architecture

Full network mode adds local OS integration in front of Portl's existing iroh
protocols:

```text
┌──────────────────────────────────────────────────────────────┐
│ user apps                                                     │
│                                                              │
│  ping   curl   browser   ssh   postgres   mosh                │
└────┬──────┬───────┬──────┬────────┬──────┬──────────────────┘
     │      │       │      │        │      │
     v      v       v      v        v      v
┌──────────────────────────────────────────────────────────────┐
│ OS resolver + kernel network stack                           │
│                                                              │
│  .portl DNS -> virtual overlay IP                            │
│  route virtual overlay CIDR -> Portl network helper/TUN       │
└────────────────────────────┬─────────────────────────────────┘
                             │
                             v
┌──────────────────────────────────────────────────────────────┐
│ local portl-agent / Portl network helper                     │
│                                                              │
│  Published hostname table                                    │
│    session-a.max-ab11.portl ->                               │
│      target=max-ab11                                         │
│      session=session-a                                       │
│      virtual_ip=198.18.x.y                                   │
│      effective caps                                          │
│                                                              │
│  Demux                                                       │
│    DNS  -> answers active .portl leases                      │
│    ICMP -> synthetic overlay ping/probe                      │
│    TCP  -> portl/tcp/v1                                      │
│    UDP  -> portl/udp/v1                                      │
│    HTTPS-looking TCP -> optional HTTPS front door             │
└────────────────────────────┬─────────────────────────────────┘
                             │
                             v
┌──────────────────────────────────────────────────────────────┐
│ iroh connection to target                                    │
│                                                              │
│  existing ticket/session auth                                │
│  existing stream/datagram transport                          │
└────────────────────────────┬─────────────────────────────────┘
                             │
                             v
┌──────────────────────────────────────────────────────────────┐
│ remote portl-agent / target                                  │
│                                                              │
│  portl/tcp/v1 -> connect 127.0.0.1:<port>                    │
│  portl/udp/v1 -> send UDP to 127.0.0.1:<port>                │
│  session provider keeps terminal workspace alive              │
└──────────────────────────────────────────────────────────────┘
```

This is not a full VPN. It is an attachment-scoped hostname overlay that maps
active `.portl` hostnames to Portl's existing TCP/UDP forwarding primitives.

## Relationship to `portl/vpn/v1`

The historical `portl/vpn/v1` design in `docs/specs/040-protocols.md` forwards
raw IPv6 packets between TUN devices on both sides:

```text
local TUN -> raw IPv6 packet over iroh datagram -> remote TUN -> remote kernel
```

That model is cleaner for a peer-level VPN, but it requires TUN privileges on
the remote target as well as the local client, uses coarse `VpnCaps`, and is
peer-scoped rather than active-session-scoped. It is not the right first path
for this feature.

Session hostname network mode supersedes `vpn/v1` for the initial
machine-like hostname UX:

```text
local TUN/helper -> userspace TCP/UDP bridge -> portl/tcp/v1 or portl/udp/v1
                 -> remote agent connects/sends to 127.0.0.1:<port>
```

Keep `VpnCaps` and the historical `vpn/v1` notes for future raw-IP overlay
work, but do not implement `vpn/v1` first. If `vpn/v1` is revived later, it
should share TUN installation, route conflict detection, MTU guidance, and
diagnostics with this network-mode subsystem rather than creating a second
parallel networking stack.

## Hostname grammar

Published hostnames use exactly two user-visible labels under `.portl`:

```text
<session>.<machine>.portl
```

Both labels must be DNS-safe:

- lowercase ASCII only,
- characters `[a-z0-9-]`,
- 1-63 octets per label,
- no leading or trailing hyphen,
- no embedded dots,
- full hostname length no more than 253 octets.

Portl should preserve the user's display names separately from DNS labels. When
a session or machine name is not DNS-safe, publishing should fail with a clear
message and a suggested safe label. Silent lossy normalization is risky because
two logical names can collapse to the same DNS label.

The `.portl` TLD is a local convention, not an ICANN-reserved private TLD.
`portl network doctor` must verify that `.portl` queries are captured locally
and do not leak to upstream resolvers. A future compatibility option may use a
reserved private-use suffix such as `.internal`, but this spec keeps `.portl`
for the primary UX.

## Process and privilege model

Full network mode has three local components:

```text
portl CLI / foreground attach
  - user process
  - starts or joins the session UI
  - asks the per-user agent to publish/unpublish hostnames

per-user portl-agent
  - owns tickets, iroh endpoints, active attachment records, effective caps,
    cert keys, DNS answers, and TCP/UDP bridge policy
  - stores the published hostname table in memory, with any durable state under
    $PORTL_HOME/data/ using 0600 files
  - exposes management IPC only on a 0600 socket under $PORTL_HOME/run/

privileged network helper
  - installed by `portl install --network`
  - owns OS integration: TUN/utun creation, route installation, scoped DNS hook
    installation, packet filter rules when needed, and optional trust-store
    mutation for the local CA
  - does not hold Portl tickets, iroh identities, peer tokens, or CA private keys
```

The privileged helper is intentionally narrow. It should create the virtual
network interface and deliver packets to the owning per-user `portl-agent`, or
pass a TUN file descriptor to that agent when the platform supports it. It must
not accept arbitrary published-hostname records from untrusted local processes.

The per-user agent owns the published hostname table. Only an authenticated
local attach operation may add, update, or remove records. IPC sockets must be
owned by the Portl user and mode `0600`. Where the helper needs a management
request, it should accept requests only from the owning UID and from the
per-user agent's authenticated control channel.

### Multi-user isolation

The MVP targets single-user developer machines. On shared multi-user hosts,
system DNS and routes can expose one user's active `.portl` hostname to other
local users unless the platform can enforce per-UID routing or filtering.

Preflight should therefore classify multi-user hosts conservatively:

- If per-UID DNS/routing enforcement is available and tested, full network mode
  can be installed for that UID.
- If not, full network mode should refuse by default and offer userspace
  fallback.
- A future override may allow machine-wide exposure, but it must be explicit and
  should say that all local users/processes may reach the published hostnames
  while they are active.

The local `.portl` resolver must bind only to loopback. It must not answer LAN
queries.

## TUN bridge and userspace stack

The TUN interface receives IP packets, not accepted TCP sockets. Reusing
`portl/tcp/v1` and `portl/udp/v1` therefore requires a new local bridge:

```text
IP packets from TUN
  -> local userspace TCP/UDP stack or platform redirect layer
  -> byte/datagram flows
  -> portl/tcp/v1 streams or portl/udp/v1 sessions
```

This is new code above the existing forwarding protocols. The bridge owns TCP
state, retransmits, FIN/RST handling, UDP flow mapping, MTU/MSS behavior,
timeouts, and error translation.

Candidate bridge implementations:

| Candidate | Fit | Tradeoffs |
| --- | --- | --- |
| `smoltcp` | Pure Rust, embeddable, no CGO/Go runtime, good for a controlled local proxy bridge. | Less battle-tested for desktop transparent proxy workloads; requires validation for retransmits, fragmentation, throughput, and many short connections. |
| gVisor netstack | Production-proven userspace TCP/IP stack used by tun2socks-style tools; strong TCP/UDP semantics. | Go integration or sidecar boundary; direct `tun2socks` projects may have incompatible licenses, so Portl should use gVisor netstack directly only after license review. |
| lwIP | Mature C userspace TCP/IP stack. | C FFI and memory-safety burden; less aligned with Portl's Rust dependency posture. |
| Platform redirects (`TPROXY`, `pf`, packet filter rules) | Can avoid owning a full TCP stack. | Linux/macOS implementations diverge heavily; more privileged state and harder install/uninstall rollback. |

Recommendation: prototype a Rust-first bridge with `smoltcp` while keeping an
explicit fallback path to a gVisor-netstack helper if smoltcp fails throughput
or compatibility tests. Do not start transparent TCP/UDP implementation until
this bridge choice has a small benchmark and conformance spike.

UDP bridge semantics:

- map `(src_ip, src_port, dst_virtual_ip, dst_port)` to a Portl UDP flow,
- create `portl/udp/v1` sessions dynamically on first datagram,
- idle-timeout inactive flows,
- preserve existing UDP linger/reattach behavior where it applies,
- reject or drop unsupported broadcast/multicast for MVP,
- document datagram size and fragmentation behavior.

TCP bridge semantics:

- complete local TCP handshakes in the userspace stack,
- open one `portl/tcp/v1` stream per accepted virtual TCP connection,
- replay any bytes read for protocol classification before forwarding,
- translate remote connect failures into local resets or connection refusals,
- clamp MSS/MTU to avoid black holes.

## Iroh connection ownership

The per-user `portl-agent` should own iroh connections for active published
hostnames. A foreground attach can use the same agent-owned connection for the
terminal session, or it can register an attachment and delegate network flows to
the agent. The important invariant is that the network helper never owns tickets
or opens authenticated iroh sessions by itself.

For each active target, the per-user agent may keep one authenticated iroh
connection and open multiple `tcp/v1`, `udp/v1`, `meta/v1`, and session streams
under the effective caps for each published hostname record. If two active
published hostnames point to the same target with different caps, cap checks
remain per virtual IP / hostname record before opening each stream.

## Platform DNS and routing hooks

Network preflight must be platform-specific rather than a generic yes/no check.

macOS:

- install `/etc/resolver/portl` pointing only `.portl` at the local Portl DNS
  listener,
- prefer a high loopback port if resolver support is available,
- create `utun` and routes through the privileged helper,
- use a root LaunchDaemon for network setup; Network Extension entitlement work
  is out of scope for the MVP.

Linux with systemd-resolved:

- create the TUN or dummy interface before configuring split DNS,
- use `resolvectl dns <iface> 127.0.0.1#<port>` and
  `resolvectl domain <iface> ~portl`, or equivalent DBus calls,
- treat DNS and TUN as a joint install unit because resolved scopes split DNS
  to an interface.

Linux with NetworkManager:

- use NetworkManager DNS integration when available,
- avoid rewriting global `/etc/resolv.conf` as the primary strategy.

Other Linux/resolv.conf-only environments:

- do not claim full network mode unless a safe split-DNS hook exists,
- fall back to userspace forwards.

WSL2 and Windows are out of scope for the first network-mode implementation.

DNS answers should use low TTLs, but the network helper must not rely on DNS
TTL for security. It must reject packets for inactive or stale records even if
an application cached an old A record. Virtual IPs should not be immediately
reused after detach; keep a short quarantine window to avoid stale-cache
misdelivery.

## Data flows

### Attach and publish

```text
User
 |
 | portl attach session-a --target max-ab11
 v
portl CLI
 |
 | normal session attach handshake
 v
remote target max-ab11
 |
 | session provider: zmx/tmux/etc.
 v
session live
 |
 | local registration
 v
Published hostname record {
  hostname: session-a.max-ab11.portl
  target: max-ab11
  session: session-a
  virtual_ip: 198.18.42.10
  mode: foreground
  effective_caps: tcp/udp/http-front-door as allowed
}
```

The foreground attach process or local agent heartbeat keeps this record alive.

### DNS lookup

```text
curl http://session-a.max-ab11.portl:8055/foo
        |
        v
OS resolver asks local .portl resolver
        |
        v
Portl resolver checks published hostname table
        |
        +-- record exists -> A 198.18.42.10, optionally AAAA later
        |
        +-- no record -> NXDOMAIN or no answer
```

Only active attachments resolve.

### TCP forwarding

```text
curl -> TCP SYN 198.18.42.10:8055
          |
          v
kernel route sends packet to Portl TUN/helper
          |
          v
Portl network helper:
  virtual_ip -> published hostname record
  dst_port   -> remote port 8055
          |
          v
open/reuse iroh connection to max-ab11
          |
          v
open portl/tcp/v1 stream:
  host = 127.0.0.1
  port = 8055
          |
          v
remote portl-agent connects to 127.0.0.1:8055
          |
          v
duplex stream copy
```

The MVP maps every port to remote loopback:

```text
session-a.max-ab11.portl:PORT -> remote 127.0.0.1:PORT
```

More explicit service bindings can come later.

### UDP forwarding

```text
app -> UDP 198.18.42.10:60000
        |
        v
Portl helper maps virtual IP -> published hostname record
        |
        v
portl/udp/v1:
  target = 127.0.0.1:60000
        |
        v
remote UDP socket
```

UDP should be in the MVP and should reuse existing `portl/udp/v1`, including
its linger and reattach concepts where applicable.

### Ping

```text
ping session-a.max-ab11.portl
        |
        v
DNS -> 198.18.42.10
        |
        v
ICMP echo reaches Portl helper
        |
        v
Portl checks:
  - published hostname record exists
  - backing iroh connection/target is reachable
        |
        v
synthesize ICMP echo reply
```

Ping means the Portl overlay path for this active attachment is alive. It does
not mean the remote kernel answered ICMP.

### HTTPS front door

Default TCP/TLS behavior is passthrough until an HTTPS front door is explicitly
or automatically enabled for a host/port.

MVP HTTPS should be explicit:

```bash
portl forward --https session-a.max-ab11.portl:8055
```

or an equivalent per-port front-door configuration. This avoids silently
breaking real HTTPS backends, gRPC over `h2`, mTLS, Postgres TLS, Redis TLS,
custom TLS protocols, and HTTP/3/QUIC clients.

Automatic HTTPS remains an explicit final rollout step, not a skipped feature.
When automatic HTTPS is enabled, it should inspect the first bytes of a TCP
connection and only terminate when the traffic is for an active `.portl`
hostname and the classifier is confident it is browser/curl-style HTTP(S):

```text
Chrome/curl opens:
  https://foobar.max-ab11.portl:1112/

OS resolver:
  foobar.max-ab11.portl -> virtual IP

Portl helper receives TCP connection:
  virtual IP:1112

First bytes:
  TLS ClientHello
    SNI  = foobar.max-ab11.portl
    ALPN = h2 / http/1.1
```

Automatic mode must provide a passthrough escape hatch per host/port and should
be disabled for ambiguous traffic. Any bytes read for classification must be
replayed if the connection falls back to transparent passthrough.

Portl-managed HTTPS front doors must strip `Alt-Svc` advertising HTTP/3 unless
Portl also supports a QUIC-aware front door for that origin. They must not add
HSTS headers for `.portl` hostnames.

## HTTPS and local CA model

The local CA is a convenience for local clients. It is not the source of Portl
peer trust.

```text
Portl CA:
  local browser/curl trust for Portl HTTPS front doors

Iroh + tickets:
  remote peer/session trust and authorization

Published hostname record:
  decides whether a .portl hostname is active/routable
```

The local CA should not be derived from `identity.bin`, and the TLS security
model should not depend on binding certificates to Portl peer IDs. Normal TLS
clients validate DNS names and CA trust; they do not validate Portl endpoint
IDs. Portl should enforce backend access through active attachments, iroh, and
tickets.

CA and leaf cert material lives in one directory:

```text
$PORTL_HOME/data/certs/
  ca.crt
  ca.key
  ca.json

  max-ab11.portl.wildcard.crt
  max-ab11.portl.wildcard.key
  max-ab11.portl.wildcard.json
```

Permissions:

```text
$PORTL_HOME/data/certs/                 0700
$PORTL_HOME/data/certs/ca.key           0600
$PORTL_HOME/data/certs/*.wildcard.key   0600
$PORTL_HOME/data/certs/*.crt            0644
$PORTL_HOME/data/certs/*.json           0600
```

Runtime behavior:

- Generate one local Portl CA per `PORTL_HOME`.
- Trust it once during `portl install --network` or `portl network ca trust`.
- The generated CA must include critical X.509 Name Constraints permitting only
  `.portl` DNS names where supported by the platform/client stack. Preflight
  must test the supported trust targets; if the local stack ignores constraints
  on trust anchors, HTTPS trust should be reported as weaker or unavailable.
- Lazily mint per-machine wildcard leaf certs such as `*.max-ab11.portl`, or
  eagerly mint them when an explicit HTTPS front door is configured.
- Regenerate wildcard certs on expiry, CA rotation, or when the machine label's
  current iroh endpoint ID differs from the endpoint ID stored in the cert
  sidecar. This endpoint ID binding is cache hygiene and stale-label detection,
  not browser-visible TLS peer authentication.
- Use conservative validity periods: CA default 10 years; wildcard leaf default
  90 days; backdate leaf `notBefore` by a few minutes for clock skew.
- Cap the wildcard cert cache and prune least-recently-used entries.
- Store optional endpoint ID and label metadata in the `.json` sidecar for
  diagnostics and stale-label rotation.
- Refuse to use `$PORTL_HOME/data/certs` if ownership, permissions, or symlinks
  are unsafe.

## Permissioning

Every transparent flow remains bounded by the effective caps used for the
attachment.

```text
TCP packet to session-a.max-ab11.portl:8055
        |
        v
published hostname record contains effective caps
        |
        v
Portl opens portl/tcp/v1 only if tcp caps allow remote 127.0.0.1:8055
```

UDP follows the same rule through UDP caps and `portl/udp/v1`.

HTTPS front-door behavior is permitted only when:

- the published hostname is active,
- TCP caps allow the upstream host/port,
- network HTTPS support is enabled,
- the user configured an explicit front door, or automatic HTTPS has reached the
  final rollout stage and the classifier accepts the traffic,
- the host/port is not marked passthrough-only.

Attachment records must be lease-based. Foreground attach removes the record on
normal detach. Crashes, sleep/wake, local agent restart, and remote disconnects
must converge on record removal through heartbeat expiry. Background attach is
future work; before it ships, it must define owner UID, logout behavior, kill
semantics, and revocation handling. Revocation should remove published hostname
records promptly; background mode must periodically re-check revocation or use a
revocation push channel.

The default remote address policy for the MVP is remote loopback:

```text
<session>.<machine>.portl:PORT -> remote 127.0.0.1:PORT
```

## Install and preflight

Network mode is explicit at first:

```bash
portl network doctor
portl install --network --dry-run
portl install --network --apply --yes
```

The preflight should classify the machine into:

```text
full-network     = DNS + route/TUN + ICMP + TCP + UDP can be installed
full-with-https  = full-network + Portl CA trust can be installed
partial-network  = some pieces can be installed, but not enough for the full UX
userspace-only   = fall back to localhost forwards / Portl-native commands
```

Core probes:

- platform and service manager,
- root/admin status or sudo availability,
- single-user vs shared multi-user host risk,
- scoped `.portl` DNS resolver integration,
- local resolver listener availability and loopback-only binding,
- TUN/utun and route installation,
- virtual CIDR conflicts at install time and attach time,
- packet-filter or per-UID isolation support where needed,
- ICMP delivery via the virtual interface,
- local CA trust-store options and Name Constraints enforcement,
- install/uninstall rollback state.

The installer should be conservative:

```text
If DNS + TUN/route are not both installable,
do not claim machine-like mode is installed.
```

CA trust is an enhancement. It should not block TCP, UDP, DNS, or ping.

## Userspace fallback

Locked-down machines should still get useful user-space workflows.

```bash
portl attach session-a --target max-ab11
portl status session-a.max-ab11.portl
portl ping session-a.max-ab11.portl
portl forward session-a.max-ab11.portl:8055
portl open http://session-a.max-ab11.portl:8055/foo
```

`portl forward <hostname>:<port>` is an ergonomic userspace wrapper around the
existing TCP forwarding path. For `.portl` hostnames, it should require an
active published hostname record so that fallback mode preserves the same active
intent gate as network mode. Standalone forwarding from saved tickets remains
available through the existing explicit `portl tcp <target> -L ...` surface.

The fallback is explicit localhost forwarding with automatic local port
selection unless the user supplies one:

```text
localhost:PORT <-> session-a.max-ab11.portl:REMOTE_PORT
               <-> remote 127.0.0.1:REMOTE_PORT
```

Example output:

```text
Forwarding:
  http://127.0.0.1:18055
    -> session-a.max-ab11.portl:8055
    -> max-ab11 / 127.0.0.1:8055

Press Ctrl-C to stop.
```

Fallback mode should be honest: arbitrary `ping`, `curl`, or browser usage of
`.portl` hostnames is not guaranteed unless network mode is installed.

## CLI and UX surface

Suggested commands:

```bash
portl network doctor
portl network status
portl network ca status
portl network ca trust
portl network ca untrust
portl network ca rotate
portl network uninstall

portl install --network --dry-run
portl install --network --apply --yes

portl forward session-a.max-ab11.portl:8055
```

Attach output with network mode:

```text
Attached to session-a on max-ab11

Published hostname:
  session-a.max-ab11.portl

Try:
  ping session-a.max-ab11.portl
  curl http://session-a.max-ab11.portl:8055/
```

Attach output without network mode:

```text
Attached to session-a on max-ab11

.portl hostnames are not installed on this machine.

Use a local forward:
  portl forward session-a.max-ab11.portl:8055
```

Network status output:

```text
Portl Network: enabled

Published hostnames:
  HOSTNAME                    TARGET    SESSION     IP
  session-a.max-ab11.portl    max-ab11  session-a   198.18.42.10

Data plane:
  DNS   enabled
  ICMP  enabled
  TCP   enabled
  UDP   enabled

HTTPS:
  Local CA: trusted
  Explicit front doors: available
  Automatic front door: final rollout step
  Cert directory: ~/.portl/data/certs
```

## Error handling

### Network mode not installed

```text
.portl hostnames are not installed on this machine.

Install:
  portl install --network

Fallback:
  portl forward session-a.max-ab11.portl:8055
```

### Hostname has no active attachment

```text
session-a.max-ab11.portl is not active.

Start it:
  portl attach session-a --target max-ab11

For now, start it with a foreground attach. Background publishing is planned but
not part of the first network-mode slice.
```

### HTTPS support not trusted

```text
HTTPS support is not trusted on this machine.

Enable:
  portl network ca trust

Or use plain HTTP:
  curl http://session-a.max-ab11.portl:8055/
```

### HTTPS classifier passthrough

If traffic looks like non-HTTP TLS, pass it through. This should be debug or
status output, not noisy user output:

```text
TLS ClientHello has no HTTP ALPN and no explicit HTTPS front-door binding.
Using transparent TCP passthrough.
```

## Testing strategy

Unit tests:

- hostname parser and DNS label validator for valid and invalid
  `<session>.<machine>.portl` names,
- virtual IP allocator uniqueness, release, quarantine, exhaustion, and CIDR
  conflict handling,
- published hostname lifecycle on attach, detach, crash, heartbeat expiry,
  sleep/wake, and remote disconnect,
- cert path handling under `$PORTL_HOME/data/certs/`,
- CA Name Constraints generation and verification where supported,
- TLS classifier for HTTP ALPN, gRPC/h2, mTLS, SNI-less TLS, slow/fragmented
  ClientHello, and custom TLS passthrough,
- permissions for CA and wildcard cert files,
- userspace TCP bridge behavior for retransmits, FIN/RST, MSS/MTU, and remote
  connect failures,
- UDP flow mapping, idle timeouts, datagram size, and unsupported
  broadcast/multicast behavior.

Integration tests:

- DNS lookup resolves only active attachments and does not leak `.portl` queries
  upstream,
- TCP to virtual IP maps to `portl/tcp/v1`,
- UDP to virtual IP maps to `portl/udp/v1`,
- ping receives a synthetic ICMP reply only after a recent successful
  `portl/meta/v1` ping or equivalent health probe,
- detach stops DNS/routing and stale cached DNS cannot reach a new attachment
  through an immediately reused IP,
- userspace fallback creates localhost forwards and requires active `.portl`
  records for `.portl` hostname syntax,
- HTTPS front door mints a wildcard cert, rotates on endpoint-ID sidecar
  mismatch, strips `Alt-Svc`, avoids HSTS, and forwards HTTP,
- multi-user isolation tests verify that user B cannot use user A's published
  hostname unless machine-wide mode was explicitly enabled.

Platform tests:

- macOS resolver preflight, utun/route preflight, and user/system CA trust
  preflight,
- Linux systemd-resolved preflight, `/dev/net/tun` and route preflight, and CA
  trust preflight.

E2E smoke:

```bash
portl install --network --dry-run
portl attach demo --target local-test
ping demo.local-test.portl
curl http://demo.local-test.portl:8055/
portl forward --https demo.local-test.portl:8055
curl https://demo.local-test.portl:8055/
```

## Open risks

1. **Platform-specific resolver behavior.** macOS, systemd-resolved,
   NetworkManager, and locked-down corporate machines have different resolver
   hooks. The preflight must be honest and conservative.
2. **TUN helper permissions.** The full UX requires privileged route/TUN setup.
   `portl install --network` should be explicit until this is proven.
3. **TUN bridge complexity.** A packet-level TUN cannot be copied directly into
   `tcp/v1`; Portl must choose and validate a userspace TCP/UDP stack or a
   platform redirect strategy before transparent TCP/UDP implementation.
4. **Multi-user exposure.** System DNS/routes are often machine-wide. Full
   network mode should refuse shared hosts unless per-UID isolation is available
   or the user explicitly accepts machine-wide exposure.
5. **HTTPS auto-classification.** TLS ClientHello inspection plus HTTP ALPN is a
   useful final-stage convenience, but non-standard clients, gRPC, mTLS, HTTP/3,
   and custom TLS need explicit passthrough controls.
6. **Ping semantics.** Synthetic ping is useful, but documentation must say it
   checks Portl overlay reachability rather than remote-kernel ICMP. Traceroute
   and tracepath will not behave like a real routed network.
7. **Remote address scope.** Mapping all ports to remote loopback is simple. If
   users later expect access to arbitrary remote LAN addresses, that should be a
   separate service-binding or VPN design.
8. **TLD collision/leakage.** `.portl` is not reserved. Network doctor must
   verify local capture and document the tradeoff versus `.internal`.

## Incremental rollout

1. Add `portl network doctor` and preflight classification.
2. Add published hostname records tied to foreground `portl attach`.
3. Add userspace fallback `portl forward <hostname>:<port>` for active records.
4. Add `.portl` DNS resolution for active records.
5. Prototype and benchmark the TUN bridge stack (`smoltcp` first, gVisor
   netstack fallback candidate) before committing to transparent routing.
6. Add virtual IP/TUN routing and TCP passthrough via `portl/tcp/v1`.
7. Add UDP passthrough via `portl/udp/v1`.
8. Add synthetic ICMP ping based on recent Portl overlay health.
9. Add local CA management under `$PORTL_HOME/data/certs/` with Name
   Constraints, safe path checks, trust/untrust, rotation, and cache pruning.
10. Add explicit HTTPS front doors for configured host/port pairs.
11. Add automatic HTTPS front door for `.portl` HTTP(S) traffic as the final UX
    step, with passthrough controls and HTTP/3/Alt-Svc handling.
12. After the opt-in network install is stable, let normal agent install attempt
    network mode by default and fall back based on preflight results.
