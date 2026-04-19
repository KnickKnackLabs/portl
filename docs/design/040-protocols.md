# 04 — Protocols (ALPNs)

Each protocol is a separate crate (`portl-proto-*`) implementing a common
trait. All frames are **postcard**-encoded (matching the ticket wire
format; see `030-tickets.md §2.1`). All streams are QUIC bidirectional
streams. Datagrams are QUIC datagrams (RFC 9221).

## 1. Common handshake: `portl/ticket/v1`

Every connection begins with exactly one `portl/ticket/v1` stream. No other
streams are served until `TicketAck.ok == true`. The wire format is
specified canonically here; `030-tickets.md §9` cross-references this
section for proof-of-possession semantics.

```
 Client                                                       Agent
   │                                                             │
   │── open bi-stream (ALPN=portl/ticket/v1) ─────────────────────────►│
   │                                                             │
   │── send postcard:                                             │
   │    TicketOffer {                                             │
   │       ticket:        Vec<u8>,          // postcard-encoded   │
   │                                        //   PortlTicket      │
   │                                        //   (terminal)       │
   │       chain:         Vec<Vec<u8>>,     // parent tickets,    │
   │                                        //   root-first;      │
   │                                        //   empty for root   │
   │       proof:         Option<[u8; 64]>, // ed25519 sig,       │
   │                                        //   iff terminal.to  │
   │                                        //   is Some          │
   │       client_nonce:  [u8; 16]          // fresh random       │
   │    }                                                         │
   │                                                             │
   │                                  Agent pipeline (see         │
   │                                  020-architecture.md §4):     │
   │                                   1. per-source-IP rate gate │
   │                                   2. postcard parse          │
   │                                   3. canonicalization check  │
   │                                      (re-encode & compare)   │
   │                                   4. chain verify (§3):      │
   │                                      sig-verify each parent  │
   │                                      BEFORE using its sig    │
   │                                      for parent_ticket_id    │
   │                                      hash match              │
   │                                   5. monotone narrow caps    │
   │                                   6. revocation lookup       │
   │                                      (every ticket in chain) │
   │                                   7. TTL + clock-skew check  │
   │                                   8. proof verify iff `to`:  │
   │                                      proof =                 │
   │                                        ed25519_sign(         │
   │                                          to_priv,            │
   │                                          sha256(             │
   │                                            "portl/ticket-    │
   │                                             pop/v1" ||       │
   │                                            ticket_id ||      │
   │                                            client_nonce))    │
   │                                                             │
   │◄── send postcard:                                            │
   │    TicketAck {                                               │
   │       ok:              bool,                                 │
   │       reason:          Option<AckReason>,    // see below    │
   │       peer_token:      Option<[u8; 16]>,     // iff ok       │
   │       effective_caps:  Option<Capabilities>, // iff ok       │
   │       server_time:     u64                  // unix seconds  │
   │    }                                                         │
   │                                                             │
   │── close stream ──────────────────────────────────────────────│
```

`AckReason` is a small closed enum so clients can branch cleanly
without string parsing:

```
AckReason =
      BadSignature
    | BadChain                // link mismatch, depth exhausted, etc.
    | CapsExceedParent        // non-monotone narrowing
    | NotYetValid             // now + SKEW < not_before
    | Expired                 // now > not_after
    | Revoked                 // ticket_id in revocation set
    | ProofMissing            // to set, proof absent
    | ProofInvalid            // proof sig fails
    | RateLimited             // caller should back off
    | InternalError { detail: Nullable<Text> }
```

`peer_token` accompanies every subsequent stream open as a CBOR preamble:

```
StreamPreamble { peer_token: Bytes(16), alpn: Text }
```

The agent maps `peer_token → effective_caps` and uses it to avoid
re-verifying the ticket on each stream open. `peer_token` is valid for
the lifetime of the QUIC connection only.

## 2. `portl/meta/v1` — ping, info, revocation push

### 2.1 Ping

```
Client                                                   Agent
   │                                                       │
   │── open bi-stream (ALPN=portl/meta/v1) ─────────────────────►│
   │── Preamble + MetaReq::Ping { t_client_us: u64 } ─────►│
   │                                                       │
   │◄── MetaResp::Pong { t_server_us: u64 } ───────────────│
   │                                                       │
   │── close stream ──────────────────────────────────────│
```

### 2.2 Info

```
MetaReq::Info {} →
MetaResp::Info {
    agent_version:    Text,
    supported_alpns:  Array<Text>,
    uptime_s:         u64,
    hostname:         Text,
    os:               Text,
    tags:             Map<Text,Text>,   // orchestrator-injected metadata
}
```

### 2.3 Revocation push

```
Operator (holds revoker ticket)                          Agent
   │                                                       │
   │── MetaReq::PublishRevocations {                       │
   │       items: Array<RevocationRecord>                  │
   │   } ────────────────────────────────────────────────►│
   │                                                       │
   │                                   verify each record  │
   │                                    is signed by a     │
   │                                    trust-root pubkey; │
   │                                    append to /var/lib │
   │                                    /portl/revocations │
   │                                                       │
   │◄── MetaResp::PublishedRevocations {                   │
   │       accepted: u32,                                  │
   │       rejected: Array<{id, reason}>                   │
   │   } ──────────────────────────────────────────────────│
```

## 3. `portl/shell/v1` — PTY + exec

A shell session uses **multiple QUIC sub-streams** opened from a single
control stream. Each data direction gets its own QUIC stream so
QUIC's per-stream flow control does the work — stdout back-pressure
never head-of-line-blocks stdin.

### 3.1 Control stream

The first stream opened for `portl/shell/v1` is the control stream.

```
ShellReq {
    preamble  : StreamPreamble,
    mode      : "shell" | "exec",
    argv      : Nullable<Array<Text>>, // iff mode=exec
    env_patch : Vec<(Text, EnvValue)>, // postcard-encoded; sort by key
                                     // for canonical form; semantically a map
    cwd       : Nullable<Text>,
    pty       : Nullable<PtyCfg>,
    user      : Nullable<Text>,        // drop to which unix user
}

PtyCfg   { term: Text, cols: u16, rows: u16 }
EnvValue = Set(Text) | Unset             // "" sent via Unset clears key
```

### 3.2 Response and stream layout

```
Agent on control stream:
    verifies user ∈ ShellCaps.user_allowlist ∩ policy
    checks pty / exec flags vs caps
    applies env_patch per ShellCaps.env_policy (see §3.5)
    spawns process (with PTY if cfg present)

    writes ShellAck { ok, reason?, pid, session_id } as first CBOR frame.

    If ok: the client then opens additional QUIC sub-streams,
    each carrying session_id + kind as StreamPreamble:

        stdin   : client → agent, raw bytes
        stdout  : agent  → client, raw bytes
        stderr  : agent  → client, raw bytes
        signal  : client → agent, CBOR frames { sig: u8 }
        resize  : client → agent, CBOR frames { cols: u16, rows: u16 }
        exit    : agent  → client, single CBOR frame { code: i32 }

StreamPreamble (for portl/shell/v1 sub-streams) {
    peer_token : Bytes(16),
    alpn       : "portl/shell/v1",
    session_id : Bytes(16),
    kind       : "stdin" | "stdout" | "stderr" |
                 "signal" | "resize" | "exit"
}
```

Closing the control stream from either side tears down the shell
session and all associated sub-streams. Closing `stdin` from the
client sends EOF to the child process; closing `stdout`/`stderr`
from the agent indicates the child closed that fd.

### 3.5 Environment variable semantics

`ShellCaps.env_policy` in the ticket controls how `ShellReq.env_patch`
is combined with the target user's login environment:

| `env_policy` | Behavior |
| --- | --- |
| `Deny` | `env_patch` ignored; child process sees only the target user's login env |
| `Merge { allow: None }` | `env_patch` merged into login env; client-supplied keys override; `Unset` removes keys |
| `Merge { allow: Some([K1, K2, …]) }` | Same as `Merge` but only keys in the allowlist are accepted from `env_patch`; others are silently dropped |
| `Replace { base: [...] }` | Login env discarded; child process sees `base` merged with `env_patch` under the same merge rules |

`env_policy` is part of `ShellCaps` in the ticket schema
(`030-tickets.md §2`), so the shape is proof-carrying: a narrowed
delegation can tighten `env_policy` (e.g. Merge → Merge-with-allowlist,
or Merge → Deny) but cannot widen it.

### 3.3 Sequence diagram

```
Client                                              Agent
  │                                                   │
  │── portl/ticket/v1 handshake done ────────────────│
  │                                                   │
  │── open control stream ALPN=portl/shell/v1 ─────────────►│
  │── ShellReq { mode:"shell", pty, user:"ubuntu" } ─►│
  │                                                   │
  │                                         spawn bash -l in PTY
  │                                                   │
  │◄── ShellAck { ok:true, pid:1234,                  │
  │              session_id:0x9f…}                    │
  │                                                   │
  │── open stdin  sub-stream (kind=stdin)  ──────────►│
  │── open stdout sub-stream (kind=stdout) ──────────►│
  │── open stderr sub-stream (kind=stderr) ──────────►│
  │── open resize sub-stream (kind=resize) ──────────►│
  │── open signal sub-stream (kind=signal) ──────────►│
  │                                                   │
  │── stdin:  "ls\n"                               ──►│
  │◄── stdout: "Desktop  Docs ...\n"                  │
  │── resize: {cols:120, rows:40}                  ──►│
  │   ...                                             │
  │── signal: {sig:2}  (ctrl-C)                    ──►│
  │                                                   │
  │◄── exit (one-shot stream): {code:130}             │
  │── close control stream ──────────────────────────►│
```

QUIC handles flow-control and head-of-line isolation per-stream, so
stdout back-pressure can never block the client from sending a resize
event or a SIGINT.

## 4. `portl/tcp/v1` — TCP port forward

One stream **per forwarded TCP connection**. Simple, stateless on the agent.

### 4.1 Sequence

```
Client                                            Agent                service
  │                                                 │                    │
  │                                                 │                    │
  │  local app connects to 127.0.0.1:3000           │                    │
  │  (bound by portl tcp peer -L 3000:127.0.0.1:22) │                    │
  │                                                 │                    │
  │── open stream ALPN=portl/tcp/v1 ─────────────────────►│                    │
  │── TcpReq {                                      │                    │
  │     preamble,                                   │                    │
  │     host:"127.0.0.1",                           │                    │
  │     port:22                                     │                    │
  │   } ─────────────────────────────────────────── │                    │
  │                                                 │                    │
  │                                      verify caps                     │
  │                                      for tcp:   │                    │
  │                                      host_glob  │                    │
  │                                      match 127… │                    │
  │                                      port 22    │                    │
  │                                      in range   │                    │
  │                                                 │                    │
  │                                      connect 127.0.0.1:22 ─────────►│
  │                                                 │◄── TCP connected ──│
  │                                                 │                    │
  │◄── TcpAck { ok:true }                          │                    │
  │                                                 │                    │
  │  ══════════════ duplex bytes ════════════════════════════════════════│
  │                                                 │                    │
  │  local app closes                               │                    │
  │── FIN on stream ──────────────────────────────►│                    │
  │                                                 │── close ─────────►│
```

### 4.2 Flow control

QUIC stream backpressure propagates end-to-end. When the remote TCP peer
can't drain fast enough, the local `portl-cli` sees the stream back off
and in turn applies TCP backpressure on the local socket. No explicit
windowing frames needed.

## 5. `portl/udp/v1` — UDP port forward

One **control stream** to set up the session, then **QUIC datagrams** for
payload.

### 5.1 Control phase

```
UdpCtlReq {
    preamble,
    session_id : Bytes(8),   // zero on first attach; echoed on reattach
    // list of local binds the client holds open and wants forwarded
    binds: Array<UdpBind>
}

UdpBind {
    local_port_range : (u16, u16),   // what client bound locally
    target           : { host: Text, port_range: (u16, u16) },
}

UdpCtlResp {
    ok         : bool,
    error      : Nullable<Text>,
    session_id : Bytes(8),
}
```

The `session_id` scopes subsequent datagrams to this `UdpCtl` session.

#### Session lifecycle across transport flaps

A UDP session has state both in the agent (the outbound UDP sockets
it has bound to reach the service) and in the client (the `src_tag →
local 5-tuple` mapping used for replies). When the underlying QUIC
connection drops and the client reconnects (e.g. laptop wake, IP
change, transient network blip), applications like mosh expect the
logical session to survive.

```
Session state persistence:

  agent holds the session record for session_id for up to
  UDP_SESSION_LINGER = 60s after the QUIC connection that owns it
  closes. During linger, outbound UDP sockets stay bound and the
  demux table stays populated, so replies keep flowing to the
  (detached) session.

  on reconnect, the client presents its ticket again, then
  re-sends UdpCtlReq with the SAME session_id plus the same
  `binds`. If the session exists and is still within linger,
  the agent re-attaches it to the new QUIC connection and
  returns UdpCtlResp { ok:true, session_id }. Otherwise the
  client starts a fresh session.

  after UDP_SESSION_LINGER expires with no reconnect, the
  session is destroyed and its sockets closed.
```

The 60 s default is a config knob (`[udp] session_linger_secs` in
`090-config.md`). Mosh-quality roaming is the target use case.

### 5.2 Datagram frame (QUIC datagram, not stream)

```
UdpDatagram {
    session_id   : Bytes(8),
    target_port  : u16,
    src_tag      : u32,    // client-chosen; identifies the local src 5-tuple
    payload      : Bytes,
}
```

Encoded tightly (fixed header, then payload) to keep within MTU.

### 5.3 Flow diagram

```
  client machine                                 target

  app ◄── UDP ──┐                                ┌── UDP ──► svc
                │                                │
   src=:54321   │                                │   dst=:60000
                ▼                                ▼
          portl-cli  ───── QUIC datagram ─────► portl-agent
          (maintains                            (demux by
           src_tag ↔                             session_id +
           5-tuple map,                          target_port;
           session_id from                       reply wrapped
           UdpCtlResp)                           with same
                                                 src_tag)
                ▲                                ▲
                └────── reply datagram ──────────┘
          app ◄── UDP ──  routed back to :54321
```

### 5.4 Handling replies

Agent keeps, per `(session_id, src_tag)`, a `SocketAddr` for the real
external peer (if the agent is connecting a new UDP socket per src_tag),
or a local-bind port from a shared socket (if using `recv_from`-style).
Replies arrive as datagrams tagged with the originating `src_tag`; the
client uses that to `sendto` back to the original local source.

### 5.5 Size limits

- QUIC datagram cap: ~1200 bytes after framing.
- Enough for mosh (~300 byte SSP frames), DNS (≤512), most game netcode.
- Oversize payloads are rejected with an error datagram to src_tag; apps
  fall back per their own policies.

## 6. `portl/fs/v1` — minimal file operations (deferred to v0.2)

> **Deferred from v0.1.** `portl/fs/v1` is a nontrivial rabbit hole (symlink
> traversal, sparse files, cross-OS permission bits, chunking,
> resumability) and the v0.1 workaround is adequate:
>
> ```
> portl sh peer 'tar -c PATH' | tar -xC ./local/
> ```
>
> The design sketch below is preserved for v0.2 implementation.

```
FsReq::Stat   { path: Text }
FsReq::List   { path: Text }
FsReq::Get    { path: Text }            // body = stream of bytes back
FsReq::Put    { path: Text, mode: u32 } // body = stream of bytes in
FsReq::Remove { path: Text }
FsReq::Mkdir  { path: Text, mode: u32 }

All constrained by FsCaps.roots and readonly flag.
```

Sequence for `portl cp peer:/etc/issue /tmp/issue`:

```
Client                                            Agent
  │── open stream ALPN=portl/fs/v1 ──────────────────►│
  │── FsReq::Get { path:"/etc/issue" } ────────│
  │                                              │
  │                            verify /etc/issue ∈ roots
  │                            open file
  │◄── FsGetHeader { ok:true, size, mode }      │
  │◄── (stream of bytes)                         │
  │◄── FIN                                       │
```

## 7. `portl/vpn/v1` — TUN-based overlay (optional)

Feature-gated; requires TUN privileges on both ends.

### 7.1 Control stream

```
VpnCtlReq {
    preamble,
    my_ula    : Ipv6Addr,   // must match client's derived ULA
    peer_ula  : Ipv6Addr,   // should match agent's derived ULA
    mtu       : u16,        // negotiated
}

VpnCtlResp {
    ok       : bool,
    error    : Nullable<Text>,
    mtu_final: u16,
}
```

### 7.2 Datagram framing

```
VpnDatagram = raw IPv6 packet   // no extra header; the IP header carries
                                //   src/dst and everything else we need
```

Because both peers have agreed ULAs and there's only one peer per
connection, no session multiplexing is needed.

### 7.3 End-to-end

```
  client app                                       target service
   │                                                  │
   │── IPv6 pkt src=fd7a:…:A::1 dst=fd7a:…:B::1       │
   │                                                  │
   │  kernel route table:                             │
   │    fd7a::/32 → TUN portl0                        │
   │                                                  │
   ▼                                                  │
  portl vpn driver (client)                           │
    reads packet from TUN                             │
    opens QUIC datagram on portl/vpn/v1 conn ────────►│
                                                      │
                                                      ▼
                                           portl-agent vpn service
                                              writes packet to its
                                              TUN portl0 (inside VM)
                                                      │
                                                      ▼
                                             kernel delivers to
                                             target service by its
                                             own routing table
```

## 8. Error model

Common error envelope on any response message. `kind` is a closed
enum so clients can branch on it cleanly without string parsing
(error taxonomy is stable and part of the wire contract):

```
Error {
    kind           : ErrorKind,   // closed enum, see below
    message        : Text,        // human-readable, may be empty
    retry_after_ms : Nullable<u32>,
}

ErrorKind =
      ProtoError          // malformed frame, bad encoding
    | CapDenied           // caps did not authorise this operation
    | NotFound            // path / object not present
    | RateLimited         // caller should back off (see retry_after_ms)
    | Overloaded          // agent cannot accept more work
    | VersionMismatch     // unsupported ALPN version
    | InternalError       // unexpected; check logs
    | Timeout
    | Cancelled
```

Error propagation:

- At `portl/ticket/v1` phase: stream carries `TicketAck { ok:false, reason }`
  then closes; connection stays up so the client can print a clear
  message and retry.
- At per-protocol phase: protocol-specific response with `ok:false`; stream
  closes; other streams in the connection unaffected.
- At transport level: QUIC `ApplicationClose` with short reason code.
  Defined codes:
  - `0x1000` ticket_required
  - `0x1001` policy_denied
  - `0x1002` overloaded
  - `0x1003` version_mismatch
  - `0x1004` shutting_down

## 10. Protocol requirements

All v0.1 protocols run on a single data plane: iroh QUIC (streams
plus datagrams). This table is reference material for future
post-v0.1 work where an alternate data plane (WebRTC, Loom) might
not support every ALPN. If/when that happens, the full
`ProtocolRequirements` design is at
`future/140-transport-abstraction.md`.

| ALPN | Streams | Datagrams | Interactive | Notes |
| --- | --- | --- | --- | --- |
| `portl/ticket/v1` | ✓ | — | no | required on every connection |
| `portl/meta/v1` | ✓ | — | no | ping, info, revocation push |
| `portl/shell/v1` | ✓ (many) | — | yes | PTY latency matters; multi-stream |
| `portl/tcp/v1` | ✓ | — | no | one stream per forwarded conn |
| `portl/udp/v1` | ✓ control | ✓ data | often | needs datagrams |
| `portl/fs/v1` | ✓ | — | no | v0.2; deferred |
| `portl/vpn/v1` | ✓ control | ✓ data | depends | needs datagrams |

## 9. Versioning

Each ALPN carries a `/vN` suffix. A peer supports a specific version per
ALPN; mismatches are detected at `open_bi()` time (the endpoint rejects
unknown ALPNs). When we revise `portl/shell/v1` incompatibly, it becomes
`portl/shell/v2`; the agent can advertise both during a transition period by
registering two handlers.

The ticket's `alpns` array declares what the ticket authorises. Agent
policy may further restrict to a subset of its compiled-in ALPNs. If a
client tries to open an ALPN not in its authorised set, the agent aborts
the stream with `policy_denied`.
