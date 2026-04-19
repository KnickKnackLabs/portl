# 10 — End-to-end walkthroughs

Each walkthrough is a self-contained story with diagrams. Read them in
order — later ones build on earlier concepts.

## 1. Peer-to-peer: two laptops, no orchestrator

### Setup

```
┌── laptop A ────────────────┐        ┌── laptop B ────────────────┐
│ portl  (client + agent)    │        │ portl  (client + agent)    │
│ identity.key (Ka)          │        │ identity.key (Kb)          │
│ agent secret (Sa)          │        │ agent secret (Sb)          │
└────────────────────────────┘        └────────────────────────────┘
```

### Diagram

```
 Step 1. Both laptops generate identities and agent secrets.
 Step 2. A mints a root ticket for B's node-id, signed by Ka,
         with caps = [shell, tcp:22].
 Step 3. A → B (out of band): "portl1…"
 Step 4. B → A: `portl ticket import <ticket>`
 Step 5. B: `portl shell A` works.

  A                                     B
  │ portl id new                        │ portl id new
  │ portl-agent run &                   │ portl-agent run &
  │                                     │
  │──────── exchange pubkeys ───────────│
  │                                     │
  │ # trust.roots on A includes Kb       │
  │ # trust.roots on B includes Ka       │
  │                                     │
  │ portl mint-root \
  │   --node $(cat B.pub) \
  │   --caps shell,tcp:22 \
  │   --ttl 30d \
  │   --issued-by Ka -o B-access.ticket │
  │                                     │
  │────── B-access.ticket ─────────────►│
  │                                     │
  │                                     │ portl ticket import B-access.ticket --as A
  │                                     │ portl shell A
  │                                     │       ↓
  │                                     │   opens QUIC to A's node-id
  │                                     │   ticket/v1 handshake ok
  │                                     │   shell/v1 stream
  │                                     │   interactive PTY on A's host
```

### Properties

- No coordinator; no shared infrastructure beyond an iroh relay.
- Revocable from A at any time.
- Only the ticket flows on the wire; keys never leave their machines.

## 2. Slicer-driven: create a VM agent and shell in

### Preconditions

- Operator has `master-homelab.ticket` imported.
- A `portl-agent --mode gateway` is running on the slicer host;
  slicer-mac / slicer daemon is up.

### Diagram

```
operator          portl-cli     portl-agent(gw)     slicer daemon         VM agent
   │                          │                   │                    │                  │
   │ portl slicer vm add sbox --tag agent=claude  │                    │                  │
   │────────────────────────►│                   │                    │                  │
   │                          │ generate S, node_id=pub(S)             │                  │
   │                          │                   │                    │                  │
   │                          │ HTTP via master ticket + bearer        │                  │
   │                          │──── POST /secret ─►│                   │                  │
   │                          │                   │── POST /secret ───►│                  │
   │                          │                   │◄──── 200 ──────────│                  │
   │                          │◄─── 200 ──────────│                    │                  │
   │                          │                   │                    │                  │
   │                          │──── POST /vm/add ►│                    │                  │
   │                          │  includes userdata with install script │                  │
   │                          │                   │── POST /vm/add ───►│                  │
   │                          │                   │◄──── 200 ──────────│                  │
   │                          │                                                           │
   │                          │                                               boot; systemd
   │                          │                                               starts      │
   │                          │                                               portl-agent │
   │                          │                                                           │
   │                          │────── meta/v1 ping loop ─────────────────────────────────►│
   │                          │◄─────────────── pong ─────────────────────────────────────│
   │                          │                                                           │
   │                          │ mint root ticket for node_id, signed by Ka (operator)    │
   │                          │ save as ~/.config/portl/tickets/claude-1.ticket          │
   │                          │                                                           │
   │◄── printed ticket + alias ────────────────────────────────────────────────────────── │
   │                                                                                      │
   │ portl shell claude-1                                                                 │
   │────────────────────────────── ticket/v1 + shell/v1 ──────────────────────────────────►│
```

### Observations

- Provisioning traffic goes through `portl-agent --mode gateway →
  slicer daemon`. Direct peer traffic after that is peer-to-peer.
- The operator never needs a direct route to the slicer host daemon
  socket; the gateway-mode agent fronts it.

## 3. Sharing with a collaborator

### Diagram

```
Alice (operator)         Bob (operator)            VM agent
     │                        │                        │
     │ already holds          │                        │
     │ claude-1.ticket        │                        │
     │ (root, issued by Ka)   │                        │
     │                        │                        │
     │ portl share claude-1 \ │                        │
     │   --caps shell,tcp:22\ │                        │
     │   --ttl 24h          \ │                        │
     │   --to $KB           \ │                        │
     │   -o bob.ticket        │                        │
     │                        │                        │
     │                        │                        │
     │ ─────── bob.ticket ───►│                        │
     │                        │                        │
     │                        │ portl ticket import   │
     │                        │   bob.ticket           │
     │                        │ portl shell claude-1   │
     │                        │                        │
     │                        │── ticket/v1 ──────────►│
     │                        │                        │
     │                        │    agent verifies:     │
     │                        │      delegated ticket  │
     │                        │      parent = Alice's  │
     │                        │        root            │
     │                        │      Ka ∈ trust.roots  │
     │                        │      caps ⊆ parent     │
     │                        │      TTL 24h ok        │
     │                        │      proof-of-key ok   │
     │                        │                        │
     │                        │◄── TicketAck ok ───────│
     │                        │                        │
     │                        │    Bob's session has   │
     │                        │    caps={shell,        │
     │                        │         tcp:22}        │
     │                        │    Only. VPN/fs/udp    │
     │                        │    all denied.         │
```

## 4. Revocation after a leaked ticket

```
 Alice                  Agent (in VM)             External actor
   │                        │                           │
   │ (bob.ticket leaked)    │                           │
   │                        │                     attempts portl shell
   │                        │                           │
   │                        │◄── ticket/v1 offer ───────│
   │                        │                           │
   │                        │ (still valid here — no    │
   │                        │  revocation yet)          │
   │                        │                           │
   │                        │─── TicketAck ok ─────────►│
   │                        │                           │
   │ portl revoke <id>      │                           │
   │ portl revocations \    │                           │
   │   publish --to claude-1│                           │
   │                        │                           │
   │─── meta/v1 ───────────►│                           │
   │    PublishRevocations  │                           │
   │    [{id, reason}]      │                           │
   │                        │                           │
   │                        │ append to                 │
   │                        │ revocations.jsonl         │
   │                        │                           │
   │                        │                     next connect:
   │                        │                           │
   │                        │◄── ticket/v1 offer ───────│
   │                        │                           │
   │                        │─── TicketAck ok:false ───►│
   │                        │    err: "revoked"         │
```

## 5. UDP + mosh (post M5)

```
Client (Mac)                                          Target VM (Linux)
                                                       mosh-server :60000

 portl udp claude-1 -L 60000:127.0.0.1:60000
    │
    │ binds UDP 127.0.0.1:60000 on client
    │ opens udp/v1 control stream to agent
    │ gets session_id
    │
 user runs: mosh --server=mosh-server localhost
    │
 mosh binds UDP on client, sends to 127.0.0.1:60000
    │
    ▼
 portl-cli recv_from → wraps as QUIC datagram:
    { session_id, target_port=60000, src_tag=hash(src) }
    │
    ▼ (QUIC datagram)
 portl-agent receives, sendto 127.0.0.1:60000
                                                          mosh-server processes
                                                          sends reply
    ◄ QUIC datagram reply (same src_tag) ◄
 portl-cli sendto original client src
    │
    ▼
 mosh continues as if talking to a local UDP endpoint
```

## 6. VPN mode (M7, stretch)

```
 step 1: `portl vpn up claude-1 sbox-2`
         │
         │  creates local TUN portl0
         │  routes fd7a::/32 → portl0
         │  starts DNS stub for *.portl.local
         │  computes ULAs:
         │    claude-1 → fd7a:<h(claude_nodeid)>::1
         │    sbox-2   → fd7a:<h(sbox_nodeid)>::1
         │  establishes vpn/v1 to each peer

 step 2: `ping claude-1.portl.local`
         │
         │  dns stub returns fd7a:<h(claude_nodeid)>::1
         │  kernel routes IPv6 to TUN
         │  portl reads packet, wraps as QUIC datagram
         │  sends on vpn/v1 conn to claude-1
         │  agent (in VM) receives datagram
         │  writes to its TUN → kernel → icmp echo reply
         │  reply flows back same way
         │
         │  result: mosh, curl, ssh, anything-UDP/TCP
         │  can speak directly to claude-1 by name
```

## 7. Reconnecting from another machine

```
 Day 1 (laptop A):
   portl ticket import ticket-from-slicer-vm --as claude-1
   portl shell claude-1 --bootstrap "tmux new-session -A -s work"
   (ctrl-b d; close laptop)

 Day 2 (desktop, different physical location):
   gh gist view <my-tickets-gist> > ~/tmp/c1.ticket
   portl ticket import ~/tmp/c1.ticket --as claude-1
   portl shell claude-1 --bootstrap "tmux attach -t work"
   │
   │ same tmux session, agents still running inside VM
   │ uninterrupted by client IP changes
   │ because VM agent didn't restart, only client did
```

## 8. Fleet view: three peers, one operator key

```
                ┌─────────────┐
                │ operator Ka │
                └──────┬──────┘
                       │ signs root tickets for:
         ┌─────────────┼─────────────┐
         │             │             │
         ▼             ▼             ▼
    ┌─────────┐   ┌─────────┐   ┌─────────┐
    │claude-1 │   │ sbox-2  │   │ relay-1 │
    │ (sbox)  │   │ (sbox)  │   │  (relay)│
    └─────────┘   └─────────┘   └─────────┘

All three agents have trust.roots = [Ka.pub].
Operator holds one ticket per peer.
Bob (collaborator) holds one delegated ticket for claude-1 only.

 portl list              # shows all three of operator's tickets + path status
 portl status            # live RTT + direct/relay per peer
 portl share sbox-2 --caps shell,tcp:* --ttl 2h --to bob
 …
```

## 9. What happens on agent restart

```
 agent process exits (crash, oom, systemd restart)
   │
   │  QUIC connections drop.
   │  Client sees `connection lost`; tmux-in-VM survives (no
   │    coupling with portl conn).
   ▼
 systemd restarts portl-agent
   │
   │  loads /var/lib/portl/secret (same key; same node_id)
   │  rebinds iroh endpoint
   │  re-registers with relays
   ▼
 client's next attempt succeeds; session resumes by re-attaching
 to the pre-existing tmux / long-running workload.
```

## 10. Non-goals walkthrough: what portl won't do

```
 "I want portl to provide its own identity provider for users."
    ─ No. Use any SSO you want in the agent's user system; portl only
      knows about the operator's ed25519 keys.

 "I want portl to mesh-route packets between non-adjacent peers."
    ─ No. Each connection is a single iroh hop. Relays forward but don't
      multi-hop-route. For true mesh, run something like Yggdrasil.

 "I want portl to replace my full site-to-site WireGuard tunnel."
    ─ Probably not the right tool. VPN mode is useful for dev / remote
      access; for bulk site-to-site at line rate, use WireGuard.

 "I want a web UI with graphs."
    ─ Out of scope for v1. Third parties welcome to build one on top.
```
