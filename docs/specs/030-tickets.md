# 03 — Tickets
+
+> **Ticket schema is still live; CLI examples are partly historical.**
+> The wire format in this document remains valid in v0.2.0. Where
+> examples use `portl id new` or `portl mint-root`, read those as
+> the modern `portl init` and `portl mint` commands.

Tickets are the **only** multi-party object in portl. Everything that
crosses a trust boundary is a ticket.

## 1. Anatomy

```
 Wire form  :  portl<base32-lowercase-payload>
                │     │
                │     └── postcard-encoded Ticket, base32-lowercase
                └──────── KIND prefix (matches iroh-tickets convention)

 Typical length  :  260–450 characters (see §10)
 URL-safe        :  yes (no +, /, =, whitespace)
 Terminal-safe   :  yes (no control chars)
 Encoding        :  postcard + base32-lowercase, kind-prefixed.
                    See §11 for the relationship to iroh-tickets.
```

Example (illustrative, not real bytes):

```
portlqyn5wx4nsazd6vy2ytfr7tywmzc3x4hw6f5fmuw2u4kv9qmxpx8a4ahsxyjwf3y
z7yybfdebtnjv3q5w3pxwj8gufaqhxwfg6nqmmm8yz2kp8p27k9mhkqar9fea7cwj1k
3f5g7h9l2m4n6p8q0r2s4t6u8v0w2x4y6z8a0b2c4d6e8f0g2h4i6j8k0l2m4n6o8p0
q2r4s6t8u0v2w4x6y8z0a2b4c6d8e0f2g4h6i8j0k2l4m6n8o0p2q4r6s8
```

The lack of checksum (compared to bech32m) is deliberate: this format
matches iroh's own tickets so a ticket pasted into
`ticket.iroh.computer` produces a useful "kind = portl, NN bytes"
diagnostic. Typos that garble the payload are caught at the postcard-
decode / signature-verify stages; the CLI surfaces `ticket_id` after
successful import so users can visually confirm the ticket they
imported matches the one they were sent.

## 2. Postcard payload schema (v1)

```rust
pub struct PortlTicket {
    v:    u8,                      // format version, currently 1
    addr: iroh_base::EndpointAddr, // target EndpointId + TransportAddrs
    body: PortlBody,               // signed body (see below)
    sig:  [u8; 64],                // ed25519(resolved_issuer) over
                                   //   canonical(body)
}

pub struct PortlBody {
    caps:        Capabilities,     // presence-bitmap + present bodies
                                   //   (see §2.3); implicitly
                                   //   determines which ALPNs this
                                   //   ticket authorises
    alpns_extra: Vec<String>,      // MUST be empty in v0.1; reserved
                                   //   as an escape hatch for
                                   //   application-specific ALPNs
                                   //   outside the Capabilities enum
    not_before:  u64,              // unix seconds
    not_after:   u64,              // unix seconds; MUST be finite
    issuer:      Option<[u8; 32]>, // signer pubkey; canonicalization
                                   //   rule below
    parent:      Option<Delegation>,
    nonce:       [u8; 8],          // random; entropy for ticket_id
    bearer:      Option<Vec<u8>>,  // master-ticket payload (§7)
    to:          Option<[u8; 32]>, // iff set: proof-of-possession
                                   //   required (§9)
}

pub struct Capabilities {
    presence:  u8,                 // bitmask; bit i = presence[i]
    shell:     Option<ShellCaps>,  //   bit 0
    tcp:       Option<Vec<PortRule>>, // bit 1
    udp:       Option<Vec<PortRule>>, // bit 2
    fs:        Option<FsCaps>,     // bit 3; deferred to v0.2
    vpn:       Option<VpnCaps>,    // bit 4
    meta:      Option<MetaCaps>,   // bit 5
}
//   Wire encoding is `presence: u8` followed by present bodies in
//   bit order. Postcard field elision is required: bits not set in
//   `presence` MUST NOT have their body encoded.

pub struct PortRule {              // canonicalization: hosts lexico-
    host_glob: String,             //   graphically sorted, ports
    port_min:  u16,                //   ascending; duplicates rejected
    port_max:  u16,
}

pub struct ShellCaps {
    user_allowlist:    Option<Vec<String>>,
    pty_allowed:       bool,
    exec_allowed:      bool,
    command_allowlist: Option<Vec<String>>,
    env_policy:        EnvPolicy,
}

pub enum EnvPolicy {
    Deny,
    Merge   { allow: Option<Vec<String>> },
    Replace { base:  Vec<(String, String)> },
}

pub struct FsCaps {
    roots:    Vec<String>,
    readonly: bool,
    max_size: Option<u64>,
}

pub struct VpnCaps {
    my_ula:   [u8; 16],
    peer_ula: [u8; 16],
    mtu:      u16,
}

pub struct MetaCaps {
    ping: bool,
    info: bool,
}

pub struct Delegation {
    parent_ticket_id: [u8; 16],   // sha256("portl/parent/v1"||parent.sig)[..16]
    depth_remaining:  u8,
}
```

### 2.1 Relationship to iroh-tickets

`PortlTicket` implements `iroh_tickets::Ticket`:

```rust
impl Ticket for PortlTicket {
    const KIND: &'static str = "portl";
    fn to_bytes(&self) -> Vec<u8> { postcard::to_stdvec(self).unwrap() }
    fn from_bytes(b: &[u8]) -> Result<Self, ParseError> {
        postcard::from_bytes(b).map_err(ParseError::from)
    }
}
```

This gives us three things for free: the `portl<base32>` URI shape
(via the default `Display` impl on `Ticket`), parseability in the
iroh ticket explorer at `ticket.iroh.computer`, and the same
dialing-info layout (`EndpointAddr`) every other iroh app uses.

### 2.2 Canonicalization (normative)

Signature is over the exact bytes of `canonical(body)` where
`canonical` enforces the following. Verifiers MUST re-encode after
decode and reject any mismatch.

1. **Issuer elision is mandatory, not optional**:
    - If `body.issuer == Some(body.addr.endpoint_id)` → **reject**.
    - If `body.issuer == None` → the effective signing key is
       `body.addr.endpoint_id`.
    - If `body.issuer == Some(k)` with `k != body.addr.endpoint_id`
       → the effective signing key is `k`.
    - Call the chosen key `resolved_issuer(ticket)`; use it everywhere
       (signature verification, trust-root check, audit logs, CLI
       display).
2. **Capabilities presence bitmap** matches the set of `Some` fields
    exactly. A bit set with the corresponding field `None`, or a bit
    clear with the field `Some`, MUST be rejected.
3. **Vecs are sorted**:
    - `PortRule` arrays: lexicographic on `(host_glob, port_min,
       port_max)`; no duplicates.
    - `FsCaps.roots`: lexicographic; no duplicates.
    - `ShellCaps.user_allowlist`, `.command_allowlist`,
       `EnvPolicy::Merge.allow`, `EnvPolicy::Replace.base` (by key):
       lexicographic; no duplicates.
    - `alpns_extra`: lexicographic; no duplicates.
4. **Timestamps**: `not_after > not_before`; `not_after - not_before
    ≤ 365 days`; `nonce` non-zero.
5. **Signature uniqueness**: `sig` MUST be a strict Ed25519 signature
    (canonical `S`; low-order rejection per RFC 8032 §5.1.7).
6. **Re-encode invariant**: `postcard::to_stdvec(decoded) ==
    received_bytes`. Reject on mismatch.

### 2.3 Ticket ID and hash domains

```
ticket_id         = sha256("portl/ticket-id/v1" || sig)[..16]  // 128-bit
parent_ticket_id  = sha256("portl/parent/v1"    || sig)[..16]  // 128-bit
```

Domain separation is load-bearing: it ensures that a 64-bit birthday
collision found in one usage (e.g. while mining matching `ticket_id`s
for audit-log confusion) cannot be replayed to match a
`parent_ticket_id` in another ticket's delegation chain.

`ticket_id` uses:
- revocation records (agent lookup table)
- audit logs (cross-referenceable to sessions)
- `to`-proof binding (see §9); **this makes `ticket_id` security-
   critical**, not merely a UX convenience
- user-visible identifier when sharing/revoking

`parent_ticket_id` uses:
- chain linkage only (see §3)

Both truncations are 128-bit. Second-preimage cost is ≈ 2^128 on
SHA-256 in the random-oracle model; the relevant worry in practice
is **birthday collisions (2^64)** when a malicious issuer can grind
matching IDs. Domain separation blocks cross-use exploitation of
such a collision.

## 3. Root vs delegated

```
 ROOT ticket                               DELEGATED ticket
 ───────────                               ────────────────
 body.parent  == None                      body.parent  == Some(Delegation)
 resolved_issuer ∈ trust.roots             resolved_issuer = signer of this
                                           ticket (its own issuer); the
                                           chain ultimately roots in
                                           trust.roots
 sig = sign(resolved_issuer,               sig = sign(resolved_issuer,
            canonical(body))                          canonical(body))
                                           parent.parent_ticket_id pins
                                           the parent's signature; parent
                                           bytes travel on the wire in
                                           TicketOffer.chain (§9).
```

**Root tickets** are signed by a key the agent trusts (an entry in
`trust.roots` in its config). Two shapes are both valid:

- **Operator-issued root** (common case): some operator key `Ka` is
   in the agent's `trust.roots`, and `Ka` signs a ticket naming the
   agent's `addr.endpoint_id`. `body.issuer = Some(Ka)`.
- **Self-signed root / bootstrap**: the agent's own `endpoint_id` is
   in `trust.roots`, and signs a ticket naming itself.
   `body.issuer = None`, elided per §2.2. Mainly useful for cold
   bootstrap and agent-for-self tickets.

Either way, `resolved_issuer(ticket) ∈ trust.roots` is the authority
check.

**Delegated tickets** form a chain that must terminate at a root.
Each delegated ticket carries `parent.parent_ticket_id` as link
metadata; the full parent ticket *bytes* travel on the wire inside
`TicketOffer.chain` (see §9). `depth_remaining` bounds how deep
delegation can nest; each level decrements it.

### Chain verification

The agent is given `(terminal, chain[])` where `chain` is ordered
root-first and may be empty (terminal is itself a root).

```
MAX_DELEGATION_DEPTH = 8
HASH_TICKET_ID   = "portl/ticket-id/v1"
HASH_PARENT_REF  = "portl/parent/v1"

verify_chain(terminal, chain):
    # 1. Identify chain and root
    all_tickets := chain + [terminal]          // ordered root-first
    require all_tickets.len() ≥ 1
    require all_tickets.len() ≤ MAX_DELEGATION_DEPTH + 1

    # 2. Every ticket targets the same peer
    target := all_tickets[0].addr.endpoint_id
    for t in all_tickets[1..]:
        require t.addr.endpoint_id == target

    # 3. Root trust + signature (always first, always under
    #    resolved_issuer)
    T_root := all_tickets[0]
    require T_root.body.parent == None
    root_key := resolved_issuer(T_root)
    require root_key ∈ trust.roots
    require ed25519_verify_strict(
                T_root.sig, root_key,
                canonical(T_root.body))

    # 4. Walk each delegation hop; verify BEFORE using the parent's
    #    sig as a hash input. Order matters.
    T_parent := T_root
    for T_child in all_tickets[1..]:
        require T_child.body.parent.is_some()

        # 4a. Sig-verify the child under the parent's resolved issuer.
        parent_key := resolved_issuer(T_parent)
        require ed25519_verify_strict(
                    T_child.sig, parent_key,
                    canonical(T_child.body))

        # 4b. Pin the parent by hash (this is the whole point of
        #     parent_ticket_id; at this point T_parent.sig has
        #     already been verified at step 3 or the previous
        #     iteration).
        expected_pref := sha256(HASH_PARENT_REF || T_parent.sig)[..16]
        require T_child.body.parent.parent_ticket_id == expected_pref

        # 4c. Monotone narrowing.
        require caps(T_child)      ⊆ caps(T_parent)
        require not_after(T_child) ≤ not_after(T_parent)
        require not_before(T_child) ≥ not_before(T_parent)

        # 4d. Depth monotone.
        expected_depth := match T_parent.body.parent {
            Some(d) => d.depth_remaining - 1,
            None    => MAX_DELEGATION_DEPTH - 1,
        }
        require T_child.body.parent.depth_remaining == expected_depth

        T_parent := T_child

    # 5. Terminal-specific checks (only the leaf governs new sessions)
    require now ∈ [terminal.not_before - SKEW_TOLERANCE, terminal.not_after]
    require compute_ticket_id(terminal) ∉ revocation_set
    for t in all_tickets:
        require compute_ticket_id(t) ∉ revocation_set   // ancestor revoke
                                                         //  kills descendants

compute_ticket_id(t) = sha256(HASH_TICKET_ID || t.sig)[..16]
resolved_issuer(t)   = t.body.issuer.unwrap_or(t.addr.endpoint_id)
```

`SKEW_TOLERANCE` is ±60 s on `not_before` (see `070-security.md §4`);
`not_after` is enforced strictly.

### Key invariants (enforced at verify time)

- **Verify-before-hash**: a parent's `sig` is NEVER used as a hash
   input until that sig has itself been verified. This closes the
   "plant a blob with a matching hash, then use its body to pick the
   child's key" class of attack.
- **Single verification key per child**: the child's sig is verified
   under `resolved_issuer(parent)` only — no fallback, no alternate
   key. If a parent was itself a root via `issuer: None`, the child
   is verified under `parent.addr.endpoint_id`.
- **Chain bytes are mandatory**: the verifier MUST NOT reconstruct or
   fetch parent tickets by `parent_ticket_id` from a cache, the DHT,
   or any other source. If `chain` doesn't contain the required
   bytes, the offer is rejected.
- **Ancestor revocation kills descendants**: revoking any ticket in
   the chain invalidates every leaf that descends from it.
- **Caps are monotone**: delegated tickets can only narrow, never
   broaden.
- **TTL is monotone** in both directions: a child's validity window
   must fit inside its parent's.
- **Depth is monotone**: `depth_remaining` strictly decreases down
   the chain, bounded by `MAX_DELEGATION_DEPTH = 8`.

## 4. Ticket lifecycle

```
          ┌─────── mint ────────────┐
          │                         │
          ▼                         │
   ┌────────────┐         ┌─────────┴────────┐
   │  ISSUED    │─────────│  (stored on disk)│
   └─────┬──────┘         └──────────────────┘
         │ paste / send out-of-band
         ▼
   ┌────────────┐
   │  IMPORTED  │   operator A presents to operator B
   └─────┬──────┘
         │ used
         ▼
   ┌────────────┐
   │  LIVE      │   in-flight sessions active
   └─┬────────┬─┘
     │        │
     │        │ not_after passed
     │        ▼
     │   ┌────────────┐
     │   │  EXPIRED   │
     │   └────────────┘
     │
     │ portl revoke
     ▼
   ┌────────────┐
   │  REVOKED   │  broadcast to relevant agents
   └────────────┘
```

## 5. Minting

### 5.1 Self-signed root (cold bootstrap)

```
agent generates secret S
agent derives endpoint_id = pubkey(S)
agent constructs PortlTicket {
    v: 1,
    addr:   EndpointAddr { endpoint_id, transports: [...agent config...] },
    body:   PortlBody {
        caps:        Capabilities { shell, tcp, ... } (= full self-ad),
        alpns_extra: [],
        not_before:  now,
        not_after:   now + 10 y,
        issuer:      None,                    // elided per §2.2
        parent:      None,
        nonce:       random,
        bearer:      None,
        to:          None,
    },
    sig:    ed25519_sign(S, canonical(body))
}
```

This ticket is limited in practical use on its own (it says "this
peer says you may reach itself"). Use case: cold bootstrap where the
agent's own `endpoint_id` is in `trust.roots` and the operator later
uses this ticket as a parent when delegating a usable narrowed
token.

### 5.2 Operator-issued root (the common case)

The agent's `trust.roots` contains the operator's public key `Ka`.
`Ka` signs a root ticket naming the agent's `endpoint_id`. Because
`trust.roots` authorises `Ka`, the agent accepts any ticket whose
chain ultimately roots in a `Ka` signature.

```
portl init                                   # creates Ka locally
# in agent env / deployment: PORTL_TRUST_ROOTS includes Ka.pub
portl mint --endpoint <endpoint_id> \
           --caps all --ttl 1y               # signs with Ka; this IS a root ticket
```

The resulting body has `issuer: Some(Ka_pub)` (not elided, because
`Ka != endpoint_id`).

### 5.3 Delegated (`portl share`)

```
portl share <peer> --caps shell,tcp:22 --ttl 24h --to <recipient-pub>
    │
    │ load operator identity Ka
    │ load parent ticket T (already trusted for <peer>)
    │ intersect requested caps ∩ T.caps  (must be ⊆)
    │ build child body with
    │     parent: Some(Delegation {
    │         parent_ticket_id: sha256("portl/parent/v1" || T.sig)[..16],
    │         depth_remaining:  T.body.parent.depth_remaining - 1
    │                           if T.body.parent.is_some()
    │                           else MAX_DELEGATION_DEPTH - 1,
    │     })
    │ sign with Ka
    ▼
    writes ticket bundle (terminal URI + parent chain) to stdout or -o file.
```

Delegation is asymmetric on purpose: you can only narrow. Bob cannot
re-widen back toward Alice's ticket even by re-signing; every cap in his
chain must appear in the parent's caps.

## 6. Revocation

Revocation is **advisory but enforced by every agent that pulls the list**.
The set of revocations for a given agent is a small file:

```
/var/lib/portl/revocations.jsonl
  { "ticket_id": "a1b2c3...", "reason": "leak",
    "revoked_at": 1734..., "revoked_by": <operator_pub> }
  { "ticket_id": "d4e5f6...", "reason": "rotation",
    ... }
```

Ways a revocation enters an agent:

1. **Operator push**: `portl revocations publish --to <peer>` sends records
   over `portl/meta/v1`.
2. **Automatic on delete**: `portl slicer vm delete <name>` auto-revokes
   all tickets targeting that node_id.
3. **Manual sync**: admin copies the file over out-of-band.
4. **Future**: pkarr/DHT-published revocation set (post v1).

Effect: the agent will refuse any `TicketOffer` whose `ticket_id` is in the
set, even if the signature and chain are valid.

## 7. Master tickets

A "master ticket" isn't a separate type — it's a ticket whose:

- `caps.tcp` grants reach to the orchestrator's HTTP API endpoint
  (e.g. `127.0.0.1:8080`),
- `bearer` field is non-empty (containing the slicer API token, or
  equivalent),
- target is a **gateway-mode agent** (a `portl-agent` running with
  `--mode gateway`; see `080-cli.md §2.1`) that proxies the HTTP API.

```
Master ticket for a slicer host gateway
───────────────────────────────────────
  node_id  : <node-id of the portl-agent --mode gateway
              running beside slicer-mac>
  alpns    : ["portl/tcp/v1"]
  caps     : tcp: [{ host: "127.0.0.1", port: 8080 }]
  bearer   : <base64 slicer API token; the gateway-mode agent injects
             "Authorization: Bearer <...>" into each tunnelled HTTP
             request>
  ttl      : ≤ 30 days (see 070-security.md §4.3a for bearer handling)
```

The bearer field only exists in master tickets. Regular per-peer tickets
omit it. Master tickets carry elevated risk (leaking the URL ≡ leaking
the API token it wraps) and should always be `to`-bound to a specific
operator; see `070-security.md §4.3a`.

## 8. Sharing UX

```
operator A                              operator B
─────────                               ─────────

$ portl share claude-1 \
   --caps shell,tcp:127.0.0.1:22 \
   --ttl 24h --to $PUB_B \
   -o bob.ticket

    (a narrowed delegated ticket
     written to bob.ticket)

   ─── hand off over any channel ──▶
                                        $ portl ticket import bob.ticket --as claude-1

                                        $ portl shell claude-1           # works
                                        $ portl tcp claude-1 -L 3000:... # fails:
                                                                         #   caps
                                                                         #   exclude
                                                                         #   port 3000
```

`--to <pubkey>` is optional. Tickets that omit `to` are bearer-style; any
holder can present them. Tickets with `to` bind usage to that operator's
public key — the agent requires a proof-of-key signature during the
handshake.

## 9. Proof-of-possession

When a ticket includes `to: Some(op_pubkey)`, it is bound to that
operator: the handshake requires a signature from `op_pubkey` to
prove possession of the corresponding private key. When `to` is
absent, the ticket is bearer-style and anyone holding the bytes can
present it.

The canonical `TicketOffer` / `TicketAck` wire format (see also
`040-protocols.md §1`):

```
TicketOffer {
    ticket        : Bytes,          // postcard-encoded PortlTicket
                                    //   (the terminal ticket)
    chain         : Vec<Bytes>,     // parent tickets, root-first;
                                    //   empty iff ticket is a root
    proof         : Option<Bytes>,  // ed25519 sig; required iff
                                    //   terminal.to is Some
    client_nonce  : [u8; 16],       // fresh random per offer
}

TicketAck {
    ok              : bool,
    reason          : Option<AckReason>,         // present iff !ok
    peer_token      : Option<[u8; 16]>,          // present iff ok
    effective_caps  : Option<Capabilities>,      // present iff ok
    server_time     : u64,                       // for clock-skew sanity
}
```

Notes:

- **`proof` computation when `to` is set**:
  ```
  proof = ed25519_sign(
              op_priv,
              sha256("portl/ticket-pop/v1" || ticket_id || client_nonce))
  ```
  where `ticket_id = compute_ticket_id(terminal)` (§2.3). The
  domain-separation tag and the inclusion of `ticket_id` (not just
  the nonce) prevent cross-protocol and cross-ticket signature
  reuse.
- **`chain` ordering**: root first. Verification follows §3.
- **`chain` is mandatory when required**: the verifier MUST NOT
  fetch or cache parent tickets by `parent_ticket_id`. If `chain`
  is missing any link, the offer is rejected.
- **No extra mutual challenge**: iroh's QUIC TLS already binds the
  peer's identity to the connection. Layering a second mutual
  challenge-response here adds complexity without closing any gap
  that matters at v0.1. (If/when a non-iroh data plane lands that
  doesn't bind identity at the transport layer, a transport-level
  mutual-auth turn is re-examined then.)

## 10. Size budget with concrete examples

All numbers below are after the v0.1 compression wins (§12): iroh's
`EndpointAddr` for dialing, `issuer` elision for self-signed roots,
`Delegation` carries only a 16-B `parent_ticket_id` + depth,
`Capabilities` uses a presence bitmap, `alpns_extra` is empty for
the routine ALPNs.

### 10.1 Minimal root — `portl mint --caps shell --ttl 24h`

Postcard byte-by-byte for a self-signed agent root:

```
v: u8 = 1                                                      1
addr: EndpointAddr
  endpoint_id: [u8; 32]                                       32
  transports: Vec<TransportAddr> len=2                         1
    - Ipv4Addr(192.0.2.5):63241  discriminant + 4 + 2          7
    - RelayUrl("https://euw1.relay.iroh.network")
        discriminant + varint(30) + 30 bytes                  32
body:
  caps: Capabilities
    presence: u8 = 0b00000001    (shell)                       1
    shell: Some(ShellCaps {
        user_allowlist: None,       1 (None tag)
        pty_allowed: true,          1
        exec_allowed: true,         1
        command_allowlist: None,    1
        env_policy: EnvPolicy::Deny 1 (tag only)
    })                                                         5
  alpns_extra: Vec<String> len=0                               1
  not_before: u64 varint (post-2020)                           5
  not_after:  u64 varint                                       5
  issuer:     None (self-signed root; elided)                  1
  parent:     None                                             1
  nonce:      [u8; 8]                                          8
  bearer:     None                                             1
  to:         None                                             1
sig: [u8; 64]                                                 64
────────────────────────────────────────────────────────────────
total                                                        167 B
base32-lowercase                                             268 chars
URI ("portl" prefix + base32)                                273 chars
```

### 10.2 Typical delegated — `portl share` over the above

Operator `Ka` (in `trust.roots`) issues a 24-h delegation to teammate
`Kb` authorising `shell` + `tcp:127.0.0.1:22` + `tcp:127.0.0.1:3000-3010`,
`--to $Kb_pub`.

Delta from §10.1:
```
body.caps.tcp: Some(Vec<PortRule> len=2)
  rule 1: host_glob "127.0.0.1" (varint 9 + 9) + ports 22+22  14
  rule 2: same host + 3000+3010                               14
  vec len header + presence bit flip                           1
  Some-body-header                                             1
                                                              +30
body.issuer: Some(Ka)                                         +33
body.parent: Some(Delegation {
    parent_ticket_id: [u8; 16]           16
    depth_remaining: u8                   1
    Some-tag                              1
})                                                            +18
body.to: Some([u8; 32])                                       +33
```

Note `parent` cost is only **+18 B**, not +99 B — that's the whole
point of §2.3 parent_ticket_id.

```
total                                                        281 B
base32-lowercase                                             450 chars
URI                                                          455 chars
```

### 10.3 Master ticket — slicer-adapter-issued gateway token

Same as §10.2 minus the `tcp:3000-3010` rule (gateway only needs
`127.0.0.1:8080`), plus a 48-B slicer API bearer token. `--to`-bound
per §07 `§4.3a`.

```
caps drops one port rule                                     −14 B
body.bearer: Some(Vec<u8> len=48)
  Some + varint(48) + 48                                     +50 B
                                                             ─────
total                                                        317 B
base32-lowercase                                             508 chars
URI                                                          513 chars
```

### 10.4 Three-level chain — only the terminal URI is shared

Root T0 by `Ka` → T1 delegated to team-lead `Kb` → T2 delegated to
dev `Kc`. Chain lengths:

| Level | Role | URI size | Notes |
| --- | --- | --- | --- |
| T0 | root, `issuer = Ka`, full `shell`+`tcp:*` | ~260 chars | kept on Ka's disk |
| T1 | `issuer = Kb`, shell + tcp:22,3000-3010, `to = Kb` | ~455 chars | kept on Kb's disk |
| T2 | `issuer = Kc`, shell + tcp:3000-3010, `to = Kc` | **~455 chars** | pasted to Kc |

Pasted URI size is **independent of chain depth** — parent bytes
travel over the wire in `TicketOffer.chain`:

```
TicketOffer wire size for T2 presentation:
  ticket (T2 postcard)                       ~281 B
  chain[0] = T0 postcard                     ~167 B
  chain[1] = T1 postcard                     ~281 B
  Vec<Bytes> framing                           ~6 B
  proof: Some([u8; 64])                       ~65 B
  client_nonce                                 16 B
────────────────────────────────────────────────────
total                                        ~816 B  (single QUIC MTU)
```

### 10.5 Worst-case "fat" ticket

Designed to stress the format: 6 transports, all caps populated,
5-level chain, 48-B bearer, allow-lists of ~10 items each.

```
addr (3 transports + 3 relays)                              ~170 B
body.caps (shell + user/cmd allowlists, 10 tcp, 5 udp,
  5 fs roots v0.2, vpn ULA pair, meta)                      ~730 B
body.alpns_extra: empty                                        1 B
body.{timestamps, nonce, issuer Some, bearer 48, to Some}   ~145 B
body.parent: Some(Delegation)                                ~18 B
sig                                                           64 B
─────────────────────────────────────────────────────────────────
total                                                     ~1128 B
base32-lowercase                                            ~1810 chars
URI                                                         ~1815 chars
```

Past the point where inline paste is sensible. `portl share ... -o
beefy.portl` / `portl ticket import -f beefy.portl` is the
prescribed workflow.

### 10.6 Summary

| Use case | Postcard B | URI chars |
| --- | --- | --- |
| §10.1 Minimal self-signed root | **167** | **273** |
| §10.2 Typical delegated, `to`-bound | **281** | **455** |
| §10.3 Master (gateway + 48-B bearer) | **317** | **513** |
| §10.4 3-level chain (terminal URI only) | **281** | **455** |
| §10.5 Fat ticket (file-only) | **~1130** | **~1815** |

Routine tickets fit in one ~500-char paste. Chained delegations do
not balloon the URI. File-based import handles the edge cases.

## 11. Relationship to iroh-tickets

See §2.1 for the `impl Ticket for PortlTicket` shape. Wire form is
`portl<base32-lowercase(postcard_bytes)>` — exactly iroh's pattern
with `KIND = "portl"`. This gives us:

- **Parseability in `ticket.iroh.computer`**: pasting a portl URI
  renders "kind: portl, N bytes" + a hex dump. Users debugging a
  bad paste can confirm the prefix and length without any portl
  tooling.
- **Reuse of `iroh_base::EndpointAddr`**: dialing semantics match
  every other iroh app; no custom relay encoding.
- **Serde + postcard dependency only**: no extra crypto/encoding
  crates for the URI shape.
- **Extensibility**: if someone forks portl and adds an adapter-
  specific ticket kind (`slicer-gw`, `docker-portl`, …) they pick a
  different `KIND` string and get the same plumbing for free.

The cost of this choice over, say, bech32m: no BCH error-detection
checksum. In practice postcard's frame and the ed25519 signature
are both catastrophic on any bit flip, so typos produce "decode
failed" errors rather than subtly-wrong results. The CLI always
prints `ticket_id` after import so operators can cross-check out-of-
band if they're paranoid.

## 12. Design decisions and tradeoffs

This section records the load-bearing tradeoffs in the ticket design
so future contributors can challenge them on the right axis.

### 12.1 Compression wins taken in v0.1

| Win | Mechanism | Per-ticket save | Why safe |
| --- | --- | --- | --- |
| Single data plane | `addr: EndpointAddr` (iroh's type) instead of custom `node_id + relays[]` | ~40 B | Matches `future/140-transport-abstraction.md` non-commitment |
| Postcard over CBOR | field-order encoding, no map keys | ~20% overall | Both are well-reviewed; postcard matches iroh |
| Kind-prefixed base32 (no bech32m) | follows iroh's `<KIND><base32>` | ~10 chars | Signature rejection catches typos |
| Elide `issuer` when == `addr.endpoint_id` | §2.2 canonicalization rule | 32 B for self-signed roots | `resolved_issuer()` is deterministic; MUST reject the non-canonical form |
| Shrink `parent` to `parent_ticket_id: [u8; 16]` | reference into the on-wire chain, domain-separated hash | 48 B per delegation level | Verify-before-hash order (§3); 2^128 second-preimage bound |
| Elide `parent_issuer` | extracted from parent body after chain-verify | 32 B per delegation level | Parent bytes are mandatory on wire, already sig-verified |
| Drop `alpns` field | derive from `Capabilities` presence bitmap | 15–25 B typical | `alpns_extra` reserved for future custom ALPNs only |
| `Capabilities` presence bitmap | one `u8` vs. six `Option<T>` tags | ~5 B | Postcard field elision is mandatory per §2.2 |

End-to-end effect: a minimal root went from ~345 URI chars in the
first draft (CBOR + bech32m + `node_id+relays[]`) to **~273 chars**
here. Typical delegated went from ~600 chars to **~455 chars**.
Chained delegations no longer grow the URI at all.

### 12.2 Compression alternatives rejected

| Alternative | Would save | Rejected because |
| --- | --- | --- |
| BLS-aggregated signatures across chain | 64 B per level, collapses n sigs to 1 | Breaks iroh compatibility; exotic crypto; single-sig shape is already fine |
| Reference-based tickets (URI = `id+sig`, body looked up) | ~150 B | Requires central registry or DHT; breaks zero-infrastructure property; first-time recipients have nothing to resolve against |
| Hash-committed caps (cap body pre-registered with agent) | 30–400 B | Requires cap registry pushed to every agent; breaks ad-hoc sharing |
| zstd over postcard | 5–10% | Tickets are signature- and pubkey-dense (high entropy); small win for added dep + CPU on verify |
| ALPN registry with small int tags | 10–20 B | Schema-version fragility; `alpns_extra` escape hatch retained for future |
| Day-granularity timestamp truncation | 4–8 B | Loses second-level revocation timing |
| Relay URL registry (common URLs → 1 B index) | 25 B per URL | Introduces coordinated registry ≡ centralization |
| Shorter nonce (`[u8; 4]`) | 4 B | `nonce` feeds into `ticket_id` → `to`-proof → revocation; 2^32 is not enough margin for a long-lived issuer |
| Hybrid "reference-for-roots, embed-for-leaves" | ~100 B on multi-level chains | Complicates caching/invalidation; saves bytes in the wrong place |

### 12.3 Security-critical subtleties

These aren't "tradeoffs" — they're invariants with sharp edges that
implementers and reviewers must hold in mind.

- **128-bit `ticket_id` and `parent_ticket_id` are auth inputs.**
  They're not just lookup keys. The `to`-proof binds to
  `ticket_id`; the chain links via `parent_ticket_id`. Domain
  separation (§2.3) is the reason a 2^64 birthday collision found
  in one context can't be replayed in another.
- **Verify-before-hash ordering in §3 is load-bearing.** If an
  implementation uses `parent_ticket_id` to *find* the parent
  before sig-verifying it, an attacker can plant a blob with a
  matching hash and use its body to pick the child's verification
  key. The spec's verification order closes this.
- **Canonicalization rejection is not optional.** Two encodings of
  "the same" ticket — for instance `issuer: Some(endpoint_id)` vs
  `issuer: None` — would have different `sig`s, different
  `ticket_id`s, and different revocation records. The §2.2 re-
  encode-and-reject rule exists to make this impossible.
- **Ancestor revocation kills descendants** (§3 step 5). Without
  this rule, a leaked intermediate delegator's ticket cannot be
  neutralised without reaching every leaf.
- **Strict Ed25519 verification.** Implementations MUST use
  ed25519-dalek's `verify_strict` (or equivalent): canonical `S`
  rejection, low-order point rejection. Lax verification expands
  the signature malleability surface and undermines ticket_id
  uniqueness.

### 12.4 Known accepted issues

- **Unsigned `addr.transports`**: the relay URLs and direct
  addresses in a URI are not covered by the signature, so an
  attacker who intercepts the URI before delivery can substitute
  adversary-controlled relays. iroh's QUIC end-to-end encryption
  prevents session MITM; the residual risk is targeted DoS or
  traffic analysis. Accepted for v0.1; matches iroh convention.
  See `070-security.md §4.5`.
- **Ad-hoc sharing of delegated tickets requires bundle, not URI
  alone**: a recipient of a delegated terminal URI cannot complete
  `TicketOffer.chain` without receiving the parent bytes out of
  band. `portl share ... -o bob.ticket` writes a multi-ticket
  bundle file. Single-URI paste works only for root tickets.
- **Inline `addr` can go stale**: the addresses a minter baked into
  a ticket may not reflect the agent's current network location.
  iroh's discovery layer (DNS, Pkarr, Local/mDNS) covers the
  common re-resolution case; operators who want bulletproof
  long-lived tickets SHOULD include relay URLs, not only direct
  addrs.
- **Master-ticket leak ≡ credential leak**: a ticket with non-empty
  `bearer` carries a real API credential and MUST be treated
  accordingly. Short TTLs (≤ 30 d enforced at mint), mandatory
  `to`-binding, audit-log bearer redaction. See `070-security.md
  §4.3a`.

### 12.5 When to revisit

Schedule a revisit of this design when any of the following become
true:

- A second genuine data plane ships (WebRTC, Loom/AWDL,
  BLE/LoRa). That would motivate a `transports[]` array and a v2
  schema. See `future/140-transport-abstraction.md`.
- Birthday-collision cost on SHA-256 drops below ~2^60. Domain
  separation is the mitigation today; a genuine break would force
  a full 32-B hash migration.
- PQ-transition requirement materialises. Would bump the schema
  version to add hybrid ed25519+ML-DSA signatures.
- Ticket-size complaints surface in practice. If the 455-char
  typical-URI becomes a user-experience bottleneck we haven't
  anticipated (say, a specific chat client breaks on it), we
  revisit compression-without-breaking-iroh-compat ideas.
