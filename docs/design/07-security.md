# 07 — Security model

## 1. Trust hierarchy

```
   operator identity key (Ka)
          │
          │   signs
          ▼
   root ticket for node_id Kv       ◄── accepted iff Ka ∈ agent.trust.roots
          │
          │   delegates
          ▼
   narrowed ticket held by someone else
          │
          │   delegates
          ▼
   even narrower ticket
          │
          │   (bounded by agent.max_delegation_depth)
          ▼
   …
```

Authority flows downward; every delegation is monotone narrowing.

## 2. What's trusted, by whom, for what

| Actor | Trusts | For what |
| --- | --- | --- |
| Agent | own secret on disk | its own identity |
| Agent | keys in `trust.roots` | issuing root tickets it will honour |
| Agent | local policy file | hard ceiling on any ticket's caps |
| Agent | revocation file | authoritative "not this ticket" list |
| Operator | operator identity key | signing tickets they issue |
| Operator | tickets on disk | authority to do what they say |
| Operator | relay pubkey pin (optional) | avoid MITM against a specific relay |
| Relay | its own secret | stable address for peers to rendezvous |
| Client CLI | nothing beyond the above | — |

Explicit non-trust:

- Agent does **not** trust the client CLI's self-declared caps.
- Agent does **not** trust the relay with message contents (QUIC E2E
  encrypted).
- Operator does **not** need to trust the relay; relay can drop but not
  read.
- Clients do **not** trust DNS or pkarr to give the right addresses; the
  node-id is cryptographically verified during QUIC handshake.

## 3. Data plane confidentiality

```
                  ┌──────────────┐                 ┌──────────────┐
   payload ──►    │   encrypt    │ ──── bytes ──►  │   decrypt    │ ──► payload
                  │  QUIC+TLS1.3 │                 │  QUIC+TLS1.3 │
                  │ (ed25519 ID) │                 │ (ed25519 ID) │
                  └──────────────┘                 └──────────────┘
                  client                            agent
                        │                                │
                        │     if relay in path           │
                        │    ┌──────────────┐            │
                        └───►│    RELAY     │───────────►│
                             │  (ciphertext │
                             │   only)      │
                             └──────────────┘
```

No intermediary can read traffic; relay sees only node-id-addressed
ciphertext.

## 4. Threat model

Each threat, its impact, and the mitigation.

### 4.1 Stolen operator key (Ka)

**Impact.** Attacker can mint tickets for any target that already trusts
Ka.

**Mitigation.**
- Keep Ka on hardware (YubiKey, Secure Enclave) when possible.
- Operators may keep a *separate* identity per fleet.
- Rotation plan: generate Ka', push Ka' to each agent's `trust.roots`,
  remove Ka, re-mint all in-flight tickets under Ka'.
- Revocation can't help — Ka was the signer, not a specific ticket.

### 4.2 Stolen agent key (Kv)

**Impact.** Attacker can impersonate the target. With the key, they can
decrypt past captured traffic destined for Kv (but only if you didn't use
PFS — QUIC does, so this is mostly a concern for key-compromise going
forward).

**Mitigation.**
- Agents rotate keys on a schedule (e.g. 30 days); old keys published to
  revocation list.
- Operators re-issue root tickets after rotation.
- For ephemeral VMs, rotation is implicit: a new VM has a new key.

### 4.3 Ticket leak (attacker captures a delegated ticket)

**Impact.** Attacker can use the ticket within its caps + TTL.

**Mitigation.**
- Short TTLs on delegated tickets (24h default).
- `to <pubkey>` binding + proof-of-possession to require possession of the
  operator key who was intended to receive it.
- Revocation set the moment leak is suspected.

### 4.3a Master-ticket / bearer leak (elevated-risk variant)

**Impact.** A ticket carrying a non-empty `bearer` field (master
tickets, see `03-tickets.md §7`) is equivalent to leaking the wrapped
credential itself (slicer API token, cloud IAM bearer, etc.). The
gateway injects this credential into every proxied request, so an
attacker who decodes the CBOR can skip portl entirely and hit the
underlying API directly.

Treat a master ticket with the same care as an SSH private key or
raw API token — **not** as a narrow capability ticket.

**Mitigation.**
- Short TTLs (7d max recommended; we enforce ≤30d at mint time).
- Always `to`-bind master tickets; never hand out bearer-style
  master tickets.
- Rotate the underlying credential frequently; on rotation, revoke
  every outstanding master ticket that wrapped the old value.
- Store master tickets outside of `portl ticket list` default output;
  they appear only with `portl ticket list --include-master`.
- Audit log redacts the bearer bytes, logging only a SHA-256 prefix.

### 4.4 Compromised relay

**Impact.** Can drop traffic (DoS); cannot read (encrypted).

**Mitigation.**
- Multiple relay hints per ticket.
- Clients fall through the hint list.
- Self-hosted relay + community fallback.
- Optionally pin relay node-id.

### 4.5 Compromised DHT / pkarr

**Impact.** Can return wrong addresses → attacker hopes to MITM.

**Mitigation.**
- QUIC handshake requires the peer to present a signature by the node-id
  in the ticket; attacker without Kv can't complete it.
- Discovery is strictly a performance hint; correctness relies on the
  public-key handshake.

### 4.6 Compromised agent host

**Impact.** Game over for that target. Attacker holds Kv, all local data,
all bearer tokens routed through that host (if it's a gateway).

**Mitigation.**
- Per-target isolation is orthogonal to portl; run separate
  hosts/VMs/containers for anything with different blast radius.
- Revoke the root ticket for that node_id; rotate `trust.roots` on other
  agents if Kv was reused (it shouldn't be).

### 4.7 Malicious operator CLI build

**Impact.** Could silently exfiltrate Ka or tickets.

**Mitigation.**
- Reproducible builds for `portl-cli` releases.
- Published binaries signed by a cold key.
- Users who care run from source.

### 4.8 Operator opens `portl shell peer` against a malicious peer

**Impact.** Peer gets bytes the operator sends to stdin; peer can present
a fake shell prompt; the operator could be tricked into typing secrets.

**Mitigation.**
- Peer identity (node_id) shown at connect time; operator visually
  verifies.
- Operators only `portl shell` into peers whose tickets they trust; the
  ticket authorizes you TO them, so you chose this.
- Agent-side: no impact — agent is serving, not consuming.

### 4.9 Replay attacks

**Impact.** Re-sending captured `TicketOffer` to re-establish a session.

**Mitigation.**
- `TicketOffer.client_nonce` is fresh random per offer.
- For `to`-bound tickets, `proof` is `sign(op_priv, tag || ticket_id ||
  client_nonce)`, so replay requires both the original nonce and
  `op_priv`.
- `peer_token` is bound to the QUIC connection and does not survive
  disconnect.
- Agent re-verifies ticket on each fresh connection; no ticket-level
  nonce cache needed.

### 4.10 DoS — rate-limit taxonomy

Pre-authentication CPU exhaustion (e.g. Ed25519-verify floods) is
real; the pipeline in `02-architecture.md §4` enforces these layers
in order, cheapest first:

1. **Per-source-IP connection cap** (applied before QUIC handshake
   completes): default 16 concurrent, 64/minute burst.
2. **QUIC retry / address-validation** (built in to quinn).
3. **Per-source-node-id connection cap** (applied after QUIC handshake
   reveals peer identity): default 8 concurrent.
4. **`ticket/v1` offer rate**: 10/sec/node_id, then 429
   `Error::RateLimited` with `retry_after_ms` set.
5. **Stream-open rate**: 100/sec/connection.
6. **Datagram rate** (`udp/v1`, `vpn/v1`): 10k/sec/session, drop excess
   silently (UDP semantics).
7. **`fs/v1` list/stat rate** (v0.2): 100 ops/sec/connection.
8. **Shell-spawn rate** (`shell/v1` ShellReq): 5/min/node_id.
9. **Revocation publish rate** (`meta/v1 PublishRevocations`): 1/sec/
   node_id, at most 1000 records per batch.

All limits are configurable under `[limits]` in the agent config.
Exceeded limits increment metrics counters (`09-config.md §7`) so
operators can see abuse in real time.

Relay-level DoS is out of scope for the agent; operators that self-host
an iroh-relay configure ACLs there.

## 4.11 Clock skew

Ticket validity checks use `not_before` and `not_after` in unix
seconds. Agents and operators in cloud VMs regularly drift by a few
seconds, and agents in suspended slicer VMs can drift by *minutes*
between resume events.

- **`not_before`**: accept a window of `now + SKEW_TOLERANCE`, default
  **60 s**, configurable per-agent. A ticket minted exactly "now" on
  a laptop with a slightly-ahead clock must still be usable.
- **`not_after`**: enforce strictly. The cost of accepting an expired
  ticket is worse than the cost of a brief un-mintable window.
- **Already-open sessions**: not terminated when their ticket expires.
  The TTL gates *new sessions*; live sessions continue until one side
  closes. This is an explicit policy; the alternative (mid-session
  revalidation with kill) is available only via `portl sessions kill`
  or an explicit revocation push.
- **Clock-source guidance**: agents SHOULD run chrony/systemd-timesyncd
  / equivalent. `portl agent status` warns if the system clock is
  more than 30 s from the agent's last-seen `TicketOffer.client_time`
  or from a system NTP source.

## 4.12 Revocation-set GC

The revocation set would grow unboundedly if records were never
evicted. Policy:

```
RevocationRecord { ticket_id, reason, revoked_at, not_after_of_ticket }

GC rule: drop records where
    revoked_at + REVOCATION_LINGER < now
    AND (not_after_of_ticket == 0 OR not_after_of_ticket < now)
```

`REVOCATION_LINGER` default is **7 days past the ticket's original
`not_after`**. This guarantees that an agent pulling a revocation
feed within a week of ticket expiry still sees the record — enough
to defeat replay races against slightly-late-expiring tickets.

Operators who want longer retention (forensics, compliance) can bump
`REVOCATION_LINGER` in agent config; the storage cost is trivial
(100s of bytes per record) but the threat-mitigation value plateaus
quickly.

## 5. Key custody recommendations

| Where | Permission | Owner | File |
| --- | --- | --- | --- |
| operator laptop | 0600 | user | `~/.config/portl/identity.key` |
| operator laptop (hardware) | — | user | smartcard-backed equivalent |
| agent host | 0400 | root | `/var/lib/portl/secret` |
| relay host | 0400 | root | `/var/lib/portl-relay/secret` |
| backups | encrypted at rest | user | GPG-wrapped copy |

Never commit any `.key` or `/var/lib/portl/secret` equivalent to source
control. `portl id export` writes an **encrypted** tarball gated on a
passphrase, for backup.

## 6. Audit

Every accepted session emits an `AuditRecord`:

```
AuditRecord {
    timestamp      : u64,
    peer_node_id   : Bytes(32),
    ticket_id      : Bytes(16),
    ticket_issuer  : Bytes(32),
    alpn           : Text,
    cap_snapshot   : Capabilities,
    bytes_in       : u64,
    bytes_out      : u64,
    duration_ms    : u64,
    close_reason   : Text,
}
```

Sink is configurable: journald, file (JSONL), or an adapter-specific
store. The agent *always* logs; disabling audit requires recompilation.

Rejections are logged too, with a separate counter per `(peer, reason)`
so repeated attempts are visible without flooding:

```
RejectRecord { timestamp, peer_node_id, reason, detail, count_in_window }
```

## 7. Compliance & safety surface

- **TLS**: entirely handled by `quinn`/`rustls`. No custom crypto.
- **PQC**: not in v0.1. When required, migration will bump the ticket
  version (v1 → vN for the PQ-capable schema) and introduce hybrid
  ed25519+ML-DSA signatures. There is no wire-format commitment to a
  specific version bump yet; other schema changes (e.g. adding a
  `transports[]` array for alternate data planes) may land first and
  consume v2.
- **Export control**: standard crypto (TLS/ChaCha20-Poly1305/AES-GCM/
  ed25519). No export-restricted algorithms.
- **FIPS**: not targeted. If needed, swap `rustls` for a FIPS-validated
  provider at build time.

## 8. What portl cannot protect against

To be explicit:

- **Supply-chain attacks on dependencies** (you trust the Cargo
  ecosystem).
- **Rubber-hose** attacks on the operator or target keyholder.
- **Traffic analysis** that observes timing / volume.
- **Correlated metadata** (the relay knows "A talked to B", even if it
  can't read the conversation).
- **Compromised hardware** (CPU-level, firmware-level).

These are explicit non-goals; a user with these threats needs additional
layers (Tor, airgap, HSM, etc.).

## 9. Security review checklist (for release)

- [ ] `unsafe` usage audit across all crates.
- [ ] `cargo deny` + `cargo audit` clean.
- [ ] Fuzz targets for: ticket decoder, protocol frame parsers.
- [ ] Integration test: revoked ticket rejected within 1s on all agents.
- [ ] Integration test: delegated ticket wider than parent rejected.
- [ ] Integration test: TLS handshake with a fake node-id fails closed.
- [ ] Third-party review of `portl-core/crypto.rs` (the only place we
  touch signatures directly).
- [ ] Docs: this file is current.
