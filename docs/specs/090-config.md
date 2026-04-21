# 09 — Config, on-disk state, file layout

> **Note:** this document describes the v0.1 layout, including
> `agent.toml` and the SQLite alias store. v0.2 replaces both with
> env-var-only config and a JSON alias store; see
> [`140-v0.2-operability.md §8-§9`](140-v0.2-operability.md#8-environment-and-configuration).

## 1. Client (operator) layout
+
+> **Historical layout warning.** The tree below is the v0.1 shape.
+> Shipped v0.2.0 replaces `agent.toml` with env-only config and
+> `aliases.sqlite` with `aliases.json`. Keep this section for
+> provenance, not as the current deployment recipe.

```
~/.config/portl/
├── config.toml
├── identity.key                   0600   ed25519 secret
├── identity.pub                   0644   hex pubkey for sharing
├── tickets/
│   ├── claude-1.ticket            0600   portl1... blob (one per line)
│   ├── sbox-3.ticket              0600
│   └── master-homelab.ticket      0600
├── revocations.jsonl              0600   locally-known revocations
└── adapters/
    └── slicer.toml                       adapter-specific config
~/.local/state/portl/
├── peers.sqlite                          address book + path history
└── logs/
    ├── client.log                        rotated
    └── forwards.log
```

### 1.1 `config.toml` (annotated)

```toml
# ~/.config/portl/config.toml

[defaults]
relay_fallbacks = [
    "https://relay.n0.computer",           # community default
    "https://relay.myhomelab.xyz",         # self-hosted
]
log_level      = "info"
prefer_direct  = true                       # wait up to connect_grace_ms
                                            #   for a direct path before
                                            #   committing to relay
connect_grace_ms = 750

[alias]
home = "master-homelab"
sbox = "slicer-sbox-1"

[discovery]
pkarr_publish   = false                    # opt-in
pkarr_lookup    = true                     # use DHT on connect when needed
ticket_hints    = true                     # trust relay hints inside tickets

[vpn]
ula_prefix      = "fd7a::/32"
tun_name        = "portl0"
mtu             = 1200
dns_stub_listen = "127.0.0.53:53"
dns_suffix      = "portl.local"

[audit.client]
enabled         = true
sink            = "file"
path            = "~/.local/state/portl/logs/client.log"
```

### 1.2 Ticket file format

One ticket URI per line:

```
portl1ey3xqyn5wx4nsazd6vy2ytfr7tywmzc3x4hw6f5fmuw2u4kv9qmxpx8a4ah...
```

Filename is the alias. Files are atomic (write temp, rename).

## 2. Agent layout

```
/var/lib/portl/
├── secret                         0400 root:root  ed25519 secret
├── revocations.jsonl              0400 root:root
├── audit.log                      0640 root:adm   (if file sink)
└── enroll.once                              legacy
/etc/portl/
├── agent.toml                     0644
└── policy.d/
    ├── 10-defaults.toml
    └── 20-operator-overlay.toml
/run/portl/
└── agent.sock                     0660 root:portl unix socket for
                                            `portl agent <subcmd>`
```

### 2.1 `agent.toml`

```toml
# /etc/portl/agent.toml

identity_key = "/var/lib/portl/secret"

max_concurrent_connections      = 64
max_streams_per_connection      = 64
handshake_timeout_ms            = 5000
clock_skew_tolerance_secs       = 60      # ±window on not_before

[listen]
relays = ["https://relay.myhomelab.xyz"]

[discovery]
# See 020-architecture.md §11. These map directly to iroh's Discovery
# services; portl-core::discovery translates the flags into iroh
# DiscoveryBuilder options.
dns   = true    # iroh DNS discovery (default origin dns.iroh.link)
pkarr = true    # signed records, served over DNS
local = true    # mDNS-like multicast on attached LANs
dht   = false   # opt-in Mainline DHT

# Advanced: override iroh's DNS server (self-hosted iroh-dns-server)
# dns_origin = "dns.example.com"

[limits]
# See 070-security.md §4.10 for the full rate-limit taxonomy.
per_src_ip_concurrent        = 16
per_src_ip_burst_per_minute  = 64
per_node_id_concurrent       = 8
ticket_offers_per_sec        = 10
stream_opens_per_sec         = 100
shell_spawns_per_minute      = 5
revocation_publishes_per_sec = 1

[udp]
session_linger_secs  = 60      # agent holds UDP session state this long
                               # after QUIC disconnect, allowing mosh-
                               # style roaming via ticket re-present

[metrics]
# Prometheus text format on a local-only unix socket.
# Empty string disables the metrics endpoint.
socket = "/run/portl/metrics.sock"

[trust]
roots = [
    "a1b2c3d4e5f6...",                   # operator-Ka hex
    "f9e8d7c6b5a4..."                    # rotation successor Ka'
]
max_delegation_depth = 3

[policy.shell]
enabled          = true
allowed_users    = ["ubuntu", "root"]
pty_allowed      = true
exec_allowed     = true
command_allowlist = []                    # empty = no restriction

[policy.tcp]
enabled = true
rules = [
    { host_glob = "127.0.0.1", port_min = 22,    port_max = 22    },
    { host_glob = "127.0.0.1", port_min = 1024,  port_max = 65535 },
]

[policy.udp]
enabled = true
rules = [
    { host_glob = "127.0.0.1", port_min = 60000, port_max = 61000 }
]

[policy.fs]
enabled  = true
roots    = ["/home/ubuntu", "/workspace"]
readonly = false
max_size = 10737418240                    # 10 GiB per transfer

[policy.vpn]
enabled = false

[audit]
sink = "journald"                         # or "file" or "stderr"
# path = "/var/log/portl/audit.log"       # only if sink = "file"
rotate_mb       = 64
retain_days     = 30
redact_payloads = true
```

### 2.2 Policy precedence

```
[effective caps for a session]
  = ticket.caps
  ∩ agent.policy.*  (per-ALPN rules)
  ∩ dynamic overlays from /etc/portl/policy.d/ (alphabetical)
```

Everything is intersection; no rule can widen.

## 3. Adapter config (example: slicer)

```toml
# ~/.config/portl/adapters/slicer.toml

master_ticket_alias = "master-homelab"

[defaults.userdata]
portl_release_url   = "https://github.com/KnickKnackLabs/portl/releases/download/v0.1.0"

[defaults.relays]
list = ["https://relay.myhomelab.xyz"]

[defaults.policy]
shell_users = ["ubuntu"]
```

## 4. State sqlite schema (client)

```sql
PRAGMA user_version = 1;

CREATE TABLE peers (
    node_id       BLOB  PRIMARY KEY,
    alias         TEXT  UNIQUE,
    first_seen    INTEGER,
    last_seen     INTEGER,
    caps_hash     BLOB,
    path_last     TEXT,       -- "direct" | "relay:<url>" | "lan"
    discovery_src TEXT         -- "dns" | "pkarr" | "local" | "dht" | "ticket"
);

CREATE TABLE path_history (
    node_id    BLOB,
    ts         INTEGER,
    path       TEXT,
    rtt_us     INTEGER,
    bytes_in   INTEGER,
    bytes_out  INTEGER
);

CREATE INDEX idx_ph_node_ts ON path_history(node_id, ts);
```

Bounded retention (e.g. 30 days of path_history); vacuumed on startup.

### 4.1 Migration strategy

Schema changes are forward-only. Each crate that owns a SQLite file
ships a numbered migration sequence; on open, the client:

1. Reads `PRAGMA user_version`.
2. If < current, runs every migration file numbered in `(user_version
   .. current]` inside a single transaction.
3. Sets `PRAGMA user_version = current`.

Migrations are additive in spirit (new tables, new nullable columns).
Column-type changes or drops require an explicit rebuild migration
that copies into a new table. No framework (sqlx-migrate etc.) — the
migration set is small enough for a hand-written `&[(u32, &str)]`
constant per crate.

Agents own `/var/lib/portl/agent.sqlite` (revocations, audit index,
peer_token cache); the same pattern applies there.

## 4a. Metrics endpoint

The agent exposes a Prometheus text-format endpoint at the path in
`[metrics].socket` (unix-socket only; never a TCP port by default).
Scrape with `curl --unix-socket /run/portl/metrics.sock http://unused/`.

Core counters / gauges (stable across v0.x):

```
portl_connections_open               gauge, labels: {path}
portl_streams_open                   gauge, labels: {alpn}
portl_ticket_offers_total            counter, labels: {outcome}
portl_ticket_verifies_total          counter, labels: {outcome}
portl_handshake_duration_seconds     histogram
portl_stream_bytes_total             counter, labels: {alpn, dir}
portl_rate_limited_total             counter, labels: {kind}
portl_revocation_set_size            gauge
portl_discovery_resolutions_total    counter, labels: {service, outcome}
```

`{outcome}` is the `AckReason` enum from `040-protocols.md §1`. See
`070-security.md §4.10` for `{kind}` enumeration.

## 5. Directories by OS

```
Linux           macOS                               Windows
~/.config/portl ~/Library/Application Support/portl %APPDATA%\portl
~/.local/state  ~/Library/Logs/portl                %LOCALAPPDATA%\portl\state
```

v1 targets Linux + macOS. Windows client is best-effort; Windows agent
is post-v1.

## 6. Environment variables (already listed in 080-cli §5)

## 7. Secret lifecycle

```
operator identity key
  │
  │   portl id new                (or generated implicitly on first use)
  ▼
~/.config/portl/identity.key
  │
  │   portl id export             (backup, age-encrypted)
  ▼
encrypted tarball


agent secret
  │
  │   generated by operator CLI during portl <adapter> vm add
  │   delivered to target via adapter-specific path
  ▼
/var/lib/portl/secret            (on target)
  │
  │   rotation: generate new S', deliver, restart, publish revocation
  ▼
/var/lib/portl/secret            (overwritten)
```

## 8. File permissions summary

| File | Mode | Owner | Notes |
| --- | --- | --- | --- |
| `identity.key` | 0600 | user | must not be group/world readable |
| `tickets/*.ticket` | 0600 | user | loose with caps, strict with files |
| `revocations.jsonl` (client) | 0600 | user | — |
| `peers.sqlite` | 0600 | user | — |
| `/var/lib/portl/secret` | 0400 | root | agent reads once at startup |
| `/etc/portl/agent.toml` | 0644 | root | readable by operators on host |
| `audit.log` (file sink) | 0640 | root:adm | — |

## 9. Portability of the on-disk format

- Ticket file format is the portl1 URI; copy/pasteable between machines.
- `identity.key` is raw 32-byte ed25519 secret; portable across OSes.
- `peers.sqlite` is SQLite — portable; re-generable from tickets.
- Revocation file is ndjson; mergeable with `sort -u`.

Moving from one laptop to another:

```
portl id export ~/backup/portl-identity.tar.age
rsync -a ~/.config/portl/ new-laptop:~/.config/portl/
# on new laptop:
portl id import ~/portl-identity.tar.age
# everything else is already copied
```
