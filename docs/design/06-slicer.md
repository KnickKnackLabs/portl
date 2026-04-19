# 06 — Slicer adapter

## 1. Shape

`slicer-portl` is:

- A crate that implements `Bootstrapper` against the slicer HTTP API.
- A binary (`portl-slicer-adapter`) that registers as `portl slicer ...`.
- A small userdata script template that installs `portl` and enables
  `portl-agent.service` inside the
  VM and points it at the slicer-delivered secret.

## 2. End-to-end: `portl slicer vm add`

```
operator                 portl-cli           slicer-portl adapter    slicer API      VM bootup
   │                          │                      │                    │              │
   │ portl slicer vm add sbox --tag agent=claude     │                    │              │
   │────────────────────────►│                      │                    │              │
   │                          │                      │                    │              │
   │                          │ SecretKey::generate │                    │              │
   │                          │ node_id = pubkey(S) │                    │              │
   │                          │                      │                    │              │
   │                          │ adapter.provision(..)│                    │              │
   │                          │────────────────────►│                    │              │
   │                          │                      │                    │              │
   │                          │                      │ POST /secret       │              │
   │                          │                      │   name=portl-<id>  │              │
   │                          │                      │   body=S bytes     │              │
   │                          │                      │───────────────────►│              │
   │                          │                      │◄── 200 OK          │              │
   │                          │                      │                    │              │
   │                          │                      │ POST /vm/add       │              │
   │                          │                      │   group=sbox       │              │
   │                          │                      │   secrets=portl-.. │              │
   │                          │                      │   tag portl_node=  │              │
   │                          │                      │   userdata=        │              │
   │                          │                      │     (install.sh)   │              │
   │                          │                      │───────────────────►│              │
   │                          │                      │◄── 200 VM ready    │              │
   │                          │◄── TargetHandle      │                    │              │
   │                          │                                             ──── boot ──►│
   │                          │                                                          │
   │                          │                                     /run/slicer/secrets/ │
   │                          │                                     portl-<id> is        │
   │                          │                                     readable by systemd  │
   │                          │                                     unit                 │
   │                          │                                                          │
   │                          │                                        systemctl start   │
   │                          │                                        portl-agent       │
   │                          │                                                          │
   │                          │                                        agent:            │
   │                          │                                          load S          │
   │                          │                                          bind iroh       │
   │                          │                                          advertise       │
   │                          │                                                          │
   │                          │ (poll) meta/v1 ping ─────────────────────────────────── │
   │                          │◄────────── pong ───────────────────────────────────────│
   │                          │                                                          │
   │                          │ mint root ticket                                         │
   │                          │   issuer = operator (Ka)                                 │
   │                          │   node_id = pubkey(S)                                    │
   │                          │   caps = full                                            │
   │                          │   ttl = 1y  (configurable)                               │
   │                          │   sign(Ka)                                               │
   │                          │                                                          │
   │                          │ save ~/.config/portl/tickets/<alias>.ticket              │
   │                          │                                                          │
   │◄── Ticket: portl1eyJ...  Alias: claude-1                                            │
```

## 3. Userdata template

```bash
#!/bin/bash
# Injected by slicer-portl during vm add.
# Assumes: /run/slicer/secrets/portl-<id>  contains the ed25519 secret.
set -euo pipefail

SECRET_SRC="/run/slicer/secrets/{{SECRET_NAME}}"
SECRET_DST="/var/lib/portl/secret"

install -d -m 0750 /var/lib/portl
install -d -m 0755 /etc/portl

cp "$SECRET_SRC" "$SECRET_DST"
chmod 0400 "$SECRET_DST"

# Fetch the portl multicall binary (baked in for mature image;
#   downloaded here for iteration). Installs the `portl-agent`
#   symlink so existing systemd units and operator muscle memory
#   keep working.
if ! command -v portl >/dev/null 2>&1; then
  arkade get portl --path /usr/local/bin || \
    curl -fsSL https://{{PORTL_RELEASE_URL}}/portl-aarch64-linux \
      -o /usr/local/bin/portl
  chmod +x /usr/local/bin/portl
fi
ln -sf /usr/local/bin/portl /usr/local/bin/portl-agent

cat > /etc/portl/agent.toml <<'TOML'
identity_key = "/var/lib/portl/secret"
max_concurrent_connections = 64

[listen]
relays = {{RELAY_LIST}}
discovery = ["ticket-hints"]

[trust]
roots = ["{{OPERATOR_PUBKEY}}"]
max_delegation_depth = 3

[policy.shell]
enabled = true
allowed_users = ["ubuntu", "root"]
pty_allowed = true
exec_allowed = true

[policy.tcp]
enabled = true
rules = [
  { host_glob = "127.0.0.1", port_min = 1,    port_max = 65535 }
]

[policy.udp]
enabled = true
rules = [
  { host_glob = "127.0.0.1", port_min = 1,    port_max = 65535 }
]

[policy.fs]
enabled = true
roots = ["/home"]
readonly = false

[policy.vpn]
enabled = false

[audit]
sink = "journald"
TOML

cat > /etc/systemd/system/portl-agent.service <<'UNIT'
[Unit]
Description=portl agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/portl agent run --config /etc/portl/agent.toml
Restart=always
RestartSec=2
DynamicUser=no
User=root

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now portl-agent
```

Template variables (`{{NAME}}`) are substituted by the adapter before
POSTing to slicer's `/vm/add`.

## 4. Gateway for the slicer API itself

A `portl-agent` running with `--mode gateway` lives on the slicer host
and gives the daemon's HTTP API an iroh-addressable face. ("Gateway
mode" is a flag on the normal agent binary; there is no separate
`portl-gw` binary in v0.1 — see `08-cli.md §2.1`.)

```
 host (where slicer-mac or slicer is running)

  ┌──────────────────────────────────────────────────┐
  │ slicer-mac / slicer daemon                       │
  │   HTTP API on unix:///.../slicer.sock             │
  │                   or 127.0.0.1:8080              │
  │                                                  │
  │   ┌─── portl-agent --mode gateway ─────────┐     │
  │   │                                        │     │
  │   │   iroh endpoint (its own key)          │     │
  │   │     ALPN=tcp/v1                        │     │
  │   │                                        │     │
  │   │   on accept:                           │     │
  │   │     verify ticket (has bearer field)   │     │
  │   │     open conn to slicer API            │     │
  │   │     inject bearer token from           │     │
  │   │       the master ticket                │     │
  │   │     bidirectional pipe                 │     │
  │   └────────────────────────────────────────┘     │
  └──────────────────────────────────────────────────┘
             ▲
             │ QUIC
             ▼
  operator laptop
     portl-cli uses master ticket → speaks TCP → gets HTTP
     (behaves as if slicer HTTP is on localhost)
```

In effect the gateway agent is a specialized `tcp/v1` target whose
only "port" is the slicer API, with the authorization token pre-loaded
so the operator's ticket is the only thing on the wire that proves
authority.

## 5. Master ticket mint workflow

```
 host admin            slicer daemon    portl-agent (gw)     operator
   │                        │               │                  │
   │ slicer install         │               │                  │
   │ generate operator identity (if first time)                 │
   │                        │               │                  │
   │ install portl-agent    │               │                  │
   │   binary + systemd unit│               │                  │
   │   `portl-agent enroll` │               │                  │
   │     (generates Kv)     │               │                  │
   │   → node_id G          │               │                  │
   │                        │               │                  │
   │ slicer token fetch  ───►               │                  │
   │◄── bearer B ───────────                │                  │
   │                        │               │                  │
   │ mint master ticket locally             │                  │
   │   node_id = G          │               │                  │
   │   caps.tcp = [127.0.0.1:8080]          │                  │
   │   bearer  = B          │               │                  │
   │   sign(operator identity)              │                  │
   │                        │               │                  │
   │ display master ticket  │               │                  │
   │────────────────────────────────────────────────────────► │
   │                        │               │                  │
   │                                                            │
   │                                 portl ticket import MASTER
   │                                 portl slicer vm add ...
```

## 6. Revocation on delete

```
portl slicer vm delete claude-1
   │
   │ adapter.deprovision(handle)
   ▼
slicer API: DELETE /vm/claude-1
   │
   │ after ok:
   ▼
portl-core:
   compute ticket_id of the per-VM root ticket
   append to ~/.config/portl/revocations.jsonl
   meta/v1 PublishRevocations to any peer agents that
     trust the operator root (best-effort; may be offline)
   delete ~/.config/portl/tickets/claude-1.ticket
```

If the VM is gone the revocation is mostly paperwork: no one can reach
that node_id because the agent is dead. But if a cloned disk image is
ever brought up, the revocation stops tickets minted before deletion from
suddenly working again.

## 7. Slicer subcommands exposed by the adapter

```
portl slicer login <master-ticket>
portl slicer vm add <group> [--cpus|--ram-gb|--tag|...] [--ticket-out PATH]
portl slicer vm list                      # slicer VMs + portl ticket status
portl slicer vm delete <name>
portl slicer vm shell <name>              # = portl shell <name> (alias)
portl slicer vm logs <name>
portl slicer vm pause|resume|suspend|...  # mirrors slicer vm ...

portl slicer ticket-recover <name>        # if local ticket was lost
portl slicer ticket-rotate <name>         # replace ticket with a fresh one
```

Subcommand routing (`portl-cli` ↔ `portl-slicer-adapter`) is explained in
`05-bootstrap.md §5`.

## 8. Interaction with existing slicer helpers

`slicer claude` / `slicer workspace` still exist; `portl slicer vm claude`
is a thin wrapper that:

1. Calls `portl slicer vm add sbox --tag agent=claude`
2. Runs the slicer-side "install claude binary + copy credentials" logic
   (the same steps `slicer claude` performs) via `portl exec`
3. Optionally attaches via `portl shell --bootstrap "tmux attach -t claude"`

This means existing `slicer claude` users don't lose anything; the portl
version just swaps the attach path to direct iroh.

## 9. Failure modes and diagnostics

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `vm add` hangs after "VM ready" | agent not started in guest | `slicer vm logs`, check userdata ran |
| agent started but `portl status` reports "unreachable" | relay URL not reachable from VM | edit `agent.toml` relays, restart |
| shell works but tcp denied | policy.tcp rules don't include the target port | update agent policy |
| all connections forced via relay | AVF NAT + home-router double-NAT | run your own relay on a reachable VPS |
| ticket "unknown issuer" | `trust.roots` out of sync with operator rotation | push new roots via meta/v1 or userdata |

`portl doctor` will diagnose (1), (2), (4) automatically.
