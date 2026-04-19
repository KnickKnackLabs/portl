# 05 — Bootstrap and adapters

## 1. The problem

For `portl-agent` to run inside a target, two things must be true:

1. The agent's **ed25519 secret** must be present on disk.
2. The agent's **node-id** must be discoverable by would-be clients
   (either stored out-of-band in a ticket, or registered in a directory).

How this happens depends entirely on the orchestration environment:

- For slicer: via a slicer secret + userdata bootstrap.
- For cloud-init: via userdata + instance metadata.
- For docker: via `-v` or `--env-file`.
- For baremetal: via a first-boot QR code, `systemd-firstboot`, or a USB key.
- For NixOS: via the module system + sops/age.

portl doesn't prescribe which mechanism. Instead, it defines a small
**`Bootstrapper` trait** and ships adapters that implement it.

## 2. The trait

```rust
#[async_trait]
pub trait Bootstrapper: Send + Sync {
    /// Called by the operator CLI to provision a new target.
    ///
    /// The caller has already:
    ///   - generated a fresh SecretKey
    ///   - computed node_id = pubkey(secret)
    ///   - prepared labels (tags/annotations the adapter may use)
    ///
    /// The adapter's job: get the secret onto the target such that
    /// portl-agent, on first run, picks it up; and start the agent.
    async fn provision(
        &self,
        target:  &TargetSpec,
        secret:  &SecretKey,
        labels:  &Labels,
    ) -> Result<TargetHandle>;

    /// Called after provision succeeds to register the node_id in
    /// whatever directory the orchestrator maintains.
    async fn register(
        &self,
        handle:  &TargetHandle,
        node_id: NodeId,
    ) -> Result<()>;

    /// Optional: resolve an alias to a known ticket.
    /// Used by `portl <adapter> vm shell <alias>` to avoid re-typing.
    async fn resolve(
        &self,
        name: &str,
    ) -> Result<Option<Ticket>>;

    /// Tear down a target and revoke its tickets.
    async fn deprovision(
        &self,
        handle: &TargetHandle,
    ) -> Result<()>;

    /// Adapter metadata for help text / listing.
    fn info(&self) -> AdapterInfo;
}

pub struct TargetSpec {
    pub kind:    Text,                // "slicer/vm", "docker/container", ...
    pub group:   Text,                // orchestrator-defined bucket
    pub params:  serde_json::Value,   // opaque to portl-core
}

pub struct TargetHandle {
    pub id:      Text,                // orchestrator-specific unique id
    pub alias:   Text,                // human-friendly name
    pub secret_path: Option<Text>,    // where the secret landed inside target
    pub meta:    Map<Text, Text>,
}

pub struct Labels(pub BTreeMap<String, String>);
```

## 3. Flow

```
operator CLI:   portl slicer vm add sbox --tag agent=claude
                       │
                       │
                       ▼
  ┌─────────────────────────────────────────────┐
  │ portl-core                                   │
  │                                              │
  │  1. SecretKey::generate()  →  S              │
  │     node_id = pubkey(S)                      │
  │                                              │
  │  2. adapter.provision(spec, &S, labels)      │
  │                                              │
  │  3. adapter.register(handle, node_id)        │
  │                                              │
  │  4. wait for agent heartbeat                 │
  │     (open meta/v1 ping; retry w/ backoff)    │
  │                                              │
  │  5. mint root ticket for node_id, signed by  │
  │     operator identity                        │
  │                                              │
  │  6. save to ~/.config/portl/tickets/<alias>  │
  │                                              │
  │  7. print ticket + alias to stdout           │
  └─────────────────────────────────────────────┘
```

## 4. Concrete adapters

### 4.1 `slicer-portl` (primary)

See `060-docker.md` (M4 reference) and `065-slicer.md` (M5) for
concrete adapter implementations.

```
provision     → slicer secret create portl-<id>
                slicer vm add <group> --secrets portl-<id>
                                       --tag portl_node=<node_id>
                                       --userdata <install-script>
register      → (no-op; tag already set in provision)
resolve       → slicer vm list → find by tag → synthesize ticket
deprovision   → slicer vm delete <name>
                remove local ticket file
                push revocation to any trust-root-peer agents
```

### 4.2 `cloud-init-portl`

```
provision     → write secret to base64 user-data (#cloud-config):
                  write_files:
                    - path: /var/lib/portl/secret
                      permissions: '0400'
                      encoding: b64
                      content: <...>
                  runcmd:
                    - apt-get install -y portl-agent
                    - systemctl enable --now portl-agent
                pass this user-data to the cloud API (EC2, GCP, etc.)
register      → store (instance_id, node_id) in a local mapping file
                  or in instance metadata tag
resolve       → read the mapping
deprovision   → stop instance via cloud API
```

### 4.3 `docker-portl`

```
provision     → docker volume create portl-<id>
                docker run -d \
                  -v portl-<id>:/var/lib/portl \
                  --cap-add NET_ADMIN \
                  --name <name> \
                  --label portl.node_id=<node_id> \
                  <image>
                write secret to the volume before starting
register      → label already set
resolve       → docker ps --filter label=portl.node_id
deprovision   → docker rm -f <name>; docker volume rm portl-<id>
```

### 4.4 `nixos-portl`

```
provision     → invoke `nixos-rebuild test` with a module that renders
                /var/lib/portl/secret from sops-nix, enables the
                portl-agent systemd unit
register      → write node_id into the flake's nodes.json (source-controlled)
resolve       → read nodes.json
deprovision   → remove node from flake; nixos-rebuild; the agent secret
                is deleted as part of the rollout
```

### 4.5 `manual-portl`

A "do it yourself" adapter. `provision` just prints:

```
#   copy this to the target and restart portl-agent:
mkdir -p /var/lib/portl
cat > /var/lib/portl/secret <<'EOF'
<base64-secret>
EOF
chmod 400 /var/lib/portl/secret
systemctl restart portl-agent
```

…and does nothing else. Useful for baremetal, lab use, and proving the
trait's shape.

## 5. Adapter discovery / registration

```
portl-cli
  │
  │ scans $PATH for binaries named `portl-*-adapter`
  │   (e.g. portl-slicer-adapter, portl-docker-adapter)
  │ queries each with  `--adapter-info`
  │ dispatches `portl <name> ...` to the matching binary
  ▼
adapter binary
  statically links portl-core + its Bootstrapper impl
  exposes its own subcommands
```

This keeps the portl-cli binary small and avoids linking every adapter's
dependency tree into everyone's install. It also means adapters can be
closed-source, vendor-specific, or licensed differently.

## 6. Dynamic resolution: `portl shell <alias>`

```
portl-cli receives `shell claude-1`
       │
       ▼
is `claude-1` in ~/.config/portl/tickets/ ?
       │
       │  yes                        no
       ▼                              │
  load ticket                         ▼
  connect                       try each registered adapter's
       │                        resolve("claude-1") in turn
       ▼                              │
  ok                                  ▼
                                ticket found by adapter?
                                      │
                                      │ yes              no
                                      ▼                   ▼
                             cache to ~/.config/   error: unknown peer
                             portl/tickets/
                             then connect
```

## 7. Keys for the adapter itself

Adapters never need their own identity keys. They only handle:

- the target's future secret (in transit during provisioning),
- opaque orchestrator credentials (slicer master ticket, cloud API creds,
  docker socket).

This keeps the crypto footprint small and puts the signing authority
squarely in `portl-core` + the operator's identity key.

## 8. Adapter contract: what may fail, what must not

| Step | Must succeed atomically? | On failure |
| --- | --- | --- |
| secret generation | yes (before adapter runs) | abort |
| provision | best-effort; may leak resources | CLI prints cleanup hint |
| register | idempotent; retryable | CLI auto-retries N times |
| heartbeat wait | bounded timeout | CLI offers `--no-wait` |
| ticket mint | must not fail after provision succeeds | if it does, revoke & retry |
| save ticket to disk | must succeed | atomic rename |

This ordering means: if provisioning succeeds but the operator never sees
a ticket, the target is live but unreachable. Mitigation: provision writes
a **bootstrap-only** ticket first (valid 5 minutes, caps: meta-only), so
that a later `portl <adapter> ticket-recover <name>` can mint a proper
ticket by talking to the live agent.

## 9. Testing adapters

`portl-core` ships a `MockBootstrapper` used in integration tests; any
adapter providing a similar in-memory fake can be tested end-to-end:

```
  test harness
    ├── portl-core with MockBootstrapper
    ├── portl-agent running in-process as a tokio task
    └── assertions over:
         - secret delivered where expected
         - node_id registered
         - heartbeat observed
         - tickets round-trip
```
