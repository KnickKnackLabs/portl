# 06 — Docker adapter (M4 reference)

The `docker-portl` adapter is the canonical `Bootstrapper` reference
implementation for v0.1. It provisions a container, installs the
portl multicall binary (plus its `portl-agent` symlink), injects an
ed25519 secret out-of-band, wires up the systemd-free entrypoint,
and registers the container's `endpoint_id` locally.

The Docker adapter was picked over the slicer adapter as the first
one to ship because Docker is:

- Available on every developer workstation and every CI runner
  without a license gate.
- Cross-platform (macOS, Linux, Windows, WSL, CI) with the same
  invocation surface.
- Fast to iterate on (sub-second boot vs. VM boot).
- An environment that stress-tests the "no systemd, no cloud-init"
  code path in the agent.

See `065-slicer.md` for the slicer adapter (M5), which exercises
gateway-mode, master tickets, and systemd installs. Most other
adapters (cloud-init, nixos, k8s) follow the same pattern as
docker-portl with a different provisioning verb.

## 1. Shape

`docker-portl` is:

- A crate (`adapters/docker-portl`) that implements `Bootstrapper`
  against a local `dockerd` (unix socket) or a remote docker
  context over TLS / SSH.
- A binary (`portl-docker-adapter`) registered as the dynamic
  subcommand `portl docker …`.
- An optional reference container image published to
  `ghcr.io/knickknacklabs/portl-agent:<version>` from M5 onward.
  At M4 the adapter accepts any image that contains the `portl`
  multicall binary.

### 1.1 Dependency surface

```
bollard      = "0.x"      # docker API client
serde        = "1"
tokio        = { version = "1", features = ["rt-multi-thread"] }
tracing      = "0.1"
portl-core   = { path = "../../crates/portl-core" }
```

Shells out to `docker` only for interactive diagnostics
(`portl docker logs <name>`); all provisioning goes through the
API client so errors are structured.

## 2. Bootstrapper trait implementation

```rust
impl Bootstrapper for DockerBootstrapper {
    async fn provision(&self, spec: &TargetSpec) -> Result<Handle> {
        // 1. Generate ed25519 secret on host, write to
        //    /var/folders/.../portl-secret-<hex> (0600).
        // 2. docker run -d \
        //       --name <spec.name> \
        //       --label portl.endpoint_id=<endpoint_id> \
        //       --label portl.adapter=docker-portl \
        //       --network <spec.network or "bridge"> \
        //       -v <secret_host_path>:/var/lib/portl/secret:ro \
        //       -v <agent_toml_host_path>:/etc/portl/agent.toml:ro \
        //       --restart unless-stopped \
        //       <spec.image> \
        //       portl agent run --config /etc/portl/agent.toml
        // 3. Unlink secret_host_path once container is running.
        // 4. Return Handle { container_id, endpoint_id, ... }.
    }

    async fn register(&self, h: &Handle, id: EndpointId) -> Result<()> {
        // Labels were set at provision time; nothing to do.
        // Verify by reading back the label.
    }

    async fn resolve(&self, h: &Handle) -> Result<TargetStatus> {
        // docker inspect <container_id>; map State.Status → TargetStatus.
    }

    async fn teardown(&self, h: &Handle) -> Result<()> {
        // docker stop --time=10 && docker rm
    }
}
```

Spec → command mapping is 1:1; no hidden state. The adapter keeps
a small SQLite table (`portl-cli::config`) mapping aliases to
`(container_id, endpoint_id, image, network)` so `portl docker
container list` can render status even when the agent is offline.

## 3. CLI shape

```
portl docker container add <name>
    [--image IMG]            # default: ghcr.io/knickknacklabs/portl-agent:latest
    [--network MODE]          # bridge | host | <user-defined>
    [--agent-caps CAP-LIST]   # defaults from /etc/portl/docker-defaults.toml
    [--ttl DURATION]           # root ticket TTL; default 30d
    [--to <PUBKEY>]            # bind root ticket to operator pubkey
    [--dockerfile PATH]        # build-and-use convenience; else pulls IMG
    [--label KEY=VALUE]...     # additional docker labels
    → prints a portl ticket URI and (if --to) a ready-to-share bundle

portl docker container list [--json]
    ALIAS           CONTAINER      STATUS       ENDPOINT      CAPS
    claude-1        a1b2c3d4…      running      f9e8…         shell,tcp,udp
    demo-box        c3d4e5f6…      exited (0)   —             —

portl docker container rm <name> [--force] [--keep-tickets]
    Stop and remove the container. Tickets pointing at it remain
    valid on disk unless --force (also revokes root ticket locally).

portl docker container rebuild <name>
    Shortcut for `rm` + `add` with the same spec. Endpoint id
    changes (new secret), so old tickets naming this name become
    invalid. Use case: updating the image.

portl docker logs <name> [--follow] [--tail N]
    Thin shell-out to `docker logs`. Mostly for debugging the
    agent's own stdout/stderr.
```

Adapter defaults (e.g. which caps an operator hands a fresh
container) live in `~/.config/portl/adapters/docker.toml`:

```toml
default_image   = "ghcr.io/knickknacklabs/portl-agent:latest"
default_network = "bridge"
default_ttl     = "30d"

[default_caps]
shell = { pty_allowed = true, exec_allowed = true,
          allowed_users = ["root"] }
tcp   = [{ host_glob = "127.0.0.1", port_min = 1, port_max = 65535 }]
udp   = [{ host_glob = "127.0.0.1", port_min = 1, port_max = 65535 }]
```

## 4. Networking modes

Container networking is the only genuinely Docker-specific concern
in this adapter. portl itself is networking-oblivious — iroh's
hole-punching and relay fallback handle whatever substrate is
beneath.

| Mode | Linux | macOS Docker Desktop | Windows | Notes |
| --- | --- | --- | --- | --- |
| `bridge` (default) | ✅ | ✅ | ✅ | Container gets a private IP; iroh hole-punches outbound; inbound via relay unless the host forwards a UDP port. Works without host config. |
| `host` | ✅ | ❌ | ❌ | Container shares host network stack. No NAT, direct paths likely. Recommended for benchmark/demo use on Linux. |
| `<user-defined>` | ✅ | ✅ | ✅ | Behaves like `bridge`; picks up the network's IPAM settings. |
| `none` | ✅ | ✅ | ✅ | Useless for portl; rejected at `add` time with a clear error. |

`bridge` is the default because it works identically on every
platform. Operators who want hot-path performance on Linux hosts
can pass `--network host`.

### 4.1 Inbound reachability on Docker Desktop (macOS)

Docker Desktop on macOS puts the container behind a qemu/Virtio
NAT. Hole-punching *out* works because the outbound side initiates
the connection. Pure inbound (peer-dialing a laptop's container
from outside) relies on iroh's relay fallback. This is the same
story as NAT-ed residential networks and is expected to work
transparently.

If a macOS user wants direct paths, they run `portl agent run`
directly on the host instead of in a container. The adapter isn't
the answer to every topology.

## 5. Secret injection

The adapter generates the agent's ed25519 secret on the host and
mounts it read-only into the container:

```
host side                                   container side
─────────                                   ──────────────
/var/folders/…/portl-secret-<hex>           /var/lib/portl/secret
  0600 operator:operator                       0400 root:root (read by agent)
```

After the container is up and the agent has loaded the secret, the
adapter `unlink()`s the host-side file. Only the in-container
mount remains; if the container is stopped and restarted, Docker
re-establishes the bind mount from the now-deleted path and the
container fails to start — prompting the adapter to regenerate.
(Trade-off: secret is only paged in while the container is
running. Not ideal for long-lived unchanged containers; acceptable
at M4. M5+ may switch to a Docker secret or a named volume.)

**Rejected alternative: `-e PORTL_SECRET=…`.** Leaks in `docker
inspect`, `ps -ef`, and `/proc`. Never use env vars for secrets.

## 6. Full provisioning sequence

```
operator          portl-cli             docker-portl       dockerd       container
────────          ─────────             ────────────       ───────       ─────────
$ portl docker container add claude-1 --image ghcr.io/…/portl-agent
  ───────────────►
                  load adapter
                   ────────────►
                                      generate Sv (ed25519)
                                      write secret file (0600)
                                      render agent.toml from
                                       adapter defaults + flags
                                       ────────────────────────►
                                                              pull image
                                                              create container
                                                               ──────────────►
                                                                           PID 1:
                                                                           `portl agent run`
                                                              started
                                       receive container_id
                                      unlink host secret file
                                      mint root ticket for endpoint_id,
                                       signed by operator identity Ka,
                                       caps = default_caps, ttl = default_ttl
                  ◄──────────── return ticket URI
prints ticket URI ◄───────────
  + saves to ~/.config/portl/tickets/claude-1.ticket
```

From operator action to "ticket in hand" is typically <3 s on a
warm image; <10 s with an image pull.

## 7. Running without systemd

Inside the container, the agent is PID 1. That means:

- **Signal handling**: `portl agent run` installs `SIGTERM`/`SIGINT`
  handlers that initiate graceful shutdown (close QUIC connections,
  flush audit log, exit 0 within 10 s or be SIGKILLed by docker).
- **Zombie reaping**: when `shell/v1` exec or any other child
  process exits, its zombie must be reaped. The agent spawns a
  dedicated reaper task subscribed to `SIGCHLD` on unix; no `tini`
  or `dumb-init` wrapper needed.
- **OOM**: the agent's own memory is bounded (<100 MiB typical).
  Child processes (shells, port-forwards) are constrained via the
  container's cgroup.

Reference container entrypoint:

```dockerfile
FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates bash coreutils \
 && rm -rf /var/lib/apt/lists/*
COPY portl /usr/local/bin/portl
RUN ln -s /usr/local/bin/portl /usr/local/bin/portl-agent \
 && mkdir -p /var/lib/portl /etc/portl \
 && chmod 0700 /var/lib/portl
ENTRYPOINT ["/usr/local/bin/portl", "agent", "run"]
CMD ["--config", "/etc/portl/agent.toml"]
```

## 8. Image requirements

The adapter doesn't require its own image — any image that contains
the `portl` binary works. Minimum requirements:

- glibc ≥ 2.28 OR musl (the multicall binary ships both variants;
  adapter picks based on image OS detected via `docker inspect`).
- Writable `/var/lib/portl/` for revocation store + session log.
- Readable `/etc/portl/agent.toml` (or configurable via `--config`).
- `bash` or `sh` for `shell/v1` PTY spawning (the agent uses
  `/bin/sh` by default; overridable per-session).

From M5 we publish `ghcr.io/knickknacklabs/portl-agent:<version>`
built from the reference Dockerfile above. Operators who want
their own image just drop the multicall binary into it and set the
entrypoint.

## 9. Gateway mode (NOT applicable)

Docker has a local API only — `dockerd` listens on a unix socket
that requires root (or docker group) to access. There's no remote
orchestrator HTTP API that benefits from being wrapped in a portl
master ticket. Operators manage containers directly from their
laptop; no gateway needed.

Gateway-mode is slicer's story (see `065-slicer.md §4`). If a
future docker-adapter variant wants to expose remote docker hosts
(e.g. `DOCKER_HOST=tcp://server:2376`), portl's regular `tcp/v1`
port-forward is the right primitive — the master-ticket pattern
doesn't add value there.

## 10. CI integration

The Docker adapter is the canonical integration test target. A
single workflow file exercises the entire v0.1 protocol surface:

```yaml
# .github/workflows/ci-e2e.yml (sketch)
jobs:
  e2e:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo build --release --workspace
      - run: |
          # Two ephemeral targets on the same runner.
          ./target/release/portl docker container add t1 --image portl-test:ci
          ./target/release/portl docker container add t2 --image portl-test:ci
          ./target/release/portl shell t1 -- echo hi
          ./target/release/portl tcp t1 -L 127.0.0.1:18080:127.0.0.1:80 -N &
          sleep 1 && curl -sSf http://127.0.0.1:18080/
          # Multi-hop delegation
          ./target/release/portl share t1 --caps shell --ttl 10m > /tmp/delegated.ticket
          ./target/release/portl ticket import -f /tmp/delegated.ticket --as t1-del
          ./target/release/portl shell t1-del -- echo delegated
          # Revocation
          ./target/release/portl revoke --alias t1-del
          ! ./target/release/portl shell t1-del -- echo should-fail
```

This kind of end-to-end coverage is infeasible without an
adapter that CI can drive freely.

## 11. Known limitations

- **VPN mode**: requires `--cap-add NET_ADMIN --device /dev/net/tun`
  which we don't set by default. Operators who want `vpn/v1` from a
  container pass `--cap-add` via `portl docker container add …
  --label portl.cap_add=NET_ADMIN`.
- **`fs/v1` (v0.2)**: container rootfs is isolated; fs operations
  target mounted volumes only. The agent refuses fs access to
  paths outside `policy.fs.roots` exactly as on a VM, but operators
  need to think about mounts.
- **Rootless Docker**: supported. The adapter doesn't assume it's
  talking to privileged dockerd; it works against rootless
  installations with UID remapping.
- **Docker Desktop resource limits**: Docker Desktop on macOS
  defaults to 4 CPU / 2 GiB RAM. `portl agent` is light (~40 MiB)
  but heavy client workloads (PTY-based LLM coding agents) may
  need higher limits; the adapter emits a warning if Desktop's
  configured memory is below 4 GiB.
- **`--network host` on macOS/Windows**: not supported by Docker
  itself. Adapter rejects with a clear error.
- **Swarm/compose integration**: out of scope for M4. The adapter
  treats each container as an independent target.

## 12. What docker-portl validates in the core design

Shipping docker-portl at M4 forces the core to handle cases a
VM-only adapter would let us skip:

- Agent-as-PID-1 signal handling and zombie reaping.
- Non-systemd lifecycle (bring-up, config reload, teardown).
- Secrets delivered via bind mount instead of cloud-init userdata.
- NAT-ed inbound reachability (Docker Desktop on macOS is a
  textbook double-NAT).
- Ephemeral targets (name reuse after teardown; endpoint_id
  rotation).
- Rapid spec iteration (the adapter runs thousands of times per
  day in CI).

The slicer adapter (M5) then adds:

- Systemd unit lifecycle.
- Cloud-init / userdata templating.
- Gateway mode wrapping an external HTTP API.
- Master tickets and long-lived bearer credentials.

Building docker first, slicer second means the ticket/v1 and
`Bootstrapper` trait surfaces get exercised by two meaningfully
different adapters before v0.1 ships. Design churn caught between
M4 and M5 is design churn that doesn't make it into a release.

## 13. Reference Dockerfile

Shipped in-tree at `adapters/docker-portl/images/Dockerfile.reference`:

```dockerfile
# syntax=docker/dockerfile:1.7
FROM debian:stable-slim AS base
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates bash coreutils tini \
 && rm -rf /var/lib/apt/lists/*

FROM base AS runtime
ARG TARGETARCH
# Built by release.yml and baked into the context at image-build time.
COPY portl-${TARGETARCH} /usr/local/bin/portl
RUN chmod +x /usr/local/bin/portl \
 && ln -s /usr/local/bin/portl /usr/local/bin/portl-agent \
 && mkdir -p /var/lib/portl /etc/portl \
 && chmod 0700 /var/lib/portl

# tini keeps us honest about PID-1 signal semantics even though the
# agent handles them itself; one less foot-gun for image inheritors.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/portl", "agent", "run"]
CMD ["--config", "/etc/portl/agent.toml"]

LABEL org.opencontainers.image.title="portl-agent"
LABEL org.opencontainers.image.source="https://github.com/KnickKnackLabs/portl"
LABEL org.opencontainers.image.licenses="MIT"
```

Image size target: <80 MiB uncompressed on `linux/amd64` (debian-
slim is ~30 MiB, tini ~1 MiB, `portl` ~17 MiB static musl variant).

## 14. Non-goals for v0.1

- Docker Swarm / Kubernetes orchestration. A k8s adapter is a
  separate design (future work); it can't reuse docker-portl's
  direct-dockerd assumptions.
- Multi-container portl meshes inside the same pod/stack. Each
  container is an independent peer.
- Image building. Operators build their own; adapter consumes.
- Auto-update of the in-container agent. Rebuild with a newer
  image via `portl docker container rebuild`.

These are rejected, not deferred — the shape of their solution
lives outside docker-portl.
