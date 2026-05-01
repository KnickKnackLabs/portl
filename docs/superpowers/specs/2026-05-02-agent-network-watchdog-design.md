# Agent network watchdog design

## Context

Portl agents can be locally healthy while their long-running network endpoint is
stale from the point of view of remote peers. We observed this on `max`: local
IPC and `portl-agent status` were healthy, but `vn3` could not complete
`portl status max` until the max agent was restarted. The first robustness
slice should make this class of failure self-healing without introducing a
broader mesh, peer fanout, or revocation/event synchronization.

## Goals

- Run automatically inside `portl-agent` when the agent is shareable.
- Keep idle CPU and network overhead negligible.
- Detect stale agent network endpoints even when local IPC is healthy.
- Recover by refreshing/recreating the network endpoint before resorting to a
  full process restart.
- Expose enough health state for `portl status --json` and `portl doctor` to
  explain what happened.
- Avoid restart or reconnect thrash during real network outages.

## Non-goals

- Always-on peer mesh or gossip/pubsub.
- Periodic probing of every peer.
- Ticket revocation propagation.
- Signed mesh events or peer status synchronization.
- Treating absence of peer traffic as an immediate failure.

## Watchdog model

The watchdog is mostly passive. It records cheap health signals from existing
agent activity, then runs a slow self-probe only when recent activity has not
already proven the endpoint healthy.

### Passive signals

The agent tracks:

- `endpoint_generation`
- `endpoint_started_at`
- `last_inbound_handshake_at`
- `last_successful_self_probe_at`
- `last_failed_self_probe_at`
- `consecutive_self_probe_failures`
- `last_endpoint_refresh_at`
- `endpoint_refresh_count`
- `last_endpoint_refresh_error`

Successful inbound handshakes reset the stale timer because they prove remote
dialability. Endpoint creation increments `endpoint_generation`.

### Active self-probe

The watchdog wakes on a jittered interval. Before probing, it checks whether an
inbound handshake happened recently enough; if so, it records no work and goes
back to sleep.

If a probe is needed, the agent creates an independent lightweight client path
to its own endpoint id and performs the smallest useful Portl handshake/meta
ping. The probe closes immediately after success or failure. It does not probe
other peers.

Default policy:

- interval: 5 minutes, jittered
- timeout: 5 seconds
- failure threshold before healing: 3 consecutive probe failures
- disabled when the agent is not in shareable/agent mode

## Self-healing policy

On a self-probe failure:

1. Increment `consecutive_self_probe_failures` and record the failure time.
2. If the threshold is not reached, take no recovery action.
3. Once the threshold is reached, recreate the agent network endpoint and record
   `endpoint_refresh_count`, `last_endpoint_refresh_at`, and any error.
4. If endpoint recreation fails repeatedly, use exponential backoff.
5. If the network subsystem remains unrecoverable across a long backoff window,
   exit and allow launchd/systemd to restart the service. This last-resort exit
   is enabled in agent mode because the service manager is already responsible
   for keeping the agent alive.

Successful inbound handshakes, successful self-probes, and successful endpoint
recreation reset the consecutive failure count.

## Anti-thrash behavior

- Add jitter so multiple agents do not probe at the same instant.
- Back off recovery attempts after repeated failures: 5m, 10m, 20m, then a
  capped maximum such as 1h.
- Do not restart the whole process as the first response.
- Preserve local IPC availability while the network subsystem is being
  refreshed whenever possible.
- Report degraded health instead of churning if the host network is down.

## Status and doctor output

`portl status --json` should include a network health section, for example:

```json
{
  "network_health": {
    "state": "ok",
    "endpoint_generation": 2,
    "endpoint_started_at": 1777677000,
    "last_inbound_handshake_at": 1777677550,
    "last_self_probe_ok_at": 1777677600,
    "last_self_probe_failed_at": null,
    "consecutive_self_probe_failures": 0,
    "endpoint_refresh_count": 1,
    "last_endpoint_refresh_at": 1777677300,
    "last_endpoint_refresh_error": null
  }
}
```

`portl doctor` should summarize the same state:

- ok: self-probe succeeded recently or inbound traffic proved reachability
- warn: recent probe failures triggered endpoint refresh/backoff
- fail: endpoint refresh is repeatedly failing or watchdog is disabled in agent
  mode when it should be active

Target-mode JSON status should also become machine-readable by emitting only
JSON when `--json` is set. Human peer routing/status lines should remain on
stderr or be suppressed in JSON mode.

## Configuration

Add conservative knobs with safe defaults:

- `PORTL_AGENT_WATCHDOG=auto|off`
- `PORTL_AGENT_WATCHDOG_INTERVAL`, default `5m`
- `PORTL_AGENT_WATCHDOG_TIMEOUT`, default `5s`
- `PORTL_AGENT_WATCHDOG_FAILURES`, default `3`

The default should be `auto`: enabled for shareable agent mode and disabled for
non-agent/client-only invocations.

## Testing strategy

- Unit-test health-state transitions and backoff math without networking.
- Integration-test that an inbound handshake updates `last_inbound_handshake_at`.
- Use a fake probe implementation to prove consecutive failures trigger endpoint
  refresh and that success resets failures.
- Verify `portl status --json` and `portl doctor` render healthy, degraded, and
  failed watchdog states.
- Add a regression for target-mode `portl status --json` emitting parseable JSON
  only.

## Implementation notes

- If the current agent architecture cannot recreate the Iroh endpoint in place,
  the implementation should first introduce a narrow network-subsystem boundary
  and then wire the watchdog through that boundary. It should not scatter
  endpoint recreation logic through unrelated handlers.
- Last-resort process exit is part of the first design, but only after repeated
  failed endpoint refresh attempts and exponential backoff. The service manager
  then performs the actual process restart.
