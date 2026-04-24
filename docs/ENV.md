# portl environment variables

This page is the authoritative list of `PORTL_*` variables and the
small set of standard variables that the portl CLI treats as public
surface.

## Public user surface

| Variable | Purpose |
| --- | --- |
| `PORTL_HOME` | State directory override for identity, peer store, tickets, and revocations. |
| `PORTL_CONFIG` | Alternate `portl.toml` path. |
| `PORTL_JSON` | Force `--json` on commands that support structured output. Truthy values are `1`, `true`, `yes`, and `on`; falsey values are `0`, `false`, `no`, and `off`. |
| `PORTL_QUIET` | Force quiet output on commands that support it, including `init` and `doctor`. Uses the same boolean values as `PORTL_JSON`. |
| `NO_COLOR` | Disable color output, following the community `NO_COLOR` convention. |

Precedence for behavior variables is: explicit CLI flag, then the
environment variable, then the built-in default.

## Relay operator surface

| Variable | Purpose |
| --- | --- |
| `PORTL_RELAY_BIND` | HTTP bind address for the relay. |
| `PORTL_RELAY_HTTPS_BIND` | HTTPS bind address for the relay. |
| `PORTL_RELAY_CERT` | TLS certificate path. |
| `PORTL_RELAY_KEY` | TLS key path. |
| `PORTL_RELAY_HOSTNAME` | Advertised relay hostname. |
| `PORTL_RELAY_POLICY` | Relay access policy (`open`, `closed`, or allowlist-style policy). |
| `PORTL_RELAY_ENABLE` | Enable or disable relay support on the agent. |
| `PORTL_TRUST_ROOTS` | Additional trust roots for relay peers. |
| `PORTL_REVOCATIONS_PATH` | Override the agent revocations log path. |
| `PORTL_REVOCATIONS_MAX_BYTES` | Size cap for the revocations log. |
| `PORTL_UDP_SESSION_LINGER_SECS` | UDP session linger tuning. |
| `PORTL_LISTEN_ADDR` | Agent listen address override. |
| `PORTL_DISCOVERY` | Discovery backend selection. |
| `PORTL_RATE_LIMIT` | Per-peer rate limit. |
| `PORTL_METRICS` | Metrics endpoint toggle. |
| `PORTL_MODE` | Agent run mode. |

## Internal and test-only variables

These names are implementation plumbing. They are intentionally not
shown in user-facing help, may change without notice, and should only
be set by portl itself or by portl's test harness.

- `PORTL_IDENTITY_KEY`
- `PORTL_IDENTITY_SECRET_HEX`
- `PORTL_AUDIT_SHELL_EXIT_PATH`
- `PORTL_SESSION_REAPER_HELPER`
- `PORTL_SESSION_REAPER_PID_FILE`
- `PORTL_SIGNAL_CHILD`
- `PORTL_SIGNAL_CHILD_MODE`
- `PORTL_ABOUT`
- `PORTL_TEST_*`
- `PORTL_RUN_ENV_DENY_REGRESSION`
