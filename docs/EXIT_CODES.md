# portl exit codes

portl reserves low exit codes for CLI and transport failures so shell
scripts can distinguish local setup problems from remote process
status.

| Code | Category | Meaning |
| ---: | --- | --- |
| 0 | ok | Success. |
| 1 | generic | Unspecified error. |
| 2 | usage | Clap parse error. |
| 10 | local | Local config or identity missing. |
| 11 | local | Agent unreachable over local IPC. |
| 12 | local | Local store I/O failed. |
| 20 | trust | Peer or target not found in local stores. |
| 21 | network | Target dial failed, no route, relay down, or timeout. |
| 22 | trust | Ticket expired. |
| 23 | trust | Ticket revoked. |
| 24 | trust | Ticket capability mismatch. |
| 25 | trust | Peer authentication rejected. |
| 29 | network | Relay rejected the request. |
| 30+ | passthrough | Remote `shell` or `exec` process exit code. |

Codes 3–9, 13–19, and 26–28 are reserved for future portl-originated
errors and should not be emitted by portl.

## When you see this

- Code 10 usually means `portl init` has not been run, or the config
  path is wrong.
- Code 11 means the local agent socket could not be reached. Start the
  agent with `portl install --apply` or run `portl-agent` directly.
- Code 20 means target resolution failed. Check `portl peer ls`,
  `portl ticket ls`, `portl docker ls`, and `portl slicer ls`.
- Codes 22–24 point to ticket lifecycle or permission issues. Re-issue
  a ticket with the needed caps.
- Codes 21 and 29 are network or relay path failures. Retry after
  checking discovery and relay configuration.

## How to diagnose

Start with local health:

```sh
portl doctor
portl status --json
```

For a specific target, use:

```sh
portl status <target>
portl status <target> --json
```

## Script-author quickstart

```sh
portl exec laptop make test
code=$?
case "$code" in
  0)        echo "ok" ;;
  11)       echo "agent not running" ;;
  22|23|24) echo "ticket problem; re-issue" ;;
  21|29)    echo "network; retry" ;;
  *)        echo "remote or generic exit $code" ;;
esac
```
