---
name: portl-live-e2e
description: Use when validating Portl against a real target machine, especially session attach providers, TUI clients, remote bridge/helper processes, deployed agents, or commands like `portl attach vn3/herdr`.
---

# Portl Live E2E

## Overview

Live Portl E2E must prove the exact user command works on the real target and leaves the target clean. Unit/fake-provider tests do not catch version drift, inherited env vars, dirty TUI focus, or stale remote helper processes.

## Required Evidence

1. Build and record local/remote versions:

```bash
cargo build -p portl-cli --bin portl
./target/debug/portl --version
./target/debug/portl status TARGET --timeout 8s
ssh TARGET '~/.local/bin/portl-agent --version'
```

2. Verify provider discovery:

```bash
./target/debug/portl session providers --target TARGET
```

3. Run the exact user command plus an isolated session when state matters:

```text
Exact smoke:      portl attach TARGET/herdr
Deterministic:    portl attach TARGET/herdr/fresh-test-session
```

Default sessions can be dirty after repeated probes. Use a fresh named session for deterministic text/control assertions, while still running the exact shorthand smoke.

## TUI Automation Rules

- Prefer `expect` with `log_user 0`; write raw transcript to `/tmp` or `scratch/`.
- Never put literal backticks in an unquoted shell heredoc; use Tcl `\x60` for Herdr's backtick prefix.
- Capture the remote Herdr log line count before attach, then inspect only new lines.
- Use marker files for text input: `echo marker > /tmp/unique-file`.
- Unset nested Herdr guard when launching from inside Herdr: `env -u HERDR_ENV ...`.

## Herdr Checks

For Herdr, verify all of these after detach:

```bash
ssh vn3 'cat /tmp/marker-file'
ssh vn3 'tail -n +$START ~/.config/herdr/herdr-server.log | grep -E "client connected|tab created|workspace created|client detach|client disconnected"'
ssh vn3 'ps -eo pid,ppid,comm,args | grep -E "[h]erdr remote-client-bridge|[p]ortl-agent|[h]erdr server" || true'
```

Expected process state: no `herdr remote-client-bridge`; `portl-agent` active; remote `herdr server` may remain.

To clean stale bridge probes without matching your SSH shell:

```bash
ssh vn3 'ps -eo pid=,comm=,args= | awk '\''$2=="herdr" && index($0,"remote-client-bridge") {print $1}'\'' | xargs -r kill -TERM'
```

## Common Mistakes

- Running live E2E with a stale `target/debug/portl`; always rebuild and print `--version`.
- Checking only connect/detach and skipping process cleanup.
- Treating a successful named-session test as proof that the exact shorthand works.
- Letting raw TUI output flood the harness instead of logging it to a file.
- Running parallel Portl/Herdr probes against the same target; use sequential probes to avoid endpoint contention.
