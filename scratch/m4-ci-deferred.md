# M4 CI cases deferred to M7

Delegation and revocation coverage is intentionally deferred to M7.

Those flows need the planned CLI surface:

- `portl share`
- `portl ticket import`
- `portl revoke`

Until that polish lands, CI covers M4's bootstrap, exec, PTY shell, TCP forward,
and container cleanup paths only.
