# autoresearch ideas

## Gateway crate split — deferred indefinitely

v0.2.1 shipped the "gateway isolation" subset: `reqwest` direct
dep dropped from `portl-agent`, ignored wiremock-backed test
deleted, and `AgentMode` now gates at handshake + ALPN dispatch
(commits `cae40c5`, `55be9b1`).

The fuller crate split — pulling gateway forwarding, master-ticket
handling, and the HTTP bearer-injection path into a dedicated
`portl-gateway` crate (ideally with a shared `portl-runtime`
library underneath both daemons) — remains deferred. It only pays
off when there is a second gateway consumer or a real push to
publish a stable runtime library API. Until then the 309-line
`gateway.rs` inside `portl-agent` is cheaper to maintain than a
split that forces a pipeline API to stabilize on a single consumer.

## `portl revoke --compact`

Add a maintenance subcommand that compacts expired-and-revoked
entries out of `revocations.jsonl` once they are past both the
underlying ticket expiry and the linger window.

Deferred from v0.2.0 Task 2.5 because the runtime-safety contract
needed the size ceiling + fail-closed `ResourceExhausted` behavior
first, and a correct compactor would have pushed the task beyond the
smallest-correct scope for this phase.
