# autoresearch ideas

## v0.2.1 — Gateway crate extraction

Extract gateway code from `portl-agent` into its own
`portl-gateway` crate. Drop `reqwest` as a direct dep of
`portl-agent` (gateway was its only consumer). Move
master-ticket bearer validation out of `portl-core` /
`portl-proto` into `portl-gateway::master_ticket` so the ticket
crate stops knowing what a "master" ticket is. Move
`wiremock` dev-dep with the gateway integration tests.

Scoped out of v0.2.0 because it is a ≥19-file refactor
entangled with `AgentState`, `Session`, `caps_enforce`,
`stream_io`, and `audit`. Shipping it in the same release as
§4 CLI collapse + §5 docker orchestrate + §13 runtime safety
multiplies regression risk.

User-observable §10 behaviour (the `portl-gateway` multicall
entrypoint) ships in v0.2.0 via the small-scope Task 1.2. The
binary-size / build-time wins are deferred by one release.
