## Review
- What's correct
  - The review-fix commits materially improved the branch: `portl id *` is now actually removed from the CLI surface and replaced with an explicit compatibility error, `--from-release` support exists for docker inject/bake paths, `portl docker run --watch` is implemented, and revocation publish now appends atomically before acknowledging success.
  - Runtime invariants look substantially better after `06787a4`: publish paths use `append_batch_atomic`, local file appends are reloaded into the live agent, and `shell_exit` audit emission now happens before the exit watcher is notified.
  - Install/docs/help consistency is much closer to spec after `1d65389`: `portl install dockerfile --output DIR` works, user-systemd units point at a user env file, launchd restart semantics were improved, and release packaging includes `portl-gateway`.
- Issues, potential fixes, and preferred choice.
  - Medium: `portl docker detach` still does not meet the spec’s ownership invariant. The implementation records only the injected path, not whether that path pre-existed, and later unconditionally removes it on detach (`crates/portl-cli/src/commands/docker.rs`). Preferred fix: record whether the binary was copied vs already present, and only remove copied files; if that is not feasible before tag, disable `detach` rather than risk deleting a pre-existing container binary.
  - Medium: `portl docker detach` is Linux-host-only (`crates/portl-cli/src/commands/docker.rs`), while the v0.2 docker surface is otherwise advertised cross-platform. Preferred fix: remove the binary with a container-side `docker exec rm -f ...` path so Docker Desktop/macOS hosts work too.
  - Observation / nice-to-have: the shipped CLI omits `slicer bake` even though spec 140 still lists it. Preferred fix: either implement it or explicitly document the deferral before/with the release notes.
  - Observation / nice-to-have: `portl install dockerfile` is still hard-coded to `debian:stable-slim`; spec 140 says the base should be overridable with `--base`.
- Note: Observations
  - I do not see remaining high-priority runtime/revocation blockers after the fix commits.
  - The main remaining blocker risk is on the docker detach contract, not on the revocation/runtime changes.
Current date: 2026-04-21
