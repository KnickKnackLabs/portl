---
name: portl-release
description: Use when preparing, validating, tagging, or publishing a Portl release, especially when CHANGELOG.md may be missing, duplicated, stale, or too raw for users.
---

# Portl Release

## Overview

Portl releases combine deterministic mise tasks with agent judgment. Let scripts handle mechanical version/tag safety; use review judgment for changelog quality and GitHub release readiness.

## Required Workflow

1. Inspect state: `git status --short --branch`, `git log --oneline --decorate -5`, and `git describe --tags --abbrev=0`.
2. Decide/confirm version. Patch bumps are normal for docs/CLI cleanup; use SemVer.
3. Audit `CHANGELOG.md` before scripts:
   - missing Unreleased entries → run `mise run release:changelog:draft -- VERSION`, inspect linked commits, rewrite into user-facing notes, and ask for review if impact is unclear,
   - duplicate release headings → consolidate manually before prep; `prep` skips changelog finalization when the target heading already exists, so duplicates can survive until verification/release extraction fails,
   - raw commit-speak → rewrite into user-facing bullets, merging related commits and dropping implementation-only noise,
   - stale or duplicated historical references → preserve true historical statements like “v0.5.0 shipped”, but do not update them as current-version examples.
4. Run `mise run release:prep -- VERSION` once the changelog is ready. Use `--dry-run` first if you want a non-mutating preview.
5. Run `mise run release:verify -- VERSION --local` before committing the release bump. This keeps local verification fast by checking metadata/fmt/diff, focused nextest suites for the core crates, and focused clippy. Use `--full` only when you intentionally want to reproduce CI plus ignored smoke tests locally.
6. Commit with subject `Release vVERSION` and a body explaining the bump.
7. Push `main`.
8. Before tagging, verify the pushed release commit's comprehensive CI with `mise run release:watch -- VERSION --ci-only`; before the tag exists this requires local `HEAD` to match upstream, and it refuses a stale existing `vVERSION` tag unless `--allow-existing-tag` is explicit. Then run `mise run release:tag -- VERSION`.
9. After tagging, watch/report CI and release publishing with `mise run release:watch -- VERSION`. Avoid raw `gh run watch` unless debugging interactively; it repeats large job tables and annotations.

## Changelog Rules

- Keep `## Unreleased` at the top, empty after finalizing.
- Each release section must be `## X.Y.Z — YYYY-MM-DD`.
- Prefer user-facing categories: `### Added`, `### Changed`, `### Fixed`.
- `prep` hard-exits if Unreleased is empty unless `--allow-empty-changelog` is passed; use that flag only for no-user-impact bumps.
- `mise run release:changelog:draft -- VERSION` creates a scratch draft with commit links and a compare link. Treat it as source material, not final copy.
- Final release notes should be human-friendly. Include commit or compare links sparingly when they help trace ambiguous changes; do not publish a raw commit list.
- If a release has no user-facing changes, say so explicitly; do not leave an empty section.

## Mise Tasks

- `mise run release:prep -- VERSION` — bump manifests/README, finalize populated Unreleased, and refresh release metadata. Requires a clean tree; supports `--dry-run`, `--allow-dirty`, and `--allow-empty-changelog`.
- `mise run release:verify -- VERSION` — metadata checks, `cargo fmt --check`, and `git diff --check` without compiling just to check `portl --version`.
- `mise run release:verify -- VERSION --local` — default verification plus focused local nextest (`portl-cli`, `portl-core`, and `portl-agent` library tests) and focused clippy for `portl-cli`/`portl-core`. This is the normal pre-release local gate.
- `mise run release:verify -- VERSION --ci` — default verification plus CI-equivalent `cargo nextest run --profile ci --workspace --all-features --lib --bins --tests` and workspace clippy. Prefer GitHub CI for this unless you explicitly need to reproduce it locally.
- `mise run release:verify -- VERSION --smoke` — default verification plus ignored release smoke tests through nextest.
- `mise run release:verify -- VERSION --full` — default verification plus `--ci --smoke`. Use sparingly for high-risk releases or CI debugging. Add `--allow-existing-tag` only when auditing an already-tagged release.
- `mise run release:changelog:draft -- VERSION [--since TAG]` — write `scratch/release-vVERSION-changelog-draft.md` with raw commit subjects, commit links, and compare link for rewrite.
- `mise run release:tag -- VERSION` — fetch remote tags, verify HEAD is pushed upstream, re-check changelog, then create and push annotated `vVERSION` tag. Supports `--no-push` and `--allow-unpushed`.
- `mise run release:watch -- VERSION` — low-noise watcher for the tag commit's CI run and the tag's Release run. Prints compact status only when it changes and exits nonzero on terminal failure. Use `--once`, `--ci-only`, `--release-only`, `--poll`, `--timeout`, `--json`, `--verbose`, or `--allow-existing-tag` for focused checks. Exit `124` means the workflows were still pending at timeout, not necessarily failed; `--json` is snapshot-only.

## If CI or Release Fails

1. Start with `mise run release:watch -- VERSION --verbose` or `gh run view RUN_ID --log-failed`; do not paste full watch transcripts into context. If `release:watch` times out, re-check with `mise run release:watch -- VERSION --once` before treating it as a failed workflow.
2. Fix locally, then run the smallest relevant verification before `mise run release:verify -- VERSION --full`.
3. Commit and push the fix to `main`.
4. If the tag was pushed but `gh release view vVERSION` confirms the GitHub release was not published, move it only with explicit intent: delete/recreate or force-update local `vVERSION`, then `git push --force origin refs/tags/vVERSION`.
5. If the GitHub release was already published, do not move the tag; cut the next patch version instead.

## Common Mistakes

- Tagging before the release commit is pushed.
- Letting a script invent final release notes without review.
- Replacing historical spec references while bumping README current-version examples.
- Forgetting the GitHub release workflow extracts the matching changelog section.
- Using raw `gh run watch` by default; prefer `release:watch` to avoid repeated annotations and huge transcripts.
- Moving a tag after the GitHub release has been published; cut a new patch release instead.
