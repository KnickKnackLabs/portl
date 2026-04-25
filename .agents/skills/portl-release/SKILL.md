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
5. Run `mise run release:verify -- VERSION --full` before commit/tag unless the user explicitly requests a lighter check.
6. Commit with subject `Release vVERSION` and a body explaining the bump.
7. Push `main`.
8. After CI is green or the user accepts using the release workflow gate, run `mise run release:tag -- VERSION`.
9. Watch/report the GitHub release workflow URL and status. If `gh` is available, use `gh run list --workflow=release.yml --limit 3`; otherwise report `https://github.com/KnickKnackLabs/portl/actions`.

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
- `mise run release:verify -- VERSION --full` — metadata checks, fmt/diff/version, focused tests, clippy. Add `--allow-existing-tag` only when auditing an already-tagged release.
- `mise run release:changelog:draft -- VERSION [--since TAG]` — write `scratch/release-vVERSION-changelog-draft.md` with raw commit subjects, commit links, and compare link for rewrite.
- `mise run release:tag -- VERSION` — fetch remote tags, verify HEAD is pushed upstream, re-check changelog, then create and push annotated `vVERSION` tag. Supports `--no-push` and `--allow-unpushed`.

## Common Mistakes

- Tagging before the release commit is pushed.
- Letting a script invent final release notes without review.
- Replacing historical spec references while bumping README current-version examples.
- Forgetting the GitHub release workflow extracts the matching changelog section.
