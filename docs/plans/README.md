# Plans

Implementation recipes. Each plan takes one or more design decisions
from [`../specs/`](../specs/) and turns them into bite-sized TDD tasks
with exact file paths, exact test code, exact commands, and exact
commit messages — ready for an engineer or a subagent to execute
step-by-step.

Plans retire when the feature ships. Their substance graduates to
[`../../CHANGELOG.md`](../../CHANGELOG.md). Expect older plans to be
deleted rather than preserved as historical record.

## Naming

`NNN-<slug>.md`, same 3-digit convention as specs, but with an
independent sequence that tracks execution order rather than spec
order. A plan's filename usually encodes the release or named
subproject it implements, not the spec number.

## Current plans

| # | File | Implements | Status |
| --- | --- | --- | --- |
| 010 | `010-v0.1.1-safety-net.md` | `specs/150-v0.1.1-safety-net.md` | pending |
| 020 | `020-v0.1.2-alias-isolation.md` | `specs/160-v0.1.2-alias-isolation.md` | pending |
| 030 | `030-v0.2-operability.md` *(deferred)* | `specs/140-v0.2-operability.md` | written after v0.1.1 + v0.1.2 land |

## Structure of a plan

Every plan starts with the writing-plans skill header:

```markdown
# <Feature> Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** [one sentence]

**Architecture:** [2–3 sentences about approach]

**Tech Stack:** [key crates/tools]

---
```

Then tasks. Each task lists the files it touches, then a sequence of
checkbox steps: write the failing test, run it, implement, run again,
commit. No placeholders. See the writing-plans skill for the full
template.

## Why numbered, not dated

Superpowers' default filename is `YYYY-MM-DD-<topic>-design.md`.
portl uses 3-digit numbering across `specs/` and `plans/` for
consistency with the pre-v0.1 architectural docs (`specs/010-*`
through `specs/130-*`). The skills' date convention is a default;
the content contract is the same.
