# 190 — CLI Ergonomics: Friction Reduction

> Status: **draft, first pass**. Drafted after a full CLI audit
> and a three-reviewer roundtable. Intended to be iterated on
> section-by-section. Release-slotting is tracked separately in
> the roadmap; this spec describes the target surface, not a
> release.

## 1. Summary

The `portl` CLI is ergonomically uneven: ~30% of positional
args and ~25% of flags have no help text, examples exist only
on `ticket issue`, two commands use the verb-in-flag
anti-pattern (`peer invite --list/--revoke`,
`ticket revoke --list/--publish`), and error messages rarely
name the next command to run. This spec lays out the target
shape of the CLI after a friction-reduction pass.

The work splits naturally into two tiers. The first tier is
pure help-surface and error-message polish: fill docstrings,
add examples, add a `completions` subcommand, tighten
clap-level `requires`/`conflicts_with`, and rewrite error
messages to suggest next steps. No behavior change, no rename,
no script breakage.

The second tier is deliberate surface change. portl has
not been publicly released, so each section picks a final
name or shape and deletes the old one rather than carrying
alias debt. Tier 2 splits the two verb-in-flag commands
into proper subverbs, restructures `config` with a
`template` verb and stdin-friendly validation, adds
`ls`/`rm` aliases across the tree, extends `status [PEER]`
into a unified self-or-peer health verb, ships `portl
man`, stabilizes exit codes, and audits the `PORTL_*`
env-var surface.

Three structural recommendations from the initial audit are
**dropped** based on unanimous reviewer veto: collapsing
`shell` + `exec` into `run [--pty]`, renaming
`peer add-unsafe-raw`, and introducing a global `--yes`. See
§13.

## 2. Goals

1. **Reduce newcomer confusion.** Every subcommand's `--help`
   answers "what does this do, when do I use it, what's the
   next command?" without a visit to the docs site.
2. **Pick names and stick with them.** portl is not yet
   publicly released; we lock the final surface now rather
   than accumulate alias debt. Where an alias does exist
   (docker/slicer `list` → `ls`), it matches a tool we
   don't control, is permanent and silent, and emits no
   deprecation stderr.
3. **Make error messages teach the tool.** Every failure
   surfaces at least one suggested next command.
4. **Zero security-signal regressions.** The `-unsafe-` in
   `peer add-unsafe-raw` stays. The friction is the feature.
5. **Reviewable in chunks.** Tier 1 is a single PR of
   clap-attribute and error-message edits — no behavior
   changes, reviewable in one sitting. Tier 2 ships as
   per-section PRs, each a focused surface change.

## 3. Non-goals

- Collapsing `shell` and `exec`. Separate verbs map to
  `ssh` / `ssh host cmd` muscle memory and prevent accidental
  PTY hangs in scripts.
- Renaming `peer add-unsafe-raw`. The full word in the verb
  is the safety signal.
- Global `--yes` at the top level. Confirmation scope is
  per-command by design; different commands have different
  semantics around "skip the prompt."
- Moving `portl gateway` under `portl slicer`. Gateway may be
  an independent forwarding primitive; revisit once the role
  is clearer.
- Touching any wire protocol. This is pure CLI surface.
- Touching any on-disk file layout, config key, or default
  value. `portl.toml` parses unchanged before and after this
  work.

## 4. Tiers

Work is grouped into two tiers by behavior-change risk. The
tier assignment is the spec's compatibility contract with
users; release-slotting (which patch / minor picks up which
tier) is a roadmap concern.

### 4.1 Tier 1 — pure help and error-message polish

Zero behavior changes. Clap attributes, docstrings,
`after_long_help` blocks, error-message rewrites, and one
genuinely-new utility verb (`completions`) that doesn't
affect any existing invocation.

- §5:  top-level help restructure
- §6:  fill every missing arg/flag docstring
- §7:  `after_long_help` examples on high-traffic verbs
- §8:  `<PEER>` help constant, reused everywhere
- §9:  clap `requires` / `conflicts_with` audit
- §10: `portl completions <shell>`
- §11: actionable error messages
- §12: `init --quiet`
- §13: explicitly dropped items

### 4.2 Tier 2 — deliberate surface change (delete, don't alias)

Each section picks a final name or shape and deletes the
old one. The exception is a handful of silent aliases
(documented per section) kept to match muscle memory from
tools we don't control — notably docker/slicer `list` →
`ls`. No deprecation stderr anywhere.

- §14: split `peer invite` verb-in-flag
- §15: split `ticket revoke` verb-in-flag
- §16: `ticket caps` sub-verb (replacing `--list-caps`)
- §17: `config` restructure
  (`template` / `init` / `edit`)
- §18: `ls` / `rm` aliases across the tree
- §19: `portl status [PEER]` unified self-or-peer health
- §20: `portl man` via `clap_mangen`
- §21: exit code stabilization
- §22: `PORTL_*` env var audit + `PORTL_JSON` /
  `PORTL_QUIET`

### 4.3 Out of scope for this spec

- `doctor --fix=auto|prompt` consolidation
- `gateway` placement review (flat vs `slicer gateway`)
- JSON schema versioning policy (becomes load-bearing once
  `--json` is universal; worth its own spec)

## 5. Top-level help restructure

Shared help conventions. Referenced from every later section.

### 5.1 Help grouping

Current `portl --help` lists subcommands in source order, which
mixes setup, runtime, and integration concerns. Regroup via
`#[command(display_order = N)]` and `#[command(next_help_heading = "…")]`.

Groups, in the order they render:

- **Setup**: `init`, `doctor`, `install`, `config`, `whoami`
- **Trust**: `peer`, `invite`
- **Pairing**: `accept`
- **Sessions (advanced)**: `ticket`
- **Connect**: `status`, `shell`, `exec`, `tcp`, `udp`
- **Integrations**: `docker`, `slicer`, `gateway`
- **Utility**: `completions`, `help`

The `ticket` demotion, the new `invite` namespace, and the
`accept` flat verb are all finalized in §14. This section
only reflects the grouping outcome.

### 5.2 Top-level `long_about` + `after_long_help`

Adds a one-paragraph description and a "Getting started"
worked example to `portl --help`.

```text
portl — peer-to-peer remote access and port forwarding.

Pair two machines:
  $ portl init
  $ portl invite                   # on the other machine (receive a code)
  $ portl accept PORTLINV-…        # on this machine (paste the code)
  $ portl shell other-machine      # connect

Run `portl <COMMAND> --help` for details on any subcommand.
```

### 5.3 Acceptance

- `portl --help` renders groups in the order above.
- `crates/portl-cli/tests/help_cli.rs` snapshots regenerate
  and pass.
- No behavior change.

### 5.4 Open questions

None. Keep the current one-liner at the usage line; the
`long_about` block (§5.2) is where newcomers get their
orientation.

## 6. Fill every missing arg/flag docstring

### 6.1 Summary

~30% of positional args and ~25% of flags have zero help
text today. Biggest gaps (from the initial audit):
`install`, `docker`, `slicer`, `shell`, `exec`, `tcp`,
`udp`, `gateway`, `init --force/--role`,
`peer add-unsafe-raw`, and the new verbs introduced in
§14–§19.

Action: add `help = "…"` to every `#[arg(…)]` in
`crates/portl-cli/src/`. Use `long_help` for args where
behavior is non-obvious (e.g. `init --role`, `install
--apply`, `tcp -L`, `invite --initiator`,
`ticket revoke publish`).

### 6.2 Scope

Pass is complete when:

- `cargo run -q -p portl-cli -- <verb> --help` shows at
  least one sentence next to every flag and positional.
- `clap_complete` generates completions without empty
  descriptions (asserted by grep in
  `help_cli.rs` snapshots — no `:$` lines with an empty
  description).
- Snapshot tests pass.

### 6.3 Style rules

Per-verb consistency is enough; a CLI-wide style guide is
out of scope.

- Help text is a single complete sentence ending in a
  period.
- Positional help uses the imperative voice ("Target peer
  to probe.") rather than reverse-labeling ("The peer.").
- Flags describe the effect, not the mechanism
  ("Force the handshake over the relay path." not "Sets
  the force_relay boolean.").
- `long_help` is reserved for flags whose effect has
  non-obvious preconditions or failure modes.

### 6.4 Risks

- Large mechanical diff, easy to churn snapshots. Mitigate
  with a single reviewer doing a one-sitting pass.
- Tier 2 renames land in the same release; coordinate the
  snapshot regeneration so §6 isn't reverted by §14–§19's
  help changes.

### 6.5 Open questions

None.

## 7. Examples on high-traffic verbs

### 7.1 Summary

Add `#[command(after_long_help = "…")]` to every verb a
newcomer is likely to reach for. Each block is 3–6 lines
of worked commands only, no prose.

### 7.2 Target verbs

Connect:
- `portl shell`
- `portl exec`
- `portl tcp`
- `portl udp`
- `portl status` (§19 already includes examples in its
  help; confirm they land via `after_long_help`)

Setup:
- `portl init`
- `portl doctor`
- `portl install`

Trust:
- `portl invite` (§14)
- `portl accept` (§14)
- `portl peer ls`
- `portl peer add-unsafe-raw`
- `portl ticket issue` (already has examples in body;
  move to `after_long_help` for consistency)
- `portl ticket revoke` (§15)
- `portl ticket caps` (§16)

Config:
- `portl config show`
- `portl config validate`
- `portl config template` (§17)

Integrations (skipped for Tier 1 — revisit once §13.4
gateway placement is resolved):
- `portl docker run`
- `portl slicer run`

### 7.3 Storage

Examples live in source docstrings, not external files.
Rationale: diff-friendly, review-friendly, and
`help_cli.rs` snapshots already make regressions
visible. External files were considered for translation
but portl has no localization story today; revisit only
if that changes.

### 7.4 Acceptance

- Every verb listed in §7.2 has an `after_long_help`
  block.
- Each block is 3–6 lines.
- Every command shown in the examples parses cleanly
  (asserted by a smoke test that runs each example line
  with `--help` appended).
- Help snapshots regenerate.

### 7.5 Open questions

None.

## 8. `<PEER>` help constant

New `const PEER_HELP: &str = …` in `crates/portl-cli/src/lib.rs`
used as `#[arg(help = PEER_HELP)]` on every `<PEER>` positional
(today: `status`, `shell`, `exec`, `tcp`, `udp`).

Content:

```text
Peer identifier. Accepts any of:

  * label       — short name from `portl peer ls`
  * endpoint_id — 64-char hex (see `portl whoami --eid`)
  * ticket      — a saved-ticket label or raw ticket string

Disambiguation: label is tried first, then endpoint_id, then
ticket.
```

### 8.1 Acceptance

- One constant, used by at least 5 positional args.
- Error text from "peer not found" (§11) references the same
  three identifier types.

## 9. clap `requires` / `conflicts_with` audit

Tighten flag relationships where the runtime already behaves
correctly but clap doesn't enforce it. Zero behavior change —
we're moving runtime errors earlier to clap's parse phase.

| Command | Change |
|---|---|
| `status --relay` | `requires = "peer"` (also §19.6) |
| `status --count` | `requires = "peer"` (also §19.6) |
| `status --timeout` | `requires = "peer"` (also §19.6) |
| `status --watch` | `conflicts_with = "peer"` (also §19.6) |
| `whoami --eid` | `conflicts_with = "json"` |
| `whoami --json` | `conflicts_with = "eid"` |
| `install --yes` | `requires = "apply"` |
| `install --apply` | `conflicts_with_all = ["output","detect","dry_run"]` |
| `install --detect` | `conflicts_with_all = ["apply","dry_run","output"]` |
| `install --dry-run` | `conflicts_with = "apply"` |
| `invite --initiator` (bare form) | `conflicts_with = "action"` (also §14.9) |
| `invite --ttl` (bare form) | `conflicts_with = "action"` (also §14.9) |
| `invite --for` (bare form) | `conflicts_with = "action"` (also §14.9) |
| `ticket revoke <ID>` | `conflicts_with = "action"` (also §15.7) |
| `config validate --path` | `conflicts_with = "stdin"` (also §17.6) |

### 9.1 Acceptance

- `portl status --relay` (no peer) prints a clap error, not a
  runtime error.
- `portl whoami --eid --json` prints a clap error.
- `portl install --apply --output foo.toml` prints a clap
  error.

### 9.2 Risks

- Any existing script passing `--yes` without `--apply` to
  `install` will break. portl is not publicly released; no
  production scripts to audit. Land the `requires`.

### 9.3 Open questions

None.

## 10. `portl completions <shell>`

Uses `clap_complete::generate`. ~30 lines of code.

### 10.1 Surface

```text
Usage: portl completions <SHELL>

Arguments:
  <SHELL>  [possible values: bash, zsh, fish, powershell, elvish, nushell]
```

### 10.2 Examples

```text
portl completions bash  | sudo tee /etc/bash_completion.d/portl
portl completions zsh   > "${fpath[1]}/_portl"
portl completions fish  > ~/.config/fish/completions/portl.fish
```

### 10.3 Non-goals

- Dynamic completion (peer labels, ticket labels) is out of
  scope for Tier 1. `clap_complete` static completion
  covers verbs and flags only.

### 10.4 Open questions

- `install.sh` shell-completion auto-install is deferred
  from Tier 1 to keep the diff pure CLI. Land it alongside
  §20's `install.sh` man-page step (same pattern: detect
  shell, detect target dir, best-effort install,
  `PORTL_INSTALL_COMPLETIONS=0` to opt out). Tracked in
  §10.5 rather than the master list.

### 10.5 Follow-up (not blocking)

`install.sh` completion step, paired with §20.4's man-page
step:

- Detect `$SHELL` (or probe via `ps -p $PPID -o comm=`).
- For bash: write to
  `${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions/portl`
  if writable; fall back to `/etc/bash_completion.d/` if
  running as root.
- For zsh: write to the first writable directory in
  `fpath`; fall back to
  `${XDG_DATA_HOME:-$HOME/.local/share}/zsh/site-functions/_portl`.
- For fish: write to
  `${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions/portl.fish`.
- Skip silently on failure.
- `PORTL_INSTALL_COMPLETIONS=0` opts out.

## 11. Actionable error messages

Unanimous reviewer call: single highest-leverage newcomer
change in the entire plan.

Every user-facing failure gets a "next command" suggestion
appended via `anyhow::Context` or a tiny `suggest!` macro.

### 11.1 Concrete rewrites

| Trigger | Before | After |
|---|---|---|
| No identity | `Error: identity file not found` | `error: no local identity. Run \`portl init\` first.` |
| Peer not found (label) | `Error: peer not found: foo` | `error: no peer labeled 'foo'. Run \`portl peer ls\` to see known peers, or \`portl accept <code>\` to add one from an invite.` |
| Malformed `-L` spec | `Error: invalid local forward spec` | `error: invalid forward '8080'. Expected [LOCAL_HOST:]LOCAL_PORT:REMOTE_HOST:REMOTE_PORT (e.g. 8080:localhost:80).` |
| Agent not running (IPC calls) | `Error: could not open UDS: connection refused` | `error: agent is not running. Start it with \`portl install --apply\` or run \`portl-agent\` in the foreground.` |
| Ticket expired | `Error: ticket expired at …` | `error: ticket expired at <RFC3339>. Issue a fresh one with \`portl ticket issue\` on the peer.` |
| Invite code expired | `Error: invite code expired` | `error: invite code expired N seconds ago. Ask the issuer for a fresh code (\`portl invite\`).` |
| Ticket revoked | `Error: ticket revoked` | `error: ticket revoked. Issue a fresh one with \`portl ticket issue\` on the peer.` |
| Ticket cap mismatch | `Error: capability not granted` | `error: ticket does not grant '<cap>'. Run \`portl ticket caps\` for the grammar, or ask the peer to re-issue with \`--caps <new>\`.` |
| Wrong prefix: `accept PORTLTKT-…` | `Error: invalid invite code` | `error: that looks like a ticket (PORTLTKT-…), not an invite. Did you mean \`portl ticket save <label> <ticket>\`?` (also §14.14) |
| Wrong prefix: `ticket save PORTLINV-…` | `Error: invalid ticket` | `error: that looks like an invite (PORTLINV-…), not a ticket. Did you mean \`portl accept <code>\`?` (also §14.14) |
| Unknown cap in `ticket issue` | `Error: unknown cap 'foo'` | `error: unknown cap 'foo'. Run \`portl ticket caps\` for the grammar.` |
| Unreachable (ping fails) | `Error: dial failed` | `error: could not reach <peer> (N/M probes failed). Run \`portl doctor --verbose\` on both sides, or check \`portl peer ls --active\`.` |

### 11.2 Implementation

- Prefer `anyhow::Context::with_context(|| …)` at the call
  site rather than a global error-remapping layer.
- Two-line rule: first line is the bare error, second line
  (empty or `note:` prefixed) is the suggested command.
- Never suggest a command that doesn't exist in the CLI.
  Enforced by a unit test that parses `help --all` and
  asserts every backtick-quoted suggestion resolves.
- Suggestions use commands that work at the user's current
  state. The "peer not found" suggestion offers both
  `peer ls` (to see what exists) and `accept <code>` (to
  add a new one) — not `invite`, which only makes sense on
  the other machine.

### 11.3 Acceptance

- Integration test matrix in `crates/portl-cli/tests/
  error_messages.rs` covering each row of §11.1.
- Manual smoke against the six most common newcomer foot-
  guns.

### 11.4 Open questions

None.

## 12. `init --quiet`

### 12.1 Summary

New `--quiet` / `-q` flag on `portl init`. Suppresses the
post-init doctor table and the welcome banner; does not
suppress stderr errors. Useful for CI and `Dockerfile RUN`
steps where the doctor output is noise.

```rust
#[arg(long, short = 'q', help = "Suppress the doctor table and welcome banner.")]
quiet: bool,
```

Precedence (same rule as §22.5):

1. `--quiet` on the CLI.
2. `PORTL_QUIET=1` in the environment.
3. Default: verbose.

### 12.2 Acceptance

- `portl init --quiet` prints nothing on success; exits 0.
- `PORTL_QUIET=1 portl init` same behavior.
- `portl init --quiet` still prints error details on
  failure (e.g. permission denied on state dir).
- Help snapshots regenerate.

### 12.3 Non-goals

- Global `--quiet` on every verb. That is Tier 2 via
  `PORTL_QUIET` (§22.2). `init --quiet` is the single
  high-leverage case that ships in Tier 1.

### 12.4 Open questions

None.

## 13. Explicitly dropped items

Dropped from the audit based on unanimous reviewer veto.
Documented here so we don't rediscover them.

### 13.1 Do NOT collapse `shell` + `exec` into `run [--pty]`

- All three reviewers rejected.
- `shell`/`exec` map 1:1 to `ssh` / `ssh host cmd` muscle
  memory.
- Separate verbs prevent scripts accidentally hanging with a
  PTY.
- Different flag surface is warranted
  (`shell` needs resize signalling, `exec` needs exit-code
  passthrough).

### 13.2 Do NOT rename `peer add-unsafe-raw`

- All three reviewers rejected.
- `-unsafe-` in the verb name is a deliberate safety signal.
- Renaming to `peer add --raw` (or any flag-only form) erodes
  the signal.
- If renamed in the future, the word "unsafe" must remain in
  what the user types, e.g. `peer add --unsafe`.

### 13.3 Do NOT add a global `--yes`

- All three reviewers rejected.
- Different commands have different confirmation semantics:
  - `doctor --yes` (only meaningful with `--fix`)
  - `peer add-unsafe-raw --yes` (skip retype prompt)
  - `install --yes` (skip write/enable prompt)
- A top-level `--yes` would silently auto-approve all three.
- Scope stays per-command by design.

### 13.4 Do NOT move `gateway` under `slicer` yet

- Two reviewers flagged this as premature.
- `gateway` may be an independent forwarding primitive, not
  just a slicer helper.
- Revisit once the role is clearer.

### 13.5 Do NOT emit deprecation warnings on aliases

- Any alias that does land (see §18.4) is permanent and
  silent. Never emit deprecation stderr.
- Deprecation stderr on every invocation is user-hostile in
  cron / systemd logs.
- Removal of the old form is the default under this spec:
  portl has not been publicly released, so each section
  picks the final name and deletes the rest.

## 14. Invite namespace + Model A (inviter-dictated permission shape)

### 14.1 Summary

The current `peer invite` / `peer pair` / `peer accept`
trio is replaced with a dedicated top-level `invite`
namespace plus one top-level consumer verb. The permission
shape moves from the acceptor (today) to the inviter: the
issuer of an invite specifies what access the code grants,
and the acceptor either takes the offered terms or refuses.

This is **the largest CLI change in the spec** and the one
with the most reviewer scrutiny. Section 14 locks the
surface, the wire change, the help copy (including
personalized confirmation prompts), and the relationship to
the `peer` and `ticket` namespaces.

Roundtable review calibrated three surface-level choices
that differ from earlier drafts:

- `--initiator mutual|me|them` replaces the earlier
  `--mutual` / `--inbound-only` / `--outbound-only` trio.
- `portl accept <code>` is a first-class top-level verb;
  `portl invite accept <code>` is a visible subcommand
  alias for namespace completeness.
- Help, prompts, and success messages share one
  two-clause phrasing ("{X} can reach {Y}"), with three
  voices: generic (help), first-person observer
  (inviter's prompts), second-person direct (acceptor's
  prompts).

### 14.2 Final surface

```text
Top-level:
  invite                      issue a code (shorthand: invite issue with defaults)
  invite issue [flags]        issue a code (explicit form)
  invite ls [--json]          list my pending invites
  invite rm <prefix>          revoke one of my pending invites
  invite accept <code>        consume a code (alias of top-level accept)
  accept <code>               consume a code (canonical top-level form)

peer namespace (slimmed):
  peer ls
  peer rm                     (was: peer unlink; unlink removed outright)
  peer add-unsafe-raw         (unchanged)

Removed outright (no compat shim, no redirect):
  peer invite                 → invite
  peer pair                   → deleted (use `accept` under Model A)
  peer accept                 → accept
  peer unlink                 → peer rm
```

### 14.3 Model A: inviter dictates the relationship

v0.3.4 shipped with acceptor-chooses: `peer pair` produced
mutual trust, `peer accept` produced one-way inbound.
Inviter had no input into the result.

Model A inverts this. The issuer specifies the offered
shape when minting the code. The shape is encoded in the
code's wire body. The acceptor runs one verb; they either
agree to the offered terms or refuse.

Rationale — **capability, not consistency**. The v0.3.4
model cannot express a support engineer issuing a one-way
inbound grant that the customer is prevented from
unilaterally upgrading to mutual. Model A makes that
expressible. Alignment with SSH / WireGuard / Tailscale /
Matrix is a nice side-effect but not the load-bearing
argument.

### 14.4 `--initiator` flag

The flag answers *"who opens connections after pairing?"*

```text
--initiator <WHO>    Default: mutual.

    mutual   both sides can reach each other           (paired devices)
    me       I can reach them; they cannot reach me    (remote support)
    them     they can reach me; I cannot reach them    (inbound-only hosts)
```

Design choice: the value names (`me`, `them`) are anchored
to the person typing the command. That anchor eliminates
the "inbound to whom?" confusion that directional names
(`--inbound-only`, etc.) guaranteed. `me` is always the
inviter; `them` is always the acceptor.

Rejected alternatives:

- `--inbound-only` / `--outbound-only`: describes the
  connection from the acceptor's POV while the inviter is
  making an outbound action. All three reviewers flagged
  as unshippable.
- `--they-reach-me` / `--i-reach-them`: unambiguous but
  two flags for what is conceptually one choice.
- `--mode support|reverse|mutual`: use-case names collide
  with scenarios (a support engineer and an inbound-only
  server both use `--initiator me` or `them` depending on
  which side is hosting).
- `--caller`: over-implies phone/voice semantics.

### 14.5 Personalized help, prompts, and success messages

Every operator- and acceptor-facing string about this
relationship uses the same two-clause phrasing:
`{X} can reach {Y}` / `{X} cannot reach {Y}`. The voice
shifts by moment:

1. **Static `--help` (generic voice).** Shown before any
   runtime context; uses "I" / "they".
2. **Inviter's issue-time prompt (first-person observer).**
   Shown after `portl invite …` parses and before the
   code is minted; uses the inviter's self-label and the
   `--for` hint (or "them" when hint is absent).
3. **Acceptor's accept-time prompt (second-person direct).**
   Shown when `portl accept <code>` runs and before the
   peer row is written; uses the inviter's label (resolved
   from the code + PairResponse) and second-person
   "you".
4. **Post-pair success messages (match the prompts).** Both
   sides reuse the exact phrasing from their respective
   prompts.

Each moment is `--yes`-suppressible; non-TTY contexts
imply `--yes`.

#### 14.5.1 Inviter's issue-time prompt

```text
$ portl invite --initiator me --for laptop

You are about to issue an invite as 'max'.

  After laptop accepts this code:
    max can reach laptop
    laptop cannot reach max

Issue? [Y/n]
```

With `--initiator them`:

```text
  After laptop accepts this code:
    laptop can reach max
    max cannot reach laptop
```

With `--initiator mutual` (default):

```text
  After laptop accepts this code:
    max and laptop can reach each other
```

With no `--for` hint, "laptop" falls back to "them":

```text
  After they accept this code:
    max can reach them
    they cannot reach max
```

#### 14.5.2 Acceptor's accept-time prompt

```text
$ portl accept PORTLINV-…

max is inviting you to pair with one-way access.

  If you accept:
    max can reach you
    you cannot reach max

Accept? [Y/n]
```

With `--initiator them` on the inviter side:

```text
  If you accept:
    you can reach max
    max cannot reach you
```

With `--initiator mutual`:

```text
max is inviting you to pair with mutual access.

  If you accept:
    max and you can reach each other
```

#### 14.5.3 Post-pair success messages

Inviter side (printed by the agent to its log/dashboard;
shown live if operator is watching `portl status`):

```text
laptop paired. max can reach laptop; laptop cannot reach max.
```

Acceptor side (printed to stdout by `portl accept`):

```text
paired with max. max can reach you; you cannot reach max.
```

#### 14.5.4 Label resolution fallbacks

| Slot | Primary | Fallback |
|---|---|---|
| Inviter's self-label | `peer ls` self-row label, or `whoami` advertised name | "I" (help) / first 8 hex of inviter eid |
| Acceptor's label on inviter side | `--for <LABEL>` flag | "them" (help) / the hint string if untrusted |
| Inviter's label on acceptor side | From PairResponse (inviter's advertised name) | First 8 hex of inviter eid |
| Acceptor's label on acceptor side | always "you" (second-person) | — |

Inviter's advertised name in PairResponse is inviter-chosen
and untrusted; the acceptor's client should truncate to
reasonable length and strip control characters before
displaying. Treated as UX polish, not auth.

### 14.6 Wire format

Invite code body:

```text
  version:1, inviter_eid:32, nonce:16, not_after:u64_le,
  initiator:1, relay_hint_len:1, relay_hint:var

initiator byte (after nonce+expiry, before hint):
  0x00 = mutual
  0x01 = me (inviter initiates)
  0x02 = them (acceptor initiates)
  0x03..=0xFF reserved (reject on parse)

version byte:
  0x01 only.
```

The initiator byte is added to portl's existing pair
code body. portl has not been publicly released; there
is no on-the-wire compatibility burden. The version byte
reads `0x01` and stays at `0x01`. Reserved initiator
values (`0x03..=0xFF`) are explicitly rejected on parse so
that future extensions cannot produce ambiguous semantics.

The pair ALPN stays `portl/pair/v1`. Servers and clients
are upgraded together; there is no cross-version handshake
to defend against.

### 14.7 Legacy verb removal

`peer invite`, `peer pair`, `peer accept`, and `peer unlink`
are deleted outright. No compat shim, no hidden redirects.
portl has not been publicly released, so there is no
accumulated muscle memory or script surface to soften.

Users who copy a stale command from pre-spec notes get
clap's normal "unrecognized subcommand" error, which on
modern clap includes a did-you-mean suggestion driven by
edit distance. For the three removed pair verbs, that
suggestion is good enough; the surface area of confusion
is tiny and short-lived.

### 14.8 (reserved)

Intentionally left blank. The previous §14.8 covered
`peer unlink` compat, which is now resolved by §14.7
(removed outright).

### 14.9 Clap shape

```rust
#[derive(Subcommand, Debug)]
enum TopLevel {
    // … existing verbs …

    // Namespace: invite. Fully parallel to `ticket`.
    Invite {
        #[command(subcommand)]
        action: Option<InviteAction>,

        // Bare-invite shorthand flags. When no subcommand is
        // given, these are forwarded to `InviteAction::Issue`.
        // Each conflicts with `action` at parse time.
        #[arg(long, value_enum, conflicts_with = "action")]
        initiator: Option<InitiatorMode>,
        #[arg(long, conflicts_with = "action")]
        ttl: Option<String>,
        #[arg(long = "for", conflicts_with = "action")]
        for_label: Option<String>,
        #[arg(long, conflicts_with = "action")]
        json: bool,
        #[arg(long, conflicts_with = "action")]
        yes: bool,
    },

    // Flat consumer. Top-level canonical.
    Accept {
        code: String,
        #[arg(long)] yes: bool,
    },

    Peer { #[command(subcommand)] action: PeerAction },
}

#[derive(Subcommand, Debug)]
enum InviteAction {
    Issue {
        #[arg(long, value_enum, default_value_t = InitiatorMode::Mutual)]
        initiator: InitiatorMode,
        #[arg(long)] ttl: Option<String>,
        #[arg(long = "for")] for_label: Option<String>,
        #[arg(long)] json: bool,
        #[arg(long)] yes: bool,
    },
    Ls { #[arg(long)] json: bool },
    Rm { prefix: String },
    // Alias of top-level `accept` for namespace completeness.
    Accept { code: String, #[arg(long)] yes: bool },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum InitiatorMode { Mutual, Me, Them }

#[derive(Subcommand, Debug)]
enum PeerAction {
    Ls { … },
    Rm { label: String },
    AddUnsafeRaw { … },
    // No Invite/Pair/Accept/Unlink variants. Removed.
}
```

Dispatch for the bare `Invite { action: None, … }` case
forwards the shorthand flags into `InviteAction::Issue`'s
handler directly. If `action` is `Some(Issue { … })`
**and** shorthand flags are also set, clap's
`conflicts_with` rejects at parse time — no silent
override.

### 14.10 Help text (final, canonical)

```text
Usage: portl invite [OPTIONS]
       portl invite <COMMAND>

Issue an invite code for another machine to redeem.

Commands:
  issue        Issue a code (explicit form)
  ls           List my pending invites
  rm           Revoke a pending invite
  accept       Consume a code (alias of `portl accept`)

Options (bare form, forwarded to `invite issue`):
      --initiator <WHO>
          Who can open connections after pairing. Default: mutual.

          mutual   both sides can reach each other           (paired devices)
          me       I can reach them; they cannot reach me    (remote support)
          them     they can reach me; I cannot reach them    (inbound-only hosts)

      --ttl <DURATION>
          Time-to-live. Seconds or s/m/h/d shorthand. Default: 1h.

      --for <LABEL>
          Hint the acceptor should use as the local peer label.

      --json
          Emit the issued code and metadata as JSON.

      --yes
          Skip the confirmation prompt. Implied in non-TTY.

  -h, --help
          Print help

Examples:
  portl invite                              # mutual pair, 1h TTL
  portl invite --initiator me --for cust    # remote-support invite
  portl invite --ttl 10m --for laptop
  portl invite ls
  portl invite rm abc123
```

```text
Usage: portl accept <CODE>

Consume an invite code issued by another machine.

Arguments:
  <CODE>   PORTLINV-… code received from the inviter.

Options:
      --yes    Skip the confirmation prompt. Implied in non-TTY.
  -h, --help   Print help

Examples:
  portl accept PORTLINV-ABCDEFGH…
  portl accept --yes PORTLINV-ABCDEFGH…
```

### 14.11 `Trust` group placement

Per roundtable (opus's dissent): `ticket` is demoted from
the newcomer-facing Trust group. Tier-1 `portl --help`
shows only the two verbs most newcomers will ever use for
trust management:

```text
Trust:
  peer      Manage paired machines
  invite    Issue codes to pair with new machines

Sessions (advanced):
  ticket    Manage session credentials

Pairing:
  accept    Consume an invite code
```

`ticket` keeps the same clap implementation and continues
to respond to `portl ticket --help`; it simply moves to a
less-prominent group so the tier-1 help reflects the
common-case surface. This is the only roundtable change
that touches §5's grouping table.

### 14.12 Getting Started block (docs + `portl --help`
after_long_help)

```text
Pair two machines:
  $ portl init
  $ portl invite                  # on the other machine (receive a code)
  $ portl accept PORTLINV-…       # on this machine (paste the code)
  $ portl shell other-machine     # connect
```

Four lines. Four verbs. The word "pair" lives in the
section header (task language preserved) while the verbs
are honest about the asymmetric trust model underneath.

### 14.13 Relationship to `peer` and `ticket`

This section appears in `portl invite --help` and
`portl peer --help` and `portl ticket --help` so newcomers
see the map from any entry point.

```text
                    peer              invite              ticket
Owns on disk        peers.json        pending_invites.jsonl  tickets.json + revocations.jsonl
Lifecycle           permanent         ephemeral (single-use) scoped by TTL
When created        on accept         by `portl invite`      by `portl ticket issue`
When consumed       on rm/unlink      on `portl accept`      every session

Workflow:
    first contact     →  `portl invite` + `portl accept`  (writes peer row)
    day-to-day auth   →  `portl shell <peer>`              (uses peer row implicitly)
    advanced: bounded →  `portl ticket issue` + `ticket save` (session credentials)
```

### 14.14 Cross-verb error teaching

`portl accept` and `portl ticket save` are the two receiver-
side consumer verbs. A user with a string in their
clipboard will sometimes pick the wrong verb. Both surfaces
redispatch with a helpful error:

```text
$ portl accept PORTLTKT-abc…

error: this looks like a ticket string, not an invite code.
       To save it for later use:
         portl ticket save PORTLTKT-abc…
```

```text
$ portl ticket save PORTLINV-abc…

error: this looks like an invite code, not a ticket.
       To redeem it and pair with the inviter:
         portl accept PORTLINV-abc…
```

Detection is prefix-only (`PORTLINV-` vs `PORTLTKT-`). No
network side-effect occurs on prefix mismatch.

### 14.15 Tier placement

All of §14 is **Tier 2**. It changes the wire format,
deletes verbs, introduces new verbs, and restructures one
namespace. It ships as a single coherent release together
with §15 (`ticket revoke` split), §17 (`config`
restructure), and §18 (`ls`/`rm` unification).

### 14.16 Acceptance

- `portl invite --help` renders the §14.10 help text
  exactly.
- `portl accept --help` renders the §14.10 help text.
- `portl invite --initiator me --for laptop` shows the
  §14.5.1 confirmation prompt.
- `portl accept <code>` shows the §14.5.2 prompt for any
  initiator value 0x00..=0x02 and rejects with a clear
  parse error for reserved values 0x03..=0xFF.
- `portl peer pair <code>`, `portl peer accept <code>`,
  `portl peer invite`, and `portl peer unlink foo` all
  exit non-zero with clap's standard "unrecognized
  subcommand" error (no custom redirect).
- `portl accept PORTLTKT-…` prints the §14.14 redirect
  to `ticket save`.
- `portl ticket save PORTLINV-…` prints the §14.14
  redirect to `accept`.
- `portl status <peer>` post-pair shows the relationship
  shape in its row output (not just "paired").
- All personalized strings use the §14.5 two-clause
  phrasing; integration test asserts the six phrasings
  (3 modes × 2 voices) render correctly.
- Invite wire roundtrips via postcard; reserved initiator
  bytes rejected with the documented error text.
- `crates/portl-proto/src/pair_v1.rs` keeps its module
  name and ALPN (`portl/pair/v1`); only the body's
  `initiator` byte is added.
- `crates/portl-cli/tests/help_cli.rs` snapshots
  regenerate for every renamed/removed verb.

### 14.17 Open questions

None. All surface questions from prior drafts are
resolved in §§14.4, 14.5, and 14.11.

## 15. Split `ticket revoke` verb-in-flag

### 15.1 Summary

Today `ticket revoke` is a verb-in-flag: `<ID>` triggers
revocation, `--list` swaps to listing, `--publish` adds a
broadcast side effect. Three conceptual verbs share one
surface.

Split into a bare positional form for the common case plus
two management subverbs. No sub-sub `add` / `append` verb:
the bare form is already unambiguous once `ls` and
`publish` are peers. Old flag forms are removed outright
(no public release means no compat debt).

### 15.2 Final surface

```text
Usage: portl ticket revoke <ID>
       portl ticket revoke <COMMAND>

Commands:
  ls        List local revocations
  publish   Broadcast revocations to paired peers
```

### 15.3 Bare form — `ticket revoke <ID>`

Appends a revocation to the local revocations log. Does
**not** publish automatically. Exits 0 on success with a
suggestion:

```text
$ portl ticket revoke a1b2c3d4e5f6a7b8

revoked a1b2c3d4e5f6a7b8

note: this revocation is local only. To broadcast to
      paired peers:
        portl ticket revoke publish a1b2c3d4e5f6a7b8
      or publish all unpushed revocations:
        portl ticket revoke publish
```

Rationale for local-only default: revocation is
destructive and security-critical. Auto-publishing could
push a revocation of the wrong ID to every paired peer
before the operator notices. Opt-in broadcast is the
safer default. The trailing `note:` teaches the next
command (§11 pattern).

Accepts `<ID>` in two forms:

1. 16-char `ticket_id` hex (from `portl ticket ls --json`).
2. A saved-ticket label (resolved via the alias store).

This matches the current shipped behavior.

### 15.4 `ticket revoke ls`

```text
Usage: portl ticket revoke ls [OPTIONS]

List local revocations (contents of revocations.jsonl).

Options:
      --json    Emit structured JSON.
  -h, --help    Print help
```

Pure read operation. No side effects.

### 15.5 `ticket revoke publish`

```text
Usage: portl ticket revoke publish [OPTIONS] [ID]

Broadcast revocations to all paired peers.

Arguments:
  [ID]    Publish only this ticket_id. Omit to publish all
          unpushed revocations.

Options:
      --yes     Skip the confirmation prompt. Implied in non-TTY.
  -h, --help    Print help
```

TTY behavior — `publish` (no ID):

```text
$ portl ticket revoke publish

Publishing 3 revocations to 4 paired peers:
  a1b2c3d4e5f6a7b8 (revoked 2h ago)
  c3d4e5f6a7b8a1b2 (revoked 1d ago)
  e5f6a7b8a1b2c3d4 (revoked 3d ago)

Continue? [Y/n]
```

TTY behavior — `publish <ID>`:

```text
$ portl ticket revoke publish a1b2c3d4e5f6a7b8

Publishing 1 revocation (a1b2c3d4e5f6a7b8) to 4 paired peers.
Continue? [Y/n]
```

Both forms skippable via `--yes`. Non-TTY implies `--yes`.

If `<ID>` is passed but not present in the local
revocations log, errors:

```text
error: no local revocation for a1b2c3d4e5f6a7b8.
       To revoke and publish in one go:
         portl ticket revoke a1b2c3d4e5f6a7b8 && \
           portl ticket revoke publish a1b2c3d4e5f6a7b8
```

### 15.6 Removals

Deleted outright:

- `portl ticket revoke --list`
- `portl ticket revoke --publish`
- `portl ticket revoke --publish <ID>` combined form

Users typing the old flag get clap's standard
"unrecognized flag" error. No custom redirect.

### 15.7 Clap shape

```rust
#[derive(Args, Debug)]
struct RevokeArgs {
    // Bare positional: the ticket_id or alias to revoke locally.
    #[arg(conflicts_with = "action")]
    id: Option<String>,

    #[command(subcommand)]
    action: Option<RevokeAction>,
}

#[derive(Subcommand, Debug)]
enum RevokeAction {
    Ls {
        #[arg(long)] json: bool,
    },
    Publish {
        id: Option<String>,
        #[arg(long)] yes: bool,
    },
}
```

Dispatch: if `action.is_some()`, run that subverb; else
if `id.is_some()`, run the bare revoke; else error with
clap's required-arg message.

### 15.8 Tier placement

**Tier 2.** Ships alongside §14, §17, §18 in the same
release.

### 15.9 Acceptance

- `portl ticket revoke --help` renders the §15.2 shape.
- `portl ticket revoke <ID>` appends and prints the §15.3
  teaching note.
- `portl ticket revoke ls` lists; `--json` round-trips.
- `portl ticket revoke publish` with no args shows the
  §15.5 "3 revocations to 4 peers" prompt, skippable via
  `--yes`.
- `portl ticket revoke publish <ID>` shows the
  single-revocation prompt; errors with the §15.5
  "no local revocation" message if ID not in log.
- `portl ticket revoke --list` exits non-zero with clap
  "unrecognized flag".
- `portl ticket revoke --publish <ID>` exits non-zero
  with clap error.
- Help snapshots regenerate.

### 15.10 Open questions

None. Q1 (default publish behavior) resolved in §15.3 as
local-only with a teaching note. Q2 (`add`/`append`
sub-sub-verb) resolved in §15.1 as not needed. Q3
(`publish` scope) resolved in §15.5 as all-with-prompt.

## 16. `ticket caps` sub-verb

### 16.1 Summary

The capability grammar reference is currently emitted by
`portl ticket issue --list-caps` — a flag doing a verb's
job. Promote it to a proper subverb: `portl ticket caps`.
Delete the flag.

### 16.2 Final surface

```text
Usage: portl ticket caps [OPTIONS]

Print the capability-grammar reference used by
`portl ticket issue`.

Options:
      --cap <NAME>   Print only the entry for this cap
                     (e.g. `shell`, `tcp`, `meta:info`).
                     Exit non-zero if unknown.
      --json         Emit structured JSON. One object per
                     cap with `name`, `summary`,
                     `argument_grammar`, `examples`.
  -h, --help         Print help

Examples:
  portl ticket caps
  portl ticket caps --cap tcp
  portl ticket caps --json | jq '.[] | .name'
```

### 16.3 Removals

Deleted outright:

- `portl ticket issue --list-caps`

Users typing the old flag get clap's standard
"unrecognized flag" error. No custom redirect (no public
release).

### 16.4 Output shape

Human output identical to today's `ticket issue
--list-caps` (§16 is not rewriting the reference text).

JSON schema:

```json
{
  "schema": 1,
  "kind": "ticket.caps",
  "caps": [
    {
      "name": "shell",
      "summary": "Full shell access — PTY allowed, exec allowed, no env filter.",
      "argument_grammar": null,
      "examples": [
        "portl ticket issue shell --ttl 10m"
      ]
    },
    {
      "name": "tcp",
      "summary": "TCP port forward.",
      "argument_grammar": "tcp:<host_glob>:<port>[-<port_max>]",
      "examples": [
        "portl ticket issue 'tcp:*:8080' --ttl 1h",
        "portl ticket issue 'tcp:127.0.0.1:6000-6100' --ttl 30m"
      ]
    }
  ]
}
```

`--cap <NAME>` emits the matching entry (single object
under `caps: [...]` or, in human mode, just the one
entry's section). Unknown cap → non-zero exit with:

```text
error: unknown cap 'foo'. Run `portl ticket caps` for the
       full reference.
```

### 16.5 Clap shape

```rust
#[derive(Args, Debug)]
struct CapsArgs {
    #[arg(long, value_name = "NAME")] cap: Option<String>,
    #[arg(long)] json: bool,
}
```

Added to `TicketAction` alongside `Issue`, `Save`, `Ls`,
`Rm`, `Prune`, `Revoke`.

### 16.6 Tier placement

**Tier 2.** Ships alongside §14, §15, §17, §18 in the
same release.

### 16.7 Acceptance

- `portl ticket caps` prints the full reference (same
  text as today's `--list-caps`).
- `portl ticket caps --cap shell` prints only the shell
  entry.
- `portl ticket caps --cap bogus` exits non-zero with the
  §16.4 error.
- `portl ticket caps --json` emits valid JSON matching
  the §16.4 schema.
- `portl ticket caps --cap tcp --json` emits a
  single-entry JSON array.
- `portl ticket issue --list-caps` exits non-zero with
  clap "unrecognized flag".
- Help snapshots regenerate for `ticket --help` and
  `ticket caps --help`.

### 16.8 Open questions

None.

## 17. `config` command group

### 17.1 Summary

The verb tree stays at four commands. One verb is renamed
(`default` → `template`), one flag is renamed
(`validate --file` → `--path`), and `--json` is added to
the two verbs that produce structured data. Old names and
flags are removed outright (no alias). Every verb gains a
long-form description and `after_long_help` examples.

Three earlier proposals are **dropped** from this spec:
`config edit`, `config init`, and `config show --include-env`.
Rationale inline below.

### 17.2 Final tree

```text
portl config <COMMAND>
  show       Print the effective file-layer config
  path       Print the absolute path to portl.toml
  template   Print a commented default template to stdout   (was: default)
  validate   Parse + type-check portl.toml
```

### 17.3 `config show` — add `--json`

**Tier:** Tier 1 (additive).

Current output: pretty-printed TOML with a `# source: …`
header. `--json` emits the same parsed `PortlConfig`
serialized as JSON, omitting the header.

`config show` stays strictly file-layer. Env-var overrides
are not shown. The existing help comment (`env overrides not
shown`) becomes enforced behavior: there is no
`--include-env` flag. Rationale:

- `PORTL_*` names collide with shape-based secret detection
  (e.g. `PORTL_RELAY_KEY` is a path, not a key; a blocklist
  matching `*KEY*` would redact a benign path).
- A blocklist is fragile: a future `PORTL_AUTH_PASS` would
  leak.
- Operators who want the env surface can use `env | grep
  ^PORTL_` today; a dedicated verb can land later if demand
  materializes. Out of scope here.

Surface:

```text
Usage: portl config show [OPTIONS]

Print the effective file-layer config. Env overrides
(`PORTL_*`) are not shown; inspect them with
`env | grep ^PORTL_`.

Options:
      --json    Emit structured JSON instead of TOML.
  -h, --help    Print help

Examples:
  portl config show
  portl config show --json | jq '.agent.listener'
```

### 17.4 `config path` — documentation only

**Tier:** Tier 1.

No behavior change. Help text clarifies that the path is
derived from `PORTL_HOME` and that the file is allowed to
not exist (path is printed regardless).

```text
Usage: portl config path

Print the absolute path to `portl.toml`. Honors
`$PORTL_HOME`; falls back to the platform default. The file
is not required to exist.

Examples:
  portl config path
  cat "$(portl config path)"
  portl config template > "$(portl config path)"
```

### 17.5 `config default` → `config template` (rename)

**Tier:** Tier 2 (rename).

Rationale: `default` reads as "print the default value of a
key" (cf. `git config --default`), not "emit a template
file." `template` is unambiguous.

- `config template` becomes canonical.
- `config default` is **removed outright** — no hidden
  alias. portl has not been publicly released; no compat
  shim earned.
- Behavior is byte-for-byte identical to today.
- Help text changes to describe scaffolding via redirection.

```text
Usage: portl config template

Print a commented default `portl.toml` template to stdout.
Pipe into the path from `portl config path` to scaffold.

Examples:
  portl config template > "$(portl config path)"
  portl config template | portl config validate --stdin
```

### 17.6 `config validate` — `--path` rename + `--json` + `--stdin`

**Tier:** Tier 2 for the rename; Tier 1 for `--json` and
`--stdin` (both additive).

Today: `--file <PATH>` or no flag (defaults to
`$PORTL_HOME/portl.toml`).

Changes:

- Rename `--file` → `--path`. Every other path-taking flag
  in portl is spelled `--path`; `config validate` was the
  outlier.
- `--file` is **removed outright** — no hidden alias.
- Add `--stdin` to read TOML from standard input (useful
  for `template | validate --stdin` pipelines and for CI
  that generates configs dynamically).
- Add `--json` for structured parse errors. Non-`--json`
  output unchanged.

`--path` and `--stdin` are mutually exclusive (clap
`conflicts_with`).

Surface:

```text
Usage: portl config validate [OPTIONS]

Parse + type-check a `portl.toml`. Defaults to
`$PORTL_HOME/portl.toml`. Exits 0 on success, non-zero on
parse or type error.

Options:
      --path <PATH>   Path to validate. Defaults to
                      `$PORTL_HOME/portl.toml`. Conflicts
                      with --stdin.
      --stdin         Read TOML from standard input.
      --json          Emit structured errors as JSON.
  -h, --help          Print help

Examples:
  portl config validate
  portl config validate --path ./staging-portl.toml
  portl config template | portl config validate --stdin
  portl config validate --json | jq .errors
```

### 17.7 Dropped from this spec

Three earlier proposals are out of scope. Captured here so
they do not get re-invented without a fresh discussion.

- **`config init`**. `portl init` already scaffolds
  `portl.toml` on fresh installs; `portl config template >
  "$(portl config path)"` covers re-scaffolding. Two verbs
  that write the same file is the bug, not the feature.
- **`config edit`**. `$EDITOR "$(portl config path)"` is the
  canonical pattern. Atomic validate-and-rollback adds
  code paths (tempfile shuffle, swap, editor probing) for a
  small ergonomic win. Revisit only if user demand
  materializes.
- **`config show --include-env`**. Shape-based secret
  redaction is fragile against `PORTL_*` naming collisions
  (e.g. `PORTL_RELAY_KEY` is a path). Env surface can live
  in a dedicated verb if it ever ships.

### 17.8 Tier summary

| Change | Tier | Breakage |
|---|---|---|
| `config show --json` | 1 | none (additive) |
| `config validate --json` | 1 | none (additive) |
| `config validate --stdin` | 1 | none (additive) |
| Docstrings + `after_long_help` on all four verbs | 1 | none |
| `config default` → `config template` | 2 | rename, no alias |
| `config validate --file` → `--path` | 2 | rename, no alias |

### 17.9 Acceptance

- `portl config --help` lists 4 verbs with the new
  descriptions.
- `portl config default` exits non-zero with clap
  "unrecognized subcommand".
- `portl config validate --file foo.toml` exits non-zero
  with clap "unrecognized flag".
- `portl config show --json` round-trips through
  `serde_json::from_str::<PortlConfig>` cleanly.
- `portl config template | portl config validate --stdin`
  exits 0.
- `crates/portl-cli/tests/help_cli.rs` snapshots
  regenerate and pass.

### 17.10 Open questions

None. Tracked decisions are captured in §17.7.

## 18. Unify the `ls` / `rm` verbs

### 18.1 Summary

The verb tree today has two inconsistencies:

- `peer` and `ticket` use `ls`; `docker` and `slicer` use
  `list`.
- `peer` uses `unlink`; `ticket`, `docker`, `slicer` use
  `rm`.

Unify on `ls` and `rm` using two different strategies:

- **`list` → `ls`** across the tree, Docker-style:
  `ls` is canonical and shown in `--help`; `list` keeps
  working silently. This matches the docker convention
  (`docker container ls` canonical, `docker container
  list` accepted), so operators already moving between
  tools do not have to re-learn.
- **`unlink` → `rm`** on `peer`: `unlink` is removed
  outright. It is portl-specific vocabulary nobody types
  unless they learned it from our own docs; keeping a
  silent alias would carry dead weight.

### 18.2 Final tree

```text
portl docker   ls   (alias: list)
portl slicer   ls   (alias: list)
portl peer     rm   (unlink: removed)
portl ticket   rm   (already canonical; unchanged)
portl peer     ls   (already canonical; unchanged)
portl ticket   ls   (already canonical; unchanged)
```

### 18.3 Additions

| New canonical | Namespace | Visible in `--help` |
|---|---|---|
| `portl docker ls` | docker | yes |
| `portl slicer ls` | slicer | yes |
| `portl peer rm <label>` | peer | yes |

No new handler code. These are clap-attribute flips —
existing handler functions swap which name is canonical.

### 18.4 Silent aliases (kept forever)

| Hidden alias | Canonical form |
|---|---|
| `portl docker list` | `portl docker ls` |
| `portl slicer list` | `portl slicer ls` |

These keep working byte-for-byte identically. Not shown in
`--help`. No deprecation stderr. Matches Docker's own
pattern.

### 18.5 Removals (breaking)

| Removed | Replacement |
|---|---|
| `portl peer unlink <label>` | `portl peer rm <label>` |

`peer unlink` is removed outright, not aliased. Any script
invoking it will need a one-line change. Migration note
lands in the release CHANGELOG; no deprecation window.

Rationale: `unlink` is not vocabulary any operator types
from muscle memory on other tools — it is strictly something
they copy-pasted from portl's own documentation.
Eliminating it removes a line from the help output and from
user confusion ("is it rm or unlink?"); keeping it as a
silent alias would propagate the inconsistency indefinitely.

Trade-off acknowledged: one reviewer argued `unlink` is
semantically more precise than `rm` for trust severance.
The operator call was to prioritize simplicity over
semantic precision, since `rm` already applies to peers'
sibling noun (`ticket`) without confusion.

### 18.6 Explicitly untouched

| Namespace | Verb | Reason untouched |
|---|---|---|
| peer | `add-unsafe-raw` | Safety signal (§13.2) |
| ticket | `issue`, `save`, `prune`, `revoke` | Domain verbs |
| ticket | `rm` | Already canonical |
| ticket | — | No `unlink` alias added; nobody types it |
| docker | `run`, `attach`, `detach`, `bake`, `rm` | Domain verbs / already canonical |
| slicer | `run`, `rm` | Domain verbs / already canonical |

### 18.7 Clap shape

```rust
// docker / slicer: visible canonical + silent alias
#[derive(Subcommand, Debug)]
enum DockerAction {
    Run { … },
    Attach { … },
    Detach { … },
    #[command(name = "ls", alias = "list")]
    Ls { … },
    Rm { … },
    Bake { … },
}

// peer: canonical-only, no backward alias.
// (Invite/pair/accept deleted; see §14.)
#[derive(Subcommand, Debug)]
enum PeerAction {
    Ls { … },
    Rm { label: String },   // note: no `alias = "unlink"`
    AddUnsafeRaw { … },
}
```

Use clap's `alias` (not `visible_alias`) for the `list →
ls` pairings so the hidden form works silently without
cluttering `--help`.

### 18.8 Tier placement

All of §18 is **Tier 2** (surface change). It ships
alongside other alias-landing work (§14, §15) in the same
release.

### 18.9 Migration impact

Scripts / docs to sweep:

- `crates/portl-agent/src/lib.rs` comment referring to
  `portl peer unlink` → `portl peer rm`.
- `crates/portl-cli/src/commands/peer/add_unsafe_raw.rs`
  error message → `portl peer rm`.
- `crates/portl-cli/src/commands/peer/unlink.rs` module →
  rename file to `rm.rs`, update `mod.rs`.
- `crates/portl-cli/src/lib.rs` `Command::PeerUnlink` →
  `Command::PeerRm`.
- `crates/portl-cli/tests/help_cli.rs` snapshots.
- `CHANGELOG.md` migration note on the release that lands
  this.

Historical CHANGELOG entries (pre-Tier-2) stay as-is.

### 18.10 Acceptance

- `portl docker --help` shows `ls` not `list`; `docker
  list foo` keeps working.
- `portl slicer --help` shows `ls` not `list`; `slicer
  list` keeps working.
- `portl peer --help` shows `rm` not `unlink`; `peer
  unlink foo` errors with a clap "unknown subcommand"
  message that suggests `rm`.
- `crates/portl-cli/tests/backward_compat.rs` covers
  `docker list`, `slicer list` as still-working forms and
  asserts `peer unlink` is a clap error.
- Help snapshots regenerated.

### 18.11 Open questions

None. Decisions captured in §§18.4–18.6.

## 19. `portl status [PEER]`

### 19.1 Summary

`portl status` is the single "how are things?" verb. With
no argument, it reports on **self** (local dashboard:
agent health, paired peers, active sessions). With a
`<PEER>` argument, it reports on a remote peer (one-shot
reachability probe plus metadata).

"Self" is the default because every operator's first
question on a fresh machine is "am I set up?" — the
answer should not require typing `portl status self` or
similar. An explicit peer argument switches the subject
from self to that peer.

No separate `portl ping` verb. One verb, one subject
(inferred from args). Documentation is the load-bearing
part: `status` means "check health," and the optional
positional is the target.

### 19.2 Final surface

```text
Usage: portl status [OPTIONS] [PEER]

Report health. With no PEER, reports on the local agent
and paired peers (the "self" dashboard). With a PEER,
probes that peer and prints the probe result.

Arguments:
  [PEER]   Label, endpoint_id, or ticket. Omit for the
           local dashboard (self).

Options (any target):
      --json             Emit structured JSON.
  -h, --help             Print help

Options (self only; ignored when PEER is given):
      --watch <SECS>     Re-render dashboard every N seconds
                         (min 1, max 3600). Incompatible
                         with --json.

Options (peer only; error if PEER omitted):
      --relay            Force the handshake over the
                         peer's relay path.
      --count <N>        Probe N times with 1s intervals
                         (default 1).
      --timeout <DUR>    Fail a single probe after DUR
                         (e.g. `500ms`, `3s`, default
                         `5s`). Reuses ticket TTL
                         duration parser.

Examples:
  portl status                     # self: agent + peers
  portl status --watch 2           # refresh self every 2s
  portl status --json              # self, structured
  portl status laptop              # probe a peer once
  portl status laptop --count 5    # probe 5 times
  portl status laptop --relay      # force relay path
  portl status laptop --json       # structured probe
```

### 19.3 Argument-mode matrix

clap enforces which flags apply to which mode. Flags in
the wrong mode are rejected at parse time.

| Flag | self (no PEER) | peer (PEER given) |
|---|---|---|
| `--json`    | ok | ok |
| `--watch`   | ok | **reject** (`--watch` requires no PEER) |
| `--relay`   | **reject** (`--relay` requires a PEER) | ok |
| `--count`   | **reject** | ok |
| `--timeout` | **reject** | ok |

Reject messages name the offending flag and state the
missing/forbidden argument — e.g.:

```text
error: --watch cannot be used with a PEER argument
       (watch is for the self dashboard).

error: --relay requires a PEER argument
       (nothing to relay when target is self).
```

### 19.4 Exit codes

- Self dashboard renders successfully → 0.
- Self dashboard: agent unreachable → 11.
- Peer probe: any successful probe (at least one of N) → 0.
- Peer probe: all probes fail → 21 (peer dial failed).
- Peer probe: peer not found in local store → 20.
- Argument mode violation → 2 (clap).

### 19.5 JSON shape

Self mode — single object:

```json
{
  "schema": 1,
  "kind": "status.self",
  "agent": { "running": true, "version": "0.3.4", "uptime_s": 3612 },
  "identity": { "endpoint_id": "…", "label": "laptop" },
  "peers": [
    { "label": "server", "endpoint_id": "…", "last_seen_s": 42 }
  ],
  "sessions": [ … ]
}
```

Peer mode — NDJSON per probe (one line each with
`--count N`):

```json
{"schema":1,"kind":"status.probe","seq":0,"peer":"laptop","path":"direct","rtt_ms":14.2,"ok":true}
{"schema":1,"kind":"status.probe","seq":1,"peer":"laptop","path":"relay","rtt_ms":87.1,"ok":true}
{"schema":1,"kind":"status.probe","seq":2,"peer":"laptop","rtt_ms":null,"ok":false,"error":"timeout after 5s"}
```

`kind` differs between modes (`status.self` vs
`status.probe`) so downstream parsers can branch on it
without peeking at the top-level shape.

### 19.6 Clap shape

```rust
#[derive(Args, Debug)]
struct StatusArgs {
    peer: Option<String>,

    #[arg(long)] json: bool,

    // Self-only.
    #[arg(long, conflicts_with = "peer")]
    watch: Option<u64>,

    // Peer-only. `requires = "peer"` makes each a parse
    // error when PEER is absent.
    #[arg(long, requires = "peer")]
    relay: bool,
    #[arg(long, requires = "peer", default_value_t = 1)]
    count: u32,
    #[arg(long, requires = "peer", default_value = "5s",
          value_parser = parse_duration)]
    timeout: Duration,
}
```

clap's `requires` / `conflicts_with` produces the
reject behavior described in §19.3 without a custom
dispatch layer.

### 19.7 Tier placement

**Tier 2.** The flag matrix (requires/conflicts) and
added peer-mode options are new surface; ships alongside
§14–§18 in the same release.

### 19.8 Acceptance

- `portl status --help` renders the §19.2 help text with
  the three option groups labeled.
- `portl status` renders the self dashboard.
- `portl status --watch 2` refreshes every 2s.
- `portl status --json` emits a `status.self` object.
- `portl status laptop` probes once, exits 0 on success.
- `portl status laptop --count 5` probes 5 times; exits 0
  if any succeed.
- `portl status laptop --json` emits one `status.probe`
  NDJSON line.
- `portl status laptop --count 3 --json` emits 3 NDJSON
  lines.
- `portl status laptop --timeout 200ms` fails fast.
- `portl status laptop --relay` records `"path":"relay"`.
- `portl status --relay` exits 2 with "--relay requires
  a PEER".
- `portl status --count 3` exits 2 with "--count
  requires a PEER".
- `portl status laptop --watch 2` exits 2 with "--watch
  cannot be used with a PEER".
- `portl status bogus-peer` exits 20 (peer not found).
- Help snapshots regenerate.
- `docs/` references `portl status` (not `portl ping`)
  everywhere it used to say `ping`.

### 19.9 Open questions

None.

### 20.1 Summary

Ship man pages generated from the clap command tree via
`clap_mangen`. One page per subcommand. No hand-written
roff; the command tree is the source of truth.

Why: long-form reference is the `--help` use case that
pipes to `less` miserably. `man portl-ticket-issue` is
familiar to Unix operators and pairs with shell
completions as a Tier-2 operator UX package.

### 20.2 Final surface

```text
Usage: portl man [OPTIONS]

Generate man pages for portl.

Options:
      --out-dir <DIR>   Write one man page per subcommand
                        to DIR (creating it if missing).
                        Files are named `portl.1`,
                        `portl-ticket.1`,
                        `portl-ticket-issue.1`, etc.
      --section <N>     Man section for generated pages
                        (default 1).
  -h, --help            Print help

Default (no --out-dir): print the root `portl.1` to
stdout.

Examples:
  portl man | groff -Tascii -man | less
  portl man --out-dir ./man
  sudo portl man --out-dir /usr/local/share/man/man1
```

### 20.3 Implementation notes

- `clap_mangen::Man` over the `Cli` root command.
- For `--out-dir`, walk `Command::get_subcommands()`
  recursively and emit one file per visible leaf and
  group. Hidden subcommands are skipped.
- File naming: `portl-<path>.1` with `-` joining the
  clap subcommand chain (matches `git-rebase.1`
  convention).
- Stdout default writes only `portl.1` (the root page),
  not the whole tree, so `portl man | less` is readable.

### 20.4 install.sh integration

`install.sh` gains a best-effort man-page step:

- If `portl man` is available in `PATH` and
  `$prefix/share/man/man1` is writable, run
  `portl man --out-dir $prefix/share/man/man1`.
- On failure (permission, missing directory), skip
  silently. Not load-bearing; `portl --help` still works.
- Controlled by `PORTL_INSTALL_MAN=0` to opt out.

### 20.5 Tier placement

**Tier 2.** New surface; additive.

### 20.6 Acceptance

- `portl man | groff -Tascii -man | less` renders the root
  man page without formatting errors.
- `portl man --out-dir /tmp/man` produces one file per
  subcommand (root, groups, leaves).
- `man -M /tmp/man portl` opens the root page.
- `man -M /tmp/man portl-ticket-issue` opens the
  per-command page.
- `portl man --section 8` emits pages named `*.8`.
- `install.sh` installs man pages when
  `$prefix/share/man/man1` is writable; skips silently
  otherwise.
- `PORTL_INSTALL_MAN=0 install.sh …` skips the man step.
- Help snapshots regenerate for `portl man --help`.

### 20.7 Open questions

None.

## 21. exit code stabilization

### 21.1 Summary

Lock the exit-code surface before any scripts come to
depend on it. portl is split into **portl-originated** and
**passthrough** codes:

- **0–9**: reserved for conventional meanings.
- **10–29**: portl-originated errors. Scriptable triggers
  for local misconfiguration, IPC, trust, and network
  failures.
- **30+**: exec / shell passthrough (remote process's own
  exit code, unmodified).

The portl-originated range deliberately stops before 30 so
that `portl exec` returning a `30..=255` remote exit is
unambiguous.

### 21.2 Final table

| Code | Category | Meaning |
|---|---|---|
| 0   | ok      | Success |
| 1   | generic | Unspecified error (default for unclassified `anyhow`) |
| 2   | usage   | Clap parse error (clap default; don't override) |
| 10  | local   | Local config or identity missing |
| 11  | local   | Agent unreachable (UDS IPC failed) |
| 12  | local   | Local store I/O failed (peer store / ticket store / revocations log) |
| 20  | trust   | Peer not found in local store |
| 21  | network | Peer dial failed (no route; relay unreachable; timeout) |
| 22  | trust   | Ticket expired |
| 23  | trust   | Ticket revoked |
| 24  | trust   | Ticket cap mismatch (request not covered by grant) |
| 25  | trust   | Peer auth rejected (signature / identity mismatch) |
| 29  | network | Relay rejected request (policy, rate limit, closed relay) |
| 30+ | passthrough | Remote process exit code (`shell` / `exec`) |

Codes 3–9, 13–19, 26–28 are reserved and MUST NOT be
emitted by portl. Reserved ranges leave room for future
additions without renumbering.

### 21.3 Passthrough semantics

`portl exec` and `portl shell` return the remote process's
exit code verbatim. Because the portl-originated range
stops at 29, any code in `30..=255` is guaranteed to be
the remote process's own.

When `portl exec`'s own handshake fails (peer not found,
ticket revoked, etc.), it emits a portl-originated code
from the table above — the remote command never ran.

### 21.4 Mapping policy

Every `Err` path in `portl-cli` must map to a code in the
table. Concrete mapping rules:

- `anyhow::Error` downcast to a typed error first; fall
  back to code 1 only when no typed error matches.
- `portl-core::trust::Error::{Expired, Revoked, CapMismatch,
  AuthRejected}` → 22, 23, 24, 25.
- `portl-agent::ipc::Error::NotRunning` → 11.
- `portl-core::store::Error::Io` → 12.
- `portl-proto::dial::Error::{NoRoute, Timeout, RelayDown}` → 21.
- `portl-proto::relay::Error::Rejected` → 29.

(Exact type names may shift during implementation; the
categorization is the commitment.)

### 21.5 `docs/EXIT_CODES.md`

Single authoritative doc. Structure:

- One-line summary per code (from §21.2).
- "When you see this" section with example triggers.
- "How to diagnose" section pointing to `portl doctor`,
  `portl status <peer>`, and the relevant `--json` surface.
- Script-author quickstart:
  ```sh
  portl exec laptop make test
  case $? in
    0)        echo "ok" ;;
    11)       echo "agent not running" ;;
    22|23|24) echo "ticket problem; re-issue" ;;
    21|29)    echo "network; retry" ;;
    *)        echo "remote exit $?" ;;
  esac
  ```

### 21.6 Tier placement

**Tier 2.** Locking numbers is a breaking change of sorts
even without public users: any internal script or doc that
inherited the v0.2 shape must be swept. Ships alongside
§14–§20 in the same release.

### 21.7 Acceptance

- `docs/EXIT_CODES.md` lists every code from §21.2.
- `crates/portl-cli/tests/exit_codes.rs` asserts at least
  one trigger per code produces that exit code (skipping
  passthrough, covered by `exec` integration tests).
- `install.sh` references codes 10, 11, 21 in its error
  paths where relevant.
- No code path in `portl-cli` emits a code in the reserved
  ranges (3–9, 13–19, 26–28); enforced by grep-style
  lint in the same test.

### 21.8 Open questions

None.

## 22. env var audit + `PORTL_JSON` / `PORTL_QUIET`

### 22.1 Summary

portl's env surface has accreted ad-hoc. This spec splits
it into three explicit tiers:

- **Public** — intentional user surface. Documented in
  `--help`, stable, versioned contract.
- **Relay operator** — documented but narrower audience
  (whoever runs `portl-relay`).
- **Internal / test-only** — implementation plumbing.
  Undocumented in user-facing help; may change without
  notice; `PORTL_TEST_*` and child-IPC vars live here.

Adds two new public-tier vars: `PORTL_JSON` and
`PORTL_QUIET`.

### 22.2 Public tier (documented in `portl --help`)

| Var | Purpose |
|---|---|
| `PORTL_HOME` | State directory override (peer store, identity, revocations) |
| `PORTL_CONFIG` | Alt `portl.toml` path |
| `PORTL_JSON` | *New.* If `1`/`true`, force `--json` on every command that supports it. CLI `--json` overrides. |
| `PORTL_QUIET` | *New.* If `1`/`true`, force `--quiet` on every command that supports it. CLI `--quiet` overrides. |
| `NO_COLOR` | Standard; respect everywhere. |

### 22.3 Relay operator tier (documented in `portl-relay --help`)

| Var | Purpose |
|---|---|
| `PORTL_RELAY_BIND` | HTTP bind address |
| `PORTL_RELAY_HTTPS_BIND` | HTTPS bind address |
| `PORTL_RELAY_CERT` | TLS cert path |
| `PORTL_RELAY_KEY` | TLS key path |
| `PORTL_RELAY_HOSTNAME` | Advertised hostname |
| `PORTL_RELAY_POLICY` | Access policy (open / closed / allowlist) |
| `PORTL_RELAY_ENABLE` | Enable / disable relay on agent |
| `PORTL_TRUST_ROOTS` | Additional trust roots for relay peers |
| `PORTL_REVOCATIONS_PATH` | Override revocations.jsonl path (for agent) |
| `PORTL_REVOCATIONS_MAX_BYTES` | Size cap on revocations log |
| `PORTL_UDP_SESSION_LINGER_SECS` | UDP linger tuning |
| `PORTL_LISTEN_ADDR` | Agent listen addr override |
| `PORTL_DISCOVERY` | Discovery backend selection |
| `PORTL_RATE_LIMIT` | Per-peer rate limit |
| `PORTL_METRICS` | Metrics endpoint toggle |
| `PORTL_MODE` | Agent run mode |

### 22.4 Internal / test-only tier (undocumented)

Not shown in any `--help`. May change without notice.
Touching them outside portl's own code is unsupported.

- `PORTL_IDENTITY_KEY`, `PORTL_IDENTITY_SECRET_HEX`
  (dev-only identity override; redacted in all output)
- `PORTL_AUDIT_SHELL_EXIT_PATH`
- `PORTL_SESSION_REAPER_HELPER`, `PORTL_SESSION_REAPER_PID_FILE`
- `PORTL_SIGNAL_CHILD`, `PORTL_SIGNAL_CHILD_MODE`
- `PORTL_ABOUT` (build-time)
- `PORTL_TEST_*` (all test harness flags)
- `PORTL_RUN_ENV_DENY_REGRESSION`

These are listed here only so that future spec authors
know they exist and can decide whether to promote one to
public tier.

### 22.5 Precedence

For every public-tier behavior var (`PORTL_JSON`,
`PORTL_QUIET`, `NO_COLOR`):

1. Explicit CLI flag wins.
2. Env var applies if no flag given.
3. Built-in default applies otherwise.

Explicit negation: `PORTL_JSON=0` or `PORTL_JSON=false`
disables even if a parent shell exported `1`. Values
parsed case-insensitively; anything other than
`{1,true,yes,on}` or `{0,false,no,off}` is a parse error
at startup with exit code 2.

### 22.6 `--help` surfacing

Top-level `portl --help` gains an `after_long_help`
section:

```text
Environment variables:
  PORTL_HOME       State directory override.
  PORTL_CONFIG     Alt portl.toml path.
  PORTL_JSON       Force --json where supported (0/1).
  PORTL_QUIET      Force --quiet where supported (0/1).
  NO_COLOR         Disable color output.

See `docs/ENV.md` for the full list including relay and
internal variables.
```

Per-subcommand `--help` does not repeat the env list;
individual vars are referenced where they change a
specific flag's behavior.

### 22.7 `docs/ENV.md`

Single authoritative doc. One table per tier. Same
structure as `docs/EXIT_CODES.md` (§21.5).

### 22.8 Dedicated `portl env` subcommand — deferred

A `portl env` verb (or `portl config env`) that prints
the resolved env-var state at runtime is **not in this
spec**. Reason: redaction rules for
`PORTL_IDENTITY_SECRET_HEX` and similar are delicate;
adding a reflecting verb is a separate design
discussion. Revisit only if user demand materializes.

### 22.9 Tier placement

Adding `PORTL_JSON` and `PORTL_QUIET` is additive
(Tier 1). Documenting every existing var and splitting
the tiers is documentation-only (Tier 1). Ships
whenever `--help` and `docs/ENV.md` land.

### 22.10 Acceptance

- `docs/ENV.md` enumerates every var in §22.2–§22.4.
- `portl --help` `after_long_help` lists the five public
  vars from §22.2.
- `PORTL_JSON=1 portl doctor` emits JSON; `--json` on the
  CLI (or `PORTL_JSON=0`) overrides.
- `PORTL_QUIET=1 portl doctor` suppresses progress output.
- Precedence test: `PORTL_JSON=1 portl doctor --json=false`
  (or equivalent) respects CLI.
- `PORTL_JSON=bogus portl doctor` exits 2 with a parse
  error naming the variable.
- No `PORTL_TEST_*` appears in any rendered `--help`.
- Help snapshots regenerate.

### 22.11 Open questions

None.

## 23. Testing & acceptance

### 23.1 Tier 1

- `cargo test --workspace` passes.
- `crates/portl-cli/tests/help_cli.rs` snapshots regenerated
  and committed.
- `crates/portl-cli/tests/error_messages.rs` NEW; one case
  per §11.1 row.
- `cargo clippy --workspace --all-features --all-targets
  -- -D warnings` clean.
- Manual smoke: walk through the "Getting started" block in
  §5.2 on a clean VM.

### 23.2 Tier 2

- New verbs covered by their own help snapshot + behavior
  tests.
- Removed forms (§14, §15, §16, §17, §18, §19) each have
  a negative-assertion test: invoking the old form exits
  non-zero with clap's standard error. Lives in
  `crates/portl-cli/tests/removed_forms.rs`.
- Exit-code test matrix (§21.7).
- docker/slicer `list` aliases (§18.4) assert byte-for-byte
  equivalence with `ls`.

## 24. Rollout

### 24.1 Tier 1

- One PR.
- CHANGELOG entry under `## 0.3.4.1 — <date>` describing
  only help and error-message changes.
- Tag, release, no migration notes needed.

### 24.2 Tier 2

- Multi-PR, one per section (14–22).
- CHANGELOG entry with:
  - "Added" section listing new verbs.
  - "Changed" section listing renames (with any silent
    aliases noted — currently just docker/slicer `list`).
  - "Removed" section listing every deleted verb / flag.
  - "Deprecated" section empty — we don't deprecate.
- No migration notes promised; portl has not been
  publicly released.

## 25. Open questions (master list)

None. All prior entries were resolved inline:

- §7.1 → §7.3 (source docstrings; external files not
  justified without localization).
- §9.2 → §9.2 (no public release = no scripts to audit).
- §10.4 → §10.5 (deferred follow-up paired with §20.4
  install.sh man-page step).
- §22.3 → §22.8 (deferred; redaction rules warrant a
  separate design pass).

## 26. Status

Spec complete. Sections §1–§22 locked. Ready for
implementation planning: per-section PRs in Tier-1-first,
Tier-2-second order, ending with a single release.

Implementation sequencing note: §6 (docstrings) and §14–§19
(surface changes) both rewrite help snapshots. Land §6 in
the same release as the Tier 2 PRs, not ahead of them,
to avoid regenerating snapshots twice.
