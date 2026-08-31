# Bash hook: zero command authority

_Design, 2026-08-31. Status: proposed (rev 2, after review)._

## Problem

`context-guard-rewrite-bash` runs as a `PreToolUse:Bash` hook. Its stated job is
to reduce avoidable context: wrap noisy commands in `context-guard-trim-output`
or `context-guard-sanitize-output` so their output arrives bounded and redacted.

It currently does a second, undeclared job: it **denies command execution**.
`classify_command()` returns `action="deny"` for every command it cannot place in
its routing table, and `main()` turns that into a `permissionDecision: "deny"`
response. The agent never runs the command.

This is a category error, and it is expensive.

### Evidence

A user CLI unrelated to ContextGuard (`packet-ask`) was silently unrunnable in a
project with ContextGuard installed. Every reasonable invocation failed:

| Invocation | Reason code |
| --- | --- |
| `packet-ask doctor` | `route_policy_denied` |
| `/abs/path/to/packet-ask doctor` | `command_identity_denied` |
| `sh -c 'packet-ask doctor'` | `forbidden_command_denied` |
| `uv tool run --from packet-ask packet-ask doctor` | `route_policy_denied` |
| `cmd_a; cmd_b` (any two-command line) | `active_3e` |

Diagnosing this took more than ten tool calls, because the surfaced text is
`MiniShell-v1 rejected command (active_3e)` — a policy-internal code that names
neither ContextGuard, nor the matched rule, nor a remedy. A tool whose purpose is
to conserve context manufactured a context incident.

`MiniShell-v1` is this file's own policy name (`MINISHELL_ROUTE_POLICY_VERSION`),
not vendored lineage. It is an internal identifier and should not appear in
user-facing text regardless of the outcome of this design.

### Why the deny path cannot be repaired in place

1. **Deny-by-default over the unbounded space of shell commands guarantees false
   denials by construction.** The route table enumerates the commands whose
   output shape ContextGuard knows how to trim (`ls`, `cat`, `sed`, `sort`,
   `grep`, `git`, …). Everything else a user might legitimately run is, by
   definition, outside it. Growing the table is an infinite treadmill.

2. **For network egress, the security value is approximately nil.**
   `MINISHELL_DENIED_COMMAND_BASENAMES` blocks `curl`, `ssh`, `nc`, `socat`,
   `scp` and friends. An agent seeking egress reaches it through `wget`,
   `python -c`, `git push`, `npm`, or any of a hundred paths the list does not
   name. The denylist stops legitimate work and does not stop an adversary.

3. **Immutability inverts the product's own thesis.** ContextGuard is
   "local-first", yet this gate does not trust the user on their own machine.
   `deny()` honours `CONTEXT_GUARD_SANITIZER_FAIL_OPEN`, but `deny_boundary()`
   and `deny_invalid_hook_input()` deliberately bypass it — and those are
   precisely the paths that broke `packet-ask`. The escape hatch exists and does
   not cover the cases that need it.

4. **The README never advertised command blocking.** This behaviour is
   undocumented, so removing it is a bug fix rather than a feature removal. It
   still requires a changelog entry, because installed behaviour changes.

## Design

> **ContextGuard does not arbitrate execution. It decides only whether it can
> safely wrap a command, and it asks a human in the one case where being wrong is
> irreversible.**

`classify_command()` keeps its affirmative routes unchanged. Failure
classifications are re-mapped.

### Route table after this change

| Condition | Before | After |
| --- | --- | --- |
| Recognized noisy command, safe to wrap | `trim` / `sanitize` | unchanged |
| Recognized quiet command | `noop` | unchanged |
| Digest reference expansion | `reference` | unchanged |
| **Active tilde on an otherwise recognized route** | deny | **route normally** (see below) |
| **Side-effecting `find` (`-delete`, `-exec`, `-ok`, …)** | deny | **`ask`** |
| Not in the routing table (`route_policy_denied`) | deny | noop |
| Grammar not fully consumed (`parsed.denial_reason`, e.g. `active_3e`) | deny | noop |
| Non-bare command path (`command_identity_denied`) | deny | noop |
| Forbidden basename — `curl`, `ssh`, `nc`, `eval`, … | deny | noop |
| Shell reserved word (`reserved_word_denied`) | deny | noop |
| Assignment-only input (`assignment_only_denied`) | deny | noop |
| Restricted / unsafe env prefix | deny | noop |
| Heredoc consumer mismatch (`heredoc_consumer_denied`) | deny | noop |
| Pipeline PATH override (`route_operand_denied`) | deny | noop |
| **Malformed hook payload** | deny | **noop (crash-open)** |
| Incoming / nested ContextGuard execution wrapper | deny | **deny (kept)** |

### Three rows that are not plain `noop`

**Active tilde.** `cat ~/.ssh/id_rsa` is denied today by
`active_shell_expansion_denied`. Deleting that blanket denial is the whole fix:
the route predicates match on flags and command identity, not on operand text,
so `cat ~/.ssh/id_rsa` routes to `trim` on its literal operand exactly as
`cat /home/you/.ssh/id_rsa` does, and the wrapper redacts it.

An earlier revision of this design also expanded `~` at routing time, on the
theory that the tilde pushed the command out of the route table. That theory was
wrong, and the machinery was measured to change **zero** decisions across
operand, command-word, env-prefix and pipeline positions. It was deleted. The
lesson is worth recording in a project with this much apparatus: a mechanism
whose removal changes no observable behaviour is not a safeguard.

**Side-effecting `find` → `ask`.** This is the one row where the deny was doing
real work: `find … -delete` / `-exec rm` is irreversible, and the users most
likely to install a token-saver are the ones running with permission prompts
disabled, where no second gate exists. Vetoing is not ContextGuard's call, but
neither is silently removing the last brake. `permissionDecision: "ask"`
delegates to the human, which is the honest classification.

The line drawn here is: **`ask` where the false-positive cost is near zero and
the damage is irreversible; `noop` everywhere else.** Side-effecting `find` is
rarely a legitimate agent action and costs one keystroke when it is. `curl` is
constantly legitimate, and denying it buys nothing an adversary could not route
around — so egress rows become `noop`, and this design states plainly that a
porous brake is being given up rather than pretending it was worthless.

Known tradeoff: a hook `ask` prompts even when the user has allowlisted the
command in host settings. This is why the kill switch below is mandatory rather
than optional.

**Malformed payload → crash-open.** "The hook cannot parse its own stdin, so it
has no command to pass through" was wrong on the mechanism. `noop` does not pass
a command anywhere; the command lives in the host's tool call, and `print_noop()`
emits `{}`, meaning *no intervention*. Failing closed here converts any host
payload drift — a Claude Code schema change, a different host — into a **total,
silent Bash outage for every user**: the `packet-ask` incident at fleet scale.

Accordingly: unparseable payload emits `{}`, and `main()` gains a top-level
exception guard with the same crash-open semantics. The hook may never be the
reason a command does not run.

### Why `noop` and not `trim` for unknown commands

Wrapping is not free, and three of its costs apply specifically to commands whose
semantics we have not reasoned about:

1. **Non-termination.** `build_wrapped_command()` emits
   `<python> -I <trim-output> --max-lines N -- <shell> -c <command>`. An
   interactive or stdin-reading command blocks until the 600-second watchdog —
   the same invariant the existing `sed` and `git shortlog` predicates guard.
2. **Permission matching degrades.** The host's permission analyzer sees the
   wrapper argv, not the command. Allowlist entries stop matching and prompts
   multiply. A token-saver that manufactures permission friction is
   self-defeating.
3. **Semantic fidelity.** Wrappers perturb `$?`, signal delivery, and stdout
   structure. Models act on exit codes.

A third option — a hardening wrap (`</dev/null`, an inner `timeout`, byte cap,
exit-code preservation) — is **rejected on the record**: for unknown semantics,
silent truncation and killed builds produce confidently-wrong agents, which is a
worse failure than verbose output producing annoyed ones.

To be precise about the claim: `noop` does not eliminate hangs, since an
unwrapped interactive command still runs until the host's own timeout. It bounds
the damage to host policy, which is the correct owner of that timeout.

The accepted cost is that output from unrecognized commands is no longer
trimmed. That is the pre-installation baseline, not a regression against any
promise ContextGuard makes.

### Kill switch

`CONTEXT_GUARD_DISABLE=1` makes the hook emit `{}` and exit before any
classification. This ships in the same PR, and it is not optional:

- it is the user's escape hatch from **rewrite** authority, which this change
  leaves fully intact and which is more invasive to a careful workflow than a
  visible deny (trim mangling `git log --pretty=…`, a downstream script consuming
  wrapped `sed` output, exit-code drift);
- it is the mitigation for a future hook bug, including the `ask` friction above;
- it is what a user reaches for instead of uninstalling.

The philosophy must not invert into maximal trust on execution and zero trust on
rewriting. A project-local route-override *file* remains a non-goal; the escape
hatch, not the file, is the capability users need.

`deny_boundary()` and `deny_invalid_hook_input()` no longer bypass fail-open
state, because after this change neither denies a user command.

## Non-goals

- No project-local allowlist file (see kill switch above).
- No change to `guard_large_read.py` (the `Read` matcher). Its scope is one
  tool's file argument, and it warns rather than denies.
- No change to the affirmative trim/sanitize routes, their safety predicates
  (other than tilde normalization), or the digest reference route.

## Deferred to a follow-up PR: decision telemetry

The route decision is valuable telemetry — knowing that 80% of a session's Bash
output went unwrapped tells a user which route rules are worth adding. It is
deliberately **not** in this PR, because a log with no consumer is exactly the
kind of unused apparatus this project already has too much of.

The follow-up ships the log and its consumer together, or not at all:

- **Artifact:** versioned JSONL, per-project and gitignored. Fields: `schema_v`,
  timestamp, decision (`wrap:trim` | `wrap:sanitize` | `reference` | `noop` |
  `ask` | `deny`), `decline_reason`, matched route, `argv[0]`, and a redacted
  command prefix (~80 chars) — a full-fidelity record of everything the agent
  types is a new sensitive artifact even when local.
- **Bounds:** size-rotated, lazily created, write failures swallowed. Tested:
  logging must never block or break a command.
- **Consumer, same release:** `context-guard doctor` answers two questions —
  "what did ContextGuard do for me lately" and "which decline reason should I
  configure next", with counts, one example, and the route snippet that would
  cover it. A contract test in CI asserts doctor parses what the hook writes, so
  format drift fails the build.
- **Channel discipline:** declined wraps emit no model-visible text. At a high
  decline rate, per-command messages recreate the noise problem in the tool's own
  voice.
- **Acceptance criterion:** if `doctor` cannot produce those two answers from the
  log, the log is deleted rather than maintained.

## Message contract

Policy-internal codes may appear as a trailing parenthetical for bug reports,
never as the whole message. Retained denial:

```
ContextGuard refused a command carrying its own execution wrapper. This is
ContextGuard's recursion guard, not a policy about your command. If you did not
construct this command yourself, please report it. (incoming_wrapper_denied)
```

`ask` prompt reason:

```
ContextGuard: this find command modifies or deletes files. ContextGuard does not
block it; confirm if you intended it. Set CONTEXT_GUARD_DISABLE=1 to disable
ContextGuard's Bash hook entirely.
```

## Compatibility

- Commands that are wrapped today are wrapped identically.
- Commands that are denied today begin to run. This is the intended change.
- Side-effecting `find` changes from denied to prompted.
- Diagnostic messages and stderr text change; the claim is behavioural
  compatibility for executed commands, not byte-identical output.
- `CommandDecision` keeps `action="deny"`; the set of conditions producing it
  shrinks to one. Existing reason codes are retained on `noop` decisions as
  `decline_reason`, so diagnostics and tests can assert *why* a wrap was declined
  without asserting that execution was blocked.

## Gate-B: resolved by narrowing, not by re-blessing

`scripts/verify_gate_b_rollback.py` initially failed on this change:

```
component paths changed after durable reapplication:
['tests/test_context_guard_kit.py']
```

That path was a member of `SHARED_INTEGRATION_PATHS`, and it was the *only*
component path this change touches. It is not avoidable by moving code: the
migrated tests that asserted the old deny behaviour live in that file.

The release runbook's own step 1 says to prefer the cheaper options — "splitting
a large frozen test file, or narrowing the frozen path set for a future
generation" — over a routine re-bless. Narrowing is the right one here, because
freezing a 30,000-line general test module means *any* PR touching *any*
ContextGuard test breaks a release proof. That is a mis-scoped component path,
not a deliberate constraint.

`gen16` therefore drops `tests/test_context_guard_kit.py` from the
shared-integration set. No Gate-B or residual marker owns that path, so the
marker contract is unaffected; the generation carries every earlier marker and
path set otherwise. Because the change touches none of the paths `gen16` still
owns, its `residual_edits` is empty and its bless content for those paths is
byte-identical to `gen15`'s.

**The file is now permanently outside the freeze.** Restoring it requires
another explicit, reviewed generation. That is the trade this PR is making, and
it is called out here and in the runbook because the freeze is the thing being
reduced.

The same trap remains armed for `context-guard-kit/setup_wizard.py` and
`plugins/context-guard/bin/context-guard-setup`, which stay frozen — but those
are implementation surfaces the proof genuinely guards, not a catch-all test
module.

## Open question for the `find` row

A hook `permissionDecision: "ask"` is assumed to prompt even in
`bypassPermissions` mode. If the pinned host downgrades `ask` to allow in that
mode, this row is decorative for exactly the population it was written for — the
users running without prompts. Verify against the pinned host version before
treating it as a safeguard.

## As built: things the design did not anticipate

1. **`find … -exec rm {} \;` never reaches the routing loop.** `{}` fails the
   MiniShell grammar (`active_7b`), so the command declines at the parse stage.
   The old deny was therefore coincidental — it came from the parser, not from
   the `find` predicate. Placing the `ask` gate after parsing would have removed
   the brake for the most common destructive spelling while appearing to keep
   it. A parse-independent textual check (`_raw_command_is_side_effecting_find`)
   now runs before parsing. Being a heuristic is acceptable here precisely
   because the outcome is a question, not a veto: a false positive costs one
   keystroke.

2. **`sed -i` becomes `noop`.** In-place editing is irreversible file mutation,
   but it is also a routine editing command with a high false-positive cost, so
   it fails the "false-positive cost is near zero" half of the `ask` test. The
   host permission system governs it. Recorded here because 12 pinned spellings
   previously asserted it stayed denied.

3. **A near-v0 wrapper envelope becomes `noop`.** A command shaped like the
   hook's own output but not matching it exactly (`--max-lines 221`) was
   previously denied by the route table, not by the recursion guard. It now
   passes through. This is safe: the hook grants it nothing, because it declines
   to wrap it.

4. **`reason_code` is kept on declined decisions**, not moved to
   `decline_reason` alone. The cause is the cause regardless of the consequence,
   and the existing oracles pin causes rather than outcomes. `decline_reason`
   remains as the explicit marker that a `noop` was a declined wrap rather than
   a quiet pass.

5. **A forged wrapper envelope is refused, not passed through.** Recognising an
   incoming envelope originally required an exact `--max-lines` value, so a
   one-character change escaped it and was denied only coincidentally by the
   route table. With that coincidence gone, a host allowlist that trusts the
   canonical wrapper argv shape would suppress the prompt for an arbitrary inner
   command. Envelope matching now accepts any `--max-lines` value while still
   requiring the isolated runtime-shell argv, so direct CLI use
   (`context-guard-trim-output --max-lines 10 -- pytest`) stays ordinary and the
   forged envelope is denied.

6. **`CONTEXT_GUARD_SANITIZER_FAIL_OPEN` no longer changes behaviour.** Its
   purpose was "run unwrapped rather than be blocked"; nothing blocks, so that is
   now the default. `CONTEXT_GUARD_DISABLE` is the knob for turning off
   rewriting. Both accept the same value set.

7. **The crash-open guard does not cover git-guard exec mode.** In that mode
   stdout carries command output rather than hook protocol, so emitting `{}` and
   returning 0 would corrupt the stream and mask git's exit code.

8. **A missing trim/sanitize wrapper now declines instead of blocking.** This
   row was not in the original table. A partial install previously blocked every
   noisy command, and `CONTEXT_GUARD_SANITIZER_FAIL_OPEN` was the only way out.
   An incomplete ContextGuard install is a ContextGuard problem, not a reason to
   stop the user's command.

## Test migration

The suite encoded the deny/allow axis as its theory, so the migration was not a
literal substitution. The discriminating axis becomes **wrapped / not wrapped**,
plus the cause. Concretely:

- `tests/corpus_adversarial_pins.py` is **unchanged**. Its contents are hashed by
  `scripts/verify_route_historical_baseline.py`; an early attempt to flip its
  `expected_decision` values pulled five extra rows into the relaxation set
  (70 → 75) and broke the pinned baseline. A single translation helper,
  `expected_action()`, maps the frozen table's `deny` to the current `noop`, and
  exempts the recursion-guard rows.
- `assert_bounded_deny` became `assert_bounded_decline`: bounded output, no
  partial `updatedInput`, no payload echo, no traceback. That was always the
  security-relevant half of the assertion.
- The execution canaries now pin what they were really about — that the hook
  itself executes nothing while deciding — rather than that the command was
  blocked.
- `test_b1_assignment_shaped_tilde_provenance_all_word_positions` no longer
  asserts a single route for active tildes, because tilde provenance no longer
  determines the route. It pins provenance, and that execution is never blocked.

## Verification

Ordered by risk.

1. **Payload parser failure behaviour (highest risk).** Golden and fuzz tests for
   valid-JSON-wrong-shape, missing `command`, wrong types, non-UTF-8, and
   oversized payloads. Invariant: *any* input produces either a valid noop or a
   valid structured response — never a traceback, never fail-closed. This is the
   one path that can reproduce the incident fleet-wide after the change.
2. **`main()` contract tests**, not only `classify_command()`: pipe real payload
   JSON, assert exact output JSON and exit code per table row, including a
   byte-exact passthrough assertion for `noop` (no rewritten-command key).
3. **Whole-suite sweep for reason-code and exit-code assertions**, not just
   `action == "deny"` — doctor tests, e2e tests, doctests, and shipped
   docs/templates can assert denial transitively.
4. **The five reproduction cases** from the Evidence table, end to end, messages
   included.
5. **Non-termination:** unknown commands are never routed to `trim`.
6. **Upgrade path:** a v0.10.0 install with an existing hook registration,
   upgraded, with the repro cases verified live.
7. Full `context-guard-kit` suite passes; changelog entry lands with the change.
