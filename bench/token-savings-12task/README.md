# Real 12-task token-savings suite (S003)

This directory holds the **real, non-example** sanitized task suite used by the
measurement study, plus the inputs needed to rehearse the study at zero cost.
The placeholder starters under `docs/benchmark-fixtures/` stay placeholders and
are not used here.

## Layout

| Path | Purpose |
| --- | --- |
| `tasks.json` | The 12 hermetic tasks. Each declares a `fixture_tree` and a `success_checker` that lives **outside** that tree. A free-form `success_command` is forbidden. |
| `trees/<nn>-<slug>/` | One sanitized fixture tree per task. It never contains the checker. |
| `checkers/<nn>-<slug>.py` | The bounded success checker for that task, kept out of the measured workspace. |
| `settings/baseline.settings.json` | Baseline arm settings. Exactly the treatment settings with the registered ContextGuard hooks pruned. |
| `settings/treatment.settings.json` | Treatment arm settings with the registered ContextGuard hook bindings. |
| `variants.template.json` | Arm template. `{{CANDIDATE_HASH}}`, `{{NAMESPACE}}`, and `{{ARTIFACT_ROOT}}` are substituted per run so the concrete variants file always binds the exact candidate under measurement. |
| `study-plan.json` | Canonical `contextguard.bench.study-plan.v1` plan: 12 tasks x 2 arms x 3 repetitions = 72 initial attempts, with `one_retry_after_valid_task_failure_v1`. |
| `hook-event-evidence.json` | External evidence that every registered hook event exists in the provider CLI, with its collection method and boundary. |
| `rehearsal/solutions.json` | Rehearsal-only scripted workspace writes for the fake provider. Never part of any fixture tree and never used by a real provider run. |

## Task coverage

The 12 categories are fixed and ordered: small fix, bugfix, exploration, review,
long log, migration, docs, refactor, performance, telemetry, cache/layout, and
artifact receipt.

## Hermetic contract

- Every attempt runs in its own isolated run root. The workspace is emptied and
  the declared fixture tree is re-materialized from the exact same bytes before
  each launch, so a retried or resumed attempt starts from a cold tree.
- Directories are created `0700` and data files `0600`. Symlinks are never
  created or followed.
- The study manifest binds the prompt hash, the ordered fixture-tree file hashes,
  the domain-separated `tree_sha256`, and the checker hash. Any byte change in a
  tree or checker changes the manifest and therefore invalidates prior evidence.

## Checker integrity

The measured agent holds `Write`, `Edit`, and `Bash` in its workspace, so the
checker must be unreachable from there:

- The checker is **not** part of the fixture tree, and loading refuses a tree that
  contains one or a checker path under the tree root.
- Its bytes are bound before the run and recorded in the manifest by hash. Each
  attempt materializes that bound copy into a private `0700` directory outside
  the workspace, as a `0500` file, and runs it with the workspace as the current
  directory. Planting `check.py` or `checker.py` in the workspace has no effect.
- The argv is derived from the bound checker, so a fixture cannot substitute
  another command. Declaring `success_command` next to a `fixture_tree` is
  refused outright.
- Checkers read workspace files through bounded no-follow IO. Missing
  `O_NOFOLLOW`/`O_DIRECTORY` support fails closed instead of silently degrading,
  and a symlinked leaf or any symlinked parent component is rejected.
- **Candidate code never runs in the checker's own process.** Anything that
  imports or calls candidate modules runs in a child process that only reports
  observed values on a nonce-tagged `PROBE` line; the parent re-verifies those
  values. A child that exits early (`SystemExit`, `os._exit`), crashes, times
  out, or emits no correctly tagged line fails closed. Rebinding the parent's
  helpers from candidate code is not reachable.
- The parent additionally validates every candidate file with its own no-follow
  read before probing, so a symlinked module cannot be smuggled past the child's
  ordinary import.
- Behavioural properties are verified behaviourally. The performance task counts
  real element comparisons instead of pattern-matching source text, so the
  idiomatic single-pass answer passes and a single-loop quadratic implementation
  still fails.

### Residual limitation

Isolation makes accidental and casual false-success paths fail closed, and it
makes forging a verdict require emitting exactly the values the parent expects
under a per-run nonce. It is not an OS-level sandbox: a deliberately adversarial
candidate that reconstructs the expected report could still fake a pass. The
measured agents in this study are not adversarial, and any real run should treat
an implausible all-success result as a reason to inspect receipts rather than as
proof.

## Zero-cost rehearsal

```bash
python3 scripts/rehearse_measurement_study.py --output-root /tmp/s003-rehearsal
```

The harness generates an official-shaped fake Claude CLI, materializes cold
local/session roots, executes all 72 scheduled initial attempts plus the scripted
retry cases, and writes `rehearsal-report.json` plus `overhead-ledger.jsonl`.

Offline behaviour is proved at runtime, not only by reading the source: the fake
CLI installs a fail-closed audit hook that aborts on any socket, urllib, http,
ssl, mail/ftp, browser, subprocess, or process-spawn audit event, and every
invocation records a clean-audit receipt. The harness fails if the clean-audit
count does not match the executed attempts, if any violation is recorded, or if
a credential-shaped environment name reached the child.

Reproducibility is reported two ways:

- Across different output roots, the report's `deterministic` block — including
  `attempt_order_sha256` and `analysis_sha256` — is identical. The fields that
  are genuinely derived from run-local absolute paths are listed in
  `analysis_normalized_fields` and replaced with a placeholder instead of being
  silently dropped.
- Re-running into the same output root reproduces `study-manifest.json`,
  `study-report.json`, and `attempts.jsonl` byte for byte, which covers those
  path-derived fields too.

`artifact_completeness` records the receipt files, artifact-index rows, terminal
runs, and terminal attempts whose recorded receipt hash matches the stored
receipt bytes. Only the `declared_timestamps` block changes between runs.

## Verified hook-event note

The measured treatment registers `PreToolUse` and `PostToolUse`, but each event is
conditional on the model invoking a matching tool. Registered classes define the
events the runner permits and validates when they occur; the ordered
`required_event_classes` subset defines events that must occur in every attempt.
The analytic suite leaves that subset empty so stochastic tool choice cannot
silently filter the treatment sample. Every observed hook process must still
succeed, and any unregistered event still invalidates the attempt. A discarded
canary that forces both matching tool calls separately verifies `PreToolUse` and
`PostToolUse` before analytic authorization.

`PostToolUseFailure` is a real event, but the exact treatment candidate does not
configure the failure-nudge hook. It remains **out of the measured treatment for
this suite**, which narrows what the study can claim about that specific guardrail.

The event evidence itself is external rather than circular. `hook-event-evidence.json` records the resolved
`claude --version` output and literal occurrence counts for every event the
treatment arm registers, measured against the installed CLI bundle: `PreToolUse`
133, `PostToolUse` 185, `PostToolUseFailure` 54 in Claude Code 2.1.220. A test
re-checks the installed CLI directly when one is present and falls back to the
recorded evidence with an explicit skip when it is not, so pinning to this
project's own frozen list is no longer the only argument.

Occurrence counts prove the event name ships in the CLI. They do not prove a
matching tool invocation occurs in every attempt. Runtime validation instead
rejects unregistered event classes, missing explicitly required classes, and any
observed hook process failure. Re-collect this evidence against the exact CLI
version before freezing a measurement manifest.

## Recorded R9 outcome

The first frozen live study is retained as an **inconclusive** result. One
arm-unit failed both its initial attempt and its sole fixed-policy retry, so the
complete-pair gate could not pass. No subset estimate or correction assessment
was performed, and no token-savings claim is allowed. See the sanitized
[R9 report](results/r9-summary.md), [dashboard](results/r9-dashboard.md), and
[machine-readable summary](results/r9-summary.json).

## Claim boundary

- The rehearsal makes no provider call, opens no network socket, reads no
  credential, and spends no USD. Its token counts are scripted local fixtures.
- Rehearsal output is substrate readiness evidence only. It is never evidence of
  provider-measured token or cost savings, and it never authorizes a public or
  release claim.
- Any savings statement remains limited to: *Token savings demonstrated only for
  the exact frozen 12-task suite under manifest `<sha256>`.*
