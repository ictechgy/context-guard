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
| `study-plan-v2.json` | Additive `contextguard.bench.study-plan.v2` preregistration: 12 tasks x 3 arms x 3 repetitions, a frozen blocked-order seed, task-level inference, raw corpus SHA-256, and a domain-separated ordered checker-inventory binding. The fixed corpus is explicitly descriptive-only because no independent effect model supports an 80% power claim. It does not replace the v1 plan. |
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

The additive v2 rehearsal invokes a local fake CLI as real subprocesses, never a
provider:

```bash
python3 scripts/rehearse_measurement_study.py --study-version v2 --output-root /tmp/contextguard-v2-rehearsal
```

It executes 108 initials plus 12 deterministic retries (120 fake CLI processes).
One retry remains a valid task failure and later schedule entries still run.
Provider calls, network calls, and USD spend remain zero. The report is always
descriptive and never claim-authorizing. The v2 rehearsal requires a local C
compiler to build its temporary native fake-CLI trampoline; this adds no compiler
dependency to a real executable study.

## v2 executable workflow

Build the npm candidates once, then prepare the private immutable root. The
candidate hash is the SHA-256 of the exact canonical manifest bytes. Prepare
verifies both tarballs' sizes, SHA-256 values, SHA-512 SRI strings, and the exact
checksum document before performing exactly one offline, scripts-disabled npm
install with package-lock generation disabled. npm versions that still emit an
inert hidden lockfile have that one exact regular file removed before the overlay
allowlist is checked; no other extra path is accepted:

```bash
python3 context-guard-kit/benchmark_runner.py \
  --study-v2-action prepare \
  --study-v2-plan bench/token-savings-12task/study-plan-v2.json \
  --study-v2-tasks bench/token-savings-12task/tasks.json \
  --study-v2-checkers-dir bench/token-savings-12task/checkers \
  --study-v2-candidate-manifest /private/candidate/candidate-manifest.json \
  --study-v2-candidate-checksums /private/candidate/candidate-sha256sums.txt \
  --study-v2-candidate-hash <sha256-of-exact-manifest-bytes> \
  --claude-bin /exact/path/to/claude \
  --study-v2-use-existing-login \
  --study-v2-output-root /private/location/v2-study
```

`prepare` makes no model/provider request, but it does execute the selected CLI's
local `--version`, `--help`, and `auth status --json` probes. The auth probe
requires an existing first-party `claude.ai` login and stores only a safe method/
provider projection plus domain-separated hashes of the login identity and
canonical HOME path; email and organization text are never persisted. It accepts
only a native CLI executable;
script launchers are rejected because their external dependency closure cannot
be proven. It binds the resolved executable bytes, probe output, runner and
runner-Python bytes, task/fixture/checker bytes, and the frozen PATH/locale plus
hook interpreter bytes. Existing-login mode passes the bound HOME to the exact
CLI, keeps XDG/cache/tmp paths per-attempt, omits `CLAUDE_CONFIG_DIR`, passes no
credential-shaped environment variable, and continues to load only the explicit
project settings snapshot through `--setting-sources project`. It is an explicit
trusted-host operating mode, not an OS filesystem sandbox: the exact CLI and its
allowed tools run as the operator account. Use it only with the frozen synthetic
corpus and reviewed candidate. The remaining trust boundary is the exact native
Claude artifact plus the host OS substrate; backend and model revisions remain
unavailable rather than inferred.

Run the two-call discarded host-routing canary before any analytic call, then
run, resume after interruption, and analyze with the same output root and exact
same `--claude-bin`:

```bash
python3 context-guard-kit/benchmark_runner.py \
  --study-v2-action canary --study-v2-output-root /private/location/v2-study \
  --study-v2-use-existing-login \
  --claude-bin /exact/path/to/claude
python3 context-guard-kit/benchmark_runner.py \
  --study-v2-action run --study-v2-output-root /private/location/v2-study \
  --study-v2-use-existing-login \
  --claude-bin /exact/path/to/claude
python3 context-guard-kit/benchmark_runner.py \
  --study-v2-action resume --study-v2-output-root /private/location/v2-study \
  --study-v2-use-existing-login \
  --claude-bin /exact/path/to/claude
python3 context-guard-kit/benchmark_runner.py \
  --study-v2-action analyze --study-v2-output-root /private/location/v2-study \
  --claude-bin /exact/path/to/claude
```

`prepare`, `canary`, `run`, and `resume` require the explicit existing-login
flag and the same bound HOME/login identity. Any drift is rejected before the
next identity reservation. `analyze` makes no provider call and deliberately
does not require current login access, so a completed or stopped root remains
analyzable after logout.

The explicit `canary` action makes two provider calls, one with each hook arm.
Each must create the exact marker through Bash and produce a successful
host-emitted `PreToolUse` lifecycle. Its canonical evidence is mandatory for
`run`, `resume`, and `analyze`, but its calls and tokens never enter the 216
analytic identities, retry policy, effects, or record count. A reserved or
launched canary identity is never replayed. A `launched` canary may be recovered
without another provider process only if its immutable terminal artifacts fully
validate. A merely reserved/workspace-prepared canary or a launched canary
without valid recoverable evidence permanently closes that root to provider
activity and permits only `P1-X` analysis.

The forced Bash command uses the existing MiniShell-v1-supported `python3 -c`
route to write the fixed marker; it does not require output-redirection grammar
that the real hook intentionally denies. Contract tests submit that exact
command to both the legacy and reference hook modes. The local fake host also
passes the exact command to its fake hook and treats a deny decision as
terminal, so rehearsal cannot create the marker after a denied tool call.

Each canary call is contract-bound to `--max-budget-usd 0.75` and at most two
turns. Every analytic identity is also capped at `$0.75`; the frozen schedule is
108 initials, up to 108 failure-triggered retries, and two discarded canaries,
so at most 218 identities may be consumed or reserved. The CLI enforces the
`$0.75` per-process cap; multiplying those independent caps gives a `$163.50`
arithmetic maximum, but there is no separate aggregate CLI limiter. That maximum
is not an expected cost or standing spend authorization. A smaller approved
budget requires a separately frozen plan rather than partial execution or
optional stopping.

Any open analytic `launch_reserved` or `launched` state produces a `P1-X`
invalid decision and permanently closes that prepared root to later provider
launches. `P1-F` means complete valid feasibility evidence and remains
descriptive-only; `P1-D` is bounded diagnostic evidence and unlocks no
dependent promotion. None of the three states authorizes a public savings
claim. The `analyze` action writes the canonical P1-X artifact and exits `3`;
valid P1-F analysis exits `0`, so automation cannot confuse invalid evidence
with a valid report by checking only the process status.

All 216 initial/retry identities are fixed before launch. Every cold workspace
receives a physical copy of the same verified `node_modules` overlay; safe
internal npm symlinks are preserved and regular files are not hardlinked.
`host_unmodified` has no ContextGuard Bash hook. `legacy_trim` uses the
workspace-local `PreToolUse(Bash)` rewrite, and `bash_reference_v1` uses the same
command plus `--bash-reference-v1`. Analytic resume is allowed only when every
consumed identity has valid terminal evidence and no reservation remains open;
it never converts ambiguity into zero usage or launches a later identity.

Executable manifests are `contextguard.bench.study-manifest.v4`; analytic
attempt ledgers remain `contextguard.bench.study-attempt-ledger.v3`. Roots
created with older manifest or attempt schemas are retired: there is no
migration, repair, ledger-copy, or reuse path. After selecting the final commit
and candidate, prepare a fresh owner-private v4 root and never copy an old
ledger into it.

Analytic attempts intentionally do not require a Bash event: tool choice is part
of the randomized intention-to-treat outcome, so filtering to attempts that
happened to invoke Bash would bias the estimate. Observed hook lifecycles must
still be valid and successful. Only the discarded canary requires
`PreToolUse` in both hook arms.

Success is derived only from a valid provider terminal usage record plus the
manifest-bound checker executed outside the writable workspace. Provider
`success` booleans are not evidence. Raw output, receipt, artifact index, token
buckets, checker result, and pre/post inventories are revalidated on resume and
analysis. A retry is launched only after a valid initial task failure; a failed
retry is retained and does not stop the schedule. Missing correction, retrieval,
or shifted-cost observers remain unavailable/null, never zero or token proxies.
Every report sets `descriptive_only=true`, `claim_allowed=false`, and
`claim=null` because the frozen plan has no independent power model.

For every arm-unit, token, correction, and retrieval burdens sum all retained
attempts, including an unsuccessful initial attempt followed by its fixed retry.
A missing, non-finite, negative, or Boolean correction/retrieval value on any
attempt makes that effect unavailable and its claim gate fail closed. The v2
corpus hash remains the SHA-256 of exact `tasks.json` bytes. Its checker hash is
domain-separated as `contextguard.bench.v2.checker-binding.v1` over the ordered
relative filename, byte size, and per-file SHA-256 inventory; concatenated
checker contents alone are not the binding. The ordered task IDs are separately
bound with `contextguard.bench.v2.corpus-task-order.v1`, so a manifest cannot
reuse the real corpus hash with a fabricated schedule/task projection.

## Legacy v1 rehearsal details

The legacy v1 harness generates an official-shaped fake Claude CLI, materializes cold
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

## Legacy v1 verified hook-event note

The legacy v1 measured treatment registers `PreToolUse` and `PostToolUse`, but each event is
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
