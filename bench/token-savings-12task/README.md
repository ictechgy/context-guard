# Real 12-task token-savings suite (S003)

This directory holds the **real, non-example** sanitized task suite used by the
measurement study, plus the inputs needed to rehearse the study at zero cost.
The placeholder starters under `docs/benchmark-fixtures/` stay placeholders and
are not used here.

## Layout

| Path | Purpose |
| --- | --- |
| `tasks.json` | The 12 hermetic tasks. Each one declares a `fixture_tree`, a real `success_command`, and a `success_checker` inside that tree. |
| `trees/<nn>-<slug>/` | One sanitized fixture tree per task, including the executable bounded `check.py`. |
| `settings/baseline.settings.json` | Baseline arm settings. Exactly the treatment settings with the registered ContextGuard hooks pruned. |
| `settings/treatment.settings.json` | Treatment arm settings with the registered ContextGuard hook bindings. |
| `variants.template.json` | Arm template. `{{CANDIDATE_HASH}}`, `{{NAMESPACE}}`, and `{{ARTIFACT_ROOT}}` are substituted per run so the concrete variants file always binds the exact candidate under measurement. |
| `study-plan.json` | Canonical `contextguard.bench.study-plan.v1` plan: 12 tasks x 2 arms x 3 repetitions = 72 initial attempts, with `one_retry_after_valid_task_failure_v1`. |
| `rehearsal/solutions.json` | Rehearsal-only scripted workspace writes for the fake provider. Never part of any fixture tree and never used by a real provider run. |

## Task coverage

The 12 categories are fixed and ordered: small fix, bugfix, exploration, review,
long log, migration, docs, refactor, performance, telemetry, cache/layout, and
artifact receipt.

## Hermetic contract

- Every attempt runs in its own isolated run root. The workspace is emptied and
  the declared fixture tree is re-materialized from the exact same bytes before
  each launch, so a retried or resumed attempt starts from a cold tree.
- Directories are created `0700`, data files `0600`, and declared executables
  `0700`. Symlinks are never created or followed.
- The success checker runs inside that materialized workspace, reads only
  workspace files, and uses no network or shell composition.
- The study manifest binds the prompt hash, the ordered fixture-tree file hashes,
  the domain-separated `tree_sha256`, and the checker hash. Any byte change in a
  tree or checker changes the manifest and therefore invalidates prior evidence.

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

## Claim boundary

- The rehearsal makes no provider call, opens no network socket, reads no
  credential, and spends no USD. Its token counts are scripted local fixtures.
- Rehearsal output is substrate readiness evidence only. It is never evidence of
  provider-measured token or cost savings, and it never authorizes a public or
  release claim.
- Any savings statement remains limited to: *Token savings demonstrated only for
  the exact frozen 12-task suite under manifest `<sha256>`.*
