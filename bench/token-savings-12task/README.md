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
retry cases, and writes `rehearsal-report.json` plus `overhead-ledger.jsonl`. The
report's `deterministic` block reproduces byte for byte across runs; only the
`declared_timestamps` block changes.

## Claim boundary

- The rehearsal makes no provider call, opens no network socket, reads no
  credential, and spends no USD. Its token counts are scripted local fixtures.
- Rehearsal output is substrate readiness evidence only. It is never evidence of
  provider-measured token or cost savings, and it never authorizes a public or
  release claim.
- Any savings statement remains limited to: *Token savings demonstrated only for
  the exact frozen 12-task suite under manifest `<sha256>`.*
