# WeightClass advisory mode

ContextGuard advisory mode is a local, non-persistent activation gate for
WeightClass-style router and advisor runs. It does not install hooks, edit
`AGENTS.md`, create a skill, store a receipt, read task text, inspect project
paths, or call a provider.

Invoke the packaged helper through the existing cost command surface:

```bash
context-guard cost advisory --workload workload.json --json
```

The input is a closed `contextguard.advisory-workload.v1` JSON object. It contains
only the provider label, boolean invocation capabilities, integer byte/count
signals, and integer limits. Task prompts, paths, file content, log content,
credentials, provider responses, and model output are outside the contract.

The decision always has an empty `provider_context` and
`provider_context_bytes: 0`. A router consumes `actions` locally; it must never
append the advisory JSON or explanatory text to a provider request.

## Activation rules

- Small tasks and candidates below the configured net-savings floor return
  `decision: bypass` with no actions.
- Existing ContextGuard rules or skills make the run measurement-ineligible.
- A treatment whose host tool surface differs from control is
  measurement-ineligible.
- Claude `safe_mode` makes hooks ineffective. An active safe-mode decision can
  use only an explicit router-owned local wrapper.
- A local-overhead estimate above its budget returns a bypass.
- Graph is selected only when a repo map is already cached, at least one
  candidate exists, and replacement bytes exceed added candidate bytes. A zero
  candidate or uncached graph is a no-op before graph execution.

## Action mapping

`actions` are typed plans, not shell commands:

- `trim_output`: the router wraps or transforms a large local output before it
  constructs the provider request.
- `symbol_slice`: the router uses an already selected path/symbol through a
  bounded symbol reader. Paths and symbols never enter the advisory workload.
- `context_pack`: the router builds a bounded local pack with the requested
  adaptive/graph booleans. Graph must remain disabled unless the decision marks
  it selected.

The router owns command construction, path validation, timeout handling, and
the exact provider request. ContextGuard owns only the closed activation and
break-even decision.

## WeightClass experiment requirements

For a paired control/treatment experiment:

1. Keep vendor, model, effort, task, host tool surface, and quality checker
   identical.
2. Run advisory mode before any provider call.
3. If it returns `bypass`, reuse the exact control invocation. Do not add a
   second provider call merely to measure a zero-overhead bypass.
4. If it returns `active`, execute only the selected local action and record its
   wall time.
5. Exclude `measurement_eligible: false` runs from savings estimates while
   reporting their count and reason.
6. Measure provider input/output/cache tokens, provider cost when authoritative,
   local action time, retries/corrections, and the same quality outcome.

Provider token or cost savings are never inferred from byte estimates. They
require matched successful tasks, non-inferior quality, and measured shifted
costs.

## Provider-free matrix

The repository benchmark exercises small Codex, Claude safe-mode, large-log,
large-symbol, broad adaptive, graph no-candidate, graph cached/uncached,
local-overhead, and persistent-context cases without task content:

```bash
python3 -B scripts/benchmark_advisory_mode.py --matrix-json --repetitions 1000
```

The default benchmark output remains the small-task provider-visible overhead
metric used by the performance gate.

### Provider-free sample collected 2026-08-22

One local run used 10 workload classes with 1,000 planner repetitions per
class. Six classes selected an action, four bypassed, and one persistent-context
case was correctly marked measurement-ineligible. The median per-case planner
latency was 0.004438 ms. Provider-visible ContextGuard instruction bytes were
zero for every class. Synthetic candidate-context accounting was 290,144 bytes
for control versus 105,200 estimated bytes after selected actions, a 184,944-byte
(63.74%) provider-free proxy reduction.

These figures validate decision overhead and factor gating only. They are not
provider token, cost, latency, or quality evidence. Live paired measurements
must follow the experiment requirements above.

## Bounded live sample harness

Review the exact egress plan without a provider call:

```bash
python3 -B scripts/collect_advisory_live_samples.py \
  --dry-run --vendor all --repetitions 3
```

The live path requires `--confirm-provider-egress`, caps repetitions at five and
calls at twenty, uses only a generated sanitized log, reads no repository task
content, and reports aggregate usage/quality rows without prompt or model output.
Claude runs in safe mode with tools disabled; Codex runs ephemeral, read-only,
and with user config and exec-policy rules ignored. Each CLI owns its existing
authentication. The harness does not read credential files.

### Descriptive live sample collected 2026-08-22

The bounded harness ran one synthetic sanitized-log task with three repetitions
per arm and vendor. Control and advisory both passed quality 3/3 for Claude and
3/3 for Codex. Prompt bytes fell from 16,764 to 420 (97.49%).

| Vendor | Metric | Control median | Advisory median | Change |
| --- | ---: | ---: | ---: | ---: |
| Claude Sonnet 5 | total provider tokens | 14,519 | 6,857 | -52.77% |
| Claude Sonnet 5 | provider-reported cost | $0.0737887 | $0.0237387 | -67.83% |
| Claude Sonnet 5 | provider wall time | 3.762374 s | 3.654458 s | -2.87% |
| Claude Sonnet 5 | wall time plus 100.689 ms local compression | 3.762374 s | 3.755147 s | -0.19% |
| Codex Luna | total provider tokens | 19,296 | 15,717 | -18.55% |
| Codex Luna | provider wall time | 5.052055 s | 4.366928 s | -13.56% |
| Codex Luna | wall time plus 89.751 ms local compression | 5.052055 s | 4.456679 s | -11.78% |

Claude totals include disjoint uncached input, cache-read input, cache-creation
input, and output buckets. Codex cached input remains a breakout inside input
tokens and is not double-counted. Codex subscription output did not provide an
authoritative cost field, so no Codex cost change is reported.

This is a small synthetic descriptive sample, not evidence for long-term average
savings or every task type. The corrected Claude sample was recollected after a
test caught and fixed an initial cache-bucket parser omission; the invalid token
totals from that first collection are excluded.
