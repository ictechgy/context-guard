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

- Small tasks and candidates below the configured gross context-byte floor return
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

The default benchmark output is a reference-composer small-task bypass overhead
metric used by the advisory regression test. It does not capture a WeightClass
production request builder. Planner timing is descriptive and not a
cross-platform CI performance gate.

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
  --dry-run --vendor all --repetitions 4
```

The live path requires `--confirm-provider-egress`, caps repetitions at four and
CLI invocations at sixteen, uses only a generated sanitized log, reads no
repository task content, and reports aggregate usage/quality rows without prompt
or model output. Provider transport retries are unobserved and therefore are not
claimed as part of that CLI-invocation cap or as a hard spend/egress bound.
Claude live collection runs in safe mode with tools disabled. Codex remains
available in the provider-free dry-run plan, but live Codex collection fails
closed before any local action or provider call because the current subscription
CLI exposes a read-only agent sandbox rather than a preventive no-tools mode.
Post-run tool-event rejection is retained only as evidence validation, not as a
privacy boundary. Each CLI owns its existing authentication; the harness does
not read credential files.

### Excluded live attempt collected 2026-08-22

The first bounded synthetic-log collection is retained only as an excluded
attempt record. It used a fixed control-then-advisory order, a substring quality
check, one Claude-shaped capability plan for both vendors, and an initial Claude
cache-bucket parser that required correction. Those defects make its numeric
token, cost, time, and quality comparisons non-authoritative; this document does
not publish them as advisory evidence.

The corrected harness now alternates AB/BA order, records paired deltas, requires
one exact result line, builds a separate capability plan for each vendor, and
feeds measured local compression time into the overhead gate. A new provider
sample must be collected and reviewed before any live numeric table is added.
The dry-run preview compression is explicitly reported as excluded dry-run-only
calibration. Live collection does no unassigned preflight compression: every
compression execution is measured, gated, and charged to its advisory row.
