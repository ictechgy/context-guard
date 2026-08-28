# Net-efficiency P0-P2 design

## Objective

Measure and improve the complete coding-agent loop without treating prompt
bytes or total tokens as proof of savings. All new surfaces are local,
provider-free, bounded, and advisory. They neither mutate a live provider
request nor authorize a token, cost, latency, or quality claim.

## P0 contracts

`evaluate net-efficiency` compares matched baseline and candidate observations.
Each observation contains only closed numeric/boolean telemetry: valid task
success, quality score, fully loaded cost, wall time, provider input/output and
cache tokens, model requests, tool calls, tool yields, correction turns,
rehydration calls, and shifted local/external costs. Candidate promotion
requires quality non-inferiority and an improvement beyond a caller-declared
noise floor without exceeding caller-declared cost or p95-latency regression
margins. Failure is never made cheap by excluding unsuccessful attempts.
Caller-supplied HMAC run-window identities enforce a minimum number of distinct
canary conditions without disclosing dates, infrastructure labels, or paths.
Separate pair and task HMACs allow repeated measurements of the same task while
rejecting duplicate matched-pair identities.

The same report exposes output/round-trip regressions explicitly. It recommends
only a shadow disposition; it does not rewrite effort, verbosity, output
budgets, stop conditions, or provider parameters.

## P1 contracts

`evaluate prefix-plan` compares caller-supplied HMAC identities for rendered
prefix components and caller-supplied provider capabilities. It reports cache
invalidation, minimum-cacheable-length risk, caller-supplied write/read
amortization, and whether session-stable tools or native deferred loading should
be evaluated. It never emits component identities or bundles provider pricing
or feature claims.

`evaluate fanout-plan` gates batch execution using only content-free workload
shape: independent operation count, sequential dependencies, estimated source
and retained bytes, baseline model round trips, and shifted cost. It grants no
execution authority and holds single-call or sequential work by default.

`evaluate prune-plan` selects only stale tool-result indexes at an explicit task
boundary. Protected results, results without exact fallback, and results already
rehydrated beyond policy are retained. The report is a plan only; no transcript
or artifact is edited.

`receipt_batch` performs up to sixteen bounded exact slices over capabilities
that were already issued by `receipt_context` for the same task scope. Total
returned bytes are capped at one ordinary context slice. It adds no filesystem
discovery, shell, runner, provider, credential, or network authority. Every
result carries the original capability and exact byte range for rehydration.

## P2 contract

`evaluate shadow-policy` ranks bounded candidate lanes using their P0 reports.
The baseline/no-op lane is mandatory. A candidate is eligible only when its
evidence is complete, quality is non-inferior, and the P0 decision is
`recommend`; ties prefer no-op and then deterministic lane order. The result is
shadow-only and cannot activate routing, batching, compaction, model changes,
or request mutation.

## Compatibility and failure behavior

- Existing CLI commands and MCP tools retain their schemas and behavior.
- New evaluators use versioned closed envelopes and stable non-reflective error
  codes.
- Inputs and outputs remain bounded canonical JSON.
- Raw prompts, paths, tool results, model names, and pricing tables are neither
  required nor emitted by evaluator reports.
- Invalid, incomplete, ambiguous, or over-limit input fails closed.
- Provider-measured matched successful canaries remain required before any
  future active integration or public performance claim.

## Verification contract

Tests cover schema closure, quality-first decisions, output/round-trip
regressions, cache amortization and drift, protected pruning, task-scope
isolation, batch byte caps, deterministic no-op tie breaking, CLI distribution,
and non-reflection of caller-controlled markers.
