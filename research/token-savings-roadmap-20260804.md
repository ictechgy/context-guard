# ContextGuard Token-Savings Roadmap

_Last updated: 2026-08-04 11:11 KST_

> Status: research-backed execution roadmap. This document is not runtime authority,
> paid-provider authorization, or a token-savings claim.

## 1. North star

ContextGuard should evolve only where evidence supports it: from local, reversible
context hygiene into an **opt-in, provenance-preserving request-boundary evidence
broker**. The broker should substitute bounded evidence plus an exact expansion path,
not silently veto context. It should stay out of the way when intervention is unlikely
to pay back.

The primary economic question is:

> Does an intervention reduce total billed and shifted cost per quality-gated
> successful task, without worsening failures, corrections, security, or latency?

Provider input/output/cache usage, helper work, indexing, rehydration, retries, failed
attempts, and correction burden remain visible. A smaller prompt, response, byte count,
or diff is not by itself a successful outcome.

## 2. Why the current product did not demonstrate headline savings

| Confirmed observation | Meaning for the roadmap |
| --- | --- |
| R9 is `inconclusive`; 33 of 72 planned attempts were consumed, the complete paired population was unreachable, and no token estimate was computed. | Preserve R9 unchanged. It supports neither a positive nor a negative effect claim. Start any new experiment with a new plan, freeze, and authorization chain. |
| The frozen treatment installed a `Read` `PreToolUse` hook and a `Bash` `PostToolUse` hook. | The study exercised narrow tool boundaries, not request assembly across the full agent loop. |
| The default Read threshold is 48,000 bytes, while the largest frozen fixture was below that threshold; a separate scan saw no explicit large-read block or output-trim marker. | The intended material intervention was not observed. This is an activation/design problem before it is an efficacy conclusion. It does not prove that Bash post-processing could never have run. |
| Current helpers deny or narrow Reads, trim/store output, detect repeated failures, build bounded packs, and report cache/schema signals. | Reuse these reversible primitives; do not build a new lossy compressor first. The missing layer is coordinated selection at the request boundary. |
| Brief mode adds a fixed instruction-block cost on every request and its provider-token effect is unmeasured. | Add a do-nothing/pass-through path. Always-on intervention is not the default target. |
| Graphify, Caveman, and Ponytail report different units such as corpus-to-query context, prose/output, LOC, or workload-specific agent tokens. | Do not use their headline percentages as a whole-session acceptance target or claim parity without a matched denominator. |

Sources: [`r9-summary.md`](../bench/token-savings-12task/results/r9-summary.md),
[`treatment.settings.json`](../.omx/measurement/q015-r9/frozen-live/inputs/treatment.settings.json),
[`guard_large_read.py`](../context-guard-kit/guard_large_read.py),
[`README.md`](../README.md), and
[`forge-token-savings-brainstorm-20260804.md`](forge-token-savings-brainstorm-20260804.md).

## 3. Non-negotiable evidence and safety contract

### Measurement contract

- Preserve the R9 artifacts and verdict byte-for-byte; never extend R9 or analyze its
  successful subset.
- Freeze a new task corpus, prompt, model, request layout, retry policy, success
  commands, human-review rubric where needed, and stop rules before a new effect study.
- Require a complete quality-gated paired population before calculating an effect.
- Record provider input, output, cache creation, and cache read usage for every consumed
  attempt. Keep unavailable values explicitly unavailable; never impute them as zero.
- Record helper/subagent usage and cost, index/cache build and maintenance, tool turns,
  rehydrations, wall latency, retries, failures, and human corrections.
- Report both `tokens_per_successful_task` and fully loaded
  `total_cost_with_shift_usd`; retain failure-inclusive totals as separate endpoints.
- Keep the existing 10 percentage-point failure-rate guardrail. Increased human
  correction burden remains a quality watch even when token or cost fields improve.
- Separate cold and warm cache conditions. Charge cache writes, reads, invalidations,
  and amortized build cost instead of treating a cache hit as free.
- Treat byte, character, artifact, LOC, and response-length reductions as proxy
  diagnostics until provider-measured paired evidence passes the quality gate.

### Safety and operational contract

- Start read-only and observe-only. A shadow broker must not change a live request.
- Protected instructions, source/diff literals, security evidence, secrets, credential
  paths, and exact-retrieval-required material are pass-through or deny-by-default;
  never summarize them silently.
- Store bounded hashes, classifications, policy decisions, and validation metadata;
  do not log raw prompts, raw tool payloads, credentials, cookies, private keys, or PII.
- Every substitution must carry source provenance, content revision/hash, a bounded
  range when safe, and a verified local exact-rehydration handle.
- A broker/runtime failure takes an observable safe bypass to the unchanged baseline
  path. An access-control or secret-filter failure remains fail-closed.
- Isolate indexes and receipts by repository, worktree/branch, revision, and permission
  boundary. Stale or ambiguous anchors force a source reread.
- No external forwarding, provider call, credential handling, or paid run follows from
  this roadmap. Each such experiment needs a fresh exact authorization.

## 4. Priority decisions

| Priority | Decision | Rationale |
| --- | --- | --- |
| Now | Measurement-product positioning and a pass-through ledger | Complete accounting is required before any runtime effect can be interpreted. |
| Now | Observe-only request-boundary broker | Tests selection, provenance, and exact expansion without risking task quality. |
| Next | Opt-in progressive disclosure with baseline bypass | This is the first mechanism that can reduce already-selected request context. |
| Next | Do-nothing router and prefix/cache observation | Prevents fixed overhead and catches cases where restructuring harms cache economics. |
| Later | Execution twin, failure-cone recovery, typed edit blueprint | These can reduce repeated context and retries after the broker boundary is proven. |
| Research only | Context leases/GC, cheap-scout cascade, counterfactual ledger, negative-context firewall | Keep them shadowed until accounting, freshness, and omission safety are demonstrated. |
| Hold | Automatic dynamic schema hydration and live history rewriting | Both can destabilize a reusable prefix or lose rationale; test separately only after cache economics are known. |
| Reject as first move | Lossy broad semantic compression or silent context veto | Omission risk and recovery cost are too high without exact fallback and protected-zone proof. |

## 5. Stage-gated roadmap

The roadmap is dependency-based rather than calendar-based:

`P0 contract → P1 pass-through measurement → P2 shadow broker → P3 active canary → P4 routing/cache → P5 adjuncts → P6 specialized tracks`

No phase advances on an impressive proxy number. It advances only after its stated
quality, provenance, privacy, and accounting gate passes.

### P0 — Freeze the new decision contract

**Goal:** turn the research conclusion into a reviewable experiment charter without
changing runtime behavior.

**Minimum deliverables**

- A read-only map of request assembly and the narrowest viable interception point.
- A gap analysis between the existing benchmark ledger and the measurement contract
  above.
- A stratified task proposal covering small/local edits, repository navigation,
  debugging, long-output recovery, and cross-cutting changes.
- Explicit protected zones, safe-bypass rules, exact-rehydration contract, retry policy,
  stop rules, and claim language.
- A new experiment plan path and manifest namespace that cannot be confused with R9.

**Exit gate**

- Reviewers can reconstruct every intended denominator and identify who supplies each
  field.
- No new runtime, network, provider, or paid authority is implied.
- R9 references remain read-only and retain `inconclusive`/`claim_allowed=false`.

**Stop signal:** any proposal depends on successful-subset analysis, silent omission,
unmeasured shifted cost, or reuse of a spent R9 authorization.

### P1 — Establish pass-through measurement feasibility

**Goal:** prove that a no-mutation lane can attribute complete quality and cost evidence
before testing a broker effect.

**Minimum deliverables**

- A bounded, redacted request-segment ledger for stable-prefix/tail layout, tool/result
  class, intervention eligibility, and bypass reasons.
- Provider usage/provenance joins plus helper, cache/index, latency, retry, failure, and
  correction fields.
- Deterministic fixtures proving that raw prompts, raw tool payloads, and protected
  content are not persisted.
- A newly frozen pass-through feasibility run; its purpose is data completeness, not a
  savings estimate.

**Exit gate**

- Every consumed attempt has all claim-critical fields or is explicitly blocked from
  claims.
- Task success and failure can be independently reproduced from frozen commands and
  evidence.
- The complete paired-population and stop-rule machinery works before active mutation.

**Kill/rollback:** any sensitive-content retention, irreconcilable provider provenance,
or accounting path that drops failed attempts stops the experiment.

### P2 — Run an observe-only request-boundary broker

**Goal:** evaluate whether ContextGuard can select sufficient bounded evidence without
changing what the primary agent receives.

**Minimum deliverables**

- Candidate evidence packs with source/hash/range provenance, selection rationale,
  protected-zone disposition, and exact local expansion commands.
- Shadow-only duplicate/stale-output detection and a negative-context firewall report.
- Prefix/tail layout fingerprints that observe cache stability without rewriting the
  request.
- Retrieval evaluation against the evidence, symbols, tests, and configuration actually
  needed by successful baseline runs.

**Exit gate**

- Every candidate omission is exactly rehydratable and freshness-checked.
- A predeclared evidence-recall threshold is met across each supported task stratum;
  the threshold must be set in the new frozen plan, not chosen after seeing results.
- Protected and ambiguous material is retained, and shadow accounting includes broker
  construction cost and latency.
- Candidate-size reduction remains labeled proxy-only.

**Kill/rollback:** missing provenance, stale-anchor acceptance, protected evidence in an
eligible omission set, or inability to reproduce a candidate pack keeps the broker in
diagnostic mode.

### P3 — Activate a bounded progressive-disclosure canary

**Goal:** determine whether a broker substitution actually improves fully loaded task
economics at equal quality.

**Minimum deliverables**

- Explicit opt-in for low-risk, well-localized task strata only.
- A minimal evidence pack, exact expansion handle, unresolved-reference expansion path,
  and one-step baseline bypass.
- A newly frozen randomized paired comparison of pass-through versus broker; all retry,
  expansion, cache, failure, and correction costs remain in the ledger.
- Initial exclusions for authentication/security-sensitive changes, migrations,
  concurrency, generated behavior, and dynamic/runtime configuration unless separately
  reviewed.

**Exit gate**

- The complete paired population exists and both lanes pass the same success rubric.
- Failure rate stays within the existing 10 percentage-point guardrail and correction
  burden does not worsen.
- Provider-measured tokens and fully loaded shifted cost improve under the predeclared
  rule; cache writes and failed attempts are included.
- Exact rehydration works without manual reconstruction for every exercised handle.

**Kill/rollback:** a security/privacy boundary breach, unrecoverable omission, wrong patch
caused by stale evidence, or worse fully loaded cost triggers immediate baseline bypass
and ends promotion for the affected task stratum.

### P4 — Add the do-nothing router and test cache economics

**Goal:** intervene only where evidence predicts benefit, while preserving stable prompt
prefixes.

**Minimum deliverables**

- A shadow/advisory router choosing pass-through, observe-only, or bounded broker mode,
  with confidence and bypass reason.
- A regret report by task stratum comparing the router with always-pass-through and
  always-on policies.
- Separately frozen prefix-layout A/B evidence covering cache creation, cache reads,
  invalidations, provider cost, latency, and quality.
- Schema-hydration experiments, if any, isolated from prefix-layout experiments so their
  effects are not confounded.

**Exit gate**

- The router matches or beats the better simple policy under the predeclared total-cost
  and quality rule without excluding abstentions or failures.
- Low-confidence and high-risk tasks choose pass-through.
- Prefix changes show favorable complete cache economics, not merely fewer visible
  schema bytes.

**Kill/rollback:** negative regret in a task stratum disables automation there; cache
churn, higher tail cost, or quality regression demotes layout/schema changes to
observe-only.

### P5 — Reduce repeated context and repair loops

**Goal:** add broker-adjacent state only after the request boundary is proven.

**Minimum deliverables**

- An append-only execution twin containing changed paths, commands, test status, failed
  assumptions, revision bindings, and exact artifact handles.
- A failure-cone receipt retaining exit status and diagnostic differences while
  suppressing duplicate logs.
- A typed edit blueprint recording intended files/symbols, invariants, source
  obligations, tests, and an explicit rewire/bypass path.

**Exit gate**

- Staleness injection forces source and test revalidation.
- Similar error signatures with different root causes are not merged silently.
- A cross-cutting task can invalidate and safely expand its original blueprint.
- Each adjunct shows incremental fully loaded improvement over the proven broker lane.

**Kill/rollback:** stale state skips verification, failure grouping hides differentiating
evidence, or a blueprint blocks a necessary change. Do not rewrite live transcript
history as a shortcut.

### P6 — Test specialized high-upside tracks

**Goal:** look for large gains only in narrowly declared workloads after the general
control plane is trustworthy.

**Candidates**

- Task-scoped expansion leases/context GC with source retention.
- Cheap-scout/expensive-surgeon retrieval, charging all helper tokens and recovery work.
- Counterfactual context ledger using hashes/categories rather than raw payloads.
- Negative-context firewall moving from shadow to active only after critical-evidence
  retention is independently verified.
- Execution-twin or bounded micro-agent compilation for large, stable, repeatedly used
  repositories.

**Exit gate**

- A new independently frozen workload-specific study shows fully loaded improvement at
  equal quality and publishes its amortization assumptions.
- Results remain scoped to the measured repository/task/cache conditions.

**Kill/rollback:** coordination, indexing, human repair, or operational support cost
erases the gain; a repository-specific result is presented as universal.

## 6. Mapping the ten brainstorm ideas to delivery

| Idea | Roadmap home | Initial mode |
| --- | --- | --- |
| Request-boundary evidence broker | P2–P3 | Shadow, then opt-in canary |
| Prefix-preserving broker | P2 observation, P4 A/B | Observe-only first |
| Expansion leases/context GC | P6 | Research only |
| Cheap-scout/expensive-surgeon | P6 | Bounded experimental lane |
| Verified execution twin | P5 | Append-only, revision-bound |
| Failure-cone recovery | P5 | Post-failure only |
| Typed edit blueprint | P5 | Advisory metadata |
| Do-nothing router | P4 | Shadow/advisory |
| Counterfactual context ledger | P1/P6 | Metadata only |
| Negative-context firewall | P2/P6 | Shadow only before promotion |

## 7. First execution packet

The next implementation session should begin with P0 only:

1. Create `research/request-boundary-integration-map.md` from a read-only code-path
   inspection; identify what ContextGuard can observe before request assembly and where
   host ownership makes interception impossible.
2. Create `research/request-boundary-measurement-gap.md`; map every required field to an
   existing source, a new local observation, or `unavailable/claim-blocking`.
3. Draft a new experiment charter and manifest namespace without copying R9 authority.
4. Define protected-zone, exact-rehydration, safe-bypass, and stale-anchor test fixtures.
5. Review the P0 packet before writing a broker runtime or performing any provider run.

P0 is complete only when the first two maps and the proposed charter are internally
consistent, reviewable without secrets, and make no savings claim.

## 8. Claim and marketing guardrails

Do not claim:

- a universal percentage reduction or parity with Graphify, Caveman, or Ponytail;
- that R9 proved success, failure, zero effect, or an effect direction;
- that fewer bytes, LOC, output tokens, or primary-agent tokens alone means lower total
  task cost;
- zero accuracy loss, safe automatic compression, or complete semantic replacement;
- that caches, indexes, helpers, local compute, failures, retries, or human repair are
  free;
- that a shadow plan, candidate pack, artifact receipt, or local proxy record is a
  hosted-provider savings result.

Any future numeric claim must name the workload, model, repository condition, cold/warm
cache state, task success rule, complete denominator, and fully loaded accounting. It
must remain limited to the frozen population that produced it.

## 9. Source map

- [`HANDOFF.md`](../HANDOFF.md): current repository and authority state.
- [`r9-summary.md`](../bench/token-savings-12task/results/r9-summary.md): immutable public
  R9 outcome and claim boundary.
- [`benchmark-plan.md`](benchmark-plan.md): established task, metric, failure,
  correction, and shifted-cost rules.
- [`experimental-token-reduction-radar.md`](experimental-token-reduction-radar.md):
  current experimental safety and promotion gates.
- [`claude-code-token-reduction.md`](claude-code-token-reduction.md): existing operational
  token-diet and cache research.
- [`forge-token-savings-brainstorm-20260804.md`](forge-token-savings-brainstorm-20260804.md):
  independent synthesis, risks, falsifiers, and ten candidate ideas.

