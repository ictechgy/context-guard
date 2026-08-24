# ContextGuard token-savings review — 2026-08-04

## Lens

- **Direct evidence:** R9 is `inconclusive`, has no permitted claim, and stopped after a baseline arm-unit exhausted its sole fixed retry; it consumed 33 attempts, yielding 30 successes and 3 valid failures rather than its required complete paired population. No token, retry, correction, interval, or favorable-subset estimate may be derived from those successes. `bench/token-savings-12task/results/r9-summary.md:7-16` `bench/token-savings-12task/results/r9-summary.md:20-35` `bench/token-savings-12task/results/r9-summary.json:11-45`
- **Direct evidence:** The frozen treatment registered only a `Read` `PreToolUse` hook and a `Bash` `PostToolUse` hook; the required event classes were empty. The separate scan found no explicit `Large Read blocked` or `output trimmed` marker. This is evidence that the intended material interventions were not observed, not proof that the hooks could never have run. `.omx/measurement/q015-r9/frozen-live/inputs/treatment.settings.json:2-24` `research/forge-token-savings-prompt-20260804.md:33-36`
- **Direct evidence:** The Read guard’s default byte threshold is 48,000 bytes. The largest frozen fixture was 28,663 bytes, so the size-based Read block could not activate for that fixture population; this says nothing decisive about Bash `PostToolUse`. `context-guard-kit/guard_large_read.py:49-69` `research/forge-token-savings-prompt-20260804.md:34-35`
- **Direct evidence:** ContextGuard already has narrow, local mechanisms: progressive Read denial, output trimming/artifact receipts, repeated-failure nudges, bounded context packs, cache-layout diagnostics, and bounded tool-schema reports. It does not own request assembly across the entire agent loop. `README.md:59-84` `README.md:335-351` `research/forge-token-savings-prompt-20260804.md:38`
- **Inference:** The absence of observed activation plus a fixture population below the read threshold is a more immediate explanation for the lack of a dramatic demonstrated effect than an inference that ContextGuard’s local transformations are intrinsically ineffective. R9 cannot validate that inference because its paired population was incomplete.
- **Inference:** Graphify, Caveman, and Ponytail describe different denominators—corpus/subquery, prose output, and LOC/agentic tokens—rather than a comparable whole-session, quality-gated bill. Their advertised figures therefore do not establish a benchmark ContextGuard should match. `research/forge-token-savings-prompt-20260804.md:42-45`
- **Hypothesis:** The practical gap is a missing request-boundary control plane that can choose evidence, preserve stable prefixes, expose exact expansion paths, and account for costs displaced to helpers, retries, local compute, latency, and human repair.

## Top ideas

### 1. Request-boundary evidence broker

- **Evidence class — Hypothesis. Mechanism:** Place an opt-in broker immediately before request assembly. It selects a bounded, provenance-carrying evidence pack and substitutes an expansion handle plus exact retrieval command for omitted material; it never silently vetoes evidence.
- **Controlled boundary:** Only the caller-supplied, non-protected request tail is eligible. Stable system instructions, user instructions, code/diff literals, credentials, and protected zones are pass-through unless an explicit policy permits a structurally safe representation.
- **Savings surface:** Avoided input tokens from duplicate files, stale logs, and unneeded tool results across the assembled request, rather than relying solely on individual Read or Bash hooks.
- **Shifted costs:** Local selection/index maintenance, receipt storage, re-expansion turns, broker latency, cache-write/cache-read changes, and reviewer time must be charged to each successful task.
- **Failure mode:** An omitted dependency, stale receipt, or unusable expansion handle causes extra tool calls, a wrong edit, or a correction loop that exceeds the avoided input.
- **Smallest falsifier:** In a newly authorized matched-task study, compare pass-through assembly with broker assembly while requiring identical quality gates and successful exact rehydration; reject the broker lane if it causes any gated omission failure or higher total billed-plus-shifted cost per success.

### 2. Prefix-preserving broker mode

- **Evidence class — Hypothesis. Mechanism:** Make the broker append bounded volatile evidence after a deliberately stable instruction/tool prefix; it records a redacted segment-layout fingerprint but does not rewrite the prefix during a session.
- **Controlled boundary:** Operate on request ordering and tail selection only; do not mutate provider-owned cache state, raw prompts, instructions, or model/tool schemas.
- **Savings surface:** Potentially improves cache-read reuse while reducing volatile-tail input, subject to provider-measured usage fields rather than character proxies.
- **Shifted costs:** Cache creation charges, cache invalidation from an unstable prefix, telemetry collection, additional request assembly latency, and missed-context recovery.
- **Failure mode:** Reordering can invalidate a cache-friendly prefix or change instruction salience, producing cache churn or quality regression.
- **Smallest falsifier:** Freeze two otherwise identical request layouts and collect provider input, cache-creation, cache-read, output, latency, and quality data. Demote this mode if cache economics or task quality is non-inferior only under a denominator that excludes write costs or failures.

### 3. Expansion leases with context garbage collection

- **Evidence class — Hypothesis. Mechanism:** Give each brokered evidence handle a task-scoped lease, usage count, source revision, and expiry; retire only the compact reference after its dependency set is closed, retaining exact local rehydration.
- **Controlled boundary:** Never delete source material, alter transcript history, or compact protected evidence. Lease expiry affects future request inclusion, not recoverability.
- **Savings surface:** Prevents obsolete tool output and superseded evidence from returning in later turns.
- **Shifted costs:** Dependency tracking, disk retention, lease bookkeeping, re-expansion latency, and human diagnosis when a dependency graph is incomplete.
- **Failure mode:** Premature expiry hides a still-needed rationale, producing retries or a false confidence edit.
- **Smallest falsifier:** Seed a task fixture with a delayed dependency and require the system to rehydrate it without human intervention; reject automatic expiry if the dependency is omitted or if rehydration adds more successful-task cost than retaining it.

### 4. Quality-gated cheap-scout / expensive-surgeon cascade

- **Evidence class — Hypothesis. Mechanism:** Use a low-cost local or cheaper-model scout only to rank candidate evidence and produce citations; the primary coding model makes the final interpretation and edit from verified source slices.
- **Controlled boundary:** Scout output is advisory metadata, never authoritative code, security policy, or hidden evidence replacement. The surgeon may inspect source slices and override the ranking.
- **Savings surface:** Reduces expensive-model input devoted to repository orientation and irrelevant candidate files.
- **Shifted costs:** Scout-model tokens, local compute, orchestration latency, false-positive review, false-negative recovery, and dual-model operational complexity.
- **Failure mode:** A weak scout misses the only relevant file, forcing repeated discovery or a poor patch.
- **Smallest falsifier:** Run a retrieval-recall gate over frozen coding tasks before any end-to-end cost trial; reject the cascade if verified relevant evidence recall is below the predeclared gate or total quality-gated cost rises after scout costs are included.

### 5. Verified execution twin

- **Evidence class — Hypothesis. Mechanism:** Maintain a local, deterministic task-state record containing changed paths, commands, test status, failed assumptions, and exact artifact handles. Inject only the delta needed for the next action, not a narrative history rewrite.
- **Controlled boundary:** The twin is an append-only local execution receipt and cannot overwrite the agent’s instructions, transcript, source, or provider request history.
- **Savings surface:** Avoids replaying long command output and rediscovering already verified state on retries, handoffs, and test-failure recovery.
- **Shifted costs:** State capture/storage, invalidation when files change, synchronization latency, and repair when command results are ambiguous.
- **Failure mode:** A stale or incomplete twin directs the agent to skip a necessary test or assumes an edit remains present.
- **Smallest falsifier:** Introduce an external file change and a failing test after state capture; reject use of the twin as a context substitute if it cannot flag staleness and force source/test revalidation.

### 6. Failure-cone recovery controller

- **Evidence class — Hypothesis. Mechanism:** On a failed command or quality gate, construct a bounded cone of the command, diagnostic signature, changed files, relevant test slice, and prior attempted remedy; suppress duplicate logs while retaining exact artifact retrieval.
- **Controlled boundary:** It activates only after a nonzero result or failed quality gate and cannot hide exit status, error signature, protected paths, or the full sanitized artifact handle.
- **Savings surface:** Reduces repeated failure transcripts and redundant exploratory tool calls during recovery.
- **Shifted costs:** Artifact creation, classifier false matches, an extra recovery turn, delayed full-log inspection, and human escalation.
- **Failure mode:** Over-grouping distinct failures masks a root cause; under-grouping provides no reduction.
- **Smallest falsifier:** Feed two failures with a similar signature but different root causes; reject automatic cone reuse if it recommends the prior remedy without surfacing the differentiating evidence.

### 7. Typed edit blueprint with source obligations

- **Evidence class — Hypothesis. Mechanism:** Before editing, compile a compact typed blueprint: intended files/symbols, invariants, source-slice handles, planned tests, and rollback condition. The primary model receives the blueprint plus exact required slices, not broad repository prose.
- **Controlled boundary:** The blueprint is plan metadata only; it cannot apply edits, infer missing code, or replace protected code/diff literals.
- **Savings surface:** Limits repeated broad reads and reduces correction turns caused by ambiguous edit intent.
- **Shifted costs:** Blueprint generation/validation, schema maintenance, source retrieval, planning latency, and abandonment if the task changes.
- **Failure mode:** An overly rigid type schema excludes an unconventional but necessary edit path and causes workaround turns.
- **Smallest falsifier:** Use a cross-cutting task that invalidates the initial blueprint; reject mandatory use if an explicit safe expansion/rewire path cannot recover without manual bypass or quality loss.

### 8. Do-nothing router with measurement-product positioning

- **Evidence class — Inference:** Because brief mode has a fixed installed byte cost and provider-token impact is unmeasured, some tasks should preserve the ordinary request rather than pay a guardrail or transformation overhead. `README.md:100-124` `research/forge-token-savings-prompt-20260804.md:37`
- **Mechanism:** Build a passive router that chooses pass-through, observe-only, or a narrowly bounded intervention based on predeclared local signals and uncertainty; position ContextGuard first as measurement, safety, and evidence-quality infrastructure.
- **Controlled boundary:** The router is advisory by default, never changes model choice, sends no telemetry externally, and treats unknown cache/provider pricing behavior as a reason to observe rather than optimize.
- **Savings surface:** Avoids negative savings from unnecessary transforms, prompt-prefix churn, brief-mode overhead, and operational complexity.
- **Shifted costs:** Routing logic, false abstention, missed opportunities, instrumentation maintenance, and user comprehension of non-action.
- **Failure mode:** A permissive router lets true bloat persist; an aggressive router adds overhead to short or already terse tasks.
- **Smallest falsifier:** In a frozen mixed workload, compare the router with always-on and pass-through policies using total billed-plus-shifted cost per quality-gated success; reject the router if it cannot beat or match the better simple policy without excluding abstentions.

## Wild cards

### 9. Counterfactual context ledger

- **Evidence class — Wild card. Mechanism:** For every accepted broker substitution, retain a privacy-preserving local ledger of the pass-through byte class, chosen representation, expansion count, downstream retries, and repair outcome. It produces counterfactual candidates for later authorized replay without asserting a saved token amount.
- **Controlled boundary:** Record only hashes, categories, measured provider usage fields, and explicit human-repair annotations; never retain credentials, raw prompts, raw tool payloads, or hidden model reasoning.
- **Savings surface:** Identifies which omission classes actually correlate with successful-task economics, enabling removal of harmful transforms rather than broad compression.
- **Shifted costs:** Ledger storage, schema evolution, privacy review, annotation burden, and replay-study cost.
- **Failure mode:** Selection bias turns the ledger into a favorable-case catalogue or sensitive metadata becomes operationally burdensome.
- **Smallest falsifier:** Independently audit randomly sampled accepted and rejected decisions for complete cost/quality fields and privacy-policy compliance; reject product use if either denominator cannot be reconstructed.

### 10. Negative-context firewall in shadow mode

- **Evidence class — Wild card. Mechanism:** Shadow-classify context units likely to be distractors—duplicate stale logs, superseded diffs, unrelated tool schemas, or already-resolved errors—then report a proposed exclusion and exact rehydration handle without changing the live request.
- **Controlled boundary:** Shadow mode cannot omit or rewrite anything. A later explicit experiment may authorize exclusion only for non-protected, source-retrievable units that pass a human-reviewed policy.
- **Savings surface:** Could expose negative-value context that increases reasoning and correction effort even when raw byte volume is moderate.
- **Shifted costs:** Classifier development, policy review, false-negative opportunity cost, false-positive recovery, and increased operational explanation.
- **Failure mode:** Relevance is task-dependent; a seemingly stale log may contain the sole clue to a regression.
- **Smallest falsifier:** On frozen annotated tasks, require the firewall to preserve every predeclared critical unit and to show no quality regression in a separately authorized shadow-to-active transition; otherwise keep it diagnostic only.

## Risks / failure modes

- **Direct evidence:** R9’s incomplete paired population means a success-only denominator would be misleading; its frozen design expressly forbids that subset analysis. `bench/token-savings-12task/results/r9-summary.md:33-35` `bench/token-savings-12task/results/r9-summary.json:14-15`
- **Inference:** Omission risk is the central product hazard: a compact reference is useful only if the right evidence remains selected and an exact expansion path is reliable.
- **Inference:** Stale indexes, execution twins, receipts, and leases can create false confidence after source, environment, tool version, or test state changes; revisions and invalidation must be observable.
- **Inference:** Retry amplification can overwhelm a byte reduction when a brokered request causes one extra investigation, test run, model turn, or human correction.
- **Hypothesis:** Cache invalidation can make dynamic schema hydration or history mutation net-negative when it destabilizes a reusable prefix; provider cache-write and cache-read telemetry must be counted together.
- **Direct evidence:** ContextGuard’s current security stance is deliberately local and bounded, with protection/redaction and exact-retrieval guidance; a request-boundary runtime must preserve those boundaries rather than become a general prompt or credential proxy. `README.md:152-164` `README.md:608-610`
- **Inference:** Operational complexity—multiple models, indexes, artifacts, leases, router policies, migrations, and on-call diagnostics—can outweigh a small token effect and make failures hard to recover.
- **Hypothesis:** Misleading denominators arise if a report omits cache writes, helper models, local compute, latency, retries, provider billing provenance, failed tasks, or human repair; the required unit should be total billed and shifted cost per quality-gated successful task, with failures retained in the study accounting.

## Assumptions to validate

- **Hypothesis:** A request-boundary broker can obtain complete provenance and exact rehydration handles for all eligible evidence without retaining raw sensitive material.
- **Hypothesis:** Stable-prefix ordering can improve or preserve provider cache economics after cache creation, cache reads, and invalidation are measured from provider telemetry.
- **Hypothesis:** A top-k tool-schema or evidence selection method retains all task-critical context at a predeclared recall threshold.
- **Hypothesis:** The execution twin’s invalidation signals detect source/test/environment changes before its compact state is used to skip a verification step.
- **Hypothesis:** Cheap-scout costs, latency, and false-negative recovery are lower than the primary-model orientation work they displace.
- **Hypothesis:** Failure cones reduce duplicated recovery context without conflating distinct root causes.
- **Hypothesis:** Brief-mode or history-compaction overhead clears its fixed prompt cost on the selected task distribution; installed byte size alone is not a provider-token result. `README.md:100-124`
- **Hypothesis:** Any human-repair accounting can be captured consistently enough to compare interventions without hiding rework in an unmeasured queue.

## Recommended next experiments

- **Direct evidence:** Preserve R9 unchanged. It is an inconclusive frozen study with no allowed token-savings claim; a new decisive study requires a new plan, freeze, and authorization rather than an extension or reinterpretation of R9. `HANDOFF.md:19-25` `HANDOFF.md:60-62`
- **Hypothesis — One-week study:** Plan, freeze, rehearse, and obtain authorization for a one-week matched-task pilot of an **observe-only request-boundary broker** versus pass-through. The broker may log bounded candidate evidence packs and prefix/tail layout metadata, but it must not modify the live request in this first study.
- **Hypothesis — Primary endpoint:** The primary endpoint is feasibility: complete quality-gated paired task population with complete provider usage/provenance and shifted-cost records for every consumed attempt. This is deliberately not a token-savings effect estimate.
- **Hypothesis — Quality gate:** Predeclare task-specific success commands, human-review rubric where needed, source-coverage/rehydration checks for broker candidates, fixed retry policy, and stop rules. Stop analysis before any effect calculation if the complete paired population or telemetry provenance gate fails.
- **Hypothesis — Shifted-cost accounting:** For every attempt record input, cache creation, cache reads, output, provider-reported cost when available, helper-model tokens/cost, local CPU/RAM/energy proxy if measurable, index build/maintenance time, wall latency, retries, corrections, and human repair. Keep unavailable fields explicitly unavailable rather than imputing them as zero.
- **Hypothesis — Kill condition:** Kill the active-mutation follow-up if observe-only coverage cannot capture the complete fields and exact rehydration evidence, if any privacy/security boundary is crossed, or if a subsequent small authorized active pilot has a quality failure, unrecoverable omission, or worse total billed-plus-shifted cost per successful task under its predeclared decision rule.
- **Hypothesis — Sequencing:** Only after the feasibility gate passes, run separately frozen A/B studies for prefix preservation, broker substitution, and schema hydration. Do not combine them initially, because cache behavior and selection quality would be confounded.

## Decision matrix

| option | upside | downside | implementation cost | operational risk | confidence | best next test |
| --- | --- | --- | --- | --- | --- | --- |
| Request broker | **Hypothesis:** controls selected evidence at the assembly boundary, where isolated hooks cannot. | **Hypothesis:** omission and rehydration failures can cause expensive recovery. | **Inference:** High | **Inference:** High | **Inference:** Medium | **Hypothesis:** Observe-only provenance and rehydration feasibility pilot. |
| Prefix stability | **Hypothesis:** preserves cache-friendly ordering while bounding volatile tails. | **Hypothesis:** provider cache economics can be worsened by a layout change. | **Inference:** Medium | **Inference:** Medium | **Inference:** Low | **Hypothesis:** Frozen layout A/B with provider cache write/read telemetry. |
| Schema hydration | **Hypothesis:** avoids sending unused tool schemas. | **Inference:** dynamic hydration may destabilize a cached prefix and add expansion turns. | **Inference:** Medium | **Inference:** Medium | **Inference:** Low | **Hypothesis:** Measure static catalog selection recall and complete cache economics before mutation. |
| History compaction | **Hypothesis:** reduces stale prior-turn context. | **Inference:** rewriting or summarizing history risks lost rationale and cache invalidation. | **Inference:** High | **Inference:** High | **Inference:** Low | **Hypothesis:** Start with execution-twin delta receipts; avoid live history mutation. |
| Execution twin | **Hypothesis:** prevents repeated replay of verified state and failure details. | **Hypothesis:** stale state can skip required verification. | **Inference:** Medium | **Inference:** Medium | **Inference:** Medium | **Hypothesis:** Staleness-injection and exact-revalidation tests. |
| Do-nothing router | **Inference:** avoids fixed overhead where intervention is unlikely to pay back. | **Hypothesis:** may miss true bloat or be harder to explain than an always-on rule. | **Inference:** Low–Medium | **Inference:** Low | **Inference:** Medium | **Hypothesis:** Mixed-workload comparison against pass-through and always-on policies. |
| Measurement-product positioning | **Direct evidence:** the product already emphasizes conservative local measurement rather than fixed savings promises. `README.md:36` `README.md:138-150` | **Inference:** it may be less marketable than a headline compression claim. | **Inference:** Low | **Inference:** Low | **Inference:** High | **Hypothesis:** Feasibility study that proves complete accounting and quality gates before any runtime claim. |

## Final stance

- **Inference:** ContextGuard should remain a local-first safety, measurement, artifact-retrieval, and evidence-quality product. Its conservative claim posture is appropriate because R9 does not support a savings result. `README.md:36` `bench/token-savings-12task/results/r9-summary.md:75-81`
- **Hypothesis:** The needed new runtime boundary is an opt-in, provenance-preserving request-boundary evidence broker with bounded substitutions, exact expansion handles, protected-zone pass-through, prefix-observation mode, and complete cost/quality accounting.
- **Inference:** Demote automatic dynamic tool-schema hydration and live history rewriting until prefix/cache economics and omission recovery are measured; reject any design that merely vetoes evidence without a bounded substitute and expansion path.
- **Inference:** Treat the execution twin, failure-cone recovery, typed blueprint, and do-nothing router as testable adjuncts to the broker—not independent savings claims. Retain the negative-context firewall and counterfactual ledger in shadow/measurement mode until a newly frozen, authorized, quality-gated study establishes whether their shifted costs justify activation.
