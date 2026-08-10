# ContextGuard token-savings roadmap

_Status date: 2026-08-10 KST_

This file is the canonical dependency, maturity, stop-gate, and claim contract
for ContextGuard token-savings work. Draft run packets and implementation plans
may narrow it but may not grant authority or relax its gates.

## North star and current position

ContextGuard should reduce fully loaded provider token/cost per quality-gated
successful task while keeping failures, retries, cache writes, retrievals,
helper work, latency, and human corrections visible.

Current position:

| Dimension | Status |
| --- | --- |
| Shipped-code readiness | Narrow P3-style opt-in Bash-output reference route is merged. |
| Evidence readiness | P1 live feasibility/effect gate is not passed. |
| Release readiness | An attested immutable candidate exists; npm publication has not occurred. |
| Public claim | Forbidden: no provider-backed v3 decision record exists. |

The roadmap is dependency-gated:

`P0 contract -> P1 live measurement -> P2 shadow broker -> P3 bounded canary -> P4 router/cache -> P5 adjuncts -> P6 specialized tracks`

An implementation may exist ahead of its evidence stage, but it must remain
default-off, diagnostic, or claim-blocked until every preceding exit gate is
met.

## Phase gates

| Phase | Entry gate | Exit gate | Stop or fallback gate |
| --- | --- | --- | --- |
| P1 live measurement | P0 complete; exact provider-free candidate, corpus, observers, retry policy, privacy boundary, calls, and spend are frozen; separate provider approval is recorded. | Complete frozen population has valid provider usage and checker evidence; every consumed identity and every measured/unavailable field is honestly accounted for. | Missing claim-critical evidence, an incomplete population, drift, ambiguity, privacy failure, or limit breach keeps P1 blocked and stops active P2-P6 promotion. |
| P2 shadow broker | P1 exit passed; authoritative host evidence identifies a supported interception/attribution boundary; phase-specific evaluation authority is recorded. | Every stratum meets preregistered recall; construction cost is complete; every omission rehydrates exactly and freshly; protected-zone eligibility violations equal zero. | Unsupported boundary keeps P2 diagnostic; any recall, provenance, freshness, rehydration, accounting, or protected-zone failure retains unchanged requests and the narrow Bash route only. |
| P3 bounded canary | P2 exit passed for the enabled stratum; opt-in, unchanged bypass, matched design, and provider/cost authority are frozen. | Complete randomized evidence passes exact retrieval, failure-rate increase below 10 percentage points, no worse correction burden, and provider-measured fully loaded cost improvement. | Security/privacy breach, stale or unrecoverable evidence, guardrail failure, or worse fully loaded cost immediately demotes that stratum to baseline. |
| P4 router/cache | P3 exit passed for the enabled stratum; router remains shadow/advisory and cache accounting is frozen. | Router matches or beats the better always-pass-through or always-on policy; cache experiments account separately for creation, reads, invalidation, latency, provider cost, and quality. | Negative regret, low confidence, incomplete cache accounting, or quality regression disables automation for that stratum and selects pass-through. |
| P5 adjuncts | P4 exit passed; each adjunct has an independent revision-bound design, baseline, bypass, and evaluation. | Each adjunct independently improves quality-gated fully loaded outcomes; staleness and root-cause differentiation tests pass. | Stale state, merged distinct failures, missing evidence obligations, or an uneconomic result disables only that adjunct and preserves the proven route. |
| P6 specialized tracks | P5 exit passed; each track has its own frozen workload, baseline, privacy boundary, quality rule, complete cost model, rollback, and authority. | A track independently passes provider-measured matched success, correction/failure guardrails, privacy, exact fallback, and shifted-cost accounting. | Failure or unavailable critical evidence keeps that track plan/evaluation-only; results never generalize beyond the measured repository, task, model, and cache conditions. |

## Completed foundation

### P0 — decision and safety contract: complete

- Protected zones, exact fallback, provenance, failure-inclusive accounting,
  retry/stop policy, and claim boundaries are represented in repository
  contracts and tests.
- R9 remains immutable and `inconclusive`; it supplies no effect direction.
- Provider-free Stage 2 evidence honestly records that a general host
  request-assembly observer cannot be authorized from repository-only facts.

### Narrow progressive-disclosure implementation: complete, not promoted

- `bash_reference_v1` stores strongly sanitized long Bash output in a private,
  authenticated Receipt store and emits a compact exact-retrieval handle.
- Retrieval is project-bound, expiry-bound, package-bound, and paginated.
- Unsupported installs and preparation failures deterministically retain legacy
  behavior. The route is default-off.
- This is a tool-output intervention, not a general request-boundary broker.

### Measurement and release substrate: complete locally

- The v2 study freezes three arms, corpus/checkers, schedule, CLI/runtime,
  candidate overlay, environment, receipts, and crash-safe attempt identity.
- Its provider-free rehearsal exercises the live artifact contract:
  `study-manifest.v4`, `study-attempt.v3`, `study-report.v4`, and the
  `study-invalid-decision.v1` P1-X record. Rehearsal evidence itself remains
  descriptive and cannot substitute for provider-backed evidence.
- A mandatory discarded canary proves host-emitted `PreToolUse(Bash)` for both
  hook arms without filtering analytic intention-to-treat attempts.
- Offline rehearsal uses no provider/network/credentials and cannot support a
  savings claim.
- npm candidate, clean-install, publication, promotion, and rollback gates are
  implemented, but no external publication follows automatically.

## P1 — close live measurement feasibility

### Local work

1. Re-run the exact candidate build, provider-free v2 rehearsal, package checks,
   protected-surface verification, and release smoke from the new branch.
2. Produce a frozen live-run authorization packet containing exact CLI/model,
   task corpus, call count, spend ceiling, retry/stop policy, output root,
   privacy boundary, and expected unavailable observers.
3. Confirm every report field is either measured or explicitly unavailable;
   unavailable values must never become zero or a proxy.

Current provider-free progress: candidate construction, paired clean-install
smoke, post-hardening v2 rehearsal, focused benchmark/npm/Receipt/Gate-B/Stage2
verification, the authorization packet, and full offline
`python3 scripts/prepublish_check.py` (`1564` tests, `3` skips) have passed.
GitHub candidate run `31314422888` attested both package tarballs and the
canonical manifest for merged source `2489f999...`; no npm registry publication
occurred.

### External gate

The user recorded exact approval on 2026-08-09 for repository-scoped GitHub
activity, npm candidate-only construction, and the capped P1 Claude study. After
a reviewed commit and immutable candidate exist, run `prepare`, the two-call
discarded canary, the fixed analytic schedule with conservative resume semantics,
and `analyze` using the same exact native Claude CLI and candidate.
The candidate workflow must be dispatched from a retained remote branch or tag
whose tip is verified to equal the reviewed merge SHA; a detached local build
is diagnostic-only and cannot replace workflow attestation.

### 2026-08-10 live checkpoint

- Exact candidate `2489f999...` completed provider-free `prepare` in a new
  owner-private root.
- The first `legacy_trim` canary identity reached a terminal process failure
  reporting `Not logged in`; the CLI reported zero input/output tokens, zero
  provider API duration, and `$0` cost. Follow-up provider-free diagnosis proved
  the operator's normal exact CLI was logged in. The failure came from the
  runner replacing both HOME and `CLAUDE_CONFIG_DIR` with empty per-attempt
  directories, thereby hiding the login from the CLI. The second canary and all
  analytic identities were not launched.
- The failed root is permanently closed to provider activity. During evidence
  closure, a contract bug was found: `analyze` refused a terminal failed canary
  before writing the promised P1-X record. A provider-free regression test and
  minimal fix now make failed canaries emit a bound
  `failed_canary_terminal_evidence` P1-X without any replay.
- A reviewed and merged fix now requires explicit existing-login opt-in, binds
  only hashed identity/HOME evidence plus safe auth method/provider fields, rejects auth
  drift before reservation, preserves isolated XDG/session paths, and passes no
  credential-shaped environment variable. The operator approved this exact-CLI
  internal auth reuse and raised the cumulative identity ceiling to 219 on
  2026-08-10.
- Exact merged source `af93dca...` and candidate run `31345333296` then passed
  prepare in a second fresh root. Its first `legacy_trim` canary reached the
  real provider and emitted a valid host `PreToolUse(Bash)` lifecycle, but the
  hook correctly denied the requested `printf ... > file` command because
  MiniShell-v1 forbids active output redirection. The model therefore could not
  create the marker. Provider-free `analyze` wrote the canonical P1-X and no
  second canary or analytic identity launched. This root is also permanently
  closed.
- The two stopped roots now account for two identities. The second consumed
  `$0.07436490000000001` and reported 4 input, 9,095 cache-creation, 56,943
  cache-read, and 137 output tokens. The approved cumulative ceiling remains
  219, leaving 217 identities; a new complete root still needs up to 218, so no
  provider retry is authorized unless the cumulative ceiling is explicitly
  raised to at least 220.
- The provider-free remediation keeps MiniShell unchanged and replaces the
  canary's denied redirection with an already-supported exact `python3 -c`
  marker write. Regression coverage invokes both real hook modes and makes the
  fake host honor a hook denial before writing the marker. A new reviewed
  immutable candidate is required before any later live retry.
- Exact merged source `db415c7...` and candidate run `31348702952` then passed
  provider-free prepare and both real host-mediated canaries. The analytic run
  terminally accounted 42 initial identities with zero retry calls before
  stopping: one provider `invalid_stream` and one successful provider/checker
  attempt whose Python hook wrapper created a `__pycache__` file inside the
  immutable candidate overlay. The ledger has zero open identities and the
  root is permanently closed. The original analyzer refused that drifted
  terminal row, so no canonical P1-F decision exists and no claim is allowed.
- PR #292 merged the provider-free closure as `0b35a8cb...`: executable v2 now
  freezes `PYTHONDONTWRITEBYTECODE=1`, re-derives terminal overlay drift as
  infrastructure invalid, blocks every later provider launch, and writes a
  claim-disabled `terminal_analytic_infrastructure_invalid` P1-X on future
  roots. Local prepublish passed `1568/1568`; Linux 3.11, Linux 3.12, macOS,
  and CodeRabbit passed on the exact PR head.
- Candidate run `31357316775` attempt 2 built and attested the exact
  `0b35a8cb...` pair after all release gates and paired smoke passed. Root
  SHA-256 is `3b71c654...`; Receipt SHA-256 is `ec00b91d...`; the manifest and
  both tarballs passed GitHub attestation verification. No npm publish or
  dist-tag mutation occurred.
- Cumulative P1 accounting is now 46 consumed/reserved identities out of the
  approved 220, leaving 174. A fresh fixed root may consume 218 identities, so
  no further provider run is authorized. A future retry requires an explicit
  cumulative ceiling of at least 264, a newly frozen finite call/spend plan,
  and a fresh exact candidate.
- The user subsequently approved that exact retry boundary: cumulative ceiling
  264, with the 46 prior identities retained and at most 218 new identities in
  one fresh root. The new root keeps the frozen 2 canaries + 108 initials + up
  to 108 policy-valid retries, `sonnet`, `$0.75` per process, `$163.50`
  arithmetic maximum, no optional stopping, and the existing privacy/stop
  rules. Candidate run `31357316775` attempt 2 is the fresh exact PR #292
  candidate. npm `next`/`latest` and active P2-P6 work before P1-F remain
  unauthorized.
- Fresh v6 root `/private/tmp/contextguard-p1-live-v6.MS256a` passed both real
  canaries and terminally accounted 41 analytic initials before a successful
  baseline long-log result was followed by Claude Code's three local
  background-task shutdown events. The frozen parser rejected any event after
  `result`, so the runner correctly stopped later launches and wrote canonical
  P1-X `cf09039a...` with no ambiguous identities. The root is closed.
- Provider-free TDD now permits only the exact same-session bounded shutdown
  triad while continuing to reject duplicate results, other sessions, running
  tasks, other terminal statuses, missing fields, and arbitrary post-result
  events. The actual frozen raw reparses as success; v2 and benchmark surfaces
  passed 219/219 and full prepublish passed 1569/1569 with 3 skips. PR #294
  merged the fix as `5bf699bd...` after CodeRabbit and all hosted CI jobs
  passed.
- V6 consumed 43 identities including canaries. Cumulative accounting is now
  89/264, leaving 175. Another maximum-size root requires an explicit ceiling
  of at least 307 and a new finite call/spend freeze. P1-F remains unpassed.
- Candidate run `31396910541` built the exact PR #294 merge, passed paired
  clean-install smoke, produced three verified attestations, and uploaded both
  immutable artifacts. Manifest SHA-256 is `88670200...`; root tarball SHA-256
  is `fce70526...`; Receipt tarball SHA-256 remains `ec00b91d...`. No npm
  publication or dist-tag operation occurred.

P2-P6 active promotion remains stopped until a fresh P1 exit gate passes.

### Exit gate

- Every consumed identity is terminally accounted for.
- Provider usage and checker evidence are valid for the complete frozen
  population.
- Failure, correction, retrieval, cache, and shifted-cost availability is
  reported honestly.
- No favorable subset analysis is permitted.

If the complete population or claim-critical evidence is unavailable, P1 stays
blocked and active P2–P6 promotion stops.

P1 decisions are schema-bound: `P1-F` is complete valid feasibility evidence,
`P1-D` is explicitly bounded diagnostic evidence that unlocks nothing, and
`P1-X` is an ambiguous, incomplete, corrupt, unsafe, selectively analyzed, or
over-limit study. Every decision remains descriptive-only with claims disabled.

## P2 — observe-only request-boundary broker

P2 may start only after `P1-F`, authoritative host evidence identifies a
supported interception/attribution boundary, a P2 preregistration is approved,
and any P2 provider/cost authorization is separately granted.

Deliverables:

- shadow candidate evidence packs with source/hash/range provenance;
- exact local rehydration and freshness checks for every candidate omission;
- protected/ambiguous material retained unchanged;
- prefix/tail and duplicate/staleness diagnostics without live request mutation;
- recall evaluation against evidence required by successful baseline tasks.

Exit requires a predeclared recall threshold for every supported task stratum,
complete construction-cost accounting, and zero protected-zone eligibility
violations. If the host boundary remains unsupported, P2 remains diagnostic and
the Bash route stays the only active narrow mechanism.

## P3 — bounded progressive-disclosure canary

The existing Bash reference route is the first narrow implementation candidate.
Promotion requires:

- explicit opt-in and one-step unchanged/legacy bypass;
- randomized matched comparison with complete retries and failures;
- exact retrieval success for every exercised handle;
- failure-rate increase below 10 percentage points and no worse correction
  burden;
- provider-measured token and fully loaded shifted-cost improvement under the
  frozen decision rule.

Security/privacy breach, stale evidence, unrecoverable omission, or worse fully
loaded cost immediately demotes the affected stratum to baseline.

## P4 — do-nothing router and cache economics

Build the router first as shadow/advisory metadata over the three deterministic
routes. It must expose confidence and bypass reasons and retain abstentions and
failures in its regret report.

Exit requires the router to match or beat the better always-pass-through or
always-on policy under the same quality/total-cost rule. Prefix-layout/cache
experiments must separately account for cache creation, reads, invalidation,
latency, and provider cost. Negative regret disables automation for that
stratum.

## P5 — repeated-context and repair-loop adjuncts

Implement separately and promote incrementally:

1. append-only execution twin bound to revision, paths, commands, tests, failed
   assumptions, and exact artifact handles;
2. failure-cone receipt preserving exit status and diagnostic differences while
   suppressing only proven duplicates;
3. typed edit blueprint with intended files/symbols, invariants, evidence
   obligations, tests, and explicit rewire/bypass.

Staleness injection must force source/test revalidation. Similar-looking errors
with different roots must not be merged. No live transcript rewriting is
authorized.

## P6 — specialized high-upside tracks

Each track gets its own frozen workload and can be promoted only independently:

- task-scoped expansion leases/context GC;
- cheap-scout/expensive-surgeon retrieval with all helper cost charged;
- counterfactual context ledger storing hashes/categories, not raw payloads;
- negative-context firewall moving from shadow only after critical-evidence
  retention is independently verified;
- execution-twin or bounded micro-agent compilation for large stable repos.

Existing semantic-GC, image-context-pack, proof-carrying-context,
semantic-checkpoint, learned-compression, and static-relevance surfaces remain
plan-only/evaluation-only unless a new track satisfies provider-measured matched
success, correction/failure guardrails, privacy, exact fallback, and shifted
cost accounting.

## Immediate ordered work

1. Refresh HANDOFF and establish this canonical roadmap.
2. Close all provider-free P1 readiness checks and write the external
   authorization packet.
3. Use the recorded GitHub/P1/npm-candidate authorization. Keep npm `next`, npm
   `latest`, artifact deletion, and P2-P6 provider work blocked.
4. Execute and analyze P1. Stop if its exit gate fails.
5. Implement/evaluate P2, then P3, then P4, then P5, then P6, checkpointing each
   gate before starting the next.

The external authorization packet records the user's bounded authority; the
packet does not create or expand authority by itself. It must be frozen after
the source revision and immutable candidate are selected; an older development
candidate is never reused after source changes.

## Authority and claim boundary

- Local source changes and provider-free tests do not expand the recorded P1,
  GitHub, or npm-candidate authority and never authorize credential access.
- Candidate build does not authorize publication; `next` publication does not
  authorize `latest` promotion.
- Provider/model calls require an exact bounded approval and may expose frozen
  prompts/task fixtures to that provider.
- The recorded provider authority covers P1 only. Every P2-P6 provider
  evaluation requires a new phase-specific call and USD authorization.
- No universal percentage, parity with another tool, or hosted token/cost claim
  is allowed from byte counts, token proxies, rehearsal, successful subsets, or
  plan-only experiments.
