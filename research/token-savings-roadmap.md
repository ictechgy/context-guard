# ContextGuard token-savings roadmap

_Status date: 2026-08-13 KST_

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
| Shipped-code readiness | PR #302 merged normally as `1211a58c92e30b9a70b1b47cf86909fcf39a91f7`. G1-G6 provider-free implementation is complete, including the closed P2-P6 evaluators, explicit non-activating MCP workflow, and opt-in graph-applied context pack. Implementation does not imply provider execution or runtime activation. |
| Evidence readiness | P1-F: v8 completed 108 initials, 13 policy-valid retries, and 2 discarded canaries with every identity accounted for. On 2026-08-13 the narrow Claude print-JSON P2 shadow completed its fixed 240-call schedule: closed-pack passed implementation readiness without activation, while realistic-fallback stayed diagnostic because of protected omissions. Provider token fields were invalidated after post-run model-usage review, so P3 is blocked rather than inferred. |
| Release readiness | Immutable candidate run `31652575332` is bound to source `540c6e02222f25346ca9c797197882cebbe5331d`; its root and Receipt artifacts are `9163551917` and `9163551685`. npm publication and `next`/`latest` dist-tag mutation have not occurred. |
| Public claim | Forbidden: power, correction, retrieval, shifted-cost, quality, and failure gates do not support a claim. |

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

### Explicit file/log context path: implemented, opt-in, not promoted

- The Receipt MCP now exposes one high-level `receipt_context` tool. A caller
  supplies only an explicitly eligible repository-relative file or log path;
  the server reads and binds the exact local bytes without requiring those bytes
  in the tool request.
- The existing conservative byte-benefit router keeps small or uneconomic input
  unchanged and emits a compact exact process-local reference only when deferral
  clears the fixed thresholds. Repeated unchanged requests reuse that live
  capability, and progressive reads return exact slices capped at 65,536 bytes.
- Optional task scopes bind a live capability to one explicit task. Explicit
  release revokes it immediately, while bounded context history keeps only
  process-keyed HMACs, counts, and decisions. This is the task-scoped lease/GC
  portion of the P6 plan; it is not a host context lease.
- `receipt_diagnose` projects the existing shadow firewall, router economics,
  prefix reuse, and cheap-scout/expensive-surgeon advisory lane directly from an
  eligible local path without returning its bytes. It applies no route.
- Starting MCP with an explicit private `--state-dir` enables only the existing
  authenticated execution twin. Tool calls cannot choose the state path, and
  twin append/inspect never execute a declared action. Evidence packs and typed
  blueprints remain available through `receipt_assemble` for explicit failure
  cones and edit obligations.
- Non-eligible classifications are rejected before file content is read or
  reflected. Repository drift, capability expiry, process exit, or restart
  invalidates the route and requires an explicit new invocation.
- This is the first usable wrapper/MCP product path around the shipped P3-P6
  building blocks. It does not intercept whole host context, auto-register an
  MCP server, persist capability cache across restart, execute twin actions, or
  grant a hosted savings claim. P2 live observation remains unsupported; P3-P6
  provider-measured promotion remains dependency- and authority-gated.

### Measurement and release substrate: complete locally

- The v2 study freezes three arms, corpus/checkers, schedule, CLI/runtime,
  candidate overlay, environment, receipts, and crash-safe attempt identity.
- Its provider-free rehearsal exercises the live artifact contract:
  `study-manifest.v6`, `study-attempt.v4`, `study-report.v4`, and the
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
- On 2026-08-11 the user approved the exact v7 retry boundary: cumulative
  ceiling 307, retaining the 89 prior terminal identities and authorizing at
  most 218 new identities in one fresh root. The unchanged finite shape is two
  canaries + 108 initials + up to 108 policy-valid retries, `sonnet`, `$0.75`
  per process, `$163.50` arithmetic maximum, no optional stopping, no old-root
  replay, and immediate P1-X on integrity, privacy, ambiguity, or spend
  failure. npm remains candidate-only and active P2-P6 still require P1-F.
  Provider-free preflight confirmed current `main` differs from candidate
  source `5bf699bd...` only in these research documents and the exact native
  Claude CLI bytes remain unchanged.
- PR #296 merged the v7 authorization packet as `16a71ac...` after exact-head
  hosted CI passed. Candidate run `31406020654` then passed every release gate,
  paired smoke, three attestations, and two immutable artifact uploads. The
  candidate manifest SHA-256 is `a0906987...`; root tarball SHA-256 is
  `fce70526...`; Receipt tarball SHA-256 is `ec00b91d...`. No npm registry or
  dist-tag mutation occurred.
- Fresh v7 root `/private/tmp/contextguard-p1-live-v7.jd6MT4` passed both
  discarded host-mediated canaries. It terminally accounted 79 analytic
  identities before `ts12_08_refactor/bash_reference_v1/repetition-1` reached
  the frozen 12-turn limit. Claude emitted a well-formed nonzero
  `error_max_turns` terminal with complete usage and eight valid PreToolUse
  lifecycles, but attempt-v3 precedence classified every nonzero provider exit
  as infrastructure-invalid and zeroed its usage. The runner stopped all later
  launches; provider-free analysis wrote canonical claim-disabled P1-X
  `80387242...`, with zero ambiguous identities. This root is permanently
  closed and must never be resumed, repaired, migrated, or reinterpreted.
- V7 consumed 81 identities including canaries. Cumulative accounting is now
  170/307, leaving 137. A new maximum-size root requires a separately approved
  cumulative ceiling of at least 388 and a newly frozen finite plan; no further
  provider call is currently authorized.
- Provider-free TDD now versions the contract as `study-manifest.v6` and
  `study-attempt.v4`. Only exact nonzero `error_max_turns` terminals with all
  four usage buckets and valid hook lifecycles become retry-eligible task
  failures. Their provider
  `process_error` remains truthful, the checker is explicitly not run, measured
  usage remains in the estimator, and retry/later schedule execution continues.
  `error_max_budget_usd` is a spend stop, never a task failure: it becomes
  infrastructure-invalid, blocks the retry and every later launch, and
  persists canonical claim-disabled P1-X when its terminal ledger validates.
  Execution errors, malformed usage, success/nonzero contradictions, and hook
  failures likewise remain infrastructure-invalid. The frozen v7 artifact is recognized
  read-only as 453,278 primary tokens, but its v7 decision remains P1-X; only a
  fresh reviewed candidate and fresh root may exercise the new contract.
- The user approved the exact v8 retry boundary on 2026-08-11: cumulative
  ceiling 388, retaining the 170 prior terminal identities and authorizing at
  most 218 new identities in one fresh root. The frozen shape remains two
  canaries + 108 initials + up to 108 policy-valid retries, `sonnet`, `$0.75`
  per process, `$163.50` arithmetic maximum, no optional stopping, no old-root
  reuse, and immediate P1-X on integrity, privacy, ambiguity, or spend failure.
  PR #298 merge `d4b6302...` and candidate run `31457488674` verified the
  provider-free P2-P6 delivery, but the authorization amendment requires a new
  reviewed merge and exact candidate before live v8 `prepare`.
- PR #300 merged the v8 source/spend closure as
  `fb2e177f3efb15e817f54f5742beacdbe5daf96a`. Attested candidate run
  `31464306133`, root artifact `9091361857`, and Receipt artifact `9091361298`
  bind that exact source and passed every release gate, paired smoke, and all
  three attestations. The canonical candidate-manifest SHA-256 is
  `39b02e542c83ac4f15d7761d9cf1b2b61a37cfbcb6eafe6a3580949857b26ca4`;
  no npm publication or dist-tag mutation occurred.
- Fresh v8 root `/private/tmp/contextguard-p1-live-v8.rLM3P6/study` passed
  provider-free prepare and both discarded host-mediated canaries, then
  terminally accounted all 108 initials plus 13 policy-valid retries. The
  remaining 95 retry identities are canonically `not_needed`; there are no open
  or ambiguous identities. Provider-free analysis emitted canonical `P1-F` in
  report SHA-256
  `09eca0ff9953a7f45da2d373d568dff22e09abe19965bc58952d65822151a8a5`,
  with 121 analytic records and every unfavorable run retained.
- The primary host-unmodified minus `bash_reference_v1` descriptive token point
  estimate is 7,071.31 primary tokens, with task-cluster 95% interval
  [1,583.33, 13,736.99]. Exact task-cluster sign permutation passed the frozen
  binary non-inferiority test (`p=0.000488...`, point 0.0, margin 0.1). This is
  not a savings claim: power remains unmet; correction, retrieval, and shifted
  cost are explicitly unavailable; quality/failure/correction/retrieval/cost
  gates remain false; `claim_allowed=false` and `descriptive_only=true`.

The P1 dependency gate has passed. P2 now has one narrow, supported Claude
print-JSON measurement boundary; the existing general host request-assembly
observer remains unsupported. Closed-pack may enter a future P3 only after a
separate approval and authoritative fully loaded provider cost become
available. Realistic-fallback remains stopped at P2.

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

Implementation status: the packaged local evaluator computes per-stratum
recall, exact rehydration, freshness, construction cost, and protected-zone
violations from a closed P2 record. The separately approved
`research/provider-live-roadmap/p2/v1` runner completed the exact 240-call
Claude print-JSON shadow on 2026-08-13 without mutating live requests.

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

Result: closed-pack passed implementation readiness but received no activation
authority. Realistic-fallback failed readiness on `protected_omission` and
remains diagnostic. The run completed 237 provider calls successfully; three
transport exclusions removed three whole four-arm blocks from paired analysis.
The recorded USD 0.894320 CLI cost is explicitly non-authoritative. Post-run
review found that the executed observer omitted helper/cache model-usage fields,
so provider token metrics are unavailable and no savings claim is permitted.

A corrected Max-session usage attempt repeated the fixed 240-call schedule, but
only 11 calls completed; 228 were transport exclusions and one timed out. No
complete four-arm block remained. The successful calls reported 61,547 total
tokens, but this sparse diagnostic total cannot estimate arm-to-arm savings.
The attempt is hash-bound in `usage-attempt-result.json`; a fresh complete
fixed-schedule run is still required before P3 consideration.

One-use follow-up probes identified an observer defect rather than a confirmed
transport outage: a dated first-party Haiku helper key was rejected because its
canonical model omits the date suffix. The parser now accepts only that bounded
date-suffix form, retains the exact primary-model requirement, and passed a live
two-model usage probe. The invalid attempt remains excluded; it is not repaired
or reinterpreted after the fact.

The corrected observer subsequently completed a new fixed 240-call Max run:
234 calls succeeded and 55 complete four-arm blocks were analyzed. On 30
closed-pack blocks, combined used 7.096850% fewer total tokens than ordinary
(182,603 versus 196,552) with both arms correct on 30/30. Adaptive-only used
6.677622% fewer with the same correctness. On 25 complete realistic-fallback
blocks, combined used 0.637534% more tokens but improved exact correctness from
0/25 to 10/25; adaptive-only used 7.099103% fewer but stayed 0/25 correct.
These are descriptive frozen-corpus measurements, not generalized savings or
activation evidence. P3 remains blocked on authoritative fully loaded provider
cost and a separate exact P3 approval.

A separate Codex subscription replication completed the same frozen 240-unit
schedule with Codex CLI `0.146.0` and `gpt-5.6-luna` at low reasoning effort.
It produced 226 complete receipts and 14 closed-schema exclusions, leaving 50
complete four-arm blocks and 200 analyzed units. On all 30 closed-pack blocks,
combined used 5,741 fewer tokens than ordinary (2.755010%) with both correct on
29/30 units. On 20 analyzable realistic-fallback blocks, combined used 223,363
fewer tokens (55.605123%) and was correct on 9/20 versus ordinary's 0/20.
These are descriptive provider-specific results. Cached input and reasoning
output remain subset counters and were not double-counted. The ChatGPT route
provides no authoritative dollar receipt or stable subscription-quota
conversion, so it does not support a cost- or quota-savings claim.

## P3 — bounded progressive-disclosure canary

Implementation status: the packaged evaluator verifies exact matched pairs,
retrievals, failure/correction guardrails, and fully loaded provider-cost fields.
It still evaluates imported measurements only and launches no canary or
provider call. A separate one-use `research/provider-live-roadmap/p3-api/v1`
runner completed the approved direct Anthropic API measurement without granting
the packaged evaluator or production path any provider authority.

The final 2026-08-17 run completed all 240 fixed-schedule calls with exact
`claude-sonnet-5` usage receipts and zero cache tokens. On closed-pack, combined
used 36.590437% fewer total tokens than ordinary with both correct on 30/30. On
realistic fallback, combined used 5.789384% more total tokens and was correct on
1/30 versus ordinary's 0/30. Across both strata, combined used 13.317087% fewer
total tokens, but its published-list-price estimate was 1.105507% higher because
output usage increased 41.556257%. The standard API key had no Admin Usage &
Cost access, so the USD 0.580690 calculation is not an authoritative billing
receipt or fully loaded shifted cost. No P3 savings or activation claim is
permitted; `p3-api/v1/result.json` binds the minimized private evidence.

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

Implementation status: the packaged evaluator now compares advisory,
always-pass-through, and always-on outcomes with separate cache creation, read,
invalidation, latency, and provider-cost accounting. Its route is advisory only.
The same deterministic byte-benefit policy is now exercised by the explicit
`receipt_context` MCP path. `context-guard-pack auto --apply-symbol-memory`
additionally applies up to four safe direct import-neighbor slices within the
existing pack byte budget, while preserving higher-priority explicit/query
seeds, excluding secret-risk neighbors, and retaining exact fallback.
`auto --apply-adaptive-k` separately prunes only heuristic-selected sources to
the local recommendation after its regression gates pass, always retaining
caller-declared file/output/test-output and diff evidence. All applied paths are
explicit and default-off; no host-wide route is enabled and local proxies do
not establish provider-token savings.

The 2026-08-12 [live synthetic smoke](progressive-context-benchmark-2026-08-12.md)
ran 12 generated instances from two templates, three repetitions per arm, and
72 accepted provider calls. Both arms passed 36/36 external checkers. The
combined adaptive-k plus symbol-memory treatment reduced generated pack bytes
85.72%, but primary-token inference was inconclusive: treatment minus baseline
was -197.83 tokens at the paired point estimate with a 95% task-cluster interval
of [-9,693.42, 9,375.02]. Corrections and fully loaded shifted-cost inference
remain unavailable. This evidence does not promote P4, authorize automation, or
support a savings/parity claim.

Build the router first as shadow/advisory metadata over the three deterministic
routes. It must expose confidence and bypass reasons and retain abstentions and
failures in its regret report.

Exit requires the router to match or beat the better always-pass-through or
always-on policy under the same quality/total-cost rule. Prefix-layout/cache
experiments must separately account for cache creation, reads, invalidation,
latency, and provider cost. Negative regret disables automation for that
stratum.

## P5 — repeated-context and repair-loop adjuncts

Implementation status: execution-twin, failure-cone, and typed-blueprint
evidence receive independent freshness, differentiation, fallback, quality,
and cost decisions. The explicit MCP path can now append/inspect the advisory
twin and can assemble caller-selected evidence packs and blueprints, but it
does not execute an action or rewrite a transcript.

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

Implementation status: the five named tracks have independent closed evaluation
records for scope, workload, baseline, privacy, quality, failure/correction
guardrails, complete cost model, fallback, rollback, provider evidence, and
authority. The explicit MCP path locally exercises task-scoped capability GC,
content-free counterfactual history, shadow negative-context firewall advice,
scout/surgeon prefix advice, and advisory execution-twin evidence. These are
manual, provider-free components—not promoted tracks—and no result may
generalize beyond its frozen scope.

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

Provider-free G1-G6 implementation and the explicit local MCP bridge are merged
through PR #302. P1-F is complete and the 2026-08-13 narrow P2 shadow is now
recorded. Closed-pack passed P2 implementation readiness; realistic-fallback
did not. Runtime activation and claim authority remain false, exact fallback is
unchanged, P3 is blocked on authoritative fully loaded provider cost and a
separate phase approval, and P4-P6 are dependency-blocked. npm `next`/`latest`
remain unauthorized and untouched.

1. Preserve the P1-F and P2 private evidence identities; never reinterpret
   unavailable provider token/cost fields or false gates as zero/pass.
2. Keep realistic-fallback diagnostic until every protected omission is removed
   or explicitly proven eligible without weakening the protected-zone policy.
3. Before a closed-pack P3 canary, obtain authoritative fully loaded provider
   billing evidence and a new P3-specific privacy/call/spend approval.
4. Keep the completed Codex subscription replication provider-specific and
   descriptive; do not reinterpret it as dollar, quota, or cross-provider
   evidence.
5. Keep P4-P6 evaluation-only while P3 is blocked. A failed dependency gate
   stops later provider phases and preserves the exact prior route.
6. Treat candidate, npm `next`, npm `latest`, and cleanup as separate authority
   tiers; none is implied by the P2 result.

The prepared-unapproved packet records prerequisites only; it does not create,
record, or expand external authority. A separate approval system must bind the
exact source revision and a newly constructed immutable candidate before any
authorized external run. The pre-merge development source and every older
candidate remain historical evidence and must never be reused as the PR #302
candidate.

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
