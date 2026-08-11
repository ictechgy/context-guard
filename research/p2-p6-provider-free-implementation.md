# P2-P6 provider-free implementation boundary

_Status date: 2026-08-11 KST_

This document maps the stronger token-saving mechanisms that already exist to
the P2-P6 roadmap and defines the remaining local implementation work. It does
not activate a host route, authorize provider calls, or support a savings
claim. Until the phase gates pass, every surface remains explicit, default-off,
shadow-only, advisory, or evaluation-only.

## Shipped mechanism inventory

The inventory below is source- and test-backed. A mechanism can be implemented
without being activated, provider-measured, or eligible for a claim.

| Mechanism | Phase use | Shipped source | Focused evidence | Frozen boundary |
| --- | --- | --- | --- | --- |
| Exact assembly and protected fallback | P2 candidate construction; P5 blueprint assembly | `packages/context-guard-receipt/python/context_guard_receipt/assembly.py` | `packages/context-guard-receipt/tests/contract/test_g005_assembly.py`, `test_g005_evidence_pack.py` | Caller supplies local bytes and an explicit root. Non-beneficial, protected, ambiguous, or unavailable issuance preserves exact input or refuses; it never changes a host request. |
| Exact capability expansion | P2/P3 rehydration; P5 whole/item fallback | `packages/context-guard-receipt/python/context_guard_receipt/expansion.py` | `packages/context-guard-receipt/tests/contract/test_g005_expansion.py`, `test_g008_expansion.py` | Capability-only, source-bound, selection-bound exact local recovery. Missing, invalid, or stale evidence closes rather than guessing. |
| Diagnostics and diagnostic ledger | P2 duplicate/staleness observation; P4 prefix/cache evaluation | `packages/context-guard-receipt/python/context_guard_receipt/diagnostics.py`, `diagnostic_ledger.py` | `packages/context-guard-receipt/tests/contract/test_g009_diagnostics.py`, `test_g009_ledger.py` | Keyed fingerprints and advisory metadata only. Diagnostics do not contain source content and do not apply a route. Durable state requires its explicit opt-in tuple. |
| Deterministic router and shadow firewall | P4 regret evaluation | `packages/context-guard-receipt/python/context_guard_receipt/router.py`, `assembly.py` | `packages/context-guard-receipt/tests/contract/test_g005_router.py`, `test_g005_assembly.py` | Byte-cost decision and shadow report only. The caller retains pass-through authority; no automatic routing or provider-cache conclusion follows. |
| Bounded runner and merged capture | P3 narrow disclosure evaluation; P5 repair-loop evidence | `packages/context-guard-receipt/python/context_guard_receipt/runner.py`, `merged_capture.py` | `packages/context-guard-receipt/tests/contract/test_g008_runner.py`, `test_g014_merged_capture.py` | Explicit local command or completed-capture input only, with sanitized bounded output and exact escrow expansion. It neither observes nor rewrites a provider request. |
| Typed blueprint | P5 edit-adjunct evaluation | `packages/context-guard-receipt/python/context_guard_receipt/blueprint.py`, `assembly.py` | `packages/context-guard-receipt/tests/contract/test_g005_assembly.py`, `test_g005_expansion.py` | Descriptor and local source evidence only. It emits a typed advisory artifact with exact whole/item fallback, never autonomous edit authority. |
| Execution twin | P5 repeated-context/revision evaluation; P6 specialized track | `packages/context-guard-receipt/python/context_guard_receipt/execution_twin.py` | `packages/context-guard-receipt/tests/contract/test_g010_twin.py`, `test_g010_cli.py` | Explicit `--experimental-twin` and isolated local state are required. Results are append-only comparison evidence, not replay, transcript mutation, or route authority. |
| Reference expiry | P3 stale-reference guard; P6 specialized track | `packages/context-guard-receipt/python/context_guard_receipt/reference_expiry.py` | `packages/context-guard-receipt/tests/contract/test_g011_reference_expiry.py`, `test_g011_cli.py` | Explicit `--experimental-reference-expiry` administration only. It changes capability eligibility, not source/store contents, and ordinary paths do not create expiry state. |
| Root-scoped MCP | P2/P3 explicit local retrieval; P6 specialized track | `packages/context-guard-receipt/python/context_guard_receipt/mcp.py` | `packages/context-guard-receipt/tests/contract/test_g012_mcp.py`, `test_g012_mcp_cli.py`, `packages/context-guard-receipt/tests/e2e/test_g012_mcp_stdio.py`, adversarial `test_g012_mcp_capabilities.py` and `test_g012_mcp_limits.py` | Ephemeral stdio server for one explicit absolute root. It installs no server/settings/hooks, creates no durable state, and exposes no runner, twin, expiry administration, credentials, or network. |
| Default-off experiments | P4 advisory cache work; P6 independent specialized tracks | `context-guard-kit/experimental_registry.py`, `benchmark_runner.py`, `cost_guard.py` | `tests/test_context_guard_kit.py` (registry, proof-carrying context, static relevance, semantic GC, learned/visual/local-proxy surfaces), `tests/test_context_guard_kit_benchmark_surfaces.py` | Registry enablement records local intent only. Plan/evaluation surfaces grant no runtime activation; explicit local emit/record surfaces remain separately gated. Provider-backed promotion and hosted savings claims remain unavailable. |

Phase mapping is therefore additive, not a maturity claim:

| Phase | Reused shipped mechanisms | Implementation readiness | Activation/evidence boundary |
| --- | --- | --- | --- |
| P2 shadow broker | assembly, expansion, evidence packs, protection, diagnostics, MCP | Local candidate construction, exact recovery, and diagnostic primitives exist. | No supported host observer is established; no live request mutation is authorized. P2 remains shadow/diagnostic and P1-F remains an unmet dependency. |
| P3 bounded disclosure | default-off `bash_reference_v1`, runner, merged capture, expansion, reference expiry, matched-study substrate | The narrow Bash reference route and local evaluation substrate exist. | Only explicit opt-in narrow output handling is implemented. No broader canary activation or provider/cost promotion evidence exists. |
| P4 router/cache | deterministic router, shadow firewall, diagnostics/ledger, cache score, cost guard, benchmark metadata | Local advisory decisions and separate accounting fields exist. | Automation stays off. Provider cache creation/read/invalidation economics and regret gates are not closed. |
| P5 adjuncts | execution twin, runner capture, typed blueprint, exact expansion | Local independent adjunct artifacts exist. | Each is explicit and advisory; no transcript rewrite, replay, autonomous edit, or coupled activation is authorized. |
| P6 specialized tracks | expiry, MCP, ledger, twin, proof-carrying-context verifier, semantic-GC/static-relevance/image-context plan gates | Bounded local components and evaluation surfaces exist per track. | No track inherits readiness from another. Every track remains default-off, plan/evaluation-only, or explicitly local until its own closed evidence and authority gates pass. |

## Implemented frozen evaluation contract

The closed evaluator is a pure, provider-free decision over
caller-supplied bounded local records. It must not read credentials, settings,
hooks, provider state, npm state, or the network; execute a provider; mutate a
request; activate a route; or emit a token, cost, percentage, or savings claim.

For each phase, and for each P5 adjunct or P6 track independently, its result
must keep these four dimensions separate:

1. `implementation_readiness`: whether the named local mechanisms and required
   fallback/rollback surfaces are present and locally verified.
2. `activation_authority`: whether every dependency gate and a separate,
   explicit phase/track activation authorization are present.
3. `provider_evidence`: whether the frozen provider-measured matched population
   and fully loaded accounting required by the roadmap are complete. Local or
   imported synthetic evidence cannot satisfy this dimension.
4. `claim_authority`: whether the claim-specific evidence and scope gates pass.
   This is false whenever provider evidence, shifted-cost accounting, quality,
   failure/correction guardrails, provenance, or scope binding is incomplete.

The result is closed and deny-by-default:

- unknown fields, duplicate phase/track IDs, missing required evidence,
  ambiguous evidence, or inconsistent authority must produce a blocked result;
- `implementation_readiness=true` must never imply activation, provider
  evidence, or claim authority;
- a blocked or unavailable result must select the exact unchanged baseline or
  the independently verified exact local fallback—never a partial substitute;
- failure in one P5 adjunct or P6 track disables only that unit and cannot
  promote, demote, or generalize another unit;
- activation requires the canonical roadmap dependency chain through that
  phase plus separately recorded authority; this inventory supplies neither;
- evaluator output is advisory evidence only and cannot change runtime state.

At this freeze, the only permissible repository-wide evaluation conclusion is:

| Dimension | Frozen value |
| --- | --- |
| Implementation readiness | Per-mechanism and per-track; the inventory above establishes only the shipped local surfaces. |
| Activation authority | `false` for P2-P6 promotion. |
| Provider evidence | `incomplete`; P1-F and later phase-specific provider gates are not passed. |
| Claim authority | `false`; no savings claim is supported. |
| Fallback | Exact unchanged baseline, or the mechanism's independently verified exact local expansion when explicitly invoked. |

## Provider-free implementation delivered

`context-guard-kit/phase_evaluation.py` is the canonical evaluator and the
Receipt package ships an exact byte-identical copy. The installed entry point is
`context-guard-receipt evaluate phase --input <file|->`; it accepts at most 2
MiB of duplicate-key-rejecting canonical JSON and emits canonical JSON. Closed,
recursively constrained input schemas for P2-P6 and a phase-specific result
schema ship with the package.

The evaluator covers:

1. P2 recall, exact rehydration, freshness, protected-zone, and construction-cost checks.
2. P3 matched failure/correction/retrieval and fully loaded cost guardrails.
3. P4 regret against always-pass-through and always-on plus separate cache accounting.
4. P5 revision freshness, source/test revalidation, failure differentiation, blueprint obligations, and independent bypass.
5. P6 independent workload, privacy, quality, cost, fallback, rollback, provider evidence, and non-generalization gates for every specialized track.

The evaluator consumes only bounded canonical local records, changes no
runtime route, and emits no provider token, cost, percentage, or savings claim
of its own. Missing authority or provider measurements block activation without
blocking safe pass-through behavior. `tests/test_phase_evaluation.py` verifies
each phase's deny-by-default behavior and independent fallback;
`test_g015_phase_evaluation_cli.py` verifies installed CLI delivery, canonical
copy parity, ambiguous-input refusal, and recursively closed schemas. This
implementation grants no P2-P6 activation, provider-call, or claim authority.
