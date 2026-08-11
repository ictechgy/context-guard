# Comparator mechanism acceptance matrix

_Status date: 2026-08-12 KST_

This matrix answers whether ContextGuard has absorbed the useful mechanisms
associated with Graphify, Caveman, and Ponytail. It does not claim feature or
numeric parity. Comparator headline semantics are carried forward from the
project's 2026-08-04 local research and were not revalidated over the network in
this implementation batch.

## Denominator boundary

- Graphify's cited headline compared a large estimated repository corpus with a
  much smaller graph subquery; it was not a measured whole-agent bill.
- Caveman's cited headline concerned prose/output reduction; agentic reductions
  were smaller in the prior local research.
- Ponytail's cited headline mixed code LOC and workload-specific agent tokens or
  cost. It was not interchangeable with the other two denominators.
- ContextGuard therefore accepts a mechanism only on observable behavior and
  exact fallback. Numeric parity requires a later matched, quality-gated,
  fully-loaded provider study.

## Matrix

| Comparator-derived advantage | ContextGuard mechanism | Current acceptance | Evidence / command | Remaining gap |
| --- | --- | --- | --- | --- |
| Graph/symbol subquery instead of whole-repository context | Deterministic repo map, import edges, graph rank, symbol memory, exact slices | **Applied locally, explicit; live smoke inconclusive** | `context-guard-pack auto ... --apply-symbol-memory` adds at most four direct import-neighbor slices and rebuilds inside the same byte budget; the 2026-08-12 combined-workflow smoke preserved its six graph dependencies | No standalone graph ablation, persistent semantic index, LSP/tree-sitter dependency, whole-host automatic selection, or provider-measured savings result |
| Avoid unrelated graph expansion | Seed-priority preservation, direct-neighbor-only traversal, four-source cap, secret-risk exclusion | **Accepted** | `tests/test_context_guard_kit.py` graph-application tests | Broader multi-hop expansion needs an independent recall/quality gate |
| Adaptive context breadth instead of fixed top-k | Score-elbow/budget recommendation plus explicit gated application | **Applied locally, explicit; live smoke inconclusive** | `context-guard-pack auto ... --apply-adaptive-k` prunes heuristic sources only after local regression gates pass and retains caller-declared sources; the 2026-08-12 combined smoke omitted 36 heuristic sources in its adaptive family | No standalone adaptive ablation, hidden-oracle recall workload, or provider-measured savings result |
| Shorter prose and noisy output | Conservative compressor, structured command digest, duplicate-log folding, Bash reference receipt | **Implemented, explicit/default-off** | `context-guard-compress`, `context-guard-trim-output --digest ... --artifact-receipt` | No universal interception of assistant prose and no claim that shorter output preserves quality on every task |
| Concise coding output / smaller patches | Brief-mode rules, typed edit blueprint, symbol/line retrieval, protected-zone structural transforms | **Partial** | `context-guard setup ... --brief-mode ...`; Receipt blueprint assembly | Guidance is not an enforced minimal-diff compiler; code LOC and correction burden are not yet provider-measured |
| Reuse stable context instead of replaying it | Process-local context capabilities, task scopes, cache reuse, progressive slices, execution twin | **Implemented locally** | Receipt MCP `receipt_context`, `receipt_twin` | Capability bytes do not persist across MCP restart; durable host-wide request memory is unsupported |
| Retrieve detail only when necessary | Exact expansion handles, slice/symbol commands, scout/surgeon advice | **Implemented locally** | Receipt MCP plus context-pack retrieval hints | No supported automatic host request observer or helper-model cost evidence |
| Remove negative or duplicated context | Do-nothing router, sketch duplicate veto, shadow firewall, HMAC decision history | **Implemented as opt-in/shadow** | `--sketch-duplicate-veto`, `receipt_diagnose`, `receipt_context history` | Active host-wide omission remains blocked until critical-evidence recall is measured |
| Safe recovery when compression is wrong | Exact source receipts, unchanged fallback, capability expansion, baseline bypass | **Accepted** | Pack receipts, Receipt expansion, protected-zone tests | Recovery cost still has to be charged in a matched provider study |

## Product-level verdict

ContextGuard now absorbs the major *mechanism classes*: graph-bounded selection,
explicit gated adaptive breadth,
conservative output compaction, progressive disclosure, task-scoped reuse,
negative-context diagnostics, and exact recovery. It does not yet match the
competitors' automatic experience because no supported API exposes the whole
host request assembly boundary. The honest status is therefore
`mechanisms_implemented_explicitly`, not `automatic_parity` or
`measured_savings_parity`.

The [2026-08-12 live synthetic smoke](progressive-context-benchmark-2026-08-12.md)
completed with all 72 fixture checkers passing and generated pack bytes fell
85.72%. It did not demonstrate
provider token savings. The paired 95% interval crossed zero, corrections and
fully loaded shifted cost were incomplete, and the two-arm design could not
attribute either mechanism independently. The product-level verdict is
unchanged.

## Next acceptance gates

1. Replace the completed but inconclusive combined-workflow smoke with a
   four-arm ordinary/adaptive-only/symbol-only/combined ablation over independent
   task structures. Measure hidden-oracle critical-source recall, retrievals,
   failures, corrections, provider usage, index/build time, and fully loaded
   shifted cost.
2. Add persistent context only behind an authenticated revision/worktree-bound
   store with expiry, quota, invalidation, and exact-recovery tests.
3. Activate automatic selection only if a supported host observer exists and
   the phase-specific privacy, provider-call, spend, and rollback gates pass.
