# ContextGuard Broker action and claim policy

## Stage 1/P0 rule

This is a provider-free policy contract. It introduces no runtime mutation,
settings change, Read redirection, packaging change, CSV change, or R9 change.
The resolver emits exactly one action and the full set of applicable
claim-blocking reason codes. A higher-precedence action never deletes a lower
precedence blocker. `transport_rejected` keeps Stage 2 pass-through attribution
possible and stops Stages 3–5; R9 remains immutable, inconclusive, and cannot
support efficacy.

## Precedence and phase table

| Priority | Category and examples | Pre-activation action | Post-activation action | Claim result |
| --- | --- | --- | --- | --- |
| 1 | Integrity/security: protected path or secret match, unsafe root, permission ambiguity, symlink/root escape, pack hash mismatch, protected classifier unavailable after activation | `BLOCK_TOOL` | `BLOCK_TOOL` | retain every blocker |
| 2 | Recoverable freshness: source/index/dirty-state/candidate-universe/authorization mismatch with exact safe reread possible | first occurrence: `REREAD_THEN_DECIDE`; recurrence: `PASS_THROUGH_UNCHANGED` | first occurrence: `REREAD_THEN_DECIDE`; recurrence: `BLOCK_TOOL` | retain every blocker |
| 3 | Eligibility/availability before activation: no descriptor, ineligible stratum, unsupported host, stale authorization, protected classifier unavailable before activation, materialization/budget failure, empty selection, ordinary index unavailable | `PASS_THROUGH_UNCHANGED` | unreachable | retain every blocker |
| 4 | Evidence after a baseline-safe execution: missing/truncated Read observation, missing provider join, cost/quality gap, hook failure, reset mismatch, cross-arm leakage, receipt durability uncertainty | unreachable | `CLAIM_BLOCK_ONLY` | retain every blocker |

The resolver rejects a reason that is unreachable in the asserted phase. This
makes the table exhaustive over the reachable Cartesian combinations: any
integrity reason wins; otherwise freshness wins while the single reread remains;
otherwise pre-activation eligibility passes through; otherwise post-execution
evidence defects block claims only. The machine policy fixes `reread_limit` to
one. A reread re-enumerates or rereads exactly once and then re-enters this same
resolver; it cannot loop.

The decision-receipt schema admits only the frozen machine-policy catalog and
mirrors this precedence with phase-specific branches. In particular, a receipt
cannot pair an integrity/security blocker with pass-through, use an unknown
uppercase reason, or omit a higher-precedence category while claiming the
lower-precedence action.

`DESCRIPTOR_MISSING` is represented without invented provenance:
`descriptor_id` and `selection_snapshot_id` are both `null`. Every other
decision references a real descriptor, and every post-activation decision also
references the selection snapshot that was active.

Protected-classifier availability is phase-sensitive by design. Before
activation, no protected material has been substituted, so an unavailable
classifier is an eligibility failure and returns `PASS_THROUGH_UNCHANGED`.
After activation begins, the same condition is an integrity/security failure
and returns `BLOCK_TOOL`; it is never downgraded to a claim-only defect.

## Decision algorithm

1. Collect all observed reason codes without filtering for the selected action.
2. If any integrity/security reason exists, return `BLOCK_TOOL`.
3. Else if a recoverable-freshness reason exists and no reread was consumed,
   return `REREAD_THEN_DECIDE`; if it recurs, return pass-through before
   activation or block after activation.
4. Else if the phase is pre-activation and an eligibility/availability reason
   exists, return `PASS_THROUGH_UNCHANGED`.
5. Else return `CLAIM_BLOCK_ONLY` for post-execution evidence defects.

For example, pack-hash mismatch plus a missing provider join returns
`BLOCK_TOOL` and preserves both blocker codes. Security uncertainty never
permits active substitution. A baseline-safe, already-completed tool execution
with missing attribution is not retrospectively blocked, but is ineligible for
the corresponding effectiveness claim.
