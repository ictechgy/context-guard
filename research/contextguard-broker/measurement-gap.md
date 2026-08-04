# ContextGuard Broker measurement source map

## Stage 1/P0 scope

This document freezes definitions and source ownership without changing runtime
hooks, installed settings, packages, setup, CSV columns, or R9. A field is
either supplied by an existing authority, added later as a privacy-safe
subordinate observation, or marked unavailable and claim-blocking. No missing
field may be imputed from source-file size, intended pack size, hook JSON size,
or a successful-only subset. `transport_rejected` stops Stages 3–5 while leaving
Stage 2 pass-through attribution eligible; R9 is immutable, inconclusive, and
not efficacy input.

## EPR: Evidence Payload Reduction

EPR is mechanism-only. For every Read, measure the exact UTF-8 byte length of
the host-provided result content visible to the model and exposed by Read
`PostToolUse`, after host framing and before receipt redaction. This includes
line numbering, provenance headers, errors, expansions, retries, and unchanged
bypass Reads. Persist only a domain-separated content SHA-256 and byte length.
For each assigned task and arm, sum every Read observation, then calculate
treatment total minus baseline total before aggregation. A receipt-backed zero
means zero observed bytes; absence is unavailable and claim-blocking rather than
zero. The required `tool_use_id`, framed byte length, and content hash are new
subordinate observations; a missing, truncated, or host-unobservable result is
`unavailable_claim_blocking`. Existing attempt/session identity and timing live
in `benchmark_runner.py`; they do not prove model-visible Read bytes.

## FLC-QGS: Fully Loaded Cost per Quality-Gated Success

FLC-QGS is the truth metric. Its numerator is the disjoint sum `A+B+C`: A is all
provider charges for every assigned attempt, including provider turns caused by
expansion, retry, correction, and consumed failure; B is paid-helper charges not
in A; C is index/build/maintenance and other non-provider charges not in A or B.
Each cost event is assigned exactly once. Expansion/retry/correction/failure is
an inclusion-status field proving coverage, not an extra cost bucket. Existing
provider provenance and attempt state supply A; subordinate cost components
supply B and C and carry provenance. Receipt-backed zero cost is observed;
missing cost is unavailable and claim-blocking.

The denominator is quality-gated successes among every assigned task. At P0,
`flc_qgs.quality_gated_success` is `unavailable_claim_blocking` until a future
quality gate is frozen; existing checker success does not fill that field.
Always report success probability and treatment-minus-baseline failure-rate
difference after the gate exists. Zero or predeclared-insufficient successes
blocks the claim; no successful-subset denominator is allowed.

## PAT-PCD: Paired Assigned-Task Cost Difference

PAT-PCD is the mandatory co-primary economic endpoint. `pair_id`, arm
assignment, assigned-task provider cost, retry/correction/failure status, and
quality outcome are existing or extended attempt authority. Activation and
bypass status, exact Read observation linkage, and any helper/index allocation
are subordinate observations. Every assigned pair remains in analysis:
failures, retries, bypasses, unactivated treatment assignments, and consumed
attempts are all retained. The paired sign is treatment assigned-task A+B+C
minus baseline assigned-task A+B+C, so a negative observed value favors
treatment. Observed equal complete costs produce zero; missing arm or cost data
is unavailable and claim-blocking. Absent pair linkage, cost provenance,
activation state, or quality evidence is likewise unavailable and
claim-blocking.

## Claim-completeness rule

`measurement-source-map.json` enumerates each machine-readable field with one
of `existing_authority`, `new_subordinate_observation`, or
`unavailable_claim_blocking`. An absent field in the last class makes the
associated endpoint claim-incomplete. Every row names its concrete schema,
existing, derived, or unavailable contract field; distinguishes an observed or
not-applicable zero from missing data; and fixes missing data as claim-blocking.
The activation, completeness, correction, failure, latency, privacy,
provenance, and quality gates are explicit source-map fields. Receipt bundles
carry their supporting observations, while the later claim-completeness result
evaluates them after the bundle hash exists. EPR, FLC-QGS, and PAT-PCD retain
independent status and blocker sets: one unavailable endpoint does not erase a
complete or blocked endpoint. The overall result is `claim_blocked` if any
endpoint or gate is blocked while preserving every unrelated unavailable
status; otherwise it is `incomplete` if any status is unavailable, and `complete`
with `claim_allowed=true` only when every endpoint is complete and every
activation, correction, failure, latency, privacy, provenance, and quality
gate passes. Endpoint definitions are frozen here, but
numeric paid-study effect, precision, spend, and promotion thresholds are not:
they belong only in the later active-canary decision record.
