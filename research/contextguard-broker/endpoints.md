# ContextGuard Broker endpoint definitions

## P0 freeze and scope

Stage 1 freezes names, units, accounting populations, and claim-blocking rules.
It does not set numeric paid-study thresholds and does not modify runtime hooks,
installed settings, packages, setup, CSV columns, or R9. The artifact-root
`transport_rejected` outcome halts Stages 3–5; Stage 2 can still establish
pass-through attribution. R9 is permanently immutable and inconclusive, so it
is not an endpoint baseline, prior, authorization, or efficacy input.

## Canonical bytes and hash domains

Broker JSON fixtures and future receipts use UTF-8 JSON with keys sorted,
compact separators, ASCII escaping, finite numbers only, and exactly one final
LF. Duplicate keys, non-finite numbers, CR bytes, alternate key order, or extra
whitespace are invalid. Every manifest below is canonically sorted by its
declared stable keys before canonical JSON encoding; input discovery order is
never part of its identity.

The exact domain/preimage contracts are:

| Identity | SHA-256 preimage |
| --- | --- |
| Model-visible Read result | `"contextguard-broker/epr-read-result/v1" || 0x00 || result_bytes`, using the exact host-framed UTF-8 bytes |
| Candidate universe | `"contextguard-broker/candidate-universe/v1" || 0x00 || canonical_json(candidate_manifest)`, with every enumerated entry sorted by evidence class, normalized repository-relative path, and stable entry ID |
| Dirty state | `"contextguard-broker/dirty-state/v1" || 0x00 || canonical_json(dirty_manifest)`, with tracked and untracked entries sorted by normalized repository-relative path and binding status, mode, and content identity |
| Diff | `"contextguard-broker/diff/v1" || 0x00 || canonical_json(diff_manifest)`, binding diff basis, base revision, head-or-dirty identity, and changed entries sorted by normalized repository-relative path |
| Index contents | `"contextguard-broker/index-contents/v1" || 0x00 || canonical_json(index_manifest)`, binding index schema/build revision/policy and entries sorted by normalized repository-relative path and stable entry ID |
| Delivered pack | `"contextguard-broker/pack-content/v1" || 0x00 || pack_bytes`, using the exact immutable delivered pack bytes |
| Expansions | `"contextguard-broker/expansion-identity/v1" || 0x00 || canonical_json(expansions)`, where entries are sorted by normalized repository-relative source path, start byte, nonzero byte length, and expansion ID |

`canonical_json` includes the one final LF. A hash field naming its containing
artifact is calculated over the canonical object with only that hash field
omitted, prefixed by `contextguard-broker/<schema-version>/<hash-field>` and a
NUL byte. A bundle `receipt_sha256` instead hashes the complete stored canonical
receipt bytes. These domains prevent equal raw bytes in unrelated artifact
classes from sharing an identity.

Each expansion is bounded by the descriptor's maximum expansion count and by
an explicit per-entry normalized source path, immutable source total length,
start byte, and nonzero byte length; the exact half-open range is
`[start, start + length)`. Entries use canonical path/start/length/ID order and
cannot overlap for one source path; source ID and normalized path map
one-to-one within the snapshot. An `immutable` entry requires delivered
length and hash to equal the exact source range; unequal observed bytes resolve
to `verification_failed`/`PACK_HASH_MISMATCH`, not another immutable identity.
Raw payloads are never retained. Overlap, out-of-range offsets, excess entries,
or an observed-vs-declared identity mismatch is claim-blocking and follows the
action policy.

## EPR — Evidence Payload Reduction

EPR is a mechanism diagnostic, not a whole-task savings claim. For each Read,
record the exact UTF-8 length of host-framed result content made model-visible
and exposed to Read `PostToolUse`, before receipt redaction. Count line
numbering, host framing, provenance headers, errors, expansions, retries, and
unchanged bypass Reads. Store a domain-separated content hash and byte length,
not raw content. Within each assigned task and arm, sum the observed byte lengths
of every Read, including expansions, retries, errors, and bypasses; then compute
the paired value as treatment total minus baseline total before aggregation. A
numeric zero is a real observation only when a complete receipt proves no bytes
were delivered. A missing observation is unavailable and claim-blocking, never
zero. A missing `tool_use_id`, Read observation, untruncated
framed result, or provider/attempt join makes EPR unavailable and blocks its
claim. Source bytes, pack-file bytes, intended budget, and hook payload bytes
are not substitutes.

## FLC-QGS — Fully Loaded Cost per Quality-Gated Success

FLC-QGS is the named truth metric:

```text
A = all provider charges for every assigned attempt, including provider turns
    caused by expansion, retry, correction, and consumed failure
B = paid-helper charges not already included in A
C = index, build, maintenance, and other non-provider charges not in A or B
FLC-QGS = (A + B + C) / quality-gated successes among every assigned task
```

The three sets are disjoint and each billable event is assigned exactly once.
Expansion, retry, correction, and failure are inclusion statuses, not a fourth
cost bucket added on top of A, B, or C. The denominator never drops assigned
failures. At P0, quality-gated success is unavailable and claim-blocking until a
future quality gate is frozen; existing checker success alone is not a frozen
quality gate. Once frozen, report success probability and the
treatment-minus-baseline failure-rate difference. An observed zero charge is
valid only with provenance; a missing charge is unavailable and claim-blocking.
Zero or predeclared-insufficient quality-gated successes blocks FLC-QGS.

## PAT-PCD — Paired Assigned-Task Cost Difference

PAT-PCD is the co-primary economic endpoint. Retain each assigned pair,
including failures, retries, bypasses, unactivated treatment assignments, and
consumed attempts. Its sign is frozen as treatment assigned-task total cost
minus baseline assigned-task total cost, using the same disjoint A+B+C
allocation and counting every cost event exactly once. Thus a negative value
favors treatment. A numeric zero means equal observed complete costs; it cannot
stand in for a missing arm or missing cost. Missing pair identity, arm
assignment, cost provenance, activation/bypass status, or quality evidence is
unavailable and claim-blocking rather than an exclusion.

Any later promotion requires a pre-frozen FLC-QGS rule and an improved PAT-PCD
or a pre-frozen non-inferiority rule, plus quality, failure, correction, latency,
privacy, provenance, completeness, and activation gates. Paid-study sample,
effect, precision, latency, spend, and promotion numbers are intentionally
deferred to the Stage 5 active-canary decision record.

The claim-completeness result preserves separate EPR, FLC-QGS, and PAT-PCD
statuses and separate promotion-gate statuses. Any blocker makes the overall
result `claim_blocked` even when another status is unavailable; with no blocker,
an unavailable status makes it `incomplete`. Only all-complete metrics plus
all-passing gates can set
`claim_allowed=true`. Thus an unavailable EPR never deletes an otherwise
complete economic endpoint, but it still prevents a whole-claim authorization.
