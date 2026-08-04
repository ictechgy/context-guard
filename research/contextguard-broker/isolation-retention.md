# ContextGuard Broker isolation and retention policy

## Stage 1/P0 constraints

This policy is a contract and fixture boundary only: it changes no runtime
behavior, installed settings, package, setup, CSV column, or R9 artifact.
`transport_rejected` stops transport, shadow, and active stages (Stages 3–5),
while Stage 2 pass-through attribution can continue without substituting Read
input. R9 remains immutable, inconclusive, and excluded from efficacy claims.

## Attempt isolation

Each consumed attempt uses exactly one isolated worktree, one Claude session,
and one attempt-specific artifact root. No pack, mutable index, session,
generated artifact, or cache state may be reused across arms. Before/after
reset hashes make leakage or reset mismatch terminal claim-blocking evidence.
Cold lanes pay independent index builds; warm lanes may use identical frozen
index snapshots for both arms only under the frozen study rule. Randomized arm
order is within the declared cache lane.

A selected macOS root is exactly
`/private/tmp/contextguard-broker/<attempt_id>` and is joined to the same
immutable `attempt_id` in the permission decision. `/tmp` aliases, workspace or
user paths, secret areas, and any other location class are not selectable even
when a caller supplies optimistic proof flags.

An eligible root is owner-only, bounded, attempt-specific, Git/workspace
excluded, and non-symlinked at every path component. The candidate root and all
parents are checked before materialization and before use. A symlink, root
escape, incorrect owner/mode, permission ambiguity, or unrelated Read/tool
visibility is integrity/security evidence and resolves to `BLOCK_TOOL`. The
broad `.context-guard/**` denial is not weakened to make storage convenient.
Descriptor seed paths must be normalized repository-relative paths with no
absolute form, traversal, non-normal segment, or secret-like path. Normalization
does not replace protection: every seeded source and every expansion must still
pass the protected-zone classifier under the descriptor's frozen policy.

## Subordinate receipt bundles

Every consumed attempt has one content-addressed immutable subordinate bundle.
It stores only canonical hashes, bounded byte lengths/counts, safe enums,
timestamps/durations, revisions, and opaque relative identifiers. It never
stores raw prompts, source, model-visible tool output, environment values,
credentials, or arbitrary commands. The terminal attempt may reference bundle
schema version, opaque identifier, bundle SHA-256, and completeness class, but
the bundle cannot create attempts, consume retries, alter state/terminality,
authorize a retry, determine success, or overwrite earlier evidence.
Receipt references are split into fixed receipt-type maps and keyed by opaque
receipt ID; each value is the SHA-256 of the complete canonical receipt bytes.
This representation cannot encode two hashes for the same typed receipt
identity, and an untyped or unhashed path is not a valid bundle member. For a
`complete` bundle, `pass_through` requires decision, Read observation, and
provider-turn join receipts; `activated` additionally requires artifact-root,
selection-snapshot, and pack identities. A `pre_activation_blocked`,
`claim_blocked`, or `incomplete` record may retain an empty typed map when the
absent receipt has an explicit blocking reason.
The bundle also binds both descriptor ID and
descriptor SHA-256 so an identifier cannot silently resolve to new policy.
The bundle may contain the disjoint provider, paid-helper, and non-provider cost
components and the observations supporting activation, completeness,
correction, failure, latency, privacy, provenance, and quality gates. It must
not contain a `claim_completeness_result`: claim completeness is calculated
only after immutable bundle publication and references the bundle SHA-256, so a
reverse reference would form an unverifiable hash cycle.

Bundle `complete` is not a label that can override its evidence. It requires an
activated or pass-through profile, an empty blocker set, nonblocking cost and
latency observations, passing privacy and provenance, and every receipt the
profile requires. `claim_blocked` and `incomplete` require explicit blockers.
Endpoint and promotion-gate completeness is then evaluated independently in
the post-publication claim result; a mixed result is retained rather than
flattened or discarded.

Expansion records are bounded by descriptor count/byte limits. Each entry uses
a normalized repository-relative source path, immutable source total length,
explicit start byte, and nonzero byte length defining the exact half-open range
`[start, start + length)`. The semantic invariant rejects out-of-range or
overlapping ranges, inconsistent totals for one source identity, and
noncanonical path/start/length/ID ordering. Expansion IDs are unique, one source
ID resolves to exactly one path and total length, and the reverse path-to-ID
mapping is also single-valued so aliases cannot evade overlap checks. An
`immutable` delivery requires
the delivered byte length and SHA-256 to equal the exact source range; a
mismatch is `verification_failed` evidence and cannot masquerade as immutable.
Raw source and delivered bytes remain prohibited from the bundle.

## Durability, retention, and cleanup

Write a bundle to a private temporary path, validate canonical bytes and hash,
then atomically publish an immutable final path. On crash, retain only
non-final temporary material within the attempt root for bounded recovery
inspection; it is never consumed as evidence. A failed write, missing hash, or
durability uncertainty remains a claim blocker. Cleanup is bounded to the
attempt-specific root after the frozen retention interval and confirms the path
still belongs to that attempt, is owner-only, and has no symlinked component.
It must not recurse into a workspace, Git tree, shared root, or another
attempt. Retained bundle metadata remains immutable for the declared audit
period; raw content is prohibited at every retention stage.
