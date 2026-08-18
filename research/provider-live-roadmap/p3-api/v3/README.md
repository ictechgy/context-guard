# Provider-live factorial benchmark v3

This directory preregisters a finite retrospective benchmark before any v3
provider call. It uses twelve bounded historical patch tasks from three
independent, long-lived public repositories: Requests, TypeScript, and Swift
Argument Parser. The corpus is curated after the historical solutions were
known; it is not a probability sample and does not support a universal quality
or future-project guarantee.

The design has three provider-visible binary factors: adaptive pruning, a pure
symbol projection, and graph closure. Their eight combinations are scheduled
in 36 paired task/repetition blocks, for 288 one-shot units. Raw symbol-memory
objects are never sent to the provider. The pure symbol projection excludes
graph fields, while graph-only arms change the packed manifest without adding
the projection.

Quality is fail-closed for this corpus. A response must be exactly one bounded
unified diff, touch only the frozen task paths, apply cleanly, reproduce the
frozen selected-path historical patch bytes, and satisfy the scorer-only source
assertions. Any invalid or checker-failing patch is a completed quality failure;
it is not technical missingness. This is stronger than accepting an arbitrary
alternative patch, but it proves only equivalence to these twelve selected
historical patches—not full upstream-suite or all-task correctness.

The selected-path patch is not necessarily the whole upstream commit. Any
upstream-changed path omitted to keep a task within the 8 KiB response envelope
is recorded explicitly in the corpus manifest and is outside the task claim.

Per-request Anthropic token usage is provider-authoritative. A price computed
from those tokens is only a list-price calculation. With the available Console
export, one exclusive API key can confirm only an experiment-total daily cost;
even eight arm-isolated keys could confirm arm aggregates, not per-request USD.
The benchmark must report per-request provider-confirmed cost as unavailable
unless a request-level provider export or a unique billing bucket per request
becomes available.

The three repositories are the independent clusters. Four tasks from the same
repository are not treated as independent evidence. With only three project
clusters, the study makes no null-hypothesis rejection claim: it reports the
four preregistered contrasts and seven factorial effects descriptively, with
all 27 ordered project-cluster resamples and three leave-one-project-out rows as
finite-corpus sensitivity analyses.

`preregistration.json` is only a prepared draft until the complete directory,
generator, and regression test are committed. No provider call is allowed
before that commit. The provider-live runner remains a later gate and requires
a separately approved call cap and USD ceiling.

Before that approval, a second committed rehearsal gate must freeze all 96
task-arm cells (mapped across 288 scheduled units), demonstrate byte-level
one-factor isolation, and prove scorer-owned fields are absent from every
provider input. An activated factor that has no candidates or recommends no
change is recorded as a zero-byte-effect pair; no artificial marker is added to
make inputs different. Consequently, the unique prompt count is measured by
the rehearsal rather than forced to 96. This preregistration deliberately does
not substitute declarative arm booleans for byte-level proof.

`evaluator.py` implements that gate without a provider. It first verifies that
the approved partial-clone caches are fully hydrated, then disables lazy
fetching. Each parent is exported into a no-history snapshot. Byte-identical
canonical/plugin packer, sanitizer, and credential-policy files are bound; the
captured canonical bytes run under an isolated Python child with a minimal
environment. Its audit hook denies network, writes, out-of-snapshot reads, and
every subprocess except the shipped packer's exact bounded
`git -C <snapshot> ls-files -z` scan against a no-history index. The retrieval
query is the first public allowed patch path; no scorer field selects context.
The provider-visible pure symbol projection contains only path, kind, name,
signature, and line fields from the shipped symbol receipt. All 96 inputs are
sealed and validated before the scorer-only checker file is opened.

`provider-input-freeze.json` is metadata-only: it seals source, prompt, pack,
projection, manifest, application-receipt, producer, factor-pair, and exact
288-unit schedule identities without storing raw prompts, packs, symbol
objects, responses, tasks, or checkers. The later rehearsal report binds the
scorer artifact and records the enforced phase order. In the current frozen
corpus, 52 of 96
cells have unique provider inputs and 88 of 144 one-factor pairs change provider
bytes; the other 56 pairs are honest mechanism no-ops. Broken down by factor,
adaptive changes 24/48 pairs, graph closure changes 16/48, and the pure symbol
projection changes 48/48. These activation counts are part of the eventual
result, not evidence to curate different tasks after seeing provider outcomes.
`rehearsal-report.json`
records only the provider-free audit probes and the 12 historical-checker
rehearsals. Provider quality, token, cost, and savings evidence all remain
explicitly unavailable, and provider execution remains unauthorized.

## v3 live gate

`live_runner.py` is a fail-closed, two-envelope gate for the frozen 288-unit
schedule: two immutable 144-unit batches, a USD 20.00 ceiling per batch and
USD 40.00 cumulative, one HTTPS `POST /v1/messages` request per unit, and no
retry. Before either approval is consumed, it sums a conservative whole-batch
list-price reservation from each exact request body plus 8,192 input-token
overhead and 4,096 output tokens. It binds prompt preparation to this committed
evaluator, the metadata-only capture, and an explicit captured-corpus root; it
does not accept arbitrary prompt builders. A real run requires two exact
one-use external approval envelopes, with the pinned approval module/schema and
separate verification and registry keys.

Batch authorization and each unit reservation are durable. The owner-only
0700/0600 HMAC ledger is keyed by a domain-separated derivation of the external
registry key and stores no key beside the ledger. A reserved unit with a sealed
private transport capsule is reconstructed without replay; a reserved unit
without one is recorded as ambiguous and all later units are marked
not-dispatched/spend-unknown. Scoring is opened only after 288 terminal units;
until bound patch/postimage/assertion scoring completes, public status remains
`provider_receipts_sealed_pending_scoring`. Raw responses and provider request
IDs remain private, and public evidence reports scheduled/reserved/provider-
receipt/usage-complete counts rather than a hard-coded call count. Evidence
retention is explicitly unavailable/manual-owner cleanup. Direct CLI invocation
refuses; `live_launcher.py` is the separately bound production entry point and
reads owner-only approval/verification/registry files and the fixed
`contextguard-anthropic-p3` Keychain service only after an explicit
`--execute`.
Its activation is intentionally separate from the core contract: it pins the
core commit, runner bytes, and contract bytes and must be refreshed after the
core commit is created.

The first production protocol-validation request on 2026-08-18 was rejected
before model output with HTTP 400 because `temperature` is deprecated for the
selected model. It returned no usable provider usage receipt, was not retried,
and is excluded from every benchmark outcome. Its spend is therefore unknown,
not zero. `protocol-amendment.json` freezes this fact without storing the raw
private response, removes `temperature` from future request bodies, leaves the
288-unit schedule and all estimands unchanged, and reserves the failed call at
the conservative maximum-request bound inside the existing USD 40 cumulative
ceiling. A fresh approval must raise the lifetime external-call cap from 288 to
289 before a new balanced 288-unit run may be activated; until then the old
launcher hashes deliberately fail closed.

The amended run has twelve sealed HTTP 200 provider receipts. Eleven include
authoritative usage and a final text answer. One stopped at `max_tokens` with
only a private thinking block. The earlier parser deliberately rejected each
previously unregistered shape, sealed the response, and stopped before any
later request. No answer or thinking text was inspected while correcting the
parser. `response-amendment.json` freezes both response-shape corrections and
the recovery policy. The parser accepts exact leading
`{type, thinking, signature}` blocks plus an optional final `{type, text}`
block; a missing text block is accepted only when `stop_reason` is
`max_tokens`, in which case the empty answer is scored as a completed quality
failure rather than technical missingness. Thinking and signatures remain
private and are neither published nor scored. Recovery verifies all twelve
prior HMAC-bound capsules, reclassifies the same bytes without redispatch, and
continues only the remaining 276 calls. The lifetime cap remains 289.

Regenerate and verify locally without provider or network access:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  research/provider-live-roadmap/p3-api/v3/build_preregistration.py --write
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  tests/provider-live-roadmap/test_p3_factorial_preregistration_v3.py
CONTEXTGUARD_V3_CORPUS_ROOT=/path/to/captured/clones \
  PYTHONDONTWRITEBYTECODE=1 python3 -B \
  research/provider-live-roadmap/p3-api/v3/evaluator.py \
  --corpus-root /path/to/captured/clones --write
CONTEXTGUARD_V3_CORPUS_ROOT=/path/to/captured/clones \
  PYTHONDONTWRITEBYTECODE=1 python3 -B \
  tests/provider-live-roadmap/test_p3_factorial_evaluator_v3.py
```

If the three approved read-only public clones are present, set
`CONTEXTGUARD_V3_CORPUS_ROOT` to their common parent to additionally verify all
commit, tree, patch, and target-versus-parent checker identities. The clone
directory is temporary evidence and is never committed.
