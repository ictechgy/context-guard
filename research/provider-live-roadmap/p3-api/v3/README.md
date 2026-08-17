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
unique task-arm prompt hashes (mapped across 288 scheduled units), demonstrate
byte-level one-factor isolation, and prove scorer-owned fields are absent from
every provider input. This preregistration deliberately does not substitute
declarative arm booleans for that later byte-level proof.

Regenerate and verify locally without provider or network access:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  research/provider-live-roadmap/p3-api/v3/build_preregistration.py --write
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  tests/provider-live-roadmap/test_p3_factorial_preregistration_v3.py
```

If the three approved read-only public clones are present, set
`CONTEXTGUARD_V3_CORPUS_ROOT` to their common parent to additionally verify all
commit, tree, patch, and target-versus-parent checker identities. The clone
directory is temporary evidence and is never committed.
