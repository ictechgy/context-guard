# G5 P2 preregistration-only contract

G5 freezes a future experimental design before any observation. Its status is
`preregistered_contract_only`, its observation status is `no_observations`, and
`execution_authorized` is permanently false in this artifact. The fixed sample
capacity is operational (`capacity_fixed_not_effect_estimate`) and is explicitly
not derived from G3 or G4 outcomes. G5 contains no result, observation, evidence,
run-receipt, approval, executable runner, provider selection, model selection,
credential, network permission, or mutable price schedule.

The only upstream trust root is the exact frozen G4 contract: lock, tree,
verifier, claim policy, and schema-set identities. No G3/G4 aggregate value is
copied. The independent boundary profile captures all G5 and required G4 bytes,
passes them over stdin to a `LANG`-only isolated child, and recaptures paths after
execution. The mutable verifier refuses direct execution.

## Frozen design

The experimental unit is one scheduled task × arm × repetition request. Task
lineage is the cluster; all four arms are paired within a complete lineage and
repetition block. The schedule contains exactly 60 primary blocks (30 in each
stratum), four units per block, and exactly 30 primary units per stratum and arm,
for an absolute maximum of 240. There are no replacement or warmup units. Every
incomplete block is retained and reported as missing, never replaced. There is no
interim analysis, early significance stop, extension, resampling, or
outcome-dependent exclusion.

`schedule.json` stores every block, task, partition, stratum, repetition, arm
order, assignment identity, and scheduled-unit identity. Its order is fixed by
the implementation-independent unsigned FNV-1a-64 specification and ASCII
tie-break in the contract. The verifier independently recomputes the full
schedule and every conservation identity.

## Future minimized observer

The observation schema is a data-minimization contract, not collected data. It
allows scheduled identities; payload, assignment, model, observer, request and
receipt identities; bounded status/event/count fields; monotonic pack boundaries;
correctness; usage, correction, and retrieval accounting; authoritative billing
receipt state; closed exclusion reason; and audit state. It rejects prompts,
responses, headers, URLs, credentials, environment, and arbitrary paths.

Cost minor units and currency may come only from an authoritative provider
billing receipt. When unavailable, values are null and explicitly unavailable,
never zero or estimated. Provider, model, credential, network, and write root
remain unselected and future-authorization blocking.

Observer states are exhaustive: completed, normal completion, eligible, and no
exclusion are equivalent. Every other completion event is excluded under the
identical closed reason, with all metrics, correctness, receipt, and costs null
and unavailable under `excluded_unit`. Completed metric and correctness reasons
are separately closed. Billing authority, status, and reference are equivalent
states: an authoritative observed receipt has a non-null reference, while an
unavailable receipt has a null reference. All observed components share that
receipt and one currency; paired cost summaries require the same currency.

## Analysis boundary

Closed-pack and realistic-fallback strata are summarized separately. The primary
descriptive contrast is combined minus ordinary. Ten technical repetitions are
first paired within repetition and then reduced to an exact rational arithmetic
mean of the available paired differences per task lineage and stratum;
repetitions are never treated as independent clusters. The six metrics are
closed: input usage; total usage as input plus output plus correction tokens;
retrieval count; pack latency as monotonic end minus start; total authoritative
minor-unit cost as the three same-receipt, same-currency components; and
correctness encoded as correct=1 and incorrect=0. A pair is available only when
both arm values for that metric are observed. Missing counts, ties, exact
rational arithmetic, rank order, currency handling, and no-rounding rules are
frozen. No caller-authored pair row can produce a result. The single batch
reducer requires the exact frozen 60-block/240-unit schedule, one schema-valid
terminal observation per scheduled unit, globally unique request and receipt
identities, and all four arms eligible before it internally derives the
ordinary/combined pair. A failure in either auxiliary arm excludes the whole
block from every metric and is retained in metric availability denominators.
The batch output reports all sixteen closed terminal-exclusion reasons,
terminal-excluded-unit counts separately from block-policy analytic exclusions,
and each excluded block's closed reason set. Every metric, stratum, and arm has
a scheduled denominator of 30 split exactly into observed and unavailable;
every paired contrast likewise splits its denominator of 30 into observed and
unavailable pairs. The randomized/analyzed/excluded block and unit identities
are emitted and checked without treating analytic block exclusions as extra
terminal failures.
All eight sign assignments over the three task lineages per stratum are reported
only as finite-corpus descriptive sensitivity endpoints, never as a confidence
interval, p-value, hypothesis test, or generalization. No savings,
provider-performance, production-readiness, external-validity, or generalization
claim is allowed, regardless of sign.

Run validation only through the independent profile:

```sh
env -i PATH="$PATH" LANG=C.UTF-8 python3 -I -B scripts/verify_provider_free_roadmap.py run --contract research/provider-free-roadmap/boundary-contract.json --profile g5-p2-preregistration
```
