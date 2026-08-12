# G4 authenticated claim gate

G4 accepts no caller-supplied or synthetic evidence. Its pinned boundary
profile captures the frozen G2/G3/G4 inputs, creates a new 0700 temporary root,
runs the captured G3 rehearsal into that root, and invokes G3's authenticated
schema, inventory, semantic-replay, event, context, cost, timing, and exact
enumeration verification using the exact captured G3 manifest as trust root.

Only then does G4 derive an in-memory sanitized record for each of the exact 24
task-arm receipts. A record contains only its domain-separated identity, frozen
task/partition/stratum, arm, immutable receipt hash, eligibility, and the
bounded local validation outcome. It contains no scorer/oracle material,
sealed representation, prompt, required path or symbol, label, cost, timing,
interval, or free prose.

Low-level source/report builders are internal and the legacy public helper
names fail closed. Public artifact verification requires the authenticated G3
output plus every captured upstream root, re-derives the sanitized source, and
requires exact source bytes before validating the report. Sanitization also
requires outer and receipt task, arm, and stratum identities to agree.

The public report has 24 separate partition × stratum × arm count rows. Every
cell contains exactly one eligible record; arm, partition, stratum, and total
conservation identities are explicit. The combined view is count-only and is
labelled `descriptive_count_only_no_pooled_inference`. G4 performs no pooled or
stratum inference and never recomputes G3 measurements from arbitrary records.

The closed claim vocabulary permits only `provider_free_rehearsal`,
`correctness_of_local_contract`, `reproducibility`, and
`measurement_readiness`. It permanently rejects `token_savings`,
`provider_performance`, `production_readiness`, `external_validity`, and
`generalization`; synonyms and free prose are not accepted.

This is an audited CPython process boundary, not an OS sandbox. Negative probes
exercise network, DNS, process, and out-of-private-root write denial without
touching credentials. Publication uses 0700 directories and exclusive 0600
files. The independently pinned freeze capture rejects missing, extra,
symlinked, hardlinked, mode-drifted, or changed inputs and recaptures after the
child exits. The mutable verifier command refuses direct execution.

Use the clean provider-free command:

```sh
env -i PATH="$PATH" LANG=C.UTF-8 python3 -I -B scripts/verify_g4_provider_free.py
```

It validates the historical P1 inventory and runs the independently pinned G2,
G3, and G4 profiles. It performs no network, provider, credential, npm, or
runtime activation.
