# G3 captured provider-free rehearsal

G3 is a descriptive local rehearsal over the exact frozen G2 corpus. It makes
no provider, token, USD, savings, quality, parity, production-readiness, or
generalization claim. Provider, token, USD, and savings fields are explicitly
`unavailable` in the public aggregate.

Run it only through the independently pinned boundary profile:

```sh
env -i PATH="$PATH" LANG=C.UTF-8 python3 -I -B scripts/verify_provider_free_roadmap.py run --contract research/provider-free-roadmap/boundary-contract.json --profile g3-rehearsal-tests
```

The direct mutable `rehearse.py` command refuses execution. The profile pins
and captures `freeze-lock.json`, the test, runner, public manifest, frozen cost
model, every schema, the current G2 lock/tree/verifier, and then injects those
bytes into a `LANG`-only isolated CPython child. The child does not import or
open mutable G3 source paths. Both the G3 and G2 inputs are recaptured after the
run to detect path drift.

## Oracle boundary

The public manifest contains one closed retrieval plan per G2 task. Each
retrieval step fixes the fixture tree, path, exact line range, full-source byte
count/hash, and returned-slice byte count/hash. Before scorer bytes are opened,
the runner executes all 24 G2 task-arm packs and every closed retrieval/context
event, captures exact rendered pack bytes, and deep-canonical seals immutable
receipts. Receipts bind fixture inputs, manifest source paths and ranges,
selected paths, adaptive/graph/symbol receipts, rendered pack bytes/hash/count,
event-derived retrieval round identities, and provenance-rich final context.
Raw packer payloads are discarded.

The manifest also commits the exact captured-input map and, per task, the
canonical public-task identity and complete fixture-input digest. Replay opens
and canonical-checks every sealed JSON value (including adaptive, graph, and
symbol receipts), recursively rejects private scorer/oracle keys, and binds the
published task, fixture, and captured-input claims to those commitments. The
scorer additionally requires every arm's final context to contain the oracle's
required public evidence; an irrelevant retrieval plan cannot receive the full
validation status.

The output copy of the resolved manifest is never a replay trust root. Replay
requires the independently captured, freeze-authenticated manifest bytes and
their SHA-256 and rejects any byte-canonical difference. That manifest commits
all 24 exact task/arm packer-receipt digests, binding every selected source's
whole-file identity, range and slice, rendered pack, and adaptive/graph/symbol
claim to the captured G2 pack output. Synchronized output-manifest rewrites and
resealed source, graph-reason, or symbol-name forgeries therefore fail replay.

Only after exactly 24 seals exist does the runner capture scorer bytes. Scoring
reconstructs the minimal G2 view from immutable receipts and runs the full G2
oracle, graph, topology, adaptive-label, required-symbol, and arm-contract
validations. The scorer cannot choose retrieval targets or mutate context; a
required-path mutation regression test proves pre-oracle receipt and seal bytes
remain identical. No experimental execution is allowed after scorer load.

## Measurement and output

`cost-model.json` is a frozen non-currency byte-equivalent model. Its five
nonoverlapping components are recomputed from sealed rendered bytes and events.
Replay requires the sealed receipt cost, outer result cost, and this independent
recomputation to be byte-equal, and requires outer/receipt stratum to equal the
authenticated public-task stratum.
Inference enumerates all `6^6 = 46,656` paired task-block resamples without a
PRNG. Means and nearest-rank 95% endpoints (ranks 1,167 and 45,490) are stored as
exact rationals with denominator six, both per arm and as paired deltas from
ordinary. These statistics are descriptive only.

Only the measured `*_ns` timing values are normalized out of the deterministic
bundle commitment; timing metadata, ordered task/arm identities, and the
declared normalization paths remain committed. `timing.jsonl` records only the
exact bound-packer child invocation measured by `time.monotonic_ns`;
`timing-summary.json` reports its integer summaries and marks task execution
unavailable/null. All other artifacts are byte-deterministic across runs.

Publication creates a private no-follow staging directory, writes exclusive
0600 regular files, fsyncs them, and atomically renames to a previously absent
0700 output root. The inventory covers every other artifact with byte counts
and SHA-256 hashes and declares timing normalization. The replay verifier
rejects symlinks, hardlinks, unsafe modes, missing/extra files, inventory drift,
schema failure, receipt/plan/event/context/cost/pack/reproducibility drift, and
exact-enumeration drift. The independent freeze lock records exact modes and
the boundary capture rejects missing, unlisted, symlinked, hardlinked, or
mode-drifted G3 inputs before executing the captured child.
Artifact inventory paths are checked for uniqueness before constructing the
verification map, independently of schema item-count enforcement.

## Security claim

The runner and G2 packer install audited deny-by-default Python process
boundaries before untrusted experiment bytes. Real decoy probes exercise and
count network, DNS, process, exec, environment, native-load, credential-decoy,
and out-of-snapshot denials. Only the exact authenticated G2 packer child is
allowed. This is an audited CPython process boundary, not an OS sandbox; it does
not defend against hostile host/root or same-UID processes or a compromised
Python/native runtime. Decoys contain no real credentials, and no credential
file may be touched.
