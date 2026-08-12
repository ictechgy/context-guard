# Provider-free roadmap boundary

This directory records a provider-free boundary. The evidence manifest is
historical: it describes only the repository-side P1-v8 evidence stored in the
immutable Git commit `96cfd58f82c02166c2749389a22dd1249712c92d`. The verifier
enumerates the named roots and reads every artifact byte from that commit's Git
objects. It does not treat the current worktree or the later roadmap as P1-v8
evidence.

The private study root
`/private/tmp/contextguard-p1-live-v8.rLM3P6/study` is not inventoried as if its
files were available. The manifest records only the known source/run/artifact
identities, two known digests, and the 121-record analytic count, with status
`unavailable_claim_blocking`.

Run each operation from the repository root with an empty inherited environment.
The verifier rejects every inherited name except `PATH` and `LANG`; in
particular, Python loader/startup variables, dynamic-loader variables, and
credential/profile variables are rejected by name without printing their
values.

```sh
env -i PATH="$PATH" LANG=C.UTF-8 python3 -I -B scripts/verify_provider_free_roadmap.py inventory --manifest research/provider-free-roadmap/p1-v8-evidence-manifest.json
env -i PATH="$PATH" LANG=C.UTF-8 python3 -I -B scripts/verify_provider_free_roadmap.py run --contract research/provider-free-roadmap/boundary-contract.json --profile boundary-tests
env -i PATH="$PATH" LANG=C.UTF-8 python3 -I -B scripts/verify_provider_free_roadmap.py run --contract research/provider-free-roadmap/boundary-contract.json --profile g2-contract-tests
env -i PATH="$PATH" LANG=C.UTF-8 python3 -I -B scripts/verify_provider_free_roadmap.py run --contract research/provider-free-roadmap/boundary-contract.json --profile g3-rehearsal-tests
```

`run` is both the boundary check and the execution. It resolves the currently
running Python, applies isolated/no-bytecode flags, first requires the contract
profile to equal the verifier's independently pinned module/path/byte-count/hash,
then captures the verified bytes and feeds them over stdin to a fixed, pinned
bootstrap. The child compiles those captured bytes with the pinned filename and
never reopens the mutable workspace source. The boundary-test child contains
only `PATH` and `LANG`; the G2 child contains only `LANG` (apart from a
recognized macOS-injected runtime name, which is not forwarded). There is no
caller-supplied interpreter, bootstrap, or arbitrary argv preflight.

These checks are integrity and execution-boundary controls, not a network
sandbox. The contract grants no authority for provider calls, credential
access, runtime activation, npm publication, token/cost claims, or a future
live run. The new roadmap output roots remain disjoint from every historical
evidence root.

## Frozen g2 ablation

The versioned four-arm structural contract and six independent fixture trees
are under `g2/v1/`; its immutable inventory is `g2/freeze-lock.json`. Run G2
only through the `g2-contract-tests` bound profile above. The boundary verifier
independently pins the exact test bytes, captures them before spawning the
isolated child, and additionally captures and injects the exact pinned G2
verifier and lock bytes with the independently pinned lock SHA and tree root.
The G2 verifier captures public fixture and packer bytes, executes from a
private immutable snapshot, seals every scorer-consumed structural field, and
only then opens scorer-only bytes. A final drift pass rejects repository paths
changed during execution.

G2 executes only the bound local packer and supports no provider, retrieval,
correction, latency, cost, bootstrap, inference, or savings claim. The hidden
oracle and graph evidence are scorer-only and are loaded after all public arm
outputs have been sealed; neither is copied into an arm projection.

The G2 packer child runs the exact lock-bound CPython 3.14 executable with
`-I -B`, `LANG` only, and a verifier-owned audit hook installed before packer
bytes. Through this reviewed Python audit surface it rejects sockets/DNS,
process spawning/exec, late or native dynamic loading, environment mutation,
writes and filesystem mutation, and reads outside the captured workspace.
This is not an OS security sandbox and makes no guarantee against hostile
host/root or same-UID processes, a compromised Python/native runtime, or
OS-wide isolation.

## Frozen G3 rehearsal

G3 is independently frozen by `g3/freeze-lock.json` and runs only through the
`g3-rehearsal-tests` profile. The boundary captures its test, runner, manifest,
cost model, and schemas plus the exact current G2 lock/tree/verifier, injects
only those bytes into a `LANG`-only child, and recaptures all paths afterward.
All task-arm execution and retrieval/context construction completes and is
sealed before scorer bytes load. Timing is isolated in timing-only artifacts;
deterministic evidence uses exact paired task-block enumeration and remains
provider-, token-, currency-, and savings-unavailable. See `g3/v1/README.md`
for the receipt, replay, publication, and audited CPython boundary contracts.
