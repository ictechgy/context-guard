# Provider-input budget policy v4

The completed v3 run found that the fully enabled arm increased provider
tokens. This directory preserves that result and fixes the activation policy
for future provider inputs; it does not rewrite the 288 historical calls.

The cause is additive composition. The pure Symbol projection appended
1,311–2,121 bytes of off-pack signatures to every Symbol-enabled prompt.
Graph closure changed only the four Requests tasks, where it appended direct
import neighbors to unused global pack budget. Those graph candidates were
lower priority than every already selected source. The all-enabled arm had no
shared provider-input ceiling, so Adaptive savings could be more than consumed
by Symbol and Graph additions.

`budget_policy.py` implements `self_financing_context_v1` over the 96 prompt
cells already sealed in v3. Each task's ordinary `a000` prompt is the absolute
ceiling. Adaptive activates first and only if it makes the prompt strictly
smaller. Symbol may then spend that saved headroom, followed by Graph. A factor
that has no byte effect or exceeds the remaining headroom becomes an honest
no-op. The policy selects only an existing frozen prompt cell and therefore
never trims, rebuilds, or invents unsealed provider input.

On the frozen corpus, 48/96 historical cells exceeded their task's ordinary
ceiling, by as much as 12,049 bytes. The policy reduces that count to zero. It
keeps Adaptive active in 24 requested cells and Symbol active in 12; Graph is
suppressed or a byte no-op in all 48 requested cells because none of its
nonempty expansions fit the ceiling. Across the 96-cell matrix, selected
prompt bytes fall from 1,269,938 to 1,053,798, avoiding 216,140 historical
prompt bytes (17.019729%). This is a deterministic byte result, not a measured
USD saving.

Each frozen prompt was sent three times in v3, and Anthropic reported the same
input-token count on all three repetitions of every task/arm cell. Replaying
the policy's selected exact prompt identities over the frozen 288-unit schedule
therefore projects 1,277,418 input tokens instead of the observed 1,541,826:
264,408 fewer (17.149017%). This projection is bound to provider-observed input
usage for these exact prompts. It is not a new provider call, and it cannot
project the stochastic output-token response or provider-billed USD.

The policy guarantees only that selected input prompt bytes cannot exceed the
ordinary prompt for the same frozen task. It cannot guarantee lower output
tokens, total provider tokens, or preserved quality on a future task. Graph
needs a later candidate-level budgeted implementation and a new quality-valid
provider run before it can make a savings claim. The v3 result and its failed
0/288 exact historical-patch quality gate remain unchanged.

Future provider orchestration must call `select_provider_cell()` with the exact
frozen capture bytes, task ID, and requested arm. The returned cell ID and
prompt SHA identify the only permitted existing input. The report alone does
not activate a provider call.

`live_runner.py` applies that policy to the frozen 288-unit schedule before
building any Anthropic request.  It seals both the requested arm and the
policy-selected prompt identity into request IDs, approval scopes, transport
capsules, the private ledger, and public evidence.  Selected prompt bytes are
rechecked against the frozen capture and the same-task ordinary ceiling at the
last request-building boundary.  V3 approvals, ledgers, and capsules cannot be
migrated into this V4 protocol, and the historical V3 launcher now refuses
before reading approval or credential material.

Activation uses two commits.  The core commit left `live_launcher.py`
fail-closed.  The follow-up activation commit binds that exact core commit plus
the exact runner and contract blobs before the V4 launcher can read private
inputs or call its production surface.  This changes no historical V3 call or
result and performs no provider call by itself.

The active approval format is `contextguard.external-approval/v2`. It keeps the
historical v1 module and state registry compatible, but binds retention
truthfully as manual owner cleanup with no fabricated deletion deadline. V1
envelopes are rejected before plan preparation or durable state, and approval
schemas are never migrated. This resolves the signed-scope mismatch; it does
not add automatic deletion or satisfy a finite-retention production gate.

The live runner caches an immutable, metadata-bound selection index for the
unchanged frozen artifacts, builds each reservation body once, avoids rewriting
the HMAC ledger for logical reads, and refuses a duplicate output-root launcher
after a bounded lock wait. These changes reduce local preparation and recovery
overhead without relaxing the final digest checks or provider-call cap.

Rebuild the metadata-only report without network or provider access:

```bash
python3 -B research/provider-live-roadmap/p3-api/v4/budget_policy.py --write-report
python3 -B tests/provider-live-roadmap/test_p3_budget_policy_v4.py
```
