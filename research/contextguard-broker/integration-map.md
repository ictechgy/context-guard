# ContextGuard Broker P0 integration map

## Scope and gate

Stage 1 is a P0 contract-and-fixture release only. It creates no runtime hook,
settings, package, setup-wizard, plugin-copy, CSV, or R9 mutation. The selected
architecture is an immutable, descriptor-qualified multi-file evidence pack at
the existing Claude `Read` boundary, but no Read redirection is activated here.
`artifact-root-decision.json` is authoritative for transport: when its status
is `transport_rejected`, Stages 3, 4, and 5 stop. Stage 2 may still add a
canary-only pass-through attribution observer because it does not substitute a
Read input. R9 remains immutable, inconclusive, and unavailable as efficacy
evidence.

## Existing owners and extension anchors

| Concern | Current owner and anchor | Stage 2+ ownership boundary |
| --- | --- | --- |
| Attempt identity, state, costs, retries, terminality, and corrections | `context-guard-kit/benchmark_runner.py`: `CSV_COLUMNS` (line 88), `_parse_measurement_hook_events` (3243), `append_study_attempt_event` (8685), `fold_study_attempt_events` (8704) | Extend the existing attempt authority only; a receipt bundle never creates an attempt, consumes a retry, or changes terminality. |
| Read hook response | `context-guard-kit/guard_large_read.py`: hook `updatedInput` response (937) | Stage 3 probe may qualify a narrowly scoped immutable pack redirect only after Stage 2 attribution and a selected permission tuple. |
| Candidate selection and rendering | `context-guard-kit/context_pack.py`: `build_pack` (1828), `slice_source` (1969), `suggest_pack` (2946), `auto_pack` (3909) | Stage 4 reuses these primitives and binds the complete candidate universe; it does not add a parallel pack engine. |
| Installed-settings composition | `context-guard-kit/setup_wizard.py`: `build_adapter_plan` (1222), `_setup_command` (2253) | Canary fixture only through Stages 2–5. Normal setup, update, uninstall, and defaults stay unchanged until a separate product decision. |
| Commands and package manifest | `context-guard-kit/context_guard_commands.py`: `IMPLEMENTATION_PAIRS` (8) | A later helper is packaged only if needed, and packaging never promotes an observer to a default. |
| Copy and release equality | `scripts/sync_plugin_copies.py`: `build_copy_specs` (151); `scripts/prepublish_check.py`: manifest checks (176); `scripts/release_smoke.py`: `main` (1694) | Any later package change must update kit/plugin pairs together and pass copy, prepublish, and release smoke checks. |

## Boundary contract

Stage 2 records a pass-through chain: existing attempt identity -> `session_id`
-> `tool_use_id` -> observation receipt identifier and hash -> immediately
following attributable provider turn -> provider cost/usage provenance. Missing
links are retained as claim blockers, not discarded observations. Stage 3 adds
no new root selection: it can use only the frozen `{host version, settings hash,
root}` tuple selected in Stage 1. Stage 4 may construct shadow snapshots but
must not mutate live Read input. Each snapshot binds the isolated worktree,
repository and candidate-universe fingerprints, index build revision and policy,
diff basis, renderer version, descriptor version, protected-zone policy, and
selected/rejected/unenumerated evidence-class counts. Stage 5 is opt-in,
paired, and requires its own frozen authorization, manifest, rehearsal, and all
preceding gates.

The artifact-root record has one owner for each tuple component: top-level
`host`, top-level `settings.effective_settings_sha256`, and
`selected_tuple.selected_candidate`. It does not duplicate host or settings
values inside the tuple. Alternative `candidates` are structurally
non-selected; a selected candidate can exist only in `selected_tuple`. Settings
sources are keyed exactly once by `local`, `managed`, `project`, and `user`.
A provider-free semantic invariant rejects duplicate candidate IDs within the
alternative list or across the selected/alternative boundary. Selection stores
only the canonical macOS system-temporary path
`/private/tmp/contextguard-broker/<attempt_id>` and requires its basename to
equal the decision's immutable `attempt_id`; workspace, user-cache, secret-area,
relative, traversal, and `/tmp` symlink aliases cannot be selected. Eight
explicit true proofs cover attempt scoping, bounded cleanup, deny precedence,
workspace exclusion, narrow readability, non-symlinked components, owner-only
mode, and unrelated-tool exclusion. An executed selection also requires the
exact three positive evaluator-evidence codes and excludes every
unavailable/unproven evidence code.
A selected decision requires a complete inventory in which every source is
either safely inspected with hashes or confirmed absent, plus an executed
permission evaluator with no unproven capability.

Descriptor seed paths are normalized repository-relative paths: absolute paths,
`..` traversal, non-normal forms, and secret-like paths are invalid. A seed path
is only an enumeration boundary, never a safety allowlist. The protected-zone
classifier remains mandatory for every selected source and expansion; an
allowed seed cannot bypass it. Subordinate bundles reference canonical receipt
hashes in receipt-type maps keyed by opaque receipt ID, making two hashes for
the same typed identity structurally impossible. Bundle profiles freeze the
minimum receipts needed before a bundle may call itself complete. A blocked or
incomplete bundle may keep a typed map empty when the missing or non-durable
receipt is itself the retained blocker.
Decision receipts likewise preserve an explicit missing state: a
`DESCRIPTOR_MISSING` pass-through uses null descriptor and selection references
instead of fabricated IDs; post-activation decisions always carry their real
selection-snapshot reference.
Bundles may carry disjoint cost components plus activation, completeness,
correction, failure, latency, privacy, provenance, and quality gate evidence.
They cannot contain the claim-completeness result: that result references the
already-frozen bundle hash, so including it in the bundle would create a hash
cycle.

The R9 refusal is bounded to public evidence whose bytes are frozen by this
stage: summary JSON, summary Markdown, dashboard, study plan, and hook-event
evidence. Private ignored artifacts were not inspected. The R9 manifest identity
is accepted only as the value recorded by the immutable public summary, not as
an independently inspected private manifest. Those limits do not weaken the
public conclusion: 33 consumed attempts remain immutable and inconclusive,
`claim_allowed=false`, and R9 cannot be reused as efficacy evidence,
authorization, or a prior.

The broad `Read(./.context-guard/**)` denial remains intact. The P0 schemas,
fixtures, and decision records are planning evidence; none is an instruction to
modify installed Claude permissions or call a provider.
