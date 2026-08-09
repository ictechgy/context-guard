# P1 live-study and npm-release authorization packet

_Drafted: 2026-08-09 KST_

This packet is the controlling scope for the authorization recorded on
2026-08-09. Approved actions are repository-scoped GitHub activity, candidate-
only construction for the selected commit, and the bounded P1 Claude study.
Not approved are npm `next`, npm `latest`, artifact deletion, P2-P6 provider
activity, broader credential/data access, or any action outside this packet.

## Current readiness verdict

- PR #287 merged the v3 accounting/budget hardening; PR #288 merged the bounded
  GitHub-hosted runtime normalization required by the candidate workflow.
- Candidate run `31314422888` succeeded for retained ref
  `refs/heads/candidate/p1-v3-2489f9995822` at exact source
  `2489f9995822325d273bbc4406299469214aba02`. Both tarballs, the canonical
  manifest, checksums, SRI values, and all three GitHub attestations were
  independently verified. npm `next`/`latest` were not invoked.
- Provider-free rehearsal passed with 108 initials, 12 deterministic retries,
  two discarded fake canaries, zero network/provider calls, and
  `claim_allowed=false`.
- The first live root completed `prepare`, then terminally accounted one failed
  `legacy_trim` canary. The exact Claude CLI reported that it was not logged in;
  provider API duration, input/output tokens, and cost were all zero. No second
  canary or analytic identity launched.
- The failed root exposed a provider-free closure bug: `analyze` refused the
  terminal failed canary instead of writing the promised P1-X. The minimal fix
  now emits a ledger-bound `failed_canary_terminal_evidence` P1-X without
  replay. Full offline verification after the fix passed: `1561` tests,
  `3` skips, `prepublish check: OK`.
- The source now differs from candidate `2489f999...`; one new reviewed
  immutable candidate is required before another live `prepare`.
- P1 remains blocked. The recorded 218-identity authorization has one terminally
  accounted identity and 217 remaining, which is insufficient for a fresh
  complete 218-identity lifecycle. A new live attempt requires operator login
  and separate authorization increasing the total ceiling to at least 219.

## Frozen study shape

| Field | Value |
| --- | --- |
| Plan | `bench/token-savings-12task/study-plan-v2.json` |
| Corpus | `bench/token-savings-12task/tasks.json` |
| Corpus tasks | 12 |
| Arms | `host_unmodified`, `legacy_trim`, `bash_reference_v1` |
| Repetitions | 3 |
| Model selector | `sonnet` |
| Max turns per analytic call | 12 |
| Max budget per analytic call | `$0.75` |
| Discarded canaries | 2 (`legacy_trim`, `bash_reference_v1`) |
| Max turns per canary | 2 |
| Max budget per canary | `$0.75` |
| Initial analytic calls | 108 |
| Retry identities | up to 108; only after valid initial task failure |
| Maximum consumed/reserved identities | 218 |
| Per-process CLI cap | `$0.75` |
| Derived arithmetic maximum | `$163.50` |
| Aggregate CLI limiter | none |
| Optional stopping | forbidden |
| Primary contrast | `host_unmodified` vs `bash_reference_v1` |
| Diagnostic contrast | `legacy_trim` vs `bash_reference_v1` |
| Statistical authority | descriptive-only; fixed corpus has no independent power model |

The CLI enforces 218 independent per-process caps, not one aggregate budget.
`218 × $0.75 = $163.50` is therefore a derived arithmetic maximum, not an
estimate or a request to spend that amount. The user may authorize a smaller
amount only by approving a new frozen plan; silently truncating this plan would
make the complete population unreachable and keep P1 failed.

## Frozen Claude executable identity

The private `prepare` record retains and revalidates the exact invoked and
resolved filesystem paths. This committed packet retains only the portable
identity fields:

- executable: `claude`
- resolved version: `2.1.226`
- type: Mach-O 64-bit arm64 native executable
- size: `279661952` bytes
- SHA-256:
  `013a1cf17df5ff1dcc189d5d6fd3fdd5f097ddc3cd41aa9992e99805574febbe`

`prepare` must re-resolve and bind this exact executable, local `--version` and
`--help` probe output, runner and Python bytes, fixture/checker bytes,
candidate overlay, PATH/locale, and hook interpreter. Any drift stops before
analytic reservation. Backend and model revisions remain unavailable rather
than inferred.

## Data and privacy boundary

During the approved run, Claude receives the twelve frozen sanitized prompts
and can read only each cold synthetic fixture workspace through the allowed
tools. The canary receives its fixed marker-writing prompt. Local settings,
hook lifecycle events, terminal usage, and bounded model output are retained in
the private study root for verification.

The runner must continue to:

- strip credential-shaped environment variables;
- avoid reading `.env`, auth files, keychains, npm credentials, Claude
  credentials, cookies, or unrelated user settings;
- write only to a new absolute owner-private output root outside the repository;
- never upload raw study artifacts automatically;
- record missing correction, retrieval, shifted-cost, backend-revision, or
  model-revision observations as unavailable/null, never zero or a proxy.

## Live execution order and stop rules

1. Select one reviewed committed source revision.
2. Create and retain a dedicated remote branch or tag whose tip is exactly the
   reviewed `MERGED_SHA`, verify it with `git ls-remote`, then dispatch the
   trusted candidate workflow using that ref and the identical `commit_sha`.
   Verify its manifest, checksums, SRI, provenance, and paired clean install.
   Do not delete the retained ref without separate retention authority.
3. Run provider-free `prepare` with the exact native Claude executable.
4. Run the two-call discarded canary. A `launched` canary may be recovered
   without a provider replay only when its immutable terminal artifacts fully
   validate. A merely reserved/workspace-prepared canary, an unrecoverable
   launched canary, or a failed canary closes the root to provider activity and
   permits only `P1-X` analysis; no analytic reservation may exist first.
5. Run the fixed analytic schedule. Resume is allowed only when no analytic
   `launch_reserved` or `launched` state remains open. Any open analytic state
   permanently closes the root, forbids every later provider launch, and
   permits only `P1-X` analysis.
6. Run `analyze` to emit `P1-F` for the complete valid population or the
   canonical `P1-X` invalid decision for a stopped ambiguous root.
7. Keep `claim_allowed=false` and report the P1 feasibility verdict. No
   successful subset or universal savings statement is allowed.

Immediate stop conditions:

- candidate, CLI, runtime, fixture, checker, settings, or environment drift;
- canary lifecycle/hook/checker failure;
- credential-shaped environment leakage or unexpected external access;
- output-root integrity failure or unrecoverable reservation ambiguity;
- operator cancellation or projected spend outside the explicitly approved
  ceiling.

## Separate npm action scopes

These are three independent decisions:

1. **Candidate only:** build and attest exact `@ictechgy/context-guard@0.5.0`
   and `@ictechgy/context-guard-receipt@0.2.0` tarballs from one approved commit
   through a retained remote ref resolving exactly to that commit.
2. **Publish to `next`:** publish only the exact attested pair to the npm
   registry after clean-install and dependency-integrity verification.
3. **Promote to `latest`:** separately verify the reviewed `next` pair, record
   previous tags, then move Receipt followed by root with compensating rollback.

Candidate approval does not authorize publication. `next` publication does not
authorize `latest` promotion. Artifact deletion is a separate retention
decision.

## Authorization status

- [x] OpenAI Codex network use for Ralplan/Ultragoal workers, limited to this
      repository and excluding secret files.
- [x] GitHub network use for fetch/push/PR/CI, limited to
      `ictechgy/context-guard`.
- [x] Claude live study: exact committed source/candidate, executable above,
      `sonnet`, up to 218 consumed/reserved identities, `$0.75` per-process CLI
      caps, and the derived `$163.50` arithmetic maximum, with the prompt/data
      boundary and stop rules above.
- [x] npm candidate workflow for the exact approved commit.
- [ ] npm publication of the exact pair to `next`.
- [ ] npm promotion of that exact reviewed pair to `latest`.

The approvals above were recorded on 2026-08-09. `next` and `latest` remain
blocked. No credentials need to be shown to or inspected by Codex; environment-
protected operator workflows should consume them without exposing values.
