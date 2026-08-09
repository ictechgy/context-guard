# P1 live-study and npm-release authorization packet

_Drafted: 2026-08-09 KST; amended with explicit auth reuse and 219-identity
ceiling approval on 2026-08-10 KST_

This packet is the controlling scope for the authorization recorded on
2026-08-09. Approved actions are repository-scoped GitHub activity, candidate-
only construction for the selected commit, and the bounded P1 Claude study.
Not approved are npm `next`, npm `latest`, artifact deletion, P2-P6 provider
activity, broader credential/data access, or any action outside this packet.

## Current readiness verdict

- PR #287 merged the v3 accounting/budget hardening; PR #288 merged the bounded
  GitHub-hosted runtime normalization required by the candidate workflow.
- Replacement candidate run `31319482425` succeeded for retained ref
  `refs/heads/candidate/p1-v3-6bde86be91c3` at exact source
  `6bde86be91c3f5197f347b42a481fa397b92aade`. Both tarballs, the canonical
  manifest, checksums, SRI values, and all three GitHub attestations were
  independently verified. npm `next`/`latest` were not invoked.
- Provider-free rehearsal passed with 108 initials, 12 deterministic retries,
  two discarded fake canaries, zero network/provider calls, and
  `claim_allowed=false`.
- The first live root completed `prepare`, then terminally accounted one failed
  `legacy_trim` canary. It reported `Not logged in`; provider API duration,
  input/output tokens, and cost were all zero. Provider-free follow-up proved
  the operator's normal exact CLI was logged in and isolated the cause to the
  runner's empty HOME/`CLAUDE_CONFIG_DIR`, not the account.
- The failed root exposed a provider-free closure bug: `analyze` refused the
  terminal failed canary instead of writing the promised P1-X. The minimal fix
  now emits a ledger-bound `failed_canary_terminal_evidence` P1-X without
  replay. Full offline verification after the fix passed: `1561` tests,
  `3` skips, `prepublish check: OK`.
- The source now differs from candidate `6bde86be...`; one new reviewed
  immutable candidate is required before another live `prepare`.
- The operator approved exact-CLI internal reuse of the existing first-party
  login and increased the cumulative consumed/reserved identity ceiling from
  218 to 219 on 2026-08-10. One identity is already terminally accounted; the
  fresh root may therefore execute its unchanged maximum 218 identities.

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

Across the original stopped root and a fresh complete root, the newly approved
cumulative ceiling is 219 identities and the arithmetic ceiling is `$164.25`.
The fresh root itself remains capped at 218 identities and `$163.50`; the
already-accounted failed canary recorded `$0`.

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

Existing-login mode is explicit. The runner invokes the exact bound CLI's local
`auth status --json`, retains only the safe auth method/provider fields and
domain-separated hashes of the private identity fields and canonical HOME path,
and never persists email or organization text. Provider processes receive that
bound HOME so the exact CLI can use its existing first-party login; XDG/cache/
tmp remain per-attempt, `CLAUDE_CONFIG_DIR` is omitted, user settings are
excluded by `--setting-sources project`, and credential-shaped environment
variables remain forbidden. Codex does not directly read or print auth files,
keychain values, tokens, cookies, email, or organization identity.

This is a trusted-host boundary, not an OS filesystem sandbox. The exact CLI and
its allowed tools execute as the operator account, so the live run is limited to
the frozen synthetic prompts, exact candidate, and owner-controlled host. A
strict hostile-model filesystem isolation claim is unavailable.

The runner must continue to:

- strip credential-shaped environment variables;
- never directly inspect `.env`, auth files, keychains, npm credentials, Claude
  credential values, cookies, or unrelated user settings;
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
3. Run provider-free `prepare` with the exact native Claude executable and the
   explicit `--study-v2-use-existing-login` gate. Bind the safe auth projection,
   private identity digest, and HOME identity without persisting identity text.
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
   canonical `P1-X` invalid decision for a stopped ambiguous root or terminal
   failed canary.
7. Keep `claim_allowed=false` and report the P1 feasibility verdict. No
   successful subset or universal savings statement is allowed.

Immediate stop conditions:

- candidate, CLI, runtime, fixture, checker, settings, or environment drift;
- canary lifecycle/hook/checker failure;
- credential-shaped environment leakage, auth/HOME drift, or unexpected
  external access;
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
      `sonnet`, cumulative ceiling 219 consumed/reserved identities across the
      stopped and fresh roots, `$0.75` per-process CLI caps, fresh-root maximum
      `$163.50`, cumulative arithmetic maximum `$164.25`, and explicit exact-CLI
      internal reuse of the bound existing first-party login under the prompt/
      data boundary and stop rules above.
- [x] npm candidate workflow for the exact approved commit.
- [ ] npm publication of the exact pair to `next`.
- [ ] npm promotion of that exact reviewed pair to `latest`.

The original approvals were recorded on 2026-08-09; auth reuse and the expanded
identity ceiling were recorded on 2026-08-10. `next` and `latest` remain blocked.
No credential value may be shown to or inspected by Codex; the exact CLI
consumes the existing login internally without exposing values.
