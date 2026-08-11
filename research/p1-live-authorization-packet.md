# P1 live-study and npm-release authorization packet

_Drafted: 2026-08-09 KST; amended with explicit auth reuse, stopped-root
checkpoints, the exact 264-identity v6 ceiling approval on 2026-08-10 KST,
and the exact 307-identity v7 and 388-identity v8 ceiling approvals on
2026-08-11 KST_

This packet is the controlling scope for the authorization recorded on
2026-08-09. Approved actions are repository-scoped GitHub activity, candidate-
only construction for the selected commit, and the bounded P1 Claude study.
Not approved are npm `next`, npm `latest`, artifact deletion, P2-P6 provider
activity before P1-F, broader credential/data access, or any action outside
this packet.

## Current readiness verdict

- PR #287 merged the v3 accounting/budget hardening; PR #288 merged the bounded
  GitHub-hosted runtime normalization required by the candidate workflow.
- Replacement candidate run `31345333296` succeeded for retained ref
  `refs/heads/candidate/p1-v4-af93dca64cfd` at exact source
  `af93dca64cfdbbba231e577b9226497b720f9d92`. Both tarballs, the canonical
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
  replay. Full offline verification after the fix passed: `1564` tests,
  `3` skips, `prepublish check: OK`.
- A second fresh root prepared that exact candidate and reused the bound login
  successfully. Its first `legacy_trim` canary reached the provider and emitted
  a valid host `PreToolUse(Bash)` lifecycle, but MiniShell-v1 correctly denied
  the prompt's active `printf ... > file` redirection. The marker checker
  failed, provider-free `analyze` emitted P1-X, and no second canary or analytic
  identity launched. The root is permanently closed.
- That second identity consumed `$0.07436490000000001` and reported 4 input,
  9,095 cache-creation, 56,943 cache-read, and 137 output tokens. Together the
  two stopped roots account for two identities. The current source replaces
  the denied redirection with an already-supported exact `python3 -c` marker
  write and adds real-hook/fake-host denial regressions, so it again requires a
  reviewed immutable candidate before another live `prepare`.
- The operator approved exact-CLI internal reuse of the existing first-party
  login and increased the cumulative consumed/reserved identity ceiling from
  218 to 219 on 2026-08-10. Two identities are now terminally accounted, so
  only 217 remain under that approval. A new complete root still requires up to
  218 identities and is not authorized unless the cumulative ceiling is
  explicitly raised to at least 220.
- A later root bound to merged source `db415c7...` passed both live canaries,
  then terminally accounted 42 analytic initials before candidate-overlay
  bytecode drift stopped all later launches. Across all stopped roots and
  canaries, 46 identities are consumed/reserved and none remain open.
- PR #292 merged the provider-free closure as `0b35a8cb...`; candidate run
  `31357316775` attempt 2 attested its exact package pair. The user has now
  approved one fresh v6 root under the unchanged study shape below, raising
  the cumulative ceiling from 220 to exactly 264 identities. This grants at
  most 218 new identities, each capped at `$0.75`, for a fresh-root arithmetic
  maximum of `$163.50`. It does not authorize replay of an old root, optional
  stopping, npm publication, or active P2-P6 work before P1-F.
- Fresh root `/private/tmp/contextguard-p1-live-v6.MS256a` passed provider-free
  prepare and both host-mediated canaries, then terminally accounted 41
  analytic initials before the baseline long-log call stopped the root as
  `invalid_stream`. Provider-free analyze wrote canonical P1-X
  `cf09039a...`; there are no ambiguous or open identities and no retry ran.
  The exact CLI stream contained a valid successful result followed by three
  same-session background-task shutdown events. The frozen runner's older
  post-result rule rejected that tail. The root is permanently closed and is
  not eligible for reinterpretation or replay.
- This root consumed 43 identities including its two discarded canaries.
  Cumulative accounting is now 89/264, leaving 175. A new maximum-size root
  would require a separately approved cumulative ceiling of at least 307 and
  a new finite call/spend freeze.
- PR #294 merged the bounded parser repair as
  `5bf699bd0583e0a9b07ffa4061509e2a59c18644` after CodeRabbit and all three
  hosted CI jobs passed. Candidate run `31396910541` then built, paired-smoked,
  attested, and uploaded the exact package pair. Its manifest SHA-256 is
  `88670200df9bce48c5565056222d2c7b46408b6fd6b2c19d5141222b7408187d`;
  root tarball SHA-256 is `fce705266ad98f2daba008a35f31c804d260f4128736fc180ac6a47335a67194`;
  Receipt remains `ec00b91dc8eebce14a676d0a48f1250edefe33fb1d5d57fcf37b0b7584b79ec0`.
  All three downloaded subjects passed GitHub attestation verification. No npm
  registry publish or dist-tag mutation occurred.
- On 2026-08-11 the user approved one fresh v7 root under the unchanged study
  shape below, raising the cumulative consumed/reserved ceiling from 264 to
  exactly 307. The grant retains the 89 terminal identities and authorizes at
  most 218 new identities: two discarded canaries, 108 initials, and up to 108
  policy-valid retries. The model remains `sonnet`, every process remains
  capped at `$0.75`, and the fresh-root arithmetic maximum remains `$163.50`.
  Old-root reuse, replay, optional stopping, npm publication, and active P2-P6
  work before P1-F remain forbidden. The mode-0600 authorization evidence has
  SHA-256 `834214b36d30bb6c3a1174a37f073c2af84c65724f66d7f8247efd9bb71b0e76`.
- PR #296 merged the packet as `16a71ac...`; exact candidate run
  `31406020654` passed and produced verified immutable artifacts without an npm
  publish or dist-tag mutation. Fresh v7 root
  `/private/tmp/contextguard-p1-live-v7.jd6MT4` passed both canaries, consumed
  79 analytic identities, and then stopped on an `error_max_turns` result that
  the bound attempt-v3 runner classified as infrastructure-invalid. Analysis
  wrote claim-disabled P1-X `80387242...`; the root has no ambiguous identity
  and is permanently closed.
- V7 consumed 81 identities including canaries. Cumulative accounting is now
  170/307, leaving 137; therefore this authorization grants no further provider
  call. A fresh maximum-size root would require a new finite freeze and an
  explicit cumulative ceiling of at least 388. Provider-free attempt-v4 TDD
  repairs the bounded-failure classification for a future reviewed candidate,
  but does not alter, migrate, resume, or reinterpret the v7 P1-X record.
- On 2026-08-11 the user approved one fresh v8 root under the unchanged finite
  study shape below, raising the cumulative consumed/reserved ceiling from 307
  to exactly 388. The grant retains all 170 terminal identities and authorizes
  at most 218 new identities: two discarded canaries, 108 initials, and up to
  108 policy-valid retries. The model remains `sonnet`, every process remains
  capped at `$0.75`, and the fresh-root arithmetic maximum remains `$163.50`.
  Old-root reuse, replay, repair, migration, optional stopping, npm publication,
  and active P2-P6 work before P1-F remain forbidden. Integrity, privacy,
  ambiguity, or spend failure must immediately close the root to provider work
  and produce the canonical claim-disabled P1-X.
- PR #298 merged the provider-free P2-P6 evaluator as `d4b6302...`; candidate
  run `31457488674` passed for that exact merge and its downloaded manifest and
  tarballs passed paired smoke and attestation verification. Because this
  authorization amendment changes the selected source revision, that earlier
  candidate is delivery evidence only and cannot be reused for v8. A new
  reviewed merge, retained ref, and exact candidate are required before live
  `prepare`.

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

The approved cumulative ceiling is exactly 388 identities. One hundred seventy
identities are already terminally consumed/reserved, leaving exactly 218 for
one fresh maximum-size root. No identity beyond the ceiling and no second fresh
root are authorized. The implementation must stop immediately on the frozen
integrity, privacy, ambiguity, or spend conditions rather than trying to
consume the ceiling.

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
- [x] Claude live study authority: executable above, `sonnet`, cumulative
      ceiling exactly 388 consumed/reserved identities, `$0.75` per-process
      CLI caps, and explicit exact-CLI internal reuse of the bound existing
      first-party login under the prompt/data boundary and stop rules above.
      One hundred seventy identities are terminally accounted; exactly 218
      remain for one fresh v8 root under the frozen shape and stop rules.
- [x] npm candidate workflow for the exact approved commit.
- [ ] npm publication of the exact pair to `next`.
- [ ] npm promotion of that exact reviewed pair to `latest`.

The original approvals were recorded on 2026-08-09; auth reuse and the v6
ceiling were recorded on 2026-08-10; the exact v7 and v8 ceilings were recorded
on 2026-08-11. `next` and `latest` remain blocked. No credential value may be shown
to or inspected by Codex; the exact CLI consumes the existing login internally
without exposing values.
