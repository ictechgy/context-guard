# Changelog

All notable changes for the ContextGuard plugin are documented here.

## [Unreleased]

- Added a passive full-wire budget gate that compares complete
  baseline and candidate request envelopes under one canonical-byte ceiling.
  The shipped surface is `context-guard-receipt evaluate full-wire`; it detects
  protected JSON-pointer changes and output-budget growth, reports cache-prefix
  preservation diagnostically, and never emits or stores request content.
- Added provider-free HMAC-only cost calibration that joins preflight and
  observation rows, emits integer input/cache/output corrections only after a
  declared sample floor, and never grants automatic routing authority.
- Added additive shadow-only total-cost router v2 accounting for provider
  input/output, cache, expansion, retry, helper, and local cost while preserving
  the existing byte router contract.
- Added the task-scoped `receipt_pack` MCP tool for bounded multi-file evidence
  packs and exact deferred expansion, plus session-stable tool profiles that
  reuse one catalog snapshot and reject profile drift.
- Bumped the independent Receipt companion to 0.3.0 and updated the root exact
  dependency and package trust manifest for the new public contracts.

## [0.8.0] - 2026-08-27

- Added an opt-in `--graph-cache` flag to `context-guard-pack auto` that
  caches deterministic graph-rank/repo-map explain metadata, keyed to a
  clean git commit, worktree/query, with content-hash self-authentication,
  TTL expiry, and a bounded quota with oldest-first eviction.
- Hardened `--graph-cache`: the cache key no longer depends on the
  worktree's absolute filesystem path (two clean checkouts of the same
  commit/content now share one cache entry); a symlinked
  `CONTEXT_GUARD_GRAPH_CACHE_DIR` is never followed (the cache is bypassed
  for that invocation instead of writing through it); `--explain` now
  reports a machine-readable `repo_map_cache` receipt (`hit`,
  `graph_cache_key`, `resolved_content_sha256`, `ttl_expires_at`).
- Added `--graph-cache-ttl-seconds` to override the fixed default cache
  expiry window for a single invocation.
- Added `--graph-impact-scope` (with `--graph-impact-scope-depth`, default
  1): used together with `--diff`, reports which other files are within N
  import-edge hops of the diff's changed files as additive
  `explain.repo_map.graph.impact_scope` metadata.
- Bound `receipt_expand` to an optional caller-declared `task_scope`,
  matching the same scope-commitment check `receipt_context` already
  applies - plumbing only, no current issuer populates a scope yet.
- Added `runner_result_summary`, a purely additive trim-output digest
  field that recognizes pytest's and cargo test's own terminal aggregate
  summary line regardless of exit code, so a large successful run gets the
  same structured digest benefit a failing run already had.

## [0.7.1] - 2026-08-24

- Hardened three context-guard-kit security surfaces: `run_guarded_git()` now
  resolves `git` through the fixed-path approved-runtime-executable resolver
  instead of a PATH lookup, `FallbackLineSanitizer` gained PEM private-key
  block and Cookie header redaction plus a corrected userinfo-credential
  regex, and adjacent wrapper scripts are opened with `O_NOFOLLOW` before use
  to reject a pre-planted symlink.
- Corrected `sanitize_output.py`'s docstring to accurately describe that
  `anonymize_paths_for_context()` is a deliberate no-op for `unknown_text`/
  `source_code` contexts (behavior unchanged).

## [0.7.0] - 2026-08-22

- Added a zero-provider-context advisory mode for WeightClass-style routing.
  Small tasks bypass without standing instructions, while larger tasks select
  only locally eligible log trimming, symbol slicing, adaptive packing, or
  cached graph expansion candidates that pass the configured gross-byte floor
  and local-overhead budget. Those gates do not guarantee provider token or
  cost savings. The bounded sample harness now counterbalances arm order,
  charges preprocessing per advisory run, rejects ambiguous usage and cache
  accounting, and keeps invalid historical measurements excluded.
- Kept live Claude collection behind safe mode, an empty tool surface, trusted
  executable ancestry, a minimal non-redirectable environment, exact quality
  checks, and explicit provider-egress confirmation. Live Codex collection
  fails closed before local or provider action until the subscription CLI has
  a preventive no-tools mode; provider-free Codex planning remains available.
- Hardened Homebrew formula verification through an isolated temporary tap,
  preserved pre-existing installation state, rendered release-safe formula
  syntax, and registered the formula template as an explicit support surface.

## [0.6.0] - 2026-08-21

- Added a provider-free `context-guard-receipt evaluate phase` surface with
  closed P2-P6 input/result schemas. It computes shadow/canary/router/adjunct/
  specialized-track readiness from bounded canonical local records while
  keeping runtime activation, generalization, provider calls, and savings
  claims disabled behind the existing sequential phase gates.
- Changed the discarded v2 Bash canary's fixed marker write from denied shell
  output redirection to an existing MiniShell-v1-supported `python3 -c` route.
  Both real hook modes now guard the exact command in provider-free tests, and
  the offline fake host honors hook denials before creating any marker.
- Added an explicit `--study-v2-use-existing-login` gate for executable v2
  provider actions. `prepare` now verifies and pseudonymously binds the exact
  first-party Claude login plus its owned, non-writable HOME identity without
  persisting email or organization text. Every provider reservation rechecks
  that binding, keeps XDG/session paths isolated, excludes credential-shaped
  environment variables, and omits `CLAUDE_CONFIG_DIR`; `analyze` remains
  provider- and auth-independent.
- Bound both discarded v2 Bash-routing canary calls to the same hard `$0.75`
  per-call Claude CLI budget as each analytic task. The value is part of the
  immutable canary contract, so prepare/resume rejects drift; the frozen study's
  218 consumed/reserved identities imply a `$163.50` arithmetic maximum. The
  CLI enforces each process cap; there is no separate aggregate CLI limiter.
- Published the sanitized result of the first frozen 12-task live study. The
  study is explicitly `inconclusive`: one arm-unit exhausted its fixed retry,
  no favorable subset or correction assessment was analyzed, and no token or
  cost savings claim is allowed.

## [0.5.1] - 2026-08-19

- Bounded context-pack source, diff, and non-Git traversal input before
  allocation; made Markdown evidence fences content-derived; and reused one
  immutable source snapshot across suggest/build so representative pack latency
  falls from tens of seconds to sub-second without changing ordinary pack bytes.
- Pinned automatic hook and statusline runtimes instead of trusting ambient
  `PATH`, Python startup variables, shell startup variables, or executable
  overrides, while retaining setup-approved OMC integration.
- Added the backward-compatible Receipt external-approval v2 envelope whose
  scope truthfully binds manual owner cleanup, plus bounded V4 authorization
  lock waits, read-only ledger snapshots, cached immutable selection artifacts,
  and shared V3/V4 failure conformance tests.
- Preserved sparse token availability in the Mac consumer and added the
  provider-live test directory to the release gate.

## [0.5.0] - 2026-08-06

- Added the default-off Claude Code `PreToolUse:Bash` reference route. After
  strong local sanitization, long merged command output can stay in a private
  project-local Receipt store while the transcript receives a compact,
  exact-retrieval handle and an executable `context-guard reference` command.
  Retrieval derives private state internally and pages exact UTF-8 output in
  fixed 20,000-byte-or-smaller chunks, so resolving a handle cannot replay the
  complete 10 MB capture in one turn. The legacy trim route and unchanged route
  remain deterministic fallbacks; source/plugin-only installs cannot enable
  this npm-only mode.
- Added the independently versioned `@ictechgy/context-guard-receipt@0.2.0`
  exact dependency, fixed seven-day reference expiry, bounded authenticated
  import recovery journal, 10,000,000-byte merged capture ceiling, and
  expired/revoked reference refusal. Installation and disablement never erase
  stored artifacts automatically.
- Added an executable three-arm study across `host_unmodified`, `legacy_trim`,
  and `bash_reference_v1`, with an explicit `prepare` → `canary` → `run`/`resume`
  → `analyze` lifecycle. `prepare` binds the CLI and runs local
  `--version`/`--help` probes without a model request. Provider/model requests
  occur only during canary and analytic execution. A separate provider-free
  offline rehearsal exercises the lifecycle with a native fake CLI. The study
  binds a fixed 12-task corpus and reports the legacy contrast diagnostically;
  without an independent power model the result is descriptive-only and cannot
  authorize a savings claim.
- Added build-once npm candidate manifests, exact cross-package hashes/SRI,
  paired clean-install discovery smoke, separate trusted publication to
  `next`, and preflight/rollback-aware promotion to `latest`. No package is
  published or promoted automatically by this release.

## [0.4.16] - 2026-08-01

- Sanitizer output-scanning is now one monotonic left-to-right pass. All nine location-prefix consumers previously re-parsed the same optional `path:line:` fragment at every offset, which made lines with few colons quadratic: a single 82,015-byte line took 2.62 s and a 100,014-byte line took 3.98 s. The leading prefix is identified once and the seven unanchored consumers run as fragment-free twins, while the two `^`-anchored header consumers keep their original patterns because they were never a per-offset cost. The same lines now take 64.3 ms and 0.078 s, with doubling ratios of 1.84 to 2.01. Redaction output is byte-identical to the previous implementation, pinned by a differential oracle against a hash-frozen baseline across eleven corpora, three sanitization contexts, both path-display modes, and both shared-state and per-line runs.
- `context-guard-trim-output --digest` no longer inflates small output. When a command succeeds and its output is already smaller than the digest would be, the output is passed through with a one-line marker; a 19-byte output previously produced a 461-byte markdown digest or a 755-byte JSON digest. A failing command always keeps the digest, because that is where the exit code and failure signature live, and requesting `--artifact-receipt` always keeps it too. Pass `--digest-always` to force the structured digest in every case.
- Both READMEs now document the standing per-request cost of the advisory rule blocks (`brief-mode.lite` 1,487 bytes, `brief-mode.standard` 1,568, `brief-mode.ultra` 1,523, `narration-mode.quiet` 866) and frame that size as the break-even threshold a reply-length reduction has to clear. Hook guardrails are contrasted honestly: they charge only when they act, and a sub-threshold `Read` adds 3 bytes.
- Added a default-off, Claude-only quiet-narration rule managed through a dedicated rules-only setup path. It suppresses discretionary narration while preserving approvals, blockers, failures, safety warnings, final results, changed files, and verification; it does not activate settings or hooks or claim guaranteed savings.
- Benchmark measurement substrate for the planned token-savings study: scheduling, accounting, resume, and inference surfaces plus a real twelve-task fixture suite with out-of-workspace success checkers and a zero-cost seventy-two-run fake-provider rehearsal. These are measurement-enabling only. No provider-measured token or cost savings are claimed, and the rehearsal explicitly records that its own token counts are scripted local fixtures.

## [0.4.15] - 2026-07-15

- Added conservative plan-only and evaluation-only proof-carrying-context, semantic-GC, and image-context-pack surfaces without enabling automatic omission, renderer/OCR/provider/proxy execution, promotion authority, or hosted savings claims.
- Added deterministic matched image-context benchmark fixtures and the optional `contextguard.bench.image-context-pack-evaluation.v1` profile with prompt binding, imported fallback attestation, protected-zone review, missed-context/correction checks, provider/shifted-cost agreement, prewrite rejection, and authority clamps.
- Added local proof verification, content-addressed pack and rolling-delta metadata, an opt-in sketch duplicate veto, local stdio MCP compress/retrieve/stats middleware, and bounded caller-supplied static relevance evidence.
- Expanded hostile-input, concurrency, source/package parity, release-smoke, and cross-platform regression coverage while preserving default-off, local-first, no-new-dependency behavior.

## [0.4.14] - 2026-07-10

- Added the default-off `semantic-checkpoint` experimental planning gate with deterministic readiness payloads, explicit scope/metric/rollback validation, prompt-cache caveats, and hosted-savings claim boundaries.
- Documented semantic-checkpoint as a plan-only roadmap lane across README/plugin materials and updated the experimental token-reduction radar.
- Expanded regression coverage for semantic-checkpoint validation, preview truncation, config isolation, and plugin copy synchronization.

## [0.4.13] - 2026-06-22

- Kept the Bash rewrite hook stdout JSON-parseable while routing sanitizer-worthy read-only pipelines through `context-guard-sanitize-output`.
- Preserved fail-closed handling for side-effecting shell operators, redirections, here-strings, `tee`, network commands, environment-prefixed filters, and file-reading/writing filter options.

## [0.4.12] - 2026-06-22

- Published the post-merge README, Korean README, and GitHub Pages copy polish into the npm/package metadata so package consumers see the same setup, packaging, helper-trust, and conservative savings-claim guidance as the product site.

## [0.4.11] - 2026-06-21

- Hardened token-savings advisory surfaces with cache-score amortization risk accounting, tool-prune deferred-schema proxy accounting, and benchmark measurement-baseline contracts while preserving claim-safe boundaries.
- Added benchmark evidence replay dashboards, default matrix reporting, and public claim readiness gates so public savings claims remain blocked unless matched successful tasks, provider-measured tokens/cost, quality non-inferiority, shifted-cost accounting, confidence notes, and complete provider-export provenance all pass.
- Added output artifact sandbox receipts and local artifact search with stable `contextguard-artifact:<id>` handles, compact summaries, exact rehydration commands, custom-dir path redaction, and no hosted savings claims.
- Added local-proxy response sandbox envelopes for safe UTF-8 loopback responses, plus docs and safety tests that keep proxy behavior one-shot, literal-loopback, credential-free, and non-claimable for hosted token/cost savings.
- Productionized adaptive context packing as explicit `--adaptive-k` policies and `--symbol-memory` source-verification metadata without automatically changing manifests, packs, receipts, or provider-savings claims.
- Hardened large-input processing bounds, private helper IO, adjacent helper loading, release smoke execution, and symlink/no-follow handling for artifact, tool-prune, benchmark, setup, and related helper paths.
- Constrained release and runtime command manifests to literal-only data, kept legacy `claude-*` wrappers packaged but out of npm `.bin` aliases, and locked npm/package smoke checks to canonical `context-guard`/`context-guard-*` entrypoints.
- Constrained macOS visibility helper discovery to bundled/resource/executable-relative paths or absolute explicit overrides, removed launch-CWD trust, rejected relative overrides, and launched the helper with a minimal allowlisted child environment.
- Polished README, Korean README, and GitHub Pages copy after Claude review so setup, packaging, helper trust, and conservative savings-claim boundaries match the shipped product.

## [0.4.10] - 2026-06-14

- Added `context-guard-artifact search`, a local sanitized artifact sandbox search that returns capped literal matches with exact `get --lines` rehydration commands and no hosted savings claims.
- Added `context-guard-pack suggest/auto --adaptive-k` selectable local policies (`--adaptive-k-policy balanced|recall|precision`), metadata-only recall/precision proxy gates, capped selected/omitted evidence, and structured source-verification hints without changing manifests, packs, receipts, or claiming provider-token savings.
- Added `context-guard-pack auto --symbol-memory`, an opt-in repo-map-derived symbol/graph advisory with exact source verification hints that does not change manifests, packs, receipts, or provider-savings claims.
- Added `context-guard-compress --mode readable`, an opt-in sanitized-prose readable preview mode with high-risk protected/prompt-like signal blocking, exact fallback guidance, and no learned compressor/model/embedding/reranker execution.
- Added `context-guard-cache-score`, a static local prompt cacheability lint with char/4 proxy labeling, provider caveats, dynamic-prefix warnings, and no provider calls, ledger writes, or savings claims.
- Extended `context-guard-tool-prune` with `defer-report` for core-vs-deferred tool schema planning backed by the existing sanitized receipt/payload retrieval path.
- Added a fixture-only token-savings 12-task benchmark starter and executable report-shape tests that preserve matched-task, shifted-cost, and proxy-byte claim boundaries.
- Hardened release gates with isolated npm install smoke, CI Node setup, full unittest discovery, Homebrew template stale-version checks, and explicit CI/subprocess timeouts.
- Hardened `context-guard experiments serve local-proxy` with a private ready-file nonce handoff that rejects missing, duplicate, or invalid nonce headers before forwarding and keeps the raw nonce out of public output and upstream requests.
- Hardened `context-guard-filter` config loading with bounded no-follow regular-file reads, nonblocking FIFO/device rejection, and fail-closed unsupported-platform checks.
- Hardened artifact escrow writes with parent-traversal rejection, dir-fd/no-follow private directories, 0600 temp files before atomic replace, and explicit pre/post-replace fsync failure semantics.
- Disabled setup helper `PATH` fallback by default; trusted fallback now requires `--allow-path-helper-fallback`, canonical no-symlink executable paths, and a bounded helper identity probe.
- Polished README, Korean README, and GitHub Pages copy after Claude review while preserving local-only/passive boundaries, install-vs-activation separation, and conservative token/cost claim wording.

## [0.4.9] - 2026-06-12

- Added `context-guard experiments plan local-proxy-external-forwarding`, a design-only dry-run gate for future external forwarding proposals with explicit intent, HTTPS allowlist, threat model notes, credential redaction policy, provider-evidence boundary, and no DNS lookup, external service call, traffic forwarding, credential persistence, or hosted savings claim.
- Added optional `context-guard experiments serve local-proxy --diagnostic-ledger-jsonl ...` shifted-cost diagnostic rows for successful literal-loopback forwarded requests without raw headers, bodies, credential persistence, external forwarding, or hosted savings claims.
- Added an explicit `context-guard experiments serve local-proxy ...` one-shot loopback forwarding MVP that requires runtime and forwarding acknowledgements, literal loopback bind/target IPs, bounded bytes/timeouts, and credential-free requests while keeping external forwarding, CONNECT/TLS proxying, API-key persistence, and hosted savings claims disallowed.
- Added a hidden diagnostic readiness receipt for local-proxy serve tests and kept listener startup deterministic on macOS by avoiding reverse-DNS during bind.
- Added an explicit `context-guard experiments record local-proxy-runtime-gate --ledger-jsonl ...` runtime that appends one localhost-only gate row without starting listeners, forwarding traffic, performing DNS lookup, persisting API keys, calling external services, or making hosted savings claims.
- Added an explicit `context-guard experiments emit learned-compression ...` runtime that emits only caller-supplied compact prose candidates after deny-by-default protected-signal checks and verified exact local fallback content, without running compressors/models or making hosted savings claims.
- Added an explicit `context-guard experiments emit visual-crop-ocr ...` runtime that emits local caller-supplied visual crop/OCR evidence packs while preserving full evidence receipts, missed-context guardrails, no-service boundaries, and hosted savings claim denial.
- Added an explicit `context-guard experiments emit context-diff-compaction --receipt-id ... --reexpand-command ...` runtime for caller-supplied compact diff replacements gated by exact local artifact content matching the input diff plus re-expand metadata.
- Added an explicit `context-guard experiments record self-hosted-metrics-ledger --ledger-jsonl ...` runtime for local self-hosted metrics sidecar rows while keeping dry-run previews read-only and hosted API savings claims disallowed.
- Polished the English and Korean README release guidance so install, experiment, and claim-boundary wording match the shipped product.

## [0.4.8] - 2026-06-11

- Hardened experimental registry config writes with same-directory atomic replace so failed writes or symlink swaps do not truncate or redirect the live config.
- Hardened dispatcher version metadata reads with dir-fd no-follow parent traversal to close parent symlink races.
- Preserved bounded filter passthrough ordering without holding the capture state lock during emission.
- Serialized context pack sanitizer factory first load and added focused race/failure regression coverage.
- Kept plugin bin mirrors synchronized for the updated helper hardening.

## [0.4.7] - 2026-06-11

- Added default-off experimental opt-in registry surfaces for future token-reduction lanes, preserving project-local intent without enabling runtime behavior.
- Added dry-run checker/planner gates for context-diff compaction, visual crop/OCR metadata, learned compression safety policy, self-hosted metrics ledger previews, and local-proxy advisory metadata.
- Hardened experimental planners with deny-by-default validation, redaction, exact fallback/receipt requirements, localhost-only proxy constraints, and claim boundaries for hosted API savings.
- Updated README, Korean README, and GitHub Pages copy to document experimental opt-ins, non-shipped runtime boundaries, and evidence/future-PR gates.

## [0.4.6] - 2026-06-10

- Hardened local cost ledger/key storage against symlink traversal, unsafe permissions, and partial writes while improving recent-ledger loading performance.
- Replaced Pages publishing with least-privilege GitHub Pages artifact deployment and pinned first-party Actions.
- Hardened the macOS audit adapter execution boundary, output caps, temp directory permissions, and Swift CI coverage.
- Made context pack outputs and receipts use atomic same-directory writes.
- Added `scripts/sync_plugin_copies.py` so duplicated plugin bin/lib copies are reproducible, symlink-safe, mode-checked, and covered by release gates.

## [0.4.5] - 2026-06-09

- Added a package-visible `mac_visibility` feasibility contract for future local macOS-visible surfaces without building a GUI or inferring live headroom from historical transcript scans.
- Clarified README, plugin README, kit README, and GitHub Pages measurement boundaries for self-hosted metrics sidecars, benchmark evidence, mac visibility contracts, and experimental fixtures.

## [0.4.4] - 2026-06-08

- Added top-level `cache_layout_advice` to transcript audit JSON and feasibility output so cache-prefix instability can be prioritized without mixing advice into evidence-only diagnostics.
- Documented the `cache_layout_advice` consumer contract and conservative cause boundaries for volatile-prefix findings.
- Refined cache-prefix recommendation wording after quad-review so advice does not overclaim cache reads or session-splitting evidence.

## [0.4.3] - 2026-06-08

- Fixed the Homebrew formula template so packaged helper paths are handled as Pathname objects during install.
- Supersedes the unpublished `0.4.2` npm candidate after Brew install validation caught the formula issue.

## [0.4.2] - 2026-06-08

- Polished Korean README, plugin README, kit README, and GitHub Pages copy with Claude-assisted proofreading while preserving conservative token/cost claim boundaries.

## [0.4.1] - 2026-06-05

- Publish the cross-agent distribution release under a fresh npm version because `0.4.0` is unavailable on the registry while still returning a public 404.

## [0.4.0] - 2026-06-04

- Added budgeted context packs with prioritized local evidence, bounded receipts, safe slice retrieval hints, and explicit proxy-token labeling.
- Added tool/MCP schema pruning that emits bounded top-k advisory reports while keeping full sanitized schemas retrievable from local receipts.
- Added conservative stdin compression helpers for JSON, diff, logs, search output, code, and prose with observed byte evidence and estimated token proxies.
- Expanded context hygiene scanning across multi-agent rule surfaces, context-exclusion recommendations, and bounded scanner reporting.
- Improved artifact receipts, benchmark evidence gates, cache-friendliness diagnostics, and redaction safeguards so savings claims remain measured and conservative.
- Added brief-mode rule snippets and refreshed README/GitHub Pages copy for broader AI-tool positioning without fixed token-savings promises.

## [0.3.1] - 2026-06-01

- Fixed setup migration for upgraded projects that still had legacy `claude-token-*` hook commands, rewriting them to current `context-guard-*` helpers so Claude no longer reports `command not found` hook errors.
- Ensured setup scans all matcher-covering hook entries before deciding a hook is already configured, so later stale legacy entries cannot survive behind an earlier canonical entry.

## [0.3.0] - 2026-06-01

- Added `context-guard-audit --feasibility-json` as a stable local data contract for Mac/GUI visibility prototypes.
- Exposed scan integrity, metric availability, source freshness, redaction mode, and stable token/cost totals while keeping the embedded legacy summary diagnostic and backward-compatible.
- Distinguished missing cache fields from observed zero cache fields and labeled partial scans when transcript files or records are skipped.
- Documented the Mac visibility data-spike findings and limitations for local transcript-derived metrics versus official billing data.

## [0.2.0] - 2026-05-29

- Renamed the public plugin identity to ContextGuard with `/context-guard:*` skills and `context-guard-*` helper commands.
- Kept legacy CLI wrappers (`claude-token-*`, `claude-read-symbol`, `claude-trim-output`, and `claude-sanitize-output`) for existing automation, while documenting that the old `/claude-token-optimizer:*` plugin slash-command namespace is not aliased by Claude Code.
- Preserved artifact query compatibility by letting `context-guard-artifact get/list` read the legacy `.claude-token-optimizer/artifacts` default while new stores use `.context-guard/artifacts`.
- Added legacy-state deny rules and legacy helper detection so setup/diet scans stay clean for users upgrading from the previous naming.
- Updated marketplace install docs to use the renamed GitHub repository slug `ictechgy/context-guard`.

## [0.1.1] - 2026-05-29

- Hardened skill `allowed-tools` so arbitrary command wrappers are no longer granted from plugin skill frontmatter.
- Made setup helper resolution, hook deduplication, and settings writes safer against PATH hijacking, basename collisions, and lost updates.
- Tightened Bash rewrite, read guard, artifact escrow, benchmark, audit, trim/sanitize, and statusline paths with fail-closed behavior, bounded reads, symlink/TOCTOU checks, and stronger redaction.
- Expanded release gates and regression coverage for the quad-review hardening findings.

## [0.1.0] - 2026-05-29

- Initial marketplace-ready Claude Code plugin packaging for token reduction helpers, statusline integration, large-read guards, repeated-failure nudges, transcript auditing, and setup planning.
- Recommended setup enables the repeated-failure nudge by default, with `--no-failed-attempt-nudge` for projects that prefer a quieter hook set.
- Recommended setup now runs a read-only post-apply `context-guard-diet scan` and prints a summary by default, with `--no-diet-scan` for automation that only wants settings changes.
- Added release gates for source/plugin binary parity, manifest consistency, package cleanliness, Python compilation, shell syntax checks, full regression tests, and staged plugin smoke execution.
- Hardened helper execution and file handling around symlink rejection, no-follow/nonblocking reads, bounded subprocess output, process-group teardown, diagnostic redaction, and owner-only setup/config writes.
- Documented the release runbook, evidence checklist, rollback policy, and clean-install smoke expectations used before publishing.
- Polished release README guidance to frame the plugin as a conservative local context-hygiene toolkit and avoid unmeasured fixed-savings claims.
