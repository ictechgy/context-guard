# Changelog

All notable changes for the ContextGuard plugin are documented here.

## [Unreleased]

- Added an explicit `context-guard experiments emit context-diff-compaction --receipt-id ... --reexpand-command ...` runtime for caller-supplied compact diff replacements gated by exact local artifact content matching the input diff plus re-expand metadata.
- Added an explicit `context-guard experiments record self-hosted-metrics-ledger --ledger-jsonl ...` runtime for local self-hosted metrics sidecar rows while keeping dry-run previews read-only and hosted API savings claims disallowed.

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
