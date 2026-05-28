# Changelog

All notable changes for the Claude token optimizer plugin are documented here.

## [0.1.1] - 2026-05-29

- Hardened skill `allowed-tools` so arbitrary command wrappers are no longer granted from plugin skill frontmatter.
- Made setup helper resolution, hook deduplication, and settings writes safer against PATH hijacking, basename collisions, and lost updates.
- Tightened Bash rewrite, read guard, artifact escrow, benchmark, audit, trim/sanitize, and statusline paths with fail-closed behavior, bounded reads, symlink/TOCTOU checks, and stronger redaction.
- Expanded release gates and regression coverage for the quad-review hardening findings.

## [0.1.0] - 2026-05-29

- Initial marketplace-ready Claude Code plugin packaging for token reduction helpers, statusline integration, large-read guards, repeated-failure nudges, transcript auditing, and setup planning.
- Recommended setup enables the repeated-failure nudge by default, with `--no-failed-attempt-nudge` for projects that prefer a quieter hook set.
- Recommended setup now runs a read-only post-apply `claude-token-diet scan` and prints a summary by default, with `--no-diet-scan` for automation that only wants settings changes.
- Added release gates for source/plugin binary parity, manifest consistency, package cleanliness, Python compilation, shell syntax checks, full regression tests, and staged plugin smoke execution.
- Hardened helper execution and file handling around symlink rejection, no-follow/nonblocking reads, bounded subprocess output, process-group teardown, diagnostic redaction, and owner-only setup/config writes.
- Documented the release runbook, evidence checklist, rollback policy, and clean-install smoke expectations used before publishing.
- Polished release README guidance to frame the plugin as a conservative local context-hygiene toolkit and avoid unmeasured fixed-savings claims.
