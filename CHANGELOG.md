# Changelog

All notable changes for the Claude token optimizer plugin are documented here.

## [0.1.0] - 2026-05-27

- Initial marketplace-ready Claude Code plugin packaging for token reduction helpers, statusline integration, large-read guards, repeated-failure nudges, transcript auditing, and setup planning.
- Recommended setup enables the repeated-failure nudge by default, with `--no-failed-attempt-nudge` for projects that prefer a quieter hook set.
- Added release gates for source/plugin binary parity, manifest consistency, package cleanliness, Python compilation, shell syntax checks, full regression tests, and staged plugin smoke execution.
- Hardened helper execution and file handling around symlink rejection, no-follow/nonblocking reads, bounded subprocess output, process-group teardown, diagnostic redaction, and owner-only setup/config writes.
- Documented the release runbook, evidence checklist, rollback policy, and clean-install smoke expectations used before publishing.
