# Release runbook

This repository ships a Claude Code plugin plus standalone helper entrypoints. Use this runbook before publishing plugin artifacts, merging release-sensitive changes, or cutting a tag.

## Release gates

Run both local gates from the repository root:

```bash
python3 scripts/prepublish_check.py
python3 scripts/release_smoke.py
```

Success sentinels include the following lines; `prepublish_check.py` may also print unittest output first:

```text
prepublish check: OK
release smoke: OK
```

`prepublish_check.py` verifies package invariants, manifest consistency, synchronized plugin binaries, forbidden package artifacts, Python compile checks, and the regression test suite. It must also keep failure diagnostics safe to copy into issues: secret-shaped package artifact names, credential-like path labels, URL userinfo, control-character labels, and maintainer-local override paths should be redacted or summarized rather than printed raw. `release_smoke.py` first stages a clean copy of the plugin package, rejects symlinked package entries, then executes representative packaged plugin entrypoints in a temporary project with isolated `HOME`, `XDG_*`, `TMP*`, and a minimal environment so local credentials or optimizer config cannot affect the result.

## PR release workflow

1. Start from up-to-date `main`.
2. Make one focused, reviewable change.
3. Keep duplicated kit/plugin entrypoints synchronized when a helper changes.
4. Run the local release gates.
5. Commit using the Lore commit protocol.
6. Push a branch and open a PR.
7. Wait for GitHub Actions to pass on all supported Python/platform lanes. The Ubuntu Python matrix keeps the historical `test-and-prepublish (3.11)` / `test-and-prepublish (3.12)` check names; the macOS release lane is `test-and-prepublish (macos-latest, 3.12)`.
8. Run quad review against the PR/diff and save a concise evidence comment on the PR. The comment should list the target hash or commit, which tracks completed, which tracks were unavailable, and whether any blocker findings remain.
9. If any blocker is reported, commit a fix, push it, and re-run CI plus quad review. Do not merge on stale review output from an earlier commit.
10. Merge only after CI is green and quad review has no blocker findings on the latest head.

Claude review track may be unavailable on a machine that has not logged in to the local Claude CLI. Record that as unavailable; do not treat it as approval.

## Evidence checklist

Before merge or publish, capture enough evidence that another maintainer can reproduce the release decision:

- Local commands run and their success sentinels:
  - `python3 scripts/prepublish_check.py`
  - `python3 scripts/release_smoke.py`
- GitHub Actions check names and final status:
  - `test-and-prepublish (3.11)`
  - `test-and-prepublish (3.12)`
  - `test-and-prepublish (macos-latest, 3.12)`
- Quad-review summary:
  - PR number or diff range
  - latest commit hash reviewed
  - redacted target hash when available
  - per-track verdicts and unavailable tracks
  - blocker fix/re-review loop outcome
- Diagnostic hygiene confirmation for release-sensitive changes:
  - no raw tokens, URL userinfo, private local paths, or secret-shaped filenames in new failure output
  - safe package-relative labels remain useful for ordinary non-sensitive artifacts

## Version and manifest checks

Before publishing a versioned artifact, verify:

- `plugins/claude-token-optimizer/.claude-plugin/plugin.json` has the intended version.
- Repository-root `.claude-plugin/marketplace.json` lists the same plugin version and `Apache-2.0` license.
- Repository-root `CHANGELOG.md` contains a release-notes entry for that exact plugin version.
- `scripts/prepublish_check.py` passes without path overrides.
- No generated caches, logs, or symlinks are inside `plugins/claude-token-optimizer/`.

## Clean-install smoke coverage

`release_smoke.py` automates the read-only subset of the clean-install smoke by staging the plugin into a temporary package copy and running:

```bash
claude-token-setup --plan --json
claude-token-diet scan . --json
claude-token-audit <temporary-project> --json
claude-token-delegate status
```

The setup command must be read-only in `--plan` mode. The diet scanner must not follow symlinks when reading settings or context-like files. Delegation must remain opt-in and project-local. If you perform an additional manual smoke after installing a marketplace artifact, run the same commands from a clean project and compare the success shape against the automated gate rather than bypassing it.

## Rollback notes

If a release gate fails after a publish candidate has been prepared:

1. Stop the release.
2. Keep the failing artifact or PR branch for investigation, but do not paste raw logs until credential-like strings and private paths have been removed.
3. Revert or supersede the candidate with a focused fix PR. For an already-pushed tag or marketplace artifact, pin the bad version in the incident note and publish a corrected version rather than mutating history.
4. Re-run this runbook from the beginning, including CI and quad-review evidence on the new head.

Do not publish by bypassing `prepublish_check.py`, `release_smoke.py`, CI, or blocker-free quad review.
