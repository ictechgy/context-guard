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

`prepublish_check.py` verifies package invariants, manifest consistency, synchronized plugin binaries, forbidden package artifacts, Python compile checks, and the regression test suite. `release_smoke.py` executes representative packaged plugin entrypoints in a temporary project with isolated `HOME`, `XDG_*`, `TMP*`, and a minimal environment so local credentials or optimizer config cannot affect the result.

## PR release workflow

1. Start from up-to-date `main`.
2. Make one focused, reviewable change.
3. Keep duplicated kit/plugin entrypoints synchronized when a helper changes.
4. Run the local release gates.
5. Commit using the Lore commit protocol.
6. Push a branch and open a PR.
7. Wait for GitHub Actions to pass on all supported Python/platform lanes. The Ubuntu Python matrix keeps the historical `test-and-prepublish (3.11)` / `test-and-prepublish (3.12)` check names; the macOS release lane is `test-and-prepublish (macos-latest, 3.12)`.
8. Run quad review against the PR/diff.
9. If any blocker is reported, commit a fix, push it, and re-run CI plus quad review.
10. Merge only after CI is green and quad review has no blocker findings.

Claude review track may be unavailable on a machine that has not logged in to the local Claude CLI. Record that as unavailable; do not treat it as approval.

## Version and manifest checks

Before publishing a versioned artifact, verify:

- `plugins/claude-token-optimizer/.claude-plugin/plugin.json` has the intended version.
- Repository-root `.claude-plugin/marketplace.json` lists the same plugin version and `Apache-2.0` license.
- `scripts/prepublish_check.py` passes without path overrides.
- No generated caches, logs, or symlinks are inside `plugins/claude-token-optimizer/`.

## Manual smoke checklist

After a release candidate is installed in a clean project, verify:

```bash
claude-token-setup --plan --json
claude-token-diet scan . --json
claude-token-audit ~/.claude/projects --json
claude-token-delegate status
```

The setup command must be read-only in `--plan` mode. The diet scanner must not follow symlinks when reading settings or context-like files. Delegation must remain opt-in and project-local.

## Rollback notes

If a release gate fails after a publish candidate has been prepared:

1. Stop the release.
2. Keep the failing artifact or PR branch for investigation.
3. File or commit the fix as a new focused PR.
4. Re-run this runbook from the beginning.

Do not publish by bypassing `prepublish_check.py`, `release_smoke.py`, CI, or blocker-free quad review.
