# Release runbook

This repository ships a Claude Code plugin plus standalone helper entrypoints. Use this runbook before publishing plugin artifacts, merging release-sensitive changes, or cutting a tag.

## Release gates

Run the copy check and both local gates from the repository root:

```bash
python3 scripts/sync_plugin_copies.py --check
python3 scripts/prepublish_check.py
python3 scripts/release_smoke.py
```

Success sentinels include the following lines; `prepublish_check.py` may also print unittest output first:

```text
prepublish check: OK
release smoke: OK
```

`sync_plugin_copies.py --check` verifies the maintainer-facing exact-copy contract before the heavier gates. If a source helper under `context-guard-kit/` changed, run `python3 scripts/sync_plugin_copies.py --write` first to refresh the packaged `plugins/context-guard/bin` and `plugins/context-guard/lib` copies while applying the package mode contract: executable bin entrypoints are `0755`, lib helper copies are `0644`. The npm package intentionally ships those plugin-local copies only, not the checkout-only `context-guard-kit` source tree, to avoid duplicate implementation payloads. Legacy `claude-token-*` compatibility wrappers remain packaged files, but npm `.bin` links intentionally expose only canonical `context-guard-*` commands; `release_smoke.py` verifies both sides of that policy. `prepublish_check.py` verifies package invariants, manifest consistency, synchronized plugin binaries, forbidden package artifacts, Python compile checks, and the regression test suite. It must also keep failure diagnostics safe to copy into issues: secret-shaped package artifact names, credential-like path labels, URL userinfo, control-character labels, and maintainer-local override paths should be redacted or summarized rather than printed raw. `release_smoke.py` first stages a clean copy of the plugin package, rejects symlinked package entries, then executes representative packaged plugin entrypoints in a temporary project with isolated `HOME`, `XDG_*`, `TMP*`, and a minimal environment so local credentials or optimizer config cannot affect the result. Release/runtime command manifests are parsed as bounded AST literals; loaders do not execute Python manifest source.

## PR release workflow

1. Start from up-to-date `main`.
2. Make one focused, reviewable change.
3. Keep duplicated kit/plugin entrypoints synchronized when a helper changes with `python3 scripts/sync_plugin_copies.py --write`.
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
  - `python3 scripts/sync_plugin_copies.py --check`
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

- `plugins/context-guard/.claude-plugin/plugin.json` has the intended version.
- Repository-root `.claude-plugin/marketplace.json` lists the same plugin version and `Apache-2.0` license.
- Repository-root `CHANGELOG.md` contains a release-notes entry for that exact plugin version.
- `scripts/prepublish_check.py` passes without path overrides.
- `scripts/sync_plugin_copies.py --check` reports `plugin copies synchronized`.
- No generated caches, logs, or symlinks are inside `plugins/context-guard/`.

## npm trusted publishing

npm publishing uses trusted publishing/OIDC through `.github/workflows/npm-publish.yml`.
The npm package trusted-publisher configuration must use workflow filename
`npm-publish.yml` and an empty environment name. The workflow publishes only
from an existing GitHub release tag or an explicit manual dispatch tag, verifies
that the tag matches `package.json` and plugin manifest versions, runs the same
release gates, and uses `id-token: write` without `NODE_AUTH_TOKEN` or
`NPM_TOKEN`.

## Clean-install smoke coverage

`release_smoke.py` automates the read-only subset of the clean-install smoke by staging the plugin into a temporary package copy and running:

```bash
context-guard-setup --plan --json
context-guard-diet scan . --json
context-guard-audit <temporary-project> --json
```

The setup command must be read-only in `--plan` mode. The diet scanner must not follow symlinks when reading settings or context-like files. If you perform an additional manual smoke after installing a marketplace artifact, run the same commands from a clean project and compare the success shape against the automated gate rather than bypassing it.

## Staged npm tarball evidence

`release_smoke.py` also exercises the artifact produced by `npm pack`, not only the source checkout or staged plugin directory. To reproduce that artifact boundary manually:

```bash
stage_root="$(mktemp -d)"
npm pack --json --ignore-scripts --pack-destination "$stage_root" >"$stage_root/pack.json"
tarball="$(python3 - "$stage_root" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
print(root / json.loads((root / "pack.json").read_text(encoding="utf-8"))[0]["filename"])
PY
)"
mkdir "$stage_root/project" "$stage_root/isolated-install"
(cd "$stage_root/project" && npm install --ignore-scripts --no-audit --fund=false --prefix "$stage_root/isolated-install" "$tarball")
"$stage_root/isolated-install/node_modules/.bin/context-guard" --version
```

The automated smoke additionally checks help and setup plan/apply behavior, quiet-narration apply/removal, every packaged dispatcher, legacy-wrapper package presence without npm bin exposure, and lifecycle-script rejection. Capture the `sync-plugin-copies: plugin copies synchronized` and `release smoke: OK` sentinels, tarball filename, size, integrity value from `pack.json`, command exit codes, and the absence of unexpected credentials. Keep the staging root only long enough to collect redacted evidence, then remove it and confirm no temporary release artifacts were added to the repository.

## Integration release order

Release the integrated safety work in public A, then B, then C, then D order. C is the optional Claude-only quiet-narration rule and remains default-off; D is optional measurement or research and cannot authorize a numeric claim without matched provider evidence. Keep the internal A0/A1/A2 and B1/B2 boundaries independently revertible even when they share one public release gate.

Before advancing to the next public gate, verify the canonical implementation, its packaged mirror, and the dedicated tests as one owned unit. A feature rollback reverts that complete unit together. Revert shared package metadata only after every dependent feature has been reverted or superseded; reverting shared metadata first can leave an older package manifest pointing at newer behavior.

Gate B has an executable history proof rather than a hunk-by-hunk rollback recipe:

```bash
python3 scripts/verify_gate_b_rollback.py --json
```

The rollback proof requires the merge-preserved Gate-B proof commits and a
full-history checkout. An unavailable history is reported separately as JSON
`status: "unavailable"` with exit code `3`; it is not reported as a failed
rollback. CI and the npm publish workflow use `fetch-depth: 0`, and the publish
workflow runs this proof as an explicit blocking step. If a release checkout is
shallow, fetch the full history and rerun the command before publishing. If a
complete history is missing a merge-preserved proof commit, the command fails
instead: restore the proof chain rather than treating it as unavailable.

The proof checks the immutable B1 nudge/FSM and B2 usage-reducer feature commits against their exact owned canonical, packaged, and dedicated-test paths. In disposable clones it applies and reverts each feature independently from the same pre-B base, verifies the reverted tree equals that base, proves each feature can be reverted alone from the current head, and finally proves the integrated rollback order `B1 -> B2 -> shared integration`. It reports unavailable when the checkout lacks the required history, and fails when a component path set changes, either feature needs hunk surgery, or shared integration cannot be reverted last. CI therefore uses full Git history. Treat the emitted commit and tree hashes as the release evidence; do not substitute a successful source-only test for the mechanical history proof.

### Gate B generations

The proof anchor is an append-only `GENERATIONS` list in `scripts/verify_gate_b_rollback.py`, not a single hardcoded set of four commits. Every generation (retired or active) is checked forever for structure (parent chain, disjoint owned path sets), apply/revert tree equality, and its own residual contract. Only the **active generation** (the last element of `GENERATIONS`) is checked against the live `HEAD`: the freeze that rejects any post-reapplication edit to its component paths, the ordered live rollback (`B1 -> B2 -> shared integration`), and presence/absence of that generation's Gate-B markers. A retired generation's four commits stay immutable, so once its checks pass they remain true forever — the durable guarantee a retired generation keeps making is that its four proof commits stay uniquely reachable.

**Re-blessing is not an automatic re-anchor.** It is an explicit, human-reviewed commit that appends one new generation record. The new generation's `bless` commit is the review artifact: its diff against the previous generation's `bless` is exactly "this is the Gate-B-free residual content we are blessing now," scoped to the component paths declared for that generation.

Re-blessing procedure:

1. Confirm the freeze is actually the blocker (an otherwise-unrelated PR touches a frozen component path) and that no cheaper option — narrowing the frozen path set for a future generation, or splitting a large frozen test file — resolves it instead.
2. Author the new generation's four reapply commits (`bless`, `b1`, `b2`, `shared-integration`) with subjects that are globally unique across the whole `GENERATIONS` history (uniqueness is enforced mechanically: two commits sharing a subject make the proof fail with "found N" instead of silently picking one).
3. Append a new `Generation` record to `GENERATIONS` in the same commit that lands the fourth reapply commit's ancestor chain. Do not edit any prior generation's record — the list is append-only, including its path sets and markers.
4. Declare every component path whose blessed content legitimately changes relative to the previous generation in the new generation's `residual_edits`. An undeclared change to a path both generations own is rejected.
5. **Pull the review pathspec from the proof itself — do not hand-maintain a path list.** Run `python3 scripts/verify_gate_b_rollback.py --json` and read the `review_pathspec` key: it is the sorted union of every generation's component paths, computed by the script, not typed in by a reviewer. A hardcoded list goes stale the moment a generation adds or drops a path; deriving from only the active generation would let a narrowing generation hide a path from review. Use it to scope the actual review diff:
   ```bash
   python3 scripts/verify_gate_b_rollback.py --json > /tmp/gate-b-proof.json
   jq -r '.review_pathspec[]' /tmp/gate-b-proof.json
   ```
   then review `git diff <previous-generation-bless> <new-generation-bless> -- <paths from review_pathspec>` line by line, confirming every changed line is one of the declared `residual_edits`.
6. Run the full proof (`--json` and plain) and the targeted Gate-B test modules locally before pushing; the publish workflow runs the proof as a blocking step, but a broken generation record should never reach CI first.

### Gate-B incident exception to append-only

`GENERATIONS` is append-only during normal operation. The one exception is a security incident: if a re-blessed generation is later found to have laundered Gate-B surface into the residual (a legitimate-looking `bless` diff that actually leaves Gate-B code reachable), the bad generation record may be removed. That removal is itself a reviewed commit with an incident note explaining what was found and why the generation was pulled, not a silent history rewrite. See the incident steps under Rollback notes below; do not use this exception to escape a normal freeze — that is exactly the softness this proof exists to prevent.

## Rollback notes

If a release gate fails after a publish candidate has been prepared:

1. Stop the release.
2. Keep the failing artifact or PR branch for investigation, but do not paste raw logs until credential-like strings and private paths have been removed.
3. Identify the smallest failed owned unit. Revert its canonical implementation, packaged mirror, and dedicated tests together; do not mix versions within a pair.
4. Revert shared package or release metadata only after its dependent feature units. Preserve unrelated managed bytes and fail closed if a setup rollback detects an external edit after the expected post-image.
5. Revert or supersede the candidate with a focused fix PR. For an already-pushed tag or marketplace artifact, pin the bad version in the incident note and publish a corrected version rather than mutating history.
6. Re-run this runbook from the beginning, including CI and quad-review evidence on the new head.
7. Gate B generations specifically: if the incident is a laundered re-blessing (see "Gate-B incident exception to append-only" above), the fix PR that removes the bad generation record goes through the same CI-green-plus-blocker-free-quad-review bar as any other change — there is no separate approval path. Do not delete or edit an older, unaffected generation record to work around this; only the specific bad record is removed, and the incident note stays attached to the fix PR.

Do not publish by bypassing `prepublish_check.py`, `release_smoke.py`, CI, or blocker-free quad review.
