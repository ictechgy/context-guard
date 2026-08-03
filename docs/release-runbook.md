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

`GENERATION_RECORD_FINGERPRINTS` mechanically binds the complete ordered record list. Each digest covers the generation name, four subjects, all three owned path sets, residual markers, Gate-B markers, and declared residual edits. The verifier first checks the current records against those digests, then reads every committed verifier version reachable from `HEAD` and requires each historical digest tuple to be an exact prefix of the current tuple. Therefore deleting a prior generation, editing one of its fields, or shrinking one of its recorded path sets fails even if the same change also rewrites the current digest tuple. This protects already-shipped records; it does not silently redefine the separate, explicit review decision to append a future generation with a different active path set.

**Re-blessing is not an automatic re-anchor.** It is an explicit, human-reviewed commit that appends one new generation record. The new generation's `bless` commit is the review artifact: its diff against the previous generation's `bless` is exactly "this is the Gate-B-free residual content we are blessing now," scoped to the component paths declared for that generation.

The active `gen3` record is the S007 non-login-shell wrapper re-bless. It
preserves S006 `gen2`; the next routine re-bless must append `gen4` rather than
rewriting or reusing an existing generation.

Re-blessing procedure:

1. Confirm the freeze is actually the blocker (an otherwise-unrelated PR touches a frozen component path) and that no cheaper option — narrowing the frozen path set for a future generation, or splitting a large frozen test file — resolves it instead.
2. Author the new generation's four reapply commits (`bless`, `b1`, `b2`, `shared-integration`) with subjects that are globally unique across the whole `GENERATIONS` history (uniqueness is enforced mechanically: two commits sharing a subject make the proof fail with "found N" instead of silently picking one).
3. Append a new `Generation` record to `GENERATIONS` and append its canonical digest to `GENERATION_RECORD_FINGERPRINTS` in the same commit that lands the fourth reapply commit's ancestor chain. Do not edit or delete any prior record or digest — both tuples are append-only, including every prior path set and marker. Compute the digest with the production canonicalizer rather than hand-serializing the record:
   ```bash
   python3 - <<'PY'
   import runpy
   proof = runpy.run_path(
       "scripts/verify_gate_b_rollback.py",
       run_name="gate_b_fingerprint",
   )
   generation = proof["GENERATIONS"][-1]
   print(proof["generation_record_fingerprint"](generation))
   PY
   ```
   Run the full verifier again after committing. A worktree run can prove that the previously committed ledger is still a prefix, but only the committed PR head is durable release evidence for the newly appended record and digest.

   The record itself is validated mechanically before any git work happens (`assert_generation_records_wellformed`, a git-free pre-pass so a malformed record fails loudly even in a truncated checkout). A new generation is rejected outright when:
   - its `name` duplicates any existing generation's `name` — `all_commits` is keyed by name, so a collision would silently make one generation overwrite the other and both cross-generation checks (`residual_edits` and the existence-set invariant) would compare a `bless` commit against itself and pass vacuously;
   - its `gate_b_markers` is empty — that is the reverse anti-laundering check, and an empty tuple would make both the presence check at `HEAD` and the absence check on the `bless` tree pass without evaluating anything. The re-blesser must not be able to switch off the check that constrains the re-blessing;
   - its `residual_markers` is empty, or maps a path to an empty needle tuple, or contains an empty/whitespace-only needle — all three keep the outer collection non-empty while making the content check evaluate nothing (`"" in content` is true for any content);
   - any `gate_b_markers` entry has an empty literal, or names an `owner_path` that is not one of that generation's own component paths, or any `residual_markers` key is not one of them — C3-b scans every component path in the `bless` tree, while C3-a and forward carry use the declared owner to anchor the marker inside the generation's frozen boundary;
   - any component path (`b1_paths`, `b2_paths`, or `shared_paths`) starts with `:`, or contains a C0/DEL/C1 control character, whitespace, or a shell/glob metacharacter — a leading `:` is git pathspec magic; whitespace lets unquoted shell word-splitting silently drop a path; and raw `jq -r` control bytes can move or erase terminal output so a neighboring path is invisible even though the mechanical gate still sees it;
   - it **drops a Gate-B marker that the previous generation declared for a path this generation still owns** (forward carry). Without this, "non-empty" is satisfied by a nonce marker: a re-blesser could declare one throwaway literal and leave the real Gate-B literals sitting in its `bless`. Carry is **not** retroactive — it checks the *new* `bless` against *old* markers, never the reverse, so the per-generation non-retroactive property is preserved. Carry is scoped to paths the new generation still owns, because a path removed from the component set cannot satisfy the owner-must-be-a-component-path rule; removing the path instead is the separately-documented narrowing vector, and `review_pathspec` still surfaces it.

   Beyond the record itself, the absence check searches every marker literal across **every component path present in the `bless` tree**, not only its declared owner. Moving Gate-B code or a marker literal to another component therefore remains visible. It also rejects an active generation where no component path exists in `bless`, because that would evaluate no marker and pass vacuously. `commit_paths` uses `diff-tree --name-only` and is status-blind, so a path the `bless` deletes is still a legitimate component path; the all-absent guard keeps that deletion shape fail-closed.

   Note what is deliberately **not** required: full marker monotonicity. A generation need not carry markers for paths it no longer owns.

   **Consequence to plan for: a Gate-B marker literal is an immutable anchor for as long as its owner path stays in the component set.** Forward carry forces the literal to keep being declared, and the presence check requires it to exist at live `HEAD`. So renaming a marked identifier (say `failures-v2.json` bumping to `v3`) hard-fails the publish gate, and no compliant re-blessing clears it: dropping the marker is rejected by carry, keeping it is rejected by the presence check. This fails **closed**, so it is not a laundering hole — but choose marker literals for structural stability (prefer stable symbol names over versioned data filenames). If a marked surface genuinely has to move, the only compliant resolutions are (a) keep the old literal present at `HEAD`, or (b) a reviewed decision to drop the owner path from the component set — which must be called out explicitly in the re-bless PR, because it also drops that path from the freeze. There is deliberately no marker-retirement escape field: such a field would let a re-blesser point at exactly the marker that would have caught them.
4. Declare every component path whose blessed content legitimately changes relative to the previous generation in the new generation's `residual_edits`. An undeclared change to a path both generations own is rejected.
5. **Pull the review pathspec from the proof itself — do not hand-maintain a path list.** Run `python3 scripts/verify_gate_b_rollback.py --json` and read the `review_pathspec` key: it is the sorted union of every generation's component paths, computed by the script, not typed in by a reviewer. A hardcoded list goes stale the moment a generation adds or drops a path; deriving from only the active generation would let a narrowing generation hide a path from review. Use it to scope the actual review diff:
   ```bash
   python3 scripts/verify_gate_b_rollback.py --json > /tmp/gate-b-proof.json
   jq -r '.review_pathspec[]' /tmp/gate-b-proof.json
   ```
   then review the diff line by line, confirming every changed line is one of the declared `residual_edits`. **Do not interpolate `jq`'s output directly with `$(...)` in the `git diff` argument list** — unquoted command substitution word-splits on whitespace before git ever runs, so a component path containing a space is silently dropped from the diff you review while the mechanical gate (which never goes through a shell) still sees it. Read each pathspec into an array, one per line, then expand the array quoted. This works on bash 3.2 (macOS's shipped `/bin/bash`, which has neither `mapfile -d ''` nor `git diff --pathspec-from-file`):
   ```bash
   paths=()
   while IFS= read -r path; do
     paths+=("$path")
   done < <(jq -r '.review_pathspec[]' /tmp/gate-b-proof.json)
   GIT_LITERAL_PATHSPECS=1 git diff <previous-generation-bless> <new-generation-bless> \
     -- "${paths[@]}"
   ```
   **Keep the `GIT_LITERAL_PATHSPECS=1` prefix and the quoted array expansion — both.** The proof script sets `GIT_LITERAL_PATHSPECS=1` internally for every git call it makes, but this command runs in *your* shell, where it is unset — and a component path spelled `:(exclude)<other>` would then hide `<other>` from the diff you are reading while the mechanical gate still sees both paths. The script now rejects component paths starting with `:`, or containing C0/DEL/C1 control characters, whitespace, or shell/glob metacharacters, outright. The control rule protects terminal rendering; the prefix and quoted array protect shell/git interpretation. Keep all of them, because the one that fails first is the one that keeps a human from reviewing a diff that has been quietly narrowed or visually erased.
6. Run the full proof (`--json` and plain) and the targeted Gate-B test modules locally before pushing; the publish workflow runs the proof as a blocking step, but a broken generation record should never reach CI first.

### Gate-B incident handling without history deletion

There is no deletion exception to append-only history. If a re-blessed generation is later found to have laundered Gate-B surface into the residual, retain the implicated record and commits, stop the release, attach the incident note, and append a corrective generation whose reviewed `bless` removes the laundering. Deleting or rewriting the implicated record would erase the evidence needed to explain the incident and is mechanically rejected by the fingerprint-history prefix check.

## Rollback notes

If a release gate fails after a publish candidate has been prepared:

1. Stop the release.
2. Keep the failing artifact or PR branch for investigation, but do not paste raw logs until credential-like strings and private paths have been removed.
3. Identify the smallest failed owned unit. Revert its canonical implementation, packaged mirror, and dedicated tests together; do not mix versions within a pair.
4. Revert shared package or release metadata only after its dependent feature units. Preserve unrelated managed bytes and fail closed if a setup rollback detects an external edit after the expected post-image.
5. Revert or supersede the candidate with a focused fix PR. For an already-pushed tag or marketplace artifact, pin the bad version in the incident note and publish a corrected version rather than mutating history.
6. Re-run this runbook from the beginning, including CI and quad-review evidence on the new head.
7. Gate B generations specifically: if the incident is a laundered re-blessing (see "Gate-B incident handling without history deletion" above), keep the bad generation as incident evidence and append a corrective generation. Do not delete, edit, or reorder any historical generation record or fingerprint; the verifier rejects that rewrite before performing the rollback proof.

Do not publish by bypassing `prepublish_check.py`, `release_smoke.py`, CI, or blocker-free quad review.
