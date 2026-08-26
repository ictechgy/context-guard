# Using `wclass-advisory` against this repository

This is the operating policy for the external, sealed `wclass-advisory`
campaign tool (paired Claude/Codex design/review/diagnosis/implementation
runs) when it is used against this repository. It is unrelated to
`docs/weightclass-advisory-mode.md`, which documents ContextGuard's own
`context-guard cost advisory` router feature - the name overlap is
coincidental.

## Canonical dispatch command and preflight checklist

Run the advisory with an explicit workflow, repository, task file, vendor,
and task-egress confirmation:

```sh
wclass-advisory run \
  --workflow design \
  --repo /path/to/clean/repository \
  --task-file /path/to/task-file.md \
  --vendor both \
  --confirm-task-egress
```

The `--repo`, `--task-file`, `--vendor`, and `--workflow` flags accept both
the separated form shown above and argparse's `--flag=value` spelling
(e.g. `--workflow=design`); the hook predicate recognizes both.
`--confirm-task-egress` acknowledges that the task file's contents leave
this machine for the selected vendor(s) - do not put secrets in the task
file.

Before dispatch, confirm:

- The repository is a clean git checkout: `git status --porcelain` prints no
  output.
- The task file is an owner-only regular file, for example after
  `chmod 600 /path/to/task-file.md`, and lives outside the repository
  (a scratch/tmp directory) - never inside the Git workspace, even if
  gitignored. Delete it once the run has started; the tool reads it once.

After the session's advisory work is done:

- Restore the `hooks` block in `.claude/settings.json` to re-enable the
  hook.

## The hook stays on

`context-guard-kit/rewrite_bash_for_token_budget.py`'s PreToolUse Bash hook
denies-by-default. `_git_is_safe()` in particular denies `checkout`,
`commit`, `merge`, and every other write subcommand deliberately (R-1): a
model-driven session must not be able to silently write git history. That
protection stays on for normal agent sessions.

PR #315's `CGW_EXACT_NAME_EXTENSIONS` registry is the *only* hook exception
for `wclass-advisory` itself, and it is narrow on purpose: exact executable
name, full-argv-validated `run`/`review` forms only. It does not, and must
not, grow into a general git-write carve-out. A model-settable signal
(an env var, a command prefix, a repo-path check) inside the hook cannot
distinguish "the advisory tool asked for this" from "the model claims the
advisory tool asked for this" - that is exactly the class of bypass R-1 and
R-5 exist to close, so it is not an acceptable design regardless of how
much friction it would remove.

## Advisory work happens with the hook disabled locally

Producing an advisory candidate, dispatching a campaign, applying a
verified patch, and committing the result all require git write operations
the hook denies. Do that work with the hook off:

```json
// .claude/settings.json (gitignored, local-only - never commit this with hooks emptied)
{
  "hooks": {}
}
```

This is a deliberate, human-initiated choice for a specific session, not a
runtime bypass the hook itself grants. Re-enable the hook (restore the
`hooks` block) once the advisory work for that session is done.

## Applying a candidate patch is a separate, explicit step

A `wclass-advisory run --workflow implementation` result is a patch file on
disk, not an auto-applied change. Review it - against the task's fixed
acceptance criteria and the actual code - before running `git apply`.
Nothing in this workflow should commit a candidate's patch automatically.

## `.weightclass/` scaffolding is structural, not per-file registered

`tests/test_contextguard_stage2_feasibility.py`'s `is_weightclass_scaffolding_path()`
exempts any direct, verifier-shaped file under `.weightclass/` (`verify`,
`verify-review`, `verify-<workflow>`, ...) from both the legacy-production
freeze and the provider-free changed-path gate. A new `.weightclass/verify-*`
file for a new campaign does not need to be registered anywhere; a
non-verifier-shaped file, or anything nested under a subdirectory, is still
treated as an undeclared production change and will fail CI - the exemption
is scoped to the directory's actual purpose, not a blanket allowance.

## Sharing `--graph-cache` across a campaign's lanes (roadmap A1/A5)

`context-guard-kit/context_pack.py`'s `--graph-cache` flag (revision-bound
graph-rank/repo-map caching; see `research/graph-cache-advisory-integration-
roadmap-20260825.md`) can save every lane in a campaign from independently
recomputing the same repo map for the same commit, if they share a cache
directory. This is safe to do because `wclass-advisory` isolates lanes only
by environment-variable narrowing, not a filesystem jail (confirmed from
`weightclass/advisory/speculative_run.py`'s own comments, roadmap §5) - an
absolute-path cache directory is reachable from every lane exactly as if
isolation were off, so this needs no cooperation from the advisory tool
itself.

**Warm once, share read-only, write only from the owner process:**

```sh
CACHE_DIR="$(mktemp -d)/graph-cache"   # outside the repo; owner-only by mktemp
context-guard-pack auto --root /path/to/clean/repository \
  --graph-cache --explain --json \
  --query "<the campaign's actual query>" \
  > /dev/null
CONTEXT_GUARD_GRAPH_CACHE_DIR="$CACHE_DIR" wclass-advisory run ... --confirm-task-egress
```

- The warm-up call runs as the owner process, before dispatch, using the
  exact `--query`/seed paths the campaign's task actually needs - a
  mismatched query misses the cache and defeats the point.
- Point every lane's environment at the same `CONTEXT_GUARD_GRAPH_CACHE_DIR`
  so a lane that also calls `context-guard-pack ... --graph-cache` hits the
  warmed record instead of rebuilding it.
- **A5 (write/read separation)** is a task-authoring convention, not an
  isolation guarantee: nothing stops a lane from writing to
  `CONTEXT_GUARD_GRAPH_CACHE_DIR` too. Either don't tell candidate tasks to
  pass `--graph-cache` at all (let them read the pre-warmed directory only
  if your task text says so) or point `--cheap-home`/`--advisor-home`/
  `--expensive-home` (see the section above) such that a candidate's own
  writes land somewhere other than the shared directory.
- Check the receipt (`explain.repo_map_cache`, roadmap A4) on any lane call
  that used `--graph-cache` to confirm `"hit": true` before trusting that
  the cache actually saved that lane the rebuild.
- This does not change what a candidate is allowed to modify inside its own
  clone - the shared directory sits outside the repo the campaign operates
  on, same as the task file itself.
