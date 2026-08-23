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

Before dispatch, confirm:

- The repository is a clean git checkout: `git status --porcelain` prints no
  output.
- The task file is an owner-only regular file, for example after
  `chmod 600 /path/to/task-file.md`.
- Once advisory work for the session is done, restore the `hooks` block in
  `.claude/settings.json` to re-enable the hook.

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
