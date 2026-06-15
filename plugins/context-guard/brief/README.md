# ContextGuard brief mode (advisory)

Brief mode is a set of **agent-neutral, advisory** rule snippets that ask a coding or
tool-using agent to cut filler from its responses while preserving the technical evidence a
reviewer needs. It is guidance text, not an enforcement mechanism.

- **Advisory / best-effort.** Compatible agents may follow these rules fully, partially, or
  ignore them. Brief mode does not intercept, rewrite, or block model output.
- **No guaranteed savings.** Brief mode does **not** promise any token or cost reduction.
  Verbosity behavior varies by agent and model. Measure real before-and-after results for your
  own tasks with `context-guard-bench` before making any savings claim.
- **Evidence first.** Every level keeps the same mandatory evidence floor (see below). Brief
  mode trims wording, never correctness-critical content.
- **Local and reversible.** Snippets are plain text you install into an agent's own rule or
  instruction file. They are delimited by stable markers so a setup/adapter step can add or
  remove them without touching unrelated configuration.

## Levels

Brief mode ships three deterministic levels. Each level file contains one marker-delimited
block that is safe to copy into an agent rules file as-is.

| Level | File | Verbosity dial |
| --- | --- | --- |
| `lite` | [`brief-mode.lite.md`](brief-mode.lite.md) | Drop pleasantries and restated context; keep explanations where they aid understanding. |
| `standard` | [`brief-mode.standard.md`](brief-mode.standard.md) | Answer first, bullets over paragraphs, one short rationale line where it matters. |
| `ultra` | [`brief-mode.ultra.md`](brief-mode.ultra.md) | Telegraphic: results/bullets/tables only, no preamble or self-narration. |

The levels differ only in how aggressively they cut wording. They never differ in what
evidence must be preserved.

## Mandatory evidence floor (all levels)

A brief-mode response must still include, whenever relevant:

1. **File paths** — exact paths, with line numbers where useful (e.g. `src/app.py:42`).
2. **Commands** — the exact commands that were run.
3. **Command output / failure evidence** — relevant output, error messages, stack traces,
   and exit codes. Never hide a failure to look terse.
4. **Code blocks** — when code is needed for correctness, keep it in a fenced block.
5. **Verification status** — what was run to verify, and whether it passed or failed.
6. **Changed files** — the list of files created, modified, or deleted.
7. **Known gaps** — TODOs, untested paths, and assumptions made.
8. **Caveats** — uncertainty and anything the reader must double-check.

## Installing and removing

Brief mode is installed by copying the marker-delimited block from a level file into the
target agent's rule/instruction file (for example a repo `AGENTS.md`, `CLAUDE.md`,
`.cursorrules`, or `.github/copilot-instructions.md`). The cross-agent setup planner is the
intended automation for this:

```bash
context-guard setup --agent codex --scope project --brief-mode standard --plan
context-guard setup --agent codex --scope project --brief-mode standard --yes
context-guard setup --agent codex --scope project --brief-mode off --yes
```

Per the project safety rules, it stays dry-run first, writes only local files, backs up
existing rule files before changing anything, and applies only with explicit approval.

Each block is wrapped in stable markers:

```text
<!-- BEGIN context-guard:brief-mode level=<level> version=1 -->
...rules...
<!-- END context-guard:brief-mode -->
```

To remove brief mode, delete the block between (and including) those two marker lines. Only
one brief-mode block should be present at a time; installing a different level replaces the
existing block rather than stacking a second one.
