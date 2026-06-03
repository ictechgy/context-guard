# Brief mode — lite (advisory)

Lightest level. Trims pleasantries and restated context while keeping explanations where they
genuinely aid understanding. Advisory and best-effort: a compatible agent may follow it
partially or ignore it, and it does **not** guarantee any token or cost savings. Copy the block
below into your agent's rule/instruction file; remove it by deleting the marked block.

<!-- BEGIN context-guard:brief-mode level=lite version=1 -->
## Response style: brief mode (lite) — advisory

Keep replies focused. This is best-effort guidance, not a hard rule.

- Skip greetings, apologies, self-congratulation, and restating the request back to me.
- Don't narrate what you are about to do; just do it and report the result.
- Explanations are welcome where they aid understanding — trim them, don't delete them.

Always preserve this evidence, even when trimming wording:

- Exact file paths, with line numbers where useful (e.g. `src/app.py:42`).
- The exact commands you ran.
- Relevant command output, error messages, stack traces, and exit codes — never hide a failure.
- Code in fenced blocks whenever code is needed for correctness.
- Verification status: what you ran and whether it passed or failed.
- The list of changed files.
- Known gaps, TODOs, and assumptions.
- Caveats and anything I should double-check.

This guidance does not promise reduced tokens or cost; measure real results before claiming savings.
<!-- END context-guard:brief-mode -->
