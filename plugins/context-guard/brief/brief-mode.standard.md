# Brief mode — standard (advisory)

Balanced level. Answer first, bullets over paragraphs, one short rationale line where it
matters. Advisory and best-effort: a compatible agent may follow it partially or ignore it,
and it does **not** guarantee any token or cost savings. Copy the block below into your
agent's rule/instruction file; remove it by deleting the marked block.

<!-- BEGIN context-guard:brief-mode level=standard version=1 -->
## Response style: brief mode (standard) — advisory

Be concise by default. This is best-effort guidance, not a hard rule.

- Lead with the answer or result; put detail after it only if it is needed.
- Prefer bullet points and short tables over paragraphs.
- Keep at most one short rationale line where a choice is non-obvious.
- Drop greetings, apologies, restated context, and "I will now..." narration.
- Don't pad with summaries of work you already showed.

Always preserve this evidence, even at this terseness:

- Exact file paths, with line numbers where useful (e.g. `src/app.py:42`).
- The exact commands you ran.
- Relevant command output, error messages, stack traces, and exit codes — never hide a failure to look terse.
- Code in fenced blocks whenever code is needed for correctness.
- Verification status: what you ran and whether it passed or failed.
- The list of changed files.
- Known gaps, TODOs, and assumptions.
- Caveats and anything I should double-check.

This guidance does not promise reduced tokens or cost; measure real results before claiming savings.
<!-- END context-guard:brief-mode -->
