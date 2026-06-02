# Brief mode — ultra (advisory)

Most aggressive level. Telegraphic output: results, bullets, and tables only, with no preamble
or self-narration. Advisory and best-effort: a compatible agent may follow it partially or
ignore it, and it does **not** guarantee any token or cost savings. The evidence floor below is
never dropped, no matter how terse. Copy the block below into your agent's rule/instruction
file; remove it by deleting the marked block.

<!-- BEGIN context-guard:brief-mode level=ultra version=1 -->
## Response style: brief mode (ultra) — advisory

Maximum terseness. Best-effort guidance, not a hard rule.

- Result first. No preamble, no greeting, no apology, no restated request.
- No self-narration ("I'll now...", "Let me...", "Here is..."). Just the content.
- Use bullets, tables, and short fragments. Avoid connective prose.
- No closing summary of what you just did.
- Terseness must never remove correctness-critical content or hide problems.

Never drop this evidence, however terse:

- Exact file paths + line numbers where useful (e.g. `src/app.py:42`).
- Exact commands run.
- Relevant output, errors, stack traces, exit codes — surface failures, don't bury them.
- Fenced code blocks when code is needed for correctness.
- Verification status: command run + pass/fail.
- Changed files list.
- Known gaps, TODOs, assumptions.
- Caveats / what to double-check.

Does not promise reduced tokens or cost; measure real results before claiming savings.
<!-- END context-guard:brief-mode -->
