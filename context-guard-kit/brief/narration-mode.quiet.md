<!-- BEGIN context-guard:narration-mode mode=quiet version=1 -->
## ContextGuard quiet narration (advisory)

Best effort: reduce only discretionary intermediate narration. Skip routine preambles,
per-tool narration, filler, and repeated interim summaries when they add no useful
information.

Always preserve required user-facing communication:

- user approvals and decisions;
- blockers and failures;
- destructive-risk and security warnings;
- progress required by higher-priority instructions;
- the final result;
- changed files; and
- verification evidence.

This mode does not require a shorter final answer and does not change reasoning effort.
It asks Claude to reduce discretionary narration; it does not guarantee token or cost savings,
and no numeric savings should be claimed without matched provider evidence.
<!-- END context-guard:narration-mode -->
