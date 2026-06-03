---
description: Audit local Claude Code transcript usage and summarize likely token hotspots. Use when the user asks where Claude Code tokens are going or wants evidence before optimizing.
argument-hint: [optional transcript path]
disable-model-invocation: true
---

# ContextGuard Audit

Run a best-effort transcript audit, then interpret the result conservatively.

Default command:

```bash
context-guard-audit ~/.claude/projects --top 20 --recommend
```

If the user supplies a path, audit that path instead. If no path is supplied, keep the default Claude projects path:

```bash
if [ -n "$ARGUMENTS" ]; then
  context-guard-audit "$ARGUMENTS" --top 20 --recommend
else
  context-guard-audit ~/.claude/projects --top 20 --recommend
fi
```

Report:

- observed token buckets: input, output, cache_read, cache_creation;
- model distribution;
- query_source distribution: main, subagent, auxiliary;
- top transcript files and commands observed;
- generated recommendations with priority, reason, action, and evidence;
- `cache_friendliness` status, bounded prefix/tail churn signals, and any cache-layout findings;
- top likely causes and one safe next experiment.

Privacy: default output uses basename+hash transcript labels and command category+hash labels. Do not ask for `--show-paths` or `--show-commands` unless the user explicitly wants local identifiers in the report. Cache-friendliness diagnostics use bounded redacted segment hashes and do not print raw prompt text. Recommendations are heuristics; treat them as hypotheses, especially with small `files` or `records` counts.

Caveat: Claude Code transcript schemas can change. Treat this as an operational signal, not billing authority. `cache_read`/`cache_creation` and `cache_friendliness` are provider-cache diagnostics, not proof of ContextGuard-caused token reduction. For billing authority, use Claude Console, cloud-provider billing, or configured OpenTelemetry metrics.
