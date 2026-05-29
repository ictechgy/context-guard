# ContextGuard

A Claude Code plugin with skills and local helper commands for keeping context small, focused, and safer to send to Claude.

Start with `/context-guard:setup`. It applies project-local settings for safe defaults, then prints a read-only diet scan summary of remaining gaps. The plugin does not mutate global Claude settings and does not configure external AI offload.

Rebrand note: Claude Code does not alias the old `/claude-token-optimizer:*`
plugin slash-command namespace. Use `/context-guard:*`; legacy `claude-token-*`
CLI wrappers remain in `bin/` for existing automation.

## Skills

After installation, use:

```text
/context-guard:setup
/context-guard:optimize
/context-guard:audit
```

## Helper commands

The primary helper prefix is now `context-guard-*`. Legacy `claude-token-*` wrappers remain in `bin/` so existing automation keeps working during the rebrand.

The plugin includes executables under `bin/`. Claude Code can call them from plugin skills, but your normal shell may not automatically add plugin `bin/` to `PATH`. If a command is not found, either run it by path from this repository root or add the bin directory to `PATH` for the current shell:

```bash
./plugins/context-guard/bin/context-guard-setup --plan
export PATH="$PWD/plugins/context-guard/bin:$PATH"
```

When the plugin bin directory is on `PATH`, the commands are:

```bash
context-guard-audit ~/.claude/projects --top 20 --recommend
context-guard-setup
context-guard-diet scan . --json
context-guard-artifact store --command "long-command" --json < large.log
context-guard-artifact get <artifact_id> --lines 1:80
context-guard-trim-output --max-lines 120 -- npm test
context-guard-read-symbol path/to/file.py TargetSymbol
context-guard-sanitize-output -- rg -n "TOKEN|SECRET" .
context-guard-sanitize-output -- git diff
context-guard-guard-read
context-guard-statusline
context-guard-statusline-merged
context-guard-rewrite-bash
context-guard-failed-nudge
```

These helpers reduce common sources of token waste, but they do not guarantee a fixed percentage savings. Use `context-guard-bench --ledger-jsonl ... --report-json ...` when you need measured before/after evidence for your own tasks.

`context-guard-audit --recommend` anonymizes transcript paths and command strings by default (`basename#hash`, `command#hash`). Use `--show-paths` or `--show-commands` only for local/private reports.

The audit scanner also bounds transcript reads by default: files above
`--max-file-bytes` and individual JSONL records above `--max-line-bytes` are
skipped with explicit skip counts and warnings instead of being loaded into
memory.

The JSON output includes a `cache_metrics` block (`cache_hit_rate`, `cache_amortization`, `cache_amortization_defined`, raw cache_read/cache_creation/input tokens) so you can tell whether the prompt cache is paying back its write cost. Two recommendations operate on these metrics:

- `improve-prompt-cache-reuse` triggers when amortization (`cache_read / cache_creation`) drops below 0.5 with non-trivial cache writes (`cache_creation` ≥ 10,000 tokens and `cache_read` ≥ 1), which protects baseline / cache-cold sessions from false positives.
- `evaluate-1h-ttl-cache` is heuristic — it flags sessions where writes are large but reuse is moderate; whether to actually flip on the 1h TTL prompt cache beta depends on whether reuse spans more than 5 minutes. See [`research/claude-code-token-reduction.md` §2.7](../../research/claude-code-token-reduction.md) for the price math, break-even reasoning, and an enable/disable checklist before turning the beta on.

`context-guard-setup` is the post-install wizard. Prefer `/context-guard:setup` inside Claude Code. In a normal terminal, run `./plugins/context-guard/bin/context-guard-setup --plan` from this repository root, or use `context-guard-setup --plan` only after adding the plugin bin directory to `PATH`. It merges `.claude/settings.json` instead of replacing it, no longer configures external model offload, and after applying settings it automatically prints a read-only `context-guard-diet scan` summary of remaining gaps. Use `--no-diet-scan` when automation needs setup output without the post-apply scan summary.

`context-guard-diet scan` is a local read-only scanner for project Claude settings and context bloat. It checks missing `permissions.deny` guardrails, Bash trim hook/statusline setup, broad read allows, high default model/effort, many MCP servers, and large/secret-like `CLAUDE.md` or `AGENTS.md` context files. It anonymizes the project root by default; use `--show-paths` only for local/private reports.

`context-guard-guard-read` is an opt-in PreToolUse Read hook that blocks large whole-file reads and returns a progressive read ladder: search with `rg -n`, read a symbol slice with `context-guard-read-symbol`, then use a small line-range Read only if needed. For Python, JavaScript/TypeScript, Go, Rust, and Markdown files it also includes a bounded-prefix top-level outline and line estimate. If the same oversized file fingerprint is retried, the guard adds a repeated-read dedup hint so Claude reuses the previous ladder instead of retrying full-file Read. `context-guard-read-symbol` extracts a function/class/type-sized slice from Python, JavaScript/TypeScript, Go, or Rust files.

`context-guard-artifact` stores large command output as a local sanitized artifact instead of sending the raw log into Claude context. `store` reads stdin, redacts/anonymizes with the same sanitizer family, writes private `0o600` artifact files under `.context-guard/artifacts` by default, and returns a compact receipt with `artifact_id`, byte/line counts, top error lines, representative samples, and `get --lines` / `get --pattern` query examples. `get` and `list` also read the legacy `.claude-token-optimizer/artifacts` default so old receipts remain queryable after the rebrand. `get` returns only the requested exact slice. Pipeline mode is for capture/query; preserve the producer command's exit code explicitly with shell `pipefail` or a saved `$?` in release checks, or use `context-guard-trim-output -- ...` when exit-code preservation is the primary requirement.

`context-guard-statusline` prints a compact token/cost/model statusline when enabled through project settings. When the Claude Code statusline payload includes a readable `transcript_path`, the line also appends `cache <N>%` — the cache-read share of input-side tokens computed from the transcript tail. The cache label is omitted (rather than failing) when the transcript is missing, unreadable, or `python3` is unavailable, so the statusline never breaks.

`context-guard-statusline-merged` is the default in `examples/settings.example.json` and combines `context-guard-statusline` with the [oh-my-claudecode (OMC)](https://github.com/Yeachan-Heo/oh-my-claudecode) HUD when both are installed. The wrapper auto-detects OMC's HUD at `~/.claude/hud/omc-hud.mjs`: if it is present, the line shows OMC's 5h/week/session usage plus `cost`/`cache` from this plugin; if OMC is not installed, the wrapper falls back to plain `context-guard-statusline` so non-OMC users see no behavior change. Override paths via `OMC_HUD_SCRIPT` and `CONTEXT_GUARD_STATUSLINE_BIN` if your install layout differs.

`context-guard-failed-nudge` is a `PostToolUse` hook on `Bash` that suggests `/clear` (or `/compact focus on …`) when the same Bash command direction fails twice in a row in the same session. On the third repeated failure it adds a strategy-switch signal so Claude stops retrying the identical command path and changes hypothesis, reproducer, or diagnostic scope. Failed attempts pollute the conversation context and force prompt cache rewarming on every retry; nudging Claude to step out and rephrase reduces both. The hook is included in the recommended project-local setup by default because it only emits after repeated failures and never blocks execution. Disable it with `context-guard-setup --no-failed-attempt-nudge` (or pick "no" in the interactive wizard) if the extra hint is noisy for a project. State is project-local under `.context-guard/failures-<session>.json` (file mode `0o600`).

`context-guard-bench` automates `research/benchmark-plan.md` runs: it loads task and variant fixtures from JSON, drives `claude -p --output-format json` for each (task, variant), runs the fixture's `success_command`, and appends a row matching the `tokens_per_successful_task` CSV schema. Add `--ledger-jsonl` to write a per-run cost-shift ledger and `--report-json` to generate a baseline-vs-variant A/B report with real token/cost savings separated from proxy byte reduction, matched successful task coverage, and failure-rate guardrails. `--dry-run` prints the planned `claude` invocations without calling them; `--resume` skips `(task_id, variant)` pairs already present in the CSV. `success_command` is parsed with `shlex.split` and executed with `shell=False`, so fixture JSON is never a shell-injection surface — wrap any pipeline-style success check in a small helper script and reference that script's path instead.

`context-guard-rewrite-bash` is the opt-in `PreToolUse` Bash hook used by the example settings. It rewrites single safe test/build/lint commands and `find`/`tree` directory walks through `context-guard-trim-output`, and single safe `rg`/`grep`/`git diff` style commands plus production log streams (`kubectl logs`, `docker logs`, `docker compose logs`, `docker stack logs`) through `context-guard-sanitize-output` so noisy or secret-bearing output is redacted and trimmed before Claude sees it. Compound shell commands (pipes, redirects, command substitution) are rejected unchanged so the wrapper only applies to a single safe argv.

`context-guard-trim-output` preserves the wrapped command exit code and, when output is trimmed, adds a runner-aware failure summary for common test runners: pytest node ids, Jest/Vitest failing files/tests, `go test` failures, and `cargo test` panic locations. This usually gives Claude the actionable file/test target without sending the full log. Add `--digest markdown` or `--digest json` to emit a compact semantic digest instead of head/tail logs; digest mode keeps status, exit code, truncation counts, runner failure facts, representative lines, redaction counts, and suggested next queries. Wrapped commands time out after 600 seconds by default (`--timeout-seconds` to tune) and return 124 on timeout after terminating the process group where supported. ANSI color codes are stripped and absolute paths are anonymized by default as `basename#path:<hash>`; add `--show-paths` only for local/private debugging.

`context-guard-sanitize-output` is for `rg`/`grep`/`git diff` style output. It redacts common credential patterns, private key blocks, auth headers, and credential URLs, preserves wrapped command exit codes in wrapper mode, enforces the same default 600-second wrapped-command timeout, and trims large results to head / grep-diff-security anchors / tail. Stdin pipeline mode is supported for ad-hoc cleanup, but it cannot preserve the producer command's exit code unless your shell uses `pipefail`. Absolute paths are anonymized by default; add `--show-paths` only for local/private debugging. The example Bash hook rewrites single safe search/diff commands to use this sanitizer automatically.

## Local test before publishing

From the marketplace repository root:

```bash
claude --plugin-dir ./plugins/context-guard
```

Then run:

```text
/context-guard:optimize
```

For marketplace testing:

```text
/plugin marketplace add ./
/plugin install context-guard@context-guard
```


## License

Copyright 2026 jinhongan. Licensed under the Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
