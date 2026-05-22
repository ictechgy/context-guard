# claude-token-optimizer

A Claude Code plugin with skills and helper commands for reducing token usage.

## Skills

After installation, use:

```text
/claude-token-optimizer:setup
/claude-token-optimizer:optimize
/claude-token-optimizer:audit
/claude-token-optimizer:delegate
```

## Helper commands

The plugin includes executables under `bin/`. Claude Code can call them from plugin skills, but your normal shell may not automatically add plugin `bin/` to `PATH`. If a command is not found, either run it by path from this repository root or add the bin directory to `PATH` for the current shell:

```bash
./plugins/claude-token-optimizer/bin/claude-token-setup --plan
export PATH="$PWD/plugins/claude-token-optimizer/bin:$PATH"
```

When the plugin bin directory is on `PATH`, the commands are:

```bash
claude-token-audit ~/.claude/projects --top 20 --recommend
claude-token-setup
claude-token-diet scan . --json
claude-trim-output --max-lines 120 -- npm test
claude-read-symbol path/to/file.py TargetSymbol
claude-sanitize-output -- rg -n "TOKEN|SECRET" .
claude-sanitize-output -- git diff
claude-token-guard-read
claude-token-statusline
claude-token-statusline-merged
claude-token-rewrite-bash
claude-token-delegate status
claude-token-delegate enable --provider gemini
claude-token-delegate ask --provider gemini --prompt "Summarize this log" --context ./log.txt
claude-token-delegate disable
```

`claude-token-audit --recommend` anonymizes transcript paths and command strings by default (`basename#hash`, `command#hash`). Use `--show-paths` or `--show-commands` only for local/private reports.

The audit scanner also bounds transcript reads by default: files above
`--max-file-bytes` and individual JSONL records above `--max-line-bytes` are
skipped with explicit skip counts and warnings instead of being loaded into
memory.

The JSON output includes a `cache_metrics` block (`cache_hit_rate`, `cache_amortization`, `cache_amortization_defined`, raw cache_read/cache_creation/input tokens) so you can tell whether the prompt cache is paying back its write cost. Two recommendations operate on these metrics:

- `improve-prompt-cache-reuse` triggers when amortization (`cache_read / cache_creation`) drops below 0.5 with non-trivial cache writes (`cache_creation` ≥ 10,000 tokens and `cache_read` ≥ 1), which protects baseline / cache-cold sessions from false positives.
- `evaluate-1h-ttl-cache` is heuristic — it flags sessions where writes are large but reuse is moderate; whether to actually flip on the 1h TTL prompt cache beta depends on whether reuse spans more than 5 minutes. See [`research/claude-code-token-reduction.md` §2.7](../../research/claude-code-token-reduction.md) for the price math, break-even reasoning, and an enable/disable checklist before turning the beta on.

`claude-token-setup` is the post-install wizard. Prefer `/claude-token-optimizer:setup` inside Claude Code. In a normal terminal, run `./plugins/claude-token-optimizer/bin/claude-token-setup --plan` from this repository root, or use `claude-token-setup --plan` only after adding the plugin bin directory to `PATH`. It merges `.claude/settings.json` instead of replacing it, never enables manual Gemini/Codex delegation unless selected explicitly with `--aux-provider gemini|codex`, and only enables automatic delegation for that provider when `--auto-delegate` is also provided. Rerunning setup with `--aux-provider` but without `--auto-delegate` clears prior automatic-delegation consent.

`claude-token-diet scan` is a local read-only scanner for project Claude settings and context bloat. It checks missing `permissions.deny` guardrails, Bash trim hook/statusline setup, broad read allows, high default model/effort, many MCP servers, and large/secret-like `CLAUDE.md` or `AGENTS.md` context files. It anonymizes the project root by default; use `--show-paths` only for local/private reports.

`claude-token-guard-read` is an opt-in PreToolUse Read hook that blocks large whole-file reads and suggests `rg -n` plus `claude-read-symbol` or small line-range reads. `claude-read-symbol` extracts a function/class/type-sized slice from Python, JavaScript/TypeScript, Go, or Rust files.

`claude-token-statusline` prints a compact token/cost/model statusline when enabled through project settings. When the Claude Code statusline payload includes a readable `transcript_path`, the line also appends `cache <N>%` — the cache-read share of input-side tokens computed from the transcript tail. The cache label is omitted (rather than failing) when the transcript is missing, unreadable, or `python3` is unavailable, so the statusline never breaks.

`claude-token-statusline-merged` is the default in `examples/settings.example.json` and combines `claude-token-statusline` with the [oh-my-claudecode (OMC)](https://github.com/Yeachan-Heo/oh-my-claudecode) HUD when both are installed. The wrapper auto-detects OMC's HUD at `~/.claude/hud/omc-hud.mjs`: if it is present, the line shows OMC's 5h/week/session usage plus `cost`/`cache` from this plugin; if OMC is not installed, the wrapper falls back to plain `claude-token-statusline` so non-OMC users see no behavior change. Override paths via `OMC_HUD_SCRIPT` and `CLAUDE_TOKEN_STATUSLINE_BIN` if your install layout differs.

`claude-token-failed-nudge` is an optional `PostToolUse` hook on `Bash` that suggests `/clear` (or `/compact focus on …`) when the same Bash command direction fails twice in a row in the same session. Failed attempts pollute the conversation context and force prompt cache rewarming on every retry; nudging Claude to step out and rephrase reduces both. The hook is **off by default** — opt in with `claude-token-setup --failed-attempt-nudge` (or pick "yes" in the interactive wizard). State is project-local under `.claude-token-optimizer/failures-<session>.json` (file mode `0o600`).

`claude-token-bench` automates `research/benchmark-plan.md` runs: it loads task and variant fixtures from JSON, drives `claude -p --output-format json` for each (task, variant), runs the fixture's `success_command`, and appends a row matching the `tokens_per_successful_task` CSV schema. `--dry-run` prints the planned `claude` invocations without calling them; `--resume` skips `(task_id, variant)` pairs already present in the CSV. `success_command` is parsed with `shlex.split` and executed with `shell=False`, so fixture JSON is never a shell-injection surface — wrap any pipeline-style success check in a small helper script and reference that script's path instead.

`claude-token-rewrite-bash` is the opt-in `PreToolUse` Bash hook used by the example settings. It rewrites single safe test/build/lint commands and `find`/`tree` directory walks through `claude-trim-output`, and single safe `rg`/`grep`/`git diff` style commands plus production log streams (`kubectl logs`, `docker logs`, `docker compose logs`, `docker stack logs`) through `claude-sanitize-output` so noisy or secret-bearing output is redacted and trimmed before Claude sees it. Compound shell commands (pipes, redirects, command substitution) are rejected unchanged so the wrapper only applies to a single safe argv.

`claude-trim-output` preserves the wrapped command exit code and, when output is trimmed, adds a runner-aware failure summary for common test runners: pytest node ids, Jest/Vitest failing files/tests, `go test` failures, and `cargo test` panic locations. This usually gives Claude the actionable file/test target without sending the full log. Wrapped commands time out after 600 seconds by default (`--timeout-seconds` to tune) and return 124 on timeout after terminating the process group where supported. ANSI color codes are stripped and absolute paths are anonymized by default as `basename#path:<hash>`; add `--show-paths` only for local/private debugging.

`claude-sanitize-output` is for `rg`/`grep`/`git diff` style output. It redacts common credential patterns, private key blocks, auth headers, and credential URLs, preserves wrapped command exit codes in wrapper mode, enforces the same default 600-second wrapped-command timeout, and trims large results to head / grep-diff-security anchors / tail. Stdin pipeline mode is supported for ad-hoc cleanup, but it cannot preserve the producer command's exit code unless your shell uses `pipefail`. Absolute paths are anonymized by default; add `--show-paths` only for local/private debugging. The example Bash hook rewrites single safe search/diff commands to use this sanitizer automatically.

## Local test before publishing

From the marketplace repository root:

```bash
claude --plugin-dir ./plugins/claude-token-optimizer
```

Then run:

```text
/claude-token-optimizer:optimize
```

For marketplace testing:

```text
/plugin marketplace add ./
/plugin install claude-token-optimizer@claude-token-tools
```


## Auxiliary AI delegation

`claude-token-delegate` lets you opt in to using another locally authenticated AI CLI, such as Gemini or Codex, as a read-only assistant for broad analysis or long logs. It is disabled by default and writes project-local state under `.claude-token-optimizer/`.

```bash
claude-token-delegate status
claude-token-delegate enable --provider gemini
claude-token-delegate enable --provider codex
claude-token-delegate auto-enable
claude-token-delegate ask --provider codex --prompt "Find the likely files to inspect" --context ./error.log
claude-token-delegate disable
```

Only delegate context you are allowed to share with that external provider. The helper prints a bounded, untrusted preview to Claude and saves the full untrusted auxiliary response locally.

Automatic delegation is separate from manual delegation and bound to the approved provider. Use `claude-token-delegate auto-enable` only after manual delegation is enabled and only when plugin skills may share non-sensitive project-local source/log context with the current/default provider. Automatic calls use `--auto` without `--provider`, require helper-validated `--context`, keep `--prompt` to a short read-only instruction, avoid blocked/sensitive/customer/policy-prohibited data, and verify auxiliary output before acting.

Delegation allows project-root context files by default and blocks outside-project paths, obvious secret-like paths, and credential-like file contents. If policy review approves sharing a blocked file with the selected provider, allow only that exact path in the trusted private config `context_policy`; there is no CLI bypass flag. Saved responses are written under `.claude-token-optimizer/` with private file permissions and a private `.gitignore`.

Provider CLIs run with a sanitized environment and isolated `HOME`/XDG/TMP directories. This reduces ambient credential exposure, but it may require API-key based provider auth or a reviewed custom provider setup instead of implicit home-directory OAuth state.

## License

Copyright 2026 jinhongan. Licensed under the Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
