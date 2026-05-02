# claude-token-optimizer

A Claude Code plugin with skills and helper commands for reducing token usage.

## Skills

After installation, use:

```text
/claude-token-optimizer:optimize
/claude-token-optimizer:audit
/claude-token-optimizer:delegate
```

## Helper commands

The plugin exposes executables in `bin/` while enabled:

```bash
claude-token-audit ~/.claude/projects --top 20 --recommend
claude-token-diet scan . --json
claude-trim-output --max-lines 120 -- npm test
claude-token-statusline
claude-token-rewrite-bash
claude-token-delegate status
claude-token-delegate enable --provider gemini
claude-token-delegate ask --provider gemini --prompt "Summarize this log" --context ./log.txt
claude-token-delegate disable
```

`claude-token-audit --recommend` anonymizes transcript paths and command strings by default (`basename#hash`, `command#hash`). Use `--show-paths` or `--show-commands` only for local/private reports.

`claude-token-diet scan` is a local read-only scanner for project Claude settings and context bloat. It checks missing `permissions.deny` guardrails, Bash trim hook/statusline setup, broad read allows, high default model/effort, many MCP servers, and large/secret-like `CLAUDE.md` or `AGENTS.md` context files. It anonymizes the project root by default; use `--show-paths` only for local/private reports.

`claude-trim-output` preserves the wrapped command exit code and, when output is trimmed, adds a runner-aware failure summary for common test runners: pytest node ids, Jest/Vitest failing files/tests, `go test` failures, and `cargo test` panic locations. This usually gives Claude the actionable file/test target without sending the full log. ANSI color codes are stripped and absolute paths are anonymized by default as `basename#path:<hash>`; add `--show-paths` only for local/private debugging.

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
claude-token-delegate ask --provider codex --prompt "Find the likely files to inspect" --context ./error.log
claude-token-delegate disable
```

Only delegate context you are allowed to share with that external provider. The helper prints a bounded, untrusted preview to Claude and saves the full untrusted auxiliary response locally.


Delegation allows project-root context files by default and blocks outside-project paths, obvious secret-like paths, and credential-like file contents. If policy review approves sharing a blocked file with the selected provider, allow only that exact path in the trusted private config `context_policy`; there is no CLI bypass flag. Saved responses are written under `.claude-token-optimizer/` with private file permissions and a private `.gitignore`.

Provider CLIs run with a sanitized environment and isolated `HOME`/XDG/TMP directories. This reduces ambient credential exposure, but it may require API-key based provider auth or a reviewed custom provider setup instead of implicit home-directory OAuth state.
