# Claude Code Token Reduction Research

Research date: 2026-05-01

This repository is a research and experiment workspace for reducing Claude Code CLI token usage and context waste.

Korean documentation is available in [`README.ko.md`](README.ko.md).

## Artifacts

- `research/claude-code-token-reduction.md` — core research report and prioritized action plan
- `research/benchmark-plan.md` — benchmark design for validating token savings
- `claude-token-kit/` — statusline, output trim/sanitize, transcript audit, settings scan, large Read guard, and auxiliary AI delegation tools
- `plugins/claude-token-optimizer/` — Claude Code plugin distribution package

## 5-minute application summary

1. In Claude Code, check `/usage`, `/context`, `/model`, and `/effort` first.
2. Use `/clear` when switching unrelated tasks; for long tasks, use `/compact <what to preserve>`.
3. Default to `sonnet`, reserve `opusplan` for design or difficult reasoning, and use lower `/effort` for simple work.
4. Keep `CLAUDE.md` short; move long workflow instructions into skills or custom commands.
5. Minimize MCP servers and prefer CLI tools such as `gh`, `rg`, `jq`, `aws`, and `gcloud` where possible.
6. Return only failure-focused slices of test/build logs to Claude through hooks or wrappers.
7. Use subagents to isolate noisy research/log analysis, but keep agent teams small because each agent multiplies token usage.

For the rationale and the safe-vs-not-recommended distinction, see `research/claude-code-token-reduction.md`.

## Claude Code plugin distribution

This repository is also structured as a Claude Code plugin marketplace.

- Marketplace file: `.claude-plugin/marketplace.json`
- Plugin: `plugins/claude-token-optimizer/`
- Main skills after install:
  - `/claude-token-optimizer:setup`
  - `/claude-token-optimizer:optimize`
  - `/claude-token-optimizer:audit`
  - `/claude-token-optimizer:delegate`

Local test:

```bash
claude --plugin-dir ./plugins/claude-token-optimizer
```

Marketplace test from this repository root:

```text
/plugin marketplace add ./
/plugin install claude-token-optimizer@claude-token-tools
```

After publishing to GitHub, users can add the marketplace with:

```text
/plugin marketplace add YOUR_GITHUB_USER/YOUR_REPO
/plugin install claude-token-optimizer@claude-token-tools
```

This plugin intentionally does not auto-enable hooks globally. See `plugins/claude-token-optimizer/examples/settings.example.json` for an opt-in project settings example.

After installing, run the guided project setup instead of memorizing all helper commands. Inside Claude Code, use:

```text
/claude-token-optimizer:setup
```

Plugin helper binaries are not guaranteed to be added to your normal shell `PATH`. For local testing from this repository root, run the helper by path:

```bash
./plugins/claude-token-optimizer/bin/claude-token-setup --plan
./plugins/claude-token-optimizer/bin/claude-token-setup --yes
```

If you want short shell commands during local development, temporarily add the plugin bin directory:

```bash
export PATH="$PWD/plugins/claude-token-optimizer/bin:$PATH"
claude-token-setup --plan
```

The wizard lets you choose deny rules, statusline, Bash trim/sanitize hook, large Read guard, model/effort defaults, and optional Gemini/Codex delegation. It merges project-local `.claude/settings.json`; it does not modify global Claude settings.

Note: this plugin source repository ignores local Claude runtime state, including `.claude/`, because setup runs here are test-local. In your own project, decide whether team-wide `.claude/settings.json` should be committed or kept local according to your policy.

For local project hygiene, run:

```bash
./plugins/claude-token-optimizer/bin/claude-token-diet scan .
```

It reports missing `permissions.deny` guardrails, noisy-output hook/statusline gaps, broad reads, expensive defaults, many MCP servers, and large/secret-like context files.

For large files, prefer symbol-sized context:

```bash
./plugins/claude-token-optimizer/bin/claude-read-symbol path/to/file.py TargetSymbol
```

The example settings can also enable `claude-token-guard-read`, which blocks accidental whole-file reads above the guard threshold and points Claude to `rg` plus symbol/line-range reads.

For long test/build logs, trim output before sending it back to Claude:

```bash
./plugins/claude-token-optimizer/bin/claude-trim-output --max-lines 120 -- npm test
```

For search or diff output that may contain secrets, sanitize before sending it back to Claude:

```bash
./plugins/claude-token-optimizer/bin/claude-sanitize-output -- rg -n "TOKEN|SECRET" .
./plugins/claude-token-optimizer/bin/claude-sanitize-output -- git diff
```

Wrapper mode preserves the wrapped command exit code. Pipeline mode such as `git diff | claude-sanitize-output` is still useful for ad-hoc cleanup, but the sanitizer cannot know the producer's exit code unless your shell uses `pipefail`. The same Bash hook that trims test/build logs can also auto-wrap single safe `rg`/`grep`/`git diff` commands with the sanitizer.

### Optional: auxiliary AI delegation

If you also have Gemini CLI or Codex CLI access, the plugin can use them as an opt-in read-only assistant to save Claude tokens on broad exploration or long logs:

```text
/claude-token-optimizer:delegate enable --provider gemini
/claude-token-optimizer:delegate auto-enable
/claude-token-optimizer:delegate ask --provider gemini --prompt "Summarize this failing test log" --context ./log.txt
/claude-token-optimizer:delegate disable
```

The underlying command is `claude-token-delegate`. Manual delegation is OFF by default, stores local state in `.claude-token-optimizer/`, prints only a bounded preview back to Claude, and saves full auxiliary responses locally. Do not delegate secrets or private data to another AI provider unless your policy allows it.

Automatic delegation is a separate provider-bound opt-in. After manual delegation is enabled, run `claude-token-delegate auto-enable` only if plugin skills may use the current/default provider for safe read-only work that would otherwise burn a lot of Claude context, such as long-log summarization, broad file triage, root-cause hypotheses, or second-opinion planning. Automatic calls omit `--provider` so the helper uses only the approved provider, must use helper-validated `--context` files, keep `--prompt` to a short instruction, avoid blocked/sensitive/customer/policy-prohibited data, and treat auxiliary output as untrusted until verified.

## License

Copyright 2026 jinhongan. Licensed under the Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
