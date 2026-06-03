# ContextGuard

ContextGuard is a local-first context-hygiene toolkit for AI coding and tool agents. It ships as a Claude Code plugin first, then extends the same project-local guardrails to other agents through plain local helper commands and advisory brief-mode rule snippets.

Start with `/context-guard:setup`. Setup is explicit, project-local, and reversible: it merges recommended project settings, prints a read-only context hygiene scan, does not mutate global Claude settings, and does not configure external AI offload.

## Token-waste paths it targets

ContextGuard is a local context-hygiene layer, not a provider prompt cache or semantic answer cache. Its helpers reduce avoidable context bloat before it enters an agent conversation: large file reads are steered toward search/symbol/line-range slices, long command output can be trimmed or digested, large logs can be stored as local artifact receipts, secret-like values are redacted best-effort, repeated Bash failures trigger a strategy nudge, and audit/benchmark evidence stays tied to your own tasks.

## Rebrand note

Claude Code does not alias the old `/claude-token-optimizer:*` plugin slash-command namespace. Use `/context-guard:*` after installing this plugin.

Legacy local CLI wrappers (`claude-token-*`, `claude-read-symbol`, `claude-trim-output`, and `claude-sanitize-output`) remain in `bin/` so existing automation can migrate gradually.

## Skills

After installation, use these skills inside Claude Code:

```text
/context-guard:setup
/context-guard:optimize
/context-guard:audit
```

| Skill | Purpose |
| --- | --- |
| `/context-guard:setup` | First-time project setup wizard. |
| `/context-guard:optimize` | Inspect and tune context guardrails. |
| `/context-guard:audit` | Audit local Claude transcript token/cost hotspots. |

## Helper commands and PATH

The canonical helper prefix is `context-guard-*`. Claude Code plugin skills can call the packaged helpers, but your normal shell may not automatically add the plugin `bin/` directory to `PATH`.

From this repository root, run helpers by path:

```bash
./plugins/context-guard/bin/context-guard-setup --plan
./plugins/context-guard/bin/context-guard-diet scan . --json
```

For local development, add the plugin bin directory to your current shell:

```bash
export PATH="$PWD/plugins/context-guard/bin:$PATH"
context-guard-setup --plan
```

Common helpers:

```bash
context-guard-audit ~/.claude/projects --top 20 --recommend
context-guard-setup
context-guard-diet scan . --json
context-guard-artifact store --command "long-command" --json < large.log
context-guard-artifact get <artifact_id> --lines 1:80
context-guard-compress --json < large-output.txt
context-guard-trim-output --max-lines 120 -- npm test
context-guard-read-symbol path/to/file.py TargetSymbol
context-guard-sanitize-output -- rg -n "TOKEN|SECRET" .
context-guard-sanitize-output -- git diff
context-guard-pack build --root . --source 'path=README.md,priority=100,lines=1:80' --budget-bytes 12000 --json
context-guard-pack slice --root . --path README.md --lines 1:40 --json
context-guard-statusline
context-guard-statusline-merged
```

## What the helpers do

- **Setup wizard** merges `.claude/settings.json` instead of replacing it, then prints a read-only `context-guard-diet scan` summary. Use `--no-diet-scan` when automation needs setup output without the post-apply scan.
- **Context hygiene scanner** checks missing `permissions.deny` guardrails, Bash trim hook/statusline setup, broad read allows, high default model/effort, many MCP servers, large or secret-like agent rule files, and advisory context-exclusion recommendations for bulky/sensitive local paths.
- **Large-read guard and symbol reader** guide the agent from search to symbol slices to small line ranges before attempting a whole-file read. Supported source slices include Python, JavaScript/TypeScript, Go, and Rust.
- **Artifact store** saves large sanitized command output under `.context-guard/artifacts` by default and returns compact receipts or exact requested slices. JSON receipts include line-numbered top errors, duplicate-line groups, and sanitized bounded suggested queries. `get` and `list` can also read legacy `.claude-token-optimizer/artifacts` receipts.
- **Budgeted context packer** assembles prioritized local file evidence into a rendered byte-budgeted Markdown pack with included/partial/omitted source metadata, bounded `.context-guard/packs` receipts, and exact sanitized `slice` commands.
- **Conservative compressor** classifies sanitized stdin as JSON, diff, log, search output, code, or prose and shrinks it with observed byte evidence plus estimated token proxies.
- **Output trimmer** preserves the wrapped command exit code, trims long logs, and can emit `--digest markdown` or `--digest json` summaries with runner failure facts, sanitized failure signatures, duplicate-line groups, and suggested next queries.
- **Sanitizer** redacts common credential patterns, private key blocks, auth headers, credential URLs, and sensitive-looking paths from search, diff, and log output.
- **Statusline** displays compact model/context/cost signals and, when transcript data is available, cache-read and cache-reuse signals.
- **Repeated-failure nudge** warns after repeated Bash failures so the agent switches strategy instead of retrying the same context-heavy path.
- **Benchmark helper** records matched baseline/variant runs with real token and cost fields, separate byte-reduction proxy evidence, diagnostic `wall_time_seconds`, `provider_cached_tokens`, and provider-cache availability telemetry.

## Brief mode (advisory)

Brief mode ships agent-neutral, advisory rule snippets that ask a coding agent to cut filler while preserving evidence: file paths, commands, command output and errors, code blocks, verification status, changed files, known gaps, and caveats. It is best-effort guidance, not enforcement, and does **not** guarantee any token or cost savings.

Three deterministic levels — `lite`, `standard`, `ultra` — live under [`brief/`](brief/). Each is a single marker-delimited block you install into an agent's rule/instruction file (such as `AGENTS.md`, `CLAUDE.md`, a Cursor rules file, or Copilot instructions) and remove by deleting the block. See [`brief/README.md`](brief/README.md).

## Conservative claims

These helpers reduce common sources of context bloat, but they do not guarantee a fixed percentage savings. Use `context-guard-bench --ledger-jsonl ... --report-json ...` when you need measured before/after evidence for your own tasks; token-savings claims require `primary_tokens_measured` on both matched sides, and wall-time/provider-cache fields are diagnostic telemetry, not standalone savings proof. Benchmark CSV schemas are strict, so start a new CSV or migrate the header after helper upgrades.

ContextGuard also does not send work to external AI providers to save model tokens. All helper commands run locally.

Cross-agent rule snippets are advisory: the target agent may ignore them, so measure actual before/after behavior when you need a savings claim.

## Local test before publishing

From the marketplace repository root:

```bash
claude --plugin-dir ./plugins/context-guard
```

Then run inside Claude Code:

```text
/context-guard:setup
```

Marketplace installation test:

```text
/plugin marketplace add ./
/plugin install context-guard@context-guard
```

## License

Copyright 2026 jinhongan. Licensed under the Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
