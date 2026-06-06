# ContextGuard

ContextGuard is a local-first context-hygiene toolkit for AI coding and tool agents. It ships as a Claude Code plugin first, then extends the same project-local guardrails to other agents through plain local helper commands and advisory brief-mode rule snippets.

Start with `/context-guard:setup`. Setup is explicit, project-local, and reversible: it merges recommended project settings, prints a read-only context hygiene scan, does not mutate global Claude settings, and does not configure external AI offload.

## Token-waste paths it targets

ContextGuard is a local context-hygiene layer, not a provider prompt cache or semantic answer cache. Its helpers reduce avoidable context bloat before it enters an agent conversation: large file reads are steered toward search/symbol/line-range slices, long command output can be trimmed or digested, large logs can be stored as local artifact receipts, secret-like values are redacted best-effort, repeated Bash failures trigger a strategy nudge, cache-friendly prompt layout can be audited from bounded redacted segment hashes, and audit/benchmark evidence stays tied to your own tasks.

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

The canonical command is `context-guard`; backwards-compatible helper commands keep the `context-guard-*` prefix. Claude Code plugin skills can call the packaged helpers, but your normal shell may not automatically add the plugin `bin/` directory to `PATH`.

For Codex or other terminal-first agents, install the npm package or run it one-off with npx. Installation is passive and does not write configuration.

```bash
npm install -g @ictechgy/context-guard
context-guard setup --agent codex --scope project --with-init --with-skill --plan
npx @ictechgy/context-guard --version
```

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
context-guard cost preflight --request request.json --budget-krw 3000 --json
context-guard cost observe --usage usage.json --json
context-guard-trim-output --max-lines 120 -- npm test
context-guard-read-symbol path/to/file.py TargetSymbol
context-guard-sanitize-output -- rg -n "TOKEN|SECRET" .
context-guard-sanitize-output -- git diff
context-guard-pack suggest --root . --query "review failing tests" --diff HEAD --manifest-out suggested-pack.json --json
context-guard-pack build --root . --manifest suggested-pack.json --budget-bytes 12000 --json
context-guard-pack slice --root . --path README.md --lines 1:40 --json
context-guard-tool-prune select --catalog tools.json --query "review failing tests" --top 5 --budget-bytes 12000 --json
context-guard-tool-prune get <receipt_id> --tool read_file --json
context-guard-statusline
context-guard-statusline-merged
```

## What the helpers do

- **Setup wizard** merges `.claude/settings.json` instead of replacing it, then prints a read-only `context-guard-diet scan` summary. Use `--no-diet-scan` when automation needs setup output without the post-apply scan.
- **Context hygiene scanner** checks missing `permissions.deny` guardrails, Bash trim hook/statusline setup, broad read allows, high default model/effort, many MCP servers, large or secret-like agent rule files, and advisory context-exclusion recommendations for bulky/sensitive local paths. Its `--top` cap applies to both context-like files and context-exclusion recommendations.
- **Large-read guard and symbol reader** guide the agent from search to symbol slices to small line ranges before attempting a whole-file read. Supported source slices include Python, JavaScript/TypeScript, Go, and Rust.
- **Artifact store** saves large sanitized command output under `.context-guard/artifacts` by default and returns compact receipts or exact requested slices. JSON receipts include line-numbered top errors, duplicate-line groups, and sanitized bounded suggested queries. In suggested `--lines START:END` queries, `--max-lines` is only the returned-line cap for that selected range, not a wider selector. `get` and `list` can also read legacy `.claude-token-optimizer/artifacts` receipts.
- **Budgeted context packer** assembles prioritized local file evidence into a rendered byte-budgeted Markdown pack with included/partial/omitted source metadata, bounded `.context-guard/packs` receipts, exact sanitized `slice` commands when safe, and `retrieval_omitted_reason` when a path/root should not be echoed. The additive `suggest` subcommand ranks local query, diff, explicit file, and sanitized output/test-output signals into a build-compatible manifest without network, model, embedding, or provider-cost calls. Token counts are estimated `chars_div_4` proxies, not measured provider-token savings.
- **Tool/MCP schema pruner** ranks local tool catalogs into bounded top-k advisory reports while preserving full sanitized schema fallback through compact receipts and payload integrity checks.
- **Conservative compressor** classifies sanitized stdin as JSON, diff, log, search output, code, or prose and shrinks it with observed byte evidence plus estimated token proxies.
- **Anthropic cost guard** provides `context-guard cost preflight/observe/ledger/compile` for passive pre-call estimates, provider-usage reconciliation, keyed-HMAC cache-risk history, and stable-prefix layout advice. It stores no raw prompt text and does not replace Anthropic prompt caching.
- **Output trimmer** preserves the wrapped command exit code, trims long logs, and can emit `--digest markdown` or `--digest json` summaries with runner failure facts, sanitized failure signatures, duplicate-line groups, and suggested next queries.
- **Sanitizer** redacts common credential patterns, private key blocks, auth headers, credential URLs, and sensitive-looking paths from search, diff, and log output.
- **Statusline** displays compact model/context/cost signals and, when transcript data is available, cache-read and cache-reuse signals.
- **Transcript audit** aggregates usage/cost/cache buckets, flags likely token hotspots, and exposes `cache_friendliness` prompt-layout findings from bounded redacted segment hashes without printing raw prompt text.
- **Repeated-failure nudge** warns after repeated Bash failures so the agent switches strategy instead of retrying the same context-heavy path.
- **Benchmark helper** records matched baseline/variant runs with real token and cost fields, separate byte-reduction proxy evidence, diagnostic `wall_time_seconds`, `provider_cached_tokens`, and provider-cache availability telemetry.

Cost guard creates its local HMAC key automatically at `.context-guard/cost-ledger/hmac.key`. If you provision that file yourself, it must contain exactly one canonical URL-safe base64 32-byte key with required padding and no trailing newline or whitespace. Reports never emit the key or raw prompt text, and the local ledger does not replace Anthropic/provider prompt caching.

## Brief mode (advisory)

Brief mode ships agent-neutral, advisory rule snippets that ask a coding agent to cut filler while preserving evidence: file paths, commands, command output and errors, code blocks, verification status, changed files, known gaps, and caveats. It is best-effort guidance, not enforcement, and does **not** guarantee any token or cost savings.

Three deterministic levels — `lite`, `standard`, `ultra` — live under [`brief/`](brief/). Each is a single marker-delimited block you install into an agent's rule/instruction file (such as `AGENTS.md`, `CLAUDE.md`, a Cursor rules file, or Copilot instructions) and remove by deleting the block. See [`brief/README.md`](brief/README.md).

## Conservative claims

These helpers reduce common sources of context bloat, but they do not guarantee a fixed percentage savings. Use `context-guard-bench --ledger-jsonl ... --report-json ...` when you need measured before/after evidence for your own tasks; token-savings claims require `primary_tokens_measured` on both matched sides, and wall-time/provider-cache fields are diagnostic telemetry, not standalone savings proof. Audit `cache_friendliness` findings are heuristic layout signals, not billing authority. Benchmark CSV schemas are strict, so start a new CSV or migrate the header after helper upgrades.

ContextGuard also does not send work to external AI providers to save model tokens. All helper commands run locally. Local RAM/disk receipts can reduce what you choose to send, but they do not replace a provider prompt cache. Before release or billing claims for Anthropic, recheck the official prompt-caching and pricing docs: https://docs.anthropic.com/en/build-with-claude/prompt-caching and https://platform.claude.com/docs/en/about-claude/pricing.

Future learned, multimodal, and self-hosted optimization ideas are tracked only in [`../../research/experimental-token-reduction-radar.md`](../../research/experimental-token-reduction-radar.md). That radar is not a shipped runtime feature and does not claim hosted API savings without provider-measured matched-task evidence.

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
