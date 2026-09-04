# ContextGuard

ContextGuard is a local-first context-management toolkit for AI coding and tool-using agents. It starts with a Claude Code plugin: install it once, enable it explicitly per project, and roll it back when needed.

It trims noisy output, guides agents toward symbol-level reads, flags repeated failures, redacts secret-like patterns, and measures usage. The same guardrails are reusable by other agents through local helper commands and advisory brief-mode snippets.

- Korean documentation: [`README.ko.md`](README.ko.md)
- Static landing page: [GitHub Pages](https://ictechgy.github.io/context-guard/) ([source](docs/index.html))

## Quickstart

```bash
/plugin marketplace add ictechgy/context-guard && /plugin install context-guard@context-guard   # Claude Code
/context-guard:setup          # applies the recommended project-local hooks after showing a plan
/context-guard:audit          # shows where your tokens went, by tool and per turn
```

npm users run `npx @ictechgy/context-guard setup --profile recommended --plan` then `--yes`.

## TL;DR

Installation and activation are deliberately separate. Installing ContextGuard only makes local helpers or Claude plugin skills available; it does not write configuration until you run an explicit setup command.

| If you use... | Install | Activate |
| --- | --- | --- |
| Claude Code | `/plugin marketplace add ictechgy/context-guard` then `/plugin install context-guard@context-guard` | Run `/context-guard:setup` inside the project. |
| Codex CLI or any terminal-first agent | `npm install -g @ictechgy/context-guard` or one-shot `npx @ictechgy/context-guard ...` | `context-guard setup --agent codex --scope project --with-init --with-skill --with-mcp --plan`, then rerun with `--yes`. |
| Other rule-file agents | Use the npm/npx install path above. | Use `--with-init`; add `--with-mcp` for Gemini, Cursor, Copilot, OpenCode, or ForgeCode. |
| macOS/Homebrew users | Release path: `brew install ictechgy/tap/context-guard` | Same `context-guard setup ...` commands after install. |

Common commands:

```bash
npm install -g @ictechgy/context-guard
npx @ictechgy/context-guard --version
context-guard setup --agent codex --scope project --with-init --with-skill --with-mcp --plan
context-guard setup --agent claude --scope user --verify --json  # read-only user-scope check
context-guard setup --agent claude --scope user --plan
```

Project scope is the default. User-level setup is opt-in, requires an explicit agent for writes, records backups and rollback metadata, and never runs during package installation. Before applying setup, run `context-guard setup --verify` for a read-only health check; `context-guard doctor` is an alias of it. Setup looks for bundled or checkout-local helpers first; it does not trust arbitrary `PATH` helpers unless you explicitly pass `--allow-path-helper-fallback` for a known-good install.

Distribution and helper trust boundaries are conservative too: npm exposes only canonical `context-guard`/`context-guard-*` bin links, command manifests are treated as literal data rather than executable Python, and the macOS visibility helper is discovered only from bundled/resource/executable-relative paths or an absolute explicit override with a minimal child environment. Current working directories, relative overrides, symlinked helpers, arbitrary `PATH`, and ambient shell environment are not trusted by default.

ContextGuard is intentionally conservative about savings claims. It reduces common sources of context bloat and provides benchmark tooling so you can measure before-and-after results on your own tasks. It does **not** promise a fixed token or cost reduction for every repository.

## Claude Code first, other agents too

ContextGuard ships as a Claude Code plugin first, which is still the fastest starting point for Claude users. After installation, the same local-first guardrails can be reused by other AI coding and tool-using agents through:

- **Local helper commands** (`context-guard-*`) that run as plain shell commands, independent of any specific agent.
- **Advisory brief-mode rule snippets** that you install into an agent's own instruction file (`AGENTS.md`, `GEMINI.md`, `.cursorrules`, Copilot instructions, and similar rule files) and remove by deleting the marker-delimited block.
- **Dry-run cross-agent setup** that writes only local files, backs up before changing anything, and applies only with explicit approval.

Current setup surfaces:

| Agent or tool | ContextGuard surface |
| --- | --- |
| Claude Code | Native plugin setup for project-local hooks, deny rules, and statusline configuration. |
| OpenAI Codex CLI | Advisory `AGENTS.md` plus optional project skill and `.codex/config.toml` stdio MCP setup. |
| Gemini CLI | Advisory `GEMINI.md` plus optional `.gemini/settings.json` MCP. |
| Cursor | Advisory `.cursorrules` plus optional `.cursor/mcp.json`. |
| Windsurf | Advisory `.windsurf/rules/contextguard.md` rule block. |
| Cline | Advisory `.clinerules` rule block, with file/directory handling. |
| GitHub Copilot Coding Agent | Advisory `.github/copilot-instructions.md` plus optional `.vscode/mcp.json`. |
| OpenCode | Existing project skill plus optional `opencode.json` MCP. |
| ForgeCode | Optional project `.mcp.json`; helpers remain shell-driven. |
| Windsurf, Cline, or unknown agents | Rule-file or shell usage; no automatic project MCP write. |

The generated [setup capability and flag reference](docs/setup-reference.md)
is derived from the adapter registry and CLI parser and is checked for drift by
the prepublish gate.

## How ContextGuard reduces token waste

ContextGuard does not change model prices. It reduces avoidable context before it reaches an AI coding agent, then gives you signals to measure whether the change helped.

| Waste path | ContextGuard guardrail |
| --- | --- |
| Whole-file reads for one function | Suggest search, symbol slices, bounded outlines, and small line ranges before a full read. |
| Long test, build, search, or diff output | Trim output, emit structured digests, or store large logs locally and return compact receipts. |
| Repeated failing commands | Warn after repeated Bash failures so the agent changes strategy before more stale logs enter context. |
| Secret-like or noisy terminal output | Apply best-effort pattern-based redaction for common credential patterns and sensitive-looking paths before output is copied into context. |
| Unknown token/cost hotspots | Surface statusline signals, transcript audits, and matched benchmark reports for before/after evidence. |
| Anthropic API requests that may miss prompt cache | `context-guard cost preflight` estimates input size, breakpoint-level cache risk, and low/mid/high cost ranges before a call; default mode warns only. |
| Volatile context before stable prompt prefixes | Audit bounded redacted prompt-segment hashes and flag likely cache-unfriendly prompt layouts without exposing raw prompt text. |
| Large tool/MCP catalogs for one narrow task | Rank a local tool catalog into a bounded top-k schema report while keeping full sanitized schemas retrievable from local receipts. |

## How it fits with caching and compression tools

ContextGuard complements provider and semantic caches, and works alongside prompt compression. Its main job is simpler: **do not send unnecessary files, logs, or output in the first place**.

| Tool category | Saves by | ContextGuard relationship |
| --- | --- | --- |
| Provider prompt/context caching | Reusing stable prompt prefixes. | Complementary; ContextGuard helps keep the changing tail of context smaller and cleaner, `context-guard-audit` can flag likely volatile prefix layouts, and `context-guard cost` can warn when an Anthropic request is likely to cache-write instead of cache-read. |
| Semantic response cache | Reusing answers to identical or similar requests. | Complementary; ContextGuard does not serve cached AI answers. |
| Prompt/context compression | Shortening text that is already selected for the model. | Adjacent; ContextGuard trims and summarizes local output, but does not promise lossless semantic compression. |
| Experimental planners and local runtimes | Default-off, explicit-command-only lanes. | All experimental planners are off by default, plan-only, and documented in [`docs/experiments.md`](docs/experiments.md). |
| ContextGuard | Avoiding unnecessary files, logs, repeated failures, and noisy output before they enter agent context. | Local guardrails, reversible artifacts, and measurement. |

Related patterns that informed the design:

| Approach | What it emphasizes | ContextGuard relationship |
| --- | --- | --- |
| Compression-first | Shortening text already selected for the model, often with lossy transforms. | ContextGuard prefers local artifact storage with exact slice retrieval over lossy one-way compression, so you can get the original back. |
| Terse-output rulesets across agents | Installing brief-mode output rules into many agents at once. | ContextGuard offers advisory brief-mode snippets and dry-run cross-agent setup — opt-in per project, no guaranteed savings claimed. |
| ContextGuard | Avoiding unnecessary files, logs, and output before they enter context, with conservative measurement. | Local guardrails, reversible artifacts and retrieval, plus benchmark evidence you measure yourself. |

## Brief mode (advisory)

Brief mode is a set of agent-neutral, advisory rule snippets that ask a coding agent to cut filler while preserving reviewer evidence: file paths, commands, command output and errors, code blocks, verification status, changed files, known gaps, and caveats. It is best-effort guidance, not enforcement, and does **not** guarantee token or cost savings.

Three deterministic levels ship under [`plugins/context-guard/brief/`](plugins/context-guard/brief/): `lite`, `standard`, and `ultra`. Each level is a single marker-delimited block for an agent's rule/instruction file (for example `AGENTS.md`, `CLAUDE.md`, a Cursor rules file, or Copilot instructions). Manage it through setup with `context-guard setup --agent codex --scope project --brief-mode standard --plan`, rerun with `--yes` to apply, and use `--brief-mode off` to remove the managed block. See [`plugins/context-guard/brief/README.md`](plugins/context-guard/brief/README.md).

### Standing cost and break-even

Advisory rule blocks are not free. They live in an agent's rule file, so they are
re-sent with every request for as long as they are installed:

| Managed block | Installed size |
| --- | --- |
| `brief-mode.lite` | 1,487 bytes |
| `brief-mode.standard` | 1,568 bytes |
| `brief-mode.ultra` | 1,523 bytes |
| `narration-mode.quiet` | 866 bytes |

That is a fixed per-request cost paid up front, while the benefit is a
probabilistic reduction in reply length that ContextGuard cannot enforce. On a
session with few turns, or with an agent that already answers tersely, the block
can cost more than it saves. The hook-based guardrails behave differently: they
charge only when they act, and the measured worst cases stay small — a
sub-threshold `Read` adds 3 bytes, and repeated large-read attempts shrink after
the first warning instead of accumulating.

Before installing a rule block for its token effect, measure it. Use
`context-guard-bench` on matched tasks with and without the block, and treat the
block's installed size as the break-even threshold your reply-length reduction has
to clear. Byte counts here are observed; token effects are not, and no fixed
saving is claimed.

## Quiet narration for Claude (advisory)

Quiet narration is a separate, default-off Claude-only rule for reducing discretionary preambles, per-tool narration, filler, and repeated interim summaries. It still requires approvals and decisions, blockers, failures, destructive or security warnings, higher-priority progress updates, the final result, changed files, and verification. It is best-effort guidance, independent of final-answer brevity or reasoning depth, and does **not** guarantee token or cost savings.

```bash
context-guard setup --rules-only --agent claude --scope project --narration-mode quiet --plan
context-guard setup --rules-only --agent claude --scope project --narration-mode quiet --yes
context-guard setup --rules-only --agent claude --scope project --narration-mode default --yes
```

This isolated operation manages only ContextGuard's narration span in the project's `CLAUDE.md`. It does not read or change Claude settings, hooks, permissions, statusline, model defaults, or other agents' rule files. It cannot be combined with brief mode, initialization, skill generation, or normal setup actions. Gate C verifies the static rule and setup side effects only; it does not prove model compliance or authorize a numeric savings claim.

## What to measure

If you need a savings claim, measure it on your own tasks:

- full-file reads versus symbol or line-range reads
- raw logs versus digest output or artifact receipts
- transcript hotspots reported by `context-guard-audit`, including `cache_friendliness` prompt-layout signals and `cache_layout_advice` experiment priorities
- statusline `cache` / `reuse` as observed transcript/provider-cache signals, not savings caused by ContextGuard
- `context-guard cost preflight` estimates for Anthropic request JSON, followed by `context-guard cost observe` using provider usage fields (`cache_creation_input_tokens`, `cache_read_input_tokens`) after the call
- static prompt/request cache layout checks from `context-guard-cache-score`, including optional user-supplied cache write/read multiplier amortization risk; its char/4 token estimates and warnings are advisory only until provider usage fields confirm real cache hits
- matched successful baseline/variant runs from `context-guard-bench`
- large tool/MCP catalogs versus `context-guard-tool-prune` top-k reports plus receipt retrieval
- optional experimental lanes in [`research/experimental-token-reduction-radar.md`](research/experimental-token-reduction-radar.md); fixture-only starters in [`docs/experimental-benchmark-fixtures.md`](docs/experimental-benchmark-fixtures.md) use the same matched-task benchmark gates before any savings claim

## What ContextGuard does not do

- It does not guarantee a fixed token or cost reduction.
- It does not send work to external AI providers to save model tokens.
- It does not mutate global Claude settings during install.
- It does not execute command manifests as code or trust arbitrary `PATH`/current-working-directory helpers during setup or packaged smoke checks.
- It does not replace real before/after measurement when you need a savings claim.
- Local RAM/disk receipts can help reduce what you send next, but they do **not** replace Anthropic's provider prompt cache or guarantee cache hits. Recheck Anthropic prompt-caching and pricing docs before release or billing claims: https://docs.anthropic.com/en/build-with-claude/prompt-caching and https://platform.claude.com/docs/en/about-claude/pricing.
- Experimental helpers are default-off, plan-only or narrow explicit local runtimes; see [`docs/experiments.md`](docs/experiments.md).
- ContextGuard does not ship learned/synthetic compressor execution, embeddings, rerankers, model calls, generated replacement text, screenshot capture, image cropping, OCR execution, image parsing, external OCR/image services, self-hosted KV/latent inference optimization beyond explicit local metrics recording, or broader proxy forwarding beyond literal-loopback, one-request HTTP forwarding with credential material blocked.
- It does not alias the old `/claude-token-optimizer:*` Claude Code slash-command namespace. Use `/context-guard:*` after installing this plugin.

Legacy `claude-*` wrapper names were removed in this release; use the `context-guard-*` names instead (migration: replace the prefix).

## Features

| Feature | What it helps with |
| --- | --- |
| Claude Code plugin skills | Guided setup, optimization, and transcript usage audits. |
| Project-local setup wizard | Applies recommended `.claude/settings.json` options without touching global settings. |
| Context management scanner | Finds missing guardrails, noisy hooks, broad reads, large context files, secret-like files, excessive MCP servers, and expensive defaults. |
| Structural-waste doctor | Opt-in local diagnostics for duplicate rules, stale imports, unused skill candidates, oversized tool schemas, and repeated read/tool-call loops. |
| Large-read guard and symbol reader | Nudges the agent toward `rg`, symbol reads, and small line ranges instead of full-file reads. |
| Output trimming and sanitizing | Keeps test, build, search, and diff output compact while redacting likely secrets before they enter agent context. |
| Declarative output filter | Opt-in JSON DSL for user-owned command filters with protected failure passthrough and validation before use. |
| Local artifact store | Saves large sanitized logs outside the conversation and returns compact receipts or exact requested slices. |
| Anthropic cost guard | `context-guard cost preflight/observe/ledger/compile` estimates cache risk and cost ranges. `context-guard-receipt evaluate full-wire` compares complete baseline/candidate request envelopes under one canonical-byte ceiling and can require protected JSON pointers plus the output-token budget to stay unchanged or smaller. `context-guard route-advisor` summarizes local total-cost and batchability route candidates, stores only keyed HMAC fingerprints where a ledger is used, and stays passive unless `--enforce` is explicit. |
| Budgeted context packer | Assembles prioritized local file evidence into a byte-budgeted Markdown pack, can suggest a build-compatible manifest from local signals, adds `--explain` for compact local selection reasons plus bounded repo-map metadata, and adds opt-in `--adaptive-k` / `--symbol-memory` advisory metadata. |
| Tool/MCP schema pruner | Emits bounded top-k tool/schema advisory reports from local catalogs with compact receipts and full sanitized payload retrieval. |
| Conservative stdin compressor | Shrinks selected JSON, diffs, logs, search output, code, and prose with observed byte evidence and estimated token proxies; `--mode readable` adds an opt-in readable prose preview with exact fallback guidance. |
| Protected-zone policy receipts | Opt-in `context-guard-compress --protected-policy` and `context-guard cost compile` metadata mark code/diff/path/hash/JSON/literal zones as structural-only with exact retrieval guidance. |
| Repeated-failure nudge | Warns after repeated Bash failures so the agent changes strategy before stale logs fill the context. |
| Statusline, audit, and benchmarks | Shows context/cache/cost signals, finds usage and cache-friendliness hotspots, and records conservative before/after evidence. |

### Cost guard key provisioning

Cost guard creates its local HMAC key automatically at `.context-guard/cost-ledger/hmac.key`. If you provision that file yourself, it must contain exactly one canonical URL-safe base64 32-byte key with required padding and no trailing newline or whitespace. Reports never emit the key or raw prompt text, and the local ledger does not replace Anthropic/provider prompt caching.

## Install in Claude Code

Add the marketplace and install the plugin:

```text
/plugin marketplace add ictechgy/context-guard
/plugin install context-guard@context-guard
```

Then run setup from Claude Code in the project you want to protect:

```text
/context-guard:setup
```

Available plugin skills:

| Skill | Purpose |
| --- | --- |
| `/context-guard:setup` | First-time project setup wizard. |
| `/context-guard:optimize` | Inspect and tune context guardrails. |
| `/context-guard:audit` | Audit local Claude transcript token/cost hotspots. |

Setup is explicit, project-local, and reversible. The plugin does not configure external model delegation or offload; all helper commands run locally. See [`plugins/context-guard/examples/settings.example.json`](plugins/context-guard/examples/settings.example.json) for an example settings file.

## Install with npm/npx

The npm package exposes a canonical `context-guard` command plus `context-guard-*` helper commands. Package installation is passive: there is no `postinstall` setup hook and no config write until you run `context-guard setup` yourself. npm global/`npx` bin links intentionally expose only canonical `context-guard`/`context-guard-*` commands; the legacy `claude-*` wrapper files were removed in this release. If setup cannot find bundled or checkout-local helpers, `PATH` fallback remains disabled by default; use `--allow-path-helper-fallback` only for trusted helper directories after `context-guard doctor` or `setup --verify` confirms the plan.

```bash
npm install -g @ictechgy/context-guard
context-guard --version
context-guard doctor --root . --json
context-guard setup --agent codex --scope project --with-init --with-skill --with-mcp --plan
context-guard setup --agent codex --scope project --brief-mode standard --plan
```

For a one-off run without global installation:

```bash
npx @ictechgy/context-guard setup --agent codex --scope project --with-init --with-skill --with-mcp --plan
npx @ictechgy/context-guard setup --agent codex --scope project --brief-mode standard --plan
npm exec @ictechgy/context-guard -- --version
```

Use `--scope project` for repository files such as `AGENTS.md` and `.agents/skills/...`. Use `--scope user` only when you intentionally want a user-level path; applying user scope requires `--yes` plus an explicit `--agent`, and supported writes record rollback metadata.

`--with-mcp` safely manages one backed-up Codex project stdio block; other
verified project targets use the same conflict-safe JSON merge. Windsurf and
Cline remain report-only for MCP because their documented settings are user or
IDE scoped. See the [official Codex MCP documentation](https://learn.chatgpt.com/docs/extend/mcp).

### Opt-in Bash references for Claude Code

The `bash_reference_v1` route is available only from an exact, project-local npm
installation. The root package pins `@ictechgy/context-guard-receipt@0.4.0`; a
global, `npx`, source-checkout, Homebrew, or Claude marketplace-plugin layout
keeps the existing Bash trim behavior and setup reports the reference route as
unavailable.

That requirement is deliberate rather than an oversight. Installing into the
project anchors the Receipt bytes to the registry integrity value in the
project's own lockfile — a root of trust outside the running ContextGuard — so a
compromised update channel cannot swap the code that handles a project's
captured output without a reinstall the project owner performs. A relaxation
that replaced the install with a project-owned file naming a version was
designed and rejected in review for losing exactly that anchor; see
[`research/receipt-install-shape-boundary-20260831.md`](research/receipt-install-shape-boundary-20260831.md).

```bash
npm install --save-exact @ictechgy/context-guard@0.12.5
./node_modules/.bin/context-guard setup --root . --agent claude --scope project --bash-reference-v1 --plan
./node_modules/.bin/context-guard setup --root . --agent claude --scope project --bash-reference-v1 --yes
```

This default-off `PreToolUse:Bash` mode keeps strongly sanitized long command
output in the private project-local Receipt store and puts only a compact
retrieval handle in the digest. The handle is bearer-like and can be visible to
Claude/the provider; it expires exactly seven days after issuance. Before Bash
starts, the wrapper creates an anonymous owner-only capture descriptor and one
verified Receipt broker, which preloads code and retains the repository, store,
expiry, and journal boundaries. Even output below the 8,192-byte disclosure
threshold can therefore initialize those local axes; it sends `ABORT` and emits
no handle. If strong sanitization, the exact package pin, the absolute Node
runtime, broker preparation, or final registration is unavailable, execution
falls back to legacy trimming without changing the wrapped command's exit
status. The mode is mutually exclusive with legacy `--artifact-receipt`
capture.

The digest renders the handle as an executable, project-local retrieval command:

```bash
./node_modules/.bin/context-guard reference <cgr1p-handle>
```

Run it from the same physical project root that issued the handle. It derives
the private sibling state location internally and returns one exact sanitized
UTF-8 page, capped at 20,000 bytes. When more bytes remain, its diagnostic gives
the next continuation `--offset`; each page stays bounded, so retrieval cannot dump
the full retained output into the transcript in one step. Invalid, expired,
wrong-root, stale-source, changed-package, and malformed references return no
payload.

Disable the route before uninstalling:

```bash
./node_modules/.bin/context-guard setup --root . --agent claude --scope project --no-bash-reference-v1 --yes --no-diet-scan
npm uninstall @ictechgy/context-guard
```

Receipt state is kept outside the repository in a private sibling directory
named `.context-guard-receipt-state-<root-selector-sha256>`. The selector binds
the normalized root path and its device/inode identity so sibling repositories
do not share authority. Disablement and package removal preserve that directory
for a later exact reinstall or separately authorized artifact cleanup. `npm
uninstall` removes the verified package-local code and
`node_modules/.bin/context-guard`, so reference retrieval is unavailable until
the exact project-local pair is reinstalled. This mechanism can reduce
transcript input for large Bash output, but it does not guarantee a fixed
provider-token or cost reduction.

To remove that retained state, stop agents using the repository, run a
read-only cleanup plan, review its counts and hash, and confirm the same plan:

```bash
./node_modules/.bin/context-guard-receipt cleanup --bash-reference-v1 --root "$(pwd -P)" --plan
./node_modules/.bin/context-guard-receipt cleanup --bash-reference-v1 --root "$(pwd -P)" --yes --confirm-plan-sha256 <64-lowercase-hex>
```

The cleanup command accepts no arbitrary state path and fails closed on links,
non-private entries, hard links, filesystem-boundary crossings, tree drift, or
a mismatched plan. Handles are
49-byte bearer strings matching `^cgr1p_[A-Za-z0-9_-]{43}$`, bound to the same
physical root, and valid for at most seven days.

## Homebrew release path

Homebrew is available through the shared `ictechgy/tap` tap:

```bash
brew install ictechgy/tap/context-guard
context-guard --version
```

If you already tapped `ictechgy/tap`, `brew install context-guard` also works.

## Helper commands

Most users should start with `/context-guard:setup`. The helper commands below are useful for local testing, automation, or targeted debugging. The canonical command prefix is `context-guard-*`.

### Health check before setup

```bash
context-guard doctor --root . --json
context-guard setup --agent claude --scope user --verify --json
```

Both modes are read-only configuration checks. `doctor` reports recommended next commands, and `setup --verify` checks whether setup is complete without applying changes. With `--json`, the report is written to stdout.

### Scan context management

```bash
./plugins/context-guard/bin/context-guard-diet scan .
```

The scanner reports missing guardrails, noisy hooks, broad context paths, large or secret-like instruction/rule files across common AI-agent surfaces, and local context-exclusion recommendations for bulky or sensitive paths. `--top` caps both the reported context-like files and context-exclusion recommendations. Recommendations are heuristic/advisory unless they are emitted as Claude `permissions.deny` entries.

### Diagnose structural context waste

```bash
./plugins/context-guard/bin/context-guard-diet structural-waste . \
  --tool-catalog tools.json \
  --log-path .claude \
  --json
```

The structural-waste doctor is opt-in and read-only. It reuses the diet scanner's local safety model, then adds advisory findings for duplicate rule units, stale Python imports, unused skill candidates, excessive MCP/tool schema catalogs, and repeated file reads or duplicate tool calls from local JSON/JSONL logs. It does not edit files, disable tools, call the network, or print raw prompt/tool-input text; default output uses relative paths, hashed labels, and redacted secret-shaped path components. Treat low-confidence import/skill findings as review prompts, not deletion instructions.

### Read symbols instead of whole large files

```bash
./plugins/context-guard/bin/context-guard-read-symbol path/to/file.py TargetSymbol
```

The optional Read guard uses a progressive path for oversized files: search first, then symbol slices, then small line ranges. When possible, it also returns a bounded top-level outline. Repeated attempts to full-read the same oversized file get a deduplicated warning instead of repeating the same context-heavy path.

Its enforcement surface is deliberately limited to the installed Claude Code `PreToolUse` hook whose matcher is `Read`:

When that Read guard is selected, setup removes only the exact legacy deny values `Read(./.env)` and `Read(./.env.*)`; similar permission entries and their relative order are preserved.

| Claude tool | Covered behavior |
| --- | --- |
| `Read` | The hook checks bounded large-file ranges and denies a basename beginning with `.env`, except the exact template names `.env.example`, `.env.sample`, and `.env.template`. Nested paths are included; ambiguous symlink paths fail closed. |
| `Glob` | May list matching names. It does not read file contents through this `Read` hook. |
| `Grep` | Out of scope for this hook and may read matching file contents. |
| `Bash` | Out of scope for this hook and may read file contents. |

This is Claude `Read` protection, not universal `.env` or Bash protection. The hook proves the file state it opens without following symlinks and revalidates that same descriptor, but Claude performs the actual `Read` with a later open after the hook returns. A replacement in that post-hook window is a documented TOCTOU limitation.

### Store and query large logs locally

```bash
long-command 2>&1 | ./plugins/context-guard/bin/context-guard-artifact store --command "long-command" --json
./plugins/context-guard/bin/context-guard-artifact search "ERROR" --json
./plugins/context-guard/bin/context-guard-artifact receipt <artifact_id> --json
./plugins/context-guard/bin/context-guard-artifact get <artifact_id> --lines 1:80
./plugins/context-guard/bin/context-guard task-memory put --task issue-123 --source src/app.py --json < stable-context.txt
./plugins/context-guard/bin/context-guard task-memory get <opaque_handle> --task issue-123 --source src/app.py --max-bytes 65536
```

Artifact mode is for capture, sandbox search, and retrieval. It stores sanitized output under `.context-guard/artifacts` by default and can still read legacy `.claude-token-optimizer/artifacts` receipts from before the rebrand. JSON receipts include line-numbered top-error receipts, duplicate-line groups, sanitized bounded `suggested_queries`, and an `output_sandbox` envelope with a stable `contextguard-artifact:<id>` handle. Use `context-guard-artifact receipt <artifact_id> --json` to rehydrate metadata-only handles without returning content, then fetch the smallest useful exact slice instead of replaying the full log. `search` scans the local sanitized artifact sandbox by literal substring, returns capped match/context records, and includes `context-guard-artifact get ... --lines START:END` rehydration commands for omitted detail. For custom `--dir` values, raw private paths stay redacted by default; rerun with the same `--dir`, or pass `search --show-paths` when you explicitly want a directly executable local command. The search report is local-only and does not make hosted token/cost savings claims. When `--max-lines` accompanies a `--lines START:END` selector, it caps lines returned within that range; it does not expand the selector. Preserve the producer command's exit code yourself when using shell pipelines in release checks, or use `context-guard-trim-output -- ...` when exit-code preservation is the primary requirement.

### Build a budgeted context pack

```bash
./plugins/context-guard/bin/context-guard-pack auto \
  --root . \
  --query "review failing tests" \
  --diff HEAD \
  --manifest-out suggested-pack.json \
  --pack-out context-pack.md \
  --budget-bytes 12000 --json --explain --adaptive-k --symbol-memory
# Explicitly add up to four safe direct import neighbors to the pack:
./plugins/context-guard/bin/context-guard-pack auto \
  --root . --files src/app.py --query "review entrypoint" --top 1 \
  --budget-bytes 12000 --json --no-artifact --apply-symbol-memory
# Explicitly prune heuristic sources after the local quality gates pass:
./plugins/context-guard/bin/context-guard-pack auto \
  --root . --query "review failing tests" --top 8 \
  --budget-bytes 12000 --json --no-artifact --apply-adaptive-k
# Or run the two explicit steps:
./plugins/context-guard/bin/context-guard-pack suggest \
  --root . --query "review failing tests" --diff HEAD \
  --manifest-out suggested-pack.json --budget-bytes 12000 --json --adaptive-k --adaptive-k-policy recall
./plugins/context-guard/bin/context-guard-pack build \
  --root . --manifest suggested-pack.json --budget-bytes 12000 --json
# Optional diagnostic comparison against one exact private local receipt:
./plugins/context-guard/bin/context-guard-pack build \
  --root . --manifest suggested-pack.json --budget-bytes 12000 --json --no-artifact \
  --delta-from-pack-id 0123456789abcdef0123
./plugins/context-guard/bin/context-guard-pack slice --root . --path README.md --lines 1:40 --json
```

`context-guard-pack auto` is the one-command, local-only path: it runs the suggestion step and immediately builds the budgeted Markdown pack.

A few boundaries are intentional:

- Add `--explain` for compact deterministic local selection/build reasons in JSON or text output.
- `--explain` may include bounded `repo_map` metadata: sampled byte/token-proxy tree entries, category-only secret-risk counts, signature-first file hints, explain-only graph ranks, and exact `slice`/symbol retrieval hints.
- Explain metadata does not change the manifest, pack body, receipt, or byte budget. It does not use network/model/embedding calls, and token values remain local `chars_div_4` proxies rather than provider-token or savings claims.
- Add `--adaptive-k` to `suggest` or `auto` for advisory-only shrink/expand top-k metadata derived from local score distribution, byte-budget fit, and clamped score-mass recall/precision proxies. Use `--adaptive-k-policy balanced|recall|precision` plus optional `--adaptive-k-min-recall-proxy` / `--adaptive-k-min-precision-proxy` gates to choose a local recommendation policy; gate failures are metadata-only (`pass|failed`). The adaptive block includes capped selected/omitted evidence and structured source-verification hints, never applies the recommendation automatically, and does not change the manifest, pack body, receipt, or byte budget.
- Add `--apply-adaptive-k` to `auto` for an explicit, default-off pruning pass. It applies the local recommendation only when its regression gates pass, always retains caller-declared file/output/test-output and diff sources, rebuilds inside the same byte budget, and records `adaptive_k_application`. It implies `--adaptive-k` and does not authorize a provider-token or cost-savings claim.
- Add `--symbol-memory` to `auto` for repo-map-derived symbol/graph advisory metadata with exact `slice` / `read-symbol` verification hints. It is source-verification guidance only and does not change the manifest, pack body, receipt, or byte budget.
- Add `--apply-symbol-memory` for an explicit, default-off Graphify-style step: after the ordinary suggestion pass, it adds at most four direct import-neighbor slices to the manifest and rebuilds within the same byte budget. Explicit/query seeds keep higher priority, secret-risk neighbors are excluded, the exact source/fallback receipt remains available, and the result records a closed `graph_application` block. This implies symbol-memory output but makes no provider-token or cost claim.
- Add `--self-financing-selection` for the composed default-off path. It freezes the ordinary pack byte ceiling, applies Adaptive, then task-matching Symbol slices, then bounded one-hop Graph neighbors. Each candidate records its frozen identity, secret-risk decision, byte delta, exact fallback, and any lower-value non-caller source it replaces; candidates that cannot fit safely are recorded as no-ops. This is a local byte-ceiling policy, not a provider-token or cost-savings claim.
- Use `auto --selection-plan --json` to produce a provider-free, read-only, content-addressed plan without writing a pack, manifest, or receipt. Save that JSON deliberately, then use the same task inputs with `--apply-selection-plan PATH --no-artifact` (or explicitly choose output/artifact options) to apply it. Apply recomputes the closed plan and revalidates source identities before emitting anything; drift, incomplete scans, secret-risk or scorer/private inputs, unsafe host/output boundaries, and missing exact recovery fail closed.

```bash
context-guard-pack auto --root . --query "fix checkout retry" --diff worktree --output logs/test.txt --json --selection-plan > selection-plan.json
context-guard-pack auto --root . --query "fix checkout retry" --diff worktree --output logs/test.txt --json --apply-selection-plan selection-plan.json --no-artifact
```
- `--manifest-out` writes a build-compatible manifest; `--pack-out` saves the rendered pack.
- `context-guard-pack suggest` is the lower-level additive local-only planning step. It ranks candidate files and line ranges from `--query`, `--diff`, repeated `--files`, and optional sanitized `--output` / `--test-output` files under `--root`, then writes a manifest that `build --manifest` can consume.
- `context-guard-pack build` assembles prioritized local file evidence into a Markdown body whose rendered UTF-8 bytes stay within `--budget-bytes`. JSON output records included, partial, duplicate, unsafe, missing, and budget-omitted sources.
- Every build reports a `content_address` (`sha256:<digest>`) of the exact rendered pack bytes while retaining the legacy `pack_id`. On `build` or `auto`, opt-in `--delta-from-pack-id PACK_ID` reads only `.context-guard/packs/PACK_ID.json` and reports bounded, fail-soft `rolling_delta` diagnostics. It never changes selection, the pack body, `pack_id`, or default behavior, and it is not a provider token/cost savings claim. Diagnostics are reported only in `--json` output or a stored artifact receipt; when `--no-artifact` is used, `--json` is required to report them, while legacy text stdout remains the exact pack body.
- Bounded receipts are stored under `.context-guard/packs`. When path/root display is safe, JSON output includes copy-pasteable `slice` commands for exact sanitized retrieval; otherwise it records `retrieval_omitted_reason`.

The packer uses deterministic standard-library heuristics only: no network, model calls, embeddings, or provider-cost estimate. Byte counts are observed; token counts remain estimated `chars_div_4` proxies, not measured provider-token savings.

### Prune a tool/MCP catalog for a task

```bash
./plugins/context-guard/bin/context-guard-tool-prune select \
  --catalog tools.json \
  --query "review failing tests" \
  --top 5 --budget-bytes 12000 --json
./plugins/context-guard/bin/context-guard-tool-prune defer-report \
  --catalog tools.json \
  --query "review failing tests" \
  --core-top 3 --deferred-top 20 --json
./plugins/context-guard/bin/context-guard-tool-prune get <receipt_id> --tool read_file --json
```

`context-guard-tool-prune` ranks a local tool or MCP catalog with deterministic lexical heuristics and emits a bounded top-k advisory report. Inline selected schemas respect an observed UTF-8 byte budget, and omitted or budget-skipped schemas remain recoverable from a compact local receipt plus a separate sanitized payload under `.context-guard/tool-prune`. `defer-report` uses the same receipt path to split a catalog into core inline tools plus deferred tool stubs and namespace summaries, and reports gross deferred-schema plus net initial-report char/4 proxy accounting so you can see what moved out of the first prompt. This is advisory only: it does not mutate MCP configuration, does not configure native provider tool search, and token counts remain estimated proxies rather than measured provider savings.

### Score static prompt cacheability

```bash
./plugins/context-guard/bin/context-guard-cache-score --input prompt.json --provider openai --json
./plugins/context-guard/bin/context-guard cache-score --input prompt.txt --provider anthropic --json
```

`context-guard-cache-score` is a local static lint for prompt/request layout. It estimates total and cacheable-prefix size with a tokenizer-free char/4 proxy, warns about dynamic-looking values near the prefix, and records provider caveats for OpenAI, Anthropic, Gemini, or a generic threshold. Optional `--expected-reuses`, `--cache-write-multiplier`, and `--cache-read-multiplier` inputs add an advisory amortization-risk section using user-supplied economics only. It does not call providers, store raw prompts, estimate prices from bundled defaults, observe cache hits, or prove token/cost savings; verify real cache behavior with provider usage telemetry.

### Advise on total cost, batchability, and routing

```bash
context-guard-receipt evaluate full-wire --input full-wire-evaluation.json
./plugins/context-guard/bin/context-guard route-advisor --workload workload.json --json
./plugins/context-guard/bin/context-guard-cost route-advisor --feature batch_api=true --feature structured_outputs=true --json < workload.json
./plugins/context-guard/bin/context-guard cost advisory --workload advisory-workload.json --json
```

`context-guard-receipt evaluate full-wire` reads one bounded canonical JSON envelope containing `schema_version=contextguard.full-wire-budget-request/v1`, `baseline`, `candidate`, `protected_pointers`, and boolean `enforce`. It compares complete canonical JSON bytes, requires selected protected pointers to remain equal, and rejects an increased or unavailable `max_tokens` budget when the other side declares one. Cache-prefix preservation is diagnostic. It does not emit or store either request, and it treats canonical JSON bytes as a local comparison unit, not exact HTTP wire bytes or provider-measured token savings.

`context-guard-receipt evaluate calibration` joins HMAC-only preflight and observation rows after a declared sample floor, while `evaluate route-v2` applies the resulting integer total-cost policy as shadow-only advice. Neither command authorizes an automatic route or a savings claim.

The Receipt companion also exposes provider-free `evaluate net-efficiency`,
`fanout-plan`, `prefix-plan`, `prune-plan`, and `shadow-policy` contracts. They
measure matched quality, full shifted cost, p95 latency, output/model rounds,
distinct canary windows, fan-out shape, cache-prefix stability, and safe
task-boundary pruning while remaining shadow-only. Its task-scoped
`receipt_batch` MCP tool returns multiple already-authorized exact slices in
one bounded read-only call; it adds no shell, provider, or network authority.
Copy-paste canonical JSON and commands for all five evaluators are in the
[Receipt minimal evaluator inputs](packages/context-guard-receipt/README.md#minimal-evaluator-inputs).

`context-guard route-advisor` is a local, passive advisor. It reads caller-supplied workload JSON, provider feature declarations, usage telemetry, and shifted external/local costs, then emits total-cost accounting, batchability blockers, and candidate routes such as batch API, prompt-cache prefix preservation, structured outputs, or cheaper-model evaluation. It does not start a queue, call providers, refresh pricing docs, or treat bundled provider feature knowledge as authoritative; unknown or caller-supplied features are marked recheck-required. Treat recommendations as candidates only. Hosted token or cost savings claims require matched successful tasks, non-inferior quality, and shifted-cost evidence.

`context-guard cost advisory` is the zero-persistent-context WeightClass/router gate. It accepts only closed numeric and boolean capability signals, returns an empty provider context on every path, bypasses small or non-profitable work, and permits graph only for cached positive replacement evidence. See [WeightClass advisory mode](https://github.com/ictechgy/context-guard/blob/main/docs/weightclass-advisory-mode.md).

### Compress selected local text conservatively

```bash
git diff | ./plugins/context-guard/bin/context-guard-compress --json
pytest -q 2>&1 | ./plugins/context-guard/bin/context-guard-compress --type log
cat evidence.txt | ./plugins/context-guard/bin/context-guard-compress --json --protected-policy
cat sanitized-prose.txt | ./plugins/context-guard/bin/context-guard-compress --json --type prose --mode readable
```

`context-guard-compress` classifies sanitized stdin as JSON, diff, log, search output, code, or prose, then applies deterministic reductions such as JSON compaction, diff context folding, duplicate log/search line collapse, and whitespace normalization. It never claims observed model-token savings; byte counts are observed, token counts are labeled as estimates, and lossy receipts point you back to `context-guard-artifact store` for exact retrieval.

Add `--protected-policy` when the input may contain semantic-sensitive zones such as code fences, diffs, identifiers, numeric constants, hashes, paths, stack frames, quoted strings, or JSON keys. The flag does not change default compressor behavior; it adds `protected_zone_policy` and `transform_policy` metadata that denies semantic/paraphrase rewrites, allows only structural transforms plus artifact retrieval, and stores only class/count policy metadata rather than raw protected spans.

Add `--mode readable` only for sanitized prose previews. It uses a deterministic sentence window, blocks prompt-like or high-risk protected signals, stores no raw protected spans, and marks exact fallback retrieval as required before edits or claims. It does not run learned compressors, models, embeddings, or rerankers.

### Trim or summarize command output

```bash
./plugins/context-guard/bin/context-guard-trim-output --max-lines 120 -- npm test
```

Use `--digest markdown` or `--digest json` for a compact semantic digest instead of head/tail logs. When a command succeeds and its output is already smaller than the digest would be, the output is passed through with a one-line marker instead, so enabling digest mode on quiet commands cannot inflate context. A failing command always keeps the digest, because that is where the exit code and failure signature live; pass `--digest-always` to keep the structured digest in every case. Digest mode keeps status, exit code, truncation counts, runner failure facts, a sanitized failure signature, duplicate-line groups, representative lines, redaction counts, and suggested next queries while preserving the wrapped command exit code. Add `--artifact-receipt` with digest mode when you want the exact sanitized full output stored locally as a `context-guard-artifact` receipt; keep the emitted `contextguard-artifact:<id>` handle in agent context and re-expand with the emitted `context-guard-artifact receipt/get/search ...` commands before relying on omitted details. Wrapped commands time out after 600 seconds by default; tune this with `--timeout-seconds`.

### Sanitize search and diff output

```bash
./plugins/context-guard/bin/context-guard-sanitize-output -- rg -n "TOKEN|SECRET" .
./plugins/context-guard/bin/context-guard-sanitize-output -- git diff
```

The sanitizer reduces the chance that token-like, key-like, password-like, or sensitive path values are copied into agent context.

### Apply an opt-in declarative output filter

```bash
cat > .context-guard/filter-dsl.json <<'JSON'
{
  "schema_version": "contextguard.filter-dsl.v1",
  "filters": [
    {
      "id": "git-status-short",
      "match": {"argv_prefix": ["git", "status", "--short"]},
      "include_regex": ["^[ MADRCU?!]"],
      "max_lines": 80
    }
  ]
}
JSON
./plugins/context-guard/bin/context-guard-filter validate --config .context-guard/filter-dsl.json
./plugins/context-guard/bin/context-guard-filter run --config .context-guard/filter-dsl.json -- git status --short
```

`context-guard-filter` is an opt-in local helper for user-owned JSON filter files; it does not install default filters or change hooks. Invalid configs, no-match commands, filtering errors, empty filtered output, and protected `git`/test/lint/`gh` command failures pass the original command stdout/stderr and exit code through. In filtered mode, line rules apply to combined stdout+stderr and write the filtered result to stdout; passthrough mode preserves stdout/stderr streams. `run --json-report` writes filter diagnostics to stderr so stdout remains command/filter output; protected nonzero passthrough suppresses that report to keep stderr raw. Treat filtered byte reductions as local presentation changes, not hosted token/cost savings claims.

### Audit local transcript usage

```bash
./plugins/context-guard/bin/context-guard-audit ~/.claude/projects --top 20 --recommend
```

The audit command skips oversized transcript files and JSONL records by default (`--max-file-bytes`, `--max-line-bytes`) and reports skipped counts. That keeps a corrupt trace from dominating memory or hiding scan gaps.

JSON output can include several evidence surfaces:

- `cache_friendliness` and [`cache_diagnostics`](docs/cache-diagnostics-schema.md): heuristic prompt-layout/cache-read diagnostics built from bounded usage fields, timestamped cache telemetry records, and redacted segment hashes.
- `cache_layout_advice`: ranked **checks/experiments** such as splitting long sessions or stabilizing early prompt prefixes, with observed issues kept separate from hypothesized or corroborated causes.
- `tool_result_bytes`: where context bytes actually came from, counted from the **content of transcript `tool_result` blocks** — by tool, by content class (image, text, unknown), by file extension, plus the size distribution, the share carried by the largest results, the exact-duplicate share, and what share of file-read bytes came from reads that requested an explicit range. `tool_use` blocks are read for attribution and for the extension and range labels, but their input bytes are never counted, and neither is anything outside tool results. Bytes are attributed per content block, so one result holding both an image and text counts into both classes. Extension labels are drawn from a known-extension list — a suffix that is not on it becomes `(not-an-extension)` rather than being emitted, because a shape check cannot stop a filename fragment like `notes.clientAcme` from passing as an "extension"; unusual real extensions fold into that bucket too, which costs the extension dimension but never the byte totals. Sizes are measured on a canonical serialization, so they approximate rather than reproduce on-disk bytes, and a stored result is re-sent on later requests, so these are a lower bound on context exposure. Provider token accounting is per-request and cannot attribute tokens to a tool, so this section is byte-based and states that boundary in its own output.
- `tool_result_bytes.token_estimate`: the same content classes counted in **estimated tokens** rather than bytes, because byte share is not a cost signal for images. Providers resize an image to a long-edge cap and then price it by area, so an image's token cost stops growing above that cap no matter how large the payload is, while text cost is uncapped and roughly linear in bytes. Reading only the byte column therefore overstates images by a wide margin. Each class row names its own `method`: images use a published provider formula (stamped with a version id) applied to pixel dimensions parsed from the PNG/JPEG header, and text uses a `bytes_div_4` proxy that under-counts dense source code. Payloads whose header cannot be read — a media type with no parser here, a reference block carrying no inline data, or a header past the bounded decode window — are counted as `dimensions_unavailable` rather than dropped, so a non-zero count means the image token total is a lower bound. These are estimates, never billed amounts, and never a savings claim.
- `tool_result_bytes.repeat_reads`: file-read results whose exact content was already seen in the same session, i.e. bytes spent re-delivering something already in context. Scope is the session, so the same file read in two sessions is not a repeat; content-identical reads of different files do count, and a file that changed between reads does not.
- `new_tokens_per_turn`: the distribution of `cache_creation_input_tokens` per turn. Under prompt caching the billable input for a turn is roughly the newly written prefix plus discounted cached reads, so new tokens per turn — not total context size — is the quantity that moves cost. Turns reporting zero are counted separately instead of being folded into the percentiles, which would drag them toward zero. These are provider usage fields, so the counts are observed rather than estimated; observing where new tokens land is still not evidence that any change reduced them.
- `--feasibility-json` / [`mac_visibility`](docs/mac-visibility-feasibility-schema.md): a contract for local macOS-visible consumers. Only stable top-level fields are binding targets; `summary` is not a primary UI binding source.

Guardrails cost something to run and not every one pays off on every project, so measure before enabling. Reported byte shares are observations, not savings: they say where the bytes went, not what you would recover by trimming them. Reading paths are never emitted here — file extensions only.

These fields can flag likely volatile content near the prompt prefix, stable-prefix candidates, cache-miss hypotheses, and TTL/headroom evidence gaps. They do not print raw prompt text, do not prove provider cache hits, and may be `missing`, `partial`, `hypothesis`, or `unavailable` when transcript schemas do not expose enough evidence.

### Watch context and cache health in the statusline

```text
[Sonnet] repo | main | ctx 86% ⚠ | cost $0.123 | cache 80% | reuse 8.0x
```

`cache N%` is the cache-read share of observed input-side tokens in the bounded transcript tail and stays hidden until at least one cache read is observed. `reuse X.Yx` is `cache_read / cache_creation` and is shown only when cache read is positive and cache creation is non-zero. The `⚠` marker appears when context usage reaches the warning threshold, defaulting to 80%. Automatic hooks run with an isolated environment, so set `CONTEXT_GUARD_STATUSLINE_CTX_WARN=90` and rerun setup to pin that safe behavior setting into the installed command; Python and shell loader variables are never carried through.

### Run a repeatable benchmark

```bash
./plugins/context-guard/bin/context-guard-bench \
  --tasks bench/tasks.json --variants bench/variants.json --csv bench/results.csv \
  --ledger-jsonl bench/cost-shift.jsonl --report-json bench/report.json \
  --dashboard-md bench/dashboard.md
```

Each task fixture may set `output_format` to `json` (the default) or opt in to
`stream-json`. Stream mode adds the runner-controlled `--verbose` flag and only
accepts a bounded NDJSON stream whose final event is a valid terminal result.
Its client-reported cost remains diagnostic and is not authoritative provider billing.

For deterministic local replay before a live provider run, add `--evidence-jsonl docs/benchmark-fixtures/token-savings-12task.evidence.example.jsonl` and, for the 12-task fixture, `--baseline-variant baseline_full_context_fixture`. Replay mode skips provider and `success_command` execution, writes the same CSV/report/dashboard surfaces, and marks synthetic/manual evidence as non-public-claim-eligible.

Read the report through its claim boundaries before writing any savings statement:

- Successful baseline/variant runs are compared by real tokens and `cost_usd + external_cost_usd`; byte reductions stay proxy evidence.
- Token-savings claims require `primary_tokens_measured` on both sides of a matched task.
- `matched_pair_evidence` links each successful task bucket to the transform, measurement availability, quality gate, and claim boundary.
- `default_matrix` classifies trimming, artifact escrow, tool pruning, cache advice, adaptive-k, and optional compression as `default-on`, `advisory`, `experimental`, or `reject/rework` from the same matched evidence. The matrix is report-only: it does not change runtime defaults or authorize hosted token/cost savings claims.
- `public_claim_readiness` is the authoritative release/public-claim gate. It remains false unless matched successful tasks, provider-measured primary tokens/cost, quality non-inferiority, shifted-cost accounting, explicit confidence/failure notes, and complete provider-export provenance all pass; unsupported hosted savings claims are forbidden when `claim_allowed` is false.
- `wall_time_seconds`, `provider_cached_tokens`, and `provider_cached_tokens_measured` are diagnostic telemetry, not proof of ContextGuard-caused token or cost savings.
- Optional `self_hosted_metrics` from provider payloads are stored as per-row JSONL ledger sidecars, kept out of CSV/report summaries, and must not be folded into hosted API token/cost savings claims.
- If cost fields are zero or unavailable, the report can still mark token savings but will not claim shifted-cost savings.
- CSV schemas are strict; after upgrading the benchmark helper, start a new `--csv` file or migrate the header named in the mismatch error.

See [`docs/benchmark-report.example.json`](docs/benchmark-report.example.json) for a minimal report-shape example, [`docs/benchmark-workflow-examples.md`](docs/benchmark-workflow-examples.md) for workflow-specific synthetic examples, and [`docs/experimental-benchmark-fixtures.md`](docs/experimental-benchmark-fixtures.md) for fixture-only experimental task/variant starters plus synthetic evidence replay.

## Experimental features

All experimental planners are off by default, plan-only, and documented in [`docs/experiments.md`](docs/experiments.md); their later-roadmap gates keep those lanes experimental/non-shipped until matched successful, provider-measured tasks and a separate future PR satisfy them.

## Repository layout

- `.claude-plugin/marketplace.json` — Claude Code marketplace manifest.
- `plugins/context-guard/` — installable Claude Code plugin package.
- `context-guard-kit/` — checkout-local Python/Bash helper sources. npm packages ship synchronized `plugins/context-guard/bin` and `plugins/context-guard/lib` copies instead of duplicating this source tree.
- `docs/index.html` — static landing page for the project.
- `tests/` — regression tests for helper behavior.

## Local development

Run Claude Code with the plugin directory:

```bash
claude --plugin-dir ./plugins/context-guard
```

Test marketplace installation from the repository root:

```text
/plugin marketplace add ./
/plugin install context-guard@context-guard
```

Plugin helper binaries are not added to `PATH` by default. For local testing, invoke them by full path:

```bash
./plugins/context-guard/bin/context-guard-setup --plan
./plugins/context-guard/bin/context-guard-setup --agent codex --brief-mode standard --plan
./plugins/context-guard/bin/context-guard-setup --yes
```

To use shorter commands during local development, add the plugin bin directory to your shell:

```bash
export PATH="$PWD/plugins/context-guard/bin:$PATH"
context-guard-setup --plan
```

Do not rely on `PATH` lookup for generated hooks by default. The setup wizard records explicit bundled or checkout-local helper paths; `--allow-path-helper-fallback` is only for trusted external installs and validates the resolved helper path, symlink state, and bounded identity probe before writing commands. The macOS app helper follows the same trust model: no launch-CWD discovery, no relative override paths, and no inherited ambient shell environment beyond the allowlisted values it needs to start.

## Local MCP adapter

`context-guard mcp` (or `context-guard-mcp`) is a dependency-free local stdio MCP server. Each process is fixed to one root and one namespace; it exposes only compression, sanitized artifact retrieval, and local statistics. It has no HTTP, SSE, network, provider, model, proxy, or automatic client-configuration surface. Stored fallback content is an exact sanitized copy, not raw input, and artifacts from another namespace are not retrievable. This local adapter makes no hosted token or cost-savings claim.

For explicit repeated file or log context, the bundled Receipt companion also
provides `context-guard-receipt-mcp --root /absolute/repository`. Its
`receipt_context` accepts an explicitly eligible relative path, returns a
compact exact reference when the byte-benefit router says deferral is useful,
reuses that live reference for repeated reads, and retrieves exact slices of at
most 65,536 bytes. Optional task scopes prevent cross-task reuse, explicit
release performs context GC, and the content-free history records only
process-keyed HMACs and decisions. `receipt_diagnose` adds non-applying shadow
firewall/router plus prefix-reuse scout/surgeon advice without returning file
bytes. `receipt_pack` creates a caller-ordered bounded multi-file pack only from
prior `receipt_context` capabilities bound to the same required task scope.
Optional task-scoped
`receipt_tool_select` profiles reuse one stable catalog bundle and reject drift
instead of silently rebuilding a new tool prefix. Starting the same binary with an explicit private `--state-dir` enables
only `receipt_twin`, which records authenticated revalidation evidence but
executes no action. The flow remains opt-in: it does not register itself,
intercept whole prompts, survive capability restart, call a provider, or make a
hosted savings claim.

## Release checks

Before publishing or merging release-sensitive changes, run the copy check and both gates:

```bash
python3 scripts/sync_plugin_copies.py --check
python3 scripts/prepublish_check.py
python3 scripts/release_smoke.py
```

When a helper under `context-guard-kit/` changes, run `python3 scripts/sync_plugin_copies.py --write` before the gates. `sync_plugin_copies.py --check` verifies the maintainer-facing exact-copy contract up front. npm packages intentionally ship only the synchronized plugin-local `plugins/context-guard/bin` entrypoints and `plugins/context-guard/lib` helpers to avoid duplicate implementation payloads, and the npm bin map intentionally omits legacy `claude-*` wrapper aliases. Command manifests are loaded as literal assignments for release and runtime checks; executable Python, imports, functions, or shadow manifests are rejected. `prepublish_check.py` verifies package invariants, synchronized plugin binaries, manifests, diagnostic redaction, and the regression suite. `release_smoke.py` executes representative packaged entrypoints from `plugins/context-guard/bin` in a temporary project so broken CLI wiring is caught before publish. See [docs/release-runbook.md](docs/release-runbook.md) for the full release workflow, evidence checklist, quad-review requirement, and rollback checklist.

Versioned release notes live in [CHANGELOG.md](CHANGELOG.md); the prepublish gate requires an entry matching the plugin manifest version before publishing.

## License

Copyright 2026 jinhongan. Licensed under the Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
