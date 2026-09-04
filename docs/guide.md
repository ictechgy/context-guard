# ContextGuard guide

Every shipped ContextGuard surface, in full. Start from the
[README](../README.md) for the short path; trust boundaries, standing
cost, and claim wording live in [safety-reference.md](safety-reference.md).

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

The generated [setup capability and flag reference](setup-reference.md)
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
| Experimental planners and local runtimes | Default-off, explicit-command-only lanes. | All experimental planners are off by default, plan-only, and documented in [`docs/experiments.md`](experiments.md). |
| ContextGuard | Avoiding unnecessary files, logs, repeated failures, and noisy output before they enter agent context. | Local guardrails, reversible artifacts, and measurement. |

Related patterns that informed the design:

| Approach | What it emphasizes | ContextGuard relationship |
| --- | --- | --- |
| Compression-first | Shortening text already selected for the model, often with lossy transforms. | ContextGuard prefers local artifact storage with exact slice retrieval over lossy one-way compression, so you can get the original back. |
| Terse-output rulesets across agents | Installing brief-mode output rules into many agents at once. | ContextGuard offers advisory brief-mode snippets and dry-run cross-agent setup — opt-in per project, no guaranteed savings claimed. |
| ContextGuard | Avoiding unnecessary files, logs, and output before they enter context, with conservative measurement. | Local guardrails, reversible artifacts and retrieval, plus benchmark evidence you measure yourself. |

## Brief mode (advisory)

Brief mode is a set of agent-neutral, advisory rule snippets that ask a coding agent to cut filler while preserving reviewer evidence: file paths, commands, command output and errors, code blocks, verification status, changed files, known gaps, and caveats. It is best-effort guidance, not enforcement, and does **not** guarantee token or cost savings.

Three deterministic levels ship under [`plugins/context-guard/brief/`](../plugins/context-guard/brief/): `lite`, `standard`, and `ultra`. Each level is a single marker-delimited block for an agent's rule/instruction file (for example `AGENTS.md`, `CLAUDE.md`, a Cursor rules file, or Copilot instructions). Manage it through setup with `context-guard setup --agent codex --scope project --brief-mode standard --plan`, rerun with `--yes` to apply, and use `--brief-mode off` to remove the managed block. See [`plugins/context-guard/brief/README.md`](../plugins/context-guard/brief/README.md).

## Quiet narration for Claude (advisory)

Quiet narration is a separate, default-off Claude-only rule for reducing discretionary preambles, per-tool narration, filler, and repeated interim summaries. It still requires approvals and decisions, blockers, failures, destructive or security warnings, higher-priority progress updates, the final result, changed files, and verification. It is best-effort guidance, independent of final-answer brevity or reasoning depth, and does **not** guarantee token or cost savings.

```bash
context-guard setup --rules-only --agent claude --scope project --narration-mode quiet --plan
context-guard setup --rules-only --agent claude --scope project --narration-mode quiet --yes
context-guard setup --rules-only --agent claude --scope project --narration-mode default --yes
```

This isolated operation manages only ContextGuard's narration span in the project's `CLAUDE.md`. It does not read or change Claude settings, hooks, permissions, statusline, model defaults, or other agents' rule files. It cannot be combined with brief mode, initialization, skill generation, or normal setup actions. Gate C verifies the static rule and setup side effects only; it does not prove model compliance or authorize a numeric savings claim.

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

Setup is explicit, project-local, and reversible. The plugin does not configure external model delegation or offload; all helper commands run locally. See [`plugins/context-guard/examples/settings.example.json`](../plugins/context-guard/examples/settings.example.json) for an example settings file.

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
[`research/receipt-install-shape-boundary-20260831.md`](../research/receipt-install-shape-boundary-20260831.md).

```bash
npm install --save-exact @ictechgy/context-guard@0.13.0
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
[Receipt minimal evaluator inputs](../packages/context-guard-receipt/README.md#minimal-evaluator-inputs).

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

- `cache_friendliness` and [`cache_diagnostics`](cache-diagnostics-schema.md): heuristic prompt-layout/cache-read diagnostics built from bounded usage fields, timestamped cache telemetry records, and redacted segment hashes.
- `cache_layout_advice`: ranked **checks/experiments** such as splitting long sessions or stabilizing early prompt prefixes, with observed issues kept separate from hypothesized or corroborated causes.
- `tool_result_bytes`: where context bytes actually came from, counted from the **content of transcript `tool_result` blocks** — by tool, by content class (image, text, unknown), by file extension, plus the size distribution, the share carried by the largest results, the exact-duplicate share, and what share of file-read bytes came from reads that requested an explicit range. `tool_use` blocks are read for attribution and for the extension and range labels, but their input bytes are never counted, and neither is anything outside tool results. Bytes are attributed per content block, so one result holding both an image and text counts into both classes. Extension labels are drawn from a known-extension list — a suffix that is not on it becomes `(not-an-extension)` rather than being emitted, because a shape check cannot stop a filename fragment like `notes.clientAcme` from passing as an "extension"; unusual real extensions fold into that bucket too, which costs the extension dimension but never the byte totals. Sizes are measured on a canonical serialization, so they approximate rather than reproduce on-disk bytes, and a stored result is re-sent on later requests, so these are a lower bound on context exposure. Provider token accounting is per-request and cannot attribute tokens to a tool, so this section is byte-based and states that boundary in its own output.
- `tool_result_bytes.token_estimate`: the same content classes counted in **estimated tokens** rather than bytes, because byte share is not a cost signal for images. Providers resize an image to a long-edge cap and then price it by area, so an image's token cost stops growing above that cap no matter how large the payload is, while text cost is uncapped and roughly linear in bytes. Reading only the byte column therefore overstates images by a wide margin. Each class row names its own `method`: images use a published provider formula (stamped with a version id) applied to pixel dimensions parsed from the PNG/JPEG header, and text uses a `bytes_div_4` proxy that under-counts dense source code. Payloads whose header cannot be read — a media type with no parser here, a reference block carrying no inline data, or a header past the bounded decode window — are counted as `dimensions_unavailable` rather than dropped, so a non-zero count means the image token total is a lower bound. These are estimates, never billed amounts, and never a savings claim.
- `tool_result_bytes.repeat_reads`: file-read results whose exact content was already seen in the same session, i.e. bytes spent re-delivering something already in context. Scope is the session, so the same file read in two sessions is not a repeat; content-identical reads of different files do count, and a file that changed between reads does not.
- `new_tokens_per_turn`: the distribution of `cache_creation_input_tokens` per turn. Under prompt caching the billable input for a turn is roughly the newly written prefix plus discounted cached reads, so new tokens per turn — not total context size — is the quantity that moves cost. Turns reporting zero are counted separately instead of being folded into the percentiles, which would drag them toward zero. These are provider usage fields, so the counts are observed rather than estimated; observing where new tokens land is still not evidence that any change reduced them.
- `--feasibility-json` / [`mac_visibility`](mac-visibility-feasibility-schema.md): a contract for local macOS-visible consumers. Only stable top-level fields are binding targets; `summary` is not a primary UI binding source.

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

See [`docs/benchmark-report.example.json`](benchmark-report.example.json) for a minimal report-shape example, [`docs/benchmark-workflow-examples.md`](benchmark-workflow-examples.md) for workflow-specific synthetic examples, and [`docs/experimental-benchmark-fixtures.md`](experimental-benchmark-fixtures.md) for fixture-only experimental task/variant starters plus synthetic evidence replay.

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

When a helper under `context-guard-kit/` changes, run `python3 scripts/sync_plugin_copies.py --write` before the gates. `sync_plugin_copies.py --check` verifies the maintainer-facing exact-copy contract up front. npm packages intentionally ship only the synchronized plugin-local `plugins/context-guard/bin` entrypoints and `plugins/context-guard/lib` helpers to avoid duplicate implementation payloads, and the npm bin map intentionally omits legacy `claude-*` wrapper aliases. Command manifests are loaded as literal assignments for release and runtime checks; executable Python, imports, functions, or shadow manifests are rejected. `prepublish_check.py` verifies package invariants, synchronized plugin binaries, manifests, diagnostic redaction, and the regression suite. `release_smoke.py` executes representative packaged entrypoints from `plugins/context-guard/bin` in a temporary project so broken CLI wiring is caught before publish. See [docs/release-runbook.md](release-runbook.md) for the full release workflow, evidence checklist, quad-review requirement, and rollback checklist.

Versioned release notes live in [CHANGELOG.md](../CHANGELOG.md); the prepublish gate requires an entry matching the plugin manifest version before publishing.

## 한국어

한국어 사용자를 위한 전체 참조입니다.

### 한눈에 보기

설치와 활성화는 의도적으로 분리되어 있습니다. 설치만 하면 로컬 헬퍼나 Claude 플러그인 스킬이 준비될 뿐이며, 설정 파일은 사용자가 `setup`을 명시적으로 실행할 때만 기록됩니다.

| 쓰는 도구 | 설치 | 활성화 |
| --- | --- | --- |
| Claude Code | `/plugin marketplace add ictechgy/context-guard` 후 `/plugin install context-guard@context-guard` | 프로젝트에서 `/context-guard:setup` 실행 |
| Codex CLI 또는 터미널 기반 에이전트 | `npm install -g @ictechgy/context-guard` 또는 일회성 `npx @ictechgy/context-guard ...` | `context-guard setup --agent codex --scope project --with-init --with-skill --with-mcp --plan` 확인 후 `--yes`로 적용 |
| Gemini/Cursor/Windsurf/Cline/Copilot | 위 npm/npx 설치 경로 사용 | `--with-init`을 사용하고 Gemini/Cursor/Copilot/OpenCode/ForgeCode에는 `--with-mcp`를 추가 |
| macOS/Homebrew 사용자 | 배포 경로: `brew install ictechgy/tap/context-guard` | 설치 후 같은 `context-guard setup ...` 명령 사용 |

자주 쓰는 명령은 다음과 같습니다.

```bash
npm install -g @ictechgy/context-guard
npx @ictechgy/context-guard --version
context-guard setup --agent codex --scope project --with-init --with-skill --with-mcp --plan
context-guard setup --agent claude --scope user --verify --json  # 읽기 전용 사용자 범위 점검
context-guard setup --agent claude --scope user --plan
```

### Claude Code 우선, 다른 에이전트도 함께

Claude Code 사용자는 플러그인으로 시작하는 것이 가장 빠릅니다. 설치한 뒤에는 같은 로컬 우선 가드레일을 다음 방식으로 다른 AI 코딩·도구 에이전트에서도 재사용할 수 있습니다.

- **로컬 헬퍼 명령**(`context-guard-*`)은 특정 에이전트에 묶이지 않은 일반 셸 명령으로 실행됩니다.
- **brief 모드 스니펫**은 에이전트의 지시 파일(`AGENTS.md`, `GEMINI.md`, `.cursorrules`, Copilot 지시 파일 등)에 마커 블록으로 설치하고, 블록을 지우면 제거됩니다.
- **여러 에이전트 설정**은 먼저 dry-run으로 계획을 보여주고, 로컬 파일만 대상으로 하며, 변경 전 백업을 남긴 뒤 명시적으로 승인한 경우에만 적용합니다.

현재 지원하는 연동 방식은 다음과 같습니다.

| 에이전트 또는 도구 | ContextGuard 적용 방식 |
| --- | --- |
| Claude Code | 프로젝트 로컬 훅, deny 규칙, 상태표시줄 설정을 적용하는 네이티브 플러그인 설정. |
| OpenAI Codex CLI | 안내용 `AGENTS.md`와 선택형 프로젝트 skill 및 `.codex/config.toml` stdio MCP 설정. |
| Gemini CLI | 안내용 `GEMINI.md`와 선택형 `.gemini/settings.json` MCP. |
| Cursor | 안내용 `.cursorrules`와 선택형 `.cursor/mcp.json`. |
| Windsurf | 안내용 `.windsurf/rules/contextguard.md` 규칙 블록. |
| Cline | 파일·디렉터리 패턴을 다루는 안내용 `.clinerules` 규칙 블록. |
| GitHub Copilot Coding Agent | 안내용 `.github/copilot-instructions.md`와 선택형 `.vscode/mcp.json`. |
| OpenCode | 기존 프로젝트 skill과 선택형 `opencode.json` MCP. |
| ForgeCode | 선택형 프로젝트 `.mcp.json`; 나머지는 셸 헬퍼 사용. |
| Windsurf, Cline, 기타 | 규칙 파일 또는 셸 사용; project MCP 자동 쓰기 없음. |

### ContextGuard가 토큰 낭비를 줄이는 방식

ContextGuard는 모델 단가 자체를 낮추는 도구가 아닙니다. AI 코딩 에이전트의 컨텍스트에 들어가기 전에 불필요한 입력을 줄이고, 그 변화가 도움이 됐는지 직접 확인할 수 있는 신호를 제공합니다.

| 낭비 경로 | ContextGuard 가드레일 |
| --- | --- |
| 함수 하나를 찾으려고 파일 전체를 읽는 경우 | 파일 전체를 읽기 전에 검색, 심볼 단위 읽기, 제한된 개요, 작은 줄 범위 읽기를 먼저 제안합니다. |
| 긴 테스트·빌드·검색·diff 출력 | 출력을 축약하거나 구조화된 요약을 만들고, 큰 로그는 로컬에 저장한 뒤 간결한 요약 기록만 반환합니다. |
| 같은 실패 명령을 반복하는 경우 | Bash 실패가 반복되면 불필요한 실패 로그가 더 쌓이기 전에 전략을 바꾸도록 알립니다. |
| 민감하거나 과도한 터미널 출력 | 자격 증명처럼 보이는 값과 민감해 보이는 경로를 패턴 기반으로 최대한 가립니다. |
| 어디서 토큰과 비용이 커지는지 모르는 경우 | 상태표시줄, 대화 기록 감사, 기준 실행과 변형 실행을 쌍으로 맞춰 비교한 벤치마크 리포트로 전후 비교 근거를 남깁니다. |
| Anthropic API 요청이 provider prompt cache 적중을 놓칠 수 있는 경우 | `context-guard cost preflight`가 호출 전 입력 크기, cache breakpoint별 위험, 낮음/중간/높음 비용 범위를 추정합니다. 기본값은 경고만 합니다. |
| 안정적인 프롬프트 앞부분보다 자주 바뀌는 컨텍스트가 먼저 오는 경우 | 제한된 범위의 가림 처리된 segment hash로 프롬프트 배치를 감사하여, 원문 프롬프트를 노출하지 않고 캐시에 불리한 배치 가능성을 알립니다. |
| 좁은 작업에 비해 큰 tool/MCP catalog가 들어가는 경우 | 로컬 tool catalog를 제한된 top-k schema report로 순위화하고, 전체 가림 처리된 schema는 로컬 요약 기록으로 다시 조회할 수 있게 합니다. |

### 캐시·압축 도구와의 차이

ContextGuard는 provider 캐시, semantic cache, 프롬프트 압축 도구를 대체하지 않습니다. 핵심 역할은 더 단순합니다. **불필요한 파일·로그·출력이 에이전트 컨텍스트에 들어가기 전에 줄어들도록 돕는 것**입니다.

| 도구 유형 | 줄이는 방식 | ContextGuard와의 관계 |
| --- | --- | --- |
| Provider prompt/context caching | 안정적인 프롬프트 앞부분을 재사용합니다. | 보완 관계입니다. ContextGuard는 자주 바뀌는 컨텍스트 뒷부분을 더 작고 깨끗하게 유지하도록 돕고, `context-guard-audit`로 프롬프트 배치를 점검하며, `context-guard cost`로 Anthropic 요청이 cache read 대신 cache write가 될 가능성을 미리 알릴 수 있습니다. |
| Semantic response cache | 같거나 비슷한 요청의 이전 답변을 재사용합니다. | 보완 관계입니다. ContextGuard는 AI 답변 캐시를 제공하지 않습니다. |
| 프롬프트/컨텍스트 압축 | 이미 선택된 텍스트를 더 짧게 만듭니다. | 인접한 역할입니다. ContextGuard는 로컬 출력 축약과 요약을 제공하지만, 무손실 의미 압축을 보장하지 않습니다. |
| 실험 planner/runtime | 기본 비활성이며 명시적 명령으로만 실행하는 lane입니다. | 모든 실험 planner는 기본 비활성이고 plan 전용이며, 자세한 내용은 [`docs/experiments.md`](experiments.md)에 있습니다. |
| ContextGuard | 불필요한 파일, 로그, 반복 실패, 과도한 출력이 에이전트 컨텍스트에 들어가기 전에 줄어들도록 돕습니다. | 로컬 가드레일, 되돌릴 수 있는 로컬 보관본, 측정 도구입니다. |

설계에 참고한 관련 패턴은 다음과 같습니다.

| 접근 방식 | 강조점 | ContextGuard와의 관계 |
| --- | --- | --- |
| 압축 우선 | 모델에 이미 선택된 텍스트를 줄이며, 경우에 따라 손실형 변환을 사용합니다. | ContextGuard는 손실형 단방향 압축보다 로컬 보관본 저장과 정확한 줄·패턴 재조회를 선호하므로, 원본을 다시 가져올 수 있습니다. |
| 여러 에이전트의 간결 출력 규칙 | 여러 에이전트에 brief 모드 출력 규칙을 한꺼번에 설치합니다. | ContextGuard는 안내용 brief 모드 스니펫과 dry-run 에이전트 간 설정을 제공합니다. 프로젝트별 opt-in이며, 절감을 보장하지 않습니다. |
| ContextGuard | 불필요한 파일·로그·출력이 컨텍스트에 들어가기 전에 줄어들도록 돕고 보수적으로 측정합니다. | 로컬 가드레일, 되돌릴 수 있는 로컬 보관본·재조회, 직접 측정하는 벤치마크 근거를 제공합니다. |

### brief 모드 (안내용)

brief 모드는 코딩 에이전트가 군더더기를 줄이도록 요청하되, 리뷰에 필요한 증거(파일 경로, 명령, 명령 출력과 오류, 코드 블록, 검증 상태, 변경 파일, 남은 과제, 주의사항)는 유지하도록 돕는 에이전트 중립·안내용 규칙 스니펫 모음입니다. 강제가 아니라 최선 노력 안내이며, 토큰·비용 절감을 **보장하지 않습니다.**

사전 정의된 세 레벨이 [`plugins/context-guard/brief/`](../plugins/context-guard/brief/)에 포함됩니다: `lite`, `standard`, `ultra`. 각 레벨은 에이전트 규칙·지시 파일(`AGENTS.md`, `CLAUDE.md`, Cursor 규칙 파일, Copilot 지시 등)에 들어가는 마커 구분 블록입니다. `context-guard setup --agent codex --scope project --brief-mode standard --plan`으로 미리 보고, 적용은 `--yes`로 다시 실행하며, 제거는 `--brief-mode off`를 사용하세요. 자세한 내용은 [`plugins/context-guard/brief/README.md`](../plugins/context-guard/brief/README.md)를 참고하세요.

### Claude 조용한 진행 설명 (안내용)

조용한 진행 설명은 기본적으로 꺼져 있는 별도의 Claude 전용 규칙입니다. 선택적 사전 설명, 도구별 진행 중계, 군더더기, 반복 중간 요약은 줄이지만 승인·결정 요청, 차단 요인, 실패, 파괴적 작업·보안 경고, 상위 우선순위가 요구하는 진행 보고, 최종 결과, 변경 파일, 검증 결과는 유지합니다. 최종 답변의 간결성이나 추론 깊이와는 별개인 최선 노력 규칙이며, 토큰·비용 절감을 **보장하지 않습니다.**

```bash
context-guard setup --rules-only --agent claude --scope project --narration-mode quiet --plan
context-guard setup --rules-only --agent claude --scope project --narration-mode quiet --yes
context-guard setup --rules-only --agent claude --scope project --narration-mode default --yes
```

이 격리된 작업은 프로젝트 `CLAUDE.md` 안의 ContextGuard narration 구간만 관리합니다. Claude settings, hook, permission, statusline, model default 또는 다른 에이전트 규칙 파일은 읽거나 바꾸지 않습니다. brief mode, 초기화, skill 생성 또는 일반 setup 작업과 함께 사용할 수 없습니다. Gate C는 정적 규칙과 setup 부작용만 검증하며 모델의 준수나 수치 절감 주장을 증명하지 않습니다.

### 제공 기능

| 기능 | 도움되는 상황 |
| --- | --- |
| Claude Code 플러그인 스킬 | 설정 마법사, 최적화 점검, 대화 기록 사용량 감사를 Claude Code 안에서 실행합니다. |
| 프로젝트 단위 설정 마법사 | 전역 설정은 그대로 두고 권장 `.claude/settings.json` 옵션을 프로젝트에 적용합니다. |
| 컨텍스트 관리 스캐너 | 누락된 가드레일, 과도한 훅 출력, 넓은 읽기 범위, 큰 컨텍스트 파일, 민감해 보이는 파일, 과도한 MCP 서버, 비용이 큰 기본값을 찾습니다. |
| 구조적 낭비 진단 | 중복 규칙, stale import 후보, 쓰이지 않는 skill 후보, 과도한 tool schema, 반복 read/tool-call loop를 읽기 전용으로 진단합니다. |
| 대용량 읽기 가드와 심볼 리더 | 파일 전체 읽기 대신 `rg`, 심볼 단위 읽기, 작은 줄 범위 읽기를 사용하도록 안내합니다. |
| 출력 축약과 민감정보 가림 | 테스트·빌드·검색·diff 출력을 작게 만들고, 에이전트 컨텍스트에 들어가기 전에 민감해 보이는 값을 가립니다. |
| 선언형 출력 필터 | 사용자 정의 JSON DSL로 성공 출력만 명시적으로 줄이고, 보호해야 하는 실패 출력은 원문 stdout/stderr와 종료 코드를 보존합니다. |
| 로컬 로그 보관소 | 큰 로그를 대화 밖 로컬 저장소에 보관하고, 요약 정보나 요청한 줄 범위만 다시 가져옵니다. |
| Anthropic 비용 가드 | `context-guard cost preflight/observe/ledger/compile`이 cache 위험과 비용 범위를 추정합니다. `context-guard-receipt evaluate full-wire`는 baseline/candidate 전체 요청 envelope를 하나의 canonical-byte ceiling으로 비교하고 protected JSON pointer와 출력 토큰 예산이 유지되거나 줄었는지 검사합니다. `context-guard route-advisor`는 로컬 총비용과 batchability route 후보를 요약하며, ledger를 쓸 때도 원문 대신 keyed HMAC fingerprint만 저장합니다. `--enforce`를 명시하지 않으면 경고만 합니다. |
| 예산 기반 컨텍스트 패커 | 우선순위가 있는 로컬 파일 근거를 바이트 예산 안의 Markdown 팩으로 조립하고, 로컬 신호에서 `build`용 manifest를 추천하며, `--explain`, `--adaptive-k`, `--symbol-memory`로 로컬 자문 메타데이터를 덧붙일 수 있습니다. |
| Tool/MCP schema pruner | 로컬 catalog에서 bounded top-k tool/schema 자문 리포트를 만들고, compact 요약 기록과 전체 가림 처리된 payload 재조회 경로를 남깁니다. |
| 보수적 stdin 압축기 | 선택한 JSON, diff, 로그, 검색 출력, 코드, 산문을 줄이고, 관측 바이트 근거와 추정 토큰 proxy를 함께 표시합니다. `--mode readable`은 exact fallback 안내가 있는 opt-in 산문 preview를 추가합니다. |
| 보호 영역 정책 기록 | `context-guard-compress --protected-policy`와 `context-guard cost compile`이 코드·diff·path·hash·JSON/literal zone을 structural-only 변환 대상으로 표시하고 정확한 재조회 경계를 남깁니다. |
| 반복 실패 알림 | Bash 실패가 반복되면 실패 로그가 컨텍스트를 채우기 전에 전략을 바꾸도록 안내합니다. |
| 상태표시줄, 감사, 벤치마크 | 컨텍스트·캐시·비용 신호를 보여주고, 사용량과 캐시 친화성 집중 지점을 찾고, 보수적인 전후 비교 증거를 남깁니다. |

#### 비용 가드 키 준비

비용 가드의 로컬 HMAC 키는 기본적으로 `.context-guard/cost-ledger/hmac.key`에 자동 생성됩니다. 관리자가 직접 주입하는 경우 파일에는 필수 padding을 포함한 canonical URL-safe base64 32바이트 키만 정확히 들어 있어야 하며, trailing newline이나 공백은 허용되지 않습니다. 리포트는 키와 원문 프롬프트를 출력하지 않으며, 로컬 ledger는 Anthropic/provider prompt cache를 대체하지 않습니다.

### Claude Code에서 설치

마켓플레이스를 추가하고 플러그인을 설치합니다.

```text
/plugin marketplace add ictechgy/context-guard
/plugin install context-guard@context-guard
```

그다음, 보호하려는 프로젝트에서 Claude Code를 열고 설정 마법사를 실행합니다.

```text
/context-guard:setup
```

사용 가능한 플러그인 스킬은 다음과 같습니다.

| 스킬 | 용도 |
| --- | --- |
| `/context-guard:setup` | 처음 적용할 때 쓰는 프로젝트 설정 마법사입니다. |
| `/context-guard:optimize` | 컨텍스트 가드레일을 점검하고 조정합니다. |
| `/context-guard:audit` | 로컬 Claude 대화 기록의 토큰·비용 집중 지점을 확인합니다. |

설정은 명시적이며, 프로젝트 단위로 적용되고, 되돌릴 수 있습니다. ContextGuard는 외부 모델로 작업을 위임하거나 외부에서 실행되도록 설정하지 않으며, 모든 헬퍼 명령은 로컬에서 동작합니다. 예시 설정은 [`plugins/context-guard/examples/settings.example.json`](../plugins/context-guard/examples/settings.example.json)을 참고하세요.

### npm/npx로 설치

npm 패키지는 단일 `context-guard` 명령과 `context-guard-*` 헬퍼 명령을 함께 제공합니다. 설치는 수동적입니다. `postinstall`로 설정을 쓰지 않으며, 사용자가 직접 `context-guard setup`을 실행할 때만 프로젝트나 사용자 설정을 변경합니다. npm global/`npx` bin 링크는 의도적으로 canonical `context-guard`/`context-guard-*` 명령만 노출합니다. legacy `claude-*` 래퍼 파일은 이번 릴리스에서 제거했습니다. setup이 패키지/체크아웃 내부 헬퍼를 찾지 못해도 `PATH` fallback은 기본적으로 꺼져 있습니다. `context-guard doctor` 또는 `setup --verify`로 계획을 확인한 뒤 신뢰하는 헬퍼 디렉터리에 한해서만 `--allow-path-helper-fallback`을 사용하세요.

```bash
npm install -g @ictechgy/context-guard
context-guard --version
context-guard doctor --root . --json
context-guard setup --agent codex --scope project --with-init --with-skill --with-mcp --plan
context-guard setup --agent codex --scope project --brief-mode standard --plan
```

전역 설치 없이 한 번만 실행하려면 다음처럼 사용할 수 있습니다.

```bash
npx @ictechgy/context-guard setup --agent codex --scope project --with-init --with-skill --with-mcp --plan
npx @ictechgy/context-guard setup --agent codex --scope project --brief-mode standard --plan
npm exec @ictechgy/context-guard -- --version
```

`--scope project`는 `AGENTS.md`, `.agents/skills/...`처럼 저장소 안 파일에 적용합니다. `--scope user`는 전체 사용자 환경에 적용하려는 경우에만 의도적으로 사용하세요. 실제 적용에는 `--yes`와 명시적인 `--agent`가 필요하며, 지원되는 쓰기는 되돌리기 기록을 남깁니다.

`--with-mcp`는 Codex와 검증된 JSON project 설정을 충돌 없이 백업·병합합니다.
Windsurf와 Cline의 MCP는 문서상 사용자/IDE 범위여서 자동 쓰지 않습니다.
[공식 Codex MCP 문서](https://learn.chatgpt.com/docs/extend/mcp)를 참고하세요.

#### Claude Code용 선택적 Bash reference

`bash_reference_v1` 경로는 정확한 프로젝트 로컬 npm 설치에서만 사용할 수
있습니다. 루트 패키지는 `@ictechgy/context-guard-receipt@0.4.0`을 정확히
고정합니다. global npm, `npx`, 소스 체크아웃, Homebrew, Claude marketplace
plugin 배치에서는 기존 Bash trim 동작을 유지하고 setup이 reference 경로를
사용할 수 없다고 알립니다.

```bash
npm install --save-exact @ictechgy/context-guard@0.13.0
./node_modules/.bin/context-guard setup --root . --agent claude --scope project --bash-reference-v1 --plan
./node_modules/.bin/context-guard setup --root . --agent claude --scope project --bash-reference-v1 --yes
```

기본 비활성인 이 `PreToolUse:Bash` 모드는 강하게 가림 처리된 긴 명령 출력을
프로젝트의 비공개 Receipt 저장소에 두고 digest에는 짧은 조회 handle만
넣습니다. Handle은 bearer와 비슷하고 Claude/provider에 보일 수 있으며 발급
후 정확히 7일 뒤 만료됩니다. Bash 실행 전에 wrapper는 소유자 전용 익명 캡처
descriptor와 검증된 Receipt broker 하나를 준비합니다. Broker는 코드 로드와
repository/store/expiry/journal 경계 고정을 끝낸 뒤에만 준비 완료를 알립니다.
따라서 8,192바이트 공개 임계값보다 작은 출력도 로컬 상태 축을 초기화할 수
있지만, 이 경우 `ABORT`하고 handle은 내보내지 않습니다. Strong sanitizer,
정확한 패키지 pin, 절대 Node runtime, broker 준비 또는 최종 등록을 사용할 수
없으면 감싼 명령의 exit status를 바꾸지 않고 legacy trim으로 돌아갑니다.
기존 `--artifact-receipt` 캡처와는 동시에 사용할 수 없습니다.

Digest는 handle을 실행 가능한 프로젝트 로컬 조회 명령으로 표시합니다.

```bash
./node_modules/.bin/context-guard reference <cgr1p-handle>
```

Handle을 발급한 동일한 물리 프로젝트 root에서 실행하세요. 명령은 비공개
sibling state 위치를 내부에서 계산하고, 정확한 sanitized UTF-8 출력 중 최대
20,000바이트 한 페이지만 반환합니다. 남은 바이트가 있으면 diagnostic에 다음
연속 조회용 `--offset`을 표시하므로 전체 보관 출력을 한 번에 transcript로 쏟지
않습니다. 잘못되었거나 만료된 handle, 다른 root, stale source, 변경된 패키지,
잘못된 응답은 payload를 전혀 반환하지 않습니다.

패키지를 제거하기 전에 reference 경로를 먼저 끄세요.

```bash
./node_modules/.bin/context-guard setup --root . --agent claude --scope project --no-bash-reference-v1 --yes --no-diet-scan
npm uninstall @ictechgy/context-guard
```

Receipt 상태는 저장소 밖의 비공개 sibling 디렉터리
`.context-guard-receipt-state-<root-selector-sha256>`에 둡니다. Selector는
정규화한 root 경로와 device/inode identity를 묶으므로 나란한 저장소끼리
authority를 공유하지 않습니다. 비활성화와 패키지 제거는 나중의 정확한 재설치나
별도 사용자 승인 artifact 정리를 위해 이 디렉터리를 보존합니다. 다만 `npm
uninstall`은 검증된 package-local code와 `node_modules/.bin/context-guard`를
제거하므로, 정확한 프로젝트 로컬 pair를 다시 설치하기 전에는 reference 조회를
할 수 없습니다. 이 메커니즘은 큰 Bash 출력의 transcript 입력을 줄일 수 있지만
고정된 provider token 또는 비용 절감을 보장하지 않습니다.

### Homebrew 배포 경로

Homebrew는 공유 `ictechgy/tap` tap을 통해 macOS 배포 경로로 사용할 수 있습니다.

```bash
brew install ictechgy/tap/context-guard
context-guard --version
```

이미 `ictechgy/tap`을 tap했다면 `brew install context-guard`도 사용할 수 있습니다.

### 자주 쓰는 헬퍼 명령

대부분의 사용자는 `/context-guard:setup`부터 시작하면 됩니다. 아래 명령은 로컬 테스트, 자동화, 특정 문제 진단에 유용합니다. 기본 명령 접두사는 `context-guard-*`입니다.

#### 설치 전 상태 점검

```bash
context-guard doctor --root . --json
context-guard setup --agent claude --scope user --verify --json
```

두 명령은 모두 설정을 변경하지 않는 읽기 전용 점검입니다. `doctor`는 권장 다음 명령을 보고하고, `setup --verify`는 설정을 적용하지 않은 채 완료 여부만 확인합니다. `--json` 모드는 결과를 stdout으로 출력합니다.

#### 컨텍스트 관리 검사

```bash
./plugins/context-guard/bin/context-guard-diet scan .
```

스캐너는 누락된 가드레일, 과도한 훅 출력, 넓은 컨텍스트 경로, 여러 AI 에이전트 규칙 파일의 크거나 민감해 보이는 지시문/규칙 파일, 그리고 용량이 크거나 민감해 보이는 경로를 AI 컨텍스트에서 제외하기 위한 로컬 추천을 보고합니다. `--top`은 context-like file 목록과 context-exclusion 추천 목록에 공통으로 적용됩니다. 추천은 Claude `permissions.deny`로 나온 항목 외에는 휴리스틱/자문 성격입니다.

#### 대용량 파일을 심볼 단위로 읽기

```bash
./plugins/context-guard/bin/context-guard-read-symbol path/to/file.py TargetSymbol
```

선택형 Read 가드는 큰 파일에 대해 검색 → 심볼 구간 → 작은 줄 범위 순서의 단계적 축소 전략을 제안합니다. 가능하면 제한된 최상위 개요도 함께 보여줍니다. 같은 대용량 파일을 반복해서 전체 읽으려 하면 중복 읽기 경고를 표시해 같은 컨텍스트 낭비 경로를 반복하지 않게 합니다.

적용 범위는 의도적으로 Claude Code `PreToolUse`의 `Read` matcher 훅으로 한정됩니다.

이 Read 가드를 선택하면 setup은 기존 deny 값 중 정확히 `Read(./.env)`와 `Read(./.env.*)`만 제거합니다. 비슷한 permission 항목과 그 상대적 순서는 유지합니다.

| Claude 도구 | 보호 범위 |
| --- | --- |
| `Read` | 제한된 대용량 파일 범위를 검사하고, basename이 `.env`로 시작하면 차단합니다. 단, 정확히 `.env.example`, `.env.sample`, `.env.template`인 템플릿 이름은 허용합니다. 중첩 경로도 포함하며 symlink 여부가 모호하면 닫힌 상태로 실패합니다. |
| `Glob` | 일치하는 이름을 나열할 수 있습니다. 이 `Read` 훅을 통해 파일 내용을 읽지는 않습니다. |
| `Grep` | 이 훅의 범위 밖이며 일치하는 파일 내용을 읽을 수 있습니다. |
| `Bash` | 이 훅의 범위 밖이며 파일 내용을 읽을 수 있습니다. |

이는 Claude `Read` 보호이지 범용 `.env` 보호나 Bash 보호가 아닙니다. 훅은 symlink를 따라가지 않고 직접 연 파일 descriptor의 상태를 다시 검증하지만, 실제 Claude `Read`는 훅이 반환된 뒤 파일을 다시 엽니다. 그 사이 파일이 교체될 수 있는 post-hook 구간은 문서화된 TOCTOU 한계입니다.

#### 큰 로그를 로컬에 저장하고 필요한 부분만 조회

```bash
long-command 2>&1 | ./plugins/context-guard/bin/context-guard-artifact store --command "long-command" --json
./plugins/context-guard/bin/context-guard-artifact search "ERROR" --json
./plugins/context-guard/bin/context-guard-artifact receipt <artifact_id> --json
./plugins/context-guard/bin/context-guard-artifact get <artifact_id> --lines 1:80
./plugins/context-guard/bin/context-guard task-memory put --task issue-123 --source src/app.py --json < stable-context.txt
./plugins/context-guard/bin/context-guard task-memory get <opaque_handle> --task issue-123 --source src/app.py --max-bytes 65536
```

로컬 보관 모드는 캡처·sandbox 검색·조회 용도입니다. 기본 저장 위치는 `.context-guard/artifacts`이며, 리브랜딩 이전의 `.claude-token-optimizer/artifacts` 요약 기록도 계속 읽을 수 있습니다. JSON 요약 기록에는 줄 번호가 포함된 top-error 요약 기록, 중복 라인 그룹, 가림 처리된 범위 제한 `suggested_queries`, 안정적인 `contextguard-artifact:<id>` 핸들이 있는 `output_sandbox` envelope가 들어갑니다. `context-guard-artifact receipt <artifact_id> --json`으로 본문 없이 메타데이터/재조회 핸들만 다시 가져온 뒤, 전체 로그를 다시 넣지 않고 필요한 최소 범위만 정확하게 조회할 수 있습니다. `search`는 로컬 sanitized artifact sandbox를 literal substring으로 검색하고, bounded match/context record와 `context-guard-artifact get ... --lines START:END` 재조회 명령을 함께 반환합니다. custom `--dir` 값의 raw private path는 기본적으로 가림 처리되므로 같은 `--dir`로 다시 실행하거나, 직접 실행 가능한 local command가 꼭 필요할 때만 `search --show-paths`를 명시하세요. 이 검색 리포트는 local-only이며 hosted token/cost savings claim으로 해석하면 안 됩니다. 릴리스 확인처럼 종료 코드가 중요한 파이프라인에서는 원래 명령의 종료 코드를 직접 보존하세요. 종료 코드 보존이 핵심이면 `context-guard-trim-output -- ...`을 사용하는 편이 안전합니다.

#### 예산 기반 컨텍스트 팩 만들기

```bash
./plugins/context-guard/bin/context-guard-pack auto \
  --root . \
  --query "failing tests review" \
  --diff HEAD \
  --manifest-out suggested-pack.json \
  --pack-out context-pack.md \
  --budget-bytes 12000 --json --explain --adaptive-k --symbol-memory
# 안전한 direct import neighbor를 최대 4개까지 pack에 명시적으로 추가:
./plugins/context-guard/bin/context-guard-pack auto \
  --root . --files src/app.py --query "entrypoint 검토" --top 1 \
  --budget-bytes 12000 --json --no-artifact --apply-symbol-memory
# 로컬 품질 gate 통과 뒤 heuristic source를 명시적으로 축소:
./plugins/context-guard/bin/context-guard-pack auto \
  --root . --query "실패 테스트 검토" --top 8 \
  --budget-bytes 12000 --json --no-artifact --apply-adaptive-k
# 또는 명시적인 두 단계로 실행:
./plugins/context-guard/bin/context-guard-pack suggest \
  --root . --query "failing tests review" --diff HEAD \
  --manifest-out suggested-pack.json --budget-bytes 12000 --json --adaptive-k --adaptive-k-policy recall
./plugins/context-guard/bin/context-guard-pack build \
  --root . --manifest suggested-pack.json --budget-bytes 12000 --json
# 하나의 정확한 private local receipt와 선택적으로 진단 비교:
./plugins/context-guard/bin/context-guard-pack build \
  --root . --manifest suggested-pack.json --budget-bytes 12000 --json --no-artifact \
  --delta-from-pack-id 0123456789abcdef0123
./plugins/context-guard/bin/context-guard-pack slice --root . --path README.md --lines 1:40 --json
```

`context-guard-pack auto`는 추천 단계와 예산 기반 Markdown 팩 생성을 한 번에 실행하는 로컬 전용 경로입니다.

의도적인 경계는 다음과 같습니다.

- `--explain`을 추가하면 JSON 또는 텍스트 출력에 결정적 로컬 선택/build 이유를 짧게 포함합니다.
- JSON explain에는 bounded `repo_map`이 포함될 수 있습니다. 예시는 sampled byte/token-proxy tree, category-only secret risk count, signature-first hint, explain-only graph rank, 기존 `slice`/symbol 재조회 힌트입니다.
- repo-map은 manifest, pack 본문, receipt, byte budget을 바꾸지 않고 네트워크·모델 호출·임베딩을 쓰지 않습니다. 토큰 값은 provider-token이나 savings claim이 아닌 추정 `chars_div_4` proxy입니다.
- `suggest` 또는 `auto`에 `--adaptive-k`를 추가하면 로컬 score distribution, byte-budget fit, clamped score-mass 기반 recall/precision proxy에서 나온 advisory-only top-k shrink/expand metadata를 포함합니다. `--adaptive-k-policy balanced|recall|precision`과 선택적 `--adaptive-k-min-recall-proxy` / `--adaptive-k-min-precision-proxy` gate로 로컬 추천 정책을 고를 수 있고, gate 실패는 metadata-only(`pass|failed`)입니다. adaptive block은 capped selected/omitted evidence와 구조화된 source-verification hint를 포함하지만 추천값을 자동 적용하지 않으며 manifest, pack 본문, receipt, byte budget을 바꾸지 않습니다.
- `auto --apply-adaptive-k`는 명시적·기본 비활성 pruning 경로입니다. 회귀 gate가 통과할 때만 로컬 추천값을 적용하고, 호출자가 지정한 file/output/test-output 및 diff source는 항상 유지한 채 같은 byte budget으로 다시 build하며 `adaptive_k_application`을 기록합니다. `--adaptive-k`를 내포하지만 provider token/cost 절감 주장을 허용하지 않습니다.
- `auto`에 `--symbol-memory`를 추가하면 repo-map 기반 symbol/graph advisory metadata와 정확한 `slice` / `read-symbol` 검증 힌트를 포함합니다. 이는 source verification 안내일 뿐이며 manifest, pack 본문, receipt, byte budget을 바꾸지 않습니다.
- `--apply-symbol-memory`는 명시적·기본 비활성 Graphify식 적용 경로입니다. 일반 추천 뒤 안전한 direct import neighbor slice를 최대 4개 manifest에 추가하고 같은 byte budget으로 pack을 다시 만듭니다. explicit/query seed는 더 높은 우선순위를 유지하고 secret-risk neighbor는 제외하며 exact source/fallback receipt는 보존됩니다. 결과에는 닫힌 `graph_application` 블록이 기록되며 provider token/cost 절감 주장은 하지 않습니다.
- `--self-financing-selection`은 기본 비활성 조합 경로입니다. ordinary pack byte ceiling을 고정한 뒤 Adaptive, task-matching Symbol, bounded one-hop Graph 순서로 적용합니다. 각 후보는 frozen identity, secret-risk 판단, byte delta, exact fallback, 대체된 lower-value non-caller source를 기록하며 안전하게 맞지 않으면 정직한 no-op이 됩니다. 이는 로컬 byte-ceiling 정책이며 provider token/cost 절감 주장이 아닙니다.
- `auto --selection-plan --json`은 pack, manifest, receipt를 쓰지 않는 provider-free read-only content-addressed plan을 만듭니다. JSON을 명시적으로 저장한 뒤 같은 task 입력과 `--apply-selection-plan PATH --no-artifact`(또는 명시적인 output/artifact 옵션)를 사용해 적용합니다. apply는 출력 전에 closed plan과 source identity를 다시 검증하며 drift, incomplete scan, secret-risk 또는 scorer/private 입력, unsafe host/output boundary, exact recovery 누락을 fail-closed로 거부합니다.

```bash
context-guard-pack auto --root . --query "checkout retry 수정" --diff worktree --output logs/test.txt --json --selection-plan > selection-plan.json
context-guard-pack auto --root . --query "checkout retry 수정" --diff worktree --output logs/test.txt --json --apply-selection-plan selection-plan.json --no-artifact
```
- `--manifest-out`은 `build`가 읽을 수 있는 manifest를 저장하고, `--pack-out`은 렌더링된 팩 본문을 저장합니다.
- `context-guard-pack suggest`는 더 낮은 수준의 로컬 전용 준비 단계입니다. `--query`, `--diff`, 반복 `--files`, 그리고 `--root` 아래의 선택적 `--output` / `--test-output` 텍스트 파일을 가림 처리한 신호에서 후보 파일과 줄 범위를 순위화한 뒤 `build --manifest`가 바로 읽을 수 있는 manifest를 씁니다.
- `context-guard-pack build`는 우선순위가 있는 로컬 파일 근거를 렌더링된 UTF-8 바이트 기준 `--budget-bytes` 안의 Markdown 팩으로 조립합니다. JSON 출력은 포함·부분 포함·중복·unsafe·missing·예산 초과로 누락된 source를 기록합니다.
- 모든 build는 정확히 렌더링된 pack byte의 `content_address`(`sha256:<digest>`)를 제공하면서 기존 `pack_id`는 유지합니다. `build` 또는 `auto`의 선택적 `--delta-from-pack-id PACK_ID`는 `.context-guard/packs/PACK_ID.json` 하나만 읽고 bounded/fail-soft `rolling_delta` 진단을 반환합니다. selection, pack 본문, `pack_id`, 기본 동작을 바꾸지 않으며 provider token/cost savings claim이 아닙니다. 진단은 `--json` 출력 또는 저장된 artifact receipt에서만 보고됩니다. `--no-artifact`를 쓰면 진단 보고에 `--json`이 필요하며, 기존 text stdout은 정확한 pack 본문을 그대로 유지합니다.
- 제한된 로컬 요약 기록은 `.context-guard/packs`에 저장됩니다. `path`와 `root`를 안전하게 표시할 수 있을 때만 정확한 가림 처리 slice 명령을 제공하고, 안전하지 않으면 팩 본문과 JSON 메타데이터에 `retrieval_omitted_reason`을 남깁니다.

표준 라이브러리 기반의 결정적 휴리스틱만 사용하며, 네트워크·모델 호출·임베딩·provider 비용 추정은 하지 않습니다. 바이트 수는 관측값이고, 토큰 수는 provider가 실제 측정한 토큰 절감값이 아니라 추정 `chars_div_4` proxy입니다.

#### 작업에 맞게 tool/MCP catalog 줄이기

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

`context-guard-tool-prune`은 로컬 tool 또는 MCP catalog를 결정적 lexical heuristic(어휘 기반 휴리스틱)으로 순위화해 제한된 top-k 자문 리포트를 만듭니다. inline schema는 관측된 UTF-8 바이트 예산을 지키고, 누락되거나 예산 때문에 생략된 schema는 `.context-guard/tool-prune`의 compact 요약 기록과 별도 가림 처리 payload로 다시 조회할 수 있습니다. `defer-report`는 core inline tool과 deferred tool stub/namespace 요약을 나누고, 첫 프롬프트에서 빠진 schema의 gross/net char/4 proxy 회계를 함께 보여줍니다. 이 기능은 안내용이며 MCP 설정이나 native provider tool search를 변경하지 않습니다. 토큰 값은 provider가 측정한 절감 수치가 아니라 추정 proxy입니다.

#### 총비용, batchability, routing 후보 자문

```bash
context-guard-receipt evaluate full-wire --input full-wire-evaluation.json
./plugins/context-guard/bin/context-guard route-advisor --workload workload.json --json
./plugins/context-guard/bin/context-guard-cost route-advisor --feature batch_api=true --feature structured_outputs=true --json < workload.json
./plugins/context-guard/bin/context-guard cost advisory --workload advisory-workload.json --json
```

`context-guard-receipt evaluate full-wire`는 `schema_version=contextguard.full-wire-budget-request/v1`, `baseline`, `candidate`, `protected_pointers`, boolean `enforce`를 담은 크기 제한 canonical JSON envelope 하나를 읽습니다. 전체 canonical JSON byte를 비교하고 protected pointer 값이 같으며 한쪽에 `max_tokens`가 선언된 경우 candidate 예산이 늘거나 사라지지 않았는지 검사합니다. Cache-prefix 보존은 진단 정보이고, 요청 원문은 출력·저장하지 않으며 canonical JSON byte는 실제 HTTP wire byte나 provider 측정 token 절감값이 아닙니다.

`context-guard-receipt evaluate calibration`은 선언된 최소 표본 이후 HMAC-only preflight/observation row를 결합하고, `evaluate route-v2`는 그 integer 총비용 정책을 shadow-only 자문으로 평가합니다. 어느 명령도 자동 route나 절감 주장을 허가하지 않습니다.

Receipt companion은 provider-free `evaluate net-efficiency`, `fanout-plan`,
`prefix-plan`, `prune-plan`, `shadow-policy` 계약도 제공합니다. 이 계약은
대응 quality, 전체 shifted cost, p95 latency, output/model round, 서로 다른
canary window, fan-out 형태, cache-prefix 안정성, 안전한 task-boundary pruning을
측정하지만 항상 shadow-only입니다. Task-scoped `receipt_batch` MCP 도구는
이미 승인된 exact slice 여러 개를 하나의 제한된 read-only 호출로 반환하며
shell, provider, network 권한을 추가하지 않습니다.
다섯 evaluator의 복사·실행 가능한 canonical JSON과 명령은
[Receipt 최소 입력 예시](../packages/context-guard-receipt/README.md#minimal-evaluator-inputs)에 있습니다.

`context-guard route-advisor`는 로컬 passive advisor입니다. caller가 제공한 workload JSON, provider feature 선언, usage telemetry, 외부·로컬 shifted cost를 읽고 total-cost accounting, batchability blocker, batch API·prompt-cache prefix 보존·structured outputs·저비용 모델 평가 같은 route 후보를 출력합니다. queue를 시작하거나 provider를 호출하거나 pricing 문서를 새로 가져오지 않으며, provider feature는 caller-supplied 또는 unknown/recheck-required로 표시합니다. 추천은 후보일 뿐입니다. hosted token/cost 절감을 주장하려면 matched successful task, 비열등 quality gate, shifted-cost evidence가 필요합니다.

`context-guard cost advisory`는 WeightClass/router용 zero-persistent-context gate입니다. 닫힌 숫자·불리언 capability 신호만 받고, 모든 경로에서 provider context를 빈 값으로 유지하며, 작거나 순이익이 없는 작업을 bypass하고, cached positive replacement 근거가 있을 때만 graph를 허용합니다. 자세한 계약은 [WeightClass advisory mode](https://github.com/ictechgy/context-guard/blob/main/docs/weightclass-advisory-mode.md)를 참고하세요.

#### 선택한 로컬 텍스트를 보수적으로 압축하기

```bash
git diff | ./plugins/context-guard/bin/context-guard-compress --json
pytest -q 2>&1 | ./plugins/context-guard/bin/context-guard-compress --type log
cat evidence.txt | ./plugins/context-guard/bin/context-guard-compress --json --protected-policy
cat sanitized-prose.txt | ./plugins/context-guard/bin/context-guard-compress --json --type prose --mode readable
```

`context-guard-compress`는 가림 처리된 stdin을 JSON, diff, 로그, 검색 출력, 코드, 산문으로 분류한 뒤 JSON compact, diff 컨텍스트 접기, 중복 로그·검색 라인 제거, 공백 정규화 같은 결정적 축소를 적용합니다. 모델 토큰 절감을 관측했다고 주장하지 않으며, 바이트 수는 관측값으로, 토큰 수는 추정치로만 표시합니다. 손실형 요약 기록은 정확한 재조회를 위해 `context-guard-artifact store` 사용을 안내합니다.

입력에 코드 펜스, diff, 식별자, 숫자 상수, 해시, 경로, 스택 프레임, 따옴표 문자열, JSON 키처럼 의미 보존이 중요한 구역이 있을 때는 `--protected-policy`를 추가하세요. 이 플래그는 기본 압축 동작을 바꾸지 않고, 의미·표현 변환을 거부하며 구조적 변환과 보관본 재조회만 허용하는 `protected_zone_policy`와 `transform_policy` 메타데이터를 추가합니다. 원문 보호 구간 대신 class/count 정책 메타데이터만 저장합니다.

`--mode readable`은 가림 처리된 산문 preview에만 사용하세요. 결정적 sentence window를 쓰고, prompt-like 또는 high-risk protected signal이 있으면 차단하며, raw protected span을 저장하지 않고 edit/claim 전에 exact fallback retrieval이 필요하다고 표시합니다. learned compressor, model, embedding, reranker는 실행하지 않습니다.

#### 명령 출력을 줄이거나 요약하기

```bash
./plugins/context-guard/bin/context-guard-trim-output --max-lines 120 -- npm test
```

head/tail 로그 대신 의미 요약이 필요하면 `--digest markdown` 또는 `--digest json`을 사용하세요. 명령이 성공하고 출력이 이미 요약보다 작으면 요약 대신 원래 출력을 한 줄 표식과 함께 그대로 통과시키므로, 출력이 적은 명령에 요약 모드를 켜도 컨텍스트가 늘어나지 않습니다. 실패한 명령은 종료 코드와 실패 signature가 요약에 담기므로 항상 요약을 유지합니다. 모든 경우에 구조화된 요약을 유지하려면 `--digest-always`를 전달하세요. 요약 모드는 원래 종료 코드를 보존하면서 상태, 종료 코드, 잘린 줄 수, 실행기 실패 정보, 가림 처리된 실패 signature, 중복 라인 그룹, 대표 라인, 가림 처리 횟수, 다음 조회 제안을 남깁니다. 요약 모드에서 가림 처리된 전체 출력을 로컬 `context-guard-artifact` 보관본에 저장하려면 `--artifact-receipt`를 함께 사용하세요. 출력된 `contextguard-artifact:<id>` 핸들을 agent context에 남기고, 생략된 세부 내용에 의존하기 전에 `context-guard-artifact receipt/get/search ...` 명령으로 필요한 부분을 정확히 다시 가져오세요. 래핑된 명령은 기본 600초 뒤 종료되며, `--timeout-seconds`로 조정할 수 있습니다.

#### 검색·diff 출력 민감정보 가림

```bash
./plugins/context-guard/bin/context-guard-sanitize-output -- rg -n "TOKEN|SECRET" .
./plugins/context-guard/bin/context-guard-sanitize-output -- git diff
```

민감정보 가림 도구는 토큰, 키, 비밀번호, 민감한 경로로 보이는 값이 에이전트 컨텍스트에 그대로 복사될 가능성을 줄입니다.

#### 로컬 대화 기록 사용량 감사

```bash
./plugins/context-guard/bin/context-guard-audit ~/.claude/projects --top 20 --recommend
```

감사 명령은 기본적으로 너무 큰 대화 기록 파일과 JSONL 기록을 건너뛰고(`--max-file-bytes`, `--max-line-bytes`), 건너뛴 개수를 함께 보고합니다. 손상된 추적 기록이 메모리를 독점하거나 스캔 공백을 숨기지 않도록 하기 위한 방어입니다.

JSON 출력에는 여러 증거 surface가 포함될 수 있습니다.

- `cache_friendliness`와 [`cache_diagnostics`](cache-diagnostics-schema.md): 제한된 사용량 필드, timestamped cache telemetry records, 가림 처리된 segment hash로 만든 휴리스틱 프롬프트 배치/cache-read 진단입니다.
- `cache_layout_advice`: 긴 세션 분리, prefix 안정화 같은 순위화된 **확인/실험**으로 신호를 바꾸되, 관측된 issue와 가설/입증된 cause를 분리합니다.
- `tool_result_bytes`: 컨텍스트 바이트가 실제로 어디서 왔는지를 대화 기록 **`tool_result` 블록의 내용**에서 세어 보고합니다. 도구별, 내용 종류별(이미지·텍스트·불명), 확장자별 분포와 크기 백분위, 가장 큰 결과들이 차지하는 비중, 완전 중복 비율, 파일 읽기 바이트 중 범위를 지정한 요청이 차지하는 비중을 담습니다. `tool_use` 블록은 귀속과 확장자·범위 라벨에 쓰지만 그 입력 바이트는 세지 않으며, 도구 결과 밖의 것도 세지 않습니다. 바이트는 내용 블록 단위로 귀속하므로, 이미지와 텍스트를 함께 담은 결과 하나는 두 클래스 모두에 계상됩니다. 확장자 라벨은 알려진 확장자 목록에서만 나옵니다 — 목록에 없는 접미사는 `(not-an-extension)` 이 됩니다. 모양 검사로는 `notes.clientAcme` 같은 파일명 조각이 "확장자" 로 통과하는 것을 막을 수 없기 때문입니다. 흔치 않은 실제 확장자도 함께 접히지만, 잃는 것은 확장자 차원뿐이고 바이트 총합은 그대로입니다. 크기는 정규화된 직렬화 기준이라 디스크 바이트와 정확히 같지 않고, 저장된 결과는 이후 요청에서 다시 전송되므로 이 값은 노출량의 하한입니다. provider의 토큰 집계는 요청 단위여서 도구별 귀속이 불가능하므로 이 절은 바이트 기준이며, 그 경계를 출력 자체에 명시합니다.
- `--feasibility-json` / [`mac_visibility`](mac-visibility-feasibility-schema.md): 로컬 macOS 가시화 surface가 바인딩할 수 있는 계약입니다. 안정적인 top-level field만 가리키며, `summary`는 primary UI binding 대상이 아닙니다.

가드레일도 실행 비용이 있고 모든 프로젝트에서 이득이 되지는 않으므로, 켜기 전에 먼저 측정하세요. 여기 나오는 바이트 비중은 관측값이지 절감량이 아닙니다. 바이트가 어디로 갔는지를 말할 뿐, 그것을 줄였을 때 무엇을 회수하는지는 말하지 않습니다. 읽은 파일 경로는 절대 출력하지 않고 확장자만 집계합니다.

이 필드들은 prompt prefix 근처의 volatile content 가능성, stable-prefix 후보, cache-miss 가설, TTL/headroom evidence gap을 알려줄 수 있습니다. 원문 프롬프트를 출력하지 않고 provider cache hit나 live headroom을 증명하지 않으며, 대화 기록 스키마가 충분한 증거를 드러내지 않으면 `missing`, `partial`, `hypothesis`, `unavailable`일 수 있습니다.

#### 상태표시줄에서 컨텍스트와 캐시 상태 확인

```text
[Sonnet] repo | main | ctx 86% ⚠ | cost $0.123 | cache 80% | reuse 8.0x
```

`cache N%`는 최근 일정 범위의 대화 기록에서 관찰된 입력 토큰 중 cache read가 차지하는 비율이며, cache read가 1회 이상 있을 때만 표시됩니다. `reuse X.Yx`는 `cache_read / cache_creation` 값이며, cache read가 양수이고 cache creation이 0이 아닐 때만 표시됩니다. `⚠` 표시는 컨텍스트 사용률이 경고 기준에 도달했을 때 나타나며 기본값은 80%입니다. 자동 훅은 격리된 환경에서 실행되므로 `CONTEXT_GUARD_STATUSLINE_CTX_WARN=90`을 설정한 뒤 setup을 다시 실행해 이 안전한 동작 설정을 설치 명령에 고정하세요. Python·shell loader 변수는 전달하지 않습니다.

#### 반복 가능한 벤치마크 실행

```bash
./plugins/context-guard/bin/context-guard-bench \
  --tasks bench/tasks.json --variants bench/variants.json --csv bench/results.csv \
  --ledger-jsonl bench/cost-shift.jsonl --report-json bench/report.json
```

각 task fixture의 선택 필드 `output_format`은 기본값이 `json`이며 `json|stream-json`만
허용합니다. `stream-json` 모드는 runner가 관리하는 `--verbose`를 추가하고 bounded NDJSON의
마지막 event가 유효한 terminal result일 때만 성공으로 처리합니다. 이 경로의 client cost도
provider billing을 authoritative하게 증명하지 않는 진단값입니다.

보고서를 읽을 때는 먼저 주장 범위를 확인하세요.

- 성공한 기준/변형 실행은 실제 토큰과 `cost_usd + external_cost_usd` 기준으로 비교하고, 바이트 감소는 간접 증거로만 기록합니다.
- 토큰 절감 주장은 대응 태스크 양쪽 모두에 `primary_tokens_measured`가 있을 때만 계산합니다.
- `matched_pair_evidence`는 성공한 task bucket을 transform, 측정 가능 여부, quality gate, 주장 범위와 연결하므로 절감 문구를 쓰기 전에 먼저 확인해야 합니다.
- `default_matrix`는 같은 대응 evidence를 기반으로 trimming, artifact escrow, tool pruning, cache advice, adaptive-k, optional compression을 `default-on`, `advisory`, `experimental`, `reject/rework`로 분류합니다. 이 matrix는 report 전용이며 runtime default를 바꾸거나 hosted token/cost 절감 주장을 허용하지 않습니다.
- `public_claim_readiness`는 release/public claim의 최종 gate입니다. matched successful task, provider-measured primary token/cost, quality non-inferiority, shifted-cost accounting, 명시적 confidence/failure note, complete provider-export provenance가 모두 통과해야 `claim_allowed=true`가 되며, 그렇지 않은 hosted savings claim은 금지됩니다.
- `wall_time_seconds`, `provider_cached_tokens`, `provider_cached_tokens_measured`는 진단용 텔레메트리이며, ContextGuard가 직접 만든 토큰·비용 절감 증거로 보지 않습니다.
- 선택적 `self_hosted_metrics`는 run별 JSONL ledger sidecar로만 기록하고 CSV/report 요약에는 넣지 않으며, hosted API token/cost 절감 주장의 근거로 포함해서는 안 됩니다. `context-guard experiments plan self-hosted-metrics-ledger`는 이런 sidecar의 dry-run preview만 만들고 ledger 파일을 쓰지 않습니다.
- 비용 필드가 0이거나 없으면 토큰 절감만 표시하고 실제 비용 절감은 주장하지 않습니다.
- CSV 스키마는 엄격하게 검사합니다. 벤치마크 헬퍼를 업그레이드한 뒤에는 새 `--csv` 파일을 시작하거나 mismatch 오류가 알려주는 헤더로 마이그레이션하세요.

최소 보고서 형태 예시는 [`docs/benchmark-report.example.json`](benchmark-report.example.json)을, 작업 유형별 합성 예시와 안전한 해석 경계는 [`docs/benchmark-workflow-examples.md`](benchmark-workflow-examples.md)을, fixture-only 실험 시작 예시는 [`docs/experimental-benchmark-fixtures.md`](experimental-benchmark-fixtures.md)을 참고하세요. live provider 실행 전 deterministic local replay가 필요하면 `--evidence-jsonl docs/benchmark-fixtures/token-savings-12task.evidence.example.jsonl --dashboard-md ... --baseline-variant baseline_full_context_fixture`를 사용하세요. Replay mode는 provider와 `success_command`를 실행하지 않고 CSV/report/dashboard를 만들지만 synthetic/manual evidence는 public hosted-savings claim 불가로 표시합니다.

### 저장소 구조

- `.claude-plugin/marketplace.json` — Claude Code 마켓플레이스 매니페스트입니다.
- `plugins/context-guard/` — 설치형 Claude Code 플러그인 패키지입니다.
- `context-guard-kit/` — 체크아웃 로컬 Python/Bash 헬퍼 소스입니다. npm 패키지는 이 소스 트리를 중복 포장하지 않고 동기화된 `plugins/context-guard/bin` 및 `plugins/context-guard/lib` 복사본을 배포합니다.
- `docs/index.html` — 프로젝트용 정적 랜딩 페이지입니다.
- `tests/` — 헬퍼 동작을 검증하는 회귀 테스트입니다.

### 로컬 개발

플러그인 디렉터리를 지정해 Claude Code를 실행합니다.

```bash
claude --plugin-dir ./plugins/context-guard
```

저장소 루트에서 마켓플레이스 설치를 테스트합니다.

```text
/plugin marketplace add ./
/plugin install context-guard@context-guard
```

플러그인 헬퍼 바이너리는 기본적으로 셸 `PATH`에 포함되지 않습니다. 로컬 테스트 시에는 전체 경로로 실행하세요.

```bash
./plugins/context-guard/bin/context-guard-setup --plan
./plugins/context-guard/bin/context-guard-setup --agent codex --brief-mode standard --plan
./plugins/context-guard/bin/context-guard-setup --yes
```

개발 중 짧은 명령으로 실행하려면 플러그인 bin 경로를 현재 셸에 추가하세요.

```bash
export PATH="$PWD/plugins/context-guard/bin:$PATH"
context-guard-setup --plan
```

### 로컬 MCP 어댑터

`context-guard mcp`(또는 `context-guard-mcp`)는 의존성 없는 로컬 stdio MCP 서버입니다. 프로세스 하나는 root와 namespace 하나에 고정되며 compression, sanitization된 artifact 조회, 로컬 통계만 제공합니다. HTTP, SSE, 네트워크, provider, model, proxy, 자동 client 설정 기능은 없습니다. 저장되는 fallback은 원문이 아닌 정확한 sanitization 완료 사본이고 다른 namespace의 artifact는 조회할 수 없습니다. 이 로컬 어댑터는 hosted token/cost 절감을 주장하지 않습니다.

반복 파일·로그 컨텍스트를 명시적으로 다루려면 함께 설치되는 Receipt
companion을 `context-guard-receipt-mcp --root /absolute/repository`로 실행할
수 있습니다. `receipt_context` 도구는 사용자가 `eligible`이라고 명시한
상대 경로만 읽고, byte-benefit router가 유리하다고 판단하면 compact exact
reference를 반환하며, 반복 조회에는 같은 live reference를 재사용하고 한 번에
최대 65,536바이트의 exact slice만 가져옵니다. 이 기능은 opt-in이며
process-local입니다. 선택적 task scope는 task 간 재사용을 막고, 명시적 release는
context GC를 수행하며, content-free history에는 process-keyed HMAC과 결정만
남습니다. `receipt_diagnose`는 파일 byte를 반환하지 않고 비적용 shadow
firewall/router와 prefix 재사용 기반 scout/surgeon 안내를 제공합니다.
`receipt_pack`은 같은 필수 task scope에 먼저 묶인 `receipt_context` capability만
사용해 caller 순서의 bounded multi-file pack과 exact deferred expansion을 만들며,
task-scoped `receipt_tool_select` profile은
하나의 안정적인 catalog bundle을 재사용하고 drift를 새 prefix로 재생성하지 않고
거부합니다. 명시적
private `--state-dir`로 같은 binary를 시작하면 action을 실행하지 않는
authenticated `receipt_twin` 근거 기록만 추가됩니다. 스스로 등록되거나 전체
prompt를 가로채지 않고, capability가 재시작을 넘어 유지되지 않으며, provider를
호출하거나 hosted 절감 효과를 주장하지 않습니다.

### 릴리스 확인

릴리스에 민감한 변경을 배포하거나 머지하기 전에는 동기화 확인과 두 게이트를 모두 실행하세요.

```bash
python3 scripts/sync_plugin_copies.py --check
python3 scripts/prepublish_check.py
python3 scripts/release_smoke.py
```

헬퍼가 `context-guard-kit/` 아래에서 바뀌었다면 게이트 전에 `python3 scripts/sync_plugin_copies.py --write`를 실행하세요. `sync_plugin_copies.py --check`는 maintainer exact-copy 계약을 먼저 확인합니다. npm 패키지는 구현 payload 중복을 피하기 위해 동기화된 플러그인 로컬 `plugins/context-guard/bin` 엔트리포인트와 `plugins/context-guard/lib` 헬퍼만 배포하며, npm bin map은 legacy `claude-*` 래퍼 별칭을 의도적으로 제외합니다. 명령 매니페스트는 release/runtime 확인에서 literal assignment로만 읽고, 실행 가능한 Python·import·function·shadow manifest는 거부합니다. `prepublish_check.py`는 패키지 불변식, 동기화된 플러그인 바이너리, 매니페스트, 진단 메시지 가림 처리, 회귀 테스트를 확인합니다. `release_smoke.py`는 임시 프로젝트에서 `plugins/context-guard/bin`의 대표 패키징 엔트리포인트를 실제로 실행해, 배포 전 깨진 CLI 연결을 잡습니다. 전체 릴리스 절차, 증거 체크리스트, quad-review 요구사항, 롤백 체크리스트는 [docs/release-runbook.md](release-runbook.md)를 참고하세요.

버전별 릴리스 노트는 [CHANGELOG.md](../CHANGELOG.md)에 기록하며, 사전 배포 게이트는 플러그인 매니페스트 버전과 일치하는 항목이 있는지 확인합니다.
