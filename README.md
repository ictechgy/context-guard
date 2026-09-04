# ContextGuard

ContextGuard is a local-first context-management toolkit for AI coding and tool-using agents. It starts with a Claude Code plugin: install it once, enable it explicitly per project, and roll it back when needed. It trims noisy output, guides agents toward symbol-level reads, flags repeated failures, redacts secret-like patterns, and measures usage — and the same guardrails are reusable by other agents through local helper commands and advisory brief-mode snippets.

- Korean documentation: [`README.ko.md`](README.ko.md)
- Static landing page: [GitHub Pages](https://ictechgy.github.io/context-guard/) ([source](docs/index.html))

## Quickstart

```bash
/plugin marketplace add ictechgy/context-guard && /plugin install context-guard@context-guard   # Claude Code
/context-guard:setup          # applies the recommended project-local hooks after showing a plan
/context-guard:audit          # shows where your tokens went, by tool and per turn
```

npm users run `npx @ictechgy/context-guard setup --profile recommended --plan` then `--yes`.

## Three problems it solves

**A build or test dumps thousands of lines into the transcript.** The default Bash
wrapper escrows the sanitized output to a local artifact and leaves a compact
receipt in context. Pull back only the slice you need:

```bash
context-guard-artifact get <id> --lines a:b
```

**You do not know where your tokens went.** The audit reads local Claude
transcripts and reports new tokens per turn together with the tool that preceded
each turn, plus where result bytes came from by tool, content class, and file
extension:

```bash
context-guard-audit ~/.claude/projects --recommend
```

That is an observation, not a savings claim. It says where the bytes and the new
tokens landed; it does not say what you would recover by trimming them.

**An agent reads a whole large file for one function.** The optional Read guard
pushes search → symbol slice → small line range, and the symbol reader returns
the slice directly:

```bash
context-guard-read-symbol path/to/file.py TargetSymbol
```

Its enforcement surface is deliberately limited to the installed Claude Code
`PreToolUse` hook whose matcher is `Read`:

| Claude tool | Covered behavior |
| --- | --- |
| `Read` | The hook checks bounded large-file ranges and denies a basename beginning with `.env`, except the exact template names `.env.example`, `.env.sample`, and `.env.template`. Nested paths are included; ambiguous symlink paths fail closed. |
| `Glob` | May list matching names. It does not read file contents through this `Read` hook. |
| `Grep` | Out of scope for this hook and may read matching file contents. |
| `Bash` | Out of scope for this hook and may read file contents. |

This is Claude `Read` protection, not universal `.env` or Bash protection. The hook proves the file state it opens without following symlinks and revalidates that same descriptor, but Claude performs the actual `Read` with a later open after the hook returns. A replacement in that post-hook window is a documented TOCTOU limitation.

## Install

Installation and activation are deliberately separate. Installing ContextGuard only makes local helpers or Claude plugin skills available; it does not write configuration until you run an explicit setup command.

| If you use... | Install | Activate |
| --- | --- | --- |
| Claude Code | `/plugin marketplace add ictechgy/context-guard` then `/plugin install context-guard@context-guard` | Run `/context-guard:setup` inside the project. |
| npm, npx, or any terminal-first agent | `npm install -g @ictechgy/context-guard` or one-shot `npx @ictechgy/context-guard ...` | `context-guard setup --agent codex --scope project --with-init --with-skill --with-mcp --plan`, then rerun with `--yes`. |

`context-guard setup --profile recommended --plan` previews the recommended
profile and `--yes` applies it. Before applying setup, run `context-guard setup
--verify` for a read-only health check; `context-guard doctor` is an alias of it.
Homebrew, user-scope rules, and the cross-agent adapter matrix are in
[docs/guide.md](docs/guide.md), and the generated flag reference is in
[docs/setup-reference.md](docs/setup-reference.md).

## Run audit first

Run the audit before you enable anything. Guardrails cost something to run and
not every one pays off on every project, so measure your own workload first:

```bash
context-guard-audit ~/.claude/projects --top 20 --recommend
```

After setup, `context-guard doctor --root . --json` re-checks the installed hook
journal and configuration without changing them. The byte figures the audit
reports are observations, not savings.

## Where the rest lives

- [docs/guide.md](docs/guide.md) — every helper command, brief mode, quiet narration, the cross-agent adapters, the benchmark runner, the local MCP adapter, opt-in `bash_reference_v1`, and the Receipt companion. Pack options such as `--explain`, `--adaptive-k-policy`, `--apply-adaptive-k`, and `--apply-symbol-memory` are documented there.
- [docs/safety-reference.md](docs/safety-reference.md) — trust boundaries, the `PATH` helper policy, what ContextGuard does not do, the standing-cost and break-even table for advisory rule blocks, the Read-guard TOCTOU limit, and the wording rules for savings claims.
- [docs/builtin-overlap.md](docs/builtin-overlap.md) — feature-by-feature comparison with what Claude Code already does built in (overlap, complement, or not built in).
- [docs/experiments.md](docs/experiments.md) — default-off experimental lanes and their gates.
- [docs/setup-reference.md](docs/setup-reference.md) — generated setup capability and flag reference.
- [docs/release-runbook.md](docs/release-runbook.md) — release workflow, evidence checklist, and rollback checklist.
- [`docs/experimental-benchmark-fixtures.md`](docs/experimental-benchmark-fixtures.md) — fixture-only experimental task/variant starters; they clear the same matched-task benchmark gates before any savings claim.

## Experimental features

All experimental planners are off by default, plan-only, and documented in [`docs/experiments.md`](docs/experiments.md); their later-roadmap gates keep those lanes experimental/non-shipped until matched successful, provider-measured tasks and a separate future PR satisfy them. The wider research lanes are tracked in [`research/experimental-token-reduction-radar.md`](research/experimental-token-reduction-radar.md). ContextGuard does not guarantee a fixed token or cost reduction; the claim boundaries are in [docs/safety-reference.md](docs/safety-reference.md).

## License

Copyright 2026 jinhongan. Licensed under the Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
