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
claude-token-audit ~/.claude/projects --top 20
claude-trim-output --max-lines 120 -- npm test
claude-token-statusline
claude-token-rewrite-bash
claude-token-delegate status
claude-token-delegate enable --provider gemini
claude-token-delegate ask --provider gemini --prompt "Summarize this log" --context ./log.txt
claude-token-delegate disable
```

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

Only delegate context you are allowed to share with that external provider. The helper prints a bounded preview to Claude and saves the full auxiliary response locally.


Delegation blocks obvious secret-like context paths by default and creates a private `.gitignore` under `.claude-token-optimizer/` for saved responses. Use `--allow-sensitive-context` only when your policy allows sending that file to the selected provider.
