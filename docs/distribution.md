# ContextGuard distribution plan

ContextGuard separates **install** from **activation**.

- Install exposes local commands or Claude Code plugin skills.
- Activation is explicit and scoped through `context-guard setup` or `/context-guard:setup`.
- Package installation must not write project or user configuration.

## Supported install paths

| Path | Status | Command | Notes |
| --- | --- | --- | --- |
| Claude Code plugin | shipped | `/plugin marketplace add ictechgy/context-guard` then `/plugin install context-guard@context-guard` | Best native Claude Code workflow. |
| npm global | added | `npm install -g @ictechgy/context-guard` | Installs `context-guard` and helper aliases on PATH. |
| npx/npm exec | added | `npx @ictechgy/context-guard --version` | One-off usage; activation still requires explicit setup. |
| Homebrew | draft | `brew tap ictechgy/contextguard && brew install context-guard` | Formula template exists under `packaging/homebrew/`; publish after release artifact SHA is known. |

## Activation examples

```bash
context-guard setup --agent codex --scope project --with-init --with-skill --plan
context-guard setup --agent codex --scope project --with-init --with-skill --yes
context-guard setup --agent claude --scope user --plan
```

Project scope is the default. User scope is opt-in and requires an explicit agent for writes. Supported user-scope writes record backups and rollback metadata under `.context-guard/rollback` in the user home directory.

## Runtime requirements

The helpers are Python/shell scripts packaged through npm and Homebrew. Supported machines need:

- macOS or Linux
- Python 3 available as `python3`
- POSIX no-follow file operations for setup writes
- Node/npm only for npm/npx install paths

## Non-goals for this release

- No install-time `postinstall` configuration writes.
- No sudo/root/system configuration writes.
- No claim of native activation for agents whose current safe user-level path has not been verified.
- No fixed token or cost savings claim from packaging alone.

## Homebrew formula release checks

Before publishing the Homebrew tap, run the formula-specific checks locally or in CI when Homebrew is available:

```bash
brew style packaging/homebrew/context-guard.rb
brew audit --strict --new packaging/homebrew/context-guard.rb
brew install --build-from-source packaging/homebrew/context-guard.rb
brew test context-guard
```

The formula should rewrite Python shebangs to the declared Homebrew Python dependency and expose both `context-guard` and legacy compatibility wrappers from `plugins/context-guard/bin`.
