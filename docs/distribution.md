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
| Homebrew | shipped | `brew install ictechgy/tap/context-guard` | Formula is published in `ictechgy/homebrew-tap`; update it from a tagged release tarball SHA. |

## Activation examples

```bash
context-guard doctor --root . --json
context-guard setup --agent codex --scope project --with-init --with-skill --plan
context-guard setup --agent codex --scope project --with-init --with-skill --yes
context-guard setup --agent claude --scope user --verify --json
context-guard setup --agent claude --scope user --plan
```

Project scope is the default. `context-guard doctor` and `context-guard setup --verify` are read-only health checks. User scope is opt-in and requires an explicit agent for writes. Supported user-scope writes record backups and rollback metadata under `.context-guard/rollback` in the user home directory. Setup resolves packaged/check-out helpers first; `PATH` helper fallback is default-off and requires `--allow-path-helper-fallback` for a trusted install after canonical executable and identity validation.

## Runtime requirements

The helpers are Python/shell scripts packaged through npm and Homebrew as plugin-local `plugins/context-guard/bin` entrypoints plus `plugins/context-guard/lib` helpers; checkout-only `context-guard-kit` sources are not duplicated in the npm tarball. Supported machines need:

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

Render or copy `packaging/homebrew/context-guard.rb.template` into a real tap formula first; replace `{{VERSION}}` with the bare semver version (for example `0.4.9`, not `v0.4.9`) and `REPLACE_WITH_RELEASE_TARBALL_SHA256` with the verified tarball SHA. Do not run Homebrew audit/install directly against the placeholder template.

```bash
# Example once Formula/context-guard.rb has been rendered in the tap checkout:
brew style Formula/context-guard.rb
brew audit --strict --new ictechgy/tap/context-guard
brew install --build-from-source ictechgy/tap/context-guard
brew test ictechgy/tap/context-guard
```

The rendered formula should rewrite Python shebangs to the declared Homebrew Python dependency and expose both `context-guard` and legacy compatibility wrappers from `plugins/context-guard/bin`.
