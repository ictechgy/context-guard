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

`shipped` means the install path is publicly released and exercised by its
release checks. `added` means the public package exposes the path, while
activation remains an explicit follow-up. `report-only` in setup output means
ContextGuard found no verified write adapter for that scope and changed
nothing; it is not a partial installation.

## Activation examples

```bash
context-guard doctor --root . --json
context-guard setup --agent codex --scope project --with-init --with-skill --plan
context-guard setup --agent codex --scope project --with-init --with-skill --yes
context-guard setup --agent claude --scope user --verify --json
context-guard setup --agent claude --scope user --plan
```

Project scope is the default. `context-guard doctor` and `context-guard setup --verify` are read-only health checks. User scope is opt-in and requires an explicit agent for writes. Supported user-scope writes record backups and rollback metadata under `.context-guard/rollback` in the user home directory. Setup resolves packaged/check-out helpers first; `PATH` helper fallback is default-off and requires `--allow-path-helper-fallback` for a trusted install after canonical executable and identity validation.

## Exact npm pair for Bash references

`bash_reference_v1` is a narrower distribution than the ordinary CLI/plugin.
It accepts only an exact project-local npm topology: root
`@ictechgy/context-guard@0.12.4` declares
`@ictechgy/context-guard-receipt: 0.4.0`, and the installed Receipt inventory
must match the SHA-256 trust anchor embedded in the root policy. Hoisted and
nested npm dependency layouts are supported; global npm, `npx`, Homebrew,
source-checkout, arbitrary `PATH`, and marketplace-plugin layouts are refused.

```bash
npm install --save-exact @ictechgy/context-guard@0.12.4
./node_modules/.bin/context-guard setup --root . --agent claude --scope project --bash-reference-v1 --plan
./node_modules/.bin/context-guard setup --root . --agent claude --scope project --bash-reference-v1 --yes
```

Setup writes the opt-in flag only when the paired topology is present. Doctor
and source/plugin setup report it as unavailable otherwise and retain the
legacy Bash trim hook. Runtime discovery never launches Node by name from
`PATH`: it binds an absolute interpreter from fixed system locations, with a
GitHub Actions-only Node fallback restricted to fixed hosted-toolcache roots,
and rechecks the pinned Receipt files before starting one private broker. Before
Bash starts, every interpreter must be a regular, single-link executable owned
by root or the current user, executable, and not group- or world-writable. The
CI workflow validates the canonical hosted Python and Node locations, removes
group/world write permission from exactly those two ephemeral targets, and then
runs the same production preflight; `GITHUB_ACTIONS` never weakens this policy.
The broker has
already loaded its code and retained the repository, store, expiry, journal,
and anonymous owner-only capture descriptors. `COMMIT` therefore performs no
later package-path, interpreter, or Git lookup. Even a below-threshold command
can initialize the local state axes before the wrapper sends `ABORT`. A missing
strong sanitizer, changed package, invalid response, timeout, or unavailable
state yields legacy output, not a reference and not a changed child exit
status.

An issued digest contains the directly executable retrieval command below; it
must be run from the same physical project root:

```bash
./node_modules/.bin/context-guard reference <cgr1p-handle>
```

The root command never accepts or reveals `--root` or `--state-dir`. It derives
the deterministic sibling state internally and returns at most one exact
20,000-byte sanitized UTF-8 page. If more content remains, a compact diagnostic
provides the next continuation `--offset`. Expansion rechecks the exact package,
root/source binding, and active seven-day registry entry; any failure emits no
payload.

The handle is provider-visible bearer material with an exact seven-day expiry.
State is placed outside the repository in a private sibling named
`.context-guard-receipt-state-<root-selector-sha256>`; the selector binds the
normalized root path and device/inode identity. This keeps Receipt state
physically disjoint from the repository snapshot and separates sibling roots.
Disablement removes only the hook flag, and npm uninstall removes package code
but deliberately leaves state/artifacts intact for a later exact reinstall or
separately authorized cleanup. After uninstall, the verified package-local code
and `node_modules/.bin/context-guard` are absent, so retrieval is unavailable
until the exact project-local pair is reinstalled:

```bash
./node_modules/.bin/context-guard setup --root . --agent claude --scope project --no-bash-reference-v1 --yes --no-diet-scan
npm uninstall @ictechgy/context-guard
```

Artifact deletion is not automated; it requires a separate, explicit
user-authorized retention decision. `--bash-reference-v1` and
`--artifact-receipt` are mutually exclusive.

### Explicit Bash-reference state cleanup

Stop ContextGuard agents using the repository, then create a read-only plan
from the same physical root:

```bash
./node_modules/.bin/context-guard-receipt cleanup --bash-reference-v1 --root "$(pwd -P)" --plan
```

Review the target basename, entry counts, total bytes, and `plan_sha256`, then
apply that exact snapshot explicitly:

```bash
./node_modules/.bin/context-guard-receipt cleanup --bash-reference-v1 --root "$(pwd -P)" --yes --confirm-plan-sha256 <64-lowercase-hex>
```

Cleanup accepts no arbitrary state directory. It derives only the
`.context-guard-receipt-state-<64-lowercase-hex>` sibling bound to the root,
rejects links, non-private entries, hard-linked files, filesystem-boundary
crossings, drift, oversized trees, and mismatched plans, and never traverses
another target. A failure after
deletion begins can leave a private
`.context-guard-receipt-cleanup-<selector>-<nonce>` quarantine sibling for
manual inspection; it is never silently treated as success.

Provider-visible handles have the closed form
`^cgr1p_[A-Za-z0-9_-]{43}$` (49 ASCII bytes), are bearer material, remain bound
to the same physical root, and expire after seven days. `ABORT` can still
initialize state axes, so an apparently below-threshold command is not proof
that no retained state exists.

## Context-pack module identity

The ordinary context-pack implementation is split into six roles:
`entrypoint`, `git-boundary`, `receipts`, `rendering`, `scanning`, and
`selection`. Each canonical module and packaged plugin mirror has a
path-and-byte captured identity plus a role-and-output semantic identity. The
prepublish suite checks exact mirror bytes and runs the semantic oracle for both
entry points; a byte rewrite may retain semantic identity only when the oracle
output is unchanged.

## npm candidate and direct-latest publication gates

`.github/workflows/npm-candidate.yml` checks out one exact commit, runs both
package gates, packs each package exactly once offline, exercises the paired
tarballs in a clean install, and uploads immutable per-package artifacts. The
shared candidate manifest binds the commit, exact dependency, Receipt inventory
digest, policy digest, SHA-256, sha512 SRI, sizes, toolchain, and protocol. The
workflow refuses a requested commit that differs from its own workflow-source
commit so the later source and signer attestation digests bind the same revision.

`.github/workflows/npm-publish.yml` downloads an exact artifact by run and
artifact ID, revalidates the manifest and tarball, verifies GitHub build
provenance for both the candidate manifest and tarball against the candidate
source commit plus the exact trusted signer workflow revision, and publishes
only that tarball directly to `latest` with npm trusted publishing/OIDC. The two
package jobs share one concurrency group so their install-facing mutations
cannot overlap. Publish Receipt first; publishing the root requires both the
Receipt `latest` tag and its registry `dist.integrity` to equal the exact Receipt
record bound in the same candidate manifest. Each job then waits for bounded
registry readback of its own `latest` version and integrity. Publication remains
a manual, environment-protected operation and is not performed by CI
automatically.

There is no token-authenticated npm promotion workflow. If root publication
fails after Receipt succeeds, the old root remains installable because its
Receipt dependency is exact; fix the root failure and dispatch only the root
publication again. Do not try to republish Receipt or move tags with an
automation token.

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
