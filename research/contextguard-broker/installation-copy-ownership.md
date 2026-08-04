# ContextGuard Broker installation and copy ownership

## Stage 1/P0 ownership boundary

Stage 1 documents future ownership only. It does not change runtime hooks,
default settings, setup, packages, plugin copies, CSV columns, or R9. Until a
separate product decision, Read observers are canary-only and ordinary installs
remain unchanged. A `transport_rejected` record blocks Stages 3–5, but it does
not prevent the Stage 2 canary-only pass-through attribution work. R9 remains
immutable, inconclusive, and unavailable for efficacy promotion.

## Canonical ownership map

| Surface | Canonical owner | Required later responsibility |
| --- | --- | --- |
| Hook/settings composition, setup/update/uninstall, idempotency, equivalent-helper and duplicate-hook detection | `context-guard-kit/setup_wizard.py` | Keep canary settings distinct from normal installation; test merge, update, uninstall, and duplicate prevention together. |
| Command/helper/package/dispatcher manifest | `context-guard-kit/context_guard_commands.py` | Add a helper to `IMPLEMENTATION_PAIRS`, `HELPER_PAIRS`, bin mappings, dispatcher paths, and smoke manifest only when a packaged executable is actually needed. |
| Kit-to-plugin copies | plugin `bin/` and `lib/` copies, generated from `scripts/sync_plugin_copies.py` | Synchronize canonical kit code before publishing and reject unequal copies. |
| Package integrity | `scripts/prepublish_check.py` | Verify implementation pairs, helper pairs, command paths, package bins, and generated plugin artifacts. |
| Release behavior | `scripts/release_smoke.py` | Exercise operational command entry points and packaged-command integrity after the preceding checks. |
| Stage 2–5 receipts and study accounting | `context-guard-kit/benchmark_runner.py` | Extend the existing attempt authority; never introduce a competing ledger or alter `CSV_COLUMNS`. |

## Promotion discipline

A canary fixture is not a default. Packaging an executable, synchronizing a
plugin copy, or passing prepublish is insufficient to promote an observer or
transport behavior. Promotion requires a later explicit product decision after
the applicable Stage 2 attribution, Stage 3 transport qualification, Stage 4
shadow-selection, and Stage 5 active-canary gates. The owning change must carry
its setup/update/uninstall, duplicate-hook, package-copy, prepublish, and
release-smoke tests in the same reviewable change. No default installation is
modified merely because a helper can be installed or copied.
