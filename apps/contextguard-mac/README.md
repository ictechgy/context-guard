# ContextGuard Mac Prototype

Developer-only macOS status-item prototype for dogfooding ContextGuard visibility.

## Scope

- Runs as a Swift Package executable from `apps/contextguard-mac/`.
- Uses an AppKit `NSStatusItem` menu-bar shell with SwiftUI hosted views.
- Reads local Claude Code transcripts by invoking `context-guard-audit --feasibility-json --recommend`.
- Binds primary UI to stable top-level feasibility fields only; diagnostic `summary` is not a primary UI data source.
- Does not change the released plugin package under `plugins/context-guard/`.

## Run

```bash
cd apps/contextguard-mac
swift run ContextGuardMac
```

The prototype does not resolve `context-guard-audit` from arbitrary `PATH`. When launched from this repository it uses the repo-local helper at `../../plugins/context-guard/bin/context-guard-audit` as a trusted executable fallback and rejects fallback paths that traverse symlinks.

## Test

```bash
cd apps/contextguard-mac
swift test
```

After changes, also run the repository release gates from the project root:

```bash
python3 scripts/prepublish_check.py
python3 scripts/release_smoke.py
git diff --check
```

## Product language rules

- Treat token/cache/cost values as local transcript observations, not official billing records.
- Use “cache-read share” and “reuse ratio”; do not call this a billing hit rate.
- Hide or soften unavailable metrics according to `metric_availability` and `context_availability`.
