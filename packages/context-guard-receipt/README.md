# Context Guard Receipt

`@ictechgy/context-guard-receipt` is a small, provider-free receipt companion
whose work is confined to explicitly supplied local inputs and state.

It exposes one implemented command:

```text
context-guard-receipt inspect boundary
```

The result describes a fixed evidence boundary. It is neither Stage 1 nor Stage 2
evidence and cannot close the provider join. It does not observe a host, read
settings, contact a provider, execute requested commands, create receipts, or
establish provider or host authority. It does not report provider token, cost,
cache, or percentage-savings claims. The listed future workflow verbs are
intentionally unavailable.

The package has no dependencies, lifecycle scripts, network behavior, or
configuration files. It requires Node.js 18+ and a trusted CPython executable
from 3.11 through 3.14. Set `CONTEXT_GUARD_RECEIPT_PYTHON` to an absolute path
to the actual native CPython executable, or ensure an absolute `PATH` directory
contains `python3`. Relative `PATH` entries and script-based interpreter shims
are rejected. The selected executable remains part of the caller's trust
boundary; the compatibility probe is not interpreter authentication.

The package manager and installed launcher are the distribution authenticity
boundary. `package-files.json`, the launcher's embedded payload digests, and
the closed runtime tree provide a consistency and corruption check; they do
not replace registry signatures, lockfile integrity, or a trusted install.

Use `context-guard-receipt --help` for the human-readable command summary.
`context-guard-receipt-mcp --help` documents the unavailable MCP entry point.
