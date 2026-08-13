# P2 Claude live shadow contract

This directory freezes a one-use live measurement scope for the exact G5
240-unit schedule. It uses Claude Code `2.1.229` with the exact primary model
`claude-sonnet-5`, safe mode, no tools, no session persistence, a per-process
USD 0.35 ceiling, and a USD 100 aggregate approval ceiling. The runner sends
only the frozen sanitized G2 task prompt and the authenticated G3 rendered pack.

The authoritative boundary is the runner-owned `claude -p --output-format json`
process interface. This is a narrow, controlled evaluation surface. It is not a
general Claude Code host request-assembly observer and grants no production
interception or mutation authority. Claude Code may report internal helper-model
usage in addition to the selected primary model; every reported model and the
complete client cost estimate are retained only in owner-private evidence.

All 240 provider processes and response identities are sealed before scorer-only
G2 bytes are opened. Public evidence contains hashes, counts, frozen G5
observations, descriptive summaries, and closed P2 gate results only. Prompts,
responses, sessions, credentials, headers, environment values, and private
paths are never published. Claude Code owns credential access; this repository
does not read or store credential values.

`live_runner.py` refuses direct mutable execution. An operator must construct an
exact `contextguard.external-approval/v1` envelope, provide independent signing
and registry keys in memory, and invoke `run_live_authorized`. The approval is
consumed before the first provider process. A crash consumes the approval and
requires a new explicit approval for any resume; the fixed schedule never uses
optional stopping or replacement observations.

The exact trusted Claude Code executable is the network materializer. The
approval binds the intended Anthropic HTTPS destination and disables configured
proxies and redirects, but this Python wrapper is not an OS network sandbox and
cannot independently attest every connection made inside that pinned binary.

The resulting evidence remains descriptive. CLI `total_cost_usd` is retained as
a non-authoritative client estimate and never fills G5 authoritative billing
receipt fields. Consequently this P2 run cannot by itself satisfy P3's fully
loaded authoritative provider-cost gate.
