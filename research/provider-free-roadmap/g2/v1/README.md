# G2 structural ablation, version 1

This frozen provider-free study executes the shipped local `context-guard-pack
auto` implementation on six independent fixture trees. It records structural
selection only. Hidden scoring data stays in `scorer-only/`, is loaded only
after all 24 public arm outputs have been sealed, and is never copied into an
arm projection.

The four canonical arms are `ordinary`, `adaptive_only`, `symbol_only`, and
`combined`. Combined applies the shipped order `ordinary -> adaptive_k ->
symbol_memory`. Provider, retrieval, correction, latency, cost, bootstrap,
inference, and savings analysis are outside G2.

The three realistic-fallback fixtures are structurally different graphs, not
language translations of one template: a nested Python outgoing chain, a
TypeScript outgoing fork, and a JavaScript ESM incoming fan-in using static
re-exports. Their semantic profiles derive directed edges, connected
components, seed degrees, bidirectional seed distances, nesting depths,
specifier-resolution classes, required-neighbor direction, branching, and
re-export behavior. File extensions and authored structure labels do not
establish independence; cloned, rewired, or disconnected-padded topologies are
rejected from the parsed source graph.

The frozen JavaScript/TypeScript graph-fixture lexical subset permits static
ESM imports and re-exports but excludes every non-comment `/` operator,
including division and regular-expression literals. Slashes inside quoted
strings and raw template bodies remain data; template interpolation expressions
are code and enforce the same slash restriction. This intentionally narrow,
fail-closed subset avoids ambiguous JavaScript slash parsing; the frozen graph
fixtures require no slash operator or regular expression.

Direct execution of `verify.py` is deliberately unavailable. Use only the
independently pinned `g2-contract-tests` profile documented in the parent
provider-free roadmap README.

The bound profile captures the lock, verifier, public fixture, and packer
bytes before execution. The packer child is the exact lock-bound CPython 3.14
executable with `-I -B`, a `LANG`-only environment, and an audit hook installed
before application bytes. On the supported audited surface it rejects sockets
and DNS, process execution, late/native loading, environment mutation, writes,
and reads outside the captured workspace. All 24 public children terminate and
their scorer-consumed structural fields are sealed before any scorer-only byte
is opened.

This is a precise portable process boundary, not an OS security sandbox. It
does not claim protection from a hostile host or root, a hostile same-UID
process, a compromised interpreter or native runtime, or OS-wide isolation.
