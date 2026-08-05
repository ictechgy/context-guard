# Context Guard Receipt

`@ictechgy/context-guard-receipt` is a small, provider-free receipt companion
whose work is confined to explicitly supplied local inputs and state.

It exposes the fixed boundary inspection plus local evidence, blueprint, and
tool-schema assembly:

```text
context-guard-receipt inspect boundary
context-guard-receipt assemble --kind evidence|blueprint|tool-schemas --descriptor <file|-> --root <absolute>
```

The result describes a fixed evidence boundary. It is neither Stage 1 nor Stage 2
evidence and cannot close the provider join. It does not observe a host, read
settings, contact a provider, execute requested commands, or establish provider
or host authority. It does not report provider token, cost,
cache, or percentage-savings claims. Assembly is a byte proxy for explicitly
provided local bytes, not a token or provider-usage claim. The `run`, `inspect`
targets other than `boundary`, and MCP transport remain intentionally
unavailable.

By default assembly is nonpersistent: it emits the exact original bytes on a
safe bypass, or emits no bytes for a closed refusal, without creating state.
Local opt-in persistence requires both `--persist` and an absolute
`--state-dir`; when the byte-benefit gates pass, it can issue a local `cgr1p_`
capability that can later be used with exact local expansion:

```text
context-guard-receipt expand cgr1p_<handle> --root <absolute> --state-dir <absolute>
```

Evidence and blueprint handle expansion is capability-only and bound to
`source_current`: it returns the original bytes only while the repository and
source identity are current. A changed source is stale and is refused without
emitting payload bytes. The caller retains the original descriptor payload as
the explicit baseline bypass; the companion does not claim that every emitted
artifact embeds that baseline.

Tool-schema descriptors carry one exact canonical catalog in
`anthropic_tools/v1` or `openai_functions/v1` format, one closed policy record
per item, and a `retain_count`. Required items and at least `retain_count` items
remain inline. Without persistence, or when deferral does not pass the byte
benefit gates, assembly returns the exact catalog unchanged. A secret or
explicit refusal emits no catalog bytes and creates no state. With opt-in
persistence, beneficial assembly emits a bundle containing exact inline items,
closed references for deferred items, and a reference to the entire sealed
catalog snapshot. Expansion accepts only a closed request:

```text
{"catalog_reference":<bundle catalog_reference>,"item_reference":null|<bundle deferred item>,"schema_version":"contextguard-receipt-tool-schema-expansion-request/v1"}
context-guard-receipt expand tool-schema --request <file|-> --root <absolute> --state-dir <absolute>
```

An `item_reference` of `null` returns the exact original catalog; a deferred
item reference returns that exact item slice. These capabilities use the
`catalog_snapshot` binding and make no live-source freshness claim. Mixed,
forged, stale-store, or malformed references are refused without payload
bytes. Tool-schema receipts separately report retained wire bytes, stored
envelope bytes, and upper bounds for shifted expansion bytes; this accounting
is not a token, provider-cost, cache, or end-to-end savings claim.

If a requested `--receipt-out` cannot be published after a successful assembly,
the complete artifact remains on stdout and the command exits `74`; callers
must consume that output before retrying. `--emit json` carries both the receipt
and emitted artifact in one stdout envelope.

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

The local capability store provides a runtime boundary against other OS
principals. Every physical ancestor of its state directory and of each
repository, worktree, Git, and common-Git exclusion must be a directory owned
by root or the effective UID; group- or world-writable ancestors must also have
the sticky bit. ACLs or platform-specific grants that give other principals
equivalent access are forbidden deployment configurations. Unsupported
filesystem primitives fail with `filesystem_unsupported`, and an ancestry
violation fails with `state_dir_forbidden`.

Processes with the same effective UID, UID 0/root, debug or tracing authority,
backup authority, filesystem-administration authority, or equivalent access
are trusted and out of scope: they can already read the integrity key or stored
bytes and rename directories. Inode and path revalidation is therefore a
best-effort diagnostic for accidental replacement and corruption, not a
same-UID isolation boundary or an atomic defense against trusted actors.

Use `context-guard-receipt --help` for the human-readable command summary.
`context-guard-receipt-mcp --help` documents the unavailable MCP entry point.
