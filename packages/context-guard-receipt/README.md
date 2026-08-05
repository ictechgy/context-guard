# Context Guard Receipt

`@ictechgy/context-guard-receipt` is a small, provider-free receipt companion
whose work is confined to explicitly supplied local inputs and state.

It exposes the fixed boundary inspection, local evidence, blueprint, and
tool-schema assembly, explicit local command capture, and advisory local
diagnostics:

```text
context-guard-receipt inspect boundary
context-guard-receipt assemble --kind evidence|blueprint|tool-schemas --descriptor <file|-> --root <absolute>
context-guard-receipt run --escrow --root <absolute> --state-dir <absolute> [--timeout-seconds <positive-decimal> --max-channel-bytes <positive-decimal> --max-total-bytes <positive-decimal>] -- <absolute-command> [args...]
context-guard-receipt inspect diagnostics --input <file|->
context-guard-receipt inspect diagnostics --input <file|-> --state-scope durable --root <absolute> --state-dir <absolute>
context-guard-receipt inspect firewall --input <file|->
context-guard-receipt inspect diagnostic-ledger --state-scope durable --root <absolute> --state-dir <absolute> [--limit <1..256>]
```

The result describes a fixed evidence boundary. It is neither Stage 1 nor Stage 2
evidence and cannot close the provider join. It does not observe a host, read
settings, contact a provider, or establish provider or host authority. It does
not report provider token, cost, cache, or percentage-savings claims. Assembly
is a byte proxy for explicitly provided local bytes, not a token or
provider-usage claim. `run --escrow` is provider-free local capture only;
diagnostics and firewall results are advisory and non-applying. The remaining
reserved `inspect` targets and the MCP transport stay intentionally
unavailable.

Process-scope diagnostics use a new random fingerprint key for every invocation
and create no state. They report bounded byte accounting, a position-bound
rolling prefix comparison, the existing byte-benefit route projection, and a
shadow firewall finding with `applied: false`. They do not output supplied raw
fragments or acquire provider routing, live-observation, or efficacy-claim
authority. Exact byte counts in a report can still correlate similar inputs;
process-local HMAC unlinkability does not hide those counts.

Durable diagnostics require the complete explicit opt-in tuple
`--state-scope durable --root ... --state-dir ...`. After validating the input,
they append the same content-free fields to an independently keyed,
authenticated `auxiliary-v1/diagnostics-v1` ledger. The ledger is append-only,
keeps at most 1,024 entries, limits each canonical entry to 4,096 bytes and the
whole ledger to 4 MiB, and never evicts history. It is separate from
`store-v1`; removing the entire auxiliary compartment does not invalidate
capability-store artifacts. A stdout failure after append returns exit `74` and
cannot roll back the committed advisory row.

If an unsupported top-level entry appears after the durable-state preflight but
before a newly created lock can validate the directory, opening returns
`commit_uncertain` and preserves every name, including the lock residue. Portable
POSIX APIs cannot conditionally unlink a pathname by inode, so recovery never
risks deleting a concurrent same-UID replacement.

`run --escrow` executes only the explicitly supplied absolute executable and
argument vector. It does not invoke a shell. The child runs with the requested
absolute `--root` as its working directory, standard input closed, and the
fixed environment `LANG=C`, `LC_ALL=C`, and `PATH=/usr/bin:/bin`; caller
environment variables are not forwarded. The command can still create local
or external side effects, start descendants, or use networking on its own.
The receipt makes no external-side-effect completeness claim and no
host-request, host-runtime, provider, network-activity, or token-saving claim.
The supervisor uses bounded local process-table observations to track ordinary
descendants that change POSIX sessions or process groups, and it withholds a
receipt when that observation is unavailable or uncertain. This is not an OS
containment boundary: a deliberately daemonizing process can fork, detach,
close inherited descriptors, and reparent entirely between observations. Such
an unobserved process can survive success, timeout, cancellation, or refusal.
Use `run --escrow` for capture, not as a security sandbox; fail-closed here means
that uncertain authority is not published, not that all side effects or
processes were rolled back.

Cleanup signals are sent only through exact per-process kernel identities.
There is no numeric PID or process-group signaling fallback. The runner probes
the exact-signaling facility for itself and again for the gated trampoline
before releasing the requested executable. A facility that later becomes
unavailable still cannot be replaced with broader signaling; receipt authority
is withheld, while the non-containment limitation above continues to apply.

The CLI defaults to a 30-second timeout and 900,000 raw and sanitized bytes in
total. Optional timeout values are positive decimal seconds up to 300. Optional
per-channel and total byte limits are positive decimals up to 900,000, with the
per-channel limit no greater than the total. Timeout, capture, snapshot,
sanitization, framing, and pre-publication storage failures emit no receipt or
handle on stdout. They collapse to the nonreflective stderr reason
`command_capture_failed`, with exit `124` for a timeout, `74` for persistence or
delivery uncertainty, and `70` for other closed failures. Command side effects
are not rolled back. A child exit or signal is durably receipted and the CLI
then returns that exit status (or `128 + signal`).

After the sanitized canonical CGRF capture is durably committed, the receipt is
emitted on stdout only; `run` has no receipt sidecar or `--receipt-out` option.
The receipt omits command arguments and paths. Its observation contains only
before and after worktree hashes and `scope: worktree`; those hashes are not a
host observer, a filesystem diff, or proof about unobserved effects. If stdout
delivery fails after commit, exit `74` cannot revoke the durable capability;
its stdout publication may be partial or absent, so callers must not infer
rollback.

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

A command-capture handle is historical rather than `source_current`. While it
remains bound to the same repository instance, later worktree changes do not
stale it: exact local expansion returns the original sanitized canonical CGRF
bytes, including their stdout/stderr channel frames. This historical command
capture is not a replay, a raw-output log, or a claim about current worktree
contents.

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

The package has no dependencies, lifecycle scripts, network client, or
configuration files of its own. The explicitly launched child is outside that
no-network statement. The package requires Node.js 18+ and a trusted CPython
executable from 3.11 through 3.14. Set `CONTEXT_GUARD_RECEIPT_PYTHON` to an
absolute path to the actual native CPython executable, or ensure an absolute
`PATH` directory contains `python3`. Relative `PATH` entries and script-based
interpreter shims are rejected. The selected executable remains part of the
caller's trust boundary; the compatibility probe is not interpreter
authentication.

`run --escrow` also requires the root-owned `/bin/ps` process-table interface
and an exact local process-identity and signaling backend. macOS brackets each
`libproc` BSD-process record with two matching audit-token reads from one
retained task-name port, then signals only through that audit token. Linux uses
pidfds and probes `pidfd_send_signal` with signal zero. If those facilities are
missing, incompatible, or unusable, the runner refuses before releasing the
target command rather than silently weakening lifecycle observation.

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
