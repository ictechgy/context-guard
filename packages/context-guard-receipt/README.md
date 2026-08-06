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
context-guard-receipt inspect twin --experimental-twin --input <file|-> --root <absolute> --state-dir <absolute>
context-guard-receipt inspect twin --experimental-twin --root <absolute> --state-dir <absolute> [--limit <1..256>]
context-guard-receipt inspect reference-expiry --experimental-reference-expiry --input <file|-> --root <absolute> --state-dir <absolute>
context-guard-receipt inspect reference-expiry --experimental-reference-expiry --root <absolute> --state-dir <absolute> [--limit <1..256>]
```

Package and entry-point discovery are explicit and local. For a separate local
install, pack this directory and install that resulting tarball in the target
project, then invoke the two installed binaries directly:

```text
npm pack --ignore-scripts
npm install --ignore-scripts ./ictechgy-context-guard-receipt-0.1.0.tgz
./node_modules/.bin/context-guard-receipt --help
./node_modules/.bin/context-guard-receipt-mcp --help
./node_modules/.bin/context-guard-receipt-mcp --root /absolute/repository-root
```

The ordinary CLI and the stdio MCP binary are the only entry points. Neither
installs a hook, reads or writes host settings, registers an MCP server, or
changes a host request. A caller chooses when to launch either binary.

The result describes a fixed evidence boundary. It is neither Stage 1 nor Stage 2
evidence and cannot close the provider join. It does not observe a host, read
settings, contact a provider, or establish provider or host authority. It does
not report provider token, cost, cache, or percentage-savings claims. Assembly
is a byte proxy for explicitly provided local bytes, not a token or
provider-usage claim. `run --escrow` is provider-free local capture only;
diagnostics, firewall results, and twin results are advisory and non-applying.
Reference expiry is an explicit local capability-access control and does not
delete retained artifacts. Its fixed value is
`companion_local_receipt_only`, `selected_branch: S2-UNSUPPORTED`,
`selected_transport: NONE`, with no host-owned request, runtime observer,
provider join, Stage 1/2 evidence, or provider-claim authority. The remaining
reserved `inspect` targets, including `lease`, stay unavailable.

The MCP binary is a bounded local stdio server for one explicit absolute
`--root`. After normal MCP initialization it exposes only `receipt_assemble`,
`receipt_expand`, `receipt_inspect`, and `receipt_tool_select`; it does not
expose command capture, durable-state administration, twin, reference expiry,
configuration, or registration tools. Its `cgr1m_` capabilities are random,
process-local, limited to 300 seconds, and invalid after process exit or
restart. MCP creates no durable state. If the pinned root instance or its
logical state drifts, the server stops accepting work and must be restarted;
durable CLI workflows likewise require a new explicit invocation when their
root or chosen state directory changes.

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

There is no default durable location: every durable workflow names an absolute
`--state-dir`. The local capability store is `store-v1` beneath that directory
and permits at most 1,024 artifacts, 64 MiB total artifact bytes, and 1 MiB per
artifact. Diagnostics, the experimental twin, and the experimental
reference-expiry registry use separate `auxiliary-v1` compartments with their
own quotas and never turn a local receipt into host, provider, or network
evidence.

If an unsupported top-level entry appears after the durable-state preflight but
before a newly created lock can validate the directory, opening returns
`commit_uncertain` and preserves every name, including the lock residue. Portable
POSIX APIs cannot conditionally unlink a pathname by inode, so recovery never
risks deleting a concurrent same-UID replacement.

The execution twin is disabled unless every invocation includes the exact
`--experimental-twin`, absolute `--root`, and absolute `--state-dir` tuple. It
does not run a command, replay an action, alter a request, or inspect the
network. An append re-evaluates only 1–32 declared local predicates: repository
instance equality, Git logical-state equality, exact regular-file equality, or
exact path absence. Git logical state covers bounded Git metadata, tracked
diffs, and untracked names; it deliberately does not claim that untracked file
bytes are equal, so callers must declare `regular_file_equals` for those bytes.
Non-Git and unresolved snapshots never match that predicate. File paths are
exact-case, frozen-NFC, relative, no-follow, and bounded; persisted results
replace paths and content with per-twin, per-event observation HMACs. `verified`
means only that every declared predicate matched in two immediate local passes
between stable local repository snapshots. It is not global completeness or
execution authority.

Treat twin output as an experimental local comparison only. It is advisory and
non-applying, does not execute or replay a command, and does not observe a host
or network.

Twin state is an independently keyed, removable `auxiliary-v1/twin-v1`
compartment. Its framed append log and authenticated metadata use explicit tail
compare-and-swap, allow at most 1,024 events and 8 MiB, and never evict history.
Invalid partial bytes beyond the authenticated committed offset can be removed
as crash residue; a suffix beginning with a valid authenticated next event is
preserved and returns `commit_uncertain` because it may be replayed metadata or
an indeterminate commit. Read snapshots are derived, disposable, and
non-authoritative. Removing `twin-v1` does not
invalidate `store-v1` capabilities or `diagnostics-v1` entries; ordinary
assembly, execution, diagnostics, and MCP startup never create it.

Reference expiry is disabled unless every administrative invocation includes
the exact `--experimental-reference-expiry`, absolute `--root`, and absolute
`--state-dir` tuple. A canonical registration request names an already issued
`cgr1p_` capability and an immutable Unix-millisecond deadline; a canonical
revocation request names that capability and the expected current generation.
The capability is validated against the current repository and the actual
store namespace before registration. Expired, revoked, forged, cross-store,
and corrupt-registry lookups all collapse to the existing non-oracular
capability refusal.

The independently keyed `auxiliary-v1/reference-expiry-v1` compartment stores
only a keyed selector, bounded timestamps, a generation, and a closed status.
It never stores the capability text, artifact path, payload, content digest,
command output, prompt, or transcript. Due access atomically changes only that
compact reference record to `expired`; explicit revocation changes only the
same record. At most 1,024 references are retained, no entry is evicted
automatically, and no source, `store-v1` artifact, diagnostic-ledger row, or
twin event is deleted. Administrative inspection returns bounded counts and
keyed hashes plus the constant compartment name, never the absolute state or
artifact location. Artifact cleanup remains a separate, user-authorized
operation that this package does not implement. Ordinary assembly, command
capture, diagnostics, twin, and unregistered expansion flows do not create
reference-expiry state.

Registration revalidates source-current evidence and command captures while
accepting independently validated immutable tool-schema snapshots. Active
lookups persist a per-reference clock high-water; a backward clock observation
terminally expires that reference, and multi-reference inspection publishes
due transitions as one bounded batch.

Reference expiry is also experimental local administration, not deletion or
provider enforcement. It changes only a compact registry record. The reserved
`lease` inspection target remains unavailable and does not imply lease support.

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

When the launcher itself receives `SIGINT` or `SIGTERM`, it forwards that signal
and allows a 2.5-second graceful-cleanup window. Confirmed cleanup returns
`128 + signal`. If child shutdown cannot be confirmed, including when cleanup
requires `SIGKILL` or a repeated interrupt requests escalation, the buffered CLI
child output is withheld and the launcher instead emits `cleanup_unconfirmed`
with exit `69`. This refusal does not claim that detached or otherwise
unobserved descendants were terminated.

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

In other words, evidence and blueprint expansion returns the original raw
source bytes when its local capability remains current. This is distinct from
`run --escrow` expansion: a command-capture capability returns only the
canonical sanitized CGRF capture, never the raw command output.

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
interpreter shims are rejected. The absolute override is an explicit caller
trust decision and may select a caller-trusted managed tool-cache executable
with different ownership or writable mode bits. Both selection modes require
the execute bit applicable to the effective UID, effective GID, and
supplementary groups; effective UID 0 requires at least one execute bit.
Discovery fails closed if those effective credentials are unavailable or
invalid. Automatic `PATH` discovery resolves symlinks to their physical native
target, then requires the target and every physical parent directory to be
owned by root or the effective UID. Group- or world-writable targets are
rejected; writable parent directories are rejected unless they carry the
sticky bit. The launcher opens the target with no-follow semantics, snapshots
its device, inode, mode, owner, group, link count, size, and nanosecond change
times, and revalidates that identity, the credentials, and execute permission
before and after the bounded five-second compatibility probe and immediately
before launch. Probe timeout is `protocol_incompatible` and the stuck probe is
killed with `SIGKILL`.

Pure Node.js on the supported platforms cannot atomically execute the validated
file descriptor as `fexecve` would, so path replacement remains possible in
the final interval between revalidation and spawn. The selected executable is
therefore part of the caller's trust boundary, and same-effective-UID, root,
debug/tracing, and equivalent filesystem authority are trusted and out of
scope. The compatibility probe is not interpreter authentication.

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

Use `context-guard-receipt --help` for the human-readable command summary and
`context-guard-receipt-mcp --help` for the explicit bounded stdio MCP summary.
