# Context Guard Receipt

`@ictechgy/context-guard-receipt` is a small, provider-free receipt companion
whose work is confined to explicitly supplied local inputs and state.

It exposes the fixed boundary inspection, local evidence, blueprint, and
tool-schema assembly, explicit local command capture, and advisory local
diagnostics:

```text
context-guard-receipt inspect boundary
context-guard-receipt evaluate phase --input <file|->
context-guard-receipt evaluate full-wire --input <file|->
context-guard-receipt evaluate calibration --input <file|->
context-guard-receipt evaluate route-v2 --input <file|->
context-guard-receipt evaluate net-efficiency --input <file|->
context-guard-receipt evaluate fanout-plan --input <file|->
context-guard-receipt evaluate prefix-plan --input <file|->
context-guard-receipt evaluate prune-plan --input <file|->
context-guard-receipt evaluate shadow-policy --input <file|->
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
context-guard-receipt import merged-capture --spool <absolute> --transaction-id <64-lowercase-hex> --root <absolute> --state-dir <absolute> [--disclosure-days 7]
context-guard-receipt recover merged-capture --transaction-id <64-lowercase-hex> --root <absolute> --state-dir <absolute>
context-guard-receipt inspect merged-capture-import --root <absolute> --state-dir <absolute>
```

Package and entry-point discovery are explicit and local. For a separate local
install, pack this directory and install that resulting tarball in the target
project, then invoke the two installed binaries directly:

```text
npm pack --ignore-scripts
npm install --ignore-scripts ./ictechgy-context-guard-receipt-0.3.0.tgz
./node_modules/.bin/context-guard-receipt --help
./node_modules/.bin/context-guard-receipt-mcp --help
./node_modules/.bin/context-guard-receipt-mcp --root /absolute/repository-root
./node_modules/.bin/context-guard-receipt-mcp --root /absolute/repository-root --state-dir /absolute/private-state
```

Any downgrade to an earlier release is an external package-manager/release gate
requiring an independently retained immutable published artifact. This package
does not simulate or reconstruct an older release from the `0.3.0` runtime tree.

The ordinary CLI and the stdio MCP binary are the only entry points. Neither
installs a hook, reads or writes host settings, registers an MCP server, or
changes a host request. A caller chooses when to launch either binary.

The packaged Python module `context_guard_receipt.external_approval` is a
programmatic, non-CLI approval boundary for a separately implemented external
runner. It does not contain a provider runner or obtain credentials, open a
network connection, create an output root, publish a package, or activate a
runtime. An issuer can HMAC-authenticate one closed approval whose scope binds
the exact candidate commit, manifest, checksums and artifact IDs; provider and
model; observer, operation version and receipt schema; runtime version,
executable, argv and environment identities; credential consumer and allowed scopes;
HTTPS destinations; call, spend, currency and timeout caps; owner-private
output root; and retention. Redirects and proxies are fixed off. Approvals use
an internally observed Unix clock, expire after at most one year, are
revocable, and carry one nonce.

`authorize_and_consume` requires independent approval-verification and state
authentication keys. It serializes threads and processes, validates an exact
requested scope, checks expiry and revocation, and durably records the hashed
nonce before invoking the trusted materializer with a copied scope. Replay,
scope expansion, malformed data, unsafe state metadata, or uncertain state
durability refuses before that callback. The state directory must already
exist as an owner-private `0700` directory. It
stores only sorted SHA-256 selectors and an authenticated registry; it stores
no approval, provider/model name, destination, output path, nonce, revocation
handle, or key. The state directory is part of the operator trust boundary: an
actor able to restore an older valid filesystem snapshot can roll back any
purely local registry, so deployments needing rollback-resistant one-use
semantics must place it on a separately protected monotonic store. The caller
must also implement the bound network/runtime/output controls; this module is
an authorization gate, not an OS sandbox or an execution engine. An approval
does not grant npm publication or evidence-claim authority.

`context_guard_receipt.external_approval_v2` is a parallel, versioned adapter
for callers whose evidence lifecycle is honestly manual. It leaves the v1
module, schema, HMAC domain, and existing consumers byte-compatible, while its
closed scope binds retention exactly as
`{"mode":"manual_owner_cleanup","maximum_seconds":null}` and authenticates
the envelope under `contextguard/external-approval/v2`. V1 and v2 share the
same authenticated one-use/revocation registry, so changing envelope versions
cannot make a consumed nonce reusable. V2 does not claim finite retention or
automatic deletion; systems requiring a deletion deadline need a separate
durable lifecycle authority and receipt before approval.

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
`receipt_batch`, `receipt_context`, `receipt_diagnose`, `receipt_expand`, `receipt_inspect`,
`receipt_pack`, `receipt_tool_select`, and `receipt_twin`; it does not expose command capture,
reference-expiry administration, configuration, registration, provider, or
network tools. Its `cgr1m_` capabilities are random, process-local, limited to
300 seconds, and invalid after process exit or restart. Without `--state-dir`,
MCP creates no durable state and `receipt_twin` returns unavailable. An explicit
absolute `--state-dir` enables only the existing authenticated advisory twin;
the directory is fixed by the server process and cannot be supplied by a tool
call. If the pinned root instance or its logical state drifts, the server stops
accepting work and must be restarted.

`receipt_batch` accepts up to sixteen exact slice queries over live
`receipt_context` capabilities already bound to one required `task_scope`.
The combined returned payload is capped at 65,536 bytes, and every result keeps
its exact capability and byte range. One invalid scope or range rejects the
whole call without returning partial bytes. The tool adds no filesystem
discovery, filtering language, command execution, provider, or network access.

`receipt_pack` accepts up to sixteen explicit, unique source entries, each
containing a relative path and a live `receipt_context` capability already
bound to the same required `task_scope`. The server revalidates the capability,
its original path binding, and the current exact bytes before constructing one
caller-ordered bounded evidence pack. Whole files that fit the declared
retained-byte budget remain inline; the rest become new task-scoped exact
source-current capabilities. Paths and scope text are never returned. The tool
does not rank files, infer task relevance, or intercept host context.

`receipt_tool_select` optionally accepts `profile_id` together with
`task_scope`. Within that process, the same profile reuses the exact original
catalog bundle and capabilities. A changed catalog or retain policy is refused
as profile drift rather than silently rebuilding a new prefix, and deferred
schema expansion requires the matching task scope. Profile labels are keyed
locally and never reflected.

`receipt_context` is the explicit product bridge for repeated local files and
logs. `action: "store"` requires the caller to affirm `caller_classification:
"eligible"` with an empty `detector_signals` list, reads one bounded no-follow
regular `relative_path` beneath the pinned root, and applies the existing
conservative byte-benefit router. Small or uneconomic inputs are returned
unchanged; beneficial inputs return a direct exact reference without requiring
the caller to resend the file bytes. Repeated requests for the same unchanged
file reuse the live process capability. An optional `task_scope` binds a
capability to one caller-declared task without returning the scope text.
`action: "read"` returns only the requested exact slice, capped at 65,536 bytes,
with explicit start, end, total, and completion metadata. `action: "release"`
immediately revokes that process-local capability and `action: "history"`
returns a bounded content-free decision history containing only counts,
decisions, and process-keyed HMACs—never paths, task labels, capabilities, or
file bytes. Non-eligible classifications are refused without reading or
reflecting file content. The tool is never invoked automatically, does not
intercept a host prompt, and does not establish provider token or cost savings.

`receipt_diagnose` reads one explicitly eligible path without requiring its
bytes in the MCP request and projects the existing shadow firewall, conservative
router, prefix-reuse comparison, and `scout`/`surgeon` advisory lane. A supplied
`previous_capability` must belong to the same optional task scope. The report is
content-free, applies no route, and has no provider-routing authority. Inputs
above 700,000 bytes retain the normal `receipt_context` fallback but are refused
by this duplicate-prefix diagnostic to keep its aggregate decoded-byte bound.

`receipt_twin` appends or inspects the existing execution twin only when the MCP
process was started with `--state-dir`. It revalidates declared local predicates
and writes authenticated advisory evidence; it never executes the declared
action. Together with `receipt_assemble` evidence packs and typed blueprints,
the explicit flow is diagnose → store → bounded reads/assembly → twin evidence
→ history/release. Failure cones and blueprints remain explicit caller-selected
evidence, not automatic transcript rewriting.

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
and permits at most 1,024 artifacts, 64 MiB total artifact bytes, and ordinarily
1 MiB per artifact. Diagnostics, the experimental twin, and the experimental
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

`import merged-capture` is the runner-free adapter for one already completed,
owner-only (`0600`), no-follow regular spool of at most 10,000,000
bytes. It verifies canonical sanitized UTF-8 without sanitizing again, streams the exact bytes into
`COMMAND_CAPTURE_BYTES`, and assigns the sole subject domain
`contextguard-receipt/command-capture-merged-sanitized/v1`. Merged-import store
initialization opts into that protocol-specific single-artifact ceiling while
ordinary store initialization retains its 1 MiB default. The first merged import
atomically upgrades an exact default-limit store in place; custom limit profiles
remain refused. The optional
`--disclosure-days` consent marker accepts only `7`; the protocol records one
absolute deadline exactly 604,800,000 milliseconds after issuance and never
extends it on retry, recovery, disablement, rollback, or revocation.

Import recovery is transaction-scoped. A lowercase 64-hex random transaction
id deterministically re-derives the same store capability, while the
authenticated `reference-expiry-v1/import-transactions-v1` journal stores no
handle, spool path, payload, or command/content hash. Authority is emitted only
after read-back validation and idempotent expiry registration. A prepared
transaction with no artifact is abandoned; an uncertain committed artifact is
recovered in place and never duplicated. Aggregate inspection exposes only
counts and pending bytes. At most 32 transactions and 32 MiB of artifact bytes
may remain pending; artifacts are never automatically deleted. Expansion of
this merged subject requires a positive active registry record and returns the
exact merged bytes. Legacy canonical CGRF command captures remain readable and
do not acquire a registration requirement.

The Bash integration does not use the public pathname import above. Its private
broker accepts only an inherited anonymous regular descriptor (`0600`, current
effective uid, link count zero), announces readiness only after repository and
state preparation, and then accepts exactly one `COMMIT` or `ABORT`. `COMMIT`
uses retained store, expiry, and journal descriptors; it performs no later Git,
Node, Python, or package-path execution. Same-process recovery is attempted once
for the selected transaction before one bounded canonical final result. Broker
preparation may initialize these axes even when the eventual sanitized output
is below the root wrapper's 8,192-byte disclosure threshold.

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

## Full-wire budget and calibration evaluation

`context-guard-receipt evaluate full-wire --input <file|->` reads one bounded
canonical envelope with `baseline`, `candidate`, `protected_pointers`, and an
`enforce` boolean. It compares the complete canonical request bytes, blocks
protected-pointer or output-budget regressions, and reports stable-prefix
preservation diagnostically without emitting or storing either request.

`context-guard-receipt evaluate calibration --input <file|->` joins bounded
preflight and observed numeric rows by opaque `(model_hmac, request_hmac)`
identity. It reports integer input-estimate multipliers, cache-prediction
accuracy, and output-budget utilization only when the declared minimum sample
count is met. Recommendations are never applied automatically and contain no
raw model, request, prompt, or path data.

`context-guard-receipt evaluate route-v2 --input <file|->` evaluates one closed
integer-microusd total-cost envelope. Provider input/output, cache, expansion,
retry, helper, and local costs are summed before the quality, risk, evidence,
full-wire, and savings gates are applied. The result is shadow-only advice;
`runtime_applied` and runtime route authority remain false on every path.

`evaluate net-efficiency` compares matched HMAC task pairs and distinct HMAC
run windows using provider usage, fully loaded provider plus shifted cost,
quality, success, p95 wall time, output tokens, model requests, tool calls and
yields, corrections, and rehydrations. Caller-declared non-inferiority,
regression, and minimum-improvement margins decide only `recommend` or `hold`.

`evaluate fanout-plan` gates independent multi-call workloads before batching;
`evaluate prefix-plan` compares only HMAC component identities and
caller-supplied cache economics/capabilities; `evaluate prune-plan` selects
only stale, exact-fallback, unprotected tool-result indexes at an explicit task
boundary; and `evaluate shadow-policy` deterministically keeps the mandatory
no-op lane unless a complete, quality-safe, net-efficiency-recommended
candidate has lower full cost or, at equal cost, lower p95 latency. Exact ties
stay on no-op; any permitted tradeoff in the other metric is bounded by the
candidate's preceding net-efficiency policy. All four are content-free,
shadow-only plans and authorize no execution or request mutation.

## Closed phase evaluation

`context-guard-receipt evaluate phase --input <file|->` evaluates one canonical
P2, P3, P4, P5, or P6 local record. Input is capped at 2 MiB, parsed with the
package's duplicate-key rejecting canonical JSON parser, and constrained by the
phase schemas shipped under `schemas/phase-evaluation-*.schema.json`.

The evaluator is provider-free and advisory. It reads no credentials, provider
state, settings, hooks, or network resources; performs no provider or model
call; mutates no request or runtime route; and grants neither activation nor
claim authority. Invalid, incomplete, stale, or uneconomic evidence preserves
the exact unchanged baseline or the phase's independently verified exact local
fallback. Its numeric fields are caller-supplied evaluation measurements, not
token, cost, percentage, or savings claims made by this package.
