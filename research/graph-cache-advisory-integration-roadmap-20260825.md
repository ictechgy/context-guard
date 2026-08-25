# Graph-cache × weightclass-advisory integration roadmap

_Last updated: 2026-08-25 KST_

> Status: design brainstorm and stage-gated proposal. Nothing in this document is
> implemented, benchmarked, or authorized. No token/cost-savings claim is made.
> Ideas were solicited from three independent sources (see §1) and synthesized
> by hand; no automatic aggregation or voting was applied.

## 1. Sources and method

The revision-bound `--graph-cache` flag added to `context-guard-pack auto`
(`context-guard-kit/context_pack.py`, `tests/test_graph_rank_cache.py`) caches
graph-rank/repo-map output keyed by `(worktree path, commit sha, seed_paths,
query_terms)`, with content-hash self-authentication, TTL expiry, and a bounded
quota with oldest-first eviction. Separately, `wclass-advisory`
(`docs/wclass-advisory-workflow.md`) is an externally installed CLI — its source
is **not** in this repository — that dispatches one task to several vendors
(Claude/Codex/Grok/others) through owner-only, environment-narrowed route
profiles, in cheap → advisor → retry → expensive stages.

Three brainstorm passes fed this document:

- **Claude** (this session) — synthesized inline during the conversation.
- **Grok** — queried directly via the local `grok` CLI (`-p`, read-only,
  `--disallowed-tools` blocking file/shell access), no repository access.
- **Codex** — queried directly via `codex exec -s read-only`, no repository
  access, explicitly asked to avoid the first three ideas already converged on.

All three were given the same background paragraph and answered blind to each
other's exact wording; the "common ground" in §2 is the parts that showed up
independently across at least two of the three answers.

## 2. Idea catalog

Grouped by theme, not by source. Each entry: mechanism, one risk/trade-off, and
which side of the tool boundary it lives on (**context-guard-kit** = we own the
code; **wclass-advisory** = external tool, would need upstream change or a
wrapper).

### Theme A — Shared revision pin (fairness & reproducibility)

| # | Idea | Risk | Owner |
| --- | --- | --- | --- |
| A1 | Warm the graph cache once before dispatch and give every vendor lane the same cache key as a common input pin, so cheap/advisor/retry/expensive score the same file set instead of silently drifting. | A bad cache entry biases every lane identically — errors no longer average out across vendors. | wrapper (see §4) |
| A2 | Drop the absolute worktree path from the cache key; key on commit SHA + content-hash of the resolved seed set instead. Content-hash self-authentication already exists, so this only removes an unnecessary specificity, not a safety property. | If two repos share a SHA but differ in untracked/ignored state that affects seed resolution, a stale hit could occur — needs the content-hash check to cover exactly what seed resolution reads. | context-guard-kit |
| A3 | Add a `--graph-cache-dir` override so an external orchestrator can point every lane at one shared cache path instead of each lane's default (repo-relative) location. | Any lane with write access to a shared directory can poison every other lane's reads unless writes are separated (see A5). | context-guard-kit |
| A4 | Emit a machine-readable cache receipt (`graph_cache_key`, resolved content-hash, TTL, eviction generation) next to every `--graph-cache` run, so a campaign log can cite "this score came from this exact map." | A matching hash proves the map wasn't tampered with; it says nothing about whether the map was a *good* map. Don't conflate integrity with quality. | context-guard-kit |
| A5 | Split cache roles: only the orchestrator (owner process, outside any vendor's narrowed environment) writes; vendor lanes open the cache directory read-only. | Requires knowing whether `wclass-advisory` sandboxes lanes at the filesystem level or only narrows environment variables — see the open question in §4. | wrapper + investigation |

### Theme B — Scope & cost routing

| # | Idea | Risk | Owner |
| --- | --- | --- | --- |
| B1 | Two-tier cache: a common `(task_id, sha)` layer for fair comparison, plus a vendor-specific `query_terms` sub-key so each route profile's natural seeding style (Claude: broad seeds, Codex: test paths, Grok: design docs) still gets used. | More sub-keys means eviction pressure hits vendors unevenly — "fair" and "locally optimal" pull against each other. | context-guard-kit |
| B2 | Per-stage cache TTL policy: cheap gets a short TTL and high hit rate, advisor/retry reuse on matching SHA, expensive forces a fresh rebuild (or a wider seed) for the final verdict. | If cheap sees a stale map it can reject a candidate for the wrong reason; if only expensive sees a different map, cross-stage comparisons stop being apples-to-apples. | context-guard-kit |
| B3 | Scope the advisory input to the diff's impact subgraph: start from the commit diff, walk dependency edges, and hand vendors only the affected subgraph instead of the whole repo map. | Static graph edges miss dynamic loading, config-driven wiring, and string-based references — impact radius can be underestimated. | context-guard-kit (graph build) + wrapper (task authoring) |
| B4 | Route cheap-vs-expensive dynamically from graph features of the changed area (centrality, edge density, cycles, blast radius) instead of a fixed stage ladder. | An untuned heuristic overfits to this repo's shape and can misroute a genuinely hard task to a cheap lane. | wrapper, research-grade |
| B5 | Use cache hit/miss itself as a routing signal: a stable hit on an unchanged SHA suggests "repeat campaign on unchanged code," eligible to skip straight past expensive. | High hit rate correlates with "structure didn't change," not with "problem is easy." Quota pressure can also fake a miss pattern. | wrapper, research-grade |

### Theme C — Trust & evaluation

| # | Idea | Risk | Owner |
| --- | --- | --- | --- |
| C1 | `graph_coverage` score: how much of the important node/path set a vendor's answer actually touched, reported alongside (never combined into) the accuracy verdict. | High coverage is not high quality — must stay a diagnostic, not a ranking input. | context-guard-kit (graph side) + wrapper (scoring) |
| C2 | Claim-to-graph linking: require each vendor to cite the graph nodes/paths backing each claim, so another vendor can walk that exact path and refute it. | Richer output format invites plausible-but-nonexistent citations ("hallucinated edges"); needs automatic verification against the real graph, not trust-on-read. | wrapper, research-grade |
| C3 | Cache-bypass canary lane: force one lane per campaign to skip the cache entirely and diff its result against the cached lanes to catch staleness/poisoning. | Extra compute cost every campaign; a divergence is ambiguous between "cache bug" and ordinary model variance. | wrapper |
| C4 | Drift canary on a small fixed fixture repo, run before the real campaign; abort dispatch if ranking order disagrees across vendors/stages beyond a threshold. | A toy fixture may not represent this monorepo's real structure, giving false confidence when it passes. | wrapper |
| C5 | Fold cache hit-rate / avoided-rebuild counts into the existing runner-aware pass/fail digest (`trim_command_output.py`, landed in #324) so any cost-savings claim from caching is as auditable as the rest of the digest, instead of an unverified side note. | Digest changes need their own regression coverage; don't let a "nice number" ship without the digest's existing pass/fail discipline. | context-guard-kit |

### Theme D — Advanced multi-vendor graph collaboration (experimental)

| # | Idea | Risk | Owner |
| --- | --- | --- | --- |
| D1 | Disagreement-driven re-search: extract only the symbols/files/assumptions where vendor answers conflict, re-run graph-rank scoped to that delta, and spin a narrow second advisory round. | Can become a self-reinforcing loop that inflates cost/latency if disagreement doesn't converge. | wrapper, research-grade |
| D2 | Community-partitioned parallel expert rounds: split the repo graph into modules/clusters, assign each vendor a different cluster to review in depth, integrate at the end. | Boundary bugs fall between clusters and no single vendor owns them — needs an explicit integration pass. | wrapper, research-grade |
| D3 | Cross-vendor map consensus layer: intersect/union each vendor's top-N selected paths; feed the intersection as shared context and route disagreement to a separate evidence channel. | Intersection is too conservative and can drop a genuinely relevant file; union bloats context back toward the problem the hygiene tool exists to solve. | wrapper, research-grade |
| D4 | Pre-share subgraph minimization + policy filtering: before handing a subgraph to an external vendor, strip it to the task-relevant minimum and redact sensitive paths/filenames per policy. | Over-filtering destroys the vendor's reasoning basis; under-filtering leaks repository structure to an external vendor. Directly touches the "no external forwarding without fresh authorization" contract already in `research/token-savings-roadmap-20260804.md` §3. | context-guard-kit (extraction) + policy design |

## 3. Priority table

| Priority | Decision | Rationale |
| --- | --- | --- |
| Now | A2 (drop worktree path from cache key), A3 (`--graph-cache-dir` override), A4 (cache receipt) | All three are pure `context-guard-kit` changes, don't touch `wclass-advisory`, and are prerequisites for everything else in Theme A. |
| Now | Investigate `wclass-advisory`'s lane isolation model (env-only vs. filesystem-sandboxed) | A5, A1, and every Theme B/C/D idea that assumes a shared-but-read-only cache directory depends on this being env-narrowing only, not a filesystem jail. Evidence so far (a prior campaign log noted `HOME` is unchanged and `~/.aws/credentials` remains readable despite env narrowing) suggests filesystem access is *not* sandboxed — but that was one observation on one route profile, not a verified guarantee. |
| Next | A1 (common cache pin via wrapper), A5 (write/read separation), C5 (digest integration) | Depend on the "Now" investigation resolving in the expected direction. C5 has no such dependency and can start immediately in parallel. |
| Next | B1 (two-tier cache), B2 (per-stage TTL) | Pure `context-guard-kit` cache-policy work; can be speced once A2 lands since both build on the same key schema. |
| Later | B3 (impact-subgraph scoping), C1 (coverage score), C3/C4 (canaries) | Useful but each needs its own small validation (does impact-subgraph scoping actually shrink the map without dropping relevant files? does coverage correlate with anything?) before it's worth wiring into a live campaign. |
| Research only | B4, B5, C2, D1–D4 | Genuinely promising but speculative, expensive to validate, and several (D3, D4) touch cross-vendor information-sharing policy that needs its own authorization pass, not just an engineering spec. |
| Hold | Any idea that requires modifying `wclass-advisory` internals directly | This repo does not own that tool's source (`~/.local/share/uv/tools/weightclass`, a separately installed CLI). Everything here is scoped to what `context-guard-kit` can do plus what an external wrapper script or task-authoring convention can achieve through `wclass-advisory`'s existing CLI surface. |

## 4. P0 spec — the three items ready to build now

### 4.1 Cache key: drop the worktree path (A2)

**Current key** (as landed): `(worktree_path, commit_sha, seed_paths, query_terms)`.
**Proposed key**: `(commit_sha, content_hash_of_resolved_seed_set, query_terms)`.

- `content_hash_of_resolved_seed_set` is already computed for the existing
  self-authentication check; this change promotes it from a *verification*
  input to a *key* input, so two different worktrees at the same commit with
  the same resolved file content hit the same cache entry.
- Requires confirming the resolver reads nothing path-dependent (e.g. no
  absolute-path-derived tie-breaking in the ranking) — audit
  `context-guard-kit/context_pack.py`'s seed-resolution path before changing
  the key, since a silent behavioral dependency on the worktree path would
  turn this into a correctness bug, not just a cache-locality improvement.
- Test to add: two temp worktrees checked out to the identical commit and
  content must produce the identical cache key and a cache hit on the second
  worktree's first call.

### 4.2 `--graph-cache-dir` override (A3)

- New optional flag on `context-guard-pack auto`, defaulting to the current
  location if omitted (no behavior change for existing callers).
- Must apply the same permission/ownership checks the default cache location
  already gets (owner-only, no symlink following) — an externally supplied
  directory is a wider trust boundary than a repo-relative default.
- Test to add: pointing two separate repo checkouts' `--graph-cache-dir` at
  the same directory and confirming a cache hit recorded by the first is
  visible to the second, subject to the key change in §4.1.

### 4.3 Cache receipt (A4)

Emit alongside (not instead of) the existing `--explain` output, a small JSON
block:

```json
{
  "graph_cache_key": "<sha256 of the (commit_sha, content_hash, query_terms) tuple>",
  "resolved_content_sha256": "<content hash of the payload actually returned>",
  "hit": true,
  "ttl_expires_at": "<iso8601>",
  "eviction_generation": 42
}
```

- `hit`/`eviction_generation` make it possible to later build C5 (digest
  integration) and C3/C4 (canaries) without re-deriving cache internals from
  scratch.
- This block is diagnostic metadata, not a claim — nothing here should be
  read as a token-savings number without the same measurement contract
  `research/token-savings-roadmap-20260804.md` already requires for any such
  claim.

## 5. Open question blocking Theme A's cross-lane work

Everything past §4 that assumes a *shared* cache directory across
`wclass-advisory` vendor lanes rests on one unverified fact: whether lanes are
isolated only by environment-variable narrowing (a shared filesystem path
would work) or by an actual filesystem sandbox/jail (it would not, and A1/A5
would need a different design — e.g., each lane writing its own cache that a
later merge step reconciles, rather than true read-time sharing).

The one piece of evidence available today is a prior campaign log noting the
child environment was narrowed ("18 passed, 82 excluded") while `HOME` itself
was left unchanged and files like `~/.aws/credentials` remained readable —
i.e., env narrowing without filesystem isolation, on the route profile that
ran that campaign. That is one data point on one profile, not a documented
guarantee across all route profiles. Confirming this (by reading
`docs/wclass-advisory-workflow.md`'s route-profile review output for the
profiles actually in use, or by asking the advisory tool's own `review`
subcommand) is the next concrete step before speccing A1/A5 further.
