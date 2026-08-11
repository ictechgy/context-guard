# Progressive-context live benchmark — 2026-08-12

## Verdict

The explicit combined workflow is functional, but provider token savings are
not demonstrated. The treatment reduced the 12 generated packs from 81,200 to
11,594 bytes (85.72%) while preserving the declared critical sources and all
72 measured attempts passed their external checker. End-to-end primary tokens
were effectively flat: treatment minus baseline was -7,122 tokens (-0.17%),
with a task-cluster point estimate of -197.83 tokens and a 95% interval from
-9,693.42 to +9,375.02. The interval crosses zero, so the frozen token gate
failed and the report is `inconclusive` with `claim_allowed=false`.

The Claude CLI reported 7.37% lower cost for the treatment, but the treatment
also used nine more turns, nine more tool calls, and 66.59 more wall-clock
seconds. No uncertainty interval was preregistered for the CLI cost, correction
evidence was unavailable, and fully loaded shifted cost is incomplete. The cost
observation is diagnostic, not a savings claim.

## Frozen comparison

- Source: `334f806c6a3270894cadd4149250533cf95c2639`.
- Candidate identity:
  `cc89e4c050e0760ae7f58d61ca963b00b84cfaf8f5dd60379d405e4cbc633a8f`.
- Runtime: Claude Code 2.1.228, `sonnet`, medium effort.
- Corpus: 12 synthetic instances from two templates: six direct-import
  neighbor instances and six explicit-evidence/distractor instances.
- Design: ordinary deterministic auto pack versus the same pack builder with
  both `--apply-adaptive-k` and `--apply-symbol-memory`; three repetitions per
  instance and arm; randomized paired order; cold workspaces; bound external
  checkers; one policy retry available but none consumed.
- Calls: 72 accepted analytic calls, 36 per arm. Both arms passed 36/36.
- Pack boundary: 12,000-byte cap and exact workspace fallback retained.

This is a live-model smoke test of the combined explicit prompt-pack workflow.
It is not a test of automatic host interception, and the two-arm design cannot
attribute an effect to adaptive-k or symbol memory independently.

## Results

| Metric | Ordinary pack | Combined treatment | Treatment delta |
| --- | ---: | ---: | ---: |
| Generated pack bytes | 81,200 | 11,594 | -85.72% |
| Full prompt bytes | 87,458 | 17,852 | -79.59% |
| Local pack token proxy | 20,304 | 2,898 | -85.73% |
| Declared critical-source recall | 100% | 100% | 0 pp |
| Successful provider attempts | 36/36 | 36/36 | 0 pp |
| Primary tokens | 4,254,273 | 4,247,151 | -7,122 (-0.17%) |
| Claude CLI reported cost | $4.255087 | $3.941310 | -$0.313777 (-7.37%) |
| Turns | 137 | 146 | +9 |
| Tool calls | 101 | 110 | +9 |
| Wall time | 320.372 s | 386.960 s | +66.588 s |

The combined transformation selected six direct graph neighbors and omitted 36
heuristic sources in the adaptive template family. Across all treatment packs,
adaptive-k omitted 54 sources because it also pruned graph-template distractors
before symbol memory re-added the direct dependency.

Local pack construction was measured separately with one warmup per task/arm,
five counterbalanced repetitions, and a new process per measurement. Ordinary
pack construction averaged 103.82 ms; combined construction averaged 116.67
ms, a 12.86 ms (12.38%) local latency increase. This is end-to-end CLI timing,
not an isolated algorithm microbenchmark.

## Why this does not close the roadmap gate

1. The 12 instances are parameterized copies of two synthetic templates, not
   12 independent repositories or workload families.
2. The treatment combines two mechanisms. Ordinary graph packs already contain
   the critical neighbor; adaptive-k first prunes it and symbol memory re-adds
   it. This proves safe composition in these fixtures, not graph selection's
   standalone incremental value.
3. Workspace fallback is enabled in both arms. Extra reads, turns, cache writes,
   and latency are intentionally part of the end-to-end outcome.
4. The paired token distribution contains large turn/cache outliers. The 95%
   interval crosses zero, and correction plus fully loaded shifted-cost evidence
   is incomplete.
5. Results are scoped to this exact source, generated corpus, model alias, CLI
   version, and cache conditions. They support neither comparator parity nor a
   general product savings percentage.

The next meaningful experiment is a four-arm ablation: ordinary, adaptive-only,
symbol-only, and combined. It needs independent task structures, graph cases
where ordinary ranking genuinely misses a required neighbor, hidden-oracle
adaptive labels that are not explicit pack seeds, closed-pack and realistic
fallback strata, correction/retrieval accounting, and confidence intervals for
fully loaded cost.

## Evidence and spend

The sanitized machine summary is
[`progressive-context-benchmark-2026-08-12.json`](progressive-context-benchmark-2026-08-12.json).
The accepted private evidence hashes are:

- manifest:
  `9174ec9ae20393df1cc3e3a0348e268557e9f25cc5e9061febd303cbd6b08fc7`;
- attempt index:
  `77cd8b26b8d48be1f69542b84368e2358552e49178b7a60dc22114518a439028`;
- study report:
  `cdc88a76174a2f303eb9fbf3c107c0ab070c5e9a364961eccc79c009ab1256f1`;
- pack generation:
  `fa09a20eb5d3e6737f76e7f919eadfe40b516e71b0ca0357a1c6827bd96c02ce`;
- aggregate analysis:
  `be4886e967eee9560a84428725faf10000f9e4321f1b14a0d2db78ddf49f3874`;
- counterbalanced timing:
  `efbb8e21edce08292c5be769581a8ebe1537f0b0bb9a8e02a2ed33bca4ccf1eb`.

One private-artifact format caveat does not change the narrow result, but makes
the corresponding metadata field non-self-describing. Each pack-generation row's
`fixture_tree_sha256` uses SHA-256 over the ASCII domain
`contextguard.progressive-fixture-tree.v1` plus one zero byte, followed by each
sorted regular file encoded as an eight-byte big-endian UTF-8 path length, path
bytes, an eight-byte big-endian content length, and content bytes. It excludes
executable modes, and the private file does not declare that algorithm. The
independent audit nevertheless regenerated all 24 packs byte-for-byte; the
study manifest separately binds the canonical fixture trees and file modes.
The private study manifest is canonical under the repository contract: its
single trailing LF is required, its raw bytes exactly match the canonical
serializer, every raw-byte hash binding is consistent, and the repository
analyzer exactly reproduced the published inconclusive report. These facts
support the smoke-test conclusion, not a claim that the custom tree-hash field
was self-describing in the private pack-generation file.

The accepted run's two arm totals sum to $8.1963973 in Claude CLI reported
cost. An earlier 72-call run cost a reported $8.1176929 and was discarded before
publication after a noncritical prompt-to-fixture path drift was detected. The
combined operational total was $16.3140902. The discarded run supports no
result.
