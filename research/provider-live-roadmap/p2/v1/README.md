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

## 2026-08-13 result

The exact controller commit `abf84c9ffed96a9e51ca1de09679193ec53fe7cf`
consumed one approval and completed the fixed 240-call Claude schedule. There
were 237 provider successes and three transport exclusions, which caused three
complete four-arm blocks (12 units) to be excluded from paired analysis. The
owner-private evidence is retained for seven days and is bound by SHA-256 in
`result.json`; prompt and response content is not committed.

The closed-pack stratum passed P2 implementation readiness without granting
activation. The realistic-fallback stratum stayed diagnostic because its
omitted required sources are protected. Descriptively, combined and symbol-only
each answered 10 of 30 realistic-fallback units correctly, while ordinary and
adaptive-only answered none; this is not a deployment or savings claim.

Post-run review found that the executed controller observed the top-level token
fields but did not aggregate cache and helper-model token fields. Those token
metrics are therefore marked unavailable rather than reconstructed. The runner
now aggregates all reported first-party model-usage fields for any future run.
The recorded CLI cost estimate was USD 0.894320, but it is non-authoritative;
P3 remains blocked on fully loaded authoritative provider cost and a separate
P3 approval.

## 2026-08-13 Max token-usage attempt

The corrected observer was exercised once against the same fixed 240-call
schedule using the signed-in Claude Max session. This was a post-outcome repair
run, so it was descriptive only. Eleven calls returned complete first-party
model-usage records; 228 ended as transport exclusions and one timed out. Every
one of the 60 four-arm blocks was therefore excluded from paired analysis.

Follow-up one-use probes confirmed that the 228 `transport_error` observations
were not proven network failures. Claude Code returned successful records with
the helper key `claude-haiku-4-5-20251001` and canonical model
`claude-haiku-4-5`; the observer incorrectly required those two strings to be
identical. The parser now permits only an exact eight-digit date suffix for a
first-party helper key, continues to require the exact primary model, and
aggregates both models. A live probe passed with both model identities.

The 11 successful calls accounted for 61,295 input tokens (including reported
cache creation and cache reads) and 252 output tokens. These sparse successes
are retained only as a diagnostic total. They cannot support an arm-to-arm
token-savings estimate. `usage-attempt-result.json` binds the owner-private
evidence without publishing a private path, prompt, or response. A new complete
fixed-schedule run with the corrected observer is required before token savings
can be measured. P3 remains blocked.

## 2026-08-13 corrected Max measurement

The corrected observer then ran the entire fixed schedule from controller
commit `64e1b5595aa3377ec551f74150792784b3d5e041`. Of 240 scheduled calls, 234
completed. Five incomplete four-arm blocks were excluded, leaving 55 complete
blocks and 220 analyzed units. Both the selected Sonnet model and the dated
first-party Haiku helper were included in every reported token total.

On the 30 closed-pack blocks, combined used 182,603 tokens versus ordinary's
196,552: 13,949 fewer tokens, or 7.096850%, with both arms correct on 30/30.
Adaptive-only used 6.677622% fewer tokens with the same correctness;
symbol-only used 0.608999% more.

On the 25 complete realistic-fallback blocks, combined used 0.637534% more
tokens than ordinary while improving exact correctness from 0/25 to 10/25.
Symbol-only achieved the same correctness improvement at 6.901658% more
tokens. Adaptive-only used 7.099103% fewer tokens but remained 0/25 correct.

These are descriptive results for the frozen synthetic corpus, not generalized
or production savings claims. The CLI cost estimate remains non-authoritative,
and realistic fallback remains ineligible because of protected omission. P3 is
still blocked on authoritative fully loaded provider cost and a separate exact
P3 approval. `usage-measurement-result.json` binds the minimized private
evidence without publishing prompts, responses, credentials, or private paths.
