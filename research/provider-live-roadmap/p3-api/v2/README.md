# P3 Anthropic API v2 measurement

This version keeps the v1 240-unit schedule, model, cache-off request, spend
ceiling, one-use approval boundary, and scorer-after-all-calls lifecycle. It
changes one public candidate condition before opening scorer data:

- graph-enabled arms promote their already selected direct graph neighbors to
  secondary seeds, allowing one additional bounded local dependency hop;
- the three realistic tasks name the public entrypoint to invoke, including
  explicit arguments for the JavaScript validator.

The provider-free acceptance metric improved from two of three to three of
three realistic tasks with complete declared public context, with zero missing
declared dependency edges. Ordinary and adaptive-only pack bytes were not
changed by the graph closure mechanism.

## 2026-08-17 result

All 240 Anthropic Messages API calls completed on exact `claude-sonnet-5`, with
173,530 input tokens, 16,904 output tokens, and zero cache tokens. The list-price
estimate for this run is USD 0.516100; it remains an estimate, not an
authoritative billing receipt.

A manual Anthropic Console/CSV observation for 2026-08-17 UTC reported USD
1.03 for the day that contained both v2 runs. Its separately rounded CSV cost
rows were USD 0.69 for uncached input and USD 0.33 for output; both cost rows
equaled their list-price rows. Only these minimized aggregates are published:
no API-key identifier or raw export content is retained here. Because the
provider value is daily and cannot be attributed to either run alone, it does
not make the final run's USD 0.516100 calculation or savings authoritative.

On realistic fallback, combined was correct on 20/30 versus ordinary on 0/30,
and used 19.572096% fewer total tokens. Its list-price estimate was 56.656492%
lower. Train and calibration were each 10/10 for both graph-enabled arms. The
evaluation task remained 0/10 in every arm: its original hidden expected output
was not derivable from the original public task, and the newly frozen public
invocation did not match that legacy hidden oracle. This task is reported, not
silently repaired or excluded.

Across both strata, combined used 26.723159% fewer total tokens and its
list-price estimate was 50.299033% lower than ordinary, with exact correctness
50/60 versus 30/60. These are descriptive results for one small synthetic
corpus. They do not authorize a provider-cost savings, generalized token
savings, production-readiness, activation, or external-validity claim.

The minimized evidence remains owner-private for seven days and is bound by
hash and byte count in `result.json`. Prompt, answer, raw response, message ID,
credential, environment, header, URL, and private path values are not committed.
