# P3 Anthropic API measurement

This directory binds a one-use, direct Anthropic Messages API measurement over
the frozen G5 240-unit schedule. The executed model was exactly
`claude-sonnet-5`, adaptive thinking was disabled, tools and prompt caching were
omitted, and the standard API key existed only in process memory. The runner
accepted only HTTPS responses from `api.anthropic.com`, sealed all provider
usage receipts before opening scorer-only bytes, and published no prompt,
answer, response, message identifier, credential, header, environment value, or
private path.

`live_runner.py` refuses direct mutable execution. Each run requires an exact
one-use external approval envelope binding the complete 240-request body plan,
runner, destination, output root, timeout, and USD 20 ceiling. A consumed or
expired approval cannot be reused. The response observer fails closed on model,
shape, response-size, per-call budget, aggregate budget, and cache-usage drift.

The Messages API token counters are authoritative usage receipts for the
accepted calls. Dollar values are different: this account's standard API key
does not have the organization Admin Usage & Cost permission, so the recorded
USD 0.580690 is only the published Sonnet 5 introductory list-price calculation
for the final run. It is not a billing receipt or a fully loaded shifted-cost
measurement. The introductory price window is explicitly bounded through
2026-08-31; execution fails closed outside that window.

Pricing and model-window references:

- [Anthropic model pricing](https://platform.claude.com/docs/en/about-claude/pricing)
- [Claude Sonnet 5 model notes](https://platform.claude.com/docs/en/about-claude/models/whats-new-sonnet-5)

## 2026-08-17 result

The final fixed schedule completed all 240 calls with no exclusions. Provider
usage was 174,710 input tokens and 23,127 output tokens, for 197,837 total
tokens. Cache creation and cache reads were both exactly zero. The minimized
owner-private evidence is retained for seven days and is bound by SHA-256 and
byte count in `result.json`; it is not committed.

On the 30 closed-pack blocks, combined used 15,250 total tokens versus
ordinary's 24,050: 8,800 fewer tokens, or 36.590437%, with both arms correct on
30/30. The corresponding list-price estimate was 34.415330% lower.

On the 30 realistic-fallback blocks, combined used 30,991 total tokens versus
ordinary's 29,295: 1,696 more tokens, or 5.789384%. Combined reduced input by
280 tokens but emitted 1,976 more output tokens, making its list-price estimate
20.515012% higher. Exact correctness was 1/30 for combined and 0/30 for
ordinary. This stratum therefore does not support promotion.

Across both strata, combined used 13.317087% fewer total tokens than ordinary,
but its list-price estimate was 1.105507% higher because output tokens are more
expensive and increased by 41.556257%. This is the key result: smaller context
did not translate into a lower estimated API bill for this frozen run.

The first observer configurations were deliberately excluded after bounded
preflights exposed truncated responses and an answer-byte limit that was too
small for valid end-turn explanations. They are not pooled, repaired, or used
in `result.json`. The final contract raised only the response allowance while
preserving the same frozen prompts, schedule, model, cache-off setting, scorer,
call cap, and spend cap.

All findings are descriptive for this small frozen synthetic corpus. They do
not establish generalized token savings, provider cost savings, external
validity, production readiness, or activation authority. P3 remains blocked on
authoritative fully loaded provider cost and the protected-omission result for
realistic fallback.
