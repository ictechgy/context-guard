# P2 Codex subscription shadow contract

This directory prepares a separate Codex subscription replication of the
frozen G5 240-unit schedule. It does not reinterpret or replace the Claude Max
measurement. The exact runtime is Codex CLI `0.146.0`, model `gpt-5.6-luna`,
reasoning effort `low`, ephemeral mode, ignored user configuration and rules,
read-only sandboxing, no approvals, disabled web search, and an exact denylist
that turns off every available shell, code-host, browser, app, plugin, skill,
multi-agent, computer-use, image, and tool-suggestion feature used by this
contract.

The runner passes each frozen prompt through stdin so prompt text is absent
from process arguments. It accepts only the bounded Codex `--json` event
sequence, rejects any tool event, seals all 240 provider outputs before opening
the scorer, and publishes no prompt, response, thread identifier, credential,
environment value, or private path. The saved ChatGPT login is read only by the
pinned Codex executable after the one-use approval is consumed. Repository code
does not open or copy the authentication file: it creates a private, temporary
`auth.json` symlink inside an otherwise isolated `CODEX_HOME`, then removes that
link before publishing evidence. This excludes the operator's user config,
plugins, and personal skills from the model-visible run context.

Codex reports `input_tokens`, `cached_input_tokens`,
`cache_write_input_tokens`, `output_tokens`, and `reasoning_output_tokens`.
Cached and cache-write inputs are subsets of input, and reasoning output is a
subset of output. Therefore provider total tokens are exactly
`input_tokens + output_tokens`; the subset counters are never added again.

ChatGPT subscription usage has no per-request authoritative billing receipt and
the CLI event does not provide a stable conversion from these token counters to
subscription quota. This run can compare arms descriptively within the exact
Codex model and frozen corpus. It cannot establish dollar savings, subscription
quota savings, cross-provider equivalence, external validity, or activation
authority.

`live_runner.py` refuses direct execution. A new exact one-use external
approval must bind the 240-request stdin/argv plan, captured native executable,
minimal environment, official OpenAI destination set, private output root, and
retention window. The pinned executable is copied into a private single-link
inode before approval so a later mutable package-path replacement is not the
program that receives the saved login.

## 2026-08-17 result

The approved fixed schedule completed all 240 attempts. Codex returned 226
complete token receipts; 14 records were closed-schema exclusions, which
excluded ten complete four-arm blocks. The remaining analysis contains 200
units in 50 blocks. Across all complete receipts, provider total usage was
2,966,358 tokens: 2,930,904 input and 35,454 output. Cached input and reasoning
output remain subset counters and are not added again.

All 30 closed-pack blocks were analyzable. Combined used 202,643 total tokens
versus ordinary's 208,384, a descriptive reduction of 5,741 tokens
(2.755010%), with both arms correct on 29 of 30 units. Twenty
realistic-fallback blocks were analyzable. Combined used 178,332 tokens versus
ordinary's 401,695, a descriptive reduction of 223,363 tokens (55.605123%),
and was correct on 9 of 20 units versus ordinary's 0 of 20.

These are provider-specific frozen-corpus results, not generalized savings or
activation evidence. The ChatGPT subscription produced no authoritative
per-request billing receipt or subscription-quota conversion, so no dollar,
cost-savings, or quota-savings claim is made. `result.json` binds the private
evidence by hash and byte count without publishing its path or any prompt,
answer, thread, credential, or environment value. Any rerun still requires a
new exact one-use approval.
