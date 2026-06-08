Fixture-only baseline prompt for learned-compression experiment setup.

You are reviewing an already-sanitized context pack. This is synthetic benchmark input only. No learned compressor, latent helper, embedding model, reranker, or provider call is shipped or invoked by this fixture.

Sanitized evidence only: private paths, endpoints, screenshots, secrets, raw credentials, and unsanitized logs do not belong in this fixture. Protected evidence no semantic rewrite: protected identifiers, constants, hashes, paths, quoted strings, stack frames, JSON keys, code fences, and diff zones must remain exact or receipt-retrievable.

Sanitized context pack:
- pack id: fixture-pack-alpha
- source summary: sample_module.py lines 10:42 contain the decision branch
- protected evidence kept exact: identifier `sample_status`, numeric constant `3`, quoted string `retry`, JSON key `status`, and stack frame label `sample_module:31`
- omitted source: sample_helper.py lines 1:80
- exact retrieval fallback: context-guard-pack slice --file sample_helper.py --lines 1:80

Task:
1. Identify which source should be inspected next.
2. Explain which protected evidence must remain exact and not semantically rewritten.
3. State that real comparisons require provider-measured primary token/cost fields on matched successful tasks, plus a failure-rate guardrail, human corrections, and shifted-cost accounting.

This prompt is dry-run-only fixture scaffolding and does not claim hosted API savings.
