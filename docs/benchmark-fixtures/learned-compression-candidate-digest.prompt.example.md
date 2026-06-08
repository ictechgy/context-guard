Fixture-only candidate prompt for learned-compression experiment setup.

You are reviewing an already-sanitized compressed digest candidate. This is synthetic benchmark input only. No learned compressor, latent helper, embedding model, reranker, or provider call is shipped or invoked by this fixture.

Sanitized evidence only: private paths, endpoints, screenshots, secrets, raw credentials, and unsanitized logs do not belong in this fixture. Protected evidence no semantic rewrite: protected identifiers, constants, hashes, paths, quoted strings, stack frames, JSON keys, code fences, and diff zones must remain exact or receipt-retrievable.

Compressed digest candidate:
- candidate id: fixture-compression-alpha
- digest summary: sample_module.py branch returns retry after three attempts
- protected evidence preserved exactly: identifier `sample_status`, numeric constant `3`, quoted string `retry`, JSON key `status`, and stack frame label `sample_module:31`
- omitted protected context: sample_helper.py lines 1:80
- receipt fallback: fixture-receipt-alpha
- exact retrieval fallback: context-guard-pack slice --file sample_helper.py --lines 1:80

Task:
1. Decide whether required evidence is exact or receipt-retrievable.
2. Identify any protected evidence that would make semantic rewrite unsafe.
3. State that digest size, byte ratios, and receipt availability are proxy or retrieval evidence only, not hosted API token or cost savings evidence.
4. State that real comparisons require provider-measured primary token/cost fields on matched successful tasks, plus a failure-rate guardrail, human corrections, and shifted-cost accounting.

This prompt is dry-run-only fixture scaffolding and does not claim hosted API savings.
