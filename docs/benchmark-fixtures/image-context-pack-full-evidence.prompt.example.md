# Full sanitized textual evidence

Fixture-only baseline for one matched image-context-pack review task. The evidence below is caller-supplied sanitized text. It contains no image asset, image URL, binary payload, private path, or external service address.

Evidence:
- Review target: synthetic staging card `candidate-17`.
- Qualifying context: staging requires both the owner acknowledgement and the complete check result `all checks passed`.
- Owner acknowledgement: present.
- Complete check result: `all checks passed`.
- Decision: the sanitized evidence qualifies the card for plan review only.
- Missed context: none in this baseline.
- Full-text fallback: this entire narrative is declared available, but exact retrieval is not executed and therefore `verified=false`.

Boundaries:
- plan-only
- protected-zone deny
- no replacement
- no runtime
- no hosted claim
- no renderer call
- no OCR call
- no image-parser call
- no provider call
- no model call
- no network call
- no subprocess call

Byte counts in the companion row are sanitized textual UTF-8 byte proxies, never image bytes or provider tokens. The fixture does not establish token savings, cost savings, or quality non-inferiority.
