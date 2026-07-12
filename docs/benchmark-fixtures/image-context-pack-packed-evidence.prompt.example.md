# Packed sanitized textual evidence

Fixture-only variant for the same matched image-context-pack review task. The evidence below is caller-supplied sanitized text. It contains no image asset, image URL, binary payload, private path, or external service address.

Initial packed evidence:
- Review target: synthetic staging card `candidate-17`.
- Complete check result: `all checks passed`.
- Omitted qualifying context at first: the owner acknowledgement requirement and its value were absent from the initial pack.
- Initial decision: insufficient because the qualifying context was incomplete.

Synthetic human correction:
- One synthetic human correction states that staging also requires the owner acknowledgement and that it is present.
- After that correction, the same sanitized decision can be completed successfully.
- Missed context remains recorded rather than pretending the initial evidence was complete.
- Full-text fallback: the baseline narrative is declared available for review, but exact retrieval is not executed and therefore `verified=false`.

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

The companion row's artifact count is a synthetic declaration only with no artifact read. Byte counts are sanitized textual UTF-8 byte proxies, never image bytes or provider tokens. Success after one correction does not establish token savings, cost savings, or quality non-inferiority.
