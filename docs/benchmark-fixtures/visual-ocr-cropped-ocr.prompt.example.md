Fixture-only cropped/OCR prompt for multimodal crop/OCR experiment setup.

You are reviewing sanitized textual cropped/OCR-derived evidence only. This fixture contains no screenshot, image file, image URL, private path, endpoint, crop helper, OCR helper, visual-token helper, or provider call.

Cropped or OCR-derived evidence:
- original image dimensions telemetry: width 1200, height 800
- crop area telemetry: x 80, y 120, width 640, height 360
- visible area: checkout form region with validation text `Card number required`
- OCR text: `Card number required`; `Continue`
- OCR confidence telemetry: 0.96 for validation text; 0.92 for navigation label
- OCR error notes: footer notice omitted by crop; decorative icon ignored
- omitted context: footer notice `Sandbox order` and page-wide navigation are not visible in the crop
- missed-context guardrail: if the answer depends on omitted context, fall back to full visual evidence before judging success
- full visual fallback: rerun with baseline_full_visual_fixture evidence when OCR confidence is low, crop area excludes required context, or human correction is needed

Task:
1. Identify the navigation control associated with the visible validation error.
2. List any missed or omitted context that could change the answer.
3. State that crop area, OCR text, OCR confidence, and byte counts are proxy or telemetry evidence only, not hosted API token or cost savings evidence.
4. State that real comparisons require provider-measured image/text token or cost fields when available, matched successful tasks, failure-rate guardrail, human corrections, and shifted-cost accounting.

This prompt is dry-run-only fixture scaffolding and does not claim hosted API savings.
