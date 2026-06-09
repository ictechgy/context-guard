Fixture-only raw-output prompt for reversible output-transform A/B setup.

You are reviewing an already-sanitized command transcript. Treat this as synthetic benchmark input only.

Raw sanitized command output:
- command: python3 -m unittest sample_suite
- status: failed
- summary: one assertion failed in sample_test_alpha
- excerpt line 01: expected status ok
- excerpt line 02: actual status retry
- excerpt line 03: sanitized stack frame in sample_module
- excerpt line 04: sanitized assertion message
- excerpt line 05: sanitized context marker

Task:
1. Identify the failing command and failing check.
2. Explain whether the visible raw output is enough to diagnose the synthetic failure.
3. State that real token or cost comparisons require provider-measured telemetry on matched successful tasks, a failure-rate guardrail, human corrections, and shifted-cost accounting.

This prompt is not shipped benchmark evidence and does not claim hosted API savings.
