Fixture-only digest plus artifact receipt prompt for reversible output-transform A/B setup.

You are reviewing an already-sanitized digest and receipt. Treat this as synthetic benchmark input only.

Digest of sanitized command output:
- command: python3 -m unittest sample_suite
- status: failed
- failure summary: sample_test_alpha expected ok but saw retry
- omitted sanitized lines: 5

Artifact receipt:
- artifact id: fixture-artifact-alpha
- digest id: fixture-digest-alpha
- exact re-expand command: context-guard-artifact show fixture-artifact-alpha
- re-expand expectation: retrieves the omitted sanitized lines exactly from a user-supplied local artifact store

Task:
1. Identify the failing command and failing check.
2. Describe which exact re-expand step would retrieve the omitted sanitized lines.
3. State that artifact receipt metadata and byte counts are retrieval or proxy evidence only, not token or cost savings evidence.
4. State that real comparisons require provider-measured telemetry on matched successful tasks, a failure-rate guardrail, human corrections, and shifted-cost accounting.

This prompt is dry-run-only fixture scaffolding and does not claim hosted API savings.
