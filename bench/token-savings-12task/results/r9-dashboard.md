# R9 frozen-suite dashboard

> **No token-savings claim is allowed.**

| Gate | Status |
| --- | --- |
| Verdict | `inconclusive` |
| Claim allowed | `false` |
| Complete pairs | `false` |
| Token upper bound strictly negative | `false` |
| Retry non-regression | `false` |
| Correction assessment | Not run |
| Subset analysis | Not run |

## Execution accounting

| Metric | Value |
| --- | ---: |
| Planned initial attempts | 72 |
| Consumed attempts | 33 |
| Successful attempts | 30 |
| Valid task failures | 3 |
| Fixed-policy retries | 2 |
| Assessment calls | 0 |

One arm-unit exhausted its fixed retry. That made complete paired success
unreachable, so execution stopped and the remaining authorized budget was not
spent. See the [full sanitized report](r9-summary.md) and
[machine-readable summary](r9-summary.json).
