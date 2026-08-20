# ContextGuard longitudinal matched study v1

This directory is the preregistered, closed protocol for measuring completed
high-quality work cost. `schedule.json` expands deterministically to 125 units:
five opaque independent project identities, five task strata, and baseline plus
Adaptive-only, Symbol-only, Graph-only, and combined arms. Changing any protocol
byte creates a different protocol identity; units may not be added or replaced.

The authoritative private observation keeps provider tokens, provider-billed
cost and billing status, calculated list price, local time/cost, retrievals,
corrections, exclusions, missingness, quality, failures, and receipt identities
distinct. Unavailable values are `null` with a reason and are never interpreted
as zero. Public reports contain aggregate counts only and never project locators
or provider receipt payloads. Project-cluster summaries are descriptive for this
finite frozen corpus; they provide no confidence interval, guarantee, external
validity, or generalized savings claim.

## Provider-free rehearsal

```sh
python3 scripts/longitudinal_study.py rehearse \
  --protocol research/longitudinal-study/v1 \
  --output /tmp/contextguard-longitudinal-rehearsal
python3 scripts/longitudinal_study.py resume \
  --protocol research/longitudinal-study/v1 \
  --output /tmp/contextguard-longitudinal-rehearsal
```

The rehearsal performs no network, credential, provider, or billing operation.
Its provider fields are unavailable, so its report cannot authorize a hosted
token or cost claim.

## Live preparation gate (not authorization)

Maximum protocol budget: **USD 250.00**. Before any provider call, separately
approve that maximum and create a private approval JSON binding
`schema_version=contextguard.longitudinal-budget-approval/v1`, the protocol
SHA-256 printed by `validate`, `maximum_budget_usd=250.00`, and
`provider_calls_approved=true`. Then the exact preparation command is:

```sh
python3 scripts/longitudinal_study.py live \
  --protocol research/longitudinal-study/v1 \
  --output /private/path/contextguard-longitudinal-live \
  --approval-file /private/path/budget-approval.json \
  --max-budget-usd 250.00
```

This repository intentionally has no live provider adapter. Even with a valid
approval, the command stops after verifying the gate and makes zero provider
calls. A separately reviewed adapter and a separate explicit budget approval
are required before live execution.
