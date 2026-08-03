# Frozen 12-task R9 result: inconclusive

> **No token-savings claim is permitted from this study.**

## Abstract

R9 tested the frozen ContextGuard treatment and baseline on the exact 12-task,
three-repetition suite bound to manifest
`e5f4548371cf03fb80e134093d9a6113c7e4c29d578c267925bdb3c6f873f1df`.
The result is **inconclusive**. A baseline arm-unit failed its initial attempt
and its sole fixed retry, so the required complete paired population became
unreachable. Execution stopped rather than spending the remaining budget on a
study that could no longer satisfy its predeclared success gate.

No favorable subset was analyzed, the exhausted unit was not launched again,
and a new stochastic study was not started to chase a different result.

## Outcome

| Field | Result |
| --- | --- |
| Planned initial attempts | 72 |
| Consumed attempts | 33 (31 initial, 2 fixed-policy retries) |
| Successful attempts | 30 |
| Valid task failures | 3 |
| Complete paired success | No |
| Token estimate / interval | Not computed |
| Retry estimate / interval | Not computed |
| Correction assessment | Not measured |
| Verdict | `inconclusive` |
| Claim | `null` |

The correction assessment was not run because its frozen unit is the complete
set of 72 successful terminal arm outputs. That population did not exist, and
scoring only the available outputs would be forbidden subset analysis.

## Predeclared method

- `P = input + cache creation + cache read + output`
- `C = sum(P for every consumed attempt through success)`
- `D = C(treatment) - C(baseline)`
- `Delta = mean_task(mean_repetition(D))`
- `I = 1` only when a successful arm-unit consumed more than one attempt;
  otherwise `I = 0`.
- `Gamma = mean_task(mean_repetition(I_treatment - I_baseline))`
- `S(v,t,r)` is the resolved correction severity and
  `K(v,t,r) = 1[S(v,t,r) > 0]` is correction incidence.
- `Theta_severity = mean_task(mean_repetition(S_treatment - S_baseline))`
- `Theta_incidence = mean_task(mean_repetition(K_treatment - K_baseline))`
- Correction packets use shuffle seed `0x434F525245435433`; no packets were
  generated because the complete 72-output population did not exist.
- Uncertainty uses SplitMix64-v1 seed `0x434F4E5445585447`, unsigned bounded
  rejection draws, 10,000 task-cluster resamples, and Hyndman-Fan Type 7
  quantiles.

The decisive contract required every one of the 36 paired units to succeed in
both arms within the fixed retry policy before `Delta`, `Gamma`, or correction
endpoints could support a verdict. R9 did not meet that prerequisite.

## Cost and provenance

- The analytic run's client-reported diagnostic estimate sums to
  `$4.50374909999999998`. It is not a provider billing export and does not
  establish cost savings.
- Conservative analytic authorization accounting is `$24.75` for 33 consumed
  calls at the frozen `$0.75` per-call ceiling.
- The discarded canary is excluded from analysis; its separate client estimate
  was `$0.2653266`.
- A prior invalid analytic attempt is excluded and retained separately at a
  conservative `$2.25`.
- Assessment provider calls and assessment spend were both zero.
- Local engineering and review overhead is tracked separately and is not converted
  into a lifecycle or break-even claim here.

## Claim boundary

This report records one frozen-suite quality failure. It does not show that the
treatment saves tokens, raises tokens, or generalizes beyond this manifest.
Correction burden is unmeasured, no provider billing export is joined, and the
required paired population is incomplete. The only supported public statement
is: **R9 was inconclusive, and no token-savings claim is allowed.**
