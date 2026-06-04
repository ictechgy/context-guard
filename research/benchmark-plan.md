# Claude Code 토큰 절감 벤치마크 계획

목표: 절감 기법을 “느낌”이 아니라 **성공한 작업당 token/cost**로 평가한다.

## 1. 측정 지표

필수:

- total tokens
- input tokens
- output/thinking tokens
- cache read tokens
- cache creation tokens
- cost USD 또는 subscription usage delta
- model, effort, query_source(main/subagent/auxiliary)
- 작업 성공 여부: tests pass, build pass, reviewer accepted, human accepted 등

보조:

- tool call 수
- 읽은 파일 수
- hook trigger 수
- 원본/Claude-visible byte 수
- artifact/context escrow 사용 수
- auxiliary/subagent/provider token 및 cost
- auxiliary response preview chars / saved full response chars
- Bash output line 수
- `/context` 상위 카테고리
- human correction 횟수
- wall time

## 2. Task set

최소 12개 작업을 고정한다.

| 카테고리 | 예시 | 성공 기준 |
|---|---|---|
| 작은 수정 | 단일 파일 validation 추가 | targeted test pass |
| 중간 bugfix | 실패 test root cause 수정 | failing test -> pass |
| 탐색 | auth flow 요약 | reviewer factual check |
| code review | PR diff 리뷰 | seeded issue recall |
| 로그 분석 | 긴 CI log root cause | 정확한 failing command/file |
| migration | 파일 5개 API 변경 | build/typecheck pass |
| 문서 작업 | README 갱신 | spec coverage |
| UI/visual | screenshot 기준 수정 | visual diff/수동 승인 |

## 3. 실험군

A. Baseline

- 현재 사용자 기본 Claude Code 설정 그대로
- interactive long session 허용

B. Context hygiene

- 작업별 `/clear`
- prompt에 scope/검증 명시
- `/compact` focus 지시 사용

C. Model/effort routing

- `sonnet + effort medium`
- 어려운 planning만 `opusplan`

D. Output-budget hooks

- test/build/log 명령을 `trim_command_output.py`로 감싸기

E. Context diet

- `CLAUDE.md` 200줄 이하
- 긴 workflow는 skill로 이동
- unused MCP off
- deny generated/large dirs

F. Subagent isolation

- noisy 탐색/로그 분석만 subagent로 격리
- agent team 미사용

## 4. 실행 프로토콜

1. Claude Code 버전 기록: `claude --version`
2. 각 task 전 `/clear` 여부를 실험군에 맞춰 고정
3. prompt text를 파일로 저장해 반복 사용
4. 각 run 후 `/usage` 결과 또는 telemetry를 저장
5. 실패한 run은 실패로 기록하고, 재시도 token까지 포함한 “성공까지 총 비용”도 별도 계산
6. prompt cache 영향을 분리하려면 warm run/cold run을 나눠 2회씩 실행
7. artifact escrow, subagent, 기타 외부 실행 표면을 쓴 실험군은 `external_tokens`, `external_cost_usd`,
   `artifacts_used`를 함께 기록한다. primary cost가 줄어도 외부 비용으로 옮겨간 경우
   `total_cost_with_shift_usd` 기준으로 판정한다. 외부 token은 있지만 외부 cost가 측정되지
   않았으면 shifted-cost 절감을 주장하지 않는다.

## 5. 판정 기준

- 품질이 baseline과 같거나 더 좋은 경우만 절감으로 인정
- primary metric: `tokens_per_successful_task`
- secondary metric: `human_corrections_per_task`
- cost-shift metric: `total_cost_with_shift_usd = cost_usd + external_cost_usd`
- guardrail(source of truth for experimental radar): 실패율이 10%p 이상 상승하면 해당 절감 기법은 task class별 opt-in으로 격하
- report claim은 baseline에서 성공한 task가 variant에서도 성공한 matched task에 대해서만
  절감으로 인정한다. 성공 task set이 줄거나 실패율 guardrail을 넘으면 quality watch로 둔다.
- matched successful task에서 `human_corrections_per_task`가 baseline보다 늘어나면
  token/cost가 줄어도 quality watch로 둔다.
- 실패/재시도를 포함한 총량은 `tokens_per_task_including_failures` 및
  `total_cost_with_shift_per_task_including_failures_usd`로 별도 확인한다.
- byte reduction은 token/cost 절감의 proxy일 뿐이다. `bytes_before/bytes_after`가 줄어도
  실제 `total_tokens` 또는 shifted cost가 줄지 않으면 "절감"으로 인정하지 않는다.

## 6. 기대 결과 템플릿

```csv
date,claude_version,task_id,variant,model,effort,total_tokens,input_tokens,output_tokens,cache_read,cache_creation,cost_usd,cost_measured,turns,hook_triggers,bytes_before,bytes_after,artifacts_used,external_tokens,external_cost_usd,external_cost_measured,total_cost_with_shift_usd,success,corrections,notes
2026-05-01,2.x,t01,baseline,opus,xhigh,0,0,0,0,0,0,true,0,0,0,0,0,0,0,true,0,true,0,
```

`context-guard-bench --ledger-jsonl bench/cost-shift.jsonl --report-json bench/report.json`
를 사용하면 각 run의 cost-shift ledger와 baseline 대비 A/B report를 함께 남긴다. report의
`claim_status`는 실제 성공 run의 token/cost 지표를 기준으로 하며, byte 절감은 별도 caveat로
분리된다. cost field가 0이거나 없으면 token 절감만 별도 상태로 표시하고 shifted-cost
절감을 주장하지 않는다.

## 7. Experimental radar 연계

`experimental-token-reduction-radar.md`의 learned, multimodal, self-hosted lane은 이 문서의 matched successful task, failure-rate guardrail, human-correction tracking, shifted-cost accounting 원칙을 통과하기 전까지 hosted API token/cost 절감 주장으로 승격하지 않는다.
