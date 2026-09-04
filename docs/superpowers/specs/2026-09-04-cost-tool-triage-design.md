# ContextGuard 비용 도구 재조준 설계 (2026-09-04)

GLM, Grok, agy 세 모델의 외부 리뷰에서 합의된 5개 우선순위를 구현한다.
근거는 `HANDOFF.md`의 실측(cache_creation이 tool_result의 10.7배, 반복 읽기 0.47%,
중복 출력 0.6%)이다. provider-free 원칙은 유지한다. 절감 주장은 하지 않는다.

## 1. 측정을 비용의 본류로 옮긴다

- `context-guard-audit`: 턴별 `cache_creation`을 직전 tool_result의 도구 이름에
  귀속한 `new_tokens_by_tool` 표를 JSON과 텍스트에 추가한다. 관측값이며 인과
  증명이 아니라는 caveat를 함께 낸다. 가장 큰 도구를 가리키는 권고 1개를 낸다.
- 훅 저널: 새 helper `hook_journal.py`가 훅 호출마다 한 줄 JSONL을
  `.context-guard/hook-journal.jsonl`에 남긴다(훅 이름, 세션 해시, 경과 ms,
  입력/출력 바이트, 개입 여부, 보류한 바이트). 네트워크 없음, 1 MiB 상한 회전.
- `context-guard doctor`: 저널을 읽어 "훅 개입 N회, 보류 바이트 X, 훅 오버헤드 Y ms"
  한 줄 check를 낸다. 달러/토큰 절감으로 표기하지 않는다. statusline은 건드리지
  않는다(캐시 포맷 5곳 + merged whitelist 변경 비용 대비 가치 낮음).

## 2. 표면 정리

- plan-only 실험 절을 5개 README에서 `docs/experiments.md`로 옮기고 README에는
  3줄 링크만 남긴다. doc-parity 테스트는 새 문서를 가리키도록 바꾼다.
- `failed_attempt_nudge` 기본값을 off로 바꾼다(`--failed-attempt-nudge`로 opt-in).
- `context_compress`는 이미 기본 경로 밖이므로 변경 없음.
- MinHash sketch duplicate veto를 `context_pack.py`에서 제거하고 문서·테스트를
  정리한다. P3 live-contract 캐스케이드(4단계)와 protected-surface 핀을 갱신한다.
- legacy `claude-*` 래퍼 13개를 삭제하고 manifest, prepublish, release_smoke,
  훅의 wrapper 감지 목록, README를 정리한다.

## 3. 큰 출력 자동 escrow

- PreToolUse Bash 래퍼(`rewrite_bash_for_token_budget.py`)가 기본으로
  `--digest markdown --artifact-receipt`를 붙인다. 220줄 이하 출력은 그대로
  통과하고, 초과분만 로컬 artifact에 무손실 저장한 뒤 digest + 핸들 + 재조회
  명령을 돌려준다. 새 코드가 아니라 기존 `bash-reference-v1` 경로의 기본화다.

## 4. setup 단순화와 퀵스타트

- `--profile {minimal,recommended,max}`를 추가한다. minimal = deny + read guard,
  recommended = 현재 기본(nudge 제외), max = 모든 훅 + nudge + statusline.
  개별 `--no-*` 플래그는 예외 조정용으로 유지한다.
- `--dry-run`, `--allow-home-settings`는 파서에서 숨긴다(동작은 유지).
- `doctor`는 이미 `setup --verify`의 별칭이므로 문서만 한 곳으로 정리한다.
- 5개 README 최상단에 3줄 퀵스타트(install → setup → audit)를 둔다.

## 5. 훅 메시지와 세션 해제

- Read guard 거부 사유, nudge additionalContext를 각각 한 줄로 줄인다.
  형식: `[context-guard] <무엇> — <왜>. 끄기: context-guard hooks off <name>`.
- 새 helper `hook_switch.py`(`context-guard hooks off|on|status [read|bash|nudge|all]
  [--for 1h]`)가 `.context-guard/hooks-off.json`에 만료 시각을 기록하고, 세 훅은
  시작 시 이 파일을 읽어 해당 훅이면 no-op한다. 기본 만료 2시간.

## Gate-B

`failed_attempt_nudge.py`, audit/statusline/reducer, `setup_wizard.py`,
`context_guard_commands.py`, `release_smoke.py`는 동결 경로다. 이 브랜치의 gen20은
main의 gen20/gen21과 충돌하므로, 위 변경과 기존 audit 토큰 회계를 합쳐
origin/main 위에 **gen22** 하나로 재구성한다. 비동결 파일은 일반 커밋으로 먼저
올리고, 동결 파일은 gen22의 4개 reapply 커밋 안에서만 바뀐다.

## 검증

`python3 scripts/ci_test_gate.py core`, `python3 scripts/verify_gate_b_rollback.py`,
`python3 scripts/sync_plugin_copies.py`, protected-surface 테스트, GLM 리뷰.
