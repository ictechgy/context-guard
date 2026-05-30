# ContextGuard

Claude Code 컨텍스트를 작고 집중된 상태로 유지하고, 크거나 민감한 출력이 Claude에 그대로 전달되는 일을 줄이는 Claude Code 플러그인과 로컬 헬퍼 도구 모음입니다.

영문 문서: [`README.md`](README.md)

## 한눈에 보기

플러그인을 설치하고 프로젝트에서 `/context-guard:setup`을 실행하면, 잡음 많은 명령 출력, 대용량 파일 읽기, 반복 실패, secret-like 검색·diff 결과에 대한 프로젝트 로컬 가드레일이 적용됩니다 — 전역 설정은 건드리지 않습니다.

이 프로젝트는 절감률을 보수적으로 다룹니다. 흔한 토큰 낭비 원인을 줄이는 도구를 제공하고, 실제 절감 여부는 각자의 작업에서 측정할 수 있도록 벤치마크 도구를 포함합니다. 모든 저장소에서 고정된 절감률을 보장하지는 않습니다.

## 제공 기능

- **Claude Code 플러그인** — 가이드 설정, 최적화, 사용량 감사를 위한 설치형 스킬을 제공합니다.
- **프로젝트 설정 마법사** — 전역 Claude 설정은 건드리지 않고 권장 `.claude/settings.json` 옵션을 프로젝트에 적용합니다.
- **컨텍스트 위생 스캐너** — 누락된 가드레일, 불필요한 출력을 유발하는 훅, 비용이 큰 기본값, 광범위한 읽기, 과도한 MCP 서버, 크거나 민감한 컨텍스트 파일을 진단합니다.
- **대용량 읽기 가드와 심볼 리더** — 파일 전체 읽기 대신 `rg`와 심볼·줄 범위 읽기를 사용하도록 안내합니다.
- **출력 압축 및 정제** — 테스트·빌드·검색·diff 출력을 줄이고, Claude에 전달하기 전에 민감한 값을 제거합니다.
- **조회 가능한 artifact escrow** — 큰 로그를 대화 밖 로컬 artifact에 저장하고, receipt나 필요한 정확한 slice만 다시 가져옵니다.
- **반복 실패 nudge** — 같은 Bash 실패가 반복되면 컨텍스트가 실패 로그로 부풀기 전에 전략 전환을 권유합니다.
- **상태표시줄, 트랜스크립트 감사, 벤치마크 헬퍼** — 토큰·비용·모델 상태, 사용량 집중 지점, 보수적인 before/after 증거를 확인합니다.

## Claude Code에서 설치

마켓플레이스를 추가하고 플러그인을 설치합니다.

```text
/plugin marketplace add ictechgy/context-guard
/plugin install context-guard@context-guard
```


설치 후 Claude Code 안에서 설정 마법사를 실행합니다.

```text
/context-guard:setup
```

사용 가능한 스킬:

```text
/context-guard:setup
/context-guard:optimize
/context-guard:audit
```

플러그인은 설치만으로 전역 훅을 자동 활성화하지 않습니다. 설정은 프로젝트 단위이며 사용자가 명시적으로 적용해야 합니다. 외부 AI 위임/offload도 설정하지 않습니다. 토큰 절감 헬퍼는 로컬에서 동작합니다. 예전 `/claude-token-optimizer:*` 플러그인 slash-command namespace는 Claude Code에서 alias되지 않으므로 설치 후에는 `/context-guard:*`를 사용하세요. 기존 자동화용 legacy CLI wrapper(`claude-token-*`, `claude-read-symbol`, `claude-trim-output`, `claude-sanitize-output`)는 `bin/`에 계속 포함됩니다. 예시는 `plugins/context-guard/examples/settings.example.json`을 참고하세요.

## 저장소에서 로컬 테스트

플러그인 디렉터리를 지정해 Claude Code를 실행합니다.

```bash
claude --plugin-dir ./plugins/context-guard
```

저장소 루트에서 마켓플레이스 설치를 테스트합니다.

```text
/plugin marketplace add ./
/plugin install context-guard@context-guard
```

플러그인 헬퍼 바이너리는 기본적으로 셸 `PATH`에 포함되지 않습니다. 로컬 테스트 시 경로를 직접 지정하세요.

```bash
./plugins/context-guard/bin/context-guard-setup --plan
./plugins/context-guard/bin/context-guard-setup --yes
```

개발 중 짧은 명령으로 실행하려면 플러그인 bin 경로를 현재 셸에 추가하세요.

```bash
export PATH="$PWD/plugins/context-guard/bin:$PATH"
context-guard-setup --plan
```

## 자주 쓰는 헬퍼 명령

기본 헬퍼 명령 prefix는 이제 `context-guard-*`입니다. 기존 자동화가 깨지지 않도록 legacy wrapper(`claude-token-*`, `claude-read-symbol`, `claude-trim-output`, `claude-sanitize-output`)도 `bin/`에 함께 남겨둡니다.

대부분의 사용자는 `/context-guard:setup`부터 시작하면 됩니다. 아래 명령은 로컬 테스트, 자동화, 특정 문제 진단에 유용합니다.

프로젝트 컨텍스트 위생 검사:

```bash
./plugins/context-guard/bin/context-guard-diet scan .
```

대용량 파일 전체 대신 심볼 단위로 읽기:

```bash
./plugins/context-guard/bin/context-guard-read-symbol path/to/file.py TargetSymbol
```

선택형 Read guard는 큰 파일에 대해 검색 → symbol slice → 작은 line range
순서의 progressive ladder와 가능한 경우 bounded top-level outline을 반환합니다.
같은 큰 파일 전체 읽기를 반복하면 repeated-read dedup 힌트도 추가됩니다.

큰 로그를 대화 컨텍스트 밖의 로컬 artifact로 저장하고 필요한 줄만 다시 조회:

```bash
long-command 2>&1 | ./plugins/context-guard/bin/context-guard-artifact store --command "long-command" --json
./plugins/context-guard/bin/context-guard-artifact get <artifact_id> --lines 1:80
```

파이프라인 모드는 capture/query 용도입니다. release check에서 producer 명령의
종료 코드가 중요하면 shell `pipefail` 또는 별도 `$?` 저장으로 직접 보존하세요.
종료 코드 보존이 핵심이면 `context-guard-trim-output -- ...` 래퍼를 쓰는 편이 안전합니다.

긴 테스트·빌드 로그를 줄이면서 원래 명령의 종료 코드 보존:

```bash
./plugins/context-guard/bin/context-guard-trim-output --max-lines 120 -- npm test
```

head/tail 로그 대신 더 작은 의미 요약만 필요하면 `--digest markdown` 또는
`--digest json`을 사용하세요. digest mode는 원래 종료 코드를 보존하면서
status, exit code, truncation count, runner failure facts, 대표 라인, redaction
count, 다음에 볼 query 제안을 남깁니다.

Claude에 전달하기 전에 검색·diff 출력 정제:

```bash
./plugins/context-guard/bin/context-guard-sanitize-output -- rg -n "TOKEN|SECRET" .
./plugins/context-guard/bin/context-guard-sanitize-output -- git diff
```

로컬 Claude 트랜스크립트 사용량 감사:

```bash
./plugins/context-guard/bin/context-guard-audit ~/.claude/projects --top 20 --recommend
```

audit 명령은 기본적으로 과도하게 큰 transcript 파일/JSONL record를 건너뛰며
(`--max-file-bytes`, `--max-line-bytes`) skip count를 보고합니다. 손상된 trace가
메모리를 독점하거나 scan gap을 숨기지 않게 하기 위한 방어입니다.

Claude Code 상태표시줄로 현재 컨텍스트와 캐시 상태를 빠르게 확인할 수 있습니다:

```text
[Sonnet] repo | main | ctx 86% ⚠ | cost $0.123 | cache 80% | reuse 8.0x
```

`cache N%`는 bounded transcript tail에서 관찰한 input-side token 중 cache read가
차지한 비율이며, cache read가 1회 이상 있을 때만 표시합니다. `reuse X.Yx`는
`cache_read / cache_creation`이며, cache read가 양수이고 cache creation이 0이
아닐 때만 표시합니다. `⚠` 표시는 context 사용률이 warning threshold에 도달했을
때 나타나며 기본값은 80%입니다. 프로젝트나 셸에서
`CONTEXT_GUARD_STATUSLINE_CTX_WARN=90`처럼 조정할 수 있습니다.

반복 가능한 A/B 토큰 절감 벤치마크와 cost-shift 증거 남기기:

```bash
./plugins/context-guard/bin/context-guard-bench \
  --tasks bench/tasks.json --variants bench/variants.json --csv bench/results.csv \
  --ledger-jsonl bench/cost-shift.jsonl --report-json bench/report.json
```

report는 성공한 baseline/variant run을 실제 token과
`cost_usd + external_cost_usd` 기준으로 비교합니다. byte 감소는 proxy 증거로만
기록하며, 그 자체를 절감 증명으로 보지 않습니다. cost field가 0이거나 없으면
token 절감만 표시하고 shifted-cost 절감은 주장하지 않습니다. claim은 matched
successful task 기준이며 실패율 guardrail이 나빠지면 quality watch로 낮춥니다.

## 이 도구가 하지 않는 일

- 고정된 토큰/비용 절감률을 보장하지 않습니다.
- Claude 토큰을 아끼기 위해 작업을 외부 AI provider로 보내지 않습니다.
- 설치만으로 전역 Claude 설정을 변경하지 않습니다.
- 절감률을 주장해야 하는 상황에서 실제 before/after 측정을 대체하지 않습니다.

## 저장소 구조

- `.claude-plugin/marketplace.json` — Claude Code 마켓플레이스 매니페스트
- `plugins/context-guard/` — 설치형 Claude Code 플러그인 패키지
- `context-guard-kit/` — 기반 Python/Bash 헬퍼 도구
- `tests/` — 헬퍼 동작 검증을 위한 회귀 테스트

## 릴리스 확인

릴리스에 민감한 변경을 배포하거나 머지하기 전에는 두 게이트를 모두 실행하세요:

```bash
python3 scripts/prepublish_check.py
python3 scripts/release_smoke.py
```

`prepublish_check.py`는 패키지 불변식, 동기화된 플러그인 바이너리, 매니페스트, 진단 메시지 redaction, 회귀 테스트를 확인합니다. `release_smoke.py`는 임시 프로젝트에서 `plugins/context-guard/bin`의 대표 패키징 엔트리포인트를 실제 실행해, 배포 전 깨진 CLI 연결을 잡습니다. 전체 릴리스 절차, 증거 체크리스트, quad-review 요구사항, 롤백 체크리스트는 [docs/release-runbook.md](docs/release-runbook.md)를 참고하세요.

버전별 릴리스 노트는 [CHANGELOG.md](CHANGELOG.md)에 기록하며, prepublish 게이트는 플러그인 매니페스트 버전과 일치하는 항목이 있는지 확인합니다.

## 라이선스

Copyright 2026 jinhongan. Apache License 2.0으로 배포됩니다. 자세한 내용은 [LICENSE](LICENSE)와 [NOTICE](NOTICE)를 참고하세요.
