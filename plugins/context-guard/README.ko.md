# ContextGuard

ContextGuard는 AI 코딩·도구 에이전트를 위한 로컬 우선 컨텍스트 위생 도구 모음입니다. Claude Code 플러그인으로 가장 먼저 제공되며, 같은 프로젝트 로컬 가드레일을 일반 로컬 헬퍼 명령과 권고형 brief 모드 규칙 스니펫으로 다른 에이전트에도 확장합니다.

가장 먼저 `/context-guard:setup`을 실행하세요. 설정은 명시적이며, 프로젝트 단위로 적용되고, 되돌릴 수 있습니다. 권장 프로젝트 설정을 병합하고, 읽기 전용 컨텍스트 위생 검사 요약을 출력하며, 전역 Claude 설정은 변경하지 않습니다. 외부 AI에 작업을 넘기거나 대신 실행하도록 설정하지도 않습니다.

## 줄이려는 토큰 낭비 경로

ContextGuard는 provider prompt cache나 semantic answer cache가 아니라 로컬 컨텍스트 위생 계층입니다. 에이전트 대화에 들어가기 전에 큰 파일은 검색·심볼·줄 범위 읽기로 좁히고, 긴 명령 출력은 축약하거나 요약하며, 큰 로그는 로컬 아티팩트 요약 기록으로 남깁니다. 또한 민감 정보처럼 보이는 값과 경로를 최대한 가리고, Bash 실패가 반복되면 전략을 바꾸도록 알리며, 감사·벤치마크로 실제 작업의 전후 비교 근거를 남기도록 돕습니다.

## 리브랜딩 참고

Claude Code는 예전 `/claude-token-optimizer:*` 플러그인 슬래시 명령을 별칭으로 제공하지 않습니다. 설치 후에는 `/context-guard:*`를 사용하세요.

기존 자동화가 바로 깨지지 않도록 로컬 CLI 호환 래퍼(`claude-token-*`, `claude-read-symbol`, `claude-trim-output`, `claude-sanitize-output`)는 `bin/`에 계속 포함합니다.

## 스킬

설치 후 Claude Code 안에서 다음 스킬을 사용할 수 있습니다.

```text
/context-guard:setup
/context-guard:optimize
/context-guard:audit
```

| 스킬 | 용도 |
| --- | --- |
| `/context-guard:setup` | 처음 적용할 때 쓰는 프로젝트 설정 마법사입니다. |
| `/context-guard:optimize` | 컨텍스트 가드레일을 점검하고 조정합니다. |
| `/context-guard:audit` | 로컬 Claude 트랜스크립트의 토큰·비용 집중 지점을 확인합니다. |

## 헬퍼 명령과 PATH

기본 헬퍼 명령 접두사는 `context-guard-*`입니다. Claude Code 플러그인 스킬은 패키지에 포함된 헬퍼를 호출할 수 있지만, 일반 셸의 `PATH`에 플러그인 `bin/` 디렉터리가 자동으로 추가된다고 보장할 수는 없습니다.

이 저장소 루트에서는 경로를 직접 지정해 실행하세요.

```bash
./plugins/context-guard/bin/context-guard-setup --plan
./plugins/context-guard/bin/context-guard-diet scan . --json
```

로컬 개발 중 짧은 명령으로 실행하려면 현재 셸에 플러그인 bin 경로를 추가하세요.

```bash
export PATH="$PWD/plugins/context-guard/bin:$PATH"
context-guard-setup --plan
```

자주 쓰는 헬퍼는 다음과 같습니다.

```bash
context-guard-audit ~/.claude/projects --top 20 --recommend
context-guard-setup
context-guard-diet scan . --json
context-guard-artifact store --command "long-command" --json < large.log
context-guard-artifact get <artifact_id> --lines 1:80
context-guard-compress --json < large-output.txt
context-guard-trim-output --max-lines 120 -- npm test
context-guard-read-symbol path/to/file.py TargetSymbol
context-guard-sanitize-output -- rg -n "TOKEN|SECRET" .
context-guard-sanitize-output -- git diff
context-guard-statusline
context-guard-statusline-merged
```

## 헬퍼가 하는 일

- **설정 마법사**는 `.claude/settings.json`을 덮어쓰지 않고 병합한 뒤, 읽기 전용 `context-guard-diet scan` 요약을 출력합니다. 자동화에서 적용 후 검사 요약이 필요 없으면 `--no-diet-scan`을 사용하세요.
- **컨텍스트 위생 스캐너**는 누락된 `permissions.deny` 가드레일, Bash 출력 축약 훅, 상태표시줄 설정, 넓은 읽기 허용, 비용이 큰 기본 모델/추론 강도, 많은 MCP 서버, 크거나 민감해 보이는 에이전트 규칙 파일, bulky/sensitive 로컬 경로에 대한 자문형 context-exclusion 추천을 확인합니다.
- **대용량 읽기 가드와 심볼 리더**는 파일 전체 읽기 전에 검색, 심볼 구간, 작은 줄 범위 읽기 순서로 에이전트를 안내합니다. Python, JavaScript/TypeScript, Go, Rust 소스 구간 읽기를 지원합니다.
- **로컬 아티팩트 보관소**는 큰 명령 출력을 기본적으로 `.context-guard/artifacts`에 정제해 저장하고, 줄 번호가 있는 top error, 중복 라인 그룹, 정제된 bounded suggested query가 담긴 요약 영수증이나 요청한 정확한 줄 범위만 반환합니다. `get`과 `list`는 리브랜딩 이전의 `.claude-token-optimizer/artifacts` 영수증도 읽을 수 있습니다.
- **보수적 압축기**는 정제된 stdin을 JSON, diff, 로그, 검색 출력, 코드, 산문으로 분류하고, 관측 바이트 근거와 추정 토큰 proxy를 함께 노출합니다.
- **출력 축약기**는 감싼 명령의 종료 코드를 보존하면서 긴 로그를 줄이고, `--digest markdown` 또는 `--digest json`으로 실행기 실패 정보, 정제된 failure signature, 중복 라인 그룹, 다음 조회 제안이 담긴 요약을 만들 수 있습니다.
- **정제기**는 검색, diff, 로그 출력에서 자격 증명 패턴, 비공개 키 블록, 인증 헤더, 자격 증명이 포함된 URL, 민감해 보이는 경로를 가립니다.
- **상태표시줄**은 모델, 컨텍스트, 비용 신호를 짧게 보여주고, 트랜스크립트 데이터가 있으면 캐시 읽기와 캐시 재사용 신호도 함께 표시합니다.
- **반복 실패 알림**은 Bash 실패가 반복될 때 같은 경로를 계속 재시도하지 않고 전략을 바꾸도록 안내합니다.
- **벤치마크 헬퍼**는 기준/변형 실행을 대응해 실제 토큰·비용 필드, 별도의 바이트 감소 간접 증거, 진단용 `wall_time_seconds`, `provider_cached_tokens`, provider-cache 사용 가능성 텔레메트리로 기록합니다.

## brief 모드 (권고)

brief 모드는 코딩 에이전트가 군더더기를 줄이되 증거(파일 경로, 명령, 명령 출력과 오류, 코드 블록, 검증 상태, 변경 파일, 남은 과제, 주의사항)는 유지하도록 요청하는 에이전트 중립·권고형 규칙 스니펫을 제공합니다. 강제가 아니라 최선 노력 안내이며, 토큰·비용 절감을 **보장하지 않습니다.**

세 가지 결정적 레벨(`lite`, `standard`, `ultra`)이 [`brief/`](brief/)에 있습니다. 각 레벨은 마커로 구분된 하나의 블록이며, 에이전트의 규칙·지시 파일(`AGENTS.md`, `CLAUDE.md`, Cursor 규칙 파일, Copilot 지시 등)에 설치하고 블록을 지워서 제거합니다. 자세한 내용은 [`brief/README.md`](brief/README.md)를 참고하세요.

## 절감 수치를 과장하지 않습니다

이 헬퍼들은 흔히 컨텍스트를 불필요하게 키우는 원인을 줄이지만, 고정된 절감률을 보장하지 않습니다. 실제 전후 비교 증거가 필요하면 `context-guard-bench --ledger-jsonl ... --report-json ...`로 본인 작업에서 측정하세요. 토큰 절감 주장은 대응 태스크 양쪽 모두에 `primary_tokens_measured`가 있을 때만 계산하며, wall-time과 provider-cache 필드는 진단용 텔레메트리이지 단독 절감 증거가 아닙니다. 벤치마크 CSV 스키마는 엄격하므로 헬퍼 업그레이드 후에는 새 CSV를 시작하거나 헤더를 마이그레이션하세요.

ContextGuard는 모델 토큰을 줄이기 위해 작업을 외부 AI 서비스로 전송하지 않습니다. 모든 헬퍼 명령은 로컬에서 동작합니다.

교차 에이전트 규칙 스니펫은 권고 사항입니다. 대상 에이전트가 반드시 따른다고 보장할 수 없으므로, 절감 주장이 필요하면 실제 전후 동작을 직접 측정하세요.

## 로컬 배포 테스트

마켓플레이스 저장소 루트에서 실행합니다.

```bash
claude --plugin-dir ./plugins/context-guard
```

그다음 Claude Code 안에서 실행합니다.

```text
/context-guard:setup
```

마켓플레이스 설치 테스트:

```text
/plugin marketplace add ./
/plugin install context-guard@context-guard
```

## 라이선스

Copyright 2026 jinhongan. Apache License 2.0으로 배포됩니다. [LICENSE](LICENSE)와 [NOTICE](NOTICE)를 참고하세요.
