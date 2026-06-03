# ContextGuard

ContextGuard는 AI 코딩·도구 에이전트를 위한 로컬 우선 컨텍스트 위생 도구 모음입니다. Claude Code 플러그인으로 가장 먼저 제공되며, 한 번 설치하고 프로젝트별로 적용한 뒤 필요하면 되돌릴 수 있습니다. 잡음 많은 명령 출력, 대용량 파일 읽기, 반복 실패 로그, 민감 정보로 보이는 값, 사용량 측정을 줄이는 같은 가드레일을 로컬 헬퍼 명령과 권고형 brief 모드 규칙 스니펫으로 다른 에이전트에도 확장합니다.

- 영문 문서: [`README.md`](README.md)
- HTML 랜딩 페이지: [GitHub Pages](https://ictechgy.github.io/context-guard/) ([소스](docs/index.html))

## 한눈에 보기

플러그인을 설치하고 프로젝트 안에서 `/context-guard:setup`을 실행하면, 전역 Claude 설정은 건드리지 않고 되돌릴 수 있는 프로젝트 로컬 가드레일을 적용합니다.

```text
/plugin marketplace add ictechgy/context-guard
/plugin install context-guard@context-guard
```

그다음 보호하려는 프로젝트에서 설정을 적용합니다.

```text
/context-guard:setup
```

ContextGuard는 절감 수치를 과장하지 않습니다. 흔히 컨텍스트를 불필요하게 키우는 원인을 줄이고, 실제 전후 비교 결과는 각자의 작업에서 측정할 수 있도록 벤치마크 도구를 제공합니다. 저장소마다 효과는 달라질 수 있으며, 고정된 토큰·비용 절감률을 보장하지 않습니다.

## Claude Code 우선, 다른 에이전트도 함께

ContextGuard는 Claude Code 플러그인으로 시작하는 것이 가장 빠릅니다. 설치 후에는 같은 로컬 우선 가드레일을 다음 방식으로 다른 AI 코딩·도구 에이전트에서도 재사용할 수 있습니다.

- **로컬 헬퍼 명령**(`context-guard-*`)은 특정 에이전트에 묶이지 않은 일반 셸 명령으로 실행됩니다.
- **권고형 brief 모드 규칙 스니펫**은 에이전트의 지시 파일(`AGENTS.md`, `GEMINI.md`, `.cursorrules`, Copilot 지시 파일 등)에 마커 블록으로 설치하고, 블록을 지우면 제거됩니다.
- **교차 에이전트 설정**은 먼저 dry-run으로 계획을 보여주고, 로컬 파일만 기록하며, 변경 전 백업하고, 명시적으로 승인한 경우에만 적용합니다.

현재 설정 표면은 다음과 같습니다.

| 에이전트 또는 도구 | ContextGuard 적용 방식 |
| --- | --- |
| Claude Code | 프로젝트 로컬 훅, deny 규칙, 상태표시줄 설정을 적용하는 네이티브 플러그인 설정. |
| OpenAI Codex CLI | 권고형 `AGENTS.md` 규칙 블록. |
| Gemini CLI | 권고형 `GEMINI.md` 규칙 블록. |
| Cursor | 보통 `.cursorrules`에 들어가는 권고형 프로젝트 규칙 블록. |
| Windsurf | 권고형 `.windsurf/rules/contextguard.md` 규칙 블록. |
| Cline | 파일·디렉터리 형태를 처리하는 권고형 `.clinerules` 규칙 블록. |
| GitHub Copilot Coding Agent | 권고형 `.github/copilot-instructions.md` 규칙 블록. |
| OpenCode, ForgeCode, 알 수 없는 에이전트 | 자동 훅 없이 로컬 셸 헬퍼와 로컬 증거를 수동으로 사용. |

## ContextGuard가 토큰 낭비를 줄이는 방식

ContextGuard는 모델 가격 자체를 낮추는 도구가 아닙니다. AI 코딩 에이전트 컨텍스트에 들어가기 전의 불필요한 입력을 줄이고, 그 효과를 직접 확인할 수 있는 신호를 제공합니다.

| 낭비 경로 | ContextGuard 가드레일 |
| --- | --- |
| 함수 하나를 찾으려고 파일 전체를 읽는 경우 | 파일 전체를 읽기 전에 검색, 심볼 단위 읽기, 제한된 개요, 작은 줄 범위 읽기를 먼저 제안합니다. |
| 긴 테스트·빌드·검색·diff 출력 | 출력을 축약하거나 구조화된 요약을 만들고, 큰 로그는 로컬에 저장한 뒤 짧은 요약 기록만 반환합니다. |
| 같은 실패 명령을 반복하는 경우 | Bash 실패가 반복되면 불필요한 실패 로그가 더 쌓이기 전에 전략을 바꾸도록 알립니다. |
| 민감하거나 잡음 많은 터미널 출력 | 자격 증명처럼 보이는 값과 민감해 보이는 경로를 패턴 기반으로 최대한 가립니다. |
| 어디서 토큰과 비용이 커지는지 모르는 경우 | 상태표시줄, 트랜스크립트 감사, 기준 실행과 변형 실행을 쌍으로 맞춰 비교한 벤치마크 리포트로 전후 비교 근거를 남깁니다. |

## 캐시·압축 도구와의 차이

ContextGuard는 provider 캐시, semantic cache, 프롬프트 압축 도구를 대체하지 않습니다. 역할은 **불필요한 파일·로그·출력이 처음부터 에이전트 컨텍스트에 덜 들어가게 하는 것**입니다.

| 도구 유형 | 줄이는 방식 | ContextGuard와의 관계 |
| --- | --- | --- |
| Provider prompt/context caching | 안정적인 프롬프트 앞부분을 재사용합니다. | 보완 관계입니다. ContextGuard는 자주 바뀌는 컨텍스트 뒷부분을 더 작고 깨끗하게 유지하도록 돕습니다. |
| Semantic response cache | 같거나 비슷한 요청의 이전 답변을 재사용합니다. | 보완 관계입니다. ContextGuard는 AI 답변 캐시를 제공하지 않습니다. |
| 프롬프트/컨텍스트 압축 | 이미 선택된 텍스트를 더 짧게 만듭니다. | 역할이 일부 겹칩니다. ContextGuard는 로컬 출력 축약과 요약을 제공하지만, 무손실 의미 압축을 보장하지 않습니다. |
| ContextGuard | 불필요한 파일, 로그, 반복 실패, 잡음 많은 출력이 에이전트 컨텍스트에 들어가기 전에 줄입니다. | 로컬 가드레일, 되돌릴 수 있는 아티팩트, 측정 도구입니다. |

설계에 참고한 관련 패턴은 다음과 같습니다.

| 접근 방식 | 강조점 | ContextGuard와의 관계 |
| --- | --- | --- |
| 압축 우선 | 모델에 이미 선택된 텍스트를 줄이며, 경우에 따라 손실형 변환을 사용합니다. | ContextGuard는 손실형 단방향 압축보다 로컬 아티팩트 저장과 정확한 줄·패턴 재조회를 선호합니다. 원본을 다시 가져올 수 있습니다. |
| 여러 에이전트의 간결 출력 규칙 | 여러 에이전트에 brief 모드 출력 규칙을 한꺼번에 설치합니다. | ContextGuard는 권고형 brief 모드 스니펫과 dry-run 교차 에이전트 설정을 제공합니다. 프로젝트별 opt-in이며, 절감을 보장하지 않습니다. |
| ContextGuard | 불필요한 파일·로그·출력이 컨텍스트에 들어가기 전에 줄이고 보수적으로 측정합니다. | 로컬 가드레일, 되돌릴 수 있는 아티팩트·재조회, 직접 측정하는 벤치마크 근거입니다. |

## brief 모드 (권고)

brief 모드는 코딩 에이전트가 군더더기를 줄이되 리뷰에 필요한 증거(파일 경로, 명령, 명령 출력과 오류, 코드 블록, 검증 상태, 변경 파일, 남은 과제, 주의사항)는 유지하도록 요청하는 에이전트 중립·권고형 규칙 스니펫 모음입니다. 강제가 아니라 최선 노력 안내이며, 토큰·비용 절감을 **보장하지 않습니다.**

세 가지 결정적 레벨이 [`plugins/context-guard/brief/`](plugins/context-guard/brief/)에 포함됩니다: `lite`, `standard`, `ultra`. 각 레벨은 마커로 구분된 하나의 블록이며, 에이전트의 규칙·지시 파일(`AGENTS.md`, `CLAUDE.md`, Cursor 규칙 파일, Copilot 지시 등)에 설치하고 블록을 지워서 제거합니다. 자세한 내용은 [`plugins/context-guard/brief/README.md`](plugins/context-guard/brief/README.md)를 참고하세요.

## 먼저 확인할 지표

절감 수치가 필요하면 실제 작업에서 직접 측정하세요.

- 전체 파일 읽기와 심볼·줄 범위 읽기의 차이
- 원본 로그와 요약 출력 또는 아티팩트 요약 기록의 차이
- `context-guard-audit`가 보고한 트랜스크립트 사용량 집중 지점
- 상태표시줄의 `cache` / `reuse` 값: ContextGuard가 직접 만든 절감 효과가 아니라 관찰된 트랜스크립트·provider cache 신호입니다.
- `context-guard-bench`로 성공한 기준/변형 실행을 쌍으로 맞춰 비교한 결과

## ContextGuard가 하지 않는 일

- 고정된 토큰·비용 절감률을 보장하지 않습니다.
- 모델 토큰을 줄이기 위해 작업을 외부 AI 서비스로 전송하지 않습니다.
- 설치만으로 전역 Claude 설정을 변경하지 않습니다.
- 절감 수치가 필요할 때 직접 전후 비교 측정을 대신하지 않습니다.
- 예전 `/claude-token-optimizer:*` Claude Code 슬래시 명령을 별칭으로 제공하지 않습니다. 설치 후에는 `/context-guard:*`를 사용하세요.

기존 자동화가 바로 깨지지 않도록 로컬 CLI 호환 래퍼(`claude-token-*`, `claude-read-symbol`, `claude-trim-output`, `claude-sanitize-output`)는 `bin/`에 계속 포함합니다.

## 제공 기능

| 기능 | 도움되는 상황 |
| --- | --- |
| Claude Code 플러그인 스킬 | 설정 마법사, 최적화 점검, 트랜스크립트 사용량 감사를 Claude Code 안에서 실행합니다. |
| 프로젝트 단위 설정 마법사 | 전역 설정은 그대로 두고 권장 `.claude/settings.json` 옵션을 프로젝트에 적용합니다. |
| 컨텍스트 위생 스캐너 | 누락된 가드레일, 잡음 많은 훅, 넓은 읽기 범위, 큰 컨텍스트 파일, 민감해 보이는 파일, 과도한 MCP 서버, 비용이 큰 기본값을 찾습니다. |
| 대용량 읽기 가드와 심볼 리더 | 파일 전체 읽기 대신 `rg`, 심볼 단위 읽기, 작은 줄 범위 읽기를 사용하도록 안내합니다. |
| 출력 축약과 정제 | 테스트·빌드·검색·diff 출력을 작게 만들고, 에이전트 컨텍스트에 들어가기 전에 민감 정보로 보이는 값을 가립니다. |
| 로컬 아티팩트 보관소 | 큰 로그를 대화 밖 로컬 저장소에 보관하고, 요약 정보나 요청한 줄 범위만 다시 가져옵니다. |
| 보수적 stdin 압축기 | 선택한 JSON, diff, 로그, 검색 출력, 코드, 산문을 관측 바이트 근거와 추정 토큰 proxy로 줄입니다. |
| 반복 실패 알림 | Bash 실패가 반복되면 실패 로그가 컨텍스트를 채우기 전에 전략을 바꾸도록 안내합니다. |
| 상태표시줄, 감사, 벤치마크 | 컨텍스트·캐시·비용 신호를 보여주고, 사용량 집중 지점을 찾고, 보수적인 전후 비교 증거를 남깁니다. |

## Claude Code에서 설치

마켓플레이스를 추가하고 플러그인을 설치합니다.

```text
/plugin marketplace add ictechgy/context-guard
/plugin install context-guard@context-guard
```

그다음, 보호하려는 프로젝트에서 Claude Code를 열고 설정 마법사를 실행합니다.

```text
/context-guard:setup
```

사용 가능한 플러그인 스킬은 다음과 같습니다.

| 스킬 | 용도 |
| --- | --- |
| `/context-guard:setup` | 처음 적용할 때 쓰는 프로젝트 설정 마법사입니다. |
| `/context-guard:optimize` | 컨텍스트 가드레일을 점검하고 조정합니다. |
| `/context-guard:audit` | 로컬 Claude 트랜스크립트의 토큰·비용 집중 지점을 확인합니다. |

설정은 명시적이며, 프로젝트 단위로 적용되고, 되돌릴 수 있습니다. ContextGuard는 외부 모델에 작업을 넘기거나 대신 실행하도록 설정하지 않으며, 모든 헬퍼 명령은 로컬에서 동작합니다. 예시 설정은 [`plugins/context-guard/examples/settings.example.json`](plugins/context-guard/examples/settings.example.json)을 참고하세요.

## 자주 쓰는 헬퍼 명령

대부분의 사용자는 `/context-guard:setup`부터 시작하면 됩니다. 아래 명령은 로컬 테스트, 자동화, 특정 문제 진단에 유용합니다. 기본 명령 접두사는 `context-guard-*`입니다.

### 컨텍스트 위생 검사

```bash
./plugins/context-guard/bin/context-guard-diet scan .
```

스캐너는 누락된 가드레일, 잡음 많은 훅, 넓은 컨텍스트 경로, 크거나 민감해 보이는 파일, AI 에이전트 세션 비용을 키울 수 있는 설정을 보고합니다.

### 대용량 파일을 심볼 단위로 읽기

```bash
./plugins/context-guard/bin/context-guard-read-symbol path/to/file.py TargetSymbol
```

선택형 Read 가드는 큰 파일에 대해 검색 → 심볼 구간 → 작은 줄 범위 순서의 단계적 축소 전략을 제안합니다. 가능하면 제한된 최상위 개요도 함께 보여줍니다. 같은 대용량 파일을 반복해서 전체 읽으려 하면 중복 읽기 경고를 표시해 같은 컨텍스트 낭비 경로를 반복하지 않게 합니다.

### 큰 로그를 로컬에 저장하고 필요한 부분만 조회

```bash
long-command 2>&1 | ./plugins/context-guard/bin/context-guard-artifact store --command "long-command" --json
./plugins/context-guard/bin/context-guard-artifact get <artifact_id> --lines 1:80
```

아티팩트 모드는 캡처·조회 용도입니다. 기본 저장 위치는 `.context-guard/artifacts`이며, 리브랜딩 이전의 `.claude-token-optimizer/artifacts` 영수증도 계속 읽을 수 있습니다. JSON 영수증에는 줄 번호가 포함된 top-error 영수증, 중복 라인 그룹, 정확한 `suggested_queries`가 들어가므로 에이전트가 전체 로그를 다시 넣지 않고 필요한 최소 slice만 조회할 수 있습니다. 릴리스 확인처럼 종료 코드가 중요한 파이프라인에서는 원래 명령의 종료 코드를 직접 보존하세요. 종료 코드 보존이 핵심이면 `context-guard-trim-output -- ...`을 사용하는 편이 안전합니다.

### 선택한 로컬 텍스트를 보수적으로 압축하기

```bash
git diff | ./plugins/context-guard/bin/context-guard-compress --json
pytest -q 2>&1 | ./plugins/context-guard/bin/context-guard-compress --type log
```

`context-guard-compress`는 정제된 stdin을 JSON, diff, 로그, 검색 출력, 코드, 산문으로 분류한 뒤 JSON compact, diff 컨텍스트 접기, 중복 로그·검색 라인 제거, 공백 정규화 같은 결정적 축소를 적용합니다. 모델 토큰 절감을 관측했다고 주장하지 않으며, 바이트 수는 관측값으로, 토큰 수는 추정치로 표시합니다. 손실형 영수증은 정확한 재조회를 위해 `context-guard-artifact store` 사용을 안내합니다.

### 명령 출력을 줄이거나 요약하기

```bash
./plugins/context-guard/bin/context-guard-trim-output --max-lines 120 -- npm test
```

head/tail 로그 대신 의미 요약이 필요하면 `--digest markdown` 또는 `--digest json`을 사용하세요. 요약 모드는 원래 종료 코드를 보존하면서 상태, 종료 코드, 잘린 줄 수, 실행기 실패 정보, 정제된 실패 signature, 중복 라인 그룹, 대표 라인, 정제 횟수, 다음 조회 제안을 남깁니다. 래핑된 명령은 기본 600초 뒤 종료되며, `--timeout-seconds`로 조정할 수 있습니다.

### 검색·diff 출력 정제

```bash
./plugins/context-guard/bin/context-guard-sanitize-output -- rg -n "TOKEN|SECRET" .
./plugins/context-guard/bin/context-guard-sanitize-output -- git diff
```

정제기는 토큰, 키, 비밀번호, 민감한 경로로 보이는 값이 에이전트 컨텍스트에 그대로 복사될 가능성을 줄입니다.

### 로컬 트랜스크립트 사용량 감사

```bash
./plugins/context-guard/bin/context-guard-audit ~/.claude/projects --top 20 --recommend
```

감사 명령은 기본적으로 너무 큰 트랜스크립트 파일과 JSONL 기록을 건너뛰고(`--max-file-bytes`, `--max-line-bytes`), 건너뛴 개수를 함께 보고합니다. 손상된 추적 기록이 메모리를 독점하거나 스캔 공백을 숨기지 않도록 하기 위한 방어입니다.

### 상태표시줄에서 컨텍스트와 캐시 상태 확인

```text
[Sonnet] repo | main | ctx 86% ⚠ | cost $0.123 | cache 80% | reuse 8.0x
```

`cache N%`는 최근 일정 범위의 트랜스크립트에서 관찰된 입력 토큰 중 cache read가 차지하는 비율이며, cache read가 1회 이상 있을 때만 표시됩니다. `reuse X.Yx`는 `cache_read / cache_creation` 값이며, cache read가 양수이고 cache creation이 0이 아닐 때만 표시됩니다. `⚠` 표시는 컨텍스트 사용률이 경고 기준에 도달했을 때 나타나며 기본값은 80%입니다. 프로젝트나 셸에서 `CONTEXT_GUARD_STATUSLINE_CTX_WARN=90`처럼 조정할 수 있습니다.

### 반복 가능한 벤치마크 실행

```bash
./plugins/context-guard/bin/context-guard-bench \
  --tasks bench/tasks.json --variants bench/variants.json --csv bench/results.csv \
  --ledger-jsonl bench/cost-shift.jsonl --report-json bench/report.json
```

보고서는 성공한 기준/변형 실행을 실제 토큰과 `cost_usd + external_cost_usd` 기준으로 비교합니다. 바이트 감소는 간접 증거로만 기록하며, 그 자체를 절감 증명으로 보지 않습니다. 토큰 절감 주장은 대응 태스크 양쪽 모두에 `primary_tokens_measured`가 있을 때만 계산합니다. `wall_time_seconds`, `provider_cached_tokens`, `provider_cached_tokens_measured`는 진단용 텔레메트리이며, ContextGuard가 직접 만든 토큰·비용 절감 증거로 보지 않습니다. 비용 필드가 0이거나 없으면 토큰 절감만 표시하고 실제 비용 절감은 주장하지 않습니다. 절감 주장은 양쪽 모두 성공한 태스크 대응 기준이며, 실패율 가드레일이 악화되면 경고 수준으로 조정합니다. CSV 스키마는 엄격하게 검사합니다. 벤치마크 헬퍼를 업그레이드한 뒤에는 새 `--csv` 파일을 시작하거나 mismatch 오류가 알려주는 헤더로 마이그레이션하세요. 최소 보고서 형태 예시는 [`docs/benchmark-report.example.json`](docs/benchmark-report.example.json)을 참고하세요.

## 아직 제공하지 않는 기능

아래는 프로젝트가 기록해 둔 방향이지 약속된 기능이 아닙니다. 저장소의 다른 문서에 명시되지 않는 한 아직 제공 기능이 아닙니다.

- 큰 `AGENTS.md`, `CLAUDE.md`, 프로젝트 규칙 파일을 찾는 지시문 비대화 검사
- 프롬프트 앞부분에 자주 바뀌는 내용이 들어가 provider cache 적중률을 낮추는지 확인하는 캐시 친화성 감사
- AI 컨텍스트에서 제외하면 좋은 파일을 제안하는 `ignore` 규칙 추천 생성
- 최소 보고서 형태 fixture를 넘어서는 작업 유형별 전후 비교 벤치마크 예시 모음

## 저장소 구조

- `.claude-plugin/marketplace.json` — Claude Code 마켓플레이스 매니페스트입니다.
- `plugins/context-guard/` — 설치형 Claude Code 플러그인 패키지입니다.
- `context-guard-kit/` — 기반 Python/Bash 헬퍼 도구입니다.
- `docs/index.html` — 프로젝트용 정적 랜딩 페이지입니다.
- `tests/` — 헬퍼 동작을 검증하는 회귀 테스트입니다.

## 로컬 개발

플러그인 디렉터리를 지정해 Claude Code를 실행합니다.

```bash
claude --plugin-dir ./plugins/context-guard
```

저장소 루트에서 마켓플레이스 설치를 테스트합니다.

```text
/plugin marketplace add ./
/plugin install context-guard@context-guard
```

플러그인 헬퍼 바이너리는 기본적으로 셸 `PATH`에 포함되지 않습니다. 로컬 테스트 시에는 전체 경로로 실행하세요.

```bash
./plugins/context-guard/bin/context-guard-setup --plan
./plugins/context-guard/bin/context-guard-setup --yes
```

개발 중 짧은 명령으로 실행하려면 플러그인 bin 경로를 현재 셸에 추가하세요.

```bash
export PATH="$PWD/plugins/context-guard/bin:$PATH"
context-guard-setup --plan
```

## 릴리스 확인

릴리스에 민감한 변경을 배포하거나 머지하기 전에는 두 게이트를 모두 실행하세요.

```bash
python3 scripts/prepublish_check.py
python3 scripts/release_smoke.py
```

`prepublish_check.py`는 패키지 불변식, 동기화된 플러그인 바이너리, 매니페스트, 진단 메시지 정제, 회귀 테스트를 확인합니다. `release_smoke.py`는 임시 프로젝트에서 `plugins/context-guard/bin`의 대표 패키징 엔트리포인트를 실제 실행해, 배포 전 깨진 CLI 연결을 잡습니다. 전체 릴리스 절차, 증거 체크리스트, quad-review 요구사항, 롤백 체크리스트는 [docs/release-runbook.md](docs/release-runbook.md)를 참고하세요.

버전별 릴리스 노트는 [CHANGELOG.md](CHANGELOG.md)에 기록하며, 사전 배포 게이트는 플러그인 매니페스트 버전과 일치하는 항목이 있는지 확인합니다.

## 라이선스

Copyright 2026 jinhongan. Apache License 2.0으로 배포됩니다. 자세한 내용은 [LICENSE](LICENSE)와 [NOTICE](NOTICE)를 참고하세요.
