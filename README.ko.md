# ContextGuard

ContextGuard는 AI 코딩·도구 에이전트를 위한 로컬 우선 컨텍스트 관리 도구 모음입니다. Claude Code 플러그인으로 먼저 시작할 수 있으며, 한 번 설치한 뒤 프로젝트별로 명시적으로 활성화하고 필요하면 되돌릴 수 있습니다. 출력 축약, 심볼 단위 읽기 유도, 반복 실패 알림, 민감정보 패턴 가림, 사용량 측정 가드레일은 로컬 헬퍼 명령과 brief 모드 안내 스니펫을 통해 다른 에이전트에서도 재사용할 수 있습니다.

- 영문 문서: [`README.md`](README.md)
- HTML 랜딩 페이지: [GitHub Pages](https://ictechgy.github.io/context-guard/) ([소스](docs/index.html))

## 한눈에 보기

설치와 활성화는 의도적으로 분리되어 있습니다. 설치만 하면 로컬 헬퍼나 Claude 플러그인 스킬이 준비될 뿐이며, 설정 파일은 사용자가 `setup`을 명시적으로 실행할 때만 기록됩니다.

| 쓰는 도구 | 설치 | 활성화 |
| --- | --- | --- |
| Claude Code | `/plugin marketplace add ictechgy/context-guard` 후 `/plugin install context-guard@context-guard` | 프로젝트에서 `/context-guard:setup` 실행 |
| Codex CLI 또는 터미널 기반 에이전트 | `npm install -g @ictechgy/context-guard` 또는 일회성 `npx @ictechgy/context-guard ...` | `context-guard setup --agent codex --scope project --with-init --with-skill --plan` 확인 후 `--yes`로 적용 |
| Gemini/Cursor/Windsurf/Cline/Copilot | 위 npm/npx 설치 경로 사용 | 원하는 에이전트만 `context-guard setup --agent ... --scope project --with-init --plan`으로 확인 후 적용 |
| macOS/Homebrew 사용자 | 배포 경로: `brew install ictechgy/tap/context-guard` | 설치 후 같은 `context-guard setup ...` 명령 사용 |

자주 쓰는 명령은 다음과 같습니다.

```bash
npm install -g @ictechgy/context-guard
npx @ictechgy/context-guard --version
context-guard doctor --root . --json              # 읽기 전용 상태 점검; 변경 없음
context-guard setup --agent codex --scope project --with-init --with-skill --plan
context-guard setup --agent claude --scope user --verify --json  # 읽기 전용 사용자 범위 점검
context-guard setup --agent claude --scope user --plan
```

기본값은 프로젝트 단위 설정입니다. 사용자 단위 설정은 명시적으로 선택해야 하며, 실제 변경을 적용하려면 `--yes`와 명시적인 `--agent`가 필요합니다. 지원되는 사용자 단위 변경은 백업과 되돌리기 기록을 남기며, 패키지 설치 중에는 실행되지 않습니다. 적용 전에는 `context-guard doctor` 또는 `context-guard setup --verify`로 읽기 전용 상태를 먼저 확인하세요. `setup`은 먼저 패키지/체크아웃 내부 헬퍼를 찾습니다. 신뢰할 수 있는 설치임을 확인한 경우에만 `--allow-path-helper-fallback`으로 `PATH` 헬퍼 대체 경로를 허용하세요.

배포와 헬퍼 신뢰 경계도 보수적입니다. npm은 canonical `context-guard`/`context-guard-*` bin 링크만 노출하고 legacy `claude-*` 래퍼는 경로 기반 마이그레이션용 패키지 파일로만 남깁니다. 명령 매니페스트는 실행 가능한 Python이 아니라 literal 데이터로만 읽으며, macOS visibility 헬퍼는 번들/resource/실행 파일 기준 경로나 absolute explicit override만 사용하고 최소 환경으로 실행합니다. 현재 작업 디렉터리, 상대 override, symlink 헬퍼, 임의 `PATH`, 불필요한 상위 셸 환경은 기본적으로 신뢰하지 않습니다.

ContextGuard는 절감 수치를 과장하지 않습니다. 흔히 컨텍스트를 불필요하게 키우는 원인을 줄이고, 실제 전후 비교 결과는 각자의 작업에서 측정할 수 있도록 벤치마크 도구를 제공합니다. 저장소마다 효과는 달라질 수 있으며, 고정된 토큰·비용 절감률은 보장하지 않습니다.

## Claude Code 우선, 다른 에이전트도 함께

Claude Code 사용자는 플러그인으로 시작하는 것이 가장 빠릅니다. 설치한 뒤에는 같은 로컬 우선 가드레일을 다음 방식으로 다른 AI 코딩·도구 에이전트에서도 재사용할 수 있습니다.

- **로컬 헬퍼 명령**(`context-guard-*`)은 특정 에이전트에 묶이지 않은 일반 셸 명령으로 실행됩니다.
- **brief 모드 스니펫**은 에이전트의 지시 파일(`AGENTS.md`, `GEMINI.md`, `.cursorrules`, Copilot 지시 파일 등)에 마커 블록으로 설치하고, 블록을 지우면 제거됩니다.
- **여러 에이전트 설정**은 먼저 dry-run으로 계획을 보여주고, 로컬 파일만 대상으로 하며, 변경 전 백업을 남긴 뒤 명시적으로 승인한 경우에만 적용합니다.

현재 지원하는 연동 방식은 다음과 같습니다.

| 에이전트 또는 도구 | ContextGuard 적용 방식 |
| --- | --- |
| Claude Code | 프로젝트 로컬 훅, deny 규칙, 상태표시줄 설정을 적용하는 네이티브 플러그인 설정. |
| OpenAI Codex CLI | 안내용 `AGENTS.md` 규칙 블록과 선택형 `.agents/skills/context-guard/SKILL.md` 프로젝트 스킬. |
| Gemini CLI | 안내용 `GEMINI.md` 규칙 블록. |
| Cursor | 보통 `.cursorrules`에 들어가는 안내용 프로젝트 규칙 블록. |
| Windsurf | 안내용 `.windsurf/rules/contextguard.md` 규칙 블록. |
| Cline | 파일·디렉터리 패턴을 다루는 안내용 `.clinerules` 규칙 블록. |
| GitHub Copilot Coding Agent | 안내용 `.github/copilot-instructions.md` 규칙 블록. |
| OpenCode, ForgeCode, 알 수 없는 에이전트 | 자동 훅 없이 로컬 셸 헬퍼와 로컬 증거를 수동으로 사용. |

## ContextGuard가 토큰 낭비를 줄이는 방식

ContextGuard는 모델 단가 자체를 낮추는 도구가 아닙니다. AI 코딩 에이전트의 컨텍스트에 들어가기 전에 불필요한 입력을 줄이고, 그 변화가 도움이 됐는지 직접 확인할 수 있는 신호를 제공합니다.

| 낭비 경로 | ContextGuard 가드레일 |
| --- | --- |
| 함수 하나를 찾으려고 파일 전체를 읽는 경우 | 파일 전체를 읽기 전에 검색, 심볼 단위 읽기, 제한된 개요, 작은 줄 범위 읽기를 먼저 제안합니다. |
| 긴 테스트·빌드·검색·diff 출력 | 출력을 축약하거나 구조화된 요약을 만들고, 큰 로그는 로컬에 저장한 뒤 간결한 요약 기록만 반환합니다. |
| 같은 실패 명령을 반복하는 경우 | Bash 실패가 반복되면 불필요한 실패 로그가 더 쌓이기 전에 전략을 바꾸도록 알립니다. |
| 민감하거나 과도한 터미널 출력 | 자격 증명처럼 보이는 값과 민감해 보이는 경로를 패턴 기반으로 최대한 가립니다. |
| 어디서 토큰과 비용이 커지는지 모르는 경우 | 상태표시줄, 대화 기록 감사, 기준 실행과 변형 실행을 쌍으로 맞춰 비교한 벤치마크 리포트로 전후 비교 근거를 남깁니다. |
| Anthropic API 요청이 provider prompt cache 적중을 놓칠 수 있는 경우 | `context-guard cost preflight`가 호출 전 입력 크기, cache breakpoint별 위험, 낮음/중간/높음 비용 범위를 추정합니다. 기본값은 경고만 합니다. |
| 안정적인 프롬프트 앞부분보다 자주 바뀌는 컨텍스트가 먼저 오는 경우 | 제한된 범위의 가림 처리된 segment hash로 프롬프트 배치를 감사하여, 원문 프롬프트를 노출하지 않고 캐시에 불리한 배치 가능성을 알립니다. |
| 좁은 작업에 비해 큰 tool/MCP catalog가 들어가는 경우 | 로컬 tool catalog를 제한된 top-k schema report로 순위화하고, 전체 가림 처리된 schema는 로컬 요약 기록으로 다시 조회할 수 있게 합니다. |

## 캐시·압축 도구와의 차이

ContextGuard는 provider 캐시, semantic cache, 프롬프트 압축 도구를 대체하지 않습니다. 핵심 역할은 더 단순합니다. **불필요한 파일·로그·출력이 에이전트 컨텍스트에 들어가기 전에 줄어들도록 돕는 것**입니다.

| 도구 유형 | 줄이는 방식 | ContextGuard와의 관계 |
| --- | --- | --- |
| Provider prompt/context caching | 안정적인 프롬프트 앞부분을 재사용합니다. | 보완 관계입니다. ContextGuard는 자주 바뀌는 컨텍스트 뒷부분을 더 작고 깨끗하게 유지하도록 돕고, `context-guard-audit`로 프롬프트 배치를 점검하며, `context-guard cost`로 Anthropic 요청이 cache read 대신 cache write가 될 가능성을 미리 알릴 수 있습니다. |
| Semantic response cache | 같거나 비슷한 요청의 이전 답변을 재사용합니다. | 보완 관계입니다. ContextGuard는 AI 답변 캐시를 제공하지 않습니다. |
| 프롬프트/컨텍스트 압축 | 이미 선택된 텍스트를 더 짧게 만듭니다. | 인접한 역할입니다. ContextGuard는 로컬 출력 축약과 요약을 제공하지만, 무손실 의미 압축을 보장하지 않습니다. |
| 실험 planner/runtime | `image-context-pack`과 `semantic-checkpoint`는 plan-only gate로만 검토합니다. local proxy는 dry-run plan, external-forwarding design plan, gate record, one-shot loopback forwarding MVP로만 검토합니다. context-diff, visual evidence-pack, learned-compression, self-hosted metrics도 명시적 로컬 런타임만 지원합니다. | 모두 기본 비활성이며 명시적 명령이 필요합니다. `semantic-checkpoint`는 exact context fallback/re-expand, provenance review ack, provider-boundary ack, protected-zone denial, missed-context note가 있어야 JSON payload가 ready 상태가 됩니다. `record`는 listener·traffic forwarding·DNS lookup을 시작하지 않고, `serve local-proxy`는 literal loopback IP로 제한된 1회 요청만 bind/forward하며, `--response-sandbox`는 safe UTF-8 upstream body를 compact local artifact 재조회 envelope로 대체할 수 있습니다. 별도 근거 gate와 future PR gate 없이는 model/compressor 실행, OCR/crop service, external forwarding, credential persistence, runtime checkpoint replacement, hosted API 절감 주장으로 보지 않습니다. 자세한 내용은 “실험 기능 opt-in 관리” 섹션을 참고하세요. |
| ContextGuard | 불필요한 파일, 로그, 반복 실패, 과도한 출력이 에이전트 컨텍스트에 들어가기 전에 줄어들도록 돕습니다. | 로컬 가드레일, 되돌릴 수 있는 로컬 보관본, 측정 도구입니다. |

설계에 참고한 관련 패턴은 다음과 같습니다.

| 접근 방식 | 강조점 | ContextGuard와의 관계 |
| --- | --- | --- |
| 압축 우선 | 모델에 이미 선택된 텍스트를 줄이며, 경우에 따라 손실형 변환을 사용합니다. | ContextGuard는 손실형 단방향 압축보다 로컬 보관본 저장과 정확한 줄·패턴 재조회를 선호하므로, 원본을 다시 가져올 수 있습니다. |
| 여러 에이전트의 간결 출력 규칙 | 여러 에이전트에 brief 모드 출력 규칙을 한꺼번에 설치합니다. | ContextGuard는 안내용 brief 모드 스니펫과 dry-run 에이전트 간 설정을 제공합니다. 프로젝트별 opt-in이며, 절감을 보장하지 않습니다. |
| ContextGuard | 불필요한 파일·로그·출력이 컨텍스트에 들어가기 전에 줄어들도록 돕고 보수적으로 측정합니다. | 로컬 가드레일, 되돌릴 수 있는 로컬 보관본·재조회, 직접 측정하는 벤치마크 근거를 제공합니다. |

## brief 모드 (안내용)

brief 모드는 코딩 에이전트가 군더더기를 줄이도록 요청하되, 리뷰에 필요한 증거(파일 경로, 명령, 명령 출력과 오류, 코드 블록, 검증 상태, 변경 파일, 남은 과제, 주의사항)는 유지하도록 돕는 에이전트 중립·안내용 규칙 스니펫 모음입니다. 강제가 아니라 최선 노력 안내이며, 토큰·비용 절감을 **보장하지 않습니다.**

사전 정의된 세 레벨이 [`plugins/context-guard/brief/`](plugins/context-guard/brief/)에 포함됩니다: `lite`, `standard`, `ultra`. 각 레벨은 에이전트 규칙·지시 파일(`AGENTS.md`, `CLAUDE.md`, Cursor 규칙 파일, Copilot 지시 등)에 들어가는 마커 구분 블록입니다. `context-guard setup --agent codex --scope project --brief-mode standard --plan`으로 미리 보고, 적용은 `--yes`로 다시 실행하며, 제거는 `--brief-mode off`를 사용하세요. 자세한 내용은 [`plugins/context-guard/brief/README.md`](plugins/context-guard/brief/README.md)를 참고하세요.

## 직접 측정하는 방법

절감 수치가 필요하면 실제 작업에서 직접 측정하세요.

- 전체 파일 읽기와 심볼·줄 범위 읽기의 차이
- 원본 로그와 요약 출력 또는 로컬 보관 요약 기록의 차이
- `context-guard-audit`가 보고한 대화 기록 사용량 집중 지점, `cache_friendliness` 프롬프트 배치 신호, `cache_layout_advice` 실험 우선순위
- 상태표시줄의 `cache` / `reuse` 값: ContextGuard가 직접 만든 절감 효과가 아니라 관찰된 대화 기록·provider cache 신호입니다.
- `context-guard cost preflight`로 Anthropic 요청 JSON의 추정 비용을 보고, 호출 뒤 `context-guard cost observe`로 provider usage 필드(`cache_creation_input_tokens`, `cache_read_input_tokens`)를 대조합니다.
- `context-guard-cache-score`로 정적 cache layout과, 사용자가 직접 넣은 cache write/read multiplier 기반 amortization 위험을 안내받습니다. char/4 토큰 값은 provider 측정 절감이 아니라 추정 proxy입니다.
- `context-guard-bench`로 성공한 기준/변형 실행을 쌍으로 맞춰 비교한 결과
- 큰 tool/MCP catalog와 `context-guard-tool-prune` top-k 리포트 및 요약 기록 재조회 방식의 차이
- [`research/experimental-token-reduction-radar.md`](research/experimental-token-reduction-radar.md)의 선택적 실험 lane과 마찬가지로, [`docs/experimental-benchmark-fixtures.md`](docs/experimental-benchmark-fixtures.md)의 fixture-only 시작 예시도 절감 주장을 하려면 같은 matched-task benchmark gate를 먼저 통과해야 합니다.

## ContextGuard가 하지 않는 일

- 고정된 토큰·비용 절감률을 보장하지 않습니다.
- 모델 토큰을 줄이기 위해 작업을 외부 AI 서비스로 전송하지 않습니다.
- 설치만으로 전역 Claude 설정을 변경하지 않습니다.
- setup이나 패키징 smoke check에서 명령 매니페스트를 코드로 실행하거나 임의 `PATH`/현재 작업 디렉터리 헬퍼를 신뢰하지 않습니다.
- 절감 수치가 필요할 때 직접 전후 비교 측정을 대신하지 않습니다.
- 로컬 RAM/디스크 보관본은 다음에 보낼 컨텍스트를 줄이는 데 도움이 될 수 있지만 Anthropic provider prompt cache를 대체하거나 cache hit를 보장하지 않습니다. 배포나 청구 설명 전에는 Anthropic prompt caching/pricing 문서를 다시 확인하세요: https://docs.anthropic.com/en/build-with-claude/prompt-caching 및 https://platform.claude.com/docs/en/about-claude/pricing.
- 실험 헬퍼는 대부분 dry-run 안전성 checker/planner이며 plan-only `image-context-pack`/`semantic-checkpoint` 평가 gate와 design-only external-forwarding opt-in gate를 포함합니다. 명시적 로컬 runtime은 caller-supplied context-diff replacement payload, caller-supplied visual crop/OCR evidence pack, caller-supplied learned-compression prose candidate, self-hosted metrics JSONL sidecar 기록, local-proxy runtime-gate JSONL 기록, private ready-file nonce가 필요한 one-shot `serve local-proxy` loopback forwarding, safe UTF-8 응답을 compact artifact envelope로 바꾸는 optional `--response-sandbox`, successful forwarded request용 optional shifted-cost diagnostic JSONL row만 제공합니다.
- ContextGuard는 learned/synthetic compressor 실행·embedding·reranker·model call·생성형 replacement, screenshot 캡처·image crop·OCR 실행·image parsing·외부 OCR/image service, 명시적 local metrics 기록을 넘어선 self-hosted KV/latent inference optimization runtime, literal-loopback 1회 HTTP forwarding과 credential 차단을 넘어선 proxy forwarding은 제공하지 않습니다.
- 예전 `/claude-token-optimizer:*` Claude Code 슬래시 명령을 별칭으로 제공하지 않습니다. 설치 후에는 `/context-guard:*`를 사용하세요.

기존 자동화가 바로 깨지지 않도록 로컬 CLI 호환 래퍼(`claude-token-*`, `claude-read-symbol`, `claude-trim-output`, `claude-sanitize-output`)는 패키지 파일 `plugins/context-guard/bin/` 아래에 계속 포함합니다. npm global/`npx` bin 링크는 의도적으로 canonical `context-guard`/`context-guard-*` 명령만 노출하므로, legacy 래퍼가 필요하면 패키지/플러그인 경로로 호출하세요.

## 제공 기능

| 기능 | 도움되는 상황 |
| --- | --- |
| Claude Code 플러그인 스킬 | 설정 마법사, 최적화 점검, 대화 기록 사용량 감사를 Claude Code 안에서 실행합니다. |
| 프로젝트 단위 설정 마법사 | 전역 설정은 그대로 두고 권장 `.claude/settings.json` 옵션을 프로젝트에 적용합니다. |
| 컨텍스트 관리 스캐너 | 누락된 가드레일, 과도한 훅 출력, 넓은 읽기 범위, 큰 컨텍스트 파일, 민감해 보이는 파일, 과도한 MCP 서버, 비용이 큰 기본값을 찾습니다. |
| 구조적 낭비 진단 | 중복 규칙, stale import 후보, 쓰이지 않는 skill 후보, 과도한 tool schema, 반복 read/tool-call loop를 읽기 전용으로 진단합니다. |
| 대용량 읽기 가드와 심볼 리더 | 파일 전체 읽기 대신 `rg`, 심볼 단위 읽기, 작은 줄 범위 읽기를 사용하도록 안내합니다. |
| 출력 축약과 민감정보 가림 | 테스트·빌드·검색·diff 출력을 작게 만들고, 에이전트 컨텍스트에 들어가기 전에 민감해 보이는 값을 가립니다. |
| 선언형 출력 필터 | 사용자 정의 JSON DSL로 성공 출력만 명시적으로 줄이고, 보호해야 하는 실패 출력은 원문 stdout/stderr와 종료 코드를 보존합니다. |
| 로컬 로그 보관소 | 큰 로그를 대화 밖 로컬 저장소에 보관하고, 요약 정보나 요청한 줄 범위만 다시 가져옵니다. |
| Anthropic 비용 가드 | `context-guard cost preflight/observe/ledger/compile`이 cache 위험과 비용 범위를 추정합니다. `context-guard route-advisor`는 로컬 총비용과 batchability route 후보를 요약하며, ledger를 쓸 때도 원문 대신 keyed HMAC fingerprint만 저장합니다. `--enforce`를 명시하지 않으면 경고만 합니다. |
| 예산 기반 컨텍스트 패커 | 우선순위가 있는 로컬 파일 근거를 바이트 예산 안의 Markdown 팩으로 조립하고, 로컬 신호에서 `build`용 manifest를 추천하며, `--explain`, `--adaptive-k`, `--symbol-memory`로 로컬 자문 메타데이터를 덧붙일 수 있습니다. |
| Tool/MCP schema pruner | 로컬 catalog에서 bounded top-k tool/schema 자문 리포트를 만들고, compact 요약 기록과 전체 가림 처리된 payload 재조회 경로를 남깁니다. |
| 보수적 stdin 압축기 | 선택한 JSON, diff, 로그, 검색 출력, 코드, 산문을 줄이고, 관측 바이트 근거와 추정 토큰 proxy를 함께 표시합니다. `--mode readable`은 exact fallback 안내가 있는 opt-in 산문 preview를 추가합니다. |
| 보호 영역 정책 기록 | `context-guard-compress --protected-policy`와 `context-guard cost compile`이 코드·diff·path·hash·JSON/literal zone을 structural-only 변환 대상으로 표시하고 정확한 재조회 경계를 남깁니다. |
| 반복 실패 알림 | Bash 실패가 반복되면 실패 로그가 컨텍스트를 채우기 전에 전략을 바꾸도록 안내합니다. |
| 상태표시줄, 감사, 벤치마크 | 컨텍스트·캐시·비용 신호를 보여주고, 사용량과 캐시 친화성 집중 지점을 찾고, 보수적인 전후 비교 증거를 남깁니다. |

### 비용 가드 키 준비

비용 가드의 로컬 HMAC 키는 기본적으로 `.context-guard/cost-ledger/hmac.key`에 자동 생성됩니다. 관리자가 직접 주입하는 경우 파일에는 필수 padding을 포함한 canonical URL-safe base64 32바이트 키만 정확히 들어 있어야 하며, trailing newline이나 공백은 허용되지 않습니다. 리포트는 키와 원문 프롬프트를 출력하지 않으며, 로컬 ledger는 Anthropic/provider prompt cache를 대체하지 않습니다.

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
| `/context-guard:audit` | 로컬 Claude 대화 기록의 토큰·비용 집중 지점을 확인합니다. |

설정은 명시적이며, 프로젝트 단위로 적용되고, 되돌릴 수 있습니다. ContextGuard는 외부 모델로 작업을 위임하거나 외부에서 실행되도록 설정하지 않으며, 모든 헬퍼 명령은 로컬에서 동작합니다. 예시 설정은 [`plugins/context-guard/examples/settings.example.json`](plugins/context-guard/examples/settings.example.json)을 참고하세요.

## npm/npx로 설치

npm 패키지는 단일 `context-guard` 명령과 `context-guard-*` 헬퍼 명령을 함께 제공합니다. 설치는 수동적입니다. `postinstall`로 설정을 쓰지 않으며, 사용자가 직접 `context-guard setup`을 실행할 때만 프로젝트나 사용자 설정을 변경합니다. npm global/`npx` bin 링크는 의도적으로 canonical `context-guard`/`context-guard-*` 명령만 노출합니다. legacy `claude-*` 래퍼 파일은 명시적인 경로 기반 마이그레이션을 위해 패키지에 남지만 실행 bin 별칭으로 광고하지 않습니다. setup이 패키지/체크아웃 내부 헬퍼를 찾지 못해도 `PATH` fallback은 기본적으로 꺼져 있습니다. `context-guard doctor` 또는 `setup --verify`로 계획을 확인한 뒤 신뢰하는 헬퍼 디렉터리에 한해서만 `--allow-path-helper-fallback`을 사용하세요.

```bash
npm install -g @ictechgy/context-guard
context-guard --version
context-guard doctor --root . --json
context-guard setup --agent codex --scope project --with-init --with-skill --plan
context-guard setup --agent codex --scope project --brief-mode standard --plan
```

전역 설치 없이 한 번만 실행하려면 다음처럼 사용할 수 있습니다.

```bash
npx @ictechgy/context-guard setup --agent codex --scope project --with-init --with-skill --plan
npx @ictechgy/context-guard setup --agent codex --scope project --brief-mode standard --plan
npm exec @ictechgy/context-guard -- --version
```

`--scope project`는 `AGENTS.md`, `.agents/skills/...`처럼 저장소 안 파일에 적용합니다. `--scope user`는 전체 사용자 환경에 적용하려는 경우에만 의도적으로 사용하세요. 실제 적용에는 `--yes`와 명시적인 `--agent`가 필요하며, 지원되는 쓰기는 되돌리기 기록을 남깁니다.

## Homebrew 배포 경로

Homebrew는 공유 `ictechgy/tap` tap을 통해 macOS 배포 경로로 사용할 수 있습니다.

```bash
brew install ictechgy/tap/context-guard
context-guard --version
```

이미 `ictechgy/tap`을 tap했다면 `brew install context-guard`도 사용할 수 있습니다.

## 자주 쓰는 헬퍼 명령

대부분의 사용자는 `/context-guard:setup`부터 시작하면 됩니다. 아래 명령은 로컬 테스트, 자동화, 특정 문제 진단에 유용합니다. 기본 명령 접두사는 `context-guard-*`입니다.

### 설치 전 상태 점검

```bash
context-guard doctor --root . --json
context-guard setup --agent claude --scope user --verify --json
```

두 명령은 모두 설정을 변경하지 않는 읽기 전용 점검입니다. `doctor`는 권장 다음 명령을 보고하고, `setup --verify`는 설정을 적용하지 않은 채 완료 여부만 확인합니다. `--json` 모드는 결과를 stdout으로 출력합니다.

### 컨텍스트 관리 검사

```bash
./plugins/context-guard/bin/context-guard-diet scan .
```

스캐너는 누락된 가드레일, 과도한 훅 출력, 넓은 컨텍스트 경로, 여러 AI 에이전트 규칙 파일의 크거나 민감해 보이는 지시문/규칙 파일, 그리고 용량이 크거나 민감해 보이는 경로를 AI 컨텍스트에서 제외하기 위한 로컬 추천을 보고합니다. `--top`은 context-like file 목록과 context-exclusion 추천 목록에 공통으로 적용됩니다. 추천은 Claude `permissions.deny`로 나온 항목 외에는 휴리스틱/자문 성격입니다.

### 대용량 파일을 심볼 단위로 읽기

```bash
./plugins/context-guard/bin/context-guard-read-symbol path/to/file.py TargetSymbol
```

선택형 Read 가드는 큰 파일에 대해 검색 → 심볼 구간 → 작은 줄 범위 순서의 단계적 축소 전략을 제안합니다. 가능하면 제한된 최상위 개요도 함께 보여줍니다. 같은 대용량 파일을 반복해서 전체 읽으려 하면 중복 읽기 경고를 표시해 같은 컨텍스트 낭비 경로를 반복하지 않게 합니다.

### 큰 로그를 로컬에 저장하고 필요한 부분만 조회

```bash
long-command 2>&1 | ./plugins/context-guard/bin/context-guard-artifact store --command "long-command" --json
./plugins/context-guard/bin/context-guard-artifact search "ERROR" --json
./plugins/context-guard/bin/context-guard-artifact receipt <artifact_id> --json
./plugins/context-guard/bin/context-guard-artifact get <artifact_id> --lines 1:80
```

로컬 보관 모드는 캡처·sandbox 검색·조회 용도입니다. 기본 저장 위치는 `.context-guard/artifacts`이며, 리브랜딩 이전의 `.claude-token-optimizer/artifacts` 요약 기록도 계속 읽을 수 있습니다. JSON 요약 기록에는 줄 번호가 포함된 top-error 요약 기록, 중복 라인 그룹, 가림 처리된 범위 제한 `suggested_queries`, 안정적인 `contextguard-artifact:<id>` 핸들이 있는 `output_sandbox` envelope가 들어갑니다. `context-guard-artifact receipt <artifact_id> --json`으로 본문 없이 메타데이터/재조회 핸들만 다시 가져온 뒤, 전체 로그를 다시 넣지 않고 필요한 최소 범위만 정확하게 조회할 수 있습니다. `search`는 로컬 sanitized artifact sandbox를 literal substring으로 검색하고, bounded match/context record와 `context-guard-artifact get ... --lines START:END` 재조회 명령을 함께 반환합니다. custom `--dir` 값의 raw private path는 기본적으로 가림 처리되므로 같은 `--dir`로 다시 실행하거나, 직접 실행 가능한 local command가 꼭 필요할 때만 `search --show-paths`를 명시하세요. 이 검색 리포트는 local-only이며 hosted token/cost savings claim으로 해석하면 안 됩니다. 릴리스 확인처럼 종료 코드가 중요한 파이프라인에서는 원래 명령의 종료 코드를 직접 보존하세요. 종료 코드 보존이 핵심이면 `context-guard-trim-output -- ...`을 사용하는 편이 안전합니다.

### 예산 기반 컨텍스트 팩 만들기

```bash
./plugins/context-guard/bin/context-guard-pack auto \
  --root . \
  --query "failing tests review" \
  --diff HEAD \
  --manifest-out suggested-pack.json \
  --pack-out context-pack.md \
  --budget-bytes 12000 --json --explain --adaptive-k --symbol-memory
# 또는 명시적인 두 단계로 실행:
./plugins/context-guard/bin/context-guard-pack suggest \
  --root . --query "failing tests review" --diff HEAD \
  --manifest-out suggested-pack.json --budget-bytes 12000 --json --adaptive-k --adaptive-k-policy recall
./plugins/context-guard/bin/context-guard-pack build \
  --root . --manifest suggested-pack.json --budget-bytes 12000 --json
# 하나의 정확한 private local receipt와 선택적으로 진단 비교:
./plugins/context-guard/bin/context-guard-pack build \
  --root . --manifest suggested-pack.json --budget-bytes 12000 --json --no-artifact \
  --delta-from-pack-id 0123456789abcdef0123
./plugins/context-guard/bin/context-guard-pack slice --root . --path README.md --lines 1:40 --json
```

`context-guard-pack auto`는 추천 단계와 예산 기반 Markdown 팩 생성을 한 번에 실행하는 로컬 전용 경로입니다.

의도적인 경계는 다음과 같습니다.

- `--explain`을 추가하면 JSON 또는 텍스트 출력에 결정적 로컬 선택/build 이유를 짧게 포함합니다.
- JSON explain에는 bounded `repo_map`이 포함될 수 있습니다. 예시는 sampled byte/token-proxy tree, category-only secret risk count, signature-first hint, explain-only graph rank, 기존 `slice`/symbol 재조회 힌트입니다.
- repo-map은 manifest, pack 본문, receipt, byte budget을 바꾸지 않고 네트워크·모델 호출·임베딩을 쓰지 않습니다. 토큰 값은 provider-token이나 savings claim이 아닌 추정 `chars_div_4` proxy입니다.
- `suggest` 또는 `auto`에 `--adaptive-k`를 추가하면 로컬 score distribution, byte-budget fit, clamped score-mass 기반 recall/precision proxy에서 나온 advisory-only top-k shrink/expand metadata를 포함합니다. `--adaptive-k-policy balanced|recall|precision`과 선택적 `--adaptive-k-min-recall-proxy` / `--adaptive-k-min-precision-proxy` gate로 로컬 추천 정책을 고를 수 있고, gate 실패는 metadata-only(`pass|failed`)입니다. adaptive block은 capped selected/omitted evidence와 구조화된 source-verification hint를 포함하지만 추천값을 자동 적용하지 않으며 manifest, pack 본문, receipt, byte budget을 바꾸지 않습니다.
- `auto`에 `--symbol-memory`를 추가하면 repo-map 기반 symbol/graph advisory metadata와 정확한 `slice` / `read-symbol` 검증 힌트를 포함합니다. 이는 source verification 안내일 뿐이며 manifest, pack 본문, receipt, byte budget을 바꾸지 않습니다.
- `--manifest-out`은 `build`가 읽을 수 있는 manifest를 저장하고, `--pack-out`은 렌더링된 팩 본문을 저장합니다.
- `context-guard-pack suggest`는 더 낮은 수준의 로컬 전용 준비 단계입니다. `--query`, `--diff`, 반복 `--files`, 그리고 `--root` 아래의 선택적 `--output` / `--test-output` 텍스트 파일을 가림 처리한 신호에서 후보 파일과 줄 범위를 순위화한 뒤 `build --manifest`가 바로 읽을 수 있는 manifest를 씁니다.
- `context-guard-pack build`는 우선순위가 있는 로컬 파일 근거를 렌더링된 UTF-8 바이트 기준 `--budget-bytes` 안의 Markdown 팩으로 조립합니다. JSON 출력은 포함·부분 포함·중복·unsafe·missing·예산 초과로 누락된 source를 기록합니다.
- 모든 build는 정확히 렌더링된 pack byte의 `content_address`(`sha256:<digest>`)를 제공하면서 기존 `pack_id`는 유지합니다. `build` 또는 `auto`의 선택적 `--delta-from-pack-id PACK_ID`는 `.context-guard/packs/PACK_ID.json` 하나만 읽고 bounded/fail-soft `rolling_delta` 진단을 반환합니다. selection, pack 본문, `pack_id`, 기본 동작을 바꾸지 않으며 provider token/cost savings claim이 아닙니다. 진단은 `--json` 출력 또는 저장된 artifact receipt에서만 보고됩니다. `--no-artifact`를 쓰면 진단 보고에 `--json`이 필요하며, 기존 text stdout은 정확한 pack 본문을 그대로 유지합니다.
- 선택적 `build`/`auto --sketch-duplicate-veto`는 sanitizer를 거친 slice에 rank-stable pre-budget duplicate gate를 적용하며 `suggest`는 바꾸지 않습니다. 먼저 SHA-256 digest가 같은 후보를 byte 단위로 확인하고, 이후 Unicode casefold된 순서 보존 5-token shingle, 고정 length framing, bottom 64 unique digest, 양쪽 최소 cardinality 12, inclusive 0.90의 정직하게 명명된 sketch-set Jaccard heuristic을 사용합니다. 짧은 sketch는 exact-only입니다. eligible pair 100,000개를 검증한 뒤 실제로 처음 건너뛴 pair에서 fail open하고 이후 sketch 작업을 끄지만 exact digest/byte 확인은 계속합니다. 더 높은 rank의 winner도 최종 byte budget에 들어가지 않을 수 있으므로 편집하거나 근거로 의존하기 전에 누락 source 자체를 exact retrieval 하십시오. JSON/receipt은 standalone build 결과(또는 `auto.build`)의 `sketch_duplicate_veto.comparison_cap_reached`만 노출하고 omission reason은 `sketch_duplicate_source`이며, flagged text summary는 artifact 저장 실패와 무관하게 `sketch_comparison_cap_reached=true|false`를 붙입니다. fingerprint, match identity, overlap, score, provider token/cost savings claim은 내보내지 않으며 flag가 없으면 selection과 출력은 호환됩니다.
- 제한된 로컬 요약 기록은 `.context-guard/packs`에 저장됩니다. `path`와 `root`를 안전하게 표시할 수 있을 때만 정확한 가림 처리 slice 명령을 제공하고, 안전하지 않으면 팩 본문과 JSON 메타데이터에 `retrieval_omitted_reason`을 남깁니다.

표준 라이브러리 기반의 결정적 휴리스틱만 사용하며, 네트워크·모델 호출·임베딩·provider 비용 추정은 하지 않습니다. 바이트 수는 관측값이고, 토큰 수는 provider가 실제 측정한 토큰 절감값이 아니라 추정 `chars_div_4` proxy입니다.

### 작업에 맞게 tool/MCP catalog 줄이기

```bash
./plugins/context-guard/bin/context-guard-tool-prune select \
  --catalog tools.json \
  --query "review failing tests" \
  --top 5 --budget-bytes 12000 --json
./plugins/context-guard/bin/context-guard-tool-prune defer-report \
  --catalog tools.json \
  --query "review failing tests" \
  --core-top 3 --deferred-top 20 --json
./plugins/context-guard/bin/context-guard-tool-prune get <receipt_id> --tool read_file --json
```

`context-guard-tool-prune`은 로컬 tool 또는 MCP catalog를 결정적 lexical heuristic(어휘 기반 휴리스틱)으로 순위화해 제한된 top-k 자문 리포트를 만듭니다. inline schema는 관측된 UTF-8 바이트 예산을 지키고, 누락되거나 예산 때문에 생략된 schema는 `.context-guard/tool-prune`의 compact 요약 기록과 별도 가림 처리 payload로 다시 조회할 수 있습니다. `defer-report`는 core inline tool과 deferred tool stub/namespace 요약을 나누고, 첫 프롬프트에서 빠진 schema의 gross/net char/4 proxy 회계를 함께 보여줍니다. 이 기능은 안내용이며 MCP 설정이나 native provider tool search를 변경하지 않습니다. 토큰 값은 provider가 측정한 절감 수치가 아니라 추정 proxy입니다.

### 총비용, batchability, routing 후보 자문

```bash
./plugins/context-guard/bin/context-guard route-advisor --workload workload.json --json
./plugins/context-guard/bin/context-guard-cost route-advisor --feature batch_api=true --feature structured_outputs=true --json < workload.json
```

`context-guard route-advisor`는 로컬 passive advisor입니다. caller가 제공한 workload JSON, provider feature 선언, usage telemetry, 외부·로컬 shifted cost를 읽고 total-cost accounting, batchability blocker, batch API·prompt-cache prefix 보존·structured outputs·저비용 모델 평가 같은 route 후보를 출력합니다. queue를 시작하거나 provider를 호출하거나 pricing 문서를 새로 가져오지 않으며, provider feature는 caller-supplied 또는 unknown/recheck-required로 표시합니다. 추천은 후보일 뿐입니다. hosted token/cost 절감을 주장하려면 matched successful task, 비열등 quality gate, shifted-cost evidence가 필요합니다.

### 선택한 로컬 텍스트를 보수적으로 압축하기

```bash
git diff | ./plugins/context-guard/bin/context-guard-compress --json
pytest -q 2>&1 | ./plugins/context-guard/bin/context-guard-compress --type log
cat evidence.txt | ./plugins/context-guard/bin/context-guard-compress --json --protected-policy
cat sanitized-prose.txt | ./plugins/context-guard/bin/context-guard-compress --json --type prose --mode readable
```

`context-guard-compress`는 가림 처리된 stdin을 JSON, diff, 로그, 검색 출력, 코드, 산문으로 분류한 뒤 JSON compact, diff 컨텍스트 접기, 중복 로그·검색 라인 제거, 공백 정규화 같은 결정적 축소를 적용합니다. 모델 토큰 절감을 관측했다고 주장하지 않으며, 바이트 수는 관측값으로, 토큰 수는 추정치로만 표시합니다. 손실형 요약 기록은 정확한 재조회를 위해 `context-guard-artifact store` 사용을 안내합니다.

입력에 코드 펜스, diff, 식별자, 숫자 상수, 해시, 경로, 스택 프레임, 따옴표 문자열, JSON 키처럼 의미 보존이 중요한 구역이 있을 때는 `--protected-policy`를 추가하세요. 이 플래그는 기본 압축 동작을 바꾸지 않고, 의미·표현 변환을 거부하며 구조적 변환과 보관본 재조회만 허용하는 `protected_zone_policy`와 `transform_policy` 메타데이터를 추가합니다. 원문 보호 구간 대신 class/count 정책 메타데이터만 저장합니다.

`--mode readable`은 가림 처리된 산문 preview에만 사용하세요. 결정적 sentence window를 쓰고, prompt-like 또는 high-risk protected signal이 있으면 차단하며, raw protected span을 저장하지 않고 edit/claim 전에 exact fallback retrieval이 필요하다고 표시합니다. learned compressor, model, embedding, reranker는 실행하지 않습니다.

### 명령 출력을 줄이거나 요약하기

```bash
./plugins/context-guard/bin/context-guard-trim-output --max-lines 120 -- npm test
```

head/tail 로그 대신 의미 요약이 필요하면 `--digest markdown` 또는 `--digest json`을 사용하세요. 요약 모드는 원래 종료 코드를 보존하면서 상태, 종료 코드, 잘린 줄 수, 실행기 실패 정보, 가림 처리된 실패 signature, 중복 라인 그룹, 대표 라인, 가림 처리 횟수, 다음 조회 제안을 남깁니다. 요약 모드에서 가림 처리된 전체 출력을 로컬 `context-guard-artifact` 보관본에 저장하려면 `--artifact-receipt`를 함께 사용하세요. 출력된 `contextguard-artifact:<id>` 핸들을 agent context에 남기고, 생략된 세부 내용에 의존하기 전에 `context-guard-artifact receipt/get/search ...` 명령으로 필요한 부분을 정확히 다시 가져오세요. 래핑된 명령은 기본 600초 뒤 종료되며, `--timeout-seconds`로 조정할 수 있습니다.

### 검색·diff 출력 민감정보 가림

```bash
./plugins/context-guard/bin/context-guard-sanitize-output -- rg -n "TOKEN|SECRET" .
./plugins/context-guard/bin/context-guard-sanitize-output -- git diff
```

민감정보 가림 도구는 토큰, 키, 비밀번호, 민감한 경로로 보이는 값이 에이전트 컨텍스트에 그대로 복사될 가능성을 줄입니다.

### 로컬 대화 기록 사용량 감사

```bash
./plugins/context-guard/bin/context-guard-audit ~/.claude/projects --top 20 --recommend
```

감사 명령은 기본적으로 너무 큰 대화 기록 파일과 JSONL 기록을 건너뛰고(`--max-file-bytes`, `--max-line-bytes`), 건너뛴 개수를 함께 보고합니다. 손상된 추적 기록이 메모리를 독점하거나 스캔 공백을 숨기지 않도록 하기 위한 방어입니다.

JSON 출력에는 여러 증거 surface가 포함될 수 있습니다.

- `cache_friendliness`와 [`cache_diagnostics`](docs/cache-diagnostics-schema.md): 제한된 사용량 필드, timestamped cache telemetry records, 가림 처리된 segment hash로 만든 휴리스틱 프롬프트 배치/cache-read 진단입니다.
- `cache_layout_advice`: 긴 세션 분리, prefix 안정화 같은 순위화된 **확인/실험**으로 신호를 바꾸되, 관측된 issue와 가설/입증된 cause를 분리합니다.
- `--feasibility-json` / [`mac_visibility`](docs/mac-visibility-feasibility-schema.md): 로컬 macOS 가시화 surface가 바인딩할 수 있는 계약입니다. 안정적인 top-level field만 가리키며, `summary`는 primary UI binding 대상이 아닙니다.

이 필드들은 prompt prefix 근처의 volatile content 가능성, stable-prefix 후보, cache-miss 가설, TTL/headroom evidence gap을 알려줄 수 있습니다. 원문 프롬프트를 출력하지 않고 provider cache hit나 live headroom을 증명하지 않으며, 대화 기록 스키마가 충분한 증거를 드러내지 않으면 `missing`, `partial`, `hypothesis`, `unavailable`일 수 있습니다.

### 상태표시줄에서 컨텍스트와 캐시 상태 확인

```text
[Sonnet] repo | main | ctx 86% ⚠ | cost $0.123 | cache 80% | reuse 8.0x
```

`cache N%`는 최근 일정 범위의 대화 기록에서 관찰된 입력 토큰 중 cache read가 차지하는 비율이며, cache read가 1회 이상 있을 때만 표시됩니다. `reuse X.Yx`는 `cache_read / cache_creation` 값이며, cache read가 양수이고 cache creation이 0이 아닐 때만 표시됩니다. `⚠` 표시는 컨텍스트 사용률이 경고 기준에 도달했을 때 나타나며 기본값은 80%입니다. 프로젝트나 셸에서 `CONTEXT_GUARD_STATUSLINE_CTX_WARN=90`처럼 조정할 수 있습니다.

### 반복 가능한 벤치마크 실행

```bash
./plugins/context-guard/bin/context-guard-bench \
  --tasks bench/tasks.json --variants bench/variants.json --csv bench/results.csv \
  --ledger-jsonl bench/cost-shift.jsonl --report-json bench/report.json
```

보고서를 읽을 때는 먼저 주장 범위를 확인하세요.

- 성공한 기준/변형 실행은 실제 토큰과 `cost_usd + external_cost_usd` 기준으로 비교하고, 바이트 감소는 간접 증거로만 기록합니다.
- 토큰 절감 주장은 대응 태스크 양쪽 모두에 `primary_tokens_measured`가 있을 때만 계산합니다.
- `matched_pair_evidence`는 성공한 task bucket을 transform, 측정 가능 여부, quality gate, 주장 범위와 연결하므로 절감 문구를 쓰기 전에 먼저 확인해야 합니다.
- `default_matrix`는 같은 대응 evidence를 기반으로 trimming, artifact escrow, tool pruning, cache advice, adaptive-k, optional compression을 `default-on`, `advisory`, `experimental`, `reject/rework`로 분류합니다. 이 matrix는 report 전용이며 runtime default를 바꾸거나 hosted token/cost 절감 주장을 허용하지 않습니다.
- `public_claim_readiness`는 release/public claim의 최종 gate입니다. matched successful task, provider-measured primary token/cost, quality non-inferiority, shifted-cost accounting, 명시적 confidence/failure note, complete provider-export provenance가 모두 통과해야 `claim_allowed=true`가 되며, 그렇지 않은 hosted savings claim은 금지됩니다.
- `wall_time_seconds`, `provider_cached_tokens`, `provider_cached_tokens_measured`는 진단용 텔레메트리이며, ContextGuard가 직접 만든 토큰·비용 절감 증거로 보지 않습니다.
- 선택적 `self_hosted_metrics`는 run별 JSONL ledger sidecar로만 기록하고 CSV/report 요약에는 넣지 않으며, hosted API token/cost 절감 주장의 근거로 포함해서는 안 됩니다. `context-guard experiments plan self-hosted-metrics-ledger`는 이런 sidecar의 dry-run preview만 만들고 ledger 파일을 쓰지 않습니다.
- 비용 필드가 0이거나 없으면 토큰 절감만 표시하고 실제 비용 절감은 주장하지 않습니다.
- CSV 스키마는 엄격하게 검사합니다. 벤치마크 헬퍼를 업그레이드한 뒤에는 새 `--csv` 파일을 시작하거나 mismatch 오류가 알려주는 헤더로 마이그레이션하세요.

최소 보고서 형태 예시는 [`docs/benchmark-report.example.json`](docs/benchmark-report.example.json)을, 작업 유형별 합성 예시와 안전한 해석 경계는 [`docs/benchmark-workflow-examples.md`](docs/benchmark-workflow-examples.md)을, fixture-only 실험 시작 예시는 [`docs/experimental-benchmark-fixtures.md`](docs/experimental-benchmark-fixtures.md)을 참고하세요. live provider 실행 전 deterministic local replay가 필요하면 `--evidence-jsonl docs/benchmark-fixtures/token-savings-12task.evidence.example.jsonl --dashboard-md ... --baseline-variant baseline_full_context_fixture`를 사용하세요. Replay mode는 provider와 `success_command`를 실행하지 않고 CSV/report/dashboard를 만들지만 synthetic/manual evidence는 public hosted-savings claim 불가로 표시합니다.

### 실험 기능 opt-in 관리

실험 lane은 **기본 비활성**입니다. Registry는 프로젝트 로컬 의도와 메타데이터만 기록하며, `experiments enable`만으로 안정 런타임 동작이 켜지지 않습니다. 각 helper는 여전히 명시적인 실험 flag와 evidence boundary를 요구합니다.

```bash
context-guard experiments list
context-guard experiments status --json
context-guard experiments plan context-diff-compaction --json < change.diff
context-guard experiments emit context-diff-compaction --receipt-id <artifact-id> --reexpand-command "context-guard-artifact get <artifact-id> --full" --replacement-file compact-diff.txt --json < change.diff
context-guard experiments plan visual-crop-ocr --json --full-evidence-receipt <id> --crop-label <label> --crop-bounds 0,0,100,100 --image-size 800,600 --missed-context-note "outside crop omitted"
context-guard experiments emit visual-crop-ocr --json --full-evidence-receipt <id> --crop-label <label> --crop-bounds 0,0,100,100 --image-size 800,600 --ocr-text "visible text" --ocr-confidence 0.9 --ocr-error-note "glyph may be uncertain" --missed-context-note "outside crop omitted"
context-guard experiments plan image-context-pack --json --exact-text-fallback-receipt <id> --reexpand-command "context-guard-artifact get <id> --full" --provider-boundary-ack --protected-zone-policy deny --missed-context-note "omitted text remains retrievable before any future image pack is used" --image-size 800,600 --packed-image-size 400,300
context-guard experiments plan semantic-checkpoint --json --goal "preserve current task state for review" --constraint "do not rewrite protected evidence" --decision "ship plan-only semantic-checkpoint gate first" --open-task "verify exact fallback before any checkpoint is used" --evidence-handle "roadmap=contextguard-artifact:0123456789abcdef" --missing-provenance-note "none known after review" --unresolved-question "which provenance handle fields become mandatory later" --exact-context-fallback-receipt 0123456789abcdef --reexpand-command "context-guard-artifact get 0123456789abcdef --full" --provider-boundary-ack --protected-zone-policy deny --missed-context-note "raw transcript remains retrievable before checkpoint metadata is used"
context-guard experiments plan proof-carrying-context --json --proof-unit-json '{"source_label":"context-filesystem-roadmap","receipt_id":"0123456789abcdef","content_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","safe_range":{"kind":"lines","start":82,"end":85},"captured_at":"2026-07-10T04:11:12Z","transform_policy":"safe_range_extract","rehydrate_command":"context-guard-artifact get 0123456789abcdef --full"}' --provider-boundary-ack --protected-zone-policy deny
context-guard experiments verify proof-carrying-context --artifact-dir ./artifacts --proof-unit-json '{"source_label":"context-filesystem-roadmap","receipt_id":"0123456789abcdef","content_sha256":"12637068ee51f2ddfe27f1c00836a51cb54ba6a5cfca7f2301a4a45fbade2d14","safe_range":{"kind":"lines","start":1,"end":1},"captured_at":"2026-07-10T04:11:12Z","transform_policy":"safe_range_extract","rehydrate_command":"context-guard-artifact get 0123456789abcdef --full"}' --json
context-guard experiments plan learned-compression --json --sanitized --trusted-source --exact-fallback-receipt <id> --reexpand-command "context-guard-artifact get <id> --full" < sanitized-prose.txt
context-guard experiments emit learned-compression --json --sanitized --trusted-source --exact-fallback-receipt <id> --reexpand-command "context-guard-artifact get <id> --full" --replacement-file compact-prose.txt < sanitized-prose.txt
context-guard experiments plan self-hosted-metrics-ledger --json --latency-ms 123.5 --peak-memory-mb 2048 --quality-score 0.98
context-guard experiments record self-hosted-metrics-ledger --ledger-jsonl .context-guard/self-hosted-metrics.jsonl --latency-ms 123.5 --peak-memory-mb 2048 --quality-score 0.98 --json
context-guard experiments plan local-proxy --json --bind-host 127.0.0.1 --target-host 127.0.0.1 --runtime-gate-ack
context-guard experiments plan local-proxy-external-forwarding --external-forwarding-intent --external-forwarding-design-ack --allow-host api.example.com --allow-scheme https --credential-redaction-policy strip-sensitive-headers --provider-evidence-boundary diagnostic-only-provider-measured-required --threat-model-note "Only user-owned HTTPS endpoint; sensitive headers are stripped before any future forwarding." --json
context-guard experiments record local-proxy-runtime-gate --ledger-jsonl .context-guard/local-proxy-gates.jsonl --bind-host 127.0.0.1 --target-host 127.0.0.1 --runtime-gate-ack --json
context-guard experiments serve local-proxy --bind-host 127.0.0.1 --bind-port 18080 --target-host 127.0.0.1 --target-port 18081 --runtime-gate-ack --forwarding-gate-ack --once --ready-file .context-guard/local-proxy-ready.json --response-sandbox --response-artifact-dir .context-guard/artifacts --diagnostic-ledger-jsonl .context-guard/local-proxy-diagnostics.jsonl --json
context-guard experiments enable output-receipt-trim --root .
context-guard experiments disable output-receipt-trim --root .
```

`plan semantic-checkpoint`는 plan-only/eval-only gate입니다. CLI flag는 dry-run 검토를 위해 optional이지만, JSON payload에서는 goal, exact fallback receipt, local re-expand command, provider-boundary ack, protected-zone policy `deny`, missed-context note, provenance review note가 없으면 readiness blocker로 남습니다. re-expand command는 `context-guard-artifact get <id> --full` 또는 `context-guard artifact get <id> --full` 형태의 로컬 artifact 재조회만 허용합니다. `--missing-provenance-note`는 `none known after review` 같은 검토 확인 문구일 수 있습니다. 이 gate는 `emit`/`record`/`serve` runtime, 새 `context-guard-semantic-checkpoint` binary, file write, transcript/prompt edit, model/provider/network call, replacement context, hosted token/cost savings claim을 제공하지 않습니다.

`plan proof-carrying-context`는 기본 비활성 plan-only proof-envelope metadata readiness gate입니다. 반복 가능한 bounded inline JSON의 구문과 정의된 일관성만 검사하고 caller timestamp를 그대로 유지하며 현재 시간을 생성하거나 freshness를 비교하지 않습니다. Protected-zone policy는 선언 전용이고 range bounds, receipt storage, source content, SHA-256, timestamp freshness, rehydration은 검사하지 않은 warning으로 남습니다. Source/artifact/config/stdin content를 읽지 않고 file write, model/provider/network/subprocess call, context 생성·대체를 하지 않으며 `candidate_replacement`는 항상 `null`입니다. `emit`/`record`/`serve` runtime이나 새 binary도 없고 provider가 측정한 matched successful task 없이는 hosted token/cost savings claim을 허용하지 않습니다.

`verify proof-carrying-context`는 별도의 read-only local verifier입니다. 문서 fixture는 정확한 UTF-8 문자열 `ContextGuard proof fixture\n`(27 bytes, 1 line)이고 SHA-256은 `12637068ee51f2ddfe27f1c00836a51cb54ba6a5cfca7f2301a4a45fbade2d14`입니다. Verifier는 explicit artifact directory 하나만 사용하고 fallback search를 수행하지 않고 symlink를 follow하지 않으며, effective user 소유의 directory mode `0700`과 두 receipt leaf 모두 mode `0600`을 요구합니다. Bounded whole file을 읽어 receipt/proof hash, byte/line count, range bounds만 검증하고 range content는 retrieve/echo하지 않습니다. Exit `0`은 이 local binding만 통과했다는 뜻이고 exit `2`는 verification failure입니다. Timestamp freshness와 protected-zone semantics는 unchecked이고, rehydrate command는 syntax/receipt binding만 확인하며 실행하지 않습니다. `candidate_replacement`는 `null`이고 replacement, omission, hosted-savings claim 권한을 부여하지 않습니다.

local-proxy 예시는 side effect 기준으로 나뉩니다.

- `plan local-proxy`는 advisory metadata만 만들며 forwarding을 켜지 않습니다.
- `record local-proxy-runtime-gate`는 localhost-only gate row 하나만 append하고 listener 시작, traffic forwarding, API key 저장, hosted API 절감 주장을 하지 않습니다.
- `serve local-proxy`는 별도 MVP입니다. `--runtime-gate-ack --forwarding-gate-ack --once`와 private `--ready-file` nonce handoff가 모두 필요하고 literal loopback IP에만 bind/forward하며 byte/time limit을 적용하고 credential-bearing 요청, hostname DNS target, external forwarding, CONNECT/TLS proxying, API-key persistence, hosted savings claim을 차단합니다. Optional `--response-sandbox`는 transparent forwarding이 아니라 mediated response mode로, safe UTF-8 upstream response text만 sanitized local artifact receipt로 저장하고 `contextguard-artifact:<id>` 및 rehydration command가 담긴 compact JSON envelope를 반환합니다. binary/sensitive/oversized/blocked 응답은 artifact로 저장하지 않습니다.
- `--diagnostic-ledger-jsonl`을 지정하면 successful forwarded request 뒤에만 shifted-cost 진단 row를 append하며 raw header, request body, response body, hosted-savings evidence를 저장하지 않습니다.
- `plan local-proxy-external-forwarding`은 dry-run design gate일 뿐입니다. explicit external intent, design ack, HTTPS host allowlist, threat model note, credential redaction policy, provider-evidence boundary를 요구하지만 listener 시작, DNS lookup, external service call, traffic forwarding, credential persistence, external proxy forwarding runtime 제공, hosted savings claim을 하지 않습니다.

기본적으로 프로젝트 설정은 `.context-guard/experiments.json`에 저장됩니다. 명시적인 프로젝트 로컬 재정의가 필요할 때만 `--config <path>`를 사용하세요. 실험 메타데이터에는 risk level, gate requirement, explicit command/flag surface, 주장 범위가 포함되어 provider-measured matched-task evidence 없이는 hosted API token/cost savings claim으로 쓰지 않도록 합니다. `experiments enable`은 의도만 기록하며 helper를 실행하거나 명시 flag를 대체하거나 exact receipt/re-expand evidence 없는 content replacement를 허용하지 않습니다.

| 안전성 checker/planner/runtime | 출력하는 것 | 넘지 않는 경계 |
| --- | --- | --- |
| `context-diff-compaction` | dry-run diff 조언과 명시적 `emit ... --receipt-id ... --reexpand-command ...` 런타임으로 caller-supplied compact replacement를 출력합니다. | `plan`은 replacement를 emit하지 않습니다. `emit`은 reviewable hunk, input diff와 일치하는 exact local artifact content/re-expand metadata와 더 작은 caller-supplied replacement가 모두 있을 때만 동작하며, ContextGuard가 semantic compression을 생성하거나 hosted token/cost 절감 주장 근거로 쓰지 않습니다. |
| `visual-crop-ocr` | dry-run visual evidence 조언과 명시적 `emit visual-crop-ocr` 런타임으로 caller-supplied evidence pack을 출력합니다. | `emit`은 full visual evidence receipt, missed-context note, 완전한 user-supplied crop 및/또는 OCR evidence가 필요합니다. ContextGuard는 screenshot 캡처, image crop, OCR 실행, image parsing, 외부 service 호출, 파일 쓰기, hosted token/cost 절감 주장을 하지 않습니다. |
| `image-context-pack` | pxpipe-inspired image/context packing 평가를 위한 plan-only dry-run gate입니다. | 명시적 평가 의도, exact text artifact fallback, protected-zone denial, provider-measured matched-task boundary, missed-context guardrail, 그리고 `visual-crop-ocr`이 기존 caller-supplied visual evidence-pack surface라는 확인이 필요합니다. ContextGuard는 image rendering, OCR 실행, image parsing, model/provider call, proxy traffic, binary artifact 저장, replacement evidence 출력, hosted token/cost savings claim을 하지 않습니다. |
| `semantic-checkpoint` | 현재 작업 상태를 review용으로 보존할 준비가 되었는지 확인하는 plan-only/eval-only gate입니다. | CLI flag는 optional이지만 JSON readiness는 exact context fallback/re-expand, provider-boundary ack, protected-zone denial, missed-context note, provenance review note가 없으면 blocked입니다. `--missing-provenance-note`는 `none known after review` 같은 검토 확인 문구일 수 있습니다. ContextGuard는 file write, transcript/prompt edit, model/provider/network call, replacement context, `emit`/`record`/`serve` runtime, 새 binary, hosted token/cost savings claim을 하지 않습니다. |
| `learned-compression` | deny-by-default 정책 검사와 명시적 `emit learned-compression` 런타임으로 verified exact fallback content가 있는 caller-supplied compact prose candidate를 출력합니다. | `emit`은 sanitized trusted prose, protected-signal denial, input과 일치하는 verified local fallback artifact, 더 작은 caller-supplied prose candidate가 필요합니다. ContextGuard는 compressor, embedding, reranker, model call, subprocess, external service, 생성형 replacement, hosted savings claim을 실행/생성하지 않습니다. |
| `self-hosted-metrics-ledger` | dry-run preview와 명시적 `record ... --ledger-jsonl` 런타임으로 local/model-server latency, memory, quality, energy, throughput, local-cost metric을 기록합니다. | dry-run preview는 ledger 파일을 쓰지 않습니다. 명시적 record 명령만 로컬 JSONL sidecar를 쓰며, hosted API token/cost 절감 주장 근거로는 쓰지 않습니다. |
| `local-proxy` | 미래 local proxy 후보에 대한 localhost-only advisory metadata, future external forwarding용 design-only `plan local-proxy-external-forwarding` review, 명시적 `record local-proxy-runtime-gate --ledger-jsonl` gate row runtime, 명시적 one-shot `serve local-proxy` loopback forwarding MVP, safe UTF-8 응답을 compact artifact envelope로 바꾸는 optional `--response-sandbox`, successful forwarded request용 optional `--diagnostic-ledger-jsonl` shifted-cost diagnostics. | `plan`은 ledger를 쓰지 않습니다. `record`는 localhost-only metadata와 `--runtime-gate-ack`가 있을 때만 로컬 JSONL row를 쓰며 listener 시작이나 traffic forwarding, DNS lookup을 하지 않습니다. `serve`는 `--forwarding-gate-ack --once`, private `--ready-file` nonce handoff, literal loopback bind/target IP, nonzero port, byte/time limit, credential-free request가 필요하며 external forwarding, CONNECT/TLS proxying, API-key persistence, hosted API 절감 주장을 하지 않습니다. `--response-sandbox`는 safe UTF-8 response text만 sanitized local artifact receipt로 저장하고 raw body 대신 redacted rehydration command template가 담긴 compact envelope를 반환하며 hosted token/cost savings claim은 아닙니다. `--diagnostic-ledger-jsonl`은 successful-forward 진단 row만 쓰며 raw header/body와 hosted-savings claim을 저장하지 않습니다. `plan local-proxy-external-forwarding`은 threat model/allowlist/redaction/provider-evidence design metadata만 출력하고 DNS lookup, external service call, traffic forwarding, credential persistence, hosted savings claim을 하지 않습니다. |

## 아직 제공하지 않는 기능

아래 항목은 프로젝트가 기록해 둔 방향일 뿐, 약속된 기능이 아닙니다. 저장소의 다른 문서에 명시되지 않는 한 아직 제공 기능이 아닙니다.

ContextGuard는 아직 다음 기능을 제공하지 않습니다.

- caller-supplied learned candidate emitter를 넘어서는 learned/synthetic compressor 실행 또는 생성형 replacement
- caller-supplied visual evidence-pack emitter와 plan-only image-context-pack dry-run gate를 넘어서는 생성형 crop/OCR, visual-token pruning runtime, image-context-pack rendering/runtime
- plan-only semantic-checkpoint gate를 넘어서는 emit/record/serve runtime, replacement context, file-writing checkpoint store, transcript/prompt edit, provider/model/network-backed checkpointing, 새 `context-guard-semantic-checkpoint` binary
- 명시적 local metrics 기록을 넘어서는 self-hosted KV/latent optimization
- one-shot literal-loopback local proxy MVP를 넘어서는 external/daemon/credential-bearing proxy forwarding runtime

자세한 내용은 [experimental token-reduction radar](research/experimental-token-reduction-radar.md)와 [fixture-only experimental benchmark starters](docs/experimental-benchmark-fixtures.md)를 참고하세요. 이 항목들은 later-roadmap gate를 통과하기 전까지 제공 기능이 아닙니다. matched successful task, failure-rate guardrail, human-correction tracking, shifted-cost accounting, provider가 측정한 token/cost evidence와 별도 future PR gate가 있어야 hosted API 절감 주장이나 더 넓은 런타임 기능 주장으로 승격할 수 있습니다.

## 저장소 구조

- `.claude-plugin/marketplace.json` — Claude Code 마켓플레이스 매니페스트입니다.
- `plugins/context-guard/` — 설치형 Claude Code 플러그인 패키지입니다.
- `context-guard-kit/` — 체크아웃 로컬 Python/Bash 헬퍼 소스입니다. npm 패키지는 이 소스 트리를 중복 포장하지 않고 동기화된 `plugins/context-guard/bin` 및 `plugins/context-guard/lib` 복사본을 배포합니다.
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
./plugins/context-guard/bin/context-guard-setup --agent codex --brief-mode standard --plan
./plugins/context-guard/bin/context-guard-setup --yes
```

개발 중 짧은 명령으로 실행하려면 플러그인 bin 경로를 현재 셸에 추가하세요.

```bash
export PATH="$PWD/plugins/context-guard/bin:$PATH"
context-guard-setup --plan
```

생성되는 hook 명령은 기본적으로 `PATH` 조회에 의존하지 않습니다. setup 마법사는 명시적인 패키지/체크아웃 헬퍼 경로를 기록하며, `--allow-path-helper-fallback`은 신뢰한 외부 설치를 사용할 때만 canonical 경로·symlink 없음·bounded identity probe 검증 후 허용됩니다. macOS 앱 헬퍼도 같은 신뢰 모델을 따릅니다. launch CWD 탐색, 상대 override 경로, 필요한 allowlist 값을 넘어선 상위 셸 환경 상속을 사용하지 않습니다.

## 로컬 MCP 어댑터

`context-guard mcp`(또는 `context-guard-mcp`)는 의존성 없는 로컬 stdio MCP 서버입니다. 프로세스 하나는 root와 namespace 하나에 고정되며 compression, sanitization된 artifact 조회, 로컬 통계만 제공합니다. HTTP, SSE, 네트워크, provider, model, proxy, 자동 client 설정 기능은 없습니다. 저장되는 fallback은 원문이 아닌 정확한 sanitization 완료 사본이고 다른 namespace의 artifact는 조회할 수 없습니다. 이 로컬 어댑터는 hosted token/cost 절감을 주장하지 않습니다.

## 릴리스 확인

릴리스에 민감한 변경을 배포하거나 머지하기 전에는 동기화 확인과 두 게이트를 모두 실행하세요.

```bash
python3 scripts/sync_plugin_copies.py --check
python3 scripts/prepublish_check.py
python3 scripts/release_smoke.py
```

헬퍼가 `context-guard-kit/` 아래에서 바뀌었다면 게이트 전에 `python3 scripts/sync_plugin_copies.py --write`를 실행하세요. `sync_plugin_copies.py --check`는 maintainer exact-copy 계약을 먼저 확인합니다. npm 패키지는 구현 payload 중복을 피하기 위해 동기화된 플러그인 로컬 `plugins/context-guard/bin` 엔트리포인트와 `plugins/context-guard/lib` 헬퍼만 배포하며, npm bin map은 legacy `claude-*` 래퍼 별칭을 의도적으로 제외합니다. 명령 매니페스트는 release/runtime 확인에서 literal assignment로만 읽고, 실행 가능한 Python·import·function·shadow manifest는 거부합니다. `prepublish_check.py`는 패키지 불변식, 동기화된 플러그인 바이너리, 매니페스트, 진단 메시지 가림 처리, 회귀 테스트를 확인합니다. `release_smoke.py`는 임시 프로젝트에서 `plugins/context-guard/bin`의 대표 패키징 엔트리포인트를 실제로 실행해, 배포 전 깨진 CLI 연결을 잡습니다. 전체 릴리스 절차, 증거 체크리스트, quad-review 요구사항, 롤백 체크리스트는 [docs/release-runbook.md](docs/release-runbook.md)를 참고하세요.

버전별 릴리스 노트는 [CHANGELOG.md](CHANGELOG.md)에 기록하며, 사전 배포 게이트는 플러그인 매니페스트 버전과 일치하는 항목이 있는지 확인합니다.

### 실험적 semantic-GC plan gate

`semantic-gc`는 기본 비활성화된 deny 전용 계획 검토 gate입니다. 기본 비활성화는 registry intent를 뜻하며, 명시적 plan CLI는 계속 실행할 수 있지만 omission이나 runtime action을 활성화하지 않습니다. 전체 envelope나 graph topology가 모호하면 graph evaluation을 억제합니다. 도달할 수 없는 node는 semantic irrelevance의 증명이 아니라 검토 후보일 뿐이며 omission과 runtime action은 승인되지 않습니다. missed-context note는 신뢰되지 않은 입력입니다. 이 planner는 context/artifact 내용을 읽지 않고 provenance, fallback, provider, hosted 절감을 검증하지 않습니다. Exit 0은 `ready_for_plan_review`만 뜻하며 delete/omit 권한이 아닙니다.

context-guard experiments plan semantic-gc --json --context-unit-json '{"schema":"contextguard.semantic-gc-unit.v1","unit_id":"root","references":[],"is_root":true,"protected_zone":false}' --context-unit-json '{"schema":"contextguard.semantic-gc-unit.v1","unit_id":"orphan","references":[],"is_root":false,"protected_zone":false,"content_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","provenance":{"source_label":"canonical-example","receipt_id":"0123456789abcdef"},"missed_context_note":"A reviewer could lose the orphaned rationale.","exact_fallback_command":"context-guard-artifact get 0123456789abcdef --full"}' --provider-boundary-ack --human-review-ack --protected-zone-policy deny

## 라이선스

Copyright 2026 jinhongan. Apache License 2.0으로 배포됩니다. 자세한 내용은 [LICENSE](LICENSE)와 [NOTICE](NOTICE)를 참고하세요.
