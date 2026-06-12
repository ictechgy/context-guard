# ContextGuard

ContextGuard는 AI 코딩·도구 에이전트를 위한 로컬 우선 컨텍스트 관리 도구 모음입니다. Claude Code 플러그인으로 먼저 사용할 수 있으며, 같은 프로젝트 로컬 가드레일을 일반 로컬 헬퍼 명령과 안내용 brief 모드 규칙 스니펫으로 다른 에이전트에도 확장합니다.

처음에는 `/context-guard:setup`을 실행하세요. 설정은 명시적이며, 프로젝트 단위로 적용되고, 되돌릴 수 있습니다. 권장 프로젝트 설정을 병합하고, 읽기 전용 컨텍스트 관리 검사 요약을 출력하며, 전역 Claude 설정은 변경하지 않습니다. 외부 AI에 작업을 넘기거나 대신 실행하도록 설정하지도 않습니다.

## 줄이려는 토큰 낭비 경로

ContextGuard는 provider prompt cache나 semantic answer cache가 아니라 로컬 컨텍스트 관리 계층입니다. 에이전트 대화에 들어가기 전에 큰 파일은 검색·심볼·줄 범위 읽기로 좁히고, 긴 명령 출력은 축약하거나 요약하며, 큰 로그는 로컬 보관 요약 기록으로 남깁니다. 또한 민감 정보처럼 보이는 값과 경로를 최대한 가리고, Bash 실패가 반복되면 전략을 바꾸도록 알리며, 제한된 가림 처리된 segment hash로 캐시 친화적 프롬프트 배치를 감사하고, 감사·벤치마크로 실제 작업의 전후 비교 근거를 남기도록 돕습니다.

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
| `/context-guard:audit` | 로컬 Claude 대화 기록의 토큰·비용 집중 지점을 확인합니다. |

## 헬퍼 명령과 PATH

대표 명령은 `context-guard`이며, 기존 호환 헬퍼는 `context-guard-*` 접두사를 유지합니다. Claude Code 플러그인 스킬은 패키지에 포함된 헬퍼를 호출할 수 있지만, 일반 셸의 `PATH`에 플러그인 `bin/` 디렉터리가 자동으로 추가된다고 보장할 수는 없습니다.

Codex나 다른 터미널 기반 에이전트에서는 npm 패키지를 설치하거나 npx로 한 번만 실행할 수 있습니다. 설치 자체는 설정 파일을 변경하지 않습니다.

```bash
npm install -g @ictechgy/context-guard
context-guard doctor --root . --json  # 읽기 전용 상태 점검; 변경 없음
context-guard setup --agent codex --scope project --with-init --with-skill --plan
context-guard setup --agent codex --scope project --brief-mode standard --plan
npx @ictechgy/context-guard --version
```

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
context-guard cost preflight --request request.json --budget-krw 3000 --json
context-guard cost observe --usage usage.json --json
context-guard-trim-output --max-lines 120 -- npm test
context-guard-read-symbol path/to/file.py TargetSymbol
context-guard-sanitize-output -- rg -n "TOKEN|SECRET" .
context-guard-sanitize-output -- git diff
context-guard-pack auto --root . --query "failing tests review" --diff HEAD --manifest-out suggested-pack.json --pack-out context-pack.md --budget-bytes 12000 --json --explain
context-guard-pack build --root . --manifest suggested-pack.json --budget-bytes 12000 --json
context-guard-pack slice --root . --path README.md --lines 1:40 --json
context-guard-tool-prune select --catalog tools.json --query "review failing tests" --top 5 --budget-bytes 12000 --json
context-guard-tool-prune get <receipt_id> --tool read_file --json
context-guard-statusline
context-guard-statusline-merged
```

## 헬퍼가 하는 일

- **설정 마법사**는 `.claude/settings.json`을 덮어쓰지 않고 병합한 뒤, 읽기 전용 `context-guard-diet scan` 요약을 보여줍니다. 자동화에서 적용 후 검사 요약이 필요 없으면 `--no-diet-scan`을 사용하세요.
- **컨텍스트 관리 스캐너**는 누락된 `permissions.deny` 가드레일, Bash 출력 축약 훅, 상태표시줄 설정, 넓은 읽기 허용, 비용이 큰 기본 모델/추론 강도, 많은 MCP 서버, 크거나 민감해 보이는 에이전트 규칙 파일, 부피가 크거나 민감해 보이는 로컬 경로에 대한 자문형 context-exclusion 추천을 확인합니다.
- **대용량 읽기 가드와 심볼 리더**는 파일 전체 읽기 전에 검색, 심볼 구간, 작은 줄 범위 읽기 순서로 에이전트를 안내합니다. Python, JavaScript/TypeScript, Go, Rust 소스 구간 읽기를 지원합니다.
- **로컬 로그 보관소**는 큰 명령 출력을 기본적으로 `.context-guard/artifacts`에 가림 처리해 저장하고, 줄 번호가 있는 top error, 중복 라인 그룹, 가림 처리된 bounded suggested query가 담긴 요약 기록이나 요청한 정확한 줄 범위만 반환합니다. `get`과 `list`는 리브랜딩 이전의 `.claude-token-optimizer/artifacts` 요약 기록도 읽을 수 있습니다.
- **예산 기반 컨텍스트 패커**는 우선순위가 있는 로컬 파일 근거를 렌더링된 바이트 예산 안의 Markdown pack으로 조립하고, 포함·부분 포함·누락 source 메타데이터, bounded `.context-guard/packs` 요약 기록, 안전할 때만 정확한 가림 처리 `slice` 명령, 안전하지 않을 때의 `retrieval_omitted_reason`을 남깁니다. 추가된 `auto` 하위 명령은 추천과 pack build를 한 번에 실행하고, `auto --explain`은 manifest, pack 본문, receipt, byte budget을 바꾸지 않으면서 결정적 로컬 선택/build 이유를 짧게 추가합니다. JSON explain의 bounded repo-map은 sampled byte/token-proxy tree, category-only secret risk count, signature-first hint, explain-only graph rank, 기존 `slice`/symbol 재조회 힌트를 제공하지만 pack 선택이나 provider savings claim은 아닙니다. `suggest`는 로컬 query, diff, 명시 파일, 가림 처리된 output/test-output 신호를 `build`와 호환되는 manifest로 순위화하며 네트워크·모델 호출·임베딩·provider 비용 추정은 하지 않습니다. 토큰 수는 측정된 provider token 절감이 아니라 추정 `chars_div_4` proxy입니다.
- **Tool/MCP schema pruner**는 로컬 tool catalog를 bounded top-k 자문 리포트로 순위화하고, compact 요약 기록과 payload integrity check로 전체 가림 처리된 schema 재조회를 보존합니다.
- **보수적 압축기**는 가림 처리된 stdin을 JSON, diff, 로그, 검색 출력, 코드, 산문으로 분류하고, 관측 바이트 근거와 추정 토큰 proxy를 함께 노출합니다.
- **Anthropic 비용 가드**는 `context-guard cost preflight/observe/ledger/compile`로 호출 전 비용 추정, provider usage 대조, keyed-HMAC cache 위험 기록, 안정적인 prefix 배치 안내를 제공합니다. 원문 프롬프트를 저장하지 않으며 Anthropic prompt cache를 대체하지 않습니다.
- **출력 축약기**는 감싼 명령의 종료 코드를 보존하면서 긴 로그를 줄이고, `--digest markdown` 또는 `--digest json`으로 실행기 실패 정보, 가림 처리된 failure signature, 중복 라인 그룹, 다음 조회 제안이 담긴 요약을 만들 수 있습니다.
- **민감정보 가림 도구**는 검색, diff, 로그 출력에서 자격 증명 패턴, 비공개 키 블록, 인증 헤더, 자격 증명이 포함된 URL, 민감해 보이는 경로를 가립니다.
- **상태표시줄**은 모델, 컨텍스트, 비용 신호를 짧게 보여주고, 대화 기록 데이터가 있으면 캐시 읽기와 캐시 재사용 신호도 함께 표시합니다.
- **대화 기록 감사**는 usage/cost/cache bucket을 집계하고, 토큰 집중 지점, `cache_friendliness` 프롬프트 배치 신호, `cache_layout_advice` 확인/실험 우선순위를 제한된 가림 처리된 segment hash로 보고합니다. 원문 프롬프트는 출력하지 않습니다.
- **반복 실패 알림**은 Bash 실패가 반복될 때 같은 경로를 계속 재시도하지 않고 전략을 바꾸도록 안내합니다.
- **벤치마크 헬퍼**는 기준/변형 실행을 대응해 실제 토큰·비용 필드, 별도의 바이트 감소 간접 증거, 진단용 `wall_time_seconds`, `provider_cached_tokens`, provider-cache 사용 가능성 텔레메트리, 파일 기반 `variant_prompt_files`, 선택적 run별 `self_hosted_metrics` JSONL ledger sidecar를 기록합니다. 이 sidecar는 hosted API 절감 주장에 합치지 않습니다.

비용 가드의 로컬 HMAC 키는 기본적으로 `.context-guard/cost-ledger/hmac.key`에 자동 생성됩니다. 관리자가 직접 주입하는 경우 파일에는 필수 padding을 포함한 canonical URL-safe base64 32바이트 키만 정확히 들어 있어야 하며, trailing newline이나 공백은 허용하지 않습니다. 리포트는 키와 원문 프롬프트를 출력하지 않고, 로컬 ledger는 Anthropic/provider prompt cache를 대체하지 않습니다.

## brief 모드 (권고)

brief 모드는 코딩 에이전트가 군더더기를 줄이도록 요청하되, 증거(파일 경로, 명령, 명령 출력과 오류, 코드 블록, 검증 상태, 변경 파일, 남은 과제, 주의사항)는 유지하게 돕는 에이전트 중립·안내용 규칙 스니펫을 제공합니다. 강제가 아니라 최선 노력 안내이며, 토큰·비용 절감을 **보장하지 않습니다.**

세 가지 고정 레벨(`lite`, `standard`, `ultra`)이 [`brief/`](brief/)에 있습니다. 각 레벨은 에이전트 규칙·지시 파일(`AGENTS.md`, `CLAUDE.md`, Cursor 규칙 파일, Copilot 지시 등)에 들어가는 마커 구분 블록입니다. `context-guard setup --agent codex --scope project --brief-mode standard --plan`으로 미리 보고, `--yes`로 적용하며, 제거는 `--brief-mode off`를 사용하세요. 자세한 내용은 [`brief/README.md`](brief/README.md)를 참고하세요.

## 절감 수치를 과장하지 않습니다

이 헬퍼들은 흔히 컨텍스트를 불필요하게 키우는 원인을 줄이지만, 고정된 절감률을 보장하지 않습니다. 실제 전후 비교 증거가 필요하면 `context-guard-bench --ledger-jsonl ... --report-json ...`로 본인 작업에서 측정하세요. 토큰 절감 주장은 대응 태스크 양쪽 모두에 `primary_tokens_measured`가 있을 때만 계산하며, report의 `matched_pair_evidence`가 성공한 baseline/variant task bucket을 transform, quality gate, 측정 가능 여부, claim boundary와 연결합니다. wall-time과 provider-cache 필드는 진단용 텔레메트리이지 단독 절감 증거가 아닙니다. 감사의 `cache_friendliness`, [`cache_diagnostics`](https://github.com/ictechgy/context-guard/blob/main/docs/cache-diagnostics-schema.md), `cache_layout_advice`는 관측/추론/가설/불가 경계를 둔 휴리스틱 배치·cache-read 신호와 순위화된 확인/실험이며 청구 기준이나 provider-cache 증명이 아닙니다. 벤치마크 CSV 스키마는 엄격하므로 헬퍼 업그레이드 후에는 새 CSV를 시작하거나 헤더를 마이그레이션하세요. 작업 유형별 합성 예시는 [`docs/benchmark-workflow-examples.md`](https://github.com/ictechgy/context-guard/blob/main/docs/benchmark-workflow-examples.md)에 있고, fixture-only 실험 시작 예시는 [`docs/experimental-benchmark-fixtures.md`](https://github.com/ictechgy/context-guard/blob/main/docs/experimental-benchmark-fixtures.md)에 있습니다.

ContextGuard는 모델 토큰을 줄이기 위해 작업을 외부 AI 서비스로 전송하지 않습니다. 모든 헬퍼 명령은 로컬에서 동작합니다. 로컬 RAM/디스크 보관본은 다음에 보낼 컨텍스트를 줄이는 데 도움될 수 있지만 provider prompt cache를 대체하지 않습니다. Anthropic 배포나 청구 설명 전에는 공식 prompt caching/pricing 문서를 다시 확인하세요: https://docs.anthropic.com/en/build-with-claude/prompt-caching 및 https://platform.claude.com/docs/en/about-claude/pricing.

미래 learned, self-hosted 최적화 아이디어는 [`research/experimental-token-reduction-radar.md`](https://github.com/ictechgy/context-guard/blob/main/research/experimental-token-reduction-radar.md)에 gated experiment로 기록하며, fixture-only 시작 예시는 [`docs/experimental-benchmark-fixtures.md`](https://github.com/ictechgy/context-guard/blob/main/docs/experimental-benchmark-fixtures.md)에 둡니다. learned compression은 `context-guard experiments plan learned-compression` dry-run checker와 명시적 `context-guard experiments emit learned-compression` caller-supplied candidate emitter만 shipped 상태이고, self-hosted-metrics-ledger는 dry-run preview와 명시적 `context-guard experiments record self-hosted-metrics-ledger` local JSONL record를 제공하며, dry-run preview는 ledger 파일을 쓰지 않습니다. visual crop/OCR은 caller-supplied evidence-pack emit, context-diff는 verified-receipt caller-supplied replacement emit만 제공합니다. local proxy는 `context-guard experiments plan local-proxy` localhost-only dry-run advisory plan, design-only `context-guard experiments plan local-proxy-external-forwarding` gate, 명시적 `context-guard experiments record local-proxy-runtime-gate --ledger-jsonl ...` gate row record, one-shot `context-guard experiments serve local-proxy` loopback forwarding MVP와 successful forwarded request용 optional shifted-cost diagnostic JSONL row만 shipped 상태입니다. record는 no listener/no traffic forwarding/no DNS lookup/no external service/no API-key persistence boundary를 유지하고, serve는 literal loopback IP·`--once`·credential-free request만 허용하고 CONNECT/TLS proxying도 지원하지 않습니다. `--diagnostic-ledger-jsonl`은 successful forwarded request 뒤에만 진단 row를 쓰며 raw header/body나 hosted-savings evidence를 저장하지 않습니다. `plan local-proxy-external-forwarding`은 threat model, HTTPS allowlist, credential redaction, provider-evidence boundary를 점검하는 dry-run design gate이고 listener, DNS lookup, external service call, traffic forwarding, credential persistence, external proxy forwarding runtime, hosted savings claim을 제공하지 않습니다. learned/synthetic compressor 실행·embedding·reranker·model call·생성형 replacement, generated OCR/crop 또는 visual-token pruning, self-hosted KV/latent runtime 최적화, one-shot literal-loopback local proxy MVP를 넘어선 external/daemon/credential-bearing proxy forwarding runtime은 shipped가 아닙니다. 이 radar와 fixture는 provider가 측정한 matched-task 근거 없이 hosted API 절감을 주장하지 않습니다. Radar의 later-roadmap gate는 neural/semantic compression, trust-tiered injection-aware compression, generated visual-token reduction, broader local proxy forwarding constraint도 별도 미래 PR이 gate를 통과하기 전까지 experimental/non-shipped로 묶습니다.

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
