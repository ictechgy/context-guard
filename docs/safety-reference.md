# ContextGuard safety reference

The defensive boundaries ContextGuard commits to: what it trusts, what it
refuses to claim, and what it measurably does not do. Command usage is in
[guide.md](guide.md).

## Trust boundaries and helper policy

Project scope is the default. User-level setup is opt-in, requires an explicit agent for writes, records backups and rollback metadata, and never runs during package installation. Before applying setup, run `context-guard setup --verify` for a read-only health check; `context-guard doctor` is an alias of it. Setup looks for bundled or checkout-local helpers first; it does not trust arbitrary `PATH` helpers unless you explicitly pass `--allow-path-helper-fallback` for a known-good install.

Distribution and helper trust boundaries are conservative too: npm exposes only canonical `context-guard`/`context-guard-*` bin links, command manifests are treated as literal data rather than executable Python, and the macOS visibility helper is discovered only from bundled/resource/executable-relative paths or an absolute explicit override with a minimal child environment. Current working directories, relative overrides, symlinked helpers, arbitrary `PATH`, and ambient shell environment are not trusted by default.

ContextGuard is intentionally conservative about savings claims. It reduces common sources of context bloat and provides benchmark tooling so you can measure before-and-after results on your own tasks. It does **not** promise a fixed token or cost reduction for every repository.

Do not rely on `PATH` lookup for generated hooks by default. The setup wizard records explicit bundled or checkout-local helper paths; `--allow-path-helper-fallback` is only for trusted external installs and validates the resolved helper path, symlink state, and bounded identity probe before writing commands. The macOS app helper follows the same trust model: no launch-CWD discovery, no relative override paths, and no inherited ambient shell environment beyond the allowlisted values it needs to start.

## Standing cost and break-even

Advisory rule blocks are not free. They live in an agent's rule file, so they are
re-sent with every request for as long as they are installed:

| Managed block | Installed size |
| --- | --- |
| `brief-mode.lite` | 1,487 bytes |
| `brief-mode.standard` | 1,568 bytes |
| `brief-mode.ultra` | 1,523 bytes |
| `narration-mode.quiet` | 866 bytes |

That is a fixed per-request cost paid up front, while the benefit is a
probabilistic reduction in reply length that ContextGuard cannot enforce. On a
session with few turns, or with an agent that already answers tersely, the block
can cost more than it saves. The hook-based guardrails behave differently: they
charge only when they act, and the measured worst cases stay small — a
sub-threshold `Read` adds 3 bytes, and repeated large-read attempts shrink after
the first warning instead of accumulating.

Before installing a rule block for its token effect, measure it. Use
`context-guard-bench` on matched tasks with and without the block, and treat the
block's installed size as the break-even threshold your reply-length reduction has
to clear. Byte counts here are observed; token effects are not, and no fixed
saving is claimed.

## What to measure

If you need a savings claim, measure it on your own tasks:

- full-file reads versus symbol or line-range reads
- raw logs versus digest output or artifact receipts
- transcript hotspots reported by `context-guard-audit`, including `cache_friendliness` prompt-layout signals and `cache_layout_advice` experiment priorities
- statusline `cache` / `reuse` as observed transcript/provider-cache signals, not savings caused by ContextGuard
- `context-guard cost preflight` estimates for Anthropic request JSON, followed by `context-guard cost observe` using provider usage fields (`cache_creation_input_tokens`, `cache_read_input_tokens`) after the call
- static prompt/request cache layout checks from `context-guard-cache-score`, including optional user-supplied cache write/read multiplier amortization risk; its char/4 token estimates and warnings are advisory only until provider usage fields confirm real cache hits
- matched successful baseline/variant runs from `context-guard-bench`
- large tool/MCP catalogs versus `context-guard-tool-prune` top-k reports plus receipt retrieval
- optional experimental lanes in [`research/experimental-token-reduction-radar.md`](../research/experimental-token-reduction-radar.md); fixture-only starters in [`docs/experimental-benchmark-fixtures.md`](experimental-benchmark-fixtures.md) use the same matched-task benchmark gates before any savings claim

## What ContextGuard does not do

- It does not guarantee a fixed token or cost reduction.
- It does not send work to external AI providers to save model tokens.
- It does not mutate global Claude settings during install.
- It does not execute command manifests as code or trust arbitrary `PATH`/current-working-directory helpers during setup or packaged smoke checks.
- It does not replace real before/after measurement when you need a savings claim.
- Local RAM/disk receipts can help reduce what you send next, but they do **not** replace Anthropic's provider prompt cache or guarantee cache hits. Recheck Anthropic prompt-caching and pricing docs before release or billing claims: https://docs.anthropic.com/en/build-with-claude/prompt-caching and https://platform.claude.com/docs/en/about-claude/pricing.
- Experimental helpers are default-off, plan-only or narrow explicit local runtimes; see [`docs/experiments.md`](experiments.md).
- ContextGuard does not ship learned/synthetic compressor execution, embeddings, rerankers, model calls, generated replacement text, screenshot capture, image cropping, OCR execution, image parsing, external OCR/image services, self-hosted KV/latent inference optimization beyond explicit local metrics recording, or broader proxy forwarding beyond literal-loopback, one-request HTTP forwarding with credential material blocked.
- It does not alias the old `/claude-token-optimizer:*` Claude Code slash-command namespace. Use `/context-guard:*` after installing this plugin.

Legacy `claude-*` wrapper names were removed in this release; use the `context-guard-*` names instead (migration: replace the prefix).

## 한국어

한국어 사용자를 위한 안전 경계 참조입니다.

### 신뢰 경계와 헬퍼 정책

기본값은 프로젝트 단위 설정입니다. 사용자 단위 설정은 명시적으로 선택해야 하며, 실제 변경을 적용하려면 `--yes`와 명시적인 `--agent`가 필요합니다. 지원되는 사용자 단위 변경은 백업과 되돌리기 기록을 남기며, 패키지 설치 중에는 실행되지 않습니다. 적용 전에는 `context-guard setup --verify`로 읽기 전용 상태를 먼저 확인하세요. `context-guard doctor`는 이 명령의 별칭입니다. `setup`은 먼저 패키지/체크아웃 내부 헬퍼를 찾습니다. 신뢰할 수 있는 설치임을 확인한 경우에만 `--allow-path-helper-fallback`으로 `PATH` 헬퍼 대체 경로를 허용하세요.

배포와 헬퍼 신뢰 경계도 보수적입니다. npm은 canonical `context-guard`/`context-guard-*` bin 링크만 노출합니다. 명령 매니페스트는 실행 가능한 Python이 아니라 literal 데이터로만 읽으며, macOS visibility 헬퍼는 번들/resource/실행 파일 기준 경로나 absolute explicit override만 사용하고 최소 환경으로 실행합니다. 현재 작업 디렉터리, 상대 override, symlink 헬퍼, 임의 `PATH`, 불필요한 상위 셸 환경은 기본적으로 신뢰하지 않습니다.

ContextGuard는 절감 수치를 과장하지 않습니다. 흔히 컨텍스트를 불필요하게 키우는 원인을 줄이고, 실제 전후 비교 결과는 각자의 작업에서 측정할 수 있도록 벤치마크 도구를 제공합니다. 저장소마다 효과는 달라질 수 있으며, 고정된 토큰·비용 절감률은 보장하지 않습니다.

생성되는 hook 명령은 기본적으로 `PATH` 조회에 의존하지 않습니다. setup 마법사는 명시적인 패키지/체크아웃 헬퍼 경로를 기록하며, `--allow-path-helper-fallback`은 신뢰한 외부 설치를 사용할 때만 canonical 경로·symlink 없음·bounded identity probe 검증 후 허용됩니다. macOS 앱 헬퍼도 같은 신뢰 모델을 따릅니다. launch CWD 탐색, 상대 override 경로, 필요한 allowlist 값을 넘어선 상위 셸 환경 상속을 사용하지 않습니다.

### 상시 비용과 손익분기

안내용 규칙 블록은 공짜가 아닙니다. 에이전트의 규칙 파일에 상주하므로 설치해 둔 동안 모든 요청에 다시 실려 갑니다.

| 관리 블록 | 설치 크기 |
| --- | --- |
| `brief-mode.lite` | 1,487 바이트 |
| `brief-mode.standard` | 1,568 바이트 |
| `brief-mode.ultra` | 1,523 바이트 |
| `narration-mode.quiet` | 866 바이트 |

이 비용은 요청마다 선불로 확정되는 반면, 이득은 ContextGuard가 강제할 수 없는 확률적인 응답 길이 감소입니다. 턴 수가 적은 세션이나 이미 간결하게 답하는 에이전트에서는 블록이 절감분보다 더 들 수 있습니다. 훅 기반 가드레일은 성질이 다릅니다. 실제로 개입할 때만 비용이 들고, 측정된 최악의 경우도 작습니다. 임계값 이하 `Read`는 3바이트를 더하고, 대용량 읽기를 반복 시도해도 첫 경고 이후에는 누적되지 않고 오히려 줄어듭니다.

토큰 효과를 노려 규칙 블록을 설치하기 전에 직접 측정하십시오. `context-guard-bench`로 블록이 있는 경우와 없는 경우를 동일 과제에서 비교하고, 블록의 설치 크기를 응답 길이 감소가 넘어야 하는 손익분기점으로 취급하십시오. 여기 적힌 바이트 수는 관측값이지만 토큰 효과는 관측값이 아니며, 고정된 절감률을 보장하지 않습니다.

### 직접 측정하는 방법

절감 수치가 필요하면 실제 작업에서 직접 측정하세요.

- 전체 파일 읽기와 심볼·줄 범위 읽기의 차이
- 원본 로그와 요약 출력 또는 로컬 보관 요약 기록의 차이
- `context-guard-audit`가 보고한 대화 기록 사용량 집중 지점, `cache_friendliness` 프롬프트 배치 신호, `cache_layout_advice` 실험 우선순위
- 상태표시줄의 `cache` / `reuse` 값: ContextGuard가 직접 만든 절감 효과가 아니라 관찰된 대화 기록·provider cache 신호입니다.
- `context-guard cost preflight`로 Anthropic 요청 JSON의 추정 비용을 보고, 호출 뒤 `context-guard cost observe`로 provider usage 필드(`cache_creation_input_tokens`, `cache_read_input_tokens`)를 대조합니다.
- `context-guard-cache-score`로 정적 cache layout과, 사용자가 직접 넣은 cache write/read multiplier 기반 amortization 위험을 안내받습니다. char/4 토큰 값은 provider 측정 절감이 아니라 추정 proxy입니다.
- `context-guard-bench`로 성공한 기준/변형 실행을 쌍으로 맞춰 비교한 결과
- 큰 tool/MCP catalog와 `context-guard-tool-prune` top-k 리포트 및 요약 기록 재조회 방식의 차이
- [`research/experimental-token-reduction-radar.md`](../research/experimental-token-reduction-radar.md)의 선택적 실험 lane과 마찬가지로, [`docs/experimental-benchmark-fixtures.md`](experimental-benchmark-fixtures.md)의 fixture-only 시작 예시도 절감 주장을 하려면 같은 matched-task benchmark gate를 먼저 통과해야 합니다.

### ContextGuard가 하지 않는 일

- 고정된 토큰·비용 절감률을 보장하지 않습니다.
- 모델 토큰을 줄이기 위해 작업을 외부 AI 서비스로 전송하지 않습니다.
- 설치만으로 전역 Claude 설정을 변경하지 않습니다.
- setup이나 패키징 smoke check에서 명령 매니페스트를 코드로 실행하거나 임의 `PATH`/현재 작업 디렉터리 헬퍼를 신뢰하지 않습니다.
- 절감 수치가 필요할 때 직접 전후 비교 측정을 대신하지 않습니다.
- 로컬 RAM/디스크 보관본은 다음에 보낼 컨텍스트를 줄이는 데 도움이 될 수 있지만 Anthropic provider prompt cache를 대체하거나 cache hit를 보장하지 않습니다. 배포나 청구 설명 전에는 Anthropic prompt caching/pricing 문서를 다시 확인하세요: https://docs.anthropic.com/en/build-with-claude/prompt-caching 및 https://platform.claude.com/docs/en/about-claude/pricing.
- 실험 헬퍼는 기본 비활성이며 plan 전용이거나 좁은 명시적 로컬 runtime입니다. 자세한 내용은 [`docs/experiments.md`](experiments.md)를 참고하세요.
- ContextGuard는 learned/synthetic compressor 실행·embedding·reranker·model call·생성형 replacement, screenshot 캡처·image crop·OCR 실행·image parsing·외부 OCR/image service, 명시적 local metrics 기록을 넘어선 self-hosted KV/latent inference optimization runtime, literal-loopback 1회 HTTP forwarding과 credential 차단을 넘어선 proxy forwarding은 제공하지 않습니다.
- 예전 `/claude-token-optimizer:*` Claude Code 슬래시 명령을 별칭으로 제공하지 않습니다. 설치 후에는 `/context-guard:*`를 사용하세요.

legacy `claude-*` 래퍼 이름은 이번 릴리스에서 제거했습니다. `context-guard-*` 이름을 사용하세요(마이그레이션: 접두사만 교체).
