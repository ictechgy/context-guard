# Built-in feature overlap matrix

Claude Code ships its own context-management behaviors. This page says, feature by
feature, where ContextGuard overlaps with them, where it only complements them, and
where it does something the built-ins do not. It exists so that an experienced
Claude Code user does not have to guess "isn't this already built in?".

Built-in behaviors below were checked against the official Claude Code docs on
2026-09-05 (`code.claude.com/docs`). Defaults change; re-check before relying on a
number. Nothing on this page is a savings claim.

| ContextGuard feature | Claude Code built-in | Relationship | What ContextGuard adds, if anything |
| --- | --- | --- | --- |
| Bash escrow wrapper (default; outputs over 220 lines go to a local artifact with a digest and handle) | `BASH_MAX_OUTPUT_LENGTH` (default 30,000 characters; ceiling 150,000). Longer *successful* output is streamed to a session working file and Claude gets the path plus a short preview; *failed* commands get a head-and-tail excerpt only. | **Overlap on the mechanism, different thresholds and shape.** The built-in cap is by characters and keeps the file inside the session directory; ContextGuard caps by lines, stores a sanitized copy under `.context-guard/artifacts`, and returns a structured digest (error lines, runner summary, exact re-expand command). | Secret-pattern sanitization before storage; exact slice retrieval by handle across sessions; the same behavior for Codex/Cursor/Gemini where no built-in cap exists. If you only use Claude Code and never need sanitized cross-session retrieval, the built-in cap already covers most of this. |
| Large Read guard (`PreToolUse:Read` deny with a one-line ladder) | The Read tool is token-limited: a whole file over the limit returns a first page plus a `PARTIAL view` notice; explicit `offset`/`limit` beyond the limit returns an error. No line or byte limit is documented. | **Complement.** The built-in prevents a single oversized read from failing; it does not stop many mid-sized whole-file reads that each fit. The guard blocks reads over a byte budget (default 48,000 B) and points to search or symbol reads first. | Only covers Claude `Read`/`NotebookRead`. Grep and Bash `cat` are not guarded by either side; the audit's `guard_coverage` section measures how much large-result volume arrives that way. |
| `context-guard-tool-prune` (rank MCP schemas, top-k report) | Tool search is the default: only tool names are listed, full schemas are deferred (`ENABLE_TOOL_SEARCH`, `auto` loads schemas upfront only when they fit within 10% of the window). | **Superseded for Claude Code** on supported models and providers. Remains relevant where tool search is disabled (custom `ANTHROPIC_BASE_URL`, some cloud deployments, older models) and for agents without deferred loading. | Nothing for a default Claude Code install. The advisor never edits your MCP config either way. |
| Token statusline (`ctx % \| cost \| cache \| reuse`) | `/context` (window breakdown by category) and `/usage` (session usage, plan usage, prompt-cache hit ratio since v2.1.251). | **Overlap.** Both surfaces show the same provider signals. The statusline is always visible; `/context` and `/usage` are on demand and more detailed. | The statusline runs a Python process on every render. If you use `/usage`, you can leave the statusline off (`--profile minimal` or `--no-statusline`). |
| `context-guard-audit` (transcript audit: new tokens per turn by preceding tool, tool_result bytes, guard coverage, token-proxy reconcile) | `/usage` shows totals and cache statistics for the session. | **Not built in.** Nothing in Claude Code attributes new tokens to the tool result that preceded them, or reports which tools deliver large results outside the Read guard. | This is the part of ContextGuard with no built-in equivalent. Its numbers are observations from local transcripts, not billing authority. |
| `failed_attempt_nudge` (one-line hint after the same Bash command fails twice; off by default) | None. | **Not built in**, but its false-positive rate is unmeasured, which is why it is opt-in (`--profile max`). | A hint, not a savings mechanism. |
| Compaction, `context-guard-compress` | Auto-compaction near the model's window (`autoCompactWindow`, e.g. ~967K on Sonnet 5, ~200K on other models), `/compact`, `/clear`. | **Built-in wins.** ContextGuard's compressor is explicit-invocation only and structural (JSON compaction, log collapse); it does not replace conversation compaction. | Prefer the built-in. Use `context-guard-artifact` for lossless retrieval instead of compressing history. |
| Brief mode / quiet narration rule blocks | `/effort` and `effortLevel` (default `high`; `xhigh` on Opus 4.7) control reasoning depth, not answer length. `MAX_THINKING_TOKENS` bounds thinking on fixed-budget models. | **Different axis.** The rule blocks ask for shorter answers; effort controls thinking. The blocks cost ~1.5 KB on every request and their benefit is not enforced (see the standing-cost table in [safety-reference.md](safety-reference.md)). | Measure before installing; for short sessions the block can cost more than it saves. |
| Prompt cache friendliness diagnostics (`cache_friendliness`, `cost preflight`) | Prompt caching is automatic (`cache_control` breakpoints on the system prompt, project context, conversation; TTL 1 h on subscription, 5 min on API keys; `DISABLE_PROMPT_CACHING*`). Enabling or disabling plugins or MCP servers invalidates the prefix unless tools are deferred. | **Complement.** Claude Code caches; ContextGuard only reports when the observed usage suggests the prefix is being rewritten. | A warning, never a change to the request. |
| Hook journal + `context-guard hooks off` | Hooks themselves are built in (`PreToolUse` `updatedInput` and `permissionDecision`, `PostToolUse` `additionalContext`). There is no built-in per-hook cost journal or temporary disable switch. | **Not built in.** | Records what each hook did and cost; lets a user pause one hook for a project without editing settings. |

## What this means for a default Claude Code install

- Keep: the audit, the Read guard, the Bash escrow if you want sanitized cross-session retrieval or use other agents, deny rules.
- Optional: the statusline (duplicates `/usage`), the nudge (unmeasured), brief mode (measure first).
- Skip on Claude Code: `tool-prune`, `compress`.

The `--profile minimal` setup is the closest match to "only what the built-ins do not cover": deny rules and the Read guard.

## 한국어

Claude Code 에는 자체 컨텍스트 관리 기능이 있습니다. 이 문서는 ContextGuard 의 기능 하나하나에 대해 내장 기능과 겹치는지, 보완하는지, 내장에 없는 것인지를 밝힙니다. "이미 내장된 것 아닌가"라는 질문에 답하기 위한 페이지이며, 절감 주장은 아닙니다. 내장 기능은 2026-09-05 공식 문서 기준으로 확인했고 기본값은 바뀔 수 있습니다.

| ContextGuard 기능 | Claude Code 내장 | 관계 | ContextGuard 가 더하는 것 |
| --- | --- | --- | --- |
| Bash escrow 래퍼(기본; 220줄 초과 출력을 로컬 artifact 로) | `BASH_MAX_OUTPUT_LENGTH`(기본 30,000자, 상한 150,000자). 긴 *성공* 출력은 세션 작업 파일로 저장되고 경로와 짧은 미리보기가 전달됨. *실패*한 명령은 앞뒤 발췌만. | **메커니즘은 겹치고 기준과 형태가 다름.** 내장은 글자 수 기준이고 세션 디렉터리 안에 둠. ContextGuard 는 줄 수 기준이고 `.context-guard/artifacts` 에 sanitize 한 사본을 두며 구조화된 digest 를 돌려줌. | 저장 전 시크릿 패턴 가림, 세션을 넘어서는 핸들 기반 정확 재조회, 내장 상한이 없는 Codex/Cursor/Gemini 에서의 같은 동작. Claude Code 만 쓰고 sanitize 된 재조회가 필요 없다면 내장 상한으로 대부분 충분함. |
| 대용량 Read 가드 | Read 도구는 토큰 기준으로 제한됨. 전체 파일이 한도를 넘으면 첫 페이지와 `PARTIAL view` 안내를 돌려줌. 줄/바이트 한도는 문서화되지 않음. | **보완.** 내장은 한 번의 초대형 읽기가 실패하지 않게 할 뿐, 각각은 한도 안에 드는 중간 크기 전체 읽기 여러 번을 막지 않음. 가드는 바이트 예산(기본 48,000B) 초과 읽기를 막고 검색/심볼 읽기를 먼저 권함. | Claude `Read`/`NotebookRead` 만 덮음. Grep 과 Bash `cat` 은 양쪽 모두 못 막으며, audit 의 `guard_coverage` 절이 그 우회 바이트를 측정함. |
| `context-guard-tool-prune` | tool search 가 기본: 도구 이름만 싣고 스키마는 지연 로딩(`ENABLE_TOOL_SEARCH`). | **Claude Code 에서는 대체됨.** tool search 가 꺼지는 환경(커스텀 `ANTHROPIC_BASE_URL`, 일부 클라우드 배포, 구형 모델)과 지연 로딩이 없는 다른 에이전트에서만 의미 있음. | 기본 Claude Code 설치에서는 없음. |
| 토큰 statusline | `/context`, `/usage`(v2.1.251 부터 캐시 적중률 포함). | **겹침.** 같은 provider 신호. statusline 은 항상 보이고, `/usage` 는 요청 시 더 자세함. | statusline 은 렌더마다 Python 프로세스를 띄움. `/usage` 를 쓴다면 꺼도 됨(`--profile minimal` 또는 `--no-statusline`). |
| `context-guard-audit` | `/usage` 는 세션 합계와 캐시 통계만. | **내장에 없음.** 선행 도구별 신규 토큰 귀속, 가드 밖으로 들어오는 큰 결과 비율은 Claude Code 어디에도 없음. | ContextGuard 에서 내장 대응물이 없는 부분. 수치는 로컬 트랜스크립트의 관측이지 청구 근거가 아님. |
| `failed_attempt_nudge`(기본 off) | 없음. | **내장에 없음.** 오탐률이 측정되지 않아 opt-in. | 힌트일 뿐 절감 메커니즘이 아님. |
| 컴팩션, `context-guard-compress` | 자동 컴팩션(`autoCompactWindow`), `/compact`, `/clear`. | **내장이 우선.** ContextGuard 압축기는 명시 호출 전용의 구조적 압축이며 대화 컴팩션을 대체하지 않음. | 내장을 쓰고, 무손실 재조회는 `context-guard-artifact` 로. |
| brief 모드 / 조용한 진행 설명 | `/effort`, `effortLevel`(기본 `high`), `MAX_THINKING_TOKENS`. | **다른 축.** 규칙 블록은 답변 길이를, effort 는 사고 깊이를 다룸. 블록은 요청마다 약 1.5KB 가 확정 비용이고 이득은 강제되지 않음. | 설치 전에 측정할 것. 짧은 세션에서는 손해일 수 있음. |
| 캐시 친화도 진단, `cost preflight` | 프롬프트 캐싱 자동(구독 1시간, API 키 5분 TTL). 플러그인/MCP 변경은 접두사를 무효화함. | **보완.** Claude Code 가 캐시하고, ContextGuard 는 접두사가 다시 쓰이는 징후만 보고함. | 경고일 뿐 요청을 바꾸지 않음. |
| 훅 저널 + `context-guard hooks off` | 훅 자체는 내장. 훅별 비용 저널이나 임시 해제 스위치는 없음. | **내장에 없음.** | 각 훅이 무엇을 했고 얼마를 썼는지 기록하고, 설정을 고치지 않고 훅 하나를 프로젝트 단위로 잠시 끔. |

**기본 Claude Code 설치에서의 결론.** 유지: audit, Read 가드, (sanitize 된 재조회나 다른 에이전트가 필요하면) Bash escrow, deny 규칙. 선택: statusline, nudge, brief 모드. Claude Code 에서는 건너뜀: `tool-prune`, `compress`. `--profile minimal` 이 "내장이 못 하는 것만"에 가장 가깝습니다.
