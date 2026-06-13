# ContextGuard Kit

Claude Code CLI 컨텍스트 낭비를 줄이기 위한 도구 모음입니다. 모두 Python/Bash 표준 기능만 사용합니다.

## 구성

- `statusline.sh` — context/cost/model을 상태표시줄에 표시합니다.
- `trim_command_output.py` — 긴 명령 출력을 head/tail/error와 pytest/Jest/Vitest/Go/Rust 실패 요약 중심으로 축약하고 원래 종료 코드를 보존합니다.
- `rewrite_bash_for_token_budget.py` — Claude Code `PreToolUse` hook에서 test/build/lint 명령을 wrapper로 감쌉니다.
- `claude_transcript_cost_audit.py` — `~/.claude/projects` JSONL transcript에서 usage/cost/cache 필드와 캐시 친화적 프롬프트 배치 신호를 집계하고 `--recommend`로 절감 액션을 제안합니다.
- `context_guard_diet.py` — 프로젝트 `.claude/settings.json`의 deny/hook/statusline, 여러 AI 에이전트 규칙 파일의 컨텍스트 비대화, 로컬 context-exclusion 추천, structural-waste 진단을 스캔합니다.
- `guard_large_read.py` — Claude Code `PreToolUse` Read hook에서 큰 파일 전체 읽기를 막고 symbol/line-range 읽기로 유도합니다.
- `read_symbol.py` — Python/JS/TS/Go/Rust 파일에서 지정 symbol 주변만 출력합니다.
- `sanitize_output.py` — `rg`/`grep`/`git diff` 같은 검색·diff 출력에서 자격 증명처럼 보이는 값을 가리고 head/anchor/tail로 축약합니다.
- `context_escrow.py` — 큰 명령 출력을 정제한 뒤 로컬 artifact로 저장하고 line/pattern query로 다시 조회합니다.
- `context_pack.py` — 우선순위가 있는 로컬 파일 근거를 바이트 예산 안의 Markdown context pack으로 조립하고, 로컬 query/diff/output 신호에서 build manifest를 추천합니다.
- `context_filter.py` — 사용자 소유 JSON DSL로 성공 출력 라인 필터를 적용하되, 보호해야 할 실패 출력은 원문 그대로 통과시킵니다.
- `tool_schema_pruner.py` — 로컬 tool/MCP catalog를 top-k schema 자문 리포트로 줄이고, 전체 정제된 schema는 receipt/payload로 재조회할 수 있게 합니다.
- `benchmark_runner.py` — 고정 task/variant fixture로 A/B token/cost 절감 benchmark, cost-shift ledger, report를 생성합니다.
- `setup_wizard.py` — 설치 후 project-local `.claude/settings.json`을 대화형으로 선택하고 병합합니다.
- `failed_attempt_nudge.py` — 반복 Bash 실패 시 `/clear`/`/compact`와 전략 전환을 짧게 권유합니다.
- `settings.example.json` — project `.claude/settings.json` 예시입니다.

## 빠른 실험

```bash
python3 context-guard-kit/trim_command_output.py --max-lines 80 -- bash -lc 'seq 1 1000; echo FAIL test_x >&2; exit 1'
python3 context-guard-kit/trim_command_output.py --max-lines 80 -- pytest tests -q
python3 context-guard-kit/claude_transcript_cost_audit.py ~/.claude/projects --top 10 --recommend
python3 context-guard-kit/setup_wizard.py
python3 context-guard-kit/context_guard_diet.py scan . --json
python3 context-guard-kit/context_guard_diet.py structural-waste . --tool-catalog tools.json --log-path .claude --json
python3 context-guard-kit/context_filter.py validate --config .context-guard/filter-dsl.json --json
python3 context-guard-kit/context_filter.py run --config .context-guard/filter-dsl.json -- git status --short
python3 context-guard-kit/read_symbol.py path/to/file.py TargetSymbol
long-command 2>&1 | python3 context-guard-kit/context_escrow.py store --command "long-command" --json
python3 context-guard-kit/context_escrow.py get <artifact_id> --lines 1:80
python3 context-guard-kit/context_pack.py suggest --root . --query "failing tests review" --diff HEAD --manifest-out suggested-pack.json --budget-bytes 12000 --json
python3 context-guard-kit/context_pack.py build --root . --manifest suggested-pack.json --budget-bytes 12000 --json
python3 context-guard-kit/context_pack.py slice --root . --path README.md --lines 1:40 --json
python3 context-guard-kit/tool_schema_pruner.py select --catalog tools.json --query "review failing tests" --top 5 --budget-bytes 12000 --json
python3 context-guard-kit/tool_schema_pruner.py get <receipt_id> --tool read_file --json
python3 context-guard-kit/benchmark_runner.py --tasks bench/tasks.json --variants bench/variants.json --csv bench/results.csv --ledger-jsonl bench/cost-shift.jsonl --report-json bench/report.json
python3 context-guard-kit/sanitize_output.py -- rg -n "TOKEN|SECRET" .
python3 context-guard-kit/sanitize_output.py -- git diff
```

`trim_command_output.py`는 output이 budget을 넘을 때 runner별 failure summary를 먼저 보여줍니다. 예를 들어 pytest node id, Jest/Vitest 실패 파일/테스트, `go test`의 실패 test와 `_test.go:line`, `cargo test` panic 위치를 짧게 보존해 Claude가 전체 로그를 다시 읽지 않고도 다음에 수정할 파일을 고를 수 있게 합니다. head/tail 로그 대신 더 작은 의미 요약만 필요하면 `--digest markdown` 또는 `--digest json`을 추가하세요. digest mode는 status, exit code, truncation count, runner failure facts, 정제된 failure signature, 중복 라인 그룹, 대표 라인, redaction count, 다음 query 제안을 남깁니다. digest mode에 `--artifact-receipt`를 더하면 sanitized 전체 output을 로컬 `context-guard-artifact` receipt로 보관하고, 출력된 `context-guard-artifact get ...` 명령으로 누락된 부분을 정확히 다시 조회할 수 있습니다. 감싼 명령은 기본 600초 후 timeout 처리되며(`--timeout-seconds`로 조정), 가능한 환경에서는 process group까지 종료한 뒤 124를 반환합니다. ANSI color code는 제거하며, 절대경로는 기본적으로 `basename#path:<hash>`로 익명화합니다. 로컬 디버깅에서 원문 절대경로가 꼭 필요하면 `--show-paths`를 추가하세요.

`context_escrow.py`는 대용량 output을 Claude context에 그대로 넣지 않고 `.context-guard/artifacts` 아래 `0o600` 파일로 저장합니다. 저장 전에 sanitizer를 적용해 secret/path 노출을 줄이고, receipt에는 `artifact_id`, line/byte count, 줄 번호가 포함된 top-error receipt, 중복 라인 그룹, 대표 head/tail, 정제된 bounded `suggested_queries`와 `get --lines`/`get --pattern` query 예시만 출력합니다. suggested `--lines START:END` query에 `--max-lines`가 함께 있으면 이는 해당 line range의 반환 cap일 뿐 selector를 넓히는 옵션이 아닙니다. `get`과 `list`는 legacy 기본 위치인 `.claude-token-optimizer/artifacts`도 함께 읽어 리브랜딩 전 receipt를 계속 조회할 수 있습니다. 저장된 artifact는 sanitize된 사본이며, 필요할 때만 `get <artifact_id> --lines 10:40`처럼 정확한 범위를 조회하세요. 파이프라인 저장은 capture/query 용도이므로 producer 명령의 exit code가 필요한 release check에서는 shell `pipefail`/별도 `$?` 저장을 쓰거나 `trim_command_output.py -- ...`로 감싸세요.


`context_pack.py auto`는 `suggest`와 `build`를 한 번에 합성해 build-compatible manifest와 예산 기반 Markdown pack을 함께 만듭니다. `auto --explain`은 manifest, pack 본문, receipt, byte budget을 바꾸지 않고 결정적 로컬 선택/build 이유를 JSON 또는 텍스트로 짧게 보여줍니다. JSON explain에는 bounded `repo_map`도 포함되어 sampled byte/token-proxy tree, category-only secret risk summary, signature-first hints, explain-only graph rank, 기존 `slice`/symbol 재조회 힌트를 제공합니다. 이 repo-map은 네트워크·모델 호출·임베딩 없이 로컬 표준 라이브러리 휴리스틱만 쓰며, pack 선택/본문/receipt를 바꾸지 않고 provider token 또는 savings claim으로 해석하면 안 됩니다. `context_pack.py suggest`는 `--query`, `--diff`, 반복 `--files`, 가림 처리한 `--output`, `--test-output`에서 build-compatible manifest 후보를 만듭니다. 모두 `--root` 아래 로컬 파일과 `git diff`만 읽고, 네트워크·모델 호출·임베딩·provider 비용 추정은 하지 않습니다. `context_pack.py build`는 여러 로컬 파일 source를 우선순위와 줄 범위에 따라 정렬하고, 렌더링된 UTF-8 byte budget 안에서 Markdown context pack을 만듭니다. 포함·부분 포함·누락 source, 누락 사유, `.context-guard/packs` bounded receipt, 그리고 `slice --lines` 정확 재조회 명령을 JSON으로 남깁니다. pack 본문과 receipt를 만들기 전에 sanitizer를 적용하며, token 값은 관측값이 아닌 추정 proxy로만 표시합니다.

`context_filter.py`는 opt-in declarative output filter helper입니다. filter JSON은 사용자가 package code 밖(예: `.context-guard/filter-dsl.json`)에 두고 `validate`로 검증한 뒤 `run --config ... -- <command>`로 적용합니다. invalid config, no-match, filter error, empty output, protected `git`/test/lint/`gh` failure는 원래 command stdout/stderr와 exit code를 passthrough합니다. filtered mode는 stdout+stderr를 합친 line에 filter를 적용해 stdout으로 쓰고, passthrough mode는 stdout/stderr stream을 그대로 보존합니다. `--json-report`는 stdout을 command/filter output 전용으로 두기 위해 stderr에만 diagnostic JSON을 쓰지만, protected nonzero passthrough에서는 stderr 원문 보존을 위해 report를 생략합니다. token/cost 절감 수치는 측정 claim이 아니라 local presentation 변화로만 다루세요.

`tool_schema_pruner.py`는 provider-neutral tool/MCP catalog helper입니다. `select`는 task query와 lexical overlap으로 top-k tool을 고르고, inline schema는 `--budget-bytes` 안에만 넣으며, compact receipt와 별도 sanitized payload를 `.context-guard/tool-prune`에 기록합니다. `get`은 payload size/SHA-256을 검증한 뒤 전체 정제 schema를 반환합니다. 이 helper는 MCP 설정을 바꾸지 않으며, token 절감은 측정값이 아니라 추정 proxy로만 표현합니다.

`context_compress.py --protected-policy`는 기본 압축 동작을 바꾸지 않고 code fence, diff, identifier, numeric constant, hash, path, stack frame, quoted string, JSON key 같은 보호-zone class/count 정책 메타데이터를 추가합니다. 보호-zone 정책은 semantic/paraphrase rewrite를 금지하고 structural dedupe/window/truncate 및 artifact retrieval만 허용합니다. raw span은 receipt에 저장하지 않으며, lossy structural transform에는 정확 재조회가 필요하다는 hint를 남깁니다.

`cost_guard.py compile`은 section manifest의 `protected`, `semantic_sensitive`, `protected_zone_classes`, `content_type`, `volatile`, `ttl`, `bytes` 필드를 읽어 `protected_zone_policy`와 `transform_policy`를 출력합니다. `protected=true`와 `volatile=true`가 같이 있으면 volatile이 cache ordering을 tail 쪽으로 보내고, protection은 transform/retrieval 정책만 제어합니다. 대용량 protected section에는 local artifact retrieval을 안내하지만 provider prompt cache를 대체한다고 주장하지 않습니다.

`experimental_registry.py`는 `context-guard experiments`의 project-local 메타데이터 진입점입니다. 기본 비활성이며, `enable`/`disable`은 `.context-guard/experiments.json`만 갱신하고 기존 헬퍼 동작은 여전히 명시적 flag가 있어야 바뀝니다. 레지스트리는 receipt-backed 출력 축약 경로(`trim_command_output.py --digest markdown|json --artifact-receipt`)와 protected-zone 정책 경로(`context_compress.py --protected-policy`, `cost_guard.py compile`의 protected section 메타데이터)를 명시적 flag 실험으로 표시합니다.

`experimental_registry.py plan context-diff-compaction`은 읽기 전용 dry-run planner이고, `experimental_registry.py emit context-diff-compaction --receipt-id ... --reexpand-command ...`는 명시적 로컬 runtime입니다. `plan`은 diff 파일과 hunk만 요약하고 replacement text를 만들지 않습니다. `emit`은 review 가능한 hunk, 입력 diff와 일치하는 로컬 보관본 내용, 유효한 재확장 메타데이터, 더 작은 caller-supplied replacement가 모두 있을 때만 caller-supplied compact replacement text를 출력합니다. 로컬 보관본 내용을 검증하지만 re-expand 명령을 실행하거나 hosted savings를 주장하지 않습니다.

`experimental_registry.py plan visual-crop-ocr`은 전체 visual evidence 요약 기록과 crop/OCR fixture note를 점검하는 dry-run metadata planner이고, `experimental_registry.py emit visual-crop-ocr`은 caller-supplied crop/OCR 근거를 위한 명시적 로컬 evidence-pack runtime입니다. visual lane은 screenshot 캡처, image crop, screenshot parsing, OCR 실행, OCR/image service 호출, evidence file 쓰기, replacement evidence 생성, hosted savings 주장을 하지 않습니다.

`experimental_registry.py plan learned-compression`은 정제된 trusted prose와 exact fallback handle을 위한 deny-by-default dry-run safety checker이고, `experimental_registry.py emit learned-compression`은 검증된 exact fallback 내용이 있을 때 caller-supplied compact prose를 내보내는 명시적 로컬 candidate emitter입니다. learned lane은 learned/synthetic compressor 실행, embedding, model call, reranker, subprocess, external service, generated replacement text를 실행하지 않으며 hosted savings도 주장하지 않습니다.

`experimental_registry.py plan self-hosted-metrics-ledger`는 명시적 local/model-server latency, memory, quality, energy, throughput, local-cost sidecar evidence를 미리 보는 dry-run preview이며 ledger 파일을 쓰지 않습니다. `experimental_registry.py record self-hosted-metrics-ledger --ledger-jsonl ...`은 로컬 JSONL sidecar row 하나를 명시적으로 쓰지만, self-hosted telemetry를 hosted API token/cost savings claim으로 바꾸지 않습니다.

`experimental_registry.py plan local-proxy`는 localhost-only dry-run 안내 plan입니다. `experimental_registry.py plan local-proxy-external-forwarding`은 future external forwarding을 위한 design-only dry-run gate이며 explicit intent, HTTPS allowlist, threat model note, credential redaction policy, provider-evidence boundary를 요구하고 DNS lookup, external service call, traffic forwarding은 하지 않습니다. `experimental_registry.py record local-proxy-runtime-gate --ledger-jsonl ...`은 listener 시작, traffic forwarding, DNS lookup 없이 local gate row 하나만 기록하는 명시적 runtime입니다. `experimental_registry.py serve local-proxy`는 명시적 one-shot loopback forwarding MVP이며 `--runtime-gate-ack --forwarding-gate-ack --once`, private `--ready-file` nonce handoff, literal loopback bind/target IP, hostname DNS target 금지, nonzero port, byte/time limit, credential-free request가 필요합니다. API key를 저장하지 않고, external forwarding이나 CONNECT/TLS proxying을 지원하지 않으며, hosted savings claim도 만들지 않습니다. 선택적 `--diagnostic-ledger-jsonl`은 successful forwarded request 뒤에 raw header/body나 hosted-savings evidence 없이 shifted-cost diagnostic row 하나만 추가합니다. External proxy forwarding runtime은 shipped가 아니며, 나머지 roadmap lane은 별도 runtime gate가 생기기 전까지 안내 상태로 남습니다.

`benchmark_runner.py`는 `research/benchmark-plan.md`의 고정 task/variant 실험을 실행합니다. `variant_prompt_files`는 선택된 task/variant를 필터링한 뒤 필요한 file-backed prompt만 읽으므로 선택하지 않은 fixture의 누락 파일이 선택된 실행을 깨지 않습니다. `--ledger-jsonl`은 subagent·artifact 등 외부 실행 표면으로 옮겨간 token/cost와 run별 측정 가능 여부를 남기고, 선택적 `self_hosted_metrics` provider payload는 run별 sidecar로만 기록합니다. `--report-json`은 baseline 대비 실제 token/cost 절감과 proxy byte 감소를 분리한 A/B report를 생성하며, `self_hosted_metrics`는 CSV/report 요약에 접지 않습니다. Report의 `matched_pair_evidence`는 성공한 baseline/variant task bucket을 transform, quality gate, 측정 가능 여부, claim boundary와 연결하므로 절감 주장을 쓰기 전에 이 항목을 확인하세요.

`../research/experimental-token-reduction-radar.md`는 learned compression, generated crop/OCR/visual-token pruning, self-hosted KV/latent inference optimization 같은 선택적 미래 실험을 문서화한 gate입니다. `../docs/experimental-benchmark-fixtures.md`에는 fixture-only task/variant 시작 예시가 있습니다. 이 radar와 fixture는 hosted API token/cost 절감을 보장하지 않습니다. 현재 제공되는 helper surface는 명시적 local context-diff emit, visual evidence-pack emit, learned candidate emit, self-hosted metrics record, local proxy gate record, one-shot literal-loopback local proxy serve, design-only external-forwarding plan 같은 좁은 local surface뿐이며, hosted API token/cost 절감 주장은 provider가 측정한 matched-task 근거가 있을 때만 허용합니다. Radar의 later-roadmap gate는 neural/semantic compression, trust-tiered injection-aware compression, generated visual-token reduction, broader external/daemon/hostname-DNS/credential-bearing local proxy forwarding constraints를 별도 미래 PR이 gate를 통과하기 전까지 experimental/non-shipped로 유지합니다.

`claude_transcript_cost_audit.py --recommend`의 기본 출력은 공유 시 안전하도록 transcript 경로를 `basename#hash`, 명령을 `command#hash` 형태로 익명화합니다. 로컬 원문 식별자가 꼭 필요할 때만 `--show-paths` 또는 `--show-commands`를 추가하세요.
대용량/손상 transcript 방어를 위해 파일 단위 `--max-file-bytes`, JSONL record 단위 `--max-line-bytes` 제한도 기본 적용되며, 건너뛴 항목은 skip count와 warning으로 표시됩니다. JSON summary/feasibility 출력의 `cache_friendliness`는 제한된 정제 segment hash로 안정적인 prefix와 volatile prefix/tail 신호를 비교하는 휴리스틱입니다. `cache_layout_advice`는 그 신호를 긴 세션 분리, prefix 안정화, diet 점검 같은 순위화된 확인/실험으로 연결하지만, 관측 issue와 가설/입증 cause를 분리합니다. `--feasibility-json`은 macOS-visible prototype 같은 consumer가 안정적인 top-level field에만 바인딩하도록 `mac_visibility` 계약도 함께 제공합니다. 원문 prompt text는 출력하지 않고, provider cache token field와 historical token total은 ContextGuard가 만든 토큰 절감 또는 live headroom 증거가 아니라 별도 진단 텔레메트리로 해석하세요.

`context_guard_diet.py scan`은 항상 로컬에서만 읽는 read-only 스캐너입니다. 기본 출력은 project root를 익명화하고 상대경로 중심으로 보고합니다. `--top`은 보고서의 context-like file 목록과 context-exclusion recommendation 목록에 공통으로 적용됩니다. `--show-paths`는 로컬/비공개 디버깅에서만 쓰세요.

`context_guard_diet.py structural-waste`는 opt-in read-only 구조 진단입니다. context/rule file의 중복 rule unit, stale Python import 후보, unused skill 후보, MCP/tool schema 과다, local JSON/JSONL log의 반복 file read·중복 tool call을 bounded scan으로 보고합니다. 네트워크 호출이나 삭제/수정은 하지 않고, 기본 출력은 raw prompt/tool input/command를 출력하지 않으며 secret-shaped path component를 redaction합니다. import/skill 결과는 동적 사용을 놓칠 수 있는 advisory 후보로만 다루세요.

`context_pack.py suggest`가 쓰는 manifest는 그대로 `context_pack.py build --manifest suggested-pack.json`에 넣을 수 있습니다. `context_pack.py build`의 retrieval command는 path/root를 안전하게 표시할 수 있을 때만 출력됩니다. 안전하지 않으면 pack 본문과 JSON source metadata에 `retrieval_omitted_reason`을 기록합니다. `token_proxy`는 렌더링된 pack 문자 수를 `chars_div_4`로 나눈 추정치이며, provider가 실제로 청구/소모한 token 측정값이 아닙니다.

`setup_wizard.py`는 설치 후 한 번 실행하는 설정 마법사입니다. 터미널에서 실행하면 deny rules, statusline, Bash trim/sanitize hook, large Read guard, 반복 실패 nudge, model/effort defaults를 project-local `.claude/settings.json`에 병합합니다. 비대화형 환경에서는 `--verify`로 읽기 전용 상태 점검을 하고, `--plan`으로 미리 본 뒤, `--yes`로 추천값을 적용하세요. Codex/Gemini/Cursor 같은 rule-file 에이전트에는 `--brief-mode lite|standard|ultra`로 안내용 brief 스니펫을 설치·교체하고, `--brief-mode off`로 제거할 수 있습니다. 설정을 적용하면 read-only `context_guard_diet.py scan` 요약을 자동으로 출력해 남은 gap을 확인할 수 있습니다. 반복 실패 nudge가 방해되는 프로젝트는 `--no-failed-attempt-nudge`로, post-setup scan이 불필요한 자동화는 `--no-diet-scan`으로 제외할 수 있습니다. `PATH` helper fallback은 기본적으로 꺼져 있으며, 신뢰한 외부 설치에서만 `--allow-path-helper-fallback`으로 canonical 실행 파일·symlink 없음·bounded identity probe 검증을 통과해야 사용됩니다.

`guard_large_read.py`는 opt-in Read hook입니다. 큰 파일 전체를 Claude context에 넣기 전에 progressive read ladder를 반환해 `rg -n` 검색, `read_symbol.py` symbol slice, 작은 `offset`/`limit` Read 순서로 좁히게 합니다. Python/JS/TS/Go/Rust/Markdown 파일은 bounded prefix에서 top-level outline과 line estimate도 함께 보여줍니다. 같은 oversized file fingerprint를 반복해서 읽으려 하면 repeated-read dedup 힌트를 추가해 이전 ladder를 재사용하게 합니다. `CONTEXT_GUARD_READ_GUARD=0`으로 로컬에서 일시 비활성화할 수 있습니다.

`failed_attempt_nudge.py`는 같은 Bash 실패 방향이 두 번 반복되면 `/clear`/`/compact` 힌트를 주고, 세 번 이상 반복되면 strategy-switch signal을 추가해 동일 명령 재시도 대신 다른 가설·더 작은 재현·수정 후 재검증으로 전환하게 합니다. recommended setup에서는 기본으로 켜지며, 실행을 막지 않고 짧은 추가 컨텍스트만 주입합니다.

`sanitize_output.py`는 grep/diff output을 Claude에게 보여주기 전에 secret-like line, Authorization header, private key block, API token, credential URL을 `[REDACTED]`로 바꾸고, 긴 결과는 head / grep·diff·security anchor / tail만 남깁니다. 명령을 감싸는 wrapper mode는 원래 종료 코드를 보존합니다. stdin pipe도 지원하지만 producer exit code는 shell `pipefail` 없이는 알 수 없으므로 자동화에는 `python3 .../sanitize_output.py -- rg ...`처럼 wrapper mode를 선호하세요. 절대경로는 기본 익명화되고 로컬 디버깅에서만 `--show-paths`를 쓰세요. `rewrite_bash_for_token_budget.py` hook은 단일 argv 형태의 `rg`, `grep`, `git grep`, `git diff`, `git show`, `git log -p`를 자동으로 이 sanitizer에 감쌉니다.

Claude Code에 적용하려면 `settings.example.json`을 `.claude/settings.json`으로 복사하되, 먼저 작은 repo에서 quoting/종료 코드를 확인하세요.


## License

Copyright 2026 jinhongan. Licensed under the Apache License 2.0. See the repository [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
