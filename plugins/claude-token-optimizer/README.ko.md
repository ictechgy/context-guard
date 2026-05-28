# claude-token-optimizer

Claude Code의 토큰 사용량을 줄이는 플러그인입니다. 설정 마법사, 사용량 감사, 설정/context 스캔, 대용량 Read guard, 출력 trim/sanitize 기능을 제공합니다.

## Skills

설치 후 Claude Code 안에서 다음 skill을 사용할 수 있습니다.

```text
/claude-token-optimizer:setup
/claude-token-optimizer:optimize
/claude-token-optimizer:audit
```

가장 먼저 `/claude-token-optimizer:setup`을 실행하는 것을 권장합니다.

## Helper commands와 PATH 주의사항

플러그인은 `bin/` 아래 helper 실행 파일들을 포함합니다. Claude Code skill은 이 helper를 호출할 수 있지만, 일반 shell의 `PATH`에 plugin `bin/`이 자동으로 추가된다고 보장할 수 없습니다.

명령어를 찾을 수 없다고 나오면 이 저장소 루트에서 경로를 직접 명시하세요.

```bash
./plugins/claude-token-optimizer/bin/claude-token-setup --plan
```

개발 중 짧은 명령으로 실행하고 싶다면 현재 shell에만 `PATH`를 추가하세요.

```bash
export PATH="$PWD/plugins/claude-token-optimizer/bin:$PATH"
claude-token-setup --plan
```

`PATH`가 설정된 경우 사용할 수 있는 주요 명령은 다음과 같습니다.

```bash
claude-token-audit ~/.claude/projects --top 20 --recommend
claude-token-setup
claude-token-diet scan . --json
claude-token-artifact store --command "long-command" --json < large.log
claude-token-artifact get <artifact_id> --lines 1:80
claude-trim-output --max-lines 120 -- npm test
claude-read-symbol path/to/file.py TargetSymbol
claude-sanitize-output -- rg -n "TOKEN|SECRET" .
claude-sanitize-output -- git diff
claude-token-guard-read
claude-token-statusline
claude-token-statusline-merged
claude-token-rewrite-bash
```

## Setup wizard

`claude-token-setup`은 설치 후 설정 마법사입니다. Claude Code 안에서는 `/claude-token-optimizer:setup`을 선호하세요.

일반 터미널에서 로컬 테스트하려면:

```bash
./plugins/claude-token-optimizer/bin/claude-token-setup --plan
./plugins/claude-token-optimizer/bin/claude-token-setup --yes
```

마법사는 `.claude/settings.json`을 덮어쓰지 않고 병합합니다. 외부 AI 위임 설정은 더 이상 제공하지 않습니다.

## 주요 기능

### 사용량 감사

```bash
./plugins/claude-token-optimizer/bin/claude-token-audit ~/.claude/projects --top 20 --recommend
```

기본 출력은 공유 안전성을 위해 transcript 경로와 command string을 익명화합니다. 로컬 비공개 디버깅에서만 `--show-paths`, `--show-commands`를 사용하세요.

audit scanner는 기본적으로 transcript read를 제한합니다. `--max-file-bytes`보다 큰 파일과
`--max-line-bytes`보다 큰 JSONL record는 메모리에 올리지 않고 건너뛰며, skip count와 warning으로 보고합니다.

JSON 출력은 `cache_metrics` 블록(`cache_hit_rate`, `cache_amortization`, `cache_amortization_defined`, 원본 cache_read/cache_creation/input 토큰)을 포함합니다. prompt cache가 write 비용을 회수하고 있는지 한눈에 보기 위한 것입니다. 두 권고가 이 메트릭을 사용합니다.

- `improve-prompt-cache-reuse`는 amortization(`cache_read / cache_creation`)이 0.5 미만이고 cache write가 의미 있는 규모(`cache_creation` ≥ 10,000 토큰, `cache_read` ≥ 1)일 때만 발화하므로 baseline / cache-cold 세션의 false-positive를 차단합니다.
- `evaluate-1h-ttl-cache`는 휴리스틱입니다 — write는 크지만 재사용이 보통 수준인 세션을 표시하고, 실제로 1h TTL prompt cache 베타를 켤지는 재사용이 5분 윈도우를 넘는지에 달려 있습니다. 가격 계산, 손익분기 분석, 활성화 전 체크리스트는 [`research/claude-code-token-reduction.md` §2.7](../../research/claude-code-token-reduction.md)을 참고하세요.

### 설정/컨텍스트 스캔

```bash
./plugins/claude-token-optimizer/bin/claude-token-diet scan . --json
```

`permissions.deny`, Bash trim hook, statusline, broad read allow, 비싼 model/effort defaults, 많은 MCP server, 큰 `CLAUDE.md`/`AGENTS.md`, secret-like context를 점검합니다. 기본 출력은 project root를 익명화하며, 로컬 비공개 보고서에서만 `--show-paths`를 사용하세요.

### 대용량 Read guard와 symbol 읽기

`claude-token-guard-read`는 opt-in `PreToolUse` Read hook입니다. 큰 파일 전체를 Claude context에 넣기 전에 `rg -n` 검색 → `claude-read-symbol` symbol slice → 작은 line-range Read 순서의 progressive read ladder를 반환합니다. Python/JS/TS/Go/Rust/Markdown 파일은 bounded prefix에서 top-level outline과 line estimate도 함께 보여줍니다. 같은 oversized file fingerprint를 반복해서 읽으려 하면 repeated-read dedup 힌트를 추가해 이전 ladder를 재사용하게 합니다.

`claude-token-artifact`는 큰 command output을 Claude context에 그대로 보내지 않고 로컬 sanitized artifact로 저장합니다. `store`는 stdin을 읽어 sanitizer로 secret/path 노출을 줄인 뒤 기본 `.claude-token-optimizer/artifacts` 아래 `0o600` 파일로 저장하고, `artifact_id`, byte/line count, top error lines, 대표 샘플, `get --lines` / `get --pattern` query 예시만 receipt로 출력합니다. `get`은 요청한 정확한 slice만 반환합니다. 파이프라인 모드는 capture/query 용도입니다. release check에서 producer 명령의 종료 코드가 중요하면 shell `pipefail` 또는 별도 `$?` 저장으로 직접 보존하고, 종료 코드 보존이 핵심이면 `claude-trim-output -- ...`를 쓰세요.

`claude-token-statusline`은 project settings로 활성화했을 때 token/cost/model 정보를 짧은 statusline으로 출력합니다. Claude Code statusline payload에 읽기 가능한 `transcript_path`가 포함되면 `cache <N>%`도 함께 표시됩니다 — 이는 transcript 끝부분에서 계산한 cache_read 비중입니다. transcript가 없거나 읽을 수 없거나 `python3`가 없으면 cache 라벨만 빠지고 나머지 statusline은 그대로 동작합니다.

`claude-token-statusline-merged`는 `examples/settings.example.json`의 default statusline이며, [oh-my-claudecode (OMC)](https://github.com/Yeachan-Heo/oh-my-claudecode)가 함께 설치되어 있으면 OMC HUD와 자동으로 결합됩니다. wrapper는 `~/.claude/hud/omc-hud.mjs`의 OMC HUD를 자동 감지합니다 — 있으면 OMC의 5h/week/session 사용량 뒤에 본 플러그인의 `cost`/`cache`가 붙고, 없으면 평소 `claude-token-statusline`처럼만 동작하므로 OMC를 쓰지 않는 사용자에게는 동작 변화가 없습니다. 설치 레이아웃이 다르면 `OMC_HUD_SCRIPT`, `CLAUDE_TOKEN_STATUSLINE_BIN` 환경변수로 경로를 지정하세요.

`claude-token-failed-nudge`는 같은 Bash 명령이 같은 세션에서 연속 두 번 실패하면 `/clear` (또는 `/compact focus on …`)을 권유하는 선택적 `PostToolUse` hook 입니다. 세 번째 반복 실패부터는 strategy-switch signal을 추가해 동일 명령 경로 재시도 대신 다른 가설, 더 작은 재현, 다른 진단 범위로 전환하게 합니다. 실패 시도가 누적되면 대화 컨텍스트가 오염되고 prompt cache 가 매 retry 마다 재워밍되어 토큰 비용이 급증합니다. 본 hook 은 짧은 추가 컨텍스트만 주입해 방향 전환을 유도합니다 (실행은 막지 않습니다). 기본 OFF이며 `claude-token-setup --failed-attempt-nudge` (또는 대화형 마법사의 "yes")로 명시적으로 켤 때만 활성화됩니다. 상태는 프로젝트 로컬 `.claude-token-optimizer/failures-<session>.json` (파일 모드 `0o600`)에 저장됩니다.

`claude-token-bench`는 `research/benchmark-plan.md` 실행을 자동화합니다. JSON fixture에서 task와 variant 정의를 읽어 각 조합에 대해 `claude -p --output-format json`을 호출하고, fixture 의 `success_command` 를 실행한 뒤 `tokens_per_successful_task` 측정용 CSV에 한 행을 append 합니다. `--ledger-jsonl` 을 추가하면 run별 cost-shift ledger를 남기고, `--report-json` 을 추가하면 baseline 대비 A/B report를 생성해 실제 token/cost 절감, proxy byte 감소, matched successful task coverage, 실패율 guardrail을 분리해 보여줍니다. `--dry-run` 은 실제 호출 없이 어떤 명령이 실행될지만 보여주고, `--resume` 은 CSV 에 이미 적재된 `(task_id, variant)` 쌍을 건너뜁니다. `success_command` 는 `shlex.split + shell=False` 로 실행되므로 fixture JSON 자체는 shell-injection 표면이 되지 않습니다 — 파이프·리디렉션이 필요한 검증은 별도 헬퍼 스크립트로 분리하고 그 경로를 `success_command` 로 둡니다.

`claude-token-rewrite-bash`는 예시 settings에서 사용하는 opt-in `PreToolUse` Bash hook입니다. 안전한 단일 test/build/lint 명령과 `find`/`tree` 같은 디렉터리 walk 출력은 `claude-trim-output`으로 감싸 head/tail 트리밍을 적용하고, 안전한 단일 `rg`/`grep`/`git diff` 계열 명령과 production 로그 스트림(`kubectl logs`, `docker logs`, `docker compose logs`, `docker stack logs`)은 `claude-sanitize-output`으로 감싸 secret redact와 트리밍을 함께 적용합니다. 파이프·리디렉션·명령 치환 등 컴파운드 셸 구문은 wrap 대상에서 제외해 단일 안전 argv 명령에만 적용됩니다.

```bash
./plugins/claude-token-optimizer/bin/claude-read-symbol path/to/file.py TargetSymbol
```

### 긴 output 축약

```bash
./plugins/claude-token-optimizer/bin/claude-trim-output --max-lines 120 -- npm test
```

감싼 명령의 exit code를 보존하며, pytest/Jest/Vitest/Go/Rust test 실패 요약을 우선 보존합니다. head/tail 로그 대신 더 작은 의미 요약만 필요하면 `--digest markdown` 또는 `--digest json`을 추가하세요. digest mode는 status, exit code, truncation count, runner failure facts, 대표 라인, redaction count, 다음 query 제안을 남깁니다. 감싼 명령은 기본 600초 후 timeout 처리되며(`--timeout-seconds`로 조정), 가능한 환경에서는 process group까지 종료한 뒤 124를 반환합니다. ANSI color code는 제거하고 absolute path는 기본적으로 익명화합니다.

### grep/diff sanitizer

```bash
./plugins/claude-token-optimizer/bin/claude-sanitize-output -- rg -n "TOKEN|SECRET" .
./plugins/claude-token-optimizer/bin/claude-sanitize-output -- git diff
```

`claude-sanitize-output`도 wrapper mode에서 동일한 기본 600초 timeout을 적용해 grep/diff/log 명령이 멈춰도 Claude 세션이 무기한 대기하지 않게 합니다.

credential pattern, private key block, auth header, credential URL을 redact하고, 긴 결과는 head / grep·diff·security anchor / tail로 줄입니다. Wrapper mode는 감싼 명령의 exit code를 그대로 보존합니다. Stdin pipe mode는 임시 정리에 쓸 수 있지만 producer exit code는 shell `pipefail` 없이는 알 수 없습니다.

## 로컬 배포 테스트

Marketplace 저장소 루트에서:

```bash
claude --plugin-dir ./plugins/claude-token-optimizer
```

Claude Code 안에서:

```text
/claude-token-optimizer:setup
```

Marketplace 설치 테스트:

```text
/plugin marketplace add ./
/plugin install claude-token-optimizer@claude-token-tools
```

## 라이선스

Copyright 2026 jinhongan. Apache License 2.0으로 배포됩니다. [LICENSE](LICENSE)와 [NOTICE](NOTICE)를 참고하세요.
