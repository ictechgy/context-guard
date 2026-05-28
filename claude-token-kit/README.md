# claude-token-kit

Claude Code CLI 토큰 절감을 위한 실험용 도구 모음입니다. 모두 Python/Bash 표준 기능만 사용합니다.

## 구성

- `statusline.sh` — context/cost/model을 statusline에 표시
- `trim_command_output.py` — 긴 명령 output을 head/tail/error와 pytest/Jest/Vitest/Go/Rust 실패 요약 중심으로 축약하고 원래 exit code 보존
- `rewrite_bash_for_token_budget.py` — Claude Code `PreToolUse` hook에서 test/build/lint 명령을 wrapper로 감쌈
- `claude_transcript_cost_audit.py` — `~/.claude/projects` JSONL transcript에서 usage/cost field를 집계하고 `--recommend`로 절감 액션 제안
- `claude_token_diet.py` — project `.claude/settings.json` deny/hook/statusline과 `CLAUDE.md`/`AGENTS.md` context bloat를 스캔
- `guard_large_read.py` — Claude Code `PreToolUse` Read hook에서 큰 파일 전체 읽기를 막고 symbol/line-range 읽기로 유도
- `read_symbol.py` — Python/JS/TS/Go/Rust 파일에서 지정 symbol 주변만 출력
- `sanitize_output.py` — `rg`/`grep`/`git diff` 같은 검색·diff output에서 credential을 redact하고 head/anchor/tail로 축약
- `context_escrow.py` — 큰 command output을 sanitize 후 로컬 artifact로 저장하고 line/pattern query로 다시 조회
- `setup_wizard.py` — 설치 후 project-local `.claude/settings.json`을 대화형으로 선택하고 병합
- `settings.example.json` — project `.claude/settings.json` 예시
- `aux_ai_delegate.py` — Gemini/Codex 같은 보조 AI CLI를 opt-in으로 호출해 Claude context를 절약

## 빠른 실험

```bash
python3 claude-token-kit/trim_command_output.py --max-lines 80 -- bash -lc 'seq 1 1000; echo FAIL test_x >&2; exit 1'
python3 claude-token-kit/trim_command_output.py --max-lines 80 -- pytest tests -q
python3 claude-token-kit/claude_transcript_cost_audit.py ~/.claude/projects --top 10 --recommend
python3 claude-token-kit/setup_wizard.py
python3 claude-token-kit/claude_token_diet.py scan . --json
python3 claude-token-kit/read_symbol.py path/to/file.py TargetSymbol
long-command 2>&1 | python3 claude-token-kit/context_escrow.py store --command "long-command" --json
python3 claude-token-kit/context_escrow.py get <artifact_id> --lines 1:80
python3 claude-token-kit/sanitize_output.py -- rg -n "TOKEN|SECRET" .
python3 claude-token-kit/sanitize_output.py -- git diff
python3 claude-token-kit/aux_ai_delegate.py status
python3 claude-token-kit/aux_ai_delegate.py enable --provider gemini
python3 claude-token-kit/aux_ai_delegate.py ask --provider gemini --prompt "Summarize this log" --context ./log.txt
python3 claude-token-kit/aux_ai_delegate.py disable
```

`trim_command_output.py`는 output이 budget을 넘을 때 runner별 failure summary를 먼저 보여줍니다. 예를 들어 pytest node id, Jest/Vitest 실패 파일/테스트, `go test`의 실패 test와 `_test.go:line`, `cargo test` panic 위치를 짧게 보존해 Claude가 전체 로그를 다시 읽지 않고도 다음에 수정할 파일을 고를 수 있게 합니다. head/tail 로그 대신 더 작은 의미 요약만 필요하면 `--digest markdown` 또는 `--digest json`을 추가하세요. digest mode는 status, exit code, truncation count, runner failure facts, 대표 라인, redaction count, 다음 query 제안을 남깁니다. 감싼 명령은 기본 600초 후 timeout 처리되며(`--timeout-seconds`로 조정), 가능한 환경에서는 process group까지 종료한 뒤 124를 반환합니다. ANSI color code는 제거하며, 절대경로는 기본적으로 `basename#path:<hash>`로 익명화합니다. 로컬 디버깅에서 원문 절대경로가 꼭 필요하면 `--show-paths`를 추가하세요.

`context_escrow.py`는 대용량 output을 Claude context에 그대로 넣지 않고 `.claude-token-optimizer/artifacts` 아래 `0o600` 파일로 저장합니다. 저장 전에 sanitizer를 적용해 secret/path 노출을 줄이고, receipt에는 `artifact_id`, line/byte count, top error lines, 대표 head/tail, `get --lines`/`get --pattern` query 예시만 출력합니다. 저장된 artifact는 sanitize된 사본이며, 필요할 때만 `get <artifact_id> --lines 10:40`처럼 정확한 범위를 조회하세요.

`claude_transcript_cost_audit.py --recommend`의 기본 출력은 공유 시 안전하도록 transcript 경로를 `basename#hash`, 명령을 `command#hash` 형태로 익명화합니다. 로컬 원문 식별자가 꼭 필요할 때만 `--show-paths` 또는 `--show-commands`를 추가하세요.
대용량/손상 transcript 방어를 위해 파일 단위 `--max-file-bytes`, JSONL record 단위 `--max-line-bytes` 제한도 기본 적용되며, 건너뛴 항목은 skip count와 warning으로 노출됩니다.

`claude_token_diet.py scan`은 항상 로컬에서만 읽는 read-only 스캐너입니다. 기본 출력은 project root를 익명화하고 상대경로 중심으로 보고합니다. `--show-paths`는 로컬/비공개 디버깅에서만 쓰세요.

`setup_wizard.py`는 설치 후 한 번 실행하는 설정 마법사입니다. 터미널에서 실행하면 deny rules, statusline, Bash trim/sanitize hook, large Read guard, model/effort defaults, 선택적 Gemini/Codex delegation을 물어보고 project-local `.claude/settings.json`에 병합합니다. 비대화형 환경에서는 `--plan`으로 미리 보고 `--yes`로 추천값을 적용하세요. 보조 AI 수동 위임은 명시적으로 `--aux-provider gemini|codex`를 선택할 때만 켜지고, 자동 위임은 `--auto-delegate`를 함께 지정할 때만 해당 provider에 대해 켜집니다. `--aux-provider`만으로 다시 실행하면 이전 자동 위임 동의 상태는 해제됩니다.

`guard_large_read.py`는 opt-in Read hook입니다. 큰 파일 전체를 Claude context에 넣기 전에 `rg -n`으로 symbol 후보를 찾고, `read_symbol.py`로 필요한 함수/클래스 주변만 읽도록 안내합니다. `CLAUDE_TOKEN_READ_GUARD=0`으로 로컬에서 일시 비활성화할 수 있습니다.

`sanitize_output.py`는 grep/diff output을 Claude에게 보여주기 전에 secret-like line, Authorization header, private key block, API token, credential URL을 `[REDACTED]`로 바꾸고, 긴 결과는 head / grep·diff·security anchor / tail만 남깁니다. 명령을 감싸는 wrapper mode는 원래 exit code를 보존합니다. stdin pipe도 지원하지만 producer exit code는 shell `pipefail` 없이는 알 수 없으므로 자동화에는 `python3 .../sanitize_output.py -- rg ...`처럼 wrapper mode를 선호하세요. 절대경로는 기본 익명화되고 로컬 디버깅에서만 `--show-paths`를 쓰세요. `rewrite_bash_for_token_budget.py` hook은 단일 argv 형태의 `rg`, `grep`, `git grep`, `git diff`, `git show`, `git log -p`를 자동으로 이 sanitizer에 감쌉니다.

Claude Code에 적용하려면 `settings.example.json`을 `.claude/settings.json`으로 복사하되, 먼저 작은 repo에서 quoting/exit code를 확인하세요.


## 보조 AI 위임

`aux_ai_delegate.py`는 기본 OFF입니다. 활성화하면 Gemini CLI나 Codex CLI를 read-only 분석 보조로 사용하고, Claude에는 짧은 preview만 반환합니다.

```bash
python3 claude-token-kit/aux_ai_delegate.py enable --provider codex
python3 claude-token-kit/aux_ai_delegate.py auto-enable
python3 claude-token-kit/aux_ai_delegate.py ask --provider codex --prompt "Which files should Claude inspect first?" --context ./error.log
python3 claude-token-kit/aux_ai_delegate.py disable
```

외부 provider로 파일 내용이 전송될 수 있으므로 secrets/private data는 보내지 마세요. 보조 AI의 preview와 저장된 전체 응답은 검증 전까지 모두 untrusted output으로 취급하세요.

자동 위임은 provider별로 별도 opt-in이 필요합니다. 수동 delegation을 켠 뒤 `auto-enable`을 실행한 경우에만 상위 plugin skill이 긴 로그, 넓은 파일 triage, 원인 가설 생성처럼 안전한 read-only 후보를 현재/default provider에 자동 위임할 수 있습니다. 자동 위임은 `--provider`를 생략해 승인된 provider만 사용하고, helper-validated `--context`를 사용하며 blocked path, secret/customer data, policy-prohibited data를 계속 제외해야 합니다.


보조 AI 위임은 기본적으로 project root 아래 파일만 context로 허용하며, outside-project paths, `.env*`, key 파일, token/secret 이름 파일, credential-like content를 차단합니다. 정책 검토 후 꼭 필요한 경우에만 trusted private config의 `context_policy`에서 차단된 exact path를 명시적으로 허용하세요. CLI flag로 차단을 우회할 수는 없습니다. 보조 AI의 전체 응답은 `.claude-token-optimizer/` 아래에 `0600` 권한 파일로 저장되며, 도구가 해당 private state 디렉터리에 `.gitignore`를 자동 생성합니다.

Provider CLI는 임시 작업 디렉터리, 격리된 `HOME`/XDG/TMP, allowlisted environment에서 실행됩니다. 따라서 OAuth credential이 필요한 CLI는 별도 provider API key 환경변수 또는 사용자가 검토한 custom provider 설정이 필요할 수 있습니다.

## License

Copyright 2026 jinhongan. Licensed under the Apache License 2.0. See the repository [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
