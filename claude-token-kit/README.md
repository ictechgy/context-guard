# claude-token-kit

Claude Code CLI token 절감을 위한 실험용 도구 모음입니다. 전부 Python/Bash 표준 기능만 사용합니다.

## 구성

- `statusline.sh` — context/cost/model을 status line에 표시
- `trim_command_output.py` — 긴 명령 output을 head/tail/error 및 pytest/Jest/Vitest/Go/Rust 실패 요약 중심으로 축약하고 원래 exit code 보존
- `rewrite_bash_for_token_budget.py` — Claude Code `PreToolUse` hook에서 test/build/lint 명령을 wrapper로 감쌈
- `claude_transcript_cost_audit.py` — `~/.claude/projects` JSONL transcript에서 usage/cost field를 찾아 합산하고 `--recommend`로 절감 액션 제안
- `claude_token_diet.py` — project `.claude/settings.json` deny/hook/statusline과 `CLAUDE.md`/`AGENTS.md` context bloat를 스캔
- `settings.example.json` — project `.claude/settings.json` 예시
- `aux_ai_delegate.py` — Gemini/Codex 같은 보조 AI CLI를 opt-in으로 호출해 Claude context를 절약

## 빠른 실험

```bash
python3 claude-token-kit/trim_command_output.py --max-lines 80 -- bash -lc 'seq 1 1000; echo FAIL test_x >&2; exit 1'
python3 claude-token-kit/trim_command_output.py --max-lines 80 -- pytest tests -q
python3 claude-token-kit/claude_transcript_cost_audit.py ~/.claude/projects --top 10 --recommend
python3 claude-token-kit/claude_token_diet.py scan . --json
python3 claude-token-kit/aux_ai_delegate.py status
python3 claude-token-kit/aux_ai_delegate.py enable --provider gemini
python3 claude-token-kit/aux_ai_delegate.py ask --provider gemini --prompt "Summarize this log" --context ./log.txt
python3 claude-token-kit/aux_ai_delegate.py disable
```

`trim_command_output.py`는 output이 budget을 넘을 때 runner별 failure summary를 먼저 보여줍니다. 예를 들어 pytest node id, Jest/Vitest 실패 파일/테스트, `go test`의 실패 test와 `_test.go:line`, `cargo test` panic 위치를 짧게 보존해 Claude가 전체 로그를 다시 읽지 않아도 다음 수정 파일을 고를 수 있게 합니다. ANSI color code는 제거하고, 절대경로는 기본적으로 `basename#path:<hash>`로 익명화합니다. 로컬 디버깅에서 원문 절대경로가 꼭 필요하면 `--show-paths`를 추가하세요.

`claude_transcript_cost_audit.py --recommend`의 기본 출력은 공유 안전성을 위해 transcript 경로를 `basename#hash`, 명령을 `command#hash` 형태로 익명화합니다. 로컬 원문 식별자가 꼭 필요할 때만 `--show-paths` 또는 `--show-commands`를 추가하세요.

`claude_token_diet.py scan`은 항상 로컬에서만 읽는 read-only scanner입니다. 기본 출력은 project root를 익명화하고 상대경로 중심으로 보고합니다. `--show-paths`는 로컬/비공개 디버깅에서만 쓰세요.

Claude Code에 적용하려면 `settings.example.json`을 `.claude/settings.json`으로 복사하되, 먼저 작은 repo에서 quoting/exit code를 확인하세요.


## 보조 AI 위임

`aux_ai_delegate.py`는 기본 OFF입니다. 활성화하면 Gemini CLI 또는 Codex CLI 같은 별도 AI 구독을 read-only 분석 비서로 사용하고, Claude에는 짧은 preview만 돌려줍니다.

```bash
python3 claude-token-kit/aux_ai_delegate.py enable --provider codex
python3 claude-token-kit/aux_ai_delegate.py ask --provider codex --prompt "Which files should Claude inspect first?" --context ./error.log
python3 claude-token-kit/aux_ai_delegate.py disable
```

외부 provider로 파일 내용이 전송될 수 있으므로 secrets/private data는 보내지 마세요. 보조 AI의 preview와 저장된 전체 응답은 모두 검증 전까지 untrusted output으로 취급하세요.


보조 AI 위임은 기본적으로 project root 아래 파일만 context로 허용하고, outside-project paths, `.env*`, key 파일, token/secret 이름 파일, credential-like content를 차단합니다. 정책 검토 후 필요한 경우에만 trusted private config의 `context_policy`로 차단된 exact path를 명시적으로 allow하세요. CLI flag로 차단을 우회할 수는 없습니다. 전체 보조 AI 응답은 `.claude-token-optimizer/` 아래에 `0600` 파일로 저장되며, 도구가 해당 private state 디렉터리에 `.gitignore`를 자동 생성합니다.

Provider CLI는 임시 작업 디렉터리, isolated `HOME`/XDG/TMP, allowlisted environment로 실행됩니다. 따라서 OAuth credential이 필요한 CLI는 별도 provider API key 환경변수 또는 사용자가 검토한 custom provider 설정이 필요할 수 있습니다.
