# claude-token-kit

Claude Code CLI token 절감을 위한 실험용 도구 모음입니다. 전부 Python/Bash 표준 기능만 사용합니다.

## 구성

- `statusline.sh` — context/cost/model을 status line에 표시
- `trim_command_output.py` — 긴 명령 output을 head/tail/error 중심으로 축약하고 원래 exit code 보존
- `rewrite_bash_for_token_budget.py` — Claude Code `PreToolUse` hook에서 test/build/lint 명령을 wrapper로 감쌈
- `claude_transcript_cost_audit.py` — `~/.claude/projects` JSONL transcript에서 usage/cost field를 찾아 합산
- `settings.example.json` — project `.claude/settings.json` 예시
- `aux_ai_delegate.py` — Gemini/Codex 같은 보조 AI CLI를 opt-in으로 호출해 Claude context를 절약

## 빠른 실험

```bash
python3 claude-token-kit/trim_command_output.py --max-lines 80 -- bash -lc 'seq 1 1000; echo FAIL test_x >&2; exit 1'
python3 claude-token-kit/claude_transcript_cost_audit.py ~/.claude/projects --top 10
python3 claude-token-kit/aux_ai_delegate.py status
python3 claude-token-kit/aux_ai_delegate.py enable --provider gemini
python3 claude-token-kit/aux_ai_delegate.py ask --provider gemini --prompt "Summarize this log" --context ./log.txt
python3 claude-token-kit/aux_ai_delegate.py disable
```

Claude Code에 적용하려면 `settings.example.json`을 `.claude/settings.json`으로 복사하되, 먼저 작은 repo에서 quoting/exit code를 확인하세요.


## 보조 AI 위임

`aux_ai_delegate.py`는 기본 OFF입니다. 활성화하면 Gemini CLI 또는 Codex CLI 같은 별도 AI 구독을 read-only 분석 비서로 사용하고, Claude에는 짧은 preview만 돌려줍니다.

```bash
python3 claude-token-kit/aux_ai_delegate.py enable --provider codex
python3 claude-token-kit/aux_ai_delegate.py ask --provider codex --prompt "Which files should Claude inspect first?" --context ./error.log
python3 claude-token-kit/aux_ai_delegate.py disable
```

외부 provider로 파일 내용이 전송될 수 있으므로 secrets/private data는 보내지 마세요.


보조 AI 위임은 `.env*`, key 파일, token/secret 이름 파일 같은 secret-like context paths를 기본 차단합니다. 정말 필요한 경우에만 `--allow-sensitive-context`를 명시하세요. 전체 보조 AI 응답은 `.claude-token-optimizer/` 아래에 저장되며, 도구가 해당 디렉터리에 private `.gitignore`를 자동 생성합니다.
