#!/usr/bin/env bash
# OMC HUD 와 claude-token-statusline 을 하나로 결합하는 statusline wrapper.
#
# 동작 매트릭스:
#   ─────────────────────────────────────────────────────────────────────────
#   OMC HUD 존재? │ token-statusline 존재? │ 출력
#   ─────────────────────────────────────────────────────────────────────────
#   yes           │ yes                    │ OMC HUD + cost/cache 결합 (1줄)
#   yes           │ no                     │ OMC HUD 단독
#   no            │ yes                    │ token-statusline 단독
#   no            │ no                     │ "[hud unavailable]"
#   ─────────────────────────────────────────────────────────────────────────
#
# 입력: stdin 으로 Claude Code 가 넘기는 statusline JSON 한 줄.
# 출력: stdout 한 줄.
#
# 환경변수(선택, 테스트/커스텀 설치용):
#   OMC_HUD_SCRIPT             OMC HUD 스크립트 경로 (기본 $HOME/.claude/hud/omc-hud.mjs)
#   CLAUDE_TOKEN_STATUSLINE_BIN claude-token-statusline 바이너리 경로
#                              (미지정 시 자기 옆 디렉토리만 사용; PATH 탐색 안 함)
set -u

input=$(cat)

sanitize_statusline() {
  # Claude statusline output must stay a single bounded terminal line. Treat
  # helper output as display data, not trusted terminal control text.
  printf '%s' "$1" \
    | LC_ALL=C tr '\r\n' '  ' \
    | LC_ALL=C tr -d '\000-\010\013\014\016-\037\177' \
    | cut -c 1-1000
}

# ── 1) OMC HUD 출력 ──────────────────────────────────────────────────────────
omc_out=''
omc_script="${OMC_HUD_SCRIPT:-$HOME/.claude/hud/omc-hud.mjs}"
if [[ -r "$omc_script" ]] && command -v node >/dev/null 2>&1; then
  omc_out=$(printf '%s' "$input" | node "$omc_script" 2>/dev/null || true)
  omc_out=$(sanitize_statusline "$omc_out")
fi

# ── 2) claude-token-statusline 바이너리 위치 결정 ────────────────────────────
# 우선순위: 환경변수 → 자기 옆 디렉토리
# PATH fallback 은 workspace/plugin 경로 shadowing 으로 untrusted binary 를
# 실행할 수 있어 사용하지 않는다. 외부 바이너리를 쓰려면 명시적으로
# CLAUDE_TOKEN_STATUSLINE_BIN 을 지정해야 한다.
tok_bin="${CLAUDE_TOKEN_STATUSLINE_BIN:-}"
if [[ -z "$tok_bin" ]]; then
  self_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
  for cand in \
    "$self_dir/claude-token-statusline" \
    "$self_dir/statusline.sh"; do
    if [[ -x "$cand" ]]; then
      tok_bin="$cand"
      break
    fi
  done
fi
tok_out=''
if [[ -n "$tok_bin" && -x "$tok_bin" ]]; then
  tok_out=$(printf '%s' "$input" | "$tok_bin" 2>/dev/null || true)
  tok_out=$(sanitize_statusline "$tok_out")
fi

# ── 3) 결합: OMC HUD 가 살아있을 때만 token 출력에서 cost/cache 만 뽑아 붙임 ─
# token-statusline 형식: "[model] dir | branch | ctx N% | cost $N.NNN | cache N%"
# OMC HUD 와 중복되는 model/dir/branch/ctx 는 버리고 cost/cache 만 채택한다.
extras=''
if [[ -n "$omc_out" && -n "$tok_out" ]]; then
  if [[ "$tok_out" =~ \|[[:space:]]+cost[[:space:]]+(\$[0-9.]+|n/a) ]]; then
    extras+=" | cost ${BASH_REMATCH[1]}"
  fi
  if [[ "$tok_out" =~ \|[[:space:]]+cache[[:space:]]+([0-9]+%) ]]; then
    extras+=" | cache ${BASH_REMATCH[1]}"
  fi
fi

# ── 4) 출력 ──────────────────────────────────────────────────────────────────
if [[ -n "$omc_out" ]]; then
  printf '%s%s\n' "$omc_out" "$extras"
elif [[ -n "$tok_out" ]]; then
  printf '%s\n' "$tok_out"
else
  printf '[hud unavailable]\n'
fi
