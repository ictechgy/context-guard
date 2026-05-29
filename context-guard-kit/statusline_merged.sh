#!/usr/bin/env bash
# OMC HUD 와 context-guard-statusline 을 하나로 결합하는 statusline wrapper.
#
# 동작 매트릭스:
#   ─────────────────────────────────────────────────────────────────────────
#   OMC HUD 존재? │ token-statusline 존재? │ 출력
#   ─────────────────────────────────────────────────────────────────────────
#   yes           │ yes                    │ OMC HUD + cost/cache/reuse 결합 (1줄)
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
#   CONTEXT_GUARD_STATUSLINE_BIN context-guard-statusline 바이너리 경로
#                              (legacy: CLAUDE_TOKEN_STATUSLINE_BIN)
#                              (미지정 시 자기 옆 디렉토리만 사용; PATH 탐색 안 함)
set -u

statusline_input_tmp=''

statusline_tmp_base() {
  local candidate="${TMPDIR:-/tmp}" resolved
  if [[ "$candidate" != "/" ]]; then
    candidate="${candidate%/}"
  fi
  if [[ -z "$candidate" || "$candidate" != /* || ! -d "$candidate" || ! -w "$candidate" ]]; then
    candidate="/tmp"
  fi
  if resolved=$(cd "$candidate" 2>/dev/null && pwd -P); then
    if [[ "$resolved" != "/" ]]; then
      resolved="${resolved%/}"
    fi
    printf '%s\n' "${resolved:-/}"
  else
    printf '/tmp\n'
  fi
}

statusline_input_max_bytes() {
  local raw="${CONTEXT_GUARD_STATUSLINE_INPUT_MAX_BYTES:-${CLAUDE_TOKEN_STATUSLINE_INPUT_MAX_BYTES:-65536}}" max=65536
  if [[ "$raw" =~ ^[0-9]+$ ]] && (( ${#raw} <= 7 )); then
    max=$((10#$raw))
  fi
  if (( max < 1 || max > 1048576 )); then
    max=65536
  fi
  printf '%s\n' "$max"
}

read_bounded_statusline_input() {
  local max input_len tmp_base
  max=$(statusline_input_max_bytes)
  tmp_base=$(statusline_tmp_base)
  statusline_input_tmp=$(mktemp "$tmp_base/context-guard-statusline.XXXXXX") || {
    printf '[input-error] could not create statusline input buffer\n'
    exit 0
  }
  trap 'rm -f "${statusline_input_tmp:-}"' EXIT
  LC_ALL=C head -c "$((max + 1))" >"$statusline_input_tmp" 2>/dev/null || true
  input_len=$(LC_ALL=C wc -c <"$statusline_input_tmp" | tr -d '[:space:]')
  if (( input_len > max )); then
    printf '[input-too-large] Claude statusline JSON exceeds %s bytes\n' "$max"
    exit 0
  fi
  input=$(cat "$statusline_input_tmp" 2>/dev/null || true)
  rm -f "$statusline_input_tmp"
  statusline_input_tmp=''
  trap - EXIT
}

read_bounded_statusline_input

strip_terminal_sequences() {
  if command -v perl >/dev/null 2>&1; then
    perl -pe 's/\e\][^\a\e]*(?:\a|\e\\)//g; s/\e[@-_][0-?]*[ -\/]*[@-~]//g'
  else
    cat
  fi
}

sanitize_statusline() {
  # Claude statusline output must stay a single bounded terminal line. Treat
  # helper output as display data, not trusted terminal control text.
  local cleaned
  cleaned=$(printf '%s' "$1" \
    | strip_terminal_sequences \
    | LC_ALL=C tr '\r\n' '  ' \
    | LC_ALL=C tr -d '\000-\010\013\014\016-\037\177-\237' \
    | cut -c 1-1000)
  if printf '%s' "$cleaned" | LC_ALL=C grep -Eiq '(gh[pousr]_|github_pat_|glpat-|xox[abprs]-|AKIA|ASIA|sk-|npm_|AIza|Bearer[[:space:]]|Basic[[:space:]])'; then
    printf '[redacted]'
  else
    printf '%s' "$cleaned"
  fi
}

# ── 1) OMC HUD 출력 ──────────────────────────────────────────────────────────
omc_out=''
omc_script="${OMC_HUD_SCRIPT:-$HOME/.claude/hud/omc-hud.mjs}"
if [[ -r "$omc_script" ]] && command -v node >/dev/null 2>&1; then
  omc_out=$(printf '%s' "$input" | node "$omc_script" 2>/dev/null || true)
  omc_out=$(sanitize_statusline "$omc_out")
fi

# ── 2) context-guard-statusline 바이너리 위치 결정 ────────────────────────────
# 우선순위: 환경변수 → 자기 옆 디렉토리
# PATH fallback 은 workspace/plugin 경로 shadowing 으로 untrusted binary 를
# 실행할 수 있어 사용하지 않는다. 외부 바이너리를 쓰려면 명시적으로
# CONTEXT_GUARD_STATUSLINE_BIN 을 지정해야 한다.
tok_bin="${CONTEXT_GUARD_STATUSLINE_BIN:-${CLAUDE_TOKEN_STATUSLINE_BIN:-}}"
if [[ -z "$tok_bin" ]]; then
  self_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
  for cand in \
    "$self_dir/context-guard-statusline" \
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

# ── 3) 결합: OMC HUD 가 살아있을 때만 token 출력에서 compact extras 만 뽑아 붙임 ─
# token-statusline 형식:
#   "[model] dir | branch | ctx N% | cost $N.NNN | cache N% | reuse N.Nx"
# OMC HUD 와 중복되는 model/dir/branch/ctx 는 버리고 cost/cache/reuse 만 채택한다.
extras=''
if [[ -n "$omc_out" && -n "$tok_out" ]]; then
  if [[ "$tok_out" =~ \|[[:space:]]+cost[[:space:]]+(\$[0-9.]+|n/a) ]]; then
    extras+=" | cost ${BASH_REMATCH[1]}"
  fi
  if [[ "$tok_out" =~ \|[[:space:]]+cache[[:space:]]+([0-9]+%) ]]; then
    extras+=" | cache ${BASH_REMATCH[1]}"
  fi
  if [[ "$tok_out" =~ \|[[:space:]]+reuse[[:space:]]+([0-9]+(\.[0-9]+)?x|n/a) ]]; then
    extras+=" | reuse ${BASH_REMATCH[1]}"
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
