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
# 외부 HUD/runtime 연동은 ambient 환경변수가 아니라 setup이 고정한 절대 경로
# 옵션으로만 허용한다. 미지정 시 자기 옆 ContextGuard statusline만 사용한다.
set -u

PATH=/usr/bin:/bin
export PATH
unset BASH_ENV ENV CDPATH PYTHONHOME PYTHONPATH PYTHONSTARTUP
unset OMC_HUD_SCRIPT CONTEXT_GUARD_STATUSLINE_BIN CLAUDE_TOKEN_STATUSLINE_BIN

approved_bash=''
approved_python=''
approved_token_statusline=''
approved_node=''
approved_omc_script=''
while (( $# > 0 )); do
  case "$1" in
    --help|-h)
      printf 'ContextGuard helper: context-guard-statusline-merged\n'
      exit 0
      ;;
    --approved-bash|--approved-python|--approved-token-statusline|--approved-node|--approved-omc-script)
      if (( $# < 2 )); then
        printf '[runtime-error] missing approved runtime path\n'
        exit 0
      fi
      case "$1" in
        --approved-bash) approved_bash=$2 ;;
        --approved-python) approved_python=$2 ;;
        --approved-token-statusline) approved_token_statusline=$2 ;;
        --approved-node) approved_node=$2 ;;
        --approved-omc-script) approved_omc_script=$2 ;;
      esac
      shift 2
      ;;
    *)
      printf '[runtime-error] unsupported statusline option\n'
      exit 0
      ;;
  esac
done

approved_regular_file() {
  [[ "$1" = /* && -f "$1" && ! -L "$1" ]]
}

approved_executable_file() {
  approved_regular_file "$1" && [[ -x "$1" ]]
}

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
  if [[ -x /usr/bin/perl && -f /usr/bin/perl && ! -L /usr/bin/perl ]]; then
    /usr/bin/perl -pe 's/\e\][^\a\e]*(?:\a|\e\\)//g; s/\e[@-_][0-?]*[ -\/]*[@-~]//g'
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
if approved_executable_file "$approved_node" && approved_regular_file "$approved_omc_script"; then
  omc_out=$(printf '%s' "$input" | "$approved_node" "$approved_omc_script" 2>/dev/null || true)
  omc_out=$(sanitize_statusline "$omc_out")
fi

# ── 2) context-guard-statusline 바이너리 위치 결정 ────────────────────────────
# setup이 고정한 절대 helper → 자기 옆 디렉토리 순서만 허용한다.
tok_bin=''
if approved_executable_file "$approved_token_statusline"; then
  tok_bin=$approved_token_statusline
fi
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
  tok_basename=${tok_bin##*/}
  if [[ "$tok_basename" == "context-guard-statusline" || "$tok_basename" == "claude-token-statusline" || "$tok_basename" == "statusline.sh" ]]; then
    tok_bash=$approved_bash
    if ! approved_executable_file "$tok_bash"; then
      tok_bash=$(command -v bash 2>/dev/null || true)
    fi
    if approved_executable_file "$tok_bash"; then
      tok_command=("$tok_bash" --noprofile --norc "$tok_bin")
      if approved_executable_file "$approved_python"; then
        tok_command+=(--approved-python "$approved_python")
      fi
      tok_out=$(printf '%s' "$input" | "${tok_command[@]}" 2>/dev/null || true)
    fi
  else
    tok_out=$(printf '%s' "$input" | "$tok_bin" 2>/dev/null || true)
  fi
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
