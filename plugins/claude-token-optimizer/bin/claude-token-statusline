#!/usr/bin/env bash
set -euo pipefail

if [[ -t 0 ]]; then
  echo "usage: pass Claude Code statusline JSON on stdin"
  exit 0
fi

input=$(cat)

if ! command -v jq >/dev/null 2>&1; then
  echo "[needs-jq] install jq for Claude token statusline"
  exit 0
fi

jq_get() {
  jq -r "$1 // empty" <<<"$input" 2>/dev/null || true
}

sanitize_status() {
  # Statusline values may come from untrusted workspace metadata; keep one-line printable text.
  LC_ALL=C tr -cd '[:print:]' <<<"$1" | cut -c 1-160
}

model=$(jq_get '.model.display_name')
model=${model:-$(jq_get '.model.id')}
model=${model:-unknown}
model=$(sanitize_status "$model")

context_pct=$(jq_get '.context_window.used_percentage')
if [[ -n "$context_pct" ]]; then
  context_pct=$(printf '%.0f' "$context_pct" 2>/dev/null || sanitize_status "$context_pct")
else
  context_pct="?"
fi

cost=$(jq_get '.cost.total_cost_usd')
if [[ -n "$cost" ]]; then
  cost=$(printf '$%.3f' "$cost" 2>/dev/null || sanitize_status "$cost")
else
  cost='n/a'
fi

cwd=$(jq_get '.workspace.current_dir')
dir=${cwd##*/}
dir=${dir:-.}
dir=$(sanitize_status "$dir")

branch=''
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  b=$(git branch --show-current 2>/dev/null || true)
  if [[ -n "$b" ]]; then
    b=$(sanitize_status "$b")
    branch=" | ${b}"
  fi
fi

# Keep it one line and cheap: this script runs locally and should not do expensive git status.
echo "[$model] ${dir}${branch} | ctx ${context_pct}% | cost ${cost}"
