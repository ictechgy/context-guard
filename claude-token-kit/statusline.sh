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

# Cache hit rate from the transcript tail (best-effort, fast — reads only the last 1MB).
# Stays empty when transcript is unavailable or python3 fails so the status line never breaks.
# NOTE: keep the token-key list and usage-extraction shape in sync with claude_transcript_cost_audit.py
# so the statusline metric matches the audit metric for the same transcript.
cache_label=''
transcript_path=$(jq_get '.transcript_path')
if [[ -n "$transcript_path" && -r "$transcript_path" ]] && command -v python3 >/dev/null 2>&1; then
  rate=$(python3 - "$transcript_path" 2>/dev/null <<'PYEOF' || true
import json
import os
import sys

path = sys.argv[1] if len(sys.argv) > 1 else ""
if not path or not os.path.isfile(path):
    sys.exit(0)

# Bounded tail read so the statusline never stalls on huge transcripts.
TAIL_BYTES = 1024 * 1024
MAX_RECORDS = 300


def _int_or_zero(value):
    """transcript usage 토큰값을 정수로 강제. bool은 int 서브클래스이므로 별도 차단."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return max(0, value)
    return 0


def _extract_usage(record):
    """transcript record에서 알려진 usage 객체 1개만 꺼낸다.

    Claude Code transcript JSONL은 record 당 한 번의 LLM 호출 usage를 다음 중 한 자리에
    넣는 것이 일반적이다 — top-level "usage", "message.usage", "response.usage".
    재귀 walk 대신 알려진 경로만 보아야 동일 값이 여러 nested 사본으로 들어왔을 때
    이중 합산되는 문제를 피할 수 있다.
    """
    if not isinstance(record, dict):
        return None
    for path_keys in (("usage",), ("message", "usage"), ("response", "usage")):
        cur = record
        for key in path_keys:
            if not isinstance(cur, dict):
                cur = None
                break
            cur = cur.get(key)
        if isinstance(cur, dict):
            return cur
    return None


input_tokens = cache_read = cache_creation = 0

try:
    size = os.path.getsize(path)
    read_size = min(size, TAIL_BYTES)
    with open(path, "rb") as fh:
        if size > read_size:
            fh.seek(size - read_size)
        chunk = fh.read(read_size)
    lines = chunk.splitlines()
    if size > read_size and lines:
        # First line in the tail window is likely partial; drop it.
        lines = lines[1:]
    for raw in lines[-MAX_RECORDS:]:
        if not raw.strip():
            continue
        try:
            obj = json.loads(raw)
        except Exception:
            continue
        usage = _extract_usage(obj)
        if not usage:
            continue
        input_tokens += _int_or_zero(usage.get("input_tokens"))
        cr = usage.get("cache_read_input_tokens")
        if cr is None:
            cr = usage.get("cacheRead")
        cache_read += _int_or_zero(cr)
        cc = usage.get("cache_creation_input_tokens")
        if cc is None:
            cc = usage.get("cacheCreation")
        cache_creation += _int_or_zero(cc)
    denom = input_tokens + cache_read + cache_creation
    # Skip the label entirely on empty / cache-cold sessions so the user does not see a
    # confusing "cache 0%" before the cache has had a chance to warm up.
    if denom <= 0 or cache_read <= 0:
        sys.exit(0)
    pct = max(0.0, min(100.0, cache_read / denom * 100))
    print(f"{pct:.0f}")
except Exception:
    sys.exit(0)
PYEOF
  )
  if [[ -n "$rate" ]]; then
    rate=$(sanitize_status "$rate")
    cache_label=" | cache ${rate}%"
  fi
fi

# Keep it one line and cheap: this script runs locally and should not do expensive git status.
echo "[$model] ${dir}${branch} | ctx ${context_pct}% | cost ${cost}${cache_label}"
