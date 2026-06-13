#!/usr/bin/env bash
set -euo pipefail

if [[ -t 0 ]]; then
  echo "usage: pass Claude Code statusline JSON on stdin"
  exit 0
fi

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

statusline_context_warn_threshold() {
  local raw="${CONTEXT_GUARD_STATUSLINE_CTX_WARN:-${CLAUDE_TOKEN_STATUSLINE_CTX_WARN:-80}}" threshold=80
  if [[ "$raw" =~ ^[0-9]{1,3}$ ]]; then
    threshold=$((10#$raw))
    if (( threshold < 1 )); then
      threshold=1
    elif (( threshold > 100 )); then
      threshold=100
    fi
  fi
  printf '%s\n' "$threshold"
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

if ! command -v jq >/dev/null 2>&1; then
  echo "[needs-jq] install jq for Claude token statusline"
  exit 0
fi

statusline_fields=$(jq -r '[
  ("v:" + ((.model.display_name // "") | tostring)),
  ("v:" + ((.model.id // "") | tostring)),
  ("v:" + ((.context_window.used_percentage // "") | tostring)),
  ("v:" + ((.cost.total_cost_usd // "") | tostring)),
  ("v:" + ((.workspace.current_dir // "") | tostring)),
  ("v:" + ((.transcript_path // "") | tostring))
] | @tsv' <<<"$input" 2>/dev/null || true)
model_display=''
model_id=''
context_raw=''
cost_raw=''
cwd=''
transcript_path=''
IFS=$'\t' read -r model_display model_id context_raw cost_raw cwd transcript_path _ <<<"$statusline_fields"
model_display=${model_display#v:}
model_id=${model_id#v:}
context_raw=${context_raw#v:}
cost_raw=${cost_raw#v:}
cwd=${cwd#v:}
transcript_path=${transcript_path#v:}

strip_terminal_sequences() {
  if command -v perl >/dev/null 2>&1; then
    perl -pe 's/\e\][^\a\e]*(?:\a|\e\\)//g; s/\e[@-_][0-?]*[ -\/]*[@-~]//g'
  else
    cat
  fi
}

sanitize_status() {
  # Statusline values may come from untrusted workspace metadata; keep one-line printable text.
  local cleaned
  cleaned=$(printf '%s' "$1" \
    | strip_terminal_sequences \
    | LC_ALL=C tr '\r\n' '  ' \
    | LC_ALL=C tr -d '\000-\010\013\014\016-\037\177-\237' \
    | cut -c 1-160)
  if printf '%s' "$cleaned" | LC_ALL=C grep -Eiq '(gh[pousr]_|github_pat_|glpat-|xox[abprs]-|AKIA|ASIA|sk-|npm_|AIza|Bearer[[:space:]]|Basic[[:space:]])'; then
    printf '[redacted]'
  else
    printf '%s' "$cleaned"
  fi
}

git_head_branch() {
  # Keep the statusline cheap and non-blocking: do not invoke `git` here.  Some
  # workspaces have slow network filesystems, hydrated-on-demand git objects, or
  # broken config; reading .git/HEAD is enough for a best-effort branch label.
  local current="$1"
  local dotgit gitdir_line gitdir head_file head_line branch
  [[ -n "$current" && -d "$current" ]] || return 1
  current=$(cd "$current" 2>/dev/null && pwd -P) || return 1

  while [[ -n "$current" ]]; do
    head_file=''
    dotgit="$current/.git"
    if [[ -d "$dotgit" && ! -L "$dotgit" ]]; then
      head_file="$dotgit/HEAD"
    elif [[ -f "$dotgit" && ! -L "$dotgit" ]]; then
      IFS= read -r gitdir_line <"$dotgit" 2>/dev/null || gitdir_line=''
      if [[ "$gitdir_line" == gitdir:\ * ]]; then
        gitdir="${gitdir_line#gitdir: }"
        [[ "$gitdir" == /* ]] || gitdir="$current/$gitdir"
        if gitdir=$(cd "$gitdir" 2>/dev/null && pwd -P) && [[ -f "$gitdir/HEAD" && ! -L "$gitdir/HEAD" ]]; then
          head_file="$gitdir/HEAD"
        fi
      fi
    fi

    if [[ -n "$head_file" && -f "$head_file" && ! -L "$head_file" ]]; then
      IFS= read -r head_line <"$head_file" 2>/dev/null || return 1
      if [[ "$head_line" == ref:\ refs/heads/* ]]; then
        branch="${head_line#ref: refs/heads/}"
        [[ -n "$branch" ]] && printf '%s\n' "$branch"
        return 0
      fi
      if [[ "$head_line" =~ ^[0-9a-fA-F]{7,40}$ ]]; then
        printf '%s\n' "${head_line:0:12}"
        return 0
      fi
      return 1
    fi

    [[ "$current" == "/" ]] && break
    current="${current%/*}"
    [[ -n "$current" ]] || current="/"
  done
  return 1
}

model=$model_display
model=${model:-$model_id}
model=${model:-unknown}
model=$(sanitize_status "$model")

context_is_numeric=0
if [[ -n "$context_raw" ]]; then
  if context_pct=$(LC_NUMERIC=C printf '%.0f' "$context_raw" 2>/dev/null); then
    if [[ "$context_pct" =~ ^-?[0-9]+$ ]]; then
      context_is_numeric=1
    else
      context_pct=$(sanitize_status "$context_raw")
    fi
  else
    context_pct=$(sanitize_status "$context_raw")
  fi
else
  context_pct="?"
fi
context_label="${context_pct}%"
if (( context_is_numeric )); then
  context_warn_threshold=$(statusline_context_warn_threshold)
  if (( context_pct >= context_warn_threshold )); then
    context_label="${context_label} ⚠"
  fi
fi

cost=$cost_raw
if [[ -n "$cost" ]]; then
  cost=$(printf '$%.3f' "$cost" 2>/dev/null || sanitize_status "$cost")
else
  cost='n/a'
fi

dir=${cwd##*/}
dir=${dir:-.}
dir=$(sanitize_status "$dir")

branch=''
branch_dir=${cwd:-$PWD}
b=$(git_head_branch "$branch_dir" 2>/dev/null || true)
if [[ -n "$b" ]]; then
  b=$(sanitize_status "$b")
  branch=" | ${b}"
fi

# Cache metrics from the transcript tail (best-effort, fast — reads only the last 1MB).
# Stays empty when transcript is unavailable or python3 fails so the status line never breaks.
# NOTE: keep the token-key list and usage-extraction shape in sync with claude_transcript_cost_audit.py
# so the statusline metric matches the audit metric for the same transcript.
metrics_label=''
if [[ -n "$transcript_path" && -r "$transcript_path" ]] && command -v python3 >/dev/null 2>&1; then
  transcript_metrics=$(python3 - "$transcript_path" "$cwd" 2>/dev/null <<'PYEOF' || true
import json
import os
import re
import stat
import sys
import time
import hashlib
import math

path = sys.argv[1] if len(sys.argv) > 1 else ""
workspace_dir = sys.argv[2] if len(sys.argv) > 2 else ""
if not path:
    sys.exit(0)

# Bounded tail read so the statusline never stalls on huge transcripts.
TAIL_BYTES = 1024 * 1024
MAX_RECORDS = 300
CACHE_SCHEMA_VERSION = 1
DEFAULT_CACHE_TTL_SECONDS = 2.0
MAX_CACHE_TTL_SECONDS = 30.0
MAX_CACHE_BYTES = 4096
METRIC_RE = re.compile(r"^\d+(?:\.\d)?$")


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


def _open_regular_transcript(path):
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode):
        return None
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            os.close(fd)
            return None
        return fd, opened
    except Exception:
        os.close(fd)
        raise


def _read_tail(fd, size):
    read_size = min(size, TAIL_BYTES)
    if size > read_size:
        os.lseek(fd, size - read_size, os.SEEK_SET)
    chunks = []
    remaining = read_size
    while remaining > 0:
        chunk = os.read(fd, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks), read_size


def _cache_ttl_seconds():
    raw = os.environ.get("CONTEXT_GUARD_STATUSLINE_CACHE_TTL_SECONDS", "")
    if raw == "":
        return DEFAULT_CACHE_TTL_SECONDS
    try:
        ttl = float(raw)
    except (TypeError, ValueError, OverflowError):
        return DEFAULT_CACHE_TTL_SECONDS
    if ttl <= 0:
        return 0.0
    return min(ttl, MAX_CACHE_TTL_SECONDS)


def _path_contains(parent, child):
    try:
        parent_real = os.path.realpath(parent)
        child_real = os.path.realpath(child)
        return os.path.commonpath([parent_real, child_real]) == parent_real
    except Exception:
        return False


def _private_cache_dir(workspace):
    home = os.path.expanduser("~")
    if not home or not os.path.isabs(home):
        return None
    root = os.path.join(home, ".cache", "context-guard", "statusline")
    if workspace and os.path.isabs(workspace) and os.path.isdir(workspace) and _path_contains(workspace, root):
        return None
    try:
        os.makedirs(root, mode=0o700, exist_ok=True)
        st = os.lstat(root)
        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
            return None
        if st.st_uid != os.getuid():
            return None
        if stat.S_IMODE(st.st_mode) != 0o700:
            os.chmod(root, 0o700)
            st = os.lstat(root)
            if stat.S_IMODE(st.st_mode) != 0o700:
                return None
        return root
    except Exception:
        return None


def _identity(path, st):
    absolute = os.path.abspath(path)
    path_hash = hashlib.sha256(os.fsencode(absolute)).hexdigest()
    return {
        "path_hash": path_hash,
        "size": int(st.st_size),
        "mtime_ns": int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1_000_000_000))),
        "dev": int(getattr(st, "st_dev", 0)),
        "ino": int(getattr(st, "st_ino", 0)),
    }


def _cache_path(identity):
    root = _private_cache_dir(workspace_dir)
    if not root:
        return None
    return os.path.join(root, f"{identity['path_hash']}.json")


def _open_no_follow_read(path):
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_CACHE_BYTES:
            os.close(fd)
            return None
        return fd, int(st.st_size)
    except Exception:
        os.close(fd)
        raise


def _metric_parts(cache_pct, reuse_x):
    cache_pct = _validated_metric(cache_pct, minimum=0.0, maximum=100.0)
    if cache_pct is None:
        return None
    if reuse_x is not None:
        reuse_x = _validated_metric(reuse_x, minimum=0.0, maximum=1_000_000.0)
        if reuse_x is None:
            return None
    parts = [f"cache_pct={cache_pct}"]
    if reuse_x:
        parts.append(f"reuse_x={reuse_x}")
    return " ".join(parts)


def _validated_metric(value, *, minimum, maximum):
    if not isinstance(value, str) or not METRIC_RE.match(value):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(number) or number < minimum or number > maximum:
        return None
    return value


def _read_cache(identity, ttl):
    if ttl <= 0:
        return None
    path = _cache_path(identity)
    if not path:
        return None
    try:
        opened = _open_no_follow_read(path)
        if opened is None:
            return None
        fd, size = opened
        try:
            raw = os.read(fd, size + 1)
        finally:
            os.close(fd)
        data = json.loads(raw.decode("utf-8", errors="strict"))
        if not isinstance(data, dict):
            return None
        if data.get("schema_version") != CACHE_SCHEMA_VERSION:
            return None
        computed_at = float(data.get("computed_at", 0))
        now = time.time()
        if not math.isfinite(computed_at):
            return None
        if now - computed_at > ttl or computed_at - now > ttl:
            return None
        for key, value in identity.items():
            if data.get(key) != value:
                return None
        return _metric_parts(data.get("cache_pct"), data.get("reuse_x"))
    except Exception:
        return None


def _write_cache(identity, cache_pct, reuse_x):
    ttl = _cache_ttl_seconds()
    if ttl <= 0:
        return
    path = _cache_path(identity)
    if not path:
        return
    payload = {
        "schema_version": CACHE_SCHEMA_VERSION,
        **identity,
        "computed_at": time.time(),
        "cache_pct": cache_pct,
        "reuse_x": reuse_x,
    }
    raw = (json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(raw) > MAX_CACHE_BYTES:
        return
    tmp_path = f"{path}.{os.getpid()}.tmp"
    fd = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(tmp_path, flags, 0o600)
        os.write(fd, raw)
        os.close(fd)
        fd = -1
        os.replace(tmp_path, path)
        os.chmod(path, 0o600)
    except Exception:
        if fd >= 0:
            try:
                os.close(fd)
            except Exception:
                pass
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


input_tokens = cache_read = cache_creation = 0

try:
    opened = _open_regular_transcript(path)
    if opened is None:
        sys.exit(0)
    fd, st = opened
    size = int(st.st_size)
    identity = _identity(path, st)
    cached = _read_cache(identity, _cache_ttl_seconds())
    if cached:
        os.close(fd)
        print(cached)
        sys.exit(0)
    try:
        chunk, read_size = _read_tail(fd, size)
    finally:
        os.close(fd)
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
    cache_pct = f"{pct:.0f}"
    reuse_x = f"{cache_read / cache_creation:.1f}" if cache_creation > 0 else None
    _write_cache(identity, cache_pct, reuse_x)
    parts = [f"cache_pct={cache_pct}"]
    if reuse_x:
        parts.append(f"reuse_x={reuse_x}")
    print(" ".join(parts))
except Exception:
    sys.exit(0)
PYEOF
  )
  if [[ -n "$transcript_metrics" ]]; then
    cache_pct=''
    reuse_x=''
    for metric in $transcript_metrics; do
      case "$metric" in
        cache_pct=*) cache_pct="${metric#cache_pct=}" ;;
        reuse_x=*) reuse_x="${metric#reuse_x=}" ;;
      esac
    done
    if [[ -n "$cache_pct" ]]; then
      cache_pct=$(sanitize_status "$cache_pct")
      metrics_label=" | cache ${cache_pct}%"
      if [[ -n "$reuse_x" ]]; then
        reuse_x=$(sanitize_status "$reuse_x")
        metrics_label+=" | reuse ${reuse_x}x"
      fi
    fi
  fi
fi

# Keep it one line and cheap: this script runs locally and should not do expensive git status.
echo "[$model] ${dir}${branch} | ctx ${context_label} | cost ${cost}${metrics_label}"
