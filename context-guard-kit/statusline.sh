#!/usr/bin/env bash
set -euo pipefail

if [[ -t 0 ]]; then
  echo "usage: pass Claude Code statusline JSON on stdin"
  exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "[needs-python3] install python3 for Claude token statusline"
  exit 0
fi

read -r -d '' CONTEXT_GUARD_STATUSLINE_PY <<'PYEOF' || true
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import sys
import time
from typing import Any

TAIL_BYTES = 1024 * 1024
MAX_RECORDS = 300
CACHE_SCHEMA_VERSION = 1
DEFAULT_CACHE_TTL_SECONDS = 2.0
MAX_CACHE_TTL_SECONDS = 30.0
MAX_CACHE_BYTES = 4096
METRIC_RE = re.compile(r"^\d+(?:\.\d)?$")
SECRET_RE = re.compile(
    r"(gh[pousr]_|github_pat_|glpat-|xox[abprs]-|AKIA|ASIA|sk-|npm_|AIza|Bearer\s|Basic\s)",
    re.IGNORECASE,
)
OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
CSI_RE = re.compile(r"\x1b[@-_][0-?]*[ -/]*[@-~]")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def _bounded_int_env(primary: str, legacy: str, default: int, *, lower: int, upper: int) -> int:
    raw = os.environ.get(primary, os.environ.get(legacy, str(default)))
    value = default
    if raw.isdigit() and len(raw) <= 7:
        value = int(raw, 10)
    if value < lower or value > upper:
        return default
    return value


def statusline_input_max_bytes() -> int:
    return _bounded_int_env(
        "CONTEXT_GUARD_STATUSLINE_INPUT_MAX_BYTES",
        "CLAUDE_TOKEN_STATUSLINE_INPUT_MAX_BYTES",
        65536,
        lower=1,
        upper=1048576,
    )


def statusline_context_warn_threshold() -> int:
    raw = os.environ.get(
        "CONTEXT_GUARD_STATUSLINE_CTX_WARN",
        os.environ.get("CLAUDE_TOKEN_STATUSLINE_CTX_WARN", "80"),
    )
    threshold = 80
    if re.fullmatch(r"\d{1,3}", raw or ""):
        threshold = int(raw, 10)
        if threshold < 1:
            threshold = 1
        elif threshold > 100:
            threshold = 100
    return threshold


def _json_tostring(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return str(value)


def _get_path(data: dict[str, Any], *keys: str) -> str:
    cur: Any = data
    for key in keys:
        if not isinstance(cur, dict):
            return ""
        cur = cur.get(key)
    return _json_tostring(cur)


def strip_terminal_sequences(value: str) -> str:
    value = OSC_RE.sub("", value)
    return CSI_RE.sub("", value)


def sanitize_status(value: str) -> str:
    cleaned = strip_terminal_sequences(str(value))
    cleaned = cleaned.replace("\r", " ").replace("\n", " ")
    cleaned = CONTROL_RE.sub("", cleaned)[:160]
    if SECRET_RE.search(cleaned):
        return "[redacted]"
    return cleaned


def git_head_branch(current: str) -> str | None:
    if not current or not os.path.isdir(current):
        return None
    try:
        current = os.path.realpath(current)
    except Exception:
        return None

    while current:
        head_file = ""
        dotgit = os.path.join(current, ".git")
        if os.path.isdir(dotgit) and not os.path.islink(dotgit):
            head_file = os.path.join(dotgit, "HEAD")
        elif os.path.isfile(dotgit) and not os.path.islink(dotgit):
            try:
                with open(dotgit, "r", encoding="utf-8", errors="replace") as fh:
                    gitdir_line = fh.readline().rstrip("\n")
            except OSError:
                gitdir_line = ""
            if gitdir_line.startswith("gitdir: "):
                gitdir = gitdir_line[len("gitdir: ") :]
                if not os.path.isabs(gitdir):
                    gitdir = os.path.join(current, gitdir)
                try:
                    gitdir = os.path.realpath(gitdir)
                except Exception:
                    gitdir = ""
                candidate = os.path.join(gitdir, "HEAD") if gitdir else ""
                if candidate and os.path.isfile(candidate) and not os.path.islink(candidate):
                    head_file = candidate

        if head_file and os.path.isfile(head_file) and not os.path.islink(head_file):
            try:
                with open(head_file, "r", encoding="utf-8", errors="replace") as fh:
                    head_line = fh.readline().strip()
            except OSError:
                return None
            if head_line.startswith("ref: refs/heads/"):
                branch = head_line[len("ref: refs/heads/") :]
                return branch or None
            if re.fullmatch(r"[0-9a-fA-F]{7,40}", head_line or ""):
                return head_line[:12]
            return None

        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent or os.sep
    return None


def _int_or_zero(value: Any) -> int:
    """Coerce transcript usage token values. bool is an int subclass, so block it."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return max(0, value)
    return 0


def _extract_usage(record: Any) -> dict[str, Any] | None:
    """Extract one known transcript usage object without recursively double-counting copies."""
    if not isinstance(record, dict):
        return None
    for path_keys in (("usage",), ("message", "usage"), ("response", "usage")):
        cur: Any = record
        for key in path_keys:
            if not isinstance(cur, dict):
                cur = None
                break
            cur = cur.get(key)
        if isinstance(cur, dict):
            return cur
    return None


def _open_regular_transcript(path: str) -> tuple[int, os.stat_result] | None:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode):
        return None
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            os.close(fd)
            return None
        return fd, opened
    except Exception:
        os.close(fd)
        raise


def _read_tail(fd: int, size: int) -> tuple[bytes, int]:
    read_size = min(size, TAIL_BYTES)
    if size > read_size:
        os.lseek(fd, size - read_size, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = read_size
    while remaining > 0:
        chunk = os.read(fd, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks), read_size


def _cache_ttl_seconds() -> float:
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


def _path_contains(parent: str, child: str) -> bool:
    try:
        parent_real = os.path.realpath(parent)
        child_real = os.path.realpath(child)
        return os.path.commonpath([parent_real, child_real]) == parent_real
    except Exception:
        return False


def _private_cache_dir(workspace: str) -> str | None:
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
        if hasattr(os, "getuid") and st.st_uid != os.getuid():
            return None
        if stat.S_IMODE(st.st_mode) != 0o700:
            os.chmod(root, 0o700)
            st = os.lstat(root)
            if stat.S_IMODE(st.st_mode) != 0o700:
                return None
        return root
    except Exception:
        return None


def _identity(path: str, st: os.stat_result) -> dict[str, int | str]:
    absolute = os.path.abspath(path)
    path_hash = hashlib.sha256(os.fsencode(absolute)).hexdigest()
    return {
        "path_hash": path_hash,
        "size": int(st.st_size),
        "mtime_ns": int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1_000_000_000))),
        "dev": int(getattr(st, "st_dev", 0)),
        "ino": int(getattr(st, "st_ino", 0)),
    }


def _cache_path(identity: dict[str, int | str], workspace_dir: str) -> str | None:
    root = _private_cache_dir(workspace_dir)
    if not root:
        return None
    return os.path.join(root, f"{identity['path_hash']}.json")


def _open_no_follow_read(path: str) -> tuple[int, int] | None:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_CACHE_BYTES:
            os.close(fd)
            return None
        return fd, int(st.st_size)
    except Exception:
        os.close(fd)
        raise


def _validated_metric(value: Any, *, minimum: float, maximum: float) -> str | None:
    if not isinstance(value, str) or not METRIC_RE.match(value):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(number) or number < minimum or number > maximum:
        return None
    return value


def _metric_parts(cache_pct: Any, reuse_x: Any) -> str | None:
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


def _read_cache(identity: dict[str, int | str], workspace_dir: str, ttl: float) -> str | None:
    if ttl <= 0:
        return None
    path = _cache_path(identity, workspace_dir)
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


def _write_cache(identity: dict[str, int | str], workspace_dir: str, cache_pct: str, reuse_x: str | None) -> None:
    ttl = _cache_ttl_seconds()
    if ttl <= 0:
        return
    path = _cache_path(identity, workspace_dir)
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


def transcript_metrics(path: str, workspace_dir: str) -> str | None:
    input_tokens = 0
    cache_read = 0
    cache_creation = 0
    try:
        opened = _open_regular_transcript(path)
        if opened is None:
            return None
        fd, st = opened
        size = int(st.st_size)
        identity = _identity(path, st)
        cached = _read_cache(identity, workspace_dir, _cache_ttl_seconds())
        if cached:
            os.close(fd)
            return cached
        try:
            chunk, read_size = _read_tail(fd, size)
        finally:
            os.close(fd)
        lines = chunk.splitlines()
        if size > read_size and lines:
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
        if denom <= 0 or cache_read <= 0:
            return None
        pct = max(0.0, min(100.0, cache_read / denom * 100))
        cache_pct = f"{pct:.0f}"
        reuse_x = f"{cache_read / cache_creation:.1f}" if cache_creation > 0 else None
        _write_cache(identity, workspace_dir, cache_pct, reuse_x)
        parts = [f"cache_pct={cache_pct}"]
        if reuse_x:
            parts.append(f"reuse_x={reuse_x}")
        return " ".join(parts)
    except Exception:
        return None


def _load_payload(raw: bytes) -> dict[str, Any]:
    try:
        data = json.loads(raw.decode("utf-8", errors="strict"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _rounded_context(raw: str) -> tuple[str, bool]:
    if not raw:
        return "?", False
    try:
        number = float(raw)
    except (TypeError, ValueError, OverflowError):
        return sanitize_status(raw), False
    if not math.isfinite(number):
        return sanitize_status(raw), False
    rendered = f"{number:.0f}"
    if re.fullmatch(r"-?\d+", rendered):
        return rendered, True
    return sanitize_status(raw), False


def render_statusline(payload: dict[str, Any]) -> str:
    model_display = _get_path(payload, "model", "display_name")
    model_id = _get_path(payload, "model", "id")
    context_raw = _get_path(payload, "context_window", "used_percentage")
    cost_raw = _get_path(payload, "cost", "total_cost_usd")
    cwd = _get_path(payload, "workspace", "current_dir")
    transcript_path = _get_path(payload, "transcript_path")

    model = sanitize_status(model_display or model_id or "unknown")

    context_pct, context_is_numeric = _rounded_context(context_raw)
    context_label = f"{context_pct}%"
    if context_is_numeric and int(context_pct) >= statusline_context_warn_threshold():
        context_label = f"{context_label} ⚠"

    if cost_raw:
        try:
            cost_number = float(cost_raw)
            if not math.isfinite(cost_number):
                raise ValueError("non-finite cost")
            cost = f"${cost_number:.3f}"
        except (TypeError, ValueError, OverflowError):
            cost = sanitize_status(cost_raw)
    else:
        cost = "n/a"

    dir_label = os.path.basename(cwd) if cwd else "."
    dir_label = sanitize_status(dir_label or ".")

    branch_label = ""
    branch_dir = cwd or os.getcwd()
    branch = git_head_branch(branch_dir)
    if branch:
        branch_label = f" | {sanitize_status(branch)}"

    metrics_label = ""
    if transcript_path and os.access(transcript_path, os.R_OK):
        raw_metrics = transcript_metrics(transcript_path, cwd)
        if raw_metrics:
            cache_pct = ""
            reuse_x = ""
            for metric in raw_metrics.split():
                if metric.startswith("cache_pct="):
                    cache_pct = metric[len("cache_pct=") :]
                elif metric.startswith("reuse_x="):
                    reuse_x = metric[len("reuse_x=") :]
            if cache_pct:
                metrics_label = f" | cache {sanitize_status(cache_pct)}%"
                if reuse_x:
                    metrics_label += f" | reuse {sanitize_status(reuse_x)}x"

    return f"[{model}] {dir_label}{branch_label} | ctx {context_label} | cost {cost}{metrics_label}"


def main() -> int:
    max_bytes = statusline_input_max_bytes()
    raw = sys.stdin.buffer.read(max_bytes + 1)
    if len(raw) > max_bytes:
        print(f"[input-too-large] Claude statusline JSON exceeds {max_bytes} bytes")
        return 0
    print(render_statusline(_load_payload(raw)))
    return 0


try:
    raise SystemExit(main())
except BrokenPipeError:
    raise SystemExit(0)
PYEOF

exec python3 -c "$CONTEXT_GUARD_STATUSLINE_PY" "$@"
