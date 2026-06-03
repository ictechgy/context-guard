#!/usr/bin/env python3
"""Store large sanitized command output outside Claude context and query slices later."""
from __future__ import annotations

import argparse
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Iterable

DEFAULT_ARTIFACT_DIR = ".context-guard/artifacts"
LEGACY_ARTIFACT_DIR = ".claude-token-optimizer/artifacts"
DEFAULT_MAX_BYTES = 10_000_000
MAX_MAX_BYTES = 100_000_000
MAX_METADATA_BYTES = 64_000
DEFAULT_MAX_LINES = 80
DEFAULT_MAX_CHARS = 20_000
MAX_LINE_CHARS = 2_000
ARTIFACT_ID_RE = re.compile(r"^[a-f0-9]{16,64}$")
ALLOWED_FIRST_ABSOLUTE_SYMLINKS = {
    "tmp": Path("/private/tmp"),
    "var": Path("/private/var"),
}
ERROR_RE = re.compile(
    r"(FAIL|FAILED|ERROR|Error:|Exception|Traceback|AssertionError|panic:|fatal:|"
    r"segmentation fault|not ok|\bE\s+assert|\[ERROR\]|✗|✖)",
    re.IGNORECASE,
)
SECRET_VALUE_RE = re.compile(
    r"(?i)(Bearer\s+\S+|Basic\s+\S+|gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|"
    r"sk-(?:ant|proj)-[A-Za-z0-9_-]{12,}|sk-[A-Za-z0-9][A-Za-z0-9_-]{20,}|"
    r"AIza[0-9A-Za-z_\-]{20,}|"
    r"([A-Za-z0-9_.-]*(?:api[_-]?key|token|secret|password|passwd|pwd)[A-Za-z0-9_.-]*\s*[:=]\s*)\S+)"
)


def bounded_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return min(max(number, minimum), maximum)


def cap_line(line: str, limit: int = MAX_LINE_CHARS) -> str:
    if len(line) <= limit:
        return line
    marker = f"...[line trimmed: {len(line)} chars]"
    return line[: max(0, limit - len(marker))] + marker


def normalized_link_target(parent: Path, raw_target: str) -> Path:
    target = Path(raw_target)
    if not target.is_absolute():
        target = parent / target
    return Path(os.path.normpath(str(target)))


def normalize_allowed_first_absolute_symlink(path: Path) -> Path:
    if not path.is_absolute() or len(path.parts) < 2:
        return path
    first = path.parts[1]
    expected = ALLOWED_FIRST_ABSOLUTE_SYMLINKS.get(first)
    if expected is None:
        return path
    link = Path(path.anchor) / first
    try:
        if not stat.S_ISLNK(os.lstat(link).st_mode):
            return path
        if normalized_link_target(Path(path.anchor), os.readlink(link)) != expected:
            return path
    except OSError:
        return path
    return expected.joinpath(*path.parts[2:])


def compact_items(lines: Iterable[str], *, limit: int) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for line in lines:
        item = cap_line(line.strip())
        if not item or item in seen:
            continue
        out.append(item)
        seen.add(item)
        if len(out) >= limit:
            break
    return out


class FallbackLineSanitizer:
    def __init__(self, *, show_paths: bool = False) -> None:
        self.show_paths = show_paths
        self.redactions = 0

    def sanitize(self, raw_line: str) -> tuple[str, bool]:
        def repl(match: re.Match[str]) -> str:
            groups = match.groups()
            if len(groups) >= 2 and groups[1]:
                return groups[1] + "[REDACTED]"
            return "[REDACTED]"

        line, count = SECRET_VALUE_RE.subn(repl, raw_line)
        if count:
            self.redactions += 1
        return line, bool(count)


def load_line_sanitizer(show_paths: bool) -> object:
    script_dir = Path(__file__).resolve().parent
    for name in ("sanitize_output.py", "context-guard-sanitize-output", "claude-sanitize-output"):
        candidate = script_dir / name
        if not candidate.exists():
            continue
        try:
            loader = importlib.machinery.SourceFileLoader(f"_claude_token_sanitize_{os.getpid()}", str(candidate))
            spec = importlib.util.spec_from_loader(loader.name, loader)
            if spec is None:
                raise RuntimeError("import spec unavailable")
            module = importlib.util.module_from_spec(spec)
            loader.exec_module(module)
            return module.LineSanitizer(show_paths=show_paths)
        except Exception as exc:
            raise RuntimeError(f"could not load sanitizer {candidate}: {exc}") from exc
    return FallbackLineSanitizer(show_paths=show_paths)


def sanitize_text(text: str, *, show_paths: bool = False) -> tuple[str, int]:
    sanitizer = load_line_sanitizer(show_paths)
    redacted = 0
    out: list[str] = []
    for line in text.splitlines(True):
        sanitized, did_redact = sanitizer.sanitize(line)  # type: ignore[attr-defined]
        out.append(sanitized)
        if did_redact:
            redacted += 1
    return "".join(out), redacted


def sanitize_one_line(text: str, *, show_paths: bool = False) -> str:
    sanitized, _ = sanitize_text(text + "\n", show_paths=show_paths)
    return cap_line(" ".join(sanitized.strip().split()))


def ensure_private_dir(path: Path) -> None:
    path = normalize_allowed_first_absolute_symlink(path)
    reject_symlink_components(path)
    path.mkdir(parents=True, exist_ok=True)
    reject_symlink_components(path)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def reject_symlink_components(path: Path) -> None:
    path = normalize_allowed_first_absolute_symlink(path)
    current = Path(path.anchor) if path.is_absolute() else Path()
    for part in path.parts:
        if path.is_absolute() and part == path.anchor:
            continue
        current = current / part
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(st.st_mode):
            raise RuntimeError(f"refusing artifact path with symlink component: {current}")
        if not stat.S_ISDIR(st.st_mode) and current != path:
            raise RuntimeError(f"refusing artifact path through non-directory component: {current}")


def regular_private_file_size(path: Path) -> int:
    path = normalize_allowed_first_absolute_symlink(path)
    reject_symlink_components(path.parent)
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"artifact file must not be a symlink: {path.name}")
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"artifact file must be a regular file: {path.name}")
    return int(st.st_size)


def read_bounded_private_text(path: Path, max_bytes: int) -> str:
    path = normalize_allowed_first_absolute_symlink(path)
    size = regular_private_file_size(path)
    if size > max_bytes:
        raise ValueError(f"artifact file exceeds trusted size cap: {path.name}: {size} > {max_bytes}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"artifact file must be a regular file: {path.name}")
        if st.st_size > max_bytes:
            raise ValueError(f"artifact file exceeds trusted size cap: {path.name}: {st.st_size} > {max_bytes}")
        data = os.read(fd, max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError(f"artifact file exceeds trusted size cap: {path.name}: > {max_bytes}")
        return data.decode("utf-8", errors="replace")
    finally:
        os.close(fd)


def write_private_text(path: Path, text: str) -> None:
    path = normalize_allowed_first_absolute_symlink(path)
    ensure_private_dir(path.parent)
    tmp = path.with_name(path.name + f".tmp-{os.getpid()}-{time.time_ns()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(tmp), flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
    except Exception:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise
    try:
        os.replace(tmp, path)
    except Exception:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def read_bounded_stdin(max_bytes: int) -> tuple[str, bool, int]:
    data = sys.stdin.buffer.read(max_bytes + 1)
    truncated = len(data) > max_bytes
    if truncated:
        data = data[:max_bytes]
    return data.decode("utf-8", errors="replace"), truncated, len(data)


def artifact_paths(directory: Path, artifact_id: str) -> tuple[Path, Path]:
    if not ARTIFACT_ID_RE.fullmatch(artifact_id):
        raise ValueError("artifact id must be 16-64 lowercase hex chars")
    directory = normalize_allowed_first_absolute_symlink(directory)
    return directory / f"{artifact_id}.txt", directory / f"{artifact_id}.json"


def artifact_read_directories(raw_dir: str) -> list[Path]:
    """Return primary plus legacy read fallback for the default artifact dir.

    Rebranded ContextGuard stores new artifacts under `.context-guard/artifacts`,
    but users may still have receipts from the old `.claude-token-optimizer`
    default. Reads and listings include that legacy default so old receipts keep
    working; stores intentionally continue to use only the new path.
    """
    primary = normalize_allowed_first_absolute_symlink(Path(raw_dir).expanduser())
    directories = [primary]
    if Path(raw_dir).expanduser() == Path(DEFAULT_ARTIFACT_DIR):
        legacy = normalize_allowed_first_absolute_symlink(Path(LEGACY_ARTIFACT_DIR).expanduser())
        if legacy != primary:
            directories.append(legacy)
    return directories


CONTENT_TYPE_VALUES = ("json", "diff", "log", "search", "code", "prose", "text")
# Recommended retrieval strategy per content type. Pattern-oriented payloads
# (logs, search hits, diffs) are best sliced by `--pattern`; structured or
# narrative payloads (json, code, prose) read best by `--lines`. Unknown/empty
# content falls back to a bounded `head` read.
STRATEGY_BY_CONTENT_TYPE = {
    "json": "lines",
    "code": "lines",
    "prose": "lines",
    "diff": "pattern",
    "log": "pattern",
    "search": "pattern",
    "text": "head",
}
_SEARCH_HIT_RE = re.compile(r"^[^\s:]+:\d+:")
_LOG_LINE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}|"
    r"\[(?:DEBUG|INFO|WARN|WARNING|ERROR|FATAL|TRACE)\]|"
    r"(?:DEBUG|INFO|WARN|WARNING|ERROR|FATAL|TRACE)\b)",
    re.IGNORECASE,
)
_CODE_LINE_RE = re.compile(
    r"^\s*(def |class |import |from \S+ import |function |const |let |var |"
    r"public |private |protected |#include|package |func |fn |impl |"
    r"return\b|if\s*\(|for\s*\(|while\s*\()"
)


def classify_content_type(text: str) -> str:
    """Classify stored content into one of CONTENT_TYPE_VALUES (advisory only).

    The classification is dependency-free and deterministic: identical input
    always yields the same label. It never influences redaction or storage; it
    only drives retrieval-strategy hints, so a wrong guess degrades to a less
    ergonomic (but still correct) retrieval suggestion. Empty input is "text".
    """
    stripped = text.strip()
    if not stripped:
        return "text"
    if stripped[0] in "{[":
        try:
            json.loads(stripped)
            return "json"
        except (ValueError, RecursionError):
            pass
    lines = stripped.splitlines()
    line_count = len(lines)
    majority = max(1, line_count // 2)
    diff_hits = sum(1 for line in lines if line.startswith(("diff --git ", "@@ ", "+++ ", "--- ", "index ")))
    if diff_hits and (lines[0].startswith(("diff --git ", "--- ", "@@ ")) or diff_hits >= 2):
        return "diff"
    # Log is checked before search because timestamps (HH:MM:SS) and bracketed
    # levels can superficially resemble the `path:line:` search shape.
    if sum(1 for line in lines if _LOG_LINE_RE.match(line)) >= majority:
        return "log"
    if sum(1 for line in lines if _SEARCH_HIT_RE.match(line)) >= majority:
        return "search"
    code_hits = sum(1 for line in lines if _CODE_LINE_RE.match(line))
    brace_lines = sum(1 for line in lines if line.rstrip().endswith(("{", "}", ";", "):")))
    if code_hits >= 2 or (code_hits >= 1 and brace_lines >= max(2, line_count // 3)):
        return "code"
    return "prose"


def recommended_strategy(content_type: str) -> str:
    """Map a content type to its default retrieval strategy hint (advisory)."""
    return STRATEGY_BY_CONTENT_TYPE.get(content_type, "head")


def first_error_anchor(text: str) -> str | None:
    """Return the first literal error token in text for a pattern hint, or None.

    The returned token is taken verbatim from ERROR_RE's match, so it is
    guaranteed to be an exact substring of the stored content. This makes the
    derived `--pattern` retrieval hint deterministic and exactly round-trippable.
    """
    for line in text.splitlines():
        match = ERROR_RE.search(line)
        if match:
            token = match.group(0).strip()
            if token:
                return token
    return None


def build_retrieval_hints(
    artifact_id: str,
    sanitized_text: str,
    *,
    content_type: str,
    strategy: str,
    total_lines: int,
) -> list[dict[str, object]]:
    """Build deterministic, machine-readable retrieval hints for exact round-trip.

    Each hint pairs a `selector` (consumable by `query_content` / the `get` CLI)
    with the exact CLI invocation. The line-range hint spans the full stored
    content (`1:total_lines`) so it round-trips to the complete payload; the
    pattern hint, when present, targets a literal token guaranteed to exist, so
    retrieval is exact and reproducible. Order is fixed (lines, pattern, head)
    for determinism; callers pick the hint whose `type` matches `strategy`.
    """
    hints: list[dict[str, object]] = []
    if total_lines >= 1:
        hints.append(
            {
                "type": "lines",
                "selector": {"start": 1, "end": total_lines},
                "cli": f"context-guard-artifact get {artifact_id} --lines 1:{total_lines}",
            }
        )
    anchor = first_error_anchor(sanitized_text)
    if anchor is not None:
        hints.append(
            {
                "type": "pattern",
                "selector": {"pattern": anchor},
                "cli": f"context-guard-artifact get {artifact_id} --pattern '{anchor}'",
            }
        )
    hints.append(
        {
            "type": "head",
            "selector": {"max_lines": DEFAULT_MAX_LINES},
            "cli": f"context-guard-artifact get {artifact_id} --max-lines {DEFAULT_MAX_LINES}",
        }
    )
    return hints


def build_digest(sanitized_text: str, *, redacted_lines: int) -> dict[str, object]:
    lines = sanitized_text.splitlines()
    top_errors = compact_items((line for line in lines if ERROR_RE.search(line)), limit=12)
    return {
        "status": "has_errors" if top_errors else "stored",
        "redacted_lines": redacted_lines,
        "redaction_counts": {
            "lines": redacted_lines,
            "markers": sanitized_text.count("[REDACTED]"),
        },
        "top_error_lines": top_errors,
        "representative_head": compact_items(lines, limit=8),
        "representative_tail": compact_items(lines[-8:], limit=8),
    }


def receipt_for(metadata: dict[str, object]) -> dict[str, object]:
    artifact_id = str(metadata["artifact_id"])
    return {
        "artifact_id": artifact_id,
        "stored": True,
        "created_at": metadata.get("created_at"),
        "command_preview": metadata.get("command_preview"),
        "content_type": metadata.get("content_type"),
        "input": metadata.get("input"),
        "stored_output": metadata.get("stored_output"),
        "digest": metadata.get("digest"),
        "retrieval": metadata.get("retrieval"),
        "available_queries": [
            f"context-guard-artifact get {artifact_id} --lines 1:80",
            f"context-guard-artifact get {artifact_id} --pattern ERROR --max-lines 40",
            f"context-guard-artifact get {artifact_id} --json --lines 1:20",
        ],
    }


def store_command(args: argparse.Namespace) -> int:
    directory = normalize_allowed_first_absolute_symlink(Path(args.dir).expanduser())
    max_bytes = bounded_int(args.max_bytes, DEFAULT_MAX_BYTES, 1, MAX_MAX_BYTES)
    raw_text, input_truncated, input_bytes = read_bounded_stdin(max_bytes)
    sanitized_text, redacted_lines = sanitize_text(raw_text, show_paths=args.show_paths)
    content_bytes = len(sanitized_text.encode("utf-8", errors="replace"))
    content_sha = hashlib.sha256(sanitized_text.encode("utf-8", errors="replace")).hexdigest()
    command_preview = sanitize_one_line(args.command or "", show_paths=args.show_paths) if args.command else None
    id_basis = json.dumps(
        {
            "content_sha256": content_sha,
            "command_preview": command_preview,
            "input_truncated": input_truncated,
        },
        sort_keys=True,
    )
    artifact_id = hashlib.sha256(id_basis.encode("utf-8")).hexdigest()[:20]
    content_path, meta_path = artifact_paths(directory, artifact_id)
    total_lines = sanitized_text.count("\n") + (1 if sanitized_text and not sanitized_text.endswith("\n") else 0)
    content_type = classify_content_type(sanitized_text)
    strategy = recommended_strategy(content_type)
    metadata: dict[str, object] = {
        "artifact_id": artifact_id,
        "created_at": int(time.time()),
        "command_preview": command_preview,
        "content_type": content_type,
        "input": {
            "bytes_read": input_bytes,
            "truncated": input_truncated,
            "max_bytes": max_bytes,
        },
        "stored_output": {
            "bytes": content_bytes,
            "lines": total_lines,
            "sha256": content_sha,
            "content_file": content_path.name,
            "metadata_file": meta_path.name,
        },
        "digest": build_digest(sanitized_text, redacted_lines=redacted_lines),
        "retrieval": {
            "strategy": strategy,
            "deterministic": True,
            "hints": build_retrieval_hints(
                artifact_id,
                sanitized_text,
                content_type=content_type,
                strategy=strategy,
                total_lines=total_lines,
            ),
        },
    }
    write_private_text(content_path, sanitized_text)
    write_private_text(meta_path, json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    receipt = receipt_for(metadata)
    if args.json:
        print(json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"artifact_id={artifact_id}")
        stored = receipt["stored_output"]
        if isinstance(stored, dict):
            print(f"stored_output={stored.get('lines')} lines/{stored.get('bytes')} bytes")
        digest = receipt.get("digest")
        if isinstance(digest, dict) and digest.get("top_error_lines"):
            print("top_error_lines:")
            for line in digest["top_error_lines"]:  # type: ignore[index]
                print(f"- {line}")
        print(f"query=context-guard-artifact get {artifact_id} --lines 1:80")
    return 0


def load_metadata(directory: Path, artifact_id: str) -> dict[str, object]:
    content_path, meta_path = artifact_paths(directory, artifact_id)
    try:
        regular_private_file_size(content_path)
        meta_text = read_bounded_private_text(meta_path, MAX_METADATA_BYTES)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"artifact not found: {artifact_id}")
    data = json.loads(meta_text)
    if not isinstance(data, dict) or data.get("artifact_id") != artifact_id:
        raise ValueError(f"artifact metadata mismatch: {artifact_id}")
    return data


def parse_line_range(value: str | None) -> tuple[int, int] | None:
    if not value:
        return None
    match = re.fullmatch(r"(\d+)(?::(\d+))?", value.strip())
    if not match:
        raise ValueError("--lines must be START or START:END using 1-based inclusive line numbers")
    start = int(match.group(1))
    end = int(match.group(2) or match.group(1))
    if start < 1 or end < start:
        raise ValueError("--lines must satisfy 1 <= START <= END")
    return start, end


def cap_text(text: str, max_chars: int) -> tuple[str, bool]:
    if len(text) <= max_chars:
        return text, False
    marker = f"\n[context-guard-kit] artifact query capped: {len(text)} chars total\n"
    keep = max(0, max_chars - len(marker))
    return text[:keep].rstrip() + marker, True


def query_content(content: str, *, line_range: tuple[int, int] | None, pattern: str | None, max_lines: int) -> tuple[str, dict[str, object]]:
    lines = content.splitlines(True)
    selected: list[tuple[int, str]] = []
    if line_range is not None:
        start, end = line_range
        selected = list(enumerate(lines[start - 1 : end], start=start))
        selector = {"type": "lines", "start": start, "end": end}
    elif pattern:
        selected = [(idx, line) for idx, line in enumerate(lines, start=1) if pattern in line]
        selector = {"type": "pattern", "pattern": pattern}
    else:
        selected = list(enumerate(lines[:max_lines], start=1))
        selector = {"type": "head", "max_lines": max_lines}
    total_matches = len(selected)
    selected = selected[:max_lines]
    text = "".join(line for _idx, line in selected)
    return text, {"selector": selector, "returned_lines": len(selected), "matched_lines": total_matches, "total_lines": len(lines)}


def get_command(args: argparse.Namespace) -> int:
    artifact_id = args.artifact_id
    max_lines = bounded_int(args.max_lines, DEFAULT_MAX_LINES, 1, 5_000)
    max_chars = bounded_int(args.max_chars, DEFAULT_MAX_CHARS, 1, 1_000_000)
    try:
        last_missing: FileNotFoundError | None = None
        for directory in artifact_read_directories(args.dir):
            try:
                metadata = load_metadata(directory, artifact_id)
                content_path, _meta_path = artifact_paths(directory, artifact_id)
                break
            except FileNotFoundError as exc:
                last_missing = exc
        else:
            if last_missing is not None:
                raise last_missing
            raise FileNotFoundError(f"artifact not found: {artifact_id}")
        stored_output = metadata.get("stored_output")
        expected_sha = stored_output.get("sha256") if isinstance(stored_output, dict) else None
        if not isinstance(expected_sha, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_sha):
            raise ValueError(f"artifact metadata missing stored_output sha256: {artifact_id}")
        expected_bytes = stored_output.get("bytes") if isinstance(stored_output, dict) else None
        if not isinstance(expected_bytes, int) or expected_bytes < 0 or expected_bytes > MAX_MAX_BYTES:
            raise ValueError(f"artifact metadata has invalid stored_output bytes: {artifact_id}")
        actual_size = regular_private_file_size(content_path)
        if actual_size != expected_bytes:
            raise ValueError(f"artifact content checksum mismatch: {artifact_id}")
        content = read_bounded_private_text(content_path, expected_bytes)
        actual_sha = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
        if actual_sha != expected_sha:
            raise ValueError(f"artifact content checksum mismatch: {artifact_id}")
        line_range = parse_line_range(args.lines)
        selected, query = query_content(content, line_range=line_range, pattern=args.pattern, max_lines=max_lines)
        selected, capped = cap_text(selected, max_chars)
    except (FileNotFoundError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"context-guard-artifact: {exc}", file=sys.stderr)
        return 1
    if args.json:
        payload = {
            "artifact_id": artifact_id,
            "content_type": metadata.get("content_type"),
            "query": query,
            "capped": capped,
            "content": selected,
            "stored_output": metadata.get("stored_output"),
            "retrieval": metadata.get("retrieval"),
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        sys.stdout.write(selected)
    return 0


def list_command(args: argparse.Namespace) -> int:
    items: list[dict[str, object]] = []
    seen: set[str] = set()
    for directory in artifact_read_directories(args.dir):
        try:
            reject_symlink_components(directory)
            directory_is_safe = directory.is_dir() and not directory.is_symlink()
        except RuntimeError:
            directory_is_safe = False
        if not directory_is_safe:
            continue
        for meta_path in sorted(directory.glob("*.json")):
            try:
                data = json.loads(read_bounded_private_text(meta_path, MAX_METADATA_BYTES))
            except (OSError, ValueError, RuntimeError, json.JSONDecodeError):
                continue
            artifact_id = str(data.get("artifact_id", "")) if isinstance(data, dict) else ""
            if isinstance(data, dict) and ARTIFACT_ID_RE.fullmatch(artifact_id) and artifact_id not in seen:
                items.append(receipt_for(data))
                seen.add(artifact_id)
    items.sort(key=lambda item: str(item.get("artifact_id", "")))
    if args.json:
        print(json.dumps({"artifacts": items}, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        for item in items:
            stored = item.get("stored_output")
            if isinstance(stored, dict):
                print(f"{item['artifact_id']}\t{stored.get('lines')} lines\t{stored.get('bytes')} bytes")
            else:
                print(item["artifact_id"])
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Store sanitized large outputs as queryable local artifacts.")
    parser.add_argument("--dir", default=DEFAULT_ARTIFACT_DIR, help=f"artifact directory (default: {DEFAULT_ARTIFACT_DIR})")
    subparsers = parser.add_subparsers(dest="command_name", required=True)

    store = subparsers.add_parser("store", help="store stdin as a sanitized artifact and print a compact receipt")
    store.add_argument("--command", help="optional command label to sanitize into the receipt")
    store.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, help="maximum stdin bytes to read before truncating")
    store.add_argument(
        "--show-paths",
        action="store_true",
        help="show raw absolute paths instead of path hashes; local debugging only because private paths may be exposed",
    )
    store.add_argument("--json", action="store_true", help="emit receipt JSON")
    store.set_defaults(func=store_command)

    get = subparsers.add_parser("get", help="query a stored artifact")
    get.add_argument("artifact_id")
    get.add_argument("--lines", help="1-based inclusive line range, e.g. 10:40")
    get.add_argument("--pattern", help="literal substring filter")
    get.add_argument("--max-lines", type=int, default=DEFAULT_MAX_LINES)
    get.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS)
    get.add_argument("--json", action="store_true", help="emit query JSON with content")
    get.set_defaults(func=get_command)

    list_parser = subparsers.add_parser("list", help="list stored artifacts")
    list_parser.add_argument("--json", action="store_true", help="emit list JSON")
    list_parser.set_defaults(func=list_command)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return int(args.func(args))
    except RuntimeError as exc:
        print(f"context-guard-artifact: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
