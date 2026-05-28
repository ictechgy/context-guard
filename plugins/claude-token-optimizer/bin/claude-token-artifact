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
import sys
import time
from typing import Iterable

DEFAULT_ARTIFACT_DIR = ".claude-token-optimizer/artifacts"
DEFAULT_MAX_BYTES = 10_000_000
MAX_MAX_BYTES = 100_000_000
DEFAULT_MAX_LINES = 80
DEFAULT_MAX_CHARS = 20_000
MAX_LINE_CHARS = 2_000
ARTIFACT_ID_RE = re.compile(r"^[a-f0-9]{16,64}$")
ERROR_RE = re.compile(
    r"(FAIL|FAILED|ERROR|Error:|Exception|Traceback|AssertionError|panic:|fatal:|"
    r"segmentation fault|not ok|\bE\s+assert|\[ERROR\]|✗|✖)",
    re.IGNORECASE,
)
SECRET_VALUE_RE = re.compile(
    r"(?i)(Bearer\s+\S+|Basic\s+\S+|gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|"
    r"sk-(?:ant|proj)-[A-Za-z0-9_-]{12,}|AIza[0-9A-Za-z_\-]{20,}|"
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
    for name in ("sanitize_output.py", "claude-sanitize-output"):
        candidate = script_dir / name
        if not candidate.exists():
            continue
        try:
            loader = importlib.machinery.SourceFileLoader(f"_claude_token_sanitize_{os.getpid()}", str(candidate))
            spec = importlib.util.spec_from_loader(loader.name, loader)
            if spec is None:
                continue
            module = importlib.util.module_from_spec(spec)
            loader.exec_module(module)
            return module.LineSanitizer(show_paths=show_paths)
        except Exception:
            continue
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
    if text and not text.endswith(("\n", "\r")) and not out:
        sanitized, did_redact = sanitizer.sanitize(text)  # type: ignore[attr-defined]
        out.append(sanitized)
        if did_redact:
            redacted += 1
    return "".join(out), redacted


def sanitize_one_line(text: str, *, show_paths: bool = False) -> str:
    sanitized, _ = sanitize_text(text + "\n", show_paths=show_paths)
    return cap_line(" ".join(sanitized.strip().split()))


def ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def write_private_text(path: Path, text: str) -> None:
    ensure_private_dir(path.parent)
    tmp = path.with_name(path.name + f".tmp-{os.getpid()}")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
    except Exception:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise
    os.replace(tmp, path)
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
    return directory / f"{artifact_id}.txt", directory / f"{artifact_id}.json"


def build_digest(sanitized_text: str, *, redacted_lines: int) -> dict[str, object]:
    lines = sanitized_text.splitlines()
    top_errors = compact_items((line for line in lines if ERROR_RE.search(line)), limit=12)
    return {
        "status": "has_errors" if top_errors else "stored",
        "redacted_lines": redacted_lines,
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
        "input": metadata.get("input"),
        "stored_output": metadata.get("stored_output"),
        "digest": metadata.get("digest"),
        "available_queries": [
            f"claude-token-artifact get {artifact_id} --lines 1:80",
            f"claude-token-artifact get {artifact_id} --pattern ERROR --max-lines 40",
            f"claude-token-artifact get {artifact_id} --json --lines 1:20",
        ],
    }


def store_command(args: argparse.Namespace) -> int:
    directory = Path(args.dir).expanduser()
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
    metadata: dict[str, object] = {
        "artifact_id": artifact_id,
        "created_at": int(time.time()),
        "command_preview": command_preview,
        "input": {
            "bytes_read": input_bytes,
            "truncated": input_truncated,
            "max_bytes": max_bytes,
        },
        "stored_output": {
            "bytes": content_bytes,
            "lines": sanitized_text.count("\n") + (1 if sanitized_text and not sanitized_text.endswith("\n") else 0),
            "sha256": content_sha,
            "content_file": content_path.name,
            "metadata_file": meta_path.name,
        },
        "digest": build_digest(sanitized_text, redacted_lines=redacted_lines),
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
        print(f"query=claude-token-artifact get {artifact_id} --lines 1:80")
    return 0


def load_metadata(directory: Path, artifact_id: str) -> dict[str, object]:
    content_path, meta_path = artifact_paths(directory, artifact_id)
    if not content_path.is_file() or not meta_path.is_file():
        raise FileNotFoundError(f"artifact not found: {artifact_id}")
    data = json.loads(meta_path.read_text(encoding="utf-8"))
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
    marker = f"\n[claude-token-kit] artifact query capped: {len(text)} chars total\n"
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
    directory = Path(args.dir).expanduser()
    artifact_id = args.artifact_id
    max_lines = bounded_int(args.max_lines, DEFAULT_MAX_LINES, 1, 5_000)
    max_chars = bounded_int(args.max_chars, DEFAULT_MAX_CHARS, 1, 1_000_000)
    try:
        metadata = load_metadata(directory, artifact_id)
        content_path, _meta_path = artifact_paths(directory, artifact_id)
        content = content_path.read_text(encoding="utf-8", errors="replace")
        line_range = parse_line_range(args.lines)
        selected, query = query_content(content, line_range=line_range, pattern=args.pattern, max_lines=max_lines)
        selected, capped = cap_text(selected, max_chars)
    except (FileNotFoundError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"claude-token-artifact: {exc}", file=sys.stderr)
        return 1
    if args.json:
        payload = {
            "artifact_id": artifact_id,
            "query": query,
            "capped": capped,
            "content": selected,
            "stored_output": metadata.get("stored_output"),
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        sys.stdout.write(selected)
    return 0


def list_command(args: argparse.Namespace) -> int:
    directory = Path(args.dir).expanduser()
    items: list[dict[str, object]] = []
    if directory.is_dir():
        for meta_path in sorted(directory.glob("*.json")):
            try:
                data = json.loads(meta_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(data, dict) and ARTIFACT_ID_RE.fullmatch(str(data.get("artifact_id", ""))):
                items.append(receipt_for(data))
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
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
