#!/usr/bin/env python3
"""Print a symbol-sized slice of a source file instead of the whole file.

This is a deliberately small, dependency-free helper for Claude Code sessions:
use it after grep/ripgrep identifies a symbol and before asking Claude to read a
large source file. It is heuristic, not a full language server.
"""
from __future__ import annotations

import argparse
import ast
import errno
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent


def _load_hook_secret_patterns():
    searched = []
    for helper_dir in (SCRIPT_DIR, SCRIPT_DIR.parent / "lib"):
        helper_path = helper_dir / "hook_secret_patterns.py"
        searched.append(str(helper_path))
        if not helper_path.is_file():
            continue
        spec = importlib.util.spec_from_file_location("_claude_token_hook_secret_patterns", helper_path)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    raise ImportError("hook_secret_patterns.py not found in " + ", ".join(searched))


def _load_sanitize_output():
    searched = []
    for helper_path in (SCRIPT_DIR / "sanitize_output.py", SCRIPT_DIR / "context-guard-sanitize-output"):
        searched.append(str(helper_path))
        if not helper_path.is_file():
            continue
        loader = importlib.machinery.SourceFileLoader("_claude_token_sanitize_output", str(helper_path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        if spec is None:
            continue
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        return module
    raise ImportError("sanitize_output helper not found in " + ", ".join(searched))


_hook_secret_patterns = _load_hook_secret_patterns()
_sanitize_output = _load_sanitize_output()
hook_label_has_sensitive_evidence = _hook_secret_patterns.hook_label_has_sensitive_evidence
redact_sensitive_hook_text = _hook_secret_patterns.redact_sensitive_hook_text
LineSanitizer = _sanitize_output.LineSanitizer

DEFAULT_CONTEXT_LINES = 3
DEFAULT_MAX_CHARS = 16_000
MAX_CONTEXT_LINES_LIMIT = 200
MIN_MAX_CHARS = 200
MAX_CHARS_LIMIT = 200_000
MAX_READ_BYTES = 2_000_000
BRACE_FALLBACK_LINES = 80
PATH_LABEL_MAX_CHARS = 80
ALLOWED_FIRST_ABSOLUTE_SYMLINKS = {
    "tmp": Path("/private/tmp"),
    "var": Path("/private/var"),
}


def bounded_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return min(max(number, minimum), maximum)


@dataclass
class SymbolSlice:
    path: str
    symbol: str
    start_line: int
    end_line: int
    language: str
    content: str
    capped: bool = False
    scan_truncated: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "symbol": self.symbol,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "language": self.language,
            "content": self.content,
            "capped": self.capped,
            "scan_truncated": self.scan_truncated,
        }


def path_label(path: Path, show_paths: bool) -> str:
    if show_paths:
        return str(path)
    digest = hashlib.sha256(str(path).encode("utf-8", "replace")).hexdigest()[:12]
    raw_name = path.name or "path"
    name = " ".join(raw_name.strip().split())
    if hook_label_has_sensitive_evidence(raw_name):
        name = "redacted-path"
    elif len(name) > PATH_LABEL_MAX_CHARS:
        name = name[: PATH_LABEL_MAX_CHARS - 15].rstrip() + "...[truncated]"
    return f"{name}#path:{digest}"


def os_error_summary(exc: OSError) -> str:
    parts = [exc.__class__.__name__]
    if getattr(exc, "errno", None) is not None:
        parts.append(f"errno={exc.errno}")
    message = " ".join(str(getattr(exc, "strerror", "") or "").strip().split())
    if message:
        parts.append(message[:160])
    return ": ".join(parts)


def has_symlink_component(path: Path) -> bool:
    """Return True when the requested path traverses an explicit symlink."""
    if path.is_symlink():
        return True
    current = Path(path.anchor) if path.is_absolute() else Path()
    for part in path.parts:
        if path.is_absolute() and part == path.anchor:
            continue
        current = current / part
        if current.is_symlink():
            return True
    return False


def _base_open_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _no_follow_flag() -> int:
    if hasattr(os, "O_NOFOLLOW"):
        return os.O_NOFOLLOW
    raise OSError("platform does not support no-follow file opens")


def _directory_flag() -> int:
    return getattr(os, "O_DIRECTORY", 0)


def _normalized_link_target(parent: Path, raw_target: str) -> Path:
    target = Path(raw_target)
    if not target.is_absolute():
        target = parent / target
    return Path(os.path.normpath(str(target)))


def _normalize_allowed_first_absolute_symlink(path: Path) -> Path:
    """Rewrite narrow platform-owned absolute aliases before no-follow traversal."""
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
        if _normalized_link_target(Path(path.anchor), os.readlink(link)) != expected:
            return path
    except OSError:
        return path
    return expected.joinpath(*path.parts[2:])


def _lstat_at_no_follow(dir_fd: int, component: str, path: Path) -> os.stat_result:
    if os.stat not in getattr(os, "supports_dir_fd", set()):
        raise OSError(errno.ENOSYS, "platform does not support directory-relative no-follow stat", str(path))
    if os.stat not in getattr(os, "supports_follow_symlinks", set()):
        raise OSError(errno.ENOSYS, "platform does not support no-follow stat", str(path))
    return os.stat(component, dir_fd=dir_fd, follow_symlinks=False)


def _open_directory_at(dir_fd: int, component: str, path: Path) -> int:
    component_stat = _lstat_at_no_follow(dir_fd, component, path)
    if stat.S_ISLNK(component_stat.st_mode):
        raise OSError(errno.ELOOP, "symlink path component", str(path))
    if not stat.S_ISDIR(component_stat.st_mode):
        raise OSError(errno.ENOTDIR, "not a directory", str(path))
    flags = _base_open_flags() | _directory_flag() | _no_follow_flag()
    fd = os.open(component, flags, dir_fd=dir_fd)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISDIR(opened.st_mode) or not os.path.samestat(component_stat, opened):
            raise OSError(errno.ELOOP, "path component changed while opening", str(path))
        return fd
    except Exception:
        os.close(fd)
        raise


def _open_regular_no_symlink(path: Path) -> int:
    """Open a regular file without following symlinks in any trusted component."""
    if os.open not in os.supports_dir_fd:
        raise OSError("platform does not support directory-relative no-follow opens")
    path = _normalize_allowed_first_absolute_symlink(path)
    nofollow = _no_follow_flag()
    components = list(path.parts)
    if path.is_absolute() and components:
        components = components[1:]
    if not components:
        raise OSError(f"not a regular file: {path}")

    root = path.anchor if path.is_absolute() else "."
    dir_fd = os.open(root or ".", _base_open_flags() | _directory_flag())
    try:
        for component in components[:-1]:
            next_fd = _open_directory_at(dir_fd, component, path)
            os.close(dir_fd)
            dir_fd = next_fd

        before = _lstat_at_no_follow(dir_fd, components[-1], path)
        if stat.S_ISLNK(before.st_mode):
            raise OSError(errno.ELOOP, "symlink path component", str(path))
        if not stat.S_ISREG(before.st_mode):
            raise OSError(errno.EINVAL, "not a regular file", str(path))
        fd = os.open(components[-1], _base_open_flags() | nofollow, dir_fd=dir_fd)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
                raise OSError(errno.ELOOP, "path changed while opening", str(path))
            return fd
        except Exception:
            os.close(fd)
            raise
    finally:
        os.close(dir_fd)


def read_text_bounded(path: Path) -> tuple[str, bool]:
    fd = _open_regular_no_symlink(path)
    try:
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            data = handle.read(MAX_READ_BYTES + 1)
        truncated = len(data) > MAX_READ_BYTES
        if truncated:
            data = data[:MAX_READ_BYTES]
        return data.decode("utf-8", "replace"), truncated
    finally:
        if fd != -1:
            os.close(fd)


def language_for(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".py":
        return "python"
    if suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        return "javascript"
    if suffix == ".go":
        return "go"
    if suffix == ".rs":
        return "rust"
    return "generic"


def symbol_patterns(symbol: str, language: str) -> list[re.Pattern[str]]:
    escaped = re.escape(symbol)
    if language == "python":
        return [
            re.compile(rf"^(?P<indent>\s*)(?:async\s+)?def\s+{escaped}\b"),
            re.compile(rf"^(?P<indent>\s*)class\s+{escaped}\b"),
        ]
    if language == "javascript":
        return [
            re.compile(rf"^\s*(?:export\s+default\s+)?(?:export\s+)?(?:async\s+)?function\s+{escaped}\b"),
            re.compile(rf"^\s*(?:export\s+)?class\s+{escaped}\b"),
            re.compile(rf"^\s*(?:export\s+)?(?:const|let|var)\s+{escaped}\b"),
            re.compile(rf"^\s*(?:export\s+)?(?:interface|type)\s+{escaped}\b"),
            re.compile(rf"^\s*(?:(?:public|private|protected|static|async|get|set)\s+)*{escaped}\s*\([^;]*\)\s*(?::[^\{{;]+)?\{{"),
            re.compile(rf"^\s*{escaped}\s*:\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*=>|[^,]+=>)"),
        ]
    if language == "go":
        return [
            re.compile(rf"^\s*func\s+(?:\([^)]*\)\s*)?{escaped}\b"),
            re.compile(rf"^\s*type\s+{escaped}\b"),
        ]
    if language == "rust":
        return [
            re.compile(rf"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+{escaped}\b"),
            re.compile(rf"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum|trait|type)\s+{escaped}\b"),
            re.compile(rf"^\s*impl\b.*\b{escaped}\b"),
        ]
    return [re.compile(rf"\b{escaped}\b")]


def find_start(lines: list[str], symbol: str, language: str) -> int | None:
    patterns = symbol_patterns(symbol, language)
    for index, line in enumerate(lines):
        if any(pattern.search(line) for pattern in patterns):
            return index
    return None


def python_block_end(lines: list[str], start: int) -> int:
    indent = len(lines[start]) - len(lines[start].lstrip())
    end = start + 1
    pending_blank_or_comment_end = end
    for index in range(start + 1, len(lines)):
        line = lines[index]
        stripped = line.strip()
        if not stripped:
            pending_blank_or_comment_end = index + 1
            continue
        current_indent = len(line) - len(line.lstrip())
        if stripped.startswith("#"):
            if current_indent > indent:
                end = index + 1
            else:
                pending_blank_or_comment_end = index + 1
            continue
        if current_indent <= indent:
            break
        end = max(index + 1, pending_blank_or_comment_end)
    return max(end, start + 1)


def python_ast_block_end(text: str, symbol: str, start: int) -> int | None:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if node.name != symbol or node.lineno - 1 != start:
            continue
        end_lineno = getattr(node, "end_lineno", None)
        if isinstance(end_lineno, int):
            return max(end_lineno, node.lineno)
    return None


def brace_block_end(lines: list[str], start: int) -> int:
    depth = 0
    started = False
    in_block_comment = False
    for index in range(start, len(lines)):
        line, in_block_comment = strip_line_for_brace_count(lines[index], in_block_comment)
        opens = line.count("{")
        closes = line.count("}")
        if opens:
            started = True
        depth += opens - closes
        if started and depth <= 0:
            return index + 1
        if not started and index >= start and line.strip().endswith((";", ",")):
            return index + 1
    # Heuristic fallback for unmatched braces or deliberately truncated files.
    return min(len(lines), start + BRACE_FALLBACK_LINES)


def strip_line_strings(line: str) -> str:
    # Good enough for brace counting in source snippets; avoids most braces in strings.
    line = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', '""', line)
    line = re.sub(r"`(?:\\.|[^`\\])*`", "``", line)
    return line


def strip_line_for_brace_count(line: str, in_block_comment: bool = False) -> tuple[str, bool]:
    # Track multi-line block comments so braces inside comments do not end a
    # JavaScript/Go/Rust symbol slice before the real closing brace.
    line = strip_line_strings(line)
    output: list[str] = []
    index = 0
    while index < len(line):
        if in_block_comment:
            end = line.find("*/", index)
            if end == -1:
                return "".join(output), True
            index = end + 2
            in_block_comment = False
            continue
        line_comment = line.find("//", index)
        block_comment = line.find("/*", index)
        if line_comment != -1 and (block_comment == -1 or line_comment < block_comment):
            output.append(line[index:line_comment])
            break
        if block_comment == -1:
            output.append(line[index:])
            break
        output.append(line[index:block_comment])
        index = block_comment + 2
        in_block_comment = True
    return "".join(output), in_block_comment


def redact_symbol_content(content: str) -> str:
    sanitizer = LineSanitizer(show_paths=True)
    return "".join(sanitizer.sanitize(line)[0] for line in content.splitlines(keepends=True))


def find_symbol_slice(path: Path, symbol: str, context: int, max_chars: int, show_paths: bool) -> SymbolSlice | None:
    text, scan_truncated = read_text_bounded(path)
    lines = text.splitlines(keepends=True)
    language = language_for(path)
    start = find_start(lines, symbol, language)
    if start is None:
        return None

    if language == "python":
        end = python_ast_block_end(text, symbol, start) or python_block_end(lines, start)
    elif language in {"javascript", "go", "rust"}:
        end = brace_block_end(lines, start)
    else:
        end = min(len(lines), start + 40)

    start_with_context = max(0, start - max(0, context))
    end_with_context = min(len(lines), end + max(0, context))
    content = "".join(lines[start_with_context:end_with_context])
    content = redact_symbol_content(content)
    content = redact_sensitive_hook_text(content, "[REDACTED]")
    capped = False
    if max_chars > 0 and len(content) > max_chars:
        marker = f"\n[context-guard-kit] symbol slice capped: {len(content)} chars total\n"
        keep = max(0, max_chars - len(marker))
        content = content[:keep].rstrip() + marker
        capped = True
    return SymbolSlice(
        path_label(path.resolve(), show_paths),
        symbol,
        start_with_context + 1,
        end_with_context,
        language,
        content,
        capped,
        scan_truncated,
    )


def print_text(result: SymbolSlice) -> None:
    print(f"[context-guard-kit] {result.path}:{result.start_line}-{result.end_line} symbol={result.symbol} language={result.language}")
    print(result.content, end="" if result.content.endswith("\n") else "\n")
    if result.capped:
        print("[context-guard-kit] rerun with a narrower symbol or larger --max-chars only if necessary.")
    if result.scan_truncated:
        print(f"[context-guard-kit] search scanned only the first {MAX_READ_BYTES} bytes of the file.")


def main() -> int:
    parser = argparse.ArgumentParser(prog="context-guard-read-symbol")
    parser.add_argument("path")
    parser.add_argument("symbol")
    parser.add_argument("--context", type=int, default=DEFAULT_CONTEXT_LINES)
    parser.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--show-paths", action="store_true", help="show raw absolute paths in output; local debugging only because private paths may be exposed")
    args = parser.parse_args()

    args.context = bounded_int(args.context, DEFAULT_CONTEXT_LINES, 0, MAX_CONTEXT_LINES_LIMIT)
    args.max_chars = bounded_int(args.max_chars, DEFAULT_MAX_CHARS, MIN_MAX_CHARS, MAX_CHARS_LIMIT)

    path = Path(args.path).expanduser()
    path = _normalize_allowed_first_absolute_symlink(path)
    safe_path = path_label(path.absolute(), args.show_paths)
    if has_symlink_component(path):
        print(f"context-guard-read-symbol: refusing symlink path component: {safe_path}", file=sys.stderr)
        return 2
    if not path.is_file():
        print(f"context-guard-read-symbol: not a file: {safe_path}", file=sys.stderr)
        return 2
    try:
        result = find_symbol_slice(path, args.symbol, args.context, args.max_chars, args.show_paths)
    except OSError as exc:
        print(f"context-guard-read-symbol: could not read file safely: {safe_path}: {os_error_summary(exc)}", file=sys.stderr)
        return 2
    if result is None:
        suffix = ""
        try:
            if path.stat().st_size > MAX_READ_BYTES:
                suffix = f" in first {MAX_READ_BYTES} bytes; use rg -n to locate a later match"
        except OSError:
            pass
        print(f"context-guard-read-symbol: symbol not found{suffix}: {args.symbol}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result.as_dict(), indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print_text(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
