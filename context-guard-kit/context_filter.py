#!/usr/bin/env python3
"""Validate and apply bounded declarative command-output filters.

This helper is intentionally opt-in. User filter configs live outside package
code and invalid/no-match/failure cases pass command output through rather than
risk hiding evidence.
"""
from __future__ import annotations

import argparse
import codecs
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shlex
import signal
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Iterable

SCHEMA_VERSION = "contextguard.filter-dsl.v1"
TOOL_NAME = "context-guard-filter"
MAX_CONFIG_BYTES = 1_000_000
MAX_FILTERS = 100
MAX_REGEXES_PER_FILTER = 20
MAX_REGEX_CHARS = 500
MAX_ARG_PARTS = 64
MAX_ARG_CHARS = 200
DEFAULT_MAX_CAPTURE_BYTES = 5_000_000
MAX_CAPTURE_BYTES_LIMIT = 50_000_000
DEFAULT_MAX_LINE_CHARS = 100_000
MAX_LINE_CHARS_LIMIT = 1_000_000
MAX_EMIT_LINES = 5_000
DEFAULT_TIMEOUT_SECONDS = 600
MAX_TIMEOUT_SECONDS = 86_400
TIMEOUT_EXIT_CODE = 124
TIMEOUT_PIPE_DRAIN_GRACE_SECONDS = 5.0
PIPE_THREAD_CLOSE_GRACE_SECONDS = 1.0
FILTER_KEYS = {"id", "match", "passthrough_on_exit", "include_regex", "exclude_regex", "head_lines", "tail_lines", "max_lines"}
MATCH_KEYS = {"argv_prefix", "argv_regex"}
PROTECTED_BASENAMES = {
    "git",
    "gh",
    "pytest",
    "ruff",
    "mypy",
    "eslint",
    "vitest",
    "jest",
}
PROTECTED_NPM_TASKS = {"test", "lint"}
PROTECTED_PYTHON_MODULES = {"pytest", "ruff", "mypy"}
PROTECTED_DIRECT_NAMES = {"pytest", "ruff", "mypy", "eslint", "vitest", "jest", "tox"}
PROTECTED_INTENT_TOKENS = {"test", "tests", "lint", "clippy"}


@dataclass(frozen=True)
class CompiledFilter:
    id: str
    argv_prefix: tuple[str, ...] | None
    argv_regex: re.Pattern[str] | None
    passthrough_on_exit: bool
    include_regex: tuple[re.Pattern[str], ...]
    exclude_regex: tuple[re.Pattern[str], ...]
    head_lines: int | None
    tail_lines: int | None
    max_lines: int | None


def bounded_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return min(max(number, minimum), maximum)


def compact(text: str, limit: int = 160) -> str:
    text = " ".join(str(text).split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 20)] + f"…[trimmed:{len(text)}]"


ALLOWED_FIRST_ABSOLUTE_SYMLINKS = {
    "tmp": Path("/private/tmp"),
    "var": Path("/private/var"),
}
NO_FOLLOW_SUPPORTED = hasattr(os, "O_NOFOLLOW")
DIR_FD_OPEN_SUPPORTED = bool(os.supports_dir_fd and os.open in os.supports_dir_fd)
DIR_FD_STAT_SUPPORTED = bool(os.supports_dir_fd and os.stat in os.supports_dir_fd)
DIR_FD_MKDIR_SUPPORTED = bool(os.supports_dir_fd and os.mkdir in os.supports_dir_fd)
NONBLOCK_SUPPORTED = hasattr(os, "O_NONBLOCK")


def os_error_detail(exc: OSError) -> str:
    detail = exc.strerror or str(exc) or exc.__class__.__name__
    if exc.errno is not None:
        return f"{detail} (errno {exc.errno})"
    return detail


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


def normalize_config_path(path: Path) -> Path:
    path = path.expanduser()
    if any(part == ".." for part in path.parts):
        raise OSError("config path must not contain parent traversal")
    if not path.is_absolute():
        path = Path.cwd() / path
    return normalize_allowed_first_absolute_symlink(Path(os.path.normpath(str(path))))


def no_follow_dir_flags() -> int:
    if not NO_FOLLOW_SUPPORTED:
        raise OSError("O_NOFOLLOW is required for safe config reads")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    return flags


def no_follow_file_flags() -> int:
    if not NO_FOLLOW_SUPPORTED:
        raise OSError("O_NOFOLLOW is required for safe config reads")
    if not NONBLOCK_SUPPORTED:
        raise OSError("O_NONBLOCK is required for safe config reads")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOCTTY"):
        flags |= os.O_NOCTTY
    return flags


def open_config_parent_no_follow(path: Path) -> int:
    if not DIR_FD_OPEN_SUPPORTED:
        raise OSError("dir_fd open support is required for safe config reads")
    flags = no_follow_dir_flags()
    if path.is_absolute():
        anchor = path.anchor or os.sep
        current_fd = os.open(anchor, os.O_RDONLY | (os.O_CLOEXEC if hasattr(os, "O_CLOEXEC") else 0))
        parts = path.parts[1:-1]
    else:
        current_fd = os.open(".", flags)
        parts = path.parts[:-1]
    try:
        for part in parts:
            if part in {"", "."}:
                continue
            if part == "..":
                raise OSError("config path must not contain parent traversal")
            next_fd = os.open(part, flags, dir_fd=current_fd)
            try:
                if not stat.S_ISDIR(os.fstat(next_fd).st_mode):
                    raise OSError("config path must not traverse non-directory components")
            except Exception:
                os.close(next_fd)
                raise
            os.close(current_fd)
            current_fd = next_fd
        owned_fd = current_fd
        current_fd = -1
        return owned_fd
    finally:
        if current_fd >= 0:
            os.close(current_fd)


def read_config_text_no_follow(path: Path, max_bytes: int) -> tuple[str | None, list[str]]:
    parent_fd = -1
    fd = -1
    try:
        path = normalize_config_path(path)
        parent_fd = open_config_parent_no_follow(path)
        leaf = path.name
        if leaf in {"", ".", ".."}:
            return None, ["config path must name a regular file"]
        if not DIR_FD_STAT_SUPPORTED:
            raise OSError("dir_fd stat support is required for safe config reads")
        try:
            st = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None, ["could not read config: missing file"]
        if not stat.S_ISREG(st.st_mode):
            return None, ["config must be a regular file"]
        if st.st_size > max_bytes:
            return None, [f"config file too large: {st.st_size}>{max_bytes} bytes"]
        fd = os.open(leaf, no_follow_file_flags(), dir_fd=parent_fd)
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            return None, ["config must be a regular file"]
        if fst.st_size > max_bytes:
            return None, [f"config file too large: {fst.st_size}>{max_bytes} bytes"]
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > max_bytes:
            return None, [f"config file too large: >{max_bytes} bytes"]
        try:
            return raw.decode("utf-8"), []
        except UnicodeDecodeError as exc:
            return None, [f"could not decode config UTF-8: {exc.reason}"]
    except OSError as exc:
        return None, [f"could not read config safely: {os_error_detail(exc)}"]
    finally:
        if fd >= 0:
            os.close(fd)
        if parent_fd >= 0:
            os.close(parent_fd)


def read_json_limited(path: Path) -> tuple[Any | None, list[str]]:
    raw, read_errors = read_config_text_no_follow(path, MAX_CONFIG_BYTES)
    if read_errors:
        return None, read_errors
    try:
        return json.loads(raw if raw is not None else ""), []
    except json.JSONDecodeError as exc:
        return None, [f"invalid JSON at line {exc.lineno}: {exc.msg}"]


def validate_str_list(value: Any, *, field: str, errors: list[str], max_items: int = MAX_REGEXES_PER_FILTER) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        errors.append(f"{field} must be a list")
        return []
    if len(value) > max_items:
        errors.append(f"{field} has too many items: {len(value)}>{max_items}")
    out: list[str] = []
    for idx, item in enumerate(value[:max_items]):
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{field}[{idx}] must be a non-empty string")
            continue
        if len(item) > MAX_REGEX_CHARS:
            errors.append(f"{field}[{idx}] exceeds {MAX_REGEX_CHARS} chars")
            continue
        out.append(item)
    return out


def compile_regexes(patterns: Iterable[str], *, field: str, errors: list[str]) -> tuple[re.Pattern[str], ...]:
    compiled: list[re.Pattern[str]] = []
    for idx, pattern in enumerate(patterns):
        try:
            compiled.append(re.compile(pattern))
        except re.error as exc:
            errors.append(f"{field}[{idx}] invalid regex: {compact(str(exc), 120)}")
    return tuple(compiled)


def bounded_optional_int(raw: Any, *, field: str, errors: list[str], minimum: int = 0) -> int | None:
    if raw is None:
        return None
    if not isinstance(raw, int) or isinstance(raw, bool):
        errors.append(f"{field} must be an integer")
        return None
    if raw < minimum or raw > MAX_EMIT_LINES:
        errors.append(f"{field} out of bounds: {minimum}..{MAX_EMIT_LINES}")
        return None
    return raw


def validate_config(raw: Any) -> tuple[list[CompiledFilter], list[str]]:
    errors: list[str] = []
    if not isinstance(raw, dict):
        return [], ["config root must be a JSON object"]
    unknown_root = sorted(set(raw) - {"schema_version", "filters"})
    if unknown_root:
        errors.append(f"unknown root keys: {', '.join(unknown_root)}")
    if raw.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    filters_raw = raw.get("filters")
    if not isinstance(filters_raw, list) or not filters_raw:
        errors.append("filters must be a non-empty list")
        return [], errors
    if len(filters_raw) > MAX_FILTERS:
        errors.append(f"filters has too many items: {len(filters_raw)}>{MAX_FILTERS}")
    seen_ids: set[str] = set()
    compiled: list[CompiledFilter] = []
    for idx, item in enumerate(filters_raw[:MAX_FILTERS]):
        prefix = f"filters[{idx}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        unknown = sorted(set(item) - FILTER_KEYS)
        if unknown:
            errors.append(f"{prefix} unknown keys: {', '.join(unknown)}")
        fid = item.get("id")
        if not isinstance(fid, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", fid):
            errors.append(f"{prefix}.id must match [A-Za-z0-9._-] and be <=80 chars")
            fid = f"invalid-{idx}"
        elif fid in seen_ids:
            errors.append(f"{prefix}.id duplicates {fid}")
        seen_ids.add(str(fid))
        match = item.get("match")
        argv_prefix: tuple[str, ...] | None = None
        argv_regex: re.Pattern[str] | None = None
        if not isinstance(match, dict):
            errors.append(f"{prefix}.match must be an object")
        else:
            unknown_match = sorted(set(match) - MATCH_KEYS)
            if unknown_match:
                errors.append(f"{prefix}.match unknown keys: {', '.join(unknown_match)}")
            if "argv_prefix" in match:
                parts = validate_str_list(match.get("argv_prefix"), field=f"{prefix}.match.argv_prefix", errors=errors, max_items=MAX_ARG_PARTS)
                for part_idx, part in enumerate(parts):
                    if len(part) > MAX_ARG_CHARS:
                        errors.append(f"{prefix}.match.argv_prefix[{part_idx}] exceeds {MAX_ARG_CHARS} chars")
                if parts:
                    argv_prefix = tuple(parts)
            if "argv_regex" in match:
                pattern = match.get("argv_regex")
                if not isinstance(pattern, str) or not pattern.strip():
                    errors.append(f"{prefix}.match.argv_regex must be a non-empty string")
                elif len(pattern) > MAX_REGEX_CHARS:
                    errors.append(f"{prefix}.match.argv_regex exceeds {MAX_REGEX_CHARS} chars")
                else:
                    compiled_argv_regex = compile_regexes([pattern], field=f"{prefix}.match.argv_regex", errors=errors)
                    argv_regex = compiled_argv_regex[0] if compiled_argv_regex else None
            if not argv_prefix and argv_regex is None:
                errors.append(f"{prefix}.match requires argv_prefix or argv_regex")
        passthrough = item.get("passthrough_on_exit", True)
        if not isinstance(passthrough, bool):
            errors.append(f"{prefix}.passthrough_on_exit must be boolean")
            passthrough = True
        include = validate_str_list(item.get("include_regex"), field=f"{prefix}.include_regex", errors=errors)
        exclude = validate_str_list(item.get("exclude_regex"), field=f"{prefix}.exclude_regex", errors=errors)
        if len(include) + len(exclude) > MAX_REGEXES_PER_FILTER:
            errors.append(f"{prefix} has too many regexes: {len(include) + len(exclude)}>{MAX_REGEXES_PER_FILTER}")
        head = bounded_optional_int(item.get("head_lines"), field=f"{prefix}.head_lines", errors=errors)
        tail = bounded_optional_int(item.get("tail_lines"), field=f"{prefix}.tail_lines", errors=errors)
        max_lines = bounded_optional_int(item.get("max_lines"), field=f"{prefix}.max_lines", errors=errors, minimum=1)
        compiled.append(CompiledFilter(
            id=str(fid),
            argv_prefix=argv_prefix,
            argv_regex=argv_regex,
            passthrough_on_exit=passthrough,
            include_regex=compile_regexes(include, field=f"{prefix}.include_regex", errors=errors),
            exclude_regex=compile_regexes(exclude, field=f"{prefix}.exclude_regex", errors=errors),
            head_lines=head,
            tail_lines=tail,
            max_lines=max_lines,
        ))
    return compiled, errors


def load_filters(path: Path) -> tuple[list[CompiledFilter], list[str]]:
    raw, read_errors = read_json_limited(path)
    if read_errors:
        return [], read_errors
    return validate_config(raw)


def command_text(argv: list[str]) -> str:
    try:
        return shlex.join(argv)
    except Exception:
        return " ".join(argv)


def filter_matches(flt: CompiledFilter, argv: list[str]) -> bool:
    if flt.argv_prefix is not None and tuple(argv[: len(flt.argv_prefix)]) == flt.argv_prefix:
        return True
    if flt.argv_regex is not None and flt.argv_regex.search(command_text(argv)):
        return True
    return False


def basename(arg: str) -> str:
    return Path(arg).name.lower()


def argv_signal_tokens(argv: list[str]) -> set[str]:
    tokens: set[str] = set()
    for arg in argv:
        lowered = basename(arg)
        if lowered:
            tokens.add(lowered)
        tokens.update(part for part in re.split(r"[^a-z0-9]+", lowered) if part)
    return tokens


def has_test_lint_signal(argv: list[str]) -> bool:
    tokens = argv_signal_tokens(argv)
    return bool(tokens & PROTECTED_DIRECT_NAMES or tokens & PROTECTED_INTENT_TOKENS)


def is_protected_command(argv: list[str]) -> bool:
    if not argv:
        return False
    first = basename(argv[0])
    if first in PROTECTED_BASENAMES:
        return True
    if first in {"python", "python3"} and len(argv) >= 3 and argv[1] == "-m" and basename(argv[2]) in PROTECTED_PYTHON_MODULES:
        return True
    if first in {"npm", "pnpm", "yarn"} and len(argv) >= 2:
        if argv[1] in PROTECTED_NPM_TASKS:
            return True
        if len(argv) >= 3 and argv[1] == "run" and has_test_lint_signal(argv[2:]):
            return True
        if len(argv) >= 3 and argv[1] in {"exec", "x", "dlx"} and has_test_lint_signal(argv[2:]):
            return True
    if first in {"npx", "bun", "make", "gradle", "gradlew", "mvn", "poetry", "uv", "pipenv", "hatch", "tox"} and has_test_lint_signal(argv):
        return True
    if first == "go" and len(argv) >= 2 and argv[1] == "test":
        return True
    if first == "cargo" and len(argv) >= 2 and argv[1] in {"test", "clippy"}:
        return True
    return False


def cap_line(line: str, max_chars: int) -> str:
    if len(line) <= max_chars:
        return line
    suffix = "\n" if line.endswith("\n") else ""
    marker = f"...[line capped:{len(line)} chars]"
    return line[: max(0, max_chars - len(marker) - len(suffix))] + marker + suffix


def select_lines(lines: list[str], flt: CompiledFilter, max_line_chars: int) -> list[str]:
    selected = [cap_line(line, max_line_chars) for line in lines]
    if flt.include_regex:
        selected = [line for line in selected if any(pattern.search(line) for pattern in flt.include_regex)]
    if flt.exclude_regex:
        selected = [line for line in selected if not any(pattern.search(line) for pattern in flt.exclude_regex)]
    if flt.head_lines is not None or flt.tail_lines is not None:
        head_n = flt.head_lines if flt.head_lines is not None else 0
        tail_n = flt.tail_lines if flt.tail_lines is not None else 0
        head = selected[:head_n] if head_n else []
        tail = selected[-tail_n:] if tail_n else []
        if head and tail:
            seen_head_count = len(head)
            tail = tail[max(0, seen_head_count + len(tail) - len(selected)):]
        selected = head + tail
    if flt.max_lines is not None and len(selected) > flt.max_lines:
        selected = selected[:flt.max_lines]
    if len(selected) > MAX_EMIT_LINES:
        selected = selected[:MAX_EMIT_LINES]
    return selected


def validation_payload(valid: bool, errors: list[str], count: int = 0) -> dict[str, Any]:
    return {"tool": TOOL_NAME, "schema_version": SCHEMA_VERSION, "mode": "validate", "valid": valid, "filter_count": count, "errors": errors}


def print_validation(valid: bool, errors: list[str], count: int, as_json: bool) -> None:
    if as_json:
        print(json.dumps(validation_payload(valid, errors, count), ensure_ascii=False, sort_keys=True))
    elif valid:
        print(f"{TOOL_NAME}: valid filter config ({count} filter(s))")
    else:
        print(f"{TOOL_NAME}: invalid filter config", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)


@dataclass
class CommandResult:
    returncode: int
    stdout_text: str
    stderr_text: str
    output_bytes: int
    capture_limited: bool
    timed_out: bool
    drain_timed_out: bool
    passthrough_emitted: bool


def write_binary_chunk(stream: Any, chunk: bytes) -> None:
    if not chunk:
        return
    stream.flush()
    binary = getattr(stream, "buffer", None)
    if binary is not None:
        binary.write(chunk)
    else:
        stream.write(chunk.decode("utf-8", "replace"))
    stream.flush()


class BoundedCapture:
    def __init__(self, max_capture_bytes: int) -> None:
        self.max_capture_bytes = max_capture_bytes
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.output_bytes = 0
        self.capture_limited = False
        self.passthrough_emitted = False
        self._lock = threading.Lock()
        self._emit_condition = threading.Condition()
        self._next_emit_order = 0
        self._active_emit_order = 0
        self._stdout_decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self._stderr_decoder = codecs.getincrementaldecoder("utf-8")("replace")

    def consume(self, stream_name: str, chunk: bytes) -> None:
        if not chunk:
            return
        passthrough: list[tuple[Any, bytes]] = []
        emit_order: int | None = None
        with self._lock:
            self.output_bytes += len(chunk)
            if self.capture_limited:
                passthrough.append((sys.stdout if stream_name == "stdout" else sys.stderr, chunk))
            else:
                stored_total = len(self.stdout) + len(self.stderr)
                remaining = self.max_capture_bytes - stored_total
                target = self.stdout if stream_name == "stdout" else self.stderr
                if len(chunk) <= remaining:
                    target.extend(chunk)
                    return
                if remaining > 0:
                    target.extend(chunk[:remaining])
                    overflow = chunk[remaining:]
                else:
                    overflow = chunk
                self.capture_limited = True
                self.passthrough_emitted = True
                passthrough.extend(
                    [
                        (sys.stdout, bytes(self.stdout)),
                        (sys.stderr, bytes(self.stderr)),
                        (sys.stdout if stream_name == "stdout" else sys.stderr, overflow),
                    ]
                )
            if passthrough:
                emit_order = self._next_emit_order
                self._next_emit_order += 1
        if emit_order is None:
            return
        with self._emit_condition:
            while emit_order != self._active_emit_order:
                self._emit_condition.wait()
        try:
            for stream, payload in passthrough:
                write_binary_chunk(stream, payload)
        finally:
            with self._emit_condition:
                self._active_emit_order += 1
                self._emit_condition.notify_all()

    def text(self) -> tuple[str, str]:
        with self._lock:
            stdout_bytes = bytes(self.stdout)
            stderr_bytes = bytes(self.stderr)
        stdout = self._stdout_decoder.decode(stdout_bytes, final=True)
        stderr = self._stderr_decoder.decode(stderr_bytes, final=True)
        return stdout, stderr


def run_command(argv: list[str], timeout_seconds: int, max_capture_bytes: int) -> CommandResult:
    if not argv:
        stderr = f"{TOOL_NAME}: command failed to start: no command provided\n"
        output_bytes = len(stderr.encode("utf-8", "replace"))
        return CommandResult(127, "", stderr, output_bytes, False, False, False, False)
    capture = BoundedCapture(max_capture_bytes)

    def read_pipe(pipe: Any, stream_name: str) -> None:
        try:
            while True:
                chunk = pipe.read(64 * 1024)
                if not chunk:
                    break
                capture.consume(stream_name, chunk)
        finally:
            try:
                pipe.close()
            except OSError:
                pass

    def terminate_processes(proc: subprocess.Popen[bytes], *, force: bool) -> None:
        if os.name == "posix":
            try:
                os.killpg(proc.pid, signal.SIGKILL if force else signal.SIGTERM)
                return
            except ProcessLookupError:
                return
            except OSError:
                pass
        try:
            if proc.poll() is not None:
                return
            if force:
                proc.kill()
            else:
                proc.terminate()
        except (OSError, ValueError):
            pass

    def close_pipes(proc: subprocess.Popen[bytes]) -> None:
        for pipe in (proc.stdout, proc.stderr):
            if pipe is None:
                continue
            try:
                pipe.close()
            except OSError:
                pass

    def join_threads_until(threads: tuple[threading.Thread, threading.Thread], deadline: float) -> bool:
        for thread in threads:
            remaining = max(0.0, deadline - time.monotonic())
            thread.join(timeout=remaining)
        return all(not thread.is_alive() for thread in threads)

    def terminate_and_close(proc: subprocess.Popen[bytes], threads: tuple[threading.Thread, threading.Thread]) -> None:
        terminate_processes(proc, force=False)
        try:
            proc.wait(timeout=PIPE_THREAD_CLOSE_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            pass
        if join_threads_until(threads, time.monotonic() + PIPE_THREAD_CLOSE_GRACE_SECONDS):
            return
        terminate_processes(proc, force=True)
        try:
            proc.wait(timeout=PIPE_THREAD_CLOSE_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            pass
        close_pipes(proc)
        for thread in threads:
            thread.join(timeout=PIPE_THREAD_CLOSE_GRACE_SECONDS)

    try:
        started_at = time.monotonic()
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=(os.name == "posix"))
        assert proc.stdout is not None
        assert proc.stderr is not None
        stdout_thread = threading.Thread(target=read_pipe, args=(proc.stdout, "stdout"), daemon=True)
        stderr_thread = threading.Thread(target=read_pipe, args=(proc.stderr, "stderr"), daemon=True)
        reader_threads = (stdout_thread, stderr_thread)
        stdout_thread.start()
        stderr_thread.start()
        timed_out = False
        drain_timed_out = False
        try:
            returncode = proc.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            returncode = TIMEOUT_EXIT_CODE
            terminate_and_close(proc, reader_threads)
        drain_deadline = time.monotonic() + TIMEOUT_PIPE_DRAIN_GRACE_SECONDS
        if not join_threads_until(reader_threads, drain_deadline):
            drain_timed_out = True
            terminate_and_close(proc, reader_threads)
        if timed_out:
            capture.consume("stderr", f"\n[{TOOL_NAME}] command timed out after {timeout_seconds}s\n".encode("utf-8"))
        elif drain_timed_out:
            capture.consume("stderr", f"\n[{TOOL_NAME}] command pipe drain timed out after direct process exit\n".encode("utf-8"))
        stdout_text, stderr_text = ("", "") if capture.capture_limited else capture.text()
        return CommandResult(returncode, stdout_text, stderr_text, capture.output_bytes, capture.capture_limited, timed_out, drain_timed_out, capture.passthrough_emitted)
    except OSError as exc:
        stderr = f"{TOOL_NAME}: command failed to start: {exc.strerror or exc.__class__.__name__}\n"
        encoded = stderr.encode("utf-8", "replace")
        output_bytes = len(encoded)
        return CommandResult(127, "", stderr, output_bytes, False, False, False, False)


def emit_run_report(args: argparse.Namespace, payload: dict[str, Any]) -> None:
    if payload.get("protected_nonzero"):
        return
    if args.json_report:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True), file=sys.stderr)
    elif payload.get("decision") == "passthrough" and payload.get("reason") not in {"no-match", "nonzero-passthrough"}:
        print(f"{TOOL_NAME}: passthrough: {payload.get('reason')}", file=sys.stderr)


def cmd_validate(args: argparse.Namespace) -> int:
    filters, errors = load_filters(Path(args.config).expanduser())
    print_validation(not errors, errors, len(filters), args.json)
    return 0 if not errors else 2


def cmd_run(args: argparse.Namespace) -> int:
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print(f"{TOOL_NAME}: missing command", file=sys.stderr)
        return 2
    max_capture = bounded_int(args.max_capture_bytes, DEFAULT_MAX_CAPTURE_BYTES, 1, MAX_CAPTURE_BYTES_LIMIT)
    max_line_chars = bounded_int(args.max_line_chars, DEFAULT_MAX_LINE_CHARS, 1, MAX_LINE_CHARS_LIMIT)
    timeout_seconds = bounded_int(args.timeout_seconds, DEFAULT_TIMEOUT_SECONDS, 1, MAX_TIMEOUT_SECONDS)
    filters, errors = load_filters(Path(args.config).expanduser())
    result = run_command(command, timeout_seconds, max_capture)
    rc = result.returncode
    output = result.stdout_text + result.stderr_text
    protected_nonzero = rc != 0 and is_protected_command(command)
    report: dict[str, Any] = {"tool": TOOL_NAME, "schema_version": SCHEMA_VERSION, "mode": "run", "command_exit_code": rc, "decision": "passthrough", "reason": "unclassified", "protected_nonzero": protected_nonzero}
    if result.timed_out:
        report["reason"] = "timeout"
    elif result.drain_timed_out:
        report["reason"] = "pipe-drain-timeout"
    elif errors:
        report["reason"] = "invalid-config"
        report["errors"] = errors[:10]
    elif result.capture_limited:
        report["reason"] = "capture-limit"
        report["output_bytes"] = result.output_bytes
        report["max_capture_bytes"] = max_capture
    else:
        matched = next((flt for flt in filters if filter_matches(flt, command)), None)
        if matched is None:
            report["reason"] = "no-match"
        elif protected_nonzero:
            report["reason"] = "protected-nonzero"
            report["filter_id"] = matched.id
        elif rc != 0 and matched.passthrough_on_exit:
            report["reason"] = "nonzero-passthrough"
            report["filter_id"] = matched.id
        else:
            try:
                lines = output.splitlines(keepends=True)
                filtered = select_lines(lines, matched, max_line_chars)
            except re.error as exc:
                report["reason"] = f"filter-error:{compact(str(exc), 80)}"
                report["filter_id"] = matched.id
            else:
                if output and not filtered:
                    report["reason"] = "empty-output-fallback"
                    report["filter_id"] = matched.id
                else:
                    sys.stdout.write("".join(filtered))
                    report.update({"decision": "filtered", "reason": "matched", "filter_id": matched.id, "input_lines": len(lines), "output_lines": len(filtered)})
                    emit_run_report(args, report)
                    return rc
    if not result.passthrough_emitted:
        sys.stdout.write(result.stdout_text)
        sys.stderr.write(result.stderr_text)
    emit_run_report(args, report)
    return rc

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=TOOL_NAME, description="Validate and apply bounded declarative command-output filters. Filtered mode applies line rules to combined stdout+stderr and writes the filtered result to stdout; passthrough mode preserves stdout/stderr streams.")
    sub = parser.add_subparsers(dest="command_name", required=True)
    validate = sub.add_parser("validate", help="validate a filter DSL JSON file")
    validate.add_argument("--config", required=True, help="path to user-owned filter JSON")
    validate.add_argument("--json", action="store_true", help="emit validation result as JSON")
    validate.set_defaults(func=cmd_validate)
    run = sub.add_parser("run", help="run a command and apply the first matching safe filter")
    run.add_argument("--config", required=True, help="path to user-owned filter JSON")
    run.add_argument("--json-report", action="store_true", help="emit filter decision JSON to stderr; protected nonzero passthrough suppresses reports to preserve raw stderr")
    run.add_argument("--max-capture-bytes", type=int, default=DEFAULT_MAX_CAPTURE_BYTES)
    run.add_argument("--max-line-chars", type=int, default=DEFAULT_MAX_LINE_CHARS)
    run.add_argument("--timeout-seconds", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    run.add_argument("command", nargs=argparse.REMAINDER)
    run.set_defaults(func=cmd_run)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
