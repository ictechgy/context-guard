#!/usr/bin/env python3
"""Bounded S003 success check.

Executed from a private directory outside the measured workspace, with the
workspace as the current directory. Reads only workspace files, uses bounded
no-follow IO, and treats a candidate module's premature exit as a failure.
"""
import json
import os
import sys
from pathlib import Path

MAX_READ_BYTES = 262_144


def fail(reason):
    print("FAIL " + reason)
    raise SystemExit(1)


def ok():
    print("OK")
    raise SystemExit(0)


def _open_no_follow(rel):
    """Open one workspace-relative regular file without following any symlink."""
    path = Path(rel)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        fail("unsafe path: " + str(rel))
    flags = getattr(os, "O_NOFOLLOW", 0)
    dir_fd = os.open(".", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        for part in path.parts[:-1]:
            try:
                next_fd = os.open(
                    part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | flags,
                    dir_fd=dir_fd,
                )
            except OSError:
                fail("missing or symlinked directory component: " + str(rel))
            os.close(dir_fd)
            dir_fd = next_fd
        try:
            return os.open(path.parts[-1], os.O_RDONLY | flags, dir_fd=dir_fd)
        except OSError:
            fail("missing regular file: " + str(rel))
    finally:
        os.close(dir_fd)


def read(rel):
    fd = _open_no_follow(rel)
    try:
        import stat as _stat
        info = os.fstat(fd)
        if not _stat.S_ISREG(info.st_mode):
            fail("not a regular file: " + str(rel))
        if info.st_size > MAX_READ_BYTES:
            fail("file too large: " + str(rel))
        chunks = []
        remaining = MAX_READ_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if len(data) > MAX_READ_BYTES:
        fail("file too large: " + str(rel))
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        fail("file is not valid UTF-8: " + str(rel))


def read_bytes(rel):
    fd = _open_no_follow(rel)
    try:
        chunks = []
        remaining = MAX_READ_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if len(data) > MAX_READ_BYTES:
        fail("file too large: " + str(rel))
    return data


def load_module(rel, name, extra_sys_path=()):
    """Import a candidate module, treating any premature exit as a failure.

    BaseException is caught on purpose: a candidate module that raises
    SystemExit(0) at import time would otherwise terminate this checker with a
    success status without any assertion running.
    """
    import importlib.util
    read(rel)  # bounded no-follow existence and size check before import
    for entry in extra_sys_path:
        resolved = str(Path(entry).resolve())
        if resolved not in sys.path:
            sys.path.insert(0, resolved)
    spec = importlib.util.spec_from_file_location(name, rel)
    if spec is None or spec.loader is None:
        fail("module not importable: " + str(rel))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except SystemExit:
        fail("module exited during import: " + str(rel))
    except BaseException as exc:
        fail("module raised on import: " + str(rel) + ": " + type(exc).__name__)
    return module
module = load_module("src/dedupe.py", "s003_dedupe")
first_unique = getattr(module, "first_unique", None)
if first_unique is None:
    fail("first_unique is missing")
cases = [
    ([], []),
    (["a"], ["a"]),
    (["b", "a", "b", "c", "a"], ["b", "a", "c"]),
]
for rows, expected in cases:
    if first_unique(list(rows)) != expected:
        fail("first_unique result changed for " + json.dumps(rows))

# 텍스트 휴리스틱 대신 실제 비교 횟수로 단일 패스 여부를 판정한다. 이차 구현은
# 요소 __eq__ 호출이 입력 길이의 제곱에 비례해 늘어난다.
COUNTS = {"eq": 0}


class Probe:
    __slots__ = ("key",)

    def __init__(self, key):
        self.key = key

    def __eq__(self, other):
        COUNTS["eq"] += 1
        return isinstance(other, Probe) and self.key == other.key

    def __hash__(self):
        return hash(self.key)

    def __repr__(self):
        return "Probe(" + repr(self.key) + ")"


SIZE = 400
rows = [Probe("k%03d" % (index % (SIZE // 2))) for index in range(SIZE)]
COUNTS["eq"] = 0
result = first_unique(list(rows))
if [item.key for item in result] != ["k%03d" % index for index in range(SIZE // 2)]:
    fail("first_unique order or dedup broke on the probe input")
budget = 4 * SIZE
if COUNTS["eq"] > budget:
    fail(
        "first_unique still scales quadratically: "
        + str(COUNTS["eq"]) + " element comparisons for " + str(SIZE)
        + " rows (budget " + str(budget) + ")"
    )
ok()
