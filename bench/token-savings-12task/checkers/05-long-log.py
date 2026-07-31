#!/usr/bin/env python3
"""Bounded S003 success check.

Executed from a private directory outside the measured workspace, with the
workspace as the current directory. It reads workspace files through bounded
no-follow IO and never executes candidate code in its own process: anything that
touches candidate modules runs in a child process whose reported values this
parent re-verifies. A child that exits early, exits nonzero, or fails to emit
exactly one well-formed PROBE line is a failure.
"""
import json
import os
import secrets
import stat
import subprocess
import sys
from pathlib import Path

MAX_READ_BYTES = 262_144
PROBE_TIMEOUT_SECONDS = 120


def fail(reason):
    print("FAIL " + str(reason))
    raise SystemExit(1)


def ok():
    print("OK")
    raise SystemExit(0)


if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
    # 무결성 속성이 플랫폼에 따라 조용히 사라지는 것을 허용하지 않는다.
    fail("platform lacks no-follow directory open support")

NOFOLLOW = os.O_NOFOLLOW
DIRFLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def _open_no_follow(rel):
    """Open one workspace-relative regular file, following no symlink component."""
    path = Path(rel)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        fail("unsafe path: " + str(rel))
    dir_fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[:-1]:
            try:
                next_fd = os.open(part, DIRFLAGS, dir_fd=dir_fd)
            except OSError:
                fail("missing or symlinked directory component: " + str(rel))
            os.close(dir_fd)
            dir_fd = next_fd
        try:
            return os.open(
                path.parts[-1], os.O_RDONLY | NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd,
            )
        except OSError:
            fail("missing regular file: " + str(rel))
    finally:
        os.close(dir_fd)


def read_bytes(rel):
    fd = _open_no_follow(rel)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
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
    return data


def read(rel):
    try:
        return read_bytes(rel).decode("utf-8")
    except UnicodeDecodeError:
        fail("file is not valid UTF-8: " + str(rel))


def load_json(rel):
    try:
        return json.loads(read(rel))
    except ValueError:
        fail("file is not valid JSON: " + str(rel))


finding = read("finding.txt").strip()
if finding != "npm run lint -- --max-warnings 0":
    fail("finding.txt does not hold the exact failing command")
if "npm run lint -- --max-warnings 0" not in read("build.log"):
    fail("build.log no longer contains the failing command")
ok()
