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


CHILD_PREAMBLE = """
import importlib.util
import json
import sys
from pathlib import Path


def load(rel, name, extra=()):
    for entry in extra:
        resolved = str(Path(entry).resolve())
        if resolved not in sys.path:
            sys.path.insert(0, resolved)
    spec = importlib.util.spec_from_file_location(name, rel)
    if spec is None or spec.loader is None:
        raise RuntimeError("not importable: " + rel)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def emit(value):
    sys.stdout.write("PROBE " + NONCE + " " + json.dumps(value, sort_keys=True, default=str) + chr(10))
    sys.stdout.flush()
"""


def probe(child_code):
    """Run candidate-touching code in a child process and return its raw report.

    The child never decides pass or fail. It reports observed values, and this
    parent compares them. An os._exit, a rebound helper, or a crash inside the
    child can only remove or corrupt the PROBE line, which fails closed here.
    """
    nonce = secrets.token_hex(8)
    script = "NONCE = " + repr(nonce) + chr(10) + CHILD_PREAMBLE + child_code
    try:
        result = subprocess.run(
            [sys.executable, "-c", script], cwd=".",
            capture_output=True, timeout=PROBE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        fail("candidate probe timed out")
    except OSError as exc:
        fail("candidate probe could not start: " + type(exc).__name__)
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip().splitlines()
        fail(
            "candidate probe exited " + str(result.returncode) + ": "
            + (detail[-1][:200] if detail else "no stderr")
        )
    marker = "PROBE " + nonce + " "
    lines = [
        line for line in result.stdout.decode("utf-8", errors="replace").splitlines()
        if line.startswith(marker)
    ]
    if len(lines) != 1:
        fail("candidate probe did not emit exactly one nonce-tagged PROBE line")
    try:
        report = json.loads(lines[0][len(marker):])
    except ValueError:
        fail("candidate probe emitted malformed JSON")
    if not isinstance(report, dict):
        fail("candidate probe report is not an object")
    return report


read("src/dedupe.py")
SIZE = 400
report = probe("""
module = load("src/dedupe.py", "s003_dedupe")
first_unique = getattr(module, "first_unique", None)
if first_unique is None:
    emit({"missing": True})
else:
    cases = []
    for rows in ([], ["a"], ["b", "a", "b", "c", "a"]):
        cases.append(first_unique(list(rows)))
    counts = {"eq": 0}

    class Probe:
        __slots__ = ("key",)

        def __init__(self, key):
            self.key = key

        def __eq__(self, other):
            counts["eq"] += 1
            return isinstance(other, Probe) and self.key == other.key

        def __hash__(self):
            return hash(self.key)

    size = 400
    rows = [Probe("k%03d" % (index % (size // 2))) for index in range(size)]
    counts["eq"] = 0
    result = first_unique(list(rows))
    emit({"missing": False, "cases": cases,
          "order": [item.key for item in result], "eq": counts["eq"]})
""")
if report.get("missing"):
    fail("first_unique is missing")
expected_cases = [[], ["a"], ["b", "a", "c"]]
if report.get("cases") != expected_cases:
    fail("first_unique result changed: " + json.dumps(report.get("cases")))
expected_order = ["k%03d" % index for index in range(SIZE // 2)]
if report.get("order") != expected_order:
    fail("first_unique order or dedup broke on the probe input")
budget = 4 * SIZE
observed = report.get("eq")
if not isinstance(observed, int) or observed < 0:
    fail("candidate probe reported no comparison count")
if observed > budget:
    fail(
        "first_unique still scales quadratically: " + str(observed)
        + " element comparisons for " + str(SIZE) + " rows (budget " + str(budget) + ")"
    )
ok()
