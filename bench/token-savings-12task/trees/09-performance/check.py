#!/usr/bin/env python3
"""Bounded S003 success check. Reads only this workspace; no network, no shell."""
import json
import sys
from pathlib import Path

MAX_READ_BYTES = 262_144


def read(rel):
    path = Path(rel)
    if path.is_symlink() or not path.is_file():
        fail("missing regular file: " + rel)
    data = path.read_bytes()
    if len(data) > MAX_READ_BYTES:
        fail("file too large: " + rel)
    return data.decode("utf-8")


def load_module(rel, name):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, rel)
    if spec is None or spec.loader is None:
        fail("module not importable: " + rel)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        fail("module raised on import: " + rel + ": " + type(exc).__name__)
    return module


def fail(reason):
    print("FAIL " + reason)
    raise SystemExit(1)


def ok():
    print("OK")
    raise SystemExit(0)
text = read("src/dedupe.py")
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
body = text.split("def first_unique", 1)[1]
loop_count = body.count("for ")
if loop_count != 1:
    fail("first_unique must use exactly one loop, found " + str(loop_count))
if " in result" in body:
    fail("membership scan over the result list is still quadratic")
ok()
