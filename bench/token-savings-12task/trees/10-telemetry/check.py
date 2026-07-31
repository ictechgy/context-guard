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
module = load_module("src/telemetry.py", "s003_telemetry")
build_record = getattr(module, "build_record", None)
if build_record is None:
    fail("build_record is missing")
record = build_record("read_file", ["alpha", "beta", "gamma"])
if set(record) != {"event", "count"}:
    fail("record keys must be exactly event and count")
if record["event"] != "read_file":
    fail("event name changed")
if record["count"] != 3:
    fail("count must be the number of payload items")
serialized = json.dumps(record)
for leaked in ("alpha", "beta", "gamma"):
    if leaked in serialized:
        fail("raw payload value leaked into the record")
ok()
