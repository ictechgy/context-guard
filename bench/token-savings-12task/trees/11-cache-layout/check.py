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
raw = read("prompt-layout.json")
try:
    layout = json.loads(raw)
except ValueError:
    fail("prompt-layout.json is not valid JSON")
segments = layout.get("segments")
if not isinstance(segments, list) or len(segments) != 4:
    fail("prompt-layout.json must keep exactly four segments")
expected = {
    "request_timestamp": ("volatile", "request at 00:00:00"),
    "system_rules": ("stable", "follow the project rules"),
    "tool_catalog": ("stable", "tools: read, write"),
    "user_turn": ("volatile", "current user question"),
}
seen = {}
for segment in segments:
    if not isinstance(segment, dict) or set(segment) != {"id", "stability", "text"}:
        fail("segment shape changed")
    seen[segment["id"]] = (segment["stability"], segment["text"])
if seen != expected:
    fail("segment ids, stability labels, or texts changed")
order = [segment["stability"] for segment in segments]
if order != ["stable", "stable", "volatile", "volatile"]:
    fail("stable segments must precede volatile segments, got " + json.dumps(order))
ok()
