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
text = read("review.md")
lowered = text.lower()
for heading in ("## risk", "## test gap"):
    if heading not in lowered:
        fail("review.md is missing the " + heading + " section")
risk = lowered.split("## risk", 1)[1].split("## test gap", 1)[0].strip()
gap = lowered.split("## test gap", 1)[1].strip()
if len(risk) < 20 or len(gap) < 20:
    fail("review.md sections need at least one concrete sentence each")
ok()
