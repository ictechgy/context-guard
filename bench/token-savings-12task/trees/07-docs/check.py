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
text = read("docs/usage.md")
lowered = text.lower()
for heading in ("# usage", "## overview", "## options"):
    if heading not in lowered:
        fail("docs/usage.md lost the " + heading + " heading")
if "--new-flag" not in text:
    fail("docs/usage.md does not document --new-flag")
if "--old-flag" not in text:
    fail("docs/usage.md dropped --old-flag")
option_block = lowered.split("## options", 1)[1]
if "--new-flag" not in option_block:
    fail("--new-flag must be documented under Options")
if "deprecat" not in option_block:
    fail("--old-flag must be marked deprecated under Options")
ok()
