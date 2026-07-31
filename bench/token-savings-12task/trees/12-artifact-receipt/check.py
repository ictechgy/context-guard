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
receipt = json.loads(read("logs/receipt.json"))
report = read("report.md")
if "## summary" not in report.lower():
    fail("report.md lost the Summary section")
if receipt["handle"] not in report:
    fail("report.md does not reference the artifact handle")
if receipt["retrieval_command"] not in report:
    fail("report.md does not include the exact retrieval command")
if len(report.encode("utf-8")) > 2_000:
    fail("report.md still inlines the bulk log body")
full_log = read("logs/full.log")
if len(full_log.encode("utf-8")) < 10_000:
    fail("logs/full.log must remain the untouched full evidence")
if "step 0400 ok" not in full_log:
    fail("logs/full.log content changed")
ok()
