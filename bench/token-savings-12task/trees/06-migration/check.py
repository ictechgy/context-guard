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
module = load_module("src/cli.py", "s003_cli")
parse_args = getattr(module, "parse_args", None)
if parse_args is None:
    fail("parse_args is missing")
try:
    new = parse_args(["--new-flag", "x"])
except SystemExit as exc:
    fail("--new-flag is still rejected: " + str(exc))
if new.get("value") != "x":
    fail("--new-flag does not set the value")
if new.get("deprecated"):
    fail("--new-flag must not record a deprecation note")
old = parse_args(["--old-flag", "x"])
if old.get("value") != "x":
    fail("--old-flag stopped working")
if "--old-flag" not in old.get("deprecated", []):
    fail("--old-flag must record a deprecation note")
ok()
