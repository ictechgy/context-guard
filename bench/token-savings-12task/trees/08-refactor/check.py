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
shared = load_module("src/shared.py", "s003_shared")
if not callable(getattr(shared, "normalize_key", None)):
    fail("src/shared.py does not define normalize_key")
if shared.normalize_key("  Some Key ") != "some_key":
    fail("shared normalize_key behaviour changed")
for rel in ("src/alpha.py", "src/beta.py"):
    text = read(rel)
    if "def normalize_key" in text:
        fail(rel + " still defines its own normalize_key")
    if "shared" not in text or "normalize_key" not in text:
        fail(rel + " does not import normalize_key from the shared module")
alpha = load_module("src/alpha.py", "s003_alpha")
beta = load_module("src/beta.py", "s003_beta")
if alpha.alpha_keys([" A b "]) != ["a_b"]:
    fail("alpha_keys behaviour changed")
if beta.beta_keys([" B a ", " A b "]) != ["a_b", "b_a"]:
    fail("beta_keys behaviour changed")
ok()
