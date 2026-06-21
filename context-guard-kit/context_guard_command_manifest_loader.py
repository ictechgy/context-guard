"""Trusted literal loader for the ContextGuard command manifest.

The command manifest is intentionally a literal-only Python data file so release
gates and runtime dispatchers can inspect it without executing manifest code.
This helper centralizes the bounded no-follow read and AST-literal parsing logic
used by the runtime dispatcher, release gates, and tests.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path
import stat
from typing import Any, Iterable, Mapping

MAX_COMMAND_MANIFEST_BYTES = 128 * 1024

COMMAND_MANIFEST_LITERAL_NAMES = frozenset(
    {
        "IMPLEMENTATION_PAIRS",
        "HELPER_PAIRS",
        "NPM_BINS",
        "NPM_BIN_PATHS",
        "DISPATCHER_SUBCOMMANDS",
        "LEGACY_WRAPPERS",
        "ENTRYPOINT_SMOKE_CASES",
        "PLUGIN_ENTRYPOINTS",
        "DISPATCHER_SMOKE_CASES",
        "EXPECTED_COMMAND_PACK_FILES",
    }
)


def manifest_open_flags() -> int | None:
    if not hasattr(os, "O_NOFOLLOW"):
        return None
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_NOCTTY"):
        flags |= os.O_NOCTTY
    return flags


def read_manifest_source(path: Path, *, max_bytes: int = MAX_COMMAND_MANIFEST_BYTES) -> str | None:
    flags = manifest_open_flags()
    if flags is None:
        return None
    fd = -1
    try:
        fd = os.open(path, flags)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes:
            return None
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(64 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                return None
        return b"".join(chunks).decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def literal_command_manifest_from_source(
    source: str,
    *,
    allowed_names: Iterable[str] = COMMAND_MANIFEST_LITERAL_NAMES,
) -> dict[str, Any]:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise ValueError(f"invalid Python manifest syntax: line {exc.lineno}: {exc.msg}") from exc
    allowed = set(allowed_names)
    values: dict[str, Any] = {}
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            continue
        target: str | None = None
        value: ast.expr | None = None
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target = node.target.id
            value = node.value
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target = node.targets[0].id
            value = node.value
        if target is None:
            raise ValueError(f"unsupported executable manifest statement: {type(node).__name__}")
        if target not in allowed or value is None:
            raise ValueError(f"unsupported manifest assignment: {target}")
        try:
            values[target] = ast.literal_eval(value)
        except (SyntaxError, ValueError) as exc:
            raise ValueError(f"manifest assignment must be a literal: {target}") from exc
    return values


def command_manifest_namespace(values: Mapping[str, Any], *, required: Iterable[str] = ()) -> type:
    missing = sorted(set(required) - set(values))
    if missing:
        raise ValueError(f"trusted command manifest missing required literals: {', '.join(missing)}")
    return type("CommandManifest", (), dict(values))


def load_command_manifest(path: Path, *, required: Iterable[str] = ()) -> type:
    source = read_manifest_source(path)
    if source is None:
        raise ValueError(f"could not load trusted command manifest source: {path}")
    values = literal_command_manifest_from_source(source)
    return command_manifest_namespace(values, required=required)
