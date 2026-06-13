#!/usr/bin/env python3
"""Canonical ContextGuard command dispatcher.

The npm/Homebrew-friendly ``context-guard`` command is intentionally passive:
installation only exposes commands on PATH. Any project or user configuration is
performed later through explicit subcommands such as ``context-guard setup``.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import stat
import sys
from types import ModuleType
from typing import Any, NoReturn

COMMAND_NAME = "context-guard"
PACKAGE_NAME = "@ictechgy/context-guard"
MAX_VERSION_METADATA_BYTES = 64 * 1024
MAX_COMMAND_MANIFEST_BYTES = 128 * 1024
ALLOWED_FIRST_ABSOLUTE_SYMLINKS = {
    "tmp": Path("/private/tmp"),
    "var": Path("/private/var"),
}

MANIFEST_LOAD_ERROR: str | None = None


def _manifest_candidates(script_dir: Path) -> tuple[Path, ...]:
    # Layout-aware and intentionally narrow: checkout scripts load only the
    # colocated kit manifest; packaged plugin/npm bins load only plugin-local
    # ../lib. A stray bin/context_guard_commands.py must not shadow the package
    # manifest.
    if script_dir.name == "context-guard-kit":
        return (script_dir / "context_guard_commands.py",)
    if script_dir.name == "bin":
        return (script_dir.parent / "lib" / "context_guard_commands.py",)
    return ()


def _manifest_open_flags() -> int | None:
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


def _read_manifest_source(path: Path) -> str | None:
    flags = _manifest_open_flags()
    if flags is None:
        return None
    fd = -1
    try:
        fd = os.open(path, flags)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_COMMAND_MANIFEST_BYTES:
            return None
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(64 * 1024, MAX_COMMAND_MANIFEST_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_COMMAND_MANIFEST_BYTES:
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


def _load_manifest_from_path(path: Path) -> ModuleType | None:
    source = _read_manifest_source(path)
    if source is None:
        return None
    module = ModuleType("_context_guard_commands_manifest")
    try:
        exec(compile(source, str(path), "exec"), module.__dict__)
    except Exception:
        return None
    return module


def _coerce_helper_subcommands(value: Any) -> dict[str, tuple[str, ...]] | None:
    if not isinstance(value, dict):
        return None
    coerced: dict[str, tuple[str, ...]] = {}
    for key, command in value.items():
        if not isinstance(key, str) or not key:
            return None
        if not isinstance(command, (tuple, list)) or not command:
            return None
        parts: list[str] = []
        for part in command:
            if not isinstance(part, str) or not part:
                return None
            parts.append(part)
        coerced[key] = tuple(parts)
    return coerced


def load_helper_subcommands() -> dict[str, tuple[str, ...]]:
    global MANIFEST_LOAD_ERROR
    script_dir = Path(__file__).resolve().parent
    candidates = _manifest_candidates(script_dir)
    for candidate in candidates:
        module = _load_manifest_from_path(candidate)
        if module is None:
            continue
        loaded = _coerce_helper_subcommands(getattr(module, "DISPATCHER_SUBCOMMANDS", None))
        if loaded is not None:
            MANIFEST_LOAD_ERROR = None
            return loaded
    MANIFEST_LOAD_ERROR = "could not load trusted command manifest from " + ", ".join(str(path) for path in candidates)
    return {}


HELPER_SUBCOMMANDS: dict[str, tuple[str, ...]] = load_helper_subcommands()


def _script_dir() -> Path:
    return Path(__file__).resolve().parent


def _candidate_roots() -> list[Path]:
    script_dir = _script_dir()
    roots = [script_dir.parent, script_dir.parent.parent]
    # When run from context-guard-kit in a checkout, the repo root is one level up.
    if script_dir.name == "context-guard-kit":
        roots.insert(0, script_dir.parent)
    return list(dict.fromkeys(roots))


def _normalized_link_target(anchor: Path, raw_target: str) -> Path:
    target = Path(raw_target)
    if target.is_absolute():
        return Path(os.path.normpath(str(target)))
    return Path(os.path.normpath(str(anchor / target)))


def _normalize_allowed_first_absolute_symlink(path: Path) -> Path:
    if not path.is_absolute():
        return path
    parts = path.parts
    if len(parts) < 2:
        return path
    expected = ALLOWED_FIRST_ABSOLUTE_SYMLINKS.get(parts[1])
    if expected is None:
        return path
    first = Path(path.anchor) / parts[1]
    try:
        if first.is_symlink() and _normalized_link_target(Path(path.anchor), os.readlink(first)) == expected:
            return expected.joinpath(*parts[2:])
    except OSError:
        return path
    return path


def _metadata_no_follow_supported() -> bool:
    return (
        hasattr(os, "O_NOFOLLOW")
        and os.open in getattr(os, "supports_dir_fd", set())
        and os.stat in getattr(os, "supports_dir_fd", set())
        and os.stat in getattr(os, "supports_follow_symlinks", set())
    )


def _directory_open_flags(*, follow_final: bool = False) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if not follow_final:
        flags |= os.O_NOFOLLOW
    return flags


def _metadata_file_open_flags() -> int:
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_NOCTTY"):
        flags |= os.O_NOCTTY
    return flags


def _leaf_name(path: Path) -> str | None:
    name = path.name
    if name in {"", ".", ".."}:
        return None
    return name


def _open_metadata_parent_no_follow(path: Path) -> int | None:
    if not _metadata_no_follow_supported():
        return None
    path = _normalize_allowed_first_absolute_symlink(path)
    try:
        if path.is_absolute():
            current_fd = os.open(path.anchor or os.sep, _directory_open_flags(follow_final=True))
            parts = path.parts[1:-1]
        else:
            current_fd = os.open(".", _directory_open_flags(follow_final=True))
            parts = path.parts[:-1]
    except OSError:
        return None
    try:
        for part in parts:
            if part in {"", "."}:
                continue
            if part == "..":
                return None
            next_fd = -1
            try:
                next_fd = os.open(part, _directory_open_flags(), dir_fd=current_fd)
                if not stat.S_ISDIR(os.fstat(next_fd).st_mode):
                    try:
                        os.close(next_fd)
                    except OSError:
                        pass
                    next_fd = -1
                    return None
            except OSError:
                if next_fd >= 0:
                    try:
                        os.close(next_fd)
                    except OSError:
                        pass
                try:
                    os.close(current_fd)
                except OSError:
                    pass
                current_fd = -1
                return None
            try:
                os.close(current_fd)
            except OSError:
                pass
            current_fd = next_fd
        owned_fd = current_fd
        current_fd = -1
        return owned_fd
    finally:
        if current_fd >= 0:
            try:
                os.close(current_fd)
            except OSError:
                pass


def _read_metadata_text(path: Path) -> str | None:
    path = _normalize_allowed_first_absolute_symlink(path)
    parent_fd = _open_metadata_parent_no_follow(path)
    if parent_fd is None:
        return None
    fd = -1
    data = b""
    try:
        leaf = _leaf_name(path)
        if leaf is None:
            return None
        pre_open = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(pre_open.st_mode):
            return None
        if pre_open.st_size > MAX_VERSION_METADATA_BYTES:
            return None
        fd = os.open(leaf, _metadata_file_open_flags(), dir_fd=parent_fd)
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            return None
        if opened.st_size > MAX_VERSION_METADATA_BYTES:
            return None
        data = os.read(fd, MAX_VERSION_METADATA_BYTES + 1)
    except OSError:
        return None
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.close(parent_fd)
        except OSError:
            pass
    if len(data) > MAX_VERSION_METADATA_BYTES:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _load_json(path: Path) -> dict[str, object] | None:
    text = _read_metadata_text(path)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def project_version() -> str:
    candidates: list[Path] = []
    for root in _candidate_roots():
        candidates.extend(
            [
                root / ".claude-plugin" / "plugin.json",
                root / "plugins" / "context-guard" / ".claude-plugin" / "plugin.json",
                root / "package.json",
            ]
        )
    for candidate in candidates:
        data = _load_json(candidate)
        version = data.get("version") if data else None
        if isinstance(version, str) and version.strip():
            return version.strip()
    return "0.0.0+unknown"


def print_help() -> None:
    version = project_version()
    commands = "\n".join(f"  {name}" for name in sorted(HELPER_SUBCOMMANDS))
    sys.stdout.write(
        f"ContextGuard {version}\n"
        f"\n"
        f"Usage:\n"
        f"  {COMMAND_NAME} --version\n"
        f"  {COMMAND_NAME} <subcommand> [args...]\n"
        f"\n"
        f"Install examples:\n"
        f"  npm install -g {PACKAGE_NAME}\n"
        f"  npx {PACKAGE_NAME} setup --agent codex --scope project --plan\n"
        f"\n"
        f"Common subcommands:\n"
        f"{commands}\n"
        f"\n"
        f"Run '{COMMAND_NAME} <subcommand> --help' for helper-specific options.\n"
        f"Installing ContextGuard never writes configuration; use 'setup' explicitly.\n"
    )


def helper_path(name: str) -> Path | None:
    script_dir = _script_dir()
    candidates = [
        script_dir / name,
        script_dir.parent / "plugins" / "context-guard" / "bin" / name,
        script_dir.parent.parent / "plugins" / "context-guard" / "bin" / name,
    ]
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def fail(message: str, code: int = 2) -> NoReturn:
    sys.stderr.write(f"{COMMAND_NAME}: {message}\n")
    raise SystemExit(code)


def run_helper(command: str, argv: list[str]) -> int:
    mapping = HELPER_SUBCOMMANDS[command]
    helper = helper_path(mapping[0])
    if helper is None:
        fail(
            f"could not find helper {mapping[0]!r}; reinstall {PACKAGE_NAME} "
            "or run from a complete ContextGuard checkout."
        )
    proc = subprocess.run([str(helper), *mapping[1:], *argv])
    return int(proc.returncode)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"-h", "--help", "help"}:
        if MANIFEST_LOAD_ERROR:
            fail(MANIFEST_LOAD_ERROR)
        print_help()
        return 0
    if args[0] in {"-V", "--version", "version"}:
        print(project_version())
        return 0
    command = args.pop(0).strip().lower()
    if command not in HELPER_SUBCOMMANDS:
        if MANIFEST_LOAD_ERROR:
            fail(MANIFEST_LOAD_ERROR)
        fail(f"unknown subcommand {command!r}. Run '{COMMAND_NAME} --help'.")
    return run_helper(command, args)


if __name__ == "__main__":
    raise SystemExit(main())
