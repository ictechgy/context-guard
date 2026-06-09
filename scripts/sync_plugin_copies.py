#!/usr/bin/env python3
"""Synchronize source helpers into the packaged plugin copy tree.

The package intentionally ships executable files under
``plugins/context-guard/bin`` so npm/Homebrew can expose stable command names.
The source of truth remains under ``context-guard-kit``.  This maintainer tool
turns that exact-copy contract into one command instead of a manual sequence of
``cp`` calls.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
import secrets
import shutil
import stat
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import prepublish_check


ROOT = prepublish_check.ROOT


class SyncError(RuntimeError):
    pass


@dataclass(frozen=True)
class CopySpec:
    source: Path
    target: Path
    mode: int
    root: Path | None = None

    def label(self) -> str:
        root = self.root or ROOT
        try:
            source = self.source.relative_to(root).as_posix()
            target = self.target.relative_to(root).as_posix()
        except ValueError:
            source = str(self.source)
            target = str(self.target)
        return f"{source} -> {target}"


@dataclass(frozen=True)
class CopyStatus:
    spec: CopySpec
    reason: str


def reject_symlink_components(path: Path, *, label: str, root: Path | None = None) -> None:
    """Reject symlinks anywhere in a copy path before reading or writing.

    The release preflight validates packaged path components, but this tool can
    run before preflight.  Check every existing component up front so --write
    cannot be redirected through a symlinked parent directory.
    """
    check_root = root or ROOT
    try:
        relative = path.relative_to(check_root)
    except ValueError:
        probe = Path(path.anchor) if path.is_absolute() else Path(".")
        parts = path.parts[1:] if path.is_absolute() else path.parts
    else:
        probe = check_root
        parts = relative.parts
        if probe.is_symlink():
            raise SyncError(f"refusing symlink {label} root: {probe}")
    for part in parts:
        probe = probe / part
        if probe.is_symlink():
            raise SyncError(f"refusing symlink {label} component: {probe}")


def require_relative_to_root(path: Path, root: Path, *, label: str) -> Path:
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise SyncError(f"{label} is outside sync root: {path}") from exc
    if any(part in ("", ".", "..") for part in relative.parts):
        raise SyncError(f"{label} contains an unsafe path component: {path}")
    return relative


def directory_open_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


def open_parent_dir_from_root(path: Path, root: Path, *, label: str) -> int:
    """Open path.parent by walking from root with O_NOFOLLOW at each component."""
    relative_parent = require_relative_to_root(path.parent, root, label=f"{label} parent")
    current_fd = os.open(root, directory_open_flags())
    try:
        for part in relative_parent.parts:
            try:
                next_fd = os.open(part, directory_open_flags(), dir_fd=current_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(part, mode=0o755, dir_fd=current_fd)
                except FileExistsError:
                    pass
                next_fd = os.open(part, directory_open_flags(), dir_fd=current_fd)
            except OSError as exc:
                raise SyncError(f"could not open {label} directory component without following symlinks: {part}: {exc.strerror}") from exc
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except Exception:
        os.close(current_fd)
        raise


def open_regular_file_from_root(path: Path, root: Path, *, label: str) -> int:
    parent_fd = open_parent_dir_from_root(path, root, label=label)
    try:
        fd = os.open(path.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
    except OSError as exc:
        raise SyncError(f"could not open {label} without following symlinks: {path}: {exc.strerror}") from exc
    finally:
        os.close(parent_fd)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise SyncError(f"{label} is not a regular file: {path}")
        return fd
    except Exception:
        os.close(fd)
        raise


def open_exclusive_temp(parent_fd: int, target_name: str, mode: int) -> tuple[int, str]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    for _ in range(100):
        temp_name = f".{target_name}.{secrets.token_hex(8)}.sync-tmp"
        try:
            return os.open(temp_name, flags, mode, dir_fd=parent_fd), temp_name
        except FileExistsError:
            continue
        except OSError as exc:
            raise SyncError(f"could not create exclusive temp file for {target_name}: {exc.strerror}") from exc
    raise SyncError(f"could not allocate unique temp file for {target_name}")


def build_copy_specs(root: Path = ROOT) -> list[CopySpec]:
    kit_dir = root / "context-guard-kit"
    plugin_dir = root / "plugins" / "context-guard"
    plugin_bin = plugin_dir / "bin"
    specs = [
        CopySpec(kit_dir / kit_name, plugin_bin / bin_name, 0o755, root)
        for kit_name, bin_name in prepublish_check.IMPLEMENTATION_PAIRS
    ]
    specs.extend(
        CopySpec(kit_dir / kit_name, plugin_dir / rel, 0o644, root)
        for kit_name, rel in prepublish_check.HELPER_PAIRS
    )
    return specs


def needs_sync(spec: CopySpec) -> str | None:
    reject_symlink_components(spec.source, label="source", root=spec.root)
    reject_symlink_components(spec.target, label="target", root=spec.root)
    if not spec.source.is_file():
        raise SyncError(f"missing source: {spec.source}")
    if not spec.target.exists():
        return "missing"
    if not spec.target.is_file():
        raise SyncError(f"target is not a regular file: {spec.target}")
    if spec.source.stat().st_size != spec.target.stat().st_size:
        return "content"
    if spec.source.read_bytes() != spec.target.read_bytes():
        return "content"
    mode = stat.S_IMODE(spec.target.stat().st_mode)
    if mode != spec.mode:
        return f"mode {oct(mode)} != {oct(spec.mode)}"
    return None


def copy_spec(spec: CopySpec) -> None:
    root = spec.root or ROOT
    reject_symlink_components(spec.source, label="source", root=spec.root)
    reject_symlink_components(spec.target, label="target", root=spec.root)
    parent_fd = open_parent_dir_from_root(spec.target, root, label="target")
    temp_name: str | None = None
    try:
        temp_fd, temp_name = open_exclusive_temp(parent_fd, spec.target.name, spec.mode)
        temp_fd_for_cleanup: int | None = temp_fd
        source_fd: int | None = None
        try:
            source_fd = open_regular_file_from_root(spec.source, root, label="source")
            with os.fdopen(temp_fd, "wb") as dst:
                temp_fd_for_cleanup = None
                with os.fdopen(source_fd, "rb") as src:
                    source_fd = None
                    shutil.copyfileobj(src, dst)
                    dst.flush()
                    os.fsync(dst.fileno())
                    os.fchmod(dst.fileno(), spec.mode)
        except Exception:
            if temp_fd_for_cleanup is not None:
                os.close(temp_fd_for_cleanup)
            if source_fd is not None:
                os.close(source_fd)
            if temp_name is not None:
                os.unlink(temp_name, dir_fd=parent_fd)
                temp_name = None
            raise

        reject_symlink_components(spec.target, label="target", root=spec.root)
        os.replace(temp_name, spec.target.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        temp_name = None
    finally:
        if temp_name is not None:
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def sync_specs(specs: list[CopySpec], *, write: bool) -> list[CopyStatus]:
    pending: list[CopyStatus] = []
    for spec in specs:
        reason = needs_sync(spec)
        if reason is None:
            continue
        pending.append(CopyStatus(spec, reason))
        if write:
            copy_spec(spec)
    return pending


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Synchronize context-guard-kit sources into packaged plugin bin/lib copies.")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--write", action="store_true", help="copy out-of-sync files into plugins/context-guard")
    action.add_argument("--check", action="store_true", help="check synchronization only (default)")
    parser.add_argument("--list", action="store_true", help="list managed copy pairs")
    args = parser.parse_args(argv)

    specs = build_copy_specs()
    if args.list:
        for spec in specs:
            print(f"{oct(spec.mode)} {spec.label()}")
        return 0

    try:
        pending = sync_specs(specs, write=args.write)
    except SyncError as exc:
        print(f"sync-plugin-copies: {exc}", file=sys.stderr)
        return 2

    if not pending:
        print("sync-plugin-copies: plugin copies synchronized")
        return 0

    for item in pending:
        action = "synced" if args.write else "out-of-sync"
        print(f"sync-plugin-copies: {action}: {item.reason}: {item.spec.label()}")
    if args.write:
        print(f"sync-plugin-copies: synchronized {len(pending)} file(s)")
        return 0
    print("sync-plugin-copies: run with --write to refresh packaged copies", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
