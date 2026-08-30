"""Explicit, plan-bound cleanup for derived Bash-reference state only."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Final

from .contracts import canonical_json, evidence_boundary


__all__ = ["CleanupError", "CleanupErrorCode", "apply_cleanup", "plan_cleanup"]


_STATE_PREFIX: Final = ".context-guard-receipt-state-"
_QUARANTINE_PREFIX: Final = ".context-guard-receipt-cleanup-"
_SELECTOR_DOMAIN: Final = b"contextguard/bash-reference-state-selector/v1\0"
_PLAN_SCHEMA_VERSION: Final = "contextguard-receipt-cleanup-plan/v1"
_RESULT_SCHEMA_VERSION: Final = "contextguard-receipt-cleanup-result/v1"
_PLAN_DOMAIN: Final = b"contextguard-receipt/cleanup-plan/v1\0"
_MAX_DEPTH: Final = 64
_MAX_ENTRIES: Final = 32_768
_MAX_TOTAL_BYTES: Final = 512 * 1024 * 1024


class CleanupErrorCode(str, Enum):
    FILESYSTEM_UNSUPPORTED = "filesystem_unsupported"
    ROOT_REJECTED = "root_rejected"
    STATE_UNSAFE = "state_unsafe"
    STATE_TOO_LARGE = "state_too_large"
    PLAN_MISMATCH = "plan_mismatch"
    CLEANUP_INCOMPLETE = "cleanup_incomplete"


class CleanupError(RuntimeError):
    """Stable non-reflective cleanup failure."""

    def __init__(self, code: CleanupErrorCode):
        self.code = code
        super().__init__(f"cleanup rejected: {code.value}")


@dataclass(frozen=True)
class _Entry:
    relative_path: str
    kind: str
    mode: int
    size: int
    device: int
    inode: int
    links: int
    modified_ns: int

    def canonical(self) -> dict[str, object]:
        return {
            "device": self.device,
            "inode": self.inode,
            "kind": self.kind,
            "links": self.links,
            "mode": self.mode,
            "modified_ns": self.modified_ns,
            "relative_path": self.relative_path,
            "size": self.size,
        }


@dataclass(frozen=True)
class _Snapshot:
    parent_fd: int
    target_fd: int | None
    target_name: str
    root_device: int
    root_inode: int
    entries: tuple[_Entry, ...]
    total_bytes: int


def _raise(code: CleanupErrorCode) -> None:
    raise CleanupError(code)


def _require_features() -> None:
    required_flags = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW")
    if any(not getattr(os, name, 0) for name in required_flags):
        _raise(CleanupErrorCode.FILESYSTEM_UNSUPPORTED)
    required_dir_fd = (os.open, os.rename, os.rmdir, os.stat, os.unlink)
    if any(function not in os.supports_dir_fd for function in required_dir_fd):
        _raise(CleanupErrorCode.FILESYSTEM_UNSUPPORTED)
    if os.scandir not in os.supports_fd:
        _raise(CleanupErrorCode.FILESYSTEM_UNSUPPORTED)


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | os.O_CLOEXEC
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_NONBLOCK", 0)
    )


def _file_flags() -> int:
    return os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _private_directory(status: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(status.st_mode)
        and status.st_uid == os.geteuid()
        and stat.S_IMODE(status.st_mode) == 0o700
    )


def _private_file(status: os.stat_result) -> bool:
    return (
        stat.S_ISREG(status.st_mode)
        and status.st_uid == os.geteuid()
        and stat.S_IMODE(status.st_mode) == 0o600
        and status.st_nlink == 1
    )


def _root_context(repository_root: str) -> tuple[int, str, os.stat_result]:
    if (
        type(repository_root) is not str
        or not repository_root
        or "\0" in repository_root
        or not os.path.isabs(repository_root)
        or repository_root == os.sep
        or os.path.normpath(repository_root) != repository_root
        or os.path.realpath(repository_root) != repository_root
    ):
        _raise(CleanupErrorCode.ROOT_REJECTED)
    root = Path(repository_root)
    try:
        root_status = root.lstat()
    except OSError:
        _raise(CleanupErrorCode.ROOT_REJECTED)
    if (
        root.is_symlink()
        or not stat.S_ISDIR(root_status.st_mode)
        or root_status.st_uid != os.geteuid()
    ):
        _raise(CleanupErrorCode.ROOT_REJECTED)
    parent_text = str(root.parent)
    if os.path.realpath(parent_text) != parent_text:
        _raise(CleanupErrorCode.ROOT_REJECTED)
    try:
        parent_fd = os.open(parent_text, _directory_flags())
        parent_status = os.fstat(parent_fd)
        anchored_root = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        try:
            os.close(parent_fd)
        except (OSError, UnboundLocalError):
            pass
        _raise(CleanupErrorCode.ROOT_REJECTED)
    parent_mode = stat.S_IMODE(parent_status.st_mode)
    parent_is_trusted = (
        stat.S_ISDIR(parent_status.st_mode)
        and parent_status.st_uid in {0, os.geteuid()}
        and (parent_mode & 0o022 == 0 or bool(parent_status.st_mode & stat.S_ISVTX))
    )
    if (
        not parent_is_trusted
        or not _same_identity(root_status, anchored_root)
        or not stat.S_ISDIR(anchored_root.st_mode)
    ):
        os.close(parent_fd)
        _raise(CleanupErrorCode.ROOT_REJECTED)
    return parent_fd, root.name, anchored_root


def _target_name(repository_root: str, root_status: os.stat_result) -> str:
    selector = hashlib.sha256()
    selector.update(_SELECTOR_DOMAIN)
    for field in (
        os.fsencode(repository_root),
        str(root_status.st_dev).encode("ascii"),
        str(root_status.st_ino).encode("ascii"),
    ):
        selector.update(len(field).to_bytes(8, "big"))
        selector.update(field)
    return _STATE_PREFIX + selector.hexdigest()


def _entry(relative_path: str, kind: str, status: os.stat_result) -> _Entry:
    return _Entry(
        relative_path=relative_path,
        kind=kind,
        mode=stat.S_IMODE(status.st_mode),
        size=status.st_size if kind == "file" else 0,
        device=status.st_dev,
        inode=status.st_ino,
        links=status.st_nlink,
        modified_ns=status.st_mtime_ns,
    )


def _safe_name(name: object) -> str:
    if (
        type(name) is not str
        or not name
        or name in {".", ".."}
        or "/" in name
        or "\0" in name
    ):
        _raise(CleanupErrorCode.STATE_UNSAFE)
    return name


def _scan_directory(
    descriptor: int,
    relative: str,
    depth: int,
    entries: list[_Entry],
    totals: list[int],
    expected_device: int,
) -> None:
    if depth > _MAX_DEPTH:
        _raise(CleanupErrorCode.STATE_TOO_LARGE)
    try:
        directory_status = os.fstat(descriptor)
    except OSError:
        _raise(CleanupErrorCode.STATE_UNSAFE)
    if (
        not _private_directory(directory_status)
        or directory_status.st_dev != expected_device
    ):
        _raise(CleanupErrorCode.STATE_UNSAFE)
    entries.append(_entry(relative, "directory", directory_status))
    if len(entries) > _MAX_ENTRIES:
        _raise(CleanupErrorCode.STATE_TOO_LARGE)
    try:
        with os.scandir(descriptor) as scanner:
            names = sorted(_safe_name(item.name) for item in scanner)
    except CleanupError:
        raise
    except OSError:
        _raise(CleanupErrorCode.STATE_UNSAFE)
    for name in names:
        child_relative = name if relative == "." else f"{relative}/{name}"
        try:
            status = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except OSError:
            _raise(CleanupErrorCode.STATE_UNSAFE)
        if status.st_dev != expected_device:
            _raise(CleanupErrorCode.STATE_UNSAFE)
        if stat.S_ISDIR(status.st_mode):
            if not _private_directory(status):
                _raise(CleanupErrorCode.STATE_UNSAFE)
            try:
                child_fd = os.open(name, _directory_flags(), dir_fd=descriptor)
                opened_status = os.fstat(child_fd)
            except OSError:
                try:
                    os.close(child_fd)
                except (OSError, UnboundLocalError):
                    pass
                _raise(CleanupErrorCode.STATE_UNSAFE)
            if not _same_identity(status, opened_status):
                os.close(child_fd)
                _raise(CleanupErrorCode.STATE_UNSAFE)
            try:
                _scan_directory(
                    child_fd,
                    child_relative,
                    depth + 1,
                    entries,
                    totals,
                    expected_device,
                )
            finally:
                os.close(child_fd)
            continue
        if not _private_file(status):
            _raise(CleanupErrorCode.STATE_UNSAFE)
        try:
            file_fd = os.open(name, _file_flags(), dir_fd=descriptor)
            opened_status = os.fstat(file_fd)
        except OSError:
            try:
                os.close(file_fd)
            except (OSError, UnboundLocalError):
                pass
            _raise(CleanupErrorCode.STATE_UNSAFE)
        os.close(file_fd)
        if not _same_identity(status, opened_status) or not _private_file(opened_status):
            _raise(CleanupErrorCode.STATE_UNSAFE)
        entries.append(_entry(child_relative, "file", opened_status))
        totals[0] += opened_status.st_size
        if len(entries) > _MAX_ENTRIES or totals[0] > _MAX_TOTAL_BYTES:
            _raise(CleanupErrorCode.STATE_TOO_LARGE)


def _snapshot(repository_root: str) -> _Snapshot:
    _require_features()
    parent_fd, _root_name, root_status = _root_context(repository_root)
    target_name = _target_name(repository_root, root_status)
    try:
        try:
            target_status = os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return _Snapshot(
                parent_fd=parent_fd,
                target_fd=None,
                target_name=target_name,
                root_device=root_status.st_dev,
                root_inode=root_status.st_ino,
                entries=(),
                total_bytes=0,
            )
        except OSError:
            _raise(CleanupErrorCode.STATE_UNSAFE)
        parent_device = os.fstat(parent_fd).st_dev
        if (
            not _private_directory(target_status)
            or target_status.st_dev != parent_device
        ):
            _raise(CleanupErrorCode.STATE_UNSAFE)
        try:
            target_fd = os.open(target_name, _directory_flags(), dir_fd=parent_fd)
            opened_status = os.fstat(target_fd)
        except OSError:
            try:
                os.close(target_fd)
            except (OSError, UnboundLocalError):
                pass
            _raise(CleanupErrorCode.STATE_UNSAFE)
        if not _same_identity(target_status, opened_status):
            os.close(target_fd)
            _raise(CleanupErrorCode.STATE_UNSAFE)
        entries: list[_Entry] = []
        totals = [0]
        try:
            _scan_directory(target_fd, ".", 0, entries, totals, parent_device)
        except Exception:
            os.close(target_fd)
            raise
        return _Snapshot(
            parent_fd=parent_fd,
            target_fd=target_fd,
            target_name=target_name,
            root_device=root_status.st_dev,
            root_inode=root_status.st_ino,
            entries=tuple(entries),
            total_bytes=totals[0],
        )
    except Exception:
        os.close(parent_fd)
        raise


def _plan_payload(snapshot: _Snapshot) -> dict[str, object]:
    files = sum(entry.kind == "file" for entry in snapshot.entries)
    directories = sum(entry.kind == "directory" for entry in snapshot.entries)
    status = "absent" if snapshot.target_fd is None else "ready"
    identity = {
        "entries": [entry.canonical() for entry in snapshot.entries],
        "root_device": snapshot.root_device,
        "root_inode": snapshot.root_inode,
        "status": status,
        "target_name": snapshot.target_name,
        "total_bytes": snapshot.total_bytes,
    }
    encoded = canonical_json(identity).encode("ascii")
    digest = hashlib.sha256(_PLAN_DOMAIN + encoded).hexdigest()
    return {
        "artifact_cleanup_performed": False,
        "directory_count": directories,
        "entry_count": max(0, len(snapshot.entries) - (1 if directories else 0)),
        "evidence_boundary": evidence_boundary(),
        "file_count": files,
        "operation": "cleanup_bash_reference_state",
        "plan_sha256": digest,
        "requires_confirmation": status == "ready",
        "schema_version": _PLAN_SCHEMA_VERSION,
        "status": status,
        "target_name": snapshot.target_name,
        "total_bytes": snapshot.total_bytes,
    }


def _close_snapshot(snapshot: _Snapshot) -> None:
    if snapshot.target_fd is not None:
        try:
            os.close(snapshot.target_fd)
        except OSError:
            pass
    try:
        os.close(snapshot.parent_fd)
    except OSError:
        pass


def plan_cleanup(repository_root: str) -> dict[str, object]:
    snapshot = _snapshot(repository_root)
    try:
        return _plan_payload(snapshot)
    finally:
        _close_snapshot(snapshot)


def _entry_matches(entry: _Entry, status: os.stat_result) -> bool:
    expected_kind = stat.S_ISDIR(status.st_mode) if entry.kind == "directory" else stat.S_ISREG(status.st_mode)
    return bool(
        expected_kind
        and stat.S_IMODE(status.st_mode) == entry.mode
        and (entry.kind == "directory" or status.st_size == entry.size)
        and status.st_dev == entry.device
        and status.st_ino == entry.inode
        and status.st_nlink == entry.links
        and status.st_mtime_ns == entry.modified_ns
        and status.st_uid == os.geteuid()
    )


def _delete_directory(
    descriptor: int,
    relative: str,
    expected: dict[str, _Entry],
) -> None:
    prefix = "" if relative == "." else f"{relative}/"
    immediate: dict[str, _Entry] = {}
    for path, entry in expected.items():
        if path == relative or not path.startswith(prefix):
            continue
        suffix = path[len(prefix):]
        if "/" not in suffix:
            immediate[suffix] = entry
    try:
        with os.scandir(descriptor) as scanner:
            names = sorted(_safe_name(item.name) for item in scanner)
    except CleanupError:
        raise
    except OSError:
        _raise(CleanupErrorCode.CLEANUP_INCOMPLETE)
    if names != sorted(immediate):
        _raise(CleanupErrorCode.CLEANUP_INCOMPLETE)
    for name in names:
        entry = immediate[name]
        try:
            status = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except OSError:
            _raise(CleanupErrorCode.CLEANUP_INCOMPLETE)
        if not _entry_matches(entry, status):
            _raise(CleanupErrorCode.CLEANUP_INCOMPLETE)
        if entry.kind == "file":
            try:
                os.unlink(name, dir_fd=descriptor)
            except OSError:
                _raise(CleanupErrorCode.CLEANUP_INCOMPLETE)
            continue
        try:
            child_fd = os.open(name, _directory_flags(), dir_fd=descriptor)
            opened = os.fstat(child_fd)
        except OSError:
            try:
                os.close(child_fd)
            except (OSError, UnboundLocalError):
                pass
            _raise(CleanupErrorCode.CLEANUP_INCOMPLETE)
        if not _entry_matches(entry, opened):
            os.close(child_fd)
            _raise(CleanupErrorCode.CLEANUP_INCOMPLETE)
        child_relative = name if relative == "." else f"{relative}/{name}"
        try:
            _delete_directory(child_fd, child_relative, expected)
        finally:
            os.close(child_fd)
        try:
            current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if not _same_identity(current, opened) or not _private_directory(current):
                _raise(CleanupErrorCode.CLEANUP_INCOMPLETE)
            os.rmdir(name, dir_fd=descriptor)
        except OSError:
            _raise(CleanupErrorCode.CLEANUP_INCOMPLETE)
    try:
        os.fsync(descriptor)
    except OSError:
        _raise(CleanupErrorCode.CLEANUP_INCOMPLETE)


def apply_cleanup(repository_root: str, confirmation_sha256: str) -> dict[str, object]:
    if (
        type(confirmation_sha256) is not str
        or len(confirmation_sha256) != 64
        or any(character not in "0123456789abcdef" for character in confirmation_sha256)
    ):
        _raise(CleanupErrorCode.PLAN_MISMATCH)
    snapshot = _snapshot(repository_root)
    quarantine_name: str | None = None
    renamed = False
    deletion_started = False
    try:
        plan = _plan_payload(snapshot)
        if not hmac.compare_digest(str(plan["plan_sha256"]), confirmation_sha256):
            _raise(CleanupErrorCode.PLAN_MISMATCH)
        if snapshot.target_fd is None:
            return {
                **plan,
                "artifact_cleanup_performed": False,
                "schema_version": _RESULT_SCHEMA_VERSION,
                "status": "absent",
            }
        try:
            live_status = os.stat(
                snapshot.target_name,
                dir_fd=snapshot.parent_fd,
                follow_symlinks=False,
            )
            opened_status = os.fstat(snapshot.target_fd)
        except OSError:
            _raise(CleanupErrorCode.PLAN_MISMATCH)
        if not _same_identity(live_status, opened_status):
            _raise(CleanupErrorCode.PLAN_MISMATCH)
        quarantine_name = (
            _QUARANTINE_PREFIX
            + snapshot.target_name[len(_STATE_PREFIX):]
            + "-"
            + secrets.token_hex(16)
        )
        try:
            os.rename(
                snapshot.target_name,
                quarantine_name,
                src_dir_fd=snapshot.parent_fd,
                dst_dir_fd=snapshot.parent_fd,
            )
            renamed = True
            os.fsync(snapshot.parent_fd)
            quarantined_status = os.stat(
                quarantine_name,
                dir_fd=snapshot.parent_fd,
                follow_symlinks=False,
            )
        except OSError:
            _raise(CleanupErrorCode.STATE_UNSAFE)
        if not _same_identity(quarantined_status, opened_status):
            _raise(CleanupErrorCode.STATE_UNSAFE)
        rescan_entries: list[_Entry] = []
        rescan_totals = [0]
        _scan_directory(
            snapshot.target_fd,
            ".",
            0,
            rescan_entries,
            rescan_totals,
            os.fstat(snapshot.parent_fd).st_dev,
        )
        rescan = _Snapshot(
            parent_fd=snapshot.parent_fd,
            target_fd=snapshot.target_fd,
            target_name=snapshot.target_name,
            root_device=snapshot.root_device,
            root_inode=snapshot.root_inode,
            entries=tuple(rescan_entries),
            total_bytes=rescan_totals[0],
        )
        if not hmac.compare_digest(
            str(_plan_payload(rescan)["plan_sha256"]), confirmation_sha256
        ):
            _raise(CleanupErrorCode.PLAN_MISMATCH)
        deletion_started = True
        expected = {entry.relative_path: entry for entry in snapshot.entries}
        _delete_directory(snapshot.target_fd, ".", expected)
        try:
            current = os.stat(
                quarantine_name,
                dir_fd=snapshot.parent_fd,
                follow_symlinks=False,
            )
            if (
                not _same_identity(current, os.fstat(snapshot.target_fd))
                or not _private_directory(current)
            ):
                _raise(CleanupErrorCode.CLEANUP_INCOMPLETE)
            os.rmdir(quarantine_name, dir_fd=snapshot.parent_fd)
            os.fsync(snapshot.parent_fd)
        except OSError:
            _raise(CleanupErrorCode.CLEANUP_INCOMPLETE)
        os.close(snapshot.target_fd)
        snapshot = _Snapshot(
            parent_fd=snapshot.parent_fd,
            target_fd=None,
            target_name=snapshot.target_name,
            root_device=snapshot.root_device,
            root_inode=snapshot.root_inode,
            entries=snapshot.entries,
            total_bytes=snapshot.total_bytes,
        )
        renamed = False
        return {
            **plan,
            "artifact_cleanup_performed": True,
            "schema_version": _RESULT_SCHEMA_VERSION,
            "status": "deleted",
        }
    except CleanupError as error:
        if renamed and not deletion_started and quarantine_name is not None:
            try:
                os.rename(
                    quarantine_name,
                    snapshot.target_name,
                    src_dir_fd=snapshot.parent_fd,
                    dst_dir_fd=snapshot.parent_fd,
                )
                os.fsync(snapshot.parent_fd)
                renamed = False
            except OSError:
                raise CleanupError(CleanupErrorCode.CLEANUP_INCOMPLETE) from error
        if renamed:
            raise CleanupError(CleanupErrorCode.CLEANUP_INCOMPLETE) from error
        raise
    finally:
        _close_snapshot(snapshot)
