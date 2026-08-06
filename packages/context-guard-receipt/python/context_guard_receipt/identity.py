"""Bounded source identities without claiming parser or provider authority."""

from __future__ import annotations

import base64
import errno
import hashlib
import logging
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import unicodedata
from dataclasses import dataclass, fields
from pathlib import Path
from types import MappingProxyType
from typing import Final

from .canonical import (
    CanonicalJSONError,
    JSONLimits,
    canonical_json_bytes,
    framed_sha256_hex,
)
from .contracts import evidence_boundary


__all__ = [
    "IdentityError",
    "IdentityLimits",
    "identify_source",
    "snapshot_repository",
]


_LOGGER = logging.getLogger(__name__)

_SOURCE_SCHEMA_VERSION: Final = "contextguard-receipt-source-identity/v1"
_REPOSITORY_SCHEMA_VERSION: Final = "contextguard-receipt-repository-snapshot/v1"
_SYMBOL_EVIDENCE_SCHEMA_VERSION: Final = (
    "contextguard-receipt-caller-symbol-evidence/v1"
)
_SYMBOL_EVIDENCE_KIND: Final = "caller_supplied_symbol_range"
_SYMBOL_EVIDENCE_KEYS: Final = frozenset(
    {
        "candidates",
        "capped",
        "complete",
        "deterministic",
        "end_byte",
        "evidence_kind",
        "fallback_used",
        "language_id",
        "occurrence",
        "parser_error",
        "producer_id",
        "qualified_name",
        "raw_range_sha256",
        "scan_complete",
        "schema_version",
        "source_sha256",
        "start_byte",
    }
)
_SYMBOL_CANDIDATE_KEYS: Final = frozenset(
    {
        "end_byte",
        "occurrence",
        "qualified_name",
        "raw_range_sha256",
        "start_byte",
    }
)
_SHA256_PATTERN: Final = re.compile(r"[0-9a-f]{64}\Z")
_OID_PATTERN: Final = re.compile(rb"[0-9a-f]{40,64}\Z")
_INDEX_RECORD_PATTERN: Final = re.compile(
    rb"(?P<mode>[0-7]{6}) (?P<oid>[0-9a-f]{40,64}) (?P<stage>[0-3])\t"
)
_GIT_FILTER_CONFIG_KEY_PATTERN: Final = re.compile(
    rb"filter\.(?P<driver>[A-Za-z0-9][A-Za-z0-9._/+:-]{0,127})\."
    rb"(?:clean|smudge|process|required)\Z",
    re.IGNORECASE,
)
_SAFE_IDENTIFIER_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/+:-]*\Z")
_FROZEN_UNICODE_DATABASE = unicodedata.ucd_3_2_0

_GIT_CONFIG_ARGUMENTS: Final[tuple[str, ...]] = (
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.hooksPath=/dev/null",
)
_GIT_FILTER_CONFIG_QUERY: Final = (
    r"^filter\..*\.(clean|smudge|process|required)$"
)
_GIT_TRAMPOLINE: Final = (
    "import os,sys\n"
    "root_fd=int(sys.argv[1]); target=tuple(sys.argv[2:])\n"
    "try:\n"
    " os.fchdir(root_fd)\n"
    " os.close(root_fd)\n"
    " os.execv(target[0],target)\n"
    "except BaseException:\n"
    " os._exit(127)\n"
)
_MAX_GIT_FILTER_DRIVERS: Final = 64
_DEFAULT_GIT_CANDIDATES: Final[tuple[str, ...]] = (
    "/usr/bin/git",
    "/usr/local/bin/git",
    "/opt/homebrew/bin/git",
)
_LIMIT_CEILINGS: Final = MappingProxyType(
    {
        "git_timeout_seconds": 30,
        "max_directory_entries": 4096,
        "max_file_bytes": 1024 * 1024,
        "max_git_nul_fields": 4096,
        "max_git_output_bytes": 1024 * 1024,
        "max_path_bytes": 4096,
        "max_symbol_evidence_bytes": 64 * 1024,
    }
)


class IdentityError(ValueError):
    """A stable, non-reflective source identity failure."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"source identity rejected: {code}")


@dataclass(frozen=True, slots=True)
class IdentityLimits:
    """Frozen resource bounds for file, evidence, and Git operations."""

    max_file_bytes: int = 1024 * 1024
    max_directory_entries: int = 4096
    max_git_output_bytes: int = 256 * 1024
    max_git_nul_fields: int = 4096
    max_path_bytes: int = 4096
    max_symbol_evidence_bytes: int = 64 * 1024
    git_timeout_seconds: int = 5

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if (
                type(value) is not int
                or value <= 0
                or value > _LIMIT_CEILINGS[field.name]
            ):
                raise IdentityError("invalid_limits")


_DEFAULT_LIMITS = IdentityLimits()


@dataclass(frozen=True, slots=True)
class _GitExecutable:
    path: str
    device: int
    inode: int


@dataclass(frozen=True, slots=True)
class _GitResult:
    returncode: int
    stdout: bytes


@dataclass(frozen=True, slots=True)
class _ReadFile:
    payload: bytes
    file_type: str
    mode: str
    device: int
    inode: int


@dataclass(frozen=True, slots=True)
class _IndexObservation:
    outcome: str
    entry: dict[str, object] | None


class _GitFailure(Exception):
    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _require_limits(limits: IdentityLimits) -> IdentityLimits:
    if type(limits) is not IdentityLimits:
        raise IdentityError("invalid_limits")
    for field in fields(limits):
        value = getattr(limits, field.name)
        if (
            type(value) is not int
            or value <= 0
            or value > _LIMIT_CEILINGS[field.name]
        ):
            raise IdentityError("invalid_limits")
    return limits


def _base64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _root_path(root: object) -> str:
    if isinstance(root, bytes):
        raise IdentityError("invalid_root")
    try:
        raw_path = os.fspath(root)  # type: ignore[arg-type]
    except TypeError:
        raise IdentityError("invalid_root") from None
    if type(raw_path) is not str or not raw_path or "\x00" in raw_path:
        raise IdentityError("invalid_root")
    return os.path.abspath(raw_path)


def _fstat_owned_descriptor(descriptor: int, error_code: str) -> os.stat_result:
    try:
        return os.fstat(descriptor)
    except OSError:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise IdentityError(error_code) from None


def _open_root(root_path: str) -> int:
    try:
        path_status = os.lstat(root_path)
    except OSError:
        raise IdentityError("invalid_root") from None
    if stat.S_ISLNK(path_status.st_mode) or not stat.S_ISDIR(path_status.st_mode):
        raise IdentityError("invalid_root")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if no_follow == 0:
        raise IdentityError("no_follow_unavailable")
    try:
        descriptor = os.open(root_path, flags | no_follow)
    except OSError:
        raise IdentityError("invalid_root") from None
    opened_status = _fstat_owned_descriptor(descriptor, "root_changed")
    if (
        opened_status.st_dev != path_status.st_dev
        or opened_status.st_ino != path_status.st_ino
        or not stat.S_ISDIR(opened_status.st_mode)
    ):
        os.close(descriptor)
        raise IdentityError("root_changed")
    return descriptor


def _duplicate_root(root_fd: object) -> int:
    if type(root_fd) is not int or root_fd < 0:
        raise IdentityError("invalid_root")
    try:
        descriptor = os.dup(root_fd)
    except (OSError, OverflowError):
        raise IdentityError("invalid_root") from None
    root_status = _fstat_owned_descriptor(descriptor, "invalid_root")
    if not stat.S_ISDIR(root_status.st_mode):
        os.close(descriptor)
        raise IdentityError("invalid_root")
    return descriptor


def _root_is_unchanged(root_path: str, expected: os.stat_result) -> None:
    try:
        current = os.stat(root_path, follow_symlinks=False)
    except OSError:
        raise IdentityError("root_changed") from None
    if (
        current.st_dev != expected.st_dev
        or current.st_ino != expected.st_ino
        or not stat.S_ISDIR(current.st_mode)
    ):
        raise IdentityError("root_changed")


def _has_structural_git_marker(root_descriptor: int) -> bool:
    """Conservatively inspect Git markers without reopening the root path."""

    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        current = os.dup(root_descriptor)
    except OSError:
        return True
    visited: set[tuple[int, int]] = set()
    try:
        while True:
            try:
                current_status = os.fstat(current)
            except OSError:
                return True
            current_identity = (current_status.st_dev, current_status.st_ino)
            if current_identity in visited or not stat.S_ISDIR(current_status.st_mode):
                return True
            visited.add(current_identity)
            try:
                os.stat(".git", dir_fd=current, follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError:
                return True
            else:
                return True
            parent = -1
            try:
                parent = os.open("..", directory_flags, dir_fd=current)
                parent_status = os.fstat(parent)
            except OSError:
                if parent >= 0:
                    try:
                        os.close(parent)
                    except OSError:
                        pass
                return True
            parent_identity = (parent_status.st_dev, parent_status.st_ino)
            if not stat.S_ISDIR(parent_status.st_mode):
                os.close(parent)
                return True
            if parent_identity == current_identity:
                os.close(parent)
                break
            os.close(current)
            current = parent
    finally:
        try:
            os.close(current)
        except OSError:
            pass

    try:
        head = os.stat("HEAD", dir_fd=root_descriptor, follow_symlinks=False)
        objects = os.stat("objects", dir_fd=root_descriptor, follow_symlinks=False)
        refs = os.stat("refs", dir_fd=root_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return (
        stat.S_ISREG(head.st_mode)
        and stat.S_ISDIR(objects.st_mode)
        and stat.S_ISDIR(refs.st_mode)
    )


def _validate_relative_path(relative_path: object, limits: IdentityLimits) -> tuple[str, bytes]:
    if type(relative_path) is not str:
        raise IdentityError("invalid_relative_path")
    if (
        not relative_path
        or relative_path.startswith("/")
        or "\x00" in relative_path
        or "\\" in relative_path
    ):
        raise IdentityError("invalid_relative_path")
    parts = relative_path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise IdentityError("invalid_relative_path")
    try:
        raw = relative_path.encode("utf-8", errors="strict")
        if len(raw) > limits.max_path_bytes:
            raise IdentityError("path_too_large")
        canonical_json_bytes(
            relative_path,
            JSONLimits(
                max_document_bytes=limits.max_path_bytes + 3,
                max_string_bytes=limits.max_path_bytes,
            ),
        )
    except IdentityError:
        raise
    except (UnicodeEncodeError, CanonicalJSONError):
        raise IdentityError("invalid_relative_path") from None
    return relative_path, raw


def _require_exact_directory_entry(
    directory_descriptor: int,
    component: str,
    limits: IdentityLimits,
) -> os.stat_result:
    normalized_component = _FROZEN_UNICODE_DATABASE.normalize("NFC", component)
    folded_component = normalized_component.casefold()
    exact_count = 0
    alias_found = False
    entry_count = 0
    try:
        with os.scandir(directory_descriptor) as entries:
            for entry in entries:
                entry_count += 1
                if entry_count > limits.max_directory_entries:
                    raise IdentityError("directory_too_large")
                name = os.fsdecode(entry.name)
                normalized_name = _FROZEN_UNICODE_DATABASE.normalize("NFC", name)
                if name == component:
                    exact_count += 1
                elif (
                    normalized_name == normalized_component
                    or normalized_name.casefold() == folded_component
                ):
                    alias_found = True
    except IdentityError:
        raise
    except OSError:
        raise IdentityError("source_missing") from None
    if alias_found or exact_count != 1:
        if alias_found:
            raise IdentityError("ambiguous_path")
        raise IdentityError("source_missing")
    try:
        return os.stat(component, dir_fd=directory_descriptor, follow_symlinks=False)
    except OSError:
        raise IdentityError("source_missing") from None


def _open_regular_file(
    root_descriptor: int, relative_path: str, limits: IdentityLimits
) -> int:
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | os.O_NOFOLLOW
    )
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | os.O_NOFOLLOW
    )
    current_descriptor = os.dup(root_descriptor)
    try:
        parts = relative_path.split("/")
        for component in parts[:-1]:
            component_status = _require_exact_directory_entry(
                current_descriptor, component, limits
            )
            if stat.S_ISLNK(component_status.st_mode):
                raise IdentityError("source_symlink")
            if not stat.S_ISDIR(component_status.st_mode):
                raise IdentityError("source_not_regular")
            try:
                next_descriptor = os.open(
                    component, directory_flags, dir_fd=current_descriptor
                )
            except OSError as error:
                if error.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise IdentityError("source_symlink") from None
                raise IdentityError("source_missing") from None
            os.close(current_descriptor)
            current_descriptor = next_descriptor
        file_status = _require_exact_directory_entry(
            current_descriptor, parts[-1], limits
        )
        if stat.S_ISLNK(file_status.st_mode):
            raise IdentityError("source_symlink")
        if not stat.S_ISREG(file_status.st_mode):
            raise IdentityError("source_not_regular")
        try:
            file_descriptor = os.open(
                parts[-1], file_flags, dir_fd=current_descriptor
            )
        except OSError as error:
            if error.errno in (errno.ELOOP, errno.ENOTDIR):
                raise IdentityError("source_symlink") from None
            raise IdentityError("source_missing") from None
    finally:
        os.close(current_descriptor)
    opened_status = _fstat_owned_descriptor(
        file_descriptor, "source_changed_during_read"
    )
    if not stat.S_ISREG(opened_status.st_mode):
        os.close(file_descriptor)
        raise IdentityError("source_not_regular")
    return file_descriptor


def _read_stable_file(
    root_descriptor: int, relative_path: str, limits: IdentityLimits
) -> _ReadFile:
    descriptor = _open_regular_file(root_descriptor, relative_path, limits)
    try:
        before = os.fstat(descriptor)
        if before.st_size > limits.max_file_bytes:
            raise IdentityError("file_too_large")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, limits.max_file_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > limits.max_file_bytes:
                raise IdentityError("file_too_large")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity or total != after.st_size:
            raise IdentityError("source_changed_during_read")
        payload = b"".join(chunks)
    finally:
        os.close(descriptor)
    verification_descriptor = _open_regular_file(
        root_descriptor, relative_path, limits
    )
    try:
        verified = os.fstat(verification_descriptor)
    finally:
        os.close(verification_descriptor)
    if (verified.st_dev, verified.st_ino) != (after.st_dev, after.st_ino):
        raise IdentityError("source_changed_during_read")
    return _ReadFile(
        payload=payload,
        file_type="regular",
        mode=f"{stat.S_IMODE(after.st_mode):04o}",
        device=after.st_dev,
        inode=after.st_ino,
    )


def _validate_executable_path(path: str) -> _GitExecutable:
    if not os.path.isabs(path) or os.path.normpath(path) != path or "\x00" in path:
        raise IdentityError("invalid_git_executable")
    try:
        path_status = os.lstat(path)
    except OSError:
        raise IdentityError("invalid_git_executable") from None
    if (
        stat.S_ISLNK(path_status.st_mode)
        or not stat.S_ISREG(path_status.st_mode)
        or not os.access(path, os.X_OK)
    ):
        raise IdentityError("invalid_git_executable")
    return _GitExecutable(path=path, device=path_status.st_dev, inode=path_status.st_ino)


def _resolve_git_executable(git_executable: object) -> _GitExecutable | None:
    if git_executable is not None:
        if isinstance(git_executable, bytes):
            raise IdentityError("invalid_git_executable")
        try:
            raw_path = os.fspath(git_executable)  # type: ignore[arg-type]
        except TypeError:
            raise IdentityError("invalid_git_executable") from None
        if type(raw_path) is not str:
            raise IdentityError("invalid_git_executable")
        return _validate_executable_path(raw_path)

    for candidate in _DEFAULT_GIT_CANDIDATES:
        if not os.path.exists(candidate):
            continue
        resolved = os.path.realpath(candidate)
        try:
            return _validate_executable_path(resolved)
        except IdentityError:
            continue
    return None


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            process.kill()
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass


def _run_git(
    root_descriptor: int,
    executable: _GitExecutable,
    limits: IdentityLimits,
    arguments: tuple[str, ...],
    config_overrides: tuple[tuple[str, str], ...] = (),
) -> _GitResult:
    try:
        current_executable = os.lstat(executable.path)
    except OSError:
        raise _GitFailure("git_command_failed") from None
    if (
        current_executable.st_dev != executable.device
        or current_executable.st_ino != executable.inode
        or not stat.S_ISREG(current_executable.st_mode)
    ):
        raise _GitFailure("git_command_failed")

    environment = {
        "GIT_CONFIG_COUNT": str(len(config_overrides)),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_LITERAL_PATHSPECS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    for index, (key, value) in enumerate(config_overrides):
        environment[f"GIT_CONFIG_KEY_{index}"] = key
        environment[f"GIT_CONFIG_VALUE_{index}"] = value
    trampoline_python = os.path.realpath(sys.executable)
    try:
        trampoline_status = os.lstat(trampoline_python)
    except OSError:
        raise _GitFailure("git_command_failed") from None
    if (
        not os.path.isabs(trampoline_python)
        or os.path.normpath(trampoline_python) != trampoline_python
        or not stat.S_ISREG(trampoline_status.st_mode)
        or not os.access(trampoline_python, os.X_OK)
    ):
        raise _GitFailure("git_command_failed")
    target = (executable.path, *_GIT_CONFIG_ARGUMENTS, *arguments)
    command = [
        trampoline_python,
        "-I",
        "-S",
        "-B",
        "-c",
        _GIT_TRAMPOLINE,
        str(root_descriptor),
        *target,
    ]
    try:
        process = subprocess.Popen(
            command,
            cwd="/",
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            pass_fds=(root_descriptor,),
            start_new_session=True,
        )
    except OSError:
        raise _GitFailure("git_command_failed") from None
    if process.stdout is None or process.stderr is None:
        _stop_process(process)
        raise _GitFailure("git_command_failed")

    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    stdout_chunks: list[bytes] = []
    total_output = 0
    deadline = time.monotonic() + limits.git_timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _stop_process(process)
                raise _GitFailure("git_timeout")
            events = selector.select(min(remaining, 0.25))
            if not events:
                continue
            for key, _mask in events:
                try:
                    chunk = os.read(
                        key.fileobj.fileno(),
                        min(64 * 1024, limits.max_git_output_bytes - total_output + 1),
                    )
                except OSError:
                    _stop_process(process)
                    raise _GitFailure("git_command_failed") from None
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                total_output += len(chunk)
                if total_output > limits.max_git_output_bytes:
                    _stop_process(process)
                    raise _GitFailure("git_output_limit")
                if key.data == "stdout":
                    stdout_chunks.append(chunk)
        try:
            returncode = process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            _stop_process(process)
            raise _GitFailure("git_timeout") from None
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return _GitResult(returncode=returncode, stdout=b"".join(stdout_chunks))


def _single_git_value(result: _GitResult) -> bytes:
    if result.returncode != 0 or not result.stdout.endswith(b"\n"):
        raise _GitFailure("git_state_malformed")
    return result.stdout[:-1]


def _discover_git_filter_overrides(
    root_descriptor: int,
    executable: _GitExecutable,
    limits: IdentityLimits,
) -> tuple[tuple[str, str], ...]:
    result = _run_git(
        root_descriptor,
        executable,
        limits,
        (
            "config",
            "--null",
            "--name-only",
            "--includes",
            "--get-regexp",
            _GIT_FILTER_CONFIG_QUERY,
        ),
    )
    if result.returncode == 1 and not result.stdout:
        return ()
    if result.returncode != 0:
        raise _GitFailure("git_command_failed")
    if not result.stdout:
        raise _GitFailure("git_state_malformed")

    raw_keys = _nul_records(result.stdout, limits)
    drivers: list[str] = []
    seen_drivers: set[str] = set()
    for raw_key in raw_keys:
        match = _GIT_FILTER_CONFIG_KEY_PATTERN.fullmatch(raw_key)
        if match is None:
            raise _GitFailure("git_state_malformed")
        driver = match.group("driver").decode("ascii")
        if driver in seen_drivers:
            continue
        if len(drivers) >= _MAX_GIT_FILTER_DRIVERS:
            raise _GitFailure("git_output_limit")
        seen_drivers.add(driver)
        drivers.append(driver)

    overrides: list[tuple[str, str]] = []
    for driver in drivers:
        overrides.extend(
            (
                (f"filter.{driver}.clean", "cat"),
                (f"filter.{driver}.smudge", "cat"),
                (f"filter.{driver}.process", ""),
                (f"filter.{driver}.required", "false"),
            )
        )
    return tuple(overrides)


def _logical_state_digest(core: dict[str, object]) -> str:
    return framed_sha256_hex(
        "contextguard-receipt/repository-logical-state/v1",
        canonical_json_bytes(core),
    )


def _instance(
    *,
    root_path: str,
    root_status: os.stat_result,
    kind: str,
    git_directory: bytes = b"",
    common_directory: bytes = b"",
) -> dict[str, object]:
    identity_sha256 = framed_sha256_hex(
        "contextguard-receipt/repository-instance/v1",
        str(root_status.st_dev).encode("ascii"),
        str(root_status.st_ino).encode("ascii"),
        os.fsencode(root_path),
        git_directory,
        common_directory,
    )
    return {"identity_sha256": identity_sha256, "kind": kind}


def _repository_snapshot(
    *,
    disposition: str,
    reason: str,
    logical_state: dict[str, object],
    instance: dict[str, object],
) -> dict[str, object]:
    return {
        "artifact_kind": "repository_snapshot",
        "disposition": disposition,
        "evidence_boundary": evidence_boundary(),
        "instance": instance,
        "logical_state": logical_state,
        "reason": reason,
        "schema_version": _REPOSITORY_SCHEMA_VERSION,
    }


def _non_git_snapshot(root_path: str, root_status: os.stat_result) -> dict[str, object]:
    logical_core: dict[str, object] = {"kind": "non_git"}
    logical_state = dict(logical_core)
    logical_state["state_sha256"] = _logical_state_digest(logical_core)
    return _repository_snapshot(
        disposition="pass_through",
        reason="non_git_directory",
        logical_state=logical_state,
        instance=_instance(
            root_path=root_path, root_status=root_status, kind="directory"
        ),
    )


def _unresolved_snapshot(
    root_path: str, root_status: os.stat_result, reason: str
) -> dict[str, object]:
    logical_core: dict[str, object] = {"kind": "unresolved", "reason": reason}
    logical_state = dict(logical_core)
    logical_state["state_sha256"] = _logical_state_digest(logical_core)
    return _repository_snapshot(
        disposition="pass_through",
        reason=reason,
        logical_state=logical_state,
        instance=_instance(
            root_path=root_path, root_status=root_status, kind="directory"
        ),
    )


def _snapshot_once(
    root_path: str,
    root_descriptor: int,
    root_status: os.stat_result,
    git_executable: object,
    limits: IdentityLimits,
) -> dict[str, object]:
    executable = _resolve_git_executable(git_executable)
    if executable is None:
        return _unresolved_snapshot(root_path, root_status, "git_unavailable")

    def run_without_filter_overrides(*arguments: str) -> _GitResult:
        return _run_git(root_descriptor, executable, limits, tuple(arguments))

    try:
        inside_result = run_without_filter_overrides(
            "rev-parse", "--is-inside-work-tree"
        )
        if inside_result.returncode == 128:
            if _has_structural_git_marker(root_descriptor):
                raise _GitFailure("git_command_failed")
            return _non_git_snapshot(root_path, root_status)
        inside = _single_git_value(inside_result)
        if inside not in (b"true", b"false"):
            raise _GitFailure("git_state_malformed")

        filter_overrides = _discover_git_filter_overrides(
            root_descriptor, executable, limits
        )

        def run(*arguments: str) -> _GitResult:
            return _run_git(
                root_descriptor,
                executable,
                limits,
                tuple(arguments),
                filter_overrides,
            )

        bare = _single_git_value(run("rev-parse", "--is-bare-repository"))
        if bare not in (b"true", b"false"):
            raise _GitFailure("git_state_malformed")
        is_bare = bare == b"true"
        if is_bare == (inside == b"true"):
            raise _GitFailure("git_state_malformed")

        git_directory = _single_git_value(run("rev-parse", "--git-dir"))
        common_directory = _single_git_value(run("rev-parse", "--git-common-dir"))

        oid_result = run("rev-parse", "--verify", "HEAD")
        if oid_result.returncode == 0:
            head_oid = _single_git_value(oid_result)
            if _OID_PATTERN.fullmatch(head_oid) is None:
                raise _GitFailure("git_state_malformed")
        elif oid_result.returncode == 128:
            head_oid = None
        else:
            raise _GitFailure("git_command_failed")

        ref_result = run("symbolic-ref", "-q", "HEAD")
        if ref_result.returncode == 0:
            head_ref = _single_git_value(ref_result)
            if not head_ref:
                raise _GitFailure("git_state_malformed")
        elif ref_result.returncode == 1:
            head_ref = None
        else:
            raise _GitFailure("git_command_failed")

        if head_oid is None and head_ref is not None:
            head_state = "unborn"
        elif head_oid is not None and head_ref is not None:
            head_state = "attached"
        elif head_oid is not None and head_ref is None:
            head_state = "detached"
        else:
            raise _GitFailure("git_state_malformed")

        logical_core: dict[str, object] = {
            "head_state": head_state,
            "kind": "git_bare" if is_bare else "git_worktree",
        }
        if head_oid is not None:
            logical_core["head_oid_b64u"] = _base64url(head_oid)
        if head_ref is not None:
            logical_core["head_ref_b64u"] = _base64url(head_ref)

        if not is_bare:
            status_result = run(
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=dirty",
            )
            if status_result.returncode != 0:
                raise _GitFailure("git_command_failed")
            raw_status = status_result.stdout
            if raw_status and not raw_status.endswith(b"\0"):
                raise _GitFailure("git_state_malformed")
            nul_fields = raw_status.count(b"\0")
            if nul_fields > limits.max_git_nul_fields:
                raise _GitFailure("git_output_limit")
            index_result = run("ls-files", "--stage", "-z")
            if index_result.returncode != 0:
                raise _GitFailure("git_command_failed")
            raw_index = index_result.stdout
            if raw_index and not raw_index.endswith(b"\0"):
                raise _GitFailure("git_state_malformed")
            index_records = raw_index.count(b"\0")
            if index_records > limits.max_git_nul_fields:
                raise _GitFailure("git_output_limit")
            diff_result = run(
                "diff",
                "--binary",
                "--full-index",
                "--no-ext-diff",
                "--no-textconv",
                "--ignore-submodules=dirty",
                "--",
            )
            if diff_result.returncode != 0:
                raise _GitFailure("git_command_failed")
            logical_core.update(
                {
                    "index_format": "git-ls-files-stage-z",
                    "index_nul_records": index_records,
                    "index_sha256": hashlib.sha256(raw_index).hexdigest(),
                    "status_format": "git-status-porcelain-v1-z",
                    "status_nul_fields": nul_fields,
                    "status_sha256": hashlib.sha256(raw_status).hexdigest(),
                    "worktree_diff_sha256": hashlib.sha256(
                        diff_result.stdout
                    ).hexdigest(),
                }
            )

        logical_state = dict(logical_core)
        logical_state["state_sha256"] = _logical_state_digest(logical_core)
        if is_bare:
            instance_kind = "bare_repository"
            reason = "git_bare_state"
        elif git_directory != common_directory:
            instance_kind = "linked_worktree"
            reason = (
                "git_unborn_worktree_state"
                if head_state == "unborn"
                else "git_worktree_state"
            )
        else:
            instance_kind = "worktree"
            reason = (
                "git_unborn_worktree_state"
                if head_state == "unborn"
                else "git_worktree_state"
            )
        return _repository_snapshot(
            disposition="captured",
            reason=reason,
            logical_state=logical_state,
            instance=_instance(
                root_path=root_path,
                root_status=root_status,
                kind=instance_kind,
                git_directory=git_directory,
                common_directory=common_directory,
            ),
        )
    except _GitFailure as failure:
        _LOGGER.debug("repository snapshot degraded: %s", failure.code)
        return _unresolved_snapshot(root_path, root_status, failure.code)


def _snapshot_with_open_root(
    root_path: str,
    root_descriptor: int,
    root_status: os.stat_result,
    git_executable: object,
    limits: IdentityLimits,
) -> dict[str, object]:
    first = _snapshot_once(
        root_path, root_descriptor, root_status, git_executable, limits
    )
    second = _snapshot_once(
        root_path, root_descriptor, root_status, git_executable, limits
    )
    if (
        first["instance"] != second["instance"]
        or first["logical_state"] != second["logical_state"]
    ):
        return _unresolved_snapshot(root_path, root_status, "git_state_changed")
    return second


def snapshot_repository(
    root: object,
    git_executable: object = None,
    limits: IdentityLimits = _DEFAULT_LIMITS,
    *,
    root_fd: object = None,
) -> dict[str, object]:
    """Capture bounded Git metadata plus a local repository instance identity."""

    checked_limits = _require_limits(limits)
    root_path = _root_path(root)
    borrowed_root = root_fd is not None
    root_descriptor = (
        _duplicate_root(root_fd) if borrowed_root else _open_root(root_path)
    )
    try:
        root_status = os.fstat(root_descriptor)
        result = _snapshot_with_open_root(
            root_path,
            root_descriptor,
            root_status,
            git_executable,
            checked_limits,
        )
        if not borrowed_root:
            _root_is_unchanged(root_path, root_status)
        return result
    finally:
        os.close(root_descriptor)


def _validated_exclusion_directory(
    root_path: str, raw_git_path: bytes
) -> tuple[Path, tuple[int, int], str]:
    if not raw_git_path or b"\0" in raw_git_path:
        raise IdentityError("repository_exclusion_unavailable")
    decoded_path = os.fsdecode(raw_git_path)
    candidate = (
        decoded_path
        if os.path.isabs(decoded_path)
        else os.path.join(root_path, decoded_path)
    )
    resolved = os.path.realpath(os.path.abspath(candidate))
    descriptor = _open_root(resolved)
    try:
        directory_status = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    return (
        Path(resolved),
        (directory_status.st_dev, directory_status.st_ino),
        os.path.normcase(resolved),
    )


def _repository_exclusion_snapshot(
    root: object,
    *,
    git_executable: object = None,
    limits: IdentityLimits = _DEFAULT_LIMITS,
) -> tuple[tuple[Path, tuple[int, int]], ...]:
    """Return validated exclusion paths with identities from one root snapshot."""

    checked_limits = _require_limits(limits)
    root_path = _root_path(root)
    root_descriptor = _open_root(root_path)
    try:
        root_status = os.fstat(root_descriptor)
        resolved_root = os.path.realpath(root_path)
        resolved_descriptor = _open_root(resolved_root)
        try:
            resolved_status = os.fstat(resolved_descriptor)
        finally:
            os.close(resolved_descriptor)
        root_identity = (root_status.st_dev, root_status.st_ino)
        if root_identity != (resolved_status.st_dev, resolved_status.st_ino):
            raise IdentityError("repository_exclusion_unavailable")

        result = [(Path(resolved_root), root_identity)]
        seen_identities = {root_identity}
        seen_paths = {os.path.normcase(resolved_root)}
        executable = _resolve_git_executable(git_executable)
        if executable is None:
            raise IdentityError("repository_exclusion_unavailable")

        def run_without_filter_overrides(*arguments: str) -> _GitResult:
            return _run_git(
                root_descriptor, executable, checked_limits, tuple(arguments)
            )

        try:
            inside_result = run_without_filter_overrides(
                "rev-parse", "--is-inside-work-tree"
            )
            if inside_result.returncode == 128:
                if _has_structural_git_marker(root_descriptor):
                    raise _GitFailure("git_command_failed")
                _root_is_unchanged(root_path, root_status)
                return tuple(result)
            inside = _single_git_value(inside_result)
            filter_overrides = _discover_git_filter_overrides(
                root_descriptor, executable, checked_limits
            )

            def run(*arguments: str) -> _GitResult:
                return _run_git(
                    root_descriptor,
                    executable,
                    checked_limits,
                    tuple(arguments),
                    filter_overrides,
                )

            bare = _single_git_value(run("rev-parse", "--is-bare-repository"))
            if inside not in (b"true", b"false") or bare not in (b"true", b"false"):
                raise _GitFailure("git_state_malformed")
            if (bare == b"true") == (inside == b"true"):
                raise _GitFailure("git_state_malformed")
            raw_directories = (
                _single_git_value(run("rev-parse", "--git-dir")),
                _single_git_value(run("rev-parse", "--git-common-dir")),
            )
        except _GitFailure as failure:
            _LOGGER.debug("repository exclusions unavailable: %s", failure.code)
            raise IdentityError("repository_exclusion_unavailable") from None

        for raw_directory in raw_directories:
            path, directory_identity, normalized_path = _validated_exclusion_directory(
                root_path, raw_directory
            )
            if directory_identity in seen_identities or normalized_path in seen_paths:
                continue
            seen_identities.add(directory_identity)
            seen_paths.add(normalized_path)
            result.append((path, directory_identity))
        _root_is_unchanged(root_path, root_status)
        return tuple(result)
    finally:
        os.close(root_descriptor)


def _repository_exclusion_paths(
    root: object,
    *,
    git_executable: object = None,
    limits: IdentityLimits = _DEFAULT_LIMITS,
) -> tuple[Path, ...]:
    """Return private validated directories that repository-local storage must avoid."""

    return tuple(
        path
        for path, _identity in _repository_exclusion_snapshot(
            root,
            git_executable=git_executable,
            limits=limits,
        )
    )


def _validate_byte_range(byte_range: object, byte_length: int) -> tuple[int, int]:
    if type(byte_range) is not tuple or len(byte_range) != 2:
        raise IdentityError("invalid_byte_range")
    start_byte, end_byte = byte_range
    if (
        type(start_byte) is not int
        or type(end_byte) is not int
        or start_byte < 0
        or end_byte < start_byte
        or end_byte > byte_length
    ):
        raise IdentityError("invalid_byte_range")
    return start_byte, end_byte


def _nul_records(raw: bytes, limits: IdentityLimits) -> list[bytes]:
    if not raw:
        return []
    if not raw.endswith(b"\0"):
        raise _GitFailure("git_state_malformed")
    records = raw[:-1].split(b"\0")
    if len(records) > limits.max_git_nul_fields:
        raise _GitFailure("git_output_limit")
    return records


def _observe_source_index(
    root_descriptor: int,
    relative_path: str,
    path_bytes: bytes,
    git_executable: object,
    limits: IdentityLimits,
) -> _IndexObservation:
    executable = _resolve_git_executable(git_executable)
    if executable is None:
        return _IndexObservation("unavailable", None)

    try:
        filter_overrides = _discover_git_filter_overrides(
            root_descriptor, executable, limits
        )

        def run(*arguments: str) -> _GitResult:
            return _run_git(
                root_descriptor,
                executable,
                limits,
                tuple(arguments),
                filter_overrides,
            )

        stage_result = run("ls-files", "--stage", "-z", "--", relative_path)
        if stage_result.returncode != 0:
            raise _GitFailure("git_command_failed")
        stage_records = _nul_records(stage_result.stdout, limits)
        parsed_records: list[tuple[bytes, bytes, int, bytes]] = []
        for record in stage_records:
            match = _INDEX_RECORD_PATTERN.match(record)
            if match is None:
                raise _GitFailure("git_state_malformed")
            record_path = record[match.end() :]
            if record_path != path_bytes:
                raise _GitFailure("git_state_malformed")
            parsed_records.append(
                (
                    match.group("mode"),
                    match.group("oid"),
                    int(match.group("stage"), 10),
                    record,
                )
            )

        flag_result = run("ls-files", "-v", "-z", "--", relative_path)
        if flag_result.returncode != 0:
            raise _GitFailure("git_command_failed")
        flag_records = _nul_records(flag_result.stdout, limits)
        for flag_record in flag_records:
            if len(flag_record) < 3 or flag_record[1:2] != b" ":
                raise _GitFailure("git_state_malformed")
            if flag_record[2:] != path_bytes:
                raise _GitFailure("git_state_malformed")
            if flag_record[:1].upper() == b"S":
                return _IndexObservation("sparse", None)

        if not parsed_records:
            if flag_records:
                raise _GitFailure("git_state_malformed")
            return _IndexObservation("usable", {"status": "untracked"})
        if len(parsed_records) != 1 or parsed_records[0][2] != 0:
            return _IndexObservation("unmerged", None)
        if len(flag_records) != 1:
            raise _GitFailure("git_state_malformed")

        index_mode, object_id, stage, raw_record = parsed_records[0]
        if index_mode == b"120000":
            return _IndexObservation("symlink", None)
        if index_mode not in (b"100644", b"100755"):
            return _IndexObservation("not_regular", None)
        return _IndexObservation(
            "usable",
            {
                "index_mode": index_mode.decode("ascii"),
                "object_id_b64u": _base64url(object_id),
                "record_sha256": hashlib.sha256(raw_record + b"\0").hexdigest(),
                "stage": stage,
                "status": "tracked",
            },
        )
    except _GitFailure as failure:
        _LOGGER.debug("source index observation degraded: %s", failure.code)
        return _IndexObservation("unavailable", None)


def _canonical_symbol_evidence(
    symbol_evidence: object, limits: IdentityLimits
) -> bytes | None:
    try:
        return canonical_json_bytes(
            symbol_evidence,
            JSONLimits(
                max_document_bytes=limits.max_symbol_evidence_bytes,
                max_depth=16,
                max_total_values=256,
                max_object_members=32,
                max_string_bytes=limits.max_symbol_evidence_bytes,
            ),
        )
    except CanonicalJSONError as error:
        if error.code in (
            "document_too_large",
            "max_string_bytes_exceeded",
        ):
            raise IdentityError("symbol_evidence_too_large") from None
        return None


def _complete_symbol_range(
    symbol_evidence: object,
    evidence_bytes: bytes | None,
    payload: bytes,
    explicit_range: tuple[int, int] | None,
) -> tuple[str, tuple[int, int] | None]:
    if evidence_bytes is None or type(symbol_evidence) is not dict:
        return "symbol_evidence_incomplete", None
    if frozenset(symbol_evidence) != _SYMBOL_EVIDENCE_KEYS:
        return "symbol_evidence_incomplete", None
    if (
        symbol_evidence.get("schema_version") != _SYMBOL_EVIDENCE_SCHEMA_VERSION
        or symbol_evidence.get("evidence_kind") != _SYMBOL_EVIDENCE_KIND
        or symbol_evidence.get("complete") is not True
        or symbol_evidence.get("deterministic") is not True
        or symbol_evidence.get("scan_complete") is not True
        or symbol_evidence.get("capped") is not False
        or symbol_evidence.get("fallback_used") is not False
        or symbol_evidence.get("parser_error") is not False
    ):
        return "symbol_evidence_incomplete", None
    for key, maximum_length in (
        ("producer_id", 128),
        ("language_id", 64),
        ("qualified_name", 1024),
    ):
        value = symbol_evidence.get(key)
        if (
            type(value) is not str
            or not value
            or len(value.encode("utf-8")) > maximum_length
            or _SAFE_IDENTIFIER_PATTERN.fullmatch(value) is None
        ):
            return "symbol_evidence_incomplete", None
    evidence_source_sha256 = symbol_evidence.get("source_sha256")
    if (
        type(evidence_source_sha256) is not str
        or _SHA256_PATTERN.fullmatch(evidence_source_sha256) is None
    ):
        return "symbol_evidence_incomplete", None
    source_sha256 = hashlib.sha256(payload).hexdigest()
    if evidence_source_sha256 != source_sha256:
        return "symbol_evidence_mismatch", None
    if payload.startswith(b"\xef\xbb\xbf"):
        return "symbol_source_unsupported", None
    try:
        payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return "symbol_source_unsupported", None
    start_byte = symbol_evidence.get("start_byte")
    end_byte = symbol_evidence.get("end_byte")
    if (
        type(start_byte) is not int
        or type(end_byte) is not int
        or start_byte < 0
        or end_byte <= start_byte
        or end_byte > len(payload)
    ):
        return "symbol_evidence_mismatch", None
    evidence_range = (start_byte, end_byte)
    if explicit_range is not None and explicit_range != evidence_range:
        return "symbol_evidence_mismatch", None

    raw_range_sha256 = symbol_evidence.get("raw_range_sha256")
    if (
        type(raw_range_sha256) is not str
        or _SHA256_PATTERN.fullmatch(raw_range_sha256) is None
        or raw_range_sha256
        != hashlib.sha256(payload[start_byte:end_byte]).hexdigest()
    ):
        return "symbol_evidence_mismatch", None
    try:
        payload[:start_byte].decode("utf-8", errors="strict")
        payload[start_byte:end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return "symbol_source_unsupported", None

    occurrence = symbol_evidence.get("occurrence")
    qualified_name = symbol_evidence.get("qualified_name")
    if type(occurrence) is not int or occurrence < 0 or occurrence > 2**31 - 1:
        return "symbol_evidence_incomplete", None
    candidates = symbol_evidence.get("candidates")
    if type(candidates) is not list or not candidates or len(candidates) > 16:
        return "symbol_evidence_incomplete", None
    candidate_identities: set[tuple[str, int]] = set()
    candidate_occurrences: dict[str, list[tuple[int, int]]] = {}
    matching_candidates = 0
    for candidate in candidates:
        if type(candidate) is not dict or frozenset(candidate) != _SYMBOL_CANDIDATE_KEYS:
            return "symbol_evidence_incomplete", None
        candidate_name = candidate.get("qualified_name")
        candidate_occurrence = candidate.get("occurrence")
        candidate_start = candidate.get("start_byte")
        candidate_end = candidate.get("end_byte")
        candidate_hash = candidate.get("raw_range_sha256")
        if (
            type(candidate_name) is not str
            or not candidate_name
            or len(candidate_name.encode("utf-8")) > 1024
            or _SAFE_IDENTIFIER_PATTERN.fullmatch(candidate_name) is None
            or type(candidate_occurrence) is not int
            or candidate_occurrence < 0
            or candidate_occurrence > 2**31 - 1
            or type(candidate_start) is not int
            or type(candidate_end) is not int
            or candidate_start < 0
            or candidate_end <= candidate_start
            or candidate_end > len(payload)
            or type(candidate_hash) is not str
            or _SHA256_PATTERN.fullmatch(candidate_hash) is None
        ):
            return "symbol_evidence_incomplete", None
        candidate_identity = (candidate_name, candidate_occurrence)
        if candidate_identity in candidate_identities:
            return "symbol_evidence_incomplete", None
        candidate_identities.add(candidate_identity)
        candidate_occurrences.setdefault(candidate_name, []).append(
            (candidate_start, candidate_occurrence)
        )
        if (
            candidate_hash
            != hashlib.sha256(payload[candidate_start:candidate_end]).hexdigest()
        ):
            return "symbol_evidence_mismatch", None
        try:
            payload[:candidate_start].decode("utf-8", errors="strict")
            payload[candidate_start:candidate_end].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return "symbol_source_unsupported", None
        if candidate_identity == (qualified_name, occurrence):
            if (
                candidate_start != start_byte
                or candidate_end != end_byte
                or candidate_hash != raw_range_sha256
            ):
                return "symbol_evidence_mismatch", None
            matching_candidates += 1
    for positions in candidate_occurrences.values():
        positions.sort(key=lambda item: item[0])
        previous_start: int | None = None
        for expected_occurrence, (candidate_start, claimed_occurrence) in enumerate(
            positions
        ):
            if candidate_start == previous_start or claimed_occurrence != expected_occurrence:
                return "symbol_evidence_incomplete", None
            previous_start = candidate_start
    if matching_candidates != 1:
        return "symbol_evidence_incomplete", None
    return "complete", evidence_range


def _source_base(
    *,
    disposition: str,
    reason: str,
    path_bytes: bytes,
    repository: dict[str, object],
) -> dict[str, object]:
    return {
        "artifact_kind": "source_identity",
        "disposition": disposition,
        "evidence_boundary": evidence_boundary(),
        "path_b64u": _base64url(path_bytes),
        "reason": reason,
        "repository": repository,
        "schema_version": _SOURCE_SCHEMA_VERSION,
    }


def identify_source(
    root: object,
    relative_path: object,
    byte_range: object = None,
    symbol_evidence: object = None,
    git_executable: object = None,
    limits: IdentityLimits = _DEFAULT_LIMITS,
) -> dict[str, object]:
    """Identify exact raw bytes and conservatively classify semantic evidence."""

    checked_limits = _require_limits(limits)
    checked_relative_path, path_bytes = _validate_relative_path(
        relative_path, checked_limits
    )
    evidence_bytes = (
        None
        if symbol_evidence is None
        else _canonical_symbol_evidence(symbol_evidence, checked_limits)
    )
    root_path = _root_path(root)
    root_descriptor = _open_root(root_path)
    try:
        root_status = os.fstat(root_descriptor)
        repository = _snapshot_with_open_root(
            root_path,
            root_descriptor,
            root_status,
            git_executable,
            checked_limits,
        )
        _root_is_unchanged(root_path, root_status)
        repository_kind = repository["logical_state"]["kind"]  # type: ignore[index]
        if repository_kind == "git_bare":
            return _source_base(
                disposition="pass_through",
                reason="bare_repository",
                path_bytes=path_bytes,
                repository=repository,
            )
        if repository_kind == "unresolved":
            return _source_base(
                disposition="pass_through",
                reason="repository_state_unresolved",
                path_bytes=path_bytes,
                repository=repository,
            )

        if repository_kind == "git_worktree":
            index_before = _observe_source_index(
                root_descriptor,
                checked_relative_path,
                path_bytes,
                git_executable,
                checked_limits,
            )
            index_failure_reasons = {
                "not_regular": "source_not_regular",
                "sparse": "sparse_path",
                "symlink": "source_symlink",
                "unavailable": "git_index_unavailable",
                "unmerged": "unmerged_path",
            }
            if index_before.outcome != "usable":
                return _source_base(
                    disposition="pass_through",
                    reason=index_failure_reasons[index_before.outcome],
                    path_bytes=path_bytes,
                    repository=repository,
                )
        else:
            index_before = _IndexObservation(
                "usable", {"status": "not_applicable"}
            )

        try:
            file_read = _read_stable_file(
                root_descriptor, checked_relative_path, checked_limits
            )
        except IdentityError as error:
            if error.code not in {
                "source_changed_during_read",
                "source_missing",
                "source_not_regular",
                "source_symlink",
            }:
                raise
            return _source_base(
                disposition="pass_through",
                reason=error.code,
                path_bytes=path_bytes,
                repository=repository,
            )
        _root_is_unchanged(root_path, root_status)

        repository_after = _snapshot_with_open_root(
            root_path,
            root_descriptor,
            root_status,
            git_executable,
            checked_limits,
        )
        before_repository_key = (
            repository["logical_state"]["state_sha256"],  # type: ignore[index]
            repository["instance"]["identity_sha256"],  # type: ignore[index]
        )
        after_repository_key = (
            repository_after["logical_state"]["state_sha256"],  # type: ignore[index]
            repository_after["instance"]["identity_sha256"],  # type: ignore[index]
        )
        if before_repository_key != after_repository_key:
            return _source_base(
                disposition="pass_through",
                reason="repository_state_changed",
                path_bytes=path_bytes,
                repository=repository_after,
            )
        if repository_kind == "git_worktree":
            index_after = _observe_source_index(
                root_descriptor,
                checked_relative_path,
                path_bytes,
                git_executable,
                checked_limits,
            )
            if (
                index_after.outcome != "usable"
                or index_before.entry != index_after.entry
            ):
                return _source_base(
                    disposition="pass_through",
                    reason="repository_state_changed",
                    path_bytes=path_bytes,
                    repository=repository_after,
                )
    finally:
        os.close(root_descriptor)

    payload = file_read.payload
    source_sha256 = hashlib.sha256(payload).hexdigest()
    instance_sha256 = repository["instance"]["identity_sha256"]  # type: ignore[index]
    logical_state_sha256 = repository["logical_state"]["state_sha256"]  # type: ignore[index]
    if index_before.entry is None:
        raise IdentityError("git_index_unavailable")
    source_identity_sha256 = framed_sha256_hex(
        "contextguard-receipt/raw-file/v1",
        bytes.fromhex(logical_state_sha256),  # type: ignore[arg-type]
        bytes.fromhex(instance_sha256),  # type: ignore[arg-type]
        path_bytes,
        file_read.file_type.encode("ascii"),
        file_read.mode.encode("ascii"),
        canonical_json_bytes(index_before.entry),
        payload,
    )
    source = {
        "byte_length": len(payload),
        "content_sha256": source_sha256,
        "file_type": file_read.file_type,
        "git_index": index_before.entry,
        "identity_sha256": source_identity_sha256,
        "mode": file_read.mode,
    }

    explicit_range = (
        None
        if byte_range is None
        else _validate_byte_range(byte_range, len(payload))
    )
    if symbol_evidence is None and explicit_range is None:
        result = _source_base(
            disposition="exact_file",
            reason="raw_file_identity",
            path_bytes=path_bytes,
            repository=repository,
        )
        result["selection"] = {
            "byte_length": len(payload),
            "content_sha256": source_sha256,
            "end_byte": len(payload),
            "identity_sha256": source_identity_sha256,
            "kind": "raw_file",
            "start_byte": 0,
        }
        result["source"] = source
        return result

    evidence_status = "absent"
    evidence_range: tuple[int, int] | None = None
    if symbol_evidence is not None:
        evidence_status, evidence_range = _complete_symbol_range(
            symbol_evidence,
            evidence_bytes,
            payload,
            explicit_range,
        )
    selected_range = evidence_range if evidence_range is not None else explicit_range
    if selected_range is None:
        result = _source_base(
            disposition="pass_through",
            reason=evidence_status,
            path_bytes=path_bytes,
            repository=repository,
        )
        result["source"] = source
        return result

    start_byte, end_byte = selected_range
    selected_bytes = payload[start_byte:end_byte]
    selection_identity_sha256 = framed_sha256_hex(
        "contextguard-receipt/raw-byte-range/v1",
        bytes.fromhex(source_identity_sha256),
        str(start_byte).encode("ascii"),
        str(end_byte).encode("ascii"),
        selected_bytes,
    )
    selection = {
        "byte_length": len(selected_bytes),
        "content_sha256": hashlib.sha256(selected_bytes).hexdigest(),
        "end_byte": end_byte,
        "identity_sha256": selection_identity_sha256,
        "kind": "raw_range",
        "start_byte": start_byte,
    }

    if evidence_status == "complete":
        evidence_sha256 = framed_sha256_hex(
            "contextguard-receipt/caller-symbol-evidence/v1",
            evidence_bytes,  # type: ignore[arg-type]
        )
        symbol_identity_sha256 = framed_sha256_hex(
            "contextguard-receipt/caller-symbol/v1",
            bytes.fromhex(selection_identity_sha256),
            bytes.fromhex(evidence_sha256),
        )
        result = _source_base(
            disposition="exact_symbol",
            reason="caller_complete_deterministic_symbol_evidence",
            path_bytes=path_bytes,
            repository=repository,
        )
        result["symbol"] = {
            "authority": "caller_supplied",
            "evidence_sha256": evidence_sha256,
            "identity_sha256": symbol_identity_sha256,
        }
    else:
        reason = (
            "raw_range_without_symbol_authority"
            if symbol_evidence is None
            else evidence_status
        )
        result = _source_base(
            disposition="range_candidate",
            reason=reason,
            path_bytes=path_bytes,
            repository=repository,
        )
    result["selection"] = selection
    result["source"] = source
    return result
