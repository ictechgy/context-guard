"""Bounded non-reflective binary I/O for the receipt companion CLI."""

from __future__ import annotations

import os
import stat
import sys
from typing import Final


MAX_DESCRIPTOR_BYTES: Final = 2 * 1024 * 1024
MAX_RECEIPT_BYTES: Final = 256 * 1024


class CliIOError(OSError):
    """Stable I/O failure whose message never contains caller data."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _raise(code: str) -> None:
    raise CliIOError(code) from None


def _read_all(descriptor: int, maximum_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        try:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - total))
        except OSError:
            _raise("descriptor_unreadable")
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum_bytes:
            _raise("descriptor_too_large")


def _stable_file(status: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def read_descriptor(argument: str, *, maximum_bytes: int = MAX_DESCRIPTOR_BYTES) -> bytes:
    """Read stdin or one stable regular non-symlink without reflecting its path."""

    if type(argument) is not str or type(maximum_bytes) is not int or maximum_bytes <= 0:
        _raise("invalid_io_argument")
    if argument == "-":
        raw = sys.stdin.buffer.read(maximum_bytes + 1)
        if len(raw) > maximum_bytes:
            _raise("descriptor_too_large")
        return raw

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(argument, flags)
    except OSError:
        _raise("descriptor_unreadable")
    try:
        try:
            before = os.fstat(descriptor)
        except OSError:
            _raise("descriptor_unreadable")
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum_bytes:
            _raise("descriptor_unreadable")
        raw = _read_all(descriptor, maximum_bytes)
        try:
            after = os.fstat(descriptor)
        except OSError:
            _raise("descriptor_unreadable")
        if _stable_file(before) != _stable_file(after) or len(raw) != after.st_size:
            _raise("descriptor_unstable")
        return raw
    finally:
        os.close(descriptor)


def write_stdout(payload: bytes) -> None:
    if type(payload) is not bytes:
        _raise("invalid_io_argument")
    try:
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()
    except OSError:
        _raise("stdout_unwritable")


def write_receipt(path: str, payload: bytes) -> None:
    """Create a new private receipt without following or replacing a path."""

    if (
        type(path) is not str
        or not os.path.isabs(path)
        or os.path.normpath(path) != path
        or type(payload) is not bytes
        or len(payload) > MAX_RECEIPT_BYTES
    ):
        _raise("receipt_unwritable")
    parent_path = os.path.dirname(path)
    leaf_name = os.path.basename(path)
    if not parent_path or leaf_name in {"", ".", ".."}:
        _raise("receipt_unwritable")
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        parent_descriptor = os.open(parent_path, directory_flags)
    except OSError:
        _raise("receipt_unwritable")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor: int | None = None
    created_identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(leaf_name, flags, 0o600, dir_fd=parent_descriptor)
        created = os.fstat(descriptor)
        created_identity = (created.st_dev, created.st_ino)
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                _raise("receipt_unwritable")
            offset += written
        os.fsync(descriptor)
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or stat.S_IMODE(status.st_mode) != 0o600
            or status.st_size != len(payload)
            or (status.st_dev, status.st_ino) != created_identity
        ):
            _raise("receipt_unwritable")
        os.fsync(parent_descriptor)
    except (CliIOError, OSError):
        if created_identity is not None:
            try:
                current = os.stat(
                    leaf_name, dir_fd=parent_descriptor, follow_symlinks=False
                )
                if (current.st_dev, current.st_ino) == created_identity:
                    os.unlink(leaf_name, dir_fd=parent_descriptor)
                    os.fsync(parent_descriptor)
            except OSError:
                pass
        _raise("receipt_unwritable")
    finally:
        for open_descriptor in (descriptor, parent_descriptor):
            if open_descriptor is not None:
                try:
                    os.close(open_descriptor)
                except OSError:
                    pass
