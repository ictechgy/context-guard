"""Bounded local command capture with sanitized, canonical framed storage."""

from __future__ import annotations

import ctypes
import errno
import inspect
import math
import os
import select
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field, fields
from enum import Enum
from typing import Callable, Final

from . import sanitizer as _sanitizer
from .canonical import canonical_json_bytes, framed_sha256_hex
from .contracts import evidence_boundary
from .identity import snapshot_repository
from .store import ArtifactRequest, ArtifactType, StoreError, StoreErrorCode


__all__ = [
    "CHANNEL_STDERR",
    "CHANNEL_STDOUT",
    "FRAME_MAGIC",
    "CaptureFrame",
    "CommandCaptureReceipt",
    "CommandOutcome",
    "CommandOutcomeKind",
    "CommandRunResult",
    "RunnerErrorCode",
    "RunnerLimits",
    "frame_sanitized_capture",
    "map_cli_exit_code",
    "run_command",
    "validate_command_capture_receipt",
    "validate_framed_capture",
]


FRAME_MAGIC: Final = b"CGRF1\x00"
CHANNEL_STDOUT: Final = 1
CHANNEL_STDERR: Final = 2
_FRAME_PAYLOAD_BYTES: Final = 4096
_FRAME_HEADER_BYTES: Final = 13
_HARD_CAPTURE_BYTES: Final = 900_000
_HARD_FRAMED_BYTES: Final = 902_879
_STORE_ARTIFACT_BYTES: Final = 1024 * 1024
_READ_BYTES: Final = 64 * 1024
_MAX_ARGV_ITEMS: Final = 256
_MAX_ARGV_BYTES: Final = 256 * 1024
_MAX_TRACKED_PROCESSES: Final = 256
_TERMINATION_GRACE_SECONDS: Final = 0.5
_PROCESS_TABLE_EXECUTABLE: Final = "/bin/ps"
_PROCESS_TABLE_ARGUMENTS: Final = (
    _PROCESS_TABLE_EXECUTABLE,
    "-A",
    "-o",
    "pid=,ppid=,pgid=,ruid=,state=",
)
_PROCESS_TABLE_MAX_BYTES: Final = 8 * 1024 * 1024
_PROCESS_TABLE_READ_BYTES: Final = 64 * 1024
_PROCESS_TABLE_SCAN_SECONDS: Final = 0.25
_QUIESCENCE_OBSERVATIONS: Final = 2
_DARWIN_LIBPROC_PATH: Final = "/usr/lib/libproc.dylib"
_DARWIN_LIBSYSTEM_PATH: Final = "/usr/lib/libSystem.B.dylib"
_DARWIN_PROC_PIDTBSDINFO: Final = 3
_DARWIN_PROC_STATUS_ZOMBIE: Final = 5
_DARWIN_TASK_AUDIT_TOKEN: Final = 15
_DARWIN_TASK_AUDIT_TOKEN_COUNT: Final = 8
_DARWIN_EXACT_ATTEMPTS: Final = 3
_DARWIN_MACH_SEND_INVALID_DEST: Final = 0x10000003
_DARWIN_KERN_INVALID_ARGUMENT: Final = 4
_PROC_FILE_MAX_BYTES: Final = 64 * 1024
_PIDFD_UNSUPPORTED_ERRNOS: Final = frozenset(
    {
        errno.EACCES,
        errno.EINVAL,
        errno.ENOSYS,
        errno.ENOTSUP,
        errno.EPERM,
    }
)
_RECEIPT_SCHEMA_VERSION: Final = "contextguard-receipt-command-capture/v1"
_FIXED_ENVIRONMENT: Final = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
_EXEC_TRAMPOLINE: Final = (
    "import os,sys\n"
    "root_fd=int(sys.argv[1]); error_fd=int(sys.argv[2]); start_fd=int(sys.argv[3]); target=tuple(sys.argv[4:])\n"
    "try:\n"
    " marker=os.read(start_fd,1)\n"
    " os.close(start_fd)\n"
    " if marker != b'G': raise OSError\n"
    " os.fchdir(root_fd)\n"
    " os.close(root_fd)\n"
    " os.set_inheritable(error_fd,False)\n"
    " os.execv(target[0],target)\n"
    "except BaseException:\n"
    " try: os.write(error_fd,b'E')\n"
    " except BaseException: pass\n"
    " os._exit(127)\n"
)
_EXEC_ERROR_MARKER: Final = b"E"
_EXEC_START_MARKER: Final = b"G"


class RunnerErrorCode(str, Enum):
    INVALID_ARGUMENT = "invalid_argument"
    UNSUPPORTED_PLATFORM = "unsupported_platform"
    SNAPSHOT_UNRESOLVED = "snapshot_unresolved"
    REPOSITORY_REPLACED = "repository_replaced"
    SPAWN_FAILED = "spawn_failed"
    READ_FAILED = "read_failed"
    RAW_LIMIT_EXCEEDED = "raw_limit_exceeded"
    SANITIZATION_INCOMPLETE = "sanitization_incomplete"
    FRAMED_LIMIT_EXCEEDED = "framed_limit_exceeded"
    TIMEOUT = "timeout"
    INTERNAL = "internal"
    STORE_FAILED = "store_failed"
    DELIVERY_FAILED = "delivery_failed"
    COMMIT_UNCERTAIN = "commit_uncertain"


class CommandOutcomeKind(str, Enum):
    EXITED = "exited"
    SIGNALED = "signaled"


@dataclass(frozen=True, slots=True)
class RunnerLimits:
    raw_per_channel_bytes: int = _HARD_CAPTURE_BYTES
    raw_total_bytes: int = _HARD_CAPTURE_BYTES
    sanitized_per_channel_bytes: int = _HARD_CAPTURE_BYTES
    sanitized_total_bytes: int = _HARD_CAPTURE_BYTES
    framed_bytes: int = _HARD_FRAMED_BYTES
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        byte_maximums = {
            "raw_per_channel_bytes": _HARD_CAPTURE_BYTES,
            "raw_total_bytes": _HARD_CAPTURE_BYTES,
            "sanitized_per_channel_bytes": _HARD_CAPTURE_BYTES,
            "sanitized_total_bytes": _HARD_CAPTURE_BYTES,
            "framed_bytes": _HARD_FRAMED_BYTES,
        }
        for item in fields(self):
            value = getattr(self, item.name)
            if item.name == "timeout_seconds":
                if (
                    type(value) not in (int, float)
                    or not math.isfinite(value)
                    or value <= 0
                    or value > 3600
                ):
                    raise ValueError(RunnerErrorCode.INVALID_ARGUMENT.value)
            elif type(value) is not int or value < 0 or value > byte_maximums[item.name]:
                raise ValueError(RunnerErrorCode.INVALID_ARGUMENT.value)
        if self.raw_per_channel_bytes > self.raw_total_bytes:
            raise ValueError(RunnerErrorCode.INVALID_ARGUMENT.value)
        if self.sanitized_per_channel_bytes > self.sanitized_total_bytes:
            raise ValueError(RunnerErrorCode.INVALID_ARGUMENT.value)
        if self.framed_bytes >= _STORE_ARTIFACT_BYTES:
            raise ValueError(RunnerErrorCode.INVALID_ARGUMENT.value)


@dataclass(frozen=True, slots=True)
class CaptureFrame:
    sequence: int
    channel: int
    payload: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class CommandOutcome:
    kind: CommandOutcomeKind
    exit_code: int | None = None
    signal: int | None = None

    def to_receipt(self) -> dict[str, object]:
        result: dict[str, object] = {"kind": self.kind.value}
        if self.kind is CommandOutcomeKind.EXITED:
            result["exit_code"] = self.exit_code
        else:
            result["signal"] = self.signal
        return result


@dataclass(frozen=True, slots=True)
class _ChannelSummary:
    sanitized_bytes: int
    frame_count: int
    argument_derived_output_redacted: bool
    excerpt: str = field(repr=False)

    def to_receipt(self) -> dict[str, object]:
        return {
            "argument_derived_output_redacted": self.argument_derived_output_redacted,
            "excerpt": self.excerpt,
            "frame_count": self.frame_count,
            "sanitized_bytes": self.sanitized_bytes,
        }


@dataclass(frozen=True, slots=True)
class CommandCaptureReceipt:
    handle: str = field(repr=False)
    namespace_id: str
    artifact_bytes: int
    artifact_digest_sha256: str
    subject_identity_sha256: str
    before_observation_sha256: str
    after_observation_sha256: str
    outcome: CommandOutcome
    stdout: _ChannelSummary
    stderr: _ChannelSummary

    def to_receipt(self) -> dict[str, object]:
        return {
            "artifact": {
                "artifact_type": ArtifactType.COMMAND_CAPTURE_BYTES.value,
                "byte_length": self.artifact_bytes,
                "digest_sha256": self.artifact_digest_sha256,
                "subject_identity_sha256": self.subject_identity_sha256,
            },
            "evidence_boundary": evidence_boundary(),
            "handle": self.handle,
            "namespace_id": self.namespace_id,
            "observation": {
                "after_sha256": self.after_observation_sha256,
                "before_sha256": self.before_observation_sha256,
                "scope": "worktree",
            },
            "outcome": self.outcome.to_receipt(),
            "schema_version": _RECEIPT_SCHEMA_VERSION,
            "status": "captured",
            "stderr": self.stderr.to_receipt(),
            "stdout": self.stdout.to_receipt(),
        }


@dataclass(frozen=True, slots=True)
class CommandRunResult:
    error_code: RunnerErrorCode | None
    receipt: CommandCaptureReceipt | None = field(default=None, repr=False)

    @property
    def succeeded(self) -> bool:
        return self.receipt is not None and self.error_code is None

    def to_receipt(self) -> dict[str, object]:
        if self.receipt is not None:
            return self.receipt.to_receipt()
        return {
            "evidence_boundary": evidence_boundary(),
            "reason": (
                self.error_code.value
                if self.error_code is not None
                else RunnerErrorCode.INTERNAL.value
            ),
            "schema_version": _RECEIPT_SCHEMA_VERSION,
            "status": "refused",
        }


class _RunnerAbort(Exception):
    __slots__ = ("code",)

    def __init__(self, code: RunnerErrorCode) -> None:
        self.code = code
        super().__init__(code.value)


class _PinnedRoot:
    """An object-capability for the exact directory selected before snapshotting."""

    __slots__ = ("descriptor", "device", "inode", "path")

    def __init__(self, path: str) -> None:
        descriptor = -1
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        if no_follow == 0 or getattr(os, "O_DIRECTORY", 0) == 0:
            raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM)
        try:
            path_status = os.stat(path, follow_symlinks=False)
            if stat.S_ISLNK(path_status.st_mode) or not stat.S_ISDIR(path_status.st_mode):
                raise OSError
            descriptor = os.open(path, flags | no_follow)
            descriptor_status = os.fstat(descriptor)
        except OSError:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise _RunnerAbort(RunnerErrorCode.SNAPSHOT_UNRESOLVED) from None
        if (
            not stat.S_ISDIR(descriptor_status.st_mode)
            or descriptor_status.st_dev != path_status.st_dev
            or descriptor_status.st_ino != path_status.st_ino
        ):
            os.close(descriptor)
            raise _RunnerAbort(RunnerErrorCode.SNAPSHOT_UNRESOLVED)
        self.path = path
        self.descriptor = descriptor
        self.device = descriptor_status.st_dev
        self.inode = descriptor_status.st_ino

    def require_current(self) -> None:
        try:
            current = os.stat(self.path, follow_symlinks=False)
            pinned = os.fstat(self.descriptor)
        except OSError:
            raise _RunnerAbort(RunnerErrorCode.REPOSITORY_REPLACED) from None
        if (
            not stat.S_ISDIR(current.st_mode)
            or not stat.S_ISDIR(pinned.st_mode)
            or current.st_dev != self.device
            or current.st_ino != self.inode
            or pinned.st_dev != self.device
            or pinned.st_ino != self.inode
        ):
            raise _RunnerAbort(RunnerErrorCode.REPOSITORY_REPLACED)

    def close(self) -> None:
        descriptor = self.descriptor
        self.descriptor = -1
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


class _SignalGuard:
    """Convert one interrupt into unwinding and defer repeats until cleanup ends."""

    __slots__ = (
        "cleaning",
        "deferred",
        "interrupt_started",
        "pending_signum",
        "previous_int",
        "previous_term",
    )

    def __init__(self) -> None:
        self.cleaning = False
        self.deferred = True
        self.interrupt_started = False
        self.pending_signum: int | None = None
        self.previous_int: object | None = None
        self.previous_term: object | None = None

    def _raise_interrupt(self, signum: int) -> None:
        self.interrupt_started = True
        self.pending_signum = None
        if signum == signal.SIGINT:
            raise KeyboardInterrupt
        raise SystemExit(128 + signum)

    def _handle(self, signum: int, _frame: object) -> None:
        if self.cleaning or self.deferred:
            if not self.interrupt_started and self.pending_signum is None:
                self.pending_signum = signum
            return
        self._raise_interrupt(signum)

    def install(self) -> None:
        if threading.current_thread() is not threading.main_thread():
            raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM)
        try:
            previous_int = signal.getsignal(signal.SIGINT)
            previous_term = signal.getsignal(signal.SIGTERM)
        except (OSError, ValueError):
            raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM) from None
        if previous_int is not signal.default_int_handler or previous_term != signal.SIG_DFL:
            raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM)
        self.previous_int = previous_int
        self.previous_term = previous_term
        try:
            signal.signal(signal.SIGTERM, self._handle)
            signal.signal(signal.SIGINT, self._handle)
        except (OSError, ValueError):
            try:
                signal.signal(signal.SIGINT, previous_int)
            except (OSError, ValueError):
                pass
            try:
                signal.signal(signal.SIGTERM, previous_term)
            except (OSError, ValueError):
                pass
            self.previous_int = None
            self.previous_term = None
            raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM) from None
        self.resume_interrupts()

    def defer_interrupts(self) -> None:
        self.deferred = True

    def resume_interrupts(self) -> None:
        self.deferred = False
        if not self.interrupt_started and self.pending_signum is not None:
            self._raise_interrupt(self.pending_signum)

    def begin_cleanup(self) -> None:
        self.cleaning = True

    def restore(self) -> None:
        previous_int = self.previous_int
        previous_term = self.previous_term
        if previous_term is not None:
            try:
                signal.signal(signal.SIGTERM, previous_term)
            except (OSError, ValueError):
                pass
        if previous_int is not None:
            try:
                signal.signal(signal.SIGINT, previous_int)
            except (OSError, ValueError):
                pass
        self.previous_int = None
        self.previous_term = None

    def raise_pending_after_cleanup(self) -> None:
        if not self.interrupt_started and self.pending_signum is not None:
            self._raise_interrupt(self.pending_signum)


def _failure(code: RunnerErrorCode) -> CommandRunResult:
    return CommandRunResult(error_code=code)


def _require_bytes(value: object) -> bytes:
    if type(value) is not bytes:
        raise ValueError(RunnerErrorCode.INVALID_ARGUMENT.value)
    return value


def frame_sanitized_capture(stdout: bytes, stderr: bytes) -> bytes:
    """Serialize two already-sanitized channel projections in canonical order."""

    checked_stdout = _require_bytes(stdout)
    checked_stderr = _require_bytes(stderr)
    if len(checked_stdout) > _HARD_CAPTURE_BYTES or len(checked_stderr) > _HARD_CAPTURE_BYTES:
        raise ValueError(RunnerErrorCode.FRAMED_LIMIT_EXCEEDED.value)
    if len(checked_stdout) + len(checked_stderr) > _HARD_CAPTURE_BYTES:
        raise ValueError(RunnerErrorCode.FRAMED_LIMIT_EXCEEDED.value)

    output = bytearray(FRAME_MAGIC)
    sequence = 0
    for channel, payload in (
        (CHANNEL_STDOUT, checked_stdout),
        (CHANNEL_STDERR, checked_stderr),
    ):
        for offset in range(0, len(payload), _FRAME_PAYLOAD_BYTES):
            chunk = payload[offset : offset + _FRAME_PAYLOAD_BYTES]
            output.extend(sequence.to_bytes(8, "big"))
            output.append(channel)
            output.extend(len(chunk).to_bytes(4, "big"))
            output.extend(chunk)
            sequence += 1
    framed = bytes(output)
    if len(framed) > _HARD_FRAMED_BYTES:
        raise ValueError(RunnerErrorCode.FRAMED_LIMIT_EXCEEDED.value)
    return framed


def validate_framed_capture(raw: bytes) -> tuple[CaptureFrame, ...]:
    """Validate and decode the one canonical CGRF v1 representation."""

    checked = _require_bytes(raw)
    if len(checked) > _HARD_FRAMED_BYTES or not checked.startswith(FRAME_MAGIC):
        raise ValueError("invalid_framed_capture")
    cursor = len(FRAME_MAGIC)
    frames: list[CaptureFrame] = []
    expected_sequence = 0
    stderr_seen = False
    short_channel: set[int] = set()
    projections = {CHANNEL_STDOUT: bytearray(), CHANNEL_STDERR: bytearray()}
    while cursor < len(checked):
        if len(checked) - cursor < _FRAME_HEADER_BYTES:
            raise ValueError("invalid_framed_capture")
        sequence = int.from_bytes(checked[cursor : cursor + 8], "big")
        channel = checked[cursor + 8]
        length = int.from_bytes(checked[cursor + 9 : cursor + 13], "big")
        cursor += _FRAME_HEADER_BYTES
        if sequence != expected_sequence or channel not in projections:
            raise ValueError("invalid_framed_capture")
        if length < 1 or length > _FRAME_PAYLOAD_BYTES or len(checked) - cursor < length:
            raise ValueError("invalid_framed_capture")
        if channel == CHANNEL_STDOUT and stderr_seen:
            raise ValueError("invalid_framed_capture")
        if channel in short_channel:
            raise ValueError("invalid_framed_capture")
        if channel == CHANNEL_STDERR:
            stderr_seen = True
        if length < _FRAME_PAYLOAD_BYTES:
            short_channel.add(channel)
        payload = checked[cursor : cursor + length]
        cursor += length
        projections[channel].extend(payload)
        frames.append(CaptureFrame(sequence=sequence, channel=channel, payload=payload))
        expected_sequence += 1
    if cursor != len(checked):
        raise ValueError("invalid_framed_capture")
    if frame_sanitized_capture(
        bytes(projections[CHANNEL_STDOUT]), bytes(projections[CHANNEL_STDERR])
    ) != checked:
        raise ValueError("invalid_framed_capture")
    return tuple(frames)


def _validated_invocation(argv: object, root: object, limits: object) -> tuple[tuple[str, ...], str, RunnerLimits]:
    if type(argv) is not tuple or not argv or len(argv) > _MAX_ARGV_ITEMS:
        raise _RunnerAbort(RunnerErrorCode.INVALID_ARGUMENT)
    if any(type(item) is not str or "\x00" in item for item in argv):
        raise _RunnerAbort(RunnerErrorCode.INVALID_ARGUMENT)
    try:
        encoded_argv = tuple(item.encode("utf-8", errors="strict") for item in argv)
    except UnicodeEncodeError:
        raise _RunnerAbort(RunnerErrorCode.INVALID_ARGUMENT) from None
    if sum(len(item) for item in encoded_argv) > _MAX_ARGV_BYTES:
        raise _RunnerAbort(RunnerErrorCode.INVALID_ARGUMENT)
    if not os.path.isabs(argv[0]):
        raise _RunnerAbort(RunnerErrorCode.INVALID_ARGUMENT)
    if isinstance(root, bytes):
        raise _RunnerAbort(RunnerErrorCode.INVALID_ARGUMENT)
    try:
        root_path = os.fspath(root)
    except TypeError:
        raise _RunnerAbort(RunnerErrorCode.INVALID_ARGUMENT) from None
    if (
        type(root_path) is not str
        or not root_path
        or "\x00" in root_path
        or not os.path.isabs(root_path)
        or os.path.normpath(root_path) != root_path
    ):
        raise _RunnerAbort(RunnerErrorCode.INVALID_ARGUMENT)
    if type(limits) is not RunnerLimits:
        raise _RunnerAbort(RunnerErrorCode.INVALID_ARGUMENT)
    if os.name != "posix":
        raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM)
    return argv, root_path, limits


def _snapshotter_accepts_root_fd(snapshotter: Callable[..., object]) -> bool:
    if snapshotter is snapshot_repository:
        return True
    try:
        signature = inspect.signature(snapshotter)
    except (TypeError, ValueError):
        return False
    parameter = signature.parameters.get("root_fd")
    if parameter is None or parameter.kind not in (
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        inspect.Parameter.KEYWORD_ONLY,
    ):
        return False
    try:
        signature.bind(object(), root_fd=0)
    except TypeError:
        return False
    return True


def _freeze_snapshot(
    snapshotter: Callable[..., dict[str, object]], pin: _PinnedRoot
) -> tuple[bytes, str]:
    snapshot_root_fd = -1
    try:
        pin.require_current()
        if _snapshotter_accepts_root_fd(snapshotter):
            snapshot_root_fd = os.dup(pin.descriptor)
            snapshot = snapshotter(pin.path, root_fd=snapshot_root_fd)
        else:
            snapshot = snapshotter(pin.path)
        pin.require_current()
        if type(snapshot) is not dict or snapshot.get("disposition") != "captured":
            raise _RunnerAbort(RunnerErrorCode.SNAPSHOT_UNRESOLVED)
        if snapshot.get("evidence_boundary") != evidence_boundary():
            raise _RunnerAbort(RunnerErrorCode.SNAPSHOT_UNRESOLVED)
        instance = snapshot.get("instance")
        if type(instance) is not dict:
            raise _RunnerAbort(RunnerErrorCode.SNAPSHOT_UNRESOLVED)
        identity_sha256 = instance.get("identity_sha256")
        if (
            type(identity_sha256) is not str
            or len(identity_sha256) != 64
            or any(character not in "0123456789abcdef" for character in identity_sha256)
        ):
            raise _RunnerAbort(RunnerErrorCode.SNAPSHOT_UNRESOLVED)
        frozen = canonical_json_bytes(snapshot)
    except _RunnerAbort:
        raise
    except Exception:
        raise _RunnerAbort(RunnerErrorCode.SNAPSHOT_UNRESOLVED) from None
    finally:
        if snapshot_root_fd >= 0:
            try:
                os.close(snapshot_root_fd)
            except OSError:
                pass
    return frozen, identity_sha256


def _validated_private_roots(value: object) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise _RunnerAbort(RunnerErrorCode.INVALID_ARGUMENT)
    try:
        _sanitizer.sanitize_bytes(
            b"",
            limits=_sanitizer.SanitizerLimits(max_input_bytes=0, max_output_bytes=0),
            private_roots=value,
        )
    except (_sanitizer.SanitizationError, TypeError, ValueError):
        raise _RunnerAbort(RunnerErrorCode.INVALID_ARGUMENT) from None
    return value


def _close_pipe(pipe: object) -> None:
    close = getattr(pipe, "close", None)
    if callable(close):
        try:
            close()
        except Exception:
            pass


@dataclass(frozen=True, slots=True)
class _ProcessRecord:
    pid: int
    ppid: int
    pgid: int
    uid: int
    state: bytes


@dataclass(frozen=True, slots=True)
class _ExactProcessInfo:
    pid: int
    ppid: int
    pgid: int
    uid: int
    status: int
    birth: tuple[int, int] = field(repr=False)


class _ProcessGone(Exception):
    pass


class _ProcessTopologyChanged(Exception):
    pass


class _DarwinTaskTransition(Exception):
    pass


class _PinState(str, Enum):
    LIVE = "live"
    EXITED = "exited"


@dataclass(frozen=True, slots=True)
class _PinObservation:
    state: _PinState
    info: _ExactProcessInfo | None


def _inspect_pin(pin: object) -> _PinObservation:
    inspect_pin = getattr(pin, "inspect", None)
    if callable(inspect_pin):
        observation = inspect_pin()
        if type(observation) is not _PinObservation:
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        return observation
    current = pin.current()
    return _PinObservation(
        state=_PinState.LIVE if current is not None else _PinState.EXITED,
        info=current,
    )


class _DarwinProcBsdInfo(ctypes.Structure):
    _fields_ = (
        ("pbi_flags", ctypes.c_uint32),
        ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32),
        ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32),
        ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32),
        ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32),
        ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32),
        ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * 16),
        ("pbi_name", ctypes.c_char * 32),
        ("pbi_nfiles", ctypes.c_uint32),
        ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32),
        ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32),
        ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64),
        ("pbi_start_tvusec", ctypes.c_uint64),
    )


_DARWIN_LIBPROC_HANDLE: object | None = None
_DARWIN_MACH_HANDLE: object | None = None


def _darwin_libproc_handle() -> object:
    global _DARWIN_LIBPROC_HANDLE
    if _DARWIN_LIBPROC_HANDLE is None:
        try:
            handle = ctypes.CDLL(_DARWIN_LIBPROC_PATH, use_errno=True)
            proc_pidinfo = handle.proc_pidinfo
            proc_pidinfo.argtypes = (
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_uint64,
                ctypes.c_void_p,
                ctypes.c_int,
            )
            proc_pidinfo.restype = ctypes.c_int
            proc_signal = handle.proc_signal_with_audittoken
            proc_signal.argtypes = (ctypes.POINTER(ctypes.c_uint32), ctypes.c_int)
            proc_signal.restype = ctypes.c_int
        except (AttributeError, OSError):
            raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM) from None
        _DARWIN_LIBPROC_HANDLE = handle
    return _DARWIN_LIBPROC_HANDLE


def _darwin_mach_handle() -> object:
    global _DARWIN_MACH_HANDLE
    if _DARWIN_MACH_HANDLE is None:
        try:
            handle = ctypes.CDLL(_DARWIN_LIBSYSTEM_PATH, use_errno=True)
            handle.mach_task_self.argtypes = ()
            handle.mach_task_self.restype = ctypes.c_uint32
            handle.task_name_for_pid.argtypes = (
                ctypes.c_uint32,
                ctypes.c_int,
                ctypes.POINTER(ctypes.c_uint32),
            )
            handle.task_name_for_pid.restype = ctypes.c_int
            handle.task_info.argtypes = (
                ctypes.c_uint32,
                ctypes.c_int,
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_uint32),
            )
            handle.task_info.restype = ctypes.c_int
            handle.mach_port_deallocate.argtypes = (
                ctypes.c_uint32,
                ctypes.c_uint32,
            )
            handle.mach_port_deallocate.restype = ctypes.c_int
        except (AttributeError, OSError):
            raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM) from None
        _DARWIN_MACH_HANDLE = handle
    return _DARWIN_MACH_HANDLE


def _darwin_proc_pidinfo(pid: int) -> _ExactProcessInfo | None:
    if ctypes.sizeof(_DarwinProcBsdInfo) != 136:
        raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM)
    function = getattr(_darwin_libproc_handle(), "proc_pidinfo", None)
    if not callable(function):
        raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM)
    raw = _DarwinProcBsdInfo()
    ctypes.set_errno(0)
    result = function(
        pid,
        _DARWIN_PROC_PIDTBSDINFO,
        0,
        ctypes.byref(raw),
        ctypes.sizeof(raw),
    )
    if result <= 0:
        if ctypes.get_errno() in (0, errno.ESRCH):
            return None
        raise _RunnerAbort(RunnerErrorCode.INTERNAL)
    if result != ctypes.sizeof(raw):
        raise _RunnerAbort(RunnerErrorCode.INTERNAL)
    if (
        raw.pbi_pid != pid
        or raw.pbi_pid <= 0
        or raw.pbi_ppid > 2**31 - 1
        or raw.pbi_pgid > 2**31 - 1
        or raw.pbi_start_tvsec <= 0
        or raw.pbi_start_tvusec >= 1_000_000
    ):
        raise _RunnerAbort(RunnerErrorCode.INTERNAL)
    return _ExactProcessInfo(
        pid=int(raw.pbi_pid),
        ppid=int(raw.pbi_ppid),
        pgid=int(raw.pbi_pgid),
        uid=int(raw.pbi_ruid),
        status=int(raw.pbi_status),
        birth=(int(raw.pbi_start_tvsec), int(raw.pbi_start_tvusec)),
    )


def _darwin_open_task_name(pid: int) -> tuple[int, int] | None:
    if type(pid) is not int or pid <= 0:
        raise _RunnerAbort(RunnerErrorCode.INTERNAL)
    handle = _darwin_mach_handle()
    try:
        task_self = int(handle.mach_task_self())
        task_name = ctypes.c_uint32(0)
        result = int(handle.task_name_for_pid(task_self, pid, ctypes.byref(task_name)))
    except Exception:
        raise _RunnerAbort(RunnerErrorCode.INTERNAL) from None
    if result != 0:
        if _darwin_proc_pidinfo(pid) is None:
            return None
        raise _DarwinTaskTransition
    if task_name.value == 0:
        # task_name_for_pid succeeded but returned no send right: the target
        # crossed an exec/reuse transition while the request was in flight.
        raise _DarwinTaskTransition
    if task_self <= 0 or task_name.value <= 0:
        raise _RunnerAbort(RunnerErrorCode.INTERNAL)
    return task_self, int(task_name.value)


def _darwin_task_audit_token(task_name: int) -> tuple[int, ...]:
    if type(task_name) is not int or task_name <= 0:
        raise _RunnerAbort(RunnerErrorCode.INTERNAL)
    token = (ctypes.c_uint32 * _DARWIN_TASK_AUDIT_TOKEN_COUNT)()
    count = ctypes.c_uint32(_DARWIN_TASK_AUDIT_TOKEN_COUNT)
    try:
        result = int(
            _darwin_mach_handle().task_info(
                task_name,
                _DARWIN_TASK_AUDIT_TOKEN,
                ctypes.byref(token),
                ctypes.byref(count),
            )
        )
    except Exception:
        raise _RunnerAbort(RunnerErrorCode.INTERNAL) from None
    if result in (_DARWIN_MACH_SEND_INVALID_DEST, _DARWIN_KERN_INVALID_ARGUMENT):
        raise _DarwinTaskTransition
    if result != 0 or count.value != _DARWIN_TASK_AUDIT_TOKEN_COUNT:
        raise _RunnerAbort(RunnerErrorCode.INTERNAL)
    return tuple(int(item) for item in token)


def _darwin_deallocate_task_name(task_self: int, task_name: int) -> None:
    if (
        type(task_self) is not int
        or task_self <= 0
        or type(task_name) is not int
        or task_name <= 0
    ):
        raise _RunnerAbort(RunnerErrorCode.INTERNAL)
    try:
        result = int(_darwin_mach_handle().mach_port_deallocate(task_self, task_name))
    except Exception:
        raise _RunnerAbort(RunnerErrorCode.INTERNAL) from None
    if result != 0:
        raise _RunnerAbort(RunnerErrorCode.INTERNAL)


def _darwin_exact_process_snapshot(
    pid: int,
) -> tuple[tuple[int, ...], _ExactProcessInfo] | None:
    for attempt in range(_DARWIN_EXACT_ATTEMPTS):
        try:
            opened = _darwin_open_task_name(pid)
        except _DarwinTaskTransition:
            if attempt + 1 < _DARWIN_EXACT_ATTEMPTS:
                continue
            raise _RunnerAbort(RunnerErrorCode.INTERNAL) from None
        if opened is None:
            if attempt + 1 < _DARWIN_EXACT_ATTEMPTS:
                continue
            return None
        task_self, task_name = opened
        transition = False
        try:
            try:
                token_before = _darwin_task_audit_token(task_name)
                current = _darwin_proc_pidinfo(pid)
                token_after = _darwin_task_audit_token(task_name)
            except _DarwinTaskTransition:
                transition = True
        finally:
            _darwin_deallocate_task_name(task_self, task_name)
        if transition:
            if attempt + 1 < _DARWIN_EXACT_ATTEMPTS:
                continue
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        if current is None:
            if attempt + 1 < _DARWIN_EXACT_ATTEMPTS:
                continue
            return None
        if token_before != token_after:
            if attempt + 1 < _DARWIN_EXACT_ATTEMPTS:
                continue
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        if (
            len(token_before) != _DARWIN_TASK_AUDIT_TOKEN_COUNT
            or token_before[5] != pid
            or token_before[3] != current.uid
        ):
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        return token_before, current
    raise _RunnerAbort(RunnerErrorCode.INTERNAL)


def _darwin_signal_audit_token(token: tuple[int, ...], signal_number: int) -> bool:
    if (
        type(token) is not tuple
        or len(token) != _DARWIN_TASK_AUDIT_TOKEN_COUNT
        or any(type(item) is not int or item < 0 or item > 2**32 - 1 for item in token)
        or signal_number not in (signal.SIGTERM, signal.SIGKILL, signal.SIGCONT)
    ):
        raise _RunnerAbort(RunnerErrorCode.INTERNAL)
    raw = (ctypes.c_uint32 * _DARWIN_TASK_AUDIT_TOKEN_COUNT)(*token)
    function = getattr(_darwin_libproc_handle(), "proc_signal_with_audittoken", None)
    if not callable(function):
        raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM)
    ctypes.set_errno(0)
    try:
        result = int(function(raw, signal_number))
    except Exception:
        raise _RunnerAbort(RunnerErrorCode.INTERNAL) from None
    if result == 0:
        return True
    if result == errno.ESRCH or ctypes.get_errno() == errno.ESRCH:
        return False
    raise _RunnerAbort(RunnerErrorCode.INTERNAL)


class _DarwinProcessPin:
    __slots__ = ("audit_token", "birth", "closed", "last_info", "pid", "uid")

    exact_signals = True

    def __init__(self, pid: int) -> None:
        snapshot = _darwin_exact_process_snapshot(pid)
        if snapshot is None:
            raise _ProcessGone
        audit_token, current = snapshot
        self.pid = pid
        self.uid = current.uid
        self.birth = current.birth
        self.audit_token = audit_token
        self.last_info = current
        self.closed = False

    def current(self) -> _ExactProcessInfo | None:
        observation = self.inspect()
        return observation.info if observation.state is _PinState.LIVE else None

    def inspect(self) -> _PinObservation:
        if self.closed:
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        snapshot = _darwin_exact_process_snapshot(self.pid)
        if snapshot is None:
            return _PinObservation(_PinState.EXITED, self.last_info)
        audit_token, current = snapshot
        if current.uid != self.uid or current.birth != self.birth:
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        self.audit_token = audit_token
        self.last_info = current
        return _PinObservation(
            _PinState.EXITED
            if current.status == _DARWIN_PROC_STATUS_ZOMBIE
            else _PinState.LIVE,
            current,
        )

    def send_signal(self, signal_number: int) -> bool:
        for _attempt in range(_DARWIN_EXACT_ATTEMPTS):
            if self.current() is None:
                return False
            if _darwin_signal_audit_token(self.audit_token, signal_number):
                return True
        return False

    def close(self) -> None:
        self.closed = True


def _read_proc_file(pid: int, name: str) -> bytes:
    if type(pid) is not int or pid <= 0 or name not in ("stat", "status"):
        raise _RunnerAbort(RunnerErrorCode.INTERNAL)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    if no_follow == 0 or close_on_exec == 0:
        raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM)
    descriptor = -1
    output = bytearray()
    try:
        try:
            descriptor = os.open(
                f"/proc/{pid}/{name}", os.O_RDONLY | no_follow | close_on_exec
            )
        except (FileNotFoundError, ProcessLookupError):
            raise _ProcessGone from None
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        while True:
            chunk = os.read(descriptor, min(4096, _PROC_FILE_MAX_BYTES + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > _PROC_FILE_MAX_BYTES:
                raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        return bytes(output)
    finally:
        output.clear()
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _pidfd_is_dead(descriptor: int) -> bool:
    try:
        poller = select.poll()
        poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
        return bool(poller.poll(0))
    except (OSError, ValueError):
        raise _RunnerAbort(RunnerErrorCode.INTERNAL) from None


def _linux_numeric_proc_pidinfo(pid: int) -> _ExactProcessInfo | None:
    try:
        stat_raw = _read_proc_file(pid, "stat")
        status_raw = _read_proc_file(pid, "status")
    except _ProcessGone:
        return None
    close_paren = stat_raw.rfind(b") ")
    if close_paren <= 0:
        raise _RunnerAbort(RunnerErrorCode.INTERNAL)
    try:
        parsed_pid = int(stat_raw[: stat_raw.find(b" ")], 10)
        fields = stat_raw[close_paren + 2 :].split()
        process_state = fields[0]
        ppid = int(fields[1], 10)
        pgid = int(fields[2], 10)
        start_ticks = int(fields[19], 10)
    except (IndexError, ValueError):
        raise _RunnerAbort(RunnerErrorCode.INTERNAL) from None
    uid_lines = [line.split() for line in status_raw.splitlines() if line.startswith(b"Uid:")]
    if len(uid_lines) != 1 or len(uid_lines[0]) != 5:
        raise _RunnerAbort(RunnerErrorCode.INTERNAL)
    try:
        uid = int(uid_lines[0][1], 10)
        native_pgid = os.getpgid(pid)
    except ProcessLookupError:
        return None
    except (OSError, ValueError):
        raise _RunnerAbort(RunnerErrorCode.INTERNAL) from None
    if (
        parsed_pid != pid
        or ppid < 0
        or pgid <= 0
        or pgid != native_pgid
        or uid < 0
        or start_ticks <= 0
    ):
        raise _RunnerAbort(RunnerErrorCode.INTERNAL)
    return _ExactProcessInfo(
        pid=pid,
        ppid=ppid,
        pgid=pgid,
        uid=uid,
        status=_DARWIN_PROC_STATUS_ZOMBIE if process_state == b"Z" else 0,
        birth=(start_ticks, 0),
    )


class _LinuxProcessPin:
    __slots__ = ("birth", "closed", "descriptor", "pid", "uid")

    exact_signals = True

    def __init__(self, pid: int) -> None:
        pidfd_open = getattr(os, "pidfd_open", None)
        if not callable(pidfd_open):
            raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM)
        descriptor = -1
        try:
            try:
                descriptor = pidfd_open(pid, 0)
            except OSError as error:
                code = (
                    RunnerErrorCode.UNSUPPORTED_PLATFORM
                    if error.errno in _PIDFD_UNSUPPORTED_ERRNOS
                    else RunnerErrorCode.INTERNAL
                )
                raise _RunnerAbort(code) from None
            os.set_inheritable(descriptor, False)
            observation = self._inspect_open(pid, descriptor, None)
            if observation.state is not _PinState.LIVE or observation.info is None:
                raise _ProcessGone
        except BaseException:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise
        self.pid = pid
        self.descriptor = descriptor
        self.uid = observation.info.uid
        self.birth = observation.info.birth
        self.closed = False

    @staticmethod
    def _inspect_open(
        pid: int,
        descriptor: int,
        identity: tuple[int, tuple[int, int]] | None,
    ) -> _PinObservation:
        dead_before = _pidfd_is_dead(descriptor)
        current = _linux_numeric_proc_pidinfo(pid)
        dead_after = _pidfd_is_dead(descriptor)
        if current is not None and identity is not None:
            if (current.uid, current.birth) != identity:
                raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        if dead_before or dead_after:
            return _PinObservation(_PinState.EXITED, current)
        if current is None:
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        return _PinObservation(_PinState.LIVE, current)

    def current(self) -> _ExactProcessInfo | None:
        observation = self.inspect()
        return observation.info if observation.state is _PinState.LIVE else None

    def inspect(self) -> _PinObservation:
        if self.closed:
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        return self._inspect_open(
            self.pid, self.descriptor, (self.uid, self.birth)
        )

    def send_signal(self, signal_number: int) -> bool:
        if self.current() is None:
            return False
        pidfd_send_signal = getattr(signal, "pidfd_send_signal", None)
        if not callable(pidfd_send_signal):
            raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM)
        try:
            pidfd_send_signal(self.descriptor, signal_number, None, 0)
            return True
        except ProcessLookupError:
            return False
        except OSError as error:
            code = (
                RunnerErrorCode.UNSUPPORTED_PLATFORM
                if error.errno in _PIDFD_UNSUPPORTED_ERRNOS
                else RunnerErrorCode.INTERNAL
            )
            raise _RunnerAbort(code) from None

    def close(self) -> None:
        descriptor = self.descriptor
        self.descriptor = -1
        self.closed = True
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _pin_process(pid: int) -> object:
    if sys.platform == "darwin":
        return _DarwinProcessPin(pid)
    if sys.platform.startswith("linux"):
        return _LinuxProcessPin(pid)
    raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM)


def _require_process_pinning() -> None:
    if sys.platform.startswith("linux") and (
        not callable(getattr(os, "pidfd_open", None))
        or not callable(getattr(signal, "pidfd_send_signal", None))
    ):
        raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM)
    pin: object | None = None
    try:
        pin = _pin_process(os.getpid())
        current = pin.current()
        if current is None or current.pid != os.getpid() or current.uid != os.getuid():
            raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM)
        probe_signal = signal.SIGCONT if sys.platform == "darwin" else 0
        if not pin.send_signal(probe_signal):
            raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM)
    except _ProcessGone:
        raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM) from None
    except _RunnerAbort as error:
        if error.code is RunnerErrorCode.UNSUPPORTED_PLATFORM:
            raise
        raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM) from None
    except Exception:
        raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM) from None
    finally:
        if pin is not None:
            try:
                pin.close()
            except Exception:
                pass


def _require_process_table_executable() -> None:
    path = _PROCESS_TABLE_EXECUTABLE
    if type(path) is not str or path != "/bin/ps":
        raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM)
    try:
        status = os.stat(path, follow_symlinks=True)
    except OSError:
        raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM) from None
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_uid != 0
        or status.st_mode & 0o022
        or not os.access(path, os.X_OK)
    ):
        raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM)


def _parse_process_table(raw: bytes) -> dict[int, _ProcessRecord]:
    if type(raw) is not bytes or not raw or len(raw) > _PROCESS_TABLE_MAX_BYTES:
        raise _RunnerAbort(RunnerErrorCode.INTERNAL)
    records: dict[int, _ProcessRecord] = {}
    for line in raw.splitlines():
        if not line.strip():
            continue
        if len(line) > 64:
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        parts = line.split()
        if len(parts) != 5:
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        try:
            pid, ppid, pgid, uid = (int(item, 10) for item in parts[:4])
        except ValueError:
            raise _RunnerAbort(RunnerErrorCode.INTERNAL) from None
        process_state = parts[4]
        if (
            pid <= 0
            or pid > 2**31 - 1
            or ppid < 0
            or ppid > 2**31 - 1
            or pgid < 0
            or pgid > 2**31 - 1
            or uid < 0
            or uid > 2**32 - 1
            or not process_state
            or len(process_state) > 8
            or any(item < 33 or item > 126 for item in process_state)
        ):
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        if pid in records:
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        records[pid] = _ProcessRecord(
            pid=pid,
            ppid=ppid,
            pgid=pgid,
            uid=uid,
            state=process_state,
        )
    if not records:
        raise _RunnerAbort(RunnerErrorCode.INTERNAL)
    return records


def _read_process_table(
    *, deadline: float, clock: Callable[[], float]
) -> dict[int, _ProcessRecord]:
    """Read a bounded numeric process table without exposing command text."""

    now = clock()
    if deadline <= now:
        raise _RunnerAbort(RunnerErrorCode.TIMEOUT)
    scan_budget = min(deadline - now, _PROCESS_TABLE_SCAN_SECONDS)
    scan_deadline = time.monotonic() + scan_budget
    process: subprocess.Popen[bytes] | None = None
    pin: object | None = None
    pipe: object | None = None
    selected: selectors.BaseSelector | None = None
    output = bytearray()
    try:
        try:
            process = subprocess.Popen(
                _PROCESS_TABLE_ARGUMENTS,
                shell=False,
                cwd="/",
                env=dict(_FIXED_ENVIRONMENT),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=False,
                bufsize=0,
            )
        except OSError:
            raise _RunnerAbort(RunnerErrorCode.INTERNAL) from None
        pipe = process.stdout
        if pipe is None:
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        try:
            pin = _pin_process(process.pid)
        except (_ProcessGone, _RunnerAbort):
            # The pin is a cleanup capability, not process-table evidence.
            # Hardened/short-lived helpers can reject exact pinning; continue
            # draining and validating their bounded output, but never fall
            # back to numeric signaling if cleanup later needs a kill.
            pin = None
        os.set_blocking(pipe.fileno(), False)
        selected = selectors.DefaultSelector()
        selected.register(pipe, selectors.EVENT_READ)
        while selected.get_map():
            remaining = scan_deadline - time.monotonic()
            if remaining <= 0:
                code = (
                    RunnerErrorCode.TIMEOUT
                    if deadline <= clock()
                    else RunnerErrorCode.INTERNAL
                )
                raise _RunnerAbort(code)
            try:
                events = selected.select(min(remaining, 0.02))
            except OSError:
                raise _RunnerAbort(RunnerErrorCode.INTERNAL) from None
            for key, _mask in events:
                try:
                    chunk = os.read(key.fileobj.fileno(), _PROCESS_TABLE_READ_BYTES)
                except BlockingIOError:
                    continue
                except OSError:
                    raise _RunnerAbort(RunnerErrorCode.INTERNAL) from None
                if not chunk:
                    selected.unregister(key.fileobj)
                    break
                if len(output) + len(chunk) > _PROCESS_TABLE_MAX_BYTES:
                    raise _RunnerAbort(RunnerErrorCode.INTERNAL)
                output.extend(chunk)
        remaining = scan_deadline - time.monotonic()
        if remaining <= 0:
            code = (
                RunnerErrorCode.TIMEOUT
                if deadline <= clock()
                else RunnerErrorCode.INTERNAL
            )
            raise _RunnerAbort(code)
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            code = (
                RunnerErrorCode.TIMEOUT
                if deadline <= clock()
                else RunnerErrorCode.INTERNAL
            )
            raise _RunnerAbort(code) from None
        if returncode != 0:
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        return _parse_process_table(bytes(output))
    finally:
        output.clear()
        if selected is not None:
            try:
                selected.close()
            except Exception:
                pass
        _close_pipe(pipe)
        if process is not None and process.poll() is None:
            if pin is not None:
                try:
                    pin.send_signal(signal.SIGKILL)
                except Exception:
                    pass
            try:
                process.wait(timeout=_TERMINATION_GRACE_SECONDS)
            except Exception:
                pass
        if pin is not None:
            try:
                pin.close()
            except Exception:
                pass


class _DescendantTracker:
    """Track observed descendants; process-table sampling is not a sandbox.

    This tracks ordinary observed detached-process lifecycles and fails closed
    when an observation is malformed or unavailable. It cannot prove
    containment of a malicious daemon that detaches completely between bounded
    observations.
    """

    __slots__ = (
        "active_groups",
        "closed",
        "pin_factory",
        "pins",
        "root_pid",
        "runner_pgid",
        "runner_uid",
    )

    def __init__(
        self, root_pid: int, *, pin_factory: Callable[[int], object] | None = None
    ) -> None:
        if type(root_pid) is not int or root_pid <= 1:
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        try:
            runner_pgid = os.getpgrp()
            runner_uid = os.getuid()
        except OSError:
            raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM) from None
        if (
            type(runner_pgid) is not int
            or runner_pgid <= 0
            or type(runner_uid) is not int
            or runner_uid < 0
        ):
            raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM)
        self.root_pid = root_pid
        self.runner_pgid = runner_pgid
        self.runner_uid = runner_uid
        self.pin_factory = pin_factory if pin_factory is not None else _pin_process
        if not callable(self.pin_factory):
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        self.pins: dict[int, object] = {}
        self.active_groups: set[int] = set()
        self.closed = False

    @staticmethod
    def _crosscheck(record: _ProcessRecord, current: _ExactProcessInfo) -> None:
        if (
            record.pid != current.pid
            or record.ppid != current.ppid
            or record.pgid != current.pgid
            or record.uid != current.uid
        ):
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)

    def _adopt(self, record: _ProcessRecord) -> _ExactProcessInfo | None:
        if record.uid != self.runner_uid:
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        existing = self.pins.get(record.pid)
        if existing is not None:
            observation = _inspect_pin(existing)
            if observation.state is not _PinState.LIVE or observation.info is None:
                raise _RunnerAbort(RunnerErrorCode.INTERNAL)
            self._crosscheck(record, observation.info)
            return observation.info
        if len(self.pins) >= _MAX_TRACKED_PROCESSES:
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        pin: object | None = None
        try:
            pin = self.pin_factory(record.pid)
            observation = _inspect_pin(pin)
            if observation.state is not _PinState.LIVE or observation.info is None:
                return None
            current = observation.info
            if (
                record.pid == current.pid
                and record.uid == current.uid
                and (record.ppid != current.ppid or record.pgid != current.pgid)
            ):
                raise _ProcessTopologyChanged
            self._crosscheck(record, current)
            self.pins[record.pid] = pin
            pin = None
            return current
        except _ProcessGone:
            return None
        finally:
            if pin is not None:
                try:
                    pin.close()
                except Exception:
                    pass

    def establish(self, *, deadline: float, clock: Callable[[], float]) -> None:
        records = _read_process_table(deadline=deadline, clock=clock)
        root = records.get(self.root_pid)
        if (
            root is None
            or root.pgid != self.root_pid
            or root.pgid == self.runner_pgid
            or root.uid != self.runner_uid
        ):
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        current = self._adopt(root)
        if current is None:
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        self.active_groups.add(root.pgid)

    def probe_root_signal(self) -> None:
        pin = self.pins.get(self.root_pid)
        if pin is None or not bool(getattr(pin, "exact_signals", False)):
            raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM)
        probe_signal = signal.SIGCONT if sys.platform == "darwin" else 0
        try:
            delivered = pin.send_signal(probe_signal)
        except _RunnerAbort as error:
            if error.code is RunnerErrorCode.UNSUPPORTED_PLATFORM:
                raise
            raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM) from None
        except Exception:
            raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM) from None
        if not delivered:
            raise _RunnerAbort(RunnerErrorCode.UNSUPPORTED_PLATFORM)

    def observe(
        self, *, deadline: float, clock: Callable[[], float]
    ) -> tuple[_ExactProcessInfo, ...]:
        for attempt in range(2):
            retained_pids = frozenset(self.pins)
            retained_groups = frozenset(self.active_groups)
            try:
                return self._observe_once(deadline=deadline, clock=clock)
            except _ProcessTopologyChanged:
                added_pins = tuple(
                    self.pins.pop(pid)
                    for pid in tuple(self.pins)
                    if pid not in retained_pids
                )
                self.active_groups.clear()
                self.active_groups.update(retained_groups)
                for pin in added_pins:
                    try:
                        pin.close()
                    except Exception:
                        pass
                if attempt != 0:
                    raise _RunnerAbort(RunnerErrorCode.INTERNAL) from None
        raise _RunnerAbort(RunnerErrorCode.INTERNAL)

    def _observe_once(
        self, *, deadline: float, clock: Callable[[], float]
    ) -> tuple[_ExactProcessInfo, ...]:
        if self.closed:
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        records = _read_process_table(deadline=deadline, clock=clock)
        live: dict[int, _ExactProcessInfo] = {}
        for pid, pin in self.pins.items():
            observation = _inspect_pin(pin)
            record = records.get(pid)
            if observation.state is _PinState.EXITED:
                if record is not None and observation.info is None:
                    raise _RunnerAbort(RunnerErrorCode.INTERNAL)
                if record is not None and observation.info is not None:
                    self._crosscheck(record, observation.info)
                    if not record.state.startswith(b"Z"):
                        records = _read_process_table(deadline=deadline, clock=clock)
                        record = records.get(pid)
                        observation = _inspect_pin(pin)
                        if observation.state is not _PinState.EXITED:
                            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
                        if record is None:
                            continue
                        if observation.info is None:
                            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
                        self._crosscheck(record, observation.info)
                        if not record.state.startswith(b"Z"):
                            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
                continue
            current = observation.info
            if current is None:
                raise _RunnerAbort(RunnerErrorCode.INTERNAL)
            if record is None:
                raise _RunnerAbort(RunnerErrorCode.INTERNAL)
            self._crosscheck(record, current)
            live[pid] = current
        reusable_groups: set[int] = set()
        for group in self.active_groups:
            current_leader = records.get(group)
            expected_leader = self.pins.get(group)
            if current_leader is not None and expected_leader is None:
                reusable_groups.add(group)
        self.active_groups.difference_update(reusable_groups)
        while True:
            anchored_groups = frozenset(
                record.pgid for record in live.values() if record.pgid > 1
            ) | frozenset(self.active_groups)
            added = False
            for record in records.values():
                if record.pid in self.pins:
                    continue
                if record.ppid not in live and record.pgid not in anchored_groups:
                    continue
                current = self._adopt(record)
                if current is not None:
                    live[record.pid] = current
                    added = True
            if not added:
                break
        represented_groups = {
            record.pgid for record in records.values() if record.pgid in self.active_groups
        }
        self.active_groups.intersection_update(represented_groups)
        self.active_groups.update(
            record.pgid for record in live.values() if record.pgid > 1
        )
        return tuple(live[pid] for pid in sorted(live))

    def _cached_live(self) -> dict[int, tuple[object, _ExactProcessInfo]]:
        live: dict[int, tuple[object, _ExactProcessInfo]] = {}
        for pid, pin in self.pins.items():
            try:
                observation = _inspect_pin(pin)
            except Exception:
                continue
            if observation.state is not _PinState.LIVE:
                continue
            current = observation.info
            if current is None or current.pgid <= 1 or current.pgid == self.runner_pgid:
                continue
            live[pid] = (pin, current)
        return live

    def refresh_for_cleanup(self) -> None:
        try:
            self.observe(
                deadline=time.monotonic() + _PROCESS_TABLE_SCAN_SECONDS,
                clock=time.monotonic,
            )
        except Exception:
            pass

    def signal(self, signal_number: int) -> bool:
        live = self._cached_live()
        if not live:
            return False
        if not all(bool(getattr(pin, "exact_signals", False)) for pin, _info in live.values()):
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        signaled = False
        for pid in sorted(live):
            pin, _info = live[pid]
            try:
                signaled = bool(pin.send_signal(signal_number)) or signaled
            except Exception:
                pass
        return signaled

    def has_live(self) -> bool:
        return bool(self._cached_live())

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        pins = tuple(self.pins.values())
        self.pins.clear()
        self.active_groups.clear()
        for pin in pins:
            try:
                pin.close()
            except Exception:
                pass


def _terminate_process_unchecked(
    process: object,
    tracker: _DescendantTracker | None = None,
) -> None:
    pid = getattr(process, "pid", None)
    if type(pid) is not int or pid <= 0:
        return
    wait = getattr(process, "wait")
    if tracker is None:
        return
    cleanup_clock = time.monotonic
    tracker.refresh_for_cleanup()
    tracker.signal(signal.SIGTERM)
    grace_deadline = cleanup_clock() + _TERMINATION_GRACE_SECONDS
    while cleanup_clock() < grace_deadline:
        tracker.refresh_for_cleanup()
        if not tracker.has_live():
            break
        time.sleep(min(0.01, max(0.0, grace_deadline - cleanup_clock())))
    tracker.refresh_for_cleanup()
    if tracker.has_live():
        tracker.signal(signal.SIGKILL)
    try:
        wait(timeout=_TERMINATION_GRACE_SECONDS)
    except Exception:
        pass


def _terminate_process(
    process: object,
    tracker: _DescendantTracker | None = None,
) -> None:
    try:
        _terminate_process_unchecked(process, tracker)
    except Exception:
        pass


def _append_raw(
    buffers: dict[int, bytearray], channel: int, chunk: bytes, limits: RunnerLimits
) -> None:
    candidate_channel = len(buffers[channel]) + len(chunk)
    candidate_total = len(buffers[CHANNEL_STDOUT]) + len(buffers[CHANNEL_STDERR]) + len(chunk)
    if candidate_channel > limits.raw_per_channel_bytes or candidate_total > limits.raw_total_bytes:
        raise _RunnerAbort(RunnerErrorCode.RAW_LIMIT_EXCEEDED)
    buffers[channel].extend(chunk)


def _drain_process(
    process: object,
    *,
    exec_status: object,
    tracker: _DescendantTracker,
    limits: RunnerLimits,
    deadline: float,
    selector_factory: Callable[[], object],
    clock: Callable[[], float],
) -> tuple[bytes, bytes, int]:
    stdout = getattr(process, "stdout", None)
    stderr = getattr(process, "stderr", None)
    if stdout is None or stderr is None:
        raise _RunnerAbort(RunnerErrorCode.INTERNAL)
    buffers = {CHANNEL_STDOUT: bytearray(), CHANNEL_STDERR: bytearray()}
    exec_failed = False
    selected: object | None = None
    try:
        selected = selector_factory()
        for pipe, channel in (
            (stdout, CHANNEL_STDOUT),
            (stderr, CHANNEL_STDERR),
            (exec_status, 0),
        ):
            descriptor = pipe.fileno()
            os.set_blocking(descriptor, False)
            selected.register(pipe, selectors.EVENT_READ, channel)
        while selected.get_map():
            remaining = deadline - clock()
            if remaining <= 0:
                raise _RunnerAbort(RunnerErrorCode.TIMEOUT)
            tracker.observe(deadline=deadline, clock=clock)
            remaining = deadline - clock()
            if remaining <= 0:
                raise _RunnerAbort(RunnerErrorCode.TIMEOUT)
            try:
                events = selected.select(min(remaining, 0.05))
            except OSError:
                raise _RunnerAbort(RunnerErrorCode.READ_FAILED) from None
            for key, _mask in events:
                pipe = key.fileobj
                channel = key.data
                try:
                    chunk = os.read(pipe.fileno(), _READ_BYTES)
                except BlockingIOError:
                    continue
                except OSError:
                    raise _RunnerAbort(RunnerErrorCode.READ_FAILED) from None
                if chunk:
                    if channel == 0:
                        if chunk != _EXEC_ERROR_MARKER or exec_failed:
                            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
                        exec_failed = True
                    else:
                        _append_raw(buffers, channel, chunk, limits)
                else:
                    try:
                        selected.unregister(pipe)
                    except Exception:
                        pass
                    _close_pipe(pipe)
        remaining = deadline - clock()
        if remaining <= 0:
            raise _RunnerAbort(RunnerErrorCode.TIMEOUT)
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            raise _RunnerAbort(RunnerErrorCode.TIMEOUT) from None
        if type(returncode) is not int:
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        pid = getattr(process, "pid", None)
        if type(pid) is not int or pid <= 0:
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        empty_observations = 0
        while empty_observations < _QUIESCENCE_OBSERVATIONS:
            live_descendants = tracker.observe(deadline=deadline, clock=clock)
            remaining = deadline - clock()
            if remaining <= 0:
                raise _RunnerAbort(RunnerErrorCode.TIMEOUT)
            if live_descendants:
                empty_observations = 0
                time.sleep(min(remaining, 0.01))
            else:
                empty_observations += 1
        if exec_failed:
            raise _RunnerAbort(RunnerErrorCode.SPAWN_FAILED)
        return bytes(buffers[CHANNEL_STDOUT]), bytes(buffers[CHANNEL_STDERR]), returncode
    finally:
        for buffer in buffers.values():
            buffer.clear()
        close_selector = getattr(selected, "close", None)
        if callable(close_selector):
            try:
                close_selector()
            except Exception:
                pass
        _close_pipe(stdout)
        _close_pipe(stderr)
        _close_pipe(exec_status)


def _sanitize(raw: bytes, output_limit: int, private_roots: tuple[str, ...]) -> bytes:
    try:
        sanitized = _sanitizer.sanitize_bytes(
            raw,
            limits=_sanitizer.SanitizerLimits(
                max_input_bytes=len(raw),
                max_output_bytes=output_limit,
            ),
            private_roots=private_roots,
        )
    except (_sanitizer.SanitizationError, ValueError):
        raise _RunnerAbort(RunnerErrorCode.SANITIZATION_INCOMPLETE) from None
    return sanitized.payload


def _redact_argument_derived_output(
    raw: bytes, payload: bytes, argv: tuple[str, ...]
) -> tuple[bytes, bool]:
    argument_bytes = frozenset(item.encode("utf-8") for item in argv if item)
    if any(candidate in raw or candidate in payload for candidate in argument_bytes):
        return b"", True
    return payload, False


def _bounded_excerpt(payload: bytes) -> str:
    candidate = payload[:256]
    while candidate:
        try:
            return candidate.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            candidate = candidate[:-1]
    return ""


def _outcome(returncode: int) -> CommandOutcome:
    if returncode < 0:
        return CommandOutcome(kind=CommandOutcomeKind.SIGNALED, signal=-returncode)
    return CommandOutcome(kind=CommandOutcomeKind.EXITED, exit_code=returncode)


def _frame_count(length: int) -> int:
    return (length + _FRAME_PAYLOAD_BYTES - 1) // _FRAME_PAYLOAD_BYTES


def _receipt_hex(value: object) -> bool:
    return bool(
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _valid_channel_receipt(value: object) -> tuple[int, int] | None:
    if type(value) is not dict or frozenset(value) != frozenset(
        {
            "argument_derived_output_redacted",
            "excerpt",
            "frame_count",
            "sanitized_bytes",
        }
    ):
        return None
    redacted = value["argument_derived_output_redacted"]
    excerpt = value["excerpt"]
    frame_count = value["frame_count"]
    sanitized_bytes = value["sanitized_bytes"]
    if (
        type(redacted) is not bool
        or type(excerpt) is not str
        or type(frame_count) is not int
        or type(sanitized_bytes) is not int
        or sanitized_bytes < 0
        or sanitized_bytes > _HARD_CAPTURE_BYTES
        or frame_count != _frame_count(sanitized_bytes)
    ):
        return None
    try:
        if len(excerpt.encode("utf-8", errors="strict")) > 256:
            return None
    except UnicodeEncodeError:
        return None
    if redacted and (excerpt or frame_count != 0 or sanitized_bytes != 0):
        return None
    return sanitized_bytes, frame_count


def validate_command_capture_receipt(value: object) -> bool:
    """Validate the closed receipt shape plus cross-field framing arithmetic."""

    if type(value) is CommandCaptureReceipt:
        value = value.to_receipt()
    if type(value) is not dict or frozenset(value) != frozenset(
        {
            "artifact",
            "evidence_boundary",
            "handle",
            "namespace_id",
            "observation",
            "outcome",
            "schema_version",
            "status",
            "stderr",
            "stdout",
        }
    ):
        return False
    if (
        value["evidence_boundary"] != evidence_boundary()
        or value["schema_version"] != _RECEIPT_SCHEMA_VERSION
        or value["status"] != "captured"
    ):
        return False
    handle = value["handle"]
    if (
        type(handle) is not str
        or len(handle) != 49
        or not handle.startswith("cgr1p_")
        or any(
            character
            not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            for character in handle[6:]
        )
        or not _receipt_hex(value["namespace_id"])
    ):
        return False
    artifact = value["artifact"]
    observation = value["observation"]
    outcome = value["outcome"]
    if (
        type(artifact) is not dict
        or frozenset(artifact)
        != frozenset(
            {
                "artifact_type",
                "byte_length",
                "digest_sha256",
                "subject_identity_sha256",
            }
        )
        or artifact["artifact_type"] != ArtifactType.COMMAND_CAPTURE_BYTES.value
        or type(observation) is not dict
        or frozenset(observation)
        != frozenset({"after_sha256", "before_sha256", "scope"})
        or observation["scope"] != "worktree"
        or not _receipt_hex(observation["after_sha256"])
        or not _receipt_hex(observation["before_sha256"])
        or not _receipt_hex(artifact["digest_sha256"])
        or not _receipt_hex(artifact["subject_identity_sha256"])
    ):
        return False
    if type(outcome) is not dict:
        return False
    if outcome.get("kind") == CommandOutcomeKind.EXITED.value:
        if (
            frozenset(outcome) != frozenset({"exit_code", "kind"})
            or type(outcome["exit_code"]) is not int
            or not 0 <= outcome["exit_code"] <= 255
        ):
            return False
    elif outcome.get("kind") == CommandOutcomeKind.SIGNALED.value:
        if (
            frozenset(outcome) != frozenset({"kind", "signal"})
            or type(outcome["signal"]) is not int
            or not 1 <= outcome["signal"] <= 127
        ):
            return False
    else:
        return False
    stdout_summary = _valid_channel_receipt(value["stdout"])
    stderr_summary = _valid_channel_receipt(value["stderr"])
    if stdout_summary is None or stderr_summary is None:
        return False
    sanitized_total = stdout_summary[0] + stderr_summary[0]
    frame_total = stdout_summary[1] + stderr_summary[1]
    byte_length = artifact["byte_length"]
    return bool(
        sanitized_total <= _HARD_CAPTURE_BYTES
        and type(byte_length) is int
        and byte_length == len(FRAME_MAGIC) + sanitized_total + frame_total * _FRAME_HEADER_BYTES
        and byte_length <= _HARD_FRAMED_BYTES
    )


def run_command(
    argv: tuple[str, ...],
    root: object,
    *,
    store_factory: Callable[[], object],
    limits: RunnerLimits | None = None,
    private_roots: tuple[str, ...] = (),
    snapshotter: Callable[..., dict[str, object]] = snapshot_repository,
    popen_factory: Callable[..., object] = subprocess.Popen,
    selector_factory: Callable[[], object] = selectors.DefaultSelector,
    clock: Callable[[], float] = time.monotonic,
) -> CommandRunResult:
    """Capture a command locally and publish authority only after durable storage."""

    process: object | None = None
    exec_status: object | None = None
    pinned_root: _PinnedRoot | None = None
    tracker: _DescendantTracker | None = None
    signal_guard: _SignalGuard | None = None
    raw_stdout = b""
    raw_stderr = b""
    sanitized_stdout = b""
    sanitized_stderr = b""
    framed = b""
    try:
        checked_argv, root_path, checked_limits = _validated_invocation(
            argv, root, limits if limits is not None else RunnerLimits()
        )
        _require_process_table_executable()
        _require_process_pinning()
        checked_private_roots = _validated_private_roots(private_roots)
        signal_guard = _SignalGuard()
        signal_guard.install()
        pinned_root = _PinnedRoot(root_path)
        before_frozen, root_identity = _freeze_snapshot(snapshotter, pinned_root)
        before_hash = framed_sha256_hex(
            "contextguard-receipt/command-before-observation/v1", before_frozen
        )
        started = clock()
        exec_read_descriptor = -1
        exec_write_descriptor = -1
        start_read_descriptor = -1
        start_write_descriptor = -1
        try:
            exec_read_descriptor, exec_write_descriptor = os.pipe()
            start_read_descriptor, start_write_descriptor = os.pipe()
            exec_status = os.fdopen(exec_read_descriptor, "rb", buffering=0)
            exec_read_descriptor = -1
            trampoline_python = os.path.realpath(sys.executable)
            if not os.path.isabs(trampoline_python):
                raise OSError
            trampoline_argv = (
                trampoline_python,
                "-I",
                "-S",
                "-B",
                "-c",
                _EXEC_TRAMPOLINE,
                str(pinned_root.descriptor),
                str(exec_write_descriptor),
                str(start_read_descriptor),
                *checked_argv,
            )
            signal_guard.defer_interrupts()
            try:
                process = popen_factory(
                    trampoline_argv,
                    shell=False,
                    cwd="/",
                    env=dict(_FIXED_ENVIRONMENT),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    close_fds=True,
                    pass_fds=(
                        pinned_root.descriptor,
                        exec_write_descriptor,
                        start_read_descriptor,
                    ),
                    start_new_session=True,
                    bufsize=0,
                )
                pid = getattr(process, "pid", None)
                if type(pid) is not int or pid <= 1:
                    raise _RunnerAbort(RunnerErrorCode.INTERNAL)
                tracker = _DescendantTracker(pid)
                tracker.establish(
                    deadline=started + float(checked_limits.timeout_seconds),
                    clock=clock,
                )
                tracker.probe_root_signal()
                with os.fdopen(start_write_descriptor, "wb", buffering=0) as start_writer:
                    start_write_descriptor = -1
                    if start_writer.write(_EXEC_START_MARKER) != 1:
                        raise _RunnerAbort(RunnerErrorCode.SPAWN_FAILED)
            finally:
                signal_guard.resume_interrupts()
        except _RunnerAbort:
            raise
        except Exception:
            raise _RunnerAbort(RunnerErrorCode.SPAWN_FAILED) from None
        finally:
            if exec_read_descriptor >= 0:
                try:
                    os.close(exec_read_descriptor)
                except OSError:
                    pass
            if exec_write_descriptor >= 0:
                try:
                    os.close(exec_write_descriptor)
                except OSError:
                    pass
            if start_read_descriptor >= 0:
                try:
                    os.close(start_read_descriptor)
                except OSError:
                    pass
            if start_write_descriptor >= 0:
                try:
                    os.close(start_write_descriptor)
                except OSError:
                    pass
        if tracker is None:
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        raw_stdout, raw_stderr, returncode = _drain_process(
            process,
            exec_status=exec_status,
            tracker=tracker,
            limits=checked_limits,
            deadline=started + float(checked_limits.timeout_seconds),
            selector_factory=selector_factory,
            clock=clock,
        )
        exec_status = None
        process = None
        if returncode < -127 or returncode > 255:
            raise _RunnerAbort(RunnerErrorCode.INTERNAL)
        after_frozen, after_identity = _freeze_snapshot(snapshotter, pinned_root)
        if after_identity != root_identity:
            raise _RunnerAbort(RunnerErrorCode.REPOSITORY_REPLACED)
        after_hash = framed_sha256_hex(
            "contextguard-receipt/command-after-observation/v1", after_frozen
        )
        sanitized_stdout = _sanitize(
            raw_stdout, checked_limits.sanitized_per_channel_bytes, checked_private_roots
        )
        sanitized_stderr = _sanitize(
            raw_stderr, checked_limits.sanitized_per_channel_bytes, checked_private_roots
        )
        if len(sanitized_stdout) + len(sanitized_stderr) > checked_limits.sanitized_total_bytes:
            raise _RunnerAbort(RunnerErrorCode.SANITIZATION_INCOMPLETE)
        sanitized_stdout, stdout_argument_redacted = _redact_argument_derived_output(
            raw_stdout, sanitized_stdout, checked_argv
        )
        sanitized_stderr, stderr_argument_redacted = _redact_argument_derived_output(
            raw_stderr, sanitized_stderr, checked_argv
        )
        try:
            framed = frame_sanitized_capture(sanitized_stdout, sanitized_stderr)
        except ValueError:
            raise _RunnerAbort(RunnerErrorCode.FRAMED_LIMIT_EXCEEDED) from None
        if len(framed) > checked_limits.framed_bytes:
            raise _RunnerAbort(RunnerErrorCode.FRAMED_LIMIT_EXCEEDED)
        subject_hash = framed_sha256_hex(
            "contextguard-receipt/command-capture-subject/v1", framed
        )
        artifact_digest = framed_sha256_hex(
            "contextguard-receipt/command-capture-payload/v1", framed
        )
        request = ArtifactRequest(
            payload=framed,
            root_identity_sha256=root_identity,
            subject_identity_sha256=subject_hash,
            artifact_type=ArtifactType.COMMAND_CAPTURE_BYTES,
        )
        pinned_root.require_current()
        store = None
        try:
            try:
                store = store_factory()
            except StoreError as error:
                code = (
                    RunnerErrorCode.COMMIT_UNCERTAIN
                    if error.code is StoreErrorCode.COMMIT_UNCERTAIN
                    else RunnerErrorCode.STORE_FAILED
                )
                raise _RunnerAbort(code) from None
            except Exception:
                raise _RunnerAbort(RunnerErrorCode.STORE_FAILED) from None
            try:
                issued = store.issue_batch((request,))
            except StoreError as error:
                code = (
                    RunnerErrorCode.COMMIT_UNCERTAIN
                    if error.code is StoreErrorCode.COMMIT_UNCERTAIN
                    else RunnerErrorCode.STORE_FAILED
                )
                raise _RunnerAbort(code) from None
            except Exception:
                raise _RunnerAbort(RunnerErrorCode.COMMIT_UNCERTAIN) from None
            if type(issued) is not tuple or len(issued) != 1:
                raise _RunnerAbort(RunnerErrorCode.COMMIT_UNCERTAIN)
            handle = getattr(issued[0], "handle", None)
            namespace_id = getattr(issued[0], "namespace_id", None)
            if (
                type(handle) is not str
                or len(handle) != 49
                or not handle.startswith("cgr1p_")
                or any(
                    character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                    for character in handle[6:]
                )
                or type(namespace_id) is not str
                or len(namespace_id) != 64
                or any(character not in "0123456789abcdef" for character in namespace_id)
            ):
                raise _RunnerAbort(RunnerErrorCode.COMMIT_UNCERTAIN)
        except _RunnerAbort:
            raise
        finally:
            try:
                close_store = getattr(store, "close", None)
            except Exception:
                raise _RunnerAbort(RunnerErrorCode.COMMIT_UNCERTAIN) from None
            if callable(close_store):
                try:
                    close_store()
                except Exception:
                    raise _RunnerAbort(RunnerErrorCode.COMMIT_UNCERTAIN) from None

        try:
            pinned_root.require_current()
        except _RunnerAbort:
            raise _RunnerAbort(RunnerErrorCode.COMMIT_UNCERTAIN) from None

        receipt = CommandCaptureReceipt(
            handle=handle,
            namespace_id=namespace_id,
            artifact_bytes=len(framed),
            artifact_digest_sha256=artifact_digest,
            subject_identity_sha256=subject_hash,
            before_observation_sha256=before_hash,
            after_observation_sha256=after_hash,
            outcome=_outcome(returncode),
            stdout=_ChannelSummary(
                sanitized_bytes=len(sanitized_stdout),
                frame_count=_frame_count(len(sanitized_stdout)),
                argument_derived_output_redacted=stdout_argument_redacted,
                excerpt=_bounded_excerpt(sanitized_stdout),
            ),
            stderr=_ChannelSummary(
                sanitized_bytes=len(sanitized_stderr),
                frame_count=_frame_count(len(sanitized_stderr)),
                argument_derived_output_redacted=stderr_argument_redacted,
                excerpt=_bounded_excerpt(sanitized_stderr),
            ),
        )
        if not validate_command_capture_receipt(receipt):
            return _failure(RunnerErrorCode.COMMIT_UNCERTAIN)
        return CommandRunResult(error_code=None, receipt=receipt)
    except _RunnerAbort as failure:
        return _failure(failure.code)
    except Exception:
        return _failure(RunnerErrorCode.INTERNAL)
    finally:
        if signal_guard is not None:
            signal_guard.begin_cleanup()
        if process is not None:
            _terminate_process(process, tracker)
            _close_pipe(getattr(process, "stdout", None))
            _close_pipe(getattr(process, "stderr", None))
        if tracker is not None:
            tracker.close()
        if exec_status is not None:
            _close_pipe(exec_status)
        if pinned_root is not None:
            pinned_root.close()
        raw_stdout = b""
        raw_stderr = b""
        sanitized_stdout = b""
        sanitized_stderr = b""
        framed = b""
        if signal_guard is not None:
            signal_guard.restore()
            signal_guard.raise_pending_after_cleanup()


def map_cli_exit_code(result: CommandRunResult) -> int:
    """Map a closed runner result to stable CLI exit semantics."""

    if type(result) is not CommandRunResult:
        return 70
    if result.receipt is not None:
        outcome = result.receipt.outcome
        if outcome.kind is CommandOutcomeKind.SIGNALED and outcome.signal is not None:
            return min(255, 128 + outcome.signal)
        if (
            outcome.kind is CommandOutcomeKind.EXITED
            and outcome.exit_code is not None
            and 0 <= outcome.exit_code <= 255
        ):
            return outcome.exit_code
        return 70
    if result.error_code is RunnerErrorCode.TIMEOUT:
        return 124
    if result.error_code in (
        RunnerErrorCode.STORE_FAILED,
        RunnerErrorCode.DELIVERY_FAILED,
        RunnerErrorCode.COMMIT_UNCERTAIN,
    ):
        return 74
    return 70
