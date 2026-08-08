"""Narrow, fail-closed policy boundary for optional Bash receipt references.

Only an integrity-pinned Receipt CLI from the same project-local npm install
is eligible.  Every discovery, launch, or response failure is an ordinary
legacy-routing outcome and never changes the wrapped command's result.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import subprocess
import sys
import time
from typing import Protocol


REFERENCE_POLICY_VERSION = "bash_reference_v1"
REFERENCE_DISCLOSURE_DAYS = 7
REFERENCE_ADAPTER_TIMEOUT_SECONDS = 8
REFERENCE_MIN_SANITIZED_BYTES = 8_192
RECEIPT_PACKAGE_NAME = "@ictechgy/context-guard-receipt"
ROOT_PACKAGE_NAME = "@ictechgy/context-guard"
RECEIPT_CLI_RELATIVE_PATH = Path("bin/context-guard-receipt.cjs")
RECEIPT_LAUNCHER_RELATIVE_PATH = Path("bin/launcher.cjs")
RECEIPT_STATE_DIRECTORY_PREFIX = ".context-guard-receipt-state-"
_RECEIPT_STATE_SELECTOR_DOMAIN = b"contextguard/bash-reference-state-selector/v1\0"
# Audited digest of Receipt's package-files.json for each exact dependency
# version. Invalid or missing pins are deliberately unavailable in production.
EXPECTED_RECEIPT_PACKAGE_FILES_SHA256_BY_VERSION: dict[str, str] = {
    "0.2.0": "17a930f7877127698c8189181d19fae7e973c446d03cf65dc9cb4b520f316f6e",
}
_TRANSACTION_ID_RE = re.compile(r"^[a-f0-9]{64}$")
_EXACT_NPM_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
_MAX_PACKAGE_JSON_BYTES = 128 * 1024
_MAX_VERIFIED_PACKAGE_FILE_BYTES = 8 * 1024 * 1024
_TRUSTED_NODE_CANDIDATES: tuple[Path, ...] = (
    Path("/usr/bin/node"),
    Path("/usr/local/bin/node"),
    Path("/opt/homebrew/bin/node"),
)
_TRUSTED_GITHUB_TOOLCACHE_PREFIXES: tuple[Path, ...] = (
    Path("/opt/hostedtoolcache"),
    Path("/Users/runner/hostedtoolcache"),
    Path("/hostedtoolcache"),
)


@dataclass(frozen=True)
class ReceiptAdapterResult:
    status: str
    reference: str | None = None
    reason_code: str = "receipt_adapter_unavailable"
    actionable: bool = False


class ReceiptAdapter(Protocol):
    def start_broker(self, capture_fd: int, *, root: str, transaction_id: str,
                     disclosure_days: int, timeout_seconds: int) -> tuple[object | None, str]: ...

    def query_reference(self, reference: str, *, root: str, offset: int,
                        timeout_seconds: int) -> object: ...


_BROKER_READY = b"READY contextguard-bash-reference-broker/v1\n"
_BROKER_FINAL_PREFIX = b"FINAL "
_BROKER_MAX_LINE_BYTES = 4096
_REFERENCE_HANDLE_RE = re.compile(r"^cgr1p_[A-Za-z0-9_-]{43}$", re.ASCII)
_REFERENCE_QUERY_SCHEMA = "contextguard-receipt-bash-reference-query/v1"
_REFERENCE_QUERY_MAX_PAYLOAD_BYTES = 20_000
_REFERENCE_QUERY_MAX_ARTIFACT_BYTES = 10_000_000
_REFERENCE_QUERY_MAX_STDOUT_BYTES = 28_000
_REFERENCE_QUERY_MAX_STDERR_BYTES = 4096


@dataclass(frozen=True)
class ReferenceQueryResult:
    status: str
    reference: str | None = None
    payload: bytes = field(default=b"", repr=False)
    offset: int = 0
    next_offset: int = 0
    total_bytes: int = 0
    reason_code: str = "reference_query_unavailable"


def _read_bounded_process_channels(
    process: subprocess.Popen[bytes],
    *,
    stdout_maximum: int,
    stderr_maximum: int,
    timeout_seconds: int,
) -> tuple[int, bytes, bytes] | None:
    """Drain stdout and stderr together without unbounded communicate buffers."""

    if process.stdout is None or process.stderr is None:
        return None
    stdout_fd = process.stdout.fileno()
    stderr_fd = process.stderr.fileno()
    buffers = {stdout_fd: bytearray(), stderr_fd: bytearray()}
    maxima = {stdout_fd: stdout_maximum, stderr_fd: stderr_maximum}
    active = {stdout_fd, stderr_fd}
    deadline = time.monotonic() + timeout_seconds
    try:
        while active:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            readable, _, _ = select.select(list(active), [], [], remaining)
            if not readable:
                return None
            for descriptor in readable:
                target = buffers[descriptor]
                maximum = maxima[descriptor]
                chunk = os.read(
                    descriptor, min(4096, maximum + 1 - len(target))
                )
                if not chunk:
                    active.remove(descriptor)
                    continue
                target.extend(chunk)
                if len(target) > maximum:
                    return None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        status = process.wait(timeout=remaining)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None
    return status, bytes(buffers[stdout_fd]), bytes(buffers[stderr_fd])


def _read_bounded_line(
    process: subprocess.Popen[bytes], *, maximum: int, timeout_seconds: int
) -> bytes | None:
    stream = process.stdout
    if stream is None:
        return None
    deadline = time.monotonic() + timeout_seconds
    data = bytearray()
    try:
        descriptor = stream.fileno()
        while len(data) <= maximum:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            readable, _, _ = select.select([descriptor], [], [], remaining)
            if not readable:
                return None
            chunk = os.read(descriptor, 1)
            if not chunk:
                return None
            data.extend(chunk)
            if chunk == b"\n":
                return bytes(data)
    except (OSError, ValueError):
        return None
    return None


class PreparedReceiptBroker:
    """Bounded control channel for one already-READY Receipt transaction."""

    def __init__(
        self,
        process: subprocess.Popen[bytes],
        *,
        transaction_id: str,
        timeout_seconds: int,
    ) -> None:
        self._process = process
        self._transaction_id = transaction_id
        self._timeout_seconds = timeout_seconds
        self._finished = False

    @staticmethod
    def _parse_final(raw: bytes, transaction_id: str) -> ReceiptAdapterResult:
        if not raw.startswith(_BROKER_FINAL_PREFIX) or not raw.endswith(b"\n"):
            return ReceiptAdapterResult(
                status="failure", reason_code="receipt_broker_response_invalid"
            )
        document = raw[len(_BROKER_FINAL_PREFIX) : -1]
        try:
            response = json.loads(document.decode("utf-8", errors="strict"))
            canonical = json.dumps(
                response,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, UnicodeDecodeError, UnicodeEncodeError, json.JSONDecodeError):
            return ReceiptAdapterResult(
                status="failure", reason_code="receipt_broker_response_invalid"
            )
        reference = response.get("reference") if isinstance(response, dict) else None
        deadline = (
            response.get("expires_at_unix_ms")
            if isinstance(response, dict)
            else None
        )
        if (
            canonical != document
            or not isinstance(response, dict)
            or response.get("status") != "registered"
            or response.get("transaction_id") != transaction_id
            or response.get("actionable") is not True
            or not isinstance(deadline, int)
            or deadline <= time.time_ns() // 1_000_000
            or not isinstance(reference, str)
            or _REFERENCE_HANDLE_RE.fullmatch(reference) is None
        ):
            return ReceiptAdapterResult(
                status="failure", reason_code="receipt_broker_response_invalid"
            )
        return ReceiptAdapterResult(
            status="success",
            reference=reference,
            reason_code="reference_published",
            actionable=True,
        )

    def _send(self, command: bytes) -> bool:
        stream = self._process.stdin
        if stream is None or self._finished:
            return False
        try:
            stream.write(command)
            stream.flush()
            stream.close()
            return True
        except (OSError, ValueError):
            return False

    def commit(self) -> ReceiptAdapterResult:
        if not self._send(b"COMMIT\n"):
            self.close()
            return ReceiptAdapterResult(
                status="failure", reason_code="receipt_broker_unavailable"
            )
        raw = _read_bounded_line(
            self._process,
            maximum=_BROKER_MAX_LINE_BYTES,
            timeout_seconds=self._timeout_seconds,
        )
        try:
            status = self._process.wait(timeout=self._timeout_seconds)
        except (OSError, subprocess.TimeoutExpired):
            status = None
        self._finished = True
        if status != 0 or raw is None:
            _terminate_adapter_process(self._process)
            return ReceiptAdapterResult(
                status="failure", reason_code="receipt_broker_unavailable"
            )
        _close_adapter_streams(self._process)
        return self._parse_final(raw, self._transaction_id)

    def abort(self) -> None:
        if self._finished:
            return
        sent = self._send(b"ABORT\n")
        try:
            status = self._process.wait(timeout=1) if sent else None
        except (OSError, subprocess.TimeoutExpired):
            status = None
        self._finished = True
        if status != 0:
            _terminate_adapter_process(self._process)
        else:
            _close_adapter_streams(self._process)

    def close(self) -> None:
        if not self._finished and self._process.poll() is None:
            self.abort()
        else:
            _close_adapter_streams(self._process)
        self._finished = True


class NpmReceiptCliAdapter:
    """Verified package-local Receipt CLI; never resolves the executable via PATH."""

    def __init__(
        self,
        cli_path: Path,
        *,
        node_path: Path | None = None,
        node_identity: tuple[int, ...] | None = None,
        protected_paths: tuple[Path, ...] | None = None,
        protected_hashes: tuple[tuple[Path, str], ...] | None = None,
    ) -> None:
        self._cli_path = cli_path
        self._node_path = Path(node_path).absolute() if node_path is not None else None
        self._node_identity = node_identity or (
            _executable_identity(self._node_path)
            if self._node_path is not None
            else None
        )
        self._python_path = Path(sys.executable).resolve()
        self._python_identity = _executable_identity(self._python_path)
        if protected_hashes is None:
            paths = protected_paths or (cli_path,)
            self._protected_hashes = tuple(
                (Path(path), _sha256_file(Path(path)) or "")
                for path in paths
            )
        else:
            self._protected_hashes = tuple(
                (Path(path), digest if re.fullmatch(r"[a-f0-9]{64}", digest) else "")
                for path, digest in protected_hashes
            )

    def _protected_package_intact(self) -> bool:
        return bool(self._protected_hashes) and all(
            expected and _sha256_file(path) == expected
            for path, expected in self._protected_hashes
        )

    @staticmethod
    def _parse_reference_query_response(
        raw: bytes, *, reference: str, offset: int
    ) -> ReferenceQueryResult:
        failure = ReferenceQueryResult(
            status="failure", reason_code="receipt_query_response_invalid"
        )
        if (
            type(raw) is not bytes
            or len(raw) > _REFERENCE_QUERY_MAX_STDOUT_BYTES
            or type(reference) is not str
            or _REFERENCE_HANDLE_RE.fullmatch(reference) is None
            or type(offset) is not int
            or offset < 0
        ):
            return failure
        try:
            response = json.loads(raw.decode("utf-8", errors="strict"))
            canonical = json.dumps(
                response,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8") + b"\n"
        except (TypeError, UnicodeDecodeError, UnicodeEncodeError, json.JSONDecodeError):
            return failure
        expected_keys = {
            "next_offset",
            "offset",
            "payload_b64u",
            "request",
            "schema_version",
            "status",
            "total_bytes",
        }
        request = response.get("request") if type(response) is dict else None
        if (
            canonical != raw
            or type(response) is not dict
            or set(response) != expected_keys
            or response.get("schema_version") != _REFERENCE_QUERY_SCHEMA
            or response.get("status") != "exact"
            or type(request) is not dict
            or set(request) != {"offset", "reference"}
            or type(request.get("reference")) is not str
            or _REFERENCE_HANDLE_RE.fullmatch(request["reference"]) is None
            or not hmac.compare_digest(request["reference"], reference)
            or type(request.get("offset")) is not int
            or request["offset"] != offset
            or type(response.get("offset")) is not int
            or response.get("offset") != offset
        ):
            return failure
        encoded_payload = response.get("payload_b64u")
        next_offset = response.get("next_offset")
        total_bytes = response.get("total_bytes")
        if (
            type(encoded_payload) is not str
            or re.fullmatch(r"[A-Za-z0-9_-]*", encoded_payload, re.ASCII) is None
            or type(next_offset) is not int
            or type(total_bytes) is not int
            or not 0 <= offset <= next_offset <= total_bytes <= _REFERENCE_QUERY_MAX_ARTIFACT_BYTES
        ):
            return failure
        try:
            padded = encoded_payload + "=" * (-len(encoded_payload) % 4)
            payload = base64.b64decode(
                padded.encode("ascii"), altchars=b"-_", validate=True
            )
            if (
                base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
                != encoded_payload
                or len(payload) > _REFERENCE_QUERY_MAX_PAYLOAD_BYTES
                or next_offset != offset + len(payload)
                or (not payload and offset != total_bytes)
            ):
                return failure
            payload.decode("utf-8", errors="strict")
        except (UnicodeDecodeError, UnicodeEncodeError, ValueError):
            return failure
        return ReferenceQueryResult(
            status="success",
            reference=reference,
            payload=payload,
            offset=offset,
            next_offset=next_offset,
            total_bytes=total_bytes,
            reason_code="reference_query_exact",
        )

    def query_reference(
        self,
        reference: str,
        *,
        root: str,
        offset: int,
        timeout_seconds: int,
    ) -> ReferenceQueryResult:
        failure = lambda reason: ReferenceQueryResult(
            status="failure", reason_code=reason
        )
        repository_root = Path(root)
        if (
            _REFERENCE_HANDLE_RE.fullmatch(reference) is None
            or type(offset) is not int
            or not 0 <= offset <= _REFERENCE_QUERY_MAX_ARTIFACT_BYTES
            or timeout_seconds != REFERENCE_ADAPTER_TIMEOUT_SECONDS
            or not repository_root.is_absolute()
        ):
            return failure("receipt_adapter_argument_invalid")
        if self._node_path is None or self._node_identity is None:
            return failure("receipt_node_interpreter_unavailable")
        if _executable_identity(self._node_path) != self._node_identity:
            return failure("receipt_node_interpreter_changed_before_launch")
        if (
            self._python_identity is None
            or _executable_identity(self._python_path) != self._python_identity
        ):
            return failure("receipt_python_interpreter_changed_before_launch")
        if not self._protected_package_intact():
            return failure("receipt_package_changed_before_launch")
        try:
            state_dir = receipt_state_directory(repository_root)
        except (OSError, ValueError):
            return failure("receipt_state_location_unavailable")
        command = [
            str(self._node_path),
            str(self._cli_path),
            "--private-bash-reference-query-v1",
            reference,
            "--root",
            str(repository_root),
            "--state-dir",
            str(state_dir),
            "--offset",
            str(offset),
        ]
        environment = {
            "CONTEXT_GUARD_RECEIPT_PYTHON": str(self._python_path),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.defpath,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUTF8": "1",
        }
        try:
            process = subprocess.Popen(
                command,
                cwd=str(repository_root),
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                bufsize=0,
                close_fds=True,
                start_new_session=(os.name != "nt"),
            )
        except OSError:
            return failure("receipt_adapter_launch_failed")
        captured = _read_bounded_process_channels(
            process,
            stdout_maximum=_REFERENCE_QUERY_MAX_STDOUT_BYTES,
            stderr_maximum=_REFERENCE_QUERY_MAX_STDERR_BYTES,
            timeout_seconds=timeout_seconds,
        )
        if captured is None:
            _terminate_adapter_process(process)
            return failure("receipt_query_unavailable")
        status, stdout, stderr = captured
        _close_adapter_streams(process)
        if status != 0 or stderr:
            return failure("receipt_query_unavailable")
        return self._parse_reference_query_response(
            stdout, reference=reference, offset=offset
        )

    def start_broker(
        self,
        capture_fd: int,
        *,
        root: str,
        transaction_id: str,
        disclosure_days: int,
        timeout_seconds: int,
    ) -> tuple[PreparedReceiptBroker | None, str]:
        repository_root = Path(root)
        if (
            type(capture_fd) is not int
            or capture_fd < 0
            or not repository_root.is_absolute()
            or not _TRANSACTION_ID_RE.fullmatch(transaction_id)
            or disclosure_days != REFERENCE_DISCLOSURE_DAYS
            or timeout_seconds != REFERENCE_ADAPTER_TIMEOUT_SECONDS
        ):
            return None, "receipt_adapter_argument_invalid"
        if self._node_path is None or self._node_identity is None:
            return None, "receipt_node_interpreter_unavailable"
        if _executable_identity(self._node_path) != self._node_identity:
            return None, "receipt_node_interpreter_changed_before_launch"
        if (
            self._python_identity is None
            or _executable_identity(self._python_path) != self._python_identity
        ):
            return None, "receipt_python_interpreter_changed_before_launch"
        if not self._protected_package_intact():
            return None, "receipt_package_changed_before_launch"
        try:
            state_dir = receipt_state_directory(repository_root)
        except (OSError, ValueError):
            return None, "receipt_state_location_unavailable"
        command = [
            str(self._node_path),
            str(self._cli_path),
            "--private-bash-reference-broker-v1",
            "--capture-fd",
            str(capture_fd),
            "--transaction-id",
            transaction_id,
            "--root",
            str(repository_root),
            "--state-dir",
            str(state_dir),
            "--disclosure-days",
            str(REFERENCE_DISCLOSURE_DAYS),
        ]
        environment = {
            "CONTEXT_GUARD_RECEIPT_PYTHON": str(self._python_path),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.defpath,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUTF8": "1",
        }
        process: subprocess.Popen[bytes] | None = None
        try:
            process = subprocess.Popen(
                command,
                cwd=str(repository_root),
                env=environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=False,
                bufsize=0,
                pass_fds=(capture_fd,),
                close_fds=True,
                start_new_session=(os.name != "nt"),
            )
        except OSError:
            return None, "receipt_adapter_launch_failed"
        ready = _read_bounded_line(
            process,
            maximum=len(_BROKER_READY),
            timeout_seconds=timeout_seconds,
        )
        if ready != _BROKER_READY or process.poll() is not None:
            _terminate_adapter_process(process)
            return None, "receipt_broker_unavailable"
        return (
            PreparedReceiptBroker(
                process,
                transaction_id=transaction_id,
                timeout_seconds=timeout_seconds,
            ),
            "receipt_broker_ready",
        )


def receipt_state_directory(repository_root: Path) -> Path:
    """Select one stable private sibling so Receipt state stays outside the repo."""

    root = Path(repository_root)
    root_text = str(root)
    if (
        not root.is_absolute()
        or os.path.normpath(root_text) != root_text
        or root.is_symlink()
    ):
        raise ValueError("repository root must be a normalized physical path")
    status = root.lstat()
    if not stat.S_ISDIR(status.st_mode):
        raise ValueError("repository root must be a directory")
    selector = hashlib.sha256()
    selector.update(_RECEIPT_STATE_SELECTOR_DOMAIN)
    for field in (
        os.fsencode(root_text),
        str(status.st_dev).encode("ascii"),
        str(status.st_ino).encode("ascii"),
    ):
        selector.update(len(field).to_bytes(8, "big"))
        selector.update(field)
    return root.parent / f"{RECEIPT_STATE_DIRECTORY_PREFIX}{selector.hexdigest()}"


def _close_adapter_streams(process: subprocess.Popen[bytes]) -> None:
    for name in ("stdin", "stdout", "stderr"):
        stream = getattr(process, name, None)
        if stream is not None:
            try:
                stream.close()
            except (OSError, ValueError):
                pass


def _terminate_adapter_process(process: subprocess.Popen[bytes]) -> None:
    """Bounded cleanup for a timed-out adapter; never touches the caller child."""
    try:
        if process.poll() is None:
            try:
                if os.name != "nt":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except (OSError, ProcessLookupError):
                pass
            try:
                process.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                pass
    finally:
        _close_adapter_streams(process)


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
        value.st_uid, value.st_gid, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )


def _trusted_github_toolcache_roots() -> tuple[Path, ...]:
    if os.environ.get("GITHUB_ACTIONS", "").lower() != "true":
        return ()
    roots: list[Path] = []
    for prefix in _TRUSTED_GITHUB_TOOLCACHE_PREFIXES:
        try:
            roots.append(prefix.resolve(strict=True))
        except OSError:
            continue
    return tuple(roots)


def _path_is_under(path: Path, roots: tuple[Path, ...]) -> bool:
    try:
        path = path.resolve(strict=True)
    except OSError:
        return False
    return any(path == root or root in path.parents for root in roots)


def _executable_identity(path: Path) -> tuple[int, ...] | None:
    """Bind one already-absolute interpreter without following a final link."""
    try:
        status = path.lstat()
    except OSError:
        return None
    if (
        not path.is_absolute()
        or not stat.S_ISREG(status.st_mode)
        or status.st_nlink != 1
        or status.st_uid not in {0, os.geteuid()}
        or status.st_mode & 0o022
        or not status.st_mode & 0o111
    ):
        return None
    return _stat_identity(status)


def _trusted_ci_node_from_path(project_root: Path) -> tuple[Path, tuple[int, ...]] | None:
    """Resolve PATH's Node only for GitHub Actions under fixed toolcache roots."""
    try:
        project_root = project_root.resolve(strict=True)
    except OSError:
        return None
    if not project_root.is_dir():
        return None
    trusted_prefixes = _trusted_github_toolcache_roots()
    if not trusted_prefixes:
        return None
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry:
            continue
        candidate = Path(entry) / "node"
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(project_root)
            continue
        except ValueError:
            pass
        except OSError:
            continue
        if not _path_is_under(resolved, trusted_prefixes):
            continue
        identity = _executable_identity(resolved)
        if identity is not None:
            return resolved, identity
    return None


def _trusted_node_interpreter(project_root: Path) -> tuple[Path, tuple[int, ...]] | None:
    """Resolve Node from fixed locations, with a CI-only toolcache fallback."""
    try:
        project_root = project_root.resolve(strict=True)
    except OSError:
        return None
    if not project_root.is_dir():
        return None
    for candidate in _TRUSTED_NODE_CANDIDATES:
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(project_root)
        except ValueError:
            identity = _executable_identity(resolved)
            if identity is not None:
                return resolved, identity
        except OSError:
            continue
    return _trusted_ci_node_from_path(project_root)


def _read_stable_regular_bytes(path: Path, *, max_bytes: int) -> bytes | None:
    """Read one no-follow file only if its identity remains unchanged."""
    if not hasattr(os, "O_NOFOLLOW"):
        return None
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > max_bytes:
            return None
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or _stat_identity(opened) != _stat_identity(before):
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
        after_fd = os.fstat(fd)
        after_path = path.lstat()
        if (
            _stat_identity(after_fd) != _stat_identity(opened)
            or _stat_identity(after_path) != _stat_identity(opened)
        ):
            return None
        return b"".join(chunks)
    except OSError:
        return None
    finally:
        os.close(fd)


def _read_regular_json(path: Path) -> dict[str, object] | None:
    """Read a small package descriptor without accepting links or swaps."""
    raw = _read_stable_regular_bytes(path, max_bytes=_MAX_PACKAGE_JSON_BYTES)
    if raw is None:
        return None
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _regular_descendant(root: Path, path: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return False
    current = root
    try:
        if current.is_symlink():
            return False
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                return False
        return path.is_file() and stat.S_ISREG(path.stat().st_mode)
    except OSError:
        return False


def _sha256_file(path: Path) -> str | None:
    raw = _read_stable_regular_bytes(path, max_bytes=_MAX_VERIFIED_PACKAGE_FILE_BYTES)
    return hashlib.sha256(raw).hexdigest() if raw is not None else None


def _verified_package_hashes(
    root: Path,
    package_dir: Path,
    *,
    expected_manifest_sha256: str,
) -> tuple[tuple[Path, str], ...] | None:
    """Return only externally anchored package-file hashes."""
    manifest_path = package_dir / "package-files.json"
    if not _regular_descendant(root, manifest_path):
        return None
    if not re.fullmatch(r"[a-f0-9]{64}", expected_manifest_sha256):
        return None
    manifest_bytes = _read_stable_regular_bytes(
        manifest_path,
        max_bytes=_MAX_PACKAGE_JSON_BYTES,
    )
    if manifest_bytes is None or hashlib.sha256(manifest_bytes).hexdigest() != expected_manifest_sha256:
        return None
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    entries = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(entries, list):
        return None
    expected: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            return None
        path = entry.get("path")
        digest = entry.get("sha256")
        if isinstance(path, str) and isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{64}", digest):
            expected[path] = digest
    required = {
        "package.json",
        str(RECEIPT_CLI_RELATIVE_PATH),
        str(RECEIPT_LAUNCHER_RELATIVE_PATH),
    }
    if not required <= expected.keys():
        return None
    for relative in required:
        candidate = package_dir / relative
        if not _regular_descendant(root, candidate) or _sha256_file(candidate) != expected[relative]:
            return None
    return (
        (manifest_path, expected_manifest_sha256),
        *((package_dir / relative, expected[relative]) for relative in sorted(required)),
    )


def _verified_package_cli(
    root: Path,
    package_dir: Path,
    *,
    expected_manifest_sha256: str,
) -> Path | None:
    """Compatibility helper returning the CLI after complete pin verification."""
    protected_hashes = _verified_package_hashes(
        root,
        package_dir,
        expected_manifest_sha256=expected_manifest_sha256,
    )
    return package_dir / RECEIPT_CLI_RELATIVE_PATH if protected_hashes is not None else None


def _installed_context_guard_package(project_root: Path) -> Path | None:
    """Prove this policy is inside the canonical npm package layout."""
    policy_path = Path(__file__).absolute()
    suffix = ("plugins", "context-guard", "bin", "bash_reference_policy.py")
    if tuple(policy_path.parts[-4:]) != suffix:
        return None
    package_root = policy_path.parents[3]
    if (
        package_root.name != "context-guard"
        or package_root.parent.name != "@ictechgy"
        or package_root.parent.parent.name != "node_modules"
        or not _regular_descendant(project_root, policy_path)
    ):
        return None
    return package_root


def discover_adapter(root: Path) -> tuple[ReceiptAdapter | None, str]:
    """Accept only a pinned, local npm package rooted in this exact project.

    PATH, global npm folders, arbitrary checkout paths, symlinks, and unpinned
    source workspaces are intentionally not discovery candidates.
    """
    try:
        if root.is_symlink():
            return None, "receipt_root_symlink_rejected"
        root = root.absolute()
    except OSError:
        return None, "receipt_root_unavailable"
    context_guard_root = _installed_context_guard_package(root)
    if context_guard_root is None:
        return None, "receipt_source_or_plugin_only"
    context_guard_package = _read_regular_json(context_guard_root / "package.json")
    if not context_guard_package or context_guard_package.get("name") != ROOT_PACKAGE_NAME:
        return None, "receipt_context_guard_package_unverified"
    dependencies = context_guard_package.get("dependencies")
    requested = dependencies.get(RECEIPT_PACKAGE_NAME) if isinstance(dependencies, dict) else None
    if not isinstance(requested, str) or not _EXACT_NPM_VERSION_RE.fullmatch(requested):
        return None, "receipt_dependency_unpinned"
    nested = context_guard_root / "node_modules" / "@ictechgy" / "context-guard-receipt"
    hoisted = root / "node_modules" / "@ictechgy" / "context-guard-receipt"
    try:
        (nested / "package.json").lstat()
    except FileNotFoundError:
        package_dir = hoisted
    except OSError:
        return None, "receipt_npm_package_unavailable"
    else:
        package_dir = nested
    package_json = package_dir / "package.json"
    if not _regular_descendant(root, package_json):
        return None, "receipt_npm_package_unavailable"
    receipt_package = _read_regular_json(package_json)
    if not receipt_package or receipt_package.get("name") != RECEIPT_PACKAGE_NAME:
        return None, "receipt_npm_package_invalid"
    if receipt_package.get("version") != requested:
        return None, "receipt_npm_package_version_mismatch"
    manifest_pin = EXPECTED_RECEIPT_PACKAGE_FILES_SHA256_BY_VERSION.get(requested, "")
    if not re.fullmatch(r"[a-f0-9]{64}", manifest_pin):
        return None, "receipt_package_manifest_pin_unavailable"
    protected_hashes = _verified_package_hashes(
        root,
        package_dir,
        expected_manifest_sha256=manifest_pin,
    )
    if protected_hashes is None:
        return None, "receipt_npm_package_integrity_invalid"
    node_interpreter = _trusted_node_interpreter(root)
    if node_interpreter is None:
        return None, "receipt_node_interpreter_unavailable"
    node_path, node_identity = node_interpreter
    cli_path = package_dir / RECEIPT_CLI_RELATIVE_PATH
    return NpmReceiptCliAdapter(
        cli_path,
        node_path=node_path,
        node_identity=node_identity,
        protected_hashes=protected_hashes,
    ), "receipt_adapter_available"
