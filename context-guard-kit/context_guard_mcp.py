#!/usr/bin/env python3
"""Strict local stdio MCP adapter for the ContextGuard helper CLIs.

This module deliberately has no network/client configuration surface.  It is a
small JSON-RPC membrane around the sibling compressor and artifact helpers.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from typing import Any

SUPPORTED_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26")
MAX_MESSAGE_BYTES = 1024 * 1024
MAX_CONTENT_BYTES = 768 * 1024
MAX_RETURN_BYTES = 20 * 1024
MAX_RETRIEVE_CHARS = 20_000
MAX_RETRIEVE_LINES = 500
MAX_CALLS = 1000
MAX_ARTIFACTS = 1000
MAX_VISITED_ENTRIES = 4000
HELPER_TIMEOUT = 10.0
MAX_HELPER_STDERR = 16 * 1024
MAX_HELPER_OUTPUT = 5 * 1024 * 1024
MAX_RESPONSE_BYTES = 128 * 1024
MAX_JSON_DEPTH = 64
ARTIFACT_ID_RE = re.compile(r"^[a-f0-9]{20}$")
NAMESPACE_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
LINES_RE = re.compile(r"^[1-9][0-9]{0,6}(?::[1-9][0-9]{0,6})?$")
CONTENT_TYPES = ("json", "diff", "log", "search", "code", "prose")
MODES = ("conservative", "readable")
PROTECTED_CLASSES = (
    "code_fence", "diff", "identifier", "numeric_constant", "hash", "path",
    "stack_frame", "quoted_string", "json_key",
)
ERROR_MESSAGES = {
    "invalid_arguments": "Invalid tool arguments.",
    "input_too_large": "Content exceeds the configured byte limit.",
    "result_too_large_without_fallback": "Compressed result exceeds the response limit without a stored fallback.",
    "artifact_not_found": "Artifact not found in this namespace.",
    "artifact_invalid": "Artifact failed integrity validation.",
    "namespace_full": "Namespace artifact limit reached.",
    "namespace_ambiguous": "Namespace storage is ambiguous.",
    "helper_failed": "Local helper failed.",
    "rate_limit_reached": "Tool call limit reached.",
    "response_too_large": "Response exceeds the configured limit.",
}


class DuplicateKey(ValueError):
    pass


class NonFinite(ValueError):
    pass


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKey(key)
        value[key] = item
    return value


def reject_nonfinite(_value: str) -> None:
    raise NonFinite()


def compact(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def line_count(value: str) -> int:
    return value.count("\n") + (1 if value and not value.endswith("\n") else 0)


def cap_utf8(value: str, limit: int) -> tuple[str, bool]:
    data = value.encode("utf-8")
    if len(data) <= limit:
        return value, False
    out: list[str] = []
    used = 0
    for char in value:
        encoded = char.encode("utf-8")
        if used + len(encoded) > limit:
            break
        out.append(char)
        used += len(encoded)
    return "".join(out), True


def is_safe_scalar(value: object) -> bool:
    """Validate JSON-shaped values without recursive traversal or encoding.

    Parsed wire data is attacker-controlled.  Keep its nesting below a fixed
    bound so neither this guard nor a later serializer can reach Python's
    recursion limit.  The identity set also makes the helper safe for direct
    unit-test inputs containing an accidental container cycle.
    """
    pending: list[tuple[object, int]] = [(value, 0)]
    seen: set[int] = set()
    while pending:
        item, depth = pending.pop()
        if isinstance(item, str):
            if any(0xD800 <= ord(char) <= 0xDFFF for char in item):
                return False
            continue
        if isinstance(item, list):
            if depth >= MAX_JSON_DEPTH or id(item) in seen:
                return False
            seen.add(id(item))
            pending.extend((child, depth + 1) for child in item)
            continue
        if isinstance(item, dict):
            if depth >= MAX_JSON_DEPTH or id(item) in seen:
                return False
            seen.add(id(item))
            for key, child in item.items():
                if not isinstance(key, str) or any(0xD800 <= ord(char) <= 0xDFFF for char in key):
                    return False
                pending.append((child, depth + 1))
    return True


def safe_utf8_bytes(value: str) -> bytes | None:
    """Encode only JSON strings that can safely be returned on the wire."""
    try:
        if not is_safe_scalar(value):
            return None
        return value.encode("utf-8")
    except UnicodeEncodeError:
        return None


def cap_codepoints(value: str, limit: int) -> tuple[str, bool]:
    return (value, False) if len(value) <= limit else (value[:limit], True)


def error_response(request_id: object, code: int, message: str) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def tool_error(code: str) -> dict[str, object]:
    return {
        "schema_version": "contextguard.mcp.tool-error.v1",
        "error": {"code": code, "message": ERROR_MESSAGES[code], "retryable": False},
    }


def call_result(payload: dict[str, object], is_error: bool) -> dict[str, object]:
    text = compact(payload)
    return {"content": [{"type": "text", "text": text}], "structuredContent": payload, "isError": is_error}


def nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def exact_object(value: object, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def valid_tool_payload(payload: object, is_error: bool) -> bool:
    """The single recursive allowlist for all MCP structured tool payloads."""
    if not isinstance(payload, dict) or not is_safe_scalar(payload):
        return False
    if is_error:
        return (exact_object(payload, {"schema_version", "error"})
                and payload.get("schema_version") == "contextguard.mcp.tool-error.v1"
                and exact_object(payload.get("error"), {"code", "message", "retryable"})
                and payload["error"].get("code") in ERROR_MESSAGES
                and payload["error"].get("message") == ERROR_MESSAGES[payload["error"]["code"]]
                and payload["error"].get("retryable") is False)
    version = payload.get("schema_version")
    if version == "contextguard.mcp.compress.v1":
        if not exact_object(payload, {"schema_version", "content", "content_capped", "compression", "artifact"}):
            return False
        c = payload["compression"]
        if not isinstance(payload["content"], str) or not isinstance(payload["content_capped"], bool) or not exact_object(c, {"content_type", "type_source", "strategy", "lossy", "bytes", "lines", "token_proxy", "redaction", "protected_policy"}):
            return False
        if c["content_type"] not in CONTENT_TYPES or c["type_source"] not in ("detected", "override") or c["strategy"] not in {"json-compact", "diff-keep-changes", "log-collapse-repeats", "search-dedupe", "code-whitespace", "prose-whitespace", "prose-readable-window"} or not isinstance(c["lossy"], bool):
            return False
        for section, keys in (("bytes", {"measurement", "original", "compressed", "returned"}), ("lines", {"measurement", "original", "compressed", "returned"})):
            if not exact_object(c[section], keys) or c[section].get("measurement") != "observed" or not all(nonnegative_int(c[section][key]) for key in keys - {"measurement"}):
                return False
        token = c["token_proxy"]
        redaction = c["redaction"]
        policy = c["protected_policy"]
        if not (exact_object(token, {"measurement", "method", "original", "compressed"}) and token.get("measurement") == "estimated" and token.get("method") == "chars_div_4" and nonnegative_int(token.get("original")) and nonnegative_int(token.get("compressed")) and exact_object(redaction, {"redacted_lines", "redacted_before_receipt"}) and nonnegative_int(redaction.get("redacted_lines")) and redaction.get("redacted_before_receipt") is True and exact_object(policy, {"enabled", "retrieval_required", "detected_classes"}) and isinstance(policy.get("enabled"), bool) and isinstance(policy.get("retrieval_required"), bool) and isinstance(policy.get("detected_classes"), list) and policy["detected_classes"] == sorted(set(policy["detected_classes"])) and all(item in PROTECTED_CLASSES for item in policy["detected_classes"])):
            return False
        artifact = payload["artifact"]
        return artifact is None or (exact_object(artifact, {"artifact_id", "handle", "stored_bytes", "stored_lines", "exact_scope", "retrieve"}) and isinstance(artifact.get("artifact_id"), str) and bool(ARTIFACT_ID_RE.fullmatch(artifact["artifact_id"])) and artifact.get("handle") == "contextguard-artifact:" + artifact["artifact_id"] and nonnegative_int(artifact.get("stored_bytes")) and nonnegative_int(artifact.get("stored_lines")) and artifact.get("exact_scope") == "sanitized_accepted_input" and exact_object(artifact.get("retrieve"), {"tool", "arguments"}) and artifact["retrieve"].get("tool") == "context_guard_retrieve" and exact_object(artifact["retrieve"].get("arguments"), {"artifact_id"}) and artifact["retrieve"]["arguments"].get("artifact_id") == artifact["artifact_id"])
    if version == "contextguard.mcp.retrieve.v1":
        if not exact_object(payload, {"schema_version", "artifact_id", "content", "content_capped", "returned_bytes", "query", "stored"}):
            return False
        query = payload["query"]
        stored = payload["stored"]
        query_keys = {"type", "returned_lines", "matched_lines", "total_lines"}
        if isinstance(query, dict) and query.get("type") == "lines":
            query_keys |= {"start", "end"}
        return (isinstance(payload["artifact_id"], str) and bool(ARTIFACT_ID_RE.fullmatch(payload["artifact_id"])) and isinstance(payload["content"], str) and isinstance(payload["content_capped"], bool) and nonnegative_int(payload["returned_bytes"]) and payload["returned_bytes"] == len(payload["content"].encode("utf-8")) and exact_object(query, query_keys) and query.get("type") in ("head", "lines", "pattern") and all(nonnegative_int(query[key]) for key in {"returned_lines", "matched_lines", "total_lines"}) and (query.get("type") != "lines" or nonnegative_int(query.get("start")) and nonnegative_int(query.get("end"))) and exact_object(stored, {"bytes", "lines"}) and nonnegative_int(stored.get("bytes")) and nonnegative_int(stored.get("lines")))
    if version == "contextguard.mcp.stats.v1":
        if not exact_object(payload, {"schema_version", "namespace", "session", "storage"}):
            return False
        namespace, session, storage = payload["namespace"], payload["session"], payload["storage"]
        return (exact_object(namespace, {"fingerprint", "scope", "isolation"}) and isinstance(namespace.get("fingerprint"), str) and bool(re.fullmatch(r"[a-f0-9]{16}", namespace["fingerprint"])) and namespace.get("scope") == "session" and namespace.get("isolation") == "single_root_single_namespace" and exact_object(session, {"tool_calls", "tool_errors", "protocol_errors", "accepted_input_bytes", "compressed_bytes", "retrieved_bytes", "redacted_lines"}) and all(exact_object(session[key], set(TOOL_NAMES)) and all(nonnegative_int(item) for item in session[key].values()) for key in ("tool_calls", "tool_errors")) and all(nonnegative_int(session[key]) for key in {"protocol_errors", "accepted_input_bytes", "compressed_bytes", "retrieved_bytes", "redacted_lines"}) and exact_object(storage, {"artifacts_observed", "stored_bytes_observed", "visited_entries", "artifact_cap", "visited_entry_cap", "ambiguous", "artifact_cap_reached", "scan_capped"}) and all(nonnegative_int(storage[key]) for key in {"artifacts_observed", "stored_bytes_observed", "visited_entries", "artifact_cap", "visited_entry_cap"}) and isinstance(storage.get("ambiguous"), bool) and isinstance(storage.get("artifact_cap_reached"), bool) and isinstance(storage.get("scan_capped"), bool))
    return False


def safe_regular(path: Path, *, executable: bool = False) -> Path:
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
        raise ValueError("invalid trusted helper layout")
    if executable and not st.st_mode & stat.S_IXUSR:
        raise ValueError("invalid trusted helper layout")
    return path.resolve(strict=True)


def directory_flags() -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    return flags | getattr(os, "O_CLOEXEC", 0)


def regular_read_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


class Server:
    def __init__(self, root: Path, namespace: str) -> None:
        if not NAMESPACE_RE.fullmatch(namespace):
            raise ValueError("invalid namespace")
        if root.is_symlink() or not root.is_dir():
            raise ValueError("invalid root")
        self.root = root.resolve(strict=True)
        self.root_fd = os.open(self.root, directory_flags())
        if not stat.S_ISDIR(os.fstat(self.root_fd).st_mode):
            os.close(self.root_fd)
            raise ValueError("invalid root")
        self.namespace_fd = -1
        self.lock_fd = -1
        self.server_dir = Path(__file__).resolve().parent
        try:
            self.compress_helper, self.artifact_helper = self._trusted_layout()
            self.namespace_dir = self._namespace_dir(namespace)
            self.lock_fd = self._lock_namespace()
        except BaseException:
            self.close()
            raise
        self.secret = os.urandom(32)
        self.state = "PRE_INIT"
        self.calls = {name: 0 for name in TOOL_NAMES}
        self.errors = {name: 0 for name in TOOL_NAMES}
        self.protocol_errors = 0
        self.accepted_input_bytes = 0
        self.compressed_bytes = 0
        self.retrieved_bytes = 0
        self.redacted_lines = 0
        self.attempts = 0

    def _trusted_layout(self) -> tuple[Path, Path]:
        here = self.server_dir
        current = Path(__file__).name
        source = current == "context_guard_mcp.py"
        expected = (
            ("context_guard_mcp.py", "context_compress.py", "context_escrow.py", "sanitize_output.py")
            if source else
            ("context-guard-mcp", "context-guard-compress", "context-guard-artifact", "context-guard-sanitize-output")
        )
        if current != expected[0]:
            raise ValueError("invalid trusted helper layout")
        alternate = (
            ("context-guard-mcp", "context-guard-compress", "context-guard-artifact", "context-guard-sanitize-output")
            if source else
            ("context_guard_mcp.py", "context_compress.py", "context_escrow.py", "sanitize_output.py")
        )
        if any((here / name).exists() or (here / name).is_symlink() for name in alternate):
            raise ValueError("invalid trusted helper layout")
        resolved = [safe_regular(here / name, executable=not source) for name in expected]
        if any(item.parent != here for item in resolved):
            raise ValueError("invalid trusted helper layout")
        return resolved[1], resolved[2]

    def _open_private_child_dir(self, parent_fd: int, name: str) -> int:
        """Create/open one storage component without ever following its name."""
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        fd = os.open(name, directory_flags(), dir_fd=parent_fd)
        try:
            st = os.fstat(fd)
            if not stat.S_ISDIR(st.st_mode):
                raise ValueError("invalid namespace storage")
            os.fchmod(fd, stat.S_IMODE(st.st_mode) & 0o700)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _namespace_dir(self, namespace: str) -> Path:
        digest = hashlib.sha256(
            b"contextguard.mcp.namespace.v1\0" + str(self.root).encode("utf-8") + b"\0" + namespace.encode("utf-8")
        ).hexdigest()[:24]
        parent_fd = self.root_fd
        opened: list[int] = []
        try:
            for component in (".context-guard", "mcp", "ns-" + digest):
                child = self._open_private_child_dir(parent_fd, component)
                opened.append(child)
                parent_fd = child
            self.namespace_fd = opened[-1]
            for fd in opened[:-1]:
                os.close(fd)
            return self.root / ".context-guard" / "mcp" / ("ns-" + digest)
        except BaseException:
            for fd in opened:
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise

    def _lock_namespace(self) -> int:
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(".context-guard-mcp.lock", flags, 0o600, dir_fd=self.namespace_fd)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError()
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except OSError:
            os.close(fd)
            raise ValueError("namespace is already in use")

    def close(self) -> None:
        if self.lock_fd >= 0:
            try:
                fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(self.lock_fd)
            except OSError:
                pass
            self.lock_fd = -1
        if self.namespace_fd >= 0:
            try:
                os.close(self.namespace_fd)
            except OSError:
                pass
            self.namespace_fd = -1
        if getattr(self, "root_fd", -1) >= 0:
            try:
                os.close(self.root_fd)
            except OSError:
                pass
            self.root_fd = -1

    def fingerprint(self) -> str:
        return hmac.new(self.secret, self.namespace_dir.name.encode("ascii"), hashlib.sha256).hexdigest()[:16]

    def run_helper(self, argv: list[str], stdin: bytes, stdout_cap: int) -> dict[str, object] | None:
        env = {"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1", "LANG": "C", "LC_ALL": "C"}
        deadline = time.monotonic() + HELPER_TIMEOUT
        try:
            proc = subprocess.Popen(
                [sys.executable, *map(str, argv)], cwd=self.root, env=env, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, close_fds=True, start_new_session=True,
            )
        except OSError:
            return None
        output = {"stdout": bytearray(), "stderr": bytearray()}
        overflow = threading.Event()
        writer_done = threading.Event()
        writer_failed = threading.Event()

        def drain(name: str, stream: Any, cap: int) -> None:
            try:
                while True:
                    part = stream.read(65536)
                    if not part:
                        return
                    if len(output[name]) + len(part) > cap:
                        overflow.set()
                        # Continue draining after the bounded capture is full so a
                        # malicious child cannot keep a pipe or a grandchild alive.
                    elif not overflow.is_set():
                        output[name].extend(part)
            finally:
                try:
                    stream.close()
                except OSError:
                    pass

        def write_stdin() -> None:
            try:
                assert proc.stdin is not None
                view = memoryview(stdin)
                while view:
                    written = proc.stdin.write(view)
                    if written is None:
                        written = 0
                    view = view[written:]
                proc.stdin.flush()
            except (BrokenPipeError, OSError, ValueError):
                writer_failed.set()
            finally:
                try:
                    if proc.stdin is not None:
                        proc.stdin.close()
                except OSError:
                    pass
                writer_done.set()

        threads = [
            threading.Thread(target=drain, args=("stdout", proc.stdout, stdout_cap), daemon=True),
            threading.Thread(target=drain, args=("stderr", proc.stderr, MAX_HELPER_STDERR), daemon=True),
        ]
        for thread in threads:
            thread.start()
        writer = threading.Thread(target=write_stdin)
        writer.start()
        failed = False
        terminated = False

        def terminate_group() -> None:
            nonlocal terminated
            if terminated:
                return
            terminated = True
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except OSError:
                try:
                    proc.terminate()
                except OSError:
                    pass
            try:
                proc.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    try:
                        proc.kill()
                    except OSError:
                        pass

        while proc.poll() is None or not writer_done.is_set():
            if overflow.is_set() or writer_failed.is_set() or time.monotonic() >= deadline:
                failed = True
                terminate_group()
                break
            time.sleep(0.01)
        try:
            proc.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            failed = True
            terminate_group()
        if not writer_done.is_set():
            failed = True
            terminate_group()
            try:
                if proc.stdin is not None:
                    proc.stdin.close()
            except OSError:
                pass
        # All pipe workers must finish: never leave daemon pipe threads or a
        # process group behind after a timed-out/non-reading helper.
        for thread in (*threads, writer):
            thread.join(1.0)
        if any(thread.is_alive() for thread in (*threads, writer)):
            failed = True
            terminate_group()
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                try:
                    if stream is not None:
                        stream.close()
                except OSError:
                    pass
            for thread in (*threads, writer):
                thread.join(1.0)
        if failed or overflow.is_set() or writer_failed.is_set() or any(thread.is_alive() for thread in (*threads, writer)) or proc.returncode != 0:
            return None
        try:
            raw = bytes(output["stdout"]).decode("utf-8")
            parsed = json.loads(raw, object_pairs_hook=reject_duplicates, parse_constant=reject_nonfinite)
            if not isinstance(parsed, dict) or not is_safe_scalar(parsed):
                return None
            return parsed
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            return None

    def scan(self) -> dict[str, object]:
        observed = 0
        bytes_observed = 0
        visited = 0
        ambiguous = False
        capped = False
        names: dict[str, set[str]] = {}
        try:
            # scandir owns only the duplicate descriptor; the retained namespace
            # descriptor remains the canonical authority for every later open.
            with os.scandir(os.dup(self.namespace_fd)) as entries:
                for entry in entries:
                    if entry.name == ".context-guard-mcp.lock":
                        continue
                    if visited >= MAX_VISITED_ENTRIES:
                        capped = True
                        ambiguous = True
                        break
                    visited += 1
                    match = re.fullmatch(r"([a-f0-9]{20})\.(txt|json)", entry.name)
                    if match is None:
                        ambiguous = True
                        continue
                    try:
                        st = os.stat(entry.name, dir_fd=self.namespace_fd, follow_symlinks=False)
                        if not stat.S_ISREG(st.st_mode):
                            ambiguous = True
                            continue
                    except OSError:
                        ambiguous = True
                        continue
                    names.setdefault(match.group(1), set()).add(match.group(2))
        except OSError:
            return {"observed": 0, "bytes": 0, "visited": 0, "ambiguous": True, "capped": False}
        for artifact_id, pair in names.items():
            if set(pair) != {"txt", "json"}:
                ambiguous = True
                continue
            metadata_fd = -1
            try:
                txt_st = os.stat(artifact_id + ".txt", dir_fd=self.namespace_fd, follow_symlinks=False)
                if not stat.S_ISREG(txt_st.st_mode):
                    raise ValueError()
                metadata_fd = os.open(artifact_id + ".json", regular_read_flags(), dir_fd=self.namespace_fd)
                st = os.fstat(metadata_fd)
                if not stat.S_ISREG(st.st_mode) or st.st_size > 65536:
                    raise ValueError()
                chunks: list[bytes] = []
                remaining = st.st_size + 1
                while remaining:
                    part = os.read(metadata_fd, min(65536, remaining))
                    if not part:
                        break
                    chunks.append(part)
                    remaining -= len(part)
                os.close(metadata_fd)
                metadata_fd = -1
                raw_meta = b"".join(chunks)
                if len(raw_meta) != st.st_size:
                    raise ValueError()
                metadata = json.loads(raw_meta.decode("utf-8"), object_pairs_hook=reject_duplicates, parse_constant=reject_nonfinite)
                stored = metadata.get("stored_output") if isinstance(metadata, dict) else None
                valid = isinstance(stored, dict) and metadata.get("artifact_id") == artifact_id and stored.get("content_file") == artifact_id + ".txt" and stored.get("metadata_file") == artifact_id + ".json" and isinstance(stored.get("bytes"), int) and not isinstance(stored.get("bytes"), bool) and 0 <= stored["bytes"] <= MAX_CONTENT_BYTES and txt_st.st_size == stored["bytes"] and isinstance(stored.get("lines"), int) and not isinstance(stored.get("lines"), bool) and stored["lines"] >= 0 and isinstance(stored.get("sha256"), str) and bool(re.fullmatch(r"[a-f0-9]{64}", stored["sha256"]))
                if not valid:
                    raise ValueError()
                if observed < MAX_ARTIFACTS:
                    observed += 1
                    bytes_observed += stored["bytes"]
            except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError, DuplicateKey, NonFinite):
                ambiguous = True
            finally:
                if metadata_fd >= 0:
                    try:
                        os.close(metadata_fd)
                    except OSError:
                        pass
        return {"observed": min(observed, MAX_ARTIFACTS), "bytes": bytes_observed, "visited": visited, "ambiguous": ambiguous, "capped": capped}

    def result(self, tool: str, payload: dict[str, object], is_error: bool = False) -> dict[str, object]:
        if not valid_tool_payload(payload, is_error) or self._payload_leaks_private_value(payload):
            is_error = True
            payload = tool_error("response_too_large")
        if is_error:
            self.errors[tool] += 1
        result = call_result(payload, is_error)
        if len(compact(result).encode("utf-8")) > MAX_RESPONSE_BYTES:
            if not is_error:
                self.errors[tool] += 1
                return call_result(tool_error("response_too_large"), True)
        return result

    def _payload_leaks_private_value(self, value: object, *, content: bool = False) -> bool:
        """Reject internal values structurally; do not inspect sanctioned content."""
        private = {
            str(self.root), str(self.namespace_dir), str(self.compress_helper),
            str(self.artifact_helper), self.namespace_dir.name,
        }
        if isinstance(value, dict):
            return any(self._payload_leaks_private_value(item, content=content or key == "content") for key, item in value.items())
        if isinstance(value, list):
            return any(self._payload_leaks_private_value(item, content=content) for item in value)
        if isinstance(value, str) and not content:
            # Exact comparison protects short values; only long internal tokens
            # receive containment checking, avoiding false positives for a one-byte
            # namespace such as "A" in normal protocol strings.
            return any(value == item or len(item) >= 8 and item in value for item in private)
        return False

    def fail(self, tool: str, code: str) -> dict[str, object]:
        return self.result(tool, tool_error(code), True)

    def compress(self, arguments: object) -> dict[str, object]:
        tool = "context_guard_compress"
        if not isinstance(arguments, dict) or set(arguments) - {"content", "content_type", "mode", "protected_policy", "store"} or not isinstance(arguments.get("content"), str):
            return self.fail(tool, "invalid_arguments")
        content = arguments["content"]
        if not is_safe_scalar(content):
            return self.fail(tool, "invalid_arguments")
        content_type = arguments.get("content_type")
        mode = arguments.get("mode", "conservative")
        protected = arguments.get("protected_policy", True)
        store = arguments.get("store", True)
        if content_type is not None and content_type not in CONTENT_TYPES or mode not in MODES or not isinstance(protected, bool) or not isinstance(store, bool):
            return self.fail(tool, "invalid_arguments")
        raw = content.encode("utf-8")
        if len(raw) > MAX_CONTENT_BYTES:
            return self.fail(tool, "input_too_large")
        self.accepted_input_bytes += len(raw)
        if store:
            scan = self.scan()
            if scan["ambiguous"]:
                return self.fail(tool, "namespace_ambiguous")
            if scan["observed"] >= MAX_ARTIFACTS:
                return self.fail(tool, "namespace_full")
        argv: list[str] = [str(self.compress_helper), "--json", "--max-bytes", str(MAX_CONTENT_BYTES), "--mode", str(mode)]
        if content_type is not None:
            argv.extend(["--type", str(content_type)])
        if protected:
            argv.append("--protected-policy")
        compressed = self.run_helper(argv, raw, min(MAX_HELPER_OUTPUT, len(raw) * 6 + 256 * 1024))
        if compressed is None:
            return self.fail(tool, "helper_failed")
        text = compressed.get("content")
        metadata = compressed.get("metadata")
        if not isinstance(text, str) or not isinstance(metadata, dict):
            return self.fail(tool, "helper_failed")
        bytes_meta = metadata.get("bytes")
        lines_meta = metadata.get("lines")
        token_meta = metadata.get("token_proxy")
        redaction = metadata.get("redaction")
        policy = metadata.get("protected_zone_policy")
        strategy = metadata.get("strategy")
        selected_type = metadata.get("content_type")
        type_source = metadata.get("type_source")
        if not (isinstance(bytes_meta, dict) and isinstance(lines_meta, dict) and isinstance(token_meta, dict) and isinstance(redaction, dict) and isinstance(policy, dict) and selected_type in CONTENT_TYPES and type_source in ("detected", "override") and strategy in {"json-compact", "diff-keep-changes", "log-collapse-repeats", "search-dedupe", "code-whitespace", "prose-whitespace", "prose-readable-window"} and isinstance(metadata.get("lossy"), bool)):
            return self.fail(tool, "helper_failed")
        def integer(source: dict[str, object], key: str) -> int | None:
            value = source.get(key)
            return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None
        original_b, compressed_b = integer(bytes_meta, "original"), integer(bytes_meta, "compressed")
        original_l, compressed_l = integer(lines_meta, "original"), integer(lines_meta, "compressed")
        original_t, compressed_t = integer(token_meta, "original"), integer(token_meta, "compressed")
        redacted = integer(redaction, "redacted_lines")
        if None in (original_b, compressed_b, original_l, compressed_l, original_t, compressed_t, redacted):
            return self.fail(tool, "helper_failed")
        self.compressed_bytes += compressed_b
        self.redacted_lines += redacted
        preview, capped = cap_utf8(text, MAX_RETURN_BYTES)
        artifact: object = None
        if store:
            stored = self.run_helper([str(self.artifact_helper), "--dir", str(self.namespace_dir), "store", "--json", "--max-bytes", str(MAX_CONTENT_BYTES), "--command", "context-guard-mcp compress"], raw, 256 * 1024)
            if stored is None:
                return self.fail(tool, "helper_failed")
            artifact_id = stored.get("artifact_id")
            stored_output = stored.get("stored_output")
            if not isinstance(artifact_id, str) or not ARTIFACT_ID_RE.fullmatch(artifact_id) or not isinstance(stored_output, dict):
                return self.fail(tool, "helper_failed")
            stored_bytes, stored_lines = integer(stored_output, "bytes"), integer(stored_output, "lines")
            if stored_bytes is None or stored_lines is None:
                return self.fail(tool, "helper_failed")
            artifact = {"artifact_id": artifact_id, "handle": "contextguard-artifact:" + artifact_id, "stored_bytes": stored_bytes, "stored_lines": stored_lines, "exact_scope": "sanitized_accepted_input", "retrieve": {"tool": "context_guard_retrieve", "arguments": {"artifact_id": artifact_id}}}
        elif capped:
            return self.fail(tool, "result_too_large_without_fallback")
        zone_counts = policy.get("zone_counts") if protected else {}
        classes = sorted(key for key in PROTECTED_CLASSES if isinstance(zone_counts, dict) and isinstance(zone_counts.get(key), int) and zone_counts[key] > 0)
        payload = {"schema_version": "contextguard.mcp.compress.v1", "content": preview, "content_capped": capped, "compression": {"content_type": selected_type, "type_source": type_source, "strategy": strategy, "lossy": metadata["lossy"], "bytes": {"measurement": "observed", "original": original_b, "compressed": compressed_b, "returned": len(preview.encode("utf-8"))}, "lines": {"measurement": "observed", "original": original_l, "compressed": compressed_l, "returned": line_count(preview)}, "token_proxy": {"measurement": "estimated", "method": "chars_div_4", "original": original_t, "compressed": compressed_t}, "redaction": {"redacted_lines": redacted, "redacted_before_receipt": True}, "protected_policy": {"enabled": protected, "retrieval_required": bool(policy.get("retrieval_required")) if protected else False, "detected_classes": classes}}, "artifact": artifact}
        return self.result(tool, payload)

    def retrieve(self, arguments: object) -> dict[str, object]:
        tool = "context_guard_retrieve"
        if not isinstance(arguments, dict) or set(arguments) - {"artifact_id", "lines", "pattern", "max_lines", "max_chars"}:
            return self.fail(tool, "invalid_arguments")
        artifact_id = arguments.get("artifact_id")
        lines = arguments.get("lines")
        pattern = arguments.get("pattern")
        max_lines = arguments.get("max_lines", MAX_RETRIEVE_LINES)
        max_chars = arguments.get("max_chars", MAX_RETRIEVE_CHARS)
        if not isinstance(artifact_id, str) or not ARTIFACT_ID_RE.fullmatch(artifact_id) or lines is not None and not isinstance(lines, str) or pattern is not None and not isinstance(pattern, str) or lines is not None and pattern is not None or not isinstance(max_lines, int) or isinstance(max_lines, bool) or not 1 <= max_lines <= MAX_RETRIEVE_LINES or not isinstance(max_chars, int) or isinstance(max_chars, bool) or not 1 <= max_chars <= MAX_RETRIEVE_CHARS:
            return self.fail(tool, "invalid_arguments")
        if lines is not None:
            if not LINES_RE.fullmatch(lines):
                return self.fail(tool, "invalid_arguments")
            parts = [int(item) for item in lines.split(":")]
            if len(parts) == 1:
                parts.append(parts[0])
            if parts[0] > parts[1] or parts[1] > 10_000_000:
                return self.fail(tool, "invalid_arguments")
        if pattern is not None and (not is_safe_scalar(pattern) or "\0" in pattern or not 1 <= len(pattern.encode("utf-8")) <= 512):
            return self.fail(tool, "invalid_arguments")
        argv = [str(self.artifact_helper), "--dir", str(self.namespace_dir), "get", artifact_id, "--json", "--max-lines", str(max_lines), "--max-chars", str(max_chars)]
        if lines is not None:
            argv.extend(["--lines", lines])
        elif pattern is not None:
            argv.extend(["--pattern", pattern])
        found = self.run_helper(argv, b"", 128 * 1024)
        if found is None:
            # The helper intentionally keeps error detail on stderr.  It is not
            # safe to classify it more finely, so verify pair shape locally.
            present = []
            malformed = False
            for name in (artifact_id + ".txt", artifact_id + ".json"):
                try:
                    st = os.stat(name, dir_fd=self.namespace_fd, follow_symlinks=False)
                    present.append(True)
                    malformed = malformed or not stat.S_ISREG(st.st_mode)
                except FileNotFoundError:
                    present.append(False)
                except OSError:
                    return self.fail(tool, "artifact_invalid")
            if not any(present):
                return self.fail(tool, "artifact_not_found")
            return self.fail(tool, "artifact_invalid")
        text, query, stored = found.get("content"), found.get("query"), found.get("stored_output")
        if not isinstance(text, str) or not isinstance(query, dict) or not isinstance(stored, dict):
            return self.fail(tool, "artifact_invalid")
        selector = query.get("selector")
        if not isinstance(selector, dict) or selector.get("type") not in ("head", "lines", "pattern"):
            return self.fail(tool, "artifact_invalid")
        returned_lines, matched_lines, total_lines = query.get("returned_lines"), query.get("matched_lines"), query.get("total_lines")
        stored_bytes, stored_lines = stored.get("bytes"), stored.get("lines")
        values = (returned_lines, matched_lines, total_lines, stored_bytes, stored_lines)
        if not all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in values):
            return self.fail(tool, "artifact_invalid")
        text, chars_capped = cap_codepoints(text, max_chars)
        text, bytes_capped = cap_utf8(text, MAX_RETURN_BYTES)
        capped = chars_capped or bytes_capped
        query_out: dict[str, object] = {"type": selector["type"], "returned_lines": returned_lines, "matched_lines": matched_lines, "total_lines": total_lines}
        if selector["type"] == "lines":
            start, end = selector.get("start"), selector.get("end")
            if not isinstance(start, int) or not isinstance(end, int):
                return self.fail(tool, "artifact_invalid")
            query_out.update({"start": start, "end": end})
        self.retrieved_bytes += len(text.encode("utf-8"))
        return self.result(tool, {"schema_version": "contextguard.mcp.retrieve.v1", "artifact_id": artifact_id, "content": text, "content_capped": bool(found.get("capped")) or capped, "returned_bytes": len(text.encode("utf-8")), "query": query_out, "stored": {"bytes": stored_bytes, "lines": stored_lines}})

    def stats(self, arguments: object) -> dict[str, object]:
        tool = "context_guard_stats"
        if not isinstance(arguments, dict) or arguments:
            return self.fail(tool, "invalid_arguments")
        scan = self.scan()
        storage = {"artifacts_observed": scan["observed"], "stored_bytes_observed": scan["bytes"], "visited_entries": scan["visited"], "artifact_cap": MAX_ARTIFACTS, "visited_entry_cap": MAX_VISITED_ENTRIES, "ambiguous": scan["ambiguous"], "artifact_cap_reached": scan["observed"] >= MAX_ARTIFACTS, "scan_capped": scan["capped"]}
        payload = {"schema_version": "contextguard.mcp.stats.v1", "namespace": {"fingerprint": self.fingerprint(), "scope": "session", "isolation": "single_root_single_namespace"}, "session": {"tool_calls": dict(self.calls), "tool_errors": dict(self.errors), "protocol_errors": self.protocol_errors, "accepted_input_bytes": self.accepted_input_bytes, "compressed_bytes": self.compressed_bytes, "retrieved_bytes": self.retrieved_bytes, "redacted_lines": self.redacted_lines}, "storage": storage}
        return self.result(tool, payload)


TOOL_NAMES = ("context_guard_compress", "context_guard_retrieve", "context_guard_stats")


def tools() -> list[dict[str, object]]:
    base = {"type": "object", "additionalProperties": False}
    compress_schema = dict(base, properties={"content": {"type": "string", "maxLength": MAX_CONTENT_BYTES, "description": "Content to sanitize and compress; UTF-8 bytes are capped at 786432."}, "content_type": {"type": "string", "enum": list(CONTENT_TYPES), "description": "Optional content classification override."}, "mode": {"type": "string", "enum": list(MODES), "default": "conservative", "description": "Compression mode; conservative preserves more structure."}, "protected_policy": {"type": "boolean", "default": True, "description": "Preserve detected protected zones and require retrieval when needed."}, "store": {"type": "boolean", "default": True, "description": "Store sanitized accepted input for namespace-scoped retrieval."}}, required=["content"])
    retrieve_schema = dict(base, properties={"artifact_id": {"type": "string", "pattern": "^[a-f0-9]{20}$", "description": "Namespace-scoped sanitized artifact identifier."}, "lines": {"type": "string", "pattern": "^[1-9][0-9]{0,6}(?::[1-9][0-9]{0,6})?$", "description": "Optional inclusive one-based line or line range selector."}, "pattern": {"type": "string", "minLength": 1, "maxLength": 512, "description": "Optional literal UTF-8 pattern selector."}, "max_lines": {"type": "integer", "minimum": 1, "maximum": MAX_RETRIEVE_LINES, "default": MAX_RETRIEVE_LINES, "description": "Maximum returned lines, limited to 500."}, "max_chars": {"type": "integer", "minimum": 1, "maximum": MAX_RETRIEVE_CHARS, "default": MAX_RETRIEVE_CHARS, "description": "Maximum returned Unicode code points, limited to 20000."}}, required=["artifact_id"], allOf=[{"not": {"required": ["lines", "pattern"]}}])
    return [
        {"name": "context_guard_compress", "description": "Sanitize, compress, and optionally retain local content.", "inputSchema": compress_schema, "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False}},
        {"name": "context_guard_retrieve", "description": "Retrieve sanitized content from this local namespace.", "inputSchema": retrieve_schema, "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}},
        {"name": "context_guard_stats", "description": "Return local session and namespace statistics.", "inputSchema": base, "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}},
    ]


def valid_id(value: object) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        encoded = safe_utf8_bytes(value)
        return encoded is not None and len(encoded) <= 128
    return isinstance(value, int) and not isinstance(value, bool) and -(2**53 - 1) <= value <= 2**53 - 1


def valid_wire_response(value: object) -> bool:
    """Final exact response schema check immediately before stdout writes."""
    if not isinstance(value, dict) or not is_safe_scalar(value) or set(value) != {"jsonrpc", "id", "result"} and set(value) != {"jsonrpc", "id", "error"} or value.get("jsonrpc") != "2.0" or not valid_id(value.get("id")):
        return False
    if "error" in value:
        error = value["error"]
        return exact_object(error, {"code", "message"}) and isinstance(error.get("code"), int) and not isinstance(error.get("code"), bool) and isinstance(error.get("message"), str)
    result = value["result"]
    if result == {}:
        return True
    if exact_object(result, {"protocolVersion", "capabilities", "serverInfo"}):
        return result.get("protocolVersion") in SUPPORTED_VERSIONS and result.get("capabilities") == {"tools": {"listChanged": False}} and result.get("serverInfo") == {"name": "context-guard-mcp", "version": "1.0.0"}
    if exact_object(result, {"tools"}):
        return result.get("tools") == tools()
    if not exact_object(result, {"content", "structuredContent", "isError"}) or not isinstance(result.get("isError"), bool) or not isinstance(result.get("content"), list) or len(result["content"]) != 1:
        return False
    text = result["content"][0]
    return exact_object(text, {"type", "text"}) and text.get("type") == "text" and isinstance(text.get("text"), str) and isinstance(result.get("structuredContent"), dict) and valid_tool_payload(result["structuredContent"], result["isError"]) and text["text"] == compact(result["structuredContent"])


def base_request(value: object) -> tuple[bool, bool, object]:
    if not isinstance(value, dict) or set(value) - {"jsonrpc", "method", "params", "id"} or value.get("jsonrpc") != "2.0" or not isinstance(value.get("method"), str) or "params" in value and not isinstance(value["params"], dict) or "id" in value and not valid_id(value["id"]):
        return False, False, None
    return True, "id" not in value, value.get("id")


def params_only_meta(params: object) -> bool:
    return params is None or isinstance(params, dict) and set(params) <= {"_meta"} and ("_meta" not in params or isinstance(params["_meta"], dict))


def initialize_params(params: object) -> bool:
    if not isinstance(params, dict) or set(params) - {"protocolVersion", "capabilities", "clientInfo", "_meta"} or not isinstance(params.get("protocolVersion"), str) or not isinstance(params.get("capabilities"), dict) or not isinstance(params.get("clientInfo"), dict) or "_meta" in params and not isinstance(params["_meta"], dict):
        return False
    info = params["clientInfo"]
    return set(info) <= {"name", "version", "title", "description", "websiteUrl", "icons"} and isinstance(info.get("name"), str) and isinstance(info.get("version"), str) and all(isinstance(info[key], str) for key in ("title", "description", "websiteUrl") if key in info) and ("icons" not in info or isinstance(info["icons"], list))


def handle(server: Server, request: dict[str, object], notification: bool) -> dict[str, object] | None:
    method, params, request_id = request["method"], request.get("params"), request.get("id")
    def response(result: dict[str, object]) -> dict[str, object] | None:
        return None if notification else {"jsonrpc": "2.0", "id": request_id, "result": result}
    def failure(code: int, message: str) -> dict[str, object] | None:
        if code in (-32600, -32602, -32603):
            server.protocol_errors += 1
        return None if notification else error_response(request_id, code, message)
    if method == "ping":
        return response({}) if params_only_meta(params) else failure(-32602, "Invalid params")
    if method == "initialize":
        if server.state != "PRE_INIT":
            return failure(-32600, "Already initialized")
        if not initialize_params(params):
            return failure(-32602, "Invalid params")
        if notification:
            return None
        version = params["protocolVersion"]
        negotiated = version if version in SUPPORTED_VERSIONS else SUPPORTED_VERSIONS[0]
        server.state = "WAIT_INITIALIZED"
        return response({"protocolVersion": negotiated, "capabilities": {"tools": {"listChanged": False}}, "serverInfo": {"name": "context-guard-mcp", "version": "1.0.0"}})
    if method == "notifications/initialized":
        if notification and server.state == "WAIT_INITIALIZED" and params_only_meta(params):
            server.state = "READY"
        if notification:
            return None
        if server.state in {"PRE_INIT", "WAIT_INITIALIZED"}:
            return failure(-32002, "Server not initialized")
        return failure(-32601, "Method not found")
    if server.state == "PRE_INIT" or server.state == "WAIT_INITIALIZED":
        return failure(-32002, "Server not initialized")
    if method == "tools/list":
        if not (params is None or isinstance(params, dict) and set(params) <= {"cursor", "_meta"} and (params.get("cursor") is None) and ("_meta" not in params or isinstance(params["_meta"], dict))):
            return failure(-32602, "Invalid params")
        return response({"tools": tools()})
    if method == "tools/call":
        if not isinstance(params, dict) or set(params) - {"name", "arguments", "_meta"} or not isinstance(params.get("name"), str) or "arguments" in params and not isinstance(params["arguments"], dict) or "_meta" in params and not isinstance(params["_meta"], dict):
            return failure(-32602, "Invalid params")
        name = params["name"]
        if name not in TOOL_NAMES:
            return failure(-32602, "Invalid params")
        if notification:
            return None
        server.attempts += 1
        server.calls[name] += 1
        if server.attempts > MAX_CALLS:
            return response(server.fail(name, "rate_limit_reached"))
        if name == "context_guard_compress":
            result = server.compress(params.get("arguments", {}))
        elif name == "context_guard_retrieve":
            result = server.retrieve(params.get("arguments", {}))
        else:
            result = server.stats(params.get("arguments", {}))
        return response(result)
    return failure(-32601, "Method not found")


def emit(value: dict[str, object]) -> bool:
    try:
        if not valid_wire_response(value):
            return False
        wire = compact(value)
        if len(wire.encode("utf-8")) > MAX_RESPONSE_BYTES:
            return False
        sys.stdout.write(wire + "\n")
        sys.stdout.flush()
        return True
    except (BrokenPipeError, UnicodeEncodeError):
        return False


def serve(server: Server) -> int:
    stream = sys.stdin.buffer
    while True:
        line = stream.readline(MAX_MESSAGE_BYTES + 3)
        if not line:
            return 0
        if len(line) == MAX_MESSAGE_BYTES + 3:
            emit(error_response(None, -32600, "Message too large"))
            return 1
        if not line.endswith(b"\n"):
            emit(error_response(None, -32700, "Parse error"))
            return 1
        payload = line[:-1]
        if payload.endswith(b"\r"):
            payload = payload[:-1]
        if len(payload) > MAX_MESSAGE_BYTES:
            emit(error_response(None, -32600, "Message too large"))
            return 1
        try:
            data = json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicates, parse_constant=reject_nonfinite)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            server.protocol_errors += 1
            emit(error_response(None, -32700, "Parse error"))
            continue
        except (DuplicateKey, NonFinite, ValueError):
            server.protocol_errors += 1
            emit(error_response(None, -32600, "Invalid Request"))
            continue
        valid, notification, _request_id = base_request(data)
        if not valid or not is_safe_scalar(data):
            server.protocol_errors += 1
            emit(error_response(None, -32600, "Invalid Request"))
            continue
        try:
            result = handle(server, data, notification)
        except Exception:
            # A valid request must not let an implementation defect escape as a
            # traceback or local detail.  Notifications deliberately stay
            # silent even on this path.
            server.protocol_errors += 1
            result = None if notification else error_response(data.get("id"), -32603, "Internal error")
        if result is not None and not emit(result):
            return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the local ContextGuard stdio MCP server.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--namespace", default="default")
    args = parser.parse_args(argv)
    try:
        server = Server(args.root, args.namespace)
    except (OSError, ValueError, UnicodeError):
        print("context-guard-mcp: startup failed", file=sys.stderr)
        return 2
    try:
        return serve(server)
    finally:
        try:
            server.close()
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
