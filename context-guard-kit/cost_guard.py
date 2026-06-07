#!/usr/bin/env python3
"""Passive Anthropic prompt-cache cost guardrails for ContextGuard.

This helper is intentionally advisory. It never calls Anthropic, never claims a
provider cache hit as billing authority, and never stores raw request text. The
local ledger stores keyed HMAC fingerprints over confirmed provider observations
so future preflights can warn about likely cache misses without leaking prompts.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import sys
import time
from dataclasses import dataclass
from typing import Any, NoReturn

TOOL_NAME = "context-guard-cost"
SCHEMA_VERSION = "contextguard.cost.v1"
DEFAULT_STORE_DIR = ".context-guard/cost-ledger"
LEDGER_NAME = "ledger.jsonl"
KEY_NAME = "hmac.key"
LOCK_OWNER_NAME = "owner.json"
HMAC_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{43}=$")
KEY_LOCK_WAIT_ATTEMPTS = 100
KEY_LOCK_POLL_SECONDS = 0.05
KEY_LOCK_STALE_SECONDS = 60.0
KEY_LOCK_METADATA_CLOCK_SKEW_SECONDS = 5.0
DEFAULT_MAX_BYTES = 10_000_000
MAX_MAX_BYTES = 100_000_000
TOKEN_PROXY_CHARS_PER_TOKEN = 4
DEFAULT_USD_TO_KRW = 1350.0
DEFAULT_SAFETY_FACTOR = 1.25
DEFAULT_LARGE_SECTION_BYTES = 64_000
MAX_LEDGER_ROWS = 20_000
TTL_SECONDS = {"5m": 5 * 60, "1h": 60 * 60}
ANTHROPIC_DOCS_URL = "https://docs.anthropic.com/en/build-with-claude/prompt-caching"
ANTHROPIC_PRICING_URL = "https://platform.claude.com/docs/en/about-claude/pricing"

SECRET_RE = re.compile(
    r"(?is)("
    r"-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----.*?-----END (?:[A-Z0-9 ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----|"
    r"AKIA[0-9A-Z]{16}|"
    r"gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"glpat-[A-Za-z0-9_-]{12,}|"
    r"xox[abprs]-[A-Za-z0-9-]{10,}|"
    r"sk-(?:ant|proj)-[A-Za-z0-9_-]{8,}|"
    r"sk-[A-Za-z0-9][A-Za-z0-9_-]{20,}|"
    r"AIza[0-9A-Za-z_\-]{20,}|"
    r"(?i:Authorization)\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+|"
    r"[?&](?:X-Amz-Signature|X-Amz-Credential|X-Amz-Security-Token|AWSAccessKeyId|Signature|sig|access_token|refresh_token|id_token|auth|authorization|api[_-]?key|apikey|token|secret|password|client[_-]?secret|private[_-]?key|privatekey|pgp[_-]?private[_-]?key|pgpprivatekey|ssh[_-]?key|sshkey|(?:aws[_-]?)?access[_-]?key(?:[_-]?id)?|awsaccesskeyid)=[^&#\s,}\]]+|"
    r"(?<![A-Za-z0-9])(?:api[_-]?key|apikey|token|secret|password|client[_-]?secret|authorization|credential|signature|sig|private[_-]?key|privatekey|pgp[_-]?private[_-]?key|pgpprivatekey|ssh[_-]?key|sshkey|(?:aws[_-]?)?access[_-]?key(?:[_-]?id)?|awsaccesskeyid)\s*[:=]\s*[^\s,}\]]+"
    r")"
)


class CostGuardError(ValueError):
    """User-facing deterministic failure."""


def fail(message: str) -> NoReturn:
    raise CostGuardError(message)


def reject_json_constant(value: str) -> NoReturn:
    raise ValueError(f"invalid JSON constant: {value}")


def json_bytes(data: Any) -> str:
    try:
        return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except ValueError as exc:
        fail(f"JSON value contained a non-finite number: {exc}")


def require_json_object(data: Any, label: str) -> dict[str, Any]:
    if not isinstance(data, dict):
        fail(f"{label} must be a JSON object")
    return data


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def finite_float_arg(value: Any, label: str, *, minimum: float = 0.0, allow_zero: bool = True) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        fail(f"{label} must be numeric")
    if not math.isfinite(number):
        fail(f"{label} must be finite")
    if allow_zero:
        if number < minimum:
            fail(f"{label} must be >= {minimum:g}")
    elif number <= minimum:
        fail(f"{label} must be > {minimum:g}")
    return number


def non_negative_int_arg(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if number < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return number


def byte_len_text(text: str) -> int:
    return len(text.encode("utf-8", errors="replace"))


def token_proxy_text(text: str) -> int:
    if not text:
        return 0
    return max(1, math.ceil(len(text) / TOKEN_PROXY_CHARS_PER_TOKEN))


def token_proxy_obj(data: Any) -> int:
    return token_proxy_text(json_bytes(data))


def read_text_path(path: str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> tuple[str, bool]:
    if max_bytes < 1 or max_bytes > MAX_MAX_BYTES:
        fail(f"max bytes must be between 1 and {MAX_MAX_BYTES}")
    if path == "-":
        raw = sys.stdin.buffer.read(max_bytes + 1)
    else:
        p = Path(path)
        try:
            st = p.stat()
        except OSError as exc:
            fail(f"could not read input file: {exc}")
        if not stat.S_ISREG(st.st_mode):
            fail("input path must be a regular file")
        if st.st_size > max_bytes + 1:
            # Read only the bounded prefix so large requests cannot exhaust memory.
            with p.open("rb") as fh:
                raw = fh.read(max_bytes + 1)
        else:
            raw = p.read_bytes()
    truncated = len(raw) > max_bytes
    if truncated:
        raw = raw[:max_bytes]
    return raw.decode("utf-8", errors="replace"), truncated


def load_json_input(path: str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> tuple[Any, bool]:
    text, truncated = read_text_path(path, max_bytes=max_bytes)
    if truncated:
        fail("JSON input exceeded max bytes")
    try:
        data = json.loads(text, parse_constant=reject_json_constant)
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON input at line {exc.lineno}: {exc.msg}")
    except ValueError as exc:
        fail(f"invalid JSON input: {exc}")
    return data, truncated


def secret_count_in_text(text: str) -> int:
    return sum(1 for _ in SECRET_RE.finditer(text))


def is_provider_cache_control(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    raw_type = value.get("type")
    raw_ttl = value.get("ttl")
    if raw_type is not None:
        return str(raw_type).strip().lower() == "ephemeral"
    if raw_ttl is None:
        return False
    ttl = str(raw_ttl).strip().lower()
    return ttl in {"5m", "1h", "60m", "hour"}


def clone_jsonish(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): clone_jsonish(v) for k, v in value.items()}
    if isinstance(value, list):
        return [clone_jsonish(item) for item in value]
    return value


def strip_cache_control(value: Any) -> Any:
    """Strip a provider cache_control marker from this object only.

    `cache_control` can also be legitimate user/application data nested inside
    tool schemas. Keep nested values intact unless the caller explicitly selects
    a recognized provider container.
    """
    if isinstance(value, dict):
        return {
            str(k): clone_jsonish(v)
            for k, v in value.items()
            if not (k == "cache_control" and is_provider_cache_control(v))
        }
    if isinstance(value, list):
        return [clone_jsonish(item) for item in value]
    return value


def strip_cache_control_at_path(value: Any, path: tuple[str, ...]) -> Any:
    if not path:
        return strip_cache_control(value)
    if isinstance(value, dict):
        head, *tail = path
        return {
            str(k): strip_cache_control_at_path(v, tuple(tail)) if str(k) == head else clone_jsonish(v)
            for k, v in value.items()
        }
    return clone_jsonish(value)


def strip_known_cache_controls(request: Any) -> Any:
    """Strip provider cache_control markers only from recognized request slots."""
    if not isinstance(request, dict):
        return clone_jsonish(request)
    out = clone_jsonish(request)

    explicit = out.get("cache_breakpoints")
    if isinstance(explicit, list):
        out["cache_breakpoints"] = [
            strip_cache_control(item) if isinstance(item, dict) else clone_jsonish(item)
            for item in explicit
        ]

    tools = out.get("tools")
    if isinstance(tools, list):
        out["tools"] = [strip_cache_control(tool) if isinstance(tool, dict) else clone_jsonish(tool) for tool in tools]

    system = out.get("system")
    if isinstance(system, list):
        out["system"] = [
            strip_cache_control(block) if isinstance(block, dict) else clone_jsonish(block)
            for block in system
        ]
    system_cache = out.get("system_cache")
    if isinstance(system_cache, dict):
        out["system_cache"] = strip_cache_control(system_cache)

    messages = out.get("messages")
    if isinstance(messages, list):
        stripped_messages = []
        for message in messages:
            if not isinstance(message, dict):
                stripped_messages.append(clone_jsonish(message))
                continue
            stripped_message = strip_cache_control(message)
            content = stripped_message.get("content")
            if isinstance(content, list):
                stripped_message["content"] = [
                    strip_cache_control(block) if isinstance(block, dict) else clone_jsonish(block)
                    for block in content
                ]
            stripped_messages.append(stripped_message)
        out["messages"] = stripped_messages

    return out


def cache_ttl(cache_control: Any) -> str:
    if not isinstance(cache_control, dict):
        return "5m"
    ttl = str(cache_control.get("ttl") or "5m").strip().lower()
    if ttl in {"1h", "60m", "hour"}:
        return "1h"
    return "5m"


def find_cache_control(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        cc = value.get("cache_control")
        if is_provider_cache_control(cc):
            return cc
    return None


def has_unsupported_cache_control(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and "cache_control" in value
        and not is_provider_cache_control(value.get("cache_control"))
    )


@dataclass(frozen=True)
class CacheBreakpoint:
    index: int
    kind: str
    ttl: str
    prefix: list[Any]
    section: Any
    unsupported: bool = False

    @property
    def breakpoint_id(self) -> str:
        return f"bp{self.index:03d}"


def _prompt_unit(kind: str, value: Any, *, cache_control_path: tuple[str, ...] = (), **meta: Any) -> dict[str, Any]:
    out = {"kind": kind, "value": strip_cache_control_at_path(value, cache_control_path)}
    for key, val in sorted(meta.items()):
        if val is not None:
            out[key] = val
    return out


def _append_unit(
    units: list[Any],
    breakpoints: list[CacheBreakpoint],
    *,
    kind: str,
    value: Any,
    cc: Any,
    cache_control_path: tuple[str, ...] = (),
    **meta: Any,
) -> None:
    unit = _prompt_unit(kind, value, cache_control_path=cache_control_path, **meta)
    units.append(unit)
    if isinstance(cc, dict):
        breakpoints.append(
            CacheBreakpoint(
                index=len(breakpoints) + 1,
                kind=kind,
                ttl=cache_ttl(cc),
                prefix=list(units),
                section=unit,
            )
        )


def extract_cache_breakpoints(request: Any) -> tuple[list[CacheBreakpoint], dict[str, Any]]:
    """Return cache breakpoints as ordered canonical prompt prefixes.

    Anthropic prompt caching is prefix-oriented. This parser therefore hashes the
    canonical prompt material from the beginning of the request through each
    cache_control breakpoint, rather than hashing arbitrary snippets. The parser
    is intentionally conservative and emits confidence warnings for unrecognized
    cache_control layouts.
    """
    units: list[Any] = []
    breakpoints: list[CacheBreakpoint] = []
    unsupported_cache_controls = 0

    if not isinstance(request, dict):
        return [], {"request_shape": "unsupported", "unsupported_cache_controls": 0}

    explicit = request.get("cache_breakpoints")
    if isinstance(explicit, list):
        for item in explicit:
            if not isinstance(item, dict):
                unsupported_cache_controls += 1
                continue
            if "cache_control" in item:
                cc = find_cache_control(item)
                if cc is None:
                    unsupported_cache_controls += 1
            else:
                cc = {"type": "ephemeral", "ttl": item.get("ttl", "5m")}
            _append_unit(units, breakpoints, kind=str(item.get("kind") or "explicit"), value=item, cc=cc)

    tools = request.get("tools")
    if isinstance(tools, list):
        for i, tool in enumerate(tools):
            cc = find_cache_control(tool)
            if has_unsupported_cache_control(tool):
                unsupported_cache_controls += 1
            _append_unit(units, breakpoints, kind="tool", value=tool, cc=cc, index=i)
    elif tools is not None:
        units.append(_prompt_unit("tools", tools))

    system = request.get("system")
    if isinstance(system, list):
        for i, block in enumerate(system):
            cc = find_cache_control(block)
            if has_unsupported_cache_control(block):
                unsupported_cache_controls += 1
            _append_unit(units, breakpoints, kind="system", value=block, cc=cc, index=i)
    elif system is not None:
        system_cache = request.get("system_cache") or {}
        cc = find_cache_control(system_cache)
        if has_unsupported_cache_control(system_cache):
            unsupported_cache_controls += 1
        _append_unit(units, breakpoints, kind="system", value=system, cc=cc)

    messages = request.get("messages")
    if isinstance(messages, list):
        for mi, message in enumerate(messages):
            if not isinstance(message, dict):
                _append_unit(units, breakpoints, kind="message", value=message, cc=None, index=mi)
                continue
            role = str(message.get("role") or "unknown")
            content = message.get("content")
            msg_cc = find_cache_control(message)
            if has_unsupported_cache_control(message):
                unsupported_cache_controls += 1
            if isinstance(content, list):
                for ci, block in enumerate(content):
                    cc = find_cache_control(block)
                    if has_unsupported_cache_control(block):
                        unsupported_cache_controls += 1
                    _append_unit(
                        units,
                        breakpoints,
                        kind="message_content",
                        value={"role": role, "content": block},
                        cc=cc,
                        cache_control_path=("content",),
                        message_index=mi,
                        content_index=ci,
                    )
                if msg_cc and not any(find_cache_control(block) for block in content if isinstance(block, dict)):
                    # Message-level cache_control around a list is less common, but keep a
                    # conservative prefix fingerprint over the whole message.
                    _append_unit(units, breakpoints, kind="message", value=message, cc=msg_cc, index=mi)
            else:
                _append_unit(units, breakpoints, kind="message", value=message, cc=msg_cc, index=mi)
    elif messages is not None:
        units.append(_prompt_unit("messages", messages))

    raw = json_bytes(request)
    found_cc = raw.count('"cache_control"')
    metadata = {
        "request_shape": "anthropic_like",
        "prompt_units": len(units),
        "unsupported_cache_controls": unsupported_cache_controls,
        "cache_control_markers": found_cc,
    }
    return breakpoints, metadata


def ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def os_error_detail(exc: OSError) -> str:
    detail = exc.strerror or exc.__class__.__name__
    if exc.errno is not None:
        return f"{detail} (errno {exc.errno})"
    return detail


def lock_guidance() -> str:
    return f"<store-dir>/{KEY_NAME}.lock"


def ensure_hmac_key_private_mode(key_path: Path) -> None:
    try:
        os.chmod(key_path, 0o600)
    except OSError as exc:
        if os.name == "posix":
            fail(f"could not secure local HMAC key file: {os_error_detail(exc)}")
        return
    if os.name == "posix":
        try:
            mode = stat.S_IMODE(key_path.stat().st_mode)
        except OSError as exc:
            fail(f"could not verify local HMAC key file privacy: {os_error_detail(exc)}")
        if mode != 0o600:
            fail("could not verify local HMAC key file privacy: expected mode 0600")


def read_hmac_key(key_path: Path) -> bytes:
    try:
        raw = key_path.read_text(encoding="utf-8")
    except UnicodeError:
        fail("invalid local HMAC key file: expected UTF-8 canonical URL-safe base64 text")
    except OSError as exc:
        fail(f"could not read local HMAC key file: {os_error_detail(exc)}")
    try:
        raw_ascii = raw.encode("ascii")
    except UnicodeEncodeError:
        fail("invalid local HMAC key file: expected ASCII canonical URL-safe base64 text")
    if not HMAC_KEY_RE.fullmatch(raw):
        fail("invalid local HMAC key file: expected canonical URL-safe 32-byte key")
    try:
        key = base64.b64decode(raw_ascii, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        fail("invalid local HMAC key file: invalid canonical URL-safe base64")
    if base64.urlsafe_b64encode(key).decode("ascii") != raw:
        fail("invalid local HMAC key file: expected canonical URL-safe 32-byte key")
    if len(key) != 32:
        fail("invalid local HMAC key file: expected 32 decoded bytes")
    ensure_hmac_key_private_mode(key_path)
    return key


def fsync_parent_dir(path: Path) -> None:
    if os.name != "posix":
        return
    try:
        fd = os.open(path.parent, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    total = 0
    while total < len(data):
        written = os.write(fd, view[total:])
        if written <= 0:
            raise OSError("short write to local HMAC key file")
        total += written


@dataclass(frozen=True)
class KeyLock:
    nonce: str
    metadata_written: bool


def write_key_lock_metadata(lock_dir: Path) -> KeyLock:
    nonce = secrets.token_hex(8)
    metadata = {
        "pid": os.getpid(),
        "created_at_unix": time.time(),
        "nonce": nonce,
    }
    path = lock_dir / LOCK_OWNER_NAME
    try:
        path.write_text(json_bytes(metadata), encoding="utf-8")
        os.chmod(path, 0o600)
        fsync_parent_dir(path)
        return KeyLock(nonce=nonce, metadata_written=True)
    except OSError:
        return KeyLock(nonce=nonce, metadata_written=False)


def key_lock_age_seconds(lock_dir: Path, now: float | None = None) -> float:
    current = time.time() if now is None else now
    metadata_path = lock_dir / LOCK_OWNER_NAME
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        if isinstance(metadata, dict):
            created = metadata.get("created_at_unix")
            if type(created) in (int, float) and math.isfinite(float(created)):
                created_float = float(created)
                if 0 <= created_float <= current + KEY_LOCK_METADATA_CLOCK_SKEW_SECONDS:
                    return max(0.0, current - created_float)
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError, OverflowError):
        pass
    try:
        return max(0.0, current - lock_dir.stat().st_mtime)
    except OSError:
        return 0.0


def path_mtime_age_seconds(path: Path, now: float | None = None) -> float:
    current = time.time() if now is None else now
    try:
        return max(0.0, current - path.stat().st_mtime)
    except OSError:
        return 0.0


def reclaim_stale_key_lock(lock_dir: Path, key_path: Path) -> bool:
    if key_path.exists():
        return False
    if key_lock_age_seconds(lock_dir) < KEY_LOCK_STALE_SECONDS:
        return False
    if key_path.exists():
        return False
    stale_dir = lock_dir.with_name(f"{lock_dir.name}.stale.{os.getpid()}.{secrets.token_hex(8)}")
    try:
        os.rename(lock_dir, stale_dir)
    except OSError:
        return False
    try:
        shutil.rmtree(stale_dir)
    except OSError:
        pass
    return True


def key_lock_owner_matches(lock_dir: Path, lock: KeyLock) -> bool:
    if not lock.metadata_written:
        return False
    try:
        metadata = json.loads((lock_dir / LOCK_OWNER_NAME).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    return (
        isinstance(metadata, dict)
        and metadata.get("nonce") == lock.nonce
        and metadata.get("pid") == os.getpid()
    )


def cleanup_orphaned_stale_key_locks(store_dir: Path) -> None:
    stale_prefix = f"{KEY_NAME}.lock.stale."
    cleanup_prefix = f"{KEY_NAME}.lock.cleanup."
    try:
        candidates = list(store_dir.iterdir())
    except OSError:
        return
    for candidate in candidates:
        should_remove = candidate.name.startswith(stale_prefix)
        if candidate.name.startswith(cleanup_prefix):
            should_remove = path_mtime_age_seconds(candidate) >= KEY_LOCK_STALE_SECONDS
        if not should_remove:
            continue
        try:
            if candidate.is_dir():
                shutil.rmtree(candidate)
            else:
                candidate.unlink()
        except OSError:
            pass


def cleanup_key_lock(lock_dir: Path, lock: KeyLock) -> None:
    if not key_lock_owner_matches(lock_dir, lock):
        return
    cleanup_dir = lock_dir.with_name(f"{lock_dir.name}.cleanup.{os.getpid()}.{secrets.token_hex(8)}")
    try:
        os.rename(lock_dir, cleanup_dir)
    except OSError:
        return
    if not key_lock_owner_matches(cleanup_dir, lock):
        try:
            if not lock_dir.exists():
                os.rename(cleanup_dir, lock_dir)
        except OSError:
            pass
        return
    try:
        shutil.rmtree(cleanup_dir)
    except OSError:
        pass


def acquire_key_lock(lock_dir: Path, key_path: Path) -> KeyLock | None:
    for _ in range(KEY_LOCK_WAIT_ATTEMPTS):
        try:
            os.mkdir(lock_dir, 0o700)
            try:
                os.chmod(lock_dir, 0o700)
            except OSError:
                pass
            lock = write_key_lock_metadata(lock_dir)
            if not lock.metadata_written:
                try:
                    shutil.rmtree(lock_dir)
                except OSError:
                    pass
                fail("could not write local HMAC key lock metadata; retry")
            return lock
        except FileExistsError:
            if key_path.exists():
                return None
            if reclaim_stale_key_lock(lock_dir, key_path):
                continue
            if key_path.exists():
                return None
            time.sleep(KEY_LOCK_POLL_SECONDS)
        except OSError as exc:
            fail(f"could not create local HMAC key lock at {lock_guidance()}: {os_error_detail(exc)}")
    if key_path.exists():
        return None
    fail(f"timed out waiting for local HMAC key lock; remove stale {lock_guidance()}")


def load_or_create_hmac_key(store_dir: Path) -> bytes:
    ensure_private_dir(store_dir)
    cleanup_orphaned_stale_key_locks(store_dir)
    key_path = store_dir / KEY_NAME
    if key_path.exists():
        return read_hmac_key(key_path)

    lock_dir = store_dir / f"{KEY_NAME}.lock"
    locked = acquire_key_lock(lock_dir, key_path)
    if locked is None:
        return read_hmac_key(key_path)

    tmp_path: Path | None = None
    try:
        if key_path.exists():
            return read_hmac_key(key_path)
        key = secrets.token_bytes(32)
        encoded = base64.urlsafe_b64encode(key)
        tmp_path = store_dir / f"{KEY_NAME}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
        try:
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError as exc:
            fail(f"could not create local HMAC key file: {os_error_detail(exc)}")
        close_error: OSError | None = None
        try:
            try:
                os.fchmod(fd, 0o600)
            except (AttributeError, OSError):
                pass
            write_all(fd, encoded)
            os.fsync(fd)
        except OSError as exc:
            fail(f"could not write local HMAC key file: {os_error_detail(exc)}")
        finally:
            try:
                os.close(fd)
            except OSError as exc:
                close_error = exc
        if close_error is not None:
            fail(f"could not write local HMAC key file: {os_error_detail(close_error)}")
        ensure_hmac_key_private_mode(tmp_path)
        if locked.metadata_written and not key_lock_owner_matches(lock_dir, locked):
            if key_path.exists():
                return read_hmac_key(key_path)
            fail("lost local HMAC key lock; retry")
        try:
            os.replace(tmp_path, key_path)
        except OSError as exc:
            fail(f"could not persist local HMAC key file: {os_error_detail(exc)}")
        tmp_path = None
        fsync_parent_dir(key_path)
        # Re-read the persisted file so callers always use the same bytes future
        # ledger lookups will use. The lock prevents first-use races without
        # relying on hard links or replacing another process's winner key.
        return read_hmac_key(key_path)
    finally:
        if tmp_path is not None:
            try:
                tmp_path.unlink()
            except OSError:
                pass
        cleanup_key_lock(lock_dir, locked)


def keyed_hmac(key: bytes, text: str) -> str:
    return hmac.new(key, text.encode("utf-8", errors="replace"), hashlib.sha256).hexdigest()


def ledger_path(store_dir: Path) -> Path:
    return store_dir / LEDGER_NAME


def load_ledger(store_dir: Path) -> list[dict[str, Any]]:
    path = ledger_path(store_dir)
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line, parse_constant=reject_json_constant)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(row, dict):
                rows.append(row)
    return rows[-MAX_LEDGER_ROWS:]


def append_ledger(store_dir: Path, entry: dict[str, Any]) -> None:
    ensure_private_dir(store_dir)
    path = ledger_path(store_dir)
    # JSONL is append-only. Use a single O_APPEND write plus fsync so concurrent
    # local wrappers cannot interleave bytes; load_ledger also tolerates any
    # pre-existing malformed/partial line by skipping it.
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, (json_bytes(entry) + "\n").encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def latest_fingerprint_rows(rows: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        if row.get("kind") != "observe":
            continue
        model = str(row.get("model") or "unknown")
        created = safe_int(row.get("created_at_unix") or 0, 0)
        for fp in row.get("fingerprints", []) if isinstance(row.get("fingerprints"), list) else []:
            if not isinstance(fp, dict):
                continue
            digest = fp.get("hmac")
            if not isinstance(digest, str):
                continue
            key = (model, digest)
            old = latest.get(key)
            if old is None or created >= safe_int(old.get("created_at_unix") or 0, 0):
                merged = dict(fp)
                merged["created_at_unix"] = created
                merged["model"] = model
                latest[key] = merged
    return latest


def default_pricing_profile() -> dict[str, Any]:
    return {
        "name": "anthropic-default-2026-06",
        "source": "Anthropic pricing docs retrieved 2026-06-05; recheck before release or billing assertions.",
        "source_urls": [ANTHROPIC_DOCS_URL, ANTHROPIC_PRICING_URL],
        "checked_at": "2026-06-05",
        "release_recheck_required": True,
        "usd_to_krw": DEFAULT_USD_TO_KRW,
        "cache_write_multipliers": {"5m": 1.25, "1h": 2.0},
        "cache_read_multiplier": 0.10,
        "default_input_usd_per_mtok": 3.0,
        "default_output_usd_per_mtok": 15.0,
        "models": {
            "opus 4.8": {"input_usd_per_mtok": 5.0, "output_usd_per_mtok": 25.0},
            "opus-4-8": {"input_usd_per_mtok": 5.0, "output_usd_per_mtok": 25.0},
            "opus 4.7": {"input_usd_per_mtok": 5.0, "output_usd_per_mtok": 25.0},
            "opus-4-7": {"input_usd_per_mtok": 5.0, "output_usd_per_mtok": 25.0},
            "opus 4.6": {"input_usd_per_mtok": 5.0, "output_usd_per_mtok": 25.0},
            "opus-4-6": {"input_usd_per_mtok": 5.0, "output_usd_per_mtok": 25.0},
            "opus 4.5": {"input_usd_per_mtok": 5.0, "output_usd_per_mtok": 25.0},
            "opus-4-5": {"input_usd_per_mtok": 5.0, "output_usd_per_mtok": 25.0},
            "opus 4.1": {"input_usd_per_mtok": 15.0, "output_usd_per_mtok": 75.0},
            "opus-4-1": {"input_usd_per_mtok": 15.0, "output_usd_per_mtok": 75.0},
            "opus 4": {"input_usd_per_mtok": 15.0, "output_usd_per_mtok": 75.0},
            "opus-4": {"input_usd_per_mtok": 15.0, "output_usd_per_mtok": 75.0},
            "sonnet 4.6": {"input_usd_per_mtok": 3.0, "output_usd_per_mtok": 15.0},
            "sonnet-4-6": {"input_usd_per_mtok": 3.0, "output_usd_per_mtok": 15.0},
            "sonnet 4.5": {"input_usd_per_mtok": 3.0, "output_usd_per_mtok": 15.0},
            "sonnet-4-5": {"input_usd_per_mtok": 3.0, "output_usd_per_mtok": 15.0},
            "sonnet 4": {"input_usd_per_mtok": 3.0, "output_usd_per_mtok": 15.0},
            "sonnet-4": {"input_usd_per_mtok": 3.0, "output_usd_per_mtok": 15.0},
            "haiku 4.5": {"input_usd_per_mtok": 1.0, "output_usd_per_mtok": 5.0},
            "haiku-4-5": {"input_usd_per_mtok": 1.0, "output_usd_per_mtok": 5.0},
            "haiku 3.5": {"input_usd_per_mtok": 0.80, "output_usd_per_mtok": 4.0},
            "haiku-3-5": {"input_usd_per_mtok": 0.80, "output_usd_per_mtok": 4.0},
            "sonnet": {"input_usd_per_mtok": 3.0, "output_usd_per_mtok": 15.0},
            "haiku": {"input_usd_per_mtok": 1.0, "output_usd_per_mtok": 5.0},
            "opus": {"input_usd_per_mtok": 5.0, "output_usd_per_mtok": 25.0},
        },
    }


def load_pricing_profile(raw: str | None) -> dict[str, Any]:
    profile = default_pricing_profile()
    if not raw:
        return profile
    try:
        if raw.lstrip().startswith("{"):
            override = json.loads(raw, parse_constant=reject_json_constant)
        else:
            override = json.loads(Path(raw).read_text(encoding="utf-8"), parse_constant=reject_json_constant)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        fail(f"could not load pricing profile: {exc}")
    if not isinstance(override, dict):
        fail("pricing profile must be a JSON object")
    merged = merge_dict(profile, override)
    if "models" in override:
        # A user-supplied model map is an explicit pricing contract for this
        # run. Do not let bundled release-time defaults shadow a generic custom
        # key such as "sonnet" with a more specific built-in key.
        merged["models"] = override["models"]
    return merged


def merge_dict(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = merge_dict(out[key], value)  # type: ignore[arg-type]
        else:
            out[key] = value
    return out


def float_field(data: dict[str, Any], key: str, default: float) -> float:
    try:
        val = float(data.get(key, default))
    except (TypeError, ValueError, OverflowError):
        return default
    if not math.isfinite(val) or val < 0:
        return default
    return val


def rates_for_model(profile: dict[str, Any], model: str) -> tuple[float, float, str]:
    model_l = model.lower()
    model_norm = re.sub(r"[^a-z0-9]+", "-", model_l).strip("-")
    model_tokens = set(tok for tok in model_norm.split("-") if tok)
    models = profile.get("models") if isinstance(profile.get("models"), dict) else {}
    if isinstance(models, dict):
        def match_specificity(item: tuple[Any, Any]) -> tuple[int, int]:
            key_norm = re.sub(r"[^a-z0-9]+", "-", str(item[0]).lower()).strip("-")
            return (len([tok for tok in key_norm.split("-") if tok]), len(key_norm))

        for key, raw in sorted(models.items(), key=match_specificity, reverse=True):
            key_l = str(key).lower()
            key_norm = re.sub(r"[^a-z0-9]+", "-", key_l).strip("-")
            key_tokens = [tok for tok in key_norm.split("-") if tok]
            token_subset_match = bool(key_tokens) and all(tok in model_tokens for tok in key_tokens)
            if isinstance(raw, dict) and (key_l in model_l or key_norm in model_norm or token_subset_match):
                return (
                    float_field(raw, "input_usd_per_mtok", float_field(profile, "default_input_usd_per_mtok", 3.0)),
                    float_field(raw, "output_usd_per_mtok", float_field(profile, "default_output_usd_per_mtok", 15.0)),
                    str(key),
                )
    return (
        float_field(profile, "default_input_usd_per_mtok", 3.0),
        float_field(profile, "default_output_usd_per_mtok", 15.0),
        "default",
    )


def pricing_multipliers(profile: dict[str, Any]) -> tuple[dict[str, float], float]:
    raw = profile.get("cache_write_multipliers")
    write = {"5m": 1.25, "1h": 2.0}
    if isinstance(raw, dict):
        for ttl in ("5m", "1h"):
            try:
                value = float(raw.get(ttl, write[ttl]))
            except (TypeError, ValueError, OverflowError):
                value = write[ttl]
            if math.isfinite(value) and value >= 0:
                write[ttl] = value
    read = float_field(profile, "cache_read_multiplier", 0.10)
    return write, read


def usd_to_krw(profile: dict[str, Any], override: float | None = None) -> float:
    if override is not None:
        return finite_float_arg(override, "--usd-to-krw", minimum=0.0, allow_zero=False)
    rate = float_field(profile, "usd_to_krw", DEFAULT_USD_TO_KRW)
    if rate <= 0:
        fail("pricing profile usd_to_krw must be > 0")
    return rate


def money(tokens: int, usd_per_mtok: float, multiplier: float = 1.0) -> float:
    return (max(0, tokens) / 1_000_000.0) * usd_per_mtok * multiplier


def krw(usd: float, rate: float) -> float:
    return usd * rate


def uncertainty(mid_tokens: int, safety_factor: float) -> dict[str, int]:
    high = max(mid_tokens, math.ceil(mid_tokens * max(1.0, safety_factor)))
    low = min(mid_tokens, math.floor(mid_tokens * 0.75))
    return {"low": low, "mid": mid_tokens, "high": high}


def cost_range(mid_usd: float, safety_factor: float) -> dict[str, float]:
    return {
        "low": round(mid_usd * 0.75, 8),
        "mid": round(mid_usd, 8),
        "high": round(mid_usd * max(1.0, safety_factor), 8),
    }


def budget_state(cost_usd_range: dict[str, float], args: argparse.Namespace, profile: dict[str, Any]) -> dict[str, Any]:
    budgets: list[tuple[str, float, float]] = []
    if getattr(args, "budget_usd", None) is not None:
        budget_usd = finite_float_arg(args.budget_usd, "--budget-usd", minimum=0.0, allow_zero=True)
        budgets.append(("USD", budget_usd, budget_usd))
    if getattr(args, "budget_krw", None) is not None:
        budget_krw = finite_float_arg(args.budget_krw, "--budget-krw", minimum=0.0, allow_zero=True)
        rate = usd_to_krw(profile, getattr(args, "usd_to_krw", None))
        budgets.append(("KRW", budget_krw, budget_krw / rate))
    if not budgets:
        return {"configured": False, "near_threshold": False, "over_budget": False}
    high = float(cost_usd_range.get("high", 0.0))
    mid = float(cost_usd_range.get("mid", 0.0))
    low = float(cost_usd_range.get("low", 0.0))
    checks = []
    over = False
    near = False
    for currency, display_value, budget_usd in budgets:
        is_over = high > budget_usd
        is_near = low <= budget_usd < high or mid <= budget_usd < high
        over = over or is_over
        near = near or is_near
        checks.append({"currency": currency, "budget": display_value, "budget_usd": round(budget_usd, 8), "over_high_estimate": is_over, "near_threshold": is_near})
    return {"configured": True, "near_threshold": near, "over_budget": over, "checks": checks}


def model_from_request(request: Any) -> str:
    if isinstance(request, dict) and isinstance(request.get("model"), str):
        return str(request["model"])
    return "unknown"


def build_fingerprints(breakpoints: list[CacheBreakpoint], key: bytes) -> tuple[list[dict[str, Any]], int]:
    fingerprints: list[dict[str, Any]] = []
    redactions = 0
    previous_prefix_tokens = 0
    previous_prefix_bytes = 0
    for bp in breakpoints:
        canonical = json_bytes(bp.prefix)
        section_canonical = json_bytes(bp.section)
        bp_redactions = secret_count_in_text(canonical)
        redactions += bp_redactions
        prefix_tokens = token_proxy_text(canonical)
        prefix_bytes = byte_len_text(canonical)
        prefix_delta_tokens = max(0, prefix_tokens - previous_prefix_tokens)
        prefix_delta_bytes = max(0, prefix_bytes - previous_prefix_bytes)
        previous_prefix_tokens = max(previous_prefix_tokens, prefix_tokens)
        previous_prefix_bytes = max(previous_prefix_bytes, prefix_bytes)
        fingerprints.append(
            {
                "breakpoint_id": bp.breakpoint_id,
                "kind": bp.kind,
                "ttl": bp.ttl,
                "hmac": keyed_hmac(key, canonical),
                "display_hmac": "hmac-sha256:" + keyed_hmac(key, canonical)[:16],
                "prefix_bytes": prefix_bytes,
                "prefix_delta_bytes": prefix_delta_bytes,
                "section_bytes": byte_len_text(section_canonical),
                "tokens_estimated": prefix_tokens,
                "prefix_delta_tokens_estimated": prefix_delta_tokens,
                "section_tokens_estimated": token_proxy_text(section_canonical),
                "redactions_detected": bp_redactions,
            }
        )
    return fingerprints, redactions


def annotate_cache_state(
    fingerprints: list[dict[str, Any]],
    rows: list[dict[str, Any]],
    now: int,
    *,
    model: str,
    input_rate: float,
    write_mult: dict[str, float],
    read_mult: float,
    exchange_rate: float,
) -> list[dict[str, Any]]:
    latest = latest_fingerprint_rows(rows)
    has_prior = bool(latest)
    out: list[dict[str, Any]] = []
    for fp in fingerprints:
        digest = str(fp["hmac"])
        ttl = str(fp.get("ttl") or "5m")
        prev = latest.get((model, digest))
        status = "miss"
        age_seconds: int | None = None
        expires_at_unix = 0
        ttl_remaining_seconds = 0
        reasons: list[str] = []
        if prev:
            created = int(prev.get("created_at_unix") or 0)
            age_seconds = max(0, now - created)
            previous_ttl = str(prev.get("ttl") or "5m")
            expires_at_unix = created + TTL_SECONDS.get(previous_ttl, TTL_SECONDS["5m"])
            ttl_remaining_seconds = max(0, expires_at_unix - now)
            if previous_ttl != ttl:
                status = "miss"
                reasons.append("ttl_mismatch")
            else:
                status = "hit" if ttl_remaining_seconds > 0 else "expired"
        if status == "hit":
            matched = True
            risk = "low"
        elif status == "expired":
            matched = False
            risk = "medium"
            reasons.append("ttl_expired")
        else:
            matched = False
            risk = "high"
            reasons.append("prefix_hash_changed" if has_prior else "no_previous_cache_entry")
            if has_prior and str(fp.get("kind")) == "tool":
                reasons.append("tool_schema_changed")
        if int(fp.get("redactions_detected") or 0) > 0:
            reasons.append("redaction_changed_cacheable_material")
        tokens = int(fp.get("prefix_delta_tokens_estimated") or 0)
        miss_usd = money(tokens, input_rate, write_mult.get(ttl, write_mult["5m"]))
        hit_usd = money(tokens, input_rate, read_mult)
        confidence = "medium" if int(fp.get("redactions_detected") or 0) > 0 else "high"
        visible = {k: v for k, v in fp.items() if k != "hmac"}
        visible.update(
            {
                "id": fp.get("breakpoint_id"),
                "fingerprint": fp.get("display_hmac"),
                "matched": matched,
                "risk": risk,
                "confidence": confidence,
                "projected_tokens": tokens,
                "cost_delta_if_miss": round(krw(max(0.0, miss_usd - hit_usd), exchange_rate), 2),
                "cost_delta_if_miss_usd": round(max(0.0, miss_usd - hit_usd), 8),
                "expires_at_unix": expires_at_unix,
                "ttl_remaining_seconds": ttl_remaining_seconds,
                "reasons": reasons,
                "predicted_cache_state": status,
            }
        )
        if age_seconds is not None:
            visible["age_seconds"] = age_seconds
        out.append(visible)
    return out


def preflight_command(args: argparse.Namespace) -> int:
    request_raw, _truncated = load_json_input(args.request, max_bytes=args.max_bytes)
    request = require_json_object(request_raw, "request")
    profile = load_pricing_profile(args.pricing_profile)
    if args.usd_to_krw is not None:
        profile["usd_to_krw"] = usd_to_krw(profile, args.usd_to_krw)
    if args.budget_usd is not None:
        args.budget_usd = finite_float_arg(args.budget_usd, "--budget-usd", minimum=0.0, allow_zero=True)
    if args.budget_krw is not None:
        args.budget_krw = finite_float_arg(args.budget_krw, "--budget-krw", minimum=0.0, allow_zero=True)
    safety = float(args.safety_factor)
    if not math.isfinite(safety) or safety < 1.0:
        fail("--safety-factor must be >= 1.0")

    store_dir = Path(args.store_dir)
    key = load_or_create_hmac_key(store_dir)
    rows = load_ledger(store_dir)
    now = int(time.time())
    breakpoints, parse_meta = extract_cache_breakpoints(request)
    fingerprints_private, redactions = build_fingerprints(breakpoints, key)

    model = model_from_request(request)
    input_rate, output_rate, model_rate_key = rates_for_model(profile, model)
    write_mult, read_mult = pricing_multipliers(profile)
    exchange = usd_to_krw(profile, args.usd_to_krw)
    cache_breakdowns = annotate_cache_state(
        fingerprints_private,
        rows,
        now,
        model=model,
        input_rate=input_rate,
        write_mult=write_mult,
        read_mult=read_mult,
        exchange_rate=exchange,
    )
    full_prompt_tokens_mid = token_proxy_obj(strip_known_cache_controls(request))
    cacheable_tokens_mid = max((int(fp.get("tokens_estimated") or 0) for fp in fingerprints_private), default=0)
    noncacheable_tokens_mid = max(0, full_prompt_tokens_mid - cacheable_tokens_mid)
    output_tokens_max = usage_int(request, "max_tokens")
    output_usd_mid = money(output_tokens_max, output_rate)
    predicted_mid_usd = money(noncacheable_tokens_mid, input_rate) + output_usd_mid
    all_miss_mid_usd = predicted_mid_usd
    all_hit_mid_usd = predicted_mid_usd
    for public, private in zip(cache_breakdowns, fingerprints_private):
        tokens = int(private.get("prefix_delta_tokens_estimated") or 0)
        ttl = str(private.get("ttl") or "5m")
        if public.get("predicted_cache_state") == "hit":
            predicted_mid_usd += money(tokens, input_rate, read_mult)
        else:
            predicted_mid_usd += money(tokens, input_rate, write_mult.get(ttl, write_mult["5m"]))
        all_miss_mid_usd += money(tokens, input_rate, write_mult.get(ttl, write_mult["5m"]))
        all_hit_mid_usd += money(tokens, input_rate, read_mult)

    token_estimate = uncertainty(full_prompt_tokens_mid, safety)
    cost_usd = cost_range(predicted_mid_usd, safety)
    budget = budget_state(cost_usd, args, profile)
    hit_count = sum(1 for bp in cache_breakdowns if bp.get("predicted_cache_state") == "hit")
    miss_count = sum(1 for bp in cache_breakdowns if bp.get("predicted_cache_state") == "miss")
    expired_count = sum(1 for bp in cache_breakdowns if bp.get("predicted_cache_state") == "expired")
    aggregate_reasons = sorted(
        {
            reason
            for bp in cache_breakdowns
            for reason in bp.get("reasons", [])
            if isinstance(reason, str)
        }
    )
    if not cache_breakdowns:
        cache_level = "unknown"
    elif miss_count > 0:
        cache_level = "high"
    elif expired_count > 0:
        cache_level = "medium"
    else:
        cache_level = "low"
    matched_previous_entry = bool(cache_breakdowns) and all(bool(bp.get("matched")) for bp in cache_breakdowns)
    ttl_remaining_values = [
        int(bp.get("ttl_remaining_seconds") or 0)
        for bp in cache_breakdowns
        if int(bp.get("ttl_remaining_seconds") or 0) > 0
    ]
    aggregate_ttl_remaining = min(ttl_remaining_values) if ttl_remaining_values else 0
    aggregate_fingerprint = cache_breakdowns[-1].get("fingerprint") if cache_breakdowns else None

    confidence = "high"
    reasons: list[str] = []
    if redactions:
        confidence = "medium"
        reasons.append("redaction_changed_cacheable_material")
    if int(parse_meta.get("unsupported_cache_controls") or 0) > 0:
        confidence = "medium" if confidence == "high" else confidence
        reasons.append("unsupported_cache_control_layout")
    if not breakpoints:
        confidence = "low"
        reasons.append("no_cache_control")
        if full_prompt_tokens_mid >= int(args.large_context_tokens):
            reasons.append("no_cache_control_large_context")
    for reason in reasons:
        if reason not in aggregate_reasons:
            aggregate_reasons.append(reason)

    findings: list[dict[str, Any]] = []
    if budget.get("over_budget"):
        findings.append({"severity": "warn", "code": "cost_budget_risk", "message": "high estimate exceeds configured budget"})
    elif budget.get("near_threshold"):
        findings.append({"severity": "info", "code": "near_cost_budget", "message": "uncertainty range crosses configured budget"})
    if args.max_input_tokens and token_estimate["high"] > int(args.max_input_tokens):
        findings.append({"severity": "warn", "code": "input_token_limit_risk", "message": "high estimate exceeds configured input-token threshold"})
    if len(breakpoints) > 4:
        findings.append({"severity": "warn", "code": "too_many_cache_breakpoints", "message": "Anthropic prompt caching supports up to four cache breakpoints; reduce or compile layout"})

    block = bool(args.enforce and any(f.get("severity") == "warn" for f in findings))
    decision = "block_if_enforced" if block else "warn" if findings else "allow"
    report = {
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "mode": "preflight",
        "decision": decision,
        "enforcement": "enforced" if args.enforce else "passive",
        "policy": {"action": decision, "passive": not args.enforce, "enforced": bool(args.enforce)},
        "model": model,
        "confidence": {"level": confidence, "reasons": reasons},
        "request": {"model": model, "model_rate_key": model_rate_key, "source_omitted": True},
        "token_estimate": {
            "measurement": "estimated",
            "method": f"chars_div_{TOKEN_PROXY_CHARS_PER_TOKEN}",
            "estimator": f"chars_div_{TOKEN_PROXY_CHARS_PER_TOKEN}",
            "safety_factor": safety,
            "near_threshold": bool(budget.get("near_threshold")),
            "input_tokens_low": token_estimate["low"],
            "input_tokens_mid": token_estimate["mid"],
            "input_tokens_high": token_estimate["high"],
            "cacheable_tokens_mid": cacheable_tokens_mid,
            "volatile_tokens_mid": noncacheable_tokens_mid,
            "output_tokens_max": output_tokens_max,
            **token_estimate,
        },
        "pricing": {
            "profile": str(profile.get("name") or "custom"),
            "release_recheck_required": bool(profile.get("release_recheck_required", True)),
            "source_urls": profile.get("source_urls", [ANTHROPIC_DOCS_URL, ANTHROPIC_PRICING_URL]),
            "input_usd_per_mtok": input_rate,
            "output_usd_per_mtok": output_rate,
            "usd_to_krw": exchange,
            "cache_write_multipliers": write_mult,
            "cache_read_multiplier": read_mult,
        },
        "cost_estimate": {
            "measurement": "estimated",
            "currency": "USD",
            **cost_usd,
            "krw": {k: round(krw(v, exchange), 2) for k, v in cost_usd.items()},
            "if_cache_hit": cost_range(all_hit_mid_usd, safety),
            "if_cache_miss_5m_write": cost_range(
                money(noncacheable_tokens_mid, input_rate)
                + output_usd_mid
                + sum(
                    money(int(fp.get("prefix_delta_tokens_estimated") or 0), input_rate, write_mult["5m"])
                    for fp in fingerprints_private
                ),
                safety,
            ),
            "if_cache_miss_1h_write": cost_range(
                money(noncacheable_tokens_mid, input_rate)
                + output_usd_mid
                + sum(
                    money(int(fp.get("prefix_delta_tokens_estimated") or 0), input_rate, write_mult["1h"])
                    for fp in fingerprints_private
                ),
                safety,
            ),
            "worst_case": cost_usd["high"],
            "pricing_profile_id": str(profile.get("name") or "custom"),
            "if_all_cache_miss_usd_mid": round(all_miss_mid_usd, 8),
            "if_all_cache_hit_usd_mid": round(all_hit_mid_usd, 8),
            "estimated_cache_delta_usd_mid": round(max(0.0, all_miss_mid_usd - all_hit_mid_usd), 8),
            "output_usd_mid": round(output_usd_mid, 8),
            "includes_output_token_budget": output_tokens_max > 0,
        },
        "budget": budget,
        "cache_risk": {
            "level": cache_level,
            "confidence": confidence,
            "reasons": aggregate_reasons,
            "aggregate_fingerprint": aggregate_fingerprint,
            "matched_previous_entry": matched_previous_entry,
            "ttl_remaining_seconds": aggregate_ttl_remaining,
            "breakpoints": cache_breakdowns,
            "summary": {"total": len(cache_breakdowns), "predicted_hit": hit_count, "predicted_miss": miss_count, "expired": expired_count},
            "ledger": {
                "uses_keyed_hmac": True,
                "raw_prompt_stored": False,
                "path_omitted": True,
                "append_mode": "o_append_single_write_fsync",
                "malformed_rows_skipped": True,
            },
        },
        "redaction": {"secret_like_values_detected": redactions, "redacted_before_output_or_storage": True},
        "privacy": {
            "raw_prompt_emitted": False,
            "raw_prompt_stored": False,
            "raw_paths_emitted": False,
            "hmac_key_emitted": False,
            "redacted_values": redactions,
        },
        "parse": parse_meta,
        "findings": findings,
        "recommendations": recommendations_for_findings(
            findings,
            cache_level=cache_level,
            confidence=confidence,
            breakpoints=cache_breakdowns,
        ),
        "local_artifact_retrieval": {
            "helps_reduce_sent_context": True,
            "replaces_provider_prompt_cache": False,
            "recommended_helper": "context-guard-artifact/context-guard-pack for large local evidence",
        },
    }

    if not args.no_ledger_write:
        entry: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "kind": "preflight_blocked" if block else "preflight",
            "created_at_unix": now,
            "model": model,
            "summary": {
                "breakpoints": len(fingerprints_private),
                "secret_like_values_detected": redactions,
                "raw_prompt_stored": False,
                "cache_seeded": False,
            },
        }
        append_ledger(store_dir, entry)

    emit(report, json_mode=args.json)
    return 3 if block else 0


def usage_int(data: dict[str, Any], key: str) -> int:
    value = data.get(key, 0)
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return 0
    return max(0, number)


def cache_creation_buckets(usage: dict[str, Any]) -> tuple[int, int]:
    cache_creation = usage.get("cache_creation")
    if isinstance(cache_creation, dict):
        return (
            usage_int(cache_creation, "ephemeral_5m_input_tokens"),
            usage_int(cache_creation, "ephemeral_1h_input_tokens"),
        )
    flat_5m = usage_int(usage, "cache_creation_input_tokens_5m")
    flat_1h = usage_int(usage, "cache_creation_input_tokens_1h")
    if flat_5m or flat_1h:
        return flat_5m, flat_1h
    return usage_int(usage, "cache_creation_input_tokens"), 0


def observe_command(args: argparse.Namespace) -> int:
    usage_raw, _truncated = load_json_input(args.usage, max_bytes=args.max_bytes)
    if isinstance(usage_raw, dict) and isinstance(usage_raw.get("usage"), dict):
        usage = usage_raw["usage"]
    else:
        usage = usage_raw
    if not isinstance(usage, dict):
        fail("usage must be a JSON object or an object containing a usage object")
    profile = load_pricing_profile(args.pricing_profile)
    if args.usd_to_krw is not None:
        profile["usd_to_krw"] = usd_to_krw(profile, args.usd_to_krw)
    model = str(args.model or (usage_raw.get("model") if isinstance(usage_raw, dict) else "") or "unknown")
    input_rate, output_rate, model_rate_key = rates_for_model(profile, model)
    write_mult, read_mult = pricing_multipliers(profile)
    exchange = usd_to_krw(profile, args.usd_to_krw)

    input_tokens = usage_int(usage, "input_tokens")
    output_tokens = usage_int(usage, "output_tokens")
    cache_creation_5m, cache_creation_1h = cache_creation_buckets(usage)
    cache_read = usage_int(usage, "cache_read_input_tokens")
    cost_usd_mid = (
        money(input_tokens, input_rate)
        + money(output_tokens, output_rate)
        + money(cache_creation_5m, input_rate, write_mult["5m"])
        + money(cache_creation_1h, input_rate, write_mult["1h"])
        + money(cache_read, input_rate, read_mult)
    )
    report = {
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "mode": "observe",
        "measurement": "from_usage",
        "usage_source": "provider_usage_fields",
        "request": {"model": model, "model_rate_key": model_rate_key, "source_omitted": True},
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cache_creation_input_tokens_5m": cache_creation_5m,
            "cache_creation_input_tokens_1h": cache_creation_1h,
            "cache_read_input_tokens": cache_read,
        },
        "cost_estimate": {
            "currency": "USD",
            "mid": round(cost_usd_mid, 8),
            "krw_mid": round(krw(cost_usd_mid, exchange), 2),
            "pricing_profile": str(profile.get("name") or "custom"),
            "release_recheck_required": bool(profile.get("release_recheck_required", True)),
            "source_urls": profile.get("source_urls", [ANTHROPIC_DOCS_URL, ANTHROPIC_PRICING_URL]),
        },
        "cache_effect": {
            "observed_cache_read_tokens": cache_read,
            "observed_cache_write_tokens": cache_creation_5m + cache_creation_1h,
            "provider_measured": True,
        },
        "privacy": {"raw_request_stored": False, "raw_usage_stored": False, "path_omitted": True},
    }
    confirmed_cache_tokens = cache_creation_5m + cache_creation_1h + cache_read
    if args.request and confirmed_cache_tokens > 0:
        request_raw, _ = load_json_input(args.request, max_bytes=args.max_bytes)
        request = require_json_object(request_raw, "request")
        store_dir = Path(args.store_dir)
        key = load_or_create_hmac_key(store_dir)
        breakpoints, _meta = extract_cache_breakpoints(request)
        fingerprints_private, redactions = build_fingerprints(breakpoints, key)
        confirmed_fingerprints = [
            fp
            for fp in fingerprints_private
            if int(fp.get("tokens_estimated") or 0) <= confirmed_cache_tokens
        ]
        if not confirmed_fingerprints:
            report["ledger"] = {
                "updated": False,
                "reason": "insufficient_provider_cache_tokens",
                "uses_keyed_hmac": True,
                "raw_prompt_stored": False,
                "path_omitted": True,
            }
            emit(report, json_mode=args.json)
            return 0
        append_ledger(
            store_dir,
            {
                "schema_version": SCHEMA_VERSION,
                "kind": "observe",
                "created_at_unix": int(time.time()),
                "model": model,
                "fingerprints": [
                    {k: v for k, v in fp.items() if k in {"breakpoint_id", "kind", "ttl", "hmac", "prefix_bytes", "section_bytes", "tokens_estimated", "section_tokens_estimated", "redactions_detected"}}
                    for fp in confirmed_fingerprints
                ],
                "usage": report["usage"],
                "summary": {"breakpoints": len(confirmed_fingerprints), "secret_like_values_detected": redactions, "raw_prompt_stored": False},
            },
        )
        report["ledger"] = {"updated": True, "confirmed_fingerprints": len(confirmed_fingerprints), "uses_keyed_hmac": True, "raw_prompt_stored": False, "path_omitted": True}
    elif args.request:
        report["ledger"] = {
            "updated": False,
            "reason": "no_provider_cache_tokens",
            "uses_keyed_hmac": True,
            "raw_prompt_stored": False,
            "path_omitted": True,
        }
    emit(report, json_mode=args.json)
    return 0


def ledger_command(args: argparse.Namespace) -> int:
    rows = load_ledger(Path(args.store_dir))
    latest = rows[-1] if rows else None
    counts: dict[str, int] = {}
    for row in rows:
        kind = str(row.get("kind") or "unknown")
        counts[kind] = counts.get(kind, 0) + 1
    visible_rows = []
    limit = int(args.limit)
    recent_rows = [] if limit == 0 else rows[-limit:]
    for row in recent_rows:
        visible_rows.append(
            {
                "kind": row.get("kind"),
                "created_at_unix": row.get("created_at_unix"),
                "model": row.get("model"),
                "fingerprint_count": len(row.get("fingerprints", [])) if isinstance(row.get("fingerprints"), list) else 0,
                "raw_prompt_stored": False,
            }
        )
    report = {
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "mode": "ledger",
        "summary": {"entries": len(rows), "counts": counts, "latest_created_at_unix": latest.get("created_at_unix") if isinstance(latest, dict) else None},
        "ledger": {"uses_keyed_hmac": True, "raw_prompt_stored": False, "path_omitted": True},
        "entries": visible_rows,
    }
    emit(report, json_mode=args.json)
    return 0


def safe_section_id(section: dict[str, Any], index: int) -> str:
    raw = section.get("id") or section.get("name") or f"section-{index + 1}"
    text = re.sub(r"[^A-Za-z0-9_.:-]+", "-", str(raw)).strip("-")[:80]
    return text or f"section-{index + 1}"


def section_ttl(section: dict[str, Any]) -> str:
    ttl = str(section.get("ttl") or section.get("cache_ttl") or "5m").lower()
    return "1h" if ttl in {"1h", "60m", "hour"} else "5m"


PROTECTED_ALLOWED_TRANSFORMS = ["exact_dedupe", "structural_window", "line_truncate", "whitespace_normalize", "json_compact", "artifact_retrieval"]
PROTECTED_DENIED_TRANSFORMS = ["semantic_compress", "paraphrase", "identifier_rewrite", "numeric_rewrite", "hash_rewrite", "path_rewrite", "quoted_literal_rewrite"]
PROTECTED_ZONE_CLASS_RE = re.compile(r"[^a-z0-9_.:-]+")
KNOWN_PROTECTED_CONTENT_TYPES = {"json", "diff", "log", "search", "code", "prose", "unknown"}


def manifest_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def protected_zone_classes(raw: dict[str, Any]) -> list[str]:
    value = raw.get("protected_zone_classes") or raw.get("protected_zones") or raw.get("zone_classes") or []
    if isinstance(value, str):
        items = [item.strip() for item in value.split(",")]
    elif isinstance(value, list):
        items = [str(item).strip() for item in value]
    else:
        items = []
    cleaned = sorted({PROTECTED_ZONE_CLASS_RE.sub("-", item.lower()).strip("-")[:48] for item in items if item})
    return [item for item in cleaned if item]


def protected_content_type(raw: dict[str, Any]) -> str:
    """Return a known content-type label without echoing raw manifest strings."""
    value = str(raw.get("content_type") or raw.get("type") or "unknown").strip().lower()
    return value if value in KNOWN_PROTECTED_CONTENT_TYPES else "unknown"


def section_is_protected(raw: dict[str, Any], zone_classes: list[str]) -> bool:
    return (
        manifest_bool(raw.get("protected"))
        or manifest_bool(raw.get("semantic_sensitive"))
        or bool(zone_classes)
    )


def compile_command(args: argparse.Namespace) -> int:
    manifest, _truncated = load_json_input(args.manifest, max_bytes=args.max_bytes)
    if isinstance(manifest, dict):
        raw_sections = manifest.get("sections") or manifest.get("cache_breakpoints") or []
    elif isinstance(manifest, list):
        raw_sections = manifest
    else:
        raw_sections = []
    if not isinstance(raw_sections, list):
        fail("manifest sections must be a list")
    sections: list[dict[str, Any]] = []
    for i, raw in enumerate(raw_sections):
        if not isinstance(raw, dict):
            continue
        zone_classes = protected_zone_classes(raw)
        sec = {
            "id": safe_section_id(raw, i),
            "ttl": section_ttl(raw),
            "volatile": manifest_bool(raw.get("volatile")) or manifest_bool(raw.get("changes_often")),
            "bytes": safe_int(raw.get("bytes") or raw.get("estimated_bytes") or 0),
            "tokens_estimated": safe_int(raw.get("tokens") or raw.get("estimated_tokens") or 0),
            "has_path": "path" in raw or "file" in raw,
            "protected": section_is_protected(raw, zone_classes),
            "content_type": protected_content_type(raw),
            "protected_zone_classes": zone_classes,
        }
        sections.append(sec)

    recommended = sorted(sections, key=lambda sec: (bool(sec["volatile"]), 0 if sec["ttl"] == "1h" else 1, -int(sec["bytes"] or 0), str(sec["id"])))
    findings: list[dict[str, Any]] = []
    for i, sec in enumerate(sections):
        if sec["ttl"] == "5m" and any(later["ttl"] == "1h" for later in sections[i + 1 :]):
            findings.append({"severity": "warn", "code": "ttl_order_violation", "section_id": sec["id"], "message": "place 1h cacheable stable sections before 5m sections"})
            break
    for i, sec in enumerate(sections):
        if sec["volatile"] and any(not later["volatile"] for later in sections[i + 1 :]):
            findings.append({"severity": "warn", "code": "volatile_prefix_before_stable_context", "section_id": sec["id"], "message": "move volatile context toward the tail so stable prefixes can be reused"})
            break
    if len(sections) > 4:
        findings.append({"severity": "warn", "code": "too_many_cache_breakpoints", "message": "reduce to four or fewer provider cache breakpoints"})
    for sec in sections:
        if int(sec["bytes"] or 0) > int(args.large_section_bytes):
            findings.append(
                {
                    "severity": "info",
                    "code": "use_local_artifact_retrieval",
                    "section_id": sec["id"],
                    "message": "store/query large local evidence with context-guard-artifact or context-guard-pack; RAM/disk can reduce sent context but does not replace provider prompt cache",
                }
            )
        if sec.get("protected"):
            findings.append(
                {
                    "severity": "info",
                    "code": "protected_zone_structural_only",
                    "section_id": sec["id"],
                    "message": "protected sections deny semantic/paraphrase compression; use structural transforms and exact retrieval",
                }
            )
        if sec.get("protected") and sec.get("volatile"):
            findings.append(
                {
                    "severity": "info",
                    "code": "protected_volatile_tail",
                    "section_id": sec["id"],
                    "message": "volatile controls cache ordering toward the tail; protection controls transforms and retrieval",
                }
            )
        if sec.get("protected") and int(sec["bytes"] or 0) > int(args.large_section_bytes):
            findings.append(
                {
                    "severity": "info",
                    "code": "protected_zone_artifact_retrieval",
                    "section_id": sec["id"],
                    "message": "large protected evidence should be stored locally and sent as exact retrieved slices, not semantically compressed",
                }
            )
    protected_sections = [sec for sec in sections if sec.get("protected")]
    protected_policy_sections = [
        {
            "section_id": sec["id"],
            "content_type": sec["content_type"],
            "volatile": sec["volatile"],
            "ttl": sec["ttl"],
            "large": int(sec["bytes"] or 0) > int(args.large_section_bytes),
            "zone_classes": sec["protected_zone_classes"],
            "semantic_compress": False,
            "retrieval_required": int(sec["bytes"] or 0) > int(args.large_section_bytes),
            "cache_ordering": "volatile_tail" if sec["volatile"] else "stable_prefix_eligible",
        }
        for sec in protected_sections
    ]
    report = {
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "mode": "compile",
        "provider_cache": {"replaced_by_local_ram_or_disk": False, "stable_prefix_required": True, "max_breakpoints_advisory": 4},
        "recommended_order": [
            {
                "section_id": sec["id"],
                "ttl": sec["ttl"],
                "volatile": sec["volatile"],
                "protected": sec["protected"],
                "content_type": sec["content_type"],
                "path_omitted": bool(sec["has_path"]),
                "transform_policy": "structural_only" if sec["protected"] else "default",
            }
            for sec in recommended
        ],
        "findings": findings,
        "protected_zone_policy": {
            "enabled": bool(protected_sections),
            "section_count": len(protected_sections),
            "semantic_compress": False,
            "allowed_transforms": PROTECTED_ALLOWED_TRANSFORMS,
            "denied_transforms": PROTECTED_DENIED_TRANSFORMS,
            "raw_spans_stored": False,
            "protected_volatile_precedence": "volatile controls cache ordering; protection controls transforms and retrieval",
            "sections": protected_policy_sections,
        },
        "transform_policy": {
            "scope": "protected_sections" if protected_sections else "none",
            "protected_sections_only": True,
            "semantic_transforms_allowed": False if protected_sections else None,
            "semantic_compress": False if protected_sections else None,
            "allowed": PROTECTED_ALLOWED_TRANSFORMS if protected_sections else [],
            "denied": PROTECTED_DENIED_TRANSFORMS if protected_sections else [],
            "large_protected_sections_use": "local_artifact_retrieval",
        },
        "local_artifact_retrieval": {
            "recommended_for_large_sections": True,
            "helpers": ["context-guard-artifact", "context-guard-pack"],
            "replaces_provider_prompt_cache": False,
        },
    }
    emit(report, json_mode=args.json)
    return 0


def recommendations_for_findings(
    findings: list[dict[str, Any]],
    *,
    cache_level: str,
    confidence: str,
    breakpoints: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    recs: list[dict[str, Any]] = []
    codes = {str(finding.get("code")) for finding in findings}
    if cache_level in {"high", "medium"}:
        recs.append(
            {
                "id": "stabilize-cache-prefix",
                "priority": "P1",
                "action": "Move stable tools/system/context before volatile questions, timestamps, logs, and task-specific output.",
            }
        )
    if confidence != "high":
        recs.append(
            {
                "id": "verify-cacheable-material",
                "priority": "P1",
                "action": "Redaction or unsupported cacheable material lowered confidence; compare exact request construction before relying on cache-risk predictions.",
            }
        )
    if "cost_budget_risk" in codes:
        recs.append(
            {
                "id": "reduce-or-confirm-budget",
                "priority": "P1",
                "action": "Use context-guard-pack/artifact slices, clear stale context, or explicit approval before sending an over-budget request.",
            }
        )
    if any(int(bp.get("prefix_delta_bytes") or 0) > DEFAULT_LARGE_SECTION_BYTES for bp in breakpoints):
        recs.append(
            {
                "id": "use-local-artifact-retrieval",
                "priority": "P2",
                "action": "Store large local evidence as artifacts or packs and send exact slices instead of full logs/files; this does not replace provider prompt cache.",
            }
        )
    return recs


def emit(data: dict[str, Any], *, json_mode: bool) -> None:
    if json_mode:
        try:
            print(json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False))
        except ValueError as exc:
            fail(f"JSON output contained a non-finite number: {exc}")
        return
    mode = data.get("mode")
    if mode == "preflight":
        decision = str(data.get("decision", "allow"))
        summary = data.get("cache_risk", {}).get("summary", {}) if isinstance(data.get("cache_risk"), dict) else {}
        cost = data.get("cost_estimate", {}) if isinstance(data.get("cost_estimate"), dict) else {}
        print(f"{TOOL_NAME}: {decision} · cache {summary.get('predicted_hit', 0)} hit/{summary.get('predicted_miss', 0)} miss · est ${cost.get('mid', 0)}")
    elif mode == "observe":
        usage = data.get("usage", {}) if isinstance(data.get("usage"), dict) else {}
        cost = data.get("cost_estimate", {}) if isinstance(data.get("cost_estimate"), dict) else {}
        print(f"{TOOL_NAME}: observed cache_read={usage.get('cache_read_input_tokens', 0)} tokens · est ${cost.get('mid', 0)}")
    elif mode == "compile":
        findings = data.get("findings", []) if isinstance(data.get("findings"), list) else []
        print(f"{TOOL_NAME}: compile findings={len(findings)}")
    else:
        summary = data.get("summary", {}) if isinstance(data.get("summary"), dict) else {}
        print(f"{TOOL_NAME}: ledger entries={summary.get('entries', 0)}")


def add_common_cost_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--pricing-profile", help="JSON string or file with input/output rates, cache multipliers, and usd_to_krw")
    parser.add_argument("--usd-to-krw", type=float, help="override USD→KRW exchange rate used for estimates")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, help=f"maximum JSON input bytes (default: {DEFAULT_MAX_BYTES})")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Passive Anthropic prompt-cache cost preflight, observation, ledger, and layout compiler.",
    )
    sub = parser.add_subparsers(dest="command")

    preflight = sub.add_parser("preflight", help="estimate cache miss risk and request cost before an API call")
    preflight.add_argument("--request", default="-", help="Anthropic-like request JSON path, or '-' for stdin")
    preflight.add_argument("--store-dir", default=DEFAULT_STORE_DIR, help="local HMAC ledger directory (path is never emitted in JSON)")
    preflight.add_argument("--budget-usd", type=float, help="warn/block when high estimate exceeds this USD budget")
    preflight.add_argument("--budget-krw", type=float, help="warn/block when high estimate exceeds this KRW budget")
    preflight.add_argument("--max-input-tokens", type=int, default=0, help="warn/block when high estimated input tokens exceed this threshold")
    preflight.add_argument("--large-context-tokens", type=int, default=200_000, help="threshold for no-cache-control large-context risk")
    preflight.add_argument("--safety-factor", type=float, default=DEFAULT_SAFETY_FACTOR, help="high estimate multiplier (default: 1.25)")
    preflight.add_argument("--enforce", action="store_true", help="return nonzero on warn-level findings; default is passive exit 0")
    preflight.add_argument("--no-ledger-write", action="store_true", help="do not append this preflight to the local HMAC ledger")
    add_common_cost_args(preflight)
    preflight.set_defaults(func=preflight_command)

    observe = sub.add_parser("observe", help="estimate observed cost from Anthropic usage fields")
    observe.add_argument("--usage", default="-", help="usage JSON path, or '-' for stdin")
    observe.add_argument("--request", help="optional request JSON to fingerprint into the ledger")
    observe.add_argument("--model", help="model name when usage JSON does not include it")
    observe.add_argument("--store-dir", default=DEFAULT_STORE_DIR, help="local HMAC ledger directory")
    add_common_cost_args(observe)
    observe.set_defaults(func=observe_command)

    ledger = sub.add_parser("ledger", help="summarize the local HMAC ledger without revealing prompts")
    ledger.add_argument("--store-dir", default=DEFAULT_STORE_DIR, help="local HMAC ledger directory")
    ledger.add_argument("--limit", type=non_negative_int_arg, default=20, help="maximum recent entries to include")
    ledger.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    ledger.set_defaults(func=ledger_command)

    compile_parser = sub.add_parser("compile", help="compile a cache-friendly section layout advisory from a manifest")
    compile_parser.add_argument("--manifest", default="-", help="section manifest JSON path, or '-' for stdin")
    compile_parser.add_argument("--large-section-bytes", type=int, default=DEFAULT_LARGE_SECTION_BYTES, help="recommend local artifact retrieval above this size")
    compile_parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, help=f"maximum manifest JSON bytes (default: {DEFAULT_MAX_BYTES})")
    compile_parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    compile_parser.set_defaults(func=compile_command)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    try:
        return int(args.func(args))
    except CostGuardError as exc:
        print(f"{TOOL_NAME}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
