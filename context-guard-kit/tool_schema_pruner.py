#!/usr/bin/env python3
"""Select a bounded top-k subset from a local tool/MCP schema catalog.

The helper is advisory only: it never edits MCP config or an agent's tool
registry.  It writes a compact receipt plus a separate sanitized payload so an
agent can inject a small selection report first and recover the full sanitized
schema later when needed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
from pathlib import Path
import re
import stat
import sys
import time
from dataclasses import dataclass
from typing import Any, NoReturn

TOOL_NAME = "context-guard-tool-prune"
SCHEMA_VERSION = "contextguard.tool-prune.v1"
DEFER_SCHEMA_VERSION = "contextguard.tool-prune.defer.v1"
DEFAULT_STORE_DIR = ".context-guard/tool-prune"
DEFAULT_TOP = 5
DEFAULT_CORE_TOP = 3
DEFAULT_DEFERRED_TOP = 20
DEFAULT_NAMESPACE_TOP = 20
DEFAULT_BUDGET_BYTES = 12_000
DEFAULT_MAX_CATALOG_BYTES = 1_000_000
DEFAULT_MAX_OUTPUT_BYTES = 65_536
DEFAULT_MAX_PAYLOAD_BYTES = 1_048_576
DEFAULT_MAX_RECEIPT_BYTES = 16_384
MAX_TOP = 200
MAX_DEFERRED_TOP = 1_000
MAX_NAMESPACE_TOP = 200
MAX_LABEL_CHARS = 160
NO_FOLLOW_SUPPORTED = hasattr(os, "O_NOFOLLOW")
DIR_FD_OPEN_SUPPORTED = bool(os.supports_dir_fd and os.open in os.supports_dir_fd)
DIR_FD_MKDIR_SUPPORTED = bool(os.supports_dir_fd and os.mkdir in os.supports_dir_fd)
DIR_FD_STAT_SUPPORTED = bool(os.supports_dir_fd and os.stat in os.supports_dir_fd)
DIR_FD_UNLINK_SUPPORTED = bool(os.supports_dir_fd and os.unlink in os.supports_dir_fd)
MAX_DESCRIPTION_CHARS = 360
MAX_OMITTED_TOOLS = 30
TOKEN_PROXY_CHARS_PER_TOKEN = 4
ALLOWED_FIRST_ABSOLUTE_SYMLINKS = {
    "tmp": Path("/private/tmp"),
    "var": Path("/private/var"),
}
RECEIPT_ID_RE = re.compile(r"^[a-f0-9]{16,64}$")
TERM_RE = re.compile(r"[A-Za-z0-9_]+")
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
SENSITIVE_KEY_RE = re.compile(
    r"(?i)(authorization|api[_-]?key|apikey|token|secret|password|passwd|pwd|client[_-]?secret|credential|signature|sig|x-amz-signature|x-amz-credential|awsaccesskeyid|(?:aws[_-]?)?access[_-]?key(?:[_-]?id)?|private[_-]?key|privatekey|pgp[_-]?private[_-]?key|pgpprivatekey|ssh[_-]?key|sshkey)"
)
VALUE_BEARING_KEY_RE = re.compile(r"(?i)^(default|const|enum|example|examples|value|values)$")


class ToolPruneError(ValueError):
    """User-facing fail-closed error."""


@dataclass(frozen=True)
class Candidate:
    name: str
    server: str | None
    description: str
    schema: dict[str, Any]
    index: int
    score: float = 0.0
    rank: int = 0


def fail(message: str) -> NoReturn:
    raise ToolPruneError(message)


def byte_len_text(text: str) -> int:
    return len(text.encode("utf-8", errors="replace"))


def json_bytes(data: Any, *, indent: int | None = None) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":") if indent is None else None, indent=indent)


def byte_len_json(data: Any) -> int:
    return byte_len_text(json_bytes(data))


def proxy_tokens(chars: int) -> int:
    return max(0, (int(chars) + TOKEN_PROXY_CHARS_PER_TOKEN - 1) // TOKEN_PROXY_CHARS_PER_TOKEN)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def bounded_int(value: object, *, default: int, minimum: int, maximum: int, name: str) -> int:
    try:
        number = int(default if value is None else value)
    except (TypeError, ValueError, OverflowError):
        fail(f"{name} must be an integer")
    if number < minimum:
        fail(f"{name} must be >= {minimum}")
    if number > maximum:
        fail(f"{name} must be <= {maximum}")
    return number


def cap_text(value: object, limit: int = MAX_LABEL_CHARS) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    marker = f"…[trimmed:{len(text)} chars]"
    return text[: max(0, limit - len(marker))] + marker


def redact_string(value: str) -> tuple[str, int]:
    def repl(match: re.Match[str]) -> str:
        text = match.group(0)
        if "=" in text:
            key = text.split("=", 1)[0]
            if SENSITIVE_KEY_RE.search(key):
                return key + "=[REDACTED]"
        if ":" in text:
            key = text.split(":", 1)[0]
            if SENSITIVE_KEY_RE.search(key):
                return key + ": [REDACTED]"
        return "[REDACTED]"

    return SECRET_RE.subn(repl, value)


def redact_whole_value(value: Any) -> tuple[Any, int]:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        count = 0
        for key, item in value.items():
            safe_key, key_redactions = redact_string(str(key))
            sanitized, item_redactions = redact_whole_value(item)
            out[safe_key] = sanitized
            count += key_redactions + item_redactions
        return out, count
    if isinstance(value, list):
        out: list[Any] = []
        count = 0
        for item in value:
            sanitized, item_redactions = redact_whole_value(item)
            out.append(sanitized)
            count += item_redactions
        return out, count
    return "[REDACTED]", 1


def sanitize_value(value: Any, *, sensitive_context: bool = False, sensitive_schema_context: bool = False) -> tuple[Any, int]:
    if sensitive_context:
        return redact_whole_value(value)
    if isinstance(value, str):
        return redact_string(value)
    if isinstance(value, list):
        out: list[Any] = []
        count = 0
        for item in value:
            sanitized, redactions = sanitize_value(item, sensitive_schema_context=sensitive_schema_context)
            out.append(sanitized)
            count += redactions
        return out, count
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        count = 0
        for key, item in value.items():
            raw_key = str(key)
            safe_key, key_redactions = redact_string(raw_key)
            key_sensitive = bool(SENSITIVE_KEY_RE.search(raw_key))
            value_bearing = bool(VALUE_BEARING_KEY_RE.search(raw_key))
            if key_sensitive and not isinstance(item, dict):
                sanitized, item_redactions = sanitize_value(item, sensitive_context=True)
            elif key_sensitive:
                sanitized, item_redactions = sanitize_value(item, sensitive_schema_context=True)
            elif sensitive_schema_context and value_bearing:
                sanitized, item_redactions = sanitize_value(item, sensitive_context=True)
            else:
                sanitized, item_redactions = sanitize_value(item, sensitive_schema_context=sensitive_schema_context)
            out[safe_key] = sanitized
            count += key_redactions + item_redactions
        return out, count
    return value, 0


def read_limited_path(path: Path, max_bytes: int) -> str:
    reject_symlink_components(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError as exc:
        fail(f"catalog read failed: {exc}")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            fail("catalog must be a regular file")
        if st.st_size > max_bytes:
            fail(f"catalog exceeds --max-catalog-bytes: {st.st_size} > {max_bytes}")
        data = os.read(fd, max_bytes + 1)
    finally:
        os.close(fd)
    if len(data) > max_bytes:
        fail(f"catalog exceeds --max-catalog-bytes: > {max_bytes}")
    return data.decode("utf-8", errors="replace")


def read_limited_stdin(max_bytes: int) -> str:
    data = sys.stdin.buffer.read(max_bytes + 1)
    if len(data) > max_bytes:
        fail(f"catalog exceeds --max-catalog-bytes: > {max_bytes}")
    return data.decode("utf-8", errors="replace")


def parse_catalog_text(text: str) -> tuple[Any, int]:
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        fail(f"catalog must be valid JSON: {exc.msg}")
    return sanitize_value(raw)


def first_str(mapping: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def tool_schema_from_dict(raw: dict[str, Any], *, fallback_name: str | None = None, server: str | None = None, index: int = 0) -> Candidate | None:
    name = first_str(raw, ("name", "tool", "id", "title")) or (fallback_name or "")
    name = cap_text(name, MAX_LABEL_CHARS)
    if not name:
        return None
    description = cap_text(first_str(raw, ("description", "summary", "doc", "docs")), MAX_DESCRIPTION_CHARS)
    schema = dict(raw)
    schema.setdefault("name", name)
    if description and "description" not in schema:
        schema["description"] = description
    if server and "server" not in schema:
        schema["server"] = server
    return Candidate(name=name, server=cap_text(server, MAX_LABEL_CHARS) if server else None, description=description, schema=schema, index=index)


def normalize_catalog(raw: Any) -> list[Candidate]:
    candidates: list[Candidate] = []

    def add_tool(tool: Any, *, server: str | None = None, fallback_name: str | None = None) -> None:
        if isinstance(tool, str):
            tool = {"name": tool}
        if not isinstance(tool, dict):
            return
        cand = tool_schema_from_dict(tool, fallback_name=fallback_name, server=server, index=len(candidates))
        if cand is not None:
            candidates.append(cand)

    def add_tools(tools: Any, *, server: str | None = None) -> None:
        if isinstance(tools, list):
            for tool in tools:
                add_tool(tool, server=server)
        elif isinstance(tools, dict):
            for name, schema in tools.items():
                if isinstance(schema, dict):
                    add_tool(schema, server=server, fallback_name=str(name))
                else:
                    add_tool({"name": str(name), "schema": schema}, server=server)

    if isinstance(raw, list):
        add_tools(raw)
    elif isinstance(raw, dict):
        if "tools" in raw:
            add_tools(raw.get("tools"), server=first_str(raw, ("server", "name")) or None)
        if "servers" in raw and isinstance(raw.get("servers"), list):
            for server_obj in raw.get("servers") or []:
                if isinstance(server_obj, dict):
                    add_tools(server_obj.get("tools"), server=first_str(server_obj, ("name", "id", "server")) or None)
        if "mcpServers" in raw and isinstance(raw.get("mcpServers"), dict):
            for server_name, server_obj in (raw.get("mcpServers") or {}).items():
                if isinstance(server_obj, dict):
                    add_tools(server_obj.get("tools"), server=str(server_name))
        if not candidates:
            # Simple name-to-schema map.
            for name, schema in raw.items():
                if name in {"tools", "servers", "mcpServers"}:
                    continue
                if isinstance(schema, dict):
                    add_tool(schema, fallback_name=str(name))
                elif isinstance(schema, (str, list)):
                    add_tool({"name": str(name), "schema": schema})
    if not candidates:
        fail("catalog contains no tools")
    return candidates


def terms(text: str) -> set[str]:
    return {term.lower() for term in TERM_RE.findall(text or "") if term}


def collect_parameter_text(value: Any, *, depth: int = 0, max_items: int = 500) -> list[str]:
    out: list[str] = []
    if depth > 8 or max_items <= 0:
        return out
    if isinstance(value, dict):
        for key, item in value.items():
            if len(out) >= max_items:
                break
            key_text = str(key)
            if key_text.lower() in {"properties", "parameters", "inputschema", "input_schema", "schema", "description", "title", "name"}:
                out.append(key_text)
            elif isinstance(item, (str, int, float, bool)):
                out.append(key_text)
            if isinstance(item, str) and key_text.lower() in {"description", "title", "name"}:
                out.append(item)
            out.extend(collect_parameter_text(item, depth=depth + 1, max_items=max_items - len(out)))
    elif isinstance(value, list):
        for item in value[:max_items]:
            if len(out) >= max_items:
                break
            out.extend(collect_parameter_text(item, depth=depth + 1, max_items=max_items - len(out)))
    return out[:max_items]


def score_candidate(candidate: Candidate, query_terms: set[str]) -> float:
    if not query_terms:
        return 0.0
    name_terms = terms(candidate.name)
    desc_terms = terms(candidate.description)
    parameter_terms = terms(" ".join(collect_parameter_text(candidate.schema)))
    score = 0.0
    score += 4.0 * len(query_terms & name_terms)
    score += 1.5 * len(query_terms & desc_terms)
    score += 1.0 * len(query_terms & parameter_terms)
    # Light substring bonus for names such as git_status when the query says status.
    lowered_name = candidate.name.lower()
    for term in query_terms:
        if term and term in lowered_name and term not in name_terms:
            score += 1.0
    return score


def rank_candidates(candidates: list[Candidate], query: str) -> list[Candidate]:
    query_terms = terms(query)
    scored: list[Candidate] = []
    for cand in candidates:
        scored.append(Candidate(cand.name, cand.server, cand.description, cand.schema, cand.index, score_candidate(cand, query_terms), 0))
    scored.sort(key=lambda item: (-item.score, item.index))
    ranked: list[Candidate] = []
    for rank, cand in enumerate(scored, start=1):
        ranked.append(Candidate(cand.name, cand.server, cand.description, cand.schema, cand.index, cand.score, rank))
    return ranked


def normalized_link_target(parent: Path, raw_target: str) -> Path:
    target = Path(raw_target)
    if not target.is_absolute():
        target = parent / target
    return Path(os.path.normpath(str(target)))


def normalize_allowed_first_absolute_symlink(path: Path) -> Path:
    if not path.is_absolute() or len(path.parts) < 2:
        return path
    first = path.parts[1]
    expected = ALLOWED_FIRST_ABSOLUTE_SYMLINKS.get(first)
    if expected is None:
        return path
    link = Path(path.anchor) / first
    try:
        if not stat.S_ISLNK(os.lstat(link).st_mode):
            return path
        if normalized_link_target(Path(path.anchor), os.readlink(link)) != expected:
            return path
    except OSError:
        return path
    return expected.joinpath(*path.parts[2:])


def reject_symlink_components(path: Path) -> None:
    path = normalize_allowed_first_absolute_symlink(path)
    current = Path(path.anchor) if path.is_absolute() else Path()
    for part in path.parts:
        if path.is_absolute() and part == path.anchor:
            continue
        current = current / part
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(st.st_mode):
            fail(f"refusing path with symlink component: {current}")
        if not stat.S_ISDIR(st.st_mode) and current != path:
            fail(f"refusing path through non-directory component: {current}")


def dir_fd_replace_supported() -> bool:
    try:
        import inspect

        signature = inspect.signature(os.replace)
    except (TypeError, ValueError):
        return True
    return "src_dir_fd" in signature.parameters and "dst_dir_fd" in signature.parameters


DIR_FD_REPLACE_SUPPORTED = dir_fd_replace_supported()


def reject_parent_traversal(path: Path, *, label: str) -> None:
    if ".." in path.parts:
        fail(f"{label} must not contain parent traversal")


def os_error_detail(exc: OSError) -> str:
    detail = exc.strerror or str(exc) or exc.__class__.__name__
    if exc.errno is not None:
        return f"{detail} (errno {exc.errno})"
    return detail


def no_follow_dir_flags() -> int:
    if not NO_FOLLOW_SUPPORTED:
        fail("private store IO requires O_NOFOLLOW support")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    return flags


def private_temp_file_flags() -> int:
    if not NO_FOLLOW_SUPPORTED:
        fail("private store IO requires O_NOFOLLOW support")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOCTTY"):
        flags |= os.O_NOCTTY
    return flags


def open_private_directory_no_follow(path: Path, *, label: str, create: bool) -> int:
    reject_parent_traversal(path, label=label)
    path = normalize_allowed_first_absolute_symlink(path.expanduser())
    if not DIR_FD_OPEN_SUPPORTED:
        fail(f"{label} requires dir_fd open support")
    if create and not DIR_FD_MKDIR_SUPPORTED:
        fail(f"{label} requires dir_fd mkdir support")
    flags = no_follow_dir_flags()
    if path.is_absolute():
        root_flags = os.O_RDONLY | (os.O_CLOEXEC if hasattr(os, "O_CLOEXEC") else 0)
        current_fd = os.open(path.anchor or os.sep, root_flags)
        parts = path.parts[1:]
    else:
        current_fd = os.open(".", flags)
        parts = path.parts
    try:
        for part in parts:
            if part in {"", "."}:
                continue
            if part == "..":
                fail(f"{label} must not contain parent traversal")
            try:
                next_fd = os.open(part, flags, dir_fd=current_fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o700, dir_fd=current_fd)
                next_fd = os.open(part, flags, dir_fd=current_fd)
            try:
                if not stat.S_ISDIR(os.fstat(next_fd).st_mode):
                    fail(f"{label} must not traverse non-directory components")
            except Exception:
                os.close(next_fd)
                raise
            os.close(current_fd)
            current_fd = next_fd
        owned_fd = current_fd
        current_fd = -1
        return owned_fd
    except OSError as exc:
        fail(f"could not inspect {label}: {os_error_detail(exc)}")
    finally:
        if current_fd >= 0:
            os.close(current_fd)


def precheck_private_leaf(parent_fd: int, leaf: str, *, label: str) -> None:
    if not DIR_FD_STAT_SUPPORTED:
        fail(f"{label} requires dir_fd stat support")
    try:
        st = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        fail(f"could not inspect {label}: {os_error_detail(exc)}")
    if not stat.S_ISREG(st.st_mode):
        fail(f"{label} must be missing or a regular file")


def write_all_fd(fd: int, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = os.write(fd, view[offset:])
        if written <= 0:
            raise OSError("short write")
        offset += written


def fsync_best_effort(fd: int) -> None:
    try:
        os.fsync(fd)
    except OSError:
        pass


def ensure_private_dir(path: Path) -> None:
    reject_parent_traversal(path, label="store directory")
    try:
        fd = open_private_directory_no_follow(path, label="store directory", create=True)
    except OSError as exc:
        fail(f"store directory unavailable: {exc}")
    try:
        try:
            os.fchmod(fd, 0o700)
        except OSError:
            pass
    finally:
        os.close(fd)


def write_private_json_atomic(path: Path, data: dict[str, Any], *, max_bytes: int, label: str) -> int:
    text = json_bytes(data, indent=2) + "\n"
    size = byte_len_text(text)
    if size > max_bytes:
        fail(f"{label} exceeds size cap: {size} > {max_bytes}")
    reject_parent_traversal(path, label=label)
    if not DIR_FD_REPLACE_SUPPORTED:
        fail(f"{label} write requires dir_fd replace support")
    if not DIR_FD_UNLINK_SUPPORTED:
        fail(f"{label} write requires dir_fd unlink support")
    parent_fd = open_private_directory_no_follow(path.parent, label="store directory", create=True)
    fd = -1
    temp_leaf: str | None = None
    try:
        try:
            os.fchmod(parent_fd, 0o700)
        except OSError:
            pass
        leaf = path.name
        if leaf in {"", ".", ".."}:
            fail(f"{label} must name a regular file")
        precheck_private_leaf(parent_fd, leaf, label=label)
        for _attempt in range(20):
            candidate = f".{leaf}.{os.getpid()}.{time.time_ns()}.tmp"
            try:
                fd = os.open(candidate, private_temp_file_flags(), 0o600, dir_fd=parent_fd)
                temp_leaf = candidate
                break
            except FileExistsError:
                continue
        if fd < 0 or temp_leaf is None:
            fail(f"{label} write failed: could not create temporary file")
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            fail(f"{label} temporary file must be a regular file")
        os.fchmod(fd, 0o600)
        write_all_fd(fd, text.encode("utf-8"))
        fsync_best_effort(fd)
        os.close(fd)
        fd = -1
        fsync_best_effort(parent_fd)
        os.replace(temp_leaf, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        temp_leaf = None
        fsync_best_effort(parent_fd)
    except OSError as exc:
        fail(f"{label} write failed: {os_error_detail(exc)}")
    except Exception:
        raise
    finally:
        if fd >= 0:
            os.close(fd)
        if temp_leaf is not None:
            try:
                os.unlink(temp_leaf, dir_fd=parent_fd)
            except OSError:
                pass
        os.close(parent_fd)
    return size


def read_private_text(path: Path, *, max_bytes: int, label: str) -> tuple[str, int]:
    reject_parent_traversal(path, label=label)
    parent_fd = open_private_directory_no_follow(path.parent, label=f"{label} directory", create=False)
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    leaf = path.name
    if leaf in {"", ".", ".."}:
        os.close(parent_fd)
        fail(f"{label} must name a regular file")
    try:
        fd = os.open(leaf, flags, dir_fd=parent_fd)
    except OSError as exc:
        os.close(parent_fd)
        fail(f"{label} read failed: {os_error_detail(exc)}")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            fail(f"{label} must be a regular file")
        if st.st_size > max_bytes:
            fail(f"{label} exceeds trusted size cap: {st.st_size} > {max_bytes}")
        data = os.read(fd, max_bytes + 1)
    finally:
        os.close(fd)
        os.close(parent_fd)
    if len(data) > max_bytes:
        fail(f"{label} exceeds trusted size cap: > {max_bytes}")
    return data.decode("utf-8", errors="replace"), len(data)


def read_private_json(path: Path, *, max_bytes: int, label: str) -> dict[str, Any]:
    text, _size = read_private_text(path, max_bytes=max_bytes, label=label)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        fail(f"{label} is malformed JSON: {exc.msg}")
    if not isinstance(parsed, dict):
        fail(f"{label} must be a JSON object")
    return parsed


def display_path(path: Path) -> str:
    try:
        rel = os.path.relpath(path, Path.cwd())
    except ValueError:
        rel = path.name
    rel = rel.replace(os.sep, "/")
    safe, _count = redact_string(rel)
    return safe


def store_paths(store_dir: str, receipt_id: str) -> tuple[Path, Path, Path]:
    if not RECEIPT_ID_RE.fullmatch(receipt_id):
        fail("receipt_id must be 16-64 lowercase hex chars")
    root = normalize_allowed_first_absolute_symlink(Path(store_dir).expanduser())
    return root, root / f"{receipt_id}.receipt.json", root / f"{receipt_id}.payload.json"


def build_receipt_id(payload_without_id: dict[str, Any]) -> str:
    basis = json_bytes(payload_without_id) + f"\n{time.time_ns()}:{os.getpid()}"
    return hashlib.sha256(basis.encode("utf-8", errors="replace")).hexdigest()[:20]


def build_payload(receipt_id: str, ranked: list[Candidate], query: str, redactions: int) -> dict[str, Any]:
    return {
        "tool": TOOL_NAME,
        "schema_version": SCHEMA_VERSION,
        "receipt_id": receipt_id,
        "created_at_unix": int(time.time()),
        "query": query,
        "candidate_count": len(ranked),
        "redaction": {"redacted_values": redactions},
        "tools": [
            {
                "name": cand.name,
                "server": cand.server,
                "description": cand.description,
                "score": cand.score,
                "rank": cand.rank,
                "schema_bytes": byte_len_json(cand.schema),
                "schema": cand.schema,
            }
            for cand in ranked
        ],
    }


def compact_omitted(candidates: list[Candidate], limit: int) -> tuple[list[dict[str, Any]], int]:
    items: list[dict[str, Any]] = []
    for cand in candidates[:limit]:
        items.append({
            "name": cap_text(cand.name, MAX_LABEL_CHARS),
            "server": cap_text(cand.server, MAX_LABEL_CHARS) if cand.server else None,
            "reason": "below_top_k",
            "score": cand.score,
            "rank": cand.rank,
        })
    return items, max(0, len(candidates) - len(items))


def retrieval_command(receipt_id: str, *, store_dir: str, tool_name: str | None = None) -> str:
    parts = ["context-guard-tool-prune", "get", receipt_id]
    if store_dir != DEFAULT_STORE_DIR:
        parts.extend(["--store-dir", shlex.quote(store_dir)])
    if tool_name is not None:
        parts.extend(["--tool", shlex.quote(tool_name)])
    parts.append("--json")
    return " ".join(parts)


def selected_tool_record(cand: Candidate, receipt_id: str, budget_left: int, *, store_dir: str) -> tuple[dict[str, Any], int]:
    schema_size = byte_len_json(cand.schema)
    record: dict[str, Any] = {
        "name": cand.name,
        "server": cand.server,
        "score": cand.score,
        "rank": cand.rank,
        "description": cand.description,
        "schema_bytes": schema_size,
        "retrieval": retrieval_command(receipt_id, store_dir=store_dir, tool_name=cand.name),
    }
    if schema_size <= budget_left:
        record["schema_included"] = True
        record["schema"] = cand.schema
        return record, schema_size
    record["schema_included"] = False
    record["schema_omitted_reason"] = "budget"
    return record, 0


def deferred_tool_record(cand: Candidate, receipt_id: str, *, store_dir: str) -> dict[str, Any]:
    return {
        "name": cand.name,
        "server": cand.server,
        "score": cand.score,
        "rank": cand.rank,
        "description": cand.description,
        "schema_bytes": byte_len_json(cand.schema),
        "reason": "deferred_after_core_top",
        "retrieval": retrieval_command(receipt_id, store_dir=store_dir, tool_name=cand.name),
    }


def namespace_records(
    ranked: list[Candidate],
    core_names: set[str],
    deferred_names: set[str],
    receipt_id: str,
    *,
    store_dir: str,
    namespace_top: int,
) -> tuple[list[dict[str, Any]], int]:
    grouped: dict[str, dict[str, Any]] = {}
    for cand in ranked:
        namespace = cand.server or "local"
        item = grouped.setdefault(
            namespace,
            {
                "namespace": namespace,
                "tool_count": 0,
                "core_count": 0,
                "listed_deferred_count": 0,
                "sample_tools": [],
                "retrieval": retrieval_command(receipt_id, store_dir=store_dir),
            },
        )
        item["tool_count"] += 1
        if cand.name in core_names:
            item["core_count"] += 1
        if cand.name in deferred_names:
            item["listed_deferred_count"] += 1
        samples = item["sample_tools"]
        if isinstance(samples, list) and len(samples) < 8:
            samples.append(cand.name)
    records = sorted(grouped.values(), key=lambda item: (-int(item["listed_deferred_count"]), str(item["namespace"])))
    return records[:namespace_top], max(0, len(records) - namespace_top)


def build_receipt_and_payload(ranked: list[Candidate], safe_query: str, total_redactions: int, *, store_dir_arg: str, max_payload_bytes: int, max_receipt_bytes: int) -> tuple[str, dict[str, Any], dict[str, Any], Path, Path, Path, int, int]:
    payload_without_id = build_payload("pending", ranked, safe_query, total_redactions)
    receipt_id = build_receipt_id(payload_without_id)
    payload = build_payload(receipt_id, ranked, safe_query, total_redactions)
    payload_text = json_bytes(payload, indent=2) + "\n"
    payload_bytes = byte_len_text(payload_text)
    if payload_bytes > max_payload_bytes:
        fail(f"payload exceeds --max-payload-bytes: {payload_bytes} > {max_payload_bytes}")
    payload_sha = sha256_text(payload_text.rstrip("\n"))

    store_dir, receipt_path, payload_path = store_paths(store_dir_arg, receipt_id)
    receipt = {
        "tool": TOOL_NAME,
        "schema_version": SCHEMA_VERSION,
        "receipt_id": receipt_id,
        "created_at_unix": int(time.time()),
        "path": display_path(receipt_path),
        "payload_path": display_path(payload_path),
        "payload_sha256": payload_sha,
        "payload_bytes": payload_bytes,
        "contains": "compact_metadata_plus_sanitized_payload",
        "tool_count": len(ranked),
        "tools": [cand.name for cand in ranked[:50]],
        "tools_truncated": len(ranked) > 50,
        "retrieval_hint": retrieval_command(receipt_id, store_dir=store_dir_arg, tool_name="<name>"),
    }
    receipt_size = byte_len_text(json_bytes(receipt, indent=2) + "\n")
    if receipt_size > max_receipt_bytes:
        fail(f"receipt exceeds --max-receipt-bytes: {receipt_size} > {max_receipt_bytes}")
    return receipt_id, payload, receipt, store_dir, receipt_path, payload_path, payload_bytes, receipt_size


def shrink_result_for_output(result: dict[str, Any], max_output_bytes: int) -> str:
    candidate = json_bytes(result, indent=2) + "\n"
    if byte_len_text(candidate) <= max_output_bytes:
        return candidate

    result = json.loads(json_bytes(result))
    omitted = result.get("omitted_tools")
    while isinstance(omitted, list) and len(omitted) > 0:
        # The list is halved on each pass, so even a one-item list converges.
        keep = max(0, len(omitted) // 2)
        result["omitted_tools"] = omitted[:keep]
        result["omitted_tools_truncated"] = True
        result["omitted_tools_summary"] = f"{result.get('omitted_count', 0)} tools omitted; list capped to fit --max-output-bytes"
        candidate = json_bytes(result, indent=2) + "\n"
        if byte_len_text(candidate) <= max_output_bytes:
            return candidate
        omitted = result.get("omitted_tools")

    result["omitted_tools"] = []
    result["omitted_tools_truncated"] = True
    for item in result.get("selected_tools", []):
        if isinstance(item, dict):
            item.pop("description", None)
    candidate = json_bytes(result, indent=2) + "\n"
    if byte_len_text(candidate) <= max_output_bytes:
        return candidate
    fail(f"select report exceeds --max-output-bytes: {byte_len_text(candidate)} > {max_output_bytes}")


def select_catalog(args: argparse.Namespace) -> str:
    max_catalog_bytes = bounded_int(args.max_catalog_bytes, default=DEFAULT_MAX_CATALOG_BYTES, minimum=1, maximum=100_000_000, name="--max-catalog-bytes")
    max_output_bytes = bounded_int(args.max_output_bytes, default=DEFAULT_MAX_OUTPUT_BYTES, minimum=1, maximum=10_000_000, name="--max-output-bytes")
    max_payload_bytes = bounded_int(args.max_payload_bytes, default=DEFAULT_MAX_PAYLOAD_BYTES, minimum=1, maximum=100_000_000, name="--max-payload-bytes")
    max_receipt_bytes = bounded_int(args.max_receipt_bytes, default=DEFAULT_MAX_RECEIPT_BYTES, minimum=1, maximum=10_000_000, name="--max-receipt-bytes")
    top = bounded_int(args.top, default=DEFAULT_TOP, minimum=1, maximum=MAX_TOP, name="--top")
    budget_bytes = bounded_int(args.budget_bytes, default=DEFAULT_BUDGET_BYTES, minimum=0, maximum=100_000_000, name="--budget-bytes")

    text = read_limited_path(Path(args.catalog), max_catalog_bytes) if args.catalog else read_limited_stdin(max_catalog_bytes)
    raw, redactions = parse_catalog_text(text)
    raw_query = args.query or ""
    safe_query, query_redactions = redact_string(raw_query)
    total_redactions = redactions + query_redactions
    ranked = rank_candidates(normalize_catalog(raw), raw_query)
    payload_without_id = build_payload("pending", ranked, safe_query, total_redactions)
    receipt_id = build_receipt_id(payload_without_id)
    payload = build_payload(receipt_id, ranked, safe_query, total_redactions)
    payload_text = json_bytes(payload, indent=2) + "\n"
    payload_bytes = byte_len_text(payload_text)
    if payload_bytes > max_payload_bytes:
        fail(f"payload exceeds --max-payload-bytes: {payload_bytes} > {max_payload_bytes}")
    payload_sha = sha256_text(payload_text.rstrip("\n"))

    store_dir, receipt_path, payload_path = store_paths(args.store_dir, receipt_id)
    receipt = {
        "tool": TOOL_NAME,
        "schema_version": SCHEMA_VERSION,
        "receipt_id": receipt_id,
        "created_at_unix": int(time.time()),
        "path": display_path(receipt_path),
        "payload_path": display_path(payload_path),
        "payload_sha256": payload_sha,
        "payload_bytes": payload_bytes,
        "contains": "compact_metadata_plus_sanitized_payload",
        "tool_count": len(ranked),
        "tools": [cand.name for cand in ranked[:50]],
        "tools_truncated": len(ranked) > 50,
        "retrieval_hint": retrieval_command(receipt_id, store_dir=args.store_dir, tool_name="<name>"),
    }
    receipt_size = byte_len_text(json_bytes(receipt, indent=2) + "\n")
    if receipt_size > max_receipt_bytes:
        fail(f"receipt exceeds --max-receipt-bytes: {receipt_size} > {max_receipt_bytes}")

    selected: list[dict[str, Any]] = []
    selected_schema_bytes = 0
    for cand in ranked[:top]:
        record, used = selected_tool_record(cand, receipt_id, budget_bytes - selected_schema_bytes, store_dir=args.store_dir)
        selected_schema_bytes += used
        selected.append(record)
    omitted_tools, omitted_truncated = compact_omitted(ranked[top:], MAX_OMITTED_TOOLS)
    result = {
        "tool": TOOL_NAME,
        "schema_version": SCHEMA_VERSION,
        "mode": "select",
        "query": safe_query,
        "top": top,
        "budget_bytes": budget_bytes,
        "selected_schema_bytes": selected_schema_bytes,
        "candidate_count": len(ranked),
        "selected_tools": selected,
        "omitted_tools": omitted_tools,
        "omitted_count": len(ranked[top:]),
        "omitted_tools_truncated_count": omitted_truncated,
        "receipt": {
            **receipt,
            "bytes": receipt_size,
        },
        "token_proxy": {"measurement": "estimated", "chars_per_token": TOKEN_PROXY_CHARS_PER_TOKEN},
        "caveats": [
            "Ranking is heuristic lexical overlap, not a correctness proof.",
            "Token counts are estimated proxies; byte counts and schema budgets are observed UTF-8 bytes.",
            "Use the receipt get command to retrieve full sanitized schemas before relying on omitted details.",
        ],
        "redaction": {"redacted_values": total_redactions},
    }
    rendered = shrink_result_for_output(result, max_output_bytes)

    # Only write after every size gate has passed, so failures leave no success receipt.
    ensure_private_dir(store_dir)
    written_payload_bytes = write_private_json_atomic(payload_path, payload, max_bytes=max_payload_bytes, label="payload")
    if written_payload_bytes != payload_bytes:
        fail("payload byte size changed during write")
    written_receipt_bytes = write_private_json_atomic(receipt_path, receipt, max_bytes=max_receipt_bytes, label="receipt")
    if written_receipt_bytes != receipt_size:
        fail("receipt byte size changed during write")
    return rendered


def defer_report(args: argparse.Namespace) -> str:
    max_catalog_bytes = bounded_int(args.max_catalog_bytes, default=DEFAULT_MAX_CATALOG_BYTES, minimum=1, maximum=100_000_000, name="--max-catalog-bytes")
    max_output_bytes = bounded_int(args.max_output_bytes, default=DEFAULT_MAX_OUTPUT_BYTES, minimum=1, maximum=10_000_000, name="--max-output-bytes")
    max_payload_bytes = bounded_int(args.max_payload_bytes, default=DEFAULT_MAX_PAYLOAD_BYTES, minimum=1, maximum=100_000_000, name="--max-payload-bytes")
    max_receipt_bytes = bounded_int(args.max_receipt_bytes, default=DEFAULT_MAX_RECEIPT_BYTES, minimum=1, maximum=10_000_000, name="--max-receipt-bytes")
    core_top = bounded_int(args.core_top, default=DEFAULT_CORE_TOP, minimum=1, maximum=MAX_TOP, name="--core-top")
    deferred_top = bounded_int(args.deferred_top, default=DEFAULT_DEFERRED_TOP, minimum=0, maximum=MAX_DEFERRED_TOP, name="--deferred-top")
    namespace_top = bounded_int(args.namespace_top, default=DEFAULT_NAMESPACE_TOP, minimum=0, maximum=MAX_NAMESPACE_TOP, name="--namespace-top")
    budget_bytes = bounded_int(args.budget_bytes, default=DEFAULT_BUDGET_BYTES, minimum=0, maximum=100_000_000, name="--budget-bytes")

    text = read_limited_path(Path(args.catalog), max_catalog_bytes) if args.catalog else read_limited_stdin(max_catalog_bytes)
    raw, redactions = parse_catalog_text(text)
    raw_query = args.query or ""
    safe_query, query_redactions = redact_string(raw_query)
    total_redactions = redactions + query_redactions
    ranked = rank_candidates(normalize_catalog(raw), raw_query)
    (
        receipt_id,
        payload,
        receipt,
        store_dir,
        receipt_path,
        payload_path,
        payload_bytes,
        receipt_size,
    ) = build_receipt_and_payload(
        ranked,
        safe_query,
        total_redactions,
        store_dir_arg=args.store_dir,
        max_payload_bytes=max_payload_bytes,
        max_receipt_bytes=max_receipt_bytes,
    )

    core_candidates = ranked[:core_top]
    deferred_candidates = ranked[core_top:core_top + deferred_top]
    core_tools: list[dict[str, Any]] = []
    core_schema_bytes = 0
    for cand in core_candidates:
        record, used = selected_tool_record(cand, receipt_id, budget_bytes - core_schema_bytes, store_dir=args.store_dir)
        core_schema_bytes += used
        core_tools.append(record)
    deferred_tools = [deferred_tool_record(cand, receipt_id, store_dir=args.store_dir) for cand in deferred_candidates]
    core_names = {cand.name for cand in core_candidates}
    deferred_names = {cand.name for cand in deferred_candidates}
    deferred_namespaces, deferred_namespaces_truncated_count = namespace_records(
        ranked,
        core_names,
        deferred_names,
        receipt_id,
        store_dir=args.store_dir,
        namespace_top=namespace_top,
    )
    all_schema_bytes = sum(byte_len_json(cand.schema) for cand in ranked)
    listed_deferred_schema_bytes = sum(byte_len_json(cand.schema) for cand in deferred_candidates)
    total_deferred_schema_bytes = sum(byte_len_json(cand.schema) for cand in ranked[core_top:])
    tool_stub_report_bytes = byte_len_json(core_tools) + byte_len_json(deferred_tools)
    all_schema_tokens = proxy_tokens(all_schema_bytes)
    inline_core_schema_tokens = proxy_tokens(core_schema_bytes)
    listed_deferred_schema_tokens = proxy_tokens(listed_deferred_schema_bytes)
    total_deferred_schema_tokens = proxy_tokens(total_deferred_schema_bytes)
    tool_stub_report_tokens = proxy_tokens(tool_stub_report_bytes)
    result = {
        "tool": TOOL_NAME,
        "schema_version": DEFER_SCHEMA_VERSION,
        "mode": "defer-report",
        "query": safe_query,
        "core_top": core_top,
        "deferred_top": deferred_top,
        "namespace_top": namespace_top,
        "candidate_count": len(ranked),
        "native_provider_integration": False,
        "core_tools": core_tools,
        "deferred_tools": deferred_tools,
        "listed_deferred_count": len(deferred_tools),
        "total_deferred_count": max(0, len(ranked) - core_top),
        "deferred_tools_truncated_count": max(0, len(ranked) - core_top - len(deferred_tools)),
        "deferred_namespaces": deferred_namespaces,
        "deferred_namespaces_truncated_count": deferred_namespaces_truncated_count,
        "deferred_schema_retrieval_required_before_use": True,
        "receipt": {
            **receipt,
            "bytes": receipt_size,
        },
        "token_proxy": {
            "measurement": "estimated",
            "method": "char4_proxy",
            "chars_per_token": TOKEN_PROXY_CHARS_PER_TOKEN,
            "all_schema_bytes": all_schema_bytes,
            "inline_core_schema_bytes": core_schema_bytes,
            "listed_deferred_schema_bytes": listed_deferred_schema_bytes,
            "total_deferred_schema_bytes": total_deferred_schema_bytes,
            "tool_stub_report_bytes": tool_stub_report_bytes,
            "all_schema_tokens_estimated": all_schema_tokens,
            "inline_core_schema_tokens_estimated": inline_core_schema_tokens,
            "listed_deferred_schema_tokens_estimated": listed_deferred_schema_tokens,
            "total_deferred_schema_tokens_estimated": total_deferred_schema_tokens,
            "tool_stub_report_tokens_estimated": tool_stub_report_tokens,
            "gross_listed_deferred_schema_tokens_avoided": listed_deferred_schema_tokens,
            "gross_total_deferred_schema_tokens_avoided": total_deferred_schema_tokens,
            "net_initial_report_tokens_delta": tool_stub_report_tokens - all_schema_tokens,
            "net_initial_report_tokens_delta_semantics": "tool_stub_report_tokens_estimated_minus_all_schema_tokens_estimated",
            "estimated_initial_schema_tokens_avoided": max(0, all_schema_tokens - tool_stub_report_tokens),
            "estimated_initial_schema_tokens_avoided_semantics": "max(0, all_schema_tokens_estimated - tool_stub_report_tokens_estimated)",
            "claim_boundary": "proxy_only_not_provider_billed_tokens",
        },
        "provider_patterns": [
            {
                "provider": "openai",
                "pattern": "Keep only core tool schemas inline; retrieve deferred schemas through app/tool-search plumbing or the local receipt before invoking a deferred tool.",
                "native_provider_integration": False,
            },
            {
                "provider": "anthropic",
                "pattern": "Keep stable, frequently used tool definitions in the cacheable prefix; treat deferred tools as application-managed retrieval, not Claude-native lazy loading.",
                "native_provider_integration": False,
            },
            {
                "provider": "gemini",
                "pattern": "Group large tool catalogs by namespace and load only the task-relevant subset before the model call; verify any platform-native tool retrieval separately.",
                "native_provider_integration": False,
            },
        ],
        "claim_boundary": {
            "advisory_only": True,
            "native_provider_integration": False,
            "provider_tool_search_configured": False,
            "hosted_api_token_or_cost_savings_claim_allowed": False,
            "requires_provider_measured_matched_tasks_for_savings_claims": True,
            "deferred_schema_retrieval_required_before_use": True,
        },
        "redaction": {"redacted_values": total_redactions},
        "caveats": [
            "Deferred loading is an application strategy report, not a native provider integration.",
            "Token proxy values are char/4 estimates over sanitized local JSON, not billed provider tokens.",
            "Deferred schema token fields are initial-prompt proxy accounting; full schemas must be retrieved before deferred tool use.",
            "Use receipt get commands to retrieve full sanitized schemas before using deferred tools.",
        ],
    }
    rendered = json_bytes(result, indent=2) + "\n"
    if byte_len_text(rendered) > max_output_bytes:
        fail(f"defer report exceeds --max-output-bytes: {byte_len_text(rendered)} > {max_output_bytes}")

    # Only write after every size gate has passed, so failures leave no success receipt.
    ensure_private_dir(store_dir)
    written_payload_bytes = write_private_json_atomic(payload_path, payload, max_bytes=max_payload_bytes, label="payload")
    if written_payload_bytes != payload_bytes:
        fail("payload byte size changed during write")
    written_receipt_bytes = write_private_json_atomic(receipt_path, receipt, max_bytes=max_receipt_bytes, label="receipt")
    if written_receipt_bytes != receipt_size:
        fail("receipt byte size changed during write")
    return rendered


def payload_path_from_receipt(store_dir: Path, receipt_id: str, receipt: dict[str, Any]) -> Path:
    expected_name = f"{receipt_id}.payload.json"
    raw = str(receipt.get("payload_path") or "")
    if raw:
        raw_path = Path(raw)
        if raw_path.is_absolute():
            fail("receipt payload_path must be relative")
        if raw_path.name != expected_name:
            fail("receipt payload_path does not match receipt_id")
    return store_dir / expected_name


def get_schema(args: argparse.Namespace) -> str:
    max_payload_bytes = bounded_int(args.max_payload_bytes, default=DEFAULT_MAX_PAYLOAD_BYTES, minimum=1, maximum=100_000_000, name="--max-payload-bytes")
    max_receipt_bytes = bounded_int(args.max_receipt_bytes, default=DEFAULT_MAX_RECEIPT_BYTES, minimum=1, maximum=10_000_000, name="--max-receipt-bytes")
    max_output_bytes = bounded_int(args.max_output_bytes, default=10_000_000, minimum=1, maximum=100_000_000, name="--max-output-bytes")
    receipt_id = args.receipt_id
    if not RECEIPT_ID_RE.fullmatch(receipt_id):
        fail("receipt_id must be 16-64 lowercase hex chars")
    store_dir, receipt_path, _payload = store_paths(args.store_dir, receipt_id)
    reject_symlink_components(receipt_path)
    receipt = read_private_json(receipt_path, max_bytes=max_receipt_bytes, label="receipt")
    if receipt.get("receipt_id") != receipt_id:
        fail("receipt id mismatch")
    payload_path = payload_path_from_receipt(store_dir, receipt_id, receipt)
    reject_symlink_components(payload_path)
    expected_bytes = receipt.get("payload_bytes")
    expected_sha = receipt.get("payload_sha256")
    if not isinstance(expected_bytes, int) or expected_bytes < 0:
        fail("receipt missing payload byte size")
    if expected_bytes > max_payload_bytes:
        fail(f"payload exceeds trusted size cap: {expected_bytes} > {max_payload_bytes}")
    if not isinstance(expected_sha, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_sha):
        fail("receipt missing payload sha256")

    payload_text, actual_size = read_private_text(payload_path, max_bytes=max_payload_bytes, label="payload")
    if actual_size != expected_bytes:
        fail(f"payload size mismatch: {actual_size} != {expected_bytes}")
    actual_sha = sha256_text(payload_text.rstrip("\n"))
    if actual_sha != expected_sha:
        fail("payload sha256 mismatch")
    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError as exc:
        fail(f"payload is malformed JSON: {exc.msg}")
    if not isinstance(payload, dict):
        fail("payload must be a JSON object")
    if payload.get("receipt_id") != receipt_id:
        fail("payload receipt id mismatch")
    tools = payload.get("tools")
    if not isinstance(tools, list):
        fail("payload tools missing")

    if not args.tool:
        result = {
            "tool": TOOL_NAME,
            "schema_version": SCHEMA_VERSION,
            "mode": "get",
            "receipt_id": receipt_id,
            "tools": [item.get("name") for item in tools if isinstance(item, dict)],
        }
    else:
        found = None
        for item in tools:
            if isinstance(item, dict) and item.get("name") == args.tool:
                found = item
                break
        if found is None:
            safe_tool, _tool_redactions = redact_string(args.tool)
            fail(f"tool not found in receipt: {safe_tool}")
        result = {
            "tool": TOOL_NAME,
            "schema_version": SCHEMA_VERSION,
            "mode": "get",
            "receipt_id": receipt_id,
            "tool_name": args.tool,
            "server": found.get("server"),
            "schema": found.get("schema"),
        }
    sanitized_result, _redactions = sanitize_value(result)
    if not isinstance(sanitized_result, dict):
        fail("get result sanitation failed")
    text = json_bytes(sanitized_result, indent=2) + "\n"
    if byte_len_text(text) > max_output_bytes:
        fail(f"get report exceeds --max-output-bytes: {byte_len_text(text)} > {max_output_bytes}")
    return text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Select bounded top-k tool/MCP schemas with local full-schema fallback receipts.")
    sub = parser.add_subparsers(dest="command", required=True)

    select = sub.add_parser("select", help="rank a local catalog and emit a bounded selection report")
    select.add_argument("--catalog", help="catalog JSON path; stdin is used when omitted")
    select.add_argument("--query", default="", help="task query used for lexical ranking")
    select.add_argument("--top", default=DEFAULT_TOP, help=f"number of tools to select (default: {DEFAULT_TOP})")
    select.add_argument("--budget-bytes", default=DEFAULT_BUDGET_BYTES, help=f"inline selected schema byte budget (default: {DEFAULT_BUDGET_BYTES})")
    select.add_argument("--max-catalog-bytes", default=DEFAULT_MAX_CATALOG_BYTES, help=f"maximum catalog JSON bytes (default: {DEFAULT_MAX_CATALOG_BYTES})")
    select.add_argument("--max-output-bytes", default=DEFAULT_MAX_OUTPUT_BYTES, help=f"maximum rendered select JSON bytes (default: {DEFAULT_MAX_OUTPUT_BYTES})")
    select.add_argument("--max-payload-bytes", default=DEFAULT_MAX_PAYLOAD_BYTES, help=f"maximum sanitized payload bytes (default: {DEFAULT_MAX_PAYLOAD_BYTES})")
    select.add_argument("--max-receipt-bytes", default=DEFAULT_MAX_RECEIPT_BYTES, help=f"maximum compact receipt bytes (default: {DEFAULT_MAX_RECEIPT_BYTES})")
    select.add_argument("--store-dir", default=DEFAULT_STORE_DIR, help=f"receipt/payload directory (default: {DEFAULT_STORE_DIR})")
    select.add_argument("--json", action="store_true", help="emit JSON (default and only stable output contract)")

    defer = sub.add_parser("defer-report", help="split a local catalog into core inline tools plus deferred receipt-backed tools")
    defer.add_argument("--catalog", help="catalog JSON path; stdin is used when omitted")
    defer.add_argument("--query", default="", help="task query used for lexical ranking")
    defer.add_argument("--core-top", default=DEFAULT_CORE_TOP, help=f"number of core inline tools (default: {DEFAULT_CORE_TOP})")
    defer.add_argument("--deferred-top", default=DEFAULT_DEFERRED_TOP, help=f"number of deferred tool stubs to list (default: {DEFAULT_DEFERRED_TOP})")
    defer.add_argument("--namespace-top", default=DEFAULT_NAMESPACE_TOP, help=f"number of deferred namespace summaries to list (default: {DEFAULT_NAMESPACE_TOP})")
    defer.add_argument("--budget-bytes", default=DEFAULT_BUDGET_BYTES, help=f"inline core schema byte budget (default: {DEFAULT_BUDGET_BYTES})")
    defer.add_argument("--max-catalog-bytes", default=DEFAULT_MAX_CATALOG_BYTES, help=f"maximum catalog JSON bytes (default: {DEFAULT_MAX_CATALOG_BYTES})")
    defer.add_argument("--max-output-bytes", default=DEFAULT_MAX_OUTPUT_BYTES, help=f"maximum rendered defer JSON bytes (default: {DEFAULT_MAX_OUTPUT_BYTES})")
    defer.add_argument("--max-payload-bytes", default=DEFAULT_MAX_PAYLOAD_BYTES, help=f"maximum sanitized payload bytes (default: {DEFAULT_MAX_PAYLOAD_BYTES})")
    defer.add_argument("--max-receipt-bytes", default=DEFAULT_MAX_RECEIPT_BYTES, help=f"maximum compact receipt bytes (default: {DEFAULT_MAX_RECEIPT_BYTES})")
    defer.add_argument("--store-dir", default=DEFAULT_STORE_DIR, help=f"receipt/payload directory (default: {DEFAULT_STORE_DIR})")
    defer.add_argument("--json", action="store_true", help="emit JSON (default and only stable output contract)")

    get = sub.add_parser("get", help="retrieve a full sanitized schema from a receipt payload")
    get.add_argument("receipt_id", help="receipt id returned by select")
    get.add_argument("--tool", help="tool name to retrieve; omit to list available names")
    get.add_argument("--store-dir", default=DEFAULT_STORE_DIR, help=f"receipt/payload directory (default: {DEFAULT_STORE_DIR})")
    get.add_argument("--max-output-bytes", default=10_000_000, help="maximum rendered get JSON bytes")
    get.add_argument("--max-payload-bytes", default=DEFAULT_MAX_PAYLOAD_BYTES, help=f"maximum trusted payload bytes (default: {DEFAULT_MAX_PAYLOAD_BYTES})")
    get.add_argument("--max-receipt-bytes", default=DEFAULT_MAX_RECEIPT_BYTES, help=f"maximum trusted receipt bytes (default: {DEFAULT_MAX_RECEIPT_BYTES})")
    get.add_argument("--json", action="store_true", help="emit JSON (default and only stable output contract)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "select":
            sys.stdout.write(select_catalog(args))
            return 0
        if args.command == "defer-report":
            sys.stdout.write(defer_report(args))
            return 0
        if args.command == "get":
            sys.stdout.write(get_schema(args))
            return 0
        parser.print_help(sys.stderr)
        return 2
    except ToolPruneError as exc:
        print(f"{TOOL_NAME}: {exc}", file=sys.stderr)
        return 1
    except BrokenPipeError:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
