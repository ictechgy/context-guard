#!/usr/bin/env python3
"""Revision-bound, provider-free persistent task memory."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
from typing import Any, Iterator


SCHEMA = "contextguard.task-memory.v1"
DEFAULT_STORE = ".context-guard/task-memory"
DEFAULT_TTL = 7 * 24 * 60 * 60
DEFAULT_MAX_ENTRY_BYTES = 1_000_000
DEFAULT_MAX_TOTAL_BYTES = 10_000_000
DEFAULT_MAX_ENTRIES = 100
MAX_EXACT_BYTES = 1_000_000
MAX_SOURCE_BYTES = 10_000_000
MAX_REVISION_BYTES = 10_000_000
MAX_REVISION_FILES = 4_096
MAX_METADATA_BYTES = 128_000
HANDLE_RE = re.compile(r"^contextguard-memory:([a-f0-9]{32})$")
SECRET_RE = re.compile(
    rb"(?i)(Bearer\s+\S+|Basic\s+\S+|gh[pousr]_[A-Za-z0-9_]{20,}|"
    rb"github_pat_[A-Za-z0-9_]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|"
    rb"sk-(?:ant|proj)-[A-Za-z0-9_-]{12,}|sk-[A-Za-z0-9][A-Za-z0-9_-]{20,}|"
    rb"AIza[0-9A-Za-z_-]{20,}|(?:api[_-]?key|token|secret|password|passwd|pwd)\s*[:=]\s*\S+)"
)


class MemoryError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def regular_private(path: Path, *, label: str) -> os.stat_result:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise MemoryError(f"cannot inspect {label}") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
        raise MemoryError(f"unsafe {label}")
    return info


def private_directory(path: Path, *, label: str) -> os.stat_result:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise MemoryError(f"cannot inspect {label}") from exc
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise MemoryError(f"unsafe {label}")
    return info


def secure_read(path: Path, *, maximum: int, label: str) -> bytes:
    info = regular_private(path, label=label)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise MemoryError(f"cannot open {label}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600:
            raise MemoryError(f"unsafe {label}")
        data = os.read(fd, maximum + 1)
        after = os.fstat(fd)
        if len(data) > maximum or (info.st_dev, info.st_ino, info.st_size) != (before.st_dev, before.st_ino, before.st_size) or (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size):
            raise MemoryError(f"invalid {label}")
        return data
    finally:
        os.close(fd)


def atomic_write(directory: Path, name: str, data: bytes) -> None:
    temp = f".{name}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    dir_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(temp, flags, 0o600, dir_fd=dir_fd)
    except Exception:
        os.close(dir_fd)
        raise
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    try:
        os.replace(temp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        os.fsync(dir_fd)
    except Exception:
        try:
            os.unlink(temp, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(dir_fd)


def source_read(path: Path) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise MemoryError("cannot securely open source") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise MemoryError("source must be a single-link regular file")
        if before.st_size > MAX_SOURCE_BYTES:
            raise MemoryError("source exceeds bounded identity limit")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(fd, 64 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > MAX_SOURCE_BYTES:
                raise MemoryError("source exceeds bounded identity limit")
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise MemoryError("source changed while reading")
        return b"".join(chunks), after
    finally:
        os.close(fd)


def resolve_root(raw: str) -> Path:
    supplied = Path(raw).absolute()
    try:
        if supplied.is_symlink():
            raise MemoryError("project root must not be a symlink")
        root = supplied.resolve(strict=True)
    except OSError as exc:
        raise MemoryError("invalid project root") from exc
    info = os.lstat(root)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise MemoryError("project root is not a directory")
    return root


def resolve_store(root: Path, raw: str) -> Path:
    candidate = Path(raw)
    if candidate.is_absolute():
        try:
            candidate = candidate.parent.resolve(strict=True) / candidate.name
        except OSError as exc:
            raise MemoryError("store parent is unavailable") from exc
    else:
        candidate = root / candidate
    candidate = Path(os.path.abspath(candidate))
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise MemoryError("store must be inside project root") from exc
    current = root
    for part in candidate.relative_to(root).parts:
        current = current / part
        try:
            if stat.S_ISLNK(os.lstat(current).st_mode):
                raise MemoryError("store contains a symlink component")
        except FileNotFoundError:
            continue
    return candidate


def ensure_store(store: Path) -> None:
    store.mkdir(mode=0o700, parents=True, exist_ok=True)
    records = store / "records"
    records.mkdir(mode=0o700, exist_ok=True)
    private_directory(store, label="memory store")
    private_directory(records, label="record directory")


class locked_store:
    def __init__(self, store: Path) -> None:
        self.store = store
        self.fd = -1

    def __enter__(self) -> "locked_store":
        ensure_store(self.store)
        path = self.store / "lock"
        self.fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.fchmod(self.fd, 0o600)
        info = os.fstat(self.fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
            raise MemoryError("unsafe memory lock")
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *_args: object) -> None:
        if self.fd >= 0:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)


def load_key(store: Path) -> bytes:
    path = store / "key"
    if not path.exists():
        atomic_write(store, "key", secrets.token_bytes(32))
    key = secure_read(path, maximum=64, label="authentication key")
    if len(key) != 32:
        raise MemoryError("invalid authentication key")
    return key


def git(root: Path, *args: str) -> bytes:
    executable = "/usr/bin/git"
    if not Path(executable).is_file():
        raise MemoryError("trusted Git executable unavailable")
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1", "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/usr/bin/false",
        "SSH_ASKPASS": "/usr/bin/false", "LANG": "C", "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    try:
        proc = subprocess.run(
            [executable, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", *args],
            cwd=root, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise MemoryError("project must be a readable Git worktree") from None
    if proc.returncode != 0:
        raise MemoryError("project must be a readable Git worktree")
    return proc.stdout


def project_identity(root: Path) -> dict[str, Any]:
    info = os.stat(root)
    return {"physical_root_sha256": sha256(os.fsencode(str(root))), "device": info.st_dev, "inode": info.st_ino}


def revision_identity(root: Path, store: Path) -> dict[str, str]:
    head = git(root, "rev-parse", "HEAD").decode("ascii").strip()
    staged = git(root, "diff", "--cached", "--raw", "-z", "--no-renames", "--no-ext-diff", "--no-textconv")
    names = git(root, "ls-files", "-m", "-o", "--exclude-standard", "-z").split(b"\0")
    try:
        store_rel = store.relative_to(root).as_posix()
    except ValueError:
        store_rel = ""
    rows: list[dict[str, str]] = []
    revision_bytes = 0
    revision_files = 0
    for raw in names:
        if not raw:
            continue
        rel = os.fsdecode(raw)
        if store_rel and (rel == store_rel or rel.startswith(store_rel + "/")):
            continue
        path = root / rel
        revision_files += 1
        if revision_files > MAX_REVISION_FILES:
            raise MemoryError("worktree identity exceeds bounded file limit")
        try:
            metadata = os.lstat(path)
        except OSError:
            rows.append({"path_sha256": sha256(raw), "content_sha256": "unsafe"})
            continue
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            rows.append({"path_sha256": sha256(raw), "content_sha256": "unsafe"})
            continue
        data, _metadata = source_read(path)
        revision_bytes += len(data)
        if revision_bytes > MAX_REVISION_BYTES:
            raise MemoryError("worktree identity exceeds bounded byte limit")
        rows.append({"path_sha256": sha256(raw), "content_sha256": sha256(data)})
    return {"head": head, "worktree_sha256": sha256(canonical({"staged": sha256(staged), "files": rows}))}


def source_identities(root: Path, sources: list[str]) -> list[dict[str, Any]]:
    identities: list[dict[str, Any]] = []
    for raw in sources:
        relative = Path(raw)
        if relative.is_absolute() or ".." in relative.parts or "\\" in raw or "\x00" in raw:
            raise MemoryError("source escapes project root")
        candidate = root / relative
        current = root
        for part in relative.parts:
            current = current / part
            if os.path.islink(current):
                raise MemoryError("source contains a symlink")
        data, _info = source_read(candidate)
        if SECRET_RE.search(data):
            raise MemoryError("secret-bearing source refused")
        identities.append({"relative_path_sha256": sha256(os.fsencode(relative.as_posix())), "bytes": len(data), "sha256": sha256(data)})
    return identities


def signed(metadata: dict[str, Any], key: bytes) -> dict[str, Any]:
    result = dict(metadata)
    result["mac"] = hmac.new(key, canonical(metadata), hashlib.sha256).hexdigest()
    return result


def record_paths(store: Path, record_id: str) -> tuple[Path, Path]:
    return store / "records" / f"{record_id}.json", store / "records" / f"{record_id}.data"


def metadata_rows(store: Path) -> Iterator[tuple[Path, dict[str, Any]]]:
    for path in (store / "records").glob("*.json"):
        try:
            raw = secure_read(path, maximum=MAX_METADATA_BYTES, label="record metadata")
            value = json.loads(raw)
            if isinstance(value, dict):
                yield path, value
        except (MemoryError, json.JSONDecodeError, UnicodeDecodeError):
            continue


def remove_record(store: Path, record_id: str) -> None:
    meta, data = record_paths(store, record_id)
    for path in (meta, data):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def cleanup_records(store: Path, key: bytes, now: int) -> int:
    removed = 0
    records = store / "records"
    for temp in records.glob(".*.tmp"):
        try:
            temp.unlink()
            removed += 1
        except OSError:
            pass
    for path in list(records.glob("*.json")):
        record_id = path.stem
        try:
            raw = secure_read(path, maximum=MAX_METADATA_BYTES, label="record metadata")
            meta = json.loads(raw)
            mac = meta.pop("mac")
            valid = hmac.compare_digest(str(mac), hmac.new(key, canonical(meta), hashlib.sha256).hexdigest())
            expired = int(meta["expires_at"]) < now
            data_path = records / f"{record_id}.data"
            maximum = min(int(meta["quota"]["max_entry_bytes"]), MAX_EXACT_BYTES)
            content = secure_read(data_path, maximum=maximum, label="record content")
            digest_valid = meta["content"] == {"bytes": len(content), "sha256": sha256(content)}
            if not valid or expired or not digest_valid or SECRET_RE.search(content):
                raise MemoryError("invalid record")
        except Exception:
            remove_record(store, record_id)
            removed += 1
    for data_path in list(records.glob("*.data")):
        if not data_path.with_suffix(".json").exists():
            try:
                data_path.unlink()
                removed += 1
            except OSError:
                pass
    return removed


def put_command(args: argparse.Namespace, root: Path, store: Path) -> int:
    content = sys.stdin.buffer.read(args.max_entry_bytes + 1)
    if len(content) > args.max_entry_bytes:
        raise MemoryError("entry quota exceeded")
    if SECRET_RE.search(content):
        raise MemoryError("secret-bearing content refused")
    now = int(time.time())
    with locked_store(store):
        key = load_key(store)
        cleanup_records(store, key, now)
        sources = source_identities(root, args.source)
        project = project_identity(root)
        revision = revision_identity(root, store)
        task_sha = sha256(args.task.encode("utf-8"))
        nonce = secrets.token_bytes(16)
        record_id = hmac.new(key, nonce + canonical(project) + bytes.fromhex(task_sha), hashlib.sha256).hexdigest()[:32]
        metadata: dict[str, Any] = {
            "schema": SCHEMA, "record_id": record_id, "created_at": now,
            "expires_at": now + args.ttl_seconds, "last_accessed_at": now,
            "project": project, "revision": revision, "task_sha256": task_sha,
            "sources": sources, "content": {"bytes": len(content), "sha256": sha256(content)},
            "quota": {"max_entry_bytes": args.max_entry_bytes, "max_total_bytes": args.max_total_bytes, "max_entries": args.max_entries},
        }
        existing = sorted(metadata_rows(store), key=lambda item: int(item[1].get("last_accessed_at", 0)))
        total = sum(int(item[1].get("content", {}).get("bytes", 0)) for item in existing)
        while existing and (len(existing) >= args.max_entries or total + len(content) > args.max_total_bytes):
            old_path, old = existing.pop(0)
            total -= int(old.get("content", {}).get("bytes", 0))
            remove_record(store, old_path.stem)
        if len(existing) >= args.max_entries or total + len(content) > args.max_total_bytes:
            raise MemoryError("store quota exceeded")
        meta_path, data_path = record_paths(store, record_id)
        atomic_write(data_path.parent, data_path.name, content)
        try:
            atomic_write(meta_path.parent, meta_path.name, canonical(signed(metadata, key)))
        except Exception:
            data_path.unlink(missing_ok=True)
            raise
    receipt = {"schema": SCHEMA, "handle": f"contextguard-memory:{record_id}", "expires_at": metadata["expires_at"], "bytes": len(content), "reexpand_command": f"context-guard task-memory get contextguard-memory:{record_id} --task <task> --source <source> --max-bytes {min(len(content), MAX_EXACT_BYTES)}", "claim_boundary": "local provider-free memory; no token/cost savings guarantee"}
    print(json.dumps(receipt, sort_keys=True) if args.json else receipt["handle"])
    return 0


def get_command(args: argparse.Namespace, root: Path, store: Path) -> int:
    match = HANDLE_RE.fullmatch(args.handle)
    if not match:
        raise MemoryError("invalid public handle")
    record_id = match.group(1)
    now = int(time.time())
    with locked_store(store):
        key = load_key(store)
        meta_path, data_path = record_paths(store, record_id)
        raw_meta = secure_read(meta_path, maximum=MAX_METADATA_BYTES, label="record metadata")
        try:
            signed_meta = json.loads(raw_meta)
            mac = signed_meta.pop("mac")
        except (json.JSONDecodeError, KeyError, AttributeError) as exc:
            raise MemoryError("invalid record metadata") from exc
        expected = hmac.new(key, canonical(signed_meta), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(mac), expected):
            raise MemoryError("record authentication failed")
        if signed_meta.get("schema") != SCHEMA or signed_meta.get("record_id") != record_id:
            raise MemoryError("record schema mismatch")
        content_bytes = int(signed_meta["content"]["bytes"])
        if content_bytes > args.max_bytes or args.max_bytes > MAX_EXACT_BYTES:
            raise MemoryError("bounded recovery limit exceeded")
        content = secure_read(data_path, maximum=args.max_bytes, label="record content")
        valid = (
            int(signed_meta["expires_at"]) >= now
            and signed_meta["project"] == project_identity(root)
            and signed_meta["revision"] == revision_identity(root, store)
            and signed_meta["task_sha256"] == sha256(args.task.encode("utf-8"))
            and signed_meta["sources"] == source_identities(root, args.source)
            and signed_meta["content"] == {"bytes": len(content), "sha256": sha256(content)}
            and SECRET_RE.search(content) is None
        )
        if not valid:
            raise MemoryError("record binding invalidated")
    sys.stdout.buffer.write(content)
    return 0


def cleanup_command(args: argparse.Namespace, _root: Path, store: Path) -> int:
    now = int(time.time())
    with locked_store(store):
        removed = cleanup_records(store, load_key(store), now)
    result = {"schema": SCHEMA, "removed": removed}
    print(json.dumps(result, sort_keys=True) if args.json else f"removed={removed}")
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Revision-bound persistent task memory")
    result.add_argument("--root", default=".")
    result.add_argument("--store", default=DEFAULT_STORE)
    commands = result.add_subparsers(required=True)
    put = commands.add_parser("put")
    put.add_argument("--task", required=True)
    put.add_argument("--source", action="append", required=True)
    put.add_argument("--ttl-seconds", type=int, default=DEFAULT_TTL)
    put.add_argument("--max-entry-bytes", type=int, default=DEFAULT_MAX_ENTRY_BYTES)
    put.add_argument("--max-total-bytes", type=int, default=DEFAULT_MAX_TOTAL_BYTES)
    put.add_argument("--max-entries", type=int, default=DEFAULT_MAX_ENTRIES)
    put.add_argument("--json", action="store_true")
    put.set_defaults(func=put_command)
    get = commands.add_parser("get")
    get.add_argument("handle")
    get.add_argument("--task", required=True)
    get.add_argument("--source", action="append", required=True)
    get.add_argument("--max-bytes", type=int, required=True)
    get.set_defaults(func=get_command)
    cleanup = commands.add_parser("cleanup")
    cleanup.add_argument("--json", action="store_true")
    cleanup.set_defaults(func=cleanup_command)
    return result


def validate_args(args: argparse.Namespace) -> None:
    for name in ("ttl_seconds", "max_entry_bytes", "max_total_bytes", "max_entries", "max_bytes"):
        value = getattr(args, name, None)
        if value is not None and value <= 0:
            raise MemoryError(f"{name.replace('_', '-')} must be positive")
    if getattr(args, "ttl_seconds", 1) > 30 * 24 * 60 * 60:
        raise MemoryError("ttl exceeds maximum")
    if getattr(args, "max_entry_bytes", 1) > MAX_EXACT_BYTES:
        raise MemoryError("entry limit exceeds exact recovery maximum")
    if getattr(args, "max_total_bytes", 1) > DEFAULT_MAX_TOTAL_BYTES:
        raise MemoryError("total quota exceeds maximum")
    if getattr(args, "max_entries", 1) > DEFAULT_MAX_ENTRIES:
        raise MemoryError("entry count exceeds maximum")


def main() -> int:
    args = parser().parse_args()
    try:
        validate_args(args)
        root = resolve_root(args.root)
        store = resolve_store(root, args.store)
        return int(args.func(args, root, store))
    except (MemoryError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"context-guard-task-memory: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
