"""Captured-byte and semantic identities for context-pack artifacts."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any


SHA256_RE = re.compile(r"[0-9a-f]{64}")
SEMANTIC_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")


@dataclass(frozen=True)
class ArtifactIdentity:
    captured_sha256: str
    semantic_sha256: str


def _digest(domain: bytes, value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(domain + encoded).hexdigest()


def artifact_identity(*, path: str, mode: str, size: int, sha256: str, semantic_output_sha256: str) -> ArtifactIdentity:
    parsed = PurePosixPath(path)
    if not path or parsed.is_absolute() or parsed.as_posix() != path or ".." in parsed.parts or "\\" in path or "\x00" in path:
        raise ValueError("artifact path must be safe and repository-relative")
    if mode not in {"0644", "0755"} or isinstance(size, bool) or size < 0:
        raise ValueError("artifact mode/size is invalid")
    if SHA256_RE.fullmatch(sha256) is None or SHA256_RE.fullmatch(semantic_output_sha256) is None:
        raise ValueError("artifact digest/semantic output is invalid")
    return ArtifactIdentity(
        captured_sha256=_digest(
            b"contextguard.context-pack-captured/v1\0",
            {"mode": mode, "path": path, "sha256": sha256, "size": size},
        ),
        semantic_sha256=_digest(
            b"contextguard.context-pack-semantic/v1\0",
            {"semantic_output_sha256": semantic_output_sha256},
        ),
    )


def _captured_file(root: Path, relative: str, semantic_output_sha256: str) -> dict[str, Any]:
    path = root / relative
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        if stat.S_ISLNK(current.lstat().st_mode):
            raise ValueError(f"identity artifact contains a symlink: {relative}")
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"identity artifact is not a regular file: {relative}")
    mode = f"{stat.S_IMODE(metadata.st_mode):04o}"
    if mode not in {"0644", "0755"} or metadata.st_size > 4 * 1024 * 1024:
        raise ValueError(f"identity artifact mode or size is unsafe: {relative}")
    raw = path.read_bytes()
    after = path.lstat()
    if (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError(f"identity artifact changed while reading: {relative}")
    digest = hashlib.sha256(raw).hexdigest()
    identity = artifact_identity(
        path=relative, mode=mode, size=len(raw), sha256=digest,
        semantic_output_sha256=semantic_output_sha256,
    )
    return {
        "captured_sha256": identity.captured_sha256,
        "mode": mode,
        "path": relative,
        "semantic_sha256": identity.semantic_sha256,
        "sha256": digest,
        "size": len(raw),
    }


def derive_manifest_identities(root: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    if set(manifest) != {"modules", "schema_version", "semantic_oracle_sha256"} or manifest.get("schema_version") != "contextguard.context-pack-modules/v1":
        raise ValueError("invalid context-pack module manifest")
    modules = manifest.get("modules")
    oracle = manifest.get("semantic_oracle_sha256")
    if not isinstance(oracle, str) or SHA256_RE.fullmatch(oracle) is None:
        raise ValueError("invalid context-pack semantic oracle")
    if not isinstance(modules, list) or not modules:
        raise ValueError("context-pack module manifest is empty")
    derived = []
    for entry in modules:
        if not isinstance(entry, dict) or set(entry) != {"canonical_path", "plugin_path", "role", "semantic_output"}:
            raise ValueError("invalid context-pack module entry")
        role = entry["role"]
        semantic = entry["semantic_output"]
        if (
            not isinstance(role, str)
            or SEMANTIC_NAME_RE.fullmatch(role) is None
            or not isinstance(semantic, str)
            or SEMANTIC_NAME_RE.fullmatch(semantic) is None
        ):
            raise ValueError("invalid context-pack semantic declaration")
        module_oracle = _digest(
            b"contextguard.context-pack-module-semantic/v1\0",
            {
                "oracle_sha256": oracle,
                "role": role,
                "semantic_output": semantic,
            },
        )
        derived.append({
            "role": role,
            "canonical": _captured_file(root, entry["canonical_path"], module_oracle),
            "plugin": _captured_file(root, entry["plugin_path"], module_oracle),
        })
    return derived
