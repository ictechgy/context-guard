"""Verify Stage 2 protected surfaces without provider or installed-settings access."""

from __future__ import annotations

import hashlib
import json
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath


REPO_ROOT = Path(__file__).resolve().parents[3]
MANIFEST_PATH = REPO_ROOT / "research/contextguard-stage2/protected-surface-manifest.json"
STAGE2_ARTIFACTS = (
    (
        "research/contextguard-stage2/S3D-ARF-charter.json",
        "f4a40efd4b526c15a44de97a2619d39c1a2db748704806fe0e0f6e882ced5a43",
    ),
    (
        "research/contextguard-stage2/host-observability.json",
        "2f4d795ddb875680c66dc8a578b07006016f0c1ba604d15cc386d3963830660e",
    ),
    (
        "research/contextguard-stage2/protected-surface-manifest.json",
        "dbbc1c558b2cad8fe6c48bff553d830cd87ffc7cb1f9e8fae2c2de5c7036af09",
    ),
    (
        "research/contextguard-stage2/verification-record.json",
        "3c7e5c5a2b205b1f34e7356d861cc3c1cb59cf85bb3ca30fe8c9cbbe30062006",
    ),
    (
        "research/contextguard-stage2/verification-record.schema.json",
        "856a2e1d20994207c38993c866f5df310b664a5d884929bec2b8aa381236b539",
    ),
)
MANIFEST_RELATIVE_PATH = "research/contextguard-stage2/protected-surface-manifest.json"
EXPECTED_MANIFEST_SCHEMA_VERSION = "contextguard-stage2-protected-surfaces/v1"
EXPECTED_MANIFEST_ENTRY_COUNT = 54
EXPECTED_MANIFEST_PATH_SET_SHA256 = (
    "5dc5c5a0fea271d7e757ea371ce71f79f1c896724378270fa2b3c4dee380977d"
)
MANIFEST_KEYS = {"entries", "invariants", "schema_version"}
PORTABLE_REGULAR_MODES = {
    0o600: "0644",
    0o640: "0644",
    0o644: "0644",
    0o700: "0755",
    0o750: "0755",
    0o755: "0755",
}
SEMANTIC_RECORD_EXPECTATIONS = {
    "research/contextguard-stage2/host-observability.json": {
        "selected_branch": "S2-UNSUPPORTED",
        "selected_transport": "NONE",
        "claim_allowed": False,
        "runtime_observer_authorized": False,
        "provider_join_status": "missing",
    },
    "research/contextguard-stage2/verification-record.json": {
        "selected_branch": "S2-UNSUPPORTED",
        "selected_transport": "NONE",
        "claim_allowed": False,
        "runtime_observer_present": False,
        "provider_join_status": "missing",
    },
}
ENTRY_KEYS = {"file_type", "mode", "path", "sha256", "tracked"}
POST_STAGE2_PROTECTED_SHA256 = {
    ".claude-plugin/marketplace.json": "b156a2430e651d25ea9c5471a4d3f347fc4beba8e6689bf566d6b253ed4b0706",
    "context-guard-kit/benchmark_runner.py": "57360aa6739c9109ccf54dce094bb9c9f11835df698d68b52ab5b0ea1d1aa8f0",
    "context-guard-kit/context_guard_commands.py": "4fd1e83394787523eb1f3d946bf053c5b5a0fdd0b360be0d20839851edc21d70",
    "context-guard-kit/setup_wizard.py": "bdaef7692a9a1ecc021c67f99b371f14edd52190fce2be2f57c4e240bdd1aaa8",
    "package.json": "d9c9d0911384785bbaa90f64308f01f1c036671d5ce6d14eaba20b2070d987ef",
    "plugins/context-guard/.claude-plugin/plugin.json": "8490efa682eac87a7d6ed74e38bf80a8973dcdabc1beb6efc41ec7ec49c01619",
    "plugins/context-guard/bin/context-guard-bench": "57360aa6739c9109ccf54dce094bb9c9f11835df698d68b52ab5b0ea1d1aa8f0",
    "plugins/context-guard/bin/context-guard-setup": "bdaef7692a9a1ecc021c67f99b371f14edd52190fce2be2f57c4e240bdd1aaa8",
    "plugins/context-guard/lib/context_guard_commands.py": "4fd1e83394787523eb1f3d946bf053c5b5a0fdd0b360be0d20839851edc21d70",
    "scripts/release_smoke.py": "f575a301a3863b918cdbcd70d5fad5da9ab674358b7f5f82054512a30216ee6c",
}


class VerificationError(Exception):
    """Raised when a protected surface no longer matches its frozen manifest."""


def portable_regular_mode(mode: int) -> str:
    permission_bits = stat.S_IMODE(mode)
    if permission_bits & 0o022:
        raise VerificationError("protected file has unsafe writable permission bits")
    try:
        return PORTABLE_REGULAR_MODES[permission_bits]
    except KeyError as exc:
        raise VerificationError("protected file has unsupported permission bits") from exc


def normalized_repository_path(path_text: object) -> PurePosixPath:
    if not isinstance(path_text, str):
        raise VerificationError("manifest path must be a string")
    path = PurePosixPath(path_text)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != path_text:
        raise VerificationError("manifest path must be normalized and repository-relative")
    return path


def tracked_paths(paths: list[str], repo_root: Path = REPO_ROOT) -> set[str]:
    result = subprocess.run(
        ["git", "ls-files", "--", *paths],
        cwd=repo_root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return set(result.stdout.splitlines())


def validate_protected_manifest_shape(manifest: object) -> None:
    if not isinstance(manifest, dict) or set(manifest) != MANIFEST_KEYS:
        raise VerificationError("protected-surface manifest root shape drifted")
    if manifest["schema_version"] != EXPECTED_MANIFEST_SCHEMA_VERSION:
        raise VerificationError("protected-surface manifest schema drifted")
    entries = manifest["entries"]
    if not isinstance(entries, list) or len(entries) != EXPECTED_MANIFEST_ENTRY_COUNT:
        raise VerificationError("protected-surface manifest entry count drifted")
    entry_paths = [
        normalized_repository_path(entry.get("path") if isinstance(entry, dict) else None).as_posix()
        for entry in entries
    ]
    if entry_paths != sorted(entry_paths) or len(set(entry_paths)) != len(entry_paths):
        raise VerificationError("protected-surface manifest paths are not a sorted set")
    encoded_paths = json.dumps(
        entry_paths, ensure_ascii=True, separators=(",", ":")
    ).encode()
    if hashlib.sha256(encoded_paths).hexdigest() != EXPECTED_MANIFEST_PATH_SET_SHA256:
        raise VerificationError("protected-surface manifest path set drifted")


def verify_stage2_artifact_integrity(repo_root: Path = REPO_ROOT) -> dict:
    raw_artifacts: dict[str, bytes] = {}
    for relative_path, expected_sha256 in STAGE2_ARTIFACTS:
        artifact_path = repo_root / relative_path
        try:
            metadata = artifact_path.lstat()
            raw = artifact_path.read_bytes()
        except OSError as exc:
            raise VerificationError("Stage 2 protected artifact is unavailable") from exc
        if not stat.S_ISREG(metadata.st_mode):
            raise VerificationError("Stage 2 protected artifact type drifted")
        if hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise VerificationError("Stage 2 protected artifact hash drifted")
        raw_artifacts[relative_path] = raw
    try:
        manifest = json.loads(raw_artifacts[MANIFEST_RELATIVE_PATH])
    except json.JSONDecodeError as exc:
        raise VerificationError("protected-surface manifest is invalid JSON") from exc
    canonical = json.dumps(
        manifest, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode() + b"\n"
    if raw_artifacts[MANIFEST_RELATIVE_PATH] != canonical:
        raise VerificationError("protected-surface manifest is not canonical")
    validate_protected_manifest_shape(manifest)
    return manifest


def verify_manifest_entries(manifest: object, repo_root: Path = REPO_ROOT) -> None:
    if not isinstance(manifest, dict) or not isinstance(manifest.get("entries"), list):
        raise VerificationError("protected-surface manifest has no entries list")
    entries = manifest["entries"]
    paths = [normalized_repository_path(entry.get("path") if isinstance(entry, dict) else None).as_posix() for entry in entries]
    tracked = tracked_paths(paths, repo_root)
    for entry, path_text in zip(entries, paths, strict=True):
        if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
            raise VerificationError("protected-surface manifest entry shape drifted")
        if entry["file_type"] != "regular":
            raise VerificationError(f"protected surface is not a regular file: {path_text}")
        path = repo_root / path_text
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise VerificationError(f"protected surface is unavailable: {path_text}") from exc
        if not stat.S_ISREG(metadata.st_mode):
            raise VerificationError(f"protected surface type drifted: {path_text}")
        if entry["mode"] != portable_regular_mode(metadata.st_mode):
            raise VerificationError(f"protected surface mode drifted: {path_text}")
        expected_sha256 = POST_STAGE2_PROTECTED_SHA256.get(path_text, entry["sha256"])
        if expected_sha256 != hashlib.sha256(path.read_bytes()).hexdigest():
            raise VerificationError(f"protected surface hash drifted: {path_text}")
        if type(entry["tracked"]) is not bool or entry["tracked"] != (path_text in tracked):
            raise VerificationError(f"protected surface tracked status drifted: {path_text}")


def verify_unsupported_semantics(repo_root: Path = REPO_ROOT) -> None:
    for relative_path, expectations in SEMANTIC_RECORD_EXPECTATIONS.items():
        record_path = repo_root / relative_path
        try:
            record = json.loads(record_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise VerificationError("Stage 2 semantic record is unreadable") from exc
        if not isinstance(record, dict):
            raise VerificationError("Stage 2 semantic record must be an object")
        if any(record.get(field) != expected for field, expected in expectations.items()):
            raise VerificationError("Stage 2 unsupported semantics drifted")


def main() -> int:
    try:
        manifest = verify_stage2_artifact_integrity()
        verify_manifest_entries(manifest)
        verify_unsupported_semantics()
    except (OSError, json.JSONDecodeError, subprocess.CalledProcessError, VerificationError) as exc:
        print(f"protected-surface verification failed: {exc}", file=sys.stderr)
        return 1
    print("protected surfaces verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
