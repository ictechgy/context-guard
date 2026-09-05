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
    ".claude-plugin/marketplace.json": "8f61b70bba4c1ea52c988b17db4348ccb81bee11b3ef46a8ea97ffb41ed04e59",
    "context-guard-kit/benchmark_runner.py": "716dc6710923401ca5a5ab171ca652bcf1fa0094fae567f6e7f6ee1eda24cf71",
    "context-guard-kit/context_pack.py": "6bc42070e4d3d0dea3e424388dbb02c352e2879bacf3788cb3df343f64cd5e75",
    "context-guard-kit/context_guard_commands.py": "0920128f013a8b5be62253fbf34aa917d2b30b7c6e99bc656067102d5fba727a",
    "context-guard-kit/guard_large_read.py": "81ddea324fdf927dc778b8d9466eb542f1941da40303a2ba4d16a6d68ab448e2",
    "context-guard-kit/setup_wizard.py": "c4352c4a19f4c9c30879898b6c762f03e799c4f2dc4ae5812393a7689686cde7",
    "package.json": "18811b92460edf141a379f325b989ca3559150b736191ae074056ef7a10fb3b5",
    "plugins/context-guard/.claude-plugin/plugin.json": "68d2bd26750767e6c22cc7076762223b6d324611433e957945f593bba7f9d016",
    "plugins/context-guard/bin/context-guard-bench": "716dc6710923401ca5a5ab171ca652bcf1fa0094fae567f6e7f6ee1eda24cf71",
    "plugins/context-guard/bin/context-guard-guard-read": "81ddea324fdf927dc778b8d9466eb542f1941da40303a2ba4d16a6d68ab448e2",
    "plugins/context-guard/bin/context-guard-pack": "6bc42070e4d3d0dea3e424388dbb02c352e2879bacf3788cb3df343f64cd5e75",
    "plugins/context-guard/bin/context-guard-setup": "c4352c4a19f4c9c30879898b6c762f03e799c4f2dc4ae5812393a7689686cde7",
    "plugins/context-guard/lib/context_guard_commands.py": "0920128f013a8b5be62253fbf34aa917d2b30b7c6e99bc656067102d5fba727a",
    "scripts/prepublish_check.py": "54a968be3a125cfa9fabac2a38f410120de61e470525423dee103a47d003317b",
    "scripts/release_smoke.py": "b18490bddd7d74e12a3405ceca22aaea0085dbbb688a21f143545796a9018102",
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
        observed_mode = portable_regular_mode(metadata.st_mode)
        if entry["mode"] != observed_mode:
            raise VerificationError(
                f"protected surface mode drifted: {path_text}\n"
                f"  expected: {entry['mode']}\n"
                f"  observed: {observed_mode}"
            )
        expected_sha256 = POST_STAGE2_PROTECTED_SHA256.get(path_text, entry["sha256"])
        observed_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        if expected_sha256 != observed_sha256:
            # 관측값과 핀 위치를 함께 알려 준다. 값을 자동으로 갱신하지는 않는다 —
            # 핀은 사람이 검토하라고 있는 것이고, 자동 갱신은 그 검토를 우회시킨다.
            # 다만 같은 다이제스트가 여러 파일에 박혀 있어, 어디를 봐야 하는지
            # 알려 주지 않으면 매번 저장소를 뒤져야 한다.
            # 관측값을 함께 낸다. 검토에 필요한 것은 "무엇이 어떻게 달라졌는가"
            # 이지 "어디를 고쳐라"가 아니다 — 후자를 적으면 빨간 테스트를 본
            # 자동화가 그대로 따라 하는 절차서가 된다. 이 저장소의 CI 출력은
            # 에이전트가 읽으며, 변조 상황이라면 그 절차는 변조된 바이트에 핀을
            # 맞추라는 지시가 된다. 갱신 위치는 정책 문서가 안내한다.
            raise VerificationError(
                f"protected surface hash drifted: {path_text}\n"
                f"  expected: {expected_sha256}\n"
                f"  observed: {observed_sha256}\n"
                "  this digest is pinned in more than one place and updating it "
                "requires human review; see docs/release-runbook.md"
            )
        observed_tracked = path_text in tracked
        if type(entry["tracked"]) is not bool or entry["tracked"] != observed_tracked:
            raise VerificationError(
                f"protected surface tracked status drifted: {path_text}\n"
                f"  expected: {entry['tracked']!r}\n"
                f"  observed: {observed_tracked!r}"
            )


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
