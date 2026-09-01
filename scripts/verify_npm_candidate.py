"""Verify one downloaded npm candidate artifact or its producing Actions run."""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
from typing import Any

from build_npm_candidates import (
    RECEIPT_NAME,
    ROOT_NAME,
    SHA256_RE,
    VERSION_RE,
    canonical_json,
)

MAX_CANDIDATE_BYTES = 50 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_CHECKSUM_BYTES = 8 * 1024
MAX_PACKAGE_JSON_BYTES = 512 * 1024
MAX_TAR_MEMBERS = 4096
MAX_TAR_DECLARED_BYTES = 128 * 1024 * 1024
MAX_TAR_STREAM_BYTES = 128 * 1024 * 1024
MAX_TAR_STREAM_READ_BYTES = 64 * 1024
MAX_RUN_METADATA_BYTES = 1024 * 1024
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
RUN_ID_RE = re.compile(r"[1-9][0-9]*")
SRI_RE = re.compile(r"sha512-[A-Za-z0-9+/]{86}==")
MANIFEST_KEYS = {
    "build_policy",
    "commit_sha",
    "exact_dependency",
    "packages",
    "policy_sha256",
    "receipt_package_files_sha256",
    "protocol",
    "repository",
    "schema_version",
    "tool_versions",
}
PACKAGE_KEYS = {"filename", "integrity", "name", "sha256", "size_bytes", "version"}


class CandidateVerificationError(RuntimeError):
    pass


def duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def parse_json(raw: bytes, subject: str) -> object:
    try:
        return json.loads(
            raw.decode("ascii"),
            object_pairs_hook=duplicate_keys,
            parse_float=lambda _value: (_ for _ in ()).throw(ValueError()),
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise CandidateVerificationError(f"{subject} is invalid") from None


def file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def read_bounded_regular(path: Path, maximum: int) -> bytes:
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
            or not 0 < before.st_size <= maximum
        ):
            raise CandidateVerificationError("candidate artifact contains an unsafe file")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            opened = os.fstat(descriptor)
            if file_identity(before) != file_identity(opened):
                raise CandidateVerificationError("candidate artifact changed before read")
            chunks: list[bytes] = []
            total = 0
            while total <= maximum:
                chunk = os.read(descriptor, min(65_536, maximum + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except CandidateVerificationError:
        raise
    except OSError as exc:
        raise CandidateVerificationError("candidate artifact is unreadable") from exc
    raw = b"".join(chunks)
    if (
        file_identity(opened) != file_identity(after)
        or len(raw) != opened.st_size
        or len(raw) > maximum
    ):
        raise CandidateVerificationError("candidate artifact changed during read")
    return raw


class BoundedDecompressedReader:
    def __init__(self, source: gzip.GzipFile, maximum: int) -> None:
        self.source = source
        self.maximum = maximum
        self.total = 0

    def read(self, size: int = -1) -> bytes:
        requested = MAX_TAR_STREAM_READ_BYTES if size < 0 else min(
            size, MAX_TAR_STREAM_READ_BYTES
        )
        if requested == 0:
            return b""
        remaining = self.maximum - self.total
        chunk = self.source.read(min(max(requested, 1), remaining + 1))
        if not isinstance(chunk, bytes):
            raise CandidateVerificationError("candidate decompressed stream is invalid")
        self.total += len(chunk)
        if self.total > self.maximum:
            raise CandidateVerificationError(
                "candidate tarball exceeds the decompressed stream limit"
            )
        return chunk


def package_document(tarball: bytes) -> dict[str, object]:
    package_json: bytes | None = None
    package_json_size: int | None = None
    member_count = 0
    declared_bytes = 0
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(tarball), mode="rb") as decompressed:
            bounded = BoundedDecompressedReader(decompressed, MAX_TAR_STREAM_BYTES)
            with tarfile.open(fileobj=bounded, mode="r|") as archive:
                for member in archive:
                    member_count += 1
                    if member_count > MAX_TAR_MEMBERS:
                        raise CandidateVerificationError(
                            "candidate tarball exceeds the member limit"
                        )
                    if member.size < 0:
                        raise CandidateVerificationError(
                            "candidate tarball member size is invalid"
                        )
                    declared_bytes += member.size
                    if declared_bytes > MAX_TAR_DECLARED_BYTES:
                        raise CandidateVerificationError(
                            "candidate tarball expands beyond the audit limit"
                        )
                    if member.name != "package/package.json":
                        continue
                    if package_json is not None or not member.isreg():
                        raise CandidateVerificationError(
                            "candidate package.json is ambiguous"
                        )
                    if not 0 < member.size <= MAX_PACKAGE_JSON_BYTES:
                        raise CandidateVerificationError(
                            "candidate package.json exceeds the audit limit"
                        )
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise CandidateVerificationError(
                            "candidate package.json is unreadable"
                        )
                    package_json = stream.read(MAX_PACKAGE_JSON_BYTES + 1)
                    package_json_size = member.size
    except CandidateVerificationError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise CandidateVerificationError("candidate tarball is invalid") from exc
    if package_json is None or len(package_json) != package_json_size:
        raise CandidateVerificationError(
            "candidate package.json is missing or truncated"
        )
    document = parse_json(package_json, "candidate package.json")
    if type(document) is not dict:
        raise CandidateVerificationError("candidate package.json is invalid")
    return document


def verify_run(raw: bytes, run_id: str, commit_sha: str) -> None:
    if RUN_ID_RE.fullmatch(run_id) is None or COMMIT_RE.fullmatch(commit_sha) is None:
        raise CandidateVerificationError("candidate run identity is invalid")
    payload = parse_json(raw, "candidate run metadata")
    if (
        type(payload) is not dict
        or payload.get("id") != int(run_id)
        or payload.get("event") != "workflow_dispatch"
        or payload.get("head_branch") != "main"
        or payload.get("head_sha") != commit_sha
        or payload.get("path") != ".github/workflows/npm-candidate.yml"
        or payload.get("status") != "completed"
        or payload.get("conclusion") != "success"
        or not isinstance(payload.get("repository"), dict)
        or payload["repository"].get("full_name") != "ictechgy/context-guard"
        or not isinstance(payload.get("head_repository"), dict)
        or payload["head_repository"].get("full_name") != "ictechgy/context-guard"
    ):
        raise CandidateVerificationError(
            "candidate run is not a successful main-branch candidate build"
        )


def verify_artifact(
    candidate_dir: Path,
    *,
    commit_sha: str,
    expected_package: str,
    expected_version: str,
    expected_sha256: str,
    expected_receipt_version: str,
) -> tuple[Path, str | None]:
    if (
        COMMIT_RE.fullmatch(commit_sha) is None
        or expected_package not in {RECEIPT_NAME, ROOT_NAME}
        or VERSION_RE.fullmatch(expected_version) is None
        or VERSION_RE.fullmatch(expected_receipt_version) is None
        or SHA256_RE.fullmatch(expected_sha256) is None
        or (expected_package == RECEIPT_NAME and expected_version != expected_receipt_version)
    ):
        raise CandidateVerificationError("expected candidate identity is invalid")
    try:
        directory = candidate_dir.resolve(strict=True)
        directory_metadata = candidate_dir.lstat()
        if candidate_dir.is_symlink() or not stat.S_ISDIR(directory_metadata.st_mode):
            raise CandidateVerificationError("candidate directory is unsafe")
        entries: list[Path] = []
        for entry in directory.iterdir():
            entries.append(entry)
            if len(entries) > 3:
                raise CandidateVerificationError(
                    "candidate artifact contains unexpected files"
                )
    except CandidateVerificationError:
        raise
    except OSError as exc:
        raise CandidateVerificationError("candidate artifact is unavailable") from exc
    metadata_names = {"candidate-manifest.json", "candidate-sha256sums.txt"}
    names = {entry.name for entry in entries}
    tarballs = [entry for entry in entries if entry.name not in metadata_names]
    if len(entries) != 3 or len(names) != 3 or len(tarballs) != 1:
        raise CandidateVerificationError("candidate artifact contains unexpected files")
    tarball_path = tarballs[0]
    if Path(tarball_path.name).name != tarball_path.name or not tarball_path.name.endswith(".tgz"):
        raise CandidateVerificationError("candidate filename is unsafe")

    manifest_raw = read_bounded_regular(
        directory / "candidate-manifest.json", MAX_MANIFEST_BYTES
    )
    checksum_raw = read_bounded_regular(
        directory / "candidate-sha256sums.txt", MAX_CHECKSUM_BYTES
    )
    tarball = read_bounded_regular(tarball_path, MAX_CANDIDATE_BYTES)
    manifest = parse_json(manifest_raw, "candidate manifest")
    if (
        type(manifest) is not dict
        or set(manifest) != MANIFEST_KEYS
        or manifest.get("schema_version") != "contextguard-npm-candidate-set/v1"
        or manifest.get("repository") != "ictechgy/context-guard"
        or manifest.get("commit_sha") != commit_sha
        or canonical_json(manifest).encode("ascii") != manifest_raw
    ):
        raise CandidateVerificationError("candidate manifest identity mismatch")
    packages = manifest.get("packages")
    if type(packages) is not list or len(packages) != 2:
        raise CandidateVerificationError("candidate package set is invalid")
    checksum_rows: list[str] = []
    matches: list[dict[str, object]] = []
    receipt_matches: list[dict[str, object]] = []
    for item in packages:
        if type(item) is not dict or set(item) != PACKAGE_KEYS:
            raise CandidateVerificationError("candidate package record is invalid")
        filename = item.get("filename")
        digest = item.get("sha256")
        if (
            not isinstance(filename, str)
            or Path(filename).name != filename
            or not isinstance(digest, str)
            or SHA256_RE.fullmatch(digest) is None
        ):
            raise CandidateVerificationError("candidate checksum record is invalid")
        checksum_rows.append(f"{digest}  {filename}\n")
        if item.get("name") == expected_package:
            matches.append(item)
        if item.get("name") == RECEIPT_NAME:
            receipt_matches.append(item)
    if checksum_raw != "".join(checksum_rows).encode("ascii"):
        raise CandidateVerificationError("candidate checksum document is invalid")
    if len(matches) != 1 or len(receipt_matches) != 1:
        raise CandidateVerificationError("candidate package record is missing or ambiguous")
    record = matches[0]
    declared_size = record.get("size_bytes")
    if (
        record.get("filename") != tarball_path.name
        or isinstance(declared_size, bool)
        or not isinstance(declared_size, int)
        or not 0 < declared_size <= MAX_CANDIDATE_BYTES
        or declared_size != len(tarball)
    ):
        raise CandidateVerificationError("candidate size binding mismatch")
    digest = hashlib.sha256(tarball).hexdigest()
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode("ascii")
    if (
        digest != expected_sha256
        or digest != record.get("sha256")
        or record.get("version") != expected_version
        or integrity != record.get("integrity")
        or SHA256_RE.fullmatch(str(manifest.get("receipt_package_files_sha256", ""))) is None
    ):
        raise CandidateVerificationError("candidate package binding mismatch")
    package = package_document(tarball)
    if package.get("name") != expected_package or package.get("version") != expected_version:
        raise CandidateVerificationError("candidate package identity mismatch")

    receipt_record = receipt_matches[0]
    receipt_integrity = receipt_record.get("integrity")
    if (
        receipt_record.get("version") != expected_receipt_version
        or not isinstance(receipt_integrity, str)
        or SRI_RE.fullmatch(receipt_integrity) is None
        or manifest.get("exact_dependency")
        != {"name": RECEIPT_NAME, "version": expected_receipt_version}
    ):
        raise CandidateVerificationError("candidate Receipt exact-asset binding mismatch")
    if expected_package == ROOT_NAME:
        dependencies = package.get("dependencies")
        if (
            type(dependencies) is not dict
            or dependencies.get(RECEIPT_NAME) != expected_receipt_version
        ):
            raise CandidateVerificationError(
                "candidate root package identity or exact dependency mismatch"
            )
    return tarball_path, receipt_integrity if expected_package == ROOT_NAME else None


def append_environment(path: Path, tarball: Path, receipt_integrity: str | None) -> None:
    if not path.is_absolute():
        raise CandidateVerificationError("GitHub environment path must be absolute")
    try:
        with path.open("a", encoding="utf-8") as output:
            output.write(f"CANDIDATE_TARBALL={tarball}\n")
            if receipt_integrity is not None:
                output.write(f"EXPECTED_RECEIPT_INTEGRITY={receipt_integrity}\n")
    except OSError as exc:
        raise CandidateVerificationError("GitHub environment is unavailable") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--run-id", required=True)
    run_parser.add_argument("--commit-sha", required=True)
    artifact_parser = subparsers.add_parser("artifact")
    artifact_parser.add_argument("--candidate-dir", type=Path, required=True)
    artifact_parser.add_argument("--commit-sha", required=True)
    artifact_parser.add_argument("--expected-package", required=True)
    artifact_parser.add_argument("--expected-version", required=True)
    artifact_parser.add_argument("--expected-sha256", required=True)
    artifact_parser.add_argument("--expected-receipt-version", required=True)
    artifact_parser.add_argument("--github-env", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "run":
            raw = sys.stdin.buffer.read(MAX_RUN_METADATA_BYTES + 1)
            if len(raw) > MAX_RUN_METADATA_BYTES:
                raise CandidateVerificationError("candidate run metadata exceeds the limit")
            verify_run(raw, args.run_id, args.commit_sha)
            print("npm candidate run verification: OK")
        else:
            tarball, receipt_integrity = verify_artifact(
                args.candidate_dir,
                commit_sha=args.commit_sha,
                expected_package=args.expected_package,
                expected_version=args.expected_version,
                expected_sha256=args.expected_sha256,
                expected_receipt_version=args.expected_receipt_version,
            )
            if args.github_env is not None:
                append_environment(args.github_env, tarball, receipt_integrity)
            print("npm candidate artifact verification: OK")
    except (CandidateVerificationError, OSError) as exc:
        raise SystemExit(str(exc)) from None
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
