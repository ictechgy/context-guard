#!/usr/bin/env python3
"""Build each npm candidate once and bind the resulting tarballs in a manifest."""

from __future__ import annotations

import argparse
import ast
import base64
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import BinaryIO, Mapping


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "ictechgy/context-guard"
RECEIPT_NAME = "@ictechgy/context-guard-receipt"
ROOT_NAME = "@ictechgy/context-guard"
POLICY_MEMBER = "package/plugins/context-guard/bin/bash_reference_policy.py"
RECEIPT_INVENTORY_MEMBER = "package/package-files.json"
MAX_TARBALL_BYTES = 50 * 1024 * 1024
MAX_MEMBER_BYTES = 512 * 1024
MAX_TAR_MEMBERS = 4096
MAX_TAR_DECLARED_BYTES = 128 * 1024 * 1024
MAX_TAR_STREAM_BYTES = 128 * 1024 * 1024
MAX_TAR_STREAM_READ_BYTES = 64 * 1024
MAX_PROCESS_OUTPUT_BYTES = 128 * 1024
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
VERSION_RE = re.compile(
    r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?"
)


class CandidateBuildError(RuntimeError):
    """Raised when a candidate set cannot be proven closed and exact."""


class BoundedDecompressedReader:
    """Cap bytes consumed beneath tarfile, including hidden extension records."""

    def __init__(self, source: BinaryIO, maximum: int) -> None:
        self._source = source
        self._maximum = maximum
        self._total = 0

    def read(self, size: int = -1) -> bytes:
        requested = MAX_TAR_STREAM_READ_BYTES if size < 0 else min(
            size, MAX_TAR_STREAM_READ_BYTES,
        )
        if requested == 0:
            return b""
        remaining = self._maximum - self._total
        chunk = self._source.read(min(max(requested, 1), remaining + 1))
        if not isinstance(chunk, bytes):
            raise CandidateBuildError("candidate decompressed stream is invalid")
        self._total += len(chunk)
        if self._total > self._maximum:
            raise CandidateBuildError(
                "candidate package exceeds the decompressed stream limit"
            )
        return chunk


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"


def regular_tarball(path: Path) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CandidateBuildError("candidate tarball is unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 1:
        raise CandidateBuildError("candidate tarball must be a non-empty regular file")
    if metadata.st_size > MAX_TARBALL_BYTES:
        raise CandidateBuildError("candidate tarball exceeds the audit limit")
    return metadata


def sha256_file(path: Path) -> str:
    before = regular_tarball(path)
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise CandidateBuildError("candidate tarball is unreadable") from exc
    after = regular_tarball(path)
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise CandidateBuildError("candidate tarball changed during hashing")
    return digest.hexdigest()


def sha512_sri_file(path: Path) -> str:
    before = regular_tarball(path)
    digest = hashlib.sha512()
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise CandidateBuildError("candidate tarball is unreadable") from exc
    after = regular_tarball(path)
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise CandidateBuildError("candidate tarball changed during hashing")
    return "sha512-" + base64.b64encode(digest.digest()).decode("ascii")


def read_member(tarball: Path, member_name: str) -> bytes:
    regular_tarball(tarball)
    content: bytes | None = None
    content_size: int | None = None
    member_count = 0
    declared_bytes = 0
    try:
        with tarball.open("rb") as compressed:
            with gzip.GzipFile(fileobj=compressed, mode="rb") as decompressed:
                bounded = BoundedDecompressedReader(
                    decompressed, MAX_TAR_STREAM_BYTES,
                )
                with tarfile.open(fileobj=bounded, mode="r|") as archive:
                    for member in archive:
                        member_count += 1
                        if member_count > MAX_TAR_MEMBERS:
                            raise CandidateBuildError("candidate package exceeds the member limit")
                        if member.size < 0:
                            raise CandidateBuildError("candidate package member size is invalid")
                        declared_bytes += member.size
                        if declared_bytes > MAX_TAR_DECLARED_BYTES:
                            raise CandidateBuildError("candidate package expands beyond the audit limit")
                        if member.name != member_name:
                            continue
                        if content is not None or not member.isreg():
                            raise CandidateBuildError("candidate package member is missing or ambiguous")
                        if member.size < 1 or member.size > MAX_MEMBER_BYTES:
                            raise CandidateBuildError("candidate package member exceeds the audit limit")
                        stream = archive.extractfile(member)
                        if stream is None:
                            raise CandidateBuildError("candidate package member is unreadable")
                        content = stream.read(MAX_MEMBER_BYTES + 1)
                        content_size = member.size
    except (OSError, tarfile.TarError) as exc:
        raise CandidateBuildError("candidate tarball is invalid") from exc
    if content is None:
        raise CandidateBuildError("candidate package member is missing or ambiguous")
    if content_size is None or len(content) != content_size or len(content) > MAX_MEMBER_BYTES:
        raise CandidateBuildError("candidate package member changed during inspection")
    return content


def package_document(tarball: Path) -> dict[str, object]:
    try:
        document = json.loads(read_member(tarball, "package/package.json"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateBuildError("candidate package manifest is invalid") from exc
    if not isinstance(document, dict):
        raise CandidateBuildError("candidate package manifest is invalid")
    return document


def validate_receipt_inventory(tarball: Path, raw: bytes) -> str:
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateBuildError("Receipt package-files inventory is invalid") from exc
    if (
        not isinstance(document, dict)
        or set(document) != {"files", "schema_version"}
        or document.get("schema_version") != "contextguard-receipt-package-files/v1"
        or not isinstance(document.get("files"), list)
    ):
        raise CandidateBuildError("Receipt package-files inventory is invalid")
    entries: dict[str, str] = {}
    for entry in document["files"]:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"mode", "path", "sha256"}
            or entry.get("mode") not in {"0644", "0755"}
            or not isinstance(entry.get("path"), str)
            or not isinstance(entry.get("sha256"), str)
            or SHA256_RE.fullmatch(entry["sha256"]) is None
            or entry["path"] in entries
            or Path(entry["path"]).is_absolute()
            or ".." in Path(entry["path"]).parts
        ):
            raise CandidateBuildError("Receipt package-files inventory is invalid")
        entries[entry["path"]] = entry["sha256"]
    required = {
        "package.json",
        "bin/context-guard-receipt.cjs",
        "bin/launcher.cjs",
    }
    if not required <= entries.keys():
        raise CandidateBuildError("Receipt package-files inventory is incomplete")
    for relative in required:
        content = read_member(tarball, f"package/{relative}")
        if hashlib.sha256(content).hexdigest() != entries[relative]:
            raise CandidateBuildError("Receipt package-files inventory hash mismatch")
    return hashlib.sha256(raw).hexdigest()


def receipt_policy_pin(policy: bytes, version: str) -> str:
    try:
        module = ast.parse(policy.decode("utf-8"))
    except (SyntaxError, UnicodeDecodeError) as exc:
        raise CandidateBuildError("root Receipt package-files pin is invalid") from exc
    declarations: list[ast.expr] = []
    for statement in module.body:
        if (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.target.id == "EXPECTED_RECEIPT_PACKAGE_FILES_SHA256_BY_VERSION"
            and statement.value is not None
        ):
            declarations.append(statement.value)
        elif isinstance(statement, ast.Assign) and any(
            isinstance(target, ast.Name)
            and target.id == "EXPECTED_RECEIPT_PACKAGE_FILES_SHA256_BY_VERSION"
            for target in statement.targets
        ):
            declarations.append(statement.value)
    if len(declarations) != 1:
        raise CandidateBuildError("root Receipt package-files pin is invalid")
    value = declarations[0]
    if isinstance(value, ast.Call) and len(value.args) == 1 and not value.keywords:
        value = value.args[0]
    try:
        pins = ast.literal_eval(value)
    except (ValueError, SyntaxError) as exc:
        raise CandidateBuildError("root Receipt package-files pin is invalid") from exc
    pin = pins.get(version) if isinstance(pins, dict) else None
    if not isinstance(pin, str) or SHA256_RE.fullmatch(pin) is None:
        raise CandidateBuildError("root Receipt package-files pin is invalid")
    return pin


def package_record(tarball: Path, package: Mapping[str, object]) -> dict[str, object]:
    name = package.get("name")
    version = package.get("version")
    if name not in {RECEIPT_NAME, ROOT_NAME} or not isinstance(version, str) or VERSION_RE.fullmatch(version) is None:
        raise CandidateBuildError("candidate package identity is invalid")
    metadata = regular_tarball(tarball)
    return {
        "filename": tarball.name,
        "integrity": sha512_sri_file(tarball),
        "name": name,
        "sha256": sha256_file(tarball),
        "size_bytes": metadata.st_size,
        "version": version,
    }


def candidate_manifest(
    *,
    receipt_tarball: Path,
    root_tarball: Path,
    commit_sha: str,
    tool_versions: Mapping[str, str],
) -> dict[str, object]:
    if COMMIT_RE.fullmatch(commit_sha) is None:
        raise CandidateBuildError("candidate commit SHA is invalid")
    if set(tool_versions) < {"node", "npm", "python"} or any(
        not isinstance(value, str) or not value or len(value) > 128 or "\n" in value
        for value in tool_versions.values()
    ):
        raise CandidateBuildError("candidate tool versions are invalid")

    receipt_package = package_document(receipt_tarball)
    root_package = package_document(root_tarball)
    if receipt_package.get("name") != RECEIPT_NAME or root_package.get("name") != ROOT_NAME:
        raise CandidateBuildError("candidate package order or identity is invalid")
    receipt_version = receipt_package.get("version")
    dependencies = root_package.get("dependencies")
    if (
        not isinstance(receipt_version, str)
        or not isinstance(dependencies, dict)
        or dependencies.get(RECEIPT_NAME) != receipt_version
        or VERSION_RE.fullmatch(receipt_version) is None
    ):
        raise CandidateBuildError("root candidate must declare the exact Receipt dependency")

    policy = read_member(root_tarball, POLICY_MEMBER)
    receipt_inventory = read_member(receipt_tarball, RECEIPT_INVENTORY_MEMBER)
    receipt_inventory_sha256 = validate_receipt_inventory(
        receipt_tarball, receipt_inventory,
    )
    if receipt_policy_pin(policy, receipt_version) != receipt_inventory_sha256:
        raise CandidateBuildError("root Receipt package-files pin does not match candidate")
    packages = [
        package_record(receipt_tarball, receipt_package),
        package_record(root_tarball, root_package),
    ]
    if packages[0]["filename"] == packages[1]["filename"]:
        raise CandidateBuildError("candidate tarball filenames must be unique")
    return {
        "build_policy": {
            "ignore_scripts": True,
            "lockfiles": [],
            "network": "offline",
            "package_build_count": 1,
        },
        "commit_sha": commit_sha,
        "exact_dependency": {"name": RECEIPT_NAME, "version": receipt_version},
        "packages": packages,
        "policy_sha256": hashlib.sha256(policy).hexdigest(),
        "receipt_package_files_sha256": receipt_inventory_sha256,
        "protocol": {"maximum": 1, "minimum": 1, "name": "bash_reference_v1"},
        "repository": REPOSITORY,
        "schema_version": "contextguard-npm-candidate-set/v1",
        "tool_versions": dict(sorted(tool_versions.items())),
    }


def checksum_document(manifest: Mapping[str, object]) -> str:
    packages = manifest.get("packages")
    if not isinstance(packages, list) or len(packages) != 2:
        raise CandidateBuildError("candidate manifest package set is invalid")
    rows: list[str] = []
    seen: set[str] = set()
    for package in packages:
        if not isinstance(package, dict):
            raise CandidateBuildError("candidate manifest package record is invalid")
        filename = package.get("filename")
        digest = package.get("sha256")
        if (
            not isinstance(filename, str)
            or Path(filename).name != filename
            or filename in seen
            or not isinstance(digest, str)
            or SHA256_RE.fullmatch(digest) is None
        ):
            raise CandidateBuildError("candidate checksum record is invalid")
        seen.add(filename)
        rows.append(f"{digest}  {filename}\n")
    return "".join(rows)


def bounded_run(command: list[str], *, cwd: Path, environment: Mapping[str, str]) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CandidateBuildError("offline npm pack could not complete") from exc
    if len(result.stdout) > MAX_PROCESS_OUTPUT_BYTES or len(result.stderr) > MAX_PROCESS_OUTPUT_BYTES:
        raise CandidateBuildError("offline npm pack output exceeds the audit limit")
    if result.returncode != 0:
        raise CandidateBuildError("offline npm pack failed")
    return result


def pack_one(*, npm: str, package_root: Path, output_dir: Path, environment: Mapping[str, str]) -> Path:
    before = set(output_dir.iterdir())
    result = bounded_run(
        [
            npm,
            "pack",
            "--json",
            "--offline",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            "--pack-destination",
            str(output_dir),
            str(package_root),
        ],
        cwd=ROOT,
        environment=environment,
    )
    try:
        records = json.loads(result.stdout)
        filename = records[0]["filename"]
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise CandidateBuildError("offline npm pack response is invalid") from exc
    if not isinstance(records, list) or len(records) != 1 or not isinstance(filename, str) or Path(filename).name != filename:
        raise CandidateBuildError("offline npm pack response is invalid")
    tarball = output_dir / filename
    if set(output_dir.iterdir()) - before != {tarball}:
        raise CandidateBuildError("offline npm pack produced an unexpected artifact set")
    regular_tarball(tarball)
    return tarball


def write_exclusive(path: Path, content: str) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o644,
        )
        payload = content.encode("ascii")
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short candidate metadata write")
            offset += written
        os.fsync(descriptor)
    except OSError as exc:
        raise CandidateBuildError("candidate metadata could not be written") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def command_version(command: list[str], *, environment: Mapping[str, str]) -> str:
    result = bounded_run(command, cwd=ROOT, environment=environment)
    value = result.stdout.strip()
    if not value or len(value) > 128 or "\n" in value:
        raise CandidateBuildError("candidate tool version is invalid")
    return value


def build(*, output_dir: Path, commit_sha: str) -> dict[str, object]:
    if not output_dir.is_absolute():
        raise CandidateBuildError("candidate output directory must be absolute")
    if output_dir.exists():
        if not output_dir.is_dir() or output_dir.is_symlink() or any(output_dir.iterdir()):
            raise CandidateBuildError("candidate output directory must be empty")
    else:
        output_dir.mkdir(mode=0o700, parents=True)
    npm = shutil.which("npm")
    node = shutil.which("node")
    git = shutil.which("git")
    if npm is None or node is None or git is None:
        raise CandidateBuildError("npm, node, and git are required")

    with tempfile.TemporaryDirectory(prefix="context-guard-npm-cache-") as cache_directory:
        isolated_config_root = Path(cache_directory)
        environment = dict(os.environ)
        environment.update(
            {
                "NPM_CONFIG_AUDIT": "false",
                "NPM_CONFIG_CACHE": cache_directory,
                "NPM_CONFIG_FUND": "false",
                "NPM_CONFIG_GLOBALCONFIG": str(isolated_config_root / "global.npmrc"),
                "NPM_CONFIG_IGNORE_SCRIPTS": "true",
                "NPM_CONFIG_OFFLINE": "true",
                "NPM_CONFIG_REGISTRY": "https://registry.invalid/",
                "NPM_CONFIG_UPDATE_NOTIFIER": "false",
                "NPM_CONFIG_USERCONFIG": str(isolated_config_root / "user.npmrc"),
            }
        )
        receipt_tarball = pack_one(
            npm=npm,
            package_root=ROOT / "packages" / "context-guard-receipt",
            output_dir=output_dir,
            environment=environment,
        )
        root_tarball = pack_one(
            npm=npm,
            package_root=ROOT,
            output_dir=output_dir,
            environment=environment,
        )
        tool_versions = {
            "git": command_version([git, "--version"], environment=environment),
            "node": command_version([node, "--version"], environment=environment),
            "npm": command_version([npm, "--version"], environment=environment),
            "python": sys.version.split()[0],
        }

    manifest = candidate_manifest(
        receipt_tarball=receipt_tarball,
        root_tarball=root_tarball,
        commit_sha=commit_sha,
        tool_versions=tool_versions,
    )
    write_exclusive(output_dir / "candidate-manifest.json", canonical_json(manifest))
    write_exclusive(output_dir / "candidate-sha256sums.txt", checksum_document(manifest))
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--commit-sha", required=True)
    arguments = parser.parse_args(argv)
    try:
        manifest = build(output_dir=arguments.output_dir, commit_sha=arguments.commit_sha)
    except CandidateBuildError as exc:
        print(f"candidate build failed: {exc}", file=sys.stderr)
        return 1
    print(canonical_json({"packages": manifest["packages"], "status": "ok"}), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
