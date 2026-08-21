#!/usr/bin/env python3
"""Verify the closed build-once asset set used by GitHub Release."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from build_npm_candidates import (
    RECEIPT_NAME,
    ROOT_NAME,
    SHA256_RE,
    VERSION_RE,
    canonical_json,
    checksum_document,
    sha256_file,
    sha512_sri_file,
)


MAX_MANIFEST_BYTES = 256 * 1024
MAX_CHECKSUM_BYTES = 8 * 1024
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
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
PACKAGE_KEYS = {
    "filename",
    "integrity",
    "name",
    "sha256",
    "size_bytes",
    "version",
}


class ReleaseAssetError(RuntimeError):
    pass


def duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def read_regular(path: Path, maximum: int) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise ReleaseAssetError("release metadata is unavailable") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 1
        or before.st_size > maximum
    ):
        raise ReleaseAssetError("release metadata is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        raw = os.read(descriptor, maximum + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        len(raw) > maximum
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    ):
        raise ReleaseAssetError("release metadata changed while reading")
    return raw


def verify(assets: Path, commit_sha: str) -> None:
    try:
        directory = assets.resolve(strict=True)
        metadata = assets.lstat()
    except OSError as exc:
        raise ReleaseAssetError("release asset directory is unavailable") from exc
    if assets.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseAssetError("release asset directory is unsafe")
    manifest_path = directory / "candidate-manifest.json"
    checksum_path = directory / "candidate-sha256sums.txt"
    manifest_raw = read_regular(manifest_path, MAX_MANIFEST_BYTES)
    try:
        manifest = json.loads(
            manifest_raw.decode("ascii"),
            object_pairs_hook=duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ReleaseAssetError("candidate manifest is invalid") from None
    if (
        type(manifest) is not dict
        or set(manifest) != MANIFEST_KEYS
        or manifest.get("schema_version") != "contextguard-npm-candidate-set/v1"
        or manifest.get("repository") != "ictechgy/context-guard"
        or manifest.get("commit_sha") != commit_sha
        or canonical_json(manifest).encode("ascii") != manifest_raw
    ):
        raise ReleaseAssetError("candidate manifest identity is invalid")
    packages = manifest.get("packages")
    if type(packages) is not list or len(packages) != 2:
        raise ReleaseAssetError("candidate manifest must contain exactly two packages")
    expected_names = {RECEIPT_NAME, ROOT_NAME}
    package_names: set[str] = set()
    filenames: set[str] = set()
    receipt_version: str | None = None
    for package in packages:
        if type(package) is not dict or set(package) != PACKAGE_KEYS:
            raise ReleaseAssetError("candidate package record is invalid")
        name = package.get("name")
        filename = package.get("filename")
        version = package.get("version")
        digest = package.get("sha256")
        size = package.get("size_bytes")
        integrity = package.get("integrity")
        if (
            name not in expected_names
            or name in package_names
            or not isinstance(filename, str)
            or Path(filename).name != filename
            or filename in filenames
            or not isinstance(version, str)
            or VERSION_RE.fullmatch(version) is None
            or not isinstance(digest, str)
            or SHA256_RE.fullmatch(digest) is None
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 1
            or not isinstance(integrity, str)
        ):
            raise ReleaseAssetError("candidate package identity is invalid")
        tarball = directory / filename
        if tarball.stat().st_size != size or sha256_file(tarball) != digest:
            raise ReleaseAssetError("candidate package digest is invalid")
        if sha512_sri_file(tarball) != integrity:
            raise ReleaseAssetError("candidate package integrity is invalid")
        package_names.add(name)
        filenames.add(filename)
        if name == RECEIPT_NAME:
            receipt_version = version
    if package_names != expected_names:
        raise ReleaseAssetError("candidate package set is incomplete")
    if manifest.get("exact_dependency") != {
        "name": RECEIPT_NAME,
        "version": receipt_version,
    }:
        raise ReleaseAssetError("candidate dependency binding is invalid")
    expected_files = {
        "candidate-manifest.json",
        "candidate-sha256sums.txt",
        *filenames,
    }
    actual_files = {path.name for path in directory.iterdir()}
    if actual_files != expected_files or any(path.is_symlink() for path in directory.iterdir()):
        raise ReleaseAssetError("release asset file set is not closed")
    checksum_raw = read_regular(checksum_path, MAX_CHECKSUM_BYTES)
    if checksum_raw != checksum_document(manifest).encode("ascii"):
        raise ReleaseAssetError("candidate checksum document is invalid")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assets-dir", type=Path, required=True)
    parser.add_argument("--commit-sha", required=True)
    args = parser.parse_args()
    if COMMIT_RE.fullmatch(args.commit_sha) is None:
        raise SystemExit("commit SHA must be 40 lowercase hexadecimal characters")
    try:
        verify(args.assets_dir, args.commit_sha)
    except (OSError, ReleaseAssetError) as exc:
        raise SystemExit(str(exc)) from None
    print("release asset verification: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
