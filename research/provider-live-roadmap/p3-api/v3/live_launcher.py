#!/usr/bin/env python3
"""Explicit production launcher for the pinned v3 live gate.

Nothing is read and no network-capable function is called unless ``--execute``
is present. Approval and signing material are read only from explicit
owner-only files; the API key is fetched from the fixed owner Keychain service
and is never printed.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys


V3 = Path(__file__).resolve().parent
EXPECTED_RUNNER_SHA256 = "3dc212a7ee763628fe2b554502a457e702d25509ddb50b8431982368945372a9"
EXPECTED_CONTRACT_SHA256 = "0bd1bc740079ad71851044860f12e0586c15ba968f85ec0926793e488d3a6168"
EXPECTED_CORE_COMMIT = "2fb00e4eb3e175eb6d716c67848d48ebac8588ad"
RUNNER_RELATIVE_PATH = "research/provider-live-roadmap/p3-api/v3/live_runner.py"
CONTRACT_RELATIVE_PATH = "research/provider-live-roadmap/p3-api/v3/live-contract.json"
MAX_BOUND_ARTIFACT_BYTES = 4 * 1024 * 1024
MAX_PRIVATE_INPUT_BYTES = 1024 * 1024


def _read_descriptor(path: Path, *, maximum_bytes: int, owner_private: bool) -> bytes:
    if not path.is_absolute():
        raise RuntimeError("private input unavailable" if owner_private else "bound core unavailable")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise RuntimeError("private input unavailable" if owner_private else "bound core unavailable") from None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > maximum_bytes
            or (
                owner_private
                and (
                    metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                )
            )
        ):
            raise RuntimeError("private input unavailable" if owner_private else "bound core unavailable")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > maximum_bytes:
            raise RuntimeError("private input unavailable" if owner_private else "bound core unavailable")
        return raw
    finally:
        os.close(descriptor)


def _read_bound(path: Path, expected_sha256: str) -> bytes:
    raw = _read_descriptor(
        path, maximum_bytes=MAX_BOUND_ARTIFACT_BYTES, owner_private=False
    )
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise RuntimeError("bound core unavailable")
    return raw


def _load_runner():
    path = V3 / "live_runner.py"
    raw = _read_bound(path, EXPECTED_RUNNER_SHA256)
    spec = importlib.util.spec_from_file_location("contextguard_v3_live_runner", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("runner unavailable")
    module = importlib.util.module_from_spec(spec)
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__, module.__dict__)
    return module


def _git(repo_root: Path, *arguments: str) -> bytes:
    environment = {
        "GIT_ASKPASS": "/usr/bin/false",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_SSH_COMMAND": "/usr/bin/false",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "SSH_ASKPASS": "/usr/bin/false",
    }
    try:
        completed = subprocess.run(
            ["/usr/bin/git", "-C", str(repo_root), *arguments],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("bound core unavailable") from None
    if completed.returncode:
        raise RuntimeError("bound core unavailable")
    return completed.stdout


def _verify_blob_triple(
    core_raw: bytes, head_raw: bytes, working_raw: bytes, expected_sha256: str
) -> None:
    if not all(isinstance(value, bytes) for value in (core_raw, head_raw, working_raw)):
        raise RuntimeError("bound core unavailable")
    if not (core_raw == head_raw == working_raw):
        raise RuntimeError("bound core unavailable")
    if hashlib.sha256(core_raw).hexdigest() != expected_sha256:
        raise RuntimeError("bound core unavailable")


def _verify_core_commit(repo_root: Path) -> None:
    if not repo_root.is_absolute() or repo_root.is_symlink():
        raise RuntimeError("bound core unavailable")
    try:
        resolved_root = repo_root.resolve(strict=True)
        expected_root = V3.parents[3].resolve(strict=True)
    except OSError:
        raise RuntimeError("bound core unavailable") from None
    if resolved_root != expected_root:
        raise RuntimeError("bound core unavailable")
    top_level = _git(resolved_root, "rev-parse", "--show-toplevel")
    try:
        reported_root = Path(top_level.decode("utf-8").strip()).resolve(strict=True)
    except (OSError, UnicodeError):
        raise RuntimeError("bound core unavailable") from None
    if reported_root != resolved_root:
        raise RuntimeError("bound core unavailable")
    _git(resolved_root, "merge-base", "--is-ancestor", EXPECTED_CORE_COMMIT, "HEAD")
    for relative_path, expected_sha256 in (
        (RUNNER_RELATIVE_PATH, EXPECTED_RUNNER_SHA256),
        (CONTRACT_RELATIVE_PATH, EXPECTED_CONTRACT_SHA256),
    ):
        working_path = resolved_root / relative_path
        _verify_blob_triple(
            _git(resolved_root, "show", f"{EXPECTED_CORE_COMMIT}:{relative_path}"),
            _git(resolved_root, "show", f"HEAD:{relative_path}"),
            _read_bound(working_path, expected_sha256),
            expected_sha256,
        )


def _read_owner_file(path: Path) -> bytes:
    return _read_descriptor(
        path, maximum_bytes=MAX_PRIVATE_INPUT_BYTES, owner_private=True
    )


def _read_keychain_secret() -> bytes:
    try:
        completed = subprocess.run(
            [
                "/usr/bin/security", "find-generic-password", "-s",
                "contextguard-anthropic-p3", "-w",
            ],
            env={"PATH": "/usr/bin:/bin"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("credential unavailable")
    if completed.returncode or len(completed.stdout) > 1024:
        raise RuntimeError("credential unavailable")
    value = completed.stdout[:-1] if completed.stdout.endswith(b"\n") else completed.stdout
    if not value or any(byte <= 0x20 or byte >= 0x7F for byte in value):
        raise RuntimeError("credential unavailable")
    if not value.startswith(b"sk-ant-api"):
        raise RuntimeError("credential unavailable")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--contract", type=Path)
    parser.add_argument("--repo-root", type=Path)
    parser.add_argument("--corpus-root", type=Path)
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--state-root", type=Path)
    parser.add_argument("--previous-output-root", type=Path)
    parser.add_argument("--previous-state-root", type=Path)
    parser.add_argument("--approval-1", type=Path)
    parser.add_argument("--approval-2", type=Path)
    parser.add_argument("--verification-key-file", type=Path)
    parser.add_argument("--registry-key-file", type=Path)
    args = parser.parse_args(argv)
    if not args.execute:
        print("explicit --execute is required; no live inputs were read", file=sys.stderr)
        return 2
    required = (
        args.contract, args.repo_root, args.corpus_root, args.output_root,
        args.state_root, args.previous_output_root, args.previous_state_root,
        args.approval_1, args.approval_2,
        args.verification_key_file, args.registry_key_file,
    )
    if any(value is None for value in required):
        print("explicit live input paths are required", file=sys.stderr)
        return 2
    try:
        runner = _load_runner()
        _verify_core_commit(args.repo_root)
        contract_path = V3 / "live-contract.json"
        _read_bound(contract_path, EXPECTED_CONTRACT_SHA256)
        if args.contract.resolve() != contract_path.resolve():
            raise RuntimeError("bound core unavailable")
        approvals = [
            runner.parse_json(_read_owner_file(args.approval_1), "approval"),
            runner.parse_json(_read_owner_file(args.approval_2), "approval"),
        ]
        verification_key = _read_owner_file(args.verification_key_file)
        registry_key = _read_owner_file(args.registry_key_file)
        api_key = _read_keychain_secret()
        runner.run_live_authorized(
            contract_path=contract_path,
            repo_root=args.repo_root,
            corpus_root=args.corpus_root,
            output_root=args.output_root,
            state_root=args.state_root,
            previous_output_root=args.previous_output_root,
            previous_state_root=args.previous_state_root,
            approvals=approvals,
            verification_key=verification_key,
            registry_key=registry_key,
            api_key=api_key,
        )
    except Exception:
        print("live execution refused", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
