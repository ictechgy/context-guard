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
EXPECTED_RUNNER_SHA256 = "984608ff631d3c8f095a5471d0e52d3e040fc1c91ee12499467ff855057897f4"
EXPECTED_CONTRACT_SHA256 = "c5da4a227f8b5e0388bd2e86427e4d93b9659535550c7dba5d1dcf96950125ec"


def _read_bound(path: Path, expected_sha256: str) -> bytes:
    if not path.is_absolute() or path.is_symlink():
        raise RuntimeError("bound core unavailable")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise RuntimeError("bound core unavailable")
    raw = path.read_bytes()
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


def _verify_core_commit(repo_root: Path) -> None:
    del repo_root
    # Root activation replaces this fail-closed gate with an ancestor commit
    # plus `git show <core>:runner/contract` blob equality checks.
    raise RuntimeError("launcher activation unavailable")


def _read_owner_file(path: Path) -> bytes:
    if not path.is_absolute() or path.is_symlink():
        raise RuntimeError("private input unavailable")
    metadata = path.stat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise RuntimeError("private input unavailable")
    return path.read_bytes()


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
        args.state_root, args.approval_1, args.approval_2,
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
