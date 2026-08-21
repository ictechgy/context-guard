#!/usr/bin/env python3
"""Verify historical P1-v8 Git evidence and run provider-free profiles."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath


REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_SCHEMA = "contextguard.p1-v8-evidence-manifest/v1"
BOUNDARY_SCHEMA = "contextguard.provider-free-roadmap-boundary/v1"
PINNED_COMMIT = "96cfd58f82c02166c2749389a22dd1249712c92d"
PINNED_FROZEN_ROOTS = (
    "bench/token-savings-12task",
    "research/p1-live-authorization-packet.md",
    "research/token-savings-roadmap.md",
)
PINNED_OUTPUT_ROOTS = (
    "research/provider-free-roadmap",
    "tests/provider-free-roadmap",
)
PINNED_G2_LOCK_PATH = "research/provider-free-roadmap/g2/freeze-lock.json"
PINNED_G2_LOCK_SHA256 = "dfe0bf76f9dad2441d6d7e41ecec19cf936b9c6f47ef33c8e53e7da56a4cd552"
PINNED_G2_TREE_ROOT_SHA256 = "27568e5c8488c6dd5c99665d770d11115f8048e0787675a6574daf7328a13811"
PINNED_G2_VERIFIER_SHA256 = "7785decb9381fa9027138e2c6fa82ca98dbea33e3ab9e99c2a24872942b6c98f"
PINNED_G3_LOCK_PATH = "research/provider-free-roadmap/g3/freeze-lock.json"
PINNED_G3_LOCK_SHA256 = "ad04a69d9600ce57ee23e0cd1a5e3b415f7947e3232fdcd55191da6f2e199c52"
PINNED_G3_TREE_ROOT_SHA256 = "f04f8374b2afa9621ee3719b80c295c75faa9bde2de5c286bcac1ffbce55299b"
PINNED_G4_LOCK_PATH = "research/provider-free-roadmap/g4/freeze-lock.json"
PINNED_G4_LOCK_SHA256 = "4680432dc093982db2627d207e782f523bf3896e9562d14e220b798f473b7e51"
PINNED_G4_TREE_ROOT_SHA256 = "568b7630561ab6fe48b3cf702c0f9562a92aa24fca03064419d8812818545458"
PINNED_G5_LOCK_PATH = "research/provider-free-roadmap/g5/freeze-lock.json"
PINNED_G5_LOCK_SHA256 = "4da399f445b2ff1d033c712083bd605b7cb0e6f210c7c24abe36d5f1df501f96"
PINNED_G5_TREE_ROOT_SHA256 = "de89fe567ccdaead27ff9853066108defbbab910f2a1fb42a005a2df2a7238be"
PINNED_G6_LOCK_PATH = "research/provider-free-roadmap/g6/freeze-lock.json"
PINNED_G6_LOCK_SHA256 = "d623371ca4944847b528c270359b8c48970666c9b6215416bb1f630bb79d8578"
PINNED_G6_TREE_ROOT_SHA256 = "a59a00783dd3944181556b485279039a4110b3cd97c1961f96c6f3fde17fa645"
PINNED_EXECUTION_PROFILES = {
    "boundary-tests": {
        "module": "tests.test_provider_free_roadmap_boundary",
        "test_artifact": {
            "bytes": 55701,
            "path": "tests/test_provider_free_roadmap_boundary.py",
            "sha256": "a5d860ff793d88e088894eab5c381fa0743928b610e02b68788bcee41815d871",
        },
    },
    "g2-contract-tests": {
        "module": "g2_contract_tests",
        "test_artifact": {
            "bytes": 52561,
            "path": "tests/provider-free-roadmap/test_g2_ablation_contract.py",
            "sha256": "9e74c3dffe3e7d94cc08096ace58bbf0581115fa1d837fb2a8a257ebfd7b5663",
        },
        "verifier_artifact": {
            "bytes": 81832,
            "path": "research/provider-free-roadmap/g2/v1/verify.py",
            "sha256": "7785decb9381fa9027138e2c6fa82ca98dbea33e3ab9e99c2a24872942b6c98f",
        },
    },
    "g3-rehearsal-tests": {
        "g2_verifier_artifact": {
            "bytes": 81832,
            "path": "research/provider-free-roadmap/g2/v1/verify.py",
            "sha256": PINNED_G2_VERIFIER_SHA256,
        },
        "g3_lock_artifact": {
            "bytes": 3330,
            "path": PINNED_G3_LOCK_PATH,
            "sha256": PINNED_G3_LOCK_SHA256,
        },
        "module": "g3_rehearsal_tests",
        "test_artifact": {
            "bytes": 42280,
            "path": "tests/provider-free-roadmap/test_g3_rehearsal.py",
            "sha256": "c78f2510c23f343a4355ec43f5f7924a6a5ac0e98aa174c7e199f3e937ac4496",
        },
    },
    "g4-claim-gates": {
        "g2_verifier_artifact": {
            "bytes": 81832,
            "path": "research/provider-free-roadmap/g2/v1/verify.py",
            "sha256": PINNED_G2_VERIFIER_SHA256,
        },
        "g3_lock_artifact": {
            "bytes": 3330,
            "path": PINNED_G3_LOCK_PATH,
            "sha256": PINNED_G3_LOCK_SHA256,
        },
        "g4_lock_artifact": {
            "bytes": 2202,
            "path": PINNED_G4_LOCK_PATH,
            "sha256": PINNED_G4_LOCK_SHA256,
        },
        "module": "g4_claim_gate_tests",
        "test_artifact": {
            "bytes": 15713,
            "path": "tests/provider-free-roadmap/test_g4_claim_gates.py",
            "sha256": "9a3202f5946421ec149876aaee6176c5a1227775be54ac3890e3395da791f90f",
        },
    },
    "g5-p2-preregistration": {
        "g4_lock_artifact": {
            "bytes": 2202,
            "path": PINNED_G4_LOCK_PATH,
            "sha256": PINNED_G4_LOCK_SHA256,
        },
        "g5_lock_artifact": {
            "bytes": 2438,
            "path": PINNED_G5_LOCK_PATH,
            "sha256": PINNED_G5_LOCK_SHA256,
        },
        "module": "g5_p2_preregistration_tests",
        "test_artifact": {
            "bytes": 45206,
            "path": "tests/provider-free-roadmap/test_g5_p2_preregistration.py",
            "sha256": "e3d80b078668a5b461be540ed52b95fd94b97147fe788889fedab1b2d6974e8a",
        },
    },
    "g6-prepared-unapproved": {
        "g5_lock_artifact": {
            "bytes": 2438,
            "path": PINNED_G5_LOCK_PATH,
            "sha256": PINNED_G5_LOCK_SHA256,
        },
        "g6_lock_artifact": {
            "bytes": 2069,
            "path": PINNED_G6_LOCK_PATH,
            "sha256": PINNED_G6_LOCK_SHA256,
        },
        "module": "g6_prepared_unapproved_tests",
        "test_artifact": {
            "bytes": 15895,
            "path": "tests/provider-free-roadmap/test_g6_approval_packet.py",
            "sha256": "980ccbafe1cc050ba452c0b36caa87a6660587bbcc77ec291d16a6c0c81c7fa5",
        },
    },
}
SPECIAL_PROFILE_MODULE_PATHS = {
    "g2_contract_tests": "tests/provider-free-roadmap/test_g2_ablation_contract.py",
    "g3_rehearsal_tests": "tests/provider-free-roadmap/test_g3_rehearsal.py",
    "g4_claim_gate_tests": "tests/provider-free-roadmap/test_g4_claim_gates.py",
    "g5_p2_preregistration_tests": "tests/provider-free-roadmap/test_g5_p2_preregistration.py",
    "g6_prepared_unapproved_tests": "tests/provider-free-roadmap/test_g6_approval_packet.py",
}
PINNED_PROFILE_BOOTSTRAP = (
    b"import sys\n"
    b"_filename = sys.argv[1]\n"
    b"sys.argv = sys.argv[1:]\n"
    b"_source = sys.stdin.buffer.read()\n"
    b"_globals = globals()\n"
    b"_globals.update({'__file__': _filename, '__package__': None, '__cached__': None})\n"
    b"exec(compile(_source, _filename, 'exec'), _globals, _globals)\n"
)
PINNED_PROFILE_BOOTSTRAP_SHA256 = (
    "79deee729b3885d68952e5f4ef819e836cef5f7509bb6d8a87520cd42fd37adf"
)
PINNED_G2_PROFILE_BOOTSTRAP = (
    b"import base64,json,sys\n"
    b"_filename=sys.argv[1]\n"
    b"sys.argv=sys.argv[1:]\n"
    b"_payload=json.loads(sys.stdin.buffer.read().decode('utf-8'))\n"
    b"_test=base64.b64decode(_payload['test'],validate=True)\n"
    b"_globals=globals()\n"
    b"_globals.update({'__file__':_filename,'__package__':None,'__cached__':None,"
    b"'__G2_CAPTURED_VERIFIER_BYTES__':base64.b64decode(_payload['verifier'],validate=True),"
    b"'__G2_CAPTURED_LOCK_BYTES__':base64.b64decode(_payload['lock'],validate=True),"
    b"'__G2_EXPECTED_LOCK_SHA256__':_payload['lock_sha256'],"
    b"'__G2_EXPECTED_TREE_ROOT__':_payload['tree_root']})\n"
    b"exec(compile(_test,_filename,'exec'),_globals,_globals)\n"
)
PINNED_G2_PROFILE_BOOTSTRAP_SHA256 = "3082cb3673b4d1b63da1d12393d25504f3b55ac6bbd57e29cf5bc3de0863e4d1"
PINNED_G3_PROFILE_BOOTSTRAP = (
    b"import base64,json,sys\n"
    b"_filename=sys.argv[1]\n"
    b"sys.argv=sys.argv[1:]\n"
    b"_payload=json.loads(sys.stdin.buffer.read().decode('ascii'))\n"
    b"_decode=lambda value:base64.b64decode(value,validate=True)\n"
    b"_test=_decode(_payload['test'])\n"
    b"_globals=globals()\n"
    b"_globals.update({'__file__':_filename,'__package__':None,'__cached__':None,"
    b"'__G3_CAPTURED_RUNNER_BYTES__':_decode(_payload['runner']),"
    b"'__G3_CAPTURED_MANIFEST_BYTES__':_decode(_payload['manifest']),"
    b"'__G3_CAPTURED_COST_MODEL_BYTES__':_decode(_payload['cost_model']),"
    b"'__G3_CAPTURED_SCHEMA_BYTES__':{key:_decode(value) for key,value in _payload['schemas'].items()},"
    b"'__G3_CAPTURED_G2_VERIFIER_BYTES__':_decode(_payload['g2_verifier']),"
    b"'__G3_CAPTURED_G2_LOCK_BYTES__':_decode(_payload['g2_lock']),"
    b"'__G3_EXPECTED_G2_LOCK_SHA256__':_payload['g2_lock_sha256'],"
    b"'__G3_EXPECTED_G2_TREE_ROOT__':_payload['g2_tree_root'],"
    b"'__G3_EXPECTED_G2_VERIFIER_SHA256__':_payload['g2_verifier_sha256']})\n"
    b"exec(compile(_test,_filename,'exec'),_globals,_globals)\n"
)
PINNED_G3_PROFILE_BOOTSTRAP_SHA256 = "a7ef095fa1c9996c9df2f3b6775ccc29e94235ad98208366816540de1195e63b"
PINNED_G4_PROFILE_BOOTSTRAP = (
    b"import base64,json,sys\n"
    b"_filename=sys.argv[1]\n"
    b"sys.argv=sys.argv[1:]\n"
    b"_payload=json.loads(sys.stdin.buffer.read().decode('ascii'))\n"
    b"_decode=lambda value:base64.b64decode(value,validate=True)\n"
    b"_test=_decode(_payload['test'])\n"
    b"_globals=globals()\n"
    b"_globals.update({'__file__':_filename,'__package__':None,'__cached__':None,"
    b"'__G4_CAPTURED_VERIFIER_BYTES__':_decode(_payload['g4_verifier']),"
    b"'__G4_CAPTURED_POLICY_BYTES__':_decode(_payload['g4_policy']),"
    b"'__G4_CAPTURED_SCHEMA_BYTES__':{key:_decode(value) for key,value in _payload['g4_schemas'].items()},"
    b"'__G4_CAPTURED_G3_LOCK_BYTES__':_decode(_payload['g3_lock']),"
    b"'__G4_CAPTURED_G3_RUNNER_BYTES__':_decode(_payload['g3_runner']),"
    b"'__G4_CAPTURED_G3_MANIFEST_BYTES__':_decode(_payload['g3_manifest']),"
    b"'__G4_CAPTURED_G3_COST_MODEL_BYTES__':_decode(_payload['g3_cost_model']),"
    b"'__G4_CAPTURED_G3_SCHEMA_BYTES__':{key:_decode(value) for key,value in _payload['g3_schemas'].items()},"
    b"'__G4_CAPTURED_G2_VERIFIER_BYTES__':_decode(_payload['g2_verifier']),"
    b"'__G4_CAPTURED_G2_LOCK_BYTES__':_decode(_payload['g2_lock'])})\n"
    b"exec(compile(_test,_filename,'exec'),_globals,_globals)\n"
)
PINNED_G4_PROFILE_BOOTSTRAP_SHA256 = "ff054f19e61783afd9e257e266c65b7491bc74788c06f170a565fdb81a0487e7"
PINNED_G5_PROFILE_BOOTSTRAP = (
    b"import base64,json,sys\n"
    b"_filename=sys.argv[1]\n"
    b"sys.argv=sys.argv[1:]\n"
    b"_payload=json.loads(sys.stdin.buffer.read().decode('ascii'))\n"
    b"_decode=lambda value:base64.b64decode(value,validate=True)\n"
    b"_test=_decode(_payload['test'])\n"
    b"_globals=globals()\n"
    b"_globals.update({'__file__':_filename,'__package__':None,'__cached__':None,"
    b"'__G5_CAPTURED_VERIFIER_BYTES__':_decode(_payload['g5_verifier']),"
    b"'__G5_CAPTURED_PREREG_BYTES__':_decode(_payload['g5_prereg']),"
    b"'__G5_CAPTURED_SCHEDULE_BYTES__':_decode(_payload['g5_schedule']),"
    b"'__G5_CAPTURED_SCHEMA_BYTES__':{key:_decode(value) for key,value in _payload['g5_schemas'].items()},"
    b"'__G5_CAPTURED_G4_LOCK_BYTES__':_decode(_payload['g4_lock']),"
    b"'__G5_CAPTURED_G4_VERIFIER_BYTES__':_decode(_payload['g4_verifier']),"
    b"'__G5_CAPTURED_G4_POLICY_BYTES__':_decode(_payload['g4_policy']),"
    b"'__G5_CAPTURED_G4_SCHEMA_BYTES__':{key:_decode(value) for key,value in _payload['g4_schemas'].items()}})\n"
    b"exec(compile(_test,_filename,'exec'),_globals,_globals)\n"
)
PINNED_G5_PROFILE_BOOTSTRAP_SHA256 = "e9a8097224690785a94c84a6077b270d1fdc181defd1849c14e1aac26be9fec1"
PINNED_G6_PROFILE_BOOTSTRAP = (
    b"import base64,json,sys\n"
    b"_filename=sys.argv[1]\n"
    b"sys.argv=sys.argv[1:]\n"
    b"_payload=json.loads(sys.stdin.buffer.read().decode('ascii'))\n"
    b"_decode=lambda value:base64.b64decode(value,validate=True)\n"
    b"_test=_decode(_payload['test'])\n"
    b"_globals=globals()\n"
    b"_globals.update({'__file__':_filename,'__package__':None,'__cached__':None,"
    b"'__G6_CAPTURED_VERIFIER_BYTES__':_decode(_payload['g6_verifier']),"
    b"'__G6_CAPTURED_PACKET_BYTES__':_decode(_payload['g6_packet']),"
    b"'__G6_CAPTURED_SCHEMA_BYTES__':_decode(_payload['g6_schema']),"
    b"'__G6_CAPTURED_G5_LOCK_BYTES__':_decode(_payload['g5_lock']),"
    b"'__G6_CAPTURED_G5_PREREG_BYTES__':_decode(_payload['g5_prereg']),"
    b"'__G6_CAPTURED_G5_SCHEDULE_BYTES__':_decode(_payload['g5_schedule']),"
    b"'__G6_CAPTURED_G5_SCHEMA_BYTES__':{key:_decode(value) for key,value in _payload['g5_schemas'].items()},"
    b"'__G6_CAPTURED_G5_VERIFIER_BYTES__':_decode(_payload['g5_verifier']),"
    b"'__G6_CAPTURED_INVENTORY_PATHS__':_payload['g6_inventory_paths']})\n"
    b"exec(compile(_test,_filename,'exec'),_globals,_globals)\n"
)
PINNED_G6_PROFILE_BOOTSTRAP_SHA256 = "0258260a4e3693c03c2b6e02864a43110b6a85fdf9aa04a6099b694d0a234be3"
ALLOWED_ENVIRONMENT = ("LANG", "PATH")
EXPECTED_SCOPE = {
    "current_or_later_roadmap": "out_of_scope",
    "historical_repository_evidence": "P1-v8",
    "private_study_files": "unavailable_claim_blocking",
}
EXPECTED_UNAVAILABLE_RECORD = {
    "analytic_records": 121,
    "candidate_manifest_sha256": (
        "39b02e542c83ac4f15d7761d9cf1b2b61a37cfbcb6eafe6a3580949857b26ca4"
    ),
    "candidate_run": 31464306133,
    "receipt_artifact": 9091361298,
    "report_sha256": (
        "09eca0ff9953a7f45da2d373d568dff22e09abe19965bc58952d65822151a8a5"
    ),
    "root_artifact": 9091361857,
    "source": "fb2e177f3efb15e817f54f5742beacdbe5daf96a",
    "status": "unavailable_claim_blocking",
    "study_root": "/private/tmp/contextguard-p1-live-v8.rLM3P6/study",
}
EXPECTED_PROHIBITIONS = {
    "credential_access": (
        "No credential, auth, keychain, cookie, token, .env, provider configuration, "
        "or user-login material may be read, requested, forwarded, or persisted."
    ),
    "network_and_provider_calls": (
        "No network, DNS, socket, remote Git/GitHub/npm, model, host, or provider call "
        "may be attempted."
    ),
    "npm_publication": (
        "No npm pack, publish, dist-tag, registry mutation, candidate dispatch, or "
        "release action is authorized."
    ),
    "runtime_activation": (
        "No serve, run, emit, listener, hook activation, host interception, transcript "
        "rewriting, package activation, or provider-backed execution is authorized."
    ),
    "token_savings_claims": (
        "No token-savings, cost-savings, parity, quality, production-readiness, or "
        "generalization claim may be made from this provider-free work."
    ),
}
MANIFEST_KEYS = {
    "algorithm",
    "artifacts",
    "evidence_scope",
    "frozen_roots",
    "git_anchor_commit",
    "roadmap_output_roots",
    "schema_version",
    "unavailable_claim_blocking",
}
BOUNDARY_KEYS = {
    "allowed_inherited_environment",
    "child_environment",
    "execution_profiles",
    "new_output_roots",
    "prohibitions",
    "schema_version",
}
SYSTEM_GIT = Path("/usr/bin/git")
PROFILE_TIMEOUT_SECONDS = 300
GIT_TIMEOUT_SECONDS = 30
GIT_OBJECT_ENVIRONMENT = {
    "GIT_CONFIG_COUNT": "3",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_KEY_0": "credential.helper",
    "GIT_CONFIG_KEY_1": "core.askPass",
    "GIT_CONFIG_KEY_2": "protocol.allow",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_VALUE_0": "",
    "GIT_CONFIG_VALUE_1": "/usr/bin/false",
    "GIT_CONFIG_VALUE_2": "never",
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "LANG": "C",
    "PATH": "/usr/bin:/bin",
}
APPLE_RUNTIME_ENVIRONMENT = "__CF_USER_TEXT_ENCODING"
APPLE_RUNTIME_VALUE = re.compile(r"0x[0-9A-Fa-f]+:0x[0-9A-Fa-f]+:0x[0-9A-Fa-f]+")


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def run_bounded_profile(
    profile_name: str,
    command: list[str],
    root: Path,
    environment: dict[str, str],
    payload: bytes,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            command,
            cwd=root,
            env=environment,
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=PROFILE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        fail(f"{profile_name} profile timed out")


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        fail(f"invalid contract {path}: {exc}")
    return load_json_bytes(raw, str(path))


def load_json_bytes(raw: bytes, label: str) -> dict:
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"), object_pairs_hook=reject_duplicate_keys
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        fail(f"invalid contract {label}: {exc}")
    if not isinstance(value, dict):
        fail(f"invalid contract {label}: root must be an object")
    return value


def validate_safe_file_mode(mode: int, label: str) -> None:
    bits = stat.S_IMODE(mode)
    if bits & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
        fail(f"unsafe special mode bits on {label}")
    if bits & 0o022 or bits not in {0o644, 0o755}:
        fail(f"unsafe mode on {label}")


def capture_regular_file(root: Path, relative: str, label: str) -> bytes:
    """Capture stable bytes using no-follow dirfds and exact safe file modes."""
    relative = normalized_relative_path(relative, label)
    parts = PurePosixPath(relative).parts
    root_fd: int | None = None
    current_fd: int | None = None
    file_fd: int | None = None
    try:
        root_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        current_fd = root_fd
        for component in parts[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=current_fd,
            )
            if current_fd != root_fd:
                os.close(current_fd)
            current_fd = next_fd
        file_fd = os.open(
            parts[-1],
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=current_fd,
        )
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            fail(f"unsafe {label}: {relative}")
        validate_safe_file_mode(before.st_mode, f"{label}: {relative}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(file_fd, 64 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b"".join(chunks)
        after = os.fstat(file_fd)
        identity = lambda item: (
            item.st_dev, item.st_ino, item.st_mode, item.st_nlink,
            item.st_size, item.st_mtime_ns,
        )
        if identity(before) != identity(after) or len(raw) != after.st_size:
            fail(f"changed while capturing {label}: {relative}")
        return raw
    except SystemExit:
        raise
    except OSError:
        fail(f"missing {label}: {relative}")
    finally:
        for descriptor in (file_fd, current_fd, root_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def verify_captured_artifact(raw: bytes, artifact: object, label: str) -> str:
    if not isinstance(artifact, dict) or set(artifact) != {"bytes", "path", "sha256"}:
        fail(f"invalid {label}")
    relative = normalized_relative_path(artifact["path"], label)
    byte_count = artifact["bytes"]
    digest = artifact["sha256"]
    if (
        isinstance(byte_count, bool) or not isinstance(byte_count, int)
        or not isinstance(digest, str) or byte_count != len(raw)
        or digest != hashlib.sha256(raw).hexdigest()
    ):
        fail(f"changed {label}: {relative}")
    return relative


def validate_inherited_environment() -> dict[str, str]:
    names = set(os.environ)
    apple_runtime_value = os.environ.get(APPLE_RUNTIME_ENVIRONMENT)
    if (
        sys.platform == "darwin"
        and isinstance(apple_runtime_value, str)
        and APPLE_RUNTIME_VALUE.fullmatch(apple_runtime_value)
    ):
        # A framework-linked Python materializes this after exec on macOS. It is
        # not copied into the child environment and is not a caller allowlist.
        names.remove(APPLE_RUNTIME_ENVIRONMENT)
    unexpected = sorted(names - set(ALLOWED_ENVIRONMENT))
    if unexpected:
        fail(f"prohibited inherited environment name: {unexpected[0]}")
    missing = [name for name in ALLOWED_ENVIRONMENT if not os.environ.get(name)]
    if missing:
        fail(f"missing required minimal environment name: {missing[0]}")
    return {name: os.environ[name] for name in ALLOWED_ENVIRONMENT}


def normalized_relative_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"invalid {label}")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or value == "."
        or ".." in path.parts
        or ":" in value
        or "\x00" in value
    ):
        fail(f"invalid {label}")
    return value


def paths_overlap(left: str, right: str) -> bool:
    left_path = PurePosixPath(left)
    right_path = PurePosixPath(right)
    return (
        left_path == right_path
        or left_path in right_path.parents
        or right_path in left_path.parents
    )


def validated_roots(manifest: dict) -> tuple[list[str], list[str]]:
    frozen_roots = manifest.get("frozen_roots")
    output_roots = manifest.get("roadmap_output_roots")
    if not isinstance(frozen_roots, list) or not frozen_roots:
        fail("invalid frozen evidence roots")
    if not isinstance(output_roots, list) or not output_roots:
        fail("roadmap output roots are mandatory")
    frozen = [normalized_relative_path(value, "frozen root") for value in frozen_roots]
    outputs = [normalized_relative_path(value, "roadmap output root") for value in output_roots]
    if len(frozen) != len(set(frozen)) or len(outputs) != len(set(outputs)):
        fail("roadmap output roots and frozen roots must be unique")
    for output in outputs:
        if any(paths_overlap(output, frozen_root) for frozen_root in frozen):
            fail(f"roadmap output roots overlap frozen evidence: {output}")
    for index, output in enumerate(outputs):
        if any(paths_overlap(output, other) for other in outputs[index + 1 :]):
            fail(f"roadmap output roots overlap each other: {output}")
    if tuple(frozen) != PINNED_FROZEN_ROOTS:
        fail("unexpected P1-v8 frozen evidence roots")
    if tuple(outputs) != PINNED_OUTPUT_ROOTS:
        fail("unexpected roadmap output roots")
    return frozen, outputs


def run_git(root: Path, *arguments: str) -> bytes:
    if not SYSTEM_GIT.is_file():
        fail("required local Git executable is unavailable")
    try:
        result = subprocess.run(
            [str(SYSTEM_GIT), "-C", str(root), *arguments],
            env=dict(GIT_OBJECT_ENVIRONMENT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        fail("unable to read the pinned local Git object")
    if result.returncode != 0:
        fail("unable to read the pinned local Git object")
    return result.stdout


def read_git_blobs(root: Path, object_names: list[str]) -> list[bytes]:
    try:
        result = subprocess.run(
            [str(SYSTEM_GIT), "-C", str(root), "cat-file", "--batch"],
            env=dict(GIT_OBJECT_ENVIRONMENT),
            input=("\n".join(object_names) + "\n").encode("ascii"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        fail("unable to read the pinned local Git blobs")
    if result.returncode != 0:
        fail("unable to read the pinned local Git blobs")
    blobs: list[bytes] = []
    cursor = 0
    for expected_name in object_names:
        header_end = result.stdout.find(b"\n", cursor)
        if header_end < 0:
            fail("invalid pinned Git blob stream")
        try:
            object_name, object_type, raw_size = result.stdout[cursor:header_end].split(b" ", 2)
            size = int(raw_size)
        except ValueError:
            fail("invalid pinned Git blob header")
        cursor = header_end + 1
        blob_end = cursor + size
        if (
            object_name.decode("ascii", "strict") != expected_name
            or object_type != b"blob"
            or blob_end >= len(result.stdout)
            or result.stdout[blob_end : blob_end + 1] != b"\n"
        ):
            fail("invalid pinned Git blob record")
        blobs.append(result.stdout[cursor:blob_end])
        cursor = blob_end + 1
    if cursor != len(result.stdout):
        fail("unexpected trailing pinned Git blob data")
    return blobs


def pinned_git_artifacts(root: Path, roots: list[str]) -> dict[str, tuple[int, str]]:
    resolved = run_git(root, "rev-parse", "--verify", f"{PINNED_COMMIT}^{{commit}}")
    if resolved.strip().decode("ascii", "strict") != PINNED_COMMIT:
        fail("pinned P1-v8 Git anchor does not resolve exactly")
    for relative_root in roots:
        object_type = run_git(root, "cat-file", "-t", f"{PINNED_COMMIT}:{relative_root}")
        if object_type.strip() not in {b"blob", b"tree"}:
            fail(f"invalid pinned Git root: {relative_root}")

    tree = run_git(root, "ls-tree", "-r", "-z", "--full-tree", PINNED_COMMIT, "--", *roots)
    records: list[tuple[str, str]] = []
    for record in tree.split(b"\x00"):
        if not record:
            continue
        try:
            header, raw_path = record.split(b"\t", 1)
            _, object_type, object_id = header.split(b" ", 2)
            relative = raw_path.decode("utf-8", "strict")
            object_name = object_id.decode("ascii", "strict")
        except (ValueError, UnicodeError):
            fail("invalid pinned Git tree record")
        if object_type != b"blob":
            fail(f"non-blob pinned Git artifact: {relative}")
        normalized_relative_path(relative, "pinned Git artifact path")
        records.append((relative, object_name))

    artifacts: dict[str, tuple[int, str]] = {}
    for (relative, _), raw in zip(
        records,
        read_git_blobs(root, [object_name for _, object_name in records]),
        strict=True,
    ):
        artifacts[relative] = (len(raw), hashlib.sha256(raw).hexdigest())
    return artifacts


def manifest_artifacts(manifest: dict) -> dict[str, tuple[int, str]]:
    entries = manifest.get("artifacts")
    if not isinstance(entries, list) or not entries:
        fail("invalid P1-v8 evidence artifact inventory")
    artifacts: dict[str, tuple[int, str]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"bytes", "path", "sha256"}:
            fail("invalid P1-v8 evidence artifact entry")
        relative = normalized_relative_path(entry["path"], "P1-v8 evidence artifact path")
        byte_count = entry["bytes"]
        digest = entry["sha256"]
        if (
            isinstance(byte_count, bool)
            or not isinstance(byte_count, int)
            or byte_count < 0
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            fail(f"invalid P1-v8 evidence artifact metadata: {relative}")
        if relative in artifacts:
            fail(f"duplicate P1-v8 evidence artifact: {relative}")
        artifacts[relative] = (byte_count, digest)
    if list(artifacts) != sorted(artifacts):
        fail("P1-v8 evidence artifacts must be path-sorted")
    return artifacts


def verify_inventory(root: Path, manifest_path: Path) -> None:
    manifest = load_json(manifest_path)
    if "roadmap_output_roots" not in manifest:
        fail("roadmap output roots are mandatory")
    if set(manifest) != MANIFEST_KEYS:
        fail("invalid P1-v8 evidence manifest shape")
    if manifest.get("schema_version") != MANIFEST_SCHEMA or manifest.get("algorithm") != "sha256":
        fail("invalid P1-v8 evidence manifest contract")
    if manifest.get("git_anchor_commit") != PINNED_COMMIT:
        fail("unexpected P1-v8 Git anchor")
    if manifest.get("evidence_scope") != EXPECTED_SCOPE:
        fail("invalid historical P1-v8 evidence scope")
    if manifest.get("unavailable_claim_blocking") != EXPECTED_UNAVAILABLE_RECORD:
        fail("invalid unavailable-claim-blocking live-study record")
    frozen_roots, _ = validated_roots(manifest)
    expected = manifest_artifacts(manifest)
    actual = pinned_git_artifacts(root, frozen_roots)

    unlisted = sorted(set(actual) - set(expected))
    absent = sorted(set(expected) - set(actual))
    if unlisted:
        fail(f"unlisted pinned Git artifact: {unlisted[0]}")
    if absent:
        fail(f"artifact absent from pinned Git tree: {absent[0]}")
    for relative in sorted(expected):
        if expected[relative] != actual[relative]:
            fail(f"changed pinned Git artifact: {relative}")
    print("P1-v8 Git evidence inventory: OK")


def validated_contract(contract_path: Path) -> dict:
    contract = load_json(contract_path)
    if set(contract) != BOUNDARY_KEYS:
        fail("invalid provider-free boundary contract shape")
    if contract.get("schema_version") != BOUNDARY_SCHEMA:
        fail("invalid provider-free boundary contract")
    if contract.get("allowed_inherited_environment") != list(ALLOWED_ENVIRONMENT):
        fail("invalid inherited-environment allowlist")
    if contract.get("child_environment") != {"copy_from_inherited": list(ALLOWED_ENVIRONMENT)}:
        fail("invalid child-environment contract")
    if contract.get("new_output_roots") != list(PINNED_OUTPUT_ROOTS):
        fail("invalid provider-free output roots")
    if contract.get("execution_profiles") != PINNED_EXECUTION_PROFILES:
        fail("execution profiles do not match pinned profile")
    if contract.get("prohibitions") != EXPECTED_PROHIBITIONS:
        fail("invalid provider-free prohibitions")
    return contract


def verified_profile_test(root: Path, profile: object) -> tuple[str, bytes]:
    if not isinstance(profile, dict):
        fail("invalid execution profile")
    module = profile.get("module")
    expected_keys = (
        {"module", "test_artifact", "verifier_artifact"}
        if module == "g2_contract_tests"
        else {
            "g2_verifier_artifact", "g3_lock_artifact", "module", "test_artifact"
        }
        if module == "g3_rehearsal_tests"
        else {
            "g2_verifier_artifact", "g3_lock_artifact", "g4_lock_artifact",
            "module", "test_artifact",
        }
        if module == "g4_claim_gate_tests"
        else {
            "g4_lock_artifact", "g5_lock_artifact", "module", "test_artifact",
        }
        if module == "g5_p2_preregistration_tests"
        else {
            "g5_lock_artifact", "g6_lock_artifact", "module", "test_artifact",
        }
        if module == "g6_prepared_unapproved_tests"
        else {"module", "test_artifact"}
    )
    if set(profile) != expected_keys:
        fail("invalid execution profile")
    artifact = profile["test_artifact"]
    if (
        not isinstance(module, str)
        or not module
        or not isinstance(artifact, dict)
        or set(artifact) != {"bytes", "path", "sha256"}
    ):
        fail("invalid execution profile test module")
    relative = normalized_relative_path(artifact["path"], "execution profile test artifact")
    if module in SPECIAL_PROFILE_MODULE_PATHS:
        expected_relative = SPECIAL_PROFILE_MODULE_PATHS[module]
    elif all(part.isidentifier() for part in module.split(".")):
        expected_relative = module.replace(".", "/") + ".py"
    else:
        fail("invalid execution profile test module")
    if relative != expected_relative:
        fail("execution profile module and test artifact disagree")
    raw = capture_regular_file(root, relative, "execution profile test artifact")
    verify_captured_artifact(raw, artifact, "execution profile test artifact")
    return str(root / relative), raw


def verified_g2_verifier(root: Path, profile: dict) -> tuple[str, bytes]:
    artifact = profile.get("verifier_artifact")
    if not isinstance(artifact, dict):
        fail("invalid g2 verifier artifact")
    relative = normalized_relative_path(artifact.get("path"), "g2 verifier artifact")
    if relative != "research/provider-free-roadmap/g2/v1/verify.py":
        fail("invalid g2 verifier artifact path")
    raw = capture_regular_file(root, relative, "g2 verifier artifact")
    verify_captured_artifact(raw, artifact, "g2 verifier artifact")
    return relative, raw


def execute_verified_profile_bytes(
    executable: Path,
    root: Path,
    pinned_filename: str,
    raw: bytes,
    child_environment: dict[str, str],
) -> subprocess.CompletedProcess[bytes]:
    if hashlib.sha256(PINNED_PROFILE_BOOTSTRAP).hexdigest() != PINNED_PROFILE_BOOTSTRAP_SHA256:
        fail("invalid pinned profile bootstrap")
    return run_bounded_profile(
        "boundary-tests",
        [
            str(executable),
            "-I",
            "-B",
            "-c",
            PINNED_PROFILE_BOOTSTRAP.decode("ascii"),
            pinned_filename,
        ],
        root,
        dict(child_environment),
        raw,
    )


def execute_verified_g2_profile_bytes(
    executable: Path,
    root: Path,
    pinned_filename: str,
    test_raw: bytes,
    verifier_raw: bytes,
    lock_raw: bytes,
    lock_sha256: str,
    tree_root: str,
    child_environment: dict[str, str],
) -> subprocess.CompletedProcess[bytes]:
    if hashlib.sha256(PINNED_G2_PROFILE_BOOTSTRAP).hexdigest() != PINNED_G2_PROFILE_BOOTSTRAP_SHA256:
        fail("invalid pinned g2 profile bootstrap")
    payload = {
        "lock": base64.b64encode(lock_raw).decode("ascii"),
        "lock_sha256": lock_sha256,
        "test": base64.b64encode(test_raw).decode("ascii"),
        "tree_root": tree_root,
        "verifier": base64.b64encode(verifier_raw).decode("ascii"),
    }
    return run_bounded_profile(
        "g2-contract-tests",
        [
            str(executable), "-I", "-B", "-c",
            PINNED_G2_PROFILE_BOOTSTRAP.decode("ascii"), pinned_filename,
        ],
        root,
        {"LANG": child_environment["LANG"]},
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii"),
    )


def g3_tree_root(entries: list[dict[str, object]]) -> str:
    encoded = json.dumps(entries, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(b"contextguard.g3-freeze-tree/v1\x00" + encoded).hexdigest()


def verify_independently_pinned_g3_lock(root: Path, profile: dict) -> tuple[bytes, dict]:
    artifact = profile.get("g3_lock_artifact")
    if not isinstance(artifact, dict):
        fail("invalid g3 freeze lock artifact")
    relative = normalized_relative_path(artifact.get("path"), "g3 freeze lock artifact")
    if relative != PINNED_G3_LOCK_PATH:
        fail("invalid g3 freeze lock path")
    raw = capture_regular_file(root, relative, "independently pinned g3 freeze lock")
    verify_captured_artifact(raw, artifact, "independently pinned g3 freeze lock")
    if hashlib.sha256(raw).hexdigest() != PINNED_G3_LOCK_SHA256:
        fail("changed independently pinned g3 freeze lock")
    lock = load_json_bytes(raw, relative)
    required = {"algorithm", "g2_source", "inventory", "schema_version", "tree_root_sha256"}
    if (
        set(lock) != required
        or lock.get("schema_version") != "contextguard.g3-freeze-lock/v1"
        or lock.get("algorithm") != "sha256"
        or lock.get("g2_source") != {
            "lock_sha256": PINNED_G2_LOCK_SHA256,
            "tree_root_sha256": PINNED_G2_TREE_ROOT_SHA256,
            "verifier_sha256": PINNED_G2_VERIFIER_SHA256,
        }
    ):
        fail("invalid independently pinned g3 freeze lock")
    entries = lock.get("inventory")
    if not isinstance(entries, list) or not entries:
        fail("invalid g3 freeze inventory")
    paths: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"bytes", "mode", "path", "sha256"}:
            fail("invalid g3 freeze inventory entry")
        relative = normalized_relative_path(entry["path"], "g3 freeze inventory path")
        if not (
            relative.startswith("research/provider-free-roadmap/g3/v1/")
            or relative == "tests/provider-free-roadmap/test_g3_rehearsal.py"
        ):
            fail("g3 freeze inventory escaped its scope")
        if (
            isinstance(entry["bytes"], bool) or not isinstance(entry["bytes"], int)
            or entry["bytes"] < 0 or not isinstance(entry["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is None
            or entry["mode"] not in {"0644", "0755"}
        ):
            fail("invalid g3 freeze inventory metadata")
        paths.append(relative)
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        fail("g3 freeze inventory paths must be unique and sorted")
    if lock.get("tree_root_sha256") != g3_tree_root(entries):
        fail("g3 freeze tree root mismatch")
    if lock["tree_root_sha256"] != PINNED_G3_TREE_ROOT_SHA256:
        fail("changed independently pinned g3 tree root")
    return raw, lock


def enumerate_g3_scope(root: Path) -> set[str]:
    base_relative = "research/provider-free-roadmap/g3/v1"
    base = root / base_relative
    try:
        base_metadata = base.lstat()
    except OSError:
        fail("missing g3 frozen scope")
    if stat.S_ISLNK(base_metadata.st_mode) or not stat.S_ISDIR(base_metadata.st_mode):
        fail("unsafe g3 frozen scope")
    result: set[str] = set()
    pending = [(base, base_relative)]
    while pending:
        directory, directory_relative = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError:
            fail(f"unreadable g3 frozen scope: {directory_relative}")
        for entry in entries:
            relative = f"{directory_relative}/{entry.name}"
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError:
                fail(f"changed while enumerating g3 frozen scope: {relative}")
            if stat.S_ISLNK(metadata.st_mode):
                fail(f"symlink in g3 frozen scope: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append((Path(entry.path), relative))
            elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                result.add(relative)
            else:
                fail(f"unsafe path in g3 frozen scope: {relative}")
    test_relative = "tests/provider-free-roadmap/test_g3_rehearsal.py"
    test_path = root / test_relative
    try:
        test_metadata = test_path.lstat()
    except OSError:
        fail("missing g3 frozen test artifact")
    if (
        stat.S_ISLNK(test_metadata.st_mode)
        or not stat.S_ISREG(test_metadata.st_mode)
        or test_metadata.st_nlink != 1
    ):
        fail("unsafe g3 frozen test artifact")
    result.add(test_relative)
    return result


def capture_g3_inventory(root: Path, lock: dict) -> dict[str, bytes]:
    expected_paths = {str(entry["path"]) for entry in lock["inventory"]}
    actual_paths = enumerate_g3_scope(root)
    unlisted = sorted(actual_paths - expected_paths)
    missing = sorted(expected_paths - actual_paths)
    if unlisted:
        fail(f"unlisted g3 frozen artifact: {unlisted[0]}")
    if missing:
        fail(f"missing g3 frozen artifact: {missing[0]}")
    result: dict[str, bytes] = {}
    for entry in lock["inventory"]:
        relative = str(entry["path"])
        raw = capture_regular_file(root, relative, "g3 frozen artifact")
        verify_captured_artifact(
            raw,
            {key: entry[key] for key in ("bytes", "path", "sha256")},
            "g3 frozen artifact",
        )
        actual_mode = f"{stat.S_IMODE((root / relative).lstat().st_mode):04o}"
        if actual_mode != entry["mode"]:
            fail(f"changed g3 frozen artifact mode: {relative}")
        result[relative] = raw
    required = {
        "research/provider-free-roadmap/g3/v1/README.md",
        "research/provider-free-roadmap/g3/v1/cost-model.json",
        "research/provider-free-roadmap/g3/v1/manifest.json",
        "research/provider-free-roadmap/g3/v1/rehearse.py",
        "tests/provider-free-roadmap/test_g3_rehearsal.py",
    }
    if not required <= set(result):
        fail("g3 freeze inventory is incomplete")
    schema_paths = [path for path in result if "/g3/v1/schemas/" in path]
    if not schema_paths:
        fail("g3 freeze inventory lacks schemas")
    return result


def verified_g3_g2_verifier(root: Path, profile: dict) -> bytes:
    artifact = profile.get("g2_verifier_artifact")
    if not isinstance(artifact, dict):
        fail("invalid g3 g2 verifier artifact")
    relative = normalized_relative_path(artifact.get("path"), "g3 g2 verifier artifact")
    if relative != "research/provider-free-roadmap/g2/v1/verify.py":
        fail("invalid g3 g2 verifier artifact path")
    raw = capture_regular_file(root, relative, "g3 pinned g2 verifier")
    verify_captured_artifact(raw, artifact, "g3 pinned g2 verifier")
    if hashlib.sha256(raw).hexdigest() != PINNED_G2_VERIFIER_SHA256:
        fail("changed g3 pinned g2 verifier")
    return raw


def execute_verified_g3_profile_bytes(
    executable: Path, root: Path, pinned_filename: str, test_raw: bytes,
    inventory: dict[str, bytes], g2_verifier_raw: bytes, g2_lock_raw: bytes,
    child_environment: dict[str, str],
) -> subprocess.CompletedProcess[bytes]:
    if hashlib.sha256(PINNED_G3_PROFILE_BOOTSTRAP).hexdigest() != PINNED_G3_PROFILE_BOOTSTRAP_SHA256:
        fail("invalid pinned g3 profile bootstrap")
    prefix = "research/provider-free-roadmap/g3/v1/"
    schemas = {
        path.removeprefix(prefix + "schemas/"): base64.b64encode(raw).decode("ascii")
        for path, raw in inventory.items() if path.startswith(prefix + "schemas/")
    }
    payload = {
        "cost_model": base64.b64encode(inventory[prefix + "cost-model.json"]).decode("ascii"),
        "g2_lock": base64.b64encode(g2_lock_raw).decode("ascii"),
        "g2_lock_sha256": PINNED_G2_LOCK_SHA256,
        "g2_tree_root": PINNED_G2_TREE_ROOT_SHA256,
        "g2_verifier": base64.b64encode(g2_verifier_raw).decode("ascii"),
        "g2_verifier_sha256": PINNED_G2_VERIFIER_SHA256,
        "manifest": base64.b64encode(inventory[prefix + "manifest.json"]).decode("ascii"),
        "runner": base64.b64encode(inventory[prefix + "rehearse.py"]).decode("ascii"),
        "schemas": schemas,
        "test": base64.b64encode(test_raw).decode("ascii"),
    }
    return run_bounded_profile(
        "g3-rehearsal-tests",
        [str(executable), "-I", "-B", "-c", PINNED_G3_PROFILE_BOOTSTRAP.decode("ascii"), pinned_filename],
        root,
        {"LANG": child_environment["LANG"]},
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii"),
    )


def verify_independently_pinned_g4_lock(root: Path, profile: dict) -> tuple[bytes, dict]:
    artifact = profile.get("g4_lock_artifact")
    if not isinstance(artifact, dict):
        fail("invalid g4 freeze lock artifact")
    relative = normalized_relative_path(artifact.get("path"), "g4 freeze lock artifact")
    if relative != PINNED_G4_LOCK_PATH:
        fail("invalid g4 freeze lock path")
    raw = capture_regular_file(root, relative, "independently pinned g4 freeze lock")
    verify_captured_artifact(raw, artifact, "independently pinned g4 freeze lock")
    if hashlib.sha256(raw).hexdigest() != PINNED_G4_LOCK_SHA256:
        fail("changed independently pinned g4 freeze lock")
    lock = load_json_bytes(raw, relative)
    if (
        set(lock) != {"algorithm", "g3_source", "inventory", "schema_version", "tree_root_sha256"}
        or lock.get("algorithm") != "sha256"
        or lock.get("schema_version") != "contextguard.g4-freeze-lock/v1"
        or lock.get("tree_root_sha256") != PINNED_G4_TREE_ROOT_SHA256
        or lock.get("g3_source") != {
            "lock_sha256": PINNED_G3_LOCK_SHA256,
            "manifest_sha256": "e9258b25e9af652196dc99401bfa053c3446f3241865639822db3a07ff139889",
            "runner_sha256": "6683de5244428714a273dd50f9b12a84c9a4c47e96f3cc97e1c18272c5b50f23",
            "schema_set_bytes": 25254,
            "schema_set_sha256": "2ad1c70def6011139ecc76d4761268d6534af564f39bcce381fcbcf9a1cc2a7c",
            "tree_root_sha256": PINNED_G3_TREE_ROOT_SHA256,
        }
    ):
        fail("invalid independently pinned g4 freeze lock")
    entries = lock.get("inventory")
    if not isinstance(entries, list) or not entries:
        fail("invalid g4 freeze inventory")
    paths = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"bytes", "mode", "path", "sha256"}:
            fail("invalid g4 freeze inventory entry")
        relative = normalized_relative_path(entry["path"], "g4 freeze inventory path")
        if not (
            relative.startswith("research/provider-free-roadmap/g4/v1/")
            or relative == "tests/provider-free-roadmap/test_g4_claim_gates.py"
        ):
            fail("g4 freeze inventory escaped its scope")
        if (
            isinstance(entry["bytes"], bool) or not isinstance(entry["bytes"], int)
            or entry["bytes"] < 0 or entry["mode"] not in {"0644", "0755"}
            or not isinstance(entry["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is None
        ):
            fail("invalid g4 freeze inventory metadata")
        paths.append(relative)
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        fail("g4 freeze inventory paths must be unique and sorted")
    encoded = json.dumps(entries, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    actual_tree = hashlib.sha256(b"contextguard.g4-freeze-tree/v1\x00" + encoded).hexdigest()
    if actual_tree != lock["tree_root_sha256"]:
        fail("g4 freeze tree root mismatch")
    return raw, lock


def enumerate_g4_scope(root: Path) -> set[str]:
    base_relative = "research/provider-free-roadmap/g4/v1"
    base = root / base_relative
    try:
        metadata = base.lstat()
    except OSError:
        fail("missing g4 frozen scope")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        fail("unsafe g4 frozen scope")
    result = set()
    pending = [(base, base_relative)]
    while pending:
        directory, relative_directory = pending.pop()
        with os.scandir(directory) as iterator:
            for entry in iterator:
                relative = f"{relative_directory}/{entry.name}"
                metadata = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode):
                    fail(f"symlink in g4 frozen scope: {relative}")
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append((Path(entry.path), relative))
                elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                    result.add(relative)
                else:
                    fail(f"unsafe path in g4 frozen scope: {relative}")
    test = "tests/provider-free-roadmap/test_g4_claim_gates.py"
    metadata = (root / test).lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        fail("unsafe g4 frozen test artifact")
    result.add(test)
    return result


def capture_g4_inventory(root: Path, lock: dict) -> dict[str, bytes]:
    expected = {str(entry["path"]) for entry in lock["inventory"]}
    actual = enumerate_g4_scope(root)
    if actual - expected:
        fail(f"unlisted g4 frozen artifact: {sorted(actual - expected)[0]}")
    if expected - actual:
        fail(f"missing g4 frozen artifact: {sorted(expected - actual)[0]}")
    result = {}
    for entry in lock["inventory"]:
        relative = str(entry["path"])
        raw = capture_regular_file(root, relative, "g4 frozen artifact")
        verify_captured_artifact(raw, {key: entry[key] for key in ("bytes", "path", "sha256")}, "g4 frozen artifact")
        if f"{stat.S_IMODE((root / relative).lstat().st_mode):04o}" != entry["mode"]:
            fail(f"changed g4 frozen artifact mode: {relative}")
        result[relative] = raw
    required = {
        "research/provider-free-roadmap/g4/v1/README.md",
        "research/provider-free-roadmap/g4/v1/claim-policy.json",
        "research/provider-free-roadmap/g4/v1/verify.py",
        "tests/provider-free-roadmap/test_g4_claim_gates.py",
    }
    if not required <= set(result) or not any("/g4/v1/schemas/" in path for path in result):
        fail("g4 freeze inventory is incomplete")
    return result


def execute_verified_g4_profile_bytes(
    executable: Path, root: Path, pinned_filename: str, test_raw: bytes,
    g4_inventory: dict[str, bytes], g3_inventory: dict[str, bytes],
    g4_lock_raw: bytes, g3_lock_raw: bytes, g2_verifier_raw: bytes,
    g2_lock_raw: bytes, child_environment: dict[str, str],
) -> subprocess.CompletedProcess[bytes]:
    if hashlib.sha256(PINNED_G4_PROFILE_BOOTSTRAP).hexdigest() != PINNED_G4_PROFILE_BOOTSTRAP_SHA256:
        fail("invalid pinned g4 profile bootstrap")
    g4_prefix = "research/provider-free-roadmap/g4/v1/"
    g3_prefix = "research/provider-free-roadmap/g3/v1/"
    encode = lambda raw: base64.b64encode(raw).decode("ascii")
    payload = {
        "g2_lock": encode(g2_lock_raw), "g2_verifier": encode(g2_verifier_raw),
        "g3_cost_model": encode(g3_inventory[g3_prefix + "cost-model.json"]),
        "g3_lock": encode(g3_lock_raw),
        "g3_manifest": encode(g3_inventory[g3_prefix + "manifest.json"]),
        "g3_runner": encode(g3_inventory[g3_prefix + "rehearse.py"]),
        "g3_schemas": {
            path.removeprefix(g3_prefix + "schemas/"): encode(raw)
            for path, raw in g3_inventory.items() if path.startswith(g3_prefix + "schemas/")
        },
        "g4_policy": encode(g4_inventory[g4_prefix + "claim-policy.json"]),
        "g4_schemas": {
            path.removeprefix(g4_prefix + "schemas/"): encode(raw)
            for path, raw in g4_inventory.items() if path.startswith(g4_prefix + "schemas/")
        },
        "g4_verifier": encode(g4_inventory[g4_prefix + "verify.py"]),
        "test": encode(test_raw),
    }
    return run_bounded_profile(
        "g4-claim-gates",
        [str(executable), "-I", "-B", "-c", PINNED_G4_PROFILE_BOOTSTRAP.decode("ascii"), pinned_filename],
        root,
        {"LANG": child_environment["LANG"]},
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii"),
    )


def verify_independently_pinned_g5_lock(root: Path, profile: dict) -> tuple[bytes, dict]:
    artifact = profile.get("g5_lock_artifact")
    if not isinstance(artifact, dict):
        fail("invalid g5 freeze lock artifact")
    relative = normalized_relative_path(artifact.get("path"), "g5 freeze lock artifact")
    if relative != PINNED_G5_LOCK_PATH:
        fail("invalid g5 freeze lock path")
    raw = capture_regular_file(root, relative, "independently pinned g5 freeze lock")
    verify_captured_artifact(raw, artifact, "independently pinned g5 freeze lock")
    if hashlib.sha256(raw).hexdigest() != PINNED_G5_LOCK_SHA256:
        fail("changed independently pinned g5 freeze lock")
    lock = load_json_bytes(raw, relative)
    if (
        set(lock) != {"algorithm", "g4_source", "inventory", "schema_version", "tree_root_sha256"}
        or lock.get("algorithm") != "sha256"
        or lock.get("schema_version") != "contextguard.g5-freeze-lock/v1"
        or lock.get("tree_root_sha256") != PINNED_G5_TREE_ROOT_SHA256
        or lock.get("g4_source") != {
            "claim_policy_sha256": "522413abffa1a99ff74160d7f6055bffabf2a02eaded3bf3adc077d7ea19dee2",
            "lock_sha256": PINNED_G4_LOCK_SHA256,
            "schema_set_bytes": 6533,
            "schema_set_sha256": "c522aaca41495afaeb1430b830b6f038f96d25c47e783d004eb059f391124b3d",
            "tree_root_sha256": PINNED_G4_TREE_ROOT_SHA256,
            "verifier_sha256": "60296da05f0418287a7a74fe9d98e0c8e38befaf5dad59b9d11ff4ce07a2884b",
        }
    ):
        fail("invalid independently pinned g5 freeze lock")
    entries = lock.get("inventory")
    if not isinstance(entries, list) or not entries:
        fail("invalid g5 freeze inventory")
    paths = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"bytes", "mode", "path", "sha256"}:
            fail("invalid g5 freeze inventory entry")
        item_path = normalized_relative_path(entry["path"], "g5 freeze inventory path")
        if not (
            item_path.startswith("research/provider-free-roadmap/g5/v1/")
            or item_path == "tests/provider-free-roadmap/test_g5_p2_preregistration.py"
        ):
            fail("g5 freeze inventory escaped its scope")
        if (
            isinstance(entry["bytes"], bool) or not isinstance(entry["bytes"], int)
            or entry["bytes"] < 0 or entry["mode"] not in {"0644", "0755"}
            or not isinstance(entry["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is None
        ):
            fail("invalid g5 freeze inventory metadata")
        paths.append(item_path)
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        fail("g5 freeze inventory paths must be unique and sorted")
    encoded = json.dumps(entries, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    actual_tree = hashlib.sha256(b"contextguard.g5-freeze-tree/v1\x00" + encoded).hexdigest()
    if actual_tree != lock["tree_root_sha256"]:
        fail("g5 freeze tree root mismatch")
    return raw, lock


def enumerate_g5_scope(root: Path) -> set[str]:
    base_relative = "research/provider-free-roadmap/g5/v1"
    base = root / base_relative
    try:
        metadata = base.lstat()
    except OSError:
        fail("missing g5 frozen scope")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        fail("unsafe g5 frozen scope")
    result: set[str] = set()
    pending = [(base, base_relative)]
    while pending:
        directory, relative_directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError:
            fail(f"unreadable g5 frozen scope: {relative_directory}")
        for entry in entries:
            relative = f"{relative_directory}/{entry.name}"
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                fail(f"symlink in g5 frozen scope: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append((Path(entry.path), relative))
            elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                result.add(relative)
            else:
                fail(f"unsafe path in g5 frozen scope: {relative}")
    test = "tests/provider-free-roadmap/test_g5_p2_preregistration.py"
    metadata = (root / test).lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        fail("unsafe g5 frozen test artifact")
    result.add(test)
    return result


def capture_g5_inventory(root: Path, lock: dict) -> dict[str, bytes]:
    expected = {str(entry["path"]) for entry in lock["inventory"]}
    actual = enumerate_g5_scope(root)
    if actual - expected:
        fail(f"unlisted g5 frozen artifact: {sorted(actual - expected)[0]}")
    if expected - actual:
        fail(f"missing g5 frozen artifact: {sorted(expected - actual)[0]}")
    result = {}
    for entry in lock["inventory"]:
        relative = str(entry["path"])
        raw = capture_regular_file(root, relative, "g5 frozen artifact")
        verify_captured_artifact(raw, {key: entry[key] for key in ("bytes", "path", "sha256")}, "g5 frozen artifact")
        if f"{stat.S_IMODE((root / relative).lstat().st_mode):04o}" != entry["mode"]:
            fail(f"changed g5 frozen artifact mode: {relative}")
        result[relative] = raw
    required = {
        "research/provider-free-roadmap/g5/v1/README.md",
        "research/provider-free-roadmap/g5/v1/preregistration.json",
        "research/provider-free-roadmap/g5/v1/schedule.json",
        "research/provider-free-roadmap/g5/v1/verify.py",
        "tests/provider-free-roadmap/test_g5_p2_preregistration.py",
    }
    if not required <= set(result) or len([path for path in result if "/g5/v1/schemas/" in path]) != 3:
        fail("g5 freeze inventory is incomplete")
    return result


def execute_verified_g5_profile_bytes(
    executable: Path, root: Path, pinned_filename: str, test_raw: bytes,
    g5_inventory: dict[str, bytes], g4_inventory: dict[str, bytes],
    g4_lock_raw: bytes, child_environment: dict[str, str],
) -> subprocess.CompletedProcess[bytes]:
    if hashlib.sha256(PINNED_G5_PROFILE_BOOTSTRAP).hexdigest() != PINNED_G5_PROFILE_BOOTSTRAP_SHA256:
        fail("invalid pinned g5 profile bootstrap")
    g5_prefix = "research/provider-free-roadmap/g5/v1/"
    g4_prefix = "research/provider-free-roadmap/g4/v1/"
    encode = lambda raw: base64.b64encode(raw).decode("ascii")
    payload = {
        "g4_lock": encode(g4_lock_raw),
        "g4_policy": encode(g4_inventory[g4_prefix + "claim-policy.json"]),
        "g4_schemas": {
            path.removeprefix(g4_prefix + "schemas/"): encode(raw)
            for path, raw in g4_inventory.items() if path.startswith(g4_prefix + "schemas/")
        },
        "g4_verifier": encode(g4_inventory[g4_prefix + "verify.py"]),
        "g5_prereg": encode(g5_inventory[g5_prefix + "preregistration.json"]),
        "g5_schedule": encode(g5_inventory[g5_prefix + "schedule.json"]),
        "g5_schemas": {
            path.removeprefix(g5_prefix + "schemas/"): encode(raw)
            for path, raw in g5_inventory.items() if path.startswith(g5_prefix + "schemas/")
        },
        "g5_verifier": encode(g5_inventory[g5_prefix + "verify.py"]),
        "test": encode(test_raw),
    }
    return run_bounded_profile(
        "g5-p2-preregistration",
        [str(executable), "-I", "-B", "-c", PINNED_G5_PROFILE_BOOTSTRAP.decode("ascii"), pinned_filename],
        root,
        {"LANG": child_environment["LANG"]},
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii"),
    )


def verify_independently_pinned_g6_lock(root: Path, profile: dict) -> tuple[bytes, dict]:
    artifact = profile.get("g6_lock_artifact")
    if not isinstance(artifact, dict):
        fail("invalid g6 freeze lock artifact")
    relative = normalized_relative_path(artifact.get("path"), "g6 freeze lock artifact")
    if relative != PINNED_G6_LOCK_PATH:
        fail("invalid g6 freeze lock path")
    raw = capture_regular_file(root, relative, "independently pinned g6 freeze lock")
    verify_captured_artifact(raw, artifact, "independently pinned g6 freeze lock")
    if hashlib.sha256(raw).hexdigest() != PINNED_G6_LOCK_SHA256:
        fail("changed independently pinned g6 freeze lock")
    lock = load_json_bytes(raw, relative)
    if (
        set(lock) != {"algorithm", "g5_source", "inventory", "schema_version", "tree_root_sha256"}
        or lock.get("algorithm") != "sha256"
        or lock.get("schema_version") != "contextguard.g6-freeze-lock/v1"
        or lock.get("tree_root_sha256") != PINNED_G6_TREE_ROOT_SHA256
        or lock.get("g5_source") != {
            "lock_sha256": PINNED_G5_LOCK_SHA256,
            "preregistration_sha256": "6aed6f0818d5364d052eb98413be3cf57342f13374d1c421605b2bb4526654af",
            "schedule_sha256": "326fc47df7871e39b2f9af2d888b8385ab91fe4347c6467f08dd4a6e386e7965",
            "schema_set_bytes": 41710,
            "schema_set_sha256": "7667de85f2fb71ef84b57f4edf7544a30d5a171043567b30e49fdab1b5f161b6",
            "tree_root_sha256": PINNED_G5_TREE_ROOT_SHA256,
            "verifier_sha256": "0a6952142804247c443300d28dac6345175a61d19ceaa00273840459a46e6672",
        }
    ):
        fail("invalid independently pinned g6 freeze lock")
    entries = lock.get("inventory")
    if not isinstance(entries, list) or not entries:
        fail("invalid g6 freeze inventory")
    paths = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"bytes", "mode", "path", "sha256"}:
            fail("invalid g6 freeze inventory entry")
        item_path = normalized_relative_path(entry["path"], "g6 freeze inventory path")
        if not (
            item_path.startswith("research/provider-free-roadmap/g6/v1/")
            or item_path == "tests/provider-free-roadmap/test_g6_approval_packet.py"
        ):
            fail("g6 freeze inventory escaped its scope")
        if (
            isinstance(entry["bytes"], bool) or not isinstance(entry["bytes"], int)
            or entry["bytes"] < 0 or entry["mode"] != "0644"
            or not isinstance(entry["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is None
        ):
            fail("invalid g6 freeze inventory metadata")
        paths.append(item_path)
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        fail("g6 freeze inventory paths must be unique and sorted")
    encoded = json.dumps(entries, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    actual_tree = hashlib.sha256(b"contextguard.g6-freeze-tree/v1\x00" + encoded).hexdigest()
    if actual_tree != lock["tree_root_sha256"]:
        fail("g6 freeze tree root mismatch")
    return raw, lock


def enumerate_g6_scope(root: Path) -> set[str]:
    base_relative = "research/provider-free-roadmap/g6/v1"
    base = root / base_relative
    try:
        metadata = base.lstat()
    except OSError:
        fail("missing g6 frozen scope")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        fail("unsafe g6 frozen scope")
    result: set[str] = set()
    pending = [(base, base_relative)]
    while pending:
        directory, relative_directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError:
            fail(f"unreadable g6 frozen scope: {relative_directory}")
        for entry in entries:
            relative = f"{relative_directory}/{entry.name}"
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                fail(f"symlink in g6 frozen scope: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append((Path(entry.path), relative))
            elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                result.add(relative)
            else:
                fail(f"unsafe path in g6 frozen scope: {relative}")
    test = "tests/provider-free-roadmap/test_g6_approval_packet.py"
    try:
        metadata = (root / test).lstat()
    except OSError:
        fail("missing g6 frozen test artifact")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        fail("unsafe g6 frozen test artifact")
    result.add(test)
    return result


def capture_g6_inventory(root: Path, lock: dict) -> dict[str, bytes]:
    expected = {str(entry["path"]) for entry in lock["inventory"]}
    actual = enumerate_g6_scope(root)
    if actual - expected:
        fail(f"unlisted g6 frozen artifact: {sorted(actual - expected)[0]}")
    if expected - actual:
        fail(f"missing g6 frozen artifact: {sorted(expected - actual)[0]}")
    result = {}
    for entry in lock["inventory"]:
        relative = str(entry["path"])
        raw = capture_regular_file(root, relative, "g6 frozen artifact")
        verify_captured_artifact(
            raw, {key: entry[key] for key in ("bytes", "path", "sha256")},
            "g6 frozen artifact",
        )
        if f"{stat.S_IMODE((root / relative).lstat().st_mode):04o}" != entry["mode"]:
            fail(f"changed g6 frozen artifact mode: {relative}")
        result[relative] = raw
    required = {
        "research/provider-free-roadmap/g6/v1/README.md",
        "research/provider-free-roadmap/g6/v1/STATUS.md",
        "research/provider-free-roadmap/g6/v1/preparation-packet.json",
        "research/provider-free-roadmap/g6/v1/schemas/preparation-packet.schema.json",
        "research/provider-free-roadmap/g6/v1/verify.py",
        "tests/provider-free-roadmap/test_g6_approval_packet.py",
    }
    if set(result) != required:
        fail("g6 freeze inventory is incomplete")
    return result


def execute_verified_g6_profile_bytes(
    executable: Path, root: Path, pinned_filename: str, test_raw: bytes,
    g6_inventory: dict[str, bytes], g5_inventory: dict[str, bytes],
    g5_lock_raw: bytes, child_environment: dict[str, str],
) -> subprocess.CompletedProcess[bytes]:
    if hashlib.sha256(PINNED_G6_PROFILE_BOOTSTRAP).hexdigest() != PINNED_G6_PROFILE_BOOTSTRAP_SHA256:
        fail("invalid pinned g6 profile bootstrap")
    g6_prefix = "research/provider-free-roadmap/g6/v1/"
    g5_prefix = "research/provider-free-roadmap/g5/v1/"
    encode = lambda raw: base64.b64encode(raw).decode("ascii")
    payload = {
        "g5_lock": encode(g5_lock_raw),
        "g5_prereg": encode(g5_inventory[g5_prefix + "preregistration.json"]),
        "g5_schedule": encode(g5_inventory[g5_prefix + "schedule.json"]),
        "g5_schemas": {
            path.removeprefix(g5_prefix + "schemas/"): encode(raw)
            for path, raw in g5_inventory.items() if path.startswith(g5_prefix + "schemas/")
        },
        "g5_verifier": encode(g5_inventory[g5_prefix + "verify.py"]),
        "g6_packet": encode(g6_inventory[g6_prefix + "preparation-packet.json"]),
        "g6_schema": encode(g6_inventory[g6_prefix + "schemas/preparation-packet.schema.json"]),
        "g6_verifier": encode(g6_inventory[g6_prefix + "verify.py"]),
        "g6_inventory_paths": sorted(g6_inventory),
        "test": encode(test_raw),
    }
    return run_bounded_profile(
        "g6-prepared-unapproved",
        [str(executable), "-I", "-B", "-c", PINNED_G6_PROFILE_BOOTSTRAP.decode("ascii"), pinned_filename],
        root,
        {"LANG": child_environment["LANG"]},
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii"),
    )


def verify_independently_pinned_g2_lock(root: Path) -> tuple[bytes, dict]:
    raw = capture_regular_file(root, PINNED_G2_LOCK_PATH, "independently pinned g2 freeze lock")
    if hashlib.sha256(raw).hexdigest() != PINNED_G2_LOCK_SHA256:
        fail("changed independently pinned g2 freeze lock")
    lock = load_json_bytes(raw, PINNED_G2_LOCK_PATH)
    if lock.get("tree_root_sha256") != PINNED_G2_TREE_ROOT_SHA256:
        fail("changed independently pinned g2 tree root")
    return raw, lock


def verify_pinned_python(executable: Path, lock: dict) -> None:
    binding = lock.get("python_binding")
    if not isinstance(binding, dict) or set(binding) != {
        "bytes", "implementation", "path", "sha256", "version"
    }:
        fail("invalid pinned g2 Python binding")
    try:
        resolved = executable.resolve(strict=True)
        metadata_before = resolved.lstat()
        raw = resolved.read_bytes()
        metadata_after = resolved.lstat()
    except OSError:
        fail("current Python executable is unavailable")
    validate_safe_file_mode(metadata_before.st_mode, "pinned Python executable")
    if (
        not stat.S_ISREG(metadata_before.st_mode) or metadata_before.st_nlink != 1
        or (metadata_before.st_dev, metadata_before.st_ino, metadata_before.st_size, metadata_before.st_mtime_ns)
        != (metadata_after.st_dev, metadata_after.st_ino, metadata_after.st_size, metadata_after.st_mtime_ns)
    ):
        fail("unsafe pinned Python executable")
    actual = {
        "bytes": len(raw),
        "implementation": sys.implementation.name,
        "path": str(resolved),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    }
    if actual != binding:
        fail("changed pinned Python executable")


def run_profile(
    root: Path, contract_path: Path, profile_name: str, child_environment: dict[str, str]
) -> None:
    contract = validated_contract(contract_path)
    profile = contract["execution_profiles"].get(profile_name)
    if profile is None:
        fail(f"unknown provider-free execution profile: {profile_name}")
    pinned_filename, raw = verified_profile_test(root, profile)
    try:
        executable = Path(sys.executable).resolve(strict=True)
    except OSError:
        fail("current Python executable is unavailable")
    if profile_name == "g2-contract-tests":
        lock_raw, lock = verify_independently_pinned_g2_lock(root)
        _verifier_relative, verifier_raw = verified_g2_verifier(root, profile)
        verify_pinned_python(executable, lock)
        result = execute_verified_g2_profile_bytes(
            executable, root, pinned_filename, raw, verifier_raw, lock_raw,
            PINNED_G2_LOCK_SHA256, PINNED_G2_TREE_ROOT_SHA256, child_environment,
        )
        # Stable re-capture detects pathname drift during the child run.  The
        # child has already used captured bytes, never these mutable paths.
        pinned_filename_after, raw_after = verified_profile_test(root, profile)
        _relative_after, verifier_after = verified_g2_verifier(root, profile)
        lock_after, _ = verify_independently_pinned_g2_lock(root)
        if (
            pinned_filename_after != pinned_filename or raw_after != raw
            or verifier_after != verifier_raw or lock_after != lock_raw
        ):
            fail("g2 profile path drift after captured execution")
    elif profile_name == "g3-rehearsal-tests":
        g2_lock_raw, g2_lock = verify_independently_pinned_g2_lock(root)
        verify_pinned_python(executable, g2_lock)
        g3_lock_raw, g3_lock = verify_independently_pinned_g3_lock(root, profile)
        g3_inventory = capture_g3_inventory(root, g3_lock)
        g2_verifier_raw = verified_g3_g2_verifier(root, profile)
        result = execute_verified_g3_profile_bytes(
            executable, root, pinned_filename, raw, g3_inventory,
            g2_verifier_raw, g2_lock_raw, child_environment,
        )
        # Post-run re-capture detects pathname drift.  The child consumed only
        # the captured bytes injected above and never reopens mutable G3 source.
        pinned_after, test_after = verified_profile_test(root, profile)
        g2_lock_after, _ = verify_independently_pinned_g2_lock(root)
        g3_lock_after, g3_lock_value_after = verify_independently_pinned_g3_lock(root, profile)
        inventory_after = capture_g3_inventory(root, g3_lock_value_after)
        g2_verifier_after = verified_g3_g2_verifier(root, profile)
        if (
            pinned_after != pinned_filename or test_after != raw
            or g2_lock_after != g2_lock_raw or g3_lock_after != g3_lock_raw
            or inventory_after != g3_inventory or g2_verifier_after != g2_verifier_raw
        ):
            fail("g3 profile path drift after captured execution")
    elif profile_name == "g4-claim-gates":
        g2_lock_raw, g2_lock = verify_independently_pinned_g2_lock(root)
        verify_pinned_python(executable, g2_lock)
        g3_lock_raw, g3_lock = verify_independently_pinned_g3_lock(root, profile)
        g3_inventory = capture_g3_inventory(root, g3_lock)
        g4_lock_raw, g4_lock = verify_independently_pinned_g4_lock(root, profile)
        g4_inventory = capture_g4_inventory(root, g4_lock)
        g2_verifier_raw = verified_g3_g2_verifier(root, profile)
        result = execute_verified_g4_profile_bytes(
            executable, root, pinned_filename, raw, g4_inventory, g3_inventory,
            g4_lock_raw, g3_lock_raw, g2_verifier_raw, g2_lock_raw, child_environment,
        )
        pinned_after, test_after = verified_profile_test(root, profile)
        g2_lock_after, _ = verify_independently_pinned_g2_lock(root)
        g3_lock_after, g3_lock_value_after = verify_independently_pinned_g3_lock(root, profile)
        g3_inventory_after = capture_g3_inventory(root, g3_lock_value_after)
        g4_lock_after, g4_lock_value_after = verify_independently_pinned_g4_lock(root, profile)
        g4_inventory_after = capture_g4_inventory(root, g4_lock_value_after)
        g2_verifier_after = verified_g3_g2_verifier(root, profile)
        if (
            pinned_after != pinned_filename or test_after != raw
            or g2_lock_after != g2_lock_raw or g3_lock_after != g3_lock_raw
            or g3_inventory_after != g3_inventory or g4_lock_after != g4_lock_raw
            or g4_inventory_after != g4_inventory or g2_verifier_after != g2_verifier_raw
        ):
            fail("g4 profile path drift after captured execution")
    elif profile_name == "g5-p2-preregistration":
        g4_lock_raw, g4_lock = verify_independently_pinned_g4_lock(root, profile)
        g4_inventory = capture_g4_inventory(root, g4_lock)
        g5_lock_raw, g5_lock = verify_independently_pinned_g5_lock(root, profile)
        g5_inventory = capture_g5_inventory(root, g5_lock)
        result = execute_verified_g5_profile_bytes(
            executable, root, pinned_filename, raw, g5_inventory, g4_inventory,
            g4_lock_raw, child_environment,
        )
        pinned_after, test_after = verified_profile_test(root, profile)
        g4_lock_after, g4_lock_value_after = verify_independently_pinned_g4_lock(root, profile)
        g4_inventory_after = capture_g4_inventory(root, g4_lock_value_after)
        g5_lock_after, g5_lock_value_after = verify_independently_pinned_g5_lock(root, profile)
        g5_inventory_after = capture_g5_inventory(root, g5_lock_value_after)
        if (
            pinned_after != pinned_filename or test_after != raw
            or g4_lock_after != g4_lock_raw or g4_inventory_after != g4_inventory
            or g5_lock_after != g5_lock_raw or g5_inventory_after != g5_inventory
        ):
            fail("g5 profile path drift after captured execution")
    elif profile_name == "g6-prepared-unapproved":
        g5_lock_raw, g5_lock = verify_independently_pinned_g5_lock(root, profile)
        g5_inventory = capture_g5_inventory(root, g5_lock)
        g6_lock_raw, g6_lock = verify_independently_pinned_g6_lock(root, profile)
        g6_inventory = capture_g6_inventory(root, g6_lock)
        result = execute_verified_g6_profile_bytes(
            executable, root, pinned_filename, raw, g6_inventory, g5_inventory,
            g5_lock_raw, child_environment,
        )
        pinned_after, test_after = verified_profile_test(root, profile)
        g5_lock_after, g5_lock_value_after = verify_independently_pinned_g5_lock(root, profile)
        g5_inventory_after = capture_g5_inventory(root, g5_lock_value_after)
        g6_lock_after, g6_lock_value_after = verify_independently_pinned_g6_lock(root, profile)
        g6_inventory_after = capture_g6_inventory(root, g6_lock_value_after)
        if (
            pinned_after != pinned_filename or test_after != raw
            or g5_lock_after != g5_lock_raw or g5_inventory_after != g5_inventory
            or g6_lock_after != g6_lock_raw or g6_inventory_after != g6_inventory
        ):
            fail("g6 profile path drift after captured execution")
    else:
        result = execute_verified_profile_bytes(
            executable, root, pinned_filename, raw, child_environment,
        )
    if result.returncode != 0:
        sys.stdout.write(result.stdout.decode("utf-8", "replace"))
        sys.stderr.write(result.stderr.decode("utf-8", "replace"))
        fail(f"provider-free profile failed: {profile_name}")
    print(f"Provider-free profile {profile_name}: OK")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    subparsers = result.add_subparsers(dest="command", required=True)
    inventory = subparsers.add_parser("inventory")
    inventory.add_argument("--root", type=Path, default=REPO_ROOT)
    inventory.add_argument("--manifest", type=Path, required=True)
    run = subparsers.add_parser("run")
    run.add_argument("--root", type=Path, default=REPO_ROOT)
    run.add_argument("--contract", type=Path, required=True)
    run.add_argument("--profile", required=True)
    return result


def main() -> int:
    child_environment = validate_inherited_environment()
    arguments = parser().parse_args()
    if arguments.command == "inventory":
        verify_inventory(arguments.root.resolve(), arguments.manifest.resolve())
    else:
        run_profile(
            arguments.root.resolve(),
            arguments.contract.resolve(),
            arguments.profile,
            child_environment,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
