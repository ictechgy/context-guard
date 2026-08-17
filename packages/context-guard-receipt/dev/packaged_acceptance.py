"""Exercise an installed tarball without importing checkout test modules."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_NAME = "@ictechgy/context-guard-receipt"
PYTHON_ENV = "CONTEXT_GUARD_RECEIPT_PYTHON"
EXPECTED_BOUNDARY = {
    "evidence_class": "companion_local_receipt_only",
    "host_request_owned": False,
    "provider_claim_authority": False,
    "provider_join_status": "missing",
    "runtime_observer_present": False,
    "schema_version": "contextguard-receipt-evidence-boundary/v1",
    "selected_branch": "S2-UNSUPPORTED",
    "selected_transport": "NONE",
    "stage1_evidence": False,
    "stage2_evidence": False,
}


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"


def run(command: list[str], *, cwd: Path, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def run_binary(
    command: list[str], *, cwd: Path, environment: dict[str, str], input_bytes: bytes = b""
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def capture_frame(sequence: int, channel: int, payload: bytes) -> bytes:
    return (
        sequence.to_bytes(8, "big")
        + channel.to_bytes(1, "big")
        + len(payload).to_bytes(4, "big")
        + payload
    )


def evidence_descriptor(payload: bytes, relative_path: str, selection: dict[str, object]) -> bytes:
    return canonical_json(
        {
            "caller_classification": "eligible",
            "detector_signals": [],
            "payload_b64u": base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii"),
            "schema_version": "contextguard-receipt-evidence-descriptor/v1",
            "source": {"relative_path": relative_path, "selection": selection},
        }
    ).encode("ascii")


def twin_request(predicates: list[dict[str, object]]) -> bytes:
    return canonical_json(
        {
            "declared_next_action_sha256": "a" * 64,
            "expected_tail": None,
            "predicates": predicates,
            "schema_version": "contextguard-receipt-twin-request/v1",
        }
    ).encode("ascii")


def reference_expiry_request(capability: str, *, expires_at_unix_ms: int) -> bytes:
    return canonical_json(
        {
            "capability": capability,
            "expires_at_unix_ms": expires_at_unix_ms,
            "operation": "register",
            "schema_version": "contextguard-receipt-reference-expiry-request/v1",
        }
    ).encode("ascii")


def phase_evaluation_request() -> bytes:
    return canonical_json(
        {
            "activation_authorized": True,
            "baseline_fallback_verified": True,
            "dependency_gates_passed": True,
            "minimum_recall_basis_points": 9_000,
            "observed_at": 100,
            "phase_id": "p2",
            "records": [
                {
                    "candidate_omission": True,
                    "construction_cost_microunits": 12,
                    "fresh_until": 101,
                    "protection": "eligible",
                    "recalled": True,
                    "record_id": "installed-p2",
                    "rehydrated_digest": "sha256:" + "1" * 64,
                    "relevant": True,
                    "source_digest": "sha256:" + "1" * 64,
                    "stratum": "installed",
                }
            ],
            "schema_version": "contextguard.phase-evaluation.p2/v1",
        }
    ).encode("ascii")


def tree_snapshot(root: Path) -> dict[str, tuple[str, int, str]]:
    result: dict[str, tuple[str, int, str]] = {}
    for path in sorted((root, *root.rglob("*"))):
        metadata = path.lstat()
        relative = path.relative_to(root).as_posix() or "."
        if stat.S_ISDIR(metadata.st_mode):
            result[relative] = ("directory", stat.S_IMODE(metadata.st_mode), "")
        elif stat.S_ISREG(metadata.st_mode):
            result[relative] = (
                "regular",
                stat.S_IMODE(metadata.st_mode),
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
        else:
            result[relative] = ("other", stat.S_IMODE(metadata.st_mode), "")
    return result


def distribution() -> None:
    npm = shutil.which("npm")
    node = shutil.which("node")
    git = shutil.which("git")
    if npm is None or node is None or git is None:
        raise RuntimeError("npm, node, and Git are required")
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        pack_directory, install_directory, poisoned_bin = root / "pack", root / "install", root / "poisoned-bin"
        pack_directory.mkdir()
        install_directory.mkdir()
        poisoned_bin.mkdir()
        packed = run([npm, "pack", "--json", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", "--pack-destination", str(pack_directory), str(PACKAGE_ROOT)], cwd=pack_directory)
        if packed.returncode != 0:
            raise RuntimeError("offline npm pack failed")
        records = json.loads(packed.stdout)
        tarball = pack_directory / records[0]["filename"]
        with tarfile.open(tarball, "r:gz") as archive:
            if any(member.issym() for member in archive.getmembers()):
                raise RuntimeError("tarball contains a symlink")
        installed = run([npm, "install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", str(tarball)], cwd=install_directory)
        if installed.returncode != 0:
            raise RuntimeError("offline npm install failed")
        installed_root = install_directory / "node_modules" / PACKAGE_NAME
        if installed_root.is_symlink():
            raise RuntimeError("installed package root must not be a symlink")
        installed_root = installed_root.resolve()
        receipt_bin = installed_root / "bin/context-guard-receipt.cjs"
        mcp_bin = installed_root / "bin/context-guard-receipt-mcp.cjs"
        sentinel = root / "poisoned-helper-used"
        for name in ("context-guard", "context-guard-mcp", "python", "python3"):
            helper = poisoned_bin / name
            helper.write_text(f"#!/bin/sh\ntouch '{sentinel}'\nexit 99\n", encoding="utf-8")
            helper.chmod(0o755)
        environment = {"LANG": "C", "PATH": os.pathsep.join((str(poisoned_bin), str(Path(git).resolve().parent))), "PYTHONDONTWRITEBYTECODE": "1", PYTHON_ENV: str(Path(sys.executable).resolve())}
        response = run([str(Path(node).resolve()), str(receipt_bin), "inspect", "boundary"], cwd=install_directory, environment=environment)
        expected = {"evidence_boundary": EXPECTED_BOUNDARY, "operation": "inspect_boundary", "schema_version": "contextguard-receipt-cli-response/v1", "status": "ok"}
        if response.returncode != 0 or response.stdout != canonical_json(expected) or response.stderr or sentinel.exists():
            raise RuntimeError("installed receipt command failed its closed-boundary smoke test")
        evaluated = run_binary(
            [
                str(Path(node).resolve()),
                str(receipt_bin),
                "evaluate",
                "phase",
                "--input",
                "-",
            ],
            cwd=install_directory,
            environment=environment,
            input_bytes=phase_evaluation_request(),
        )
        try:
            evaluation = json.loads(evaluated.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("installed evaluator output was not JSON") from exc
        if (
            evaluated.returncode != 0
            or evaluated.stderr
            or evaluation.get("phase_id") != "p2"
            or evaluation.get("implementation_readiness") is not True
            or evaluation.get("activation_authority") is not False
            or evaluation.get("claim_authority") is not False
            or evaluation.get("fallback") != "exact_unchanged_baseline"
            or sentinel.exists()
        ):
            raise RuntimeError("installed receipt evaluator failed its closed local smoke test")
        missing_helper_environment = dict(environment)
        missing_helper_environment.pop(PYTHON_ENV)
        missing_helper_environment["PATH"] = str(root / "missing-runtime-helper")
        missing_helper = run_binary(
            [str(Path(node).resolve()), str(receipt_bin), "inspect", "boundary"],
            cwd=install_directory,
            environment=missing_helper_environment,
        )
        expected_missing_helper = canonical_json(
            {
                "evidence_boundary": EXPECTED_BOUNDARY,
                "operation": "launcher",
                "reason": "runtime_unavailable",
                "schema_version": "contextguard-receipt-cli-response/v1",
                "status": "error",
            }
        ).encode("ascii")
        if (
            missing_helper.returncode != 69
            or missing_helper.stdout
            or missing_helper.stderr != expected_missing_helper
            or sentinel.exists()
        ):
            raise RuntimeError("installed launcher did not fail closed when its runtime helper was missing")
        sanitizer_smoke = run(
            [
                str(Path(sys.executable).resolve()), "-I", "-S", "-B", "-c",
                (
                    "import sys\n"
                    "from pathlib import Path\n"
                    "installed = Path(sys.argv[1]).resolve()\n"
                    "sys.path.insert(0, str(installed))\n"
                    "from context_guard_receipt import sanitizer\n"
                    "candidate = b'api_key=synthetic-test-value'\n"
                    "whole = sanitizer.sanitize_bytes(candidate)\n"
                    "stream = sanitizer.StreamingSanitizer()\n"
                    "stream.feed(candidate[:7])\n"
                    "stream.feed(candidate[7:])\n"
                    "split = stream.finish()\n"
                    "bytewise = sanitizer.StreamingSanitizer()\n"
                    "for byte in candidate:\n"
                    " bytewise.feed(bytes((byte,)))\n"
                    "assert whole.payload == split.payload == bytewise.finish().payload == b'[REDACTED SECRET]'\n"
                    "try:\n"
                    " sanitizer.sanitize_bytes(b'opaque-probe', limits=sanitizer.SanitizerLimits(max_input_bytes=0))\n"
                    "except sanitizer.SanitizationError as error:\n"
                    " assert error.code is sanitizer.SanitizationErrorCode.INPUT_LIMIT_EXCEEDED\n"
                    " assert 'opaque-probe' not in str(error)\n"
                    " assert 'opaque-probe' not in repr(error)\n"
                    "else:\n"
                    " raise AssertionError('expected sanitizer input failure')\n"
                    "assert Path(sanitizer.__file__).resolve().is_relative_to(installed)"
                ),
                str(installed_root / "python"),
            ],
            cwd=install_directory,
            environment={"LANG": "C", "PYTHONDONTWRITEBYTECODE": "1"},
        )
        if sanitizer_smoke.returncode != 0 or sanitizer_smoke.stdout or sanitizer_smoke.stderr:
            raise RuntimeError("installed sanitizer direct-import smoke test failed")
        repository_root = (root / "repository").resolve()
        repository_root.mkdir(mode=0o700)
        payload = (b"expand\x00\xff" * 2_048) + b"done"
        (repository_root / "source.bin").write_bytes(payload)
        state_directory = (root / "private-state").resolve()

        command_repository_root = (root / "command-repository").resolve()
        command_repository_root.mkdir(mode=0o700)
        initialized = run(
            [str(Path(git).resolve()), "init", "--quiet", str(command_repository_root)],
            cwd=root,
            environment={
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_NOSYSTEM": "1",
                "LANG": "C",
                "PATH": os.defpath,
            },
        )
        if initialized.returncode != 0:
            raise RuntimeError("local command-capture worktree initialization failed")
        command_state_directory = (root / "command-state").resolve()
        command_stdout = b"SAFE_OUTPUT\n"
        private_arguments = (
            b"synthetic-private-secret-g008",
            b"synthetic-private-argv-g008",
            b"synthetic-private-path-g008",
        )
        captured = run_binary(
            [
                str(Path(node).resolve()),
                str(receipt_bin),
                "run",
                "--escrow",
                "--root",
                str(command_repository_root),
                "--state-dir",
                str(command_state_directory),
                "--",
                str(Path(sys.executable).resolve()),
                "-I",
                "-S",
                "-B",
                "-c",
                (
                    "import os,sys; "
                    "os.write(1,bytes.fromhex('534146455f4f55545055540a')); "
                    "os.write(2,sys.argv[1].encode('ascii'))"
                ),
                *(value.decode("ascii") for value in private_arguments),
            ],
            cwd=install_directory,
            environment=environment,
        )
        if captured.returncode != 0 or captured.stderr or sentinel.exists():
            raise RuntimeError("installed command capture failed its offline smoke test")
        try:
            receipt = json.loads(captured.stdout)
            handle = receipt["handle"]
            observation = receipt["observation"]
        except (json.JSONDecodeError, KeyError, TypeError):
            raise RuntimeError("installed command capture emitted an invalid receipt") from None
        if (
            captured.stdout != canonical_json(receipt).encode("ascii")
            or not isinstance(handle, str)
            or len(handle) != 49
            or not handle.startswith("cgr1p_")
            or set(observation) != {"after_sha256", "before_sha256", "scope"}
            or observation["scope"] != "worktree"
            or receipt.get("stderr")
            != {
                "argument_derived_output_redacted": True,
                "excerpt": "",
                "frame_count": 0,
                "sanitized_bytes": 0,
            }
            or any(value in captured.stdout for value in private_arguments)
            or str(command_repository_root).encode() in captured.stdout
            or str(command_state_directory).encode() in captured.stdout
        ):
            raise RuntimeError("installed command receipt violated its closed privacy contract")

        receipt_validator = run_binary(
            [
                str(Path(sys.executable).resolve()),
                "-I",
                "-S",
                "-B",
                "-c",
                (
                    "import json,sys\n"
                    "from pathlib import Path\n"
                    "installed = Path(sys.argv[1]).resolve()\n"
                    "sys.path.insert(0, str(installed))\n"
                    "from context_guard_receipt import runner\n"
                    "receipt = json.loads(sys.stdin.buffer.read())\n"
                    "assert runner.validate_command_capture_receipt(receipt)\n"
                    "assert Path(runner.__file__).resolve().is_relative_to(installed)\n"
                ),
                str(installed_root / "python"),
            ],
            cwd=install_directory,
            environment={"LANG": "C", "PYTHONDONTWRITEBYTECODE": "1"},
            input_bytes=captured.stdout,
        )
        if receipt_validator.returncode != 0 or receipt_validator.stdout or receipt_validator.stderr:
            raise RuntimeError("installed runner receipt validator failed")

        (command_repository_root / "after-capture.txt").write_text(
            "worktree drift after capture\n", encoding="utf-8"
        )
        command_expanded = run_binary(
            [
                str(Path(node).resolve()),
                str(receipt_bin),
                "expand",
                handle,
                "--root",
                str(command_repository_root),
                "--state-dir",
                str(command_state_directory),
                "--emit",
                "bytes",
            ],
            cwd=install_directory,
            environment=environment,
        )
        expected_capture = (
            b"CGRF1\x00"
            + capture_frame(0, 1, command_stdout)
        )
        if (
            command_expanded.returncode != 0
            or command_expanded.stdout != expected_capture
            or command_expanded.stderr
            or any(value in command_expanded.stdout for value in private_arguments)
            or sentinel.exists()
        ):
            raise RuntimeError("installed historical command capture did not expand exactly")

        frame_validator = run_binary(
            [
                str(Path(sys.executable).resolve()),
                "-I",
                "-S",
                "-B",
                "-c",
                (
                    "import sys\n"
                    "from pathlib import Path\n"
                    "installed = Path(sys.argv[1]).resolve()\n"
                    "sys.path.insert(0, str(installed))\n"
                    "from context_guard_receipt.runner import validate_framed_capture\n"
                    "frames = validate_framed_capture(sys.stdin.buffer.read())\n"
                    "assert tuple(frame.channel for frame in frames) == (1,)\n"
                ),
                str(installed_root / "python"),
            ],
            cwd=install_directory,
            environment={"LANG": "C", "PYTHONDONTWRITEBYTECODE": "1"},
            input_bytes=command_expanded.stdout,
        )
        if frame_validator.returncode != 0 or frame_validator.stdout or frame_validator.stderr:
            raise RuntimeError("installed runner frame validator failed")

        failing_private_argument = b"synthetic-private-failure-g013"
        failed_command_state = (root / "failed-command-state").resolve()
        failed_command = run_binary(
            [
                str(Path(node).resolve()), str(receipt_bin), "run", "--escrow", "--root",
                str(command_repository_root), "--state-dir", str(failed_command_state),
                "--", str(Path(sys.executable).resolve()), "-I", "-S", "-B", "-c",
                "import sys; sys.exit(17)", failing_private_argument.decode("ascii"),
            ],
            cwd=install_directory,
            environment=environment,
        )
        try:
            failed_receipt = json.loads(failed_command.stdout)
            failed_handle = failed_receipt["handle"]
        except (json.JSONDecodeError, KeyError, TypeError):
            raise RuntimeError("installed child failure did not emit a receipt") from None
        failed_expansion = run_binary(
            [
                str(Path(node).resolve()), str(receipt_bin), "expand", failed_handle,
                "--root", str(command_repository_root), "--state-dir",
                str(failed_command_state), "--emit", "bytes",
            ],
            cwd=install_directory,
            environment=environment,
        )
        if (
            failed_command.returncode != 17
            or failed_command.stderr
            or failed_command.stdout != canonical_json(failed_receipt).encode("ascii")
            or failed_receipt.get("outcome") != {"exit_code": 17, "kind": "exited"}
            or not isinstance(failed_handle, str)
            or failed_expansion.returncode != 0
            or failed_expansion.stdout != b"CGRF1\x00"
            or failed_expansion.stderr
            or any(
                failing_private_argument in output
                for output in (
                    failed_command.stdout,
                    failed_command.stderr,
                    failed_expansion.stdout,
                    failed_expansion.stderr,
                )
            )
            or sentinel.exists()
        ):
            raise RuntimeError("installed child failure escaped its bounded expandable receipt")

        descriptor = json.dumps(
            {
                "caller_classification": "eligible",
                "detector_signals": [],
                "payload_b64u": base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii"),
                "schema_version": "contextguard-receipt-evidence-descriptor/v1",
                "source": {"relative_path": "source.bin", "selection": {"kind": "file"}},
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8") + b"\n"
        assembled = run_binary(
            [
                str(Path(node).resolve()), str(receipt_bin), "assemble", "--kind", "evidence",
                "--descriptor", "-", "--root", str(repository_root), "--state-dir",
                str(state_directory), "--persist", "--emit", "bytes",
            ],
            cwd=install_directory,
            environment=environment,
            input_bytes=descriptor,
        )
        if assembled.returncode != 0 or assembled.stderr or sentinel.exists():
            raise RuntimeError("installed receipt assembly failed its binary stdin smoke test")
        try:
            artifact = json.loads(assembled.stdout)
            capability = artifact["capability"]
        except (json.JSONDecodeError, KeyError, TypeError):
            raise RuntimeError("installed receipt assembly did not emit a capability reference") from None
        if artifact.get("artifact_kind") != "evidence_reference" or not isinstance(capability, str):
            raise RuntimeError("installed receipt assembly emitted an invalid capability reference")
        expanded = run_binary(
            [
                str(Path(node).resolve()), str(receipt_bin), "expand", capability, "--root",
                str(repository_root), "--state-dir", str(state_directory), "--emit", "bytes",
            ],
            cwd=install_directory,
            environment=environment,
        )
        if (
            expanded.returncode != 0
            or expanded.stdout != payload
            or expanded.stderr
            or sentinel.exists()
        ):
            raise RuntimeError("installed receipt exact expansion failed its offline round trip")

        (repository_root / "source.bin").write_bytes(b"drifted-installed-g013")
        stale_expansion = run_binary(
            [
                str(Path(node).resolve()), str(receipt_bin), "expand", capability, "--root",
                str(repository_root), "--state-dir", str(state_directory), "--emit", "bytes",
            ],
            cwd=install_directory,
            environment=environment,
        )
        (repository_root / "source.bin").write_bytes(payload)
        reread_expansion = run_binary(
            [
                str(Path(node).resolve()), str(receipt_bin), "expand", capability, "--root",
                str(repository_root), "--state-dir", str(state_directory), "--emit", "bytes",
            ],
            cwd=install_directory,
            environment=environment,
        )
        try:
            stale_refusal = json.loads(stale_expansion.stderr)
        except (json.JSONDecodeError, TypeError):
            raise RuntimeError("installed stale expansion did not emit a refusal") from None
        if (
            stale_expansion.returncode != 65
            or stale_expansion.stdout
            or stale_refusal.get("status") != "stale"
            or reread_expansion.returncode != 0
            or reread_expansion.stdout != payload
            or reread_expansion.stderr
            or sentinel.exists()
        ):
            raise RuntimeError("installed source drift did not stale then reread exactly")

        range_source = b"range-boundary-installed-g013"
        (repository_root / "range.bin").write_bytes(range_source)
        for start, end in ((0, len(range_source)), (len(range_source) - 1, len(range_source))):
            selected = range_source[start:end]
            range_assembled = run_binary(
                [
                    str(Path(node).resolve()), str(receipt_bin), "assemble", "--kind", "evidence",
                    "--descriptor", "-", "--root", str(repository_root), "--emit", "json",
                ],
                cwd=install_directory,
                environment=environment,
                input_bytes=evidence_descriptor(
                    selected,
                    "range.bin",
                    {"end_byte": end, "kind": "range", "start_byte": start},
                ),
            )
            try:
                range_result = json.loads(range_assembled.stdout)
                range_output = base64.urlsafe_b64decode(
                    range_result["output_b64u"] + "=" * 3
                )
                range_receipt = range_result["receipt"]
            except (json.JSONDecodeError, KeyError, TypeError):
                raise RuntimeError("installed range boundary emitted invalid JSON") from None
            if (
                range_assembled.returncode != 0
                or range_assembled.stderr
                or range_assembled.stdout != canonical_json(range_result).encode("ascii")
                or range_output != selected
                or range_receipt.get("disposition") != "pass_through"
                or range_receipt.get("output", {}).get("form") != "exact_payload"
                or sentinel.exists()
            ):
                raise RuntimeError("installed range boundary did not preserve exact bytes")

        ambiguous_source = b"ambiguous-range-installed-g013"
        (repository_root / "ambiguous.bin").write_bytes(ambiguous_source)
        candidate = {
            "end_byte": len(ambiguous_source),
            "occurrence": 0,
            "qualified_name": "module.value",
            "raw_range_sha256": hashlib.sha256(ambiguous_source).hexdigest(),
            "start_byte": 0,
        }
        ambiguous_evidence = {
            "candidates": [candidate, candidate],
            "capped": False,
            "complete": True,
            "deterministic": True,
            "end_byte": len(ambiguous_source),
            "evidence_kind": "caller_supplied_symbol_range",
            "fallback_used": False,
            "language_id": "python",
            "occurrence": 0,
            "parser_error": False,
            "producer_id": "packaged-acceptance/1",
            "qualified_name": "module.value",
            "raw_range_sha256": hashlib.sha256(ambiguous_source).hexdigest(),
            "scan_complete": True,
            "schema_version": "contextguard-receipt-caller-symbol-evidence/v1",
            "source_sha256": hashlib.sha256(ambiguous_source).hexdigest(),
            "start_byte": 0,
        }
        ambiguous_assembled = run_binary(
            [
                str(Path(node).resolve()), str(receipt_bin), "assemble", "--kind", "evidence",
                "--descriptor", "-", "--root", str(repository_root), "--emit", "json",
            ],
            cwd=install_directory,
            environment=environment,
            input_bytes=evidence_descriptor(
                ambiguous_source,
                "ambiguous.bin",
                {"evidence": ambiguous_evidence, "kind": "symbol"},
            ),
        )
        try:
            ambiguous_result = json.loads(ambiguous_assembled.stdout)
            ambiguous_output = base64.urlsafe_b64decode(
                ambiguous_result["output_b64u"] + "=" * 3
            )
            ambiguous_receipt = ambiguous_result["receipt"]
        except (json.JSONDecodeError, KeyError, TypeError):
            raise RuntimeError("installed ambiguous range emitted invalid JSON") from None
        if (
            ambiguous_assembled.returncode != 0
            or ambiguous_assembled.stderr
            or ambiguous_assembled.stdout != canonical_json(ambiguous_result).encode("ascii")
            or ambiguous_output != ambiguous_source
            or ambiguous_receipt.get("disposition") != "pass_through"
            or ambiguous_receipt.get("output", {}).get("form") != "exact_payload"
            or sentinel.exists()
        ):
            raise RuntimeError("installed ambiguous range gained unsupported authority")

        store_before_expiry = tree_snapshot(state_directory / "store-v1")
        expiry_registered = run_binary(
            [
                str(Path(node).resolve()),
                str(receipt_bin),
                "inspect",
                "reference-expiry",
                "--experimental-reference-expiry",
                "--input",
                "-",
                "--root",
                str(repository_root),
                "--state-dir",
                str(state_directory),
            ],
            cwd=install_directory,
            environment=environment,
            input_bytes=reference_expiry_request(capability, expires_at_unix_ms=0),
        )
        expiry_denied = run_binary(
            [
                str(Path(node).resolve()),
                str(receipt_bin),
                "expand",
                capability,
                "--root",
                str(repository_root),
                "--state-dir",
                str(state_directory),
            ],
            cwd=install_directory,
            environment=environment,
        )
        expiry_inspected = run_binary(
            [
                str(Path(node).resolve()),
                str(receipt_bin),
                "inspect",
                "reference-expiry",
                "--experimental-reference-expiry",
                "--root",
                str(repository_root),
                "--state-dir",
                str(state_directory),
                "--limit",
                "1",
            ],
            cwd=install_directory,
            environment=environment,
        )
        try:
            expiry_result = json.loads(expiry_registered.stdout)
            expiry_snapshot = json.loads(expiry_inspected.stdout)
        except (json.JSONDecodeError, TypeError):
            raise RuntimeError("installed reference expiry emitted invalid JSON") from None
        private_expiry_values = (
            capability.encode("ascii"),
            str(repository_root).encode(),
            str(state_directory).encode(),
            payload,
        )
        if (
            expiry_registered.returncode != 0
            or expiry_registered.stderr
            or expiry_denied.returncode != 65
            or expiry_denied.stdout
            or json.loads(expiry_denied.stderr).get("reason") != "capability_rejected"
            or expiry_inspected.returncode != 0
            or expiry_inspected.stderr
            or expiry_result.get("evidence_boundary") != EXPECTED_BOUNDARY
            or expiry_snapshot.get("evidence_boundary") != EXPECTED_BOUNDARY
            or expiry_result.get("retained_artifacts") is not True
            or expiry_result.get("artifact_cleanup_performed") is not False
            or expiry_snapshot.get("expired_reference_count") != 1
            or expiry_snapshot.get("state_location")
            != {
                "compartment": "auxiliary-v1/reference-expiry-v1",
                "scope": "explicit_state_dir",
            }
            or tree_snapshot(state_directory / "store-v1") != store_before_expiry
            or any(
                private_value in output
                for private_value in private_expiry_values
                for output in (expiry_registered.stdout, expiry_inspected.stdout)
            )
            or sentinel.exists()
        ):
            raise RuntimeError("installed reference expiry failed its retained-artifact smoke test")

        shutil.rmtree(state_directory / "auxiliary-v1/reference-expiry-v1")
        restored_expansion = run_binary(
            [
                str(Path(node).resolve()),
                str(receipt_bin),
                "expand",
                capability,
                "--root",
                str(repository_root),
                "--state-dir",
                str(state_directory),
                "--emit",
                "bytes",
            ],
            cwd=install_directory,
            environment=environment,
        )
        if (
            restored_expansion.returncode != 0
            or restored_expansion.stdout != payload
            or restored_expansion.stderr
            or tree_snapshot(state_directory / "store-v1") != store_before_expiry
        ):
            raise RuntimeError("removing expiry references did not restore retained artifact access")

        tool_catalog = [
            {
                "description": "inline" * 800,
                "input_schema": {"type": "object"},
                "name": "inline",
            },
            {
                "description": "deferred" * 800,
                "input_schema": {"type": "object"},
                "name": "deferred",
            },
        ]
        tool_payload = canonical_json(tool_catalog).encode("utf-8")
        tool_descriptor = canonical_json(
            {
                "catalog_format": "anthropic_tools/v1",
                "items": [
                    {
                        "caller_classification": "eligible",
                        "detector_signals": [],
                        "priority": 2 - index,
                        "required": False,
                    }
                    for index in range(2)
                ],
                "payload_b64u": base64.urlsafe_b64encode(tool_payload)
                .rstrip(b"=")
                .decode("ascii"),
                "retain_count": 1,
                "schema_version": "contextguard-receipt-tool-schema-descriptor/v1",
            }
        ).encode("utf-8")
        tool_assembled = run_binary(
            [
                str(Path(node).resolve()),
                str(receipt_bin),
                "assemble",
                "--kind",
                "tool-schemas",
                "--descriptor",
                "-",
                "--root",
                str(repository_root),
                "--state-dir",
                str(state_directory),
                "--persist",
                "--emit",
                "bytes",
            ],
            cwd=install_directory,
            environment=environment,
            input_bytes=tool_descriptor,
        )
        if tool_assembled.returncode != 0 or tool_assembled.stderr or sentinel.exists():
            raise RuntimeError("installed tool-schema assembly failed its offline smoke test")
        try:
            tool_bundle = json.loads(tool_assembled.stdout)
            catalog_reference = tool_bundle["catalog_reference"]
            item_reference = tool_bundle["deferred"][0]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError):
            raise RuntimeError("installed tool-schema assembly emitted an invalid bundle") from None
        if tool_bundle.get("artifact_kind") != "tool_schema_bundle":
            raise RuntimeError("installed tool-schema assembly emitted an invalid bundle")

        def expand_tool_schema(reference: object) -> subprocess.CompletedProcess[bytes]:
            request = canonical_json(
                {
                    "catalog_reference": catalog_reference,
                    "item_reference": reference,
                    "schema_version": "contextguard-receipt-tool-schema-expansion-request/v1",
                }
            ).encode("utf-8")
            return run_binary(
                [
                    str(Path(node).resolve()),
                    str(receipt_bin),
                    "expand",
                    "tool-schema",
                    "--request",
                    "-",
                    "--root",
                    str(repository_root),
                    "--state-dir",
                    str(state_directory),
                    "--emit",
                    "bytes",
                ],
                cwd=install_directory,
                environment=environment,
                input_bytes=request,
            )

        whole_catalog = expand_tool_schema(None)
        deferred_schema = expand_tool_schema(item_reference)
        expected_deferred_schema = canonical_json(tool_catalog[1]).encode("utf-8")[:-1]
        if (
            whole_catalog.returncode != 0
            or whole_catalog.stdout != tool_payload
            or whole_catalog.stderr
            or deferred_schema.returncode != 0
            or deferred_schema.stdout != expected_deferred_schema
            or deferred_schema.stderr
            or sentinel.exists()
        ):
            raise RuntimeError("installed tool-schema expansion failed its offline round trip")

        twin_directories_before_mcp = tuple(root.rglob("twin-v1"))
        mcp_input = b"".join(
            canonical_json(message).encode("ascii")
            for message in (
                {
                    "id": 1,
                    "jsonrpc": "2.0",
                    "method": "initialize",
                    "params": {
                        "capabilities": {},
                        "clientInfo": {"name": "packaged-acceptance", "version": "1"},
                        "protocolVersion": "2025-11-25",
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                    "params": {},
                },
                {"id": 2, "jsonrpc": "2.0", "method": "tools/list", "params": {}},
            )
        )
        mcp = run_binary(
            [str(Path(node).resolve()), str(mcp_bin), "--root", str(repository_root)],
            cwd=install_directory,
            environment=environment,
            input_bytes=mcp_input,
        )
        mcp_responses: list[dict[str, object]] = []
        try:
            mcp_responses = [json.loads(line) for line in mcp.stdout.splitlines()]
            mcp_tools = [
                tool["name"] for tool in mcp_responses[1]["result"]["tools"]
            ]
        except (IndexError, KeyError, TypeError, json.JSONDecodeError):
            mcp_tools = []
        mcp_shape_valid = bool(
            len(mcp_responses) == 2
            and isinstance(mcp_responses[0], dict)
            and mcp_responses[0].get("id") == 1
            and isinstance(mcp_responses[1], dict)
        )
        if (
            twin_directories_before_mcp
            or mcp.returncode != 0
            or mcp.stderr
            or not mcp_shape_valid
            or mcp_tools
            != [
                "receipt_assemble",
                "receipt_context",
                "receipt_diagnose",
                "receipt_expand",
                "receipt_inspect",
                "receipt_tool_select",
                "receipt_twin",
            ]
            or tuple(root.rglob("twin-v1")) != twin_directories_before_mcp
            or sentinel.exists()
        ):
            raise RuntimeError("installed MCP command failed its closed stdio smoke test")

        twin_repository_root = (root / "twin-repository").resolve()
        twin_state_directory = (root / "twin-state").resolve()
        twin_repository_root.mkdir(mode=0o700)
        private_relative_path = "synthetic-private-installed-twin-g010.txt"
        twin_appended = run_binary(
            [
                str(Path(node).resolve()),
                str(receipt_bin),
                "inspect",
                "twin",
                "--experimental-twin",
                "--input",
                "-",
                "--root",
                str(twin_repository_root),
                "--state-dir",
                str(twin_state_directory),
            ],
            cwd=install_directory,
            environment=environment,
            input_bytes=twin_request(
                [{"kind": "path_absent", "relative_path": private_relative_path}]
            ),
        )
        twin_inspected = run_binary(
            [
                str(Path(node).resolve()),
                str(receipt_bin),
                "inspect",
                "twin",
                "--experimental-twin",
                "--root",
                str(twin_repository_root),
                "--state-dir",
                str(twin_state_directory),
                "--limit",
                "1",
            ],
            cwd=install_directory,
            environment=environment,
        )
        try:
            twin_result = json.loads(twin_appended.stdout)
            twin_snapshot = json.loads(twin_inspected.stdout)
        except (json.JSONDecodeError, TypeError):
            raise RuntimeError("installed twin emitted invalid JSON") from None
        private_values = (
            private_relative_path.encode("ascii"),
            str(twin_repository_root).encode(),
            str(twin_state_directory).encode(),
        )
        authority_fields = (
            "applied",
            "execution_authority",
            "global_completeness_authority",
            "provider_claim_authority",
        )
        if (
            twin_appended.returncode != 0
            or twin_inspected.returncode != 0
            or twin_appended.stderr
            or twin_inspected.stderr
            or twin_appended.stdout != canonical_json(twin_result).encode("ascii")
            or twin_inspected.stdout != canonical_json(twin_snapshot).encode("ascii")
            or twin_result.get("evidence_boundary") != EXPECTED_BOUNDARY
            or twin_snapshot.get("evidence_boundary") != EXPECTED_BOUNDARY
            or twin_result.get("event_sequence") != 1
            or twin_snapshot.get("committed_event_count") != 1
            or len(twin_snapshot.get("latest_events", ())) != 1
            or any(twin_result.get(field) is not False for field in authority_fields)
            or any(twin_snapshot.get(field) is not False for field in authority_fields)
            or any(
                private_value in output
                for private_value in private_values
                for output in (twin_appended.stdout, twin_inspected.stdout)
            )
            or sentinel.exists()
        ):
            raise RuntimeError("installed twin failed its closed offline smoke test")

        unsafe_twin_state = twin_repository_root / "unsafe-state"
        unsafe_twin = run_binary(
            [
                str(Path(node).resolve()), str(receipt_bin), "inspect", "twin",
                "--experimental-twin", "--input", "-", "--root", str(twin_repository_root),
                "--state-dir", str(unsafe_twin_state),
            ],
            cwd=install_directory,
            environment=environment,
            input_bytes=twin_request(
                [{"kind": "path_absent", "relative_path": "never-created.txt"}]
            ),
        )
        unknown_sibling = twin_state_directory / "unknown-sibling-g013"
        unknown_sibling.write_text("untrusted", encoding="ascii")
        unknown_twin = run_binary(
            [
                str(Path(node).resolve()), str(receipt_bin), "inspect", "twin",
                "--experimental-twin", "--root", str(twin_repository_root),
                "--state-dir", str(twin_state_directory), "--limit", "1",
            ],
            cwd=install_directory,
            environment=environment,
        )
        expected_twin_unavailable = canonical_json(
            {
                "evidence_boundary": EXPECTED_BOUNDARY,
                "operation": "inspect_twin",
                "reason": "twin_unavailable",
                "schema_version": "contextguard-receipt-cli-response/v1",
                "status": "error",
            }
        ).encode("ascii")
        if (
            unsafe_twin.returncode != 74
            or unsafe_twin.stdout
            or unsafe_twin.stderr != expected_twin_unavailable
            or unknown_twin.returncode != 74
            or unknown_twin.stdout
            or unknown_twin.stderr != expected_twin_unavailable
            or sentinel.exists()
        ):
            raise RuntimeError("installed twin accepted an unsafe state or unknown sibling")

        partial_twin_root = (root / "partial-twin-repository").resolve()
        partial_twin_state = (root / "partial-twin-state").resolve()
        partial_twin_root.mkdir(mode=0o700)
        (partial_twin_root / "present.txt").write_text("present", encoding="ascii")
        partial_twin = run_binary(
            [
                str(Path(node).resolve()), str(receipt_bin), "inspect", "twin",
                "--experimental-twin", "--input", "-", "--root", str(partial_twin_root),
                "--state-dir", str(partial_twin_state),
            ],
            cwd=install_directory,
            environment=environment,
            input_bytes=twin_request(
                [
                    {"kind": "path_absent", "relative_path": "absent.txt"},
                    {"kind": "path_absent", "relative_path": "present.txt"},
                ]
            ),
        )
        try:
            partial_result = json.loads(partial_twin.stdout)
        except (json.JSONDecodeError, TypeError):
            raise RuntimeError("installed partial twin emitted invalid JSON") from None
        if (
            partial_twin.returncode != 0
            or partial_twin.stderr
            or partial_twin.stdout != canonical_json(partial_result).encode("ascii")
            or partial_result.get("predicate_count") != 2
            or partial_result.get("matched_predicate_count") != 1
            or partial_result.get("verified") is not False
            or any(partial_result.get(field) is not False for field in authority_fields)
            or sentinel.exists()
        ):
            raise RuntimeError("installed twin granted authority for partial predicates")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", choices=("distribution", "all"), default="all")
    arguments = parser.parse_args()
    try:
        distribution()
    except (OSError, RuntimeError, json.JSONDecodeError, tarfile.TarError) as exc:
        print(f"packaged acceptance failed: {exc}", file=sys.stderr)
        return 1
    print("packaged acceptance passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
