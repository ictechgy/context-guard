from __future__ import annotations

import hashlib
import json
import os
import py_compile
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = PACKAGE_ROOT.parents[1]
NODE = shutil.which("node")
PYTHON_ENV = "CONTEXT_GUARD_RECEIPT_PYTHON"

EVIDENCE_BOUNDARY = {
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
EXPECTED_BOUNDARY_RESPONSE = {
    "evidence_boundary": EVIDENCE_BOUNDARY,
    "operation": "inspect_boundary",
    "schema_version": "contextguard-receipt-cli-response/v1",
    "status": "ok",
}
EXPECTED_HELP = (
    "usage: context-guard-receipt <command>\n\n"
    "Commands:\n"
    "  inspect boundary\n"
    "  assemble --kind <kind> --descriptor <file|-> --root <absolute> [options]\n"
    "  run --escrow --root <absolute> --state-dir <absolute> "
    "[--timeout-seconds <positive-decimal> --max-channel-bytes <positive-decimal> "
    "--max-total-bytes <positive-decimal>] -- <absolute-command> [args...]\n"
    "  expand <handle> --root <absolute> --state-dir <absolute> [options]\n"
    "  expand tool-schema --request <file|-> --root <absolute> "
    "--state-dir <absolute> [options]\n"
    "  inspect <receipt|diagnostics|firewall|diagnostic-ledger|twin|lease|state> "
    "[options]\n\n"
    "Evidence, blueprint, and tool-schema assembly plus exact local expansion are available. "
    "Run is explicit local capture only. It is provider-free and makes no host-request, "
    "network, or token-saving claim. Other commands remain inert.\n"
)
EXPECTED_MCP_HELP = (
    "usage: context-guard-receipt-mcp --root <absolute-directory>\n\n"
    "The MCP transport is intentionally unavailable in this local-only companion.\n"
)
EXPECTED_PACKAGE = {
    "name": "@ictechgy/context-guard-receipt",
    "version": "0.1.0",
    "description": "Explicit local receipt workflows for bounded ContextGuard evidence.",
    "license": "Apache-2.0",
    "type": "commonjs",
    "bin": {
        "context-guard-receipt": "bin/context-guard-receipt.cjs",
        "context-guard-receipt-mcp": "bin/context-guard-receipt-mcp.cjs",
    },
    "files": [
        "LICENSE",
        "NOTICE",
        "README.md",
        "package-files.json",
        "bin/*.cjs",
        "python/**/*.py",
        "schemas/*.json",
    ],
    "engines": {"node": ">=18"},
    "os": ["darwin", "linux"],
}
EXPECTED_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://context-guard.local/schemas/receipt-evidence-boundary-v1.json",
    "title": "Context Guard Receipt evidence boundary",
    "type": "object",
    "additionalProperties": False,
    "required": sorted(EVIDENCE_BOUNDARY),
    "properties": {
        key: {"const": value}
        for key, value in EVIDENCE_BOUNDARY.items()
    },
}
EXPECTED_RUNTIME_MODES = {
    "LICENSE": 0o644,
    "NOTICE": 0o644,
    "README.md": 0o644,
    "bin/context-guard-receipt.cjs": 0o755,
    "bin/context-guard-receipt-mcp.cjs": 0o755,
    "bin/launcher.cjs": 0o644,
    "package-files.json": 0o644,
    "package.json": 0o644,
    "python/context_guard_receipt/__init__.py": 0o644,
    "python/context_guard_receipt/bootstrap.py": 0o644,
    "python/context_guard_receipt/assembly.py": 0o644,
    "python/context_guard_receipt/blueprint.py": 0o644,
    "python/context_guard_receipt/canonical.py": 0o644,
    "python/context_guard_receipt/cli.py": 0o644,
    "python/context_guard_receipt/cli_io.py": 0o644,
    "python/context_guard_receipt/contracts.py": 0o644,
    "python/context_guard_receipt/evidence_pack.py": 0o644,
    "python/context_guard_receipt/expansion.py": 0o644,
    "python/context_guard_receipt/identity.py": 0o644,
    "python/context_guard_receipt/protection.py": 0o644,
    "python/context_guard_receipt/receipts.py": 0o644,
    "python/context_guard_receipt/router.py": 0o644,
    "python/context_guard_receipt/runner.py": 0o644,
    "python/context_guard_receipt/sanitizer.py": 0o644,
    "python/context_guard_receipt/store.py": 0o644,
    "python/context_guard_receipt/tool_schemas.py": 0o644,
    "schemas/assembly-receipt.schema.json": 0o644,
    "schemas/blueprint-descriptor.schema.json": 0o644,
    "schemas/capability-record.schema.json": 0o644,
    "schemas/command-capture-receipt.schema.json": 0o644,
    "schemas/evidence-descriptor.schema.json": 0o644,
    "schemas/evidence-boundary.schema.json": 0o644,
    "schemas/evidence-pack.schema.json": 0o644,
    "schemas/evidence-reference.schema.json": 0o644,
    "schemas/expansion-envelope.schema.json": 0o644,
    "schemas/expansion-refusal.schema.json": 0o644,
    "schemas/protection-decision.schema.json": 0o644,
    "schemas/source-identity.schema.json": 0o644,
    "schemas/store-commit.schema.json": 0o644,
    "schemas/store-metadata.schema.json": 0o644,
    "schemas/typed-blueprint.schema.json": 0o644,
    "schemas/tool-schema-bundle.schema.json": 0o644,
    "schemas/tool-schema-catalog-reference.schema.json": 0o644,
    "schemas/tool-schema-descriptor.schema.json": 0o644,
    "schemas/tool-schema-expansion-envelope.schema.json": 0o644,
    "schemas/tool-schema-expansion-refusal.schema.json": 0o644,
    "schemas/tool-schema-expansion-request.schema.json": 0o644,
    "schemas/tool-schema-receipt.schema.json": 0o644,
    "schemas/tool-schema-reference.schema.json": 0o644,
}
EXPECTED_DEV_MODES = {
    "dev/package_check.py": 0o644,
    "dev/packaged_acceptance.py": 0o644,
}
FORBIDDEN_PACKAGE_PARTS = {
    ".env",
    ".npmrc",
    ".pypirc",
    "__pycache__",
    "auth.json",
    "cache",
    "settings.json",
    "state",
}


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"


def require_distribution() -> None:
    package_json = PACKAGE_ROOT / "package.json"
    if not package_json.is_file():
        raise AssertionError(f"G001 distribution is missing: {package_json}")
    if NODE is None:
        raise AssertionError("Node.js is required to exercise the receipt distribution")


def launcher_environment(**overrides: str) -> dict[str, str]:
    environment = {
        "LANG": "C",
        "PATH": os.defpath,
        "PYTHONDONTWRITEBYTECODE": "1",
        PYTHON_ENV: str(Path(sys.executable).resolve()),
    }
    environment.update(overrides)
    return environment


def run_node(
    entrypoint: str,
    *arguments: str,
    environment: dict[str, str] | None = None,
    package_root: Path = PACKAGE_ROOT,
    working_directory: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    require_distribution()
    return subprocess.run(
        [str(Path(NODE).resolve()), str(package_root / entrypoint), *arguments],
        cwd=working_directory or package_root,
        env=environment or launcher_environment(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def wait_for_process_exit(pid: int, timeout_seconds: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not process_exists(pid):
            return True
        time.sleep(0.02)
    return not process_exists(pid)


def read_child_record(path: Path, timeout_seconds: float = 5.0) -> tuple[int, int]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            child_pid, parent_pid = path.read_text(encoding="ascii").split(":", 1)
            return int(child_pid), int(parent_pid)
        except (FileNotFoundError, ValueError):
            time.sleep(0.02)
    raise AssertionError("timed out waiting for the observable child process")


def copy_runtime_with_current_launcher(destination: Path) -> Path:
    for relative_path in EXPECTED_RUNTIME_MODES:
        source = PACKAGE_ROOT / relative_path
        target = destination / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    launcher_path = destination / "bin/launcher.cjs"
    launcher = launcher_path.read_text(encoding="utf-8")
    for relative_path in EXPECTED_RUNTIME_MODES:
        if relative_path in {"bin/launcher.cjs", "package-files.json"}:
            continue
        digest = hashlib.sha256((destination / relative_path).read_bytes()).hexdigest()
        pattern = re.compile(
            rf"(  {re.escape(repr(relative_path))}: ')[0-9a-f]{{64}}(',\n)"
        )
        launcher, replacements = pattern.subn(rf"\g<1>{digest}\g<2>", launcher)
        if replacements != 1:
            raise AssertionError(f"missing trusted runtime entry: {relative_path}")
    launcher_path.write_text(launcher, encoding="utf-8")
    manifest_path = destination / "package-files.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for entry in manifest["files"]:
        entry["sha256"] = hashlib.sha256(
            (destination / entry["path"]).read_bytes()
        ).hexdigest()
    manifest_path.write_text(canonical_json(manifest), encoding="utf-8")
    return destination


def assert_json_error(
    testcase: unittest.TestCase,
    response: subprocess.CompletedProcess[str],
    *,
    code: int,
    operation: str,
    status: str,
    reason: str,
) -> None:
    expected = {
        "evidence_boundary": EVIDENCE_BOUNDARY,
        "operation": operation,
        "reason": reason,
        "schema_version": "contextguard-receipt-cli-response/v1",
        "status": status,
    }
    testcase.assertEqual(response.returncode, code, response.stderr)
    testcase.assertEqual(response.stdout, "")
    testcase.assertEqual(response.stderr, canonical_json(expected))


class G001DistributionContractTests(unittest.TestCase):
    def test_launcher_reports_closed_stdout_as_bounded_delivery_failure(self) -> None:
        """Break caught: final receipt delivery crashes with an unhandled EPIPE."""

        private_marker = "synthetic-private-launcher-delivery-g008"
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            runtime = copy_runtime_with_current_launcher(root / "runtime")
            state = root / "closed-consumer-state"
            process = subprocess.Popen(
                [
                    str(Path(NODE).resolve()),
                    str(runtime / "bin/context-guard-receipt.cjs"),
                    "run",
                    "--escrow",
                    "--root",
                    str(PACKAGE_ROOT.resolve()),
                    "--state-dir",
                    str(state),
                    "--",
                    str(Path(sys.executable).resolve()),
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    "import time; time.sleep(0.2)",
                    private_marker,
                ],
                cwd=PACKAGE_ROOT,
                env=launcher_environment(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertIsNotNone(process.stdout)
            self.assertIsNotNone(process.stderr)
            process.stdout.close()
            process.stdout = None
            stderr = process.stderr.read()
            process.stderr.close()
            returncode = process.wait(timeout=8)

        expected = canonical_json(
            {
                "evidence_boundary": EVIDENCE_BOUNDARY,
                "operation": "launcher",
                "reason": "delivery_failure",
                "schema_version": "contextguard-receipt-cli-response/v1",
                "status": "error",
            }
        ).encode("ascii")
        self.assertEqual(returncode, 74, stderr)
        self.assertEqual(stderr, expected)
        self.assertNotIn(private_marker.encode("ascii"), stderr)
        self.assertNotIn(b"cgr1p_", stderr)

    def test_launcher_forwards_interrupts_and_reaps_the_command_group(self) -> None:
        """Break caught: an interrupted Node wrapper strands the captured command."""

        for interrupt in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(interrupt=interrupt):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    root = Path(temporary_directory).resolve()
                    runtime = copy_runtime_with_current_launcher(root / "runtime")
                    record = root / "child-record"
                    state = root / "interrupt-state"
                    process = subprocess.Popen(
                        [
                            str(Path(NODE).resolve()),
                            str(runtime / "bin/context-guard-receipt.cjs"),
                            "run",
                            "--escrow",
                            "--root",
                            str(PACKAGE_ROOT.resolve()),
                            "--state-dir",
                            str(state),
                            "--",
                            str(Path(sys.executable).resolve()),
                            "-I",
                            "-S",
                            "-B",
                            "-c",
                            (
                                "import os,time; "
                                f"open({str(record)!r},'w',encoding='ascii').write("
                                "f'{os.getpid()}:{os.getppid()}'); "
                                "time.sleep(60)"
                            ),
                        ],
                        cwd=PACKAGE_ROOT,
                        env=launcher_environment(),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    child_pid = 0
                    python_pid = 0
                    try:
                        child_pid, python_pid = read_child_record(record)
                        process.send_signal(interrupt)
                        stdout, stderr = process.communicate(timeout=8)
                        self.assertEqual(process.returncode, 128 + interrupt)
                        self.assertEqual(stdout, b"")
                        self.assertEqual(stderr, b"")
                        self.assertTrue(wait_for_process_exit(child_pid))
                        self.assertFalse(state.exists())
                    finally:
                        if process.poll() is None:
                            process.kill()
                            process.wait(timeout=3)
                        for pid in (child_pid, python_pid):
                            if pid > 0 and process_exists(pid):
                                try:
                                    os.kill(pid, signal.SIGKILL)
                                except ProcessLookupError:
                                    pass

    def test_launcher_never_signals_scanned_numeric_process_groups(self) -> None:
        """Break caught: launcher ps data becomes numeric group signal authority."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            runtime = copy_runtime_with_current_launcher(root / "runtime")
            record = root / "child-record"
            signal_audit = root / "negative-signal-audit"
            preload = root / "audit-process-kill.cjs"
            preload.write_text(
                "'use strict';\n"
                "const fs = require('fs');\n"
                "const originalKill = process.kill.bind(process);\n"
                "process.kill = (pid, signalName) => {\n"
                "  if (Number.isInteger(pid) && pid < 0) {\n"
                "    fs.appendFileSync(process.env.CGR_SIGNAL_AUDIT, "
                "`${pid}:${signalName}\\n`);\n"
                "  }\n"
                "  return originalKill(pid, signalName);\n"
                "};\n",
                encoding="ascii",
            )
            state = root / "interrupt-state"
            process = subprocess.Popen(
                [
                    str(Path(NODE).resolve()),
                    str(runtime / "bin/context-guard-receipt.cjs"),
                    "run",
                    "--escrow",
                    "--root",
                    str(PACKAGE_ROOT.resolve()),
                    "--state-dir",
                    str(state),
                    "--",
                    str(Path(sys.executable).resolve()),
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    (
                        "import os,signal,time; "
                        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                        f"open({str(record)!r},'w',encoding='ascii').write("
                        "f'{os.getpid()}:{os.getppid()}'); "
                        "time.sleep(60)"
                    ),
                ],
                cwd=PACKAGE_ROOT,
                env=launcher_environment(
                    CGR_SIGNAL_AUDIT=str(signal_audit),
                    NODE_OPTIONS=f"--require={preload}",
                ),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            child_pid = 0
            python_pid = 0
            try:
                child_pid, python_pid = read_child_record(record)
                process.send_signal(signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=8)
                self.assertEqual(process.returncode, 128 + signal.SIGTERM)
                self.assertEqual(stdout, b"")
                self.assertEqual(stderr, b"")
                self.assertTrue(wait_for_process_exit(child_pid))
                self.assertEqual(
                    signal_audit.read_bytes() if signal_audit.exists() else b"",
                    b"",
                )
                self.assertFalse(state.exists())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=3)
                for pid in (child_pid, python_pid):
                    if pid > 0 and process_exists(pid):
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass

    def test_active_run_executes_safe_absolute_command_and_emits_receipt(self) -> None:
        """Break caught: a packaged launcher keeps the now-active run grammar inert."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            state = Path(temporary_directory).resolve() / "active-state"
            response = run_node(
                "bin/context-guard-receipt.cjs",
                "run",
                "--escrow",
                "--root",
                str(PACKAGE_ROOT.resolve()),
                "--state-dir",
                str(state),
                "--",
                str(Path(sys.executable).resolve()),
                "-I",
                "-S",
                "-B",
                "-c",
                "import os; os.write(1,b'g001-safe-output')",
            )
            self.assertEqual(response.returncode, 0, response.stderr)
            self.assertEqual(response.stderr, "")
            receipt = json.loads(response.stdout)
            self.assertEqual(response.stdout, canonical_json(receipt))
            self.assertEqual(receipt["status"], "captured")
            self.assertRegex(receipt["handle"], r"^cgr1p_[A-Za-z0-9_-]{43}$")
            self.assertEqual(receipt["observation"]["scope"], "worktree")
            self.assertTrue(state.is_dir())

    def test_license_and_readme_state_the_exact_distribution_trust_boundary(self) -> None:
        """Break caught: license truncation or claims beyond companion-local evidence."""
        require_distribution()
        self.assertEqual(
            (PACKAGE_ROOT / "LICENSE").read_bytes(),
            (REPO_ROOT / "LICENSE").read_bytes(),
        )
        readme = " ".join(
            (PACKAGE_ROOT / "README.md").read_text(encoding="utf-8").lower().split()
        )
        for statement in (
            "neither stage 1 nor stage 2 evidence",
            "cannot close the provider join",
            "does not report provider token, cost, cache, or percentage-savings claims",
            "trusted cpython executable",
            "package manager",
            "consistency and corruption check",
            "local opt-in persistence",
            "exact local expansion",
            "byte proxy",
            "source_current",
            "catalog_snapshot",
            "stale",
            "bypass",
            "run --escrow --root <absolute> --state-dir <absolute>",
            "does not invoke a shell",
            "fixed environment",
            "stdout only",
            "historical command capture",
            "worktree hashes",
            "external-side-effect completeness",
            "command_capture_failed",
        ):
            self.assertIn(statement, readme)

    def test_manifest_is_dependency_free_and_exposes_only_the_two_binaries(self) -> None:
        """Break caught: adding lifecycle code, dependencies, or redirecting a binary."""
        require_distribution()
        manifest = json.loads((PACKAGE_ROOT / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest, EXPECTED_PACKAGE)
        for field in (
            "bundledDependencies",
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
            "scripts",
        ):
            self.assertNotIn(field, manifest)

    def test_boundary_schema_and_inspect_response_are_exact_and_closed(self) -> None:
        """Break caught: weakening the evidence boundary or adding claim authority."""
        require_distribution()
        schema = json.loads(
            (PACKAGE_ROOT / "schemas/evidence-boundary.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(schema, EXPECTED_SCHEMA)
        response = run_node("bin/context-guard-receipt.cjs", "inspect", "boundary")
        self.assertEqual(response.returncode, 0, response.stderr)
        self.assertEqual(response.stderr, "")
        self.assertEqual(response.stdout, canonical_json(EXPECTED_BOUNDARY_RESPONSE))

    def test_runtime_manifest_hashes_exact_regular_files_and_modes(self) -> None:
        """Break caught: shipping an undeclared, replaced, symlinked, or executable file."""
        require_distribution()
        manifest = json.loads((PACKAGE_ROOT / "package-files.json").read_text(encoding="utf-8"))
        self.assertEqual(set(manifest), {"files", "schema_version"})
        self.assertEqual(manifest["schema_version"], "contextguard-receipt-package-files/v1")
        entries = manifest["files"]
        self.assertEqual(entries, sorted(entries, key=lambda entry: entry["path"]))
        expected_manifest_paths = set(EXPECTED_RUNTIME_MODES) - {"package-files.json"}
        self.assertEqual({entry["path"] for entry in entries}, expected_manifest_paths)
        for entry in entries:
            self.assertEqual(set(entry), {"mode", "path", "sha256"})
            path = PACKAGE_ROOT / entry["path"]
            self.assertTrue(path.is_file(), entry["path"])
            self.assertFalse(path.is_symlink(), entry["path"])
            self.assertEqual(entry["mode"], f"{EXPECTED_RUNTIME_MODES[entry['path']]:04o}")
            self.assertEqual(entry["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

        for relative_path, expected_mode in {**EXPECTED_RUNTIME_MODES, **EXPECTED_DEV_MODES}.items():
            path = PACKAGE_ROOT / relative_path
            self.assertTrue(path.is_file(), relative_path)
            self.assertFalse(path.is_symlink(), relative_path)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), expected_mode, relative_path)
            self.assertTrue(FORBIDDEN_PACKAGE_PARTS.isdisjoint(Path(relative_path).parts))

    def test_python_resolution_and_launcher_protocol_fail_closed(self) -> None:
        """Break caught: relative interpreters, missing runtime, or probe protocol drift."""
        require_distribution()
        absolute = run_node("bin/context-guard-receipt.cjs", "inspect", "boundary")
        self.assertEqual(absolute.returncode, 0, absolute.stderr)

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            fallback_bin = temporary_root / "fallback-bin"
            fallback_bin.mkdir()
            (fallback_bin / "python3").symlink_to(Path(sys.executable).resolve())
            fallback_environment = launcher_environment(PATH=str(fallback_bin))
            fallback_environment.pop(PYTHON_ENV)
            fallback = run_node(
                "bin/context-guard-receipt.cjs",
                "inspect",
                "boundary",
                environment=fallback_environment,
            )
            self.assertEqual(fallback.returncode, 0, fallback.stderr)

            unavailable_environment = launcher_environment(PATH=str(temporary_root / "empty"))
            unavailable_environment.pop(PYTHON_ENV)
            missing = run_node(
                "bin/context-guard-receipt.cjs",
                "inspect",
                "boundary",
                environment=unavailable_environment,
            )
            assert_json_error(
                self, missing, code=69, operation="launcher", status="error", reason="runtime_unavailable"
            )

            relative = run_node(
                "bin/context-guard-receipt.cjs",
                "inspect",
                "boundary",
                environment=launcher_environment(**{PYTHON_ENV: "python3"}),
            )
            assert_json_error(
                self, relative, code=69, operation="launcher", status="error", reason="runtime_unavailable"
            )

            fake_python = temporary_root / "fake-python"
            fake_python.write_text(
                "#!/bin/sh\nprintf '%s\\n' '{\"package_protocol\":\"wrong/v1\"}'\n",
                encoding="utf-8",
            )
            fake_python.chmod(0o755)
            incompatible = run_node(
                "bin/context-guard-receipt.cjs",
                "inspect",
                "boundary",
                environment=launcher_environment(**{PYTHON_ENV: str(fake_python)}),
            )
            assert_json_error(
                self,
                incompatible,
                code=69,
                operation="launcher",
                status="error",
                reason="runtime_unavailable",
            )

            native_incompatible = run_node(
                "bin/context-guard-receipt.cjs",
                "inspect",
                "boundary",
                environment=launcher_environment(**{PYTHON_ENV: str(Path("/usr/bin/true"))}),
            )
            assert_json_error(
                self,
                native_incompatible,
                code=78,
                operation="launcher",
                status="error",
                reason="protocol_incompatible",
            )

            relative_bin = temporary_root / "relative-bin"
            relative_bin.mkdir()
            relative_sentinel = temporary_root / "relative-python-executed"
            relative_python = relative_bin / "python3"
            relative_python.write_text(
                f"#!/bin/sh\ntouch '{relative_sentinel}'\nexit 0\n",
                encoding="utf-8",
            )
            relative_python.chmod(0o755)
            relative_path_environment = launcher_environment(PATH="relative-bin")
            relative_path_environment.pop(PYTHON_ENV)
            relative_path = run_node(
                "bin/context-guard-receipt.cjs",
                "inspect",
                "boundary",
                environment=relative_path_environment,
                working_directory=temporary_root,
            )
            assert_json_error(
                self,
                relative_path,
                code=69,
                operation="launcher",
                status="error",
                reason="runtime_unavailable",
            )
            self.assertFalse(relative_sentinel.exists())

            spoof_sentinel = temporary_root / "spoofed-python-executed"
            spoof_python = temporary_root / "spoof-python"
            spoof_python.write_text(
                "#!/bin/sh\n"
                "case \"$*\" in\n"
                "  *--launcher-probe*)\n"
                "    printf '%s\\n' '{\"implementation\":\"CPython\","
                "\"package_protocol\":\"contextguard-receipt-launch/v1\","
                "\"python_version\":[3,11]}'\n"
                "    ;;\n"
                "  *)\n"
                f"    touch '{spoof_sentinel}'\n"
                "    ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            spoof_python.chmod(0o755)
            spoofed = run_node(
                "bin/context-guard-receipt.cjs",
                "inspect",
                "boundary",
                environment=launcher_environment(**{PYTHON_ENV: str(spoof_python)}),
            )
            assert_json_error(
                self,
                spoofed,
                code=69,
                operation="launcher",
                status="error",
                reason="runtime_unavailable",
            )
            self.assertFalse(spoof_sentinel.exists())

    def test_runtime_checks_reject_rewritten_payload_manifest_and_extra_files(self) -> None:
        """Break caught: treating a mutable manifest or an open tree as authenticity."""
        require_distribution()

        def copy_runtime(destination: Path) -> None:
            for relative_path in EXPECTED_RUNTIME_MODES:
                source = PACKAGE_ROOT / relative_path
                target = destination / relative_path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            rewritten = temporary_root / "rewritten"
            copy_runtime(rewritten)
            readme = rewritten / "README.md"
            readme.write_bytes(readme.read_bytes() + b"\nrewritten\n")
            manifest_path = rewritten / "package-files.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            for entry in manifest["files"]:
                if entry["path"] == "README.md":
                    entry["sha256"] = hashlib.sha256(readme.read_bytes()).hexdigest()
            manifest_path.write_text(canonical_json(manifest), encoding="utf-8")
            rewritten_response = run_node(
                "bin/context-guard-receipt.cjs",
                "inspect",
                "boundary",
                package_root=rewritten,
            )
            assert_json_error(
                self,
                rewritten_response,
                code=70,
                operation="launcher",
                status="error",
                reason="integrity_failure",
            )

            extended = temporary_root / "extended"
            copy_runtime(extended)
            extra = extended / "python/context_guard_receipt/undeclared.py"
            extra.write_text("raise RuntimeError('must not be imported')\n", encoding="utf-8")
            extended_response = run_node(
                "bin/context-guard-receipt.cjs",
                "inspect",
                "boundary",
                package_root=extended,
            )
            assert_json_error(
                self,
                extended_response,
                code=70,
                operation="launcher",
                status="error",
                reason="integrity_failure",
            )

            cached = temporary_root / "cached"
            copy_runtime(cached)
            cache_directory = cached / "python/context_guard_receipt/__pycache__"
            cache_directory.mkdir()
            cached_contracts = cached / "python/context_guard_receipt/contracts.py"
            cache_tag = sys.implementation.cache_tag
            self.assertIsNotNone(cache_tag)
            cache_file = cache_directory / f"contracts.{cache_tag}.pyc"
            cache_sentinel = temporary_root / "adjacent-bytecode-executed"
            malicious_source = temporary_root / "contracts.py"
            prefix = (
                "from pathlib import Path\n"
                f"Path({str(cache_sentinel)!r}).touch()\n"
            ).encode("utf-8")
            target_size = cached_contracts.stat().st_size
            self.assertLess(len(prefix), target_size)
            malicious_source.write_bytes(prefix + (b"#" * (target_size - len(prefix))))
            target_stat = cached_contracts.stat()
            os.utime(malicious_source, ns=(target_stat.st_atime_ns, target_stat.st_mtime_ns))
            py_compile.compile(
                str(malicious_source),
                cfile=str(cache_file),
                doraise=True,
            )
            cached_response = run_node(
                "bin/context-guard-receipt.cjs",
                "inspect",
                "boundary",
                package_root=cached,
            )
            self.assertEqual(cached_response.returncode, 0, cached_response.stderr)
            self.assertEqual(cached_response.stdout, canonical_json(EXPECTED_BOUNDARY_RESPONSE))
            self.assertFalse(cache_sentinel.exists())

    def test_closed_cli_grammar_keeps_future_commands_inert_and_help_human_readable(self) -> None:
        """Break caught: executing a future command or echoing caller inputs in errors."""
        require_distribution()
        invalid_commands = (
            (),
            ("inspect",),
            ("inspect", "boundary", "extra"),
            ("inspect", "receipt", "extra"),
            ("assemble",),
            ("assemble", "--kind", "evidence"),
            ("assemble", "--kind", "unknown", "--descriptor", "-"),
            ("assemble", "--kind", "evidence", "--descriptor", "-", "--persist"),
            ("run", "anything"),
            ("expand", "not-a-handle", "--state-dir", "/tmp/state"),
            ("expand", "cgr1p_handle", "--state-dir", "relative"),
            (
                "expand",
                "tool-schema",
                "--request",
                "-",
                "--root",
                "/tmp/repository",
            ),
            (
                "expand",
                "tool-schema",
                "--request",
                "-",
                "--root",
                ".",
                "--state-dir",
                "/tmp/state",
            ),
            (
                "expand",
                "tool-schema",
                "--request",
                "-",
                "--root",
                "/tmp/repository",
                "--state-dir",
                "relative",
            ),
            ("unknown",),
        )
        for arguments in invalid_commands:
            with self.subTest(arguments=arguments):
                response = run_node("bin/context-guard-receipt.cjs", *arguments)
                assert_json_error(
                    self, response, code=64, operation="cli", status="error", reason="usage"
                )

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            sentinel = root / "command-executed"
            receipt_path = root / "legacy-receipt.json"
            state_path = root / "state"
            legacy_run = run_node(
                "bin/context-guard-receipt.cjs",
                "run",
                "--escrow",
                "--root",
                str(PACKAGE_ROOT.resolve()),
                "--state-dir",
                str(state_path),
                "--receipt-out",
                str(receipt_path),
                "--",
                str(Path(sys.executable).resolve()),
                "-I",
                "-S",
                "-B",
                "-c",
                f"from pathlib import Path; Path({str(sentinel)!r}).touch()",
            )
            assert_json_error(
                self,
                legacy_run,
                code=64,
                operation="cli",
                status="error",
                reason="usage",
            )
            self.assertFalse(sentinel.exists())
            self.assertFalse(state_path.exists())
            self.assertFalse(receipt_path.exists())

            inactive = (
                ("inspect_receipt", ("inspect", "receipt")),
                (
                    "inspect_diagnostics",
                    (
                        "inspect",
                        "diagnostics",
                        "--state-dir",
                        str(root / "state"),
                        "--input",
                        "-",
                    ),
                ),
            )
            for operation, arguments in inactive:
                with self.subTest(operation=operation):
                    response = run_node("bin/context-guard-receipt.cjs", *arguments)
                    assert_json_error(
                        self,
                        response,
                        code=69,
                        operation=operation,
                        status="unavailable",
                        reason="feature_not_available",
                    )
            self.assertFalse(sentinel.exists())
            self.assertFalse(state_path.exists())
            self.assertFalse(receipt_path.exists())

        help_response = run_node("bin/context-guard-receipt.cjs", "--help")
        self.assertEqual(help_response.returncode, 0, help_response.stderr)
        self.assertEqual(help_response.stderr, "")
        self.assertEqual(help_response.stdout, EXPECTED_HELP)

        mcp_help = run_node("bin/context-guard-receipt-mcp.cjs", "--help")
        self.assertEqual(mcp_help.returncode, 0, mcp_help.stderr)
        self.assertEqual(mcp_help.stderr, "")
        self.assertEqual(mcp_help.stdout, EXPECTED_MCP_HELP)

        mcp_relative = run_node("bin/context-guard-receipt-mcp.cjs", "--root", ".")
        assert_json_error(
            self, mcp_relative, code=64, operation="mcp", status="error", reason="usage"
        )


if __name__ == "__main__":
    unittest.main()
