from __future__ import annotations

import hashlib
import json
import os
import py_compile
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


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
    "  inspect diagnostics --input <file|-> [--state-scope durable --root <absolute> "
    "--state-dir <absolute>]\n"
    "  inspect firewall --input <file|->\n"
    "  inspect diagnostic-ledger --state-scope durable --root <absolute> "
    "--state-dir <absolute> [--limit <positive-decimal>]\n"
    "  inspect twin --experimental-twin --input <file|-> --root <absolute> "
    "--state-dir <absolute>\n"
    "  inspect twin --experimental-twin --root <absolute> --state-dir <absolute> "
    "[--limit <positive-decimal>]\n"
    "  inspect reference-expiry --experimental-reference-expiry --input <file|-> "
    "--root <absolute> --state-dir <absolute>\n"
    "  inspect reference-expiry --experimental-reference-expiry --root <absolute> "
    "--state-dir <absolute> [--limit <positive-decimal>]\n"
    "  inspect <receipt|lease|state> [options]\n\n"
    "Evidence, blueprint, and tool-schema assembly plus exact local expansion are available. "
    "Run is explicit local capture only. Diagnostics, firewall findings, and the experimental "
    "twin are advisory and non-applying. Experimental reference expiry revokes only compact "
    "local references and retains artifacts. The companion is provider-free and makes no "
    "host-request, network, or token-saving claim. Remaining commands are inert.\n"
)
EXPECTED_MCP_HELP = (
    "usage: context-guard-receipt-mcp --root <absolute-directory>\n\n"
    "Run the bounded local stdio MCP surface for one fixed repository root. "
    "Capabilities are process-local and expire when the process exits. No "
    "registration, provider, model, credential, or network access is performed.\n"
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
    "python/context_guard_receipt/diagnostic_ledger.py": 0o644,
    "python/context_guard_receipt/diagnostics.py": 0o644,
    "python/context_guard_receipt/execution_twin.py": 0o644,
    "python/context_guard_receipt/evidence_pack.py": 0o644,
    "python/context_guard_receipt/expansion.py": 0o644,
    "python/context_guard_receipt/identity.py": 0o644,
    "python/context_guard_receipt/mcp.py": 0o644,
    "python/context_guard_receipt/protection.py": 0o644,
    "python/context_guard_receipt/reference_expiry.py": 0o644,
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
    "schemas/diagnostic-ledger-entry.schema.json": 0o644,
    "schemas/diagnostic-ledger-inspection.schema.json": 0o644,
    "schemas/diagnostic-ledger-metadata.schema.json": 0o644,
    "schemas/diagnostics-report.schema.json": 0o644,
    "schemas/diagnostics-request.schema.json": 0o644,
    "schemas/evidence-descriptor.schema.json": 0o644,
    "schemas/evidence-boundary.schema.json": 0o644,
    "schemas/evidence-pack.schema.json": 0o644,
    "schemas/evidence-reference.schema.json": 0o644,
    "schemas/expansion-envelope.schema.json": 0o644,
    "schemas/expansion-refusal.schema.json": 0o644,
    "schemas/protection-decision.schema.json": 0o644,
    "schemas/reference-expiry-inspection.schema.json": 0o644,
    "schemas/reference-expiry-metadata.schema.json": 0o644,
    "schemas/reference-expiry-record.schema.json": 0o644,
    "schemas/reference-expiry-request.schema.json": 0o644,
    "schemas/reference-expiry-result.schema.json": 0o644,
    "schemas/shadow-firewall-report.schema.json": 0o644,
    "schemas/source-identity.schema.json": 0o644,
    "schemas/store-commit.schema.json": 0o644,
    "schemas/store-metadata.schema.json": 0o644,
    "schemas/twin-event.schema.json": 0o644,
    "schemas/twin-metadata.schema.json": 0o644,
    "schemas/twin-request.schema.json": 0o644,
    "schemas/twin-result.schema.json": 0o644,
    "schemas/twin-snapshot.schema.json": 0o644,
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
    if Path("/bin/ps").is_file():
        try:
            observed = subprocess.run(
                ["/bin/ps", "-o", "stat=", "-p", str(pid)],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=False,
                timeout=1.0,
            )
            state = observed.stdout.strip()
            if observed.returncode == 0 and state:
                return not state.startswith("Z")
        except (OSError, subprocess.TimeoutExpired):
            pass
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except (OSError, ValueError):
        return True


def wait_for_process_exit(pid: int, timeout_seconds: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not process_exists(pid):
            return True
        time.sleep(0.02)
    return not process_exists(pid)


def wait_for_process_state(
    pid: int, expected_prefix: str, timeout_seconds: float = 3.0
) -> None:
    if not Path("/bin/ps").is_file():
        raise unittest.SkipTest("/bin/ps is required to observe process state")
    deadline = time.monotonic() + timeout_seconds
    state = ""
    while time.monotonic() < deadline:
        try:
            observed = subprocess.run(
                ["/bin/ps", "-o", "stat=", "-p", str(pid)],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=False,
                timeout=1.0,
            )
        except (OSError, subprocess.TimeoutExpired):
            time.sleep(0.02)
            continue
        state = observed.stdout.strip()
        if state.startswith(expected_prefix):
            return
        time.sleep(0.02)
    raise AssertionError(
        f"timed out waiting for process {pid} state {expected_prefix!r}; observed {state!r}"
    )


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


def compile_signal_probe_runtime(root: Path, behavior: str = "cooperative") -> Path:
    source = root / f"{behavior}-probe.c"
    runtime = root / f"{behavior}-probe"
    if behavior == "cooperative":
        signal_setup = (
            "      signal(SIGINT, stop);\n"
            "      signal(SIGTERM, stop);\n"
        )
        probe_action = "      for (;;) pause();\n"
    elif behavior == "stubborn":
        signal_setup = (
            "      signal(SIGINT, SIG_IGN);\n"
            "      signal(SIGTERM, SIG_IGN);\n"
        )
        probe_action = "      for (;;) pause();\n"
    elif behavior == "success":
        signal_setup = ""
        probe_action = (
            '      fputs("{\\\"implementation\\\":\\\"CPython\\\",'
            '\\\"package_protocol\\\":\\\"contextguard-receipt-launch/v1\\\",'
            '\\\"python_version\\\":[3,11]}\\n", stdout);\n'
            "      return 0;\n"
        )
    else:
        raise AssertionError(f"unsupported probe behavior: {behavior}")
    source.write_text(
        "#include <signal.h>\n"
        "#include <stdio.h>\n"
        "#include <stdlib.h>\n"
        "#include <string.h>\n"
        "#include <unistd.h>\n"
        "static void stop(int signal_number) { _exit(128 + signal_number); }\n"
        "int main(int argc, char **argv) {\n"
        "  for (int index = 1; index < argc; ++index) {\n"
        "    if (strcmp(argv[index], \"--launcher-probe\") == 0) {\n"
        + signal_setup
        + "      const char *record_path = getenv(\"CGR_PROBE_RECORD\");\n"
        "      if (record_path != NULL) {\n"
        "        FILE *record = fopen(record_path, \"w\");\n"
        "        if (record == NULL) return 1;\n"
        "        fprintf(record, \"%ld:%ld\", (long)getpid(), (long)getppid());\n"
        "        fclose(record);\n"
        "      }\n"
        + probe_action
        + "    }\n"
        "  }\n"
        "  const char *marker_path = getenv(\"CGR_MAIN_MARKER\");\n"
        "  if (marker_path != NULL) {\n"
        "    FILE *marker = fopen(marker_path, \"w\");\n"
        "    if (marker != NULL) fclose(marker);\n"
        "  }\n"
        "  return 0;\n"
        "}\n",
        encoding="ascii",
    )
    compilation = subprocess.run(
        [str(shutil.which("cc")), str(source), "-o", str(runtime)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=15.0,
    )
    if compilation.returncode != 0:
        raise AssertionError(compilation.stderr)
    runtime.chmod(0o755)
    return runtime


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

    def test_launcher_handles_interrupt_before_spawn_wrapper_returns(self) -> None:
        """Break caught: a spawn-time interrupt kills Node and strands its descendants."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            runtime = copy_runtime_with_current_launcher(root / "runtime")
            record = root / "early-signal-child-record"
            preload = root / "early-signal.cjs"
            preload.write_text(
                "'use strict';\n"
                "const childProcess = require('child_process');\n"
                "const fs = require('fs');\n"
                "const originalSpawn = childProcess.spawn.bind(childProcess);\n"
                "const sleeper = new Int32Array(new SharedArrayBuffer(4));\n"
                "let firstSpawn = true;\n"
                "childProcess.spawn = (...arguments_) => {\n"
                "  const child = originalSpawn(...arguments_);\n"
                "  if (arguments_[1].includes('--launcher-probe')) return child;\n"
                "  if (!firstSpawn) return child;\n"
                "  firstSpawn = false;\n"
                "  const deadline = Date.now() + 5000;\n"
                "  while (Date.now() < deadline) {\n"
                "    try {\n"
                "      const record = fs.readFileSync(\n"
                "        process.env.CGR_EARLY_SIGNAL_RECORD, 'ascii'\n"
                "      );\n"
                "      if (/^\\d+:\\d+$/.test(record)) break;\n"
                "    } catch (_) {\n"
                "      // The escrowed command has not published its PID yet.\n"
                "    }\n"
                "    Atomics.wait(sleeper, 0, 0, 10);\n"
                "  }\n"
                "  process.kill(process.pid, 'SIGTERM');\n"
                "  return child;\n"
                "};\n",
                encoding="ascii",
            )
            state = root / "early-signal-state"
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
                env=launcher_environment(
                    CGR_EARLY_SIGNAL_RECORD=str(record),
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
                stdout, stderr = process.communicate(timeout=8)
                self.assertIn(process.returncode, (69, 143), stderr)
                self.assertEqual(stdout, b"")
                if process.returncode == 69:
                    self.assertEqual(
                        stderr,
                        canonical_json(
                            {
                                "evidence_boundary": EVIDENCE_BOUNDARY,
                                "operation": "launcher",
                                "reason": "cleanup_unconfirmed",
                                "schema_version": "contextguard-receipt-cli-response/v1",
                                "status": "error",
                            }
                        ).encode("ascii"),
                    )
                else:
                    self.assertEqual(stderr, b"")
                self.assertTrue(wait_for_process_exit(child_pid))
                self.assertTrue(wait_for_process_exit(python_pid))
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

    @unittest.skipUnless(shutil.which("cc"), "a native compiler is required")
    def test_signals_during_probe_are_forwarded_and_reap_probe_before_main(self) -> None:
        """Break caught: SIGINT or SIGTERM during a compatibility probe orphans it."""

        invocations = (
            ("bin/context-guard-receipt.cjs", ("inspect", "boundary")),
            ("bin/context-guard-receipt-mcp.cjs", ("--root", str(PACKAGE_ROOT.resolve()))),
        )
        for entrypoint, arguments in invocations:
            for interrupt in (signal.SIGINT, signal.SIGTERM):
                with self.subTest(entrypoint=entrypoint, interrupt=interrupt):
                    with tempfile.TemporaryDirectory() as temporary_directory:
                        root = Path(temporary_directory).resolve()
                        distribution = copy_runtime_with_current_launcher(
                            root / "distribution"
                        )
                        runtime = compile_signal_probe_runtime(root)
                        probe_record = root / "probe-record"
                        main_marker = root / "main-marker"
                        process = subprocess.Popen(
                            [
                                str(Path(NODE).resolve()),
                                str(distribution / entrypoint),
                                *arguments,
                            ],
                            cwd=distribution,
                            env=launcher_environment(
                                CGR_MAIN_MARKER=str(main_marker),
                                CGR_PROBE_RECORD=str(probe_record),
                                **{PYTHON_ENV: str(runtime)},
                            ),
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        )
                        probe_pid = 0
                        try:
                            probe_pid, parent_pid = read_child_record(probe_record)
                            self.assertEqual(parent_pid, process.pid)
                            process.send_signal(interrupt)
                            stdout, stderr = process.communicate(timeout=8)
                            self.assertEqual(process.returncode, 128 + interrupt, stderr)
                            self.assertEqual(stdout, b"")
                            self.assertEqual(stderr, b"")
                            self.assertTrue(wait_for_process_exit(probe_pid))
                            self.assertFalse(main_marker.exists())
                        finally:
                            if process.poll() is None:
                                process.kill()
                                process.wait(timeout=3)
                            if probe_pid > 0 and process_exists(probe_pid):
                                try:
                                    os.kill(probe_pid, signal.SIGKILL)
                                except ProcessLookupError:
                                    pass

    @unittest.skipUnless(shutil.which("cc"), "a native compiler is required")
    def test_probe_signal_escalation_is_canonical_and_reaps_stubborn_probe(self) -> None:
        """Break caught: forced probe cleanup is reported as a graceful interrupt."""

        expected_error = canonical_json(
            {
                "evidence_boundary": EVIDENCE_BOUNDARY,
                "operation": "launcher",
                "reason": "cleanup_unconfirmed",
                "schema_version": "contextguard-receipt-cli-response/v1",
                "status": "error",
            }
        ).encode("ascii")
        for repeat_interrupt in (False, True):
            with self.subTest(repeat_interrupt=repeat_interrupt):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    root = Path(temporary_directory).resolve()
                    distribution = copy_runtime_with_current_launcher(
                        root / "distribution"
                    )
                    runtime = compile_signal_probe_runtime(root, "stubborn")
                    probe_record = root / "probe-record"
                    main_marker = root / "main-marker"
                    process = subprocess.Popen(
                        [
                            str(Path(NODE).resolve()),
                            str(distribution / "bin/context-guard-receipt.cjs"),
                            "inspect",
                            "boundary",
                        ],
                        cwd=distribution,
                        env=launcher_environment(
                            CGR_MAIN_MARKER=str(main_marker),
                            CGR_PROBE_RECORD=str(probe_record),
                            **{PYTHON_ENV: str(runtime)},
                        ),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    probe_pid = 0
                    try:
                        probe_pid, parent_pid = read_child_record(probe_record)
                        self.assertEqual(parent_pid, process.pid)
                        process.send_signal(signal.SIGTERM)
                        if repeat_interrupt:
                            time.sleep(0.05)
                            process.send_signal(signal.SIGINT)
                        stdout, stderr = process.communicate(timeout=8)
                        self.assertEqual(process.returncode, 69, stderr)
                        self.assertEqual(stdout, b"")
                        self.assertEqual(stderr, expected_error)
                        self.assertTrue(wait_for_process_exit(probe_pid))
                        self.assertFalse(main_marker.exists())
                    finally:
                        if process.poll() is None:
                            process.kill()
                            process.wait(timeout=3)
                        if probe_pid > 0 and process_exists(probe_pid):
                            try:
                                os.kill(probe_pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass

    @unittest.skipUnless(shutil.which("cc"), "a native compiler is required")
    def test_probe_spawn_and_main_handoff_signal_races_never_launch_main(self) -> None:
        """Break caught: a queued probe or handoff signal still launches the runtime."""

        cleanup_error = canonical_json(
            {
                "evidence_boundary": EVIDENCE_BOUNDARY,
                "operation": "launcher",
                "reason": "cleanup_unconfirmed",
                "schema_version": "contextguard-receipt-cli-response/v1",
                "status": "error",
            }
        ).encode("ascii")
        for scenario, behavior, expected_code in (
            ("before-spawn-return", "cooperative", 143),
            ("probe-main-handoff", "success", 69),
        ):
            with self.subTest(scenario=scenario):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    root = Path(temporary_directory).resolve()
                    distribution = copy_runtime_with_current_launcher(
                        root / "distribution"
                    )
                    runtime = compile_signal_probe_runtime(root, behavior)
                    spawn_record = root / "spawn-record"
                    probe_record = root / "probe-record"
                    main_marker = root / "main-marker"
                    preload = root / "probe-signal-race.cjs"
                    signal_action = (
                        "  process.emit('SIGTERM');\n"
                        if scenario == "before-spawn-return"
                        else "  child.once('close', () => process.emit('SIGTERM'));\n"
                    )
                    preload.write_text(
                        "'use strict';\n"
                        "const childProcess = require('child_process');\n"
                        "const fs = require('fs');\n"
                        "const originalSpawn = childProcess.spawn.bind(childProcess);\n"
                        "childProcess.spawn = (...arguments_) => {\n"
                        "  const child = originalSpawn(...arguments_);\n"
                        "  if (!arguments_[1].includes('--launcher-probe')) return child;\n"
                        "  fs.writeFileSync(process.env.CGR_SPAWN_RECORD, "
                        "`${child.pid}:${process.pid}`);\n"
                        + signal_action
                        + "  return child;\n"
                        "};\n",
                        encoding="ascii",
                    )
                    process = subprocess.Popen(
                        [
                            str(Path(NODE).resolve()),
                            str(distribution / "bin/context-guard-receipt.cjs"),
                            "inspect",
                            "boundary",
                        ],
                        cwd=distribution,
                        env=launcher_environment(
                            CGR_MAIN_MARKER=str(main_marker),
                            CGR_PROBE_RECORD=str(probe_record),
                            CGR_SPAWN_RECORD=str(spawn_record),
                            NODE_OPTIONS=f"--require={preload}",
                            **{PYTHON_ENV: str(runtime)},
                        ),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    probe_pid = 0
                    try:
                        probe_pid, parent_pid = read_child_record(spawn_record)
                        self.assertEqual(parent_pid, process.pid)
                        stdout, stderr = process.communicate(timeout=8)
                        self.assertEqual(process.returncode, expected_code, stderr)
                        self.assertEqual(stdout, b"")
                        self.assertEqual(
                            stderr,
                            b"" if expected_code == 143 else cleanup_error,
                        )
                        self.assertTrue(wait_for_process_exit(probe_pid))
                        self.assertFalse(main_marker.exists())
                    finally:
                        if process.poll() is None:
                            process.kill()
                            process.wait(timeout=3)
                        if probe_pid > 0 and process_exists(probe_pid):
                            try:
                                os.kill(probe_pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass

    @unittest.skipUnless(shutil.which("cc"), "a native compiler is required")
    def test_signal_after_probe_unbind_never_spawns_main_runtime(self) -> None:
        """Break caught: a post-close queued signal launches the main runtime."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            distribution = copy_runtime_with_current_launcher(root / "distribution")
            runtime = compile_signal_probe_runtime(root, "success")
            preload = root / "post-unbind-signal.cjs"
            preload.write_text(
                "'use strict';\n"
                "const childProcess = require('child_process');\n"
                "const fs = require('fs');\n"
                "const originalSpawn = childProcess.spawn.bind(childProcess);\n"
                "childProcess.spawn = (...arguments_) => {\n"
                "  const child = originalSpawn(...arguments_);\n"
                "  if (!arguments_[1].includes('--launcher-probe')) {\n"
                "    fs.writeFileSync(process.env.CGR_MAIN_SPAWN_MARKER, 'spawned');\n"
                "    return child;\n"
                "  }\n"
                "  const originalOnce = child.once.bind(child);\n"
                "  let closeHooked = false;\n"
                "  child.once = (eventName, listener) => {\n"
                "    if (eventName !== 'close' || closeHooked) {\n"
                "      return originalOnce(eventName, listener);\n"
                "    }\n"
                "    closeHooked = true;\n"
                "    originalOnce(eventName, listener);\n"
                "    originalOnce(eventName, () => {\n"
                "      process.emit('SIGTERM');\n"
                "      if (process.env.CGR_REPEAT_SIGNAL === '1') process.emit('SIGINT');\n"
                "    });\n"
                "    return child;\n"
                "  };\n"
                "  return child;\n"
                "};\n",
                encoding="ascii",
            )
            cleanup_error = canonical_json(
                {
                    "evidence_boundary": EVIDENCE_BOUNDARY,
                    "operation": "launcher",
                    "reason": "cleanup_unconfirmed",
                    "schema_version": "contextguard-receipt-cli-response/v1",
                    "status": "error",
                }
            )
            for repeat_signal in (False, True):
                with self.subTest(repeat_signal=repeat_signal):
                    suffix = "repeat" if repeat_signal else "single"
                    main_marker = root / f"main-marker-{suffix}"
                    main_spawn_marker = root / f"main-spawn-marker-{suffix}"
                    response = run_node(
                        "bin/context-guard-receipt.cjs",
                        "inspect",
                        "boundary",
                        environment=launcher_environment(
                            CGR_MAIN_MARKER=str(main_marker),
                            CGR_MAIN_SPAWN_MARKER=str(main_spawn_marker),
                            CGR_REPEAT_SIGNAL="1" if repeat_signal else "0",
                            NODE_OPTIONS=f"--require={preload}",
                            **{PYTHON_ENV: str(runtime)},
                        ),
                        package_root=distribution,
                    )
                    self.assertEqual(
                        response.returncode,
                        69 if repeat_signal else 128 + signal.SIGTERM,
                        response.stderr,
                    )
                    self.assertEqual(response.stdout, "")
                    self.assertEqual(response.stderr, cleanup_error if repeat_signal else "")
                    self.assertFalse(main_spawn_marker.exists())
                    self.assertFalse(main_marker.exists())

    def test_probe_sigkill_without_close_has_bounded_unconfirmed_cleanup(self) -> None:
        """Break caught: a SIGKILLed probe without close keeps the launcher pending."""

        launcher_path = PACKAGE_ROOT / "bin/launcher.cjs"
        script = r"""
const fs = require('fs');
const { EventEmitter } = require('events');
const { PassThrough } = require('stream');
const vm = require('vm');
const launcherPath = process.argv[1];
const mode = process.argv[2];
const source = fs.readFileSync(launcherPath, 'utf8')
  .replace(
    'const PROBE_TIMEOUT_MILLISECONDS = 5000;',
    'const PROBE_TIMEOUT_MILLISECONDS = 10;',
  )
  .replace(
    'const INTERRUPT_KILL_WAIT_MILLISECONDS = 750;',
    'const INTERRUPT_KILL_WAIT_MILLISECONDS = 25;',
  )
  .replace(
    'module.exports = { launch };',
    'module.exports = { compatibleProbe };',
  );
let childUnrefs = 0;
const kills = [];
let observedChild;
const fakeChildProcess = {
  spawn: () => {
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.kill = (signalName) => { kills.push(signalName); return true; };
    child.unref = () => { childUnrefs += 1; };
    observedChild = child;
    if (mode !== 'timeout') {
      setImmediate(() => child.stdout.write(Buffer.alloc((16 * 1024) + 1, 120)));
    }
    if (mode === 'late-close') {
      child.kill = (signalName) => {
        kills.push(signalName);
        setTimeout(() => child.emit('close', null, signalName), 60);
        return true;
      };
    }
    return child;
  },
};
let removeCalls = 0;
const signalController = {
  bind: () => true,
  pending: () => 0,
  remove: () => { removeCalls += 1; },
  unbind: () => undefined,
};
const context = {
  Buffer,
  clearTimeout,
  console,
  module: { exports: {} },
  process,
  Promise,
  require: (identifier) => identifier === 'child_process'
    ? fakeChildProcess
    : require(identifier),
  setImmediate,
  setTimeout,
};
vm.runInNewContext(source, context, { filename: launcherPath });
let reported = false;
const report = (timedOut, outcome) => {
  if (reported) return;
  reported = true;
  process.stdout.write(JSON.stringify({
    childCloseListeners: observedChild.listenerCount('close'),
    childErrorListeners: observedChild.listenerCount('error'),
    childUnrefs,
    kills,
    outcome,
    removeCalls,
    stderrDestroyed: observedChild.stderr.destroyed,
    stderrListeners: observedChild.stderr.listenerCount('data') +
      observedChild.stderr.listenerCount('error'),
    stdoutDestroyed: observedChild.stdout.destroyed,
    stdoutListeners: observedChild.stdout.listenerCount('data') +
      observedChild.stdout.listenerCount('error'),
    timedOut,
  }));
};
const watchdog = setTimeout(() => report(true, 'pending'), 250);
void (async () => {
  const outcome = await context.module.exports.compatibleProbe(
    '/runtime/python3', '/package/bootstrap.py', signalController,
  );
  clearTimeout(watchdog);
  report(false, outcome);
})();
"""
        expected_error = canonical_json(
            {
                "evidence_boundary": EVIDENCE_BOUNDARY,
                "operation": "launcher",
                "reason": "cleanup_unconfirmed",
                "schema_version": "contextguard-receipt-cli-response/v1",
                "status": "error",
            }
        )
        for mode in ("overflow", "timeout", "late-close"):
            with self.subTest(mode=mode):
                result = subprocess.run(
                    [str(Path(NODE).resolve()), "-e", script, str(launcher_path), mode],
                    cwd=PACKAGE_ROOT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                    timeout=2.0,
                )
                self.assertEqual(result.returncode, 69, result.stderr)
                self.assertEqual(result.stderr, expected_error)
                observed = json.loads(result.stdout)
                self.assertFalse(observed["timedOut"])
                self.assertIsNone(observed["outcome"])
                self.assertEqual(observed["kills"], ["SIGKILL"])
                self.assertEqual(observed["removeCalls"], 1)
                self.assertEqual(observed["childUnrefs"], 1)
                self.assertEqual(observed["childCloseListeners"], 0)
                self.assertEqual(observed["childErrorListeners"], 0)
                self.assertTrue(observed["stdoutDestroyed"])
                self.assertTrue(observed["stderrDestroyed"])
                self.assertEqual(observed["stdoutListeners"], 0)
                self.assertEqual(observed["stderrListeners"], 0)

    @unittest.skipUnless(shutil.which("cc"), "a native compiler is required")
    def test_main_spawn_error_removes_lifecycle_signal_listeners(self) -> None:
        """Break caught: a post-probe spawn error leaks lifecycle signal listeners."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            distribution = copy_runtime_with_current_launcher(root / "distribution")
            runtime = compile_signal_probe_runtime(root, "success")
            listener_record = root / "listener-record"
            main_marker = root / "main-marker"
            preload = root / "spawn-error.cjs"
            preload.write_text(
                "'use strict';\n"
                "const childProcess = require('child_process');\n"
                "const fs = require('fs');\n"
                "const originalSpawn = childProcess.spawn.bind(childProcess);\n"
                "childProcess.spawn = (...arguments_) => {\n"
                "  if (arguments_[1].includes('--launcher-probe')) {\n"
                "    return originalSpawn(...arguments_);\n"
                "  }\n"
                "  throw new Error('synthetic spawn failure');\n"
                "};\n"
                "process.on('exit', () => {\n"
                "  fs.writeFileSync(process.env.CGR_LISTENER_RECORD, "
                "`${process.listenerCount('SIGINT')}:` + "
                "`${process.listenerCount('SIGTERM')}`);\n"
                "});\n",
                encoding="ascii",
            )
            response = run_node(
                "bin/context-guard-receipt.cjs",
                "inspect",
                "boundary",
                environment=launcher_environment(
                    CGR_LISTENER_RECORD=str(listener_record),
                    CGR_MAIN_MARKER=str(main_marker),
                    NODE_OPTIONS=f"--require={preload}",
                    **{PYTHON_ENV: str(runtime)},
                ),
                package_root=distribution,
            )
            assert_json_error(
                self,
                response,
                code=69,
                operation="launcher",
                status="error",
                reason="runtime_unavailable",
            )
            self.assertEqual(listener_record.read_text(encoding="ascii"), "0:0")
            self.assertFalse(main_marker.exists())

    def test_probe_spawn_error_reaps_child_handle_and_removes_signal_listeners(self) -> None:
        """Break caught: an asynchronous probe spawn error retains launcher listeners."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            distribution = copy_runtime_with_current_launcher(root / "distribution")
            listener_record = root / "listener-record"
            missing_runtime = root / "missing-probe-runtime"
            preload = root / "probe-spawn-error.cjs"
            preload.write_text(
                "'use strict';\n"
                "const childProcess = require('child_process');\n"
                "const fs = require('fs');\n"
                "const originalSpawn = childProcess.spawn.bind(childProcess);\n"
                "childProcess.spawn = (...arguments_) => {\n"
                "  if (!arguments_[1].includes('--launcher-probe')) {\n"
                "    return originalSpawn(...arguments_);\n"
                "  }\n"
                "  return originalSpawn(process.env.CGR_MISSING_RUNTIME, "
                "arguments_[1], arguments_[2]);\n"
                "};\n"
                "process.on('exit', () => {\n"
                "  fs.writeFileSync(process.env.CGR_LISTENER_RECORD, "
                "`${process.listenerCount('SIGINT')}:` + "
                "`${process.listenerCount('SIGTERM')}`);\n"
                "});\n",
                encoding="ascii",
            )
            response = run_node(
                "bin/context-guard-receipt.cjs",
                "inspect",
                "boundary",
                environment=launcher_environment(
                    CGR_LISTENER_RECORD=str(listener_record),
                    CGR_MISSING_RUNTIME=str(missing_runtime),
                    NODE_OPTIONS=f"--require={preload}",
                ),
                package_root=distribution,
            )
            assert_json_error(
                self,
                response,
                code=78,
                operation="launcher",
                status="error",
                reason="protocol_incompatible",
            )
            self.assertEqual(listener_record.read_text(encoding="ascii"), "0:0")

    def test_process_state_helper_skips_when_ps_is_unavailable(self) -> None:
        """Break caught: a missing ps binary becomes a delayed assertion failure."""

        with mock.patch.object(Path, "is_file", return_value=False):
            with self.assertRaisesRegex(unittest.SkipTest, "/bin/ps is required"):
                wait_for_process_state(1, "T", timeout_seconds=0.01)

    def test_unconfirmed_cleanup_helper_skips_before_launch_without_ps(self) -> None:
        """Break caught: unsupported cleanup tests launch before their ps guard."""

        with (
            mock.patch.object(Path, "is_file", return_value=False),
            mock.patch.object(subprocess, "Popen") as popen,
        ):
            with self.assertRaisesRegex(unittest.SkipTest, "/bin/ps is required"):
                self._assert_launcher_reports_unconfirmed_cleanup()
        popen.assert_not_called()

    @unittest.skipUnless(Path("/bin/ps").is_file(), "/bin/ps is required")
    def test_process_exit_helper_treats_a_zombie_as_exited(self) -> None:
        """Break caught: a reaped-but-unwaited child is reported as live."""

        process = subprocess.Popen(
            [str(Path(sys.executable).resolve()), "-I", "-S", "-B", "-c", "pass"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.monotonic() + 3.0
            state = ""
            while time.monotonic() < deadline:
                observed = subprocess.run(
                    ["/bin/ps", "-o", "stat=", "-p", str(process.pid)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    check=False,
                    timeout=1.0,
                )
                state = observed.stdout.strip()
                if state.startswith("Z"):
                    break
                time.sleep(0.02)
            self.assertTrue(state.startswith("Z"), f"expected zombie state, observed {state!r}")
            self.assertFalse(process_exists(process.pid))
        finally:
            process.wait(timeout=3)

    def _assert_launcher_reports_unconfirmed_cleanup(
        self, *, external_supervisor_kill: bool = False, repeat_interrupt: bool = False
    ) -> None:
        if not Path("/bin/ps").is_file():
            self.skipTest("/bin/ps is required to observe process state")
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
                os.kill(python_pid, signal.SIGSTOP)
                wait_for_process_state(python_pid, "T")
                process.send_signal(signal.SIGTERM)
                if repeat_interrupt:
                    time.sleep(0.05)
                    process.send_signal(signal.SIGINT)
                elif external_supervisor_kill:
                    time.sleep(0.05)
                    os.kill(python_pid, signal.SIGKILL)
                stdout, stderr = process.communicate(timeout=8)
                self.assertEqual(process.returncode, 69)
                self.assertEqual(stdout, b"")
                self.assertEqual(
                    stderr,
                    canonical_json(
                        {
                            "evidence_boundary": EVIDENCE_BOUNDARY,
                            "operation": "launcher",
                            "reason": "cleanup_unconfirmed",
                            "schema_version": "contextguard-receipt-cli-response/v1",
                            "status": "error",
                        }
                    ).encode("ascii"),
                )
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

    def test_launcher_reports_unconfirmed_cleanup_after_interrupt_escalation(self) -> None:
        """Break caught: forced CLI termination silently strands the escrowed command."""

        self._assert_launcher_reports_unconfirmed_cleanup(repeat_interrupt=False)

    def test_repeated_interrupt_reports_unconfirmed_cleanup_after_sigkill(self) -> None:
        """Break caught: repeated-interrupt SIGKILL is reported as graceful cleanup."""

        self._assert_launcher_reports_unconfirmed_cleanup(repeat_interrupt=True)

    def test_externally_killed_supervisor_reports_unconfirmed_cleanup(self) -> None:
        """Break caught: an externally killed supervisor is treated as graceful cleanup."""

        self._assert_launcher_reports_unconfirmed_cleanup(external_supervisor_kill=True)

    def test_mcp_launcher_preserves_normal_interrupt_exit_semantics(self) -> None:
        """Break caught: MCP rejects an expected forwarded-signal close outcome."""

        for interrupt in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(interrupt=interrupt):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    root = Path(temporary_directory).resolve()
                    runtime = copy_runtime_with_current_launcher(root / "runtime")
                    record = root / "mcp-child-record"
                    preload = root / "record-mcp-child.cjs"
                    preload.write_text(
                        "'use strict';\n"
                        "const childProcess = require('child_process');\n"
                        "const fs = require('fs');\n"
                        "const originalSpawn = childProcess.spawn.bind(childProcess);\n"
                        "childProcess.spawn = (...arguments_) => {\n"
                        "  const child = originalSpawn(...arguments_);\n"
                        "  if (arguments_[1].includes('--launcher-probe')) return child;\n"
                        "  fs.writeFileSync(\n"
                        "    process.env.CGR_MCP_CHILD_RECORD,\n"
                        "    `${child.pid}:${process.pid}`\n"
                        "  );\n"
                        "  return child;\n"
                        "};\n",
                        encoding="ascii",
                    )
                    process = subprocess.Popen(
                        [
                            str(Path(NODE).resolve()),
                            str(runtime / "bin/context-guard-receipt-mcp.cjs"),
                            "--root",
                            str(PACKAGE_ROOT.resolve()),
                        ],
                        cwd=PACKAGE_ROOT,
                        env=launcher_environment(
                            CGR_MCP_CHILD_RECORD=str(record),
                            NODE_OPTIONS=f"--require={preload}",
                        ),
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    python_pid = 0
                    try:
                        python_pid, parent_pid = read_child_record(record)
                        self.assertEqual(parent_pid, process.pid)
                        self.assertIsNotNone(process.stdin)
                        self.assertIsNotNone(process.stdout)
                        process.stdin.write(
                            canonical_json(
                                {
                                    "id": 1,
                                    "jsonrpc": "2.0",
                                    "method": "initialize",
                                    "params": {
                                        "capabilities": {},
                                        "clientInfo": {
                                            "name": "g001-signal-test",
                                            "version": "1",
                                        },
                                        "protocolVersion": "2025-11-25",
                                    },
                                }
                            ).encode("ascii")
                        )
                        process.stdin.flush()
                        readable, _, _ = select.select([process.stdout], [], [], 5.0)
                        self.assertEqual(readable, [process.stdout])
                        initialized = process.stdout.readline()
                        self.assertNotEqual(initialized, b"")
                        self.assertEqual(json.loads(initialized)["id"], 1)

                        process.send_signal(interrupt)
                        stdout, stderr = process.communicate(timeout=8)
                        self.assertEqual(process.returncode, 128 + interrupt, stderr)
                        self.assertEqual(stdout, b"")
                        self.assertEqual(stderr, b"")
                        self.assertTrue(wait_for_process_exit(python_pid))
                    finally:
                        if process.poll() is None:
                            process.kill()
                        try:
                            process.communicate(timeout=3)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.communicate(timeout=3)
                        if python_pid > 0 and process_exists(python_pid):
                            try:
                                os.kill(python_pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass

    @unittest.skipUnless(shutil.which("cc"), "a native compiler is required")
    def test_mcp_launcher_reports_unconfirmed_cleanup_after_escalation(self) -> None:
        """Break caught: forced MCP termination silently reports graceful cleanup."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            runtime = copy_runtime_with_current_launcher(root / "runtime")
            preload = root / "signal-ready.cjs"
            preload.write_text(
                "'use strict';\n"
                "const childProcess = require('child_process');\n"
                "const fs = require('fs');\n"
                "const originalSpawn = childProcess.spawn.bind(childProcess);\n"
                "childProcess.spawn = (...arguments_) => {\n"
                "  const child = originalSpawn(...arguments_);\n"
                "  if (arguments_[1].includes('--launcher-probe')) return child;\n"
                "  const originalKill = child.kill.bind(child);\n"
                "  child.kill = (signalName) => {\n"
                "    const delivered = originalKill(signalName);\n"
                "    if (signalName === 'SIGTERM') {\n"
                "      fs.writeFileSync(process.env.CGR_CHILD_SIGNAL_RECORD, 'SIGTERM');\n"
                "    }\n"
                "    return delivered;\n"
                "  };\n"
                "  return child;\n"
                "};\n"
                "fs.writeFileSync(process.env.CGR_SIGNAL_READY, 'loaded');\n"
                "const timer = setInterval(() => {\n"
                "  if (process.listenerCount('SIGTERM') > 0) {\n"
                "    fs.writeFileSync(process.env.CGR_SIGNAL_READY, 'ready');\n"
                "    clearInterval(timer);\n"
                "  }\n"
                "}, 1);\n",
                encoding="ascii",
            )
            source = root / "mcp-runtime.c"
            native_runtime = root / "mcp-runtime"
            source.write_text(
                "#include <signal.h>\n"
                "#include <stdio.h>\n"
                "#include <stdlib.h>\n"
                "#include <string.h>\n"
                "#include <unistd.h>\n"
                "int main(int argc, char **argv) {\n"
                "  for (int i = 1; i < argc; ++i) {\n"
                "    if (strcmp(argv[i], \"--launcher-probe\") == 0) {\n"
                "      fputs(\"{\\\"implementation\\\":\\\"CPython\\\","
                "\\\"package_protocol\\\":\\\"contextguard-receipt-launch/v1\\\","
                "\\\"python_version\\\":[3,11]}\\n\", stdout);\n"
                "      return 0;\n"
                "    }\n"
                "  }\n"
                "  signal(SIGINT, SIG_IGN);\n"
                "  signal(SIGTERM, SIG_IGN);\n"
                "  const char *record = getenv(\"CGR_MCP_RUNTIME_RECORD\");\n"
                "  if (record != NULL) {\n"
                "    FILE *stream = fopen(record, \"w\");\n"
                "    if (stream != NULL) {\n"
                "      fprintf(stream, \"%ld:%ld\", (long)getpid(), (long)getppid());\n"
                "      fclose(stream);\n"
                "    }\n"
                "  }\n"
                "  for (;;) pause();\n"
                "}\n",
                encoding="ascii",
            )
            compilation = subprocess.run(
                [str(shutil.which("cc")), str(source), "-o", str(native_runtime)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=15.0,
            )
            self.assertEqual(compilation.returncode, 0, compilation.stderr)
            native_runtime.chmod(0o755)
            for external_child_kill in (False, True):
                with self.subTest(external_child_kill=external_child_kill):
                    suffix = "external" if external_child_kill else "escalated"
                    record = root / f"mcp-runtime-record-{suffix}"
                    signal_ready = root / f"signal-ready-{suffix}"
                    child_signal_record = root / f"child-signal-{suffix}"
                    process = subprocess.Popen(
                        [
                            str(Path(NODE).resolve()),
                            str(runtime / "bin/context-guard-receipt-mcp.cjs"),
                            "--root",
                            str(PACKAGE_ROOT.resolve()),
                        ],
                        cwd=PACKAGE_ROOT,
                        env=launcher_environment(
                            CGR_CHILD_SIGNAL_RECORD=str(child_signal_record),
                            CGR_MCP_RUNTIME_RECORD=str(record),
                            CGR_SIGNAL_READY=str(signal_ready),
                            NODE_OPTIONS=f"--require={preload}",
                            **{PYTHON_ENV: str(native_runtime)},
                        ),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    child_pid = 0
                    try:
                        child_pid, parent_pid = read_child_record(record)
                        self.assertEqual(parent_pid, process.pid)
                        ready_deadline = time.monotonic() + 3.0
                        while time.monotonic() < ready_deadline:
                            try:
                                if signal_ready.read_bytes() == b"ready":
                                    break
                            except FileNotFoundError:
                                pass
                            time.sleep(0.02)
                        self.assertEqual(signal_ready.read_bytes(), b"ready")
                        process.send_signal(signal.SIGTERM)
                        if external_child_kill:
                            signal_deadline = time.monotonic() + 3.0
                            while time.monotonic() < signal_deadline:
                                try:
                                    if child_signal_record.read_bytes() == b"SIGTERM":
                                        break
                                except FileNotFoundError:
                                    pass
                                time.sleep(0.02)
                            self.assertEqual(
                                child_signal_record.read_bytes(), b"SIGTERM"
                            )
                            os.kill(child_pid, signal.SIGKILL)
                        stdout, stderr = process.communicate(timeout=8)
                        self.assertEqual(process.returncode, 69)
                        self.assertEqual(stdout, b"")
                        self.assertEqual(
                            stderr,
                            canonical_json(
                                {
                                    "evidence_boundary": EVIDENCE_BOUNDARY,
                                    "operation": "launcher",
                                    "reason": "cleanup_unconfirmed",
                                    "schema_version": (
                                        "contextguard-receipt-cli-response/v1"
                                    ),
                                    "status": "error",
                                }
                            ).encode("ascii"),
                        )
                    finally:
                        if process.poll() is None:
                            process.kill()
                        try:
                            process.communicate(timeout=3)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.communicate(timeout=3)
                        if child_pid > 0 and process_exists(child_pid):
                            try:
                                os.kill(child_pid, signal.SIGKILL)
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
            (fallback_bin / "python3").symlink_to(Path("/usr/bin/true"))
            fallback_environment = launcher_environment(PATH=str(fallback_bin))
            fallback_environment.pop(PYTHON_ENV)
            fallback = run_node(
                "bin/context-guard-receipt.cjs",
                "inspect",
                "boundary",
                environment=fallback_environment,
            )
            assert_json_error(
                self,
                fallback,
                code=78,
                operation="launcher",
                status="error",
                reason="protocol_incompatible",
            )

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

            writable_native = temporary_root / "caller-selected-writable-native"
            shutil.copyfile("/usr/bin/true", writable_native)
            writable_native.chmod(0o777)
            explicit_writable = run_node(
                "bin/context-guard-receipt.cjs",
                "inspect",
                "boundary",
                environment=launcher_environment(**{PYTHON_ENV: str(writable_native)}),
            )
            assert_json_error(
                self,
                explicit_writable,
                code=78,
                operation="launcher",
                status="error",
                reason="protocol_incompatible",
            )

            writable_bin = temporary_root / "writable-bin"
            writable_bin.mkdir()
            (writable_bin / "python3").symlink_to(writable_native)
            writable_path_environment = launcher_environment(PATH=str(writable_bin))
            writable_path_environment.pop(PYTHON_ENV)
            automatic_writable = run_node(
                "bin/context-guard-receipt.cjs",
                "inspect",
                "boundary",
                environment=writable_path_environment,
            )
            assert_json_error(
                self,
                automatic_writable,
                code=69,
                operation="launcher",
                status="error",
                reason="runtime_unavailable",
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

    def test_explicit_runtime_trust_does_not_weaken_automatic_discovery(self) -> None:
        """Break caught: real-UID access widens PATH trust or rejects an effective-UID runtime."""

        launcher_source = (PACKAGE_ROOT / "bin/launcher.cjs").read_text(encoding="utf-8")
        function_start = launcher_source.index("function effectiveCredentials(")
        function_end = launcher_source.index(
            "\n}\n\nfunction trustedRuntimeAncestry", function_start
        ) + 2
        function_source = launcher_source[function_start:function_end]
        script = f"""
const functionSource = {json.dumps(function_source)};
let metadata;
const fakeFs = {{
  constants: {{ O_NOFOLLOW: 0x100, O_RDONLY: 0 }},
  fstatSync: () => metadata,
  accessSync: () => {{ throw new Error('real uid cannot execute'); }},
  openSync: () => 3,
  readSync: (_descriptor, buffer) => {{ buffer.writeUInt32BE(0x7f454c46, 0); return 4; }},
  closeSync: () => undefined,
}};
const fakeProcess = {{
  getuid: () => 1000,
  geteuid: () => 2000,
  getegid: () => 3000,
  getgroups: () => [3000, 4000],
}};
const predicateFor = (candidateProcess) => new Function(
  'fs', 'process', 'Buffer', 'Set',
  `${{functionSource}}; return nativeExecutableRegularFile;`,
)(fakeFs, candidateProcess, Buffer, Set);
const evaluate = (uid, gid, mode, explicit = false, candidateProcess = fakeProcess) => {{
  metadata = {{
    isFile: () => true,
    dev: 1n,
    ino: 2n,
    mode: BigInt(mode),
    uid: BigInt(uid),
    gid: BigInt(gid),
    nlink: 1n,
    size: 4096n,
    mtimeNs: 4n,
    ctimeNs: 5n,
  }};
  return Boolean(predicateFor(candidateProcess)('/managed/runtime', explicit));
}};
process.stdout.write(JSON.stringify({{
  effective_uid_owner: evaluate(2000, 3000, 0o100755),
  effective_uid_wrong_class: evaluate(2000, 3000, 0o100401),
  real_uid_owner: evaluate(1000, 3000, 0o100755),
  root_owner: evaluate(0, 5000, 0o100755),
  root_supplementary_group: evaluate(0, 4000, 0o100410),
  root_non_group_wrong_class: evaluate(0, 5000, 0o100410),
  foreign_owner: evaluate(4242, 5000, 0o100755),
  explicit_foreign_writable: evaluate(4242, 5000, 0o100777, true),
  explicit_foreign_non_group_wrong_class: evaluate(4242, 5000, 0o100410, true),
  explicit_foreign_other_execute: evaluate(4242, 5000, 0o100401, true),
  root_effective_uid_any_execute: evaluate(
    0,
    5000,
    0o100001,
    false,
    {{ geteuid: () => 0, getegid: () => 0, getgroups: () => [0] }},
  ),
  missing_geteuid: (() => {{
    metadata = {{
      isFile: () => true,
      dev: 1n,
      ino: 2n,
      mode: 0o100755n,
      uid: 1000n,
      gid: 3n,
      nlink: 1n,
      size: 4096n,
      mtimeNs: 4n,
      ctimeNs: 5n,
    }};
    return Boolean(predicateFor({{ getuid: () => 1000 }})('/managed/runtime', false));
  }})(),
  missing_getegid: evaluate(
    4242,
    5000,
    0o100401,
    true,
    {{ geteuid: () => 2000, getgroups: () => [4000] }},
  ),
  missing_getgroups: evaluate(
    4242,
    5000,
    0o100401,
    true,
    {{ geteuid: () => 2000, getegid: () => 3000 }},
  ),
  invalid_effective_uid: evaluate(
    4242,
    5000,
    0o100401,
    true,
    {{ geteuid: () => -1, getegid: () => 3000, getgroups: () => [4000] }},
  ),
  invalid_supplementary_group: evaluate(
    4242,
    5000,
    0o100401,
    true,
    {{ geteuid: () => 2000, getegid: () => 3000, getgroups: () => [-1] }},
  ),
}}));
"""
        result = subprocess.run(
            [str(Path(NODE).resolve()), "-e", script],
            cwd=PACKAGE_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout),
            {
                "effective_uid_owner": True,
                "effective_uid_wrong_class": False,
                "real_uid_owner": False,
                "root_owner": True,
                "root_supplementary_group": True,
                "root_non_group_wrong_class": False,
                "foreign_owner": False,
                "explicit_foreign_writable": True,
                "explicit_foreign_non_group_wrong_class": False,
                "explicit_foreign_other_execute": True,
                "root_effective_uid_any_execute": True,
                "missing_geteuid": False,
                "missing_getegid": False,
                "missing_getgroups": False,
                "invalid_effective_uid": False,
                "invalid_supplementary_group": False,
            },
        )

    def test_wrong_execute_class_is_runtime_unavailable_before_probe(self) -> None:
        """Break caught: an inapplicable execute bit reaches the compatibility probe."""

        require_distribution()
        if os.geteuid() == 0:
            self.skipTest("root bypasses per-class execute bits")
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory).resolve()
            distribution = copy_runtime_with_current_launcher(temporary_root / "distribution")
            runtime_bin = temporary_root / "wrong-class" / "bin"
            runtime_bin.mkdir(parents=True)
            runtime_bin.parent.chmod(0o755)
            runtime_bin.chmod(0o755)
            runtime = runtime_bin / "python3"
            shutil.copyfile(Path(sys.executable).resolve(), runtime)
            runtime.chmod(0o401)

            explicit_environment = launcher_environment(**{PYTHON_ENV: str(runtime)})
            automatic_environment = launcher_environment(PATH=str(runtime_bin))
            automatic_environment.pop(PYTHON_ENV)
            for selection, environment in (
                ("explicit", explicit_environment),
                ("automatic", automatic_environment),
            ):
                with self.subTest(selection=selection):
                    response = run_node(
                        "bin/context-guard-receipt.cjs",
                        "inspect",
                        "boundary",
                        environment=environment,
                        package_root=distribution,
                    )
                    assert_json_error(
                        self,
                        response,
                        code=69,
                        operation="launcher",
                        status="error",
                        reason="runtime_unavailable",
                    )

    def test_automatic_runtime_path_requires_trusted_physical_ancestry(self) -> None:
        """Break caught: a native PATH runtime beneath a writable non-sticky ancestor launches."""

        require_distribution()
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory).resolve()
            distribution = copy_runtime_with_current_launcher(temporary_root / "distribution")

            safe_bin = temporary_root / "safe" / "bin"
            safe_bin.mkdir(parents=True)
            safe_bin.parent.chmod(0o1777)
            safe_bin.chmod(0o755)
            safe_python = safe_bin / "python3"
            native_fixture = Path("/usr/bin/true")
            if not native_fixture.is_file():
                native_fixture = Path("/bin/true")
            self.assertTrue(native_fixture.is_file())
            shutil.copyfile(native_fixture, safe_python)
            safe_python.chmod(0o755)
            effective_uid = os.geteuid()
            for ancestor in (safe_python.parent, *safe_python.parents[1:]):
                metadata = ancestor.stat()
                mode = stat.S_IMODE(metadata.st_mode)
                if (
                    not ancestor.is_dir()
                    or metadata.st_uid not in {0, effective_uid}
                    or ((mode & 0o022) != 0 and (mode & stat.S_ISVTX) == 0)
                ):
                    self.skipTest("the temporary ancestry is outside automatic PATH policy")
            safe_environment = launcher_environment(PATH=str(safe_bin))
            safe_environment.pop(PYTHON_ENV)
            safe = run_node(
                "bin/context-guard-receipt.cjs",
                "inspect",
                "boundary",
                environment=safe_environment,
                package_root=distribution,
            )
            assert_json_error(
                self,
                safe,
                code=78,
                operation="launcher",
                status="error",
                reason="protocol_incompatible",
            )

            unsafe_parent = temporary_root / "unsafe"
            unsafe_bin = unsafe_parent / "bin"
            unsafe_bin.mkdir(parents=True)
            unsafe_parent.chmod(0o777)
            unsafe_bin.chmod(0o755)
            unsafe_python = unsafe_bin / "python3"
            shutil.copyfile(native_fixture, unsafe_python)
            unsafe_python.chmod(0o755)
            unsafe_environment = launcher_environment(PATH=str(unsafe_bin))
            unsafe_environment.pop(PYTHON_ENV)
            unsafe = run_node(
                "bin/context-guard-receipt.cjs",
                "inspect",
                "boundary",
                environment=unsafe_environment,
                package_root=distribution,
            )
            assert_json_error(
                self,
                unsafe,
                code=69,
                operation="launcher",
                status="error",
                reason="runtime_unavailable",
            )

    def test_automatic_runtime_path_preserves_a_trusted_interpreter_symlink(self) -> None:
        """Break caught: canonicalization rejects a symlink to a trusted physical CPython target."""

        require_distribution()
        effective_uid = os.geteuid()
        interpreter = Path(sys.executable).resolve()
        leaf = interpreter.stat()
        if leaf.st_uid not in {0, effective_uid} or stat.S_IMODE(leaf.st_mode) & 0o022:
            self.skipTest("the current interpreter leaf is outside automatic PATH policy")
        for ancestor in (interpreter.parent, *interpreter.parents[1:]):
            metadata = ancestor.stat()
            mode = stat.S_IMODE(metadata.st_mode)
            if (
                not ancestor.is_dir()
                or metadata.st_uid not in {0, effective_uid}
                or ((mode & 0o022) != 0 and (mode & stat.S_ISVTX) == 0)
            ):
                self.skipTest("the current interpreter ancestry is outside automatic PATH policy")

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory).resolve()
            distribution = copy_runtime_with_current_launcher(temporary_root / "distribution")
            runtime_bin = temporary_root / "symlink" / "bin"
            runtime_bin.mkdir(parents=True)
            runtime_bin.parent.chmod(0o755)
            runtime_bin.chmod(0o755)
            (runtime_bin / "python3").symlink_to(interpreter)
            environment = launcher_environment(PATH=str(runtime_bin))
            environment.pop(PYTHON_ENV)
            response = run_node(
                "bin/context-guard-receipt.cjs",
                "inspect",
                "boundary",
                environment=environment,
                package_root=distribution,
            )
            self.assertEqual(response.returncode, 0, response.stderr)
            self.assertEqual(response.stderr, "")
            self.assertEqual(response.stdout, canonical_json(EXPECTED_BOUNDARY_RESPONSE))

    def test_probe_is_bounded_with_sigkill_and_retains_its_output_limit(self) -> None:
        """Break caught: asynchronous probe capture loses its 16 KiB fail-closed bound."""

        launcher_path = PACKAGE_ROOT / "bin/launcher.cjs"
        script = r"""
const fs = require('fs');
const { EventEmitter } = require('events');
const { PassThrough } = require('stream');
const vm = require('vm');
const launcherPath = process.argv[1];
const source = fs.readFileSync(launcherPath, 'utf8').replace(
  'module.exports = { launch };',
  'module.exports = { compatibleProbe };',
);
let captured;
let spawnCalls = 0;
const kills = [];
const fakeChildProcess = {
  spawn: (...arguments_) => {
    captured = arguments_;
    spawnCalls += 1;
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    let closed = false;
    child.kill = (signalName) => {
      kills.push(signalName);
      if (!closed) {
        closed = true;
        setImmediate(() => child.emit('close', null, signalName));
      }
      return true;
    };
    setImmediate(() => {
      if (spawnCalls === 1) {
        child.stdout.write('{"implementation":"CPython","package_protocol":' +
          '"contextguard-receipt-launch/v1","python_version":[3,11]}\n');
        closed = true;
        child.emit('close', 0, null);
      } else {
        child.stdout.write(Buffer.alloc((16 * 1024) + 1, 120));
      }
    });
    return child;
  },
};
const context = {
  Buffer,
  clearTimeout,
  console,
  module: { exports: {} },
  process,
  require: (identifier) => identifier === 'child_process'
    ? fakeChildProcess
    : require(identifier),
  setImmediate,
  setTimeout,
};
vm.runInNewContext(source, context, { filename: launcherPath });
const signalController = () => ({
  bind: () => true,
  remove: () => undefined,
  unbind: () => undefined,
});
void (async () => {
  const compatible = await context.module.exports.compatibleProbe(
    '/runtime/python3', '/package/bootstrap.py', signalController(),
  );
  const overLimit = await context.module.exports.compatibleProbe(
    '/runtime/python3', '/package/bootstrap.py', signalController(),
  );
  process.stdout.write(JSON.stringify({ compatible, kills, options: captured[2], overLimit }));
})();
"""
        result = subprocess.run(
            [str(Path(NODE).resolve()), "-e", script, str(launcher_path)],
            cwd=PACKAGE_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        captured = json.loads(result.stdout)
        self.assertTrue(captured["compatible"])
        self.assertEqual(
            captured["options"],
            {
                "stdio": ["ignore", "pipe", "pipe"],
                "windowsHide": True,
            },
        )
        self.assertFalse(captured["overLimit"])
        self.assertEqual(captured["kills"], ["SIGKILL"])

    def test_runtime_identity_replacement_after_probe_is_rejected_before_launch(self) -> None:
        """Break caught: probe success authorizes a different pathname identity for launch."""

        launcher_path = PACKAGE_ROOT / "bin/launcher.cjs"
        script = r"""
const fs = require('fs');
const { EventEmitter } = require('events');
const { PassThrough } = require('stream');
const vm = require('vm');
const launcherPath = process.argv[1];
const source = fs.readFileSync(launcherPath, 'utf8').replace(
  '  if (!validatePackage(packageRoot)) {',
  '  if (false) {',
);
const initial = {
  isFile: () => true,
  dev: 10n,
  ino: 20n,
  mode: 0o100755n,
  uid: 2000n,
  gid: 2000n,
  nlink: 1n,
  size: 4096n,
  mtimeNs: 30n,
  ctimeNs: 40n,
};
const replacement = { ...initial, ino: 21n, ctimeNs: 41n };
let fstatCalls = 0;
const openFlags = [];
const fakeFs = {
  constants: { O_NOFOLLOW: 0x100, O_RDONLY: 0, X_OK: 1 },
  realpathSync: (candidate) => candidate,
  statSync: () => ({ isFile: () => true, mode: 0o100755, uid: 2000 }),
  lstatSync: () => ({ isSymbolicLink: () => false }),
  accessSync: () => undefined,
  openSync: (_candidate, flags) => { openFlags.push(flags); return openFlags.length; },
  fstatSync: () => (++fstatCalls < 3 ? initial : replacement),
  readSync: (_descriptor, buffer) => { buffer.writeUInt32BE(0x7f454c46, 0); return 4; },
  closeSync: () => undefined,
};
let spawnCalls = 0;
const fakeChildProcess = {
  spawn: () => {
    spawnCalls += 1;
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.kill = () => true;
    setImmediate(() => {
      child.stdout.write('{"implementation":"CPython","package_protocol":' +
        '"contextguard-receipt-launch/v1","python_version":[3,11]}\n');
      child.emit('close', 0, null);
    });
    return child;
  },
};
let stderr = '';
const fakeProcess = {
  env: { CONTEXT_GUARD_RECEIPT_PYTHON: '/runtime/python3' },
  exitCode: undefined,
  geteuid: () => 2000,
  getegid: () => 2000,
  getgroups: () => [2000],
  getuid: () => 1000,
  on: () => undefined,
  removeListener: () => undefined,
  stderr: {
    once: () => undefined,
    removeListener: () => undefined,
    write: (payload, callback) => { stderr += payload.toString('ascii'); callback(); },
  },
};
const context = {
  Buffer,
  clearTimeout,
  console,
  module: { exports: {} },
  process: fakeProcess,
  require: (identifier) => {
    if (identifier === 'child_process') return fakeChildProcess;
    if (identifier === 'fs') return fakeFs;
    return require(identifier);
  },
  setImmediate,
  setTimeout,
};
vm.runInNewContext(source, context, { filename: launcherPath });
const result = context.module.exports.launch(
  'cli',
  ['inspect', 'boundary'],
  '/package/bin/context-guard-receipt.cjs',
);
setImmediate(() => setImmediate(() => process.stdout.write(JSON.stringify({
  exitCode: fakeProcess.exitCode,
  openFlags,
  resultIsUndefined: result === undefined,
  spawnCalls,
  stderr,
}))));
"""
        result = subprocess.run(
            [str(Path(NODE).resolve()), "-e", script, str(launcher_path)],
            cwd=PACKAGE_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = json.loads(result.stdout)
        self.assertEqual(observed["openFlags"], [0x100, 0x100, 0x100])
        self.assertTrue(observed["resultIsUndefined"])
        self.assertEqual(observed["exitCode"], 69)
        self.assertEqual(observed["spawnCalls"], 1)
        self.assertEqual(
            observed["stderr"],
            canonical_json(
                {
                    "evidence_boundary": EVIDENCE_BOUNDARY,
                    "operation": "launcher",
                    "reason": "runtime_unavailable",
                    "schema_version": "contextguard-receipt-cli-response/v1",
                    "status": "error",
                }
            ),
        )

    @unittest.skipUnless(shutil.which("cc"), "a native compiler is required")
    def test_hanging_native_probe_is_killed_within_the_compatibility_bound(self) -> None:
        """Break caught: a native executable that hangs during probing can hang the launcher."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory).resolve()
            distribution = copy_runtime_with_current_launcher(temporary_root / "distribution")
            source = temporary_root / "hanging-runtime.c"
            runtime = temporary_root / "hanging-runtime"
            source.write_text(
                "#include <time.h>\n"
                "int main(void) {\n"
                "  struct timespec delay = {30, 0};\n"
                "  nanosleep(&delay, 0);\n"
                "  return 0;\n"
                "}\n",
                encoding="ascii",
            )
            compilation = subprocess.run(
                [str(shutil.which("cc")), str(source), "-o", str(runtime)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(compilation.returncode, 0, compilation.stderr)
            runtime.chmod(0o755)

            started = time.monotonic()
            try:
                response = subprocess.run(
                    [
                        str(Path(NODE).resolve()),
                        str(distribution / "bin/context-guard-receipt.cjs"),
                        "inspect",
                        "boundary",
                    ],
                    cwd=distribution,
                    env=launcher_environment(**{PYTHON_ENV: str(runtime)}),
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=25.0,
                )
            except subprocess.TimeoutExpired as error:
                self.fail(f"launcher exceeded the outer {error.timeout}-second test bound")
            elapsed = time.monotonic() - started
            assert_json_error(
                self,
                response,
                code=78,
                operation="launcher",
                status="error",
                reason="protocol_incompatible",
            )
            self.assertGreater(elapsed, 4.5)
            self.assertLess(elapsed, 8.0)

    @unittest.skipUnless(shutil.which("cc"), "a native compiler is required")
    def test_deep_valid_probe_json_is_canonical_protocol_incompatible(self) -> None:
        """Break caught: bounded deep JSON escapes as a Node stack trace."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory).resolve()
            distribution = copy_runtime_with_current_launcher(
                temporary_root / "distribution"
            )
            source = temporary_root / "deep-probe.c"
            runtime = temporary_root / "deep-probe"
            source.write_text(
                "#include <stdio.h>\n"
                "#include <string.h>\n"
                "int main(int argc, char **argv) {\n"
                "  int probe = 0;\n"
                "  for (int index = 1; index < argc; ++index) {\n"
                "    if (strcmp(argv[index], \"--launcher-probe\") == 0) probe = 1;\n"
                "  }\n"
                "  if (!probe) return 0;\n"
                "  for (int depth = 0; depth < 8000; ++depth) putchar('[');\n"
                "  putchar('0');\n"
                "  for (int depth = 0; depth < 8000; ++depth) putchar(']');\n"
                "  putchar('\\n');\n"
                "  return ferror(stdout) ? 1 : 0;\n"
                "}\n",
                encoding="ascii",
            )
            compilation = subprocess.run(
                [str(shutil.which("cc")), str(source), "-o", str(runtime)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=8.0,
            )
            self.assertEqual(compilation.returncode, 0, compilation.stderr)
            runtime.chmod(0o755)
            response = subprocess.run(
                [
                    str(Path(NODE).resolve()),
                    str(distribution / "bin/context-guard-receipt.cjs"),
                    "inspect",
                    "boundary",
                ],
                cwd=distribution,
                env=launcher_environment(**{PYTHON_ENV: str(runtime)}),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=8.0,
            )
            assert_json_error(
                self,
                response,
                code=78,
                operation="launcher",
                status="error",
                reason="protocol_incompatible",
            )

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
            (
                "inspect",
                "diagnostics",
                "--state-dir",
                "/tmp/contextguard-receipt-state",
                "--input",
                "-",
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
