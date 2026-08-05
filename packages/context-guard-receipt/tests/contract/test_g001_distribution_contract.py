from __future__ import annotations

import hashlib
import json
import os
import py_compile
import shutil
import stat
import subprocess
import sys
import tempfile
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
    "  assemble --kind <kind> --descriptor <file|-> [options]\n"
    "  run --escrow --root <absolute> --state-dir <absolute> "
    "--receipt-out <file> -- <command>\n"
    "  expand <handle> --state-dir <absolute> [options]\n"
    "  inspect <receipt|diagnostics|firewall|diagnostic-ledger|twin|lease|state> "
    "[options]\n\n"
    "Only inspect boundary is available in this release.\n"
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
    "python/context_guard_receipt/canonical.py": 0o644,
    "python/context_guard_receipt/cli.py": 0o644,
    "python/context_guard_receipt/contracts.py": 0o644,
    "python/context_guard_receipt/identity.py": 0o644,
    "python/context_guard_receipt/protection.py": 0o644,
    "schemas/evidence-boundary.schema.json": 0o644,
    "schemas/protection-decision.schema.json": 0o644,
    "schemas/source-identity.schema.json": 0o644,
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
            (
                "run",
                "--escrow",
                "--root",
                ".",
                "--state-dir",
                "/tmp/state",
                "--receipt-out",
                "receipt.json",
                "--",
                "/bin/true",
            ),
            ("expand", "not-a-handle", "--state-dir", "/tmp/state"),
            ("expand", "cgr1p_handle", "--state-dir", "relative"),
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
            inactive = (
                (
                    "assemble",
                    ("assemble", "--kind", "evidence", "--descriptor", "-"),
                ),
                (
                    "assemble",
                    (
                        "assemble",
                        "--kind",
                        "blueprint",
                        "--descriptor",
                        "descriptor.json",
                        "--root",
                        str(root),
                        "--persist",
                        "--state-dir",
                        str(root / "state"),
                        "--emit",
                        "json",
                        "--receipt-out",
                        str(root / "receipt.json"),
                    ),
                ),
                (
                    "run",
                    (
                        "run",
                        "--escrow",
                        "--root",
                        str(root),
                        "--state-dir",
                        str(root / "state"),
                        "--receipt-out",
                        str(root / "receipt.json"),
                        "--",
                        "/bin/sh",
                        "-c",
                        f"touch {sentinel}",
                        "--",
                        "opaque-command-argument",
                    ),
                ),
                (
                    "expand",
                    ("expand", "cgr1p_not-issued", "--state-dir", str(root / "state")),
                ),
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
            self.assertFalse((root / "state").exists())
            self.assertFalse((root / "receipt.json").exists())

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
