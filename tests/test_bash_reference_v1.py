#!/usr/bin/env python3
"""Focused contracts for the opt-in Bash receipt-reference path."""
from __future__ import annotations

import contextlib
import base64
import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import warnings
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TRIM = ROOT / "context-guard-kit" / "trim_command_output.py"
REWRITE = ROOT / "context-guard-kit" / "rewrite_bash_for_token_budget.py"
SETUP = ROOT / "context-guard-kit" / "setup_wizard.py"
DISPATCHER = ROOT / "context-guard-kit" / "context_guard_cli.py"
VALID_HANDLE = "cgr1p_" + "R" * 43


def load_trim():
    spec = importlib.util.spec_from_file_location("trim_reference_test", TRIM)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_policy(path: Path | None = None):
    path = path or (ROOT / "context-guard-kit" / "bash_reference_policy.py")
    spec = importlib.util.spec_from_file_location("bash_reference_policy_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_script(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class BashReferenceV1Tests(unittest.TestCase):
    def test_root_policy_pin_matches_the_frozen_receipt_package_manifest(self):
        """The shipped root trust anchor must match the exact paired candidate."""
        policy = load_policy()
        receipt_root = ROOT / "packages" / "context-guard-receipt"
        package = json.loads((receipt_root / "package.json").read_text(encoding="utf-8"))
        manifest_bytes = (receipt_root / "package-files.json").read_bytes()
        self.assertEqual(
            policy.EXPECTED_RECEIPT_PACKAGE_FILES_SHA256_BY_VERSION[package["version"]],
            hashlib.sha256(manifest_bytes).hexdigest(),
        )

    def test_resolver_uses_installed_context_guard_exact_dependency_for_hoisted_receipt(self):
        """A user app need not itself be named ContextGuard or depend on Receipt."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp).resolve()
            (project / "package.json").write_text(
                json.dumps({"name": "customer-application", "dependencies": {"@ictechgy/context-guard": "0.4.16"}}),
                encoding="utf-8",
            )
            context_guard = project / "node_modules" / "@ictechgy" / "context-guard"
            policy_path = context_guard / "plugins" / "context-guard" / "bin" / "bash_reference_policy.py"
            policy_path.parent.mkdir(parents=True)
            shutil.copy2(ROOT / "context-guard-kit" / "bash_reference_policy.py", policy_path)
            (context_guard / "package.json").write_text(
                json.dumps({
                    "name": "@ictechgy/context-guard", "version": "0.4.16",
                    "dependencies": {"@ictechgy/context-guard-receipt": "0.2.0"},
                }),
                encoding="utf-8",
            )
            receipt = project / "node_modules" / "@ictechgy" / "context-guard-receipt"
            cli = receipt / "bin" / "context-guard-receipt.cjs"
            cli.parent.mkdir(parents=True)
            package_bytes = json.dumps({"name": "@ictechgy/context-guard-receipt", "version": "0.2.0"}).encode()
            cli_bytes = b"#!/usr/bin/env node\n"
            launcher_bytes = b"// verified launcher\n"
            (receipt / "package.json").write_bytes(package_bytes)
            cli.write_bytes(cli_bytes)
            (receipt / "bin" / "launcher.cjs").write_bytes(launcher_bytes)
            cli.chmod(0o700)
            manifest_bytes = json.dumps({"files": [
                {"path": "package.json", "sha256": hashlib.sha256(package_bytes).hexdigest()},
                {"path": "bin/context-guard-receipt.cjs", "sha256": hashlib.sha256(cli_bytes).hexdigest()},
                {"path": "bin/launcher.cjs", "sha256": hashlib.sha256(launcher_bytes).hexdigest()},
            ]}).encode()
            (receipt / "package-files.json").write_bytes(manifest_bytes)

            policy = load_policy(policy_path)
            policy.EXPECTED_RECEIPT_PACKAGE_FILES_SHA256_BY_VERSION["0.2.0"] = hashlib.sha256(manifest_bytes).hexdigest()
            trusted_runtime = Path(sys.executable).resolve()
            policy._trusted_node_interpreter = lambda _root: (
                trusted_runtime,
                policy._executable_identity(trusted_runtime),
            )
            adapter, reason = policy.discover_adapter(project)

            self.assertIsNotNone(adapter)
            self.assertEqual(reason, "receipt_adapter_available")

    def test_resolver_uses_installed_context_guard_nested_exact_receipt(self):
        """npm's nested dependency layout resolves from the installed package first."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp).resolve()
            (project / "package.json").write_text(json.dumps({"name": "customer-application"}), encoding="utf-8")
            context_guard = project / "node_modules" / "@ictechgy" / "context-guard"
            policy_path = context_guard / "plugins" / "context-guard" / "bin" / "bash_reference_policy.py"
            policy_path.parent.mkdir(parents=True)
            shutil.copy2(ROOT / "context-guard-kit" / "bash_reference_policy.py", policy_path)
            (context_guard / "package.json").write_text(json.dumps({
                "name": "@ictechgy/context-guard", "version": "0.4.16",
                "dependencies": {"@ictechgy/context-guard-receipt": "0.2.0"},
            }), encoding="utf-8")
            receipt = context_guard / "node_modules" / "@ictechgy" / "context-guard-receipt"
            cli = receipt / "bin" / "context-guard-receipt.cjs"
            cli.parent.mkdir(parents=True)
            package_bytes = json.dumps({"name": "@ictechgy/context-guard-receipt", "version": "0.2.0"}).encode()
            cli_bytes = b"#!/usr/bin/env node\n"
            launcher_bytes = b"// verified launcher\n"
            (receipt / "package.json").write_bytes(package_bytes)
            cli.write_bytes(cli_bytes)
            (receipt / "bin" / "launcher.cjs").write_bytes(launcher_bytes)
            cli.chmod(0o700)
            manifest_bytes = json.dumps({"files": [
                {"path": "package.json", "sha256": hashlib.sha256(package_bytes).hexdigest()},
                {"path": "bin/context-guard-receipt.cjs", "sha256": hashlib.sha256(cli_bytes).hexdigest()},
                {"path": "bin/launcher.cjs", "sha256": hashlib.sha256(launcher_bytes).hexdigest()},
            ]}).encode()
            (receipt / "package-files.json").write_bytes(manifest_bytes)

            policy = load_policy(policy_path)
            policy.EXPECTED_RECEIPT_PACKAGE_FILES_SHA256_BY_VERSION["0.2.0"] = hashlib.sha256(manifest_bytes).hexdigest()
            trusted_runtime = Path(sys.executable).resolve()
            policy._trusted_node_interpreter = lambda _root: (
                trusted_runtime,
                policy._executable_identity(trusted_runtime),
            )
            adapter, reason = policy.discover_adapter(project)

            self.assertIsNotNone(adapter)
            self.assertEqual(reason, "receipt_adapter_available")

    def test_package_json_reader_rejects_file_swap_between_inspection_and_open(self):
        """A regular-file replacement cannot change verified package identity."""
        policy = load_policy()
        with tempfile.TemporaryDirectory() as tmp:
            package_json = Path(tmp) / "package.json"
            replacement = Path(tmp) / "replacement.json"
            package_json.write_text(json.dumps({"name": "trusted"}), encoding="utf-8")
            replacement.write_text(json.dumps({"name": "swapped"}), encoding="utf-8")
            real_open = policy.os.open

            def swapping_open(path, flags, *args, **kwargs):
                replacement.replace(package_json)
                return real_open(path, flags, *args, **kwargs)

            with mock.patch.object(policy.os, "open", side_effect=swapping_open):
                result = policy._read_regular_json(package_json)

            self.assertIsNone(result)

    def test_executable_identity_rejects_writable_github_runtime(self):
        """A spoofed GHA marker cannot admit a writable interpreter."""
        policy = load_policy()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trusted_root = root / "trusted-runtime"
            trusted_root.mkdir()
            node = trusted_root / "node"
            node.write_bytes(b"trusted runtime")
            node.chmod(0o777)

            with mock.patch.object(
                policy, "_TRUSTED_GITHUB_TOOLCACHE_PREFIXES", (trusted_root,)
            ), mock.patch.dict(
                os.environ, {"GITHUB_ACTIONS": "true"}, clear=False
            ):
                identity = policy._executable_identity(node)

            self.assertIsNone(identity)

    def test_executable_identity_rejects_hardlink_inside_github_toolcache(self):
        """A spoofed GHA marker cannot admit hardlinked aliases."""
        policy = load_policy()
        with tempfile.TemporaryDirectory() as tmp:
            trusted_root = Path(tmp) / "trusted-runtime"
            trusted_root.mkdir()
            source = trusted_root / "node-source"
            node = trusted_root / "node"
            source.write_bytes(b"trusted runtime")
            source.chmod(0o700)
            try:
                os.link(source, node)
            except OSError:
                self.skipTest("hardlinks unavailable on this filesystem")

            with mock.patch.object(
                policy, "_TRUSTED_GITHUB_TOOLCACHE_PREFIXES", (trusted_root,)
            ), mock.patch.dict(
                os.environ, {"GITHUB_ACTIONS": "true"}, clear=False
            ):
                identity = policy._executable_identity(node)

            self.assertIsNone(identity)

    def test_github_runner_python_runtime_is_policy_eligible(self):
        """The real setup-python runtime must satisfy the production policy."""
        if os.environ.get("GITHUB_ACTIONS", "").lower() != "true":
            self.skipTest("GitHub-hosted runtime contract")
        policy = load_policy()
        executable = Path(sys.executable).resolve()
        metadata = executable.lstat()
        roots = policy._trusted_github_toolcache_roots()
        details = {
            "euid": os.geteuid(),
            "executable": bool(metadata.st_mode & 0o111),
            "mode": oct(metadata.st_mode & 0o7777),
            "nlink": metadata.st_nlink,
            "owner": metadata.st_uid,
            "path": str(executable),
            "regular": policy.stat.S_ISREG(metadata.st_mode),
            "trusted_roots": [str(root) for root in roots],
            "under_trusted_root": policy._path_is_under(executable, roots),
        }

        self.assertIsNotNone(
            policy._executable_identity(executable),
            json.dumps(details, sort_keys=True),
        )

    def test_github_runner_node_runtime_is_policy_eligible(self):
        """The real setup-node runtime must satisfy discovery and binding."""
        if os.environ.get("GITHUB_ACTIONS", "").lower() != "true":
            self.skipTest("GitHub-hosted runtime contract")
        policy = load_policy()
        selected = shutil.which("node")
        self.assertIsNotNone(selected, "setup-node did not expose Node")
        executable = Path(selected).resolve()
        metadata = executable.lstat()
        roots = policy._trusted_github_toolcache_roots()
        details = {
            "euid": os.geteuid(),
            "executable": bool(metadata.st_mode & 0o111),
            "mode": oct(metadata.st_mode & 0o7777),
            "nlink": metadata.st_nlink,
            "owner": metadata.st_uid,
            "path": str(executable),
            "regular": policy.stat.S_ISREG(metadata.st_mode),
            "trusted_roots": [str(root) for root in roots],
            "under_trusted_root": policy._path_is_under(executable, roots),
        }

        identity = policy._executable_identity(executable)
        self.assertIsNotNone(identity, json.dumps(details, sort_keys=True))
        binding = policy._trusted_node_interpreter(ROOT)
        self.assertIsNotNone(binding, json.dumps(details, sort_keys=True))
        bound_path, bound_identity = binding
        self.assertEqual(
            policy._executable_identity(bound_path),
            bound_identity,
            json.dumps(details, sort_keys=True),
        )
        if policy._path_is_under(executable, roots):
            with mock.patch.object(policy, "_TRUSTED_NODE_CANDIDATES", ()):
                fallback_binding = policy._trusted_node_interpreter(ROOT)
            self.assertEqual(fallback_binding, (executable, identity))
        else:
            self.assertEqual(binding, (executable, identity))

    def test_executable_identity_rejects_hardlinks_outside_trusted_github_toolcache(self):
        """Local and prefix-external hardlinks retain the single-link policy."""
        policy = load_policy()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trusted_root = root / "trusted-toolcache"
            trusted_root.mkdir()
            source = root / "node-source"
            node = root / "node"
            source.write_bytes(b"untrusted runtime")
            source.chmod(0o700)
            try:
                os.link(source, node)
            except OSError:
                self.skipTest("hardlinks unavailable on this filesystem")

            with mock.patch.object(
                policy, "_TRUSTED_GITHUB_TOOLCACHE_PREFIXES", (trusted_root,)
            ):
                with mock.patch.dict(
                    os.environ, {"GITHUB_ACTIONS": "true"}, clear=False
                ):
                    self.assertIsNone(policy._executable_identity(node))
                with mock.patch.dict(
                    os.environ, {"GITHUB_ACTIONS": ""}, clear=False
                ):
                    self.assertIsNone(policy._executable_identity(node))

    def test_interpreter_mutation_after_binding_is_detected_before_launch(self):
        """A changed single-link interpreter never reaches subprocess launch."""
        policy = load_policy()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            node = root / "node"
            cli = root / "verified-cli"
            node.write_bytes(b"trusted runtime")
            node.chmod(0o700)
            cli.write_bytes(b"trusted cli")
            adapter = policy.NpmReceiptCliAdapter(
                cli,
                node_path=node,
                protected_paths=(cli,),
            )
            node.write_bytes(b"changed runtime")

            with tempfile.TemporaryFile(
                "w+b", buffering=0
            ) as capture, mock.patch.object(policy.subprocess, "Popen") as popen:
                os.fchmod(capture.fileno(), 0o600)
                broker, reason = adapter.start_broker(
                    capture.fileno(),
                    root=str(root),
                    transaction_id="d" * 64,
                    disclosure_days=7,
                    timeout_seconds=8,
                )

        self.assertIsNone(broker)
        self.assertEqual(reason, "receipt_node_interpreter_changed_before_launch")
        popen.assert_not_called()

    def test_ci_toolcache_node_is_discovered_only_under_trusted_prefix(self):
        """CI PATH discovery accepts only resolved GitHub-hosted toolcache Node."""
        policy = load_policy()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            trusted_root = root / "trusted-toolcache"
            project = trusted_root / "workspace"
            project_bin = project / "bin"
            attacker_bin = root / "trusted-toolcache-lookalike" / "bin"
            escape_bin = trusted_root / "escape" / "bin"
            trusted_bin = trusted_root / "node" / "22.0.0" / "x64" / "bin"
            project_bin.mkdir(parents=True)
            attacker_bin.mkdir(parents=True)
            escape_bin.mkdir(parents=True)
            trusted_bin.mkdir(parents=True)
            for directory, contents in (
                (project_bin, b"project node"),
                (attacker_bin, b"attacker node"),
                (trusted_bin, b"trusted node"),
            ):
                node = directory / "node"
                node.write_bytes(contents)
                node.chmod(0o700)
            escape_node = escape_bin / "node"
            try:
                escape_node.symlink_to(attacker_bin / "node")
            except OSError:
                self.skipTest("symlinks unavailable on this filesystem")
            with mock.patch.object(policy, "_TRUSTED_NODE_CANDIDATES", ()):
                with mock.patch.object(
                    policy,
                    "_TRUSTED_GITHUB_TOOLCACHE_PREFIXES",
                    (trusted_root,),
                ):
                    with mock.patch.dict(
                        os.environ,
                        {
                            "CI": "",
                            "GITHUB_ACTIONS": "true",
                            "PATH": os.pathsep.join(
                                (
                                    str(project_bin),
                                    str(attacker_bin),
                                    str(escape_bin),
                                    str(trusted_bin),
                                )
                            ),
                        },
                        clear=False,
                    ):
                        result = policy._trusted_node_interpreter(project)

            self.assertIsNotNone(result)
            node_path, identity = result
            self.assertEqual(node_path, (trusted_bin / "node").resolve())
            self.assertEqual(identity, policy._executable_identity(node_path))

    def test_toolcache_path_discovery_is_disabled_outside_github_actions(self):
        """Ambient PATH cannot activate dynamic Node discovery outside GitHub Actions."""
        policy = load_policy()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            project = root / "project"
            trusted_bin = root / "trusted-toolcache" / "node" / "22.0.0" / "x64" / "bin"
            trusted_bin.mkdir(parents=True)
            node = trusted_bin / "node"
            node.write_bytes(b"trusted node")
            node.chmod(0o700)
            with mock.patch.object(policy, "_TRUSTED_NODE_CANDIDATES", ()):
                with mock.patch.object(
                    policy,
                    "_TRUSTED_GITHUB_TOOLCACHE_PREFIXES",
                    (root / "trusted-toolcache",),
                ):
                    with mock.patch.dict(
                        os.environ,
                        {"CI": "true", "GITHUB_ACTIONS": "", "PATH": str(trusted_bin)},
                        clear=False,
                    ):
                        result = policy._trusted_node_interpreter(project)

            self.assertIsNone(result)

    def test_ci_toolcache_node_rejects_project_through_ancestor_symlink(self):
        """An ancestor alias cannot hide a project-owned Node inside toolcache."""
        policy = load_policy()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            trusted_root = root / "trusted-toolcache"
            project = trusted_root / "project"
            project_bin = project / "bin"
            project_bin.mkdir(parents=True)
            node = project_bin / "node"
            node.write_bytes(b"project node")
            node.chmod(0o700)
            alias = root / "toolcache-alias"
            try:
                alias.symlink_to(trusted_root, target_is_directory=True)
            except OSError:
                self.skipTest("symlinks unavailable on this filesystem")
            aliased_project = alias / "project"
            with mock.patch.object(policy, "_TRUSTED_NODE_CANDIDATES", ()):
                with mock.patch.object(
                    policy, "_TRUSTED_GITHUB_TOOLCACHE_PREFIXES", (trusted_root,)
                ):
                    with mock.patch.dict(
                        os.environ,
                        {
                            "GITHUB_ACTIONS": "true",
                            "PATH": str(aliased_project / "bin"),
                        },
                        clear=False,
                    ):
                        result = policy._trusted_node_interpreter(aliased_project)

            self.assertIsNone(result)

    def test_receipt_manifest_requires_root_policy_digest_pin_before_internal_hashes(self):
        """A coherently rewritten Receipt package cannot bless its own malicious CLI."""
        policy = load_policy()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            receipt = root / "node_modules" / "@ictechgy" / "context-guard-receipt"
            cli = receipt / "bin" / "context-guard-receipt.cjs"
            cli.parent.mkdir(parents=True)
            package_bytes = b'{"name":"@ictechgy/context-guard-receipt","version":"0.2.0"}'
            trusted_cli = b"#!/usr/bin/env node\n// trusted\n"
            launcher = b"// trusted launcher\n"
            (receipt / "package.json").write_bytes(package_bytes)
            cli.write_bytes(trusted_cli)
            (receipt / "bin" / "launcher.cjs").write_bytes(launcher)
            trusted_manifest = json.dumps({"files": [
                {"path": "package.json", "sha256": hashlib.sha256(package_bytes).hexdigest()},
                {"path": "bin/context-guard-receipt.cjs", "sha256": hashlib.sha256(trusted_cli).hexdigest()},
                {"path": "bin/launcher.cjs", "sha256": hashlib.sha256(launcher).hexdigest()},
            ]}, sort_keys=True).encode()
            (receipt / "package-files.json").write_bytes(trusted_manifest)
            pin = hashlib.sha256(trusted_manifest).hexdigest()
            self.assertEqual(policy._verified_package_cli(root, receipt, expected_manifest_sha256=pin), cli)

            malicious_cli = b"#!/usr/bin/env node\n// replaced\n"
            cli.write_bytes(malicious_cli)
            malicious_manifest = json.dumps({"files": [
                {"path": "package.json", "sha256": hashlib.sha256(package_bytes).hexdigest()},
                {"path": "bin/context-guard-receipt.cjs", "sha256": hashlib.sha256(malicious_cli).hexdigest()},
                {"path": "bin/launcher.cjs", "sha256": hashlib.sha256(launcher).hexdigest()},
            ]}, sort_keys=True).encode()
            (receipt / "package-files.json").write_bytes(malicious_manifest)

            self.assertIsNone(policy._verified_package_cli(root, receipt, expected_manifest_sha256=pin))

    def test_hook_reference_flag_is_explicit_and_default_off(self):
        """The normal PreToolUse rewrite stays unchanged until opted in."""
        payload = json.dumps({"tool_input": {"command": "pytest -q"}})
        normal = subprocess.run([sys.executable, str(REWRITE)], input=payload, text=True, capture_output=True, check=False)
        opted_in = subprocess.run([sys.executable, str(REWRITE), "--bash-reference-v1"], input=payload, text=True, capture_output=True, check=False)
        normal_command = json.loads(normal.stdout)["hookSpecificOutput"]["updatedInput"]["command"]
        reference_command = json.loads(opted_in.stdout)["hookSpecificOutput"]["updatedInput"]["command"]
        self.assertNotIn("--bash-reference-v1", normal_command)
        self.assertIn("--digest json --bash-reference-v1", reference_command)

    def test_setup_source_distribution_reports_reference_unavailable_without_writing(self):
        """A source/plugin-only setup cannot claim that npm-only references are enabled."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc = subprocess.run(
                [sys.executable, str(SETUP), "--root", str(root), "--plan", "--bash-reference-v1", "--json"],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            data = json.loads(proc.stdout)
            self.assertTrue(any("reference unavailable" in item for item in data["actions"]))
            self.assertTrue(any("paired npm install" in item for item in data["warnings"]))
            self.assertFalse((root / ".claude" / "settings.json").exists())

    def test_setup_source_distribution_keeps_legacy_bash_hook_when_reference_is_requested(self):
        """Failing closed for references must still install the ordinary local Bash hook."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc = subprocess.run(
                [
                    sys.executable, str(SETUP), "--root", str(root), "--yes",
                    "--no-backup", "--no-diet-scan", "--bash-reference-v1", "--json",
                ],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            settings = (root / ".claude" / "settings.json").read_text(encoding="utf-8")
            self.assertIn("context-guard-rewrite-bash", settings)
            self.assertNotIn("--bash-reference-v1", settings)

    def test_setup_reference_policy_fifo_fails_closed_without_blocking(self):
        """A non-regular adjacent policy must not hang setup before type validation."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            package = root / "node_modules" / "@ictechgy" / "context-guard"
            setup = package / "plugins" / "context-guard" / "bin" / "context-guard-setup"
            setup.parent.mkdir(parents=True)
            shutil.copy2(SETUP, setup)
            setup.chmod(0o700)
            os.mkfifo(setup.parent / "bash_reference_policy.py", mode=0o600)
            rewrite = setup.parent / "context-guard-rewrite-bash"
            rewrite.write_text("#!/bin/sh\n", encoding="utf-8")
            rewrite.chmod(0o700)

            try:
                proc = subprocess.run(
                    [
                        sys.executable, str(setup), "--root", str(root), "--plan",
                        "--no-diet-scan", "--no-denies", "--no-statusline",
                        "--no-read-guard", "--no-model-defaults",
                        "--no-failed-attempt-nudge", "--bash-reference-v1", "--json",
                    ],
                    text=True, capture_output=True, check=False, timeout=2,
                )
            except subprocess.TimeoutExpired as exc:
                self.fail(f"setup blocked while opening a policy FIFO: {exc}")

            self.assertEqual(proc.returncode, 0, proc.stderr)
            data = json.loads(proc.stdout)
            self.assertFalse(data["choices"]["bash_reference_v1"])
            self.assertTrue(any(
                "reason=receipt_policy_unavailable" in item
                for item in data["warnings"]
            ))

    def test_setup_rejects_adapter_without_runtime_protocol(self):
        """Setup must not enable an adapter that trim/runtime would reject."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            package = root / "node_modules" / "@ictechgy" / "context-guard"
            setup = package / "plugins" / "context-guard" / "bin" / "context-guard-setup"
            setup.parent.mkdir(parents=True)
            shutil.copy2(SETUP, setup)
            setup.chmod(0o700)
            (setup.parent / "bash_reference_policy.py").write_text(
                "def discover_adapter(root):\n"
                "    return object(), 'receipt_adapter_available'\n",
                encoding="utf-8",
            )
            rewrite = setup.parent / "context-guard-rewrite-bash"
            rewrite.write_text("#!/bin/sh\n", encoding="utf-8")
            rewrite.chmod(0o700)

            proc = subprocess.run(
                [
                    sys.executable, str(setup), "--root", str(root), "--plan",
                    "--no-diet-scan", "--no-denies", "--no-statusline",
                    "--no-read-guard", "--no-model-defaults",
                    "--no-failed-attempt-nudge", "--bash-reference-v1", "--json",
                ],
                text=True, capture_output=True, check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            data = json.loads(proc.stdout)
            self.assertFalse(data["choices"]["bash_reference_v1"])
            self.assertTrue(any(
                "reason=receipt_adapter_invalid" in item
                for item in data["warnings"]
            ))

    def test_setup_package_json_only_receipt_never_enables_reference_mode(self):
        """Missing pinned Receipt files must retain the ordinary Bash hook."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            package = root / "node_modules" / "@ictechgy" / "context-guard"
            setup = package / "plugins" / "context-guard" / "bin" / "context-guard-setup"
            setup.parent.mkdir(parents=True)
            shutil.copy2(SETUP, setup)
            setup.chmod(0o700)
            shutil.copy2(
                ROOT / "context-guard-kit" / "bash_reference_policy.py",
                setup.parent / "bash_reference_policy.py",
            )
            rewrite = setup.parent / "context-guard-rewrite-bash"
            rewrite.write_text("#!/bin/sh\n", encoding="utf-8")
            rewrite.chmod(0o700)
            (package / "package.json").write_text(json.dumps({
                "name": "@ictechgy/context-guard",
                "dependencies": {"@ictechgy/context-guard-receipt": "0.2.0"},
            }), encoding="utf-8")
            receipt = root / "node_modules" / "@ictechgy" / "context-guard-receipt"
            receipt.mkdir(parents=True)
            (receipt / "package.json").write_text(json.dumps({
                "name": "@ictechgy/context-guard-receipt",
                "version": "0.2.0",
            }), encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable, str(setup), "--root", str(root), "--yes",
                    "--no-backup", "--no-diet-scan", "--no-denies", "--no-statusline",
                    "--no-read-guard", "--no-model-defaults", "--no-failed-attempt-nudge",
                    "--bash-reference-v1", "--json",
                ],
                text=True, capture_output=True, check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            data = json.loads(proc.stdout)
            settings = (root / ".claude" / "settings.json").read_text(encoding="utf-8")
            self.assertFalse(data["choices"]["bash_reference_v1"])
            self.assertIn("context-guard-rewrite-bash", settings)
            self.assertNotIn("--bash-reference-v1", settings)
            self.assertTrue(any(
                "reason=receipt_npm_package_integrity_invalid" in item
                and "recovery=" in item
                for item in data["warnings"]
            ))

    def test_setup_verified_installed_layout_enables_then_disable_removes_reference_flag(self):
        """A pinned installed pair enables, then disable keeps the ordinary Bash hook."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            package = root / "node_modules" / "@ictechgy" / "context-guard"
            setup = package / "plugins" / "context-guard" / "bin" / "context-guard-setup"
            setup.parent.mkdir(parents=True)
            shutil.copy2(SETUP, setup)
            setup.chmod(0o700)
            shutil.copy2(
                ROOT / "context-guard-kit" / "bash_reference_policy.py",
                setup.parent / "bash_reference_policy.py",
            )
            rewrite = setup.parent / "context-guard-rewrite-bash"
            rewrite.write_text("#!/bin/sh\n", encoding="utf-8")
            rewrite.chmod(0o700)
            (package / "package.json").write_text(json.dumps({
                "name": "@ictechgy/context-guard",
                "version": "0.5.0",
                "dependencies": {"@ictechgy/context-guard-receipt": "0.2.0"},
            }), encoding="utf-8")
            receipt = root / "node_modules" / "@ictechgy" / "context-guard-receipt"
            (receipt / "bin").mkdir(parents=True)
            receipt_source = ROOT / "packages" / "context-guard-receipt"
            for relative in (
                "package.json",
                "package-files.json",
                "bin/context-guard-receipt.cjs",
                "bin/launcher.cjs",
            ):
                shutil.copy2(receipt_source / relative, receipt / relative)
            common = [
                sys.executable, str(setup), "--root", str(root), "--yes",
                "--no-backup", "--no-diet-scan", "--no-denies", "--no-statusline",
                "--no-read-guard", "--no-model-defaults", "--no-failed-attempt-nudge",
            ]
            enable = subprocess.run(
                [*common, "--bash-reference-v1", "--json"],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(enable.returncode, 0, enable.stderr)
            enable_data = json.loads(enable.stdout)
            enabled_settings = (root / ".claude" / "settings.json").read_text(encoding="utf-8")
            self.assertTrue(enable_data["choices"]["bash_reference_v1"])
            self.assertTrue(any("enabled bash_reference_v1" in item for item in enable_data["actions"]))
            self.assertIn("--bash-reference-v1", enabled_settings)
            disable = subprocess.run(
                [*common, "--no-bash-reference-v1", "--json"],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(disable.returncode, 0, disable.stderr)
            settings = (root / ".claude" / "settings.json").read_text(encoding="utf-8")
            self.assertIn("context-guard-rewrite-bash", settings)
            self.assertNotIn("--bash-reference-v1", settings)

    def test_reference_and_legacy_receipt_are_rejected_before_child_execution(self):
        """A conflicting mode must not run the caller's command at all."""
        with tempfile.TemporaryDirectory() as tmp:
            sentinel = Path(tmp) / "child-ran"
            proc = subprocess.run(
                [
                    sys.executable, str(TRIM), "--digest", "json",
                    "--artifact-receipt", "--bash-reference-v1", "--",
                    sys.executable, "-c", f"from pathlib import Path; Path({str(sentinel)!r}).write_text('ran')",
                ],
                text=True, capture_output=True, check=False,
            )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("mutually exclusive", proc.stderr)
        self.assertFalse(sentinel.exists())

    def test_reference_capture_is_anonymous_and_preserves_exact_bytes(self):
        """Break caught: reference bytes regain a discoverable pathname or are normalized."""
        trim = load_trim()
        capture = trim.SanitizedArtifactCapture(enabled=True, max_bytes=128, reference_spool=True)
        try:
            capture.add("a\r\n")
            capture.add("b\r")
            self.assertFalse(hasattr(capture, "spool_path"))
            descriptor = capture.descriptor()
            self.assertIsInstance(descriptor, int)
            status = os.fstat(descriptor)
            self.assertEqual(status.st_nlink, 0)
            self.assertEqual(status.st_mode & 0o777, 0o600)
            self.assertEqual(os.pread(descriptor, 5, 0), b"a\r\nb\r")
            self.assertEqual(capture.bytes, 5)
        finally:
            capture.close()

    def test_legacy_artifact_capture_remains_lazy_and_anonymous(self):
        """Legacy receipts must not allocate a named spool or flush each streamed line."""
        trim = load_trim()
        capture = trim.SanitizedArtifactCapture(enabled=True, max_bytes=128)
        try:
            self.assertFalse(hasattr(capture, "spool_path"))
            capture.add("legacy\n")
            self.assertFalse(hasattr(capture, "spool_path"))
            self.assertEqual(capture.text(), "legacy\n")
        finally:
            capture.close()

    def test_reference_capture_descriptor_stays_open_until_broker_finishes(self):
        """Break caught: sealing closes the only anonymous descriptor before COMMIT."""
        trim = load_trim()
        capture = trim.SanitizedArtifactCapture(enabled=True, max_bytes=128, reference_spool=True)
        try:
            capture.add("sealed\n")
            descriptor = capture.descriptor()
            self.assertEqual(os.pread(descriptor, 7, 0), b"sealed\n")
            capture.add("late write\n")
            self.assertEqual(
                os.pread(descriptor, capture.bytes, 0),
                b"sealed\nlate write\n",
            )
        finally:
            capture.close()

    def test_temp_directory_scan_and_replacement_cannot_change_capture_bytes(self):
        """Break caught: a child can find and replace the reference capture by name."""

        trim = load_trim()
        with tempfile.TemporaryDirectory() as temporary_directory, mock.patch.object(
            trim.tempfile, "tempdir", temporary_directory
        ):
            capture = trim.SanitizedArtifactCapture(
                enabled=True, max_bytes=128, reference_spool=True
            )
            try:
                capture.add("descriptor-owned\n")
                descriptor = capture.descriptor()
                temp_root = Path(temporary_directory)
                self.assertEqual(
                    list(temp_root.glob("context-guard-bash-reference-*.spool")),
                    [],
                )
                planted = temp_root / "context-guard-bash-reference-planted.spool"
                planted.write_bytes(b"attacker replacement")
                planted.unlink()
                self.assertEqual(
                    os.pread(descriptor, capture.bytes, 0), b"descriptor-owned\n"
                )
                self.assertFalse(hasattr(capture, "spool_path"))
            finally:
                capture.close()

    def test_reference_broker_is_ready_before_child_launch(self):
        """Break caught: Receipt is first launched after the wrapped Bash exits."""
        trim = load_trim()
        events: list[str] = []
        real_popen = trim.subprocess.Popen
        real_loader = trim.load_adjacent_python_module

        def launch_child(*args, **kwargs):
            events.append("child")
            return real_popen(*args, **kwargs)

        class Broker:
            def commit(self):
                events.append("commit")
                return type("Result", (), {
                    "status": "success",
                    "actionable": True,
                    "reference": VALID_HANDLE,
                    "reason_code": "reference_published",
                })()

            def abort(self):
                events.append("abort")

            def close(self):
                events.append("close")

        class Adapter:
            def start_broker(self, capture_fd, **_kwargs):
                self.capture_status = os.fstat(capture_fd)
                events.append("broker")
                return Broker(), "receipt_broker_ready"

        class Policy:
            @staticmethod
            def discover_adapter(_root):
                events.append("adapter")
                return Adapter(), "receipt_adapter_available"

        def load_policy_before_child(*args, **kwargs):
            if len(args) > 1 and args[1] == "bash_reference_policy.py":
                events.append("policy")
                return Policy()
            return real_loader(*args, **kwargs)

        stdout = io.StringIO()
        argv = [
            str(TRIM), "--digest", "json", "--digest-always", "--bash-reference-v1", "--",
            sys.executable, "-c", "print(('x' * 40 + '\\n') * 300, end='')",
        ]
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)
            with (
                mock.patch.object(trim, "load_adjacent_python_module", side_effect=load_policy_before_child),
                mock.patch.object(trim.subprocess, "Popen", side_effect=launch_child),
                mock.patch.object(sys, "argv", argv),
                contextlib.redirect_stdout(stdout),
            ):
                returncode = trim.main()

        self.assertEqual(events[:4], ["policy", "adapter", "broker", "child"])
        self.assertIn("commit", events)
        self.assertNotIn("abort", events)
        self.assertEqual(returncode, 0)
        self.assertEqual(
            json.loads(stdout.getvalue())["bash_reference"]["route"],
            "reference",
        )

    def test_below_threshold_output_aborts_prepared_broker(self):
        """Break caught: below-threshold opt-in leaves its prepared broker alive."""

        trim = load_trim()
        events: list[str] = []
        real_loader = trim.load_adjacent_python_module

        class Broker:
            def commit(self):
                raise AssertionError("below threshold must not commit")

            def abort(self):
                events.append("abort")

            def close(self):
                events.append("close")

        class Adapter:
            def start_broker(self, _capture_fd, **_kwargs):
                events.append("ready")
                return Broker(), "receipt_broker_ready"

        class Policy:
            @staticmethod
            def discover_adapter(_root):
                return Adapter(), "receipt_adapter_available"

        def load_policy(*args, **kwargs):
            if len(args) > 1 and args[1] == "bash_reference_policy.py":
                return Policy()
            return real_loader(*args, **kwargs)

        stdout = io.StringIO()
        argv = [
            str(TRIM), "--digest", "json", "--digest-always",
            "--bash-reference-v1", "--", sys.executable, "-c", "print('small')",
        ]
        with (
            mock.patch.object(trim, "load_adjacent_python_module", side_effect=load_policy),
            mock.patch.object(sys, "argv", argv),
            contextlib.redirect_stdout(stdout),
        ):
            returncode = trim.main()

        self.assertEqual(returncode, 0)
        self.assertEqual(events, ["ready", "abort", "close"])
        self.assertEqual(
            json.loads(stdout.getvalue())["bash_reference"]["reason_code"],
            "receipt_output_below_reference_threshold",
        )

    def test_small_json_caps_abort_before_reference_commit_and_stay_bounded(self):
        """Break caught: a reference is committed then serialized beyond max_chars."""

        for max_chars in (1, 2, 28, 64, 128, 196, 300):
            with self.subTest(max_chars=max_chars):
                trim = load_trim()
                events: list[str] = []
                real_loader = trim.load_adjacent_python_module

                class Broker:
                    def commit(self):
                        events.append("commit")
                        return type(
                            "Result",
                            (),
                            {
                                "status": "success",
                                "actionable": True,
                                "reference": VALID_HANDLE,
                                "reason_code": "reference_published",
                            },
                        )()

                    def abort(self):
                        events.append("abort")

                    def close(self):
                        events.append("close")

                class Adapter:
                    def start_broker(self, _capture_fd, **_kwargs):
                        events.append("ready")
                        return Broker(), "receipt_broker_ready"

                class Policy:
                    @staticmethod
                    def discover_adapter(_root):
                        return Adapter(), "receipt_adapter_available"

                def load_policy(*args, **kwargs):
                    if len(args) > 1 and args[1] == "bash_reference_policy.py":
                        return Policy()
                    return real_loader(*args, **kwargs)

                stdout = io.StringIO()
                argv = [
                    str(TRIM),
                    "--digest",
                    "json",
                    "--digest-always",
                    "--bash-reference-v1",
                    "--max-chars",
                    str(max_chars),
                    "--",
                    sys.executable,
                    "-c",
                    "print(('x' * 40 + '\\n') * 300, end='')",
                ]
                with (
                    mock.patch.object(
                        trim,
                        "load_adjacent_python_module",
                        side_effect=load_policy,
                    ),
                    mock.patch.object(sys, "argv", argv),
                    contextlib.redirect_stdout(stdout),
                ):
                    returncode = trim.main()

                rendered = stdout.getvalue()
                self.assertEqual(returncode, 0)
                self.assertLessEqual(len(rendered), max_chars)
                self.assertNotIn(VALID_HANDLE, rendered)
                self.assertEqual(events, ["ready", "abort", "close"])

    def test_interrupt_aborts_broker_and_closes_anonymous_capture(self):
        """Break caught: an interrupt strands the prelaunched broker or capture fd."""

        trim = load_trim()
        events: list[str] = []
        real_loader = trim.load_adjacent_python_module

        class Broker:
            def commit(self):
                raise AssertionError("interrupt must not commit")

            def abort(self):
                events.append("abort")

            def close(self):
                events.append("close")

        class Adapter:
            def start_broker(self, _capture_fd, **_kwargs):
                return Broker(), "receipt_broker_ready"

        class Policy:
            @staticmethod
            def discover_adapter(_root):
                return Adapter(), "receipt_adapter_available"

        def load_policy(*args, **kwargs):
            if len(args) > 1 and args[1] == "bash_reference_policy.py":
                return Policy()
            return real_loader(*args, **kwargs)

        def interrupted(_stream):
            raise KeyboardInterrupt
            yield ""  # pragma: no cover

        argv = [
            str(TRIM), "--digest", "json", "--digest-always",
            "--bash-reference-v1", "--", sys.executable, "-c", "print('unused')",
        ]
        with (
            mock.patch.object(trim, "load_adjacent_python_module", side_effect=load_policy),
            mock.patch.object(trim.TimedCommandStream, "__iter__", interrupted),
            mock.patch.object(sys, "argv", argv),
            self.assertRaises(KeyboardInterrupt),
        ):
            trim.main()

        self.assertEqual(events, ["abort", "close"])

    def test_reference_failure_keeps_child_exit_and_legacy_digest(self):
        """An unavailable receipt adapter cannot alter an admitted command result."""
        proc = subprocess.run(
            [
                sys.executable, str(TRIM), "--digest", "json", "--digest-always",
                "--bash-reference-v1", "--",
                sys.executable, "-c", "import sys; print('child result'); sys.exit(7)",
            ],
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(proc.returncode, 7, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["exit_code"], 7)
        self.assertEqual(payload["bash_reference"]["route"], "legacy_trim")
        self.assertNotIn("child result", payload["bash_reference"].get("reason_code", ""))

    def test_reference_never_spools_or_publishes_fallback_sanitizer_output(self):
        """Only the strong sanitizer may feed the persistent Receipt boundary."""
        trim = load_trim()
        stdout = io.StringIO()
        argv = [
            str(TRIM), "--digest", "json", "--digest-always", "--bash-reference-v1", "--",
            sys.executable, "-c", "print('x' * 9000)",
        ]
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)
            with (
                mock.patch.object(
                    trim,
                    "load_line_sanitizer",
                    return_value=trim.FallbackLineSanitizer(context="unknown_text"),
                ),
                mock.patch.object(
                    trim.tempfile,
                    "mkstemp",
                    side_effect=AssertionError("fallback output must not get a named spool"),
                ),
                mock.patch.object(
                    trim,
                    "load_adjacent_python_module",
                    side_effect=AssertionError("fallback mode must not discover Receipt"),
                ),
                mock.patch.object(sys, "argv", argv),
                contextlib.redirect_stdout(stdout),
            ):
                returncode = trim.main()

        self.assertEqual(returncode, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["bash_reference"]["route"], "legacy_trim")
        self.assertEqual(
            payload["bash_reference"]["reason_code"],
            "receipt_strong_sanitizer_unavailable",
        )

    def test_resolver_rejects_a_symlinked_project_root_before_package_discovery(self):
        """A path swap cannot redirect production receipt discovery into another tree."""
        policy = load_policy()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            real_root = base / "real"
            package = real_root / "node_modules" / "@ictechgy" / "context-guard-receipt"
            package.mkdir(parents=True)
            (real_root / "package.json").write_text(json.dumps({
                "name": "@ictechgy/context-guard",
                "dependencies": {"@ictechgy/context-guard-receipt": "0.1.0"},
            }), encoding="utf-8")
            (package / "package.json").write_text(json.dumps({
                "name": "@ictechgy/context-guard-receipt", "version": "0.1.0",
            }), encoding="utf-8")
            alias = base / "swapped-root"
            alias.symlink_to(real_root, target_is_directory=True)
            adapter, reason = policy.discover_adapter(alias)
            self.assertIsNone(adapter)
            self.assertEqual(reason, "receipt_root_symlink_rejected")

    def test_markdown_digest_prints_only_the_final_actionable_reference(self):
        """A successful import exposes one exact static retrieval command."""
        trim = load_trim()
        rendered = trim.render_digest_markdown({
            "status": "success", "exit_code": 0, "timed_out": False,
            "raw_output": {}, "budget": {}, "bash_reference": {
                "mode": "bash_reference_v1", "route": "reference",
                "reference": VALID_HANDLE, "disclosure_days": 7,
                "retrieval_command": (
                    "./node_modules/.bin/context-guard reference " + VALID_HANDLE
                ),
            },
        }, 1000)
        self.assertIn(
            "./node_modules/.bin/context-guard reference " + VALID_HANDLE,
            rendered,
        )
        self.assertEqual(rendered.count(VALID_HANDLE), 1)
        self.assertNotIn(".spool", rendered)
        rendered_json = json.loads(trim.render_digest_json({
            "status": "success", "exit_code": 0, "timed_out": False,
            "raw_output": {}, "budget": {}, "bash_reference": {
                "mode": "bash_reference_v1", "route": "reference",
                "reference": VALID_HANDLE, "disclosure_days": 7,
                "retrieval_command": (
                    "./node_modules/.bin/context-guard reference " + VALID_HANDLE
                ),
            },
        }, 1000))
        self.assertEqual(
            rendered_json["bash_reference"]["retrieval_command"],
            "./node_modules/.bin/context-guard reference " + VALID_HANDLE,
        )
        capped = json.loads(trim.render_digest_json({
            "status": "success", "exit_code": 0, "timed_out": False,
            "raw_output": {"noise": "x" * 2_000},
            "budget": {}, "bash_reference": {
                "mode": "bash_reference_v1", "route": "reference",
                "reference": VALID_HANDLE, "disclosure_days": 7,
                "retrieval_command": (
                    "./node_modules/.bin/context-guard reference " + VALID_HANDLE
                ),
            },
        }, 400))
        self.assertEqual(
            capped["bash_reference"]["retrieval_command"],
            "./node_modules/.bin/context-guard reference " + VALID_HANDLE,
        )

    def test_small_markdown_caps_never_split_or_expose_a_reference(self):
        """Break caught: nested cap markers make Markdown exceed max_chars."""

        trim = load_trim()
        payload = {
            "status": "success",
            "exit_code": 0,
            "timed_out": False,
            "raw_output": {"noise": "x" * 2_000},
            "budget": {},
            "bash_reference": {
                "mode": "bash_reference_v1",
                "route": "reference",
                "reference": VALID_HANDLE,
                "disclosure_days": 7,
                "retrieval_command": (
                    "./node_modules/.bin/context-guard reference " + VALID_HANDLE
                ),
            },
        }

        for max_chars in (1, 2, 28, 64, 128):
            with self.subTest(max_chars=max_chars):
                rendered = trim.render_digest_markdown(payload, max_chars)
                self.assertLessEqual(len(rendered), max_chars)
                self.assertNotIn(VALID_HANDLE, rendered)

    def test_digest_rejects_noncanonical_reference_before_rendering(self):
        """Break caught: a broker-controlled handle becomes shell syntax in a digest."""
        trim = load_trim()
        hostile = VALID_HANDLE + ";touch /tmp/reference-injection"
        payload = {
            "status": "success",
            "exit_code": 0,
            "timed_out": False,
            "raw_output": {},
            "budget": {},
            "bash_reference": {
                "mode": "bash_reference_v1",
                "route": "reference",
                "reference": hostile,
                "retrieval_command": (
                    "./node_modules/.bin/context-guard reference " + hostile
                ),
            },
        }

        self.assertNotIn("context-guard reference", trim.render_digest_markdown(payload, 1000))
        rendered_json = json.loads(trim.render_digest_json(payload, 1000))
        self.assertNotIn("bash_reference", rendered_json)

    def test_dispatcher_reference_maps_to_the_existing_trim_helper(self):
        """Break caught: the public command bypasses the package-local trim helper."""
        dispatcher = load_script(DISPATCHER, "context_guard_reference_dispatch_test")
        with mock.patch.object(
            dispatcher,
            "helper_path",
            return_value=Path("/verified/context-guard-trim-output"),
        ), mock.patch.object(dispatcher.subprocess, "run") as run:
            run.return_value.returncode = 0
            result = dispatcher.main(["reference", VALID_HANDLE, "--offset", "12"])

        self.assertEqual(result, 0)
        self.assertEqual(
            run.call_args.args[0],
            [
                "/verified/context-guard-trim-output",
                "--expand-bash-reference",
                VALID_HANDLE,
                "--offset",
                "12",
            ],
        )

    def test_public_reference_writes_one_exact_chunk_and_static_continuation(self):
        """Break caught: retrieval executes a child command or leaks private state paths."""
        trim = load_trim()
        requested: list[tuple[str, str, int]] = []

        class Adapter:
            def query_reference(self, handle, *, root, offset, timeout_seconds):
                requested.append((handle, root, offset))
                page = b"" if offset == 50_000 else "two π bytes\n".encode()
                return type("Result", (), {
                    "status": "success",
                    "reference": handle,
                    "payload": page,
                    "offset": offset,
                    "next_offset": offset + len(page),
                    "total_bytes": 50_000,
                    "reason_code": "reference_query_exact",
                })()

        class Policy:
            REFERENCE_ADAPTER_TIMEOUT_SECONDS = 8

            @staticmethod
            def discover_adapter(_root):
                return Adapter(), "receipt_adapter_available"

        output = io.BytesIO()
        error = io.BytesIO()
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            trim, "load_adjacent_python_module", return_value=Policy()
        ):
            result = trim.run_bash_reference_query(
                (VALID_HANDLE, "--offset", "17"),
                output=output,
                error=error,
                cwd=Path(tmp).resolve(),
            )

        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), "two π bytes\n".encode())
        self.assertEqual(requested[0][0], VALID_HANDLE)
        self.assertEqual(requested[0][2], 17)
        hint = error.getvalue().decode("ascii")
        self.assertEqual(hint, "context-guard: more bytes available; continue with --offset 30\n")
        self.assertNotIn(tmp, hint)

        final_output = io.BytesIO()
        final_error = io.BytesIO()
        with tempfile.TemporaryDirectory() as final_tmp, mock.patch.object(
            trim, "load_adjacent_python_module", return_value=Policy()
        ):
            final_result = trim.run_bash_reference_query(
                (VALID_HANDLE, "--offset", "50000"),
                output=final_output,
                error=final_error,
                cwd=Path(final_tmp).resolve(),
            )
        self.assertEqual(final_result, 0)
        self.assertEqual(final_output.getvalue(), b"")
        self.assertEqual(
            final_error.getvalue(),
            b"context-guard: reference complete at offset 50000\n",
        )
        default_output = io.BytesIO()
        default_error = io.BytesIO()
        with tempfile.TemporaryDirectory() as default_tmp, mock.patch.object(
            trim, "load_adjacent_python_module", return_value=Policy()
        ):
            default_result = trim.run_bash_reference_query(
                (VALID_HANDLE,),
                output=default_output,
                error=default_error,
                cwd=Path(default_tmp).resolve(),
            )
        self.assertEqual(default_result, 0)
        self.assertEqual(requested[-1][2], 0)

    def test_public_reference_help_is_bounded_and_does_not_discover_state(self):
        """Break caught: help performs discovery or suggests whole-artifact output."""

        trim = load_trim()
        output = io.BytesIO()
        error = io.BytesIO()
        with mock.patch.object(
            trim,
            "load_adjacent_python_module",
            side_effect=AssertionError("help must not discover Receipt"),
        ):
            result = trim.run_bash_reference_query(
                ("--help",), output=output, error=error, cwd=ROOT
            )
        self.assertEqual(result, 0)
        self.assertLess(len(output.getvalue()), 512)
        self.assertIn(b"at most 20,000", output.getvalue())
        self.assertNotIn(b"state", output.getvalue().lower())
        self.assertEqual(error.getvalue(), b"")

    def test_public_reference_rejects_invalid_handle_without_discovery(self):
        """Break caught: injected or malformed authority reaches package discovery."""
        trim = load_trim()
        output = io.BytesIO()
        error = io.BytesIO()
        with mock.patch.object(
            trim,
            "load_adjacent_python_module",
            side_effect=AssertionError("invalid handles must fail before discovery"),
        ):
            result = trim.run_bash_reference_query(
                (VALID_HANDLE + ";id",), output=output, error=error, cwd=ROOT
            )

        self.assertEqual(result, 2)
        self.assertEqual(output.getvalue(), b"")
        self.assertNotIn(VALID_HANDLE.encode(), error.getvalue())

    def test_pretool_reference_route_rebinds_exact_command_to_sibling_helper(self):
        """Break caught: the hook executes a caller-shadowable .bin dispatcher."""
        command = (
            "./node_modules/.bin/context-guard reference "
            + VALID_HANDLE
            + " --offset 9"
        )
        proc = subprocess.run(
            [sys.executable, str(REWRITE)],
            input=json.dumps({"tool_input": {"command": command}}),
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        updated = json.loads(proc.stdout)["hookSpecificOutput"]["updatedInput"]["command"]
        self.assertNotIn("./node_modules/.bin/context-guard", updated)
        self.assertIn("trim_command_output.py --expand-bash-reference", updated)
        self.assertTrue(updated.endswith(VALID_HANDLE + " --offset 9"))

        rejected = subprocess.run(
            [sys.executable, str(REWRITE)],
            input=json.dumps({"tool_input": {"command": command + " | cat"}}),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(
            json.loads(rejected.stdout)["hookSpecificOutput"]["permissionDecision"],
            "deny",
        )

    def test_verified_adapter_prelaunches_exact_private_fd_broker(self):
        """Break caught: Receipt launches after Bash or receives a spool pathname."""
        policy = load_policy()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            cli = root / "receipt-cli"
            cli.write_text("#!/bin/sh\n", encoding="utf-8")
            cli.chmod(0o700)
            node = root / "trusted-node"
            node.write_bytes(b"trusted runtime")
            node.chmod(0o700)
            class Completed:
                pid = 123
                returncode = 0

                def __init__(self):
                    read_fd, write_fd = os.pipe()
                    os.write(
                        write_fd,
                        b"READY contextguard-bash-reference-broker/v1\n",
                    )
                    os.close(write_fd)
                    self.stdout = os.fdopen(read_fd, "rb", buffering=0)
                    self.stdin = io.BytesIO()
                    self.poll_count = 0

                def poll(self):
                    self.poll_count += 1
                    return None if self.poll_count == 1 else self.returncode

            adapter = policy.NpmReceiptCliAdapter(cli, node_path=node)
            with tempfile.TemporaryFile("w+b", buffering=0) as capture:
                os.fchmod(capture.fileno(), 0o600)
                capture_fd = capture.fileno()
                with mock.patch.object(
                    policy.subprocess, "Popen", return_value=Completed()
                ) as popen:
                    broker, reason = adapter.start_broker(
                        capture.fileno(),
                        root=str(root),
                        transaction_id="a" * 64,
                        disclosure_days=7,
                        timeout_seconds=8,
                    )
            self.assertIsNotNone(broker)
            self.assertEqual(reason, "receipt_broker_ready")
            command = popen.call_args.args[0]
            self.assertEqual(
                command[:3],
                [str(node), str(cli), "--private-bash-reference-broker-v1"],
            )
            self.assertNotIn("--spool", command)
            self.assertEqual(
                command[command.index("--capture-fd") + 1],
                str(capture_fd),
            )
            self.assertEqual(command[command.index("--root") + 1], str(root))
            expected_state_dir = policy.receipt_state_directory(root)
            self.assertEqual(
                command[command.index("--state-dir") + 1],
                str(expected_state_dir),
            )
            self.assertEqual(expected_state_dir.parent, root.parent)
            self.assertNotEqual(expected_state_dir, root)
            self.assertNotIn(root, expected_state_dir.parents)
            self.assertEqual(
                expected_state_dir,
                policy.receipt_state_directory(root),
                "state selection must remain deterministic for live handles",
            )
            self.assertEqual(command[command.index("--disclosure-days") + 1], "7")
            kwargs = popen.call_args.kwargs
            self.assertEqual(kwargs["pass_fds"], (capture_fd,))
            self.assertIs(kwargs["close_fds"], True)
            self.assertIs(kwargs["start_new_session"], True)
            self.assertNotIn("NODE_OPTIONS", kwargs["env"])
            self.assertNotIn("NODE_PATH", kwargs["env"])
            broker.close()
            self.assertTrue(broker._process.stdin.closed)
            self.assertTrue(broker._process.stdout.closed)

    def test_cli_adapter_refuses_verified_entrypoint_changed_before_launch(self):
        """A post-discovery path replacement never reaches subprocess execution."""
        policy = load_policy()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            cli = root / "verified-cli"
            cli.write_bytes(b"trusted")
            node = root / "trusted-node"
            node.write_bytes(b"trusted runtime")
            node.chmod(0o700)
            adapter = policy.NpmReceiptCliAdapter(
                cli,
                node_path=node,
                protected_paths=(cli,),
            )
            cli.write_bytes(b"replaced payload")
            with tempfile.TemporaryFile("w+b", buffering=0) as capture, mock.patch.object(
                policy.subprocess, "Popen"
            ) as popen:
                os.fchmod(capture.fileno(), 0o600)
                broker, reason = adapter.start_broker(
                    capture.fileno(),
                    root=str(root),
                    transaction_id="c" * 64,
                    disclosure_days=7,
                    timeout_seconds=8,
                )

        self.assertIsNone(broker)
        self.assertEqual(reason, "receipt_package_changed_before_launch")
        popen.assert_not_called()

    def test_cli_adapter_queries_with_closed_env_and_deterministic_private_state(self):
        """Break caught: query launch inherits secrets or lets callers choose state."""

        policy = load_policy()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            cli = root / "receipt-query.py"
            cli.write_text(
                "import base64,json,os,sys\n"
                "payload=json.dumps({'argv':sys.argv[1:],'secret':os.environ.get('CONTEXT_GUARD_TEST_SECRET')},sort_keys=True,separators=(',',':')).encode()\n"
                "handle=sys.argv[2]; offset=int(sys.argv[-1])\n"
                "response={'next_offset':offset+len(payload),'offset':offset,'payload_b64u':base64.urlsafe_b64encode(payload).rstrip(b'=').decode(),'request':{'offset':offset,'reference':handle},'schema_version':'contextguard-receipt-bash-reference-query/v1','status':'exact','total_bytes':offset+len(payload)}\n"
                "sys.stdout.write(json.dumps(response,sort_keys=True,separators=(',',':'))+'\\n')\n",
                encoding="utf-8",
            )
            cli.chmod(0o700)
            node = Path(sys.executable).resolve()
            adapter = policy.NpmReceiptCliAdapter(
                cli, node_path=node, protected_paths=(cli,)
            )
            with mock.patch.dict(
                os.environ, {"CONTEXT_GUARD_TEST_SECRET": "must-not-cross"}
            ):
                result = adapter.query_reference(
                    VALID_HANDLE,
                    root=str(root),
                    offset=7,
                    timeout_seconds=8,
                )

            self.assertEqual(result.status, "success")
            details = json.loads(result.payload)
            self.assertIsNone(details["secret"])
            self.assertEqual(
                details["argv"],
                [
                    "--private-bash-reference-query-v1",
                    VALID_HANDLE,
                    "--root",
                    str(root),
                    "--state-dir",
                    str(policy.receipt_state_directory(root)),
                    "--offset",
                    "7",
                ],
            )

    def test_cli_adapter_strictly_rejects_malformed_reference_responses(self):
        """Break caught: malformed binding/base64/offset data becomes public bytes."""

        policy = load_policy()
        page = "safe π".encode()
        valid = {
            "next_offset": len(page),
            "offset": 0,
            "payload_b64u": base64.urlsafe_b64encode(page).rstrip(b"=").decode(),
            "request": {"offset": 0, "reference": VALID_HANDLE},
            "schema_version": "contextguard-receipt-bash-reference-query/v1",
            "status": "exact",
            "total_bytes": len(page),
        }

        def encoded(value):
            return json.dumps(
                value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode() + b"\n"

        accepted = policy.NpmReceiptCliAdapter._parse_reference_query_response(
            encoded(valid), reference=VALID_HANDLE, offset=0
        )
        self.assertEqual(accepted.status, "success")

        malformed = []
        wrong_binding = dict(valid)
        wrong_binding["request"] = {"offset": 0, "reference": "cgr1p_" + "X" * 43}
        malformed.append(encoded(wrong_binding))
        boolean_request_offset = dict(valid)
        boolean_request_offset["request"] = {
            "offset": False,
            "reference": VALID_HANDLE,
        }
        malformed.append(encoded(boolean_request_offset))
        float_request_offset = dict(valid)
        float_request_offset["request"] = {
            "offset": 0.0,
            "reference": VALID_HANDLE,
        }
        malformed.append(encoded(float_request_offset))
        padded = dict(valid)
        padded["payload_b64u"] += "="
        malformed.append(encoded(padded))
        split_utf8 = dict(valid)
        split_utf8["payload_b64u"] = base64.urlsafe_b64encode(b"\xff").rstrip(b"=").decode()
        split_utf8["next_offset"] = 1
        split_utf8["total_bytes"] = 1
        malformed.append(encoded(split_utf8))
        wrong_offset = dict(valid)
        wrong_offset["next_offset"] += 1
        malformed.append(encoded(wrong_offset))
        oversized = dict(valid)
        oversized_page = b"x" * 20_001
        oversized["payload_b64u"] = base64.urlsafe_b64encode(
            oversized_page
        ).rstrip(b"=").decode()
        oversized["next_offset"] = len(oversized_page)
        oversized["total_bytes"] = len(oversized_page)
        malformed.append(encoded(oversized))
        extra = dict(valid)
        extra["path"] = "/private/state"
        malformed.append(encoded(extra))
        malformed.append(json.dumps(valid, indent=2, sort_keys=True).encode())

        accepted = policy.NpmReceiptCliAdapter._parse_reference_query_response(
            encoded(valid), reference=VALID_HANDLE, offset=0
        )
        self.assertEqual(accepted.payload, page)
        for raw in malformed:
            with self.subTest(raw=raw[:40]):
                refused = policy.NpmReceiptCliAdapter._parse_reference_query_response(
                    raw, reference=VALID_HANDLE, offset=0
                )
                self.assertEqual(refused.status, "failure")
                self.assertEqual(refused.payload, b"")
                self.assertNotIn(VALID_HANDLE, refused.reason_code)

    def test_cli_adapter_query_rechecks_package_before_launch(self):
        """Break caught: a verified Receipt entrypoint is replaced before query."""

        policy = load_policy()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            cli = root / "verified-cli"
            cli.write_bytes(b"trusted")
            node = Path(sys.executable).resolve()
            adapter = policy.NpmReceiptCliAdapter(
                cli, node_path=node, protected_paths=(cli,)
            )
            cli.write_bytes(b"replaced payload")
            with mock.patch.object(policy.subprocess, "Popen") as popen:
                result = adapter.query_reference(
                    VALID_HANDLE,
                    root=str(root),
                    offset=0,
                    timeout_seconds=8,
                )

        self.assertEqual(result.status, "failure")
        self.assertEqual(result.reason_code, "receipt_package_changed_before_launch")
        self.assertEqual(result.payload, b"")
        popen.assert_not_called()

    def test_broker_final_requires_actionable_current_exact_transaction(self):
        """Break caught: malformed/non-actionable FINAL is elevated to authority."""

        policy = load_policy()
        deadline = policy.time.time_ns() // 1_000_000 + 60_000
        payload = {
            "actionable": False,
            "expires_at_unix_ms": deadline,
            "reference": VALID_HANDLE,
            "status": "registered",
            "transaction_id": "d" * 64,
        }
        raw = (
            b"FINAL "
            + json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
        result = policy.PreparedReceiptBroker._parse_final(raw, "d" * 64)
        self.assertEqual(result.status, "failure")
        self.assertFalse(result.actionable)
        self.assertIsNone(result.reference)

    def test_broker_final_rejects_actionable_noncanonical_handle(self):
        """Break caught: an actionable FINAL smuggles shell syntax as authority."""

        policy = load_policy()
        payload = {
            "actionable": True,
            "expires_at_unix_ms": policy.time.time_ns() // 1_000_000 + 60_000,
            "reference": VALID_HANDLE + ";id",
            "status": "registered",
            "transaction_id": "e" * 64,
        }
        raw = b"FINAL " + json.dumps(
            payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode() + b"\n"

        result = policy.PreparedReceiptBroker._parse_final(raw, "e" * 64)

        self.assertEqual(result.status, "failure")
        self.assertIsNone(result.reference)

if __name__ == "__main__":
    unittest.main()
