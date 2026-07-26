#!/usr/bin/env python3
"""Focused Release-A2 tests for the ContextGuard Read hook."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import io
import json
import os
import shlex
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
READ_GUARD_SCRIPTS = (
    ROOT / "context-guard-kit" / "guard_large_read.py",
    ROOT / "plugins" / "context-guard" / "bin" / "context-guard-guard-read",
)


def load_guard(path: Path, suffix: str):
    name = f"_context_guard_a2_read_{suffix}"
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def proof(
    guard,
    data: bytes,
    *,
    offset: int,
    limit: int,
    content_budget: int,
    proof_budget: int,
):
    with tempfile.NamedTemporaryFile() as handle:
        handle.write(data)
        handle.flush()
        fd = os.open(handle.name, os.O_RDONLY)
        try:
            return guard.prove_raw_read_range(
                fd,
                file_size=len(data),
                offset=offset,
                limit=limit,
                content_budget=content_budget,
                proof_budget=proof_budget,
            )
        finally:
            os.close(fd)


def invoke_guard(
    guard,
    payload: object,
    *,
    cwd: Path,
    max_bytes: int = 4,
    max_lines: int = 400,
    proof_bytes: int | None = None,
) -> tuple[int, str, str]:
    stdin, stdout, stderr = guard.sys.stdin, guard.sys.stdout, guard.sys.stderr
    previous_cwd = Path.cwd()
    captured_stdout = io.StringIO()
    captured_stderr = io.StringIO()
    environment = {
        guard.GUARD_ENV: "1",
        guard.LEGACY_GUARD_ENV: "1",
        guard.MAX_BYTES_ENV: str(max_bytes),
        guard.LEGACY_MAX_BYTES_ENV: str(max_bytes),
        guard.MAX_LINE_RANGE_ENV: str(max_lines),
        guard.LEGACY_MAX_LINE_RANGE_ENV: str(max_lines),
    }
    if proof_bytes is not None:
        environment[guard.READ_PROOF_BYTES_ENV] = str(proof_bytes)
        environment[guard.LEGACY_READ_PROOF_BYTES_ENV] = str(proof_bytes)
    try:
        os.chdir(cwd)
        guard.sys.stdin = io.StringIO(json.dumps(payload))
        guard.sys.stdout = captured_stdout
        guard.sys.stderr = captured_stderr
        with mock.patch.dict(os.environ, environment, clear=True):
            return_code = guard.main()
        return return_code, captured_stdout.getvalue(), captured_stderr.getvalue()
    finally:
        os.chdir(previous_cwd)
        guard.sys.stdin, guard.sys.stdout, guard.sys.stderr = stdin, stdout, stderr


def hook_result(stdout: str) -> dict[str, object]:
    value = json.loads(stdout)
    assert isinstance(value, dict)
    return value


def decision(stdout: str) -> str:
    output = hook_result(stdout).get("hookSpecificOutput")
    if not isinstance(output, dict):
        return "noop"
    return str(output.get("permissionDecision", "other"))


def reason(stdout: str) -> str:
    output = hook_result(stdout)["hookSpecificOutput"]
    assert isinstance(output, dict)
    return str(output["permissionDecisionReason"])


class ReadA2ContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.guards = [
            load_guard(path, f"{index}_{self._testMethodName}")
            for index, path in enumerate(READ_GUARD_SCRIPTS)
        ]

    def test_canonical_plugin_bytes_and_contract_constants_match(self) -> None:
        self.assertEqual(READ_GUARD_SCRIPTS[0].read_bytes(), READ_GUARD_SCRIPTS[1].read_bytes())
        canonical, packaged = self.guards
        for name in (
            "DEFAULT_READ_PROOF_BYTES",
            "MIN_READ_PROOF_BYTES",
            "MAX_READ_PROOF_BYTES",
            "MAX_READ_RANGE_INTEGER",
            "ALLOWED_ENV_TEMPLATE_BASENAMES",
        ):
            self.assertEqual(getattr(canonical, name), getattr(packaged, name))
        self.assertEqual(canonical.DEFAULT_READ_PROOF_BYTES, 8 * 1024 * 1024)
        self.assertEqual(canonical.MIN_READ_PROOF_BYTES, 64 * 1024)
        self.assertEqual(canonical.MAX_READ_PROOF_BYTES, 64 * 1024 * 1024)

    def test_proof_budget_bounds_and_strict_large_range_validation(self) -> None:
        for guard in self.guards:
            with self.subTest(script=guard.__file__):
                with mock.patch.dict(os.environ, {}, clear=True):
                    self.assertEqual(guard.read_proof_bytes(), guard.DEFAULT_READ_PROOF_BYTES)
                with mock.patch.dict(os.environ, {guard.READ_PROOF_BYTES_ENV: "1"}, clear=True):
                    self.assertEqual(guard.read_proof_bytes(), guard.MIN_READ_PROOF_BYTES)
                with mock.patch.dict(
                    os.environ,
                    {guard.READ_PROOF_BYTES_ENV: str(guard.MAX_READ_PROOF_BYTES + 1)},
                    clear=True,
                ):
                    self.assertEqual(guard.read_proof_bytes(), guard.MAX_READ_PROOF_BYTES)
                with mock.patch.dict(os.environ, {guard.READ_PROOF_BYTES_ENV: "invalid"}, clear=True):
                    self.assertEqual(guard.read_proof_bytes(), guard.DEFAULT_READ_PROOF_BYTES)

                self.assertEqual(
                    guard.large_read_range({"tool_input": {"limit": "2"}}),
                    (0, 2),
                )
                self.assertEqual(
                    guard.large_read_range({"tool_input": {"offset": "3", "limit": "2"}}),
                    (3, 2),
                )
                invalid_inputs = (
                    {"limit": None},
                    {"limit": True},
                    {"limit": 1.5},
                    {"limit": "1.5"},
                    {"limit": 0},
                    {"limit": -1},
                    {"limit": guard.MAX_LINE_RANGE_LIMIT + 1},
                    {"limit": 1, "offset": True},
                    {"limit": 1, "offset": -1},
                    {"limit": 1, "offset": 1.5},
                    {"limit": 1, "offset": guard.MAX_READ_RANGE_INTEGER + 1},
                    {"limit": 2, "offset": guard.MAX_READ_RANGE_INTEGER},
                )
                for tool_input in invalid_inputs:
                    with self.subTest(script=guard.__file__, tool_input=tool_input):
                        self.assertIsNone(guard.large_read_range({"tool_input": tool_input}))

    def test_raw_byte_charging_lf_cr_eof_and_invalid_utf8(self) -> None:
        cases = (
            (b"abc", 0, 1, 4, "allowed", 3),
            (b"abc", 0, 1, 2, "content_budget_exceeded", 3),
            (b"a\nbc", 1, 1, 4, "allowed", 2),
            (b"a\nbc", 0, 2, 4, "allowed", 3),
            (b"a\r\nbc", 0, 1, 4, "allowed", 2),
            (b"\xff\xc3\xa9", 0, 1, 3, "allowed", 3),
            (b"\xff\xc3\xa9", 0, 1, 2, "content_budget_exceeded", 3),
        )
        for guard in self.guards:
            for data, offset, limit, budget, expected_outcome, charged in cases:
                with self.subTest(script=guard.__file__, data=data, offset=offset, limit=limit):
                    result = proof(
                        guard,
                        data,
                        offset=offset,
                        limit=limit,
                        content_budget=budget,
                        proof_budget=guard.MIN_READ_PROOF_BYTES,
                    )
                    self.assertEqual(result.outcome, expected_outcome)
                    self.assertEqual(result.charged_bytes, charged)

            one_line = proof(
                guard,
                b"x" * (100 * 1024),
                offset=0,
                limit=1,
                content_budget=48_000,
                proof_budget=guard.DEFAULT_READ_PROOF_BYTES,
            )
            self.assertEqual(one_line.outcome, "content_budget_exceeded")
            self.assertEqual(one_line.charged_bytes, 48_001)

    def test_eof_suffix_empty_range_and_exact_default_proof_boundary(self) -> None:
        for guard in self.guards:
            cases = (
                (b"", 0, 1, 0),
                (b"a\n", 1, 1, 0),
                (b"a\nbc", 1, 5, 2),
                (b"a\nbc", 2, 1, 0),
                (b"a\nbc", 3, 1, 0),
            )
            for data, offset, limit, charged in cases:
                with self.subTest(script=guard.__file__, data=data, offset=offset):
                    result = proof(
                        guard,
                        data,
                        offset=offset,
                        limit=limit,
                        content_budget=4,
                        proof_budget=guard.MIN_READ_PROOF_BYTES,
                    )
                    self.assertEqual(result.outcome, "allowed")
                    self.assertEqual(result.charged_bytes, charged)

            exact = b"x" * guard.DEFAULT_READ_PROOF_BYTES
            exact_result = proof(
                guard,
                exact,
                offset=1,
                limit=1,
                content_budget=guard.DEFAULT_READ_PROOF_BYTES + 1,
                proof_budget=guard.DEFAULT_READ_PROOF_BYTES,
            )
            self.assertEqual(exact_result.outcome, "allowed")
            plus_one_result = proof(
                guard,
                exact + b"x",
                offset=1,
                limit=1,
                content_budget=guard.DEFAULT_READ_PROOF_BYTES + 1,
                proof_budget=guard.DEFAULT_READ_PROOF_BYTES,
            )
            self.assertEqual(plus_one_result.outcome, "proof_budget_exhausted")

    def test_default_proof_budget_allows_valid_non_eof_high_offset_slice(self) -> None:
        high_offset = 3_000_000
        selected_line = b"chosen-slice\n"
        prefix = b"x\n" * high_offset
        data = prefix + selected_line + b"tail\n"
        for guard in self.guards:
            with self.subTest(script=guard.__file__), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                target = root / "high-offset.bin"
                target.write_bytes(data)
                original_proof = guard.prove_raw_read_range
                observed: dict[str, object] = {}

                def observing_proof(fd, **kwargs):
                    result = original_proof(fd, **kwargs)
                    observed.update(kwargs)
                    observed["result"] = result
                    return result

                with mock.patch.object(guard, "prove_raw_read_range", observing_proof):
                    return_code, stdout, stderr = invoke_guard(
                        guard,
                        {
                            "tool_name": "Read",
                            "tool_input": {
                                "file_path": target.name,
                                "offset": high_offset,
                                "limit": 1,
                            },
                        },
                        cwd=root,
                        max_bytes=len(selected_line) - 1,
                    )

                proof_result = observed["result"]
                self.assertEqual(return_code, 0)
                self.assertEqual(stdout, "{}\n")
                self.assertEqual(stderr, "")
                self.assertEqual(decision(stdout), "noop")
                self.assertEqual(observed["proof_budget"], guard.DEFAULT_READ_PROOF_BYTES)
                self.assertEqual(proof_result.outcome, "allowed")
                self.assertEqual(proof_result.charged_bytes, len(selected_line) - 1)
                self.assertEqual(proof_result.scanned_bytes, len(prefix) + len(selected_line))
                self.assertGreater(proof_result.scanned_bytes, guard.MIN_READ_PROOF_BYTES)
                self.assertLess(proof_result.scanned_bytes, len(data))

    def test_small_file_ordering_and_large_invalid_or_oversized_ranges(self) -> None:
        for guard in self.guards:
            with self.subTest(script=guard.__file__), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "small.bin").write_bytes(b"abc")
                _, stdout, _ = invoke_guard(
                    guard,
                    {"tool_name": "Read", "tool_input": {"file_path": "small.bin", "limit": 0}},
                    cwd=root,
                )
                self.assertEqual(decision(stdout), "noop")

                (root / "large.bin").write_bytes(b"x\n" * 10)
                invalid_ranges = (
                    {},
                    {"limit": True},
                    {"limit": 0},
                    {"limit": -1},
                    {"limit": 401},
                    {"limit": 1, "offset": -1},
                    {"limit": 1, "offset": 1.5},
                    {"limit": 1, "offset": 1 << 63},
                )
                for read_range in invalid_ranges:
                    payload = {"file_path": "large.bin", **read_range}
                    _, stdout, _ = invoke_guard(
                        guard,
                        {"tool_name": "Read", "tool_input": payload},
                        cwd=root,
                    )
                    self.assertEqual(decision(stdout), "deny")
                    self.assertIn("invalid_read_range", reason(stdout))

                _, stdout, _ = invoke_guard(
                    guard,
                    {
                        "tool_name": "Read",
                        "tool_input": {"file_path": "large.bin", "offset": 0, "limit": 1},
                    },
                    cwd=root,
                )
                self.assertEqual(decision(stdout), "noop")
                _, stdout, _ = invoke_guard(
                    guard,
                    {
                        "tool_name": "Read",
                        "tool_input": {"file_path": "large.bin", "offset": 20, "limit": 1},
                    },
                    cwd=root,
                )
                self.assertEqual(decision(stdout), "noop")

                (root / "one-line.bin").write_bytes(b"x" * 5)
                _, stdout, _ = invoke_guard(
                    guard,
                    {
                        "tool_name": "Read",
                        "tool_input": {"file_path": "one-line.bin", "offset": 0, "limit": 1},
                    },
                    cwd=root,
                )
                self.assertEqual(decision(stdout), "deny")
                self.assertIn("content_budget_exceeded", reason(stdout))

                (root / "proof-boundary.bin").write_bytes(
                    b"x" * (guard.MIN_READ_PROOF_BYTES + 1)
                )
                _, stdout, _ = invoke_guard(
                    guard,
                    {
                        "tool_name": "Read",
                        "tool_input": {
                            "file_path": "proof-boundary.bin",
                            "offset": 1,
                            "limit": 1,
                        },
                    },
                    cwd=root,
                    proof_bytes=guard.MIN_READ_PROOF_BYTES,
                )
                self.assertEqual(decision(stdout), "deny")
                self.assertIn("proof_budget_exhausted", reason(stdout))

                _, stdout, _ = invoke_guard(
                    guard,
                    {"tool_name": "Read", "tool_input": {"file_path": "."}},
                    cwd=root,
                )
                self.assertEqual(decision(stdout), "deny")
                self.assertIn("not a regular file", reason(stdout))

    def test_same_fd_size_and_mtime_changes_deny_with_toctou_boundary(self) -> None:
        for guard in self.guards:
            for mutation in ("size", "mtime"):
                with self.subTest(script=guard.__file__, mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    target = root / "race.bin"
                    target.write_bytes(b"a\nb\n" + (b"z\n" * 10))
                    original_proof = guard.prove_raw_read_range

                    def racing_proof(*args, **kwargs):
                        result = original_proof(*args, **kwargs)
                        if mutation == "size":
                            with target.open("ab") as handle:
                                handle.write(b"changed")
                        else:
                            current = target.stat()
                            os.utime(
                                target,
                                ns=(current.st_atime_ns, current.st_mtime_ns + 1_000_000_000),
                            )
                        return result

                    with mock.patch.object(guard, "prove_raw_read_range", racing_proof):
                        _, stdout, _ = invoke_guard(
                            guard,
                            {
                                "tool_name": "Read",
                                "tool_input": {"file_path": target.name, "offset": 0, "limit": 1},
                            },
                            cwd=root,
                        )
                    self.assertEqual(decision(stdout), "deny")
                    self.assertIn("file_changed_during_proof", reason(stdout))
                    self.assertIn("TOCTOU limitation", reason(stdout))

    def test_open_fd_inode_replacement_denies_without_path_or_secret_leak(self) -> None:
        for guard in self.guards:
            with self.subTest(script=guard.__file__), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                root = base / "project"
                root.mkdir()
                secret = "ghp_" + ("A" * 36)
                target = base / f"race-{secret}.bin"
                replacement = base / "replacement.bin"
                data = b"a\nb\n" + (b"z\n" * 10)
                target.write_bytes(data)
                replacement.write_bytes(data)
                initial_path_stat = target.stat()
                os.utime(
                    replacement,
                    ns=(initial_path_stat.st_atime_ns, initial_path_stat.st_mtime_ns),
                )
                original_proof = guard.prove_raw_read_range
                replacement_observed = False

                def replacing_proof(fd, *args, **kwargs):
                    nonlocal replacement_observed
                    initial_fd_stat = os.fstat(fd)
                    result = original_proof(fd, *args, **kwargs)
                    os.replace(replacement, target)
                    replacement_fd = os.open(target, os.O_RDONLY)
                    try:
                        replacement_stat = os.fstat(replacement_fd)
                        self.assertEqual(initial_fd_stat.st_size, replacement_stat.st_size)
                        self.assertEqual(
                            initial_fd_stat.st_mtime_ns,
                            replacement_stat.st_mtime_ns,
                        )
                        self.assertNotEqual(
                            (initial_fd_stat.st_dev, initial_fd_stat.st_ino),
                            (replacement_stat.st_dev, replacement_stat.st_ino),
                        )
                        os.dup2(replacement_fd, fd)
                        replacement_observed = True
                    finally:
                        os.close(replacement_fd)
                    return result

                with mock.patch.object(guard, "prove_raw_read_range", replacing_proof):
                    return_code, stdout, stderr = invoke_guard(
                        guard,
                        {
                            "tool_name": "Read",
                            "tool_input": {
                                "file_path": str(target),
                                "offset": 0,
                                "limit": 1,
                            },
                        },
                        cwd=root,
                    )

                combined = stdout + stderr
                self.assertTrue(replacement_observed)
                self.assertEqual(return_code, 0)
                self.assertEqual(stderr, "")
                self.assertEqual(decision(stdout), "deny")
                self.assertIn("file_changed_during_proof", reason(stdout))
                self.assertIn("TOCTOU limitation", reason(stdout))
                self.assertIn("an out-of-project file", reason(stdout))
                self.assertNotIn(str(base), combined)
                self.assertNotIn(target.name, combined)
                self.assertNotIn(secret, combined)

    def test_remediation_uses_real_relative_path_or_generic_external_guidance(self) -> None:
        for guard in self.guards:
            with self.subTest(script=guard.__file__), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "project"
                outside_root = Path(tmp) / "outside"
                root.mkdir()
                outside_root.mkdir()
                project_file = root / "bad; name.py"
                project_file.write_bytes(b"x\n" * 10)
                _, stdout, _ = invoke_guard(
                    guard,
                    {"tool_name": "Read", "tool_input": {"file_path": project_file.name}},
                    cwd=root,
                )
                project_reason = reason(stdout)
                self.assertIn(shlex.quote(project_file.name), project_reason)
                self.assertNotIn(str(root), project_reason)

                outside_file = outside_root / "external.py"
                outside_file.write_bytes(b"x\n" * 10)
                _, stdout, _ = invoke_guard(
                    guard,
                    {"tool_name": "Read", "tool_input": {"file_path": str(outside_file)}},
                    cwd=root,
                )
                external_reason = reason(stdout)
                self.assertNotIn(str(outside_file), external_reason)
                self.assertNotIn("redacted-path#path:", external_reason)
                self.assertNotIn("`rg ", external_reason)
                self.assertNotIn("context-guard-read-symbol", external_reason)
                self.assertIn("out-of-project file", external_reason)
                self.assertIn("No executable path suggestion", external_reason)

    def test_env_classifier_exact_exceptions_nested_normalized_and_symlink_ambiguity(self) -> None:
        denied_names = (
            ".env",
            ".env.local",
            ".env.production",
            ".envrc",
            ".env.example.local",
            ".ENV",
            ".Env.Example",
            ".env-example",
            ".environment",
            ".env_example",
        )
        allowed_names = (".env.example", ".env.sample", ".env.template")
        for guard in self.guards:
            with self.subTest(script=guard.__file__), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                nested = root / "nested"
                nested.mkdir()
                for name in denied_names:
                    for parent in (root, nested):
                        (parent / name).write_text("secret=1\n", encoding="utf-8")
                        requested = (parent / name).relative_to(root).as_posix()
                        _, stdout, _ = invoke_guard(
                            guard,
                            {"tool_name": "Read", "tool_input": {"file_path": requested}},
                            cwd=root,
                        )
                        self.assertEqual(decision(stdout), "deny")
                        self.assertIn("Read-only environment-file policy", reason(stdout))
                        self.assertIn("Bash/process access are out of scope", reason(stdout))

                for name in allowed_names:
                    (root / name).write_bytes(b"x\n")
                    _, stdout, _ = invoke_guard(
                        guard,
                        {"tool_name": "Read", "tool_input": {"file_path": name}},
                        cwd=root,
                    )
                    self.assertEqual(decision(stdout), "noop")

                _, stdout, _ = invoke_guard(
                    guard,
                    {"tool_name": "Read", "tool_input": {"file_path": "nested/../.env"}},
                    cwd=root,
                )
                self.assertEqual(decision(stdout), "deny")
                _, stdout, _ = invoke_guard(
                    guard,
                    {"tool_name": "Grep", "tool_input": {"file_path": ".env"}},
                    cwd=root,
                )
                self.assertEqual(decision(stdout), "noop")

                alias = root / "template-link"
                allowed_name_alias = nested / ".env.template"
                try:
                    alias.symlink_to(root / ".env.template")
                    allowed_name_alias.symlink_to(root / ".env.template")
                except (OSError, NotImplementedError) as exc:
                    self.skipTest(f"symlink unavailable: {exc}")
                for requested in (alias.name, "nested/.env.template"):
                    _, stdout, _ = invoke_guard(
                        guard,
                        {"tool_name": "Read", "tool_input": {"file_path": requested}},
                        cwd=root,
                    )
                    self.assertEqual(decision(stdout), "deny")
                    self.assertIn("symlink", reason(stdout))

    def test_canonical_and_packaged_decisions_match(self) -> None:
        payloads = (
            {"tool_name": "Read", "tool_input": {"file_path": "small.bin", "limit": 0}},
            {
                "tool_name": "Read",
                "tool_input": {"file_path": "large.bin", "offset": 0, "limit": 1},
            },
            {"tool_name": "Read", "tool_input": {"file_path": ".env"}},
            {"tool_name": "Grep", "tool_input": {"file_path": ".env"}},
        )
        outputs: list[list[str]] = [[], []]
        for index, guard in enumerate(self.guards):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "small.bin").write_bytes(b"abc")
                (root / "large.bin").write_bytes(b"x\n" * 10)
                (root / ".env").write_text("secret=1\n", encoding="utf-8")
                for payload in payloads:
                    _, stdout, stderr = invoke_guard(guard, payload, cwd=root)
                    self.assertEqual(stderr, "")
                    outputs[index].append(stdout)
        self.assertEqual(outputs[0], outputs[1])


if __name__ == "__main__":
    unittest.main()
