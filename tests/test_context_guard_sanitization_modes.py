#!/usr/bin/env python3
"""Focused A1 regression tests for explicit sanitization contexts."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

try:
    from tests.context_guard_a1_oracles import (
        SANITIZER_SEED,
        consumer_mode_cases,
        format_minimized_failure,
        sanitizer_mode_cases,
    )
except ModuleNotFoundError:  # Worker branches receive the shared oracle at integration.
    SANITIZER_SEED = 0xA15A
    consumer_mode_cases = None
    format_minimized_failure = None
    sanitizer_mode_cases = None


ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "context-guard-kit"
PLUGIN_BIN = ROOT / "plugins" / "context-guard" / "bin"


def load_script(path: Path, name: str):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        raise RuntimeError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


class SanitizationModeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sanitize = load_script(KIT / "sanitize_output.py", "a1_sanitize_output")

    def sanitize_lines(
        self,
        text: str,
        *,
        context: str,
        private_roots: tuple[str, ...] = (),
    ) -> tuple[str, object]:
        sanitizer = self.sanitize.LineSanitizer(
            context=context,
            private_roots=private_roots,
        )
        output = "".join(
            sanitizer.sanitize(line)[0] for line in text.splitlines(keepends=True)
        )
        return output, sanitizer

    def test_same_path_literals_follow_the_explicit_mode_matrix(self) -> None:
        ambiguous = (
            "/api/v1/users\n"
            "/health/check\n"
            'route = r"/foo/bar"\n'
            "from /foo/bar import widget\n"
        )
        private_listing = "/Users/alice/private/project/app.py\n"
        traceback = '  File "/Users/alice/private/project/app.py", line 12, in run\n'
        grep_location = "/Users/alice/private/project/app.py:14:9: failure\n"
        raw = ambiguous + private_listing + traceback + grep_location

        unknown, _ = self.sanitize_lines(raw, context="unknown_text")
        source, _ = self.sanitize_lines(raw, context="source_code")
        search, _ = self.sanitize_lines(raw, context="command_search_diff")
        listing, _ = self.sanitize_lines(
            raw,
            context="filesystem_listing",
            private_roots=("/Users/alice/private",),
        )

        self.assertEqual(unknown, raw)
        self.assertEqual(source, raw)
        for literal in ambiguous.splitlines():
            self.assertIn(literal, search)
            self.assertIn(literal, listing)
        self.assertIn(private_listing, search)
        self.assertEqual(search.count("/Users/alice/private"), 1)
        self.assertNotIn("/Users/alice/private", listing)
        self.assertRegex(search, r"app\.py#path:[0-9a-f]{12}:14:9")
        self.assertRegex(search, r'File "app\.py#path:[0-9a-f]{12}", line 12')

    def test_default_cli_mode_preserves_ambiguous_paths_but_redacts_credentials(self) -> None:
        raw = (
            "/api/v1/users\n"
            'route = r"/foo/bar"\n'
            "/Users/alice/project/app.py:12: error\n"
            "Authorization: Bearer opaque-secret\n"
            "API_TOKEN=ghp_" + ("A" * 36) + "\n"
        )
        for script in (
            KIT / "sanitize_output.py",
            PLUGIN_BIN / "context-guard-sanitize-output",
        ):
            with self.subTest(script=script):
                proc = subprocess.run(
                    [sys.executable, str(script)],
                    input=raw,
                    text=True,
                    capture_output=True,
                    check=True,
                )
                self.assertIn("/api/v1/users", proc.stdout)
                self.assertIn('r"/foo/bar"', proc.stdout)
                self.assertIn("/Users/alice/project/app.py:12", proc.stdout)
                self.assertIn("Authorization: [REDACTED]", proc.stdout)
                self.assertIn("API_TOKEN=[REDACTED]", proc.stdout)
                self.assertNotIn("opaque-secret", proc.stdout)
                self.assertNotIn("ghp_", proc.stdout)

    def test_source_code_preserves_benign_token_vocabulary_and_is_idempotent(self) -> None:
        secret = "ghp_" + ("B" * 36)
        raw = (
            "token_count = 123\n"
            "output_tokens: 313\n"
            "max_tokens=4096\n"
            "token_budget=100\n"
            'usage = {"token_count": 3}\n'
            "token: str\n"
            "value: Optional[str]\n"
            "token: string\n"
            "tokenizer = build_tokenizer()\n"
            "secretary = employee\n"
            "signature_algorithm = 'ed25519'\n"
            "API_TOKEN=\"" + secret + "\"\n"
        )
        once, sanitizer = self.sanitize_lines(raw, context="source_code")
        twice, _ = self.sanitize_lines(once, context="source_code")

        for benign in raw.splitlines()[:-1]:
            self.assertIn(benign, once)
        self.assertIn('API_TOKEN="[REDACTED]"', once)
        self.assertNotIn(secret, once)
        self.assertEqual(twice, once)
        self.assertEqual(sanitizer.redactions, 1)

    def test_unknown_text_redacts_bareword_colon_secrets_and_qualified_keys(self) -> None:
        raw = (
            "password: hunter2pass\n"
            "api_key: abc123def456\n"
            "jsessionid: opaque-session-value\n"
            "stripe_secret_key: stripe-value\n"
            "apikey_v2: versioned-value\n"
            "mysql_root_password_prod: production-value\n"
            "token_backup: backup-value\n"
            "request /login?token=query-secret&state=visible\n"
        )
        output, sanitizer = self.sanitize_lines(raw, context="unknown_text")
        for secret in (
            "hunter2pass",
            "abc123def456",
            "opaque-session-value",
            "stripe-value",
            "versioned-value",
            "production-value",
            "backup-value",
            "query-secret",
        ):
            self.assertNotIn(secret, output)
        self.assertIn("state=visible", output)
        self.assertGreaterEqual(sanitizer.redactions, 8)

    def test_search_context_only_anonymizes_strict_location_fields(self) -> None:
        raw = (
            "GET /api/v1/users\n"
            'regex = r"/foo/bar"\n'
            "--- /Users/alice/project/app.py\n"
            "+++ /Users/alice/project/app.py\n"
            "/Users/alice/project/app.py:22: result\n"
        )
        output, sanitizer = self.sanitize_lines(
            raw,
            context="command_search_diff",
        )
        self.assertIn("GET /api/v1/users", output)
        self.assertIn('r"/foo/bar"', output)
        self.assertNotIn("/Users/alice", output)
        self.assertGreaterEqual(sanitizer.path_redactions, 3)

    def test_context_is_immutable_and_git_global_options_keep_search_mode(self) -> None:
        context = self.sanitize.SanitizationContext(
            mode="filesystem_listing",
            private_roots=("/Users/alice/private",),
        )
        with self.assertRaises(Exception):
            context.mode = "unknown_text"
        for command in (
            ["git", "-C", "repo", "diff"],
            ["git", "--git-dir", "/tmp/repo.git", "show"],
            ["git", "--work-tree=/tmp/tree", "grep", "token"],
        ):
            with self.subTest(command=command):
                self.assertTrue(
                    self.sanitize.command_uses_search_diff_output(command)
                )

    def test_consumer_helpers_pass_declared_modes_and_roots(self) -> None:
        trim = load_script(KIT / "trim_command_output.py", "a1_trim")
        symbol = load_script(KIT / "read_symbol.py", "a1_symbol")
        compress = load_script(KIT / "context_compress.py", "a1_compress")
        pack = load_script(KIT / "context_pack.py", "a1_pack")
        escrow = load_script(KIT / "context_escrow.py", "a1_escrow")

        trim_sanitizer = trim.load_line_sanitizer(False, context="unknown_text")
        self.assertEqual(trim_sanitizer.context.mode, "unknown_text")
        self.assertIn(
            'route = r"/foo/bar"',
            symbol.redact_symbol_content('route = r"/foo/bar"\n'),
        )
        self.assertEqual(
            compress.sanitize_text(
                "/api/v1/users\n",
                context="source_code",
            )[0],
            "/api/v1/users\n",
        )
        self.assertEqual(
            pack.sanitize_text("/health/check\n", context="unknown_text")[0],
            "/health/check\n",
        )
        listed = escrow.sanitize_text(
            "/Users/alice/private/file.txt\n",
            context="filesystem_listing",
            private_roots=("/Users/alice/private",),
        )[0]
        self.assertNotIn("/Users/alice/private", listed)
        self.assertRegex(listed, r"file\.txt#path:[0-9a-f]{12}")

    def test_non_unknown_legacy_sanitizer_fallbacks_fail_closed(self) -> None:
        class LegacySanitizer:
            def __init__(self, *, show_paths: bool = False) -> None:
                self.show_paths = show_paths

        for script_name, module_name in (
            ("trim_command_output.py", "a1_trim_legacy"),
            ("context_compress.py", "a1_compress_legacy"),
            ("context_pack.py", "a1_pack_legacy"),
            ("context_escrow.py", "a1_escrow_legacy"),
        ):
            module = load_script(KIT / script_name, module_name)
            with self.subTest(script=script_name):
                with self.assertRaises(RuntimeError):
                    module.instantiate_line_sanitizer(
                        LegacySanitizer,
                        show_paths=False,
                        context="source_code",
                    )

    def test_escrow_persists_declared_origin_without_private_root_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            private_root = "/Users/alice/private"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(KIT / "context_escrow.py"),
                    "--dir",
                    tmp,
                    "store",
                    "--sanitize-context",
                    "filesystem_listing",
                    "--private-root",
                    private_root,
                    "--json",
                ],
                input=private_root + "/file.txt\n",
                text=True,
                capture_output=True,
                check=True,
            )
            receipt = json.loads(proc.stdout)
            artifact_id = receipt["artifact_id"]
            metadata = json.loads(
                (Path(tmp) / f"{artifact_id}.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                metadata["sanitization"]["context"],
                "filesystem_listing",
            )
            serialized = json.dumps(metadata, ensure_ascii=False)
            self.assertNotIn(private_root, serialized)

    def test_tool_schema_pruner_uses_exact_sensitive_key_boundaries(self) -> None:
        pruner = load_script(KIT / "tool_schema_pruner.py", "a1_tool_pruner")
        raw = {
            "token_count": 123,
            "secretary": "Ada",
            "signature_algorithm": "ed25519",
            "token": "ghp_" + ("C" * 36),
            "client_secret": {"default": "literal-secret"},
            "nested": [{"password": "hunter2"}, {"output_tokens": 313}],
        }
        sanitized, count = pruner.sanitize_value(raw)
        sanitized_twice, second_count = pruner.sanitize_value(sanitized)

        self.assertEqual(sanitized["token_count"], 123)
        self.assertEqual(sanitized["secretary"], "Ada")
        self.assertEqual(sanitized["signature_algorithm"], "ed25519")
        self.assertEqual(sanitized["token"], "[REDACTED]")
        self.assertEqual(sanitized["client_secret"]["default"], "[REDACTED]")
        self.assertEqual(sanitized["nested"][0]["password"], "[REDACTED]")
        self.assertEqual(sanitized["nested"][1]["output_tokens"], 313)
        self.assertEqual(count, 3)
        self.assertEqual(sanitized_twice, sanitized)
        self.assertEqual(second_count, 0)

    def test_tool_schema_pruner_loads_pure_policy_without_executing_sanitizer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            isolated = Path(tmp)
            shutil.copy2(KIT / "tool_schema_pruner.py", isolated / "tool_schema_pruner.py")
            shutil.copy2(KIT / "credential_policy.py", isolated / "credential_policy.py")
            marker = isolated / "sanitizer-executed"
            (isolated / "sanitize_output.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n"
                "raise RuntimeError('full sanitizer source executed')\n",
                encoding="utf-8",
            )

            pruner = load_script(
                isolated / "tool_schema_pruner.py",
                "a1_tool_pruner_isolated_policy",
            )
            sanitized, count = pruner.sanitize_value(
                {"token": "ghp_" + ("D" * 36), "token_count": 4}
            )

            self.assertFalse(marker.exists())
            self.assertEqual(sanitized, {"token": "[REDACTED]", "token_count": 4})
            self.assertEqual(count, 1)

    def test_owned_consumer_pairs_are_byte_identical(self) -> None:
        pairs = (
            ("sanitize_output.py", "context-guard-sanitize-output"),
            ("trim_command_output.py", "context-guard-trim-output"),
            ("read_symbol.py", "context-guard-read-symbol"),
            ("context_compress.py", "context-guard-compress"),
            ("context_pack.py", "context-guard-pack"),
            ("context_escrow.py", "context-guard-artifact"),
            ("tool_schema_pruner.py", "context-guard-tool-prune"),
            ("experimental_registry.py", "context-guard-experiments"),
        )
        for canonical, packaged in pairs:
            with self.subTest(canonical=canonical):
                self.assertEqual(
                    (KIT / canonical).read_bytes(),
                    (PLUGIN_BIN / packaged).read_bytes(),
                )
        self.assertEqual(
            (KIT / "credential_policy.py").read_bytes(),
            (PLUGIN_BIN.parent / "lib" / "credential_policy.py").read_bytes(),
        )

    @unittest.skipIf(sanitizer_mode_cases is None, "shared A1 oracle not integrated")
    def test_fixed_seed_sanitizer_oracle_matrix(self) -> None:
        cases = sanitizer_mode_cases()
        self.assertEqual(SANITIZER_SEED, 0xA15A)
        # FIX-6 이 리터럴 2개(`credential_url_token_only` 양성 + AC-1.3
        # `bare_userinfo_without_scheme` 음성)를 추가해 17개 리터럴 x 4 모드 = 68.
        self.assertEqual(len(cases), 68)

        for case in cases:
            raw = str(case["input"])
            output, sanitizer = self.sanitize_lines(
                raw if raw.endswith("\n") else raw + "\n",
                context=str(case["mode"]),
                private_roots=tuple(str(root) for root in case["private_roots"]),
            )
            expectation = str(case["expectation"])
            if expectation == "preserve":
                actual = "preserve" if output.rstrip("\n") == raw else "changed"
            elif expectation == "redact_path":
                actual = (
                    "redact_path"
                    if "/Users/contextguard-private" not in output
                    and "#path:" in output
                    else "path_visible"
                )
            else:
                actual = (
                    "redact_secret"
                    if output.rstrip("\n") != raw
                    and "[REDACTED" in output
                    else "secret_visible"
                )
            with self.subTest(case_id=case["case_id"]):
                if actual != expectation:
                    self.fail(
                        format_minimized_failure(
                            case,
                            actual,
                            expected_field="expectation",
                        )
                    )
                second, _ = self.sanitize_lines(
                    output,
                    context=str(case["mode"]),
                    private_roots=tuple(
                        str(root) for root in case["private_roots"]
                    ),
                )
                self.assertEqual(second, output)
                if expectation != "preserve":
                    self.assertGreater(sanitizer.redactions, 0)

    @unittest.skipIf(consumer_mode_cases is None, "shared A1 oracle not integrated")
    def test_fixed_consumer_oracle_pair_matrix(self) -> None:
        cases = consumer_mode_cases()
        self.assertEqual(len(cases), 8)
        for case in cases:
            with self.subTest(case_id=case["case_id"]):
                self.assertEqual(
                    (ROOT / str(case["canonical"])).read_bytes(),
                    (ROOT / str(case["packaged"])).read_bytes(),
                )


if __name__ == "__main__":
    unittest.main()
