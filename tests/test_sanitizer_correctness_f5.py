"""S005 (F-5) sanitizer correctness regressions.

These tests cover the intentionally behavior-changing cases that are excluded
from the frozen S004 differential corpus.  Every case uses synthetic values;
no real credential material is required.
"""
from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path
import re
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "context-guard-kit" / "sanitize_output.py"
PACKAGED = ROOT / "plugins" / "context-guard" / "bin" / "context-guard-sanitize-output"


def load_sanitizer(path: Path, name: str):
    loader = SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load sanitizer: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


SANITIZERS = (
    ("canonical", load_sanitizer(CANONICAL, "f5_sanitizer_canonical")),
    ("packaged", load_sanitizer(PACKAGED, "f5_sanitizer_packaged")),
)


def sanitize_lines(module, text: str, *, context: str = "unknown_text") -> str:
    sanitizer = module.LineSanitizer(context=context)
    return "".join(sanitizer.sanitize(line)[0] for line in text.splitlines(keepends=True))


class SanitizerCorrectnessF5Test(unittest.TestCase):
    def test_existing_consumers_keep_the_shared_punctuation_separator(self) -> None:
        pattern_names = (
            "INLINE_QUOTED_SECRET_ASSIGNMENT_RE",
            "INLINE_UNQUOTED_CALL_SECRET_ASSIGNMENT_RE",
            "INLINE_UNQUOTED_FALLBACK_SECRET_ASSIGNMENT_RE",
            "INLINE_UNQUOTED_BRACKETED_SECRET_ASSIGNMENT_RE",
            "INLINE_UNQUOTED_SECRET_ASSIGNMENT_RE",
            "UNQUOTED_MULTILINE_SECRET_ASSIGNMENT_RE",
            "MULTILINE_SECRET_ASSIGNMENT_RE",
        )
        for source, module in SANITIZERS:
            for pattern_name in pattern_names:
                with self.subTest(source=source, pattern=pattern_name):
                    self.assertIn(
                        module.SECRET_ASSIGNMENT_SEPARATOR,
                        getattr(module, pattern_name).pattern,
                    )

    def test_whitespace_consumers_are_anchored_after_the_one_pass_split(self) -> None:
        pattern_names = (
            "WHITESPACE_QUOTED_SECRET_ASSIGNMENT_NO_LOCATION_RE",
            "WHITESPACE_UNQUOTED_SECRET_ASSIGNMENT_NO_LOCATION_RE",
            "WHITESPACE_MULTILINE_SECRET_ASSIGNMENT_NO_LOCATION_RE",
            "WHITESPACE_UNQUOTED_MULTILINE_SECRET_ASSIGNMENT_NO_LOCATION_RE",
        )
        for source, module in SANITIZERS:
            for pattern_name in pattern_names:
                pattern = getattr(module, pattern_name).pattern
                with self.subTest(source=source, pattern=pattern_name):
                    self.assertIn(r"\A", pattern)
                    self.assertNotIn(module.LOCATION_PREFIX_FRAGMENT, pattern)

    def test_whitespace_separated_assignment_shapes_are_fully_redacted(self) -> None:
        cases = (
            ('api_key "quoted fixture value"\n', 'api_key "[REDACTED]"\n'),
            (
                'api_key load_secret("fixture value; still secret")\n',
                "api_key [REDACTED]\n",
            ),
            (
                'api_key configured_value or "fallback fixture value"\n',
                "api_key [REDACTED]\n",
            ),
            (
                'api_key {"source": "fixture value"}\n',
                "api_key [REDACTED]\n",
            ),
            ("api_key fixture-value\n", "api_key [REDACTED]\n"),
            ("api_key\tfixture-tab-value\n", "api_key\t[REDACTED]\n"),
            ("api_key \t fixture-mixed-value\n", "api_key \t [REDACTED]\n"),
        )
        for source, module in SANITIZERS:
            for raw, expected in cases:
                with self.subTest(source=source, raw=raw):
                    self.assertEqual(sanitize_lines(module, raw), expected)

    def test_whitespace_separated_multiline_shapes_keep_state_fail_closed(self) -> None:
        quote_input = 'api_key "first fixture line\nfixture line\nclose"\nafter = visible\n'
        expression_input = 'api_key (\n    "fixture line"\n)\nafter = visible\n'
        expected = (
            "[REDACTED MULTILINE SECRET]\n"
            "[REDACTED MULTILINE SECRET]\n"
            "[REDACTED MULTILINE SECRET]\n"
            "after = visible\n"
        )
        for source, module in SANITIZERS:
            with self.subTest(source=source, shape="quoted"):
                self.assertEqual(sanitize_lines(module, quote_input), expected)
            with self.subTest(source=source, shape="expression"):
                self.assertEqual(sanitize_lines(module, expression_input), expected)

    def test_pass_sshcommand_and_credential_helper_predicates_agree(self) -> None:
        sensitive_keys = (
            "pass",
            "smtppass",
            "sshCommand",
            "core.sshCommand",
            "credential.helper",
        )
        for source, module in SANITIZERS:
            for key in sensitive_keys:
                with self.subTest(source=source, key=key):
                    self.assertIsNotNone(
                        re.fullmatch(module.SECRET_KEY, key, re.IGNORECASE),
                        "candidate regex must admit the key",
                    )
                    self.assertTrue(
                        module.is_sensitive_key(key),
                        "shared key predicate must agree with the candidate regex",
                    )

    def test_whitespace_git_config_and_compound_pass_values_do_not_leak_tails(self) -> None:
        raw = (
            "credential.helper fixture-helper\n"
            "core.sshCommand ssh -i fixture-key-path fixture-host\n"
            "smtppass fixture-mail-password\n"
            "pass\tfixture-bare-password\n"
            "sshCommand   ssh -i fixture-key-path fixture-host\n"
            "src/config.txt:12: core.sshCommand ssh -F fixture-config fixture-host\n"
        )
        expected = (
            "credential.helper [REDACTED]\n"
            "core.sshCommand [REDACTED]\n"
            "smtppass [REDACTED]\n"
            "pass\t[REDACTED]\n"
            "sshCommand   [REDACTED]\n"
            "src/config.txt:12: core.sshCommand [REDACTED]\n"
        )
        for source, module in SANITIZERS:
            for context in ("unknown_text", "command_search_diff", "source_code"):
                with self.subTest(source=source, context=context):
                    self.assertEqual(
                        sanitize_lines(module, raw, context=context),
                        expected,
                    )

    def test_existing_punctuation_separators_and_benign_keys_are_unchanged(self) -> None:
        raw = (
            "api_key=fixture-value\n"
            "password: fixture-password\n"
            "token_count 12\n"
            "credential.helperText visible\n"
            "sshCommandLine visible\n"
            "compass north\n"
            "bypass enabled\n"
            "passenger count\n"
        )
        expected = (
            "api_key=[REDACTED]\n"
            "password: [REDACTED]\n"
            "token_count 12\n"
            "credential.helperText visible\n"
            "sshCommandLine visible\n"
            "compass north\n"
            "bypass enabled\n"
            "passenger count\n"
        )
        for source, module in SANITIZERS:
            with self.subTest(source=source):
                self.assertEqual(sanitize_lines(module, raw), expected)

    def test_whitespace_separator_does_not_match_secret_words_inside_prose(self) -> None:
        raw = (
            "no secret here at all path/file.py:2: hit\n"
            "설명 문장에는 token proxy 표현과 src/file.py:3: 위치가 있다\n"
        )
        for source, module in SANITIZERS:
            with self.subTest(source=source):
                self.assertEqual(sanitize_lines(module, raw), raw)

    def test_bare_key_prose_does_not_redact_or_enter_multiline_state(self) -> None:
        raw = (
            "password authentication failed\n"
            "token refresh pending\n"
            "PASS tests/test_example.py\n"
            'token "refresh pending\n'
            "next visible line\n"
        )
        for source, module in SANITIZERS:
            with self.subTest(source=source):
                self.assertEqual(sanitize_lines(module, raw), raw)

    def test_pass_candidates_require_an_exact_or_delimited_key_boundary(self) -> None:
        sensitive = ("pass", "smtppass", "smtp_pass", "db.pass", "db-pass")
        benign = ("compass", "bypass", "encompass", "passenger", "passport")
        for source, module in SANITIZERS:
            for key in sensitive:
                with self.subTest(source=source, key=key, expected="sensitive"):
                    self.assertIsNotNone(re.fullmatch(module.SECRET_KEY, key, re.IGNORECASE))
                    self.assertTrue(module.is_sensitive_key(key))
            for key in benign:
                with self.subTest(source=source, key=key, expected="benign"):
                    self.assertIsNone(re.fullmatch(module.SECRET_KEY, key, re.IGNORECASE))
                    self.assertFalse(module.is_sensitive_key(key))


if __name__ == "__main__":
    unittest.main()
