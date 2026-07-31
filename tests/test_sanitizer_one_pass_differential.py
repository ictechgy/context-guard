"""S004 (F-14) differential oracle for the one-pass sanitizer scanner.

The candidate sanitizer must stay byte-identical to the frozen pre-refactor
implementation across every corpus: visible bytes, per-line state after each
line, redaction and path-redaction counts, and the packaged mirror. The frozen
baseline is committed as a text fixture so the comparison cannot drift with the
working tree.

F-5 behaviour changes are deliberately out of scope for this story, so a
difference here is a regression, never an intended improvement.
"""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = ROOT / "context-guard-kit" / "sanitize_output.py"
PACKAGED = ROOT / "plugins" / "context-guard" / "bin" / "context-guard-sanitize-output"
CREDENTIAL_POLICY = ROOT / "context-guard-kit" / "credential_policy.py"
BASELINE_SOURCE = ROOT / "tests" / "fixtures" / "s004" / "sanitizer_baseline.py.txt"
GREP_CORPUS = ROOT / "tests" / "fixtures" / "s004" / "grep_corpus.txt"


def _load(path: Path, name: str):
    """Load a sanitizer module beside a copy of the credential policy it needs."""
    tmp = tempfile.mkdtemp(prefix="s004-differential-")
    target = Path(tmp) / "sanitize_output.py"
    shutil.copyfile(path, target)
    shutil.copyfile(CREDENTIAL_POLICY, Path(tmp) / "credential_policy.py")
    spec = importlib.util.spec_from_file_location(name, target)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load sanitizer: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    module._s004_tmpdir = tmp  # type: ignore[attr-defined]
    return module


BASELINE = _load(BASELINE_SOURCE, "s004_sanitizer_baseline")
CANDIDATE_MODULE = _load(CANDIDATE, "s004_sanitizer_candidate")


def project(module, lines: list[str], *, show_paths: bool) -> dict:
    """Run one sanitizer over a corpus and record every observable it owns."""
    sanitizer = module.LineSanitizer(show_paths=show_paths)
    rows = []
    for line in lines:
        text, redacted = sanitizer.sanitize(line)
        rows.append({
            "text": text,
            "redacted": redacted,
            "in_private_key_block": sanitizer.in_private_key_block,
            "multiline_secret_quote": sanitizer.multiline_secret_quote,
            "multiline_secret_expression_depth": sanitizer.multiline_secret_expression_depth,
            "redactions": sanitizer.redactions,
            "path_redactions": sanitizer.path_redactions,
        })
    return {
        "rows": rows,
        "redactions": sanitizer.redactions,
        "path_redactions": sanitizer.path_redactions,
    }


HEADER_CORPUS = [
    "Authorization: Bearer abcdefghijklmnopqrstuvwxyz\n",
    "  authorization : Bearer token-value\n",
    "Proxy-Authorization: Basic dXNlcjpwYXNz\n",
    "Set-Cookie: session=abcdef; Path=/; HttpOnly\n",
    "Cookie: a=1; b=2\n",
    "src/app.py:12: Authorization: Bearer abcdefghijklmnop\n",
    "src/app.py:12:34: Set-Cookie: session=zzzz\n",
    "+ Authorization: Bearer plus-prefixed\n",
    "- Cookie: minus=prefixed\n",
    "not a header: Authorization is discussed here\n",
]

INLINE_CORPUS = [
    "api_key = 'abcdefghijklmnopqrstuvwx'\n",
    'API_TOKEN="abcdefghijklmnopqrstuvwx"\n',
    "export SECRET_KEY=abcdefghijklmnopqrstuvwx\n",
    "password=hunter2hunter2hunter2\n",
    "config[\"secret\"] = 'abcdefghijklmnopqrstuvwx'\n",
    "os.environ.get('API_KEY', 'fallback-secret-value')\n",
    "settings.set_secret(\"abcdefghijklmnopqrstuvwx\")\n",
    "src/conf.py:9: api_key = 'abcdefghijklmnopqrstuvwx'\n",
    "src/conf.py:9:4: token='abcdefghijklmnopqrstuvwx'\n",
    "+ api_key = 'abcdefghijklmnopqrstuvwx'\n",
    "safe_key = get_public_value()\n",
    "count = 12345\n",
    "url = 'https://example.com/path?api_key=abcdefghijklmnop&x=1'\n",
    "nested = {'outer': {'secret': 'abcdefghijklmnopqrstuvwx'}}\n",
    "quoted_with_escape = 'abc\\\\'def-secret-abcdefghijkl'\n",
]

MULTILINE_CORPUS = [
    "api_key = '''\n",
    "line one of the secret\n",
    "line two of the secret\n",
    "'''\n",
    "after the block = 1\n",
    "-----BEGIN RSA PRIVATE KEY-----\n",
    "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF0qBqk7hUgV7Q2iZ\n",
    "-----END RSA PRIVATE KEY-----\n",
    "after the key = 2\n",
    "secret = (\n",
    "    'part one'\n",
    "    'part two'\n",
    ")\n",
    "after the expression = 3\n",
    "token = \"unterminated multiline\n",
    "still inside\n",
    "\" + tail\n",
]

PATH_CORPUS = [
    "/Users/someone/project/src/app.py:12: message\n",
    "/home/other/deep/nested/dir/file name with spaces.py:3: hit\n",
    "C:\\\\Users\\\\someone\\\\file.py:8: windows-like\n",
    "디렉터리/파일 이름.py:9: unicode path\n",
    "relative/path/file.py:1: relative\n",
    'File "/Users/someone/project/mod.py", line 42, in handler\n',
    "diff --git a/src/app.py b/src/app.py\n",
    "--- a/src/app.py\n",
    "+++ b/src/app.py\n",
    "@@ -1,4 +1,6 @@\n",
    "index 0123abc..4567def 100644\n",
    "Binary files a/x.bin and b/x.bin differ\n",
]

# 스캐너가 :digits: 앞의 임의 텍스트를 삼켜 비밀을 통째로 건너뛴 회귀를 고정한다.
PREFIX_ABSORPTION_CORPUS = [
    "Setting api_key = 'abcdefghijklmnopqrstuvwx' note:12: tail\n",
    "context api_key='abcdefghijklmnopqrstuvwx' src/x.py:3: hit\n",
    "Authorization: Bearer abcdefghijklmnop other:9: end\n",
    "Cookie: s=abcdefghijklmnop later:1: end\n",
    "password=hunter2hunter2hunter2 file.py:4: hit\n",
    "text before -----BEGIN RSA PRIVATE KEY----- mark:7: after\n",
    "quoted 'value with spaces' path/file.py:2: hit\n",
    "no secret here at all path/file.py:2: hit\n",
    "src/app.py:12: api_key='abcdefghijklmnopqrstuvwx'\n",
]

EDGE_CORPUS = [
    "\n",
    "   \n",
    ":\n",
    "::::\n",
    "a:1:\n",
    "\x1b[31mcolored: Authorization: Bearer abcdefghijklmnop\x1b[0m\n",
    "control\x00chars\x07here: token='abcdefghijklmnopqrstuvwx'\n",
    "tab\tseparated: api_key='abcdefghijklmnopqrstuvwx'\n",
    "x" * 500 + ": Authorization: Bearer abcdefghijklmnop\n",
    "no newline at end: api_key='abcdefghijklmnopqrstuvwx'",
]


def generated_corpus() -> list[str]:
    """Filenames, diff prefixes, and colon shapes that stress the location prefix."""
    lines = []
    names = (
        "app.py", "file name with spaces.py", "파일.py", "a-b_c.d.py",
        "deep/nested/path/mod.py", "x" * 60 + ".py",
    )
    payloads = (
        "Authorization: Bearer abcdefghijklmnop",
        "Cookie: s=abcdefghijklmnop",
        "api_key = 'abcdefghijklmnopqrstuvwx'",
        "export TOKEN=abcdefghijklmnopqrstuvwx",
        "plain message with no secret",
    )
    for name in names:
        for payload in payloads:
            for prefix in ("", "+ ", "- ", "  "):
                for location in (f"{name}:1: ", f"{name}:1:2: ", ""):
                    lines.append(f"{prefix}{location}{payload}\n")
    return lines


CORPORA = {
    "header": HEADER_CORPUS,
    "inline": INLINE_CORPUS,
    "multiline": MULTILINE_CORPUS,
    "path": PATH_CORPUS,
    "edge": EDGE_CORPUS,
    "prefix_absorption": PREFIX_ABSORPTION_CORPUS,
    "generated": generated_corpus(),
}


class DifferentialOracleTest(unittest.TestCase):
    def test_baseline_fixture_is_the_pre_refactor_implementation(self) -> None:
        """Pin the fixture by hash and by the absence of post-refactor symbols.

        A weaker guard would still pass if the fixture were regenerated from the
        refactored source, which would silently turn this differential suite into
        a comparison of the candidate against itself.
        """
        raw = BASELINE_SOURCE.read_bytes()
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            "8fb20932aea9219e39fe169e3e58c8ed2e31870f88b9c64c9eae87276a736ef1",
            "frozen baseline fixture changed; it must remain the pre-refactor source",
        )
        source = raw.decode("utf-8")
        self.assertIn("class LineSanitizer", source)
        for post_refactor in (
            "scan_location_prefix",
            "without_location_prefix",
            "LOCATION_PREFIX_FRAGMENT",
            "NO_LOCATION_RE",
        ):
            with self.subTest(symbol=post_refactor):
                self.assertNotIn(post_refactor, source)

    def test_every_corpus_is_byte_identical(self) -> None:
        for name, corpus in sorted(CORPORA.items()):
            for show_paths in (False, True):
                with self.subTest(corpus=name, show_paths=show_paths):
                    expected = project(BASELINE, corpus, show_paths=show_paths)
                    actual = project(CANDIDATE_MODULE, corpus, show_paths=show_paths)
                    self.assertEqual(
                        len(expected["rows"]), len(actual["rows"]),
                        "row count diverged",
                    )
                    for index, (want, got) in enumerate(
                        zip(expected["rows"], actual["rows"])
                    ):
                        self.assertEqual(
                            want, got,
                            f"{name}[{index}] diverged for input "
                            f"{corpus[index]!r}",
                        )
                    self.assertEqual(expected["redactions"], actual["redactions"])
                    self.assertEqual(
                        expected["path_redactions"], actual["path_redactions"],
                    )

    def test_real_grep_corpus_is_byte_identical(self) -> None:
        if not GREP_CORPUS.is_file():
            self.skipTest("grep corpus fixture is unavailable")
        lines = GREP_CORPUS.read_text(encoding="utf-8").splitlines(keepends=True)
        self.assertGreaterEqual(len(lines), 1000)
        for show_paths in (False, True):
            with self.subTest(show_paths=show_paths):
                self.assertEqual(
                    project(BASELINE, lines, show_paths=show_paths),
                    project(CANDIDATE_MODULE, lines, show_paths=show_paths),
                )

    def test_packaged_mirror_matches_the_canonical_source(self) -> None:
        self.assertEqual(CANDIDATE.read_bytes(), PACKAGED.read_bytes())


if __name__ == "__main__":
    unittest.main()
