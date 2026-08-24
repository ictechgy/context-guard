"""Focused acceptance for a runner-aware pass/fail summary field in the
structured command digest (`context-guard-kit/trim_command_output.py`,
`--digest json`/`--digest markdown`).

Background: `RunnerFailureSummary` (trim_command_output.py:883-989) already
recognizes pytest/jest/go/cargo FAILURE line shapes, but `build_digest_payload`
only populates `runner_failure_summary` when the run's exit code is nonzero
(trim_command_output.py:1158, `runner_items = runner_summary.as_dict() if rc
!= 0 else {}`). A large SUCCESSFUL run (the common case - e.g. a passing
pytest/cargo test suite) gets no structured benefit at all today: it falls
back to generic representative head/tail line sampling, which for hundreds of
"PASSED"-style lines is still far larger than a one-line summary would be.

This test pins a new, additive digest field: `runner_result_summary`. It is
populated whenever a recognized runner's own final aggregate summary line
(not a per-test line) is found anywhere in the captured output, REGARDLESS OF
EXIT CODE. It must never replace or remove any existing digest field (status,
exit_code, raw_output, representative_head/tail, etc. all stay exactly as
they are today) - this is purely additive, exact-fallback-preserving
behavior, consistent with this project's no-lossy-replace principle.

Recognized formats for this focused acceptance (exactly two runners; other
runners are out of scope for this change):

- pytest's terminal summary line, e.g. `"260 passed in 4.20s"` or
  `"3 failed, 259 passed in 5.01s"` or `"1 failed, 258 passed, 3 skipped in
  5.01s"`. Extract every `"<N> <word>"` count pair from that one line
  (passed/failed/skipped/error/errors/xfailed/xpassed/warnings), normalizing
  `error`/`errors` to a single `errors` key.
- cargo test's terminal summary line, e.g. `"test result: ok. 45 passed; 0
  failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.12s"` or
  `"test result: FAILED. 40 passed; 5 failed; 2 ignored; 0 measured; 3
  filtered out; finished in 0.20s"`. Extract `passed` and `failed` as ints.

Shape of the new field when present:
`{"runner": "pytest"|"cargo_test", "raw_line": "<the exact matched line>",
"passed": int (optional), "failed": int (optional), "skipped": int
(optional), "errors": int (optional), "xfailed": int (optional), "xpassed":
int (optional), "warnings": int (optional)}` - only the count keys actually
present in the matched line are included. When no recognized summary line is
found anywhere in the output, `runner_result_summary` must be entirely
absent from the payload (not `null`, not `{}` - the key itself absent), so
existing digest consumers that don't know about this field see no change.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
KIT_DIR = REPO_ROOT / "context-guard-kit"
PLUGIN_BIN = REPO_ROOT / "plugins" / "context-guard" / "bin"
TRIM_SCRIPTS = [KIT_DIR / "trim_command_output.py", PLUGIN_BIN / "context-guard-trim-output"]


def run_trim_python(script: Path, code: str, *, max_lines: int = 18, extra_args=None) -> subprocess.CompletedProcess[str]:
    args = [sys.executable, str(script), "--max-lines", str(max_lines)]
    if extra_args:
        args.extend(extra_args)
    args.extend(["--", sys.executable, "-c", code])
    return subprocess.run(args, text=True, capture_output=True)


import unittest


class RunnerResultSummaryDigestTests(unittest.TestCase):
    def test_pytest_all_passed_success_run_gets_a_compact_summary(self) -> None:
        code = (
            "import sys; "
            "[print(f'tests/test_a.py::test_{i} PASSED') for i in range(260)]; "
            "print('260 passed in 4.20s')"
        )
        for script in TRIM_SCRIPTS:
            with self.subTest(script=script):
                proc = run_trim_python(
                    script, code, max_lines=18,
                    extra_args=["--digest", "json", "--max-chars", "4000"],
                )
                self.assertEqual(proc.returncode, 0)
                data = json.loads(proc.stdout)
                self.assertEqual(data["status"], "success")
                self.assertIn("runner_result_summary", data)
                summary = data["runner_result_summary"]
                self.assertEqual(summary["runner"], "pytest")
                self.assertEqual(summary["passed"], 260)
                self.assertNotIn("failed", summary)
                self.assertEqual(summary["raw_line"], "260 passed in 4.20s")

    def test_pytest_mixed_result_summary_extracts_every_count(self) -> None:
        code = (
            "import sys; "
            "print('1 failed, 258 passed, 3 skipped in 5.01s'); "
            "sys.exit(1)"
        )
        for script in TRIM_SCRIPTS:
            with self.subTest(script=script):
                proc = run_trim_python(
                    script, code, max_lines=18,
                    extra_args=["--digest", "json", "--max-chars", "4000"],
                )
                self.assertEqual(proc.returncode, 1)
                data = json.loads(proc.stdout)
                summary = data["runner_result_summary"]
                self.assertEqual(summary["runner"], "pytest")
                self.assertEqual(summary["failed"], 1)
                self.assertEqual(summary["passed"], 258)
                self.assertEqual(summary["skipped"], 3)

    def test_cargo_test_all_passed_gets_a_compact_summary(self) -> None:
        code = (
            "print('running 45 tests'); "
            "[print(f'test tests::case_{i} ... ok') for i in range(45)]; "
            "print(); "
            "print('test result: ok. 45 passed; 0 failed; 0 ignored; "
            "0 measured; 0 filtered out; finished in 0.12s')"
        )
        for script in TRIM_SCRIPTS:
            with self.subTest(script=script):
                proc = run_trim_python(
                    script, code, max_lines=18,
                    extra_args=["--digest", "json", "--max-chars", "4000"],
                )
                self.assertEqual(proc.returncode, 0)
                data = json.loads(proc.stdout)
                summary = data["runner_result_summary"]
                self.assertEqual(summary["runner"], "cargo_test")
                self.assertEqual(summary["passed"], 45)
                self.assertEqual(summary["failed"], 0)

    def test_unrecognized_output_omits_the_field_entirely(self) -> None:
        code = "[print(f'noise {i}') for i in range(50)]"
        for script in TRIM_SCRIPTS:
            with self.subTest(script=script):
                proc = run_trim_python(
                    script, code, max_lines=18,
                    extra_args=["--digest", "json", "--max-chars", "2200"],
                )
                self.assertEqual(proc.returncode, 0)
                data = json.loads(proc.stdout)
                self.assertNotIn("runner_result_summary", data)

    def test_markdown_digest_renders_the_summary_line(self) -> None:
        code = "print('260 passed in 4.20s')"
        for script in TRIM_SCRIPTS:
            with self.subTest(script=script):
                proc = run_trim_python(
                    script, code, max_lines=18,
                    extra_args=["--digest", "markdown", "--digest-always", "--max-chars", "2600"],
                )
                self.assertEqual(proc.returncode, 0)
                self.assertIn("runner_result_summary", proc.stdout)
                self.assertIn("pytest", proc.stdout)
                self.assertIn("260", proc.stdout)

    def test_existing_failure_digest_fields_are_unchanged(self) -> None:
        """Regression pin: the new field must not alter any existing digest key."""

        code = (
            "import sys; "
            "[print(f'noise {i}') for i in range(90)]; "
            "print('FAILED tests/test_auth.py::test_expired_token - AssertionError: expired'); "
            "print('FAILED tests/test_auth.py::test_expired_token - AssertionError: expired'); "
            "print('tests/test_auth.py:42: AssertionError: expired'); "
            "sys.exit(7)"
        )
        for script in TRIM_SCRIPTS:
            with self.subTest(script=script):
                proc = run_trim_python(
                    script, code, max_lines=18,
                    extra_args=["--digest", "markdown", "--max-chars", "2600"],
                )
                self.assertEqual(proc.returncode, 7)
                self.assertIn("- status: failure", proc.stdout)
                self.assertIn("- exit_code: 7", proc.stdout)
                self.assertIn("runner_failure_summary", proc.stdout)
                self.assertIn("runner=pytest", proc.stdout)
                self.assertIn("failure_signature", proc.stdout)
                self.assertIn("duplicate_line_groups", proc.stdout)
                self.assertIn("count=2", proc.stdout)


if __name__ == "__main__":
    unittest.main()
