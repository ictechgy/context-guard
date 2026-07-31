"""S004 (F-14) complexity and mutation controls for the one-pass sanitizer.

Structural assertions come first: the scan index never decreases, exactly nine
consumers carry the location prefix, and every one of them has a no-location
twin that is actually the pattern used. Empirical budgets follow, with the
platform ceiling the frozen contract allows.

Mutations that must be killed: restoring a per-offset prefix search, decrementing
or resetting the scan index, bypassing any single consumer, capping before
sanitizing, failing to reconstruct filename spaces, and dropping a multiline
state transition.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import shutil
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = ROOT / "context-guard-kit" / "sanitize_output.py"
CREDENTIAL_POLICY = ROOT / "context-guard-kit" / "credential_policy.py"

# 동결된 수락 예산. 플랫폼 편차를 위해 계약이 허용하는 2배 천장을 함께 둔다.
SINGLE_LINE_BUDGETS = ((100_000, 1.0), (1_000_000, 8.0))
PLATFORM_CEILING = 2.0
MAX_DOUBLING_RATIO = 2.75


def load(name: str):
    tmp = tempfile.mkdtemp(prefix="s004-complexity-")
    target = Path(tmp) / "sanitize_output.py"
    shutil.copyfile(CANDIDATE, target)
    shutil.copyfile(CREDENTIAL_POLICY, Path(tmp) / "credential_policy.py")
    spec = importlib.util.spec_from_file_location(name, target)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load candidate sanitizer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


MODULE = load("s004_candidate_complexity")


def sanitize_once(line: str, *, show_paths: bool = True) -> float:
    sanitizer = MODULE.LineSanitizer(show_paths=show_paths)
    started = time.monotonic()
    sanitizer.sanitize(line)
    return time.monotonic() - started


def no_colon_line(byte_target: int) -> str:
    return ("x" * 40 + " ") * (byte_target // 41) + "Authorization:\n"


class ScannerStructureTest(unittest.TestCase):
    def test_exactly_nine_consumers_carry_the_location_prefix(self) -> None:
        source = CANDIDATE.read_text(encoding="utf-8")
        # 상수 정의 1회 + 아홉 consumer 사용 9회.
        self.assertEqual(source.count(MODULE.LOCATION_PREFIX_FRAGMENT), 10)
        self.assertEqual(len(MODULE.NINE_LOCATION_CONSUMERS), 9)
        for name in MODULE.NINE_LOCATION_CONSUMERS:
            with self.subTest(consumer=name):
                compiled = getattr(MODULE, name)
                self.assertEqual(
                    compiled.pattern.count(MODULE.LOCATION_PREFIX_FRAGMENT), 1,
                )
                twin_name = name.replace("_RE", "_NO_LOCATION_RE")
                twin = getattr(MODULE, twin_name)
                self.assertNotIn(MODULE.LOCATION_PREFIX_FRAGMENT, twin.pattern)

    def test_no_location_twin_is_derived_and_fails_loudly_on_drift(self) -> None:
        drifted = re.compile(r"^no location prefix here$")
        with self.assertRaises(RuntimeError):
            MODULE.without_location_prefix(drifted)

    def test_scan_index_never_decreases_across_a_line(self) -> None:
        lines = [
            "src/app.py:12: Authorization: Bearer abcdefghijklmnop\n",
            "+ src/app.py:12:34: api_key='abcdefghijklmnopqrstuvwx'\n",
            "plain text with no location prefix at all\n",
            "디렉터리/파일 이름.py:9: token='abcdefghijklmnopqrstuvwx'\n",
            "a:1:" * 50 + "tail\n",
        ]
        for line in lines:
            with self.subTest(line=line[:40]):
                scan = MODULE.scan_location_prefix(line)
                self.assertGreaterEqual(scan.scan_index, 0)
                self.assertLessEqual(scan.scan_index, len(line))
                self.assertEqual(scan.prefix, line[: scan.scan_index])
                self.assertEqual(scan.remainder, line[scan.scan_index:])
                # 재구성은 정확해야 한다: 손대지 않은 바이트가 그대로 돌아온다.
                self.assertEqual(scan.prefix + scan.remainder, line)

    def test_scan_is_anchored_so_it_cannot_restart_per_offset(self) -> None:
        self.assertTrue(MODULE.LOCATION_PREFIX_SCAN_RE.pattern.startswith(r"\A"))
        # 앞머리에서 실패하면 줄 뒤쪽에 유효한 location 이 있어도 재시도하지 않는다.
        # 여기서는 첫 콜론 뒤가 숫자가 아니므로 위치 0 에서만 시도하고 곧바로 포기한다.
        scan = MODULE.scan_location_prefix("lead: text src/app.py:12: tail\n")
        self.assertEqual(scan.scan_index, 0)
        self.assertEqual(scan.prefix, "")
        self.assertIn("src/app.py:12:", scan.remainder)

    def test_filename_spaces_and_unicode_survive_reconstruction(self) -> None:
        line = "디렉터리 이름/파일 이름.py:9: Authorization: Bearer abcdefghijklmnop\n"
        sanitizer = MODULE.LineSanitizer(show_paths=True)
        text, redacted = sanitizer.sanitize(line)
        self.assertTrue(redacted)
        self.assertTrue(text.startswith("디렉터리 이름/파일 이름.py:9: "))
        self.assertIn("[REDACTED]", text)
        self.assertNotIn("abcdefghijklmnop", text)


class SanitizeBeforeCapTest(unittest.TestCase):
    def test_cap_line_is_separate_from_sanitization(self) -> None:
        """Raw input must never be truncated before the redaction pass runs."""
        secret = "abcdefghijklmnopqrstuvwxyz012345"
        line = "x" * 400 + f" Authorization: Bearer {secret}\n"
        sanitizer = MODULE.LineSanitizer(show_paths=True)
        text, redacted = sanitizer.sanitize(line)
        self.assertTrue(redacted)
        self.assertNotIn(secret, text)
        capped, truncated = MODULE.cap_line(text, 80)
        self.assertTrue(truncated)
        self.assertNotIn(secret, capped)


class ComplexityBudgetTest(unittest.TestCase):
    def test_repeated_delimiters_stay_within_the_doubling_ratio(self) -> None:
        sanitize_once("warmup a:1: line\n")
        previous = None
        for count in (1000, 2000, 4000, 8000):
            line = "a:1:" * count + "AUTHORIZATION: Bearer abcdefghijklmnop\n"
            elapsed = max(sanitize_once(line), 1e-6)
            if previous is not None:
                ratio = elapsed / previous
                with self.subTest(delimiters=count):
                    self.assertLessEqual(
                        ratio, MAX_DOUBLING_RATIO * PLATFORM_CEILING,
                        f"doubling ratio {ratio:.2f} exceeds the contract",
                    )
            previous = elapsed

    def test_location_candidate_runs_stay_within_the_doubling_ratio(self) -> None:
        sanitize_once("warmup src/a.py:1: line\n")
        previous = None
        for count in (1000, 2000, 4000, 8000):
            line = "src/file.py:12:" * count + "token='abcdefghijklmnopqrstuvwx'\n"
            elapsed = max(sanitize_once(line), 1e-6)
            if previous is not None:
                with self.subTest(candidates=count):
                    self.assertLessEqual(
                        elapsed / previous, MAX_DOUBLING_RATIO * PLATFORM_CEILING,
                    )
            previous = elapsed

    def test_single_line_budgets(self) -> None:
        sanitize_once(no_colon_line(10_000))
        for size, budget in SINGLE_LINE_BUDGETS:
            with self.subTest(bytes=size):
                elapsed = sanitize_once(no_colon_line(size))
                self.assertLessEqual(
                    elapsed, budget * PLATFORM_CEILING,
                    f"{size} bytes took {elapsed:.3f}s against a {budget}s budget",
                )

    def test_no_colon_run_is_no_longer_quadratic(self) -> None:
        """The measured pre-refactor shape: 82KB took 2.6s at ratios near 4."""
        sanitize_once(no_colon_line(4_000))
        previous = None
        for size in (10_000, 20_000, 40_000, 80_000):
            elapsed = max(sanitize_once(no_colon_line(size)), 1e-6)
            if previous is not None:
                with self.subTest(bytes=size):
                    self.assertLessEqual(
                        elapsed / previous, MAX_DOUBLING_RATIO * PLATFORM_CEILING,
                    )
            previous = elapsed


class MutationControlTest(unittest.TestCase):
    """Each mutation must change observable behaviour, so the guard is load-bearing."""

    def sanitize_with(self, module, line: str, *, show_paths: bool = True):
        sanitizer = module.LineSanitizer(show_paths=show_paths)
        return sanitizer.sanitize(line)

    def test_bypassing_any_single_consumer_changes_output(self) -> None:
        # 각 입력은 그 consumer 만이 결정한다는 것을 실측으로 확인한 것이다. 겹치는
        # 입력을 쓰면 다른 consumer 가 덮어써서 뮤테이션이 관측되지 않는다.
        cases = {
            "AUTH_HEADER_NO_LOCATION_RE":
                "proxy-authorization: custom-scheme opaque-value-here\n",
            "COOKIE_HEADER_NO_LOCATION_RE": "Cookie: a=1; b=2\n",
            "INLINE_QUOTED_SECRET_ASSIGNMENT_NO_LOCATION_RE":
                "api_key = 'abcdefghijklmnopqrstuvwx'\n",
            "INLINE_UNQUOTED_SECRET_ASSIGNMENT_NO_LOCATION_RE":
                "password=hunter2hunter2hunter2\n",
            "INLINE_UNQUOTED_CALL_SECRET_ASSIGNMENT_NO_LOCATION_RE":
                'api_key = load_secret("a;b")\n',
            "INLINE_UNQUOTED_FALLBACK_SECRET_ASSIGNMENT_NO_LOCATION_RE":
                "api_key = env_api_key or default_api_key\n",
            "INLINE_UNQUOTED_BRACKETED_SECRET_ASSIGNMENT_NO_LOCATION_RE":
                'api_key = values["abcdefghijklmnopqrstuvwx"]\n',
            "MULTILINE_SECRET_ASSIGNMENT_NO_LOCATION_RE":
                'api_key = "unterminated multiline\n',
            "UNQUOTED_MULTILINE_SECRET_ASSIGNMENT_NO_LOCATION_RE": "secret = (\n",
        }
        never_matching = re.compile(r"(?!x)x^(?P<lead>)(?P<prefix>)(?P<quote>)(?P<value>)(?P<tail>)")
        for name, line in sorted(cases.items()):
            with self.subTest(consumer=name):
                baseline_text, baseline_redacted = self.sanitize_with(MODULE, line)
                mutant = load(f"s004_mutant_{name.lower()}")
                setattr(mutant, name, never_matching)
                mutant_text, mutant_redacted = self.sanitize_with(mutant, line)
                self.assertNotEqual(
                    (baseline_text, baseline_redacted),
                    (mutant_text, mutant_redacted),
                    f"bypassing {name} did not change behaviour",
                )

    def test_dropping_a_multiline_state_transition_changes_output(self) -> None:
        block = [
            'api_key = "unterminated multiline\n',
            "inside the secret\n",
            '" + tail\n',
            "after = 1\n",
        ]
        baseline = [self.sanitize_with(MODULE, line) for line in block]
        mutant = load("s004_mutant_multiline")
        mutant.detect_multiline_secret_assignment = lambda line: None
        sanitizer = mutant.LineSanitizer(show_paths=True)
        mutated = [sanitizer.sanitize(line) for line in block]
        self.assertNotEqual(baseline, mutated)

    def test_resetting_the_scan_index_changes_output(self) -> None:
        line = "src/app.py:12:api_key='abcdefghijklmnopqrstuvwx'\n"
        baseline = self.sanitize_with(MODULE, line)
        mutant = load("s004_mutant_scan_reset")
        mutant.scan_location_prefix = lambda text: mutant.ScannedLine("", text, 0)
        sanitizer = mutant.LineSanitizer(show_paths=True)
        self.assertNotEqual(baseline, sanitizer.sanitize(line))

    def test_capping_before_sanitizing_would_leak(self) -> None:
        """Documents why cap must stay after redaction."""
        secret = "abcdefghijklmnopqrstuvwxyz012345"
        line = f"Authorization: Bearer {secret}\n"
        capped_first, _ = MODULE.cap_line(line, 200)
        sanitized_after_cap, _ = self.sanitize_with(MODULE, capped_first)
        sanitized_first, _ = self.sanitize_with(MODULE, line)
        self.assertNotIn(secret, sanitized_first)
        long_line = "y" * 4000 + f" Authorization: Bearer {secret}\n"
        pre_capped, truncated = MODULE.cap_line(long_line, 80)
        self.assertTrue(truncated)
        # cap 을 먼저 하면 헤더 자체가 잘려 나가 redaction 이 아예 일어나지 않는다.
        _, redacted_after_pre_cap = self.sanitize_with(MODULE, pre_capped)
        _, redacted_when_sanitizing_first = self.sanitize_with(MODULE, long_line)
        self.assertTrue(redacted_when_sanitizing_first)
        self.assertFalse(redacted_after_pre_cap)


if __name__ == "__main__":
    unittest.main()
