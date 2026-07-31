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

# 동결된 수락 예산. 2배 플랫폼 천장은 절대 예산에만 적용한다. 배가 비율에 곱하면
# 상한이 5.5 가 되어 이차 증가(약 4.0)마저 통과하므로, 비율은 2.75 를 그대로 쓴다.
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


# 서브밀리초 표본에서는 스케줄러 노이즈가 비율을 흔든다. 의미 있는 하한을 넘는
# 표본에서만 비율을 단정하고, 그 아래는 명시적으로 건너뛴다.
RATIO_SAMPLE_FLOOR_SECONDS = 0.005


def sanitize_best_of(line: str, *, repeats: int = 5) -> float:
    """Best-of timing: absorbs scheduler noise without loosening the ratio bound."""
    return max(min(sanitize_once(line) for _ in range(repeats)), 1e-9)


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
                if name in MODULE.ANCHORED_LOCATION_CONSUMERS:
                    # ^ 고정 consumer 는 fragment 를 한 위치에서만 시도하므로 이차 원인이
                    # 아니고, 쌍둥이 없이 원본을 그대로 쓴다.
                    self.assertFalse(
                        hasattr(MODULE, name.replace("_RE", "_NO_LOCATION_RE")),
                        "anchored consumers must not carry a dead twin",
                    )
                    continue
                twin = getattr(MODULE, name.replace("_RE", "_NO_LOCATION_RE"))
                self.assertNotIn(MODULE.LOCATION_PREFIX_FRAGMENT, twin.pattern)

    def test_twins_preserve_the_original_compile_flags(self) -> None:
        """Rebuilding from the pattern text drops argument flags unless passed on."""
        self.assertEqual(
            len(MODULE.UNANCHORED_LOCATION_CONSUMERS)
            + len(MODULE.ANCHORED_LOCATION_CONSUMERS),
            9,
        )
        for name in MODULE.UNANCHORED_LOCATION_CONSUMERS:
            with self.subTest(consumer=name):
                original = getattr(MODULE, name)
                twin = getattr(MODULE, name.replace("_RE", "_NO_LOCATION_RE"))
                self.assertEqual(twin.flags, original.flags)
        flagged = re.compile(MODULE.LOCATION_PREFIX_FRAGMENT + "x", re.IGNORECASE | re.VERBOSE)
        self.assertEqual(
            MODULE.without_location_prefix(flagged).flags, flagged.flags,
        )

    def test_declined_scan_reports_itself_so_callers_use_original_patterns(self) -> None:
        # 스캐너는 사실만 보고한다: 분리는 항상 하고 신호 유무만 표시한다.
        declined = MODULE.scan_location_prefix("src/it's.py:5:Cookie: a=b\n")
        self.assertTrue(declined.declined)
        self.assertEqual(declined.prefix, "src/it's.py:5:")
        accepted = MODULE.scan_location_prefix("src/app.py:5: Cookie: a=b\n")
        self.assertFalse(accepted.declined)
        self.assertEqual(accepted.prefix, "src/app.py:5:")

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
        compared = 0
        previous = None
        # 표본이 5 ms 노이즈 하한을 확실히 넘도록 크기를 잡는다. 작은 크기에서는
        # 모든 비교가 스킵되어 단정이 0 회 실행됐다.
        for count in (16_000, 32_000, 64_000):
            line = "a:1:" * count + "AUTHORIZATION: Bearer abcdefghijklmnop\n"
            elapsed = sanitize_best_of(line)
            if previous is not None and min(previous, elapsed) >= RATIO_SAMPLE_FLOOR_SECONDS:
                ratio = elapsed / previous
                with self.subTest(delimiters=count):
                    self.assertLessEqual(
                        ratio, MAX_DOUBLING_RATIO,
                        f"doubling ratio {ratio:.2f} exceeds the contract",
                    )
                compared += 1
            previous = elapsed
        # 하한 게이트가 모든 비교를 삼켜 단정이 0 회 실행되는 상태를 허용하지 않는다.
        self.assertGreater(compared, 0, "all samples fell below the noise floor")

    def test_location_candidate_runs_stay_within_the_doubling_ratio(self) -> None:
        sanitize_once("warmup src/a.py:1: line\n")
        compared = 0
        previous = None
        for count in (8_000, 16_000, 32_000):
            line = "src/file.py:12:" * count + "token='abcdefghijklmnopqrstuvwx'\n"
            elapsed = sanitize_best_of(line)
            if previous is not None and min(previous, elapsed) >= RATIO_SAMPLE_FLOOR_SECONDS:
                with self.subTest(candidates=count):
                    self.assertLessEqual(elapsed / previous, MAX_DOUBLING_RATIO)
                compared += 1
            previous = elapsed
        self.assertGreater(compared, 0, "all samples fell below the noise floor")

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
        compared = 0
        previous = None
        for size in (10_000, 20_000, 40_000, 80_000, 160_000):
            elapsed = sanitize_best_of(no_colon_line(size))
            if previous is not None and min(previous, elapsed) >= RATIO_SAMPLE_FLOOR_SECONDS:
                with self.subTest(bytes=size):
                    self.assertLessEqual(
                        elapsed / previous, MAX_DOUBLING_RATIO,
                        "quadratic growth yields about 4.0, so the bound must stay "
                        "below that to fail on the regression it names",
                    )
                compared += 1
            previous = elapsed
        self.assertGreater(compared, 0, "all samples fell below the noise floor")


class MutationControlTest(unittest.TestCase):
    """Each mutation must change observable behaviour, so the guard is load-bearing."""

    def sanitize_with(self, module, line: str, *, show_paths: bool = True):
        sanitizer = module.LineSanitizer(show_paths=show_paths)
        return sanitizer.sanitize(line)

    def test_bypassing_any_single_consumer_changes_output(self) -> None:
        # 각 입력은 그 consumer 만이 결정한다는 것을 실측으로 확인한 것이다. 겹치는
        # 입력을 쓰면 다른 consumer 가 덮어써서 뮤테이션이 관측되지 않는다.
        cases = {
            "AUTH_HEADER_RE":
                "proxy-authorization: custom-scheme opaque-value-here\n",
            "COOKIE_HEADER_RE": "Cookie: a=1; b=2\n",
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
