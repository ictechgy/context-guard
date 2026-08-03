#!/usr/bin/env python3
"""ReDoS regression + verdict-equivalence tests for sanitize_output.py's
INLINE_UNQUOTED_* secret-assignment regexes.

Background: INLINE_UNQUOTED_CALL_SECRET_ASSIGNMENT_RE's CALL_ARGUMENT_CHUNK
sub-pattern had a classic ``(X+)*`` catastrophic-backtracking shape. On a
195-character line from this repo's own source (a ``keys=(...)`` call
assignment in cost_guard.py, reached by any ``grep``/``git log -p`` over the
tree) it cost ~90s of CPU per line. The fix drops the ``+`` from the first
alternative of CALL_ARGUMENT_CHUNK so each loop iteration consumes exactly one
ordinary character, leaving exactly one way to split the input -- eliminating
the backtracking ambiguity without changing the matching language.

These tests must (a) demonstrate the ReDoS actually existed by reconstructing
the vulnerable pattern and timing it against the real pathological line, (b)
prove the currently-shipped regex is fast on that same line, and (c) prove
verdicts (match / no-match, and redaction outcome) are unchanged across a
battery of representative and adversarial inputs.
"""

from __future__ import annotations

import re
import signal
import sys
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "context-guard-kit"

sys.path.insert(0, str(KIT))
import sanitize_output as so  # noqa: E402  (path must be adjusted first)


# The exact pathological line profiled in .omc/research/sanitize-performance-20260729.md:
# cost_guard.py:2313, a 3-level-nested `keys=(...)` call assigned to a
# token-named variable, reached verbatim by `grep -rn token context-guard-kit/`.
PATHOLOGICAL_LINE = (
    'context-guard-kit/cost_guard.py:2313:    external_tokens = safe_int('
    'first_present_mapping_value(telemetry, shifted, workload, '
    'keys=("external_tokens", "subagent_tokens", "embedding_tokens")), 0)'
)

# Reconstruction of the pre-fix pattern (the `+` on the first alternative is
# the catastrophic-backtracking bug). Used only to prove the bug was real and
# that the shipped fix actually removed it -- this literal is never imported
# from sanitize_output.py, it is inlined here so the test is self-contained
# and keeps failing this way even if someone reverts the source fix by hand.
UNFIXED_CALL_ARGUMENT_CHUNK = (
    r"(?:[^()\"'\n;]+|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|\([^()]*\))*"
)


def _build_call_assignment_re(call_argument_chunk: str) -> re.Pattern[str]:
    return re.compile(
        rf"(?i)(?P<lead>^|[\s;{{\[,])"
        rf"(?P<prefix>(?:(?:[^:\n]+):\d+(?::\d+)?:)?\s*(?:[+-]\s*)?(?:export\s+)?"
        rf"[\"']?(?:{so.SECRET_KEY})[\"']?\s*[:=]\s*)"
        rf"(?P<value>(?![\"']){so.CODE_IDENTIFIER}\({call_argument_chunk}\))"
    )


class _Timeout(Exception):
    pass


def _run_with_budget(call, budget_seconds: float):
    """Run ``call()`` under a SIGALRM budget; return (elapsed|None, result|'TIMEOUT').

    The previously-installed ITIMER_REAL deadline is saved and restored, not
    merely cancelled: unconditionally clearing it would silently disarm an
    outer timeout (a parallel test runner's own watchdog, for example) for the
    remainder of the process.
    """
    if threading.current_thread() is not threading.main_thread():
        raise unittest.SkipTest("SIGALRM budgeting only works on the main thread")

    def _handler(signum, frame):
        raise _Timeout()

    previous_handler = signal.signal(signal.SIGALRM, _handler)
    previous_timer, previous_interval = signal.getitimer(signal.ITIMER_REAL)
    signal.setitimer(signal.ITIMER_REAL, budget_seconds)
    start = time.perf_counter()
    try:
        result = call()
        return time.perf_counter() - start, result
    except _Timeout:
        return None, "TIMEOUT"
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer:
            remaining = max(previous_timer - (time.perf_counter() - start), 0.000001)
            signal.setitimer(signal.ITIMER_REAL, remaining, previous_interval)


def _search_with_budget(regex: re.Pattern[str], text: str, budget_seconds: float):
    """Run regex.search under a SIGALRM budget; return (elapsed|None, match|'TIMEOUT')."""
    return _run_with_budget(lambda: regex.search(text), budget_seconds)


@unittest.skipUnless(hasattr(signal, "SIGALRM"), "SIGALRM-based timing guard requires POSIX")
class RedosRegressionTests(unittest.TestCase):
    """Proves the bug was real, and that the shipped fix eliminates it."""

    def test_unfixed_pattern_times_out_on_pathological_line(self) -> None:
        """The reconstructed pre-fix regex must actually hang -- otherwise this
        regression test would be worthless (a perf test that passes on the
        broken version proves nothing)."""
        unfixed_re = _build_call_assignment_re(UNFIXED_CALL_ARGUMENT_CHUNK)
        elapsed, match = _search_with_budget(unfixed_re, PATHOLOGICAL_LINE, budget_seconds=5.0)
        self.assertEqual(match, "TIMEOUT", "expected the unfixed regex to hang past 5s budget")
        self.assertIsNone(elapsed)

    def test_shipped_regex_completes_well_under_threshold(self) -> None:
        """The regex actually shipped in sanitize_output.py must return fast."""
        elapsed, match = _search_with_budget(
            so.INLINE_UNQUOTED_CALL_SECRET_ASSIGNMENT_RE, PATHOLOGICAL_LINE, budget_seconds=5.0
        )
        self.assertNotEqual(match, "TIMEOUT", "shipped regex must not time out")
        self.assertIsNotNone(elapsed)
        self.assertLess(elapsed, 0.25, f"shipped regex took {elapsed}s, expected sub-second")

    @unittest.skipUnless(
        __import__("os").environ.get("REDOS_SLOW_EQUIVALENCE_CHECK"),
        "Resolving the unfixed regex on the real ~90s pathological line is "
        "expensive; opt in with REDOS_SLOW_EQUIVALENCE_CHECK=1. The same "
        "verdict-preservation property is covered cheaply by "
        "VerdictEquivalenceTests using an equivalent-shape, shorter line.",
    )
    def test_shipped_regex_verdict_matches_unfixed_eventual_verdict(self) -> None:
        """Both the (slow) unfixed pattern and the (fast) fixed pattern must
        agree on the match verdict for the pathological line -- proving the
        de-ambiguation changed backtracking behavior, not the matching
        language. The unfixed side needs a budget in the ~100s range (see
        the 90s measurement in .omc/research/sanitize-performance-20260729.md)."""
        unfixed_re = _build_call_assignment_re(UNFIXED_CALL_ARGUMENT_CHUNK)
        _, unfixed_match = _search_with_budget(unfixed_re, PATHOLOGICAL_LINE, budget_seconds=150.0)
        self.assertNotEqual(unfixed_match, "TIMEOUT", "raise the budget if this still times out")
        _, fixed_match = _search_with_budget(
            so.INLINE_UNQUOTED_CALL_SECRET_ASSIGNMENT_RE, PATHOLOGICAL_LINE, budget_seconds=5.0
        )
        unfixed_bool = unfixed_match is not None
        fixed_bool = fixed_match is not None
        self.assertEqual(unfixed_bool, fixed_bool, "fixed regex must preserve the match/no-match verdict")


class VerdictEquivalenceTests(unittest.TestCase):
    """Compares the shipped (fixed) INLINE_UNQUOTED_CALL_SECRET_ASSIGNMENT_RE
    against the reconstructed unfixed pattern across representative and edge
    cases, to prove the de-ambiguation is verdict-preserving in general (not
    only on the one pathological line)."""

    POSITIVE_AND_NEGATIVE_CASES = [
        ("simple_call", 'token = get_secret()'),
        ("single_arg_call", 'password = fetch_password(user_id)'),
        ("multi_arg_call", 'secret = build(a, b, c)'),
        ("quoted_string_arg", 'api_key = os.getenv("API_KEY")'),
        ("quoted_arg_with_parens_and_comma", 'token = lookup("a(b,c)", realm)'),
        (
            "nested_call_two_levels",
            'password = fetch_password(get_user(uid), realm="prod")',
        ),
        (
            "nested_call_three_levels_unambiguous",
            'token = safe_int(outer(mid(inner(x)), y))',
        ),
        (
            "three_level_keys_tuple",
            'token = safe_int(f(v, keys=("a", "b")))',
        ),
        ("non_secret_name", 'username = fetch_name(user_id)'),
        ("quoted_value_not_a_call", 'token = "static-looking-value"'),
        (
            "escaped_quote_inside_arg",
            'secret = build("a \\"quoted\\" thing", b)',
        ),
        ("unbalanced_paren_in_value", 'token = get_secret(a, b'),
        ("empty_call", 'token = noop()'),
        (
            "call_with_bracketed_literal_arg",
            'password = derive(config["password"], salt)',
        ),
    ]

    def test_fixed_and_unfixed_agree_on_representative_battery(self) -> None:
        unfixed_re = _build_call_assignment_re(UNFIXED_CALL_ARGUMENT_CHUNK)
        for name, line in self.POSITIVE_AND_NEGATIVE_CASES:
            with self.subTest(case=name):
                # The dedicated regression tests above carry the intentionally
                # slow ReDoS witnesses.  This characterization battery must stay
                # cheap so its reference regex does not make CI timing-sensitive.
                _, unfixed_match = _search_with_budget(unfixed_re, line, budget_seconds=1.0)
                self.assertNotEqual(
                    unfixed_match, "TIMEOUT", f"case {name!r} unexpectedly hangs the unfixed regex too"
                )
                fixed_match = so.INLINE_UNQUOTED_CALL_SECRET_ASSIGNMENT_RE.search(line)

                unfixed_span = unfixed_match.span() if unfixed_match else None
                fixed_span = fixed_match.span() if fixed_match else None
                self.assertEqual(
                    unfixed_span,
                    fixed_span,
                    f"case {name!r}: fixed/unfixed spans diverge ({fixed_span} vs {unfixed_span})",
                )
                if fixed_match is not None:
                    self.assertEqual(fixed_match.group(0), unfixed_match.group(0))

    # Exact end-to-end outcome of redact_secret_assignments() for every case:
    # (name, input, expected_output_line, expected_was_redacted).
    #
    # This table is a CHARACTERISATION pin, not an endorsement. Several entries
    # record known partial-redaction behaviour (e.g. 'multi_arg_call' leaves
    # ", b, c)" behind) that is tracked separately and deliberately out of scope
    # for this PR. Pinning the exact strings means any change to WHAT gets
    # redacted -- including a future fix to those defects -- shows up here as a
    # visible, reviewed diff rather than passing silently.
    REDACTION_GOLDEN = [
        ("simple_call", "token = get_secret()", "token = get_secret()", False),
        ("single_arg_call", "password = fetch_password(user_id)", "password = fetch_password(user_id)", False),
        ("multi_arg_call", "secret = build(a, b, c)", "secret = [REDACTED], b, c)", True),
        ("quoted_string_arg", 'api_key = os.getenv("API_KEY")', 'api_key = os.getenv("API_KEY")', False),
        ("quoted_arg_with_parens_and_comma", 'token = lookup("a(b,c)", realm)', "token = [REDACTED]", True),
        (
            "nested_call_two_levels",
            'password = fetch_password(get_user(uid), realm="prod")',
            "password = [REDACTED]",
            True,
        ),
        (
            "nested_call_three_levels_unambiguous",
            "token = safe_int(outer(mid(inner(x)), y))",
            "token = [REDACTED], y))",
            True,
        ),
        (
            "three_level_keys_tuple",
            'token = safe_int(f(v, keys=("a", "b")))',
            "token = [REDACTED]",
            True,
        ),
        ("non_secret_name", "username = fetch_name(user_id)", "username = fetch_name(user_id)", False),
        ("quoted_value_not_a_call", 'token = "static-looking-value"', 'token = "[REDACTED]"', True),
        ("escaped_quote_inside_arg", 'secret = build("a \\"quoted\\" thing", b)', "secret = [REDACTED]", True),
        ("unbalanced_paren_in_value", "token = get_secret(a, b", "token = [REDACTED], b", True),
        ("empty_call", "token = noop()", "token = noop()", False),
        (
            "call_with_bracketed_literal_arg",
            'password = derive(config["password"], salt)',
            "password = [REDACTED]",
            True,
        ),
    ]

    def test_redaction_outcome_matches_for_representative_battery(self) -> None:
        """End-to-end through redact_secret_assignments(), the public entry
        point actually used by LineSanitizer -- not just the isolated regex.

        Asserts the EXACT output line and the EXACT was_redacted flag. The
        previous version of this test only asserted ``if was_redacted:
        assertIn("[REDACTED]", ...)``, which passes unchanged if redaction
        stops happening entirely -- it pinned nothing.
        """
        context = so.SanitizationContext(mode="unknown_text")
        for name, line, expected_line, expected_flag in self.REDACTION_GOLDEN:
            with self.subTest(case=name):
                redacted_line, was_redacted = so.redact_secret_assignments(line, context=context)
                self.assertEqual(was_redacted, expected_flag, f"case {name!r}: was_redacted changed")
                self.assertEqual(redacted_line, expected_line, f"case {name!r}: output line changed")

    def test_redaction_golden_covers_every_battery_case(self) -> None:
        """Guards the guard: if a case is added to POSITIVE_AND_NEGATIVE_CASES
        but not to REDACTION_GOLDEN, the new case would silently have no
        end-to-end outcome pinned at all."""
        battery = {name for name, _ in self.POSITIVE_AND_NEGATIVE_CASES}
        golden = {name for name, _, _, _ in self.REDACTION_GOLDEN}
        self.assertEqual(battery, golden, "REDACTION_GOLDEN and POSITIVE_AND_NEGATIVE_CASES drifted apart")

    def test_at_least_one_case_actually_redacts(self) -> None:
        """A capability check, not a spelling check: if redaction became a
        no-op for every input, the golden table above would need wholesale
        editing -- but this makes the failure unmissable and self-explaining."""
        context = so.SanitizationContext(mode="unknown_text")
        redacted = [
            name
            for name, line, _, _ in self.REDACTION_GOLDEN
            if so.redact_secret_assignments(line, context=context)[1]
        ]
        self.assertGreaterEqual(len(redacted), 8, "call-shaped secret redaction has largely stopped working")


class AdversarialNestedCallBatteryTests(unittest.TestCase):
    """Constructs inputs designed to blow up the *fixed* regex the same way
    the original was blown up, and proves they no longer do."""

    def _adversarial_lines(self) -> list[tuple[str, str]]:
        cases = []
        # Escalating nesting depth with internal commas at every level.
        for depth in range(1, 6):
            inner = "leaf(a, b)"
            for _ in range(depth):
                inner = f"wrap({inner}, extra, key=(\"x\", \"y\"))"
            cases.append((f"depth_{depth}_comma_ambiguous", f"token = {inner}"))

        # Growing comma-separated argument counts at fixed 3-level nesting,
        # mirroring the scaling law measured in the research doc.
        for n_args in range(0, 6):
            extra_args = ", ".join(f"arg{i}" for i in range(n_args))
            sep = ", " if extra_args else ""
            cases.append(
                (
                    f"three_level_{n_args}_extra_args",
                    f'token = safe_int(first_present_mapping_value(telemetry, shifted, workload{sep}{extra_args}, keys=("a", "b", "c")))',
                )
            )

        # Long run of plain characters before a one-level paren, repeated --
        # the exact shape that made A+ ambiguous against D=\([^()]*\).
        cases.append(
            (
                "long_plain_run_before_paren",
                "token = " + "x" * 400 + "(" + "y" * 400 + ")",
            )
        )
        cases.append(
            (
                "many_short_plain_runs_and_parens",
                "token = f(" + "a(b)," * 200 + "z)",
            )
        )
        # Deliberately malformed / never-terminating call forms.
        cases.append(("unterminated_deep_nesting", "token = a(b(c(d(e(f(g(h(i(j("))
        cases.append(("many_unbalanced_parens", "token = f(" * 50))
        return cases

    def test_adversarial_battery_completes_fast(self) -> None:
        for name, line in self._adversarial_lines():
            with self.subTest(case=name):
                elapsed, match = _search_with_budget(
                    so.INLINE_UNQUOTED_CALL_SECRET_ASSIGNMENT_RE, line, budget_seconds=3.0
                )
                self.assertNotEqual(match, "TIMEOUT", f"case {name!r} still hangs the fixed regex")
                self.assertIsNotNone(elapsed)
                self.assertLess(elapsed, 1.0, f"case {name!r} took {elapsed}s, expected sub-second")


# ---------------------------------------------------------------------------
# INLINE_QUOTED_SECRET_ASSIGNMENT_RE (:102) -- a SECOND, strictly worse ReDoS
# found on the same hot path (applied FIRST, at redact_secret_assignments():494)
# and NOT covered by the original version of this file.
#
# Old value body:  (?:\\.|(?!(?P=quote)).)*
#   A backslash starts alternative 1 (`\\.`) AND satisfies alternative 2 (`.`),
#   so a run of n backslashes has Fibonacci-many parses. With no closing quote
#   the engine explores all of them: EXPONENTIAL, not merely quadratic.
#   Measured on this repo before the fix: a 47-character line cost 7.6 seconds
#   -- far worse than the 195-character/90-second CALL_ARGUMENT_CHUNK case.
# ---------------------------------------------------------------------------

UNFIXED_QUOTED_VALUE_BODY = r"(?:\\.|(?!(?P=quote)).)*"


def _build_quoted_assignment_re(value_body: str) -> re.Pattern[str]:
    return re.compile(
        rf"(?i)(?P<lead>^|[\s;{{\[,])"
        rf"(?P<prefix>(?:(?:[^:\n]+):\d+(?::\d+)?:)?\s*(?:[+-]\s*)?(?:export\s+)?"
        rf"[\"']?(?:{so.SECRET_KEY})[\"']?\s*[:=]\s*)"
        rf"(?P<quote>[\"'])(?P<value>{value_body})(?P=quote)(?P<tail>[^\s,;}}\]]*)"
    )


# A short line: 38 backslashes after an unterminated double quote. Under the
# unfixed body this takes multiple seconds; under the shipped body, microseconds.
QUOTED_PATHOLOGICAL_LINE = 'api_key = "' + "\\" * 38


@unittest.skipUnless(hasattr(signal, "SIGALRM"), "SIGALRM-based timing guard requires POSIX")
class QuotedValueRedosRegressionTests(unittest.TestCase):
    def test_unfixed_quoted_body_times_out_on_short_backslash_run(self) -> None:
        """Proves the bug was real: 38 backslashes is enough to hang it."""
        unfixed = _build_quoted_assignment_re(UNFIXED_QUOTED_VALUE_BODY)
        elapsed, match = _search_with_budget(unfixed, QUOTED_PATHOLOGICAL_LINE, budget_seconds=5.0)
        self.assertEqual(match, "TIMEOUT", "expected the unfixed quoted regex to hang past 5s")
        self.assertIsNone(elapsed)

    def test_shipped_quoted_regex_completes_fast(self) -> None:
        """Load-bearing: this fails if QUOTED_VALUE_BODY is reverted."""
        elapsed, match = _search_with_budget(
            so.INLINE_QUOTED_SECRET_ASSIGNMENT_RE, QUOTED_PATHOLOGICAL_LINE, budget_seconds=5.0
        )
        self.assertNotEqual(match, "TIMEOUT", "shipped quoted regex must not time out")
        self.assertLess(elapsed, 0.25, f"shipped quoted regex took {elapsed}s")

    def test_shipped_quoted_regex_scales_linearly_in_backslash_run(self) -> None:
        """The exponential blowup doubled cost roughly every 1.4 extra
        backslashes. Doubling the run length here must not blow up: a
        quantitative check, so a partially-de-ambiguated pattern cannot pass."""
        context = so.SanitizationContext(mode="unknown_text")
        for n in (200, 400, 800, 1600):
            line = 'api_key = "' + "\\" * n
            elapsed, result = _run_with_budget(
                lambda ln=line: so.redact_secret_assignments(ln, context=context), 5.0
            )
            self.assertNotEqual(result, "TIMEOUT", f"backslash run of {n} hangs the shipped regex")
            self.assertLess(elapsed, 1.0, f"backslash run of {n} took {elapsed}s")


class QuotedValueEquivalenceTests(unittest.TestCase):
    """The quoted de-ambiguation must not change WHICH secrets get redacted.

    Excluding backslash from the second alternative would, on its own, drop one
    string class: a value ending in a single unpaired backslash. The trailing
    ``\\?`` in QUOTED_VALUE_BODY restores exactly that class. The
    'trailing_backslash' case below is what makes that term load-bearing --
    remove the ``\\?`` and only that case flips from redacted to NOT redacted,
    i.e. a real credential would leak.
    """

    QUOTED_GOLDEN = [
        ("quoted_double", 'api_key = "FAKE-abc123"', 'api_key = "[REDACTED]"', True),
        ("quoted_single", "password = 'FAKE-pw'", "password = '[REDACTED]'", True),
        ("quoted_with_escaped_quote", 'token = "FAKE\\"esc"', 'token = "[REDACTED]"', True),
        ("quoted_trailing_backslash", 'secret = "trailing-backslash\\"', 'secret = "[REDACTED]"', True),
        ("quoted_no_space", 'aws_secret_access_key="FAKE0000"', 'aws_secret_access_key="[REDACTED]"', True),
        ("quoted_unterminated", 'api_key = "FAKE-unterminated', 'api_key = "FAKE-unterminated', False),
        ("quoted_empty", 'token = ""', 'token = "[REDACTED]"', True),
        ("quoted_windows_path", 'token = "C:\\\\Users\\\\fake\\\\creds.txt"', 'token = "[REDACTED]"', True),
    ]

    def test_quoted_redaction_outcomes_are_pinned(self) -> None:
        context = so.SanitizationContext(mode="unknown_text")
        for name, line, expected_line, expected_flag in self.QUOTED_GOLDEN:
            with self.subTest(case=name):
                out, was = so.redact_secret_assignments(line, context=context)
                self.assertEqual(was, expected_flag, f"case {name!r}: was_redacted changed")
                self.assertEqual(out, expected_line, f"case {name!r}: output changed")

    def test_shipped_and_unfixed_quoted_regexes_agree(self) -> None:
        """Differential: span AND every named group, since unquoted/quoted
        replacements are rebuilt from lead/prefix/quote/value."""
        unfixed = _build_quoted_assignment_re(UNFIXED_QUOTED_VALUE_BODY)
        for name, line, _expected, _flag in self.QUOTED_GOLDEN:
            with self.subTest(case=name):
                _, old = _search_with_budget(unfixed, line, budget_seconds=10.0)
                self.assertNotEqual(old, "TIMEOUT", f"case {name!r} hangs the unfixed regex")
                new = so.INLINE_QUOTED_SECRET_ASSIGNMENT_RE.search(line)
                if old is None or new is None:
                    self.assertIs(old, new, f"case {name!r}: match/no-match verdict diverged")
                    continue
                self.assertEqual(old.span(), new.span(), f"case {name!r}: span diverged")
                for group in ("lead", "prefix", "quote", "value", "tail"):
                    self.assertEqual(
                        old.group(group), new.group(group), f"case {name!r}: group {group!r} diverged"
                    )

    def test_trailing_backslash_term_is_load_bearing(self) -> None:
        """Guards the guard: without the trailing ``\\?`` the naive
        de-ambiguation silently stops redacting a value that ends in a lone
        backslash. Proves this test file would catch that regression."""
        naive = _build_quoted_assignment_re(r"(?:\\.|(?!(?P=quote))[^\\])*")
        line = 'secret = "trailing-backslash\\"'
        self.assertIsNone(naive.search(line), "expected the naive body to MISS this value")
        self.assertIsNotNone(
            so.INLINE_QUOTED_SECRET_ASSIGNMENT_RE.search(line),
            "shipped body must still redact a value ending in a lone backslash",
        )


class SurvivingMutantClosureTests(unittest.TestCase):
    """Closes mutants that survived a mutation sweep of sanitize_output.py.

    A mutation sweep over both synced copies (mutating only one trips
    test_owned_consumer_pairs_are_byte_identical and yields a false KILL for
    every mutant) left four survivors. One -- making CALL_ARGUMENT_CHUNK's
    outer star lazy -- was PROVEN EQUIVALENT by exhaustive differential testing
    (299,593 inputs, zero divergence: ``)`` cannot be consumed by any
    alternative, so lazy and greedy must stop at the same position). The other
    three were real coverage holes and are pinned below.
    """

    def setUp(self) -> None:
        self.context = so.SanitizationContext(mode="unknown_text")

    def _assert(self, line: str, expected_line: str, expected_flag: bool) -> None:
        out, was = so.redact_secret_assignments(line, context=self.context)
        self.assertEqual(was, expected_flag, f"{line!r}: was_redacted changed")
        self.assertEqual(out, expected_line, f"{line!r}: output changed")

    # --- closes M8: disabling INLINE_UNQUOTED_FALLBACK_SECRET_ASSIGNMENT_RE ---
    # Nothing in the suite exercised the `or`/`||`/`??`/ternary/`else` fallback
    # shape, so deleting that entire substitution left every test green while
    # `token = cfg.token or "<secret>"` leaked verbatim.
    FALLBACK_CASES = [
        ("fallback_or", 'token = cfg.token or "FAKE-fallback"', "token = [REDACTED]", True),
        ("fallback_logical_or", 'password = opts.password || "FAKE-pw"', "password = [REDACTED]", True),
        ("fallback_nullish", 'api_key = env.api_key ?? "FAKE-key"', "api_key = [REDACTED]", True),
        ("fallback_ternary", "token = flag ? primary : session_token", "token = [REDACTED]", True),
        ("fallback_else", "secret = a if b else client_secret", "secret = [REDACTED]", True),
    ]

    def test_fallback_shaped_secrets_are_redacted(self) -> None:
        for name, line, expected, flag in self.FALLBACK_CASES:
            with self.subTest(case=name):
                self._assert(line, expected, flag)

    # --- closes M2: CALL_ARGUMENT_CHUNK alt1 must EXCLUDE quote characters ---
    # If alt1 were [^()\n;] instead of [^()\"'\n;], a quote would be eaten as an
    # ordinary character rather than opening the quoted-string branch, and the
    # redacted span would end one or more characters early -- leaving residue
    # of the very value being redacted.
    QUOTE_EXCLUSION_CASES = [
        ("unterminated_dquote_then_text", 'token = f(")a', "token = [REDACTED]", True),
        ("unterminated_squote_then_paren", "token = f(')(", "token = [REDACTED]", True),
        ("unterminated_dquote_then_paren", 'token = f("))', "token = [REDACTED]", True),
        ("unterminated_dquote_with_comma", 'password = build(")x, y', "password = [REDACTED], y", True),
    ]

    def test_call_chunk_quote_exclusion_is_load_bearing(self) -> None:
        for name, line, expected, flag in self.QUOTE_EXCLUSION_CASES:
            with self.subTest(case=name):
                self._assert(line, expected, flag)

    def test_quote_including_chunk_variant_would_leave_residue(self) -> None:
        """Guards the guard: proves the cases above actually discriminate.

        The discrimination is at PIPELINE level, not at the CALL regex alone.
        On ``token = f(")a`` the shipped CALL regex does not match at all (no
        closing paren), so BRACKETED/PLAIN redact the whole tail. The
        quote-including variant *does* match -- its chunk consumes the ``"`` as
        an ordinary character so the ``)`` satisfies the required closing paren
        -- and it redacts only ``f(")``, leaving the trailing ``a`` behind.
        """
        variant_chunk = r"(?:[^()\n;]|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|\([^()]*\))*"
        variant = _build_call_assignment_re(variant_chunk)
        line = 'token = f(")a'

        shipped_out = so.redact_secret_assignments(line, context=self.context)

        # F-14 이후 파이프라인은 location fragment 를 제거한 쌍둥이를 쓴다. 주입 지점도
        # 그쪽으로 옮겨야 이 테스트가 계속 실제 동작을 고정한다.
        twin_name = "INLINE_UNQUOTED_CALL_SECRET_ASSIGNMENT_NO_LOCATION_RE"
        saved = getattr(so, twin_name)
        setattr(so, twin_name, so.without_location_prefix(variant))
        try:
            variant_out = so.redact_secret_assignments(line, context=self.context)
        finally:
            setattr(so, twin_name, saved)

        self.assertEqual(shipped_out, ("token = [REDACTED]", True))
        self.assertEqual(
            variant_out,
            ("token = [REDACTED]a", True),
            "quote-including variant must leave residue, otherwise this test pins nothing",
        )
        self.assertNotEqual(shipped_out, variant_out)

    # --- closes M16: the closing-quote lookahead in QUOTED_VALUE_BODY ---
    # Without (?!(?P=quote)) the value body swallows the closing quote and runs
    # to the LAST quote on the line, over-redacting unrelated content.
    QUOTE_TERMINATION_CASES = [
        ("second_quoted_literal_survives", 'token = "a" + b + "c"', 'token = "[REDACTED]" + b + "c"', True),
        ("following_pair_survives", 'api_key = "k1", other = "k2"', 'api_key = "[REDACTED]", other = "k2"', True),
        ("statement_tail_survives", 'secret = "a"; print("b")', 'secret = "[REDACTED]"; print("b")', True),
        ("comment_tail_survives", 'password = "p" # comment "q"', 'password = "[REDACTED]" # comment "q"', True),
    ]

    def test_quoted_value_stops_at_its_own_closing_quote(self) -> None:
        for name, line, expected, flag in self.QUOTE_TERMINATION_CASES:
            with self.subTest(case=name):
                self._assert(line, expected, flag)

    def test_dropping_closing_quote_lookahead_would_over_redact(self) -> None:
        """Guards the guard: proves the cases above actually discriminate."""
        permissive = _build_quoted_assignment_re(r"(?:\\.|[^\\])*\\?")
        line = 'token = "a" + b + "c"'
        self.assertEqual(so.INLINE_QUOTED_SECRET_ASSIGNMENT_RE.search(line).group("value"), "a")
        self.assertEqual(
            permissive.search(line).group("value"),
            'a" + b + "c',
            "permissive variant must over-run, otherwise this test pins nothing",
        )


if __name__ == "__main__":
    unittest.main()
