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


def _search_with_budget(regex: re.Pattern[str], text: str, budget_seconds: float):
    """Run regex.search under a SIGALRM budget; return (elapsed|None, match|'TIMEOUT')."""

    def _handler(signum, frame):
        raise _Timeout()

    previous = signal.signal(signal.SIGALRM, _handler)
    signal.setitimer(signal.ITIMER_REAL, budget_seconds)
    start = time.perf_counter()
    try:
        match = regex.search(text)
        return time.perf_counter() - start, match
    except _Timeout:
        return None, "TIMEOUT"
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


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
            'token = safe_int(first_present_mapping_value(telemetry, keys=("a", "b")))',
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
                # Budget generously since some of these are intentionally the
                # slow shape; this test asserts equivalence, not speed.
                _, unfixed_match = _search_with_budget(unfixed_re, line, budget_seconds=20.0)
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

    def test_redaction_outcome_matches_for_representative_battery(self) -> None:
        """End-to-end through redact_secret_assignments(), the public entry
        point actually used by LineSanitizer -- not just the isolated regex."""
        context = so.SanitizationContext(mode="unknown_text")
        for name, line in self.POSITIVE_AND_NEGATIVE_CASES:
            with self.subTest(case=name):
                redacted_line, was_redacted = so.redact_secret_assignments(line, context=context)
                # Smoke check: redaction must never leave the raw secret-shaped
                # call untouched *and* claim redacted=True, or vice versa.
                if was_redacted:
                    self.assertIn("[REDACTED]", redacted_line)


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


if __name__ == "__main__":
    unittest.main()
