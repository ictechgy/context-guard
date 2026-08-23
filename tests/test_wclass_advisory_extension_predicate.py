"""Focused acceptance test for the reviewed exact-name extension registry.

Context: `context-guard-kit/rewrite_bash_for_token_budget.py`'s Bash route
table (`command_search_diff`) is a closed, deny-by-default allowlist. Commit
53f09fb added a one-off `wclass-advisory` branch that only checks
`argv[1] in {"run", "review"}` and never constrains anything after it, so
`wclass-advisory run --bogus-flag whatever extra positional` is wrongly
routed as `noop` today. An independent design review (advisory design
campaign, codex) recommended replacing ad-hoc per-tool branches with a
reviewed, exact-name-only extension registry whose entries hold a
command-specific predicate that validates the *complete* argv shape before
granting a route - not just the first token after the executable name.

This test is the prospective, task-specific oracle for that change. It must
fail today (no registry exists yet, and the current predicate is
over-permissive) and pass only once a `wclass-advisory` entry validates the
full documented `run`/`review` grammar.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
KIT_ROOT = REPO_ROOT / "context-guard-kit"
if str(KIT_ROOT) not in sys.path:
    sys.path.insert(0, str(KIT_ROOT))

import rewrite_bash_for_token_budget as rewrite_bash  # noqa: E402


def route(*argv: str) -> str:
    return rewrite_bash.command_search_diff(argv, role="standalone")


class ExactNameExtensionRegistryShapeTests(unittest.TestCase):
    """The registry itself must exist and stay exact-name-only (no globs)."""

    def test_registry_exists_as_a_mapping(self) -> None:
        registry = getattr(rewrite_bash, "CGW_EXACT_NAME_EXTENSIONS", None)
        self.assertIsInstance(
            registry,
            dict,
            "expected a CGW_EXACT_NAME_EXTENSIONS registry mapping exact "
            "executable basenames to argv predicates",
        )

    def test_registry_contains_wclass_advisory(self) -> None:
        registry = getattr(rewrite_bash, "CGW_EXACT_NAME_EXTENSIONS", {})
        self.assertIn("wclass-advisory", registry)
        self.assertTrue(callable(registry["wclass-advisory"]))

    def test_registry_keys_are_literal_names_no_wildcards(self) -> None:
        registry = getattr(rewrite_bash, "CGW_EXACT_NAME_EXTENSIONS", {})
        self.assertTrue(registry, "registry must not be empty for this test to mean anything")
        for name in registry:
            for forbidden in ("*", "?", "[", "]", "%"):
                self.assertNotIn(
                    forbidden,
                    name,
                    f"registry key {name!r} looks like a glob/prefix pattern, "
                    "not an exact literal name (R-12 TERM*/TERMINFO lesson)",
                )


class WclassAdvisoryFullArgvPredicateTests(unittest.TestCase):
    """The predicate must validate the *whole* argv shape, not just argv[1]."""

    def test_bare_wclass_advisory_denied(self) -> None:
        self.assertEqual(route("wclass-advisory"), "deny")

    def test_unknown_subcommand_denied(self) -> None:
        self.assertEqual(route("wclass-advisory", "prune"), "deny")
        self.assertEqual(route("wclass-advisory", "report"), "deny")

    def test_bare_review_form_passes(self) -> None:
        self.assertEqual(route("wclass-advisory", "review"), "noop")

    def test_review_with_any_extra_token_denied(self) -> None:
        self.assertEqual(route("wclass-advisory", "review", "--workflow", "design"), "deny")
        self.assertEqual(route("wclass-advisory", "review", "extra"), "deny")

    def test_documented_run_form_passes(self) -> None:
        self.assertEqual(
            route(
                "wclass-advisory",
                "run",
                "--workflow",
                "design",
                "--repo",
                "/tmp/repo",
                "--task-file",
                "/tmp/task.txt",
                "--vendor",
                "both",
                "--confirm-task-egress",
            ),
            "noop",
        )

    def test_run_without_confirm_task_egress_denied(self) -> None:
        self.assertEqual(
            route("wclass-advisory", "run", "--repo", "/tmp/repo", "--task-file", "/tmp/t.txt"),
            "deny",
        )

    def test_run_with_unrecognized_flag_denied(self) -> None:
        # This is the concrete gap the ad-hoc argv[1]-only check left open:
        # any trailing flag/positional was accepted unconditionally.
        self.assertEqual(
            route("wclass-advisory", "run", "--bogus-flag", "whatever", "--confirm-task-egress"),
            "deny",
        )

    def test_run_with_extra_positional_argument_denied(self) -> None:
        self.assertEqual(
            route("wclass-advisory", "run", "--confirm-task-egress", "extra-positional"),
            "deny",
        )

    def test_run_with_value_flag_missing_its_value_denied(self) -> None:
        self.assertEqual(
            route("wclass-advisory", "run", "--repo", "--confirm-task-egress"),
            "deny",
        )

    def test_run_with_unknown_vendor_value_still_passes_shape_check(self) -> None:
        # The route predicate validates argv *shape* (flag/value pairing),
        # not domain-specific enum membership - the CLI itself validates
        # --vendor's value. Shape validation only requires a value to be
        # present, so an unrecognized-but-present value must not be denied
        # here (denying it would duplicate business logic in the gate).
        self.assertEqual(
            route(
                "wclass-advisory",
                "run",
                "--vendor",
                "anything",
                "--confirm-task-egress",
            ),
            "noop",
        )


class WclassAdvisoryFilterAndFirstRoleTests(unittest.TestCase):
    """Extension routes must obey the same role rules as every other route."""

    def test_wclass_advisory_denied_as_pipeline_filter(self) -> None:
        self.assertEqual(
            rewrite_bash.command_search_diff(
                ("wclass-advisory", "review"), role="filter"
            ),
            "deny",
        )


if __name__ == "__main__":
    unittest.main()
