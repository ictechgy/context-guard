from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
PREPUBLISH = ROOT / "scripts/prepublish_check.py"


def load_prepublish():
    spec = importlib.util.spec_from_file_location(
        "contextguard_provider_live_ci_discovery_test", PREPUBLISH
    )
    if spec is None or spec.loader is None:
        raise AssertionError("prepublish gate is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProviderLiveCIDiscoveryTests(unittest.TestCase):
    def test_provider_live_gate_collects_required_v4_test_ids(self) -> None:
        prepublish = load_prepublish()
        expected_required = frozenset(
            {
                "test_p3_anthropic_api_v4.P3AnthropicAPIV4Tests.test_authorized_v2_envelopes_execute_each_unit_once",
                "test_p3_anthropic_api_v4.P3AnthropicAPIV4Tests.test_launcher_activation_binds_exact_core_commit_and_blobs",
                "test_p3_anthropic_api_v4.P3AnthropicAPIV4Tests.test_registry_commit_crash_restarts_same_v2_approvals_without_redispatch",
                "test_p3_live_runner_conformance_v4.LiveRunnerConformanceTests.test_ledger_tamper_and_capsule_substitution_fail_closed",
                "test_p3_live_runner_conformance_v4.LiveRunnerConformanceTests.test_recovered_over_cap_ledger_refuses_before_approval_or_dispatch",
                "test_p3_live_runner_conformance_v4.LiveRunnerConformanceTests.test_unknown_receipt_and_timeout_stop_after_one_dispatch",
            }
        )

        collected = prepublish.provider_live_test_ids()

        self.assertEqual(prepublish.PROVIDER_LIVE_REQUIRED_TEST_IDS, expected_required)
        self.assertTrue(prepublish.PROVIDER_LIVE_REQUIRED_TEST_IDS.issubset(collected))
        self.assertTrue(any("test_p3_anthropic_api_v4" in test_id for test_id in collected))
        self.assertTrue(any("test_p3_live_runner_conformance_v4" in test_id for test_id in collected))

    def test_provider_live_gate_rejects_zero_or_missing_required_tests(self) -> None:
        prepublish = load_prepublish()

        with mock.patch.object(
            prepublish, "provider_live_test_ids", return_value=frozenset()
        ):
            with self.assertRaisesRegex(
                SystemExit, "missing required test IDs"
            ):
                prepublish.check_provider_live_test_discovery()

    def test_prepublish_runs_provider_live_tests_as_a_separate_suite(self) -> None:
        """Removing the dedicated provider-live discovery must fail this test."""

        prepublish = load_prepublish()
        completed = SimpleNamespace(returncode=0)
        with mock.patch.object(
            prepublish.subprocess, "run", return_value=completed
        ) as run:
            prepublish.run_tests()

        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(len(commands), 2)
        self.assertEqual(
            commands[1],
            [
                prepublish.sys.executable,
                "-m",
                "unittest",
                "discover",
                "-s",
                "tests/provider-live-roadmap",
                "-p",
                prepublish.PROVIDER_LIVE_TEST_DISCOVERY_PATTERN,
            ],
        )


if __name__ == "__main__":
    unittest.main()
