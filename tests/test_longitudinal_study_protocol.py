from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "longitudinal_study.py"
PROTOCOL = ROOT / "research" / "longitudinal-study" / "v1"


def load_module():
    spec = importlib.util.spec_from_file_location("longitudinal_study", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load longitudinal study module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class LongitudinalStudyProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.study = load_module()
        cls.schedule = json.loads((PROTOCOL / "schedule.json").read_text(encoding="utf-8"))

    def test_closed_schedule_covers_projects_strata_and_factor_isolated_arms(self) -> None:
        self.study.validate_protocol(PROTOCOL)
        units = self.study.closed_units(self.schedule)
        self.assertEqual(len(units), 125)
        self.assertEqual(len({unit["project_id"] for unit in units}), 5)
        self.assertEqual(
            {unit["task_stratum"] for unit in units},
            {"maintenance", "bug", "feature", "security", "refactor"},
        )
        expected_arms = {
            "baseline", "adaptive_only", "symbol_only", "graph_only", "combined"
        }
        for project_id in {unit["project_id"] for unit in units}:
            for task_stratum in {unit["task_stratum"] for unit in units}:
                block = [
                    unit for unit in units
                    if unit["project_id"] == project_id
                    and unit["task_stratum"] == task_stratum
                ]
                self.assertEqual({unit["arm"] for unit in block}, expected_arms)
        self.assertEqual(len({unit["scheduled_unit_id"] for unit in units}), 125)

    def test_observation_schema_rejects_zero_filled_unavailable_metrics(self) -> None:
        observation = self.study.rehearsal_observation(self.study.closed_units(self.schedule)[0])
        self.study.validate_observation(observation, PROTOCOL)
        observation["provider"]["billed_cost"]["availability"] = "unavailable"
        observation["provider"]["billed_cost"]["value"] = 0
        observation["provider"]["billed_cost"]["unavailable_reason"] = "offline_rehearsal"
        with self.assertRaisesRegex(ValueError, "unavailable metric must use null"):
            self.study.validate_observation(observation, PROTOCOL)

    def test_observation_contract_rejects_unknown_nested_and_root_fields(self) -> None:
        baseline = self.study.rehearsal_observation(
            self.study.closed_units(self.schedule)[0]
        )
        for mutate in (
            lambda value: value.__setitem__("debug", "private"),
            lambda value: value["provider"].__setitem__("debug", "private"),
            lambda value: value["provider"]["tokens"].__setitem__(
                "debug", self.study.observed_integer(1)
            ),
        ):
            changed = copy.deepcopy(baseline)
            mutate(changed)
            changed["receipt"]["observation_sha256"] = self.study.observation_identity(changed)
            with self.assertRaisesRegex(ValueError, "observation .* fields"):
                self.study.validate_observation(changed, PROTOCOL)

    def test_failed_observation_preserves_unavailable_counts_without_zero_fill(self) -> None:
        observation = self.study.rehearsal_observation(
            self.study.closed_units(self.schedule)[0]
        )
        observation["outcome"] = "failed"
        observation["quality"] = {
            "outcome": "unavailable",
            "score": self.study.unavailable_integer("failed_unit"),
            "evaluator_receipt_id": None,
        }
        observation["retrievals"]["count"] = self.study.unavailable_integer("failed_unit")
        observation["corrections"]["count"] = self.study.unavailable_integer("failed_unit")
        observation["local"]["elapsed_ms"] = self.study.unavailable_integer("failed_unit")
        observation["receipt"]["observation_sha256"] = self.study.observation_identity(observation)
        self.study.validate_observation(observation, PROTOCOL)

    def test_live_approval_requires_owner_private_regular_file(self) -> None:
        validated = self.study.validate_protocol(PROTOCOL)
        approval = {
            "schema_version": "contextguard.longitudinal-budget-approval/v1",
            "protocol_sha256": validated["protocol_sha256"],
            "maximum_budget_usd": "250.00",
            "provider_calls_approved": True,
        }
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            approval_path = root / "approval.json"
            approval_path.write_text(json.dumps(approval), encoding="utf-8")
            approval_path.chmod(0o644)
            with self.assertRaisesRegex(PermissionError, "owner-private"):
                self.study.validate_live_gate(PROTOCOL, approval_path, "250.00")
            approval_path.chmod(0o600)
            with self.assertRaisesRegex(PermissionError, "no live provider adapter"):
                self.study.validate_live_gate(PROTOCOL, approval_path, "250.00")
            link = root / "approval-link.json"
            link.symlink_to(approval_path)
            with self.assertRaisesRegex(PermissionError, "owner-private"):
                self.study.validate_live_gate(PROTOCOL, link, "250.00")

    def test_provider_free_rehearsal_resumes_with_caps_and_separates_public_data(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "study"
            first = subprocess.run(
                [
                    sys.executable, str(SCRIPT), "rehearse", "--protocol", str(PROTOCOL),
                    "--output", str(output), "--stop-after", "23",
                ],
                cwd=ROOT, text=True, capture_output=True,
            )
            self.assertEqual(first.returncode, 75, first.stderr)
            state = json.loads((output / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["completed_units"], 23)

            resumed = subprocess.run(
                [
                    sys.executable, str(SCRIPT), "resume", "--protocol", str(PROTOCOL),
                    "--output", str(output),
                ],
                cwd=ROOT, text=True, capture_output=True,
            )
            self.assertEqual(resumed.returncode, 0, resumed.stderr)
            state = json.loads((output / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["completed_units"], 125)
            self.assertLessEqual(state["attempted_units"], self.schedule["caps"]["max_units"])
            private_rows = [
                json.loads(line) for line in
                (output / "private" / "observations.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(len(private_rows), 125)
            self.assertEqual(len({row["receipt"]["receipt_id"] for row in private_rows}), 125)
            report = json.loads((output / "public" / "report.json").read_text(encoding="utf-8"))
            self.assertTrue(report["provider_free"])
            self.assertFalse(report["claims"]["provider_savings_allowed"])
            self.assertEqual(report["descriptive_inference"]["cluster_unit"], "project_id")
            self.assertEqual(report["descriptive_inference"]["project_cluster_count"], 5)
            contrasts = report["descriptive_inference"]["paired_project_contrasts"]
            self.assertEqual(len(contrasts), 100)
            provider_rows = [row for row in contrasts if row["metric"] == "provider_billed_cost"]
            self.assertTrue(provider_rows)
            self.assertTrue(all(row["observed_pairs"] == 0 for row in provider_rows))
            self.assertTrue(all(row["unavailable_pairs"] == 5 for row in provider_rows))
            local_rows = [row for row in contrasts if row["metric"] == "local_elapsed_ms"]
            self.assertTrue(all(row["observed_pairs"] == 5 for row in local_rows))
            self.assertTrue(all(row["mean_arm_minus_baseline"] is not None for row in local_rows))
            public_text = json.dumps(report, sort_keys=True)
            self.assertNotIn("private_project_locator", public_text)
            self.assertNotIn("provider_receipt_payload", public_text)

    def test_live_execution_fails_before_provider_without_budget_approval(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            completed = subprocess.run(
                [
                    sys.executable, str(SCRIPT), "live", "--protocol", str(PROTOCOL),
                    "--output", str(Path(raw) / "live"),
                ],
                cwd=ROOT, text=True, capture_output=True,
            )
            self.assertEqual(completed.returncode, 77)
            self.assertIn("explicit budget approval", completed.stderr)
            self.assertFalse((Path(raw) / "live").exists())


if __name__ == "__main__":
    unittest.main()
