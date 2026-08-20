from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "research/provider-live-roadmap/p3-api/v4/behavioral_quality.py"
SCHEMA = ROOT / "research/provider-live-roadmap/p3-api/v4/behavioral-quality.schema.json"
RUNNER = ROOT / "research/provider-live-roadmap/p3-api/v4/live_runner.py"


def load_module():
    spec = importlib.util.spec_from_file_location("p3_behavioral_quality_v4", MODULE)
    if spec is None or spec.loader is None:
        raise AssertionError("behavioral quality evaluator unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_runner():
    spec = importlib.util.spec_from_file_location("p3_behavioral_runner_v4", RUNNER)
    if spec is None or spec.loader is None:
        raise AssertionError("v4 runner unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


class BehavioralQualityV4Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.quality = load_module()

    def setUp(self) -> None:
        hidden_payload = {"exit_code": 0, "passed": True, "test_count": 7}
        build_payload = {"exit_code": 0, "passed": True, "test_count": 0}
        typecheck_payload = {"exit_code": 0, "passed": True, "test_count": 0}
        test_payload = {"exit_code": 0, "passed": True, "test_count": 31}
        self.contract = {
            "schema_version": "contextguard.behavioral-quality-contract/v1",
            "task_id": "task-1",
            "allowed_paths": ["src/parser.py", "tests/test_parser.py"],
            "required_evidence": [
                {"id": "hidden-1", "kind": "hidden_check", "check_sha256": "1" * 64},
                {"id": "build-1", "kind": "build", "check_sha256": "2" * 64},
                {"id": "types-1", "kind": "typecheck", "check_sha256": "3" * 64},
                {"id": "tests-1", "kind": "test", "check_sha256": "4" * 64},
            ],
            "limits": {
                "max_added_lines": 80,
                "max_changed_paths": 2,
                "max_corrections": 1,
                "max_deleted_lines": 40,
                "max_patch_bytes": 8192,
            },
        }
        self.contract_sha256 = digest(self.contract)
        self.evidence = {
            "schema_version": "contextguard.behavioral-quality-evidence/v1",
            "task_id": "task-1",
            "observations": [
                {"id": "hidden-1", "kind": "hidden_check", "check_sha256": "1" * 64, "payload": hidden_payload},
                {"id": "build-1", "kind": "build", "check_sha256": "2" * 64, "payload": build_payload},
                {"id": "types-1", "kind": "typecheck", "check_sha256": "3" * 64, "payload": typecheck_payload},
                {"id": "tests-1", "kind": "test", "check_sha256": "4" * 64, "payload": test_payload},
            ],
            "changed_paths": ["src/parser.py", "tests/test_parser.py"],
            "correction_count": 1,
            "correction_receipts": ["c" * 64],
            "patch": {
                "added_lines": 24,
                "bytes": 2048,
                "deleted_lines": 7,
                "historical_patch_sha256": "a" * 64,
                "sha256": "b" * 64,
            },
        }

    def evaluate(self, contract=None, evidence=None, expected=None):
        return self.quality.evaluate(
            self.contract if contract is None else contract,
            self.evidence if evidence is None else evidence,
            expected_contract_sha256=self.contract_sha256 if expected is None else expected,
            expected_evidence_sha256=digest(self.evidence if evidence is None else evidence),
        )

    def test_behavioral_success_does_not_require_historical_patch_identity(self) -> None:
        result = self.evaluate()
        self.assertTrue(result["passed"])
        self.assertFalse(result["diagnostics"]["exact_historical_patch_match"])
        self.assertEqual(result["primary_contract"], "behavioral")
        self.assertEqual(result["contract_sha256"], self.contract_sha256)
        self.assertEqual(result["evidence_sha256"], digest(self.evidence))
        self.assertNotIn("hidden-1", canonical(result).decode())

    def test_closed_versioned_schema_rejects_unknown_fields(self) -> None:
        schema = json.loads(SCHEMA.read_bytes())
        self.assertEqual(schema["$id"], "https://contextguard.dev/schemas/behavioral-quality-v1.json")
        self.assertFalse(schema["additionalProperties"])
        changed = copy.deepcopy(self.evidence)
        changed["forged"] = True
        with self.assertRaisesRegex(self.quality.QualityError, "evidence fields"):
            self.evaluate(evidence=changed)

    def test_forged_checker_result_is_rejected(self) -> None:
        changed = copy.deepcopy(self.evidence)
        changed["observations"][0]["payload"]["passed"] = False
        with self.assertRaisesRegex(self.quality.QualityError, "evidence identity mismatch"):
            self.quality.evaluate(
                self.contract,
                changed,
                expected_contract_sha256=self.contract_sha256,
                expected_evidence_sha256=digest(self.evidence),
            )

    def test_authenticated_inconsistent_checker_result_is_rejected(self) -> None:
        changed = copy.deepcopy(self.evidence)
        changed["observations"][0]["payload"]["passed"] = False
        with self.assertRaisesRegex(self.quality.QualityError, "forged checker result"):
            self.evaluate(evidence=changed)

    def test_path_escape_is_rejected(self) -> None:
        changed = copy.deepcopy(self.evidence)
        changed["changed_paths"] = ["../secret.txt"]
        with self.assertRaisesRegex(self.quality.QualityError, "unsafe path"):
            self.evaluate(evidence=changed)

    def test_missing_evidence_is_rejected(self) -> None:
        changed = copy.deepcopy(self.evidence)
        changed["observations"].pop()
        with self.assertRaisesRegex(self.quality.QualityError, "evidence set mismatch"):
            self.evaluate(evidence=changed)

    def test_count_mismatch_is_rejected(self) -> None:
        changed = copy.deepcopy(self.evidence)
        changed["correction_count"] = 0
        with self.assertRaisesRegex(self.quality.QualityError, "correction count mismatch"):
            self.evaluate(evidence=changed)

    def test_synchronized_rehash_cannot_replace_the_frozen_contract(self) -> None:
        changed_contract = copy.deepcopy(self.contract)
        changed_evidence = copy.deepcopy(self.evidence)
        changed_evidence["observations"][0]["payload"]["passed"] = False
        changed_contract["required_evidence"][0]["check_sha256"] = "a" * 64
        changed_evidence["observations"][0]["check_sha256"] = "a" * 64
        with self.assertRaisesRegex(self.quality.QualityError, "contract identity"):
            self.evaluate(contract=changed_contract, evidence=changed_evidence)

    def test_failed_required_command_and_locality_limit_fail_quality(self) -> None:
        for mutate in (
            lambda value: value["observations"][3]["payload"].update({"passed": False, "exit_code": 1}),
            lambda value: value["patch"].update({"added_lines": 81}),
            lambda value: value.update({"correction_count": 2, "correction_receipts": ["c" * 64, "d" * 64]}),
        ):
            with self.subTest(mutate=mutate):
                changed_evidence = copy.deepcopy(self.evidence)
                changed_contract = copy.deepcopy(self.contract)
                mutate(changed_evidence)
                result = self.quality.evaluate(
                    changed_contract,
                    changed_evidence,
                    expected_contract_sha256=digest(changed_contract),
                    expected_evidence_sha256=digest(changed_evidence),
                )
                self.assertFalse(result["passed"])

    def test_private_v4_scorer_accepts_semantic_alternate_patch(self) -> None:
        runner = load_runner()
        alternate = b"diff --git a/src/a.py b/src/a.py\n--- a/src/a.py\n+++ b/src/a.py\n@@ -1 +1 @@\n-old\n+new\n"
        historical = alternate.replace(b"new", b"historical")

        class FakeEvaluator:
            def validate_report(self, *args, **kwargs): pass
            def load_scorer_contract(self, *args, **kwargs):
                return {"task-1": {"assertions": []}}, {"sha256": runner.EXPECTED_SCORER_SHA256}
            def preflight_sources(self, *args, **kwargs):
                return {"task-1": {"inventory": [], "repo": Path("/unused"), "task": {
                    "allowed_patch_paths": ["src/a.py"], "parent_commit": "a" * 40,
                    "historical_commit": "b" * 40,
                }}}, {}
            def parse_object(self, *args, **kwargs): return {}
            def validate_patch_envelope(self, raw, allowed): return ["src/a.py"]
            def selected_patch(self, *args, **kwargs): return historical
            def export_snapshot(self, repo, commit, inventory, workspace):
                (workspace / "src").mkdir(parents=True)
                (workspace / "src/a.py").write_bytes(b"semantic-alternate")
            def run_git(self, *args, **kwargs): return b""
            def assertions_pass(self, *args, **kwargs): return True
            def git_blob(self, *args, **kwargs): return b"historical-postimage"
            def safe_path(self, value): return Path(value)

        evaluator = FakeEvaluator()
        contract = {"artifacts": {}}
        with mock.patch.object(runner, "_load_bound_evaluator", return_value=evaluator), \
             mock.patch.object(runner, "_load_pinned_capture", return_value={}), \
             mock.patch.object(runner, "_read_bound", return_value=b"{}"), \
             mock.patch.object(runner, "parse_anthropic_response", return_value={"answer": alternate.decode()}):
            score = runner._bound_scorer_loader(
                contract=contract, repo_root=ROOT, corpus_root=ROOT
            )()
            result = score(
                {"unit-1": {"body": b"{}"}},
                [{"scheduled_unit_id": "unit-1", "task_id": "task-1"}],
            )
        self.assertEqual(result["passed_units"], 1)
        self.assertEqual(result["exact_historical_patch_units"], 0)


if __name__ == "__main__":
    unittest.main()
