from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = PACKAGE_ROOT.parents[1]
BOOTSTRAP = PACKAGE_ROOT / "python/context_guard_receipt/bootstrap.py"
PACKAGED_EVALUATOR = PACKAGE_ROOT / "python/context_guard_receipt/phase_evaluation.py"
CANONICAL_EVALUATOR = REPOSITORY_ROOT / "context-guard-kit/phase_evaluation.py"
SCHEMA_ROOT = PACKAGE_ROOT / "schemas"


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")


def p2_record() -> dict[str, object]:
    return {
        "activation_authorized": True,
        "baseline_fallback_verified": True,
        "dependency_gates_passed": True,
        "minimum_recall_basis_points": 9_000,
        "observed_at": 100,
        "phase_id": "p2",
        "records": [
            {
                "candidate_omission": True,
                "construction_cost_microunits": 12,
                "fresh_until": 101,
                "protection": "eligible",
                "recalled": True,
                "record_id": "r1",
                "rehydrated_digest": "sha256:" + "1" * 64,
                "relevant": True,
                "source_digest": "sha256:" + "1" * 64,
                "stratum": "refactor",
            }
        ],
        "schema_version": "contextguard.phase-evaluation.p2/v1",
    }


class G015PhaseEvaluationCliTests(unittest.TestCase):
    def run_cli(self, payload: bytes) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                str(Path(sys.executable).resolve()),
                "-I",
                "-S",
                "-B",
                str(BOOTSTRAP),
                "receipt",
                "evaluate",
                "phase",
                "--input",
                "-",
            ],
            cwd=PACKAGE_ROOT,
            env={"LANG": "C", "PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"},
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_packaged_evaluator_is_the_exact_canonical_provider_free_copy(self) -> None:
        """Break caught: the installed evaluator drifts from its reviewed source."""

        self.assertEqual(PACKAGED_EVALUATOR.read_bytes(), CANONICAL_EVALUATOR.read_bytes())

    def test_phase_schemas_close_every_nested_value_shape(self) -> None:
        """Break caught: a published schema leaves nested evidence unconstrained."""

        def assert_closed(schema: object, location: str) -> None:
            self.assertIsInstance(schema, dict, location)
            document = schema
            if document.get("type") == "object":
                additional = document.get("additionalProperties")
                self.assertTrue(
                    additional is False
                    or (isinstance(additional, dict) and bool(additional)),
                    location,
                )
                properties = document.get("properties")
                required = document.get("required")
                self.assertIsInstance(properties, dict, location)
                self.assertIsInstance(required, list, location)
                self.assertEqual(set(properties), set(required), location)
                if isinstance(additional, dict):
                    assert_closed(additional, f"{location}/additionalProperties")
            for keyword in ("properties", "$defs"):
                children = document.get(keyword, {})
                if isinstance(children, dict):
                    for name, child in children.items():
                        self.assertNotEqual(child, {}, f"{location}/{keyword}/{name}")
                        assert_closed(child, f"{location}/{keyword}/{name}")
            items = document.get("items")
            if items is not None:
                self.assertNotEqual(items, {}, f"{location}/items")
                assert_closed(items, f"{location}/items")
            for keyword in ("allOf", "anyOf", "oneOf"):
                variants = document.get(keyword, [])
                if isinstance(variants, list):
                    for index, variant in enumerate(variants):
                        self.assertNotEqual(variant, {}, f"{location}/{keyword}/{index}")
                        assert_closed(variant, f"{location}/{keyword}/{index}")

        for phase_id in ("p2", "p3", "p4", "p5", "p6"):
            path = SCHEMA_ROOT / f"phase-evaluation-{phase_id}.schema.json"
            assert_closed(json.loads(path.read_text(encoding="utf-8")), path.name)
        result_path = SCHEMA_ROOT / "phase-evaluation-result.schema.json"
        assert_closed(
            json.loads(result_path.read_text(encoding="utf-8")), result_path.name
        )

    def test_cli_evaluates_bounded_canonical_local_record_without_granting_authority(self) -> None:
        """Break caught: the installed grammar cannot expose the closed local evaluator."""

        completed = self.run_cli(canonical_json(p2_record()))

        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["phase_id"], "p2")
        self.assertTrue(result["implementation_readiness"])
        self.assertTrue(result["activation_eligibility"])
        self.assertFalse(result["activation_authority"])
        self.assertFalse(result["claim_authority"])
        self.assertEqual(result["fallback"], "exact_unchanged_baseline")
        self.assertIn("external_activation_authority_required", result["blockers"])
        self.assertEqual(completed.stderr, b"")

    def test_cli_rejects_ambiguous_json_without_reflecting_input(self) -> None:
        """Break caught: duplicate evidence keys reach an evaluator or an error echo."""

        completed = self.run_cli(b'{"phase_id":"p2","phase_id":"private-value"}\n')

        self.assertEqual(completed.returncode, 65)
        self.assertEqual(completed.stdout, b"")
        response = json.loads(completed.stderr)
        self.assertEqual(response["operation"], "evaluate_phase")
        self.assertEqual(response["reason"], "evaluation_input_rejected")
        self.assertNotIn(b"private-value", completed.stderr)


if __name__ == "__main__":
    unittest.main()
