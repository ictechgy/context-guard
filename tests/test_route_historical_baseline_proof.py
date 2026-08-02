#!/usr/bin/env python3
"""Regression tests for the executable historical route baseline proof."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PROOF_SCRIPT = ROOT / "scripts" / "verify_route_historical_baseline.py"


class RouteHistoricalBaselineProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        spec = importlib.util.spec_from_file_location(
            "context_guard_route_historical_baseline_proof_test",
            PROOF_SCRIPT,
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("could not load route historical baseline proof")
        cls.proof_module: Any = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.proof_module
        spec.loader.exec_module(cls.proof_module)

    def run_cli_proof(self) -> dict[str, object]:
        proc = subprocess.run(
            [sys.executable, str(PROOF_SCRIPT), "--json"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def test_cli_executes_complete_pinned_deny_to_allow_inventory(self) -> None:
        proof = self.run_cli_proof()
        self.assertEqual(proof["status"], "ok")
        self.assertEqual(
            proof["baseline_commit"],
            "ed46287ee03710d4df6003d52f4eeee60bcd1f4e",
        )
        self.assertEqual(
            proof["baseline_tree"],
            "3f9ee86abd2b3b79775421529290822eb829a238",
        )
        self.assertEqual(
            proof["baseline_runtime_blob"],
            "2439e99c6e7388ad330d6d74b003aeff5df9b90a",
        )
        self.assertEqual(proof["relaxation_case_count"], 60)
        self.assertEqual(proof["deny_to_allow_case_count"], 57)
        self.assertEqual(proof["baseline_reason_counts"], {"route_policy_denied": 57})
        self.assertEqual(proof["candidate_entrypoints"], ["canonical", "plugin"])

    def test_proof_binds_observations_to_tree_keyed_cache(self) -> None:
        proof = self.run_cli_proof()

        self.assertEqual(
            proof.get("baseline_cache_tree"),
            "3f9ee86abd2b3b79775421529290822eb829a238",
        )
        self.assertEqual(proof.get("baseline_cache_case_count"), 57)
        self.assertRegex(str(proof.get("baseline_cache_sha256")), r"^[0-9a-f]{64}$")

    def write_mutated_cache(self, directory: Path, mutate: Any) -> Path:
        cache = json.loads(self.proof_module.BASELINE_CACHE_PATH.read_text())
        mutate(cache)
        path = directory / "mutated-cache.json"
        path.write_text(json.dumps(cache), encoding="utf-8")
        return path

    def write_mutated_corpus(self, directory: Path, suffix: str) -> Path:
        path = directory / "corpus_adversarial_pins.py"
        path.write_text(
            self.proof_module.CORPUS_PATH.read_text(encoding="utf-8") + suffix,
            encoding="utf-8",
        )
        return path

    def test_tampered_baseline_revision_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="route-baseline-test-") as temp_dir:
            cache_path = self.write_mutated_cache(
                Path(temp_dir),
                lambda cache: cache["baseline"].__setitem__(
                    "commit", "8a3fd244d208d5df15284c1c1ab7e34a403f133b"
                ),
            )
            with self.assertRaisesRegex(
                self.proof_module.ProofError,
                "cache baseline commit",
            ):
                self.proof_module.verify_route_historical_baseline(cache_path=cache_path)

    def test_cache_under_wrong_tree_hash_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="route-baseline-test-") as temp_dir:
            cache_path = self.write_mutated_cache(
                Path(temp_dir),
                lambda cache: cache["baseline"].__setitem__("tree", "0" * 40),
            )
            with self.assertRaisesRegex(
                self.proof_module.ProofError,
                "cache baseline tree",
            ):
                self.proof_module.verify_route_historical_baseline(cache_path=cache_path)

    def test_fixture_literal_cannot_substitute_for_executable_observation(self) -> None:
        suffix = """
import copy as _s008_copy
_s008_original_fix1a_relaxations = fix1a_route_predicate_relaxations
def fix1a_route_predicate_relaxations():
    cases = _s008_copy.deepcopy(_s008_original_fix1a_relaxations())
    cases[0]["baseline_reason_code"] = "fixture_substitution"
    return cases
"""
        with tempfile.TemporaryDirectory(prefix="route-baseline-test-") as temp_dir:
            corpus_path = self.write_mutated_corpus(Path(temp_dir), suffix)
            with self.assertRaisesRegex(
                self.proof_module.ProofError,
                "fixture baseline reason",
            ):
                self.proof_module.verify_route_historical_baseline(
                    corpus_path=corpus_path
                )

    def test_deleted_relaxation_case_fails_complete_inventory(self) -> None:
        suffix = """
_s008_original_fix1a_relaxations = fix1a_route_predicate_relaxations
def fix1a_route_predicate_relaxations():
    return _s008_original_fix1a_relaxations()[1:]
"""
        with tempfile.TemporaryDirectory(prefix="route-baseline-test-") as temp_dir:
            corpus_path = self.write_mutated_corpus(Path(temp_dir), suffix)
            with self.assertRaisesRegex(
                self.proof_module.ProofError,
                "cache inventory",
            ):
                self.proof_module.verify_route_historical_baseline(
                    corpus_path=corpus_path
                )


if __name__ == "__main__":
    unittest.main()
