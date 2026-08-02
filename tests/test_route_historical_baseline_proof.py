#!/usr/bin/env python3
"""Regression tests for the executable historical route baseline proof."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


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
        self.assertEqual(proof["relaxation_case_count"], 66)
        self.assertEqual(proof["deny_to_allow_case_count"], 63)
        self.assertEqual(proof["baseline_reason_counts"], {"route_policy_denied": 63})
        self.assertEqual(proof["candidate_entrypoints"], ["canonical", "plugin"])

    def test_proof_binds_observations_to_tree_keyed_cache(self) -> None:
        proof = self.run_cli_proof()

        self.assertEqual(
            proof.get("baseline_cache_tree"),
            "3f9ee86abd2b3b79775421529290822eb829a238",
        )
        self.assertEqual(proof.get("baseline_cache_case_count"), 63)
        self.assertEqual(
            proof.get("baseline_cache_sha256"),
            "30d54a8471720d5bbdf4b8ba93476d02fac272f5602509d8b86a059a6a20eb62",
        )

    def write_mutated_cache(self, directory: Path, mutate: Any) -> Path:
        cache = json.loads(
            self.proof_module.BASELINE_CACHE_PATH.read_text(encoding="utf-8")
        )
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

    def test_git_replace_cannot_substitute_pinned_runtime_bytes(self) -> None:
        replacement_source = b'raise RuntimeError("replacement executed")\n'
        with tempfile.TemporaryDirectory(prefix="route-baseline-git-") as temp_dir:
            repo = Path(temp_dir) / "repo"
            clone = subprocess.run(
                ["git", "clone", "--quiet", "--no-checkout", str(ROOT), str(repo)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(clone.returncode, 0, clone.stderr.decode())

            def run_git(*args: str, input_bytes: bytes | None = None) -> bytes:
                proc = subprocess.run(
                    ["git", "-C", str(repo), *args],
                    input=input_bytes,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr.decode())
                return proc.stdout

            replacement_blob = run_git(
                "hash-object",
                "-w",
                "--stdin",
                input_bytes=replacement_source,
            ).decode().strip()
            run_git(
                "replace",
                self.proof_module.BASELINE_RUNTIME_BLOB,
                replacement_blob,
            )
            self.assertEqual(
                run_git(
                    "show",
                    f"{self.proof_module.BASELINE_COMMIT}:"
                    f"{self.proof_module.BASELINE_RUNTIME_PATH}",
                ),
                replacement_source,
            )
            proof = self.proof_module.verify_route_historical_baseline(repo=repo)

            self.assertEqual(proof["status"], "ok")
            self.assertEqual(proof["deny_to_allow_case_count"], 63)

    def test_missing_expected_reason_code_fails_closed(self) -> None:
        suffix = """
import copy as _s008_copy
_s008_original_fix1a_relaxations = fix1a_route_predicate_relaxations
def fix1a_route_predicate_relaxations():
    cases = _s008_copy.deepcopy(_s008_original_fix1a_relaxations())
    cases[0].pop("expected_reason_code")
    return cases
"""
        with tempfile.TemporaryDirectory(prefix="route-baseline-test-") as temp_dir:
            corpus_path = self.write_mutated_corpus(Path(temp_dir), suffix)
            with self.assertRaisesRegex(
                self.proof_module.ProofError,
                "missing required fields.*expected_reason_code",
            ):
                self.proof_module.verify_route_historical_baseline(
                    corpus_path=corpus_path
                )

    def test_empty_candidate_entrypoint_inventory_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            self.proof_module.ProofError,
            "candidate entrypoint inventory is empty",
        ):
            self.proof_module.verify_route_historical_baseline(
                candidate_entrypoints=()
            )

    def test_non_object_classifier_result_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            self.proof_module.ProofError,
            "classifier returned a non-object result",
        ):
            self.proof_module._result_map(["invalid-result"], ("expected-case",))

    def test_classifier_result_case_ids_must_match_requests(self) -> None:
        with self.assertRaisesRegex(
            self.proof_module.ProofError,
            "classifier returned unexpected case ids",
        ):
            self.proof_module._result_map(
                [{"case_id": "wrong-case", "action": "deny", "reason_code": None}],
                ("expected-case",),
            )

    def test_coordinated_candidate_expectation_change_fails_pinned_digest(self) -> None:
        suffix = f"""
import copy as _s008_copy
import sys as _s008_sys
_s008_parent = _s008_sys.modules.get({self.proof_module.__name__!r})
if _s008_parent is not None:
    _s008_parent._assert_candidate_expectations = lambda cases: None
_s008_original_fix1a_relaxations = fix1a_route_predicate_relaxations
def fix1a_route_predicate_relaxations():
    cases = _s008_copy.deepcopy(_s008_original_fix1a_relaxations())
    cases[0]["expected_reason_code"] = "coordinated_mutated_reason"
    return cases
"""
        with tempfile.TemporaryDirectory(prefix="route-baseline-test-") as temp_dir:
            corpus_path = self.write_mutated_corpus(Path(temp_dir), suffix)
            cases = self.proof_module.load_route_relaxation_cases(corpus_path)
            baseline_results = self.proof_module._classify_isolated(
                self.proof_module._resolve_baseline_source(ROOT),
                cases,
            )
            baseline_by_id = {
                result["case_id"]: result for result in baseline_results
            }
            candidate_results = [
                {
                    "case_id": case["case_id"],
                    "action": case["expected_decision"],
                    "reason_code": case["expected_reason_code"],
                }
                for case in cases
                if baseline_by_id[case["case_id"]]["action"] == "deny"
            ]
            with mock.patch.object(
                self.proof_module,
                "_classify_isolated",
                side_effect=[
                    baseline_results,
                    candidate_results,
                    candidate_results,
                ],
            ):
                with self.assertRaisesRegex(
                    self.proof_module.ProofError,
                    "pinned candidate expectation digest mismatch",
                ):
                    self.proof_module.verify_route_historical_baseline(
                        corpus_path=corpus_path
                    )

    def test_cli_main_returns_json_error_for_proof_failure(self) -> None:
        stdout = io.StringIO()
        with (
            mock.patch.object(
                self.proof_module,
                "verify_route_historical_baseline",
                side_effect=self.proof_module.ProofError("tampered baseline"),
            ),
            mock.patch("sys.stdout", stdout),
        ):
            return_code = self.proof_module.main(["--json"])

        self.assertEqual(return_code, 1)
        self.assertEqual(
            json.loads(stdout.getvalue()),
            {"status": "error", "error": "tampered baseline"},
        )

    def test_coordinated_corpus_and_cache_shrink_fails_pinned_inventory(self) -> None:
        cache = json.loads(
            self.proof_module.BASELINE_CACHE_PATH.read_text(encoding="utf-8")
        )
        cached_record = cache["inventory"]["cases"][0]
        case_id = cached_record["case_id"]
        case = next(
            item
            for item in self.proof_module.load_route_relaxation_cases()
            if item["case_id"] == case_id
        )
        reduced_records = [cached_record]
        encoded_records = json.dumps(
            reduced_records,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        cache["inventory"] = {
            "case_count": 1,
            "cases_sha256": hashlib.sha256(encoded_records).hexdigest(),
            "cases": reduced_records,
        }

        with tempfile.TemporaryDirectory(prefix="route-baseline-shrink-") as temp_dir:
            directory = Path(temp_dir)
            corpus_path = directory / "reduced_corpus.py"
            corpus_path.write_text(
                "def reduced_route_predicate_relaxations():\n"
                f"    return {repr([case])}\n",
                encoding="utf-8",
            )
            cache_path = directory / "reduced_cache.json"
            cache_path.write_text(json.dumps(cache), encoding="utf-8")

            with self.assertRaisesRegex(
                self.proof_module.ProofError,
                "pinned deny-to-allow inventory",
            ):
                self.proof_module.verify_route_historical_baseline(
                    corpus_path=corpus_path,
                    cache_path=cache_path,
                )

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
                "pinned deny-to-allow inventory",
            ):
                self.proof_module.verify_route_historical_baseline(
                    corpus_path=corpus_path
                )


if __name__ == "__main__":
    unittest.main()
