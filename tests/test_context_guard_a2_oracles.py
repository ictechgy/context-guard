#!/usr/bin/env python3
"""Self-checks for the shared A2 byte/env/proof/privacy oracle."""

from __future__ import annotations

import json
from pathlib import Path
import unittest
from urllib.parse import quote

from tests.context_guard_a2_oracles import (
    ENTRYPOINTS,
    ENV_EXAMPLE_BASENAMES,
    FIXTURE_PATH,
    byte_range_cases,
    check_fixture,
    classify_env_path,
    env_path_cases,
    migrate_env_read_denies,
    migration_cases,
    oracle_document,
    privacy_findings,
    privacy_scan_cases,
    proof_budget_env_cases,
    proof_budget_env_oracle,
    proof_race_cases,
    range_proof_oracle,
    render_fixture,
    surface_claim_cases,
    validate_document,
)


class ContextGuardA2OracleTests(unittest.TestCase):
    def test_document_is_deterministic_valid_and_matches_fixture(self):
        first = oracle_document()
        second = oracle_document()
        self.assertEqual(first, second)
        validate_document(first)
        self.assertTrue(check_fixture(), f"stale or missing fixture: {FIXTURE_PATH}")
        self.assertEqual(
            json.loads(FIXTURE_PATH.read_text(encoding="utf-8")),
            first,
        )
        self.assertEqual(render_fixture(), FIXTURE_PATH.read_text(encoding="utf-8"))

    def test_each_matrix_has_canonical_and_packaged_parity(self):
        collections = (
            byte_range_cases(),
            env_path_cases(),
            proof_budget_env_cases(),
            migration_cases(),
            surface_claim_cases(),
            proof_race_cases(),
            privacy_scan_cases(),
        )
        for cases in collections:
            with self.subTest(matrix=cases[0]["case_id"].split("-", 1)[0]):
                counts = {
                    entrypoint: sum(
                        case["entrypoint"] == entrypoint for case in cases
                    )
                    for entrypoint in ENTRYPOINTS
                }
                self.assertEqual(1, len(set(counts.values())), counts)

    def test_raw_byte_oracle_charges_lf_cr_and_eof_exactly(self):
        examples = (
            (b"a\nb", 0, 1, 1, "61"),
            (b"a\r\nb", 0, 1, 2, "610d"),
            (b"a\rb\nc", 0, 1, 3, "610d62"),
            (b"\xff\xfe", 0, 1, 2, "fffe"),
        )
        for payload, offset, limit, expected_bytes, expected_hex in examples:
            with self.subTest(payload=payload):
                result = range_proof_oracle(
                    payload,
                    offset=offset,
                    limit=limit,
                    max_range_bytes=expected_bytes,
                    max_proof_bytes=len(payload),
                )
                self.assertEqual("allow", result["expected_decision"])
                self.assertEqual(expected_bytes, result["expected_range_bytes"])
                self.assertEqual(expected_hex, result["expected_selected_hex"])

    def test_raw_byte_oracle_denies_unproven_and_invalid_ranges(self):
        unproven = range_proof_oracle(
            b"x" * 64 + b"\n",
            offset=0,
            limit=1,
            max_range_bytes=128,
            max_proof_bytes=32,
        )
        self.assertEqual(
            ("deny", "proof_budget_exceeded"),
            (unproven["expected_decision"], unproven["expected_reason"]),
        )
        for offset, limit in ((-1, 1), (0, 0), ("zero", 1), (0, True)):
            with self.subTest(offset=offset, limit=limit):
                invalid = range_proof_oracle(
                    b"x\n",
                    offset=offset,
                    limit=limit,
                    max_range_bytes=8,
                    max_proof_bytes=8,
                )
                self.assertEqual("invalid_range", invalid["expected_reason"])

    def test_decimal_string_ranges_remain_compatible(self):
        result = range_proof_oracle(
            b"first\nsecond\n",
            offset="1",
            limit="+1",
            max_range_bytes=6,
            max_proof_bytes=64,
        )
        self.assertEqual("allow", result["expected_decision"])
        self.assertEqual(6, result["expected_range_bytes"])
        self.assertEqual(b"second".hex(), result["expected_selected_hex"])

    def test_env_classifier_has_only_three_exact_exceptions(self):
        self.assertEqual(
            {".env.example", ".env.sample", ".env.template"},
            set(ENV_EXAMPLE_BASENAMES),
        )
        for basename in ENV_EXAMPLE_BASENAMES:
            self.assertEqual(
                ("allow", "exact_example_exception"),
                classify_env_path(f"nested/{basename}"),
            )
            self.assertEqual(
                ("deny", "symlink_ambiguous"),
                classify_env_path(
                    f"linked/{basename}", symlink_ambiguous=True
                ),
            )
        for basename in (
            ".env",
            ".env.local",
            ".environment",
            ".envrc",
            ".env.example.bak",
            ".ENV",
            ".ENV.EXAMPLE",
        ):
            self.assertEqual(
                ("deny", "protected_env_basename"),
                classify_env_path(basename),
            )

    def test_migration_removes_only_exact_owned_strings_and_preserves_order(self):
        before = [
            "Read(./.env)",
            "Read(./nested/.env)",
            {"rule": "Read(./.env.*)"},
            "Read(./.env.*)",
            "Read(./.env.example)",
        ]
        after, removed = migrate_env_read_denies(
            before, denies_enabled=True, read_guard=True
        )
        self.assertEqual(2, removed)
        self.assertEqual(
            [
                "Read(./nested/.env)",
                {"rule": "Read(./.env.*)"},
                "Read(./.env.example)",
            ],
            after,
        )
        self.assertEqual(
            (before, 0),
            migrate_env_read_denies(
                before, denies_enabled=True, read_guard=False
            ),
        )

    def test_surface_matrix_denies_universal_protection_claims(self):
        rows = surface_claim_cases()
        by_surface = {
            row["surface"]: row
            for row in rows
            if row["entrypoint"] == "canonical"
        }
        self.assertIs(by_surface["Claude Read"]["enforced"], True)
        for surface in ("Claude Glob", "Claude Grep", "Claude Bash/process"):
            self.assertIs(by_surface[surface]["enforced"], False)
        all_forbidden = [
            claim
            for row in by_surface.values()
            for claim in row["forbidden_claims"]
        ]
        self.assertTrue(
            any("universal" in claim for claim in all_forbidden)
        )

    def test_proof_budget_env_precedence_and_clamps_are_exact(self):
        minimum = 64 * 1024
        maximum = 64 * 1024 * 1024
        default = 8 * 1024 * 1024
        self.assertEqual(
            (default, "default"), proof_budget_env_oracle(None, None)
        )
        self.assertEqual(
            (minimum, "canonical_clamped_min"),
            proof_budget_env_oracle("0", str(4 * 1024 * 1024)),
        )
        self.assertEqual(
            (maximum, "canonical_clamped_max"),
            proof_budget_env_oracle(str(maximum + 1), None),
        )
        self.assertEqual(
            (default, "canonical_invalid_default"),
            proof_budget_env_oracle("invalid", str(4 * 1024 * 1024)),
        )
        self.assertEqual(
            (4 * 1024 * 1024, "legacy"),
            proof_budget_env_oracle(None, str(4 * 1024 * 1024)),
        )

    def test_proof_race_matrix_has_one_stable_control_per_entrypoint(self):
        cases = proof_race_cases()
        for entrypoint in ENTRYPOINTS:
            rows = [
                case for case in cases if case["entrypoint"] == entrypoint
            ]
            stable = [
                case
                for case in rows
                if case["expected_reason"] == "stable_proof"
            ]
            self.assertEqual(1, len(stable), entrypoint)
            self.assertTrue(
                all(
                    case["expected_decision"] == "deny"
                    for case in rows
                    if case not in stable
                )
            )

    def test_privacy_detector_rejects_raw_and_url_encoded_fixture_leaks(self):
        for case in privacy_scan_cases():
            forbidden = case["forbidden_fragments"]
            for surface, output in case["safe_outputs"].items():
                self.assertEqual(
                    [],
                    privacy_findings(output, forbidden),
                    f"{case['case_id']}:{surface}",
                )
            for fragment in forbidden:
                with self.subTest(
                    case_id=case["case_id"], fragment=fragment
                ):
                    self.assertTrue(privacy_findings(fragment, forbidden))
                    encoded = quote(fragment, safe="")
                    if encoded != fragment:
                        self.assertTrue(
                            privacy_findings(encoded, forbidden)
                        )

    def test_fixture_contains_only_synthetic_privacy_inputs(self):
        document = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        for case in document["privacy_scan_cases"]:
            self.assertIs(case["synthetic_only"], True)
            self.assertIn("a2", case["source"].lower())

    def test_fixture_path_stays_under_test_contract_directory(self):
        expected_parent = (
            Path(__file__).resolve().parent
            / "fixtures"
            / "context_guard_contracts"
        )
        self.assertEqual(expected_parent, FIXTURE_PATH.parent)


if __name__ == "__main__":
    unittest.main()
