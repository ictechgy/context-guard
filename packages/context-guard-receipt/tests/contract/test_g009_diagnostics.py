from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path
from urllib.parse import urljoin


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))

from context_guard_receipt.canonical import framed_sha256_hex


def diagnostics_module():
    try:
        import context_guard_receipt.diagnostics as diagnostics
    except ModuleNotFoundError as error:
        raise AssertionError("G009 diagnostics implementation is missing") from error
    return diagnostics


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def request(**overrides: object) -> bytes:
    value: dict[str, object] = {
        "blueprint_b64u": b64url(b"b" * 32),
        "caller_classification": "eligible",
        "current_prefix_b64u": b64url(b"c" * 64),
        "detector_signals": [],
        "handle_b64u": b64url(b"h" * 24),
        "input_b64u": b64url(b"i" * 2_560),
        "mandatory_expansion_b64u": "",
        "previous_prefix_b64u": b64url(b"c" * 64),
        "retained_wire_b64u": "",
        "schema_version": "contextguard-receipt-diagnostics-request/v1",
        "subject_kind": "evidence",
        "wrapper_b64u": b64url(b"w" * 64),
    }
    value.update(overrides)
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


class G009DiagnosticsTests(unittest.TestCase):
    def analyze(self, **overrides: object):
        return diagnostics_module().analyze_diagnostics(
            request(**overrides), fingerprint_key=b"k" * 32
        )

    def test_511_and_512_input_boundaries_are_routed_without_token_or_cost_inputs(self) -> None:
        for length, reason in ((511, "input_too_small"), (512, "beneficial")):
            with self.subTest(length=length):
                result = self.analyze(input_b64u=b64url(b"i" * length), blueprint_b64u="")
                report = result.report()
                self.assertEqual(report["firewall"]["reason"], reason)
                self.assertEqual(report["firewall"]["would_block"], length == 511)
                self.assertEqual(
                    set(report),
                    {
                        "advisory", "evidence_boundary", "firewall", "prefix_delta",
                        "provider_claim_authority", "provider_routing_authority",
                        "live_observation_authority", "efficacy_claim_authority", "route",
                        "schema_version", "state_scope", "subject_kind",
                    },
                )
                self.assertFalse(report["provider_claim_authority"])
                self.assertFalse(report["provider_routing_authority"])
                self.assertFalse(report["live_observation_authority"])
                self.assertFalse(report["efficacy_claim_authority"])

    def test_255_and_256_savings_boundaries_are_inclusive(self) -> None:
        for predicted, reason in ((745, "savings_too_small"), (744, "beneficial")):
            with self.subTest(predicted=predicted):
                result = self.analyze(
                    input_b64u=b64url(b"i" * 1_000),
                    wrapper_b64u=b64url(b"w" * predicted),
                    handle_b64u="",
                    blueprint_b64u="",
                )
                self.assertEqual(result.report()["firewall"]["reason"], reason)

    def test_999_and_1000_basis_point_boundaries_use_integer_math(self) -> None:
        for predicted, reason in ((2_701, "savings_ratio_too_small"), (2_700, "beneficial")):
            with self.subTest(predicted=predicted):
                result = self.analyze(
                    input_b64u=b64url(b"i" * 3_000),
                    wrapper_b64u=b64url(b"w" * predicted),
                    handle_b64u="",
                    blueprint_b64u="",
                )
                self.assertEqual(result.report()["firewall"]["reason"], reason)

    def test_mandatory_expansion_reason_is_preserved(self) -> None:
        result = self.analyze(
            input_b64u=b64url(b"i" * 4_096),
            wrapper_b64u=b64url(b"w" * 200),
            handle_b64u=b64url(b"h" * 98),
            blueprint_b64u=b64url(b"b" * 400),
            mandatory_expansion_b64u=b64url(b"m" * 3_500),
        )
        self.assertEqual(result.report()["firewall"]["reason"], "mandatory_expansion_cost")

    def test_protection_reason_precedes_the_router(self) -> None:
        result = self.analyze(caller_classification="protected", input_b64u=b64url(b"i" * 8_192))
        shadow = result.report()["firewall"]
        self.assertEqual(shadow["reason"], "protected")
        self.assertTrue(shadow["would_block"])
        self.assertEqual(result.report()["advisory"]["lane"], "none")

    def test_advisory_lane_and_reason_preserve_scout_and_exact_path_policy(self) -> None:
        small = self.analyze(input_b64u=b64url(b"i" * 511), blueprint_b64u="")
        self.assertEqual(
            small.report()["advisory"],
            {"lane": "scout", "only": True, "reason": "input_too_small"},
        )
        protected = self.analyze(caller_classification="protected")
        self.assertEqual(
            protected.report()["advisory"],
            {"lane": "none", "only": True, "reason": "exact_path_required"},
        )
        secret = self.analyze(detector_signals=["secret"])
        self.assertEqual(
            secret.report()["advisory"],
            {"lane": "none", "only": True, "reason": "protection_refused"},
        )

    def test_parse_rejects_invalid_or_duplicate_signals_before_state_can_open(self) -> None:
        diagnostics = diagnostics_module()
        for overrides in (
            {"caller_classification": "not-a-classification"},
            {"detector_signals": ["not-a-signal"]},
            {"detector_signals": ["unknown", "unknown"]},
            {"detector_signals": ["unknown"] * 65},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(diagnostics.DiagnosticsError):
                    diagnostics.parse_diagnostics_request(request(**overrides))

    def test_detector_signal_set_is_normalized_for_unlinkable_hmacs(self) -> None:
        first = self.analyze(
            detector_signals=["unknown", "ambiguous"]
        ).firewall_report()["evidence_hmac_sha256"]
        second = self.analyze(
            detector_signals=["ambiguous", "unknown"]
        ).firewall_report()["evidence_hmac_sha256"]
        self.assertEqual(first, second)

    def test_policy_hash_is_domain_separated(self) -> None:
        expected = framed_sha256_hex(
            "contextguard-receipt/diagnostic-policy/v1",
            b"contextguard-receipt-diagnostics-policy/v1",
            b"contextguard-receipt-router/v1",
            (65_536).to_bytes(8, "big"),
            (64).to_bytes(8, "big"),
            (1_024).to_bytes(8, "big"),
            (9_000).to_bytes(8, "big"),
        )
        self.assertEqual(self.analyze().ledger_fields()["policy_sha256"], expected)

    def test_distributable_schema_closes_signal_sets_and_numeric_bounds(self) -> None:
        request_schema = json.loads(
            (PACKAGE_ROOT / "schemas/diagnostics-request.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIs(
            request_schema["properties"]["detector_signals"].get("uniqueItems"),
            True,
        )
        report_schema = json.loads(
            (PACKAGE_ROOT / "schemas/diagnostics-report.schema.json").read_text(
                encoding="utf-8"
            )
        )
        prefix = report_schema["$defs"]["prefix_delta"]["properties"]
        route = report_schema["$defs"]["route"]["properties"]
        self.assertEqual(prefix["current_prefix_bytes"]["maximum"], 900_000)
        self.assertEqual(prefix["prefix_delta_bytes"]["minimum"], -900_000)
        self.assertEqual(prefix["prefix_delta_bytes"]["maximum"], 900_000)
        self.assertEqual(route["predicted_cost_bytes"]["maximum"], 900_000)
        self.assertEqual(route["predicted_savings_bytes"]["minimum"], -900_000)
        self.assertEqual(route["predicted_savings_bytes"]["maximum"], 900_000)
        self.assertEqual(route["savings_basis_points"]["minimum"], -9_000_000_000)
        self.assertEqual(route["savings_basis_points"]["maximum"], 10_000)

        firewall_schema = json.loads(
            (PACKAGE_ROOT / "schemas/shadow-firewall-report.schema.json").read_text(
                encoding="utf-8"
            )
        )
        boundary_schema = json.loads(
            (PACKAGE_ROOT / "schemas/evidence-boundary.schema.json").read_text(
                encoding="utf-8"
            )
        )
        firewall_reference = report_schema["properties"]["firewall"]["$ref"]
        self.assertEqual(
            urljoin(report_schema["$id"], firewall_reference),
            firewall_schema["$id"],
        )
        self.assertEqual(
            urljoin(
                firewall_schema["$id"],
                firewall_schema["properties"]["evidence_boundary"]["$ref"],
            ),
            boundary_schema["$id"],
        )

        route_pairs = {
            (
                branch["properties"]["disposition"]["const"],
                tuple(branch["properties"]["reason"].get("enum", (
                    branch["properties"]["reason"].get("const"),
                ))),
            )
            for branch in report_schema["$defs"]["route"]["oneOf"]
        }
        self.assertEqual(
            route_pairs,
            {
                ("defer", ("beneficial",)),
                (
                    "pass_through",
                    (
                        "input_too_small",
                        "savings_too_small",
                        "savings_ratio_too_small",
                        "mandatory_expansion_cost",
                    ),
                ),
            },
        )
        advisory_pairs = {
            (
                branch["properties"]["lane"]["const"],
                tuple(branch["properties"]["reason"].get("enum", (
                    branch["properties"]["reason"].get("const"),
                ))),
            )
            for branch in report_schema["properties"]["advisory"]["oneOf"]
        }
        self.assertEqual(
            advisory_pairs,
            {
                ("none", ("protection_refused", "exact_path_required")),
                (
                    "scout",
                    (
                        "input_too_small",
                        "savings_too_small",
                        "savings_ratio_too_small",
                        "mandatory_expansion_cost",
                        "prefix_evidence_empty",
                        "prior_prefix_missing",
                        "rolling_sample_partial",
                        "prefix_churn_high",
                    ),
                ),
                ("surgeon", ("bounded_stable_benefit",)),
            },
        )

    def test_rejects_noncanonical_base64url_and_total_decoded_bytes_over_limit(self) -> None:
        diagnostics = diagnostics_module()
        for invalid in ("AA=", "A", "AB", "+A"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(diagnostics.DiagnosticsError):
                    self.analyze(input_b64u=invalid)
        with self.assertRaises(diagnostics.DiagnosticsError):
            self.analyze(input_b64u=b64url(b"i" * 900_001))

    def test_evidence_hmac_covers_every_fragment_and_enum(self) -> None:
        baseline = self.analyze().report()["firewall"]["evidence_hmac_sha256"]
        mutations = (
            {"blueprint_b64u": b64url(b"B" * 32)},
            {"current_prefix_b64u": b64url(b"C" * 64)},
            {"handle_b64u": b64url(b"H" * 24)},
            {"input_b64u": b64url(b"I" * 2_560)},
            {"mandatory_expansion_b64u": b64url(b"M")},
            {"previous_prefix_b64u": b64url(b"P" * 64)},
            {"retained_wire_b64u": b64url(b"R")},
            {"wrapper_b64u": b64url(b"W" * 64)},
            {"subject_kind": "blueprint"},
            {"detector_signals": ["unknown"]},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assertNotEqual(
                    baseline,
                    self.analyze(**mutation).report()["firewall"]["evidence_hmac_sha256"],
                )
        self.assertNotEqual(
            baseline,
            diagnostics_module().analyze_diagnostics(request(), fingerprint_key=b"z" * 32)
            .report()["firewall"]["evidence_hmac_sha256"],
        )

    def test_rolling_delta_has_exact_window_boundaries(self) -> None:
        for length, windows, status in (
            (0, 0, "complete"),
            (1, 1, "complete"),
            (63, 1, "complete"),
            (64, 1, "complete"),
            (65, 2, "complete"),
            (65_535, 1_024, "complete"),
            (65_536, 1_024, "complete"),
            (65_537, 1_024, "partial"),
        ):
            with self.subTest(length=length):
                value = b"p" * length
                rolling = self.analyze(
                    current_prefix_b64u=b64url(value), previous_prefix_b64u=b64url(value)
                ).report()["prefix_delta"]
                self.assertEqual(rolling["rolling_status"], status)
                self.assertEqual(rolling["current_window_count"], windows)
                self.assertEqual(rolling["matched_window_count"], windows)
                self.assertEqual(rolling["current_reuse_basis_points"], 10_000 if windows else 0)
        self.assertEqual(self.analyze(previous_prefix_b64u=None).report()["prefix_delta"]["rolling_status"], "unavailable")

    def test_surgeon_requires_tail_position_and_bidirectional_prefix_stability(self) -> None:
        cases = (
            (b"a" * 64 + b"x", b"a" * 64 + b"y"),
            (b"a" * 64 + b"b" * 64, b"b" * 64 + b"a" * 64),
            (b"a" * (64 * 10), b"a" * (64 * 10) + b"b" * (64 * 10)),
        )
        for current, previous in cases:
            with self.subTest(current=len(current), previous=len(previous)):
                report = self.analyze(
                    current_prefix_b64u=b64url(current),
                    previous_prefix_b64u=b64url(previous),
                ).report()
                self.assertEqual(
                    report["advisory"],
                    {"lane": "scout", "only": True, "reason": "prefix_churn_high"},
                )

    def test_advisory_surgeon_threshold_is_inclusive(self) -> None:
        current = b"a" * (64 * 10)
        prior_9000 = b"a" * (64 * 9) + b"b" * 64
        prior_8000 = b"a" * (64 * 8) + b"b" * (64 * 2)
        self.assertNotIn("advisory_level", diagnostics_module().__all__)
        self.assertEqual(
            self.analyze(current_prefix_b64u=b64url(current), previous_prefix_b64u=b64url(prior_9000))
            .report()["advisory"]["lane"],
            "surgeon",
        )
        self.assertEqual(
            self.analyze(current_prefix_b64u=b64url(current), previous_prefix_b64u=b64url(prior_8000))
            .report()["advisory"]["lane"],
            "scout",
        )

    def test_request_can_be_validated_without_retaining_raw_fragments(self) -> None:
        diagnostics = diagnostics_module()
        parsed = diagnostics.parse_diagnostics_request(request())
        self.assertIn("ParsedDiagnosticsRequest", repr(parsed))
        self.assertNotIn("aWk", repr(parsed))
        result = diagnostics.analyze_request(parsed, fingerprint_key=b"k" * 32)
        self.assertEqual(result.report()["subject_kind"], "evidence")

    def test_result_repr_and_outputs_do_not_retain_or_expose_raw_data_or_key(self) -> None:
        secret = b"private-input-must-not-appear"
        result = self.analyze(input_b64u=b64url(secret))
        rendered = repr(result) + json.dumps(result.report()) + json.dumps(result.ledger_fields())
        self.assertNotIn(secret.decode("ascii"), rendered)
        self.assertNotIn("kkkk", rendered)
        self.assertNotIn("sequence", result.ledger_fields())
        self.assertNotIn("timestamp", result.ledger_fields())
        self.assertNotIn("chain", result.ledger_fields())


if __name__ == "__main__":
    unittest.main()
