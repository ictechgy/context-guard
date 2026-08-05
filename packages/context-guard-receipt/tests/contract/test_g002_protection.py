from __future__ import annotations

import dataclasses
import hashlib
import importlib
import itertools
import json
import sys
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
SCHEMA_PATH = PACKAGE_ROOT / "schemas/protection-decision.schema.json"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))

EVIDENCE_BOUNDARY = {
    "evidence_class": "companion_local_receipt_only",
    "host_request_owned": False,
    "provider_claim_authority": False,
    "provider_join_status": "missing",
    "runtime_observer_present": False,
    "schema_version": "contextguard-receipt-evidence-boundary/v1",
    "selected_branch": "S2-UNSUPPORTED",
    "selected_transport": "NONE",
    "stage1_evidence": False,
    "stage2_evidence": False,
}
BOUNDARY_REQUIRED = list(EVIDENCE_BOUNDARY)
CALLERS = (
    "eligible",
    "exact_required",
    "protected",
    "unknown",
    "ambiguous",
    "security_sensitive",
    "refuse",
)
SIGNALS = (
    "exact_required",
    "protected",
    "unknown",
    "ambiguous",
    "security_sensitive",
    "secret",
)
REASONS = (*CALLERS, "secret")
EXPECTED_PAIR_REASONS = {
    "eligible": (
        "exact_required", "protected", "unknown", "ambiguous", "security_sensitive", "secret"
    ),
    "exact_required": (
        "exact_required", "protected", "exact_required", "exact_required", "security_sensitive", "secret"
    ),
    "protected": (
        "protected", "protected", "protected", "protected", "security_sensitive", "secret"
    ),
    "unknown": (
        "exact_required", "protected", "unknown", "ambiguous", "security_sensitive", "secret"
    ),
    "ambiguous": (
        "exact_required", "protected", "ambiguous", "ambiguous", "security_sensitive", "secret"
    ),
    "security_sensitive": (
        "security_sensitive", "security_sensitive", "security_sensitive",
        "security_sensitive", "security_sensitive", "secret"
    ),
    "refuse": ("refuse", "refuse", "refuse", "refuse", "refuse", "refuse"),
}


def protection_module():
    try:
        return importlib.import_module("context_guard_receipt.protection")
    except ModuleNotFoundError as error:
        raise AssertionError("G002 protection implementation is missing") from error


def expected_content_digest(payload: bytes) -> str:
    domain = b"contextguard-receipt/protected-content/v1"
    preimage = domain + b"\0" + len(payload).to_bytes(8, "big") + payload
    return hashlib.sha256(preimage).hexdigest()


def expected_action(reason: str) -> str:
    if reason == "eligible":
        return "eligible"
    if reason in {"refuse", "secret"}:
        return "refuse"
    return "pass_through"


def nested_keys(value: object) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        keys.update(value)
        for child in value.values():
            keys.update(nested_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.update(nested_keys(child))
    return keys


class G002ProtectionContractTests(unittest.TestCase):
    def test_closed_enums_have_only_the_contract_values(self) -> None:
        """Break caught: accepting an unreviewed classification, signal, action, or reason."""
        module = protection_module()
        self.assertEqual(module.MAX_PROTECTION_TOKEN_CHARACTERS, 18)
        self.assertEqual(tuple(item.value for item in module.CallerClassification), CALLERS)
        self.assertEqual(tuple(item.value for item in module.DetectorSignal), SIGNALS)
        self.assertEqual(
            tuple(item.value for item in module.ProtectionAction),
            ("eligible", "pass_through", "refuse"),
        )
        self.assertEqual(tuple(item.value for item in module.ProtectionReason), REASONS)

    def test_each_caller_without_signals_has_its_caller_grounded_outcome(self) -> None:
        """Break caught: dropping the caller classification when detectors are silent."""
        module = protection_module()
        payload = b"caller-grounded\x00\xff"
        for caller in CALLERS:
            with self.subTest(caller=caller):
                decision = module.decide_protection(payload, caller, ())
                self.assertEqual(decision.action.value, expected_action(caller))
                self.assertEqual(decision.reason.value, caller)
                expected_bytes = payload if caller not in {"eligible", "refuse"} else None
                self.assertEqual(decision.exact_bytes, expected_bytes)

    def test_every_caller_and_detector_pair_only_escalates(self) -> None:
        """Break caught: a detector downgrade or incorrect precedence for any pair."""
        module = protection_module()
        payload = b"\x00\x80\xffnot-utf8"
        for caller, expected_row in EXPECTED_PAIR_REASONS.items():
            for signal, reason in zip(SIGNALS, expected_row, strict=True):
                with self.subTest(caller=caller, signal=signal):
                    decision = module.decide_protection(payload, caller, (signal,))
                    self.assertEqual(decision.reason.value, reason)
                    self.assertEqual(decision.action.value, expected_action(reason))
                    expected_bytes = payload if expected_action(reason) == "pass_through" else None
                    self.assertEqual(decision.exact_bytes, expected_bytes)

    def test_detector_order_and_duplicates_cannot_change_the_decision(self) -> None:
        """Break caught: first/last-detector wins behavior or duplicate-sensitive output."""
        module = protection_module()
        payload = b"permutation\x00\xfe"
        signals = ("unknown", "ambiguous", "exact_required", "protected")
        expected = module.decide_protection(payload, "unknown", signals)
        self.assertEqual(expected.reason.value, "protected")
        for permutation in itertools.permutations(signals):
            with self.subTest(permutation=permutation):
                self.assertEqual(
                    module.decide_protection(payload, "unknown", permutation),
                    expected,
                )
        self.assertEqual(
            module.decide_protection(payload, "unknown", signals + signals),
            expected,
        )
        self.assertEqual(
            module.decide_protection(payload, "security_sensitive", ("secret", "protected")),
            module.decide_protection(payload, "security_sensitive", ("protected", "secret")),
        )
        self.assertEqual(
            module.decide_protection(payload, "refuse", ("secret",)).reason.value,
            "refuse",
        )

    def test_pass_through_preserves_arbitrary_bytes_and_decisions_are_frozen_values(self) -> None:
        """Break caught: decoding, normalizing, copying into text, or mutable decisions."""
        module = protection_module()
        payload = b"HOSTILE_REPR_SECRET" + bytes(range(256)) + b"\x00\x00\xff\xfe\xc0\x80\r\n"
        first = module.decide_protection(payload, module.CallerClassification.PROTECTED, ())
        second = module.decide_protection(payload, "protected", ())
        self.assertEqual(first, second)
        self.assertIs(first.exact_bytes, payload)
        self.assertEqual(first.exact_bytes, payload)
        self.assertNotIn("HOSTILE_REPR_SECRET", repr(first))
        self.assertNotIn("exact_bytes", repr(first))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.exact_bytes = b"changed"

    def test_artifact_is_closed_metadata_with_exact_boundary_and_framed_digest(self) -> None:
        """Break caught: raw content disclosure, boundary drift, or plain SHA-256 hashing."""
        module = protection_module()
        payload = b"\x00hostile/raw/path/detail\xff"
        decision = module.decide_protection(payload, "protected", ())
        artifact = decision.artifact()
        self.assertEqual(
            artifact,
            {
                "action": "pass_through",
                "byte_length": len(payload),
                "content_sha256": expected_content_digest(payload),
                "evidence_boundary": EVIDENCE_BOUNDARY,
                "reason": "protected",
                "schema_version": "contextguard-receipt-protection-decision/v1",
            },
        )
        self.assertEqual(set(artifact), {
            "action", "byte_length", "content_sha256", "evidence_boundary", "reason", "schema_version"
        })
        serialized = json.dumps(artifact, sort_keys=True)
        self.assertNotIn("hostile", serialized)
        self.assertNotIn("/raw/path/detail", serialized)
        self.assertNotIn("exact_bytes", serialized)

    def test_eligible_and_refuse_artifacts_hash_without_retaining_payload(self) -> None:
        """Break caught: raw bytes retained on transform-eligible or refused decisions."""
        module = protection_module()
        payload = b"do-not-retain\x00\xff"
        for caller, signals, action, reason in (
            ("eligible", (), "eligible", "eligible"),
            ("security_sensitive", ("secret",), "refuse", "secret"),
            ("refuse", ("secret",), "refuse", "refuse"),
        ):
            with self.subTest(caller=caller, signals=signals):
                decision = module.decide_protection(payload, caller, signals)
                self.assertIsNone(decision.exact_bytes)
                self.assertEqual(decision.artifact()["action"], action)
                self.assertEqual(decision.artifact()["reason"], reason)
                self.assertEqual(decision.artifact()["byte_length"], len(payload))
                self.assertEqual(
                    decision.artifact()["content_sha256"], expected_content_digest(payload)
                )

    def test_invalid_inputs_fail_with_stable_non_reflective_codes(self) -> None:
        """Break caught: coercion, open enums, or hostile values reflected in errors."""
        module = protection_module()

        class BytesSubclass(bytes):
            pass

        hostile = "HOSTILE-INPUT-/tmp/private-detail"
        cases = (
            ((hostile, "eligible", ()), "invalid_payload_type"),
            ((bytearray(b"x"), "eligible", ()), "invalid_payload_type"),
            ((memoryview(b"x"), "eligible", ()), "invalid_payload_type"),
            ((BytesSubclass(b"x"), "eligible", ()), "invalid_payload_type"),
            ((b"x", hostile, ()), "invalid_caller_classification"),
            ((b"x", "x" * 19, ()), "invalid_caller_classification"),
            ((b"x", "eligible", (hostile,)), "invalid_detector_signal"),
            ((b"x", "eligible", ("x" * 19,)), "invalid_detector_signal"),
            ((b"x", "eligible", "secret"), "invalid_detector_signals"),
            ((b"x", "eligible", []), "invalid_detector_signals"),
            ((b"x", "eligible", set()), "invalid_detector_signals"),
            ((b"x", "eligible", None), "invalid_detector_signals"),
        )
        for arguments, expected_code in cases:
            with self.subTest(code=expected_code):
                with self.assertRaises(module.ProtectionError) as caught:
                    module.decide_protection(*arguments)
                self.assertEqual(caught.exception.code, expected_code)
                self.assertEqual(str(caught.exception), expected_code)
                self.assertNotIn(hostile, str(caught.exception))
                self.assertNotIn(hostile, repr(caught.exception))

    def test_payload_size_bound_is_exact_and_non_reflective(self) -> None:
        """Break caught: disagreement with canonical framing's one-part size bound."""
        module = protection_module()
        accepted = b"x" * module.MAX_PROTECTED_CONTENT_BYTES
        decision = module.decide_protection(accepted, "protected", ())
        self.assertEqual(decision.artifact()["byte_length"], 1_048_576)
        with self.assertRaises(module.ProtectionError) as caught:
            module.decide_protection(accepted + b"x", "protected", ())
        self.assertEqual(caught.exception.code, "payload_too_large")

    def test_detector_signal_count_is_hard_bounded(self) -> None:
        """Break caught: duplicate detector input consuming unbounded local work."""
        module = protection_module()
        accepted = ("unknown",) * module.MAX_DETECTOR_SIGNALS
        self.assertEqual(
            module.decide_protection(b"x", "eligible", accepted).reason.value,
            "unknown",
        )
        with self.assertRaises(module.ProtectionError) as caught:
            module.decide_protection(b"x", "eligible", accepted + ("unknown",))
        self.assertEqual(caught.exception.code, "too_many_detector_signals")

    def test_decisions_cannot_be_directly_forged_or_replaced(self) -> None:
        """Break caught: contradictory actions or fabricated digests entering artifacts."""
        module = protection_module()
        decision = module.decide_protection(b"secret", "security_sensitive", ("secret",))
        with self.assertRaises(module.ProtectionError) as direct:
            module.ProtectionDecision(
                action=module.ProtectionAction.PASS_THROUGH,
                reason=module.ProtectionReason.SECRET,
                exact_bytes=b"secret",
                _byte_length=6,
                _content_sha256="0" * 64,
            )
        self.assertEqual(direct.exception.code, "direct_construction_forbidden")
        with self.assertRaises(module.ProtectionError) as replaced:
            dataclasses.replace(
                decision,
                action=module.ProtectionAction.PASS_THROUGH,
                exact_bytes=b"secret",
            )
        self.assertEqual(replaced.exception.code, "direct_construction_forbidden")

    def test_exported_boundary_mutation_cannot_change_artifacts_or_responses(self) -> None:
        """Break caught: mutable compatibility exports becoming receipt authority."""
        module = protection_module()
        contracts = importlib.import_module("context_guard_receipt.contracts")
        original = dict(contracts.EVIDENCE_BOUNDARY)
        try:
            contracts.EVIDENCE_BOUNDARY.clear()
            contracts.EVIDENCE_BOUNDARY.update(
                {"provider_claim_authority": True, "raw": "HOSTILE_RAW_SECRET"}
            )
            artifact = module.decide_protection(b"x", "protected").artifact()
            response = contracts.response(operation="inspect_boundary", status="ok")
        finally:
            contracts.EVIDENCE_BOUNDARY.clear()
            contracts.EVIDENCE_BOUNDARY.update(original)
        self.assertEqual(artifact["evidence_boundary"], EVIDENCE_BOUNDARY)
        self.assertEqual(response["evidence_boundary"], EVIDENCE_BOUNDARY)
        self.assertNotIn("HOSTILE_RAW_SECRET", json.dumps((artifact, response)))

    def test_schema_is_recursively_closed_and_matches_the_artifact_contract(self) -> None:
        """Break caught: schema escape hatches, raw fields, or weakened value constraints."""
        self.assertTrue(SCHEMA_PATH.is_file(), "G002 protection schema is missing")
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            set(schema),
            {
                "$id", "$schema", "additionalProperties", "oneOf", "properties",
                "required", "title", "type",
            },
        )
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(
            schema["$id"],
            "https://context-guard.local/schemas/receipt-protection-decision-v1.json",
        )
        self.assertEqual(schema["type"], "object")
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(
            set(schema["required"]),
            {"action", "byte_length", "content_sha256", "evidence_boundary", "reason", "schema_version"},
        )
        properties = schema["properties"]
        self.assertEqual(set(properties), set(schema["required"]))
        self.assertEqual(properties["schema_version"], {
            "const": "contextguard-receipt-protection-decision/v1"
        })
        self.assertEqual(properties["action"], {
            "enum": ["eligible", "pass_through", "refuse"], "type": "string"
        })
        self.assertEqual(properties["reason"], {"enum": list(REASONS), "type": "string"})
        self.assertEqual(properties["byte_length"], {
            "maximum": 1_048_576, "minimum": 0, "type": "integer"
        })
        self.assertEqual(properties["content_sha256"], {
            "maxLength": 64,
            "minLength": 64,
            "pattern": "^[0-9a-f]{64}$",
            "type": "string",
        })
        self.assertEqual(
            schema["oneOf"],
            [
                {
                    "properties": {
                        "action": {"const": "eligible"},
                        "reason": {"const": "eligible"},
                    },
                    "required": ["action", "reason"],
                },
                {
                    "properties": {
                        "action": {"const": "pass_through"},
                        "reason": {
                            "enum": [
                                "exact_required", "protected", "unknown", "ambiguous",
                                "security_sensitive",
                            ]
                        },
                    },
                    "required": ["action", "reason"],
                },
                {
                    "properties": {
                        "action": {"const": "refuse"},
                        "reason": {"enum": ["refuse", "secret"]},
                    },
                    "required": ["action", "reason"],
                },
            ],
        )
        boundary = properties["evidence_boundary"]
        self.assertEqual(set(boundary), {"additionalProperties", "properties", "required", "type"})
        self.assertEqual(boundary["type"], "object")
        self.assertIs(boundary["additionalProperties"], False)
        self.assertEqual(boundary["required"], BOUNDARY_REQUIRED)
        self.assertEqual(
            boundary["properties"],
            {key: {"const": value} for key, value in EVIDENCE_BOUNDARY.items()},
        )
        self.assertNotIn("$ref", nested_keys(schema))
        self.assertTrue(
            {"raw", "raw_bytes", "payload", "exact_bytes", "path", "detail"}.isdisjoint(
                nested_keys(schema)
            )
        )


if __name__ == "__main__":
    unittest.main()
