from __future__ import annotations

import base64
import hashlib
import importlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))

from context_guard_receipt.canonical import canonical_json_bytes, parse_canonical_json_bytes
from context_guard_receipt.store import IssuedCapability, StoreError, StoreErrorCode


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


def assembly_module():
    try:
        return importlib.import_module("context_guard_receipt.assembly")
    except ModuleNotFoundError as error:
        raise AssertionError("G005 assembly implementation is missing") from error


def git_executable() -> str:
    candidate = shutil.which("git")
    if candidate is None:
        raise unittest.SkipTest("git is unavailable")
    return str(Path(candidate).resolve())


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def evidence_descriptor(
    payload: bytes,
    relative_path: str,
    *,
    classification: str = "eligible",
) -> bytes:
    return canonical_json_bytes(
        {
            "caller_classification": classification,
            "detector_signals": [],
            "payload_b64u": b64url(payload),
            "schema_version": "contextguard-receipt-evidence-descriptor/v1",
            "source": {
                "relative_path": relative_path,
                "selection": {"kind": "file"},
            },
        },
        limits=assembly_module().DESCRIPTOR_LIMITS,
    )


def blueprint_descriptor(
    payloads: tuple[bytes, ...],
    relative_paths: tuple[str, ...],
    phases: tuple[str, ...],
    classifications: tuple[str, ...] | None = None,
    detector_signals: tuple[tuple[str, ...], ...] | None = None,
) -> bytes:
    if classifications is None:
        classifications = tuple("eligible" for _payload in payloads)
    if detector_signals is None:
        detector_signals = tuple(() for _payload in payloads)
    offset = 0
    items: list[dict[str, object]] = []
    obligations: list[dict[str, object]] = []
    for index, (payload, relative_path, phase, classification, signals) in enumerate(
        zip(
            payloads,
            relative_paths,
            phases,
            classifications,
            detector_signals,
            strict=True,
        )
    ):
        items.append(
            {
                "caller_classification": classification,
                "detector_signals": list(signals),
                "payload_end_byte": offset + len(payload),
                "payload_start_byte": offset,
                "source": {
                    "relative_path": relative_path,
                    "selection": {"kind": "file"},
                },
            }
        )
        obligations.append({"item_index": index, "phase": phase})
        offset += len(payload)
    return canonical_json_bytes(
        {
            "items": items,
            "obligations": obligations,
            "payload_b64u": b64url(b"".join(payloads)),
            "schema_version": "contextguard-receipt-blueprint-descriptor/v1",
        },
        limits=assembly_module().DESCRIPTOR_LIMITS,
    )


class RecordingStore:
    def __init__(self, *, fail: bool = False) -> None:
        self.calls: list[tuple[object, ...]] = []
        self.fail = fail

    def issue_batch(self, requests: tuple[object, ...]) -> tuple[IssuedCapability, ...]:
        self.calls.append(requests)
        if self.fail:
            raise StoreError(StoreErrorCode.WRITE_FAILED)
        return tuple(
            IssuedCapability(
                handle="cgr1p_" + chr(ord("A") + index) * 43,
                namespace_id="a" * 64,
            )
            for index in range(len(requests))
        )


class MalformedResultStore:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.calls: list[tuple[object, ...]] = []

    def issue_batch(self, requests: tuple[object, ...]):
        self.calls.append(requests)
        if self.mode == "exception":
            raise RuntimeError("private backend detail")
        if self.mode == "missing_fields":
            return tuple(object() for _request in requests)
        if self.mode == "runtime_getter":
            class RuntimeGetterIssued:
                @property
                def handle(self):
                    raise RuntimeError("backend-private-detail")

                namespace_id = "a" * 64

            return tuple(RuntimeGetterIssued() for _request in requests)
        if self.mode == "namespace":
            return tuple(
                IssuedCapability(handle="cgr1p_" + chr(ord("A") + index) * 43, namespace_id="bad")
                for index, _request in enumerate(requests)
            )
        duplicate = IssuedCapability(handle="cgr1p_" + "A" * 43, namespace_id="a" * 64)
        return tuple(duplicate for _request in requests)


class ExplodingIssuePropertyStore:
    @property
    def issue_batch(self):
        raise RuntimeError("private backend property")


class G005AssemblyTests(unittest.TestCase):
    def test_malformed_typed_phase_is_a_closed_descriptor_error(self) -> None:
        """Break caught: an unhashable phase leaks an internal TypeError."""

        assembly = assembly_module()
        payload = b"x" * 1_024
        malformed = {
            "items": [
                {
                    "caller_classification": "eligible",
                    "detector_signals": [],
                    "payload_end_byte": len(payload),
                    "payload_start_byte": 0,
                    "source": {
                        "relative_path": "value.bin",
                        "selection": {"kind": "file"},
                    },
                }
            ],
            "obligations": [{"item_index": 0, "phase": ["optional_evidence"]}],
            "payload_b64u": b64url(payload),
            "schema_version": "contextguard-receipt-blueprint-descriptor/v1",
        }
        raw = canonical_json_bytes(malformed, limits=assembly.DESCRIPTOR_LIMITS)
        try:
            with self.assertRaises(assembly.AssemblyError) as caught:
                assembly.assemble_blueprint(
                    raw,
                    root="/does/not/matter",
                    git_executable=git_executable(),
                    store=RecordingStore(),
                )
        except TypeError:
            self.fail("malformed phase leaked TypeError")
        self.assertEqual(caught.exception.code, "invalid_descriptor")

    def test_evidence_deferral_uses_actual_wire_cost_and_one_atomic_issue(self) -> None:
        """Break caught: predicted wrapper cost differs from emitted bytes or issuance is split."""

        assembly = assembly_module()
        payload = b"e" * 8_192
        store = RecordingStore()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "evidence.bin").write_bytes(payload)
            result = assembly.assemble_evidence(
                evidence_descriptor(payload, "evidence.bin"),
                root=str(root),
                git_executable=git_executable(),
                store=store,
            )

        artifact = parse_canonical_json_bytes(result.output_bytes)
        self.assertEqual(result.disposition.value, "deferred")
        self.assertEqual(len(store.calls), 1)
        self.assertEqual(len(store.calls[0]), 1)
        self.assertEqual(
            set(artifact),
            {
                "artifact_kind",
                "byte_length",
                "capability",
                "content_sha256",
                "evidence_boundary",
                "router_policy_version",
                "schema_version",
                "subject_identity_sha256",
            },
        )
        self.assertEqual(artifact["artifact_kind"], "evidence_reference")
        self.assertEqual(artifact["evidence_boundary"], EVIDENCE_BOUNDARY)
        route = result.receipt["route"]
        self.assertEqual(route["predicted_cost_bytes"], len(result.output_bytes))
        self.assertEqual(
            route["wrapper_bytes"] + route["handle_bytes"],
            len(result.output_bytes),
        )

    def test_all_pre_store_gates_return_exact_payload_without_mutation(self) -> None:
        """Break caught: protected, small, or mismatched bytes reach durable storage."""

        assembly = assembly_module()
        cases = (
            (b"p" * 8_192, b"p" * 8_192, "protected"),
            (b"s" * 511, b"s" * 511, "eligible"),
            (b"descriptor" * 1_024, b"source" * 1_024, "eligible"),
        )
        for descriptor_payload, source_payload, classification in cases:
            with self.subTest(classification=classification, size=len(descriptor_payload)):
                store = RecordingStore()
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / "value.bin").write_bytes(source_payload)
                    result = assembly.assemble_evidence(
                        evidence_descriptor(
                            descriptor_payload,
                            "value.bin",
                            classification=classification,
                        ),
                        root=str(root),
                        git_executable=git_executable(),
                        store=store,
                    )
                self.assertEqual(result.disposition.value, "pass_through")
                self.assertEqual(result.output_bytes, descriptor_payload)
                self.assertEqual(store.calls, [])

    def test_all_blueprint_protection_gates_run_before_source_identity(self) -> None:
        """Break caught: an earlier item touches identity before a later protected item."""

        assembly = assembly_module()
        payloads = (b"a" * 1_024, b"b" * 1_024)
        store = RecordingStore()
        result = assembly.assemble_blueprint(
            blueprint_descriptor(
                payloads,
                ("missing-a.bin", "missing-b.bin"),
                ("optional_evidence", "optional_evidence"),
                ("eligible", "protected"),
            ),
            root="/does/not/matter",
            git_executable=git_executable(),
            store=store,
        )
        self.assertEqual(result.disposition.value, "pass_through")
        self.assertEqual(result.output_bytes, b"".join(payloads))
        self.assertEqual(result.receipt["reason"], "protected")
        self.assertEqual(store.calls, [])

    def test_blueprint_global_secret_outranks_earlier_pass_through(self) -> None:
        """Break caught: item order lets an earlier unknown hide a later secret."""

        assembly = assembly_module()
        payloads = (b"a" * 1_024, b"secret" * 256)
        store = RecordingStore()
        result = assembly.assemble_blueprint(
            blueprint_descriptor(
                payloads,
                ("missing-a.bin", "missing-secret.bin"),
                ("optional_evidence", "optional_evidence"),
                ("unknown", "eligible"),
                ((), ("secret",)),
            ),
            root="/does/not/matter",
            git_executable=git_executable(),
            store=store,
        )
        self.assertEqual(result.disposition.value, "refused")
        self.assertEqual(result.output_bytes, b"")
        self.assertEqual(result.receipt["reason"], "secret")
        self.assertEqual(store.calls, [])

    def test_store_failure_falls_back_to_exact_payload_without_reference(self) -> None:
        """Break caught: a failed commit leaks a non-expandable reference."""

        assembly = assembly_module()
        payload = b"f" * 8_192
        store = RecordingStore(fail=True)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "value.bin").write_bytes(payload)
            result = assembly.assemble_evidence(
                evidence_descriptor(payload, "value.bin"),
                root=str(root),
                git_executable=git_executable(),
                store=store,
            )
        self.assertEqual(result.disposition.value, "pass_through")
        self.assertEqual(result.output_bytes, payload)
        self.assertEqual(len(store.calls), 1)

    def test_legacy_assemblers_close_malformed_duck_backend_results(self) -> None:
        """Break caught: legacy paths trust returned fields, namespaces, or uniqueness."""

        assembly = assembly_module()
        evidence_payload = b"e" * 8_192
        blueprint_payloads = (b"a" * 6_000, b"b" * 6_000)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "evidence.bin").write_bytes(evidence_payload)
            (root / "a.bin").write_bytes(blueprint_payloads[0])
            (root / "b.bin").write_bytes(blueprint_payloads[1])
            for mode in (
                "exception",
                "missing_fields",
                "namespace",
                "runtime_getter",
            ):
                with self.subTest(kind="evidence", mode=mode):
                    result = assembly.assemble_evidence(
                        evidence_descriptor(evidence_payload, "evidence.bin"),
                        root=str(root),
                        git_executable=git_executable(),
                        store=MalformedResultStore(mode),
                    )
                    self.assertEqual(result.disposition.value, "pass_through")
                    self.assertEqual(result.output_bytes, evidence_payload)
                    self.assertEqual(result.receipt["reason"], "store_unavailable")
            property_result = assembly.assemble_evidence(
                evidence_descriptor(evidence_payload, "evidence.bin"),
                root=str(root),
                git_executable=git_executable(),
                store=ExplodingIssuePropertyStore(),
            )
            self.assertEqual(property_result.disposition.value, "pass_through")
            self.assertEqual(property_result.output_bytes, evidence_payload)
            self.assertEqual(property_result.receipt["reason"], "store_unavailable")
            for mode in ("missing_fields", "namespace", "duplicate"):
                with self.subTest(kind="blueprint", mode=mode):
                    result = assembly.assemble_blueprint(
                        blueprint_descriptor(
                            blueprint_payloads,
                            ("a.bin", "b.bin"),
                            ("optional_evidence", "optional_evidence"),
                        ),
                        root=str(root),
                        git_executable=git_executable(),
                        store=MalformedResultStore(mode),
                    )
                    self.assertEqual(result.disposition.value, "pass_through")
                    self.assertEqual(result.output_bytes, b"".join(blueprint_payloads))
                    self.assertEqual(result.receipt["reason"], "store_unavailable")

    def test_blueprint_issues_whole_and_items_in_one_batch_with_typed_obligations(self) -> None:
        """Break caught: partial capability publication or free-form blueprint obligations."""

        assembly = assembly_module()
        payloads = (b"a" * 6_000, b"b" * 6_000)
        store = RecordingStore()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, payload in zip(("a.bin", "b.bin"), payloads, strict=True):
                (root / name).write_bytes(payload)
            result = assembly.assemble_blueprint(
                blueprint_descriptor(
                    payloads,
                    ("a.bin", "b.bin"),
                    ("optional_evidence", "optional_evidence"),
                ),
                root=str(root),
                git_executable=git_executable(),
                store=store,
            )

        artifact = parse_canonical_json_bytes(result.output_bytes)
        self.assertEqual(result.disposition.value, "deferred")
        self.assertEqual(len(store.calls), 1)
        self.assertEqual(len(store.calls[0]), 3)
        self.assertEqual(artifact["artifact_kind"], "typed_blueprint")
        self.assertEqual(len(artifact["blueprint"]["obligations"]), 2)
        for obligation in artifact["blueprint"]["obligations"]:
            self.assertEqual(
                obligation["invariants"],
                [
                    "artifact_type_matches",
                    "repository_binding_current",
                    "subject_identity_current",
                ],
            )
            self.assertEqual(
                obligation["tests"],
                [
                    "capability_only_authority",
                    "exact_byte_round_trip",
                    "stale_state_refusal",
                ],
            )
            self.assertEqual(obligation["rollback"], "expand_whole_payload")
            self.assertEqual(obligation["bypass"], "emit_original_payload")
            self.assertNotIn("description", json.dumps(obligation))
        route = result.receipt["route"]
        self.assertEqual(route["predicted_cost_bytes"], len(result.output_bytes))
        self.assertEqual(
            route["wrapper_bytes"]
            + route["handle_bytes"]
            + route["blueprint_bytes"],
            len(result.output_bytes),
        )

    def test_required_whole_payload_cost_prevents_blueprint_store_mutation(self) -> None:
        """Break caught: required-before-use expansion bytes are omitted from routing."""

        assembly = assembly_module()
        payload = b"m" * 8_192
        store = RecordingStore()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "mandatory.bin").write_bytes(payload)
            result = assembly.assemble_blueprint(
                blueprint_descriptor(
                    (payload,),
                    ("mandatory.bin",),
                    ("required_before_edit",),
                ),
                root=str(root),
                git_executable=git_executable(),
                store=store,
            )
        self.assertEqual(result.disposition.value, "pass_through")
        self.assertEqual(result.output_bytes, payload)
        self.assertEqual(store.calls, [])
        self.assertEqual(result.receipt["reason"], "mandatory_expansion_cost")

    def test_deferred_blueprint_cost_equals_wire_plus_mandatory_expansion(self) -> None:
        """Break caught: a beneficial mixed blueprint hides required expansion bytes."""

        assembly = assembly_module()
        payloads = (b"required" * 64, b"optional" * 3_000)
        store = RecordingStore()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "required.bin").write_bytes(payloads[0])
            (root / "optional.bin").write_bytes(payloads[1])
            result = assembly.assemble_blueprint(
                blueprint_descriptor(
                    payloads,
                    ("required.bin", "optional.bin"),
                    ("required_before_claim", "optional_evidence"),
                ),
                root=str(root),
                git_executable=git_executable(),
                store=store,
            )
        self.assertEqual(result.disposition.value, "deferred")
        route = result.receipt["route"]
        self.assertEqual(route["mandatory_expansion_bytes"], len(payloads[0]))
        self.assertEqual(
            route["predicted_cost_bytes"],
            len(result.output_bytes) + len(payloads[0]),
        )
        self.assertEqual(
            route["wrapper_bytes"]
            + route["handle_bytes"]
            + route["blueprint_bytes"],
            len(result.output_bytes),
        )

    def test_oversized_symbol_aggregate_envelope_is_exact_preflight_fallback(self) -> None:
        """Break caught: bounded private metadata raises after routing but before storage."""

        assembly = assembly_module()
        item_payload = b"symbol_body = 42\n" * 350
        payloads = tuple(item_payload for _index in range(16))
        item_hash = hashlib.sha256(item_payload).hexdigest()
        candidates = []
        for index in range(16):
            qualified_name = f"n{index}." + "x" * 990
            candidates.append(
                {
                    "end_byte": len(item_payload),
                    "occurrence": 0,
                    "qualified_name": qualified_name,
                    "raw_range_sha256": item_hash,
                    "start_byte": 0,
                }
            )
        selected_name = candidates[0]["qualified_name"]
        evidence = {
            "candidates": candidates,
            "capped": False,
            "complete": True,
            "deterministic": True,
            "end_byte": len(item_payload),
            "evidence_kind": "caller_supplied_symbol_range",
            "fallback_used": False,
            "language_id": "python",
            "occurrence": 0,
            "parser_error": False,
            "producer_id": "test-parser/1",
            "qualified_name": selected_name,
            "raw_range_sha256": item_hash,
            "scan_complete": True,
            "schema_version": "contextguard-receipt-caller-symbol-evidence/v1",
            "source_sha256": item_hash,
            "start_byte": 0,
        }
        items: list[dict[str, object]] = []
        obligations: list[dict[str, object]] = []
        offset = 0
        for index, payload in enumerate(payloads):
            items.append(
                {
                    "caller_classification": "eligible",
                    "detector_signals": [],
                    "payload_end_byte": offset + len(payload),
                    "payload_start_byte": offset,
                    "source": {
                        "relative_path": f"symbol-{index}.py",
                        "selection": {"evidence": evidence, "kind": "symbol"},
                    },
                }
            )
            obligations.append({"item_index": index, "phase": "optional_evidence"})
            offset += len(payload)
        descriptor = canonical_json_bytes(
            {
                "items": items,
                "obligations": obligations,
                "payload_b64u": b64url(b"".join(payloads)),
                "schema_version": "contextguard-receipt-blueprint-descriptor/v1",
            },
            limits=assembly.DESCRIPTOR_LIMITS,
        )
        store = RecordingStore()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, payload in enumerate(payloads):
                (root / f"symbol-{index}.py").write_bytes(payload)
            result = assembly.assemble_blueprint(
                descriptor,
                root=str(root),
                git_executable=git_executable(),
                store=store,
            )
        self.assertEqual(result.disposition.value, "pass_through")
        self.assertEqual(result.output_bytes, b"".join(payloads))
        self.assertEqual(result.receipt["reason"], "store_unavailable")
        self.assertEqual(store.calls, [])


if __name__ == "__main__":
    unittest.main()
