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
from types import SimpleNamespace


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))

from context_guard_receipt.canonical import canonical_json_bytes, parse_canonical_json_bytes
from context_guard_receipt.identity import identify_source
from context_guard_receipt.store import (
    IssuedCapability,
    StoreError,
    StoreErrorCode,
)


def expansion_module():
    try:
        return importlib.import_module("context_guard_receipt.expansion")
    except ModuleNotFoundError as error:
        raise AssertionError("G005 expansion implementation is missing") from error


def assembly_module():
    return importlib.import_module("context_guard_receipt.assembly")


def git_executable() -> str:
    candidate = shutil.which("git")
    if candidate is None:
        raise unittest.SkipTest("git is unavailable")
    return str(Path(candidate).resolve())


def descriptor(payload: bytes) -> bytes:
    assembly = assembly_module()
    return canonical_json_bytes(
        {
            "caller_classification": "eligible",
            "detector_signals": [],
            "payload_b64u": base64.urlsafe_b64encode(payload)
            .rstrip(b"=")
            .decode("ascii"),
            "schema_version": "contextguard-receipt-evidence-descriptor/v1",
            "source": {
                "relative_path": "source.bin",
                "selection": {"kind": "file"},
            },
        },
        limits=assembly.DESCRIPTOR_LIMITS,
    )


def symbol_descriptor(source_payload: bytes, start: int, end: int) -> bytes:
    assembly = assembly_module()
    selected_payload = source_payload[start:end]
    selected_sha256 = hashlib.sha256(selected_payload).hexdigest()
    evidence = {
        "candidates": [
            {
                "end_byte": end,
                "occurrence": 0,
                "qualified_name": "module.answer",
                "raw_range_sha256": selected_sha256,
                "start_byte": start,
            }
        ],
        "capped": False,
        "complete": True,
        "deterministic": True,
        "end_byte": end,
        "evidence_kind": "caller_supplied_symbol_range",
        "fallback_used": False,
        "language_id": "python",
        "occurrence": 0,
        "parser_error": False,
        "producer_id": "test-parser/1",
        "qualified_name": "module.answer",
        "raw_range_sha256": selected_sha256,
        "scan_complete": True,
        "schema_version": "contextguard-receipt-caller-symbol-evidence/v1",
        "source_sha256": hashlib.sha256(source_payload).hexdigest(),
        "start_byte": start,
    }
    return canonical_json_bytes(
        {
            "caller_classification": "eligible",
            "detector_signals": [],
            "payload_b64u": base64.urlsafe_b64encode(selected_payload)
            .rstrip(b"=")
            .decode("ascii"),
            "schema_version": "contextguard-receipt-evidence-descriptor/v1",
            "source": {
                "relative_path": "source.bin",
                "selection": {"evidence": evidence, "kind": "symbol"},
            },
        },
        limits=assembly.DESCRIPTOR_LIMITS,
    )


class IssuingStore:
    handle = "cgr1p_" + ("Q" * 43)

    def __init__(self) -> None:
        self.request = None

    def issue_batch(self, requests):
        self.request = requests[0]
        return (IssuedCapability(handle=self.handle, namespace_id="a" * 64),)


class ResolvingStore:
    def __init__(self, request, *, reject: bool = False) -> None:
        self.request = request
        self.reject = reject

    def resolve(self, handle: str, *, expected_root_identity_sha256: str):
        if self.reject or handle != IssuingStore.handle:
            raise StoreError(StoreErrorCode.CAPABILITY_REJECTED)
        if expected_root_identity_sha256 != self.request.root_identity_sha256:
            raise StoreError(StoreErrorCode.CAPABILITY_REJECTED)
        return SimpleNamespace(
            artifact_type=self.request.artifact_type,
            byte_length=len(self.request.payload),
            namespace_id="a" * 64,
            payload=self.request.payload,
            payload_sha256="0" * 64,
            root_identity_sha256=self.request.root_identity_sha256,
            subject_identity_sha256=self.request.subject_identity_sha256,
        )


class ExplodingResolvingStore:
    def __init__(self, error: Exception) -> None:
        self.error = error

    def resolve(self, handle: str, *, expected_root_identity_sha256: str):
        raise self.error


class ExplodingResolvePropertyStore:
    @property
    def resolve(self):
        raise RuntimeError("private backend property")


class RuntimeGetterResolvingStore:
    def resolve(self, handle: str, *, expected_root_identity_sha256: str):
        class RuntimeGetterStored:
            @property
            def payload(self):
                raise RuntimeError("backend-private-detail")

        return RuntimeGetterStored()


class G005ExpansionTests(unittest.TestCase):
    def issue_evidence(self, root: Path, payload: bytes):
        assembly = assembly_module()
        issuing = IssuingStore()
        result = assembly.assemble_evidence(
            descriptor(payload),
            root=str(root),
            git_executable=git_executable(),
            store=issuing,
        )
        self.assertEqual(result.disposition.value, "deferred")
        self.assertIsNotNone(issuing.request)
        return issuing

    def test_capability_alone_rehydrates_exact_non_utf8_bytes(self) -> None:
        """Break caught: expansion needs caller paths/hashes or transforms stored bytes."""

        expansion = expansion_module()
        payload = (b"\x00\xff\r\n" * 2_048)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.bin").write_bytes(payload)
            issued = self.issue_evidence(root, payload)
            result = expansion.expand_capability(
                issued.handle,
                root=str(root),
                git_executable=git_executable(),
                store=ResolvingStore(issued.request),
            )
        self.assertEqual(result.disposition.value, "exact")
        self.assertEqual(result.output_bytes, payload)
        self.assertIsNone(result.refusal)

    def test_g003_symbol_evidence_defer_and_expands_exact_selected_bytes(self) -> None:
        """Break caught: G005 invents a symbol shape that G003 cannot identify."""

        assembly = assembly_module()
        expansion = expansion_module()
        selected = b"answer = 42\n" * 700
        source_payload = b"prefix\n" + selected + b"suffix\n"
        start = len(b"prefix\n")
        end = start + len(selected)
        issuing = IssuingStore()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.bin").write_bytes(source_payload)
            descriptor_raw = symbol_descriptor(source_payload, start, end)
            descriptor_document = parse_canonical_json_bytes(descriptor_raw)
            identified = identify_source(
                root,
                "source.bin",
                byte_range=(start, end),
                symbol_evidence=descriptor_document["source"]["selection"]["evidence"],
                git_executable=git_executable(),
            )
            assembled = assembly.assemble_evidence(
                descriptor_raw,
                root=str(root),
                git_executable=git_executable(),
                store=issuing,
            )
            self.assertEqual(assembled.disposition.value, "deferred")
            artifact = parse_canonical_json_bytes(assembled.output_bytes)
            self.assertEqual(
                artifact["subject_identity_sha256"],
                identified["symbol"]["identity_sha256"],
            )
            expanded = expansion.expand_capability(
                issuing.handle,
                root=str(root),
                git_executable=git_executable(),
                store=ResolvingStore(issuing.request),
            )
        self.assertEqual(expanded.disposition.value, "exact")
        self.assertEqual(expanded.output_bytes, selected)

    def test_source_drift_returns_closed_stale_refusal_without_bytes(self) -> None:
        """Break caught: an old capability bypasses current source/state validation."""

        expansion = expansion_module()
        payload = b"before" * 1_400
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.bin"
            source.write_bytes(payload)
            issued = self.issue_evidence(root, payload)
            source.write_bytes(b"after" * 1_400)
            result = expansion.expand_capability(
                issued.handle,
                root=str(root),
                git_executable=git_executable(),
                store=ResolvingStore(issued.request),
            )
        self.assertEqual(result.disposition.value, "stale")
        self.assertEqual(result.output_bytes, b"")
        self.assertEqual(
            set(result.refusal),
            {"artifact_kind", "evidence_boundary", "reason", "schema_version", "status"},
        )
        self.assertEqual(result.refusal["status"], "stale")
        serialized = json.dumps(result.refusal, sort_keys=True)
        self.assertNotIn("source.bin", serialized)
        self.assertNotIn(issued.handle, serialized)

    def test_forged_capability_has_one_non_oracular_refusal(self) -> None:
        """Break caught: forged and absent handles become a binding or existence oracle."""

        expansion = expansion_module()
        payload = b"authority" * 1_024
        forged = "cgr1p_" + ("Z" * 43)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.bin").write_bytes(payload)
            issued = self.issue_evidence(root, payload)
            result = expansion.expand_capability(
                forged,
                root=str(root),
                git_executable=git_executable(),
                store=ResolvingStore(issued.request, reject=True),
            )
        self.assertEqual(result.disposition.value, "refused")
        self.assertEqual(result.output_bytes, b"")
        self.assertEqual(result.refusal["reason"], "capability_rejected")
        self.assertNotIn(forged, json.dumps(result.refusal, sort_keys=True))

    def test_missing_or_failing_resolution_backend_is_closed(self) -> None:
        """Break caught: duck-backend failures leak internal exceptions or details."""

        expansion = expansion_module()
        handle = "cgr1p_" + "A" * 43
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for store in (
                object(),
                ExplodingResolvePropertyStore(),
                ExplodingResolvingStore(RuntimeError("private detail")),
                ExplodingResolvingStore(OSError("private path")),
            ):
                with self.subTest(store_type=type(store).__name__):
                    result = expansion.expand_capability(
                        handle,
                        root=str(root),
                        git_executable=git_executable(),
                        store=store,
                    )
                    self.assertEqual(result.disposition.value, "refused")
                    self.assertEqual(result.output_bytes, b"")
                    self.assertEqual(result.refusal["reason"], "store_unavailable")
                    rendered = json.dumps(result.refusal, sort_keys=True)
                    self.assertNotIn("private", rendered)
                    self.assertNotIn(handle, rendered)

    def test_malformed_capabilities_are_rejected_before_backend_lookup(self) -> None:
        """Break caught: malformed authority reaches a duck backend or gets reflected."""

        expansion = expansion_module()

        class MustNotResolve:
            def resolve(self, handle: str, *, expected_root_identity_sha256: str):
                raise AssertionError("malformed handle reached backend")

        with tempfile.TemporaryDirectory() as directory:
            for malformed in ("bad", "cgr1p_" + "!" * 43, object()):
                with self.subTest(malformed_type=type(malformed).__name__):
                    result = expansion.expand_capability(
                        malformed,
                        root=directory,
                        git_executable=git_executable(),
                        store=MustNotResolve(),
                    )
                    self.assertEqual(result.disposition.value, "refused")
                    self.assertEqual(result.refusal["reason"], "capability_rejected")
                    self.assertEqual(result.output_bytes, b"")

    def test_stored_artifact_runtime_getter_is_a_closed_invalid_artifact(self) -> None:
        """Break caught: post-resolve result interrogation leaks backend exceptions."""

        expansion = expansion_module()
        handle = "cgr1p_" + "A" * 43
        with tempfile.TemporaryDirectory() as directory:
            result = expansion.expand_capability(
                handle,
                root=directory,
                git_executable=git_executable(),
                store=RuntimeGetterResolvingStore(),
            )
        self.assertEqual(result.disposition.value, "refused")
        self.assertEqual(result.output_bytes, b"")
        self.assertEqual(result.refusal["reason"], "artifact_invalid")
        self.assertNotIn("backend-private-detail", json.dumps(result.refusal))


if __name__ == "__main__":
    unittest.main()
