from __future__ import annotations

import base64
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
from context_guard_receipt.store import IssuedCapability, StoreError, StoreErrorCode


def assembly_module():
    return importlib.import_module("context_guard_receipt.assembly")


def expansion_module():
    return importlib.import_module("context_guard_receipt.expansion")


def git_executable() -> str:
    candidate = shutil.which("git")
    if candidate is None:
        raise unittest.SkipTest("git is unavailable")
    return str(Path(candidate).resolve())


def b64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


def pack_descriptor(
    payloads: tuple[bytes, ...],
    relative_paths: tuple[str, ...],
    modes: tuple[str, ...],
    classifications: tuple[str, ...],
    detector_signals: tuple[tuple[str, ...], ...] | None = None,
) -> bytes:
    assembly = assembly_module()
    if detector_signals is None:
        detector_signals = tuple(() for _payload in payloads)
    offset = 0
    ranges: list[dict[str, object]] = []
    for payload, relative_path, mode, classification, signals in zip(
        payloads,
        relative_paths,
        modes,
        classifications,
        detector_signals,
        strict=True,
    ):
        ranges.append(
            {
                "caller_classification": classification,
                "detector_signals": list(signals),
                "end_byte": offset + len(payload),
                "mode": mode,
                "source": {
                    "relative_path": relative_path,
                    "selection": {"kind": "file"},
                },
                "start_byte": offset,
            }
        )
        offset += len(payload)
    return canonical_json_bytes(
        {
            "payload_b64u": b64url(b"".join(payloads)),
            "ranges": ranges,
            "schema_version": "contextguard-receipt-evidence-pack-descriptor/v1",
        },
        limits=assembly.DESCRIPTOR_LIMITS,
    )


class RecordingStore:
    def __init__(self, *, fail: bool = False) -> None:
        self.calls: list[tuple[object, ...]] = []
        self.fail = fail
        self.requests_by_handle: dict[str, object] = {}

    def issue_batch(self, requests: tuple[object, ...]) -> tuple[IssuedCapability, ...]:
        self.calls.append(requests)
        if self.fail:
            raise StoreError(StoreErrorCode.WRITE_FAILED)
        issued: list[IssuedCapability] = []
        for index, request in enumerate(requests):
            handle = "cgr1p_" + chr(ord("A") + index) * 43
            self.requests_by_handle[handle] = request
            issued.append(IssuedCapability(handle=handle, namespace_id="a" * 64))
        return tuple(issued)

    def resolve(self, handle: str, *, expected_root_identity_sha256: str):
        request = self.requests_by_handle.get(handle)
        if request is None or request.root_identity_sha256 != expected_root_identity_sha256:
            raise StoreError(StoreErrorCode.CAPABILITY_REJECTED)
        return SimpleNamespace(
            artifact_type=request.artifact_type,
            byte_length=len(request.payload),
            namespace_id="a" * 64,
            payload=request.payload,
            payload_sha256="0" * 64,
            root_identity_sha256=request.root_identity_sha256,
            subject_identity_sha256=request.subject_identity_sha256,
        )


class MalformedStore(RecordingStore):
    def __init__(self, malformed: str) -> None:
        super().__init__()
        self.malformed = malformed

    def issue_batch(self, requests: tuple[object, ...]):
        self.calls.append(requests)
        if self.malformed == "count":
            return ()
        if self.malformed == "handle":
            return (IssuedCapability(handle="not-a-capability", namespace_id="a" * 64),)
        return (IssuedCapability(handle="cgr1p_" + "A" * 43, namespace_id="bad"),)


class ExplodingStore(RecordingStore):
    def __init__(self, error: Exception) -> None:
        super().__init__()
        self.error = error

    def issue_batch(self, requests: tuple[object, ...]):
        self.calls.append(requests)
        raise self.error


class G005EvidencePackTests(unittest.TestCase):
    def test_evidence_entrypoint_dispatches_the_closed_pack_version(self) -> None:
        """Break caught: the shared evidence descriptor schema has no runtime dispatch."""

        assembly = assembly_module()
        payload = b"d" * 511
        result = assembly.assemble_evidence(
            pack_descriptor(
                (payload,),
                ("missing.bin",),
                ("deferred",),
                ("eligible",),
            ),
            root="/does/not/matter",
            git_executable=git_executable(),
            store=RecordingStore(),
        )
        self.assertEqual(result.disposition.value, "pass_through")
        self.assertEqual(result.output_bytes, payload)
        self.assertEqual(result.receipt["reason"], "input_too_small")

    def test_mixed_pack_retains_caller_selected_bytes_and_defers_eligible_range(self) -> None:
        """Break caught: caller-selected exact retained bytes are dropped or stored."""

        assembly = assembly_module()
        expansion = expansion_module()
        retained = b"retained\x00bytes" * 64
        deferred = b"eligible\xffbytes" * 700
        payload = retained + deferred
        store = RecordingStore()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "deferred.bin").write_bytes(deferred)
            result = assembly.assemble_evidence_pack(
                pack_descriptor(
                    (retained, deferred),
                    ("must-not-be-read.bin", "deferred.bin"),
                    ("retained", "deferred"),
                    ("eligible", "eligible"),
                ),
                root=str(root),
                git_executable=git_executable(),
                store=store,
            )
            artifact = parse_canonical_json_bytes(result.output_bytes)
            deferred_result = expansion.expand_capability(
                artifact["segments"][1]["capability"],
                root=str(root),
                git_executable=git_executable(),
                store=store,
            )

        self.assertEqual(result.disposition.value, "deferred")
        self.assertEqual(len(store.calls), 1)
        self.assertEqual(len(store.calls[0]), 1)
        self.assertEqual(artifact["artifact_kind"], "evidence_pack")
        self.assertEqual([item["kind"] for item in artifact["segments"]], ["retained", "deferred"])
        self.assertEqual(
            base64.urlsafe_b64decode(artifact["segments"][0]["payload_b64u"] + "=="),
            retained,
        )
        self.assertEqual(deferred_result.disposition.value, "exact")
        self.assertEqual(deferred_result.output_bytes, deferred)
        self.assertEqual(
            base64.urlsafe_b64decode(artifact["segments"][0]["payload_b64u"] + "==")
            + deferred_result.output_bytes,
            payload,
        )
        route = result.receipt["route"]
        self.assertEqual(route["predicted_cost_bytes"], len(result.output_bytes))
        self.assertEqual(route["retained_wire_bytes"], len(b64url(retained)))
        self.assertEqual(
            route["wrapper_bytes"]
            + route["handle_bytes"]
            + route["retained_wire_bytes"],
            len(result.output_bytes),
        )

    def test_protected_or_exact_required_range_forces_whole_exact_pass_through(self) -> None:
        """Break caught: a protected range is wrapped or another range is stored."""

        assembly = assembly_module()
        payloads = (b"a" * 4_096, b"b" * 4_096)
        for classification in ("protected", "exact_required", "unknown"):
            with self.subTest(classification=classification):
                store = RecordingStore()
                result = assembly.assemble_evidence_pack(
                    pack_descriptor(
                        payloads,
                        ("missing-a.bin", "missing-b.bin"),
                        ("retained", "deferred"),
                        ("eligible", classification),
                    ),
                    root="/does/not/matter",
                    git_executable=git_executable(),
                    store=store,
                )
                self.assertEqual(result.disposition.value, "pass_through")
                self.assertEqual(result.output_bytes, b"".join(payloads))
                self.assertEqual(result.receipt["reason"], classification)
                self.assertEqual(store.calls, [])

    def test_secret_signal_is_a_global_closed_refusal_without_store(self) -> None:
        """Break caught: a secret range is retained inline or issued as a capability."""

        assembly = assembly_module()
        payloads = (b"a" * 4_096, b"secret" * 700)
        store = RecordingStore()
        result = assembly.assemble_evidence_pack(
            pack_descriptor(
                payloads,
                ("missing-a.bin", "missing-secret.bin"),
                ("retained", "deferred"),
                ("eligible", "eligible"),
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

    def test_two_deferred_ranges_publish_in_one_atomic_batch(self) -> None:
        """Break caught: progressive ranges publish capabilities in separate commits."""

        assembly = assembly_module()
        payloads = (b"a" * 6_000, b"b" * 6_000)
        store = RecordingStore()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.bin").write_bytes(payloads[0])
            (root / "b.bin").write_bytes(payloads[1])
            result = assembly.assemble_evidence_pack(
                pack_descriptor(
                    payloads,
                    ("a.bin", "b.bin"),
                    ("deferred", "deferred"),
                    ("eligible", "eligible"),
                ),
                root=str(root),
                git_executable=git_executable(),
                store=store,
            )

        artifact = parse_canonical_json_bytes(result.output_bytes)
        self.assertEqual(result.disposition.value, "deferred")
        self.assertEqual(len(store.calls), 1)
        self.assertEqual(len(store.calls[0]), 2)
        self.assertEqual([item["kind"] for item in artifact["segments"]], ["deferred", "deferred"])

    def test_threshold_failure_returns_exact_original_before_identity_or_store(self) -> None:
        """Break caught: a small pack performs source I/O or durable mutation before routing."""

        assembly = assembly_module()
        payload = b"s" * 511
        store = RecordingStore()
        result = assembly.assemble_evidence_pack(
            pack_descriptor(
                (payload,),
                ("missing.bin",),
                ("deferred",),
                ("eligible",),
            ),
            root="/does/not/matter",
            git_executable=git_executable(),
            store=store,
        )
        self.assertEqual(result.disposition.value, "pass_through")
        self.assertEqual(result.output_bytes, payload)
        self.assertEqual(result.receipt["reason"], "input_too_small")
        self.assertEqual(store.calls, [])

    def test_deferred_source_mismatch_returns_exact_original_without_store(self) -> None:
        """Break caught: a range capability is issued for caller bytes not in its source."""

        assembly = assembly_module()
        payload = b"descriptor" * 1_024
        store = RecordingStore()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.bin").write_bytes(b"different" * 1_024)
            result = assembly.assemble_evidence_pack(
                pack_descriptor(
                    (payload,),
                    ("source.bin",),
                    ("deferred",),
                    ("eligible",),
                ),
                root=str(root),
                git_executable=git_executable(),
                store=store,
            )
        self.assertEqual(result.disposition.value, "pass_through")
        self.assertEqual(result.output_bytes, payload)
        self.assertEqual(result.receipt["reason"], "identity_mismatch")
        self.assertEqual(store.calls, [])

    def test_invalid_coverage_is_closed_and_never_reaches_store(self) -> None:
        """Break caught: gaps, overlaps, or reordered ranges create ambiguous reconstruction."""

        assembly = assembly_module()
        payload = b"x" * 2_048
        invalid_ranges = (
            ((0, 1_000), (1_001, 2_048)),
            ((0, 1_100), (1_000, 2_048)),
            ((1_024, 2_048), (0, 1_024)),
        )
        for ranges in invalid_ranges:
            with self.subTest(ranges=ranges):
                store = RecordingStore()
                document = parse_canonical_json_bytes(
                    pack_descriptor(
                        (payload[:1_024], payload[1_024:]),
                        ("a.bin", "b.bin"),
                        ("deferred", "deferred"),
                        ("eligible", "eligible"),
                    )
                )
                for item, (start, end) in zip(document["ranges"], ranges, strict=True):
                    item["start_byte"] = start
                    item["end_byte"] = end
                raw = canonical_json_bytes(document, limits=assembly.DESCRIPTOR_LIMITS)
                with self.assertRaises(assembly.AssemblyError) as caught:
                    assembly.assemble_evidence_pack(
                        raw,
                        root="/does/not/matter",
                        git_executable=git_executable(),
                        store=store,
                    )
                self.assertEqual(caught.exception.code, "invalid_descriptor")
                self.assertEqual(store.calls, [])

    def test_store_failure_and_missing_backend_preserve_exact_original(self) -> None:
        """Break caught: backend failures leak an unusable partial pack."""

        assembly = assembly_module()
        payload = b"f" * 8_192
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.bin").write_bytes(payload)
            for store in (RecordingStore(fail=True), object()):
                with self.subTest(store_type=type(store).__name__):
                    result = assembly.assemble_evidence_pack(
                        pack_descriptor(
                            (payload,),
                            ("source.bin",),
                            ("deferred",),
                            ("eligible",),
                        ),
                        root=str(root),
                        git_executable=git_executable(),
                        store=store,
                    )
                    self.assertEqual(result.disposition.value, "pass_through")
                    self.assertEqual(result.output_bytes, payload)
                    self.assertEqual(result.receipt["reason"], "store_unavailable")

    def test_malformed_batch_return_falls_back_without_emitting_a_pack(self) -> None:
        """Break caught: a malformed backend result becomes a public capability."""

        assembly = assembly_module()
        payload = b"m" * 8_192
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.bin").write_bytes(payload)
            for malformed in ("count", "handle", "namespace"):
                with self.subTest(malformed=malformed):
                    store = MalformedStore(malformed)
                    result = assembly.assemble_evidence_pack(
                        pack_descriptor(
                            (payload,),
                            ("source.bin",),
                            ("deferred",),
                            ("eligible",),
                        ),
                        root=str(root),
                        git_executable=git_executable(),
                        store=store,
                    )
                    self.assertEqual(result.disposition.value, "pass_through")
                    self.assertEqual(result.output_bytes, payload)
                    self.assertEqual(result.receipt["reason"], "store_unavailable")

    def test_backend_exceptions_are_stable_exact_fallbacks(self) -> None:
        """Break caught: a duck backend leaks an internal exception or traceback."""

        assembly = assembly_module()
        payload = b"backend" * 1_200
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.bin").write_bytes(payload)
            for error in (
                RuntimeError("private detail"),
                OSError("private path"),
                AttributeError("private attribute"),
            ):
                with self.subTest(error_type=type(error).__name__):
                    result = assembly.assemble_evidence_pack(
                        pack_descriptor(
                            (payload,),
                            ("source.bin",),
                            ("deferred",),
                            ("eligible",),
                        ),
                        root=str(root),
                        git_executable=git_executable(),
                        store=ExplodingStore(error),
                    )
                    self.assertEqual(result.disposition.value, "pass_through")
                    self.assertEqual(result.output_bytes, payload)
                    self.assertEqual(result.receipt["reason"], "store_unavailable")

    def test_empty_zero_length_extra_key_and_invalid_mode_are_closed(self) -> None:
        """Break caught: malformed range shapes reach policy, identity, or storage."""

        assembly = assembly_module()
        payload = b"x" * 2_048
        valid = parse_canonical_json_bytes(
            pack_descriptor(
                (payload,),
                ("source.bin",),
                ("deferred",),
                ("eligible",),
            )
        )
        cases: list[dict[str, object]] = []
        empty = dict(valid)
        empty["ranges"] = []
        cases.append(empty)
        zero = parse_canonical_json_bytes(
            canonical_json_bytes(valid, limits=assembly.DESCRIPTOR_LIMITS)
        )
        zero["ranges"][0]["end_byte"] = 0
        cases.append(zero)
        extra = parse_canonical_json_bytes(
            canonical_json_bytes(valid, limits=assembly.DESCRIPTOR_LIMITS)
        )
        extra["ranges"][0]["attacker_claim"] = "ignored"
        cases.append(extra)
        invalid_mode = parse_canonical_json_bytes(
            canonical_json_bytes(valid, limits=assembly.DESCRIPTOR_LIMITS)
        )
        invalid_mode["ranges"][0]["mode"] = "archive"
        cases.append(invalid_mode)

        for document in cases:
            with self.subTest(document=document):
                store = RecordingStore()
                with self.assertRaises(assembly.AssemblyError) as caught:
                    assembly.assemble_evidence_pack(
                        canonical_json_bytes(document, limits=assembly.DESCRIPTOR_LIMITS),
                        root="/does/not/matter",
                        git_executable=git_executable(),
                        store=store,
                    )
                self.assertEqual(caught.exception.code, "invalid_descriptor")
                self.assertNotIn("attacker_claim", str(caught.exception))
                self.assertEqual(store.calls, [])

    def test_deferred_pack_capability_becomes_stale_after_source_drift(self) -> None:
        """Break caught: pack-issued ranges skip the expansion revalidation contract."""

        assembly = assembly_module()
        expansion = expansion_module()
        payload = b"before" * 1_400
        store = RecordingStore()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "private-source-name.bin"
            source.write_bytes(payload)
            assembled = assembly.assemble_evidence_pack(
                pack_descriptor(
                    (payload,),
                    (source.name,),
                    ("deferred",),
                    ("eligible",),
                ),
                root=str(root),
                git_executable=git_executable(),
                store=store,
            )
            artifact = parse_canonical_json_bytes(assembled.output_bytes)
            source.write_bytes(b"after" * 1_400)
            expanded = expansion.expand_capability(
                artifact["segments"][0]["capability"],
                root=str(root),
                git_executable=git_executable(),
                store=store,
            )
        self.assertEqual(expanded.disposition.value, "stale")
        self.assertEqual(expanded.output_bytes, b"")
        self.assertNotIn(source.name, json.dumps(expanded.refusal, sort_keys=True))
        self.assertNotIn(source.name, json.dumps(assembled.receipt, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
