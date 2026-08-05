from __future__ import annotations

import base64
import hashlib
import inspect
import json
import logging
import shutil
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))

from context_guard_receipt import assembly, expansion
from context_guard_receipt.canonical import canonical_json_bytes
from context_guard_receipt.identity import snapshot_repository
from context_guard_receipt.store import (
    ArtifactType,
    IssuedCapability,
    StoreError,
    StoreErrorCode,
    StoredArtifact,
)


HANDLE = "cgr1p_" + "H" * 43
COMMAND_SUBJECT_DOMAIN = "contextguard-receipt/command-capture-subject/v1"
STORE_PAYLOAD_DOMAIN = "contextguard-receipt/store-payload/v1"


def git_executable() -> str:
    candidate = shutil.which("git")
    if candidate is None:
        raise unittest.SkipTest("git is unavailable")
    return str(Path(candidate).resolve())


def framed_digest(domain: str, payload: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(domain.encode("ascii"))
    digest.update(b"\x00")
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)
    return digest.hexdigest()


def frame(sequence: int, channel: int, payload: bytes) -> bytes:
    return (
        sequence.to_bytes(8, "big")
        + channel.to_bytes(1, "big")
        + len(payload).to_bytes(4, "big")
        + payload
    )


def canonical_capture() -> bytes:
    return b"CGRF1\x00" + frame(0, 1, b"stdout\x00\xff\n") + frame(1, 2, b"stderr\x80\n")


def root_identity(root: Path) -> str:
    snapshot = snapshot_repository(str(root), git_executable=git_executable())
    return snapshot["instance"]["identity_sha256"]


def stored_command(root: Path, payload: bytes | None = None) -> StoredArtifact:
    framed = canonical_capture() if payload is None else payload
    return StoredArtifact(
        artifact_type=ArtifactType.COMMAND_CAPTURE_BYTES,
        byte_length=len(framed),
        namespace_id="a" * 64,
        payload=framed,
        payload_sha256=framed_digest(STORE_PAYLOAD_DOMAIN, framed),
        root_identity_sha256=root_identity(root),
        subject_identity_sha256=framed_digest(COMMAND_SUBJECT_DOMAIN, framed),
    )


class ResolvingStore:
    def __init__(self, artifact: StoredArtifact, *, reject: bool = False) -> None:
        self.artifact = artifact
        self.reject = reject
        self.calls: list[tuple[str, str]] = []

    def resolve(self, handle: str, *, expected_root_identity_sha256: str):
        self.calls.append((handle, expected_root_identity_sha256))
        if (
            self.reject
            or handle != HANDLE
            or expected_root_identity_sha256 != self.artifact.root_identity_sha256
        ):
            raise StoreError(StoreErrorCode.CAPABILITY_REJECTED)
        return self.artifact


class IssuingResolvingStore:
    def __init__(self) -> None:
        self.requests: dict[str, object] = {}

    def issue_batch(self, requests):
        issued = []
        for index, request in enumerate(requests):
            handle = "cgr1p_" + chr(ord("A") + index) * 43
            self.requests[handle] = request
            issued.append(IssuedCapability(handle=handle, namespace_id="a" * 64))
        return tuple(issued)

    def resolve(self, handle: str, *, expected_root_identity_sha256: str):
        request = self.requests.get(handle)
        if (
            request is None
            or request.root_identity_sha256 != expected_root_identity_sha256
        ):
            raise StoreError(StoreErrorCode.CAPABILITY_REJECTED)
        return StoredArtifact(
            artifact_type=request.artifact_type,
            byte_length=len(request.payload),
            namespace_id="a" * 64,
            payload=request.payload,
            payload_sha256=framed_digest(STORE_PAYLOAD_DOMAIN, request.payload),
            root_identity_sha256=request.root_identity_sha256,
            subject_identity_sha256=request.subject_identity_sha256,
        )


def b64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


def evidence_descriptor(payload: bytes) -> bytes:
    return canonical_json_bytes(
        {
            "caller_classification": "eligible",
            "detector_signals": [],
            "payload_b64u": b64url(payload),
            "schema_version": "contextguard-receipt-evidence-descriptor/v1",
            "source": {
                "relative_path": "raw.bin",
                "selection": {"kind": "file"},
            },
        },
        limits=assembly.DESCRIPTOR_LIMITS,
    )


def blueprint_descriptor(payload: bytes) -> bytes:
    return canonical_json_bytes(
        {
            "items": [
                {
                    "caller_classification": "eligible",
                    "detector_signals": [],
                    "payload_end_byte": len(payload),
                    "payload_start_byte": 0,
                    "source": {
                        "relative_path": "blueprint.bin",
                        "selection": {"kind": "file"},
                    },
                }
            ],
            "obligations": [{"item_index": 0, "phase": "optional_evidence"}],
            "payload_b64u": b64url(payload),
            "schema_version": "contextguard-receipt-blueprint-descriptor/v1",
        },
        limits=assembly.DESCRIPTOR_LIMITS,
    )


class RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


class G008ExpansionContractTests(unittest.TestCase):
    def test_handle_only_expands_exact_canonical_command_capture(self) -> None:
        """Break caught: COMMAND_CAPTURE_BYTES is mistaken for a source envelope."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = stored_command(root)
            store = ResolvingStore(artifact)
            result = expansion.expand_capability(
                HANDLE,
                root=str(root),
                store=store,
                git_executable=git_executable(),
            )

        self.assertEqual(result.disposition, expansion.ExpansionDisposition.EXACT)
        self.assertEqual(result.output_bytes, canonical_capture())
        self.assertIsNone(result.refusal)
        self.assertEqual(store.calls, [(HANDLE, artifact.root_identity_sha256)])
        parameters = inspect.signature(expansion.expand_capability).parameters
        self.assertEqual(tuple(parameters), ("handle", "root", "store", "git_executable"))
        for forbidden in ("artifact_type", "subject_identity_sha256", "namespace_id"):
            self.assertNotIn(forbidden, parameters)

    def test_worktree_drift_does_not_stale_a_historical_command_capture(self) -> None:
        """Break caught: command expansion compares the current logical state or source."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "tracked.txt"
            source.write_text("before", encoding="utf-8")
            artifact = stored_command(root)
            store = ResolvingStore(artifact)
            source.write_text("after", encoding="utf-8")
            (root / "later.txt").write_text("new", encoding="utf-8")

            result = expansion.expand_capability(
                HANDLE,
                root=str(root),
                store=store,
                git_executable=git_executable(),
            )

        self.assertEqual(result.disposition, expansion.ExpansionDisposition.EXACT)
        self.assertEqual(result.output_bytes, artifact.payload)

    def test_repository_instance_replacement_and_forged_handle_are_rejected(self) -> None:
        """Break caught: expansion binds to a path or caller claim instead of current identity."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "repository"
            root.mkdir()
            artifact = stored_command(root)
            store = ResolvingStore(artifact)
            original = base / "original"
            root.rename(original)
            root.mkdir()

            replaced = expansion.expand_capability(
                HANDLE,
                root=str(root),
                store=store,
                git_executable=git_executable(),
            )
            forged = expansion.expand_capability(
                "cgr1p_" + "Z" * 43,
                root=str(root),
                store=ResolvingStore(artifact, reject=True),
                git_executable=git_executable(),
            )

        for result in (replaced, forged):
            self.assertEqual(result.disposition, expansion.ExpansionDisposition.REFUSED)
            self.assertEqual(result.output_bytes, b"")
            self.assertEqual(result.refusal["reason"], "capability_rejected")

    def test_repository_instance_swap_during_resolution_is_stale(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "repository"
            root.mkdir()
            artifact = stored_command(root)

            class SwappingStore(ResolvingStore):
                def resolve(self, handle: str, *, expected_root_identity_sha256: str):
                    resolved = super().resolve(
                        handle,
                        expected_root_identity_sha256=expected_root_identity_sha256,
                    )
                    root.rename(base / "original")
                    root.mkdir()
                    return resolved

            result = expansion.expand_capability(
                HANDLE,
                root=str(root),
                store=SwappingStore(artifact),
                git_executable=git_executable(),
            )

        self.assertEqual(result.disposition, expansion.ExpansionDisposition.STALE)
        self.assertEqual(result.output_bytes, b"")
        self.assertEqual(result.refusal["reason"], "root_unavailable")

    def test_invalid_magic_sequence_channel_length_truncation_and_trailing_bytes_close(self) -> None:
        """Break caught: malformed or noncanonical CGRF bytes escape exact validation."""

        valid = b"CGRF1\x00" + frame(0, 1, b"safe")
        noncanonical = b"CGRF1\x00" + frame(0, 1, b"a") + frame(1, 1, b"b")
        variants = {
            "magic": b"BGRF1\x00" + valid[6:],
            "sequence": valid[:6] + (1).to_bytes(8, "big") + valid[14:],
            "channel": valid[:14] + b"\x03" + valid[15:],
            "zero_length": valid[:15] + (0).to_bytes(4, "big") + valid[19:],
            "oversized_length": valid[:15] + (4097).to_bytes(4, "big") + valid[19:],
            "truncation": valid[:-1],
            "trailing": valid + b"x",
            "noncanonical": noncanonical,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, payload in variants.items():
                with self.subTest(name=name):
                    result = expansion.expand_capability(
                        HANDLE,
                        root=str(root),
                        store=ResolvingStore(stored_command(root, payload)),
                        git_executable=git_executable(),
                    )
                    self.assertEqual(result.disposition, expansion.ExpansionDisposition.REFUSED)
                    self.assertEqual(result.output_bytes, b"")
                    self.assertEqual(result.refusal["reason"], "artifact_invalid")

    def test_wrong_type_subject_and_tampered_payload_close_without_output(self) -> None:
        """Break caught: caller-visible bytes or metadata override the sealed artifact fields."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = stored_command(root)
            tampered_payload = original.payload[:-2] + b"X\n"
            variants = {
                "type": replace(original, artifact_type=ArtifactType.RAW_EVIDENCE_BYTES),
                "subject": replace(original, subject_identity_sha256="0" * 64),
                "payload": replace(
                    original,
                    payload=tampered_payload,
                    payload_sha256=framed_digest(STORE_PAYLOAD_DOMAIN, tampered_payload),
                ),
                "length": replace(original, byte_length=original.byte_length + 1),
            }
            for name, artifact in variants.items():
                with self.subTest(name=name):
                    result = expansion.expand_capability(
                        HANDLE,
                        root=str(root),
                        store=ResolvingStore(artifact),
                        git_executable=git_executable(),
                    )
                    self.assertEqual(result.disposition, expansion.ExpansionDisposition.REFUSED)
                    self.assertEqual(result.output_bytes, b"")
                    self.assertEqual(result.refusal["reason"], "artifact_invalid")

    def test_raw_and_blueprint_source_current_expansion_remain_unchanged(self) -> None:
        """Break caught: command dispatch bypasses the G005 source-current envelope flow."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw_payload = b"raw-evidence\x00" * 1_000
            (root / "raw.bin").write_bytes(raw_payload)
            raw_store = IssuingResolvingStore()
            raw_result = assembly.assemble_evidence(
                evidence_descriptor(raw_payload),
                root=str(root),
                store=raw_store,
                git_executable=git_executable(),
            )
            self.assertEqual(raw_result.disposition.value, "deferred")
            raw_handle = next(iter(raw_store.requests))
            raw_expanded = expansion.expand_capability(
                raw_handle,
                root=str(root),
                store=raw_store,
                git_executable=git_executable(),
            )

            blueprint_payload = b"blueprint-item\xff" * 2_000
            (root / "blueprint.bin").write_bytes(blueprint_payload)
            blueprint_store = IssuingResolvingStore()
            blueprint_result = assembly.assemble_blueprint(
                blueprint_descriptor(blueprint_payload),
                root=str(root),
                store=blueprint_store,
                git_executable=git_executable(),
            )
            self.assertEqual(blueprint_result.disposition.value, "deferred")
            whole_handle = next(iter(blueprint_store.requests))
            blueprint_expanded = expansion.expand_capability(
                whole_handle,
                root=str(root),
                store=blueprint_store,
                git_executable=git_executable(),
            )

        self.assertEqual(raw_expanded.disposition, expansion.ExpansionDisposition.EXACT)
        self.assertEqual(raw_expanded.output_bytes, raw_payload)
        self.assertEqual(
            blueprint_expanded.disposition, expansion.ExpansionDisposition.EXACT
        )
        self.assertEqual(blueprint_expanded.output_bytes, blueprint_payload)

    def test_refusals_repr_and_logs_do_not_leak_private_inputs(self) -> None:
        """Break caught: backend exceptions or stored getters reflect private command data."""

        secrets = (
            "SECRET_RECEIPT",
            "SECRET_ARGV",
            "SECRET_PATH",
            "SECRET_PAYLOAD",
        )

        class HostileArtifact:
            artifact_type = ArtifactType.COMMAND_CAPTURE_BYTES

            @property
            def payload(self):
                raise RuntimeError("|".join(secrets))

        class HostileStore:
            def resolve(self, handle: str, *, expected_root_identity_sha256: str):
                return HostileArtifact()

        handler = RecordingHandler()
        package_logger = logging.getLogger("context_guard_receipt")
        previous_level = package_logger.level
        package_logger.setLevel(logging.DEBUG)
        package_logger.addHandler(handler)
        try:
            with tempfile.TemporaryDirectory(prefix="SECRET_PATH-") as directory:
                result = expansion.expand_capability(
                    HANDLE,
                    root=directory,
                    store=HostileStore(),
                    git_executable=git_executable(),
                )
        finally:
            package_logger.removeHandler(handler)
            package_logger.setLevel(previous_level)

        self.assertEqual(result.disposition, expansion.ExpansionDisposition.REFUSED)
        self.assertEqual(result.output_bytes, b"")
        self.assertEqual(result.refusal["reason"], "artifact_invalid")
        observed = repr(result) + json.dumps(result.refusal, sort_keys=True)
        observed += "".join(handler.messages)
        for secret in secrets:
            self.assertNotIn(secret, observed)


if __name__ == "__main__":
    unittest.main()
