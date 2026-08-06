"""Closed, lossless progressive evidence-pack artifacts."""

from __future__ import annotations

import base64
from typing import Final

from .canonical import JSONLimits, canonical_json_bytes
from .contracts import evidence_boundary
from .receipts import SOURCE_CURRENT_BINDING, raw_sha256
from .router import ROUTER_POLICY_VERSION


EVIDENCE_PACK_VERSION: Final = "contextguard-receipt-evidence-pack/v1"
EVIDENCE_PACK_LIMITS: Final = JSONLimits(
    max_document_bytes=2 * 1024 * 1024,
    max_depth=16,
    max_total_values=2048,
    max_object_members=32,
    max_string_bytes=1_300_000,
)
def _base64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


def retained_segment(*, start_byte: int, end_byte: int, payload: bytes) -> dict[str, object]:
    """Build a lossless inline segment without adding semantic claims."""

    return {
        "end_byte": end_byte,
        "kind": "retained",
        "payload_b64u": _base64url(payload),
        "start_byte": start_byte,
    }


def deferred_segment(
    *,
    start_byte: int,
    end_byte: int,
    payload: bytes,
    subject_identity_sha256: str,
    capability: str,
) -> dict[str, object]:
    """Build a capability-bound exact-byte segment."""

    return {
        "binding_kind": SOURCE_CURRENT_BINDING,
        "byte_length": len(payload),
        "capability": capability,
        "content_sha256": raw_sha256(payload),
        "end_byte": end_byte,
        "kind": "deferred",
        "start_byte": start_byte,
        "subject_identity_sha256": subject_identity_sha256,
    }


def build_evidence_pack(
    *, payload: bytes, segments: tuple[dict[str, object], ...]
) -> dict[str, object]:
    """Build the closed public artifact for one exactly covered payload."""

    return {
        "artifact_kind": "evidence_pack",
        "byte_length": len(payload),
        "content_sha256": raw_sha256(payload),
        "evidence_boundary": evidence_boundary(),
        "router_policy_version": ROUTER_POLICY_VERSION,
        "schema_version": EVIDENCE_PACK_VERSION,
        "segments": list(segments),
    }


def encode_evidence_pack(
    *, payload: bytes, segments: tuple[dict[str, object], ...]
) -> bytes:
    return canonical_json_bytes(
        build_evidence_pack(payload=payload, segments=segments),
        limits=EVIDENCE_PACK_LIMITS,
    )


def retained_wire_bytes(segments: tuple[dict[str, object], ...]) -> int:
    """Return exact UTF-8 bytes occupied by inline base64url values."""

    return sum(
        len(segment["payload_b64u"])
        for segment in segments
        if segment.get("kind") == "retained"
    )
