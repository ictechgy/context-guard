"""Typed, non-free-form G005 blueprint construction."""

from __future__ import annotations

from typing import Final

from .receipts import raw_sha256


INVARIANTS: Final = [
    "artifact_type_matches",
    "repository_binding_current",
    "subject_identity_current",
]
TESTS: Final = [
    "capability_only_authority",
    "exact_byte_round_trip",
    "stale_state_refusal",
]


def build_blueprint_body(
    *,
    whole_payload: bytes,
    whole_subject_identity_sha256: str,
    whole_capability: str,
    items: tuple[dict[str, object], ...],
    phases: tuple[str, ...],
    item_capabilities: tuple[str, ...],
) -> dict[str, object]:
    obligations: list[dict[str, object]] = []
    for index, (item, phase, capability) in enumerate(
        zip(items, phases, item_capabilities, strict=True)
    ):
        payload = item["payload"]
        if type(payload) is not bytes:
            raise ValueError("invalid_blueprint_item")
        obligations.append(
            {
                "bypass": "emit_original_payload",
                "byte_length": len(payload),
                "capability": capability,
                "content_sha256": raw_sha256(payload),
                "invariants": list(INVARIANTS),
                "item_index": index,
                "phase": phase,
                "rollback": "expand_whole_payload",
                "subject_identity_sha256": item["subject_identity_sha256"],
                "tests": list(TESTS),
            }
        )
    return {
        "bypass": {
            "byte_length": len(whole_payload),
            "capability": whole_capability,
            "content_sha256": raw_sha256(whole_payload),
            "subject_identity_sha256": whole_subject_identity_sha256,
        },
        "obligations": obligations,
    }
