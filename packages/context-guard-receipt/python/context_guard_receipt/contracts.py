"""Closed, dependency-free contracts for the receipt companion."""

from __future__ import annotations

import json
from typing import Final


_EVIDENCE_BOUNDARY_ITEMS: Final[tuple[tuple[str, object], ...]] = (
    ("evidence_class", "companion_local_receipt_only"),
    ("host_request_owned", False),
    ("provider_claim_authority", False),
    ("provider_join_status", "missing"),
    ("runtime_observer_present", False),
    ("schema_version", "contextguard-receipt-evidence-boundary/v1"),
    ("selected_branch", "S2-UNSUPPORTED"),
    ("selected_transport", "NONE"),
    ("stage1_evidence", False),
    ("stage2_evidence", False),
)


def evidence_boundary() -> dict[str, object]:
    """Return a fresh boundary from immutable private constants."""

    return dict(_EVIDENCE_BOUNDARY_ITEMS)


# Mutable compatibility export. Receipt construction must use evidence_boundary().
EVIDENCE_BOUNDARY: Final[dict[str, object]] = evidence_boundary()
RESPONSE_SCHEMA_VERSION: Final = "contextguard-receipt-cli-response/v1"


def canonical_json(value: object) -> str:
    """Return the sole wire encoding used by this package."""
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"


def response(*, operation: str, status: str, reason: str | None = None) -> dict[str, object]:
    """Build a closed response without reflecting untrusted input."""
    result: dict[str, object] = {
        "evidence_boundary": evidence_boundary(),
        "operation": operation,
        "schema_version": RESPONSE_SCHEMA_VERSION,
        "status": status,
    }
    if reason is not None:
        result["reason"] = reason
    return result
