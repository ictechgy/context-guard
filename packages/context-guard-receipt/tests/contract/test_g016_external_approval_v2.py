from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
SCHEMA_PATH = PACKAGE_ROOT / "schemas/external-approval-v2.schema.json"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))


KEY = bytes(range(32))
REGISTRY_KEY = bytes(reversed(range(32)))
NOW = 1_800_000_000


def exact_scope() -> dict[str, object]:
    return {
        "source_candidate": {
            "commit_sha": "b276abca21799f8d7daf86b751e5c269e6bcf0b3",
            "manifest_sha256": "f" * 64,
            "checksums_sha256": "e" * 64,
            "artifact_ids": ["p3-v4-budget-policy"],
        },
        "provider": {"provider_id": "anthropic-first-party", "model_id": "claude-sonnet-5"},
        "observer": {
            "observer_id": "anthropic-messages-json-v1",
            "surface_id": "anthropic-messages-api/v1",
            "phase": "P3",
            "receipt_schema": "contextguard.g5-authoritative-observation/v1",
        },
        "operation": {
            "receipt_schema": "contextguard.g5-authoritative-observation/v1",
            "surface_id": "p3-g5-budget-selected-anthropic-api-v4-live",
            "version": "v4",
        },
        "runtime": {
            "identity": "python-http.client-p3-v4-live",
            "version": "v4",
            "executable_sha256": "a" * 64,
            "argv_sha256": "b" * 64,
            "environment_sha256": "c" * 64,
        },
        "credential": {
            "consumer_id": "anthropic-messages-api",
            "scope_allowlist": ["provider:model.invoke"],
        },
        "destinations": [
            {"scheme": "https", "host": "api.anthropic.com", "port": 443}
        ],
        "network_policy": {"proxies_allowed": False, "redirects_allowed": False},
        "limits": {
            "call_cap": 144,
            "spend_cap": "20.00",
            "currency": "USD",
            "timeout_seconds": 120,
        },
        "output": {"mode": "owner_private", "root": "/private/output/p3-v4"},
        "retention": {
            "mode": "manual_owner_cleanup",
            "maximum_seconds": None,
        },
    }


class ExternalApprovalV2Tests(unittest.TestCase):
    def test_manual_cleanup_scope_is_closed_authenticated_and_one_use(self) -> None:
        from context_guard_receipt.external_approval_v2 import (
            ApprovalError,
            authorize_and_consume,
            create_approval,
        )

        scope = exact_scope()
        packet = create_approval(
            scope=scope,
            issued_at=NOW,
            expires_at=NOW + 3600,
            nonce="1" * 64,
            revocation_handle="2" * 64,
            signing_key=KEY,
        )
        self.assertEqual(packet["schema_version"], "contextguard.external-approval/v2")
        with tempfile.TemporaryDirectory() as name:
            state_root = Path(name) / "state"
            state_root.mkdir(mode=0o700)
            with mock.patch(
                "context_guard_receipt.external_approval.time.time",
                return_value=NOW + 1,
            ):
                result = authorize_and_consume(
                    approval=packet,
                    requested_scope=scope,
                    verification_key=KEY,
                    registry_key=REGISTRY_KEY,
                    state_root=state_root,
                    materialize=lambda approved: approved,
                )
            self.assertEqual(result, scope)
            with self.assertRaisesRegex(ApprovalError, "replayed"):
                with mock.patch(
                    "context_guard_receipt.external_approval.time.time",
                    return_value=NOW + 1,
                ):
                    authorize_and_consume(
                        approval=packet,
                        requested_scope=scope,
                        verification_key=KEY,
                        registry_key=REGISTRY_KEY,
                        state_root=state_root,
                        materialize=lambda approved: approved,
                    )

    def test_v2_rejects_finite_seconds_and_v1_rejects_manual_cleanup(self) -> None:
        from context_guard_receipt import external_approval
        from context_guard_receipt import external_approval_v2

        finite = exact_scope()
        finite["retention"] = {"seconds": 604800}
        with self.assertRaises(external_approval_v2.ApprovalError):
            external_approval_v2.create_approval(
                scope=finite,
                issued_at=NOW,
                expires_at=NOW + 3600,
                nonce="3" * 64,
                revocation_handle="4" * 64,
                signing_key=KEY,
            )
        with self.assertRaises(external_approval.ApprovalError):
            external_approval.create_approval(
                scope=exact_scope(),
                issued_at=NOW,
                expires_at=NOW + 3600,
                nonce="5" * 64,
                revocation_handle="6" * 64,
                signing_key=KEY,
            )

        packet = external_approval_v2.create_approval(
            scope=exact_scope(),
            issued_at=NOW,
            expires_at=NOW + 3600,
            nonce="7" * 64,
            revocation_handle="8" * 64,
            signing_key=KEY,
        )
        with tempfile.TemporaryDirectory() as name:
            state_root = Path(name) / "state"
            state_root.mkdir(mode=0o700)
            with self.assertRaises(external_approval.ApprovalError):
                external_approval.authorize_and_consume(
                    approval=packet,
                    requested_scope=exact_scope(),
                    verification_key=KEY,
                    registry_key=REGISTRY_KEY,
                    state_root=state_root,
                    materialize=lambda approved: approved,
                )

    def test_v1_and_v2_share_the_one_use_nonce_registry(self) -> None:
        from context_guard_receipt import external_approval
        from context_guard_receipt import external_approval_v2

        v1_scope = copy.deepcopy(exact_scope())
        v1_scope["retention"] = {"seconds": 1}
        nonce = "9" * 64
        v1_packet = external_approval.create_approval(
            scope=v1_scope,
            issued_at=NOW,
            expires_at=NOW + 3600,
            nonce=nonce,
            revocation_handle="a" * 64,
            signing_key=KEY,
        )
        v2_packet = external_approval_v2.create_approval(
            scope=exact_scope(),
            issued_at=NOW,
            expires_at=NOW + 3600,
            nonce=nonce,
            revocation_handle="b" * 64,
            signing_key=KEY,
        )
        with tempfile.TemporaryDirectory() as name:
            state_root = Path(name) / "state"
            state_root.mkdir(mode=0o700)
            with mock.patch(
                "context_guard_receipt.external_approval.time.time",
                return_value=NOW + 1,
            ):
                external_approval.authorize_and_consume(
                    approval=v1_packet,
                    requested_scope=v1_scope,
                    verification_key=KEY,
                    registry_key=REGISTRY_KEY,
                    state_root=state_root,
                    materialize=lambda approved: approved,
                )
                with self.assertRaisesRegex(
                    external_approval_v2.ApprovalError, "replayed"
                ):
                    external_approval_v2.authorize_and_consume(
                        approval=v2_packet,
                        requested_scope=exact_scope(),
                        verification_key=KEY,
                        registry_key=REGISTRY_KEY,
                        state_root=state_root,
                        materialize=lambda approved: approved,
                    )

    def test_public_v2_schema_is_recursively_closed(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text("utf-8"))
        self.assertEqual(schema["$id"], "contextguard.external-approval/v2")

        def require_closed(value: object) -> None:
            if isinstance(value, dict):
                if value.get("type") == "object" or "properties" in value:
                    self.assertIs(value.get("additionalProperties"), False)
                for child in value.values():
                    require_closed(child)
            elif isinstance(value, list):
                for child in value:
                    require_closed(child)

        require_closed(schema)
        retention = schema["$defs"]["scope"]["properties"]["retention"]
        self.assertEqual(
            retention["required"], ["mode", "maximum_seconds"]
        )
        self.assertEqual(
            retention["properties"],
            {
                "mode": {"const": "manual_owner_cleanup"},
                "maximum_seconds": {"type": "null"},
            },
        )


if __name__ == "__main__":
    unittest.main()
