from __future__ import annotations

import copy
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
APPROVAL_SCHEMA_PATH = PACKAGE_ROOT / "schemas/external-approval.schema.json"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))

from context_guard_receipt.external_approval import (
    ApprovalError,
    authorize_and_consume,
    create_approval,
    diagnostic,
    revoke,
)


KEY = bytes(range(32))
REGISTRY_KEY = bytes(reversed(range(32)))
NOW = 1_800_000_000


def exact_scope() -> dict[str, object]:
    return {
        "source_candidate": {
            "commit_sha": "b276abca21799f8d7daf86b751e5c269e6bcf0b3",
            "manifest_sha256": "f" * 64,
            "checksums_sha256": "e" * 64,
            "artifact_ids": ["9157878234", "9157877764"],
        },
        "provider": {"provider_id": "provider-A", "model_id": "model-A"},
        "observer": {
            "observer_id": "observer-A",
            "surface_id": "bash-tool-output/v1",
            "phase": "P2",
            "receipt_schema": "contextguard.phase-evaluation.p2/v1",
        },
        "operation": {
            "receipt_schema": "contextguard.phase-evaluation.p2/v1",
            "surface_id": "p2-shadow-observation",
            "version": "v1",
        },
        "runtime": {
            "identity": "cpython-3.14.0",
            "version": "3.14.0",
            "executable_sha256": "a" * 64,
            "argv_sha256": "b" * 64,
            "environment_sha256": "c" * 64,
        },
        "credential": {
            "consumer_id": "p2-shadow-runner/v1",
            "scope_allowlist": ["provider:model.invoke"],
        },
        "destinations": [
            {"scheme": "https", "host": "api.example.invalid", "port": 443}
        ],
        "network_policy": {"proxies_allowed": False, "redirects_allowed": False},
        "limits": {
            "call_cap": 240,
            "spend_cap": "12.50",
            "currency": "USD",
            "timeout_seconds": 900,
        },
        "output": {"mode": "owner_private", "root": "/private/output/p2"},
        "retention": {"seconds": 604800},
    }


def approval(
    scope: dict[str, object] | None = None, *, nonce: str = "1" * 64
) -> dict[str, object]:
    return create_approval(
        scope=exact_scope() if scope is None else scope,
        issued_at=NOW,
        expires_at=NOW + 3600,
        nonce=nonce,
        revocation_handle="2" * 64,
        signing_key=KEY,
    )


class ExternalApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.state_root = Path(self.temporary.name) / "approval-state"
        self.state_root.mkdir(mode=0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def consume(self, packet: dict[str, object], requested: dict[str, object], action):
        return authorize_and_consume(
            approval=packet,
            requested_scope=requested,
            verification_key=KEY,
            registry_key=REGISTRY_KEY,
            state_root=self.state_root,
            materialize=action,
        )

    def test_exact_authenticated_approval_materializes_once(self) -> None:
        seen: list[dict[str, object]] = []
        packet = approval()
        with mock.patch(
            "context_guard_receipt.external_approval.time.time", return_value=NOW + 1
        ):
            result = self.consume(
                packet, exact_scope(), lambda scope: seen.append(scope) or "ok"
            )
        self.assertEqual(result, "ok")
        self.assertEqual(seen, [exact_scope()])

        with self.assertRaisesRegex(ApprovalError, "replayed"):
            with mock.patch(
                "context_guard_receipt.external_approval.time.time", return_value=NOW + 1
            ):
                self.consume(
                    packet,
                    exact_scope(),
                    lambda scope: self.fail("replay reached action"),
                )

    def test_public_approval_schema_is_recursively_closed(self) -> None:
        schema = json.loads(APPROVAL_SCHEMA_PATH.read_text("utf-8"))
        self.assertEqual(schema["$id"], "contextguard.external-approval/v1")
        self.assertEqual(schema["additionalProperties"], False)

        def require_closed(value: object) -> None:
            if isinstance(value, dict):
                if value.get("type") == "object" or "properties" in value:
                    self.assertIs(
                        value.get("additionalProperties"),
                        False,
                        f"open schema object: {value}",
                    )
                for child in value.values():
                    require_closed(child)
            elif isinstance(value, list):
                for child in value:
                    require_closed(child)

        require_closed(schema)
        self.assertEqual(
            set(schema["properties"]),
            {
                "authentication_hmac_sha256",
                "expires_at",
                "issued_at",
                "nonce",
                "revocation_handle",
                "schema_version",
                "scope",
            },
        )

    def test_unapproved_expired_revoked_drifted_expanded_and_malformed_fail_before_action(self) -> None:
        cases: list[tuple[str, dict[str, object], dict[str, object], int]] = []
        unsigned = approval()
        unsigned.pop("authentication_hmac_sha256")
        cases.append(("unapproved", unsigned, exact_scope(), NOW + 1))
        cases.append(("expired", approval(), exact_scope(), NOW + 3600))

        drifted = exact_scope()
        drifted["provider"] = {"provider_id": "provider-A", "model_id": "model-B"}
        cases.append(("drifted", approval(), drifted, NOW + 1))

        expanded = exact_scope()
        expanded["destinations"] = [
            *expanded["destinations"],
            {"scheme": "https", "host": "extra.example.invalid", "port": 443},
        ]
        cases.append(("scope-expanded", approval(), expanded, NOW + 1))

        malformed_scope = exact_scope()
        malformed_scope["limits"] = {**malformed_scope["limits"], "call_cap": 241}
        malformed = approval()
        malformed["scope"] = malformed_scope
        cases.append(("malformed", malformed, exact_scope(), NOW + 1))

        for label, packet, requested, now in cases:
            with self.subTest(label=label):
                (self.state_root / label).mkdir(mode=0o700)
                reached = False

                def action(_scope):
                    nonlocal reached
                    reached = True

                with self.assertRaises(ApprovalError):
                    with mock.patch(
                        "context_guard_receipt.external_approval.time.time",
                        return_value=now,
                    ):
                        authorize_and_consume(
                            approval=packet,
                            requested_scope=requested,
                            verification_key=KEY,
                            registry_key=REGISTRY_KEY,
                            state_root=self.state_root / label,
                            materialize=action,
                        )
                self.assertFalse(reached)

        revoked_packet = approval()
        (self.state_root / "revoked").mkdir(mode=0o700)
        with mock.patch(
            "context_guard_receipt.external_approval.time.time", return_value=NOW
        ):
            revoke(
                state_root=self.state_root / "revoked",
                revocation_handle="2" * 64,
                registry_key=REGISTRY_KEY,
            )
        with self.assertRaisesRegex(ApprovalError, "revoked"):
            with mock.patch(
                "context_guard_receipt.external_approval.time.time", return_value=NOW + 1
            ):
                authorize_and_consume(
                    approval=revoked_packet,
                    requested_scope=exact_scope(),
                    verification_key=KEY,
                    registry_key=REGISTRY_KEY,
                    state_root=self.state_root / "revoked",
                    materialize=lambda scope: self.fail(
                        "revoked approval reached action"
                    ),
                )

    def test_racing_consumers_allow_exactly_one_materialization(self) -> None:
        packet = approval()
        barrier = threading.Barrier(8)
        calls = 0
        calls_lock = threading.Lock()

        def attempt() -> str:
            nonlocal calls
            barrier.wait()

            def action(_scope) -> str:
                nonlocal calls
                with calls_lock:
                    calls += 1
                return "used"

            try:
                return self.consume(packet, exact_scope(), action)
            except ApprovalError as exc:
                return exc.code

        with mock.patch(
            "context_guard_receipt.external_approval.time.time", return_value=NOW + 1
        ):
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(lambda _index: attempt(), range(8)))

        self.assertEqual(calls, 1)
        self.assertEqual(results.count("used"), 1)
        self.assertEqual(results.count("replayed"), 7)

    def test_closed_scope_rejects_unknowns_secrets_and_nonfinite_limits(self) -> None:
        mutations = []
        unknown = exact_scope()
        unknown["provider"]["region"] = "us"
        mutations.append(unknown)
        secret = exact_scope()
        secret["credential"]["api_key"] = "sk-do-not-store"
        mutations.append(secret)
        nonfinite = exact_scope()
        nonfinite["limits"]["spend_cap"] = "Infinity"
        mutations.append(nonfinite)
        relative = exact_scope()
        relative["output"]["root"] = "relative/output"
        mutations.append(relative)

        for scope in mutations:
            with self.subTest(scope=scope):
                with self.assertRaises(ApprovalError):
                    create_approval(
                        scope=scope,
                        issued_at=NOW,
                        expires_at=NOW + 1,
                        nonce="3" * 64,
                        revocation_handle="4" * 64,
                        signing_key=KEY,
                    )

    def test_non_plain_container_types_are_rejected(self) -> None:
        class DictSubclass(dict):
            pass

        class ListSubclass(list):
            pass

        scope_dict = DictSubclass(exact_scope())
        scope_list = exact_scope()
        scope_list["destinations"] = ListSubclass(scope_list["destinations"])
        for scope in (scope_dict, scope_list):
            with self.subTest(container=type(scope).__name__):
                with self.assertRaisesRegex(ApprovalError, "malformed"):
                    create_approval(
                        scope=scope,
                        issued_at=NOW,
                        expires_at=NOW + 1,
                        nonce="3" * 64,
                        revocation_handle="4" * 64,
                        signing_key=KEY,
                    )

    def test_state_and_diagnostics_store_no_secret_or_approval_values(self) -> None:
        packet = approval()
        with mock.patch(
            "context_guard_receipt.external_approval.time.time", return_value=NOW + 1
        ):
            self.consume(packet, exact_scope(), lambda _scope: None)
        state_text = "".join(
            path.read_text("utf-8")
            for path in self.state_root.rglob("*")
            if path.is_file()
        )
        serialized_packet = json.dumps(packet, sort_keys=True)
        for forbidden in (
            "provider-A",
            "model-A",
            "api.example.invalid",
            "/private/output/p2",
            "1" * 64,
            "2" * 64,
            KEY.hex(),
            REGISTRY_KEY.hex(),
            serialized_packet,
        ):
            self.assertNotIn(forbidden, state_text)

        bad = copy.deepcopy(packet)
        bad["authentication_hmac_sha256"] = "sk-live-secret-value"
        try:
            with mock.patch(
                "context_guard_receipt.external_approval.time.time", return_value=NOW + 1
            ):
                self.consume(bad, exact_scope(), lambda _scope: None)
        except ApprovalError as exc:
            rendered = json.dumps(diagnostic(exc), sort_keys=True)
        else:
            self.fail("malformed authentication unexpectedly passed")
        self.assertEqual(
            json.loads(rendered),
            {
                "approval_authorized": False,
                "reason": "malformed",
                "schema_version": "contextguard.external-approval-diagnostic/v1",
            },
        )
        self.assertNotIn("secret", rendered)

    def test_tampered_replay_registry_fails_closed(self) -> None:
        packet = approval()
        with mock.patch(
            "context_guard_receipt.external_approval.time.time", return_value=NOW + 1
        ):
            self.consume(packet, exact_scope(), lambda _scope: None)
        registry = self.state_root / "registry.json"
        state = json.loads(registry.read_text("ascii"))
        state["consumed_nonce_sha256"] = []
        registry.write_text(json.dumps(state), encoding="ascii")

        with self.assertRaisesRegex(ApprovalError, "state-unavailable"):
            with mock.patch(
                "context_guard_receipt.external_approval.time.time", return_value=NOW + 1
            ):
                self.consume(
                    packet,
                    exact_scope(),
                    lambda _scope: self.fail("tamper replayed"),
                )

    def test_caller_cannot_choose_validation_time_or_reuse_signing_key_for_state(self) -> None:
        packet = approval()
        with self.assertRaises(TypeError):
            authorize_and_consume(
                approval=packet,
                requested_scope=exact_scope(),
                verification_key=KEY,
                registry_key=REGISTRY_KEY,
                state_root=self.state_root,
                now=NOW + 1,
                materialize=lambda _scope: None,
            )
        with self.assertRaisesRegex(ApprovalError, "state-unavailable"):
            with mock.patch(
                "context_guard_receipt.external_approval.time.time", return_value=NOW + 1
            ):
                authorize_and_consume(
                    approval=packet,
                    requested_scope=exact_scope(),
                    verification_key=KEY,
                    registry_key=KEY,
                    state_root=self.state_root,
                    materialize=lambda _scope: self.fail("shared key reached action"),
                )

    def test_expiry_and_closed_network_operation_policy_are_enforced(self) -> None:
        packet = approval()
        with self.assertRaisesRegex(ApprovalError, "expired"):
            with mock.patch(
                "context_guard_receipt.external_approval.time.time",
                return_value=NOW + 3600,
            ):
                self.consume(
                    packet,
                    exact_scope(),
                    lambda _scope: self.fail("expired approval reached action"),
                )

        mutations = []
        redirect = exact_scope()
        redirect["network_policy"]["redirects_allowed"] = True
        mutations.append(redirect)
        proxy = exact_scope()
        proxy["network_policy"]["proxies_allowed"] = True
        mutations.append(proxy)
        missing_schema = exact_scope()
        missing_schema["operation"].pop("receipt_schema")
        mutations.append(missing_schema)
        noncanonical_root = exact_scope()
        noncanonical_root["output"]["root"] = "/private/output/./p2"
        mutations.append(noncanonical_root)
        excessive_lifetime = exact_scope()
        for scope in mutations:
            with self.subTest(scope=scope):
                with self.assertRaises(ApprovalError):
                    create_approval(
                        scope=scope,
                        issued_at=NOW,
                        expires_at=NOW + 1,
                        nonce="3" * 64,
                        revocation_handle="4" * 64,
                        signing_key=KEY,
                    )
        with self.assertRaises(ApprovalError):
            create_approval(
                scope=excessive_lifetime,
                issued_at=NOW,
                expires_at=NOW + 31_536_001,
                nonce="3" * 64,
                revocation_handle="4" * 64,
                signing_key=KEY,
            )

    def test_registry_is_descriptor_bound_private_and_directory_fsynced(self) -> None:
        synced_kinds: list[str] = []
        real_fsync = os.fsync

        def recording_fsync(descriptor: int) -> None:
            mode = os.fstat(descriptor).st_mode
            synced_kinds.append(
                "directory" if stat.S_ISDIR(mode) else "regular"
            )
            real_fsync(descriptor)

        with mock.patch(
            "context_guard_receipt.external_approval.time.time", return_value=NOW + 1
        ), mock.patch(
            "context_guard_receipt.external_approval.os.fsync",
            side_effect=recording_fsync,
        ):
            self.consume(approval(), exact_scope(), lambda _scope: None)
        self.assertIn("regular", synced_kinds)
        self.assertIn("directory", synced_kinds)

        registry = self.state_root / "registry.json"
        original = registry.read_bytes()
        outside = Path(self.temporary.name) / "old-registry.json"
        outside.write_bytes(original)
        registry.unlink()
        registry.symlink_to(outside)
        with self.assertRaisesRegex(ApprovalError, "state-unavailable"):
            with mock.patch(
                "context_guard_receipt.external_approval.time.time",
                return_value=NOW + 1,
            ):
                self.consume(
                    approval(nonce="5" * 64),
                    exact_scope(),
                    lambda _scope: self.fail("symlink registry reached action"),
                )

    def test_missing_or_public_state_root_is_not_created_or_used(self) -> None:
        missing = Path(self.temporary.name) / "missing-state"
        with self.assertRaisesRegex(ApprovalError, "state-unavailable"):
            with mock.patch(
                "context_guard_receipt.external_approval.time.time",
                return_value=NOW + 1,
            ):
                authorize_and_consume(
                    approval=approval(),
                    requested_scope=exact_scope(),
                    verification_key=KEY,
                    registry_key=REGISTRY_KEY,
                    state_root=missing,
                    materialize=lambda _scope: self.fail(
                        "missing state root reached action"
                    ),
                )
        self.assertFalse(missing.exists())

        public = Path(self.temporary.name) / "public-state"
        public.mkdir(mode=0o755)
        with self.assertRaisesRegex(ApprovalError, "state-unavailable"):
            revoke(
                state_root=public,
                revocation_handle="8" * 64,
                registry_key=REGISTRY_KEY,
            )

    def test_unsafe_registry_or_lock_metadata_fails_closed(self) -> None:
        with mock.patch(
            "context_guard_receipt.external_approval.time.time", return_value=NOW + 1
        ):
            self.consume(approval(), exact_scope(), lambda _scope: None)

        for name in ("registry.json", "registry.lock"):
            with self.subTest(name=name):
                path = self.state_root / name
                original_mode = stat.S_IMODE(path.stat().st_mode)
                path.chmod(0o644)
                try:
                    with self.assertRaisesRegex(ApprovalError, "state-unavailable"):
                        with mock.patch(
                            "context_guard_receipt.external_approval.time.time",
                            return_value=NOW + 1,
                        ):
                            self.consume(
                                approval(nonce=("6" if name == "registry.json" else "7") * 64),
                                exact_scope(),
                                lambda _scope: self.fail(
                                    "unsafe state metadata reached action"
                                ),
                            )
                finally:
                    path.chmod(original_mode)


if __name__ == "__main__":
    unittest.main()
