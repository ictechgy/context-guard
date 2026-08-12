from __future__ import annotations

import copy
import json
import os
import sys
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
V1 = ROOT / "research/provider-free-roadmap/g6/v1"
G5 = ROOT / "research/provider-free-roadmap/g5"


def captured(name: str, path: Path) -> bytes:
    value = globals().get(name)
    if value is None:
        return path.read_bytes()
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must contain captured bytes")
    return value


def captured_map(name: str, paths: list[Path]) -> dict[str, bytes]:
    value = globals().get(name)
    if value is None:
        return {path.name: path.read_bytes() for path in paths}
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(raw, bytes) for key, raw in value.items()
    ):
        raise TypeError(f"{name} must contain a captured byte map")
    return value


def load_verifier() -> types.ModuleType:
    raw = captured("__G6_CAPTURED_VERIFIER_BYTES__", V1 / "verify.py")
    module = types.ModuleType("captured_g6_verifier")
    module.__file__ = str(V1 / "verify.py")
    sys.modules[module.__name__] = module
    exec(compile(raw, module.__file__, "exec"), module.__dict__, module.__dict__)
    return module


class G6PreparedUnapprovedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verify = load_verifier()
        cls.inputs = {
            "packet_bytes": captured(
                "__G6_CAPTURED_PACKET_BYTES__", V1 / "preparation-packet.json"
            ),
            "packet_schema_bytes": captured(
                "__G6_CAPTURED_SCHEMA_BYTES__",
                V1 / "schemas/preparation-packet.schema.json",
            ),
            "g5_lock_bytes": captured(
                "__G6_CAPTURED_G5_LOCK_BYTES__", G5 / "freeze-lock.json"
            ),
            "g5_prereg_bytes": captured(
                "__G6_CAPTURED_G5_PREREG_BYTES__", G5 / "v1/preregistration.json"
            ),
            "g5_schedule_bytes": captured(
                "__G6_CAPTURED_G5_SCHEDULE_BYTES__", G5 / "v1/schedule.json"
            ),
            "g5_schema_bytes": captured_map(
                "__G6_CAPTURED_G5_SCHEMA_BYTES__", sorted((G5 / "v1/schemas").glob("*.json"))
            ),
            "g5_verifier_bytes": captured(
                "__G6_CAPTURED_G5_VERIFIER_BYTES__", G5 / "v1/verify.py"
            ),
        }
        cls.packet = json.loads(cls.inputs["packet_bytes"])
        cls.schema = json.loads(cls.inputs["packet_schema_bytes"])

    def validate_changed(self, changed: dict) -> None:
        self.verify.validate_schema(
            changed, self.schema, self.schema, "candidate preparation packet"
        )

    def test_captured_packet_integrity_success_never_authorizes(self) -> None:
        self.assertEqual(self.verify.validate_captured(**self.inputs), {
            "authorization": False,
            "authority_effect": "none",
            "integrity": "verified",
            "status": "prepared_unapproved",
        })

    def test_root_authority_constants_are_immutable_and_unapproved(self) -> None:
        self.assertEqual(self.packet["packet_status"], "prepared_unapproved")
        self.assertIs(self.packet["execution_authorized"], False)
        self.assertEqual(self.packet["authority_effect"], "none")
        self.assertIs(self.packet["external_approval_required"], True)
        self.assertIsNone(self.packet["approval_evidence"])
        self.assertIs(self.packet["runner_present"], False)
        self.assertIs(self.packet["command_materializable"], False)
        self.assertEqual(set(self.packet["authority_flags"].values()), {False})

    def test_every_execution_selection_and_external_requirement_blocks(self) -> None:
        expected = {"state": "blocking_unselected", "value": None}
        self.assertEqual(set(self.packet["execution_selections"]), {
            "credential", "external_decision", "model", "network", "observer",
            "output", "provider", "request_surface", "retention", "runtime",
            "source_candidate", "spend",
        })
        self.assertTrue(all(value == expected for value in self.packet["execution_selections"].values()))
        self.assertEqual(set(self.packet["external_requirements"]), {"expiry", "one_use", "revocation"})
        self.assertTrue(all(value == expected for value in self.packet["external_requirements"].values()))

    def test_future_approval_requirements_are_closed_true_and_nonmaterializing(self) -> None:
        expected = {
            "credential_consumer_identity_required",
            "credential_scope_allowlist_required",
            "exact_destination_scheme_host_port_allowlist_required",
            "exact_operation_surface_version_receipt_schema_required",
            "exact_output_root_mode_required",
            "exact_provider_observer_identity_required",
            "exact_runtime_binary_version_hash_argv_env_required",
            "exact_source_candidate_identity_required",
            "finite_expiry_required",
            "finite_retention_required",
            "finite_spend_cap_and_currency_required",
            "finite_timeout_required",
            "one_use_nonce_required",
            "proxy_default_deny",
            "redirect_default_deny",
            "revocation_handle_required",
            "scope_expansion_forbidden",
            "secret_values_forbidden",
            "shell_forbidden",
            "subsequent_evidence_review_required_before_claims",
        }
        requirements = self.packet.get("future_approval_requirements")
        self.assertIsInstance(requirements, dict, "missing closed future approval requirements")
        self.assertEqual(set(requirements), expected)
        self.assertEqual(set(requirements.values()), {True})
        call_cap = self.packet.get("future_call_cap_requirement")
        self.assertEqual(call_cap, {
            "finite_call_cap_required": True,
            "maximum_calls_upper_bound": 240,
        })
        self.verify.reject_materialization(self.packet)

    def test_future_approval_requirement_missing_false_unknown_and_call_cap_are_rejected(self) -> None:
        self.assertIsInstance(
            self.packet.get("future_approval_requirements"), dict,
            "missing closed future approval requirements",
        )
        name = "exact_provider_observer_identity_required"
        for label, mutate in (
            ("missing", lambda value: value["future_approval_requirements"].pop(name)),
            ("false", lambda value: value["future_approval_requirements"].update({name: False})),
            ("unknown", lambda value: value["future_approval_requirements"].update({"unknown_requirement": True})),
            ("call cap false", lambda value: value["future_call_cap_requirement"].update(finite_call_cap_required=False)),
            ("call cap too high", lambda value: value["future_call_cap_requirement"].update(maximum_calls_upper_bound=241)),
        ):
            with self.subTest(label=label):
                changed = copy.deepcopy(self.packet)
                mutate(changed)
                with self.assertRaises(Exception):
                    self.validate_changed(changed)

    def test_optional_publication_activation_npm_and_claims_are_disabled(self) -> None:
        expected = {"authorized": False, "state": "blocking_unselected", "value": None}
        self.assertEqual(set(self.packet["optional_surfaces"]), {
            "claim", "npm", "publication", "runtime_activation",
        })
        self.assertTrue(all(value == expected for value in self.packet["optional_surfaces"].values()))

    def test_only_frozen_g5_capacity_is_a_non_authorizing_constraint(self) -> None:
        self.assertEqual(self.packet["unapproved_constraints"], {
            "authority_effect": "none",
            "maximum_scheduled_units": 240,
            "replacement_blocks": 0,
            "source": "frozen_g5_capacity_constraint_only",
        })

    def test_packet_contains_no_materializable_surface(self) -> None:
        self.verify.reject_materialization(self.packet)
        serialized = json.dumps(self.packet, sort_keys=True).lower()
        for forbidden in (
            "command_argv", "https://", "http://", "api.anthropic.com",
            "/private/tmp", '"provider": "anthropic"', '"model": "sonnet"',
            '"credential_reference":', '"output_root":', '"spend_cap":',
            '"approval_receipt":',
        ):
            self.assertNotIn(forbidden, serialized)

    def test_all_authority_boolean_mutations_are_rejected(self) -> None:
        mutations = {
            "execution": lambda value: value.update(execution_authorized=True),
            "external approval": lambda value: value.update(external_approval_required=False),
            "runner": lambda value: value.update(runner_present=True),
            "command": lambda value: value.update(command_materializable=True),
            "interpretation": lambda value: value["verification_interpretation"].update(authorization_after_integrity_success=True),
        }
        mutations.update({
            f"flag {name}": lambda value, name=name: value["authority_flags"].update({name: True})
            for name in self.packet["authority_flags"]
        })
        mutations.update({
            f"optional {name}": lambda value, name=name: value["optional_surfaces"][name].update(authorized=True)
            for name in self.packet["optional_surfaces"]
        })
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                changed = copy.deepcopy(self.packet)
                mutation(changed)
                with self.assertRaises(Exception):
                    self.validate_changed(changed)

    def test_every_selection_rejects_inserted_value_or_nonblocking_state(self) -> None:
        inserted = {
            "provider": "provider-id", "observer": "observer-id", "model": "model-id",
            "request_surface": "request", "credential": "credential-ref",
            "network": "https://example.invalid", "runtime": "runtime-id",
            "source_candidate": "candidate", "output": "/tmp/output",
            "retention": "30-days", "spend": 1, "external_decision": "receipt",
        }
        for name, value in inserted.items():
            for field, changed_value in (("value", value), ("state", "selected")):
                with self.subTest(name=name, field=field):
                    changed = copy.deepcopy(self.packet)
                    changed["execution_selections"][name][field] = changed_value
                    with self.assertRaises(Exception):
                        self.validate_changed(changed)

    def test_approval_receipt_executable_argv_destination_and_spend_fields_are_rejected(self) -> None:
        for key, value in (
            ("approval_receipt", "receipt"), ("executable", "python3"),
            ("argv", ["run"]), ("destination", "example.invalid"),
            ("credential_reference", "credential"), ("output_root", "/tmp/output"),
            ("provider_id", "provider"), ("model_id", "model"), ("spend_cap", 1),
        ):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.packet)
                changed[key] = value
                with self.assertRaises(Exception):
                    self.validate_changed(changed)
        changed = copy.deepcopy(self.packet)
        changed["approval_evidence"] = {"receipt": "inserted"}
        with self.assertRaises(Exception):
            self.validate_changed(changed)

    def test_schema_is_recursively_closed_complete_and_has_no_transition_branch(self) -> None:
        self.verify.audit_schema(self.schema, "G6 preparation schema")
        properties = self.schema["properties"]
        self.assertFalse({"approved", "approve", "run"} & set(properties))
        enums_and_consts = json.dumps(self.schema).lower()
        self.assertNotIn('"approved"', enums_and_consts)
        self.assertNotIn('"run"', enums_and_consts)

    def test_unknown_duplicate_and_nonfinite_json_are_rejected(self) -> None:
        unknown = copy.deepcopy(self.packet)
        unknown["provider_id"] = "inserted"
        with self.assertRaises(Exception):
            self.validate_changed(unknown)
        for raw in (
            b'{"a":1,"a":2}\n',
            b'{"value":NaN}\n',
            b'{"value":Infinity}\n',
        ):
            with self.assertRaises(Exception):
                self.verify.parse(raw, "negative JSON")

    def test_synchronized_packet_and_schema_rewrite_is_rejected(self) -> None:
        changed_packet = copy.deepcopy(self.packet)
        changed_packet["execution_authorized"] = True
        changed_schema = copy.deepcopy(self.schema)
        changed_schema["properties"]["execution_authorized"]["const"] = True
        with self.assertRaisesRegex(Exception, "schema drift"):
            self.verify.validate_captured(
                **{
                    **self.inputs,
                    "packet_bytes": self.verify.canonical(changed_packet),
                    "packet_schema_bytes": self.verify.canonical(changed_schema),
                }
            )

    def test_candidate_validation_is_byte_exact(self) -> None:
        changed = copy.deepcopy(self.packet)
        changed["authority_effect"] = "external"
        with self.assertRaisesRegex(Exception, "candidate differs"):
            self.verify.validate_candidate(
                self.verify.canonical(changed),
                expected_packet_bytes=self.inputs["packet_bytes"],
                **{key: value for key, value in self.inputs.items() if key != "packet_bytes"},
            )

    def test_g5_consumed_bytes_and_final_freeze_are_exactly_bound(self) -> None:
        contract = self.packet["upstream_contract"]
        self.assertEqual(contract["g5_freeze_lock_sha256"], self.verify.G5_LOCK_SHA256)
        self.assertEqual(contract["g5_tree_sha256"], self.verify.G5_TREE_SHA256)
        self.assertEqual(contract["g5_preregistration"], self.verify.G5_PREREG)
        self.assertEqual(contract["g5_schedule"], self.verify.G5_SCHEDULE)
        self.assertEqual(contract["g5_verifier"], self.verify.G5_VERIFIER)
        self.assertEqual(contract["g5_schema_set"], self.verify.G5_SCHEMA_SET)

    def test_no_runner_or_execution_artifact_exists(self) -> None:
        captured_paths = globals().get("__G6_CAPTURED_INVENTORY_PATHS__")
        if captured_paths is None:
            names = {
                path.relative_to(V1).as_posix() for path in V1.rglob("*") if path.is_file()
            }
        else:
            self.assertIsInstance(captured_paths, list)
            prefix = "research/provider-free-roadmap/g6/v1/"
            names = {
                path.removeprefix(prefix) for path in captured_paths
                if path.startswith(prefix)
            }
        self.assertEqual(names, {
            "README.md", "STATUS.md", "preparation-packet.json",
            "schemas/preparation-packet.schema.json", "verify.py",
        })

    def test_negative_network_dns_process_and_write_probes_are_real(self) -> None:
        self.assertEqual(self.verify.audited_negative_probes(), {
            "dns_denials": 1, "network_denials": 1,
            "process_denials": 1, "write_denials": 1,
        })

    def test_bound_child_is_lang_only_and_direct_mutable_verifier_refuses(self) -> None:
        if "__G6_CAPTURED_VERIFIER_BYTES__" in globals():
            self.assertEqual(sys.flags.isolated, 1)
            self.assertEqual(sys.flags.dont_write_bytecode, 1)
            self.assertEqual(os.environ.get("LANG"), "C.UTF-8")
            self.assertTrue(set(os.environ) <= {"LANG", "__CF_USER_TEXT_ENCODING"})
        self.assertEqual(self.verify.main([]), 2)


if __name__ == "__main__":
    unittest.main()
