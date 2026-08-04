from __future__ import annotations

import ast
import copy
import hashlib
import itertools
import json
import re
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
BROKER_ROOT = REPO_ROOT / "research" / "contextguard-broker"
SCHEMA_ROOT = BROKER_ROOT / "schemas"
FIXTURE_ROOT = BROKER_ROOT / "fixtures"
POSITIVE_ROOT = FIXTURE_ROOT / "positive"

SCHEMA_NAMES = (
    "broker-task-descriptor",
    "decision-receipt",
    "tool-observation-receipt",
    "provider-turn-join",
    "selection-snapshot",
    "pack-expansion-identity",
    "attempt-subordinate-receipt-bundle",
    "artifact-root-permission-decision",
    "claim-completeness-result",
)

REQUIRED_CONTRACT_FIELDS = {
    "broker-task-descriptor": {"revision_policy_id"},
    "decision-receipt": {"attempt_id"},
    "tool-observation-receipt": {
        "session_id",
        "domain_separated_content_sha256",
        "host_framing_status",
    },
    "provider-turn-join": {
        "session_id",
        "observation_receipt_id",
        "observation_receipt_sha256",
        "immediately_following_status",
    },
    "selection-snapshot": {
        "isolated_worktree_identity_sha256",
        "index_build_revision_sha256",
        "index_policy_version",
        "diff_basis",
        "diff_base_revision_sha256",
        "diff_head_or_dirty_sha256",
        "renderer_policy_version",
        "descriptor_sha256",
        "protected_zone_policy_version",
    },
    "pack-expansion-identity": {"expansions"},
    "attempt-subordinate-receipt-bundle": {
        "blocking_reasons",
        "bundle_profile",
        "descriptor_sha256",
        "cost_components",
        "latency_observation",
        "privacy_status",
        "provenance_status",
    },
    "artifact-root-permission-decision": {"attempt_id"},
    "claim-completeness-result": {"gate_results", "metric_results"},
}

DOCUMENT_NAMES = (
    "integration-map.md",
    "measurement-gap.md",
    "action-claim-policy.md",
    "endpoints.md",
    "isolation-retention.md",
    "installation-copy-ownership.md",
)

R9_SUMMARY_JSON_SHA256 = "acd8eaa1585dea15cd2f9bb7730fbeec454c4a3d3c788fffb2abd28eae7259ee"
R9_SUMMARY_MARKDOWN_SHA256 = "dd4320452eaccaa92d251c1abf40aa7f7d48c234c44d17abd7c9331703b90e07"
R9_DASHBOARD_SHA256 = "b0089b0e20529b5d8d9352fae0f189e177a748300cb4b56f90399a245c8e1c78"
R9_STUDY_PLAN_SHA256 = "9e61ba404b5826844712301a7544073ecdade82b2591f1cf091379c510f6cd57"
R9_HOOK_EVIDENCE_SHA256 = "53fb3d59177fbb19a7d76295c924e06c357ee11a185be74134ac4e008b3bca68"
R9_MANIFEST_SHA256 = "e5f4548371cf03fb80e134093d9a6113c7e4c29d578c267925bdb3c6f873f1df"
CSV_COLUMNS_SHA256 = "b21bad1ec0eace7570ea93697a206ed30f9f93b6ae5b38219c4819f7b229866a"

REQUIRED_ACTION_REASON_CODES = frozenset(
    {
        "SECRET_OR_PROTECTED_PATH_MATCH",
        "UNSAFE_ARTIFACT_ROOT",
        "PERMISSION_AMBIGUITY",
        "SYMLINK_OR_ROOT_ESCAPE",
        "PACK_HASH_MISMATCH",
        "PROTECTED_CLASSIFIER_UNAVAILABLE_AFTER_ACTIVATION",
        "SOURCE_FRESHNESS_MISMATCH",
        "INDEX_FRESHNESS_MISMATCH",
        "DIRTY_STATE_MISMATCH",
        "CANDIDATE_UNIVERSE_MISMATCH",
        "AUTHORIZATION_FRESHNESS_MISMATCH",
        "DESCRIPTOR_MISSING",
        "INELIGIBLE_STRATUM",
        "UNSUPPORTED_HOST",
        "STALE_AUTHORIZATION_PRE_PROTECTED_ACCESS",
        "PROTECTED_CLASSIFIER_UNAVAILABLE_PRE_ACTIVATION",
        "BUDGET_OR_MATERIALIZATION_FAILURE",
        "EMPTY_SELECTION",
        "INDEX_UNAVAILABLE",
        "READ_OBSERVATION_MISSING",
        "READ_OBSERVATION_TRUNCATED",
        "PROVIDER_JOIN_MISSING",
        "COST_EVIDENCE_GAP",
        "QUALITY_EVIDENCE_GAP",
        "POST_ACTIVATION_HOOK_FAILURE",
        "RESET_MISMATCH",
        "CROSS_ARM_LEAKAGE",
        "RECEIPT_DURABILITY_UNCERTAIN",
    }
)

ALLOWED_SCHEMA_KEYWORDS = frozenset(
    {
        "$defs",
        "$id",
        "$ref",
        "$schema",
        "additionalProperties",
        "allOf",
        "anyOf",
        "const",
        "contains",
        "description",
        "enum",
        "items",
        "maxItems",
        "maxLength",
        "maxProperties",
        "maximum",
        "minItems",
        "minLength",
        "minProperties",
        "minimum",
        "oneOf",
        "pattern",
        "patternProperties",
        "properties",
        "required",
        "title",
        "type",
        "uniqueItems",
    }
)


class DuplicateKeyError(ValueError):
    pass


class ContractValidationError(ValueError):
    def __init__(self, code: str, path: str, message: str) -> None:
        super().__init__(f"{path}: {message}")
        self.code = code
        self.path = path


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(key)
        result[key] = value
    return result


def strict_json_loads(raw: bytes, *, owner: str, canonical: bool) -> Any:
    if canonical and (not raw.endswith(b"\n") or raw.endswith(b"\n\n") or b"\r" in raw):
        raise ValueError(f"{owner} must end in exactly one LF")
    try:
        text = raw[:-1].decode("utf-8") if canonical else raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{owner} must be UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite number: {value}")
            ),
        )
    except (json.JSONDecodeError, DuplicateKeyError, ValueError) as exc:
        raise ValueError(f"{owner} must be strict JSON: {exc}") from exc
    if canonical:
        encoded = (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
        if raw != encoded:
            raise ValueError(f"{owner} must use canonical JSON bytes")
    return value


def load_json(path: Path, *, canonical: bool = False) -> Any:
    return strict_json_loads(path.read_bytes(), owner=str(path), canonical=canonical)


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def artifact_identity_sha256(value: dict[str, Any], hash_field: str) -> str:
    preimage = dict(value)
    del preimage[hash_field]
    domain = f"contextguard-broker/{value['schema_version']}/{hash_field}".encode("ascii")
    return hashlib.sha256(domain + b"\x00" + canonical_json_bytes(preimage)).hexdigest()


def _json_type_matches(value: Any, expected: str) -> bool:
    if expected == "null":
        return value is None
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "string":
        return isinstance(value, str)
    if expected == "array":
        return isinstance(value, list)
    if expected == "object":
        return isinstance(value, dict)
    raise AssertionError(f"unsupported JSON Schema type in test validator: {expected}")


def _resolve_local_ref(root_schema: dict[str, Any], reference: str) -> dict[str, Any]:
    if not reference.startswith("#/"):
        raise AssertionError(f"only local JSON pointers are supported: {reference}")
    value: Any = root_schema
    for token in reference[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        value = value[token]
    if not isinstance(value, dict):
        raise AssertionError(f"schema reference does not resolve to an object: {reference}")
    return value


def validate_contract(
    value: Any,
    schema: dict[str, Any],
    *,
    root_schema: dict[str, Any] | None = None,
    path: str = "$",
) -> None:
    root_schema = schema if root_schema is None else root_schema
    if "$ref" in schema:
        validate_contract(
            value,
            _resolve_local_ref(root_schema, schema["$ref"]),
            root_schema=root_schema,
            path=path,
        )
        return

    if "type" in schema:
        expected_types = schema["type"]
        if isinstance(expected_types, str):
            expected_types = [expected_types]
        if not any(_json_type_matches(value, expected) for expected in expected_types):
            raise ContractValidationError("type", path, f"expected {schema['type']}")
    if "const" in schema and value != schema["const"]:
        raise ContractValidationError("const", path, f"expected {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise ContractValidationError("enum", path, "value is outside the enum")

    if isinstance(value, dict):
        if len(value) < schema.get("minProperties", 0):
            raise ContractValidationError("minProperties", path, "object has too few keys")
        if "maxProperties" in schema and len(value) > schema["maxProperties"]:
            raise ContractValidationError("maxProperties", path, "object has too many keys")
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                raise ContractValidationError("required", path, f"missing required key {key}")
        properties = schema.get("properties", {})
        pattern_properties = schema.get("patternProperties", {})
        if schema.get("additionalProperties") is False:
            unexpected = sorted(
                key
                for key in value
                if key not in properties
                and not any(re.fullmatch(pattern, key) for pattern in pattern_properties)
            )
            if unexpected:
                raise ContractValidationError(
                    "additionalProperties", path, f"unexpected keys: {unexpected}"
                )
        for key, child in value.items():
            if key in properties:
                validate_contract(
                    child,
                    properties[key],
                    root_schema=root_schema,
                    path=f"{path}.{key}",
                )
            for pattern, child_schema in pattern_properties.items():
                if re.fullmatch(pattern, key):
                    validate_contract(
                        child,
                        child_schema,
                        root_schema=root_schema,
                        path=f"{path}.{key}",
                    )

    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            raise ContractValidationError("minItems", path, "array is too short")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise ContractValidationError("maxItems", path, "array is too long")
        if schema.get("uniqueItems"):
            canonical_items = [
                json.dumps(item, allow_nan=False, sort_keys=True, separators=(",", ":"))
                for item in value
            ]
            if len(canonical_items) != len(set(canonical_items)):
                raise ContractValidationError("uniqueItems", path, "array items must be unique")
        item_schema = schema.get("items")
        if item_schema is not None:
            for index, child in enumerate(value):
                validate_contract(
                    child,
                    item_schema,
                    root_schema=root_schema,
                    path=f"{path}[{index}]",
                )
        if "contains" in schema:
            contains_matches = 0
            for index, child in enumerate(value):
                try:
                    validate_contract(
                        child,
                        schema["contains"],
                        root_schema=root_schema,
                        path=f"{path}[{index}]",
                    )
                except ContractValidationError:
                    continue
                contains_matches += 1
            if contains_matches < 1:
                raise ContractValidationError("contains", path, "array has no matching item")

    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            raise ContractValidationError("minLength", path, "string is too short")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise ContractValidationError("maxLength", path, "string is too long")
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            raise ContractValidationError("pattern", path, "string does not match pattern")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise ContractValidationError("minimum", path, "number is too small")
        if "maximum" in schema and value > schema["maximum"]:
            raise ContractValidationError("maximum", path, "number is too large")

    if "allOf" in schema:
        for branch in schema["allOf"]:
            validate_contract(value, branch, root_schema=root_schema, path=path)

    if "anyOf" in schema:
        for branch in schema["anyOf"]:
            try:
                validate_contract(value, branch, root_schema=root_schema, path=path)
            except ContractValidationError:
                continue
            break
        else:
            raise ContractValidationError("anyOf", path, "expected at least one semantic branch")

    if "oneOf" in schema:
        matches = 0
        for branch in schema["oneOf"]:
            try:
                validate_contract(value, branch, root_schema=root_schema, path=path)
            except ContractValidationError:
                continue
            matches += 1
        if matches != 1:
            raise ContractValidationError(
                "oneOf", path, f"expected exactly one semantic branch, got {matches}"
            )


def assert_supported_schema(test: unittest.TestCase, schema: dict[str, Any]) -> None:
    def visit(node: Any, *, in_properties: bool = False) -> None:
        if isinstance(node, list):
            for child in node:
                visit(child)
            return
        if not isinstance(node, dict):
            return
        for key, child in node.items():
            if not in_properties:
                test.assertIn(key, ALLOWED_SCHEMA_KEYWORDS)
            visit(child, in_properties=key in {"properties", "$defs", "patternProperties"})

    visit(schema)


def assert_closed_total_objects(test: unittest.TestCase, schema: dict[str, Any]) -> None:
    def visit(node: Any) -> None:
        if isinstance(node, list):
            for child in node:
                visit(child)
            return
        if not isinstance(node, dict):
            return
        declared_type = node.get("type")
        object_typed = declared_type == "object" or (
            isinstance(declared_type, list) and "object" in declared_type
        )
        if object_typed:
            test.assertIs(node.get("additionalProperties"), False)
            test.assertEqual(set(node.get("required", [])), set(node.get("properties", {})))
        for key, child in node.items():
            if key in {"properties", "$defs", "patternProperties"} and isinstance(child, dict):
                for nested_schema in child.values():
                    visit(nested_schema)
            elif key in {"contains", "items"}:
                visit(child)
            elif key in {"allOf", "anyOf", "oneOf"}:
                visit(child)

    visit(schema)


def broker_schema_path(name: str) -> Path:
    return SCHEMA_ROOT / f"{name}.schema.json"


def broker_positive_path(name: str) -> Path:
    if name == "artifact-root-permission-decision":
        return BROKER_ROOT / "artifact-root-decision.json"
    return POSITIVE_ROOT / f"{name}.json"


def validate_artifact_root_decision(
    value: dict[str, Any], schema: dict[str, Any]
) -> None:
    validate_contract(value, schema)
    alternative_ids = [candidate["candidate_id"] for candidate in value["candidates"]]
    if len(alternative_ids) != len(set(alternative_ids)):
        raise ContractValidationError(
            "candidate_identity",
            "$.candidates",
            "candidate_id must be unique across alternative candidates",
        )
    if value["status"] == "selected":
        selected_candidate = value["selected_tuple"]["selected_candidate"]
        selected_id = selected_candidate["candidate_id"]
        if selected_id in alternative_ids:
            raise ContractValidationError(
                "candidate_identity",
                "$.selected_tuple.selected_candidate.candidate_id",
                "the selected candidate must not also appear as an alternative",
            )
        root_path = selected_candidate["root_path"]
        if root_path.rsplit("/", 1)[-1] != value["attempt_id"]:
            raise ContractValidationError(
                "attempt_binding",
                "$.selected_tuple.selected_candidate.root_path",
                "the selected root basename must equal the immutable attempt_id",
            )


def validate_pack_expansion_identity(
    value: dict[str, Any], schema: dict[str, Any]
) -> None:
    validate_contract(value, schema)
    expansions = value["expansions"]
    canonical_order = sorted(
        expansions,
        key=lambda expansion: (
            expansion["source_path"],
            expansion["source_byte_start"],
            expansion["source_byte_length"],
            expansion["expansion_id"],
        ),
    )
    if expansions != canonical_order:
        raise ContractValidationError(
            "canonical_order",
            "$.expansions",
            "expansions must use canonical source path and byte-range order",
        )

    previous_end_by_source: dict[tuple[str, str], int] = {}
    total_bytes_by_source: dict[tuple[str, str], int] = {}
    source_metadata_by_id: dict[str, tuple[str, int]] = {}
    source_metadata_by_path: dict[str, tuple[str, int]] = {}
    expansion_ids: set[str] = set()
    for index, expansion in enumerate(expansions):
        expansion_id = expansion["expansion_id"]
        if expansion_id in expansion_ids:
            raise ContractValidationError(
                "expansion_identity",
                f"$.expansions[{index}].expansion_id",
                "expansion_id must be unique within the immutable pack",
            )
        expansion_ids.add(expansion_id)
        source_key = (expansion["source_id"], expansion["source_path"])
        source_total_bytes = expansion["source_total_bytes"]
        source_metadata = (expansion["source_path"], source_total_bytes)
        prior_metadata = source_metadata_by_id.setdefault(
            expansion["source_id"], source_metadata
        )
        if prior_metadata != source_metadata:
            raise ContractValidationError(
                "source_identity",
                f"$.expansions[{index}].source_id",
                "one source_id must resolve to one path and total byte length",
            )
        path_metadata = (expansion["source_id"], source_total_bytes)
        prior_path_metadata = source_metadata_by_path.setdefault(
            expansion["source_path"], path_metadata
        )
        if prior_path_metadata != path_metadata:
            raise ContractValidationError(
                "source_identity",
                f"$.expansions[{index}].source_path",
                "one normalized source path must resolve to one ID and total byte length",
            )
        prior_total = total_bytes_by_source.setdefault(source_key, source_total_bytes)
        if prior_total != source_total_bytes:
            raise ContractValidationError(
                "source_identity",
                f"$.expansions[{index}].source_total_bytes",
                "one immutable source identity must have one total byte length",
            )
        start = expansion["source_byte_start"]
        end = start + expansion["source_byte_length"]
        if end > source_total_bytes:
            raise ContractValidationError(
                "source_range",
                f"$.expansions[{index}]",
                "expansion range exceeds the immutable source length",
            )
        if start < previous_end_by_source.get(source_key, 0):
            raise ContractValidationError(
                "source_overlap",
                f"$.expansions[{index}]",
                "expansion ranges for one immutable source must not overlap",
            )
        previous_end_by_source[source_key] = end
        if value["immutable_status"] == "immutable":
            if (
                expansion["source_content_sha256"]
                != expansion["delivered_content_sha256"]
                or expansion["source_byte_length"] != expansion["delivered_utf8_bytes"]
            ):
                raise ContractValidationError(
                    "content_identity",
                    f"$.expansions[{index}]",
                    "immutable expansion delivery must equal the exact source range bytes",
                )

    expected_identity = hashlib.sha256(
        b"contextguard-broker/expansion-identity/v1\x00"
        + canonical_json_bytes(expansions)
    ).hexdigest()
    if value["expansion_identity_sha256"] != expected_identity:
        raise ContractValidationError(
            "content_identity",
            "$.expansion_identity_sha256",
            "expansion identity does not match canonical expansion bytes",
        )


def validate_claim_completeness_result(
    value: dict[str, Any], schema: dict[str, Any]
) -> None:
    validate_contract(value, schema)
    statuses = [result["status"] for result in value["metric_results"].values()]
    statuses.extend(result["status"] for result in value["gate_results"].values())
    if "claim_blocked" in statuses:
        expected_completeness = "claim_blocked"
    elif "unavailable" in statuses:
        expected_completeness = "incomplete"
    else:
        expected_completeness = "complete"
    if value["completeness"] != expected_completeness:
        raise ContractValidationError(
            "claim_precedence",
            "$.completeness",
            "overall completeness must preserve claim-blocked before unavailable state",
        )
    expected_claim_allowed = expected_completeness == "complete"
    if value["claim_allowed"] is not expected_claim_allowed:
        raise ContractValidationError(
            "claim_authorization",
            "$.claim_allowed",
            "a claim is allowed only when every metric and gate is complete",
        )


def validate_decision_receipt(
    value: dict[str, Any], schema: dict[str, Any]
) -> None:
    validate_contract(value, schema)
    descriptor_missing = "DESCRIPTOR_MISSING" in value["claim_blockers"]
    if descriptor_missing:
        if value["descriptor_id"] is not None or value["selection_snapshot_id"] is not None:
            raise ContractValidationError(
                "missing_reference",
                "$.descriptor_id",
                "DESCRIPTOR_MISSING must use null descriptor and selection references",
            )
    elif value["descriptor_id"] is None:
        raise ContractValidationError(
            "missing_reference",
            "$.descriptor_id",
            "a decision without DESCRIPTOR_MISSING must reference its descriptor",
        )

    if value["phase"] == "post_activation" and value["selection_snapshot_id"] is None:
        raise ContractValidationError(
            "missing_reference",
            "$.selection_snapshot_id",
            "a post-activation decision must reference its selection snapshot",
        )


def validate_named_broker_contract(
    name: str, value: Any, schema: dict[str, Any]
) -> None:
    if name == "artifact-root-permission-decision":
        validate_artifact_root_decision(value, schema)
    elif name == "claim-completeness-result":
        validate_claim_completeness_result(value, schema)
    elif name == "decision-receipt":
        validate_decision_receipt(value, schema)
    elif name == "pack-expansion-identity":
        validate_pack_expansion_identity(value, schema)
    else:
        validate_contract(value, schema)


def resolve_action(
    policy: dict[str, Any],
    *,
    phase: str,
    reason_codes: set[str],
    reread_attempts: int,
) -> tuple[str, set[str]]:
    if not reason_codes:
        raise ValueError("the failure resolver requires at least one reason code")
    catalog = policy["reason_catalog"]
    unknown = reason_codes - set(catalog)
    if unknown:
        raise ValueError(f"unknown reason codes: {sorted(unknown)}")
    for reason_code in reason_codes:
        if phase not in catalog[reason_code]["phases"]:
            raise ValueError(f"{reason_code} is unreachable during {phase}")

    categories = {catalog[reason_code]["category"] for reason_code in reason_codes}
    if "integrity_security" in categories:
        action = "BLOCK_TOOL"
    elif "recoverable_freshness" in categories:
        if reread_attempts < policy["reread_limit"]:
            action = "REREAD_THEN_DECIDE"
        elif phase == "pre_activation":
            action = "PASS_THROUGH_UNCHANGED"
        else:
            action = "BLOCK_TOOL"
    elif "pre_activation_eligibility" in categories:
        action = "PASS_THROUGH_UNCHANGED"
    else:
        action = "CLAIM_BLOCK_ONLY"
    return action, set(reason_codes)


class ContextGuardBrokerContractTests(unittest.TestCase):
    def test_required_stage1_artifacts_exist(self) -> None:
        expected = [BROKER_ROOT / name for name in DOCUMENT_NAMES]
        expected.extend(broker_schema_path(name) for name in SCHEMA_NAMES)
        expected.extend(broker_positive_path(name) for name in SCHEMA_NAMES)
        expected.extend(
            [
                BROKER_ROOT / "action-claim-policy.json",
                BROKER_ROOT / "artifact-root-decision.json",
                BROKER_ROOT / "measurement-source-map.json",
                FIXTURE_ROOT / "negative-cases.json",
                FIXTURE_ROOT / "r9-refusal.json",
            ]
        )
        missing = [str(path.relative_to(REPO_ROOT)) for path in expected if not path.is_file()]
        self.assertEqual(missing, [])

    def test_schemas_accept_positive_and_reject_negative_fixtures(self) -> None:
        schemas: dict[str, dict[str, Any]] = {}
        for name in SCHEMA_NAMES:
            with self.subTest(schema=name):
                schema = load_json(broker_schema_path(name))
                schemas[name] = schema
                self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
                self.assertEqual(schema["type"], "object")
                self.assertIs(schema["additionalProperties"], False)
                assert_supported_schema(self, schema)
                assert_closed_total_objects(self, schema)
                self.assertTrue(
                    REQUIRED_CONTRACT_FIELDS.get(name, set()) <= set(schema["properties"])
                )
                validate_named_broker_contract(
                    name,
                    load_json(broker_positive_path(name), canonical=True),
                    schema,
                )

        negative_manifest = load_json(FIXTURE_ROOT / "negative-cases.json", canonical=True)
        cases = negative_manifest["cases"]
        covered_schemas = {case["schema"] for case in cases}
        self.assertEqual(covered_schemas, set(SCHEMA_NAMES))
        self.assertTrue(
            {"required", "additionalProperties", "pattern", "enum", "type"}
            <= {case["expected_violation"] for case in cases}
        )
        for case in cases:
            with self.subTest(case=case["case_id"]):
                with self.assertRaises(ContractValidationError) as caught:
                    validate_contract(case["instance"], schemas[case["schema"]])
                self.assertEqual(caught.exception.code, case["expected_violation"])

    def test_explicit_missing_observation_and_join_states_validate_without_fake_ids(self) -> None:
        cases = (
            (
                "tool-observation-receipt",
                POSITIVE_ROOT / "tool-observation-receipt-missing.json",
            ),
            ("provider-turn-join", POSITIVE_ROOT / "provider-turn-join-missing.json"),
        )
        for schema_name, path in cases:
            with self.subTest(schema=schema_name):
                schema = load_json(broker_schema_path(schema_name))
                fixture = load_json(path, canonical=True)
                validate_contract(fixture, schema)
                if schema_name == "tool-observation-receipt":
                    self.assertEqual(fixture["observation_status"], "missing")
                    self.assertIsNone(fixture["result_utf8_bytes"])
                    self.assertIsNone(fixture["domain_separated_content_sha256"])
                else:
                    self.assertEqual(fixture["joining_status"], "missing")
                    self.assertIsNone(fixture["provider_turn_id"])

    def test_descriptor_missing_decision_uses_null_refs_without_fake_ids(self) -> None:
        schema = load_json(broker_schema_path("decision-receipt"))
        fixture = load_json(POSITIVE_ROOT / "decision-receipt.json", canonical=True)
        missing_descriptor = copy.deepcopy(fixture)
        missing_descriptor["action"] = "PASS_THROUGH_UNCHANGED"
        missing_descriptor["claim_blockers"] = ["DESCRIPTOR_MISSING"]
        missing_descriptor["descriptor_id"] = None
        missing_descriptor["selection_snapshot_id"] = None
        validate_decision_receipt(missing_descriptor, schema)

        fake_references = copy.deepcopy(missing_descriptor)
        fake_references["descriptor_id"] = "fabricated-descriptor"
        fake_references["selection_snapshot_id"] = "fabricated-snapshot"
        with self.assertRaises(ContractValidationError):
            validate_decision_receipt(fake_references, schema)

    def test_cross_field_contradictions_are_rejected(self) -> None:
        cases: list[tuple[str, dict[str, Any]]] = []

        root_decision = load_json(BROKER_ROOT / "artifact-root-decision.json", canonical=True)
        bad_root = copy.deepcopy(root_decision)
        bad_root["status"] = "selected"
        cases.append(("artifact-root-permission-decision", bad_root))

        observation = load_json(POSITIVE_ROOT / "tool-observation-receipt.json", canonical=True)
        bad_observation = copy.deepcopy(observation)
        bad_observation["observation_status"] = "missing"
        cases.append(("tool-observation-receipt", bad_observation))

        provider_join = load_json(POSITIVE_ROOT / "provider-turn-join.json", canonical=True)
        bad_join = copy.deepcopy(provider_join)
        bad_join["provider_turn_id"] = None
        bad_join["provider_usage_status"] = "missing"
        bad_join["provider_cost_status"] = "missing"
        cases.append(("provider-turn-join", bad_join))

        decision = load_json(POSITIVE_ROOT / "decision-receipt.json", canonical=True)
        bad_decision = copy.deepcopy(decision)
        bad_decision["action"] = "CLAIM_BLOCK_ONLY"
        bad_decision["activation_status"] = "activated"
        cases.append(("decision-receipt", bad_decision))

        claim = load_json(POSITIVE_ROOT / "claim-completeness-result.json", canonical=True)
        bad_claim = copy.deepcopy(claim)
        bad_claim["claim_allowed"] = True
        cases.append(("claim-completeness-result", bad_claim))

        for schema_name, instance in cases:
            with self.subTest(schema=schema_name):
                with self.assertRaises(ContractValidationError):
                    validate_contract(instance, load_json(broker_schema_path(schema_name)))

    def test_policy_reason_codes_fit_receipt_contracts(self) -> None:
        policy = load_json(BROKER_ROOT / "action-claim-policy.json", canonical=True)
        for schema_name in ("decision-receipt", "claim-completeness-result"):
            schema = load_json(broker_schema_path(schema_name))
            reason_schema = schema["$defs"]["reason_code"]
            for reason_code in policy["reason_catalog"]:
                with self.subTest(schema=schema_name, reason=reason_code):
                    validate_contract(reason_code, reason_schema, root_schema=schema)

    def test_decision_receipt_matches_policy_precedence_for_every_reason(self) -> None:
        policy = load_json(BROKER_ROOT / "action-claim-policy.json", canonical=True)
        schema = load_json(broker_schema_path("decision-receipt"))
        fixture = load_json(POSITIVE_ROOT / "decision-receipt.json", canonical=True)
        self.assertEqual(fixture["action"], "BLOCK_TOOL")
        self.assertEqual(fixture["claim_blockers"], ["UNSAFE_ARTIFACT_ROOT"])

        for reason_code, details in policy["reason_catalog"].items():
            for phase in details["phases"]:
                expected_action, _ = resolve_action(
                    policy,
                    phase=phase,
                    reason_codes={reason_code},
                    reread_attempts=0,
                )
                receipt = copy.deepcopy(fixture)
                receipt["action"] = expected_action
                receipt["activation_status"] = (
                    "activated" if phase == "post_activation" else "not_activated"
                )
                receipt["claim_blockers"] = [reason_code]
                receipt["phase"] = phase
                receipt["reread_attempts"] = 0
                if reason_code == "DESCRIPTOR_MISSING":
                    receipt["descriptor_id"] = None
                    receipt["selection_snapshot_id"] = None
                with self.subTest(reason=reason_code, phase=phase):
                    validate_decision_receipt(receipt, schema)

        wrong_security_action = copy.deepcopy(fixture)
        wrong_security_action["action"] = "PASS_THROUGH_UNCHANGED"
        with self.assertRaises(ContractValidationError):
            validate_contract(wrong_security_action, schema)

        unknown_reason = copy.deepcopy(fixture)
        unknown_reason["claim_blockers"] = ["UNKNOWN_BROKER_REASON"]
        with self.assertRaises(ContractValidationError):
            validate_contract(unknown_reason, schema)

        phase_categories = {
            "pre_activation": (
                "integrity_security",
                "recoverable_freshness",
                "pre_activation_eligibility",
            ),
            "post_activation": (
                "integrity_security",
                "recoverable_freshness",
                "post_execution_evidence",
            ),
        }
        for phase, categories in phase_categories.items():
            representatives = [
                next(
                    reason
                    for reason, details in policy["reason_catalog"].items()
                    if details["category"] == category and phase in details["phases"]
                )
                for category in categories
            ]
            for enabled in itertools.product((False, True), repeat=len(representatives)):
                if not any(enabled):
                    continue
                reasons = {
                    reason
                    for reason, is_enabled in zip(representatives, enabled)
                    if is_enabled
                }
                for reread_attempts in (0, 1):
                    expected_action, _ = resolve_action(
                        policy,
                        phase=phase,
                        reason_codes=reasons,
                        reread_attempts=reread_attempts,
                    )
                    receipt = copy.deepcopy(fixture)
                    receipt["action"] = expected_action
                    receipt["activation_status"] = (
                        "activated" if phase == "post_activation" else "not_activated"
                    )
                    receipt["claim_blockers"] = sorted(reasons)
                    receipt["phase"] = phase
                    receipt["reread_attempts"] = reread_attempts
                    if "DESCRIPTOR_MISSING" in reasons:
                        receipt["descriptor_id"] = None
                        receipt["selection_snapshot_id"] = None
                    with self.subTest(
                        phase=phase,
                        enabled=enabled,
                        reread_attempts=reread_attempts,
                    ):
                        validate_decision_receipt(receipt, schema)

    def test_descriptor_paths_are_normalized_repository_relative_and_non_secret(self) -> None:
        schema = load_json(broker_schema_path("broker-task-descriptor"))
        fixture = load_json(POSITIVE_ROOT / "broker-task-descriptor.json", canonical=True)
        for unsafe_path in ("../../outside", "/absolute/path", ".env", "src/../outside"):
            invalid = copy.deepcopy(fixture)
            invalid["allowed_seed_paths"] = [unsafe_path]
            with self.subTest(path=unsafe_path):
                with self.assertRaises(ContractValidationError):
                    validate_contract(invalid, schema)

    def test_expansion_entries_have_safe_paths_and_nonempty_ranges(self) -> None:
        schema = load_json(broker_schema_path("pack-expansion-identity"))
        fixture = load_json(POSITIVE_ROOT / "pack-expansion-identity.json", canonical=True)
        expansion_schema = schema["$defs"]["expansion"]
        self.assertEqual(
            set(expansion_schema["required"]),
            set(expansion_schema["properties"]),
        )
        self.assertIn("source_path", expansion_schema["required"])
        self.assertIn("source_byte_start", expansion_schema["required"])
        self.assertIn("source_byte_length", expansion_schema["required"])
        self.assertIn("source_total_bytes", expansion_schema["required"])
        self.assertNotIn("source_byte_end", expansion_schema["properties"])
        self.assertEqual(fixture["expansion_count"], 2)
        self.assertEqual(len(fixture["expansions"]), 2)
        validate_pack_expansion_identity(fixture, schema)

        for unsafe_path in ("../../outside", "/absolute/path", ".env", "src/../outside"):
            invalid = copy.deepcopy(fixture)
            invalid["expansions"][0]["source_path"] = unsafe_path
            with self.subTest(path=unsafe_path):
                with self.assertRaises(ContractValidationError):
                    validate_contract(invalid, schema)

        empty_range = copy.deepcopy(fixture)
        empty_range["expansions"][0]["source_byte_length"] = 0
        with self.assertRaises(ContractValidationError):
            validate_contract(empty_range, schema)

        unsorted = copy.deepcopy(fixture)
        unsorted["expansions"].reverse()
        with self.assertRaises(ContractValidationError):
            validate_pack_expansion_identity(unsorted, schema)

        overlapping = copy.deepcopy(fixture)
        overlapping["expansions"][1]["source_byte_start"] = 4
        with self.assertRaises(ContractValidationError):
            validate_pack_expansion_identity(overlapping, schema)

        out_of_range = copy.deepcopy(fixture)
        out_of_range["expansions"][1]["source_byte_start"] = 20
        with self.assertRaises(ContractValidationError):
            validate_pack_expansion_identity(out_of_range, schema)

        content_mismatch = copy.deepcopy(fixture)
        content_mismatch["expansions"][1]["delivered_content_sha256"] = "a" * 64
        with self.assertRaises(ContractValidationError):
            validate_pack_expansion_identity(content_mismatch, schema)

        duplicate_expansion_id = copy.deepcopy(fixture)
        duplicate_expansion_id["expansions"][1]["expansion_id"] = (
            duplicate_expansion_id["expansions"][0]["expansion_id"]
        )
        with self.assertRaises(ContractValidationError) as duplicate_caught:
            validate_pack_expansion_identity(duplicate_expansion_id, schema)
        self.assertEqual(duplicate_caught.exception.code, "expansion_identity")

        split_source_identity = copy.deepcopy(fixture)
        split_source_identity["expansions"][1]["source_path"] = "src/zsynthetic.py"
        with self.assertRaises(ContractValidationError) as source_caught:
            validate_pack_expansion_identity(split_source_identity, schema)
        self.assertEqual(source_caught.exception.code, "source_identity")

        aliased_source_path = copy.deepcopy(fixture)
        aliased_source_path["expansions"][1]["source_id"] = "source-p0-002"
        aliased_source_path["expansions"][1]["source_total_bytes"] = 999
        aliased_source_path["expansion_identity_sha256"] = hashlib.sha256(
            b"contextguard-broker/expansion-identity/v1\x00"
            + canonical_json_bytes(aliased_source_path["expansions"])
        ).hexdigest()
        with self.assertRaises(ContractValidationError) as alias_caught:
            validate_pack_expansion_identity(aliased_source_path, schema)
        self.assertEqual(alias_caught.exception.code, "source_identity")

    def test_host_ids_allow_bounded_opaque_values(self) -> None:
        schema = load_json(broker_schema_path("tool-observation-receipt"))
        fixture = load_json(POSITIVE_ROOT / "tool-observation-receipt.json", canonical=True)
        fixture["session_id"] = "SESSION.01:AbC"
        fixture["tool_use_id"] = "toolu_01ABC.def"
        validate_contract(fixture, schema)

    def test_epr_fixture_uses_the_frozen_domain_and_exact_utf8_length(self) -> None:
        framed_result = b"     1\tsynthetic evidence\n"
        expected_hash = hashlib.sha256(
            b"contextguard-broker/epr-read-result/v1\x00" + framed_result
        ).hexdigest()
        fixture = load_json(POSITIVE_ROOT / "tool-observation-receipt.json", canonical=True)
        self.assertEqual(fixture["result_utf8_bytes"], len(framed_result))
        self.assertEqual(fixture["domain_separated_content_sha256"], expected_hash)

    def test_positive_fixture_hash_chain_is_real_and_tamper_evident(self) -> None:
        self_hashes = (
            ("broker-task-descriptor.json", "descriptor_sha256"),
            ("decision-receipt.json", "decision_sha256"),
            ("provider-turn-join.json", "join_sha256"),
            ("provider-turn-join-missing.json", "join_sha256"),
            ("selection-snapshot.json", "selection_snapshot_sha256"),
            ("attempt-subordinate-receipt-bundle.json", "bundle_sha256"),
            ("claim-completeness-result.json", "result_sha256"),
        )
        for fixture_name, hash_field in self_hashes:
            fixture = load_json(POSITIVE_ROOT / fixture_name, canonical=True)
            with self.subTest(fixture=fixture_name, field=hash_field):
                self.assertEqual(
                    fixture[hash_field], artifact_identity_sha256(fixture, hash_field)
                )

        descriptor = load_json(POSITIVE_ROOT / "broker-task-descriptor.json", canonical=True)
        selection = load_json(POSITIVE_ROOT / "selection-snapshot.json", canonical=True)
        bundle_path = POSITIVE_ROOT / "attempt-subordinate-receipt-bundle.json"
        bundle = load_json(bundle_path, canonical=True)
        claim = load_json(POSITIVE_ROOT / "claim-completeness-result.json", canonical=True)
        self.assertEqual(set(claim["metric_results"]), {"EPR", "FLC-QGS", "PAT-PCD"})
        decision_path = POSITIVE_ROOT / "decision-receipt.json"
        observation_paths = {
            "provider-turn-join.json": POSITIVE_ROOT / "tool-observation-receipt.json",
            "provider-turn-join-missing.json": POSITIVE_ROOT
            / "tool-observation-receipt-missing.json",
        }
        self.assertEqual(selection["descriptor_sha256"], descriptor["descriptor_sha256"])
        self.assertEqual(bundle["descriptor_sha256"], descriptor["descriptor_sha256"])
        self.assertEqual(
            bundle["receipt_refs"]["decision_receipts"]["receipt-p0-001"],
            hashlib.sha256(decision_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(claim["bundle_sha256"], hashlib.sha256(bundle_path.read_bytes()).hexdigest())
        for join_name, observation_path in observation_paths.items():
            join = load_json(POSITIVE_ROOT / join_name, canonical=True)
            self.assertEqual(
                join["observation_receipt_sha256"],
                hashlib.sha256(observation_path.read_bytes()).hexdigest(),
            )

        pack = load_json(POSITIVE_ROOT / "pack-expansion-identity.json", canonical=True)
        pack_bytes = b"# synthetic evidence pack\n"
        self.assertEqual(
            pack["pack_content_sha256"],
            hashlib.sha256(b"contextguard-broker/pack-content/v1\x00" + pack_bytes).hexdigest(),
        )
        self.assertEqual(pack["expansion_count"], len(pack["expansions"]))
        self.assertEqual(
            pack["expansion_identity_sha256"],
            hashlib.sha256(
                b"contextguard-broker/expansion-identity/v1\x00"
                + canonical_json_bytes(pack["expansions"])
            ).hexdigest(),
        )

        tampered = copy.deepcopy(descriptor)
        tampered["task_id"] = "task-p0-tampered"
        self.assertNotEqual(
            descriptor["descriptor_sha256"],
            artifact_identity_sha256(tampered, "descriptor_sha256"),
        )

    def test_subordinate_bundle_refs_are_content_addressed_and_typed(self) -> None:
        schema = load_json(broker_schema_path("attempt-subordinate-receipt-bundle"))
        fixture = load_json(
            POSITIVE_ROOT / "attempt-subordinate-receipt-bundle.json", canonical=True
        )
        refs_schema = schema["$defs"]["receipt_refs"]
        expected_buckets = {
            "artifact_root_permission_decisions",
            "decision_receipts",
            "pack_expansion_identities",
            "provider_turn_joins",
            "selection_snapshots",
            "tool_observation_receipts",
        }
        self.assertEqual(set(refs_schema["properties"]), expected_buckets)
        self.assertEqual(set(refs_schema["required"]), expected_buckets)
        self.assertEqual(set(fixture["receipt_refs"]), expected_buckets)
        self.assertEqual(fixture["bundle_profile"], "pre_activation_blocked")
        validate_contract(fixture, schema)

        false_complete = copy.deepcopy(fixture)
        false_complete["completeness"] = "complete"
        with self.assertRaises(ContractValidationError):
            validate_contract(false_complete, schema)

        duplicate_identity = (
            b'{"receipt-p0-001":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
            b'"receipt-p0-001":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}'
        )
        with self.assertRaisesRegex(ValueError, "duplicate"):
            strict_json_loads(
                duplicate_identity,
                owner="duplicate-receipt-identity",
                canonical=False,
            )

    def test_bundle_complete_profile_requires_nonblocking_evidence_and_receipts(self) -> None:
        schema = load_json(broker_schema_path("attempt-subordinate-receipt-bundle"))
        fixture = load_json(
            POSITIVE_ROOT / "attempt-subordinate-receipt-bundle.json", canonical=True
        )
        complete = copy.deepcopy(fixture)
        complete["blocking_reasons"] = []
        complete["bundle_profile"] = "pass_through"
        complete["completeness"] = "complete"
        for component_name in (
            "index_build_maintenance_cost_usd",
            "paid_helper_cost_usd",
        ):
            complete["cost_components"][component_name] = {
                "amount_usd_micros": 0,
                "claim_blocking": False,
                "provenance": "measured",
                "status": "observed",
            }
        for inclusion_name in (
            "expansion_retry_inclusion_status",
            "expansion_retry_correction_failure_inclusion_status",
        ):
            complete["cost_components"][inclusion_name] = {
                "claim_blocking": False,
                "provenance": "measured",
                "status": "included",
            }
        complete["latency_observation"] = {
            "claim_blocking": False,
            "elapsed_ms": 0,
            "status": "observed",
        }
        complete["privacy_status"] = "pass"
        complete["provenance_status"] = "pass"
        complete["receipt_refs"]["tool_observation_receipts"] = {
            "observe-p0-001": "a" * 64
        }
        complete["receipt_refs"]["provider_turn_joins"] = {"join-p0-001": "b" * 64}
        validate_contract(complete, schema)

        missing_join = copy.deepcopy(complete)
        missing_join["receipt_refs"]["provider_turn_joins"] = {}
        with self.assertRaises(ContractValidationError):
            validate_contract(missing_join, schema)

        blocking_cost = copy.deepcopy(complete)
        blocking_cost["cost_components"]["paid_helper_cost_usd"] = {
            "amount_usd_micros": None,
            "claim_blocking": True,
            "provenance": "unavailable",
            "status": "unavailable",
        }
        with self.assertRaises(ContractValidationError):
            validate_contract(blocking_cost, schema)

        missing_receipts = copy.deepcopy(complete)
        missing_receipts["blocking_reasons"] = ["RECEIPT_DURABILITY_UNCERTAIN"]
        missing_receipts["completeness"] = "claim_blocked"
        for receipt_map in missing_receipts["receipt_refs"].values():
            receipt_map.clear()
        validate_contract(missing_receipts, schema)

    def test_claim_completeness_allows_mixed_metrics_but_never_false_authorization(self) -> None:
        schema = load_json(broker_schema_path("claim-completeness-result"))
        fixture = load_json(POSITIVE_ROOT / "claim-completeness-result.json", canonical=True)
        self.assertNotIn("blocking_reasons", schema["properties"])
        self.assertEqual(
            set(fixture["gate_results"]),
            {"activation", "correction", "failure", "latency", "privacy", "provenance", "quality"},
        )

        mixed = copy.deepcopy(fixture)
        mixed["claim_allowed"] = False
        mixed["completeness"] = "incomplete"
        mixed["metric_results"] = {
            "EPR": {
                "blocking_reasons": ["READ_OBSERVATION_MISSING"],
                "metric": "EPR",
                "status": "unavailable",
            },
            "FLC-QGS": {"blocking_reasons": [], "metric": "FLC-QGS", "status": "complete"},
            "PAT-PCD": {"blocking_reasons": [], "metric": "PAT-PCD", "status": "complete"},
        }
        mixed["gate_results"] = {
            gate: {"blocking_reasons": [], "gate": gate, "status": "pass"}
            for gate in ("activation", "correction", "failure", "latency", "privacy", "provenance", "quality")
        }
        validate_claim_completeness_result(mixed, schema)

        blocked_with_unavailable = copy.deepcopy(mixed)
        blocked_with_unavailable["completeness"] = "claim_blocked"
        blocked_with_unavailable["metric_results"]["FLC-QGS"] = {
            "blocking_reasons": ["COST_EVIDENCE_GAP"],
            "metric": "FLC-QGS",
            "status": "claim_blocked",
        }
        blocked_with_unavailable["gate_results"]["quality"] = {
            "blocking_reasons": ["QUALITY_GATE_NOT_FROZEN"],
            "gate": "quality",
            "status": "claim_blocked",
        }
        validate_claim_completeness_result(blocked_with_unavailable, schema)

        misclassified_blocker = copy.deepcopy(blocked_with_unavailable)
        misclassified_blocker["completeness"] = "incomplete"
        with self.assertRaises(ContractValidationError):
            validate_claim_completeness_result(misclassified_blocker, schema)

        false_authorization = copy.deepcopy(mixed)
        false_authorization["claim_allowed"] = True
        with self.assertRaises(ContractValidationError):
            validate_claim_completeness_result(false_authorization, schema)

        complete = copy.deepcopy(mixed)
        complete["claim_allowed"] = True
        complete["completeness"] = "complete"
        for metric in complete["metric_results"].values():
            metric["blocking_reasons"] = []
            metric["status"] = "complete"
        validate_claim_completeness_result(complete, schema)

        blocked_gate = copy.deepcopy(complete)
        blocked_gate["gate_results"]["quality"] = {
            "blocking_reasons": ["QUALITY_GATE_NOT_FROZEN"],
            "gate": "quality",
            "status": "claim_blocked",
        }
        with self.assertRaises(ContractValidationError):
            validate_claim_completeness_result(blocked_gate, schema)

    def test_all_machine_fixtures_are_canonical_and_strict(self) -> None:
        paths = list(POSITIVE_ROOT.glob("*.json"))
        paths.extend(
            [
                BROKER_ROOT / "action-claim-policy.json",
                BROKER_ROOT / "artifact-root-decision.json",
                BROKER_ROOT / "measurement-source-map.json",
                FIXTURE_ROOT / "negative-cases.json",
                FIXTURE_ROOT / "r9-refusal.json",
            ]
        )
        self.assertGreaterEqual(len(paths), 13)
        for path in paths:
            with self.subTest(path=path.name):
                load_json(path, canonical=True)

        duplicate = b'{"schema_version":"v1","schema_version":"v2"}\n'
        with self.assertRaisesRegex(ValueError, "duplicate"):
            strict_json_loads(duplicate, owner="duplicate-fixture", canonical=True)
        nonfinite = b'{"value":NaN}\n'
        with self.assertRaisesRegex(ValueError, "non-finite"):
            strict_json_loads(nonfinite, owner="nonfinite-fixture", canonical=True)

    def test_receipts_never_retain_raw_sensitive_payloads(self) -> None:
        forbidden_keys = {
            "arbitrary_command",
            "command",
            "credential",
            "credentials",
            "environment",
            "environment_values",
            "prompt",
            "raw_prompt",
            "raw_source",
            "raw_tool_output",
            "secret",
            "source_text",
            "tool_output",
        }

        def visit(value: Any, *, owner: str) -> None:
            if isinstance(value, dict):
                overlap = forbidden_keys & set(value)
                self.assertFalse(overlap, f"{owner} contains forbidden keys: {sorted(overlap)}")
                for child in value.values():
                    visit(child, owner=owner)
            elif isinstance(value, list):
                for child in value:
                    visit(child, owner=owner)

        for name in SCHEMA_NAMES:
            if name == "broker-task-descriptor":
                continue
            path = broker_positive_path(name)
            visit(load_json(path, canonical=True), owner=path.name)

    def test_action_policy_is_phase_aware_exhaustive_and_lossless(self) -> None:
        policy = load_json(BROKER_ROOT / "action-claim-policy.json", canonical=True)
        self.assertEqual(
            set(policy["actions"]),
            {
                "BLOCK_TOOL",
                "REREAD_THEN_DECIDE",
                "PASS_THROUGH_UNCHANGED",
                "CLAIM_BLOCK_ONLY",
            },
        )
        self.assertEqual(policy["reread_limit"], 1)
        self.assertEqual(
            policy["precedence"],
            [
                "integrity_security",
                "recoverable_freshness",
                "pre_activation_eligibility",
                "post_execution_evidence",
            ],
        )

        phase_categories = {
            "pre_activation": (
                "integrity_security",
                "recoverable_freshness",
                "pre_activation_eligibility",
            ),
            "post_activation": (
                "integrity_security",
                "recoverable_freshness",
                "post_execution_evidence",
            ),
        }
        catalog = policy["reason_catalog"]
        self.assertEqual(set(catalog), set(REQUIRED_ACTION_REASON_CODES))
        integrity_both = {
            "SECRET_OR_PROTECTED_PATH_MATCH",
            "UNSAFE_ARTIFACT_ROOT",
            "PERMISSION_AMBIGUITY",
            "SYMLINK_OR_ROOT_ESCAPE",
            "PACK_HASH_MISMATCH",
        }
        freshness = {
            "SOURCE_FRESHNESS_MISMATCH",
            "INDEX_FRESHNESS_MISMATCH",
            "DIRTY_STATE_MISMATCH",
            "CANDIDATE_UNIVERSE_MISMATCH",
            "AUTHORIZATION_FRESHNESS_MISMATCH",
        }
        eligibility = {
            "DESCRIPTOR_MISSING",
            "INELIGIBLE_STRATUM",
            "UNSUPPORTED_HOST",
            "STALE_AUTHORIZATION_PRE_PROTECTED_ACCESS",
            "PROTECTED_CLASSIFIER_UNAVAILABLE_PRE_ACTIVATION",
            "BUDGET_OR_MATERIALIZATION_FAILURE",
            "EMPTY_SELECTION",
            "INDEX_UNAVAILABLE",
        }
        evidence = {
            "READ_OBSERVATION_MISSING",
            "READ_OBSERVATION_TRUNCATED",
            "PROVIDER_JOIN_MISSING",
            "COST_EVIDENCE_GAP",
            "QUALITY_EVIDENCE_GAP",
            "POST_ACTIVATION_HOOK_FAILURE",
            "RESET_MISMATCH",
            "CROSS_ARM_LEAKAGE",
            "RECEIPT_DURABILITY_UNCERTAIN",
        }
        for reason in integrity_both:
            self.assertEqual(catalog[reason]["category"], "integrity_security")
            self.assertEqual(set(catalog[reason]["phases"]), set(phase_categories))
        classifier_after = "PROTECTED_CLASSIFIER_UNAVAILABLE_AFTER_ACTIVATION"
        self.assertEqual(catalog[classifier_after]["category"], "integrity_security")
        self.assertEqual(catalog[classifier_after]["phases"], ["post_activation"])
        for reason in freshness:
            self.assertEqual(catalog[reason]["category"], "recoverable_freshness")
            self.assertEqual(set(catalog[reason]["phases"]), set(phase_categories))
        for reason in eligibility:
            self.assertEqual(catalog[reason]["category"], "pre_activation_eligibility")
            self.assertEqual(catalog[reason]["phases"], ["pre_activation"])
        for reason in evidence:
            self.assertEqual(catalog[reason]["category"], "post_execution_evidence")
            self.assertEqual(catalog[reason]["phases"], ["post_activation"])
        for phase, categories in phase_categories.items():
            representative: dict[str, str] = {}
            for category in categories:
                representative[category] = next(
                    reason
                    for reason, details in catalog.items()
                    if details["category"] == category and phase in details["phases"]
                )
            for enabled in itertools.product((False, True), repeat=len(categories)):
                if not any(enabled):
                    continue
                reasons = {
                    representative[category]
                    for category, is_enabled in zip(categories, enabled)
                    if is_enabled
                }
                for reread_attempts in (0, 1):
                    with self.subTest(
                        phase=phase, enabled=enabled, reread_attempts=reread_attempts
                    ):
                        action, blockers = resolve_action(
                            policy,
                            phase=phase,
                            reason_codes=reasons,
                            reread_attempts=reread_attempts,
                        )
                        self.assertIn(action, policy["actions"])
                        self.assertEqual(blockers, reasons)
                        if enabled[0]:
                            self.assertEqual(action, "BLOCK_TOOL")
                        elif enabled[1] and reread_attempts == 0:
                            self.assertEqual(action, "REREAD_THEN_DECIDE")
                        elif enabled[1]:
                            self.assertEqual(
                                action,
                                "PASS_THROUGH_UNCHANGED"
                                if phase == "pre_activation"
                                else "BLOCK_TOOL",
                            )
                        elif phase == "pre_activation":
                            self.assertEqual(action, "PASS_THROUGH_UNCHANGED")
                        else:
                            self.assertEqual(action, "CLAIM_BLOCK_ONLY")

        for reason, details in catalog.items():
            self.assertTrue(details["claim_blocking"])
            for phase in details["phases"]:
                with self.subTest(reason=reason, phase=phase):
                    action, blockers = resolve_action(
                        policy,
                        phase=phase,
                        reason_codes={reason},
                        reread_attempts=0,
                    )
                    self.assertIn(action, policy["actions"])
                    self.assertEqual(blockers, {reason})

    def test_measurement_fields_have_explicit_sources_or_block_claims(self) -> None:
        source_map = load_json(BROKER_ROOT / "measurement-source-map.json", canonical=True)
        fields = source_map["fields"]
        field_names = [field["field"] for field in fields]
        self.assertEqual(len(field_names), len(set(field_names)))
        required = {
            "common.attempt_id",
            "common.session_id",
            "common.provider_usage_cost_provenance",
            "common.provider_turn_join_status",
            "common.failure_status",
            "common.correction_count",
            "epr.model_visible_read_result_utf8_bytes",
            "epr.domain_separated_content_sha256",
            "epr.read_tool_use_id",
            "epr.read_observation_receipt_sha256",
            "epr.host_framing_observed",
            "epr.read_observation_completeness",
            "epr.paired_task_difference_utf8_bytes",
            "flc_qgs.assigned_arm_provider_cost_usd",
            "flc_qgs.paid_helper_cost_usd",
            "flc_qgs.index_build_maintenance_cost_usd",
            "flc_qgs.expansion_retry_correction_failure_cost_inclusion_status",
            "flc_qgs.quality_gated_success",
            "flc_qgs.assigned_task_count",
            "flc_qgs.quality_gated_success_count",
            "flc_qgs.success_probability",
            "flc_qgs.treatment_minus_baseline_failure_rate_difference",
            "pat_pcd.pair_id",
            "pat_pcd.assigned_task_cost_usd",
            "pat_pcd.activation_status",
            "pat_pcd.bypass_status",
            "pat_pcd.assignment_arm",
            "pat_pcd.consumed_attempt_status",
            "pat_pcd.retry_count",
            "pat_pcd.paired_assigned_task_cost_difference_usd",
            "gate.activation_status",
            "gate.completeness_status",
            "gate.correction_status",
            "gate.failure_status",
            "gate.latency_status",
            "gate.privacy_status",
            "gate.provenance_status",
            "gate.quality_status",
        }
        self.assertTrue(required <= set(field_names))
        allowed_sources = {
            "existing_authority",
            "new_subordinate_observation",
            "unavailable_claim_blocking",
        }
        for field in fields:
            with self.subTest(field=field["field"]):
                self.assertIn(field["source_status"], allowed_sources)
                self.assertTrue(field["source"])
                self.assertRegex(
                    field["contract_field"],
                    r"^(?:derived|existing|schema|unavailable):",
                )
                self.assertIn(field["zero_semantics"], {"observed", "not_applicable"})
                self.assertEqual(field["missing_effect"], "claim_blocking")
                if field["source_status"] == "unavailable_claim_blocking":
                    self.assertTrue(field["claim_blocking_when_absent"])
        quality = next(field for field in fields if field["field"] == "flc_qgs.quality_gated_success")
        self.assertEqual(quality["source_status"], "unavailable_claim_blocking")

    def test_artifact_root_is_explicitly_transport_rejected(self) -> None:
        schema = load_json(broker_schema_path("artifact-root-permission-decision"))
        self.assertEqual(
            schema["$defs"]["settings"]["properties"]["effective_settings_sha256"],
            {"$ref": "#/$defs/nullable_sha256"},
        )
        decision = load_json(BROKER_ROOT / "artifact-root-decision.json", canonical=True)
        validate_artifact_root_decision(decision, schema)
        self.assertEqual(decision["status"], "transport_rejected")
        self.assertIsNone(decision["selected_tuple"])
        self.assertFalse(decision["network_used"])
        self.assertFalse(decision["provider_called"])
        self.assertFalse(decision["settings_modified"])
        self.assertEqual(decision["host"]["claude_code_version"], "2.1.221")
        self.assertEqual(
            decision["permission_evaluator"]["execution_status"],
            "not_executed_provider_free_path_unavailable",
        )
        self.assertIsNone(decision["settings"]["effective_settings_sha256"])
        self.assertIs(decision["settings"]["source_inventory_complete"], False)
        self.assertGreaterEqual(len(decision["settings"]["sources"]), 3)
        self.assertEqual(
            {source["source_kind"] for source in decision["settings"]["sources"].values()},
            {"local", "managed", "project", "user"},
        )
        self.assertGreaterEqual(len(decision["candidates"]), 4)
        self.assertNotIn("selected", {candidate["outcome"] for candidate in decision["candidates"]})

    def test_selected_root_tuple_has_single_owned_host_settings_and_candidate(self) -> None:
        schema = load_json(broker_schema_path("artifact-root-permission-decision"))
        decision = load_json(BROKER_ROOT / "artifact-root-decision.json", canonical=True)
        self.assertEqual(
            set(schema["$defs"]["selected_tuple"]["properties"]),
            {"selected_candidate"},
        )
        self.assertEqual(
            set(schema["$defs"]["settings_sources"]["properties"]),
            {"local", "managed", "project", "user"},
        )

        project_source = next(
            source
            for source in decision["settings"]["sources"].values()
            if source["source_kind"] == "project"
        )
        selected = copy.deepcopy(decision)
        selected["attempt_id"] = "attempt-p0-001"
        selected["status"] = "selected"
        selected["rejection_reason_codes"] = []
        selected["permission_evaluator"]["execution_status"] = "executed"
        selected["permission_evaluator"]["static_evidence"] = [
            "candidate_permission_matrix_verified",
            "installed_permission_evaluator_executed",
            "settings_semantics_evaluated",
        ]
        selected["permission_evaluator"]["unproven_capabilities"] = []
        selected["settings"] = {
            "effective_settings_sha256": "a" * 64,
            "evaluation_note": "Synthetic fully inspected settings decision.",
            "source_inventory_complete": True,
            "sources": {
                "local": {
                    "canonical_sha256": None,
                    "inspection_status": "confirmed_absent_safe_metadata",
                    "present": False,
                    "raw_sha256": None,
                    "source_kind": "local",
                },
                "managed": {
                    "canonical_sha256": None,
                    "inspection_status": "confirmed_absent_safe_metadata",
                    "present": False,
                    "raw_sha256": None,
                    "source_kind": "managed",
                },
                "project": project_source,
                "user": {
                    "canonical_sha256": None,
                    "inspection_status": "confirmed_absent_safe_metadata",
                    "present": False,
                    "raw_sha256": None,
                    "source_kind": "user",
                },
            },
        }
        selected["candidates"] = [
            candidate
            for candidate in selected["candidates"]
            if candidate["candidate_id"] != "system_temporary_attempt_directory"
        ]
        selected["selected_tuple"] = {
            "selected_candidate": {
                "candidate_id": "system_temporary_attempt_directory",
                "location_class": "system_temporary",
                "outcome": "selected",
                "root_path": "/private/tmp/contextguard-broker/attempt-p0-001",
                "verification": {
                    "attempt_specific": True,
                    "bounded_cleanup_enforced": True,
                    "existing_deny_precedence_proven": True,
                    "git_workspace_excluded": True,
                    "narrow_readability_proven": True,
                    "non_symlinked_components": True,
                    "owner_only_mode_enforced": True,
                    "unrelated_read_tool_excluded": True,
                },
            }
        }
        validate_artifact_root_decision(selected, schema)

        dangling_candidate = copy.deepcopy(selected)
        dangling_candidate["selected_tuple"]["selected_candidate"]["outcome"] = "unverified"
        with self.assertRaises(ContractValidationError):
            validate_artifact_root_decision(dangling_candidate, schema)

        unsafe_settings = copy.deepcopy(selected)
        unsafe_settings["settings"]["sources"]["user"] = {
            "canonical_sha256": None,
            "inspection_status": "not_inspected_secret_boundary",
            "present": True,
            "raw_sha256": None,
            "source_kind": "user",
        }
        with self.assertRaises(ContractValidationError):
            validate_artifact_root_decision(unsafe_settings, schema)

        duplicate_selected = copy.deepcopy(selected)
        duplicate_selected["candidates"].append(
            {
                "bounded_path_hint": "/private/tmp/contextguard-broker/alternative",
                "candidate_id": "system_temporary_attempt_directory",
                "location_class": "system_temporary",
                "outcome": "unverified",
                "reason_codes": ["permission_unproven"],
                "static_checks": ["permission_evaluator_not_executed"],
            }
        )
        with self.assertRaises(ContractValidationError):
            validate_artifact_root_decision(duplicate_selected, schema)

        duplicate_alternative = copy.deepcopy(selected)
        duplicate_alternative["candidates"].append(
            {
                **duplicate_alternative["candidates"][0],
                "bounded_path_hint": "/private/tmp/contextguard-broker/duplicate",
            }
        )
        with self.assertRaises(ContractValidationError):
            validate_artifact_root_decision(duplicate_alternative, schema)

        unsafe_root = copy.deepcopy(selected)
        unsafe_root["selected_tuple"]["selected_candidate"]["root_path"] = (
            "/private/tmp/../../workspace"
        )
        with self.assertRaises(ContractValidationError):
            validate_artifact_root_decision(unsafe_root, schema)

        missing_proof = copy.deepcopy(selected)
        missing_proof["selected_tuple"]["selected_candidate"]["verification"][
            "unrelated_read_tool_excluded"
        ] = False
        with self.assertRaises(ContractValidationError):
            validate_artifact_root_decision(missing_proof, schema)

        contradictory_evaluator = copy.deepcopy(selected)
        contradictory_evaluator["permission_evaluator"]["static_evidence"] = [
            "provider_free_permission_entry_point_unavailable"
        ]
        with self.assertRaises(ContractValidationError):
            validate_artifact_root_decision(contradictory_evaluator, schema)

        fake_evaluator = copy.deepcopy(selected)
        fake_evaluator["permission_evaluator"]["identity"] = "unrelated_evaluator"
        with self.assertRaises(ContractValidationError):
            validate_artifact_root_decision(fake_evaluator, schema)

        for invalid_root in (
            "/Users/jinhongan/Desktop/claude_token_project/contextguard-broker/attempt-p0-001",
            "/Users/jinhongan/.ssh/contextguard-broker/attempt-p0-001",
            "/Users/jinhongan/Library/Caches/contextguard-broker/attempt-p0-001",
            "/tmp/contextguard-broker/attempt-p0-001",
        ):
            invalid_location = copy.deepcopy(selected)
            invalid_location["selected_tuple"]["selected_candidate"]["root_path"] = invalid_root
            with self.subTest(root_path=invalid_root):
                with self.assertRaises(ContractValidationError):
                    validate_artifact_root_decision(invalid_location, schema)

        mismatched_attempt = copy.deepcopy(selected)
        mismatched_attempt["selected_tuple"]["selected_candidate"]["root_path"] = (
            "/private/tmp/contextguard-broker/other-attempt"
        )
        with self.assertRaises(ContractValidationError):
            validate_artifact_root_decision(mismatched_attempt, schema)

    def test_csv_columns_and_r9_public_results_remain_frozen(self) -> None:
        benchmark_path = REPO_ROOT / "context-guard-kit" / "benchmark_runner.py"
        module = ast.parse(benchmark_path.read_text(encoding="utf-8"))
        csv_columns: list[str] | None = None
        for node in module.body:
            if not isinstance(node, ast.Assign):
                continue
            if any(isinstance(target, ast.Name) and target.id == "CSV_COLUMNS" for target in node.targets):
                csv_columns = ast.literal_eval(node.value)
                break
        self.assertIsNotNone(csv_columns)
        encoded_columns = json.dumps(
            csv_columns, ensure_ascii=True, separators=(",", ":")
        ).encode("utf-8")
        self.assertEqual(hashlib.sha256(encoded_columns).hexdigest(), CSV_COLUMNS_SHA256)

        r9_json_path = REPO_ROOT / "bench/token-savings-12task/results/r9-summary.json"
        r9_markdown_path = REPO_ROOT / "bench/token-savings-12task/results/r9-summary.md"
        r9_dashboard_path = REPO_ROOT / "bench/token-savings-12task/results/r9-dashboard.md"
        r9_study_plan_path = REPO_ROOT / "bench/token-savings-12task/study-plan.json"
        r9_hook_evidence_path = REPO_ROOT / "bench/token-savings-12task/hook-event-evidence.json"
        self.assertEqual(hashlib.sha256(r9_json_path.read_bytes()).hexdigest(), R9_SUMMARY_JSON_SHA256)
        self.assertEqual(
            hashlib.sha256(r9_markdown_path.read_bytes()).hexdigest(),
            R9_SUMMARY_MARKDOWN_SHA256,
        )
        self.assertEqual(hashlib.sha256(r9_dashboard_path.read_bytes()).hexdigest(), R9_DASHBOARD_SHA256)
        self.assertEqual(hashlib.sha256(r9_study_plan_path.read_bytes()).hexdigest(), R9_STUDY_PLAN_SHA256)
        self.assertEqual(
            hashlib.sha256(r9_hook_evidence_path.read_bytes()).hexdigest(),
            R9_HOOK_EVIDENCE_SHA256,
        )
        summary = load_json(r9_json_path)
        self.assertEqual(summary["manifest_sha256"], R9_MANIFEST_SHA256)
        self.assertEqual(summary["verdict"], "inconclusive")
        self.assertIs(summary["claim_allowed"], False)
        self.assertIsNone(summary["claim"])
        self.assertIs(summary["subset_analysis_performed"], False)

        refusal = load_json(FIXTURE_ROOT / "r9-refusal.json", canonical=True)
        self.assertEqual(refusal["manifest_sha256"], R9_MANIFEST_SHA256)
        self.assertEqual(refusal["summary_json_sha256"], R9_SUMMARY_JSON_SHA256)
        self.assertEqual(refusal["summary_markdown_sha256"], R9_SUMMARY_MARKDOWN_SHA256)
        self.assertEqual(refusal["dashboard_sha256"], R9_DASHBOARD_SHA256)
        self.assertEqual(refusal["study_plan_sha256"], R9_STUDY_PLAN_SHA256)
        self.assertEqual(refusal["hook_event_evidence_sha256"], R9_HOOK_EVIDENCE_SHA256)
        self.assertEqual(refusal["consumed_attempts"], 33)
        self.assertIs(refusal["private_artifacts_inspected"], False)
        self.assertEqual(refusal["status"], "immutable_inconclusive")
        self.assertIs(refusal["claim_allowed"], False)
        self.assertIn("efficacy_input", refusal["forbidden_uses"])

        new_inputs = [
            load_json(POSITIVE_ROOT / "broker-task-descriptor.json", canonical=True),
            load_json(BROKER_ROOT / "measurement-source-map.json", canonical=True),
        ]
        self.assertNotIn(R9_MANIFEST_SHA256, json.dumps(new_inputs, sort_keys=True))

    def test_documents_are_decision_complete_without_placeholders(self) -> None:
        for name in DOCUMENT_NAMES:
            path = BROKER_ROOT / name
            with self.subTest(document=name):
                text = path.read_text(encoding="utf-8")
                self.assertGreater(len(text), 500)
                self.assertNotRegex(text, r"(?im)\b(?:TODO|TBD|FIXME)\b")


if __name__ == "__main__":
    unittest.main()
