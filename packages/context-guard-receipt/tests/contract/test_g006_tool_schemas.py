from __future__ import annotations

import base64
import importlib
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
from context_guard_receipt.store import (
    CapabilityStore,
    IssuedCapability,
    StoreError,
    StoreErrorCode,
)


def tool_schemas_module():
    try:
        return importlib.import_module("context_guard_receipt.tool_schemas")
    except ModuleNotFoundError as error:
        raise AssertionError("G006 tool-schema implementation is missing") from error


def descriptor(
    catalog: list[dict[str, object]],
    metadata: list[dict[str, object]],
    *,
    catalog_format: str = "anthropic_tools/v1",
    retain_count: int = 1,
) -> tuple[bytes, bytes]:
    payload = canonical_json_bytes(catalog)
    raw = canonical_json_bytes(
        {
            "catalog_format": catalog_format,
            "items": metadata,
            "payload_b64u": base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii"),
            "retain_count": retain_count,
            "schema_version": "contextguard-receipt-tool-schema-descriptor/v1",
        },
        limits=tool_schemas_module().DESCRIPTOR_LIMITS,
    )
    return raw, payload


def item(*, required: bool = False, priority: int = 0, classification: str = "eligible", signals=()):
    return {
        "caller_classification": classification,
        "detector_signals": list(signals),
        "priority": priority,
        "required": required,
    }


class RecordingStore:
    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []

    def issue_batch(self, requests):
        self.calls.append(requests)
        return tuple(
            IssuedCapability(
                handle="cgr1p_" + chr(ord("A") + index) * 43,
                namespace_id="a" * 64,
            )
            for index, _request in enumerate(requests)
        )


class RetrievalStore(RecordingStore):
    def __init__(self) -> None:
        super().__init__()
        self.artifacts: dict[str, object] = {}
        self.retrieve_calls: list[tuple[object, ...]] = []

    def issue_batch(self, requests):
        issued = super().issue_batch(requests)
        for capability, request in zip(issued, requests, strict=True):
            self.artifacts[capability.handle] = SimpleNamespace(
                artifact_type=request.artifact_type,
                byte_length=len(request.payload),
                namespace_id=capability.namespace_id,
                payload=request.payload,
                root_identity_sha256=request.root_identity_sha256,
                subject_identity_sha256=request.subject_identity_sha256,
            )
        return issued

    def retrieve(
        self,
        handle,
        *,
        expected_namespace_id,
        expected_root_identity_sha256,
        expected_subject_identity_sha256,
        expected_artifact_type,
    ):
        self.retrieve_calls.append(
            (
                handle,
                expected_namespace_id,
                expected_root_identity_sha256,
                expected_subject_identity_sha256,
                expected_artifact_type,
            )
        )
        artifact = self.artifacts.get(handle)
        if (
            artifact is None
            or artifact.namespace_id != expected_namespace_id
            or artifact.root_identity_sha256 != expected_root_identity_sha256
            or artifact.subject_identity_sha256 != expected_subject_identity_sha256
            or artifact.artifact_type is not expected_artifact_type
        ):
            raise StoreError(StoreErrorCode.CAPABILITY_REJECTED)
        return artifact


def issued_bundle(*, catalog_format: str = "anthropic_tools/v1"):
    module = tool_schemas_module()
    schema_key = "input_schema" if catalog_format == "anthropic_tools/v1" else "parameters"
    catalog = [
        {"description": "inline" * 700, schema_key: {"type": "object"}, "name": "inline"},
        {"description": "deferred-a" * 700, schema_key: {"type": "object"}, "name": "deferred_a"},
        {"description": "deferred-b" * 700, schema_key: {"type": "object"}, "name": "deferred_b"},
    ]
    raw, payload = descriptor(
        catalog,
        [item(priority=3), item(priority=2), item(priority=1)],
        catalog_format=catalog_format,
    )
    store = RetrievalStore()
    assembled = module.assemble_tool_schemas(raw, store=store)
    if assembled.disposition.value != "deferred":
        raise AssertionError("fixture must take the deferred route")
    return module, catalog, payload, store, parse_canonical_json_bytes(assembled.output_bytes)


class G006ToolSchemaAssemblyTests(unittest.TestCase):
    def test_native_shape_order_and_one_atomic_batch_are_exact(self) -> None:
        """Break caught: rank order, raw schema slices, or atomic request order drifts."""

        module = tool_schemas_module()
        catalog = [
            {"description": "z" * 4_000, "input_schema": {"type": "object"}, "name": "zeta"},
            {"description": "a" * 4_000, "input_schema": {"type": "object"}, "name": "alpha"},
            {"description": "b" * 4_000, "input_schema": {"type": "object"}, "name": "beta"},
        ]
        raw, payload = descriptor(
            catalog,
            [item(priority=1), item(required=True, priority=-7), item(priority=9)],
        )
        store = RecordingStore()

        result = module.assemble_tool_schemas(raw, store=store)

        self.assertEqual(result.disposition.value, "deferred")
        self.assertEqual(len(store.calls), 1)
        self.assertEqual(len(store.calls[0]), 3)
        self.assertEqual(store.calls[0][0].artifact_type.value, "tool_schema_set_bytes")
        self.assertEqual([request.artifact_type.value for request in store.calls[0][1:]], ["tool_schema_bytes"] * 2)
        bundle = parse_canonical_json_bytes(result.output_bytes)
        self.assertEqual([entry["name"] for entry in bundle["inline"]], ["alpha"])
        self.assertEqual([entry["name"] for entry in bundle["deferred"]], ["beta", "zeta"])
        self.assertEqual(result.receipt["input"]["byte_length"], len(payload))
        shifted = result.receipt["shifted_bytes"]
        deferred_raw_bytes = sum(len(canonical_json_bytes(entry)) - 1 for entry in (catalog[2], catalog[0]))
        self.assertEqual(shifted["single_expansion_upper_bound_bytes"], len(payload))
        self.assertEqual(
            shifted["all_expansion_upper_bound_bytes"], len(payload) + deferred_raw_bytes
        )
        self.assertNotIn("tokens", repr(result.receipt).lower())
        self.assertNotIn("percent", repr(result.receipt).lower())

    def test_openai_native_shape_is_selected_without_shape_guessing(self) -> None:
        """Break caught: OpenAI functions are parsed through the Anthropic shape."""

        module = tool_schemas_module()
        catalog = [
            {"description": "x" * 5_000, "name": "lookup", "parameters": {"type": "object"}},
            {"description": "y" * 5_000, "name": "write", "parameters": {"type": "object"}},
        ]
        raw, _payload = descriptor(
            catalog,
            [item(priority=2), item(priority=1)],
            catalog_format="openai_functions/v1",
        )
        result = module.assemble_tool_schemas(raw, store=RecordingStore())
        self.assertEqual(result.disposition.value, "deferred")
        parsed = parse_canonical_json_bytes(result.output_bytes)
        self.assertEqual(parsed["inline"][0], catalog[0])

    def test_secret_precedes_unsupported_shape_and_never_calls_store(self) -> None:
        """Break caught: an unsupported shape bypasses a whole-catalog secret refusal."""

        module = tool_schemas_module()
        raw, payload = descriptor(
            [{"description": "secret", "name": "leak", "parameters": {}}],
            [item(classification="unknown", signals=("secret",))],
        )
        store = RecordingStore()
        result = module.assemble_tool_schemas(raw, store=store)
        self.assertEqual(result.disposition.value, "refused")
        self.assertEqual(result.output_bytes, b"")
        self.assertEqual(store.calls, [])
        rendered = repr(result)
        self.assertNotIn("leak", rendered)
        self.assertNotIn(payload.decode("utf-8"), rendered)

    def test_duplicate_names_sensitive_values_and_no_deferred_are_exact_pass_through(self) -> None:
        """Break caught: unsafe catalogs are partially wrapped or stored."""

        module = tool_schemas_module()
        cases = (
            (
                [
                    {"input_schema": {"type": "object"}, "name": "same"},
                    {"input_schema": {"type": "object"}, "name": "same"},
                ],
                [item(), item()],
                1,
            ),
            (
                [{"input_schema": {"properties": {"password": {"default": "value"}}}, "name": "safe"}],
                [item()],
                0,
            ),
            (
                [{"description": "small", "input_schema": {"type": "object"}, "name": "only"}],
                [item(required=True)],
                0,
            ),
        )
        for catalog, metadata, retain_count in cases:
            with self.subTest(retain_count=retain_count, catalog=catalog):
                raw, payload = descriptor(catalog, metadata, retain_count=retain_count)
                store = RecordingStore()
                result = module.assemble_tool_schemas(raw, store=store)
                self.assertEqual(result.disposition.value, "pass_through")
                self.assertEqual(result.output_bytes, payload)
                self.assertEqual(store.calls, [])

    def test_raw_slices_are_stored_and_spliced_without_semantic_rebuild(self) -> None:
        """Break caught: catalog items are decoded and reconstructed before storage or output."""

        module = tool_schemas_module()
        catalog = [
            {"description": "\u00e9" * 2_000, "input_schema": {"required": [], "type": "object"}, "name": "inline"},
            {"description": "\u03bb" * 2_000, "input_schema": {"properties": {}, "type": "object"}, "name": "deferred"},
        ]
        raw, payload = descriptor(catalog, [item(priority=2), item(priority=1)])
        store = RecordingStore()
        result = module.assemble_tool_schemas(raw, store=store)
        self.assertEqual(result.disposition.value, "deferred")
        deferred_raw = canonical_json_bytes(catalog[1])[:-1]
        envelope = store.calls[0][1].payload
        metadata_length = int.from_bytes(envelope[len(module.TOOL_SCHEMA_MAGIC):len(module.TOOL_SCHEMA_MAGIC) + 4], "big")
        payload_start = len(module.TOOL_SCHEMA_MAGIC) + 4 + metadata_length
        self.assertEqual(envelope[payload_start:], deferred_raw)
        inline_raw = canonical_json_bytes(catalog[0])[:-1]
        self.assertIn(b'"inline":[' + inline_raw + b"]", result.output_bytes)

    def test_all_noneligible_protection_reasons_pass_through_before_catalog_gates(self) -> None:
        """Break caught: an aggregate protected item is deferred beside eligible siblings."""

        module = tool_schemas_module()
        catalog = [
            {"description": "x" * 5_000, "input_schema": {}, "name": "first"},
            {"description": "y" * 5_000, "input_schema": {}, "name": "second"},
        ]
        for classification in (
            "unknown",
            "ambiguous",
            "exact_required",
            "protected",
            "security_sensitive",
        ):
            with self.subTest(classification=classification):
                raw, payload = descriptor(catalog, [item(), item(classification=classification)])
                store = RecordingStore()
                result = module.assemble_tool_schemas(raw, store=store)
                self.assertEqual(result.disposition.value, "pass_through")
                self.assertEqual(result.output_bytes, payload)
                self.assertEqual(result.receipt["reason"], classification)
                self.assertEqual(store.calls, [])

    def test_all_sensitive_value_keywords_are_conservative_pass_through(self) -> None:
        """Break caught: a value-bearing JSON Schema keyword is placed in a deferred receipt."""

        module = tool_schemas_module()
        fragments = (
            {"default": 0},
            {"example": False},
            {"examples": []},
            {"properties": {"password": {"const": "x"}}},
            {"properties": {"api_token": {"enum": ["x"]}}},
        )
        for fragment in fragments:
            catalog = [
                {"description": "x" * 5_000, "input_schema": fragment, "name": "first"},
                {"description": "y" * 5_000, "input_schema": {}, "name": "second"},
            ]
            raw, payload = descriptor(catalog, [item(), item()])
            store = RecordingStore()
            result = module.assemble_tool_schemas(raw, store=store)
            self.assertEqual(result.disposition.value, "pass_through")
            self.assertEqual(result.output_bytes, payload)
            self.assertEqual(store.calls, [])

    def test_control_or_oversized_names_pass_through_and_noncanonical_payload_rejects(self) -> None:
        """Break caught: unsafe names enter references or noncanonical catalogs reach a gate."""

        module = tool_schemas_module()
        for name in ("bad\u0000name", "n" * (module.MAX_TOOL_NAME_BYTES + 1)):
            raw, payload = descriptor(
                [{"description": "x" * 5_000, "input_schema": {}, "name": name}],
                [item()],
                retain_count=0,
            )
            result = module.assemble_tool_schemas(raw, store=RecordingStore())
            self.assertEqual(result.disposition.value, "pass_through")
            self.assertEqual(result.output_bytes, payload)

        noncanonical_payload = b'[{"name":"e\\u0301","input_schema":{}}]\n'
        descriptor_raw = canonical_json_bytes(
            {
                "catalog_format": "anthropic_tools/v1",
                "items": [item()],
                "payload_b64u": base64.urlsafe_b64encode(noncanonical_payload).rstrip(b"=").decode("ascii"),
                "retain_count": 0,
                "schema_version": "contextguard-receipt-tool-schema-descriptor/v1",
            },
            limits=module.DESCRIPTOR_LIMITS,
        )
        with self.assertRaises(module.ToolSchemaError) as caught:
            module.assemble_tool_schemas(descriptor_raw, store=RecordingStore())
        self.assertEqual(caught.exception.code, "invalid_descriptor")

    def test_issue_failure_and_malformed_getters_fall_back_without_partial_artifact(self) -> None:
        """Break caught: issuance exceptions or hostile return objects leak a partial bundle."""

        module = tool_schemas_module()
        catalog = [
            {"description": "x" * 5_000, "input_schema": {}, "name": "first"},
            {"description": "y" * 5_000, "input_schema": {}, "name": "second"},
        ]
        raw, payload = descriptor(catalog, [item(), item()])

        class FailingStore:
            calls = 0

            def issue_batch(self, requests):
                self.calls += 1
                raise RuntimeError("HOSTILE_BACKEND_DETAIL")

        class GetterIssued:
            @property
            def handle(self):
                raise RuntimeError("HOSTILE_BACKEND_DETAIL")

        class GetterStore:
            calls = 0

            def issue_batch(self, requests):
                self.calls += 1
                return tuple(GetterIssued() for _request in requests)

        for store in (FailingStore(), GetterStore()):
            result = module.assemble_tool_schemas(raw, store=store)
            self.assertEqual(store.calls, 1)
            self.assertEqual(result.disposition.value, "pass_through")
            self.assertEqual(result.output_bytes, payload)
            self.assertNotIn("HOSTILE_BACKEND_DETAIL", repr(result))

    def test_router_uses_exact_49_byte_handles_at_inclusive_byte_boundaries(self) -> None:
        """Break caught: G006 estimates encoded capabilities or changes inclusive routing."""

        module = tool_schemas_module()

        def assemble(inline_size: int, deferred_size: int):
            catalog = [
                {"description": "i" * inline_size, "input_schema": {}, "name": "inline"},
                {"description": "d" * deferred_size, "input_schema": {}, "name": "deferred"},
            ]
            raw, payload = descriptor(catalog, [item(priority=2), item(priority=1)])
            return payload, module.assemble_tool_schemas(raw, store=RecordingStore())

        below_payload, below = assemble(100, 1_970)
        edge_payload, edge = assemble(100, 1_971)
        self.assertEqual(len(below_payload) - below.receipt["route"]["predicted_cost_bytes"], 255)
        self.assertEqual(len(edge_payload) - edge.receipt["route"]["predicted_cost_bytes"], 256)
        self.assertEqual(below.disposition.value, "pass_through")
        self.assertEqual(edge.disposition.value, "deferred")
        self.assertEqual(edge.receipt["route"]["handle_bytes"], 2 * 49)
        self.assertEqual(
            len(edge.output_bytes), edge.receipt["route"]["predicted_cost_bytes"]
        )

        ratio_edge_payload, ratio_edge = assemble(479, 1_971)
        ratio_below_payload, ratio_below = assemble(480, 1_971)
        edge_cost = ratio_edge.receipt["route"]["predicted_cost_bytes"]
        below_cost = ratio_below.receipt["route"]["predicted_cost_bytes"]
        self.assertEqual((len(ratio_edge_payload) - edge_cost) * 10, len(ratio_edge_payload))
        self.assertLess((len(ratio_below_payload) - below_cost) * 10, len(ratio_below_payload))
        self.assertEqual(ratio_edge.disposition.value, "deferred")
        self.assertEqual(ratio_below.disposition.value, "pass_through")

        def assemble_exact_input(deferred_size: int):
            catalog = [
                {"input_schema": {}, "name": "inline"},
                {"description": "x" * deferred_size, "input_schema": {}, "name": "deferred"},
            ]
            raw, payload = descriptor(catalog, [item(priority=2), item(priority=1)])
            return payload, module.assemble_tool_schemas(raw, store=RecordingStore())

        input_511, below_minimum = assemble_exact_input(418)
        input_512, at_minimum = assemble_exact_input(419)
        self.assertEqual((len(input_511), len(input_512)), (511, 512))
        self.assertEqual(below_minimum.receipt["reason"], "input_too_small")
        self.assertNotEqual(at_minimum.receipt["reason"], "input_too_small")

    def test_descriptor_types_counts_base64_and_scanner_fail_before_store(self) -> None:
        """Break caught: malformed count/type/framing cases are treated as safe pass-through."""

        module = tool_schemas_module()
        catalog_payload = canonical_json_bytes([{"input_schema": {}, "name": "tool"}])
        encoded = base64.urlsafe_b64encode(catalog_payload).rstrip(b"=").decode("ascii")

        def raw_descriptor(**overrides):
            value = {
                "catalog_format": "anthropic_tools/v1",
                "items": [item()],
                "payload_b64u": encoded,
                "retain_count": 0,
                "schema_version": "contextguard-receipt-tool-schema-descriptor/v1",
            }
            value.update(overrides)
            return canonical_json_bytes(value, limits=module.DESCRIPTOR_LIMITS)

        malformed = (
            raw_descriptor(retain_count=True),
            raw_descriptor(retain_count=2),
            raw_descriptor(items=[]),
            raw_descriptor(items=[item(priority=module.MAX_PRIORITY + 1)]),
            raw_descriptor(payload_b64u=encoded + "="),
            raw_descriptor(payload_b64u=base64.urlsafe_b64encode(b"{}\n").rstrip(b"=").decode("ascii")),
            raw_descriptor(payload_b64u=base64.urlsafe_b64encode(b"[{} ,{}]\n").rstrip(b"=").decode("ascii")),
        )
        for raw in malformed:
            store = RecordingStore()
            with self.subTest(raw=raw):
                with self.assertRaises(module.ToolSchemaError) as caught:
                    module.assemble_tool_schemas(raw, store=store)
                self.assertEqual(caught.exception.code, "invalid_descriptor")
                self.assertEqual(store.calls, [])


class G006ToolSchemaExpansionTests(unittest.TestCase):
    def test_whole_and_item_expansion_retrieve_the_exact_catalog_snapshot(self) -> None:
        """Break caught: expansion consults live state or returns a rebuilt schema."""

        module, catalog, payload, store, bundle = issued_bundle()
        catalog_result = module.expand_tool_schema_catalog(bundle["catalog_reference"], store=store)
        item_result = module.expand_tool_schema_item(
            bundle["catalog_reference"], bundle["deferred"][0], store=store
        )
        self.assertEqual(catalog_result.disposition.value, "exact")
        self.assertEqual(catalog_result.output_bytes, payload)
        self.assertEqual(item_result.disposition.value, "exact")
        self.assertEqual(item_result.output_bytes, canonical_json_bytes(catalog[1])[:-1])
        self.assertEqual(len(store.retrieve_calls), 3)

    def test_handle_alone_and_confused_or_tampered_references_are_closed_refusals(self) -> None:
        """Break caught: handles or mixed catalog/item authorities bypass bound retrieval."""

        module, _catalog, _payload, store, bundle = issued_bundle()
        other_module, _other_catalog, _other_payload, other_store, other_bundle = issued_bundle(
            catalog_format="openai_functions/v1"
        )
        self.assertIs(module, other_module)
        cases = (
            (bundle["catalog_reference"]["capability"], bundle["deferred"][0]),
            (bundle["catalog_reference"], other_bundle["deferred"][0]),
            ({**bundle["catalog_reference"], "namespace_id": "b" * 64}, bundle["deferred"][0]),
            (bundle["catalog_reference"], {**bundle["deferred"][0], "input_index": 99}),
        )
        for catalog_reference, item_reference in cases:
            result = module.expand_tool_schema_item(catalog_reference, item_reference, store=store)
            self.assertEqual(result.disposition.value, "refused")
            self.assertEqual(result.output_bytes, b"")
            self.assertEqual(
                set(result.refusal),
                {"artifact_kind", "evidence_boundary", "reason", "schema_version", "status"},
            )
            self.assertNotIn("capability", repr(result.refusal))
        self.assertTrue(other_store.artifacts)

    def test_tampered_envelopes_and_backend_getters_do_not_reflect_private_details(self) -> None:
        """Break caught: stored-envelope corruption or backend errors escape the refusal boundary."""

        module, _catalog, _payload, store, bundle = issued_bundle()
        catalog_reference = bundle["catalog_reference"]
        artifact = store.artifacts[catalog_reference["capability"]]
        store.artifacts[catalog_reference["capability"]] = SimpleNamespace(
            **{**vars(artifact), "payload": artifact.payload[:-1] + bytes([artifact.payload[-1] ^ 1])}
        )
        tampered = module.expand_tool_schema_catalog(catalog_reference, store=store)
        self.assertEqual(tampered.disposition.value, "refused")
        self.assertEqual(tampered.output_bytes, b"")

        class GetterStore:
            def retrieve(self, *args, **kwargs):
                class Stored:
                    @property
                    def payload(self):
                        raise RuntimeError("HOSTILE_PRIVATE_DETAIL")

                return Stored()

        getter = module.expand_tool_schema_catalog(catalog_reference, store=GetterStore())
        self.assertEqual(getter.disposition.value, "refused")
        self.assertNotIn("HOSTILE_PRIVATE_DETAIL", repr(getter))

    def test_hostile_stored_field_comparison_is_a_closed_invalid_artifact(self) -> None:
        """Break caught: an untrusted stored-field comparison escapes expansion validation."""

        module, _catalog, _payload, store, bundle = issued_bundle()
        reference = bundle["catalog_reference"]
        artifact = store.artifacts[reference["capability"]]

        class ExplodingComparison:
            def __ne__(self, _other):
                raise ValueError("HOSTILE_COMPARISON_DETAIL")

        hostile_artifact = SimpleNamespace(
            **{**vars(artifact), "namespace_id": ExplodingComparison()}
        )

        class DirectStore:
            def retrieve(self, *args, **kwargs):
                return hostile_artifact

        result = module.expand_tool_schema_catalog(reference, store=DirectStore())
        self.assertEqual(result.disposition.value, "refused")
        self.assertEqual(result.output_bytes, b"")
        self.assertEqual(result.refusal["reason"], "artifact_invalid")
        self.assertNotIn("HOSTILE_COMPARISON_DETAIL", repr(result))

        hostile_reference = {
            **reference,
            "artifact_kind": ExplodingComparison(),
        }
        reference_result = module.expand_tool_schema_catalog(
            hostile_reference, store=DirectStore()
        )
        self.assertEqual(reference_result.disposition.value, "refused")
        self.assertEqual(reference_result.refusal["reason"], "reference_rejected")
        self.assertNotIn("HOSTILE_COMPARISON_DETAIL", repr(reference_result))

    def test_real_store_round_trip_uses_catalog_authority_without_live_freshness(self) -> None:
        """Break caught: the strict retrieve API cannot round-trip G006 sealed snapshots."""

        executable = shutil.which("git")
        if executable is None:
            self.skipTest("git is unavailable for the store fixture")
        module = tool_schemas_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repository = base / "repository"
            state = base / "private-state"
            repository.mkdir(mode=0o700)
            store = CapabilityStore.open(
                state_dir=str(state),
                repository_root=str(repository),
                git_executable=str(Path(executable).resolve()),
                create=True,
            )
            try:
                catalog = [
                    {"description": "i" * 5_000, "input_schema": {}, "name": "inline"},
                    {"description": "d" * 5_000, "input_schema": {}, "name": "deferred"},
                ]
                raw, payload = descriptor(catalog, [item(priority=2), item(priority=1)])
                assembled = module.assemble_tool_schemas(raw, store=store)
                bundle = parse_canonical_json_bytes(assembled.output_bytes)
                whole = module.expand_tool_schema_catalog(bundle["catalog_reference"], store=store)
                selected = module.expand_tool_schema_item(
                    bundle["catalog_reference"], bundle["deferred"][0], store=store
                )

                other_catalog = [
                    {"description": "j" * 5_000, "input_schema": {}, "name": "other_inline"},
                    {"description": "e" * 5_000, "input_schema": {}, "name": "other_deferred"},
                ]
                other_raw, _other_payload = descriptor(
                    other_catalog, [item(priority=2), item(priority=1)]
                )
                other_assembled = module.assemble_tool_schemas(other_raw, store=store)
                other_bundle = parse_canonical_json_bytes(other_assembled.output_bytes)
                swapped = module.expand_tool_schema_item(
                    bundle["catalog_reference"], other_bundle["deferred"][0], store=store
                )
                forged_item = {
                    **bundle["deferred"][0],
                    "subject_identity_sha256": bundle["catalog_reference"][
                        "subject_identity_sha256"
                    ],
                }
                forged = module.expand_tool_schema_item(
                    bundle["catalog_reference"], forged_item, store=store
                )
            finally:
                store.close()
        self.assertEqual(whole.output_bytes, payload)
        self.assertEqual(selected.output_bytes, canonical_json_bytes(catalog[1])[:-1])
        self.assertEqual(swapped.disposition.value, "refused")
        self.assertEqual(forged.disposition.value, "refused")
        self.assertEqual(swapped.output_bytes, b"")
        self.assertEqual(forged.output_bytes, b"")

    def test_malformed_descriptor_is_nonreflective_and_fails_before_store(self) -> None:
        """Break caught: coercion or validation fallback reaches durable issuance."""

        module = tool_schemas_module()
        good_catalog = [{"input_schema": {}, "name": "tool"}]
        malformed = (
            b'{}\n',
            canonical_json_bytes(
                {
                    "catalog_format": "anthropic_tools/v1",
                    "items": [item(priority=True)],
                    "payload_b64u": base64.urlsafe_b64encode(canonical_json_bytes(good_catalog)).rstrip(b"=").decode("ascii"),
                    "retain_count": 0,
                    "schema_version": "contextguard-receipt-tool-schema-descriptor/v1",
                },
                limits=module.DESCRIPTOR_LIMITS,
            ),
        )
        for raw in malformed:
            store = RecordingStore()
            with self.subTest(raw=raw):
                with self.assertRaises(module.ToolSchemaError) as caught:
                    module.assemble_tool_schemas(raw, store=store)
                self.assertEqual(caught.exception.code, "invalid_descriptor")
                self.assertEqual(str(caught.exception), "invalid_descriptor")
                self.assertEqual(store.calls, [])


if __name__ == "__main__":
    unittest.main()
