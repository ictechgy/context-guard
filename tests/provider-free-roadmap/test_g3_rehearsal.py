from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
G3 = ROOT / "research/provider-free-roadmap/g3"
V1 = G3 / "v1"
RUNNER = V1 / "rehearse.py"
MANIFEST = V1 / "manifest.json"
COST_MODEL = V1 / "cost-model.json"
LOCK = G3 / "freeze-lock.json"
SCHEMAS = V1 / "schemas"
G2_LOCK = ROOT / "research/provider-free-roadmap/g2/freeze-lock.json"
G2_VERIFIER = ROOT / "research/provider-free-roadmap/g2/v1/verify.py"
G2_LOCK_SHA256 = "8f5c0cc432b4b7fe5b917158be191e0e631b25fec5f29ba3519322efe83d5283"
G2_TREE_SHA256 = "63f15c6e65ffe67411b0ca1ba6365f6de7cf3a9ea374b7dff2b7342cbff669dc"
G2_VERIFIER_SHA256 = "317a138d38e1d8d10282051c5166961ed1a80116eec40fdc339fa8c40bd0965f"
ARMS = ("ordinary", "adaptive_only", "symbol_only", "combined")
TASKS = (
    "train_closed", "train_graph", "calibration_closed", "calibration_graph",
    "evaluation_closed", "evaluation_graph",
)


def captured(name: str, path: Path) -> bytes:
    value = globals().get(name)
    if value is None:
        return path.read_bytes()
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must contain captured bytes")
    return value


def captured_schemas() -> dict[str, bytes]:
    value = globals().get("__G3_CAPTURED_SCHEMA_BYTES__")
    if value is None:
        return {path.name: path.read_bytes() for path in sorted(SCHEMAS.glob("*.json"))}
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(raw, bytes) for key, raw in value.items()
    ):
        raise TypeError("invalid captured schema mapping")
    return value


def load_runner() -> types.ModuleType:
    raw = captured("__G3_CAPTURED_RUNNER_BYTES__", RUNNER)
    module = types.ModuleType("captured_g3_runner")
    module.__file__ = str(RUNNER)
    sys.modules[module.__name__] = module
    exec(compile(raw, str(RUNNER), "exec"), module.__dict__, module.__dict__)
    return module


class G3RehearsalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = load_runner()
        cls.inputs = {
            "manifest_bytes": captured("__G3_CAPTURED_MANIFEST_BYTES__", MANIFEST),
            "cost_model_bytes": captured("__G3_CAPTURED_COST_MODEL_BYTES__", COST_MODEL),
            "schema_bytes": captured_schemas(),
            "g2_verifier_bytes": captured("__G3_CAPTURED_G2_VERIFIER_BYTES__", G2_VERIFIER),
            "g2_lock_bytes": captured("__G3_CAPTURED_G2_LOCK_BYTES__", G2_LOCK),
            "expected_g2_lock_sha256": globals().get(
                "__G3_EXPECTED_G2_LOCK_SHA256__", G2_LOCK_SHA256
            ),
            "expected_g2_tree_root": globals().get(
                "__G3_EXPECTED_G2_TREE_ROOT__", G2_TREE_SHA256
            ),
            "expected_g2_verifier_sha256": globals().get(
                "__G3_EXPECTED_G2_VERIFIER_SHA256__", G2_VERIFIER_SHA256
            ),
        }

    def run_rehearsal(self, output: Path) -> dict:
        return self.runner.run_captured(ROOT, output, **self.inputs)

    def output_artifacts(self, output: Path) -> dict[str, bytes]:
        return {
            path.name: path.read_bytes() for path in output.iterdir()
            if path.name != "artifact-inventory.json"
        }

    def replay(self, artifacts: dict[str, bytes]) -> None:
        manifest_bytes = self.inputs["manifest_bytes"]
        self.runner.semantic_replay(
            artifacts,
            expected_manifest_bytes=manifest_bytes,
            expected_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        )

    def verify_published(self, output: Path) -> dict:
        manifest_bytes = self.inputs["manifest_bytes"]
        return self.runner.verify_output(
            output, self.inputs["schema_bytes"],
            expected_manifest_bytes=manifest_bytes,
            expected_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        )

    def refresh_commitment(self, artifacts: dict[str, bytes]) -> None:
        repro = json.loads(artifacts["reproducibility.json"])
        commitment = getattr(self.runner, "bundle_commitment", None)
        if callable(commitment):
            repro["deterministic_evidence_sha256"] = commitment(artifacts, repro)
        else:
            core_names = (
                "aggregate-results.json", "events.jsonl", "resolved-manifest.json",
                "task-arm-results.json",
            )
            digest_input = b"".join(
                len(name).to_bytes(4, "big") + name.encode("ascii")
                + len(artifacts[name]).to_bytes(8, "big") + artifacts[name]
                for name in sorted(core_names)
            )
            repro["deterministic_evidence_sha256"] = hashlib.sha256(digest_input).hexdigest()
        artifacts["reproducibility.json"] = self.runner.canonical(repro)

    def reseal_records(self, artifacts: dict[str, bytes]) -> dict:
        results = json.loads(artifacts["task-arm-results.json"])
        for record in results["records"]:
            record["receipt_sha256"] = hashlib.sha256(
                self.runner.canonical(record["receipt"])
            ).hexdigest()
        artifacts["task-arm-results.json"] = self.runner.canonical(results)
        self.refresh_commitment(artifacts)
        return results

    def rebuild_event_log(self, results: dict) -> bytes:
        events = []
        for record in results["records"]:
            receipt = record["receipt"]
            packer = receipt["packer_receipt"]
            pack_core = {
                "arm": receipt["arm"], "event": "pack_captured",
                "manifest_sources": packer["manifest_sources"],
                "rendered_pack_sha256": packer["rendered_pack_sha256"],
                "task_id": receipt["task_id"],
            }
            events.append(dict(pack_core, event_id=self.runner.event_id(pack_core)))
            events.extend(receipt["retrieval_events"])
            context = receipt["final_context"]
            final_core = {
                "arm": receipt["arm"], "context_sha256": context["context_sha256"],
                "event": "final_context_sealed",
                "origin_event_ids": context["origin_event_ids"],
                "task_id": receipt["task_id"],
            }
            events.append(dict(final_core, event_id=self.runner.event_id(final_core)))
        return b"".join(self.runner.canonical(event) for event in events)

    def sealed_unchecked(self, value: object) -> dict:
        raw = self.runner.canonical(value)
        return {
            "bytes": len(raw),
            "canonical_base64": base64.b64encode(raw).decode("ascii"),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }

    def test_every_schema_is_recursively_closed(self) -> None:
        g2 = self.runner.load_g2(
            self.inputs["g2_verifier_bytes"], G2_VERIFIER_SHA256
        )
        for name, raw in self.inputs["schema_bytes"].items():
            with self.subTest(schema=name):
                schema = json.loads(raw)
                g2.assert_supported_schema(schema, name)
                g2.assert_closed_schema(schema, name)

    def test_public_manifest_recursively_rejects_private_scorer_keys(self) -> None:
        manifest = json.loads(self.inputs["manifest_bytes"])
        manifest["retrieval_plans"][0]["scorer_private"] = {
            "required_paths": ["evidence.txt"]
        }
        changed = dict(self.inputs, manifest_bytes=self.runner.canonical(manifest))
        with self.assertRaisesRegex(Exception, "private|scorer|oracle"):
            self.runner.capture_pre_oracle(ROOT, **changed)

    def test_public_manifest_has_closed_fixture_bound_retrieval_plans(self) -> None:
        manifest = json.loads(self.inputs["manifest_bytes"])
        plans = manifest["retrieval_plans"]
        self.assertEqual([plan["task_id"] for plan in plans], list(TASKS))
        for plan in plans:
            self.assertRegex(plan["fixture_tree_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(plan["closed_world"], True)
            for step in plan["steps"]:
                self.assertIn(step["kind"], {"retrieval", "fallback", "correction"})
                self.assertGreaterEqual(step["range"]["start"], 1)
                self.assertGreaterEqual(step["range"]["end"], step["range"]["start"])
                for identity in ("source", "slice"):
                    self.assertGreater(step[identity]["bytes"], 0)
                    self.assertRegex(step[identity]["sha256"], r"^[0-9a-f]{64}$")

    def test_pre_oracle_capture_seals_all_execution_and_discards_raw_payloads(self) -> None:
        capture = self.runner.capture_pre_oracle(ROOT, **self.inputs)
        self.assertEqual(len(capture.receipt_bytes), 24)
        self.assertEqual(len(capture.seal_bytes), 24)
        self.assertEqual(capture.pack_invocation_count, 24)
        self.assertEqual(capture.context_mutation_count, len(capture.retrieval_event_bytes))
        self.assertFalse(hasattr(capture, "raw_payloads"))
        self.assertFalse(hasattr(capture, "outcomes"))
        for raw, seal_raw in zip(capture.receipt_bytes, capture.seal_bytes, strict=True):
            receipt = json.loads(raw)
            seal = json.loads(seal_raw)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), seal["receipt_sha256"])
            public_task = self.runner.unseal_json(
                receipt["public_task"], "sealed public task"
            )
            self.assertEqual(public_task["task_id"], receipt["task_id"])
            self.assertEqual(set(receipt["captured_inputs"]), {
                "g2_lock", "g2_packer", "g2_public_snapshot", "g3_cost_model",
                "g3_schema_set",
            })
            for input_identity in receipt["captured_inputs"].values():
                self.assertGreater(input_identity["bytes"], 0)
                self.assertRegex(input_identity["sha256"], r"^[0-9a-f]{64}$")
            pack = receipt["packer_receipt"]
            rendered = base64.b64decode(pack["rendered_pack_base64"], validate=True)
            self.assertEqual(len(rendered), pack["pack_bytes"])
            self.assertEqual(hashlib.sha256(rendered).hexdigest(), pack["rendered_pack_sha256"])
            self.assertEqual(pack["selected_paths"], [s["path"] for s in pack["manifest_sources"]])
            self.assertIn("graph_application", pack)
            self.assertIn("adaptive_k_application", pack)
            self.assertIn("adaptive_k_selected_evidence", pack)
            self.assertIn("symbol_memory", pack)
            self.assertTrue(receipt["fixture_inputs"])
            context = receipt["final_context"]
            self.assertRegex(context["identity"], r"^[0-9a-f]{64}$")
            self.assertRegex(context["context_sha256"], r"^[0-9a-f]{64}$")
            for item in context["items"]:
                self.assertIn(item["origin_event_id"], context["origin_event_ids"])
                self.assertIn("range", item)
                self.assertIn("source", item)
                self.assertIn("slice", item)

    def test_scorer_required_path_mutation_cannot_change_pre_oracle_bytes(self) -> None:
        capture = self.runner.capture_pre_oracle(ROOT, **self.inputs)
        receipts_before = tuple(capture.receipt_bytes)
        seals_before = tuple(capture.seal_bytes)
        scorer = self.runner.capture_scorer_files(capture)
        oracle_path = next(path for path in scorer if path.endswith("/oracle.json"))
        oracle = json.loads(scorer[oracle_path])
        oracle["entries"][0]["required_paths"] = ["distractor.txt"]
        changed = dict(scorer)
        changed[oracle_path] = self.runner.canonical(oracle)
        with self.assertRaisesRegex(Exception, "required|oracle|adaptive|closed"):
            self.runner.score_capture(capture, changed)
        self.assertEqual(tuple(capture.receipt_bytes), receipts_before)
        self.assertEqual(tuple(capture.seal_bytes), seals_before)

    def test_public_phase_denies_oracle_path_and_basename_before_seals(self) -> None:
        capture = self.runner.capture_pre_oracle(ROOT, **self.inputs)
        oracle = ROOT / "research/provider-free-roadmap/g2/v1/scorer-only/oracle.json"
        capture.policy.phase = "public"
        for target in (str(oracle), "oracle.json"):
            with self.subTest(target=target):
                with self.assertRaisesRegex(PermissionError, "scorer|phase|snapshot"):
                    capture.policy.audit("open", (target, "r", 0))

    def test_boundary_denies_unlisted_in_repository_read(self) -> None:
        capture = self.runner.capture_pre_oracle(ROOT, **self.inputs)
        with self.assertRaisesRegex(PermissionError, "out-of-snapshot"):
            capture.policy.audit("open", (str(ROOT / "package.json"), "r", 0))
        with self.assertRaisesRegex(PermissionError, "out-of-snapshot"):
            capture.policy.audit("open", ("package.json", "r", 0))

    def test_bound_profile_environment_contains_lang_only(self) -> None:
        if "__G3_CAPTURED_RUNNER_BYTES__" not in globals():
            self.skipTest("asserted inside independently pinned G3 profile child")
        self.assertEqual(sys.flags.isolated, 1)
        self.assertEqual(sys.flags.dont_write_bytecode, 1)
        self.assertEqual(os.environ.get("LANG"), "C.UTF-8")
        self.assertTrue(set(os.environ) <= {"LANG", "__CF_USER_TEXT_ENCODING"})

    def test_outputs_are_deterministic_timing_separated_and_semantically_replayable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first"
            second = Path(temporary) / "second"
            summary = self.run_rehearsal(first)
            self.run_rehearsal(second)
            self.assertEqual(summary["record_count"], 24)
            deterministic = {
                "resolved-manifest.json", "events.jsonl", "task-arm-results.json",
                "aggregate-results.json", "reproducibility.json",
            }
            for name in deterministic:
                self.assertEqual((first / name).read_bytes(), (second / name).read_bytes(), name)
            self.assertNotEqual((first / "timing.jsonl").read_bytes(), b"")
            timing_summary = json.loads((first / "timing-summary.json").read_text())
            self.assertEqual(timing_summary["clock"], "time.monotonic_ns")
            self.assertEqual(timing_summary["scope"], "exact_bound_packer_child_invocation")
            self.assertEqual(timing_summary["task_execution"], {
                "availability": "unavailable", "observations": None,
            })
            self.assertEqual(timing_summary["observation_count"], 24)
            replay = self.verify_published(first)
            self.assertEqual(replay["status"], "verified")

    def test_semantic_replay_rejects_rehashed_event_identity_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run"
            self.run_rehearsal(output)
            artifacts = {
                path.name: path.read_bytes() for path in output.iterdir()
                if path.name != "artifact-inventory.json"
            }
            lines = artifacts["events.jsonl"].splitlines()
            first = json.loads(lines[0])
            first["event_id"] = "0" * 64
            lines[0] = self.runner.canonical(first).rstrip(b"\n")
            artifacts["events.jsonl"] = b"\n".join(lines) + b"\n"
            core_names = (
                "aggregate-results.json", "events.jsonl", "resolved-manifest.json",
                "task-arm-results.json",
            )
            digest_input = b"".join(
                len(name).to_bytes(4, "big") + name.encode("ascii")
                + len(artifacts[name]).to_bytes(8, "big") + artifacts[name]
                for name in sorted(core_names)
            )
            repro = json.loads(artifacts["reproducibility.json"])
            repro["deterministic_evidence_sha256"] = hashlib.sha256(digest_input).hexdigest()
            artifacts["reproducibility.json"] = self.runner.canonical(repro)
            with self.assertRaisesRegex(Exception, "event|identity"):
                self.replay(artifacts)

    def test_schema_rejects_rehashed_nested_receipt_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run"
            self.run_rehearsal(output)
            artifacts = self.output_artifacts(output)
            results = json.loads(artifacts["task-arm-results.json"])
            results["records"][0]["receipt"]["packer_receipt"]["scorer_private"] = {
                "required_paths": ["evidence.txt"]
            }
            artifacts["task-arm-results.json"] = self.runner.canonical(results)
            self.reseal_records(artifacts)
            with self.assertRaisesRegex(Exception, "schema|private|unknown"):
                self.runner.validate_artifact_schemas(artifacts, self.inputs["schema_bytes"])

    def test_replay_rejects_rehashed_private_inner_sealed_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run"
            self.run_rehearsal(output)
            baseline = self.output_artifacts(output)
            targets = (
                "public_task", "adaptive_k_application",
                "adaptive_k_selected_evidence", "graph_application", "symbol_memory",
            )
            for target in targets:
                with self.subTest(target=target):
                    artifacts = dict(baseline)
                    results = json.loads(artifacts["task-arm-results.json"])
                    receipt = results["records"][0]["receipt"]
                    private = self.sealed_unchecked({
                        "oracle": {"answer": "private"},
                        "required_paths": ["evidence.txt"],
                        "task_id": receipt["task_id"],
                    })
                    if target == "public_task":
                        receipt[target] = private
                    else:
                        receipt["packer_receipt"][target] = private
                    artifacts["task-arm-results.json"] = self.runner.canonical(results)
                    self.reseal_records(artifacts)
                    with self.assertRaisesRegex(
                        Exception, "private|oracle|sealed|public task"
                    ):
                        self.replay(artifacts)

    def test_replay_rejects_rehashed_unbound_receipt_input_claims(self) -> None:
        mutations = {
            "captured input": lambda receipt: receipt["captured_inputs"][
                "g2_public_snapshot"
            ].update(sha256="0" * 64),
            "fixture input": lambda receipt: receipt["fixture_inputs"][0][
                "source"
            ].update(sha256="0" * 64),
            "public task": lambda receipt: receipt.update(public_task=self.sealed_unchecked({
                "stratum": receipt["stratum"], "task_id": receipt["task_id"],
            })),
        }
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run"
            self.run_rehearsal(output)
            baseline = self.output_artifacts(output)
            for label, mutation in mutations.items():
                with self.subTest(label=label):
                    artifacts = dict(baseline)
                    results = json.loads(artifacts["task-arm-results.json"])
                    mutation(results["records"][0]["receipt"])
                    artifacts["task-arm-results.json"] = self.runner.canonical(results)
                    self.reseal_records(artifacts)
                    with self.assertRaisesRegex(
                        Exception, "captured|fixture|public task|identity|claim"
                    ):
                        self.replay(artifacts)

    def test_replay_rejects_synchronized_output_manifest_root_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run"
            self.run_rehearsal(output)
            baseline = self.output_artifacts(output)
            for label in ("captured input", "fixture source", "public task"):
                with self.subTest(label=label):
                    artifacts = dict(baseline)
                    manifest = json.loads(artifacts["resolved-manifest.json"])
                    results = json.loads(artifacts["task-arm-results.json"])
                    receipts = [record["receipt"] for record in results["records"]]
                    first = receipts[0]
                    if label == "captured input":
                        manifest["receipt_bindings"]["captured_inputs"][
                            "g2_public_snapshot"
                        ]["sha256"] = "0" * 64
                        for receipt in receipts:
                            receipt["captured_inputs"]["g2_public_snapshot"][
                                "sha256"
                            ] = "0" * 64
                    elif label == "fixture source":
                        task_receipts = [
                            receipt for receipt in receipts
                            if receipt["task_id"] == first["task_id"]
                        ]
                        for receipt in task_receipts:
                            receipt["fixture_inputs"][0]["source"]["sha256"] = "0" * 64
                        binding = next(
                            item for item in manifest["receipt_bindings"]["tasks"]
                            if item["task_id"] == first["task_id"]
                        )
                        binding["fixture_inputs_sha256"] = hashlib.sha256(
                            self.runner.canonical(task_receipts[0]["fixture_inputs"])
                        ).hexdigest()
                    else:
                        forged = self.sealed_unchecked({
                            "stratum": first["stratum"], "task_id": first["task_id"],
                        })
                        for receipt in receipts:
                            if receipt["task_id"] == first["task_id"]:
                                receipt["public_task"] = dict(forged)
                        binding = next(
                            item for item in manifest["receipt_bindings"]["tasks"]
                            if item["task_id"] == first["task_id"]
                        )
                        binding["public_task"] = {
                            "bytes": forged["bytes"], "sha256": forged["sha256"],
                        }
                    artifacts["resolved-manifest.json"] = self.runner.canonical(manifest)
                    artifacts["task-arm-results.json"] = self.runner.canonical(results)
                    self.reseal_records(artifacts)
                    with self.assertRaisesRegex(
                        Exception, "captured manifest|root|fixture|public task|identity"
                    ):
                        self.replay(artifacts)

    def test_replay_rejects_synchronized_packed_source_provenance_forgery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run"
            self.run_rehearsal(output)
            artifacts = self.output_artifacts(output)
            results = json.loads(artifacts["task-arm-results.json"])
            record = results["records"][0]
            receipt = record["receipt"]
            packer = receipt["packer_receipt"]
            pack_core = {
                "arm": receipt["arm"], "event": "pack_captured",
                "manifest_sources": packer["manifest_sources"],
                "rendered_pack_sha256": packer["rendered_pack_sha256"],
                "task_id": receipt["task_id"],
            }
            old_pack_id = self.runner.event_id(pack_core)
            source = packer["manifest_sources"][0]
            source["source"]["sha256"] = "0" * 64
            pack_core["manifest_sources"] = packer["manifest_sources"]
            new_pack_id = self.runner.event_id(pack_core)
            context = receipt["final_context"]
            for item in context["items"]:
                if item["origin_event_id"] == old_pack_id:
                    item["origin_event_id"] = new_pack_id
                    if item["path"] == source["path"]:
                        item["source"] = dict(source["source"])
            context["origin_event_ids"] = [
                new_pack_id if value == old_pack_id else value
                for value in context["origin_event_ids"]
            ]
            context["context_sha256"] = hashlib.sha256(
                self.runner.canonical(context["items"])
            ).hexdigest()
            final_core = {
                "arm": receipt["arm"], "context_sha256": context["context_sha256"],
                "event": "final_context_sealed",
                "origin_event_ids": context["origin_event_ids"],
                "task_id": receipt["task_id"],
            }
            context["identity"] = hashlib.sha256(self.runner.canonical({
                "final_event_id": self.runner.event_id(final_core),
                "origin_event_ids": context["origin_event_ids"],
            })).hexdigest()
            artifacts["events.jsonl"] = self.rebuild_event_log(results)
            artifacts["task-arm-results.json"] = self.runner.canonical(results)
            self.reseal_records(artifacts)
            with self.assertRaisesRegex(Exception, "source|provenance|fixture|packer"):
                self.replay(artifacts)

    def test_replay_rejects_rehashed_graph_and_symbol_claim_forgery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run"
            self.run_rehearsal(output)
            baseline = self.output_artifacts(output)
            mutations = {
                "graph reason": lambda packer: (
                    lambda value: (
                        value["selected_sources"][0].update(reason="forged_reason"),
                        packer.update(graph_application=self.sealed_unchecked(value)),
                    )
                )(self.runner.unseal_json(packer["graph_application"], "graph")),
                "symbol name": lambda packer: (
                    lambda value: (
                        value["symbols"][0].update(name="forged_symbol"),
                        packer.update(symbol_memory=self.sealed_unchecked(value)),
                    )
                )(self.runner.unseal_json(packer["symbol_memory"], "symbol")),
            }
            for label, mutation in mutations.items():
                with self.subTest(label=label):
                    artifacts = dict(baseline)
                    results = json.loads(artifacts["task-arm-results.json"])
                    record = next(
                        item for item in results["records"]
                        if item["task_id"] == "train_graph" and item["arm"] == "symbol_only"
                    )
                    mutation(record["receipt"]["packer_receipt"])
                    artifacts["task-arm-results.json"] = self.runner.canonical(results)
                    self.reseal_records(artifacts)
                    with self.assertRaisesRegex(Exception, "graph|symbol|packer|claim"):
                        self.replay(artifacts)

    def test_irrelevant_retrieval_plan_cannot_report_full_validation(self) -> None:
        manifest = json.loads(self.inputs["manifest_bytes"])
        plan = next(
            item for item in manifest["retrieval_plans"]
            if item["task_id"] == "train_graph"
        )
        relative = (
            "research/provider-free-roadmap/g2/v1/fixtures/train/"
            "realistic_fallback/obsolete_map.txt"
        )
        raw = (ROOT / relative).read_bytes()
        line_count = len(raw.decode("utf-8").splitlines())
        plan["steps"] = [{
            "kind": "retrieval", "path": "obsolete_map.txt",
            "range": {"end": line_count, "start": 1},
            "slice": {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
            "source": {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
        }]
        changed = dict(self.inputs, manifest_bytes=self.runner.canonical(manifest))
        capture = self.runner.capture_pre_oracle(ROOT, **changed)
        scorer = self.runner.capture_scorer_files(capture)
        with self.assertRaisesRegex(Exception, "required|relevant|context|plan"):
            self.runner.score_capture(capture, scorer)

    def test_replay_binds_receipt_plan_to_resolved_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run"
            self.run_rehearsal(output)
            artifacts = self.output_artifacts(output)
            results = json.loads(artifacts["task-arm-results.json"])
            receipt = results["records"][0]["receipt"]
            receipt["retrieval_plan"]["closed_world"] = False
            receipt["retrieval_plan_sha256"] = hashlib.sha256(
                self.runner.canonical(receipt["retrieval_plan"])
            ).hexdigest()
            artifacts["task-arm-results.json"] = self.runner.canonical(results)
            self.reseal_records(artifacts)
            with self.assertRaisesRegex(Exception, "manifest|plan"):
                self.replay(artifacts)

    def test_replay_binds_each_retrieval_event_position_to_plan_step(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run"
            self.run_rehearsal(output)
            artifacts = self.output_artifacts(output)
            results = json.loads(artifacts["task-arm-results.json"])
            record = next(
                item for item in results["records"]
                if item["receipt"]["retrieval_events"]
            )
            receipt = record["receipt"]
            event = receipt["retrieval_events"][0]
            old_id = event["event_id"]
            event["kind"] = "fallback" if event["kind"] != "fallback" else "retrieval"
            core = {
                key: event[key] for key in (
                    "arm", "kind", "ordinal", "path", "plan_sha256", "range",
                    "slice", "source", "status", "task_id",
                )
            }
            event["event_id"] = self.runner.event_id(core)
            event["round_id"] = self.runner.event_id({
                "arm": event["arm"], "event_ids": [event["event_id"]],
                "ordinal": event["ordinal"], "task_id": event["task_id"],
            })
            context = receipt["final_context"]
            for item in context["items"]:
                if item["origin_event_id"] == old_id:
                    item["origin_event_id"] = event["event_id"]
            context["origin_event_ids"] = [
                event["event_id"] if value == old_id else value
                for value in context["origin_event_ids"]
            ]
            context["context_sha256"] = hashlib.sha256(
                self.runner.canonical(context["items"])
            ).hexdigest()
            final_core = {
                "arm": receipt["arm"], "context_sha256": context["context_sha256"],
                "event": "final_context_sealed",
                "origin_event_ids": context["origin_event_ids"],
                "task_id": receipt["task_id"],
            }
            context["identity"] = hashlib.sha256(self.runner.canonical({
                "final_event_id": self.runner.event_id(final_core),
                "origin_event_ids": context["origin_event_ids"],
            })).hexdigest()
            model = json.loads(self.inputs["cost_model_bytes"])
            receipt["cost"] = self.runner.recompute_cost(receipt, model)
            record["cost"] = receipt["cost"]
            artifacts["events.jsonl"] = self.rebuild_event_log(results)
            artifacts["task-arm-results.json"] = self.runner.canonical(results)
            aggregate = json.loads(artifacts["aggregate-results.json"])
            aggregate["cost_inference"] = self.runner.exact_paired_enumeration(
                results["records"]
            )
            artifacts["aggregate-results.json"] = self.runner.canonical(aggregate)
            self.reseal_records(artifacts)
            with self.assertRaisesRegex(Exception, "position|plan|kind"):
                self.replay(artifacts)

    def test_replay_rejects_outer_record_identity_mismatch_after_rehash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run"
            self.run_rehearsal(output)
            artifacts = self.output_artifacts(output)
            results = json.loads(artifacts["task-arm-results.json"])
            results["records"][0]["stratum"] = "realistic_fallback"
            artifacts["task-arm-results.json"] = self.runner.canonical(results)
            self.refresh_commitment(artifacts)
            with self.assertRaisesRegex(Exception, "record|stratum|identity"):
                self.replay(artifacts)

    def test_replay_rejects_rehashed_inner_cost_divergence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run"
            self.run_rehearsal(output)
            artifacts = self.output_artifacts(output)
            results = json.loads(artifacts["task-arm-results.json"])
            receipt = results["records"][0]["receipt"]
            receipt["cost"]["total"] += 1
            artifacts["task-arm-results.json"] = self.runner.canonical(results)
            self.reseal_records(artifacts)
            with self.assertRaisesRegex(Exception, "cost|inner|receipt"):
                self.replay(artifacts)

    def test_replay_rejects_rehashed_stratum_divergence_from_authenticated_task(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run"
            self.run_rehearsal(output)
            artifacts = self.output_artifacts(output)
            results = json.loads(artifacts["task-arm-results.json"])
            record = results["records"][0]
            record["stratum"] = "realistic_fallback"
            record["receipt"]["stratum"] = "realistic_fallback"
            artifacts["task-arm-results.json"] = self.runner.canonical(results)
            self.reseal_records(artifacts)
            with self.assertRaisesRegex(Exception, "stratum|public task|identity"):
                self.replay(artifacts)

    def test_replay_derives_every_reproducibility_field_after_rehash(self) -> None:
        mutations = {
            "boundary": lambda value: value["boundary"].update(network_denials=99),
            "g2 binding": lambda value: value["g2_source"].update(lock_sha256="0" * 64),
            "oracle count": lambda value: value["oracle_validation_counts"].update(
                required_symbols=99
            ),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "run"
                self.run_rehearsal(output)
                artifacts = self.output_artifacts(output)
                repro = json.loads(artifacts["reproducibility.json"])
                mutation(repro)
                artifacts["reproducibility.json"] = self.runner.canonical(repro)
                self.refresh_commitment(artifacts)
                with self.assertRaisesRegex(Exception, "reproducibility|boundary|G2|oracle"):
                    self.replay(artifacts)

    def test_costs_recompute_from_sealed_events_and_use_frozen_noncurrency_model(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run"
            self.run_rehearsal(output)
            model = json.loads(self.inputs["cost_model_bytes"])
            self.assertEqual(model["units"], "byte_equivalent_units")
            self.assertEqual(model["currency"], "unavailable")
            records = json.loads((output / "task-arm-results.json").read_text())["records"]
            for record in records:
                recomputed = self.runner.recompute_cost(record["receipt"], model)
                self.assertEqual(record["cost"], recomputed)
                self.assertEqual(sum(recomputed["components"].values()), recomputed["total"])
                self.assertEqual(set(recomputed["components"]), {
                    "initial_packing", "retrieval", "fallback", "correction", "fixed_overhead",
                })

    def test_exact_paired_task_block_enumeration_is_descriptive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run"
            self.run_rehearsal(output)
            aggregate = json.loads((output / "aggregate-results.json").read_text())
            inference = aggregate["cost_inference"]
            self.assertEqual(inference["method"], "exact_paired_task_block_enumeration")
            self.assertEqual(inference["enumeration_count"], 6 ** 6)
            self.assertEqual(inference["nearest_rank_95"], {"lower": 1167, "upper": 45490})
            self.assertEqual(inference["sampling_unit"], "paired_task_block")
            self.assertEqual(inference["descriptive_only"], True)
            self.assertNotIn("seed", inference)
            self.assertNotIn("resamples", inference)
            self.assertEqual(set(inference["per_arm"]), set(ARMS))
            self.assertEqual(set(inference["paired_deltas_vs_ordinary"]), set(ARMS) - {"ordinary"})
            for section in (inference["per_arm"], inference["paired_deltas_vs_ordinary"]):
                for result in section.values():
                    for point in (result["mean"], result["interval_95"]["lower"], result["interval_95"]["upper"]):
                        self.assertEqual(point["denominator"], 6)
                        self.assertIsInstance(point["numerator"], int)

    def test_safe_atomic_output_inventory_and_public_claim_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "run"
            self.run_rehearsal(output)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            inventory = json.loads((output / "artifact-inventory.json").read_text())
            self.assertEqual(inventory["self_inventory_policy"], "excluded_self_referential_file")
            self.assertEqual(inventory["timing_normalization"], {
                "excluded_from_deterministic_digest": [
                    "timing-summary.json:pack_invocation.*_ns",
                    "timing.jsonl:*.pack_invocation_ns",
                ]
            })
            actual = sorted(path.name for path in output.iterdir() if path.name != "artifact-inventory.json")
            self.assertEqual([entry["path"] for entry in inventory["artifacts"]], actual)
            for entry in inventory["artifacts"]:
                path = output / entry["path"]
                raw = path.read_bytes()
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(path.stat().st_nlink, 1)
                self.assertEqual(entry["bytes"], len(raw))
                self.assertEqual(entry["sha256"], hashlib.sha256(raw).hexdigest())
            results_text = (output / "task-arm-results.json").read_text().lower()
            for forbidden in ("required_paths", "adaptive_labels", "expected_output", "answer_signature"):
                self.assertNotIn(forbidden, results_text)
            aggregate = json.loads((output / "aggregate-results.json").read_text())
            self.assertEqual(aggregate["availability"], {
                "provider_metrics": "unavailable", "token_metrics": "unavailable",
                "usd_metrics": "unavailable", "savings_claims": "unavailable",
            })
            with self.assertRaisesRegex(Exception, "preexisting"):
                self.run_rehearsal(output)
            symlink_output = root / "symlink"
            symlink_output.symlink_to(output, target_is_directory=True)
            with self.assertRaisesRegex(Exception, "preexisting|symlink"):
                self.run_rehearsal(symlink_output)

    def test_output_verifier_rejects_duplicate_inventory_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run"
            self.run_rehearsal(output)
            inventory_path = output / "artifact-inventory.json"
            inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
            inventory["artifacts"].append(dict(inventory["artifacts"][0]))
            inventory_path.write_bytes(self.runner.canonical(inventory))
            with self.assertRaisesRegex(Exception, "duplicate|inventory"):
                self.verify_published(output)

    def test_boundary_probe_receipts_are_real_and_claim_is_process_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run"
            self.run_rehearsal(output)
            repro = json.loads((output / "reproducibility.json").read_text())
            boundary = repro["boundary"]
            self.assertEqual(boundary["claim"], "audited_cpython_process_boundary_not_os_sandbox")
            self.assertEqual(boundary["authorized_g2_child_processes"], 24)
            for counter in (
                "network_denials", "dns_denials", "process_denials", "exec_denials",
                "environment_denials", "native_load_denials", "out_of_snapshot_read_denials",
                "credential_decoy_denials",
            ):
                self.assertGreaterEqual(boundary[counter], 1, counter)
            self.assertEqual(boundary["post_scorer_experimental_executions"], 0)
            self.assertEqual(boundary["scorer_loaded_after_seal_count"], 24)

    def test_direct_mutable_runner_refuses(self) -> None:
        self.assertEqual(self.runner.main([]), 2)


if __name__ == "__main__":
    unittest.main()
