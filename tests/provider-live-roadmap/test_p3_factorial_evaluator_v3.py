from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
V3 = ROOT / "research/provider-live-roadmap/p3-api/v3"
EVALUATOR = V3 / "evaluator.py"
CORPUS = V3 / "corpus-manifest.json"
CHECKERS = V3 / "scorer-only/checkers.json"
CAPTURE_FREEZE = V3 / "provider-input-freeze.json"
REHEARSAL_REPORT = V3 / "rehearsal-report.json"
EXPECTED_CAPTURE_FILE_SHA256 = "314f018111f417ee8892ede95da97e407a81926c43a072bcd70658fa144034cd"
EXPECTED_REPORT_FILE_SHA256 = "b7440d238e76aed229c240eceb12dd3cbc67fe71508dc86a34870ac8324e7204"
CORPUS_ROOT = Path(
    os.environ.get("CONTEXTGUARD_V3_CORPUS_ROOT", "/private/tmp/contextguard-v3-corpus.5dKHrG")
)


def load_evaluator():
    spec = importlib.util.spec_from_file_location("p3_v3_evaluator", EVALUATOR)
    if spec is None or spec.loader is None:
        raise AssertionError("unable to load v3 evaluator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def recursive_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        result = set(value)
        for item in value.values():
            result.update(recursive_keys(item))
        return result
    if isinstance(value, list):
        result: set[str] = set()
        for item in value:
            result.update(recursive_keys(item))
        return result
    return set()


class P3FactorialEvaluatorV3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.evaluator = load_evaluator()
        cls.capture = json.loads(CAPTURE_FREEZE.read_text(encoding="utf-8"))
        cls.report = json.loads(REHEARSAL_REPORT.read_text(encoding="utf-8"))

    def test_committed_metadata_only_evidence_is_closed_and_valid(self) -> None:
        self.assertEqual(self.evaluator.sha256(CAPTURE_FREEZE.read_bytes()), EXPECTED_CAPTURE_FILE_SHA256)
        self.assertEqual(self.evaluator.sha256(REHEARSAL_REPORT.read_bytes()), EXPECTED_REPORT_FILE_SHA256)
        self.evaluator.validate_capture(self.capture, repo_root=ROOT)
        self.evaluator.validate_report(self.report, capture=self.capture, repo_root=ROOT)
        forbidden = {
            "prompt", "pack", "response", "symbols", "checkers_by_task_id",
            "tasks_by_id", "required_literals", "forbidden_literals",
            "historical_subject", "excluded_upstream_changed_paths",
        }
        self.assertEqual(forbidden & recursive_keys(self.capture), set())
        self.assertEqual(forbidden & recursive_keys(self.report), set())
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        raw = CAPTURE_FREEZE.read_bytes() + REHEARSAL_REPORT.read_bytes()
        for task in corpus["tasks"]:
            self.assertNotIn(task["prompt"].encode("utf-8"), raw)
        checkers = json.loads(CHECKERS.read_text(encoding="utf-8"))
        for checker in checkers["checkers"]:
            for assertion in checker["assertions"]:
                for literal in assertion["required_literals"] + assertion["forbidden_literals"]:
                    self.assertNotIn(literal.encode("utf-8"), raw)
        self.assertLess(len(CAPTURE_FREEZE.read_bytes()), 500_000)
        self.assertLess(len(REHEARSAL_REPORT.read_bytes()), 200_000)

    def test_actual_shipped_packer_and_exact_factor_pairs_are_bound(self) -> None:
        identities = self.capture["artifact_identities"]
        canonical = ROOT / "context-guard-kit/context_pack.py"
        plugin = ROOT / "plugins/context-guard/bin/context-guard-pack"
        sanitizer = ROOT / "context-guard-kit/sanitize_output.py"
        plugin_sanitizer = ROOT / "plugins/context-guard/bin/context-guard-sanitize-output"
        credential_policy = ROOT / "context-guard-kit/credential_policy.py"
        plugin_credential_policy = ROOT / "plugins/context-guard/lib/credential_policy.py"
        self.assertEqual(canonical.read_bytes(), plugin.read_bytes())
        self.assertEqual(sanitizer.read_bytes(), plugin_sanitizer.read_bytes())
        self.assertEqual(credential_policy.read_bytes(), plugin_credential_policy.read_bytes())
        self.assertEqual(identities["canonical_packer"]["sha256"], self.evaluator.sha256(canonical.read_bytes()))
        self.assertEqual(identities["plugin_packer"]["sha256"], self.evaluator.sha256(plugin.read_bytes()))
        self.assertEqual(identities["canonical_sanitizer"]["sha256"], self.evaluator.sha256(sanitizer.read_bytes()))
        self.assertEqual(
            identities["canonical_credential_policy"]["sha256"],
            self.evaluator.sha256(credential_policy.read_bytes()),
        )
        self.assertNotIn("module.git_ls_files =", self.evaluator.PACKER_CHILD_BOOTSTRAP)
        self.assertNotIn("_LINE_SANITIZER_FACTORY_CACHE", self.evaluator.PACKER_CHILD_BOOTSTRAP)
        self.assertEqual(len(self.capture["cells"]), 96)
        self.assertEqual(len(self.capture["factor_pairs"]), 144)
        self.assertEqual(
            len({cell["prompt_sha256"] for cell in self.capture["cells"]}),
            self.capture["accounting"]["unique_provider_inputs"],
        )
        self.assertEqual(
            self.capture["accounting"]["factor_pairs_with_provider_byte_change"]
            + self.capture["accounting"]["factor_no_op_pairs"],
            144,
        )
        self.assertTrue(all(cell["producer"] == "captured_shipped_context_pack" for cell in self.capture["cells"]))

    def test_schedule_is_bound_unit_for_unit_to_the_frozen_prompt(self) -> None:
        bindings = self.capture["prepared_unit_bindings"]
        self.assertEqual(len(bindings), 288)
        self.assertEqual(len({item["unit_id"] for item in bindings}), 288)
        counts: dict[str, int] = {}
        for item in bindings:
            counts[item["cell_id"]] = counts.get(item["cell_id"], 0) + 1
        self.assertEqual(set(counts.values()), {3})

        corrupted = copy.deepcopy(self.capture)
        corrupted["prepared_unit_bindings"][0]["repetition"] = 99
        corrupted["capture_sha256"] = self.evaluator.capture_identity(corrupted)
        with self.assertRaisesRegex(self.evaluator.EvaluationError, "schedule binding"):
            self.evaluator.validate_capture(corrupted, repo_root=ROOT)

    def test_provider_task_projection_is_a_closed_allowlist(self) -> None:
        task = {
            "allowed_patch_paths": ["src/example.py"],
            "prompt": "Repair the parser.",
        }
        self.assertEqual(set(self.evaluator.provider_task_projection(task)), set(task))
        leaked = {**task, "parent_commit": "0" * 40}
        with self.assertRaisesRegex(self.evaluator.EvaluationError, "provider task field"):
            self.evaluator.provider_task_projection(leaked)

    def test_root_normalization_is_exact_and_rejects_other_absolute_paths(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first_root = Path(first).resolve()
            second_root = Path(second).resolve()
            first_pack = f"Retrieval: `context-guard-pack slice --root {first_root} --path src/a.py --lines 1:2 --json`\n"
            second_pack = f"Retrieval: `context-guard-pack slice --root {second_root} --path src/a.py --lines 1:2 --json`\n"
            self.assertEqual(
                self.evaluator.normalize_provider_pack(first_pack, first_root),
                self.evaluator.normalize_provider_pack(second_pack, second_root),
            )
            with self.assertRaisesRegex(self.evaluator.EvaluationError, "absolute path"):
                self.evaluator.normalize_provider_pack(
                    first_pack
                    + "Retrieval: `context-guard-pack slice --root /private/other/path --path src/a.py --lines 1:2 --json`\n",
                    first_root,
                )

    def test_patch_parser_rejects_unsafe_or_non_patch_responses(self) -> None:
        invalid = (
            b"prose\ndiff --git a/src/a.py b/src/a.py\n",
            b"diff --git a/../escape b/../escape\n",
            b"diff --git a/src/a.py b/src/a.py\nGIT binary patch\n",
            b"diff --git a/src/a.py b/src/a.py\nold mode 100644\nnew mode 100755\n",
            b"diff --git a/src/a.py b/src/b.py\n",
            (
                b"diff --git a/src/a.py b/src/a.py\nindex 1111111..2222222 100644\n"
                b"--- a/src/a.py\n+++ b/src/outside.py\n@@ -1 +1 @@\n-old\n+new\n"
            ),
        )
        for response in invalid:
            with self.subTest(response=response[:32]):
                with self.assertRaises(self.evaluator.EvaluationError):
                    self.evaluator.validate_patch_envelope(response, {"src/a.py"})

        new_file = (
            b"diff --git a/src/new.py b/src/new.py\nnew file mode 100644\n"
            b"index 0000000..2222222\n--- /dev/null\n+++ b/src/new.py\t\n"
            b"@@ -0,0 +1 @@\n+new\n"
        )
        self.assertEqual(
            self.evaluator.validate_patch_envelope(new_file, {"src/new.py"}),
            ["src/new.py"],
        )

    def test_report_makes_no_provider_quality_token_cost_or_savings_claim(self) -> None:
        self.assertEqual(
            self.report["audit_boundary"],
            {"attempted": 4, "denied": 4, "succeeded": 0},
        )
        self.assertEqual(self.report["historical_checker_rehearsal"]["passed_tasks"], 12)
        self.assertEqual(self.report["historical_checker_rehearsal"]["failed_tasks"], 0)
        self.assertFalse(self.report["execution_authorized"])
        self.assertEqual(
            self.report["provider_evidence"],
            {
                "cost": "unavailable_not_executed",
                "quality": "unavailable_not_executed",
                "savings": "unavailable_not_executed",
                "tokens": "unavailable_not_executed",
            },
        )

    def test_synchronized_metadata_rewrite_cannot_self_authorize(self) -> None:
        corrupted = copy.deepcopy(self.capture)
        corrupted["cells"][0]["prompt_sha256"] = "0" * 64
        corrupted["prepared_unit_bindings"] = [
            {**item, "prompt_sha256": "0" * 64}
            if item["cell_id"] == corrupted["cells"][0]["cell_id"] else item
            for item in corrupted["prepared_unit_bindings"]
        ]
        corrupted["capture_sha256"] = self.evaluator.capture_identity(corrupted)
        with self.assertRaisesRegex(self.evaluator.EvaluationError, "cell seal"):
            self.evaluator.validate_capture(corrupted, repo_root=ROOT)

        corrupted_pairs = copy.deepcopy(self.capture)
        corrupted_pairs["factor_pairs"][0] = copy.deepcopy(corrupted_pairs["factor_pairs"][1])
        corrupted_pairs["capture_sha256"] = self.evaluator.capture_identity(corrupted_pairs)
        with self.assertRaisesRegex(self.evaluator.EvaluationError, "factor isolation pair set"):
            self.evaluator.validate_capture(corrupted_pairs, repo_root=ROOT)

    def test_no_op_pair_cannot_hide_a_changed_full_prompt(self) -> None:
        corrupted = copy.deepcopy(self.capture)
        corrupted["artifact_identities"] = self.evaluator.artifact_identities(ROOT)
        pair = next(item for item in corrupted["factor_pairs"] if not item["changed_provider_sections"])
        enabled = next(
            cell for cell in corrupted["cells"] if cell["cell_id"] == pair["enabled_cell_id"]
        )
        enabled["prompt_sha256"] = "f" * 64
        enabled["cell_seal_sha256"] = self.evaluator.cell_identity(enabled)
        for binding in corrupted["prepared_unit_bindings"]:
            if binding["cell_id"] == enabled["cell_id"]:
                binding["prompt_sha256"] = enabled["prompt_sha256"]
                binding["binding_sha256"] = self.evaluator.binding_identity(binding)
        corrupted["accounting"]["unique_provider_inputs"] = len({
            cell["prompt_sha256"] for cell in corrupted["cells"]
        })
        corrupted["capture_sha256"] = self.evaluator.capture_identity(corrupted)
        with self.assertRaisesRegex(self.evaluator.EvaluationError, "factor isolation prompt"):
            self.evaluator.validate_capture(corrupted, repo_root=ROOT)

    def test_arm_booleans_are_bound_to_arm_and_cell_ids(self) -> None:
        corrupted = copy.deepcopy(self.capture)
        corrupted["artifact_identities"] = self.evaluator.artifact_identities(ROOT)
        for cell in corrupted["cells"]:
            cell["arm"]["adaptive"] = not cell["arm"]["adaptive"]
            cell["cell_seal_sha256"] = self.evaluator.cell_identity(cell)
        corrupted["capture_sha256"] = self.evaluator.capture_identity(corrupted)
        with self.assertRaisesRegex(self.evaluator.EvaluationError, "cell arm identity"):
            self.evaluator.validate_capture(corrupted, repo_root=ROOT)

    def test_metadata_shapes_reject_synchronized_extra_fields(self) -> None:
        for location in ("cell", "application"):
            with self.subTest(location=location):
                corrupted = copy.deepcopy(self.capture)
                corrupted["artifact_identities"] = self.evaluator.artifact_identities(ROOT)
                if location == "cell":
                    corrupted["cells"][0]["debug_context_pack"] = "not metadata"
                else:
                    corrupted["cells"][0]["applications"]["adaptive"]["debug"] = "extra"
                corrupted["cells"][0]["cell_seal_sha256"] = self.evaluator.cell_identity(
                    corrupted["cells"][0]
                )
                corrupted["capture_sha256"] = self.evaluator.capture_identity(corrupted)
                with self.assertRaisesRegex(self.evaluator.EvaluationError, "metadata shape"):
                    self.evaluator.validate_capture(corrupted, repo_root=ROOT)

        capture = copy.deepcopy(self.capture)
        capture["artifact_identities"] = self.evaluator.artifact_identities(ROOT)
        capture["capture_sha256"] = self.evaluator.capture_identity(capture)
        report = copy.deepcopy(self.report)
        report["audit_boundary"] = {"attempted": 4, "denied": 4, "succeeded": 0}
        report["producer"] = self.evaluator.relative_identity(EVALUATOR, ROOT)
        report["provider_input_capture_sha256"] = self.evaluator.sha256(
            self.evaluator.canonical(capture)
        )
        report["historical_checker_rehearsal"]["results"][0]["debug"] = "extra"
        with self.assertRaisesRegex(self.evaluator.EvaluationError, "rehearsal result shape"):
            self.evaluator.validate_report(report, capture=capture, repo_root=ROOT)

    def test_rehearsal_results_bind_the_exact_task_checker_and_patch(self) -> None:
        capture = copy.deepcopy(self.capture)
        capture["artifact_identities"] = self.evaluator.artifact_identities(ROOT)
        capture["capture_sha256"] = self.evaluator.capture_identity(capture)
        report = copy.deepcopy(self.report)
        report["audit_boundary"] = {"attempted": 4, "denied": 4, "succeeded": 0}
        report["producer"] = self.evaluator.relative_identity(EVALUATOR, ROOT)
        report["provider_input_capture_sha256"] = self.evaluator.sha256(
            self.evaluator.canonical(capture)
        )
        result = report["historical_checker_rehearsal"]["results"][0]
        result["checker_sha256"] = "0" * 64
        result["historical_patch_sha256"] = "1" * 64
        with self.assertRaisesRegex(self.evaluator.EvaluationError, "rehearsal identity"):
            self.evaluator.validate_report(report, capture=capture, repo_root=ROOT)

    def test_scorer_is_captured_only_after_provider_inputs_validate(self) -> None:
        self.assertNotIn("scorer_artifact", self.capture)
        self.assertEqual(
            self.report["phase_order"],
            [
                "all_96_provider_inputs_sealed",
                "scorer_artifact_captured",
                "12_historical_checkers_rehearsed",
            ],
        )
        corrupted = copy.deepcopy(self.capture)
        corrupted["cells"][0]["cell_seal_sha256"] = "0" * 64
        with mock.patch.object(self.evaluator, "load_object") as loader:
            with self.assertRaisesRegex(self.evaluator.EvaluationError, "cell seal"):
                self.evaluator.load_scorer_contract(corrupted, repo_root=ROOT)
        loader.assert_not_called()

    def test_git_environment_disables_fetch_prompts_and_credentials(self) -> None:
        environment = self.evaluator.git_environment()
        self.assertEqual(environment["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_CONFIG_COUNT"], "4")
        self.assertNotIn("HOME", environment)
        self.assertNotIn("SSH_AUTH_SOCK", environment)

    def test_source_inventory_parser_rejects_submodules_duplicates_and_escaping_links(self) -> None:
        valid = b"100644 blob " + b"a" * 40 + b" 3\tsrc/a.py\0"
        parsed = self.evaluator.parse_ls_tree(valid)
        self.assertEqual(parsed[0]["path"], "src/a.py")
        for raw in (
            b"160000 commit " + b"a" * 40 + b" -\tdep\0",
            valid + valid,
        ):
            with self.subTest(raw=raw[:12]):
                with self.assertRaises(self.evaluator.EvaluationError):
                    self.evaluator.parse_ls_tree(raw)
        self.assertEqual(
            self.evaluator.safe_symlink_destination(
                Path("tests/certs/valid/ca"), "../expired/ca"
            ).as_posix(),
            "tests/certs/expired/ca",
        )
        with self.assertRaisesRegex(self.evaluator.EvaluationError, "symlink"):
            self.evaluator.safe_symlink_destination(Path("a/link"), "../../../escape")

    def test_no_history_index_exercises_the_shipped_git_ls_files_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            entries = [
                {"bytes": 1, "mode": "100644", "object_sha": "a" * 40, "path": "src/a.py"},
                {"bytes": 1, "mode": "100755", "object_sha": "b" * 40, "path": "tools/run"},
            ]
            self.evaluator.initialize_no_history_index(workspace, entries)
            self.assertEqual(
                self.evaluator.run_git(workspace, ["ls-files", "-z"]).split(b"\0")[:-1],
                [b"src/a.py", b"tools/run"],
            )
            self.assertEqual(self.evaluator.run_git(workspace, ["remote"]).strip(), b"")

    @unittest.skipUnless(CORPUS_ROOT.is_dir(), "approved captured v3 corpus is unavailable")
    def test_regeneration_matches_committed_evidence_without_provider_or_network(self) -> None:
        generated_capture, generated_report = self.evaluator.generate_evidence(
            repo_root=ROOT,
            corpus_root=CORPUS_ROOT,
        )
        self.assertEqual(self.evaluator.canonical(generated_capture), CAPTURE_FREEZE.read_bytes())
        self.assertEqual(self.evaluator.canonical(generated_report), REHEARSAL_REPORT.read_bytes())


if __name__ == "__main__":
    unittest.main()
