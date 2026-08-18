from __future__ import annotations

import hashlib
import importlib.util
import itertools
import json
import os
from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
V3 = ROOT / "research/provider-live-roadmap/p3-api/v3"
PREREGISTRATION = V3 / "preregistration.json"
CORPUS = V3 / "corpus-manifest.json"
SCHEDULE = V3 / "schedule.json"
CHECKERS = V3 / "scorer-only/checkers.json"
GENERATOR = V3 / "build_preregistration.py"
PROMPT_TEMPLATE = V3 / "provider-prompt-template.txt"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def load_json(path: Path) -> dict:
    if not path.is_file():
        raise AssertionError(f"missing v3 artifact: {path.relative_to(ROOT)}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"v3 artifact must be an object: {path.relative_to(ROOT)}")
    return value


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def checker_passes(repo: Path, ref: str, checker: dict) -> bool:
    for assertion in checker["assertions"]:
        result = subprocess.run(
            ["git", "show", f'{ref}:{assertion["path"]}'],
            cwd=repo,
            capture_output=True,
            check=False,
        )
        raw = result.stdout if result.returncode == 0 else b""
        for literal in assertion["required_literals"]:
            if literal.encode("utf-8") not in raw:
                return False
        for literal in assertion["forbidden_literals"]:
            if literal.encode("utf-8") in raw:
                return False
    return True


class P3FactorialPreregistrationV3Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = load_json(PREREGISTRATION)

    def test_binds_three_independent_mature_projects_and_balanced_real_tasks(self) -> None:
        corpus = load_json(CORPUS)
        projects = corpus["projects"]
        self.assertEqual(
            {project["id"] for project in projects},
            {"requests", "typescript", "swift_argument_parser"},
        )
        self.assertEqual(len({project["repository_url"] for project in projects}), 3)
        self.assertTrue(all(project["independent_repository"] for project in projects))
        self.assertTrue(all(project["history_years_at_intake"] >= 5 for project in projects))
        self.assertEqual(corpus["sampling"]["kind"], "retrospective_curated_finite_corpus")
        self.assertFalse(corpus["sampling"]["probability_sample"])

        tasks = corpus["tasks"]
        taxonomies = {"bug_fix", "boundary_hardening", "feature", "maintenance"}
        self.assertEqual(len(tasks), 12)
        self.assertEqual(
            {(task["project_id"], task["taxonomy"]) for task in tasks},
            set(itertools.product({project["id"] for project in projects}, taxonomies)),
        )
        for task in tasks:
            for field in ("historical_commit", "parent_commit", "parent_tree_sha", "target_tree_sha"):
                self.assertRegex(task[field], HEX40)
            self.assertRegex(task["selected_path_historical_patch_sha256"], HEX64)
            self.assertLessEqual(task["selected_path_historical_patch_bytes"], 8192)
            self.assertIsInstance(task["excluded_upstream_changed_paths"], list)
            self.assertEqual(task["prompt_sha256"], sha256(task["prompt"].encode("utf-8")))
            self.assertGreaterEqual(len(task["allowed_patch_paths"]), 1)
            self.assertLessEqual(len(task["allowed_patch_paths"]), 5)
            self.assertFalse(
                set(task["allowed_patch_paths"]) & set(task["excluded_upstream_changed_paths"])
            )
            self.assertNotIn(task["historical_commit"], task["prompt"])

        scope = self.plan["claims"]["scope"]
        self.assertEqual(scope, "these_12_retrospective_tasks_in_3_public_projects")
        self.assertFalse(self.plan["claims"]["all_task_quality_guarantee"])
        self.assertFalse(self.plan["claims"]["future_project_generalization"])
        self.assertEqual(
            self.plan["claims"]["quality_outcome"],
            "exact_selected_path_historical_patch_reproduction_plus_source_assertions",
        )
        self.assertFalse(self.plan["claims"]["semantic_alternative_patch_acceptance"])
        self.assertFalse(self.plan["claims"]["semantic_correctness_guarantee"])

    def test_artifact_bytes_are_bound_without_a_self_authorized_freeze(self) -> None:
        self.assertEqual(self.plan["status"], "draft_preregistered_no_execution")
        self.assertFalse(self.plan["execution_authorized"])
        self.assertEqual(self.plan["provider_calls_during_preregistration"], 0)
        self.assertTrue(self.plan["freeze"]["effective_after_tracked_commit"])
        self.assertIsNone(self.plan["freeze"]["tracked_commit"])
        for name, path in {
            "checkers": CHECKERS,
            "corpus": CORPUS,
            "prompt_template": PROMPT_TEMPLATE,
            "schedule": SCHEDULE,
        }.items():
            binding = self.plan["artifacts"][name]
            raw = path.read_bytes()
            self.assertEqual(binding["path"], str(path.relative_to(ROOT)))
            self.assertEqual(binding["bytes"], len(raw))
            self.assertEqual(binding["sha256"], sha256(raw))

    def test_freeze_candidate_files_are_tracked_before_activation(self) -> None:
        runtime_residue = [
            path
            for path in V3.rglob("*")
            if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}
        ]
        self.assertEqual(runtime_residue, [])
        # This is the G3 preregistration freeze, not an assertion that every
        # artifact added by later goals was already tracked in the G3 commit.
        required = [
            V3 / "README.md",
            GENERATOR,
            CORPUS,
            PREREGISTRATION,
            PROMPT_TEMPLATE,
            SCHEDULE,
            CHECKERS,
            Path(__file__),
        ]
        for path in required:
            with self.subTest(path=str(path.relative_to(ROOT))):
                result = subprocess.run(
                    ["git", "ls-files", "--error-unmatch", "--", str(path.relative_to(ROOT))],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_generator_reproduces_every_generated_byte(self) -> None:
        spec = importlib.util.spec_from_file_location("p3_v3_prereg_generator", GENERATOR)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        corpus_raw = module.canonical(module.build_corpus())
        schedule_raw = module.canonical(module.build_schedule())
        checkers_raw = module.canonical(module.CHECKERS)
        prompt_template_raw = module.PROMPT_TEMPLATE
        self.assertEqual(CORPUS.read_bytes(), corpus_raw)
        self.assertEqual(SCHEDULE.read_bytes(), schedule_raw)
        self.assertEqual(CHECKERS.read_bytes(), checkers_raw)
        self.assertEqual(PROMPT_TEMPLATE.read_bytes(), prompt_template_raw)
        bindings = {
            "checkers": module.artifact_binding(CHECKERS, checkers_raw),
            "corpus": module.artifact_binding(CORPUS, corpus_raw),
            "prompt_template": module.artifact_binding(PROMPT_TEMPLATE, prompt_template_raw),
            "schedule": module.artifact_binding(SCHEDULE, schedule_raw),
        }
        self.assertEqual(
            PREREGISTRATION.read_bytes(),
            module.canonical(module.build_preregistration(bindings)),
        )

    def test_provider_visible_factor_interventions_are_independent(self) -> None:
        factors = self.plan["design"]["factors"]
        self.assertEqual(list(factors), ["adaptive", "symbol_memory", "graph_closure"])
        arms = self.plan["design"]["arms"]
        observed = {
            (arm["adaptive"], arm["symbol_memory"], arm["graph_closure"])
            for arm in arms
        }
        self.assertEqual(observed, set(itertools.product((False, True), repeat=3)))
        for arm in arms:
            intervention = arm["intervention"]
            self.assertFalse(intervention["provider_sees_raw_symbol_memory"])
            self.assertEqual(
                intervention["provider_sees_pure_symbol_projection"], arm["symbol_memory"]
            )
            self.assertEqual(intervention["manifest_graph_expanded"], arm["graph_closure"])
            self.assertEqual(intervention["manifest_adaptive_pruned"], arm["adaptive"])
            if arm["symbol_memory"]:
                self.assertEqual(
                    intervention["pure_symbol_projection_forbidden_fields"],
                    ["graph_context", "graph_edges", "graph_rank"],
                )
            if arm["graph_closure"] and not arm["symbol_memory"]:
                self.assertFalse(intervention["provider_sees_pure_symbol_projection"])
        self.assertEqual(
            self.plan["design"]["transformation_order"],
            ["ordinary_selection", "adaptive_pruning", "graph_expansion", "pack_build", "pure_symbol_projection"],
        )
        self.assertEqual(
            self.plan["design"]["provider_prompt_variability"],
            "only_context_pack_and_pure_symbol_projection_may_vary_by_arm",
        )
        self.assertIn(b"{allowed_patch_paths_json}", PROMPT_TEMPLATE.read_bytes())
        gate = self.plan["design"]["provider_input_rehearsal_gate"]
        self.assertEqual(gate["required_units"], 288)
        self.assertEqual(gate["required_task_arm_cells"], 96)
        self.assertEqual(gate["unique_provider_input_count"], "measured_at_rehearsal_not_forced")
        self.assertTrue(gate["activated_factor_no_op_is_recorded_as_zero_byte_effect"])
        self.assertTrue(gate["committed_before_provider_calls"])
        self.assertTrue(gate["exact_pairwise_factor_byte_isolation"])
        self.assertTrue(gate["scorer_fields_absent_from_every_provider_input"])

    def test_schedule_materializes_36_blocks_and_288_unique_units(self) -> None:
        corpus = load_json(CORPUS)
        schedule = load_json(SCHEDULE)
        task_ids = {task["id"] for task in corpus["tasks"]}
        arm_ids = {arm["id"] for arm in self.plan["design"]["arms"]}
        blocks = schedule["blocks"]
        self.assertEqual(len(blocks), 36)
        self.assertEqual(schedule["repetitions_per_task_arm"], 3)
        self.assertEqual({block["task_id"] for block in blocks}, task_ids)
        unit_ids: list[str] = []
        for block in blocks:
            self.assertIn(block["repetition"], (0, 1, 2))
            self.assertEqual(set(block["arm_order"]), arm_ids)
            self.assertEqual(len(block["units"]), 8)
            self.assertEqual([unit["arm_id"] for unit in block["units"]], block["arm_order"])
            for unit in block["units"]:
                self.assertEqual(unit["task_id"], block["task_id"])
                self.assertEqual(unit["repetition"], block["repetition"])
                unit_ids.append(unit["unit_id"])
        self.assertEqual(len(unit_ids), 288)
        self.assertEqual(len(set(unit_ids)), 288)
        self.assertEqual(schedule["scheduled_units"], 288)
        self.assertEqual(schedule["stopping_rule"], "one_terminal_receipt_per_scheduled_unit_no_reruns_replacements_or_extension")

    def test_patch_and_quality_protocol_fails_closed(self) -> None:
        self.assertIn("execution_protocol", self.plan)
        protocol = self.plan["execution_protocol"]
        self.assertEqual(protocol["response_grammar"], "exactly_one_utf8_unified_diff_no_prose_or_fences")
        self.assertTrue(protocol["seal_raw_response_and_usage_before_parse"])
        self.assertEqual(
            set(protocol["rejected_patch_features"]),
            {"absolute_path", "path_traversal", "symlink", "submodule", "binary_patch", "outside_allowed_paths"},
        )
        self.assertEqual(
            protocol["apply_steps"],
            ["git_apply_check", "git_apply", "verify_exact_selected_path_patch", "run_frozen_source_assertions"],
        )
        self.assertEqual(
            set(protocol["completed_quality_failures"]),
            {"invalid_patch", "truncated_patch", "forbidden_path", "apply_failure", "checker_failure"},
        )
        self.assertNotIn("checker_failure", protocol["technical_missingness"])
        self.assertEqual(protocol["network_during_checker"], "denied")
        self.assertEqual(protocol["provider_worktree"], "exported_parent_tree_without_git_history")
        self.assertEqual(protocol["provider_input_task_field_policy"], "closed_allowlist")
        self.assertEqual(
            protocol["provider_input_allowed_task_fields"],
            ["allowed_patch_paths", "prompt"],
        )
        self.assertTrue(protocol["provider_input_non_allowlisted_fields_forbidden"])

        quality = self.plan["analysis"]["quality_gate"]
        self.assertEqual(quality["required_terminal_receipts"], 288)
        self.assertEqual(quality["required_checker_pass_rate"], 1.0)
        self.assertEqual(quality["allowed_baseline_pass_candidate_fail_pairs"], 0)
        self.assertTrue(quality["any_failure_blocks_quality_preserving_savings_claim"])

    def test_analysis_and_cost_claim_boundaries_are_closed(self) -> None:
        analysis = self.plan["analysis"]
        self.assertNotIn("bootstrap", analysis)
        self.assertNotIn("confirmatory_test", analysis)
        self.assertNotIn("inference_cluster", analysis)
        self.assertEqual(analysis["independent_cluster"], "project")
        self.assertEqual(analysis["independent_cluster_count"], 3)
        self.assertEqual(analysis["technical_repetitions_reduced_within_task"], 3)
        self.assertEqual(
            analysis["predeclared_contrasts"],
            ["a111_minus_a000", "adaptive_main_effect", "symbol_memory_main_effect", "graph_closure_main_effect"],
        )
        self.assertEqual(
            analysis["multiplicity"],
            "no_null_rejection_claims_report_all_4_predeclared_contrasts_and_all_7_factorial_effects",
        )
        self.assertEqual(analysis["factorial_effect_count"], 7)
        self.assertEqual(analysis["total_provider_tokens"], "input_tokens_plus_output_tokens")
        self.assertEqual(
            analysis["inferential_claim_status"],
            "unavailable_only_3_independent_project_clusters",
        )
        self.assertEqual(
            analysis["main_effect_formulas"],
            {
                "adaptive": "mean_task((a100+a101+a110+a111-a000-a001-a010-a011)/4)",
                "graph_closure": "mean_task((a001+a011+a101+a111-a000-a010-a100-a110)/4)",
                "symbol_memory": "mean_task((a010+a011+a110+a111-a000-a001-a100-a101)/4)",
            },
        )
        self.assertEqual(analysis["uncertainty"]["method"], "all_27_ordered_project_cluster_resamples")
        self.assertEqual(analysis["uncertainty"]["claim"], "descriptive_finite_corpus_sensitivity_only")
        self.assertEqual(analysis["uncertainty"]["leave_one_project_out_rows"], 3)
        self.assertEqual(analysis["complete_case_rule"], "all_3_repetitions_and_all_8_arms_per_task")
        self.assertEqual(
            analysis["missingness_rule"],
            "any_missing_unit_blocks_all_predeclared_contrast_and_factorial_effect_estimates",
        )
        self.assertEqual(analysis["quality_gate"]["allowed_technical_missing_units"], 0)

        cost = self.plan["cost_evidence"]
        self.assertEqual(cost["messages_api_per_request_authority"], "token_usage_only")
        self.assertEqual(cost["calculated_list_price_authority"], "calculated_not_provider_reported")
        self.assertEqual(cost["one_exclusive_standard_key"], "provider_experiment_total_aggregate_only")
        self.assertEqual(cost["eight_exclusive_standard_keys"], "provider_arm_aggregates_at_best")
        self.assertEqual(cost["provider_confirmed_per_request_usd"], "unavailable_without_request_level_export_or_unique_bucket_per_request")

    def test_checker_spec_is_scorer_only_and_complete(self) -> None:
        corpus = load_json(CORPUS)
        checkers = load_json(CHECKERS)
        self.assertEqual({item["task_id"] for item in checkers["checkers"]}, {task["id"] for task in corpus["tasks"]})
        task_paths = {task["id"]: set(task["allowed_patch_paths"]) for task in corpus["tasks"]}
        task_patches = {
            task["id"]: {
                "bytes": task["selected_path_historical_patch_bytes"],
                "sha256": task["selected_path_historical_patch_sha256"],
            }
            for task in corpus["tasks"]
        }
        for checker in checkers["checkers"]:
            self.assertEqual(
                checker["type"],
                "source_assertions_and_exact_selected_path_historical_patch_v1",
            )
            self.assertEqual(
                checker["expected_selected_path_patch"],
                task_patches[checker["task_id"]],
            )
            self.assertGreaterEqual(len(checker["assertions"]), 1)
            for assertion in checker["assertions"]:
                self.assertIn(assertion["path"], task_paths[checker["task_id"]])
                self.assertTrue(assertion["required_literals"] or assertion["forbidden_literals"])
        corpus_raw = CORPUS.read_bytes()
        prereg_raw = PREREGISTRATION.read_bytes()
        for raw in (corpus_raw, prereg_raw):
            self.assertNotIn(b'"required_literals"', raw)
            self.assertNotIn(b'"forbidden_literals"', raw)
            self.assertNotIn(b'"assertions"', raw)

    def test_external_git_intake_matches_frozen_ids_and_checker_discriminates(self) -> None:
        cache = os.environ.get("CONTEXTGUARD_V3_CORPUS_ROOT")
        if not cache:
            self.skipTest("set CONTEXTGUARD_V3_CORPUS_ROOT for approved public-clone parity")
        corpus = load_json(CORPUS)
        checkers = {item["task_id"]: item for item in load_json(CHECKERS)["checkers"]}
        repo_names = {project["id"]: project["cache_directory"] for project in corpus["projects"]}
        for task in corpus["tasks"]:
            with self.subTest(task=task["id"]):
                repo = Path(cache) / repo_names[task["project_id"]]
                self.assertEqual(
                    subprocess.run(["git", "rev-parse", f'{task["historical_commit"]}^1'], cwd=repo, capture_output=True, text=True, check=True).stdout.strip(),
                    task["parent_commit"],
                )
                self.assertEqual(
                    subprocess.run(["git", "rev-parse", f'{task["parent_commit"]}^{{tree}}'], cwd=repo, capture_output=True, text=True, check=True).stdout.strip(),
                    task["parent_tree_sha"],
                )
                changed_paths = subprocess.run(
                    ["git", "diff", "--name-only", task["parent_commit"], task["historical_commit"]],
                    cwd=repo,
                    capture_output=True,
                    text=True,
                    check=True,
                ).stdout.splitlines()
                self.assertEqual(
                    set(changed_paths),
                    set(task["allowed_patch_paths"]) | set(task["excluded_upstream_changed_paths"]),
                )
                patch = subprocess.run(
                    ["git", "diff", "--binary", "--full-index", "--no-renames", task["parent_commit"], task["historical_commit"], "--", *task["allowed_patch_paths"]],
                    cwd=repo, capture_output=True, check=True,
                ).stdout
                self.assertEqual(len(patch), task["selected_path_historical_patch_bytes"])
                self.assertEqual(sha256(patch), task["selected_path_historical_patch_sha256"])
                self.assertTrue(checker_passes(repo, task["historical_commit"], checkers[task["id"]]))
                self.assertFalse(checker_passes(repo, task["parent_commit"], checkers[task["id"]]))


if __name__ == "__main__":
    unittest.main()
