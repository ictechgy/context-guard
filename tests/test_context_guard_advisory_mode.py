from __future__ import annotations

import copy
import io
import json
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
COST_GUARD = ROOT / "context-guard-kit" / "cost_guard.py"
BENCHMARK = ROOT / "scripts" / "benchmark_advisory_mode.py"
LIVE_COLLECTOR = ROOT / "scripts" / "collect_advisory_live_samples.py"
LIVE_EVIDENCE = ROOT / "research" / "weightclass-advisory-live-sample-2026-08-22.json"
ADVISORY_DOC = ROOT / "docs" / "weightclass-advisory-mode.md"
EXPECTED_RESPONSE = "CG_RESULT command=sample_suite check=sample_test_alpha actual=retry"


def workload() -> dict:
    return {
        "schema_version": "contextguard.advisory-workload.v1",
        "vendor": "codex",
        "invocation": {
            "safe_mode": False,
            "hooks_available": False,
            "explicit_wrappers_available": True,
            "rules_loaded": False,
            "skills_loaded": False,
            "host_tool_surface_equal_to_control": True,
        },
        "signals": {
            "candidate_context_bytes": 2048,
            "estimated_local_overhead_ms": 0,
            "graph_candidate_bytes": 0,
            "graph_candidate_count": 0,
            "graph_replacement_bytes": 0,
            "largest_file_bytes": 2048,
            "log_bytes": 0,
            "repo_map_cached": False,
            "selected_file_count": 1,
            "task_prompt_bytes": 512,
        },
        "limits": {
            "inline_log_bytes": 4096,
            "max_local_overhead_ms": 250,
            "minimum_gross_context_savings_bytes": 2048,
            "pack_bytes": 8192,
            "symbol_slice_bytes": 8192,
        },
    }


def load_module() -> dict:
    return runpy.run_path(str(COST_GUARD), run_name="contextguard_advisory_test")


class ContextGuardAdvisoryModeTests(unittest.TestCase):
    def planner(self):
        module = load_module()
        self.assertIn("advisory_decision", module)
        return module["advisory_decision"]

    def test_small_task_is_zero_overhead_bypass(self) -> None:
        decision = self.planner()(workload())
        self.assertEqual(
            set(decision),
            {
                "accounting",
                "actions",
                "activation_status",
                "capabilities",
                "claim_boundary",
                "decision",
                "measurement_eligible",
                "mode",
                "persistent_writes_allowed",
                "provider_context",
                "provider_context_bytes",
                "reason",
                "receipts_enabled",
                "schema_version",
                "selected_features",
            },
        )
        self.assertEqual(decision["decision"], "bypass")
        self.assertEqual(decision["reason"], "below_break_even")
        self.assertEqual(decision["provider_context"], "")
        self.assertEqual(decision["provider_context_bytes"], 0)
        self.assertIn("estimated_gross_context_saved_bytes", decision["accounting"])
        self.assertNotIn("estimated_net_saved_bytes", decision["accounting"])
        self.assertNotIn("provider_net_saved_bytes", decision["accounting"])
        self.assertEqual(decision["actions"], [])
        self.assertTrue(decision["measurement_eligible"])
        self.assertFalse(decision["persistent_writes_allowed"])
        self.assertFalse(decision["receipts_enabled"])
        self.assertEqual(
            decision["selected_features"],
            {"adaptive": False, "graph": False, "symbol": False, "trim_output": False},
        )

    def test_claude_safe_mode_uses_explicit_wrapper_without_claiming_hooks(self) -> None:
        candidate = workload()
        candidate["vendor"] = "claude"
        candidate["invocation"].update(
            {"safe_mode": True, "hooks_available": True}
        )
        candidate["signals"].update(
            {"candidate_context_bytes": 20000, "log_bytes": 16000}
        )
        decision = self.planner()(candidate)
        self.assertEqual(decision["decision"], "trim_output")
        self.assertEqual(decision["activation_status"], "active")
        self.assertFalse(decision["capabilities"]["hooks_effective"])
        self.assertTrue(decision["capabilities"]["explicit_wrappers_available"])
        self.assertEqual(
            decision["actions"],
            [{"kind": "trim_output", "max_inline_bytes": 4096}],
        )

    def test_unavailable_wrapper_makes_large_task_inactive(self) -> None:
        candidate = workload()
        candidate["vendor"] = "claude"
        candidate["invocation"].update(
            {
                "safe_mode": True,
                "hooks_available": True,
                "explicit_wrappers_available": False,
            }
        )
        candidate["signals"].update(
            {"candidate_context_bytes": 20000, "log_bytes": 16000}
        )
        decision = self.planner()(candidate)
        self.assertEqual(decision["activation_status"], "inactive")
        self.assertEqual(decision["decision"], "bypass")
        self.assertEqual(decision["reason"], "explicit_wrappers_unavailable")
        self.assertFalse(decision["measurement_eligible"])

    def test_persistent_context_or_host_surface_mismatch_blocks_measurement(self) -> None:
        for field in ("rules_loaded", "skills_loaded"):
            with self.subTest(field=field):
                candidate = workload()
                candidate["invocation"][field] = True
                decision = self.planner()(candidate)
                self.assertEqual(decision["reason"], "persistent_context_loaded")
                self.assertFalse(decision["measurement_eligible"])
        candidate = workload()
        candidate["invocation"]["host_tool_surface_equal_to_control"] = False
        decision = self.planner()(candidate)
        self.assertEqual(decision["reason"], "host_tool_surface_mismatch")
        self.assertFalse(decision["measurement_eligible"])

    def test_large_file_and_broad_context_select_only_profitable_factor(self) -> None:
        symbol_candidate = workload()
        symbol_candidate["signals"].update(
            {
                "candidate_context_bytes": 14000,
                "largest_file_bytes": 12000,
            }
        )
        symbol = self.planner()(symbol_candidate)
        self.assertEqual(symbol["decision"], "symbol_slice")
        self.assertTrue(symbol["selected_features"]["symbol"])

        adaptive_candidate = workload()
        adaptive_candidate["signals"].update(
            {
                "candidate_context_bytes": 50000,
                "largest_file_bytes": 12000,
                "selected_file_count": 8,
            }
        )
        adaptive = self.planner()(adaptive_candidate)
        self.assertEqual(adaptive["decision"], "adaptive_pack")
        self.assertTrue(adaptive["selected_features"]["adaptive"])
        self.assertFalse(adaptive["selected_features"]["symbol"])
        self.assertFalse(adaptive["selected_features"]["graph"])

    def test_graph_requires_cached_positive_replacement_and_never_runs_as_noop(self) -> None:
        candidate = workload()
        candidate["signals"].update(
            {
                "candidate_context_bytes": 50000,
                "largest_file_bytes": 12000,
                "selected_file_count": 8,
                "graph_candidate_count": 1,
                "graph_candidate_bytes": 1000,
                "graph_replacement_bytes": 3000,
                "repo_map_cached": False,
            }
        )
        uncached = self.planner()(candidate)
        self.assertFalse(uncached["selected_features"]["graph"])
        candidate["signals"]["repo_map_cached"] = True
        cached = self.planner()(candidate)
        self.assertTrue(cached["selected_features"]["graph"])
        self.assertEqual(cached["accounting"]["graph_replacement_delta_bytes"], 2000)
        self.assertEqual(
            cached["accounting"]["estimated_treatment_context_bytes"],
            uncached["accounting"]["estimated_treatment_context_bytes"],
        )

        candidate["signals"].update(
            {
                "graph_candidate_count": 0,
                "graph_candidate_bytes": 0,
                "graph_replacement_bytes": 0,
            }
        )
        no_candidate = self.planner()(candidate)
        self.assertFalse(no_candidate["selected_features"]["graph"])

    def test_graph_delta_cannot_invent_pack_savings_or_cross_activation_floor(self) -> None:
        candidate = workload()
        candidate["signals"].update(
            {
                "candidate_context_bytes": 10000,
                "selected_file_count": 3,
                "graph_candidate_count": 1,
                "graph_candidate_bytes": 100,
                "graph_replacement_bytes": 10000,
                "repo_map_cached": True,
            }
        )
        candidate["limits"].update(
            {"pack_bytes": 9000, "minimum_gross_context_savings_bytes": 5000}
        )
        decision = self.planner()(candidate)
        self.assertEqual(decision["decision"], "bypass")
        self.assertEqual(decision["reason"], "below_break_even")
        self.assertEqual(
            decision["accounting"]["estimated_treatment_context_bytes"], 10000
        )

    def test_local_overhead_budget_can_force_bypass(self) -> None:
        candidate = workload()
        candidate["signals"].update(
            {
                "candidate_context_bytes": 50000,
                "estimated_local_overhead_ms": 251,
                "selected_file_count": 8,
            }
        )
        decision = self.planner()(candidate)
        self.assertEqual(decision["decision"], "bypass")
        self.assertEqual(decision["reason"], "local_overhead_budget_exceeded")

    def test_contract_rejects_unknown_negative_boolean_and_inconsistent_values(self) -> None:
        planner = self.planner()
        invalid = []
        unknown = workload()
        unknown["invented"] = True
        invalid.append(unknown)
        negative = workload()
        negative["signals"]["log_bytes"] = -1
        invalid.append(negative)
        boolean_integer = workload()
        boolean_integer["signals"]["log_bytes"] = True
        invalid.append(boolean_integer)
        inconsistent = workload()
        inconsistent["signals"]["log_bytes"] = 4096
        invalid.append(inconsistent)
        for candidate in invalid:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                planner(candidate)

    def test_cli_emits_closed_json_without_task_or_path_fields(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(COST_GUARD),
                "advisory",
                "--workload",
                "-",
                "--json",
            ],
            cwd=ROOT,
            input=json.dumps(workload()),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        decision = json.loads(completed.stdout)
        encoded = json.dumps(decision, sort_keys=True)
        self.assertNotIn("task_prompt", encoded)
        self.assertNotIn("path", encoded)
        self.assertEqual(decision["provider_context_bytes"], 0)

    def test_cli_rejects_duplicate_keys_at_every_advisory_depth(self) -> None:
        encoded = json.dumps(workload(), separators=(",", ":"))
        candidates = [
            encoded.replace(
                '"vendor":"codex"', '"vendor":"claude","vendor":"codex"'
            ),
            encoded.replace(
                '"safe_mode":false', '"safe_mode":true,"safe_mode":false'
            ),
        ]
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-B",
                        str(COST_GUARD),
                        "advisory",
                        "--workload",
                        "-",
                        "--json",
                    ],
                    cwd=ROOT,
                    input=candidate,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stdout, "")
                self.assertIn("duplicate JSON key", completed.stderr)

    def test_cli_rejects_non_string_vendor_without_traceback(self) -> None:
        candidate = workload()
        candidate["vendor"] = []
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(COST_GUARD),
                "advisory",
                "--workload",
                "-",
                "--json",
            ],
            cwd=ROOT,
            input=json.dumps(candidate),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, "")
        self.assertIn("vendor must be claude or codex", completed.stderr)
        self.assertNotIn("Traceback", completed.stderr)

    def test_provider_free_sample_matrix_is_closed_and_factor_specific(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(BENCHMARK),
                "--matrix-json",
                "--repetitions",
                "5",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(completed.stdout.startswith("{"), completed.stdout)
        report = json.loads(completed.stdout)
        self.assertEqual(report["schema_version"], "contextguard.advisory-benchmark.v1")
        self.assertEqual(report["repetitions"], 5)
        self.assertEqual(len(report["cases"]), 10)
        by_name = {row["name"]: row for row in report["cases"]}
        self.assertEqual(by_name["small_codex"]["decision"], "bypass")
        self.assertEqual(by_name["safe_mode_large_log"]["decision"], "trim_output")
        self.assertFalse(by_name["graph_no_candidate"]["selected_features"]["graph"])
        self.assertTrue(by_name["graph_cached_positive"]["selected_features"]["graph"])
        self.assertEqual(report["summary"]["provider_context_bytes"], 0)
        self.assertLess(report["summary"]["planner_median_ms"], 5.0)
        encoded = json.dumps(report, sort_keys=True)
        self.assertNotIn("task_prompt", encoded)
        self.assertNotIn("path", encoded)

    def test_live_collector_dry_run_bounds_provider_egress(self) -> None:
        self.assertTrue(LIVE_COLLECTOR.exists())
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(LIVE_COLLECTOR),
                "--dry-run",
                "--vendor",
                "all",
                "--repetitions",
                "4",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        plan = json.loads(completed.stdout)
        self.assertEqual(plan["schema_version"], "contextguard.advisory-live-plan.v2")
        invocation_count = plan["provider_cli_invocations_performed"]
        self.assertIs(type(invocation_count), int)
        self.assertEqual(invocation_count, 0)
        self.assertFalse(plan["provider_transport_calls_observed"])
        self.assertEqual(plan["maximum_cli_invocations"], 16)
        self.assertNotIn("maximum_provider_calls", plan)
        self.assertLess(plan["treatment_prompt_bytes"], plan["control_prompt_bytes"])
        self.assertFalse(plan["task_or_repository_content_read"])
        self.assertEqual(
            plan["arm_orders"],
            [
                "control,advisory",
                "advisory,control",
                "control,advisory",
                "advisory,control",
            ],
        )
        self.assertEqual(
            plan["advisory_decisions"],
            {"claude": "trim_output", "codex": "trim_output"},
        )
        self.assertLessEqual(
            plan["compressed_log_bytes"], plan["selected_inline_log_bytes"]
        )

    def test_live_collector_parses_vendor_usage_without_double_counting_cache(self) -> None:
        self.assertTrue(LIVE_COLLECTOR.exists())
        module = runpy.run_path(str(LIVE_COLLECTOR), run_name="advisory_live_parser_test")
        claude = module["parse_claude_result"](
            json.dumps(
                {
                    "result": "CG_RESULT command=sample_suite check=sample_test_alpha actual=retry",
                    "usage": {
                        "input_tokens": 100,
                        "cache_read_input_tokens": 40,
                        "cache_creation_input_tokens": 10,
                        "output_tokens": 20,
                    },
                    "total_cost_usd": 0.01,
                }
            )
        )
        self.assertEqual(claude["total_tokens"], 170)
        self.assertEqual(claude["cached_input_tokens"], 40)
        self.assertEqual(claude["cache_creation_input_tokens"], 10)
        codex = module["parse_codex_result"](
            "\n".join(
                [
                    json.dumps(
                        {
                            "type": "item.completed",
                            "item": {
                                "type": "agent_message",
                                "text": "CG_RESULT command=sample_suite check=sample_test_alpha actual=retry",
                            },
                        }
                    ),
                    json.dumps(
                        {
                            "type": "turn.completed",
                            "usage": {
                                "input_tokens": 100,
                                "cached_input_tokens": 40,
                                "output_tokens": 20,
                            },
                        }
                    ),
                ]
            )
        )
        self.assertEqual(codex["total_tokens"], 120)
        self.assertEqual(codex["cached_input_tokens"], 40)
        self.assertEqual(codex["cache_creation_input_tokens"], 0)
        with self.assertRaisesRegex(Exception, "cache token"):
            module["parse_claude_result"](
                json.dumps(
                    {
                        "result": "x",
                        "usage": {
                            "input_tokens": 1,
                            "output_tokens": 1,
                            "cache_read_input_tokens": None,
                        },
                    }
                )
            )
        for conflicting_usage in (
            {
                "input_tokens": 1,
                "output_tokens": 1,
                "cached_input_tokens": 7,
                "cache_read_input_tokens": 400,
            },
            {
                "input_tokens": 1,
                "output_tokens": 1,
                "cache_creation_input_tokens": 5,
                "cache_creation": {"ephemeral_5m_input_tokens": 300},
            },
            {
                "input_tokens": 1,
                "output_tokens": 1,
                "cache_creation": {"ephemeral_2h_input_tokens": 1000},
            },
            {
                "input_tokens": 1,
                "output_tokens": 1,
                "future_cache_tokens": 1000,
            },
        ):
            with self.subTest(usage=conflicting_usage), self.assertRaisesRegex(
                Exception, "cache token"
            ):
                module["parsed_usage"](
                    EXPECTED_RESPONSE,
                    conflicting_usage,
                    cached_is_input_breakout=False,
                )
        with self.assertRaisesRegex(Exception, "tool event"):
            module["parse_codex_result"](
                "\n".join(
                    [
                        json.dumps(
                            {
                                "type": "item.completed",
                                "item": {"type": "command_execution", "command": "pwd"},
                            }
                        ),
                        json.dumps(
                            {
                                "type": "turn.completed",
                                "usage": {"input_tokens": 1, "output_tokens": 1},
                            }
                        ),
                    ]
                )
            )
        for invalid_events in (
            [
                {
                    "type": "item.completed",
                    "item": {"type": "agent_message", "text": "WRONG"},
                },
                {
                    "type": "item.completed",
                    "item": {"type": "agent_message", "text": EXPECTED_RESPONSE},
                },
                {
                    "type": "turn.completed",
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                },
            ],
            [
                {
                    "type": "item.completed",
                    "item": {"type": "agent_message", "text": EXPECTED_RESPONSE},
                },
                {
                    "type": "turn.completed",
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                },
                {
                    "type": "turn.completed",
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                },
            ],
            [
                {
                    "type": "item.completed",
                    "item": {"type": "file_read"},
                },
                {
                    "type": "item.completed",
                    "item": {"type": "agent_message", "text": EXPECTED_RESPONSE},
                },
                {
                    "type": "turn.completed",
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                },
            ],
            [
                {
                    "type": "item.started",
                    "item": {"type": "command_execution"},
                },
                {
                    "type": "item.completed",
                    "item": {"type": "agent_message", "text": EXPECTED_RESPONSE},
                },
                {
                    "type": "turn.completed",
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                },
            ],
        ):
            with self.subTest(events=invalid_events), self.assertRaisesRegex(
                Exception, "Codex"
            ):
                module["parse_codex_result"](
                    "\n".join(json.dumps(event) for event in invalid_events)
                )

    def test_live_quality_gate_requires_one_exact_result_line(self) -> None:
        module = runpy.run_path(str(LIVE_COLLECTOR), run_name="advisory_quality_test")
        expected = "CG_RESULT command=sample_suite check=sample_test_alpha actual=retry"
        prompt = module["prompt_for"](module["synthetic_log"]())
        self.assertNotIn(expected, prompt)
        self.assertIn("command=<command>", prompt)
        self.assertTrue(module["quality_passed"](expected))
        self.assertTrue(module["quality_passed"](expected + "\n"))
        self.assertFalse(module["quality_passed"](expected + "\nextra"))
        self.assertFalse(
            module["quality_passed"](
                "CG_RESULT command=sample_suite check=sample_test_alpha actual=ok"
            )
        )
        self.assertFalse(module["quality_passed"](expected + "\n" + expected))

    def test_live_vendor_plans_bind_capabilities_and_measured_overhead(self) -> None:
        module = runpy.run_path(str(LIVE_COLLECTOR), run_name="advisory_plan_test")
        raw = module["synthetic_log"]()
        claude = module["advisory_plan"](raw, "claude", 100)
        codex = module["advisory_plan"](raw, "codex", 100)
        self.assertFalse(claude["capabilities"]["hooks_effective"])
        self.assertFalse(codex["capabilities"]["hooks_effective"])
        self.assertEqual(claude["decision"], "trim_output")
        self.assertEqual(codex["decision"], "trim_output")
        blocked = module["advisory_plan"](raw, "codex", 251)
        self.assertEqual(blocked["reason"], "local_overhead_budget_exceeded")

    def test_live_collector_candidate_wires_directory_policy_and_resolves_symlink(
        self,
    ) -> None:
        module = runpy.run_path(str(LIVE_COLLECTOR), run_name="advisory_path_test")
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory) / "homebrew"
            bin_dir = prefix / "bin"
            target = prefix / "lib/node_modules/vendor/bin/codex.js"
            target.parent.mkdir(parents=True)
            bin_dir.mkdir()
            current = prefix
            fixture_directories = [current]
            for part in target.parent.relative_to(prefix).parts:
                current /= part
                fixture_directories.append(current)
            for current in fixture_directories:
                current.chmod(0o755)
            bin_dir.chmod(0o755)
            target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            target.chmod(0o755)
            candidate = bin_dir / "codex"
            candidate.symlink_to(target)

            direct_directory_policy = module["_trusted_directory"]
            candidate_globals = module["trusted_executable_candidate"].__globals__
            self.assertIs(
                candidate_globals["_trusted_ancestor_chain"],
                module["_trusted_ancestor_chain"],
            )
            checked_directories = []

            def isolated_ancestor_policy(path: Path) -> bool:
                checked_directories.append(path.resolve())
                return direct_directory_policy(path)

            with mock.patch.dict(
                candidate_globals,
                {"_trusted_ancestor_chain": isolated_ancestor_policy},
            ):
                bin_dir.chmod(0o775)
                self.assertFalse(direct_directory_policy(bin_dir))
                self.assertTrue(direct_directory_policy(target.parent))
                self.assertIsNone(module["trusted_executable_candidate"](candidate))
                negative_checked_directories = list(checked_directories)
                checked_directories.clear()
                bin_dir.chmod(0o755)
                self.assertTrue(direct_directory_policy(bin_dir))
                self.assertEqual(
                    module["trusted_executable_candidate"](candidate), target.resolve()
                )
            self.assertEqual(negative_checked_directories, [bin_dir.resolve()])
            self.assertEqual(
                set(checked_directories), {bin_dir.resolve(), target.parent.resolve()}
            )

    def test_live_collector_ancestor_chain_rejects_untrusted_intermediate(
        self,
    ) -> None:
        module = runpy.run_path(str(LIVE_COLLECTOR), run_name="advisory_chain_test")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            descendant = root / "trusted" / "blocked" / "candidate"
            descendant.mkdir(parents=True)
            blocked = (root / "trusted" / "blocked").resolve()
            checked_directories = []

            def recording_policy(path: Path) -> bool:
                resolved = path.resolve()
                checked_directories.append(resolved)
                return resolved != blocked

            chain_globals = module["_trusted_ancestor_chain"].__globals__
            self.assertIs(
                chain_globals["_trusted_directory"], module["_trusted_directory"]
            )
            with mock.patch.dict(
                chain_globals, {"_trusted_directory": recording_policy}
            ):
                self.assertFalse(module["_trusted_ancestor_chain"](descendant))
            self.assertEqual(
                checked_directories,
                [descendant.resolve(), blocked],
            )

    def test_live_codex_collection_refuses_before_any_local_or_provider_action(self) -> None:
        module = runpy.run_path(str(LIVE_COLLECTOR), run_name="advisory_codex_gate_test")
        calls = []
        with mock.patch.dict(
            module["main"].__globals__,
            {
                "compress_log": lambda *_args: calls.append("compress"),
                "run_provider": lambda *_args: calls.append("provider"),
            },
        ), self.assertRaisesRegex(Exception, "no-tools"):
            module["main"](
                [
                    "--vendor",
                    "codex",
                    "--repetitions",
                    "2",
                    "--confirm-provider-egress",
                ]
            )
        self.assertEqual(calls, [])

    def test_live_provider_process_uses_minimal_non_redirectable_environment(self) -> None:
        module = runpy.run_path(str(LIVE_COLLECTOR), run_name="advisory_env_test")
        observed = {}

        def fake_run(_command, **kwargs):
            observed.update(kwargs["env"])
            return subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps(
                    {
                        "result": EXPECTED_RESPONSE,
                        "usage": {"input_tokens": 1, "output_tokens": 1},
                        "total_cost_usd": 0.0,
                    }
                ),
                stderr="",
            )

        with mock.patch.dict(
            module["run_provider"].__globals__,
            {
                "trusted_executable": lambda _vendor: Path("/trusted/claude"),
            },
        ), mock.patch.object(module["subprocess"], "run", side_effect=fake_run):
            result = module["run_provider"]("claude", "synthetic", 30)
        self.assertTrue(result["quality_passed"])
        self.assertEqual(set(observed), {"HOME", "LANG", "LC_ALL", "PATH"})
        self.assertTrue(Path(observed["HOME"]).is_absolute())
        for prohibited in (
            "NODE_OPTIONS",
            "NODE_PATH",
            "ANTHROPIC_BASE_URL",
            "OPENAI_BASE_URL",
            "HTTPS_PROXY",
            "SSL_CERT_FILE",
        ):
            self.assertNotIn(prohibited, observed)

    def test_live_compression_is_charged_once_per_advisory_run(self) -> None:
        module = runpy.run_path(str(LIVE_COLLECTOR), run_name="advisory_accounting_test")
        observed_ms = iter((11.0, 29.0))
        calls = []

        def fake_compress(
            _raw_log: str, max_output_bytes: int
        ) -> tuple[str, float]:
            calls.append(max_output_bytes)
            return (
                "command sample_suite\nFAIL sample_test_alpha actual retry\n",
                next(observed_ms),
            )

        def fake_provider(_vendor: str, _prompt: str, _timeout: int) -> dict:
            return {
                "total_tokens": 10,
                "wall_time_seconds": 0.1,
                "cost_usd": None,
                "quality_passed": True,
            }

        output = io.StringIO()
        with mock.patch.dict(
            module["main"].__globals__,
            {
                "compress_log": fake_compress,
                "run_provider": fake_provider,
                "emit_run_record": lambda _row: None,
            },
        ), mock.patch("sys.stdout", output):
            self.assertEqual(
                module["main"](
                    [
                        "--vendor",
                        "claude",
                        "--repetitions",
                        "2",
                        "--confirm-provider-egress",
                    ]
                ),
                0,
            )
        self.assertEqual(calls, [4096, 4096])
        report = json.loads(output.getvalue())["report"]
        advisory_rows = [row for row in report["runs"] if row["arm"] == "advisory"]
        self.assertEqual(
            [row["local_preprocessing_ms"] for row in advisory_rows], [11.0, 29.0]
        )

    def test_live_collection_documentation_matches_counterbalance_contract(self) -> None:
        documentation = ADVISORY_DOC.read_text(encoding="utf-8")
        self.assertIn("--dry-run --vendor all --repetitions 4", documentation)
        self.assertIn("caps repetitions at four", documentation)
        self.assertIn("CLI invocations at sixteen", documentation)
        self.assertIn("transport retries are unobserved", documentation)
        self.assertNotIn("--dry-run --vendor all --repetitions 3", documentation)

    def test_live_collector_refuses_network_without_confirmation(self) -> None:
        self.assertTrue(LIVE_COLLECTOR.exists())
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(LIVE_COLLECTOR),
                "--vendor",
                "claude",
                "--repetitions",
                "1",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("confirm-provider-egress", completed.stderr)

    def test_live_collector_requires_even_counterbalanced_repetitions(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(LIVE_COLLECTOR),
                "--dry-run",
                "--repetitions",
                "3",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("even", completed.stderr)

    def test_live_run_row_is_flushed_as_safe_jsonl_before_later_work(self) -> None:
        module = runpy.run_path(str(LIVE_COLLECTOR), run_name="advisory_emit_test")
        stream = io.StringIO()
        row = {
            "vendor": "codex",
            "arm": "control",
            "repetition": 1,
            "quality_passed": True,
            "total_tokens": 10,
        }
        module["emit_run_record"](row, stream=stream)
        emitted = json.loads(stream.getvalue())
        self.assertEqual(emitted, {"type": "run", "run": row})

    def test_live_sample_evidence_is_canonical_aggregate_and_claim_safe(self) -> None:
        self.assertTrue(LIVE_EVIDENCE.exists())
        raw = LIVE_EVIDENCE.read_bytes()
        evidence = json.loads(raw)
        canonical = json.dumps(
            evidence, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode() + b"\n"
        self.assertEqual(raw, canonical)
        self.assertEqual(evidence["status"], "excluded")
        self.assertEqual(evidence["provider_cli_invocations_performed"], 18)
        self.assertFalse(evidence["provider_transport_calls_observed"])
        self.assertNotIn("provider_calls_performed", evidence)
        self.assertIn("fixed_arm_order", evidence["blocking_reasons"])
        self.assertIn("weak_quality_checker", evidence["blocking_reasons"])
        self.assertFalse(evidence["claim_boundary"]["long_term_savings_claim_allowed"])
        self.assertNotIn("vendors", evidence)

    def test_small_bypass_metric_captures_final_payload_equality(self) -> None:
        module = runpy.run_path(str(BENCHMARK), run_name="advisory_payload_test")
        decision = self.planner()(workload())
        control = b"exact provider request"
        treatment = module["final_provider_payload"](
            decision, control=control, transformed=b"different"
        )
        self.assertEqual(treatment, control)
        self.assertEqual(module["provider_overhead_bytes"](control, treatment), 0)


if __name__ == "__main__":
    unittest.main()
