from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = (
    ROOT
    / "research"
    / "provider-live-roadmap"
    / "p2-codex"
    / "v1"
    / "live_runner.py"
)
CONTRACT_PATH = RUNNER_PATH.with_name("contract.json")
RESULT_PATH = RUNNER_PATH.with_name("result.json")
G5_SCHEDULE = ROOT / "research" / "provider-free-roadmap" / "g5" / "v1" / "schedule.json"
G5_SCHEMA = (
    ROOT
    / "research"
    / "provider-free-roadmap"
    / "g5"
    / "v1"
    / "schemas"
    / "authoritative-observation.schema.json"
)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def load_runner():
    spec = importlib.util.spec_from_file_location("p2_codex_subscription_runner", RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("unable to load Codex subscription runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def codex_jsonl(
    answer: str,
    *,
    input_tokens: int = 100,
    cached_input_tokens: int = 40,
    cache_write_input_tokens: int = 10,
    output_tokens: int = 7,
    reasoning_output_tokens: int = 2,
    extra_events: list[dict] | None = None,
) -> bytes:
    events = [
        {"type": "thread.started", "thread_id": "private-thread-id"},
        {"type": "turn.started"},
    ]
    events.extend(extra_events or [])
    events.extend(
        [
            {
                "type": "item.completed",
                "item": {"id": "item-1", "type": "agent_message", "text": answer},
            },
            {
                "type": "turn.completed",
                "usage": {
                    "input_tokens": input_tokens,
                    "cached_input_tokens": cached_input_tokens,
                    "cache_write_input_tokens": cache_write_input_tokens,
                    "output_tokens": output_tokens,
                    "reasoning_output_tokens": reasoning_output_tokens,
                },
            },
        ]
    )
    return b"".join(
        json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        for event in events
    )


def fake_public_inputs(schedule: dict) -> tuple[dict, dict]:
    tasks: dict[str, dict] = {}
    packs: dict[tuple[str, str], dict] = {}
    for block in schedule["blocks"]:
        task_id = block["task_id"]
        tasks.setdefault(
            task_id,
            {
                "prompt": f"Return the answer for {task_id}.",
                "stratum": block["stratum"],
                "task_id": task_id,
            },
        )
        for unit in block["units"]:
            key = (task_id, unit["arm"])
            rendered = f"pack:{task_id}:{unit['arm']}\n".encode("utf-8")
            packs.setdefault(
                key,
                {
                    "cost_microunits": len(rendered) + 256,
                    "manifest_sources": [
                        {
                            "path": "public.txt",
                            "slice": {"bytes": 6, "sha256": sha256(b"public")},
                            "source": {"bytes": 6, "sha256": sha256(b"public")},
                        }
                    ],
                    "packer_receipt_sha256": sha256(rendered + b"receipt"),
                    "rendered_pack": rendered,
                    "retrieval_plan": {"steps": []},
                    "selected_paths": ["public.txt"],
                },
            )
    return tasks, packs


class P2CodexSubscriptionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = load_runner()
        cls.contract_raw = CONTRACT_PATH.read_bytes()
        cls.contract = json.loads(cls.contract_raw)
        cls.schedule_raw = G5_SCHEDULE.read_bytes()
        cls.schedule = json.loads(cls.schedule_raw)
        cls.schema_raw = G5_SCHEMA.read_bytes()

    def test_contract_is_exact_and_rejects_provider_or_usage_semantic_drift(self) -> None:
        self.runner.validate_contract(self.contract, repo_root=ROOT)
        self.assertEqual(
            self.contract["provider"],
            {
                "auth_method": "chatgpt",
                "id": "openai-codex-subscription",
                "model_id": "gpt-5.6-luna",
                "reasoning_effort": "low",
            },
        )
        self.assertEqual(self.contract["limits"]["call_cap"], 240)
        self.assertEqual(
            self.contract["usage_semantics"],
            {
                "cached_input_is_subset_of_input": True,
                "cache_write_input_is_subset_of_input": True,
                "provider_total_formula": "input_tokens + output_tokens",
                "reasoning_output_is_subset_of_output": True,
                "subscription_quota_conversion": "unavailable",
            },
        )
        for path, value in (
            (("provider", "model_id"), "gpt-5.6-sol"),
            (("usage_semantics", "provider_total_formula"), "input+cached+output"),
            (("limits", "call_cap"), 241),
        ):
            with self.subTest(path=path):
                changed = copy.deepcopy(self.contract)
                changed[path[0]][path[1]] = value
                with self.assertRaises(self.runner.CodexLiveError):
                    self.runner.validate_contract(changed, repo_root=ROOT)

    def test_jsonl_parser_counts_subsets_once_and_discards_private_identifiers(self) -> None:
        parsed = self.runner.parse_codex_jsonl(codex_jsonl("ANSWER"))
        self.assertEqual(parsed["answer"], "ANSWER")
        self.assertEqual(
            parsed["usage"],
            {
                "cache_write_input_tokens": 10,
                "cached_input_tokens": 40,
                "input_tokens": 100,
                "output_tokens": 7,
                "provider_total_tokens": 107,
                "reasoning_output_tokens": 2,
                "uncached_nonwrite_input_tokens": 50,
            },
        )
        self.assertNotIn("thread", json.dumps(parsed).lower())

    def test_jsonl_parser_fails_closed_on_tools_malformed_usage_and_content_echo(self) -> None:
        cases = [
            codex_jsonl(
                "ANSWER",
                extra_events=[
                    {
                        "type": "item.completed",
                        "item": {
                            "id": "tool-1",
                            "type": "command_execution",
                            "command": "PRIVATE_MARKER",
                            "status": "completed",
                        },
                    }
                ],
            ),
            codex_jsonl("ANSWER", cached_input_tokens=95, cache_write_input_tokens=10),
            codex_jsonl("ANSWER", output_tokens=1, reasoning_output_tokens=2),
            codex_jsonl("ANSWER")
            + json.dumps(
                {
                    "type": "turn.completed",
                    "usage": {
                        "input_tokens": 1,
                        "cached_input_tokens": 0,
                        "cache_write_input_tokens": 0,
                        "output_tokens": 1,
                        "reasoning_output_tokens": 0,
                    },
                }
            ).encode("utf-8")
            + b"\n",
        ]
        for raw in cases:
            with self.subTest(size=len(raw)):
                with self.assertRaises(self.runner.CodexLiveError) as caught:
                    self.runner.parse_codex_jsonl(raw)
                self.assertNotIn("PRIVATE_MARKER", str(caught.exception))

    def test_argv_uses_stdin_and_disables_mutable_configuration_and_tools(self) -> None:
        executable = Path("/trusted/codex")
        argv = self.runner.codex_argv(executable, contract=self.contract, cwd=Path("/private/run"))
        rendered = json.dumps(argv)
        expected_disabled_features = [
            "apps",
            "auth_elicitation",
            "browser_use",
            "browser_use_external",
            "browser_use_full_cdp_access",
            "code_mode_host",
            "computer_use",
            "goals",
            "guardian_approval",
            "hooks",
            "image_generation",
            "in_app_browser",
            "multi_agent",
            "plugin_sharing",
            "plugins",
            "remote_plugin",
            "shell_snapshot",
            "shell_tool",
            "skill_mcp_dependency_install",
            "skill_search",
            "tool_call_mcp_elicitation",
            "tool_suggest",
            "unified_exec",
            "workspace_dependencies",
        ]
        self.assertEqual(
            self.contract["runtime"]["disabled_features"],
            expected_disabled_features,
        )
        self.assertEqual(argv[0], str(executable))
        self.assertEqual(argv[-1], "-")
        self.assertIn("--ephemeral", argv)
        self.assertIn("--ignore-user-config", argv)
        self.assertIn("--ignore-rules", argv)
        self.assertIn("--strict-config", argv)
        self.assertIn("read-only", argv)
        self.assertIn("gpt-5.6-luna", argv)
        self.assertIn('approval_policy="never"', argv)
        self.assertIn("shell_environment_policy.inherit=none", argv)
        self.assertIn('web_search="disabled"', argv)
        disabled_from_argv = [
            argv[index + 1]
            for index, value in enumerate(argv[:-1])
            if value == "--disable"
        ]
        self.assertEqual(disabled_from_argv, expected_disabled_features)
        self.assertNotIn("Authenticated read-only context pack", rendered)

    def test_environment_excludes_api_keys_and_mutable_codex_configuration(self) -> None:
        original = dict(os.environ)
        try:
            os.environ.update(
                {
                    "HOME": "/private/operator-home",
                    "OPENAI_API_KEY": "PRIVATE_MARKER",
                    "CODEX_API_KEY": "PRIVATE_MARKER",
                    "CODEX_HOME": "/private/untrusted-codex-home",
                    "PYTHONPATH": "/private/untrusted-python",
                }
            )
            environment = self.runner.build_codex_environment(
                Path("/private/run/tmp"),
                home=Path("/private/run/home"),
                codex_home=Path("/private/run/codex-home"),
            )
        finally:
            os.environ.clear()
            os.environ.update(original)
        self.assertEqual(
            set(environment), {"CODEX_HOME", "HOME", "LANG", "PATH", "TMPDIR"}
        )
        self.assertEqual(environment["HOME"], "/private/run/home")
        self.assertEqual(environment["CODEX_HOME"], "/private/run/codex-home")
        self.assertNotIn("PRIVATE_MARKER", json.dumps(environment))

    def test_isolated_codex_home_links_auth_only_after_preparation_and_removes_link(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            os.chmod(root, 0o700)
            source_home = root / "source-codex-home"
            source_home.mkdir(mode=0o700)
            source_auth = source_home / "auth.json"
            source_auth.write_bytes(b"PRIVATE_MARKER")
            source_auth.chmod(0o600)
            isolated_home = root / "home"
            isolated_codex_home = root / "isolated-codex-home"
            isolated_home.mkdir(mode=0o700)
            isolated_codex_home.mkdir(mode=0o700)

            auth_link = self.runner.prepare_isolated_codex_home(
                source_auth=source_auth,
                home=isolated_home,
                codex_home=isolated_codex_home,
            )
            self.assertTrue(auth_link.is_symlink())
            self.assertEqual(os.readlink(auth_link), str(source_auth))
            self.assertEqual(isolated_home.stat().st_mode & 0o777, 0o700)
            self.assertEqual(isolated_codex_home.stat().st_mode & 0o777, 0o700)

            self.runner.remove_isolated_auth_link(auth_link)
            self.assertFalse(auth_link.exists())
            self.assertFalse(auth_link.is_symlink())
            self.assertEqual(source_auth.read_bytes(), b"PRIVATE_MARKER")

    def test_chatgpt_login_status_rejects_api_key_auth_without_echo(self) -> None:
        self.runner.validate_login_status(
            returncode=0,
            stdout=b"",
            stderr=b"Logged in using ChatGPT\n",
        )
        with self.assertRaises(self.runner.CodexLiveError) as caught:
            self.runner.validate_login_status(
                returncode=0,
                stdout=b"",
                stderr=b"Logged in using an API key PRIVATE_MARKER\n",
            )
        self.assertNotIn("PRIVATE_MARKER", str(caught.exception))

    def test_runtime_execution_uses_a_private_captured_copy_not_mutable_source_path(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            os.chmod(root, 0o700)
            source = root / "source-codex"
            source.write_bytes(b"pinned-native-bytes")
            source.chmod(0o500)
            contract = copy.deepcopy(self.contract)
            contract["runtime"]["native_executable_sha256"] = sha256(source.read_bytes())
            captured = self.runner.capture_runtime_copy(
                source,
                contract=contract,
                runtime_root=root / "captured",
            )
            source.chmod(0o700)
            source.write_bytes(b"replacement-private-marker")
            self.assertEqual(captured.read_bytes(), b"pinned-native-bytes")
            self.assertEqual(captured.stat().st_mode & 0o777, 0o500)
            self.assertEqual(captured.stat().st_nlink, 1)

    def test_explicit_javascript_launcher_resolves_to_the_pinned_native_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            package = root / "codex"
            launcher = package / "bin" / "codex.js"
            native = (
                package
                / "node_modules/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/bin/codex"
            )
            launcher.parent.mkdir(parents=True)
            native.parent.mkdir(parents=True)
            launcher.write_bytes(b"javascript-launcher")
            native.write_bytes(b"pinned-native")
            contract = copy.deepcopy(self.contract)
            contract["runtime"]["native_executable_sha256"] = sha256(native.read_bytes())
            original_run = self.runner.subprocess.run
            self.runner.subprocess.run = lambda *_args, **_kwargs: self.runner.types.SimpleNamespace(
                returncode=0,
                stdout=b"codex-cli 0.146.0\n",
                stderr=b"",
            )
            try:
                resolved, digest = self.runner.resolve_codex_runtime(
                    contract,
                    environment={"HOME": "/private/home"},
                    executable=launcher,
                )
            finally:
                self.runner.subprocess.run = original_run
            self.assertEqual(resolved, native.resolve())
            self.assertEqual(digest, sha256(native.read_bytes()))

    def test_all_240_calls_seal_before_scorer_and_preserve_token_breakdowns(self) -> None:
        tasks, packs = fake_public_inputs(self.schedule)
        calls: list[str] = []
        scorer_loaded_at: list[int] = []

        def invoke(item: dict) -> bytes:
            calls.append(item["scheduled_unit_id"])
            return codex_jsonl(f"answer-{item['task_id']}")

        def scorer() -> dict[str, str]:
            scorer_loaded_at.append(len(calls))
            return {task_id: f"answer-{task_id}" for task_id in tasks}

        with tempfile.TemporaryDirectory() as name:
            output_root = Path(name)
            os.chmod(output_root, 0o700)
            execution = self.runner.execute_schedule(
                contract=self.contract,
                schedule=self.schedule,
                observation_schema_bytes=self.schema_raw,
                tasks=tasks,
                packs=packs,
                output_root=output_root,
                invoke=invoke,
                scorer_loader=scorer,
                repo_root=ROOT,
            )
        self.assertEqual(len(calls), 240)
        self.assertEqual(scorer_loaded_at, [240])
        self.assertEqual(len(execution["sealed_runs"]), 240)
        self.assertTrue(
            all(row["correctness"]["outcome"] == "correct" for row in execution["observations"])
        )
        self.assertEqual(
            execution["token_usage"],
            {
                "cache_write_input_tokens": 2400,
                "cached_input_tokens": 9600,
                "completed_calls": 240,
                "input_tokens": 24000,
                "output_tokens": 1680,
                "provider_total_tokens": 25680,
                "reasoning_output_tokens": 480,
                "uncached_nonwrite_input_tokens": 12000,
            },
        )
        self.assertNotIn("answer-", json.dumps(execution["sealed_runs"]))

    def test_tool_event_is_a_schema_valid_exclusion_and_does_not_open_scorer_early(self) -> None:
        tasks, packs = fake_public_inputs(self.schedule)
        calls = 0
        scorer_loaded_at: list[int] = []

        def invoke(item: dict) -> bytes:
            nonlocal calls
            calls += 1
            if calls == 1:
                return codex_jsonl(
                    f"answer-{item['task_id']}",
                    extra_events=[
                        {
                            "type": "item.completed",
                            "item": {
                                "id": "tool-1",
                                "type": "command_execution",
                                "command": "ignored",
                                "status": "completed",
                            },
                        }
                    ],
                )
            return codex_jsonl(f"answer-{item['task_id']}")

        with tempfile.TemporaryDirectory() as name:
            output_root = Path(name)
            os.chmod(output_root, 0o700)
            execution = self.runner.execute_schedule(
                contract=self.contract,
                schedule=self.schedule,
                observation_schema_bytes=self.schema_raw,
                tasks=tasks,
                packs=packs,
                output_root=output_root,
                invoke=invoke,
                scorer_loader=lambda: scorer_loaded_at.append(calls)
                or {task_id: f"answer-{task_id}" for task_id in tasks},
                repo_root=ROOT,
            )
        self.assertEqual(scorer_loaded_at, [240])
        self.assertEqual(execution["observations"][0]["unit_status"], "excluded")
        self.assertEqual(
            execution["observations"][0]["exclusion_reason"],
            "malformed_required_field",
        )
        self.assertEqual(execution["token_usage"]["completed_calls"], 239)

    def test_approval_scope_binds_call_plan_without_prompt_or_cost_claim(self) -> None:
        base = self.runner.load_base(self.contract, repo_root=ROOT)
        tasks, packs = fake_public_inputs(self.schedule)
        plan = base.build_request_plan(
            contract=self.contract,
            schedule=self.schedule,
            tasks=tasks,
            packs=packs,
        )
        scope = self.runner.build_approval_scope(
            contract=self.contract,
            base=base,
            executable=Path("/trusted/codex"),
            executable_sha256="a" * 64,
            environment={"HOME": "/private/home", "LANG": "C", "PATH": "/usr/bin:/bin", "TMPDIR": "/private/tmp"},
            output_root=Path("/private/output"),
            workspace=Path("/private/workspace"),
            plan=plan,
        )
        serialized = json.dumps(scope).lower()
        self.assertEqual(scope["limits"]["call_cap"], 240)
        self.assertEqual(scope["limits"]["spend_cap"], "0.01")
        self.assertNotIn("prompt", serialized)
        self.assertNotIn("api_key", serialized)
        self.assertNotIn("subscription_quota", serialized)

    def test_external_approval_factory_receives_the_exact_prepared_scope_once(self) -> None:
        scope = {"operation": {"surface_id": "prepared-scope"}}
        received: list[dict] = []
        approval = {"schema_version": "contextguard.external-approval/v1"}

        def approve(prepared_scope: dict) -> dict:
            received.append(prepared_scope)
            prepared_scope["operation"]["surface_id"] = "mutated-copy"
            return approval

        resolved = self.runner.resolve_external_approval(approve, scope)
        self.assertIs(resolved, approval)
        self.assertEqual(len(received), 1)
        self.assertEqual(scope["operation"]["surface_id"], "prepared-scope")

    def test_direct_mutable_execution_refuses_before_provider_access(self) -> None:
        reached = False

        def forbidden(*_args, **_kwargs):
            nonlocal reached
            reached = True
            raise AssertionError("provider reached")

        original = self.runner.subprocess.Popen
        self.runner.subprocess.Popen = forbidden
        try:
            self.assertEqual(self.runner.main([]), 2)
        finally:
            self.runner.subprocess.Popen = original
        self.assertFalse(reached)

    def test_completed_result_binds_private_evidence_without_content_or_cost_claims(self) -> None:
        result = json.loads(RESULT_PATH.read_bytes())
        self.assertEqual(
            set(result),
            {
                "analysis",
                "call_accounting",
                "claims",
                "private_evidence",
                "provider",
                "schema_version",
                "source",
                "status",
                "token_usage",
            },
        )
        self.assertEqual(
            result["schema_version"],
            "contextguard.p2-codex-subscription-live-result/v1",
        )
        self.assertEqual(result["status"], "completed_descriptive_subscription_measurement")
        self.assertEqual(
            result["call_accounting"],
            {
                "analyzed_blocks": 50,
                "analyzed_units": 200,
                "completed_calls": 226,
                "excluded_blocks": 10,
                "excluded_calls": 14,
                "scheduled_calls": 240,
            },
        )
        self.assertEqual(result["analysis"]["closed_pack"]["combined"]["correct"], 29)
        self.assertEqual(
            result["analysis"]["closed_pack"]["combined_vs_ordinary_total_tokens"],
            {"denominator": 208384, "numerator": -5741},
        )
        self.assertEqual(
            result["analysis"]["realistic_fallback"]["combined_vs_ordinary_total_tokens"],
            {"denominator": 401695, "numerator": -223363},
        )
        self.assertEqual(result["claims"]["token_savings"], False)
        self.assertEqual(result["claims"]["provider_cost_savings"], False)
        self.assertEqual(
            result["source"]["executed_runner_sha256"],
            "6d5de52529294893d763f41f057cdf9365cd40724cd24921dcbe094a6e75d2d1",
        )
        self.assertEqual(result["private_evidence"]["sha256"], "795d587e760da893b2d61e9a01e73d653f908bf47911de979cf9e55ec0008da8")
        serialized = json.dumps(result, sort_keys=True).lower()
        for forbidden in ("prompt", "answer", "thread_id", "auth.json", "/tmp/"):
            self.assertNotIn(forbidden, serialized)


if __name__ == "__main__":
    unittest.main()
