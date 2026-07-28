#!/usr/bin/env python3
"""Focused regression tests for the ContextGuard Bash hook contract."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import random
import runpy
import shlex
import subprocess
import sys
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast
from unittest import mock

from tests.context_guard_a1_oracles import (
    ASSIGNMENT_SEED,
    ROUTE_SEED,
    assert_oracle_cases,
    assignment_provenance_cases,
    minishell_bound_cases,
    minishell_normative_cases,
    prepare_path_lookup_canary,
    route_cases,
)
from tests.corpus_adversarial_pins import (
    FIX1A_ROUTE_PREDICATE_CASES,
    FIX1B_ROUTE_PREDICATE_CASES,
    FIX2_ROUTE_PREDICATE_CASES,
    FIX5_ADVERSARIAL_PINS,
    FIX5_ALLOWLIST_POSITIVE_PINS,
    FIX5_ENV_WRAPPER_BYPASS_PINS,
    FIX5_GLOB_REJECTION_PINS,
    fix1a_route_predicate_relaxations,
    fix1b_ac1_4_case_count,
    fix1b_ac1b2_case_count,
    fix1b_relaxation_case_count,
    fix1b_route_predicate_relaxations,
    fix2_route_predicate_relaxations,
    fix5_case_count,
)


ROOT = Path(__file__).resolve().parents[1]
REWRITE_SCRIPTS = (
    ROOT / "context-guard-kit" / "rewrite_bash_for_token_budget.py",
    ROOT / "plugins" / "context-guard" / "bin" / "context-guard-rewrite-bash",
)
EXPECTED_MAX_HOOK_ENVELOPE_BYTES = 1_048_576


def run_rewrite_raw(script: Path, raw_payload: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script)],
        cwd=ROOT,
        input=raw_payload,
        text=True,
        capture_output=True,
        check=False,
    )


def run_rewrite(script: Path, payload: object) -> subprocess.CompletedProcess[str]:
    return run_rewrite_raw(script, json.dumps(payload, ensure_ascii=False))


def response_decision(response: dict[str, object]) -> str:
    hook_output = response.get("hookSpecificOutput")
    if not isinstance(hook_output, dict):
        return "noop"
    if hook_output.get("permissionDecision") == "deny":
        return "deny"
    if "updatedInput" in hook_output:
        return "rewrite"
    return "other"


def a1_route_decision(proc: subprocess.CompletedProcess[str]) -> str:
    response = json.loads(proc.stdout)
    decision = response_decision(response)
    if decision != "rewrite":
        return decision
    command = response["hookSpecificOutput"]["updatedInput"]["command"]
    if "sanitize_output.py" in command or "context-guard-sanitize-output" in command:
        return "rewrite_sanitize"
    return "rewrite_trim"


class MiniShellPayloadTests(unittest.TestCase):
    def assert_bounded_deny(self, proc: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertLess(len(proc.stdout), 1024)
        self.assertLess(len(proc.stderr), 1024)
        response = json.loads(proc.stdout)
        hook_output = response["hookSpecificOutput"]
        self.assertEqual(hook_output["hookEventName"], "PreToolUse")
        self.assertEqual(hook_output["permissionDecision"], "deny")
        self.assertNotIn("updatedInput", hook_output)

    def test_updated_input_preserves_complete_tool_input_for_both_entrypoints(self) -> None:
        original_input = {
            "command": "pytest tests -q",
            "description": "테스트 실행 🧪",
            "timeout": 0,
            "run_in_background": False,
            "nullable": None,
            "empty_string": "",
            "empty_list": [],
            "empty_object": {},
            "unknown_nested": {
                "levels": [
                    {"enabled": False, "count": 0, "value": None},
                    ["", [], {}, "λ"],
                ]
            },
        }
        payload = {
            "session_id": "payload-preservation",
            "tool_name": "Bash",
            "tool_input": original_input,
        }

        for script in REWRITE_SCRIPTS:
            with self.subTest(script=script):
                proc = run_rewrite(script, payload)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                response = json.loads(proc.stdout)
                hook_output = response["hookSpecificOutput"]
                self.assertEqual(hook_output["hookEventName"], "PreToolUse")

                updated_input = hook_output["updatedInput"]
                expected_input = copy.deepcopy(original_input)
                expected_input["command"] = updated_input["command"]

                self.assertEqual(updated_input, expected_input)
                self.assertNotEqual(updated_input["command"], original_input["command"])
                self.assertEqual(payload["tool_input"], original_input)

    def test_updated_input_is_recursive_deep_copy_without_aliases(self) -> None:
        original_input = {
            "command": "pytest tests -q",
            "nested": {"items": [{"value": "original"}]},
        }

        for index, script in enumerate(REWRITE_SCRIPTS):
            with self.subTest(script=script):
                namespace = runpy.run_path(str(script), run_name=f"context_guard_rewrite_{index}")
                updated_input = namespace["build_updated_input"](original_input, "wrapped")

                self.assertIsNot(updated_input, original_input)
                self.assertIsNot(updated_input["nested"], original_input["nested"])
                self.assertIsNot(
                    updated_input["nested"]["items"],
                    original_input["nested"]["items"],
                )
                self.assertIsNot(
                    updated_input["nested"]["items"][0],
                    original_input["nested"]["items"][0],
                )
                updated_input["nested"]["items"][0]["value"] = "mutated"
                self.assertEqual(original_input["nested"]["items"][0]["value"], "original")

    def test_documented_aliases_preserve_payload_and_conflicts_deny(self) -> None:
        tool_input = {
            "command": "pytest tests -q",
            "description": "preserve me",
            "run_in_background": False,
        }
        accepted_payloads = (
            {"tool_input": tool_input},
            {"toolInput": tool_input},
            {"tool_input": tool_input, "toolInput": copy.deepcopy(tool_input)},
        )

        for script in REWRITE_SCRIPTS:
            for payload in accepted_payloads:
                with self.subTest(script=script, aliases=tuple(payload)):
                    proc = run_rewrite(script, payload)
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    updated_input = json.loads(proc.stdout)["hookSpecificOutput"]["updatedInput"]
                    expected_input = copy.deepcopy(tool_input)
                    expected_input["command"] = updated_input["command"]
                    self.assertEqual(updated_input, expected_input)

            conflicting_payload = {
                "tool_input": tool_input,
                "toolInput": {**tool_input, "description": "different"},
            }
            with self.subTest(script=script, aliases="conflicting"):
                self.assert_bounded_deny(run_rewrite(script, conflicting_payload))

    def test_malformed_hook_inputs_deny_without_partial_updated_input(self) -> None:
        raw_invalid_payloads = ("{", "null", "false", "0", '"text"', "[]", "{}")
        invalid_tool_inputs = (None, False, 0, "text", [], {})
        invalid_commands = (None, False, 0, "", [], {})

        for script in REWRITE_SCRIPTS:
            for raw_payload in raw_invalid_payloads:
                with self.subTest(script=script, raw_payload=raw_payload):
                    self.assert_bounded_deny(run_rewrite_raw(script, raw_payload))
            for tool_input in invalid_tool_inputs:
                with self.subTest(script=script, tool_input=tool_input):
                    self.assert_bounded_deny(run_rewrite(script, {"tool_input": tool_input}))
            for command in invalid_commands:
                with self.subTest(script=script, command=command):
                    self.assert_bounded_deny(
                        run_rewrite(script, {"tool_input": {"command": command}})
                    )

    def test_duplicate_keys_and_oversized_envelopes_follow_bounded_deny_policy(self) -> None:
        prefix = '{"tool_input":{"command":"echo ok","padding":"'
        suffix = '"}}'
        boundary_padding = (
            EXPECTED_MAX_HOOK_ENVELOPE_BYTES
            - len(prefix.encode("utf-8"))
            - len(suffix.encode("utf-8"))
        )
        boundary_payload = prefix + ("x" * boundary_padding) + suffix
        oversized_payload = prefix + ("x" * (boundary_padding + 1)) + suffix
        self.assertEqual(len(boundary_payload.encode("utf-8")), EXPECTED_MAX_HOOK_ENVELOPE_BYTES)
        self.assertEqual(
            len(oversized_payload.encode("utf-8")),
            EXPECTED_MAX_HOOK_ENVELOPE_BYTES + 1,
        )
        duplicate_payloads = (
            '{"tool_input":{"command":"echo first"},"tool_input":{"command":"echo second"}}',
            '{"tool_input":{"command":"echo first","command":"echo second"}}',
        )

        for index, script in enumerate(REWRITE_SCRIPTS):
            with self.subTest(script=script, case="constant"):
                namespace = runpy.run_path(str(script), run_name=f"context_guard_bound_{index}")
                self.assertEqual(
                    namespace["MAX_HOOK_ENVELOPE_BYTES"],
                    EXPECTED_MAX_HOOK_ENVELOPE_BYTES,
                )
            with self.subTest(script=script, case="boundary"):
                proc = run_rewrite_raw(script, boundary_payload)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(json.loads(proc.stdout), {})
            with self.subTest(script=script, case="oversized"):
                self.assert_bounded_deny(run_rewrite_raw(script, oversized_payload))
            for duplicate_payload in duplicate_payloads:
                with self.subTest(script=script, case="duplicate"):
                    self.assert_bounded_deny(run_rewrite_raw(script, duplicate_payload))

    def test_payload_semantics_match_canonical_and_packaged_entrypoints(self) -> None:
        self.assertEqual(REWRITE_SCRIPTS[0].read_bytes(), REWRITE_SCRIPTS[1].read_bytes())

        payloads = (
            {"tool_input": {"command": "pytest tests -q", "value": 0}},
            {"toolInput": {"command": "rg -n token .", "value": False}},
            {"tool_input": {"command": "echo ok", "value": None}},
            {
                "tool_input": {"command": "echo one"},
                "toolInput": {"command": "echo two"},
            },
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                canonical = run_rewrite(REWRITE_SCRIPTS[0], payload)
                packaged = run_rewrite(REWRITE_SCRIPTS[1], payload)
                canonical_response = json.loads(canonical.stdout)
                packaged_response = json.loads(packaged.stdout)
                for response in (canonical_response, packaged_response):
                    hook_output = response.get("hookSpecificOutput")
                    if isinstance(hook_output, dict) and "updatedInput" in hook_output:
                        hook_output["updatedInput"]["command"] = "<rewritten-command>"
                self.assertEqual(canonical.returncode, packaged.returncode)
                self.assertEqual(canonical_response, packaged_response)
                self.assertEqual(canonical.stderr, packaged.stderr)

    def test_a0_payload_change_does_not_change_existing_route_decisions(self) -> None:
        expected_decisions = {
            "pytest tests -q": "rewrite",
            "rg -n token .": "rewrite",
            "echo hello": "noop",
            "rg token . && touch /tmp/context-guard-a0-canary": "deny",
        }

        for script in REWRITE_SCRIPTS:
            for command, expected_decision in expected_decisions.items():
                with self.subTest(script=script, command=command):
                    proc = run_rewrite(script, {"tool_input": {"command": command}})
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    self.assertEqual(
                        response_decision(json.loads(proc.stdout)),
                        expected_decision,
                    )


class MiniShellBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        import tempfile

        cls._staged_tmp = tempfile.TemporaryDirectory(
            prefix="context-guard-minishell-staged-"
        )
        release_smoke_path = ROOT / "scripts" / "release_smoke.py"
        spec = importlib.util.spec_from_file_location(
            "context_guard_minishell_release_smoke",
            release_smoke_path,
        )
        if spec is None or spec.loader is None:
            raise RuntimeError(f"could not load release smoke: {release_smoke_path}")
        release_smoke = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(release_smoke)
        staged = release_smoke.copy_plugin_package_for_smoke(
            ROOT / "plugins" / "context-guard",
            Path(cls._staged_tmp.name) / "installed-plugin",
        )
        cls.STAGED_REWRITE_SCRIPT = staged / "bin" / "context-guard-rewrite-bash"

    @classmethod
    def tearDownClass(cls) -> None:
        cls._staged_tmp.cleanup()

    @classmethod
    def contract_scripts(cls) -> tuple[Path, Path]:
        return (REWRITE_SCRIPTS[0], cls.STAGED_REWRITE_SCRIPT)

    def load_namespace(self, script: Path, suffix: str) -> dict[str, object]:
        return runpy.run_path(str(script), run_name=f"context_guard_minishell_{suffix}")

    def assert_command_decision(
        self,
        command: str,
        expected: str,
        *,
        script: Path = REWRITE_SCRIPTS[0],
    ) -> subprocess.CompletedProcess[str]:
        proc = run_rewrite(script, {"tool_input": {"command": command}})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(response_decision(json.loads(proc.stdout)), expected)
        return proc

    def assert_bounded_deny(self, proc: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertLess(len(proc.stdout), 1024)
        self.assertLess(len(proc.stderr), 1024)
        response = json.loads(proc.stdout)
        hook_output = response["hookSpecificOutput"]
        self.assertEqual(hook_output["permissionDecision"], "deny")
        self.assertNotIn("updatedInput", hook_output)

    def test_minishell_v1_fully_consumes_and_preserves_safe_argv(self) -> None:
        fixtures = {
            "pytest -q": ("pytest", "-q"),
            "'pytest' \"\" -q": ("pytest", "", "-q"),
            "A=1 pytest": ("A=1", "pytest"),
            "env -i A=1 pytest": ("env", "-i", "A=1", "pytest"),
            "/tmp/bin/pytest": ("/tmp/bin/pytest",),
            "./node_modules/.bin/jest": ("./node_modules/.bin/jest",),
            "rg 'token|password' .": ("rg", "token|password", "."),
            r"printf escaped\ space \"quote\" \\": (
                "printf",
                "escaped space",
                '"quote"',
                "\\",
            ),
            "py\\\ntest -q": ("pytest", "-q"),
        }

        for index, script in enumerate(REWRITE_SCRIPTS):
            namespace = self.load_namespace(script, f"accept_{index}")
            parse_minishell = namespace["parse_minishell"]
            for command, expected_argv in fixtures.items():
                with self.subTest(script=script, command=command):
                    parsed = parse_minishell(command)
                    self.assertIsNone(parsed.denial_reason)
                    self.assertEqual(parsed.argv, expected_argv)
                    self.assertEqual(parsed.consumed, len(command))

    def test_normative_minishell_oracle_on_canonical_and_staged_package(self) -> None:
        for index, script in enumerate(self.contract_scripts()):
            namespace = self.load_namespace(script, f"normative_{index}")
            parse_minishell = cast(
                Callable[[str], Any],
                namespace["parse_minishell"],
            )
            classify_command = cast(
                Callable[[str], Any],
                namespace["classify_command"],
            )
            classify_incoming_wrapper = cast(
                Callable[[Any], Any],
                namespace["classify_incoming_wrapper"],
            )
            with self.subTest(
                entrypoint="canonical" if index == 0 else "staged",
                case_id="route-policy-version",
            ):
                self.assertEqual(
                    namespace.get("MINISHELL_ROUTE_POLICY_VERSION"),
                    "minishell-route-v1",
                )
            for case in minishell_normative_cases():
                command = str(case["command"])
                with self.subTest(
                    entrypoint="canonical" if index == 0 else "staged",
                    case_id=case["case_id"],
                ):
                    parsed = parse_minishell(command)
                    decision = classify_command(command)
                    self.assertEqual(decision.action, case["expected_decision"])
                    if case["expected_decision"] != "deny":
                        self.assertIsNone(parsed.denial_reason)
                        self.assertEqual(parsed.consumed, len(command))
                    if "expected_denial_reason" in case:
                        self.assertEqual(
                            parsed.denial_reason,
                            case["expected_denial_reason"],
                        )
                    # `expected_denial_reason` 은 파서 단계(parsed.denial_reason)를,
                    # `expected_reason_code` 는 분류 단계(decision.reason_code)를 고정한다.
                    # 파싱은 성공하고 분류에서 거부되는 케이스(예: unsafe_env_name_denied)
                    # 는 후자로만 원인을 단언할 수 있다.
                    if "expected_reason_code" in case:
                        self.assertEqual(
                            decision.reason_code,
                            case["expected_reason_code"],
                        )
                    if "expected_argv" in case:
                        self.assertEqual(parsed.argv, case["expected_argv"])
                    if "expected_segments" in case:
                        self.assertEqual(
                            len(parsed.segments),
                            case["expected_segments"],
                        )
                    if "expected_heredoc_delimiter" in case:
                        self.assertEqual(
                            parsed.heredoc_delimiter,
                            case["expected_heredoc_delimiter"],
                        )
                    if "expected_wrapper_code" in case:
                        wrapper = classify_incoming_wrapper(parsed)
                        self.assertIsNotNone(wrapper)
                        self.assertEqual(
                            wrapper[0],
                            case["expected_wrapper_code"],
                        )

    def test_exact_and_plus_one_minishell_bounds_on_canonical_and_staged(self) -> None:
        for index, script in enumerate(self.contract_scripts()):
            namespace = self.load_namespace(script, f"bounds_{index}")
            parse_minishell = cast(
                Callable[[str], Any],
                namespace["parse_minishell"],
            )
            for case in minishell_bound_cases():
                command = str(case["command"])
                with self.subTest(
                    entrypoint="canonical" if index == 0 else "staged",
                    case_id=case["case_id"],
                ):
                    if "expected_command_bytes" in case:
                        self.assertEqual(
                            len(command.encode("utf-8")),
                            case["expected_command_bytes"],
                        )
                    parsed = parse_minishell(command)
                    self.assertEqual(
                        parsed.denial_reason,
                        case["expected_denial_reason"],
                    )
                    if "expected_lexical_items" in case:
                        self.assertEqual(
                            parsed.lexical_items,
                            case["expected_lexical_items"],
                        )
                    if "expected_words_per_segment" in case:
                        self.assertEqual(
                            len(parsed.segments[0]),
                            case["expected_words_per_segment"],
                        )
                    if "expected_segments" in case:
                        self.assertEqual(
                            len(parsed.segments),
                            case["expected_segments"],
                        )
                    if "expected_heredoc_delimiter" in case:
                        self.assertEqual(
                            parsed.heredoc_delimiter,
                            case["expected_heredoc_delimiter"],
                        )

    def test_denied_minishell_execution_canaries_never_run(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory(prefix="context-guard-minishell-canary-") as tmp:
            marker = Path(tmp) / "executed"
            commands = (
                f"env -i /bin/sh -c 'touch {marker}'",
                (
                    "context-guard-trim-output --max-lines 220 -- bash -lc "
                    f"'touch {marker}'"
                ),
                f"sort <<DATA\n$(touch {marker})\nDATA",
                f"printf ok | /bin/bash -lc 'touch {marker}'",
            )
            for script in self.contract_scripts():
                for command in commands:
                    with self.subTest(script=script, command=command):
                        self.assert_bounded_deny(
                            run_rewrite(
                                script,
                                {"tool_input": {"command": command}},
                            )
                        )
                        self.assertFalse(marker.exists())

    def test_minishell_v1_denies_unsupported_or_unconsumed_shell_syntax(self) -> None:
        denied = (
            ";",
            "&",
            "|",
            "&&",
            "||",
            "<",
            ">",
            ">>",
            "<<",
            "(",
            ")",
            "pytest;",
            "pytest>out",
            "pytest\n-q",
            "pytest\r-q",
            "pytest\t-q",
            "pytest 'unterminated",
            'pytest "unterminated',
            "pytest \\",
            "pytest `id`",
            "pytest $(id)",
            "pytest ${HOME}",
            "pytest $HOME",
            "$'rg' token .",
            '$"rg" token .',
            "$'git' diff",
            "find . $'-exec' sh -c 'touch /tmp/context-guard-bypass' ';'",
            "rg $'--pre' 'touch /tmp/context-guard-bypass' token .",
            "$\\\n'rg' token .",
            "$\\\n\"rg\" token .",
            "$\\\n'git' diff",
            "find . $\\\n'-exec' sh -c 'touch /tmp/context-guard-bypass' ';'",
            "rg $\\\n'--pre' 'touch /tmp/context-guard-bypass' token .",
            "pytest *.py",
            "pytest {a,b}",
            "# comment",
        )

        for script in REWRITE_SCRIPTS:
            for command in denied:
                with self.subTest(script=script, command=command):
                    self.assert_command_decision(command, "deny", script=script)

    def test_minishell_v1_distinguishes_active_syntax_from_literals(self) -> None:
        accepted = {
            "pytest\\\n -q": ("pytest", "-q"),
            "pytest '&&'": ("pytest", "&&"),
            r"rg '\$(' .": ("rg", r"\$(", "."),
            r"echo '\n'": ("echo", r"\n"),
            r"echo \;": ("echo", ";"),
        }

        for index, script in enumerate(REWRITE_SCRIPTS):
            namespace = self.load_namespace(script, f"literal_{index}")
            parse_minishell = namespace["parse_minishell"]
            for command, expected_argv in accepted.items():
                with self.subTest(script=script, command=command):
                    parsed = parse_minishell(command)
                    self.assertIsNone(parsed.denial_reason)
                    self.assertEqual(parsed.argv, expected_argv)

    def test_minishell_deny_table_is_immutable(self) -> None:
        for index, script in enumerate(REWRITE_SCRIPTS):
            namespace = self.load_namespace(script, f"deny_table_{index}")
            deny_chars = namespace["MINISHELL_DENIED_ACTIVE_CHARS"]
            deny_words = namespace["MINISHELL_DENIED_COMMAND_WORDS"]
            self.assertIsInstance(deny_chars, frozenset)
            self.assertIsInstance(deny_words, frozenset)
            with self.assertRaises(AttributeError):
                deny_chars.add(";")
            with self.assertRaises(AttributeError):
                deny_words.add("if")

    def test_boundary_denial_happens_before_routing_wrapper_env_or_lookup(self) -> None:
        for index, script in enumerate(REWRITE_SCRIPTS):
            namespace = self.load_namespace(script, f"ordering_{index}")
            classify_command = namespace["classify_command"]
            globals_dict = classify_command.__globals__
            called: list[str] = []

            def forbidden(name: str):
                def fail(*_args: object, **_kwargs: object) -> object:
                    called.append(name)
                    raise AssertionError(f"{name} ran before boundary denial")

                return fail

            replacements = {
                name: forbidden(name)
                for name in (
                    "command_search_diff",
                    "classify_incoming_wrapper",
                    "find_wrapper",
                    "fail_open_source_env",
                    "command_basename",
                )
                if name in globals_dict
            }
            with mock.patch.dict(globals_dict, replacements):
                for command in (
                    "pytest; touch /tmp/context-guard-deny-canary",
                    "PATH=/tmp/evil rg x > out",
                    "env PATH=/tmp/evil rg $(id)",
                ):
                    with self.subTest(script=script, command=command):
                        decision = classify_command(command)
                        self.assertEqual(decision.action, "deny")
            self.assertEqual(called, [])

    def test_incoming_wrappers_deny_while_direct_cli_remains_ordinary(self) -> None:
        direct_cli_commands = (
            "context-guard-trim-output --max-lines 10 -- pytest",
            "context-guard-sanitize-output --max-lines 10 -- git diff",
            "claude-trim-output --max-lines 10 -- pytest",
            "python3 /tmp/trim_command_output.py --help",
        )

        for script in REWRITE_SCRIPTS:
            for command in direct_cli_commands:
                with self.subTest(script=script, command=command):
                    self.assert_command_decision(command, "noop", script=script)

            with self.subTest(script=script, command="incoming-exact-trim"):
                first = self.assert_command_decision("pytest -q", "rewrite", script=script)
                wrapped = json.loads(first.stdout)["hookSpecificOutput"]["updatedInput"]["command"]
                self.assert_command_decision(wrapped, "deny", script=script)

            with self.subTest(script=script, command="incoming-exact-sanitize"):
                first = self.assert_command_decision("rg token .", "rewrite", script=script)
                wrapped = json.loads(first.stdout)["hookSpecificOutput"]["updatedInput"]["command"]
                namespace = self.load_namespace(script, f"cgw1_shape_{script.name}")
                wrapped_argv = namespace["parse_minishell"](wrapped).argv
                self.assertIn("--context-guard-wrapper-v1", wrapped_argv)
                sentinel_index = wrapped_argv.index("--context-guard-wrapper-v1")
                self.assertEqual(
                    wrapped_argv[sentinel_index:sentinel_index + 5],
                    (
                        "--context-guard-wrapper-v1",
                        "command_search_diff",
                        "--",
                        "bash",
                        "-lc",
                    ),
                )
                self.assertEqual(wrapped_argv[-1], "rg token .")
                self.assert_command_decision(wrapped, "deny", script=script)

            with self.subTest(script=script, command="near-v0-direct-cli"):
                first = self.assert_command_decision("pytest -q", "rewrite", script=script)
                wrapped = json.loads(first.stdout)["hookSpecificOutput"]["updatedInput"]["command"]
                self.assert_command_decision(
                    wrapped.replace("--max-lines 220", "--max-lines 221", 1),
                    "noop",
                    script=script,
                )

            with self.subTest(script=script, command="wrapper-name-as-argument"):
                self.assert_command_decision(
                    "docker logs context-guard-sanitize-output",
                    "rewrite",
                    script=script,
                )

    def test_b1_assignment_shaped_tilde_provenance_all_word_positions(self) -> None:
        fixtures = {
            "PATH=~ pytest": ("PATH=~", "pytest"),
            "export PATH=~": ("export", "PATH=~"),
            "~/bin/pytest -q": ("~/bin/pytest", "-q"),
            "pytest PATH=~": ("pytest", "PATH=~"),
            "PATH=~": ("PATH=~",),
            "echo A=x:~:y": ("echo", "A=x:~:y"),
            "echo A=a:b:~/x": ("echo", "A=a:b:~/x"),
        }

        for index, script in enumerate(REWRITE_SCRIPTS):
            namespace = self.load_namespace(script, f"b1_positions_{index}")
            parse_minishell = namespace["parse_minishell"]
            classify_command = namespace["classify_command"]
            for command, expected_argv in fixtures.items():
                with self.subTest(script=script, command=command):
                    parsed = parse_minishell(command)
                    self.assertIsNone(parsed.denial_reason)
                    self.assertEqual(parsed.argv, expected_argv)
                    self.assertTrue(any(word.active_tilde_sites for word in parsed.words))
                    self.assertEqual(classify_command(command).action, "deny")

    def test_b1_exact_name_active_delimiter_and_local_suppression(self) -> None:
        fixtures = {
            'echo A""=~': (("echo", "A=~"), "noop"),
            r"echo A\=~": (("echo", "A=~"), "noop"),
            "echo 1A=~": (("echo", "1A=~"), "noop"),
            "echo A-B=~": (("echo", "A-B=~"), "noop"),
            "echo A.B=~": (("echo", "A.B=~"), "noop"),
            "echo =~": (("echo", "=~"), "noop"),
            "echo A==~": (("echo", "A==~"), "noop"),
            "echo A:=~": (("echo", "A:=~"), "noop"),
            "echo --path=~": (("echo", "--path=~"), "noop"),
            'echo A=""~:~': (("echo", "A=~:~"), "deny"),
            r"echo A=\~:~": (("echo", "A=~:~"), "deny"),
            'echo A=~:"~":~': (("echo", "A=~:~:~"), "deny"),
            "echo A\\\n=~": (("echo", "A=~"), "deny"),
            "echo A=\\\n~": (("echo", "A=~"), "deny"),
            "echo A=x\\\n:~": (("echo", "A=x:~"), "deny"),
            r"echo A=x\:~": (("echo", "A=x:~"), "noop"),
        }

        for index, script in enumerate(REWRITE_SCRIPTS):
            namespace = self.load_namespace(script, f"b1_suppression_{index}")
            parse_minishell = namespace["parse_minishell"]
            classify_command = namespace["classify_command"]
            for command, (expected_argv, expected_decision) in fixtures.items():
                with self.subTest(script=script, command=command):
                    parsed = parse_minishell(command)
                    self.assertIsNone(parsed.denial_reason)
                    self.assertEqual(parsed.argv, expected_argv)
                    self.assertEqual(classify_command(command).action, expected_decision)

    def test_fixed_seed_minishell_and_b1_properties(self) -> None:
        grammar_rng = random.Random(0xC0FFEE)
        b1_rng = random.Random(0xB1A55)
        safe_atoms = ("alpha", "'two words'", r"escaped\ space", '""', "x=y")
        deny_atoms = (";", "&&", "|", ">", "$HOME", "$(id)", "`id`", "*.py")
        namespaces = [
            self.load_namespace(script, f"property_{index}")
            for index, script in enumerate(REWRITE_SCRIPTS)
        ]
        for _ in range(256):
            command = " ".join(grammar_rng.choice(safe_atoms) for _ in range(3))
            parsed = [namespace["parse_minishell"](command) for namespace in namespaces]
            self.assertTrue(all(result.denial_reason is None for result in parsed))
            self.assertEqual(parsed[0].argv, parsed[1].argv)
            self.assertTrue(all(result.consumed == len(command) for result in parsed))

            denied_command = command + grammar_rng.choice(deny_atoms)
            denied = [namespace["parse_minishell"](denied_command) for namespace in namespaces]
            self.assertTrue(all(result.denial_reason is not None for result in denied))

        for _ in range(256):
            prefix = "".join(b1_rng.choice("ABCxyz012_") for _ in range(4))
            valid_name = not prefix[0].isdigit()
            separator = b1_rng.choice(("=", ":"))
            word = f"{prefix}{separator}~"
            command = f"echo {word}"
            parsed = [namespace["parse_minishell"](command) for namespace in namespaces]
            decisions = [namespace["classify_command"](command) for namespace in namespaces]
            self.assertEqual(parsed[0].argv[-1], word)
            self.assertEqual(parsed[0].argv, parsed[1].argv)
            expected_decision = "deny" if valid_name and separator == "=" else "noop"
            self.assertTrue(all(result.action == expected_decision for result in decisions))

    def test_worker3_fixed_seed_route_oracle(self) -> None:
        namespaces = {
            "canonical": self.load_namespace(REWRITE_SCRIPTS[0], "route_oracle_canonical"),
            "packaged": self.load_namespace(REWRITE_SCRIPTS[1], "route_oracle_packaged"),
        }

        def evaluate(case: dict[str, object]) -> str:
            namespace = namespaces[str(case["entrypoint"])]
            return namespace["classify_command"](str(case["command"])).action.replace(
                "trim",
                "rewrite_trim",
            ).replace(
                "sanitize",
                "rewrite_sanitize",
            )

        assert_oracle_cases(
            route_cases(seed=ROUTE_SEED),
            evaluate,
            expected_field="expected_decision",
        )

    def test_worker3_fixed_seed_assignment_provenance_oracle(self) -> None:
        namespaces = {
            "canonical": self.load_namespace(REWRITE_SCRIPTS[0], "assignment_oracle_canonical"),
            "packaged": self.load_namespace(REWRITE_SCRIPTS[1], "assignment_oracle_packaged"),
        }

        def evaluate(case: dict[str, object]) -> str:
            namespace = namespaces[str(case["entrypoint"])]
            return namespace["classify_command"](str(case["command"])).action

        assert_oracle_cases(
            assignment_provenance_cases(seed=ASSIGNMENT_SEED),
            evaluate,
            expected_field="expected_decision",
        )

    def test_cg_probe_path_lookup_canary_denies_before_execution(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            case = prepare_path_lookup_canary(Path(tmp))
            for script in REWRITE_SCRIPTS:
                env = os.environ.copy()
                env.update(case["environment"])
                proc = subprocess.run(
                    [sys.executable, str(script)],
                    cwd=ROOT,
                    input=json.dumps({"tool_input": {"command": case["command"]}}),
                    text=True,
                    capture_output=True,
                    env=env,
                    check=False,
                )
                with self.subTest(
                    case_id=case["case_id"],
                    seed=ASSIGNMENT_SEED,
                    script=script,
                ):
                    self.assert_bounded_deny(proc)
                    self.assertFalse(Path(case["marker_path"]).exists())

    def test_nonfinite_nul_and_deep_payloads_fail_closed_with_bounded_json(self) -> None:
        nonfinite_payloads = (
            '{"tool_input":{"command":"pytest -q","value":NaN}}',
            '{"tool_input":{"command":"pytest -q","value":Infinity}}',
            '{"tool_input":{"command":"pytest -q","value":-Infinity}}',
        )
        nested: object = {"leaf": "value"}
        for _ in range(600):
            nested = {"next": nested}
        deep_payload = {"tool_input": {"command": "pytest -q", "nested": nested}}

        for script in REWRITE_SCRIPTS:
            for raw_payload in nonfinite_payloads:
                with self.subTest(script=script, raw_payload=raw_payload):
                    self.assert_bounded_deny(run_rewrite_raw(script, raw_payload))
            with self.subTest(script=script, case="nul"):
                self.assert_bounded_deny(
                    run_rewrite(script, {"tool_input": {"command": "pytest\u0000-q"}})
                )
            with self.subTest(script=script, case="deep-copy"):
                self.assert_bounded_deny(run_rewrite(script, deep_payload))

    def test_hard_boundary_and_destructive_find_ignore_fail_open(self) -> None:
        commands = (
            "pytest; touch /tmp/context-guard-hard-deny",
            "find . -delete",
            r"find . -exec echo x {} \;",
        )
        for script in REWRITE_SCRIPTS:
            for command in commands:
                env = os.environ.copy()
                env["CONTEXT_GUARD_SANITIZER_FAIL_OPEN"] = "1"
                proc = subprocess.run(
                    [sys.executable, str(script)],
                    cwd=ROOT,
                    input=json.dumps({"tool_input": {"command": command}}),
                    text=True,
                    capture_output=True,
                    env=env,
                    check=False,
                )
                with self.subTest(script=script, command=command):
                    self.assert_bounded_deny(proc)
                    self.assertNotIn("leaving command unchanged", proc.stderr)

    def test_fix5_adversarial_pin_count_matches_ac_5_1(self) -> None:
        """AC-5.1 — 적대적 환경변수 접두사 벡터는 정확히 19개여야 한다."""
        self.assertEqual(fix5_case_count(), 19)

    def test_fix5_adversarial_env_prefix_vectors_deny_on_canonical_and_staged(self) -> None:
        """AC-5.1/AC-5.2 — 19개 벡터가 canonical/staged 양쪽에서 전부 deny 되고,
        이름 검사가 라우팅보다 먼저 실행되므로 19건 모두 신규
        `unsafe_env_name_denied` 를 원인으로 갖는다."""
        for index, script in enumerate(self.contract_scripts()):
            namespace = self.load_namespace(script, f"fix5_adversarial_{index}")
            classify_command = namespace["classify_command"]
            for pin in FIX5_ADVERSARIAL_PINS:
                with self.subTest(
                    entrypoint="canonical" if index == 0 else "staged",
                    case_id=pin["case_id"],
                ):
                    decision = classify_command(pin["command"])
                    self.assertEqual(decision.action, pin["expected_decision"])
                    # 원인 코드는 항상 단언한다 — 생략을 허용하면 `deny` 만 보고 통과해
                    # 원인 오염(파서 우연/assignment_only 대체)을 놓치는 공허한 단언이 된다.
                    self.assertEqual(
                        decision.reason_code, pin["expected_reason_code"]
                    )

    def test_fix5_env_wrapper_forms_cannot_bypass_allowlist(self) -> None:
        """`env -- NAME=val cmd` 와 `env env NAME=val cmd` 는 이름 화이트리스트를
        우회하지 못한다.

        coreutils `env` 는 `--` 뒤에서도 선행 할당을 환경에 적용하고 중첩 호출도
        허용한다. 최초 FIX-5 구현은 `env` 를 한 번만 소비하고 `--` 이후 할당 구간을
        재검사하지 않아 두 형태 모두 noop(허용)으로 통과했다 — 즉 FIX-5 가 막으려던
        ride-along RCE 가 그대로 재현됐다."""
        for index, script in enumerate(self.contract_scripts()):
            namespace = self.load_namespace(script, f"fix5_env_wrapper_{index}")
            classify_command = namespace["classify_command"]
            for pin in FIX5_ENV_WRAPPER_BYPASS_PINS:
                with self.subTest(
                    entrypoint="canonical" if index == 0 else "staged",
                    case_id=pin["case_id"],
                ):
                    decision = classify_command(pin["command"])
                    self.assertEqual(decision.action, pin["expected_decision"])
                    self.assertEqual(
                        decision.reason_code, pin["expected_reason_code"]
                    )

    def test_fix5_env_wrapper_bypass_pins_denied_through_hook_envelope(self) -> None:
        """우회 핀 전체를 실제 훅 엔벌로프로도 검증한다(AC-5.4 확장).

        classify_command 단위 고정만으로는 분류 경로와 rewrite/엔벌로프 경로가 어긋난
        경우를 잡지 못한다. FIX-5 의 본질이 ride-along RCE 차단이므로 거부 벡터는 실제
        훅 출력에서도 deny 여야 하고, 변수 이름과 값 경로가 stdout 으로 새면 안 된다.
        허용 대조군은 라우팅 헤드가 할당 word 나 `--` 가 아니라 실제 명령이어야 한다.
        """
        for script in REWRITE_SCRIPTS:
            for pin in FIX5_ENV_WRAPPER_BYPASS_PINS:
                with self.subTest(script=script.name, case_id=pin["case_id"]):
                    if pin["expected_decision"] == "deny":
                        proc = self.assert_command_decision(
                            pin["command"], "deny", script=script
                        )
                        self.assert_bounded_deny(proc)
                        self.assertNotIn("/tmp/evil", proc.stdout)
                        self.assertNotIn("GIT_EXTERNAL_DIFF", proc.stdout)
                        self.assertNotIn("LD_PRELOAD", proc.stdout)
                    else:
                        proc = self.assert_command_decision(
                            pin["command"], "rewrite", script=script
                        )
                        updated = json.loads(proc.stdout)["hookSpecificOutput"][
                            "updatedInput"
                        ]["command"]
                        # 라우팅 헤드를 할당 word(`LANG=C`)나 `--` 로 잡으면 엉뚱한
                        # word 를 감싸게 되므로 실제 명령이 남아 있어야 한다.
                        self.assertIn("git", updated)

    def test_fix5_assignment_only_segment_reports_unsafe_name_cause(self) -> None:
        """명령어 없는 할당 전용 세그먼트도 이름 자체로 거부된다.

        예전에는 `index >= len(words)` 조기 반환이 이름 검사보다 먼저 실행되어
        `assignment_only_denied` 라는 다른 백스톱에만 의존했다. 그 경우 §5.4/§5.6
        측정이 `unsafe_env_name_denied` 로 필터링할 때 이 시도를 놓친다."""
        for index, script in enumerate(self.contract_scripts()):
            namespace = self.load_namespace(script, f"fix5_assignment_only_{index}")
            classify_command = namespace["classify_command"]
            entrypoint = "canonical" if index == 0 else "staged"
            with self.subTest(entrypoint=entrypoint, case="unsafe name"):
                decision = classify_command("PATH=/tmp/evil")
                self.assertEqual(decision.action, "deny")
                self.assertEqual(decision.reason_code, "unsafe_env_name_denied")
            with self.subTest(entrypoint=entrypoint, case="allowlisted name"):
                # 허용 이름은 기존 원인(assignment_only_denied)을 그대로 유지한다.
                decision = classify_command("LANG=C")
                self.assertEqual(decision.action, "deny")
                self.assertEqual(decision.reason_code, "assignment_only_denied")

    def test_fix5_allowlisted_env_prefix_still_routes_on_canonical_and_staged(self) -> None:
        """AC-5.3 — 시드 화이트리스트 안의 무해 접두사는 계속 허용된다."""
        for index, script in enumerate(self.contract_scripts()):
            namespace = self.load_namespace(script, f"fix5_positive_{index}")
            classify_command = namespace["classify_command"]
            for pin in FIX5_ALLOWLIST_POSITIVE_PINS:
                with self.subTest(
                    entrypoint="canonical" if index == 0 else "staged",
                    case_id=pin["case_id"],
                ):
                    decision = classify_command(pin["command"])
                    self.assertEqual(decision.action, pin["expected_decision"])
                    self.assertIsNone(decision.reason_code)

    def test_fix5_exact_name_match_rejects_glob_style_prefixes(self) -> None:
        """AC-5.6 — TERMINFO/LOCPATH 는 TERM/LANG 접두사 매칭으로 재승인되지 않는다
        (`TERM*` 글롭이었다면 재현되었을 denylist 침몰 실패 형태를 고정한다)."""
        for index, script in enumerate(self.contract_scripts()):
            namespace = self.load_namespace(script, f"fix5_glob_{index}")
            classify_command = namespace["classify_command"]
            for pin in FIX5_GLOB_REJECTION_PINS:
                with self.subTest(
                    entrypoint="canonical" if index == 0 else "staged",
                    case_id=pin["case_id"],
                ):
                    decision = classify_command(pin["command"])
                    self.assertEqual(decision.action, "deny")
                    self.assertEqual(decision.reason_code, "unsafe_env_name_denied")

    def test_fix5_multi_prefix_denies_when_any_name_is_unsafe(self) -> None:
        """다중 접두사 중 하나라도 화이트리스트 밖이면 세그먼트 전체가 거부된다."""
        for index, script in enumerate(self.contract_scripts()):
            namespace = self.load_namespace(script, f"fix5_multi_prefix_{index}")
            classify_command = namespace["classify_command"]
            entrypoint = "canonical" if index == 0 else "staged"
            with self.subTest(entrypoint=entrypoint, case="safe then unsafe"):
                decision = classify_command("TZ=UTC GIT_PAGER=/tmp/evil.sh git diff")
                self.assertEqual(decision.action, "deny")
                self.assertEqual(decision.reason_code, "unsafe_env_name_denied")
            with self.subTest(entrypoint=entrypoint, case="unsafe first"):
                # 단락 평가 순서와 무관하게 거부되어야 한다.
                decision = classify_command("GIT_PAGER=/tmp/evil.sh TZ=UTC git diff")
                self.assertEqual(decision.action, "deny")
                self.assertEqual(decision.reason_code, "unsafe_env_name_denied")
            with self.subTest(entrypoint=entrypoint, case="all safe"):
                decision = classify_command("TZ=UTC LANG=C git diff")
                self.assertNotEqual(decision.action, "deny")

    def test_fix5_env_builtin_form_enforces_same_allowlist(self) -> None:
        """리터럴 `env NAME=val -- cmd` 형태도 동일한 이름 화이트리스트를 적용받는다
        (`_routing_start` 의 두 번째 스캔 구간 — `env` 뒤 할당 목록)."""
        for index, script in enumerate(self.contract_scripts()):
            namespace = self.load_namespace(script, f"fix5_env_builtin_{index}")
            classify_command = namespace["classify_command"]
            with self.subTest(entrypoint="canonical" if index == 0 else "staged"):
                denied = classify_command("env GIT_PAGER=/tmp/evil.sh git diff")
                self.assertEqual(denied.action, "deny")
                self.assertEqual(denied.reason_code, "unsafe_env_name_denied")
                allowed = classify_command("env NODE_ENV=production npm test")
                self.assertEqual(allowed.action, "trim")
                self.assertIsNone(allowed.reason_code)

    def test_fix5_restricted_env_denied_still_covers_its_original_cause(self) -> None:
        """`restricted_env_denied` 는 이름 문제가 아닌 `env` 플래그 형태에서 여전히
        발생해야 한다 — 신규 `unsafe_env_name_denied` 와 원인이 섞이지 않았는지 확인
        (Q10, §5.4/§5.6 측정이 reason_code 로 필터링하므로 오염되면 안 된다)."""
        for index, script in enumerate(self.contract_scripts()):
            namespace = self.load_namespace(
                script, f"fix5_restricted_env_cause_{index}"
            )
            classify_command = namespace["classify_command"]
            with self.subTest(entrypoint="canonical" if index == 0 else "staged"):
                decision = classify_command("env --unknown printf ok")
                self.assertEqual(decision.action, "deny")
                self.assertEqual(decision.reason_code, "restricted_env_denied")

    def test_fix5_hook_envelope_denies_env_prefix_rce_end_to_end(self) -> None:
        """AC-5.4 — 거부된 접두사는 wrapped `bash -lc` 출력으로 도달하지 않는다."""
        for script in REWRITE_SCRIPTS:
            with self.subTest(script=script):
                proc = self.assert_command_decision(
                    "GIT_EXTERNAL_DIFF=/tmp/evil.sh git diff",
                    "deny",
                    script=script,
                )
                self.assertNotIn("GIT_EXTERNAL_DIFF", proc.stdout)

    def test_inv_a_route_predicate_relaxation_preserves_denial_for_anchors(
        self,
    ) -> None:
        """INV-A(거부 보존, plan §5.2) — `FIX1A_ROUTE_PREDICATE_CASES` 중 완화
        대상이 아닌 행(§5.5 역방향 케이스 + reason_code 이동 실증 케이스)은 개조
        전/후 어느 코드에 대해 실행해도 항상 거부되어야 한다. `reason_code` 는
        세그먼트 교차 배치(classify_command:1671-1751)로 이동할 수 있으므로 여기서
        고정하지 않는다 — 이동은 아래 `test_inv_a_reason_code_drift_is_pinned_where_documented`
        가 별도로 실측 고정한다(이 테스트만 code-state 무관하게 유지하기 위함)."""
        for index, script in enumerate(self.contract_scripts()):
            namespace = self.load_namespace(script, f"inv_a_{index}")
            classify_command = namespace["classify_command"]
            for case in FIX1A_ROUTE_PREDICATE_CASES:
                if case["expected_decision"] != "deny":
                    continue
                with self.subTest(
                    entrypoint="canonical" if index == 0 else "staged",
                    case_id=case["case_id"],
                ):
                    decision = classify_command(case["command"])
                    self.assertEqual(decision.action, "deny")

    def test_inv_a_reason_code_drift_is_pinned_where_documented(self) -> None:
        """INV-A 각주 — `baseline_reason_code` 와 다른 `expected_reason_code` 를
        명시한 행(예: `head setup.py | tee out.txt`)은 실제로 그 reason_code 로
        거부되는지 실측 고정한다. 위 test_inv_a 는 이 드리프트를 허용만 하고
        고정하지 않으므로, 여기서 별도로 "허용됨"이 아니라 "정확히 이 원인으로
        이동함"까지 검증한다 — 개조 후 코드에서만 의미 있는 고정이다(개조 전에는
        드리프트가 아직 발생하지 않아 baseline 값 그대로 관측된다)."""
        for index, script in enumerate(self.contract_scripts()):
            namespace = self.load_namespace(script, f"inv_a_drift_{index}")
            classify_command = namespace["classify_command"]
            for case in FIX1A_ROUTE_PREDICATE_CASES:
                expected_reason_code = case.get("expected_reason_code")
                if (
                    case["expected_decision"] != "deny"
                    or expected_reason_code is None
                    or expected_reason_code == case["baseline_reason_code"]
                ):
                    continue
                with self.subTest(
                    entrypoint="canonical" if index == 0 else "staged",
                    case_id=case["case_id"],
                ):
                    decision = classify_command(case["command"])
                    self.assertEqual(decision.action, "deny")
                    if decision.reason_code == case["baseline_reason_code"]:
                        continue  # 개조 전 코드 — 드리프트 아직 미발생, 스킵
                    self.assertEqual(decision.reason_code, expected_reason_code)

    def test_inv_b_deny_to_allow_transition_requires_route_policy_denied_baseline(
        self,
    ) -> None:
        """INV-B(허용 전환의 출처 제한, plan §5.2) — `FIX1A_ROUTE_PREDICATE_CASES`
        중 완화 대상 행은 전부 baseline `route_policy_denied` 여야 한다(구조적
        전제). 개조 전 코드에서는 아직 전환이 관측되지 않으므로(항상 deny) 이
        테스트는 자동으로 통과하고, 개조 후에는 실제 전환이 `expected_decision`/
        `expected_reason_code` 와 정확히 일치하는지도 고정한다 — 두 커밋 단계
        (plan §6.1a 커밋 경계 1/2) 모두에서 초록이어야 하는 이유가 이 구조다."""
        for index, script in enumerate(self.contract_scripts()):
            namespace = self.load_namespace(script, f"inv_b_{index}")
            classify_command = namespace["classify_command"]
            for case in fix1a_route_predicate_relaxations():
                with self.subTest(
                    entrypoint="canonical" if index == 0 else "staged",
                    case_id=case["case_id"],
                ):
                    self.assertEqual(
                        case["baseline_reason_code"],
                        "route_policy_denied",
                        "INV-B 위반 — 완화 대상의 baseline 이 route_policy_denied 가 아니다.",
                    )
                    decision = classify_command(case["command"])
                    if decision.action != "deny":
                        self.assertEqual(decision.action, case["expected_decision"])
                        self.assertEqual(
                            decision.reason_code, case.get("expected_reason_code")
                        )

    def test_inv_c_newly_rewrapped_head_tail_commands_roundtrip(self) -> None:
        """INV-C(재래핑 왕복, plan §5.2) — 이번 완화로 `bash -lc` trim 경로에 새로
        진입하는 명령(head/tail bare, `-n` 없음)을 전수 열거하고, 래핑된 명령을
        되찢어 원본 명령 문자열이 손실 없이 보존되는지 확인한다. `wc` 완화는
        noop(무변형 통과) 경로라 재래핑 대상이 아니므로 제외한다. 개조 전 코드에서는
        해당 명령이 아직 deny 라 스킵되고(§6.1a 커밋 경계 1 에서도 초록), 개조 후
        trim 으로 전환되면 왕복 검증이 실제로 발화한다."""
        newly_rewrapped_candidates = tuple(
            case["command"]
            for case in fix1a_route_predicate_relaxations()
            if case["expected_decision"] in {"trim", "sanitize"}
        )
        for script in self.contract_scripts():
            for command in newly_rewrapped_candidates:
                with self.subTest(script=script, command=command):
                    proc = run_rewrite(script, {"tool_input": {"command": command}})
                    decision = a1_route_decision(proc)
                    if decision == "deny":
                        continue
                    self.assertEqual(decision, "rewrite_trim")
                    response = json.loads(proc.stdout)
                    wrapped = response["hookSpecificOutput"]["updatedInput"]["command"]
                    self.assertEqual(shlex.split(wrapped)[-1], command)

    def test_inv_a_fix1b_git_pair_allowlist_anchors_stay_denied(self) -> None:
        """INV-A(거부 보존, plan §5.2) — `FIX1B_ROUTE_PREDICATE_CASES` 의 거부
        앵커는 개조 전/후 어느 코드에서도 항상 거부되어야 한다. FIX-1a 와 동일하게
        `reason_code` 는 세그먼트 교차 배치(classify_command:1671-1751)로 이동할 수
        있으므로 여기서 고정하지 않는다."""
        for index, script in enumerate(self.contract_scripts()):
            namespace = self.load_namespace(script, f"inv_a_fix1b_{index}")
            classify_command = namespace["classify_command"]
            for case in FIX1B_ROUTE_PREDICATE_CASES:
                if case["expected_decision"] != "deny":
                    continue
                with self.subTest(
                    entrypoint="canonical" if index == 0 else "staged",
                    case_id=case["case_id"],
                ):
                    decision = classify_command(case["command"])
                    self.assertEqual(decision.action, "deny")

    def test_ac1_4_zero_arity_git_writers_stay_denied(self) -> None:
        """AC-1.4 — D2(위치 인자 0개면 허용) 프로토타입이 누수시킨 쓰기 명령을
        고정한다. 서브커맨드 이름이나 arity 만으로는 읽기/쓰기를 가를 수 없다는
        실증이며, `git clean -fd` 와 `git reset --hard` 는 단순 쓰기가 아니라
        **데이터 손실**이므로 이 앵커가 무너지면 즉시 차단 사유다."""
        self.assertEqual(
            fix1b_ac1_4_case_count(),
            14,
            "AC-1.4 는 위치 인자 0개 쓰기 14건 고정을 요구한다.",
        )
        for index, script in enumerate(self.contract_scripts()):
            namespace = self.load_namespace(script, f"ac1_4_{index}")
            classify_command = namespace["classify_command"]
            for case in FIX1B_ROUTE_PREDICATE_CASES:
                if not case["case_id"].startswith("fix1b-ac1-4-"):
                    continue
                with self.subTest(
                    entrypoint="canonical" if index == 0 else "staged",
                    case_id=case["case_id"],
                ):
                    self.assertEqual(classify_command(case["command"]).action, "deny")

    def test_ac1b2_global_option_bypasses_stay_denied(self) -> None:
        """AC-1b.2 — R-5 불변식(`argv[1]` 리터럴)이 지탱하는 우회 9건을 고정한다.
        git 은 `-c`/`-C`/`-p`/`--exec-path` 를 서브커맨드보다 먼저 소비하므로,
        선행 전역 옵션을 건너뛰어 서브커맨드를 찾는 구현으로 바꾸면 표 전체가
        무력화된다. `git -c alias.x='!cmd' x` 는 임의 셸 실행이 확인된 벡터다."""
        self.assertEqual(
            fix1b_ac1b2_case_count(),
            9,
            "AC-1b.2 는 전역 옵션 우회 9건 고정을 요구한다.",
        )
        for index, script in enumerate(self.contract_scripts()):
            namespace = self.load_namespace(script, f"ac1b2_{index}")
            classify_command = namespace["classify_command"]
            for case in FIX1B_ROUTE_PREDICATE_CASES:
                if not case["case_id"].startswith("fix1b-ac1b2-"):
                    continue
                with self.subTest(
                    entrypoint="canonical" if index == 0 else "staged",
                    case_id=case["case_id"],
                ):
                    self.assertEqual(classify_command(case["command"]).action, "deny")

    def test_ac1b1_fix1b_relaxations_are_admitted_unconditionally(self) -> None:
        """AC-1b.1 — 표 신설 행 11건이 **무조건** 기대한 action/reason_code 로
        승인되는지 고정한다.

        FIX-1a 의 INV-B 테스트는 `if decision.action != "deny":` 안에서만 기대값을
        검사한다 — 개조 전/후 두 커밋 단계에서 모두 초록이어야 한다는 구조적
        제약 때문이며 그 자체는 의도된 설계다. 그러나 FIX-1b 는 이미 개조가
        끝난 시점이므로 같은 조건부 형태를 쓸 이유가 없고, 조건부로 두면 구현이
        모든 행을 다시 거부해도 테스트가 통과한다(공허). 여기서는 조건 없이
        단언한다.

        `fix1b_route_predicate_relaxations` 는 구성원을 `expected_decision`
        으로 고르므로 기대값 오염이 곧 집합 이탈이 된다 — 개수 가드로 막는다.
        """
        self.assertEqual(
            fix1b_relaxation_case_count(),
            11,
            "AC-1b.1 은 표 신설 행 11건 고정을 요구한다.",
        )
        for index, script in enumerate(self.contract_scripts()):
            namespace = self.load_namespace(script, f"ac1b1_{index}")
            classify_command = namespace["classify_command"]
            for case in fix1b_route_predicate_relaxations():
                with self.subTest(
                    entrypoint="canonical" if index == 0 else "staged",
                    case_id=case["case_id"],
                ):
                    self.assertEqual(
                        case["baseline_reason_code"],
                        "route_policy_denied",
                        "INV-B 위반 — 완화 대상의 baseline 이 route_policy_denied 가 아니다.",
                    )
                    decision = classify_command(case["command"])
                    self.assertEqual(decision.action, case["expected_decision"])
                    self.assertEqual(
                        decision.reason_code, case.get("expected_reason_code")
                    )

    def test_ac1b3_git_table_subcommands_match_oracle_families(self) -> None:
        """AC-1b.3 — 표의 서브커맨드 집합과 A1 오라클의 `git-*` family 집합이
        일치해야 한다. 개조 전 오라클에는 git family 가 `git-diff` 하나뿐이었고,
        그 때문에 쌍 화이트리스트 프로토타입의 오라클 영향이 0으로 측정됐다 —
        이는 안전이 아니라 **감시의 부재**였다. 이 단언이 있으면 표에 행만 추가하고
        family 를 빠뜨리는 순간 빌드가 깨진다."""
        oracle_families = {
            str(case["family"])[len("git-") :]
            for case in route_cases()
            if str(case["family"]).startswith("git-")
        }
        for index, script in enumerate(self.contract_scripts()):
            namespace = self.load_namespace(script, f"ac1b3_{index}")
            with self.subTest(entrypoint="canonical" if index == 0 else "staged"):
                self.assertEqual(
                    set(namespace["GIT_TABLE_SUBCOMMANDS"]),
                    oracle_families,
                    "표 행과 오라클 family 가 어긋났다 — 행 추가 시 family 도 추가할 것.",
                )

    def test_fix2_cat_route_predicate_cases_match_expected_decision(self) -> None:
        """FIX-2(plan §6.2) — `FIX2_ROUTE_PREDICATE_CASES`의 각 케이스가
        canonical/packaged 두 진입점 모두에서 `expected_decision`/
        `expected_reason_code`와 일치하는지 고정한다. 이 표의 관계는 FIX-1a/1b
        와 달리 deny -> allow 전환이 아니다(라우트 *코드*만 `noop -> trim`으로
        바뀐다) — `_cat_is_safe`의 허용 경계 자체는 이번 변경으로 전혀 바뀌지
        않았으므로 INV-A/INV-B 하네스 대신 이 직접 대조로 §5.5 4번째 열(역방향
        케이스)과 AC-2.1/AC-2.2/AC-2.5를 고정한다."""
        for index, script in enumerate(self.contract_scripts()):
            namespace = self.load_namespace(script, f"fix2_route_{index}")
            classify_command = namespace["classify_command"]
            for case in FIX2_ROUTE_PREDICATE_CASES:
                with self.subTest(
                    entrypoint="canonical" if index == 0 else "staged",
                    case_id=case["case_id"],
                ):
                    decision = classify_command(case["command"])
                    self.assertEqual(decision.action, case["expected_decision"])
                    self.assertEqual(decision.reason_code, case["expected_reason_code"])

    def test_inv_c_fix2_cat_relaxation_commands_roundtrip(self) -> None:
        """INV-C(재래핑 왕복, plan §5.2) — FIX-2로 `bash -lc` trim 경로에 새로
        진입하는 cat standalone 명령(`FIX2_ROUTE_PREDICATE_CASES`의
        `noop -> trim` 전환 대상, `fix2_route_predicate_relaxations()`)을 전수
        열거하고, 래핑된 명령을 되찢어 원본 명령 문자열이 손실 없이 보존되는지
        확인한다. `fix1a`의 동명 테스트(:1035)와 동일한 패턴이다. 파일명 자체의
        적대적 인코딩(공백/따옴표/유니코드)을 실제 `bash -lc` 실행까지 수행하는
        검증은 `test_ac2_3_cat_adversarial_filenames_survive_bash_lc_roundtrip`
        이 별도로 담당한다."""
        newly_rewrapped_candidates = tuple(
            case["command"] for case in fix2_route_predicate_relaxations()
        )
        for script in self.contract_scripts():
            for command in newly_rewrapped_candidates:
                with self.subTest(script=script, command=command):
                    proc = run_rewrite(script, {"tool_input": {"command": command}})
                    self.assertEqual(a1_route_decision(proc), "rewrite_trim")
                    response = json.loads(proc.stdout)
                    wrapped = response["hookSpecificOutput"]["updatedInput"]["command"]
                    self.assertEqual(shlex.split(wrapped)[-1], command)

    def test_ac2_3_cat_adversarial_filenames_survive_bash_lc_roundtrip(self) -> None:
        """AC-2.3(INV-C 대상, plan §6.2) — FIX-2로 `cat`이 처음 `bash -lc`
        재래핑 경로에 진입한다. 파일명은 공백/따옴표/유니코드를 다른 피연산자보다
        훨씬 자주 담는 페이로드이므로, 실제 훅 페이로드를 stdin으로 주입하고
        (`run_rewrite`) 되돌아온 `updatedInput.command`를 실제 `bash -lc`로
        한 번 더 실행해(문자열 비교가 아니라 진짜 실행) 원본 파일명이 손상 없이
        살아남는지 확인한다.

        `shell_quote`(:2172)는 이 프로젝트에서 이미 독립적으로 검증됐다 — 실제
        `bash -lc` 17개 적대 케이스(공백/따옴표/백슬래시/탭/개행/한글/leading
        dash/`$HOME`/백틱/세미콜론/별표/괄호/빈 문자열/파이프/`'''`/혼합)에서
        0/17 실패, `shlex.quote`와 바이트 동일이 확인되었다. 그래서 이 테스트는
        결함을 찾으려는 탐색이 아니라 — `cat`이 그 경로에 새로 들어오는 시점을
        고정하는 **회귀 핀**이다."""
        import tempfile

        adversarial_names = (
            "has space.txt",
            "single'quote.txt",
            'double"quote.txt',
            "back\\slash.txt",
            "한글_파일이름.txt",
            "mixed 'both\" chars 한글.txt",
        )
        for script in self.contract_scripts():
            with tempfile.TemporaryDirectory(prefix="fix2-ac2-3-roundtrip-") as tmp:
                for name in adversarial_names:
                    marker = f"FIX2-AC2-3-MARKER-{abs(hash((script.name, name)))}"
                    (Path(tmp) / name).write_text(marker + "\n", encoding="utf-8")
                    raw_command = f"cat {shlex.quote(name)}"
                    with self.subTest(script=script, filename=name):
                        proc = run_rewrite(script, {"tool_input": {"command": raw_command}})
                        self.assertEqual(proc.returncode, 0, proc.stderr)
                        self.assertEqual(a1_route_decision(proc), "rewrite_trim")
                        response = json.loads(proc.stdout)
                        wrapped = response["hookSpecificOutput"]["updatedInput"]["command"]
                        exec_proc = subprocess.run(
                            ["bash", "-lc", wrapped],
                            cwd=tmp,
                            capture_output=True,
                            text=True,
                        )
                        self.assertEqual(exec_proc.returncode, 0, exec_proc.stderr)
                        self.assertIn(
                            marker,
                            exec_proc.stdout,
                            "재래핑된 명령을 실제 bash -lc 로 실행한 결과에서 "
                            "파일 내용을 찾지 못했다 — 파일명이 왕복 중 손상됐을 수 있다.",
                        )


if __name__ == "__main__":
    unittest.main()
