#!/usr/bin/env python3
"""Focused regression tests for the ContextGuard Bash hook contract."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import random
import runpy
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
    FIX5_ADVERSARIAL_PINS,
    FIX5_ALLOWLIST_POSITIVE_PINS,
    FIX5_ENV_WRAPPER_BYPASS_PINS,
    FIX5_GLOB_REJECTION_PINS,
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


if __name__ == "__main__":
    unittest.main()
