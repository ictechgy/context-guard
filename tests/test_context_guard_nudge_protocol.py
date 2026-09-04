#!/usr/bin/env python3
"""Dedicated Gate-B1 tests for the ContextGuard failure episode protocol."""

from __future__ import annotations

import errno
import hashlib
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
NUDGE_SCRIPTS = (
    ROOT / "context-guard-kit" / "failed_attempt_nudge.py",
    ROOT / "plugins" / "context-guard" / "bin" / "context-guard-failed-nudge",
)
REWRITE_SCRIPTS = (
    ROOT / "context-guard-kit" / "rewrite_bash_for_token_budget.py",
    ROOT / "plugins" / "context-guard" / "bin" / "context-guard-rewrite-bash",
)


def load_script(path: Path, name: str):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    if spec is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


def payload(
    command: str,
    tool_use_id: str,
    *,
    event: str = "PostToolUse",
    exit_code: int = 1,
    session: str = "session-A",
) -> dict:
    value = {
        "session_id": session,
        "hook_event_name": event,
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_use_id": tool_use_id,
    }
    if event == "PostToolUse":
        value["tool_response"] = {
            "exit_code": exit_code,
            "interrupted": False,
        }
    else:
        value["error"] = "Command exited with non-zero status code 1"
        value["is_interrupt"] = False
    return value


class NudgeProtocolTests(unittest.TestCase):
    maxDiff = None

    def modules(self):
        for index, script in enumerate(NUDGE_SCRIPTS):
            yield script, load_script(script, f"_nudge_protocol_{index}_{id(self)}")

    def wrapped(self, module, kind: str, logical: str, *, legacy: bool = False) -> str:
        prefix = module._wrapper_prefixes()[kind]
        if legacy:
            argv = [
                *prefix,
                "--max-lines",
                "220",
                "--",
                "bash",
                "-c",
                logical,
            ]
        else:
            self.assertEqual(kind, "sanitize")
            argv = [
                *prefix,
                "--context-guard-wrapper-v1",
                "command_search_diff",
                "--",
                "bash",
                "-c",
                logical,
            ]
        return shlex.join(argv)

    def test_canonical_and_plugin_are_exact_mirrors(self):
        canonical, plugin = NUDGE_SCRIPTS
        self.assertEqual(canonical.read_bytes(), plugin.read_bytes())
        self.assertEqual(
            hashlib.sha256(canonical.read_bytes()).hexdigest(),
            hashlib.sha256(plugin.read_bytes()).hexdigest(),
        )

    def test_structural_identity_unwraps_only_exact_cgw1_and_v0(self):
        logical = "pytest tests/a.py -k token=super-secret"
        for script, module in self.modules():
            with self.subTest(script=script):
                expected = hashlib.sha256(logical.encode()).hexdigest()
                current = module.command_identity(
                    self.wrapped(module, "sanitize", logical)
                )
                self.assertEqual((current.protocol, current.digest), ("cgw1", expected))
                for kind in ("sanitize", "trim"):
                    legacy = module.command_identity(
                        self.wrapped(module, kind, logical, legacy=True)
                    )
                    self.assertEqual(
                        (legacy.protocol, legacy.digest),
                        ("legacy-v0", expected),
                    )

                malformed = [
                    self.wrapped(module, "sanitize", logical) + " extra",
                    self.wrapped(module, "sanitize", logical).replace(
                        "command_search_diff", "wrong_route", 1
                    ),
                    shlex.join([
                        "/tmp/context-guard-sanitize-output",
                        "--context-guard-wrapper-v1",
                        "command_search_diff",
                        "--",
                        "bash",
                        "-c",
                        logical,
                    ]),
                    self.wrapped(
                        module,
                        "sanitize",
                        self.wrapped(module, "sanitize", logical),
                    ),
                    "printf %s --context-guard-wrapper-v1",
                ]
                for command in malformed:
                    with self.subTest(command=command):
                        identity = module.command_identity(command)
                        self.assertEqual(identity.protocol, "legacy-or-foreign")
                        self.assertEqual(
                            identity.digest,
                            hashlib.sha256(command.encode()).hexdigest(),
                        )
                direct = module.command_identity("npm --prefix app build")
                self.assertEqual(direct.protocol, "direct")
                self.assertEqual(len(direct.digest), 64)

    def test_full_sha_scopes_commands_protocols_and_sessions(self):
        commands = (
            "pytest tests/a.py",
            "npm test",
            "npm --prefix app test",
            "npm --prefix app build",
        )
        for index, (script, module) in enumerate(self.modules()):
            with self.subTest(script=script):
                identities = []
                for command in commands:
                    rewrite_payload = {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "Bash",
                        "tool_input": {"command": command},
                    }
                    proc = subprocess.run(
                        [sys.executable, str(REWRITE_SCRIPTS[index])],
                        input=json.dumps(rewrite_payload),
                        text=True,
                        capture_output=True,
                        timeout=10,
                    )
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    rewritten = json.loads(proc.stdout)[
                        "hookSpecificOutput"
                    ]["updatedInput"]["command"]
                    identity = module.command_identity(rewritten)
                    self.assertEqual(identity.protocol, "legacy-v0")
                    self.assertEqual(
                        identity.digest,
                        hashlib.sha256(command.encode()).hexdigest(),
                    )
                    identities.append(identity)
                self.assertEqual(len({item.digest for item in identities}), 4)
                self.assertTrue(all(len(item.digest) == 64 for item in identities))
                event_a, reason_a = module.classify_terminal_event(
                    payload(commands[0], "tool-1", session="session-A")
                )
                event_b, reason_b = module.classify_terminal_event(
                    payload(commands[0], "tool-2", session="session-B")
                )
                self.assertIsNone(reason_a)
                self.assertIsNone(reason_b)
                self.assertNotEqual(event_a.episode_key, event_b.episode_key)
                self.assertEqual(len(event_a.session_digest), 64)
                self.assertEqual(len(event_a.tool_id_digest), 64)

    def test_fsm_emits_once_and_success_resets_same_key(self):
        for script, module in self.modules():
            with self.subTest(script=script):
                state = module.empty_state()
                state, first = module.apply_payload(
                    state, payload("pytest tests/a.py", "tool-1"), now=10
                )
                self.assertEqual(first, {})
                self.assertEqual(
                    (state["episodes"][0]["state"], state["episodes"][0]["count"]),
                    ("tracking", 1),
                )

                state, second = module.apply_payload(
                    state,
                    payload(
                        "pytest tests/a.py",
                        "tool-2",
                        event="PostToolUseFailure",
                    ),
                    now=11,
                )
                self.assertEqual(
                    second["hookSpecificOutput"]["hookEventName"],
                    "PostToolUseFailure",
                )
                self.assertLessEqual(
                    len(second["hookSpecificOutput"]["additionalContext"]),
                    800,
                )
                self.assertEqual(
                    (state["episodes"][0]["state"], state["episodes"][0]["count"]),
                    ("emitted", 2),
                )

                state, third = module.apply_payload(
                    state, payload("pytest tests/a.py", "tool-3"), now=12
                )
                self.assertEqual(third, {})
                self.assertEqual(state["episodes"][0]["count"], 3)

                state, success = module.apply_payload(
                    state,
                    payload(
                        "pytest tests/a.py",
                        "tool-4",
                        exit_code=0,
                    ),
                    now=13,
                )
                self.assertEqual(success, {})
                self.assertEqual(state["episodes"], [])
                state, restarted = module.apply_payload(
                    state, payload("pytest tests/a.py", "tool-5"), now=14
                )
                self.assertEqual(restarted, {})
                self.assertEqual(state["episodes"][0]["state"], "tracking")

    def test_tool_id_first_terminal_event_dedupes_and_conflicts(self):
        for script, module in self.modules():
            with self.subTest(script=script):
                state = module.empty_state()
                first = payload("pytest tests/a.py", "shared-tool")
                state, _ = module.apply_payload(state, first, now=1)
                state, output = module.apply_payload(state, first, now=2)
                self.assertEqual(output, {})
                self.assertEqual(state["counters"]["dedupe"], 1)
                self.assertEqual(state["episodes"][0]["count"], 1)

                state, output = module.apply_payload(
                    state,
                    payload(
                        "pytest tests/a.py",
                        "shared-tool",
                        event="PostToolUseFailure",
                    ),
                    now=3,
                )
                self.assertEqual(output, {})
                self.assertEqual(state["counters"]["dedupe"], 2)
                self.assertEqual(state["episodes"][0]["count"], 1)

                state, output = module.apply_payload(
                    state,
                    payload("npm test", "shared-tool"),
                    now=4,
                )
                self.assertEqual(output, {})
                self.assertEqual(state["counters"]["conflict"], 1)
                self.assertEqual(len(state["events"]), 1)

    def test_invalid_terminal_shapes_only_increment_reason_counters(self):
        for script, module in self.modules():
            with self.subTest(script=script):
                cases = [
                    (
                        {
                            **payload("pytest tests/a.py", "tool-missing"),
                            "tool_use_id": "",
                        },
                        "missing_tool_id",
                    ),
                    (
                        {
                            **payload("pytest tests/a.py", "tool-exit"),
                            "tool_response": {"exitCode": 1},
                        },
                        "ambiguous_exit",
                    ),
                    (
                        {
                            **payload("pytest tests/a.py", "tool-two-exits"),
                            "tool_response": {
                                "exit_code": 1,
                                "exitCode": 1,
                            },
                        },
                        "ambiguous_exit",
                    ),
                    (
                        {
                            **payload("pytest tests/a.py", "tool-no-exit"),
                            "tool_response": {},
                        },
                        "missing_exit",
                    ),
                    (
                        {
                            **payload("pytest tests/a.py", "tool-interrupt"),
                            "tool_response": {
                                "exit_code": 1,
                                "interrupted": True,
                            },
                        },
                        "interrupted",
                    ),
                    (
                        {
                            **payload(
                                "pytest tests/a.py",
                                "tool-cancel",
                                event="PostToolUseFailure",
                            ),
                            "error": "Command canceled by user",
                        },
                        "interrupted",
                    ),
                    (
                        {
                            **payload("pytest tests/a.py", "tool-bad-event"),
                            "hook_event_name": [],
                        },
                        "malformed_event",
                    ),
                    (
                        {
                            **payload("pytest tests/a.py", "tool-alias"),
                            "sessionId": "different-session",
                        },
                        "malformed_event",
                    ),
                ]
                state = module.empty_state()
                for ordinal, (event_payload, reason) in enumerate(cases):
                    state, output = module.apply_payload(
                        state, event_payload, now=ordinal
                    )
                    self.assertEqual(output, {})
                    self.assertGreaterEqual(state["counters"][reason], 1)
                self.assertEqual(state["episodes"], [])
                self.assertEqual(state["events"], [])

    def test_ttl_boundary_and_deterministic_lru_caps(self):
        for script, module in self.modules():
            with self.subTest(script=script):
                state = module.empty_state()
                state, _ = module.apply_payload(
                    state, payload("pytest tests/a.py", "tool-1"), now=0
                )
                state, response = module.apply_payload(
                    state,
                    payload(
                        "pytest tests/a.py",
                        "tool-2",
                        event="PostToolUseFailure",
                    ),
                    now=module.STATE_TTL_SECONDS,
                )
                self.assertTrue(response)

                state = module.empty_state()
                state, _ = module.apply_payload(
                    state, payload("pytest tests/a.py", "tool-1"), now=0
                )
                state, response = module.apply_payload(
                    state,
                    payload("pytest tests/a.py", "tool-2"),
                    now=module.STATE_TTL_SECONDS + 0.001,
                )
                self.assertEqual(response, {})
                self.assertEqual(state["episodes"][0]["state"], "tracking")
                self.assertEqual(state["counters"]["episode_expired"], 1)
                self.assertEqual(state["counters"]["event_expired"], 1)

                state = module.empty_state()
                for item in range(module.MAX_EPISODES + 1):
                    state, _ = module.apply_payload(
                        state,
                        payload(f"pytest tests/test_{item}.py", f"failure-{item}"),
                        now=item,
                    )
                self.assertEqual(len(state["episodes"]), module.MAX_EPISODES)
                self.assertEqual(state["counters"]["episode_evicted"], 1)
                oldest_digest = hashlib.sha256(
                    b"pytest tests/test_0.py"
                ).hexdigest()
                self.assertNotIn(
                    oldest_digest,
                    {item["command"] for item in state["episodes"]},
                )

                state = module.empty_state()
                for item in range(module.MAX_EVENT_IDS + 1):
                    state, _ = module.apply_payload(
                        state,
                        payload(
                            f"true {item}",
                            f"success-{item}",
                            exit_code=0,
                        ),
                        now=item,
                    )
                self.assertEqual(len(state["events"]), module.MAX_EVENT_IDS)
                self.assertEqual(state["counters"]["event_evicted"], 1)

    def test_private_durable_state_contains_only_bounded_hashes(self):
        secret_command = (
            "pytest /Users/private/project/tests/a.py "
            "--token ghp_" + ("A" * 36)
        )
        secret_session = "session-secret-user@example.invalid"
        secret_tool_id = "tool-secret-raw-id"
        for script, module in self.modules():
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    state_path = root / ".context-guard" / "state.json"
                    lock_path = root / ".context-guard" / "state.lock"
                    first = payload(
                        secret_command,
                        secret_tool_id,
                        session=secret_session,
                    )
                    second = payload(
                        secret_command,
                        "tool-secret-raw-id-2",
                        session=secret_session,
                    )
                    self.assertEqual(
                        module.update_state_transaction(
                            first,
                            now=1,
                            state_path=state_path,
                            lock_path=lock_path,
                        ),
                        {},
                    )
                    response = module.update_state_transaction(
                        second,
                        now=2,
                        state_path=state_path,
                        lock_path=lock_path,
                    )
                    persisted = state_path.read_text(encoding="utf-8")
                    combined = persisted + json.dumps(response, ensure_ascii=False)
                    for raw in (
                        secret_command,
                        secret_session,
                        secret_tool_id,
                        "ghp_",
                        "/Users/private",
                        str(script.parent),
                    ):
                        self.assertNotIn(raw, combined)
                    self.assertIn(hashlib.sha256(secret_command.encode()).hexdigest(), persisted)
                    self.assertIn(hashlib.sha256(secret_session.encode()).hexdigest(), persisted)
                    self.assertEqual(
                        stat.S_IMODE(state_path.stat().st_mode),
                        0o600,
                    )
                    self.assertEqual(
                        stat.S_IMODE(lock_path.stat().st_mode),
                        0o600,
                    )

    def test_corrupt_oversized_symlink_and_lock_contention_fail_closed(self):
        for script, module in self.modules():
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    state_path = root / ".context-guard" / "state.json"
                    lock_path = root / ".context-guard" / "state.lock"
                    state_path.parent.mkdir()
                    state_path.write_text("{", encoding="utf-8")
                    with self.assertRaises(module.InvalidStateError):
                        module.load_state(state_path)
                    state_path.write_bytes(b"x" * (module.MAX_STATE_BYTES + 1))
                    with self.assertRaises(module.InvalidStateError):
                        module.load_state(state_path)

                    state_path.unlink()
                    state_path.symlink_to(root / "target.json")
                    with self.assertRaises(OSError):
                        module.load_state(state_path)
                    state_path.unlink()

                    with module.state_lock(lock_path):
                        with self.assertRaises(module.StateLockTimeoutError):
                            with module.state_lock(lock_path, timeout=0):
                                self.fail("nested lock unexpectedly acquired")

                    lock_path.unlink()
                    lock_path.symlink_to(root / "target.lock")
                    with self.assertRaises(OSError):
                        with module.state_lock(lock_path, timeout=0):
                            self.fail("symlinked lock unexpectedly acquired")

    def test_durability_failure_never_returns_uncommitted_nudge(self):
        for script, module in self.modules():
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    state_path = root / ".context-guard" / "state.json"
                    lock_path = root / ".context-guard" / "state.lock"
                    module.update_state_transaction(
                        payload("pytest tests/a.py", "tool-1"),
                        now=1,
                        state_path=state_path,
                        lock_path=lock_path,
                    )
                    before = state_path.read_bytes()
                    with mock.patch.object(
                        module,
                        "save_state",
                        side_effect=OSError(errno.EIO, "durability failed"),
                    ):
                        with self.assertRaises(OSError):
                            module.update_state_transaction(
                                payload("pytest tests/a.py", "tool-2"),
                                now=2,
                                state_path=state_path,
                                lock_path=lock_path,
                            )
                    self.assertEqual(state_path.read_bytes(), before)

                    original_stdin = module.sys.stdin
                    original_stdout = module.sys.stdout
                    original_stderr = module.sys.stderr
                    with mock.patch.object(
                        module,
                        "update_state_transaction",
                        side_effect=OSError(errno.EIO, "durability failed"),
                    ):
                        module.sys.stdin = io.StringIO(json.dumps(
                            payload("pytest tests/a.py", "tool-2")
                        ))
                        module.sys.stdout = io.StringIO()
                        module.sys.stderr = io.StringIO()
                        try:
                            self.assertEqual(module.main(), 0)
                            self.assertEqual(
                                json.loads(module.sys.stdout.getvalue()),
                                {},
                            )
                        finally:
                            module.sys.stdin = original_stdin
                            module.sys.stdout = original_stdout
                            module.sys.stderr = original_stderr

    def test_parallel_writers_produce_exactly_one_nudge(self):
        for script in NUDGE_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    first = subprocess.Popen(
                        [sys.executable, str(script)],
                        cwd=tmp,
                        text=True,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    second = subprocess.Popen(
                        [sys.executable, str(script)],
                        cwd=tmp,
                        text=True,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    out_a, err_a = first.communicate(
                        json.dumps(payload("pytest tests/a.py", "parallel-1")),
                        timeout=10,
                    )
                    out_b, err_b = second.communicate(
                        json.dumps(payload("pytest tests/a.py", "parallel-2")),
                        timeout=10,
                    )
                    self.assertEqual((first.returncode, second.returncode), (0, 0))
                    self.assertEqual(err_a + err_b, "")
                    outputs = [json.loads(out_a), json.loads(out_b)]
                    self.assertEqual(sum(bool(item) for item in outputs), 1)
                    state_path = (
                        Path(tmp)
                        / ".context-guard"
                        / "failures-v2.json"
                    )
                    state = json.loads(state_path.read_text(encoding="utf-8"))
                    self.assertEqual(state["episodes"][0]["state"], "emitted")
                    self.assertEqual(state["episodes"][0]["count"], 2)
                    self.assertEqual(len(state["events"]), 2)

    def test_escrow_wrapper_shape_unwraps_to_the_same_logical_digest(self):
        """기본 래퍼가 digest/escrow 옵션을 붙여도 같은 논리 명령으로 묶여야 한다."""
        logical = "pytest tests/a.py -k token=super-secret"
        expected = hashlib.sha256(logical.encode()).hexdigest()
        for script, module in self.modules():
            with self.subTest(script=script):
                prefix = module._wrapper_prefixes()["trim"]
                escrow = shlex.join([
                    *prefix, "--max-lines", "220", "--digest", "markdown",
                    "--artifact-receipt", "--", "bash", "-c", logical,
                ])
                identity = module.command_identity(escrow)
                self.assertEqual((identity.protocol, identity.digest), ("legacy-v0", expected))
                with_budget = shlex.join([
                    *prefix, "--max-lines", "220", "--digest", "markdown",
                    "--artifact-receipt", "--head-lines", "30", "--tail-lines", "60",
                    "--", "bash", "-c", logical,
                ])
                identity = module.command_identity(with_budget)
                self.assertEqual((identity.protocol, identity.digest), ("legacy-v0", expected))
                for foreign in (
                    shlex.join([*prefix, "--max-lines", "220", "--digest", "csv", "--artifact-receipt", "--", "bash", "-c", logical]),
                    shlex.join([*prefix, "--max-lines", "220", "--unknown", "--", "bash", "-c", logical]),
                    shlex.join([*prefix, "--max-lines", "220", "--head-lines", "x", "--", "bash", "-c", logical]),
                ):
                    with self.subTest(foreign=foreign):
                        self.assertEqual(module.command_identity(foreign).protocol, "legacy-or-foreign")

    def test_nudge_text_is_one_line_without_clear_and_names_the_switch(self):
        """힌트는 한 줄이어야 하고 /clear 권유 대신 세션 스위치 해제법을 담아야 한다."""
        for script, module in self.modules():
            with self.subTest(script=script):
                text = module.NUDGE_TEXT
                self.assertNotIn("\n", text)
                self.assertLess(len(text.encode("utf-8")), 320)
                self.assertNotIn("/clear", text)
                self.assertIn("context-guard hooks off nudge", text)
                self.assertTrue(text.startswith("[context-guard]"))

    def test_session_switch_off_returns_empty_and_writes_no_state(self):
        """`context-guard hooks off nudge` 상태면 훅은 {} 만 내고 상태 파일을 만들지 않는다."""
        switch = ROOT / "context-guard-kit" / "hook_switch.py"
        journal = ROOT / "context-guard-kit" / "hook_journal.py"
        for script in NUDGE_SCRIPTS:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                subprocess.run(
                    [sys.executable, str(switch), "--root", str(root), "off", "nudge", "--for", "10m"],
                    check=True, capture_output=True,
                )
                env = {"PATH": "/usr/bin:/bin", "HOME": tmp}
                for tool_id in ("tool-1", "tool-2"):
                    completed = subprocess.run(
                        [sys.executable, "-I", str(script)],
                        input=json.dumps(payload("pytest tests/a.py", tool_id)),
                        text=True, capture_output=True, cwd=tmp, env=env, check=True,
                    )
                    self.assertEqual(json.loads(completed.stdout), {})
                self.assertFalse((root / ".context-guard" / "failures-v2.json").exists())
                journal_module = load_script(journal, f"_journal_{id(self)}")
                rows = journal_module.read_rows(root)
                self.assertEqual([row["hook"] for row in rows], ["nudge", "nudge"])
                self.assertTrue(all(row["intervened"] is False for row in rows))
                self.assertTrue(all(row.get("detail") == "switched off" for row in rows))

    def test_second_failure_journals_an_intervention(self):
        """두 번째 실패에서 힌트가 나가면 저널에 intervened=true 로 남는다."""
        journal = ROOT / "context-guard-kit" / "hook_journal.py"
        for script in NUDGE_SCRIPTS:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as tmp:
                env = {"PATH": "/usr/bin:/bin", "HOME": tmp}
                outputs = []
                for tool_id in ("tool-1", "tool-2"):
                    completed = subprocess.run(
                        [sys.executable, "-I", str(script)],
                        input=json.dumps(payload("pytest tests/a.py", tool_id)),
                        text=True, capture_output=True, cwd=tmp, env=env, check=True,
                    )
                    outputs.append(json.loads(completed.stdout))
                self.assertEqual(outputs[0], {})
                self.assertIn("hookSpecificOutput", outputs[1])
                rows = load_script(journal, f"_journal2_{id(self)}").read_rows(Path(tmp))
                self.assertEqual([row["intervened"] for row in rows], [False, True])
                joined = json.dumps(rows)
                self.assertNotIn("pytest", joined)
                self.assertNotIn("session-A", joined)


if __name__ == "__main__":
    unittest.main()
