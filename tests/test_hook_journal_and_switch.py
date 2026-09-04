"""훅 저널(`hook_journal.py`)과 세션 해제 스위치(`hook_switch.py`) 단위 테스트.

두 모듈은 세 훅이 공유하는 helper 이고, 실패해도 훅 출력을 바꾸지 않는 것이 계약이다.
그래서 여기서 고정하는 것은 "정상 동작"만이 아니라 "망가진 입력에서도 조용히 진다"는
성질이다. 특히 저널은 명령 문자열·파일 경로·출력 본문을 절대 쓰지 않아야 한다 —
로컬 파일이라도 비밀이 새는 통로를 새로 만들면 안 된다.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
KIT_DIR = ROOT / "context-guard-kit"


def load_kit_module(name: str, filename: str):
    """kit 모듈 하나를 경로로 로드한다(다른 kit 테스트와 같은 방식)."""
    spec = importlib.util.spec_from_file_location(name, KIT_DIR / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


journal = load_kit_module("context_guard_hook_journal_under_test", "hook_journal.py")
switch = load_kit_module("context_guard_hook_switch_under_test", "hook_switch.py")


class HookJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        # 저널 비활성화 환경 변수가 밖에서 새어 들어오면 테스트가 조용히 무의미해진다.
        self._saved_env = os.environ.pop(journal.JOURNAL_ENV, None)
        self.addCleanup(self._restore_env)

    def _restore_env(self) -> None:
        os.environ.pop(journal.JOURNAL_ENV, None)
        if self._saved_env is not None:
            os.environ[journal.JOURNAL_ENV] = self._saved_env

    def journal_file(self) -> Path:
        return self.root / journal.JOURNAL_DIR_NAME / journal.JOURNAL_FILE_NAME

    def test_record_writes_one_line_with_the_expected_keys(self) -> None:
        self.assertTrue(
            journal.record(
                "read",
                started=journal.start_clock(),
                intervened=True,
                session_id="session-abc",
                input_bytes=105,
                output_bytes=361,
                withheld_bytes=92_000,
                detail="deny invalid_read_range",
                root=self.root,
            )
        )
        lines = self.journal_file().read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        row = json.loads(lines[0])
        self.assertEqual(
            set(row),
            {"ts", "hook", "session", "ms", "in", "out", "intervened", "withheld", "detail"},
        )
        self.assertEqual(row["hook"], "read")
        self.assertEqual(row["in"], 105)
        self.assertEqual(row["out"], 361)
        self.assertEqual(row["withheld"], 92_000)
        self.assertIs(row["intervened"], True)
        self.assertIsInstance(row["ms"], float)

    def test_session_id_is_hashed_never_stored_raw(self) -> None:
        secret_session = "sk-live-0123456789abcdef"
        journal.record(
            "bash",
            started=None,
            intervened=True,
            session_id=secret_session,
            root=self.root,
        )
        text = self.journal_file().read_text(encoding="utf-8")
        self.assertNotIn(secret_session, text)
        row = json.loads(text)
        self.assertEqual(len(row["session"]), 12)
        self.assertIsNone(row["ms"])
        for missing in ("command", "path", "file", "stdout"):
            self.assertNotIn(missing, row)

    def test_non_string_session_ids_become_null(self) -> None:
        for value in (None, 17, {"id": "x"}, "", b"bytes"):
            with self.subTest(value=value):
                self.journal_file().unlink(missing_ok=True)
                journal.record(
                    "read", started=None, intervened=False, session_id=value, root=self.root
                )
                row = json.loads(self.journal_file().read_text(encoding="utf-8"))
                self.assertIsNone(row["session"])

    def test_hooks_never_write_the_command_or_path_into_the_journal(self) -> None:
        """저널이 새 유출 통로가 되지 않는지 훅을 실제로 돌려서 확인한다.

        `record()` 는 detail 을 자르기만 할 뿐 내용을 검사하지 않으므로, 명령 문자열과
        파일 경로가 남지 않는다는 보장은 호출부에만 있다. 그래서 대표 입력이 아니라
        비밀이 들어 있는 입력을 넣고 결과 파일 전체를 검사한다.
        """
        secret = "sk-live-0123456789abcdef"
        cases = (
            (
                KIT_DIR / "rewrite_bash_for_token_budget.py",
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "session_id": secret,
                    "tool_input": {"command": f"pytest -q -k {secret}"},
                },
            ),
            (
                KIT_DIR / "guard_large_read.py",
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Read",
                    "session_id": secret,
                    "tool_input": {"file_path": f"{secret}.log"},
                },
            ),
        )
        big = self.root / f"{secret}.log"
        big.write_bytes(b"x" * 200_000)
        for script, payload in cases:
            with self.subTest(hook=script.name):
                result = subprocess.run(
                    [sys.executable, str(script)],
                    input=json.dumps(payload),
                    capture_output=True,
                    text=True,
                    cwd=self.root,
                    timeout=120,
                )
                self.assertEqual(result.returncode, 0, result.stderr[-400:])
        text = self.journal_file().read_text(encoding="utf-8")
        self.assertEqual(len(text.splitlines()), 2)
        self.assertNotIn(secret, text)
        self.assertNotIn("pytest", text)
        self.assertNotIn(".log", text)

    def test_detail_is_truncated_and_control_characters_are_replaced(self) -> None:
        journal.record(
            "nudge",
            started=None,
            intervened=False,
            detail="a\nb\tc" + "z" * 200,
            root=self.root,
        )
        row = json.loads(self.journal_file().read_text(encoding="utf-8"))
        self.assertEqual(len(row["detail"]), journal.MAX_DETAIL_CHARS)
        self.assertNotIn("\n", row["detail"])
        self.assertNotIn("\t", row["detail"])

    def test_unknown_hook_names_collapse_to_other(self) -> None:
        journal.record("mystery", started=None, intervened=False, root=self.root)
        row = json.loads(self.journal_file().read_text(encoding="utf-8"))
        self.assertEqual(row["hook"], "other")

    def test_rotation_keeps_exactly_one_generation(self) -> None:
        current = self.journal_file()
        current.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        current.write_text("x" * journal.JOURNAL_MAX_BYTES, encoding="utf-8")
        journal.record("read", started=None, intervened=False, root=self.root)
        rotated = self.root / journal.JOURNAL_DIR_NAME / journal.JOURNAL_ROTATED_FILE_NAME
        self.assertTrue(rotated.is_file())
        self.assertEqual(rotated.stat().st_size, journal.JOURNAL_MAX_BYTES)
        self.assertLess(current.stat().st_size, journal.JOURNAL_MAX_BYTES)
        self.assertEqual(len(current.read_text(encoding="utf-8").splitlines()), 1)

    def test_env_flag_disables_recording(self) -> None:
        for value in ("0", "false", "no", "off", "disabled"):
            with self.subTest(value=value):
                os.environ[journal.JOURNAL_ENV] = value
                self.assertTrue(journal.journal_is_disabled())
                self.assertFalse(
                    journal.record("read", started=None, intervened=True, root=self.root)
                )
                self.assertFalse(self.journal_file().exists())

    def test_record_never_raises_when_the_directory_is_a_symlink(self) -> None:
        target = self.root / "elsewhere"
        target.mkdir()
        (self.root / journal.JOURNAL_DIR_NAME).symlink_to(target, target_is_directory=True)
        self.assertFalse(journal.record("read", started=None, intervened=True, root=self.root))

    def test_read_rows_skips_broken_lines_and_orders_rotated_first(self) -> None:
        directory = self.root / journal.JOURNAL_DIR_NAME
        directory.mkdir(mode=0o700)
        (directory / journal.JOURNAL_ROTATED_FILE_NAME).write_text(
            '{"hook":"read","withheld":1}\n', encoding="utf-8"
        )
        (directory / journal.JOURNAL_FILE_NAME).write_text(
            "\n"
            "not json at all\n"
            '{"hook":"bash","withheld":2}\n'
            '["a list is not a row"]\n'
            '{"hook":"nudge","withheld":\n',
            encoding="utf-8",
        )
        rows = journal.read_rows(self.root)
        self.assertEqual([row["hook"] for row in rows], ["read", "bash"])

    def test_read_rows_on_a_missing_journal_is_empty(self) -> None:
        self.assertEqual(journal.read_rows(self.root), [])

    def test_summarize_totals_and_refuses_a_savings_claim(self) -> None:
        journal.record(
            "read", started=None, intervened=True, withheld_bytes=100, root=self.root
        )
        journal.record("read", started=None, intervened=False, root=self.root)
        journal.record(
            "bash", started=None, intervened=True, withheld_bytes=50, root=self.root
        )
        summary = journal.summarize(journal.read_rows(self.root))
        self.assertEqual(summary["rows"], 3)
        self.assertEqual(summary["total"]["invocations"], 3)
        self.assertEqual(summary["total"]["interventions"], 2)
        self.assertEqual(summary["total"]["withheld_bytes"], 150)
        self.assertEqual(summary["by_hook"]["read"]["invocations"], 2)
        self.assertEqual(summary["by_hook"]["read"]["withheld_bytes"], 100)
        self.assertEqual(summary["by_hook"]["bash"]["interventions"], 1)
        self.assertFalse(
            summary["claim_boundary"]["token_or_cost_savings_claim_allowed"]
        )

    def test_summarize_ignores_hostile_field_types(self) -> None:
        rows = [
            {"hook": "read", "withheld": "9999", "ms": "abc", "intervened": "yes"},
            {"hook": 42, "withheld": -5, "ms": True, "intervened": True},
            {"hook": "bash", "withheld": True},
        ]
        summary = journal.summarize(rows)
        self.assertEqual(summary["total"]["withheld_bytes"], 0)
        self.assertEqual(summary["total"]["overhead_ms"], 0.0)
        # "yes" 는 True 가 아니다. 문자열을 참으로 세면 개입 횟수가 부풀려진다.
        self.assertEqual(summary["total"]["interventions"], 1)
        self.assertIn("other", summary["by_hook"])

    def test_render_one_line_handles_an_empty_journal(self) -> None:
        self.assertIn("no rows yet", journal.render_one_line(journal.summarize([])))


class HookSwitchTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def test_off_then_status_then_on(self) -> None:
        self.assertFalse(switch.is_disabled("read", root=self.root))
        switch.set_off("read", duration_seconds=3600, root=self.root)
        self.assertTrue(switch.is_disabled("read", root=self.root))
        self.assertFalse(switch.is_disabled("bash", root=self.root))

        report = switch.status(self.root)
        self.assertFalse(report["hooks"]["read"]["enabled"])
        self.assertGreater(report["hooks"]["read"]["expires_in_seconds"], 0)
        self.assertTrue(report["hooks"]["bash"]["enabled"])

        switch.set_on("read", root=self.root)
        self.assertFalse(switch.is_disabled("read", root=self.root))
        # 비어 있는 상태는 파일을 남기지 않는다.
        self.assertFalse(switch.state_path(self.root).exists())

    def test_all_turns_every_hook_off(self) -> None:
        switch.set_off("all", duration_seconds=600, root=self.root)
        for hook in switch.HOOK_NAMES:
            with self.subTest(hook=hook):
                self.assertTrue(switch.is_disabled(hook, root=self.root))
        switch.set_on("all", root=self.root)
        for hook in switch.HOOK_NAMES:
            with self.subTest(hook=hook):
                self.assertFalse(switch.is_disabled(hook, root=self.root))

    def test_expired_entries_are_treated_as_enabled(self) -> None:
        now = 1_000_000.0
        switch.set_off("bash", duration_seconds=60, root=self.root, now=now)
        self.assertTrue(switch.is_disabled("bash", root=self.root, now=now + 59))
        self.assertFalse(switch.is_disabled("bash", root=self.root, now=now + 61))
        self.assertTrue(switch.status(self.root, now=now + 61)["hooks"]["bash"]["enabled"])

    def test_parse_duration_bounds(self) -> None:
        self.assertEqual(switch.parse_duration("30m"), 1800)
        self.assertEqual(switch.parse_duration("2h"), 7200)
        self.assertEqual(switch.parse_duration("1d"), 86400)
        for bad in ("0m", "25h", "2d", "", "2", "h", "2w", "-1h", "1h30m", "999999d"):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                switch.parse_duration(bad)

    def test_invalid_hook_names_exit_two(self) -> None:
        self.assertEqual(
            switch.main(["--root", str(self.root), "off", "everything"]), 2
        )
        self.assertEqual(switch.main(["--root", str(self.root), "off", "read", "--for", "9d"]), 2)
        self.assertFalse(switch.state_path(self.root).exists())

    def test_cli_off_status_on_round_trip(self) -> None:
        self.assertEqual(switch.main(["--root", str(self.root), "off", "nudge"]), 0)
        self.assertTrue(switch.is_disabled("nudge", root=self.root))
        self.assertEqual(switch.main(["--root", str(self.root), "--json", "status"]), 0)
        self.assertEqual(switch.main(["--root", str(self.root), "on", "nudge"]), 0)
        self.assertFalse(switch.is_disabled("nudge", root=self.root))

    def test_symlinked_state_file_is_ignored(self) -> None:
        directory = self.root / switch.STATE_DIR_NAME
        directory.mkdir(mode=0o700)
        real = self.root / "planted.json"
        real.write_text(
            json.dumps({"version": switch.STATE_VERSION, "off": {"read": 9_999_999_999}}),
            encoding="utf-8",
        )
        (directory / switch.STATE_FILE_NAME).symlink_to(real)
        # 심볼릭 링크를 따라가면 저장소 밖 파일로 훅을 끌 수 있게 된다.
        self.assertFalse(switch.is_disabled("read", root=self.root))

    def test_is_disabled_never_raises_on_garbage(self) -> None:
        directory = self.root / switch.STATE_DIR_NAME
        directory.mkdir(mode=0o700)
        path = directory / switch.STATE_FILE_NAME
        payloads = (
            "",
            "not json",
            "[]",
            '"a string"',
            json.dumps({"version": 999, "off": {"read": 9_999_999_999}}),
            json.dumps({"version": switch.STATE_VERSION, "off": "read"}),
            json.dumps({"version": switch.STATE_VERSION, "off": {"read": "forever"}}),
            json.dumps({"version": switch.STATE_VERSION, "off": {"read": True}}),
            json.dumps({"version": switch.STATE_VERSION, "off": {"../../read": 9e9}}),
            json.dumps({"version": switch.STATE_VERSION}),
        )
        for payload in payloads:
            with self.subTest(payload=payload[:40]):
                path.write_text(payload, encoding="utf-8")
                self.assertFalse(switch.is_disabled("read", root=self.root))

        # 상한을 넘는 파일도 읽지 않는다.
        path.write_text(
            json.dumps({"version": switch.STATE_VERSION, "off": {"read": 9e9}})
            + " " * switch.MAX_STATE_BYTES,
            encoding="utf-8",
        )
        self.assertFalse(switch.is_disabled("read", root=self.root))

    def test_unknown_hook_name_is_never_disabled(self) -> None:
        switch.set_off("all", duration_seconds=600, root=self.root)
        self.assertFalse(switch.is_disabled("trim", root=self.root))
        self.assertFalse(switch.is_disabled("", root=self.root))

    def test_disable_hint_names_the_hook(self) -> None:
        for hook in switch.HOOK_NAMES:
            with self.subTest(hook=hook):
                self.assertEqual(
                    switch.disable_hint(hook),
                    f"Disable for this session: context-guard hooks off {hook}",
                )


if __name__ == "__main__":
    unittest.main()
