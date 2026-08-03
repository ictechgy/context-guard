import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "context-guard-kit" / "post_tool_trim_hook.py"
PACKAGED = ROOT / "plugins" / "context-guard" / "bin" / "context-guard-post-tool-trim"
SUITE = ROOT / "bench" / "token-savings-12task"


def post_tool_payload(
    *,
    stdout: str = "ok\n",
    stderr: str = "",
    interrupted: bool = False,
    is_image: bool = False,
) -> dict[str, object]:
    return {
        "session_id": "test-session",
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "printf test"},
        "tool_response": {
            "stdout": stdout,
            "stderr": stderr,
            "interrupted": interrupted,
            "isImage": is_image,
            "durationMs": 7,
        },
        "tool_use_id": "tool-use-test",
    }


class PostToolTrimHookTests(unittest.TestCase):
    def run_hook(
        self,
        script: Path,
        payload: dict[str, object] | str,
    ) -> subprocess.CompletedProcess[str]:
        wire = payload if isinstance(payload, str) else json.dumps(payload)
        return subprocess.run(
            [sys.executable, str(script)],
            input=wire,
            text=True,
            capture_output=True,
            timeout=20,
        )

    def test_canonical_and_packaged_entrypoints_are_synchronized(self) -> None:
        self.assertTrue(CANONICAL.is_file())
        self.assertTrue(PACKAGED.is_file())
        self.assertEqual(CANONICAL.read_bytes(), PACKAGED.read_bytes())

    def test_small_bash_output_uses_post_tool_updated_output_shape_without_inflation(self) -> None:
        response = post_tool_payload()["tool_response"]
        expected_response = {
            key: response[key]
            for key in ("stdout", "stderr", "interrupted", "isImage")
        }
        for script in (CANONICAL, PACKAGED):
            with self.subTest(script=script):
                proc = self.run_hook(script, post_tool_payload())
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(proc.stderr, "")
                self.assertEqual(
                    json.loads(proc.stdout),
                    {
                        "hookSpecificOutput": {
                            "hookEventName": "PostToolUse",
                            "updatedToolOutput": expected_response,
                        }
                    },
                )

    def test_large_stdout_is_trimmed_and_stderr_metadata_are_preserved(self) -> None:
        stdout = "".join(f"ordinary line {index}\n" for index in range(800))
        payload = post_tool_payload(
            stdout=stdout,
            stderr="warning only\n",
            interrupted=True,
            is_image=False,
        )
        proc = self.run_hook(CANONICAL, payload)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        updated = json.loads(proc.stdout)["hookSpecificOutput"]["updatedToolOutput"]
        self.assertLess(len(updated["stdout"]), len(stdout))
        self.assertIn("output trimmed", updated["stdout"])
        self.assertEqual(updated["stderr"], "warning only\n")
        self.assertIs(updated["interrupted"], True)
        self.assertIs(updated["isImage"], False)
        self.assertNotIn("durationMs", updated)

    def test_sensitive_values_and_absolute_paths_are_not_reemitted(self) -> None:
        fake_secret = "sk-ant-example-not-a-real-credential-123456"
        private_path = "/Users/example/private/project/report.txt"
        payload = post_tool_payload(stdout=f"api_key={fake_secret}\nfailed at {private_path}\n")
        payload["tool_response"]["opaqueMetadata"] = fake_secret
        proc = self.run_hook(CANONICAL, payload)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        output = proc.stdout
        self.assertNotIn(fake_secret, output)
        self.assertNotIn(private_path, output)
        self.assertIn("[REDACTED]", output)
        self.assertIn("#path:", output)

    def test_duplicate_json_keys_fail_without_echoing_input(self) -> None:
        marker = "DO_NOT_ECHO_DUPLICATE_PAYLOAD"
        wire = (
            '{"hook_event_name":"PostToolUse","tool_name":"Bash",'
            '"tool_response":{"stdout":"'
            + marker
            + '","stdout":"second","stderr":"","interrupted":false,"isImage":false}}'
        )
        proc = self.run_hook(CANONICAL, wire)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, "")
        self.assertIn("invalid hook input", proc.stderr)
        self.assertNotIn(marker, proc.stderr)

    def test_wrong_event_is_a_quiet_noop(self) -> None:
        payload = post_tool_payload()
        payload["hook_event_name"] = "PreToolUse"
        proc = self.run_hook(CANONICAL, payload)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, "")
        self.assertEqual(proc.stderr, "")

    def test_trim_runtime_failure_does_not_echo_internal_error_details(self) -> None:
        marker = "DO_NOT_ECHO_INTERNAL_TRIM_FAILURE"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            adapter = root / "post_tool_trim_hook.py"
            adapter.write_bytes(CANONICAL.read_bytes())
            (root / "trim_command_output.py").write_text(
                "def trim_captured_output(*args, **kwargs):\n"
                f"    raise RuntimeError({marker!r})\n",
                encoding="utf-8",
            )
            proc = self.run_hook(adapter, post_tool_payload())
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, "")
        self.assertIn("trim implementation unavailable", proc.stderr)
        self.assertNotIn(marker, proc.stderr)

    def test_treatment_suite_registers_the_dedicated_hook_adapter(self) -> None:
        settings = json.loads(
            (SUITE / "settings" / "treatment.settings.json").read_text(encoding="utf-8")
        )
        command = settings["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
        self.assertEqual(command, "context-guard-post-tool-trim")

        template = json.loads((SUITE / "variants.template.json").read_text(encoding="utf-8"))
        treatment = next(variant for variant in template if variant["name"] == "treatment")
        binding = next(
            item
            for item in treatment["measurement"]["hook_events"]["registered_bindings"]
            if item["hook_event"] == "PostToolUse"
        )
        self.assertEqual(binding["configured_command"], command)


if __name__ == "__main__":
    unittest.main()
