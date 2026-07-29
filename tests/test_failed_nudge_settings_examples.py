import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class FailedNudgeSettingsExamplesTests(unittest.TestCase):
    def test_examples_wire_failed_nudge_for_both_terminal_events(self):
        examples = [
            (
                ROOT / "context-guard-kit" / "settings.example.json",
                "python3 context-guard-kit/failed_attempt_nudge.py",
            ),
            (
                ROOT / "plugins" / "context-guard" / "examples" / "settings.example.json",
                "context-guard-failed-nudge",
            ),
        ]
        for example_path, expected_command in examples:
            with self.subTest(example=example_path):
                example = json.loads(example_path.read_text(encoding="utf-8"))
                for event in ("PostToolUse", "PostToolUseFailure"):
                    matches = [
                        hook
                        for entry in example["hooks"].get(event, [])
                        if entry.get("matcher") == "Bash"
                        for hook in entry.get("hooks", [])
                        if hook.get("command") == expected_command
                    ]
                    self.assertEqual(
                        len(matches),
                        1,
                        f"{event} must wire exactly one Bash failed-nudge hook in {example_path}",
                    )


if __name__ == "__main__":
    unittest.main()
