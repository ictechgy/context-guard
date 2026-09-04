"""S003-F1: the documented standing cost of advisory rule blocks must stay true.

docs/safety-reference.md states a fixed per-request byte cost for each managed rule
block. Those
numbers are the break-even threshold a user is told to measure against, so they
must match the shipped files exactly in both languages.
"""
from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
BRIEF_DIR = ROOT / "plugins" / "context-guard" / "brief"
BLOCKS = (
    "brief-mode.lite",
    "brief-mode.standard",
    "brief-mode.ultra",
    "narration-mode.quiet",
)


class StandingCostDocumentationTest(unittest.TestCase):
    def setUp(self) -> None:
        # 문장이 줄바꿈으로 나뉘어도 문구 검사가 깨지지 않게 공백을 정규화한다.
        # R3 progressive disclosure: 상시 비용 표는 README 에서 안전 참조 문서로 옮겼다.
        safety = " ".join((ROOT / "docs" / "safety-reference.md").read_text(encoding="utf-8").split())
        self.english = safety
        self.korean = safety

    def test_every_block_size_is_documented_in_both_readmes(self) -> None:
        for name in BLOCKS:
            path = BRIEF_DIR / f"{name}.md"
            with self.subTest(block=name):
                self.assertTrue(path.is_file(), f"missing shipped block: {path}")
                size = len(path.read_bytes())
                formatted = f"{size:,}"
                self.assertIn(
                    f"`{name}` | {formatted} bytes", self.english,
                    f"docs/safety-reference.md does not document {name} as {formatted} bytes",
                )
                self.assertIn(
                    f"`{name}` | {formatted} 바이트", self.korean,
                    f"docs/safety-reference.md does not document {name} as {formatted} bytes (Korean)",
                )

    def test_break_even_framing_is_present(self) -> None:
        self.assertIn("Standing cost and break-even", self.english)
        self.assertIn("break-even threshold", self.english)
        self.assertIn("상시 비용과 손익분기", self.korean)
        self.assertIn("손익분기점", self.korean)

    def test_hook_overhead_contrast_is_stated(self) -> None:
        """Hooks charge only when they act; the docs must say so with real numbers."""
        self.assertIn("sub-threshold `Read` adds 3 bytes", self.english)
        self.assertIn("3바이트", self.korean)

    def test_no_fixed_saving_is_promised(self) -> None:
        for text, phrase in (
            (self.english, "no fixed saving is claimed"),
            (self.korean, "고정된 절감률을 보장하지 않습니다"),
        ):
            self.assertIn(phrase, text)


if __name__ == "__main__":
    unittest.main()
