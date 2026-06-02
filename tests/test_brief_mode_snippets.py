#!/usr/bin/env python3
"""Regression tests for advisory brief-mode snippets.

Brief mode is advisory documentation/snippet content, not executable code. These
tests pin the contract the PRD/test-spec require:

- deterministic levels ``lite``/``standard``/``ultra`` exist,
- each level is a single marker-delimited, removable block,
- every block is explicitly labelled advisory/best-effort,
- no block claims guaranteed token/cost savings,
- every block preserves the mandatory evidence floor.

Dependency-free; run with ``python3 tests/test_brief_mode_snippets.py``.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BRIEF_DIR = ROOT / "plugins" / "context-guard" / "brief"

LEVELS = ("lite", "standard", "ultra")

BEGIN_RE = re.compile(
    r"<!--\s*BEGIN context-guard:brief-mode level=(?P<level>[a-z]+) version=(?P<version>\d+)\s*-->"
)
END_MARKER = "<!-- END context-guard:brief-mode -->"

# Substrings that prove the mandatory evidence floor is described in a block.
EVIDENCE_REQUIREMENTS = {
    "file paths": ("file path", "src/app.py:42"),
    "commands": ("command",),
    "output/errors": ("error", "stack trace", "exit code"),
    "code blocks": ("fenced",),
    "verification status": ("pass", "fail"),
    "changed files": ("changed file",),
    "known gaps": ("gap", "todo", "assumption"),
    "caveats": ("caveat", "double-check"),
}

# Phrasing that proves the advisory boundary is stated.
ADVISORY_TERMS = ("advisory", "best-effort")
# Phrasing that proves no guaranteed-savings claim is made.
NO_SAVINGS_TERMS = ("does not promise", "not guarantee", "not promise")
# A snippet must never assert guaranteed savings.
FORBIDDEN_CLAIMS = (
    "guaranteed token savings",
    "guaranteed savings",
    "guarantees savings",
    "guaranteed token reduction",
)


def level_path(level: str) -> Path:
    return BRIEF_DIR / f"brief-mode.{level}.md"


def extract_block(text: str, level: str) -> str:
    matches = list(BEGIN_RE.finditer(text))
    assert len(matches) == 1, f"expected exactly one BEGIN marker, found {len(matches)}"
    begin = matches[0]
    assert begin.group("level") == level, f"marker level {begin.group('level')!r} != {level!r}"
    end_index = text.index(END_MARKER, begin.end())
    return text[begin.end():end_index]


class BriefModeSnippetTests(unittest.TestCase):
    def test_brief_dir_and_index_exist(self) -> None:
        self.assertTrue(BRIEF_DIR.is_dir(), f"missing brief snippet dir: {BRIEF_DIR}")
        self.assertTrue((BRIEF_DIR / "README.md").is_file(), "missing brief/README.md index")

    def test_levels_are_deterministic_set(self) -> None:
        present = sorted(
            p.name[len("brief-mode."):-len(".md")]
            for p in BRIEF_DIR.glob("brief-mode.*.md")
        )
        self.assertEqual(present, sorted(LEVELS))

    def test_each_level_has_single_removable_block(self) -> None:
        for level in LEVELS:
            with self.subTest(level=level):
                text = level_path(level).read_text(encoding="utf-8")
                self.assertEqual(text.count(END_MARKER), 1, "expected exactly one END marker")
                block = extract_block(text, level)
                self.assertTrue(block.strip(), "marker block must not be empty")

    def test_each_block_is_labelled_advisory(self) -> None:
        for level in LEVELS:
            with self.subTest(level=level):
                block = extract_block(level_path(level).read_text(encoding="utf-8"), level).lower()
                self.assertTrue(
                    any(term in block for term in ADVISORY_TERMS),
                    f"{level} block missing advisory/best-effort label",
                )

    def test_no_guaranteed_savings_claim(self) -> None:
        for level in LEVELS:
            with self.subTest(level=level):
                lowered = level_path(level).read_text(encoding="utf-8").lower()
                for claim in FORBIDDEN_CLAIMS:
                    self.assertNotIn(claim, lowered, f"{level} must not claim {claim!r}")
                block = extract_block(level_path(level).read_text(encoding="utf-8"), level).lower()
                self.assertTrue(
                    any(term in block for term in NO_SAVINGS_TERMS),
                    f"{level} block must explicitly disclaim guaranteed savings",
                )

    def test_evidence_floor_preserved(self) -> None:
        for level in LEVELS:
            block = extract_block(level_path(level).read_text(encoding="utf-8"), level).lower()
            for label, options in EVIDENCE_REQUIREMENTS.items():
                with self.subTest(level=level, evidence=label):
                    self.assertTrue(
                        any(opt.lower() in block for opt in options),
                        f"{level} block must preserve evidence: {label}",
                    )

    def test_index_documents_levels_and_advisory_boundary(self) -> None:
        index = (BRIEF_DIR / "README.md").read_text(encoding="utf-8").lower()
        for level in LEVELS:
            self.assertIn(level, index, f"index missing level {level}")
        self.assertTrue(any(term in index for term in ADVISORY_TERMS), "index missing advisory label")
        self.assertIn("no guaranteed savings", index)


if __name__ == "__main__":
    unittest.main()
