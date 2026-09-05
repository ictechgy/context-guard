"""릴리스 캐스케이드 자동화 스크립트의 저장소 불변식과 기본 동작.

세 스크립트는 어떤 경로를 보호할지 결정하지 않는다. 여기서는 (1) 커밋된 트리에서
핀 검사가 일치를 보고하고, (2) 세대 작성기가 원장이 완전할 때 아무것도 만들지 않으며,
(3) 프리플라이트가 경고만 내고 exit 0 임을 고정한다.
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def run(script: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCRIPTS / script), *args], cwd=ROOT, capture_output=True, text=True)


class ReleaseAutomationTests(unittest.TestCase):
    def test_protected_pins_match_the_tree(self) -> None:
        proc = run("refresh_protected_pins.py", "--check")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("all pins match", proc.stdout)

    def test_p3_live_contract_matches_the_tree(self) -> None:
        proc = run("refresh_p3_live_contract.py", "--check")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_author_refuses_when_ledger_is_complete(self) -> None:
        proc = run("author_gate_b_generation.py", "--dry-run")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("already has a fingerprint", proc.stdout + proc.stderr)

    def test_pin_core_rejects_malformed_commit(self) -> None:
        proc = run("refresh_p3_live_contract.py", "--pin-core", "abc")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("40-character", proc.stdout + proc.stderr)

    def test_preflight_is_warning_only_by_default(self) -> None:
        proc = run("release_preflight.py", "--base", "HEAD")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
