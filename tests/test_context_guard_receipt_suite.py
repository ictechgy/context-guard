from __future__ import annotations

import re
import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class ContextGuardReceiptSuiteTests(unittest.TestCase):
    def test_package_local_receipt_contract_suite_is_discovered(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "unittest",
                "discover",
                "-s",
                "packages/context-guard-receipt/tests",
                "-p",
                "test_*.py",
                "-v",
            ],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        match = re.search(r"Ran ([1-9][0-9]*) tests?", result.stderr)
        self.assertIsNotNone(match, result.stderr)


if __name__ == "__main__":
    unittest.main()
