from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FULL_SHA_ACTION_RE = re.compile(r"uses:\s+actions/[\w-]+@[0-9a-f]{40}(?:\s+#\s+v\d+)?")
UNPINNED_ACTION_RE = re.compile(r"uses:\s+actions/[\w-]+@v\d+\b")


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class WorkflowSecurityTests(unittest.TestCase):
    def test_pages_workflow_uses_pages_deployment_permissions_not_repo_write_token(self):
        pages = read(".github/workflows/pages.yml")

        self.assertNotIn("contents: write", pages)
        self.assertNotIn("git push", pages)
        self.assertNotIn("x-access-token", pages)
        self.assertNotIn("GITHUB_TOKEN", pages)
        self.assertIn("permissions: {}", pages)
        self.assertIn("contents: read", pages)
        self.assertIn("pages: write", pages)
        self.assertIn("id-token: write", pages)
        self.assertIn("environment:", pages)
        self.assertIn("name: github-pages", pages)
        self.assertIn("actions/upload-pages-artifact@", pages)
        self.assertIn("include-hidden-files: true", pages)
        self.assertIn("actions/deploy-pages@", pages)
        self.assertTrue((ROOT / "docs" / ".nojekyll").is_file())

    def test_first_party_actions_are_pinned_to_full_sha_with_non_persistent_checkout_credentials(self):
        workflows = [read(".github/workflows/pages.yml"), read(".github/workflows/ci.yml")]
        combined = "\n".join(workflows)

        self.assertIsNone(UNPINNED_ACTION_RE.search(combined))
        uses_lines = [line.strip() for line in combined.splitlines() if line.strip().startswith("uses: actions/")]
        self.assertTrue(uses_lines)
        self.assertTrue(all(FULL_SHA_ACTION_RE.fullmatch(line) for line in uses_lines))
        self.assertEqual(combined.count("persist-credentials: false"), combined.count("actions/checkout@"))

    def test_ci_runs_swift_tests_in_macos_package_job(self):
        ci = read(".github/workflows/ci.yml")
        self.assertIn("  test-and-prepublish-macos:", ci)
        ubuntu_job, macos_job = ci.split("  test-and-prepublish-macos:", 1)

        self.assertNotIn("swift test", ubuntu_job)
        self.assertIn("runs-on: macos-latest", macos_job)
        self.assertEqual(ci.count("run: swift test"), 1)
        self.assertIn("timeout-minutes: 15", macos_job)
        self.assertIn("working-directory: apps/contextguard-mac\n        run: swift test", macos_job)


if __name__ == "__main__":
    unittest.main()
