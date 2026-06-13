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
        self.assertIn("name: Refuse unexpected hidden docs files", pages)
        self.assertLess(
            pages.index("name: Refuse unexpected hidden docs files"),
            pages.index("name: Upload docs artifact"),
        )
        self.assertIn(
            "[ -L docs/.nojekyll ] || [ ! -f docs/.nojekyll ] || [ -s docs/.nojekyll ]",
            pages,
        )
        self.assertIn("find docs -name '.*' ! -path 'docs/.nojekyll' -print", pages)
        self.assertIn("include-hidden-files: true", pages)
        self.assertIn("actions/deploy-pages@", pages)
        nojekyll = ROOT / "docs" / ".nojekyll"
        self.assertTrue(nojekyll.is_file())
        self.assertFalse(nojekyll.is_symlink())
        self.assertEqual(nojekyll.stat().st_size, 0)
        hidden_docs_paths = sorted(
            str(path.relative_to(ROOT)) for path in (ROOT / "docs").rglob(".*")
        )
        self.assertEqual(hidden_docs_paths, ["docs/.nojekyll"])

    def test_first_party_actions_are_pinned_to_full_sha_with_non_persistent_checkout_credentials(self):
        workflows = [
            read(".github/workflows/pages.yml"),
            read(".github/workflows/ci.yml"),
            read(".github/workflows/npm-publish.yml"),
        ]
        combined = "\n".join(workflows)

        self.assertIsNone(UNPINNED_ACTION_RE.search(combined))
        uses_lines = [line.strip() for line in combined.splitlines() if line.strip().startswith("uses: actions/")]
        self.assertTrue(uses_lines)
        self.assertTrue(all(FULL_SHA_ACTION_RE.fullmatch(line) for line in uses_lines))
        self.assertEqual(combined.count("persist-credentials: false"), combined.count("actions/checkout@"))

    def test_pages_configure_action_uses_node24_release(self):
        pages = read(".github/workflows/pages.yml")

        self.assertIn("actions/configure-pages@45bfe0192ca1faeb007ade9deae92b16b8254a0d # v6", pages)
        self.assertNotIn("actions/configure-pages@983d7736d9b0ae728b81ab479565c72886d7745b # v5", pages)


    def test_npm_publish_workflow_uses_oidc_trusted_publishing_without_environment(self):
        workflow = read(".github/workflows/npm-publish.yml")

        self.assertIn("name: Publish npm package", workflow)
        self.assertIn("types: [published]", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("id-token: write", workflow)
        self.assertIn("contents: read", workflow)
        self.assertNotIn("environment:", workflow)
        self.assertNotIn("NODE_AUTH_TOKEN", workflow)
        self.assertNotIn("NPM_TOKEN", workflow)
        self.assertIn('node-version: "24"', workflow)
        self.assertIn('registry-url: "https://registry.npmjs.org"', workflow)
        self.assertIn("package-manager-cache: false", workflow)
        self.assertIn("python3 scripts/sync_plugin_copies.py --check", workflow)
        self.assertIn("python3 scripts/prepublish_check.py", workflow)
        self.assertIn("python3 scripts/release_smoke.py", workflow)
        self.assertIn('npm publish --dry-run --access public --tag "$NPM_DIST_TAG"', workflow)
        self.assertIn('npm publish --access public --tag "$NPM_DIST_TAG"', workflow)
        self.assertIn("confirm_publish=true", workflow)
        self.assertIn("release tag {tag} does not match package version", workflow)

    def test_ci_release_gates_have_explicit_timeouts(self):
        ci = read(".github/workflows/ci.yml")
        self.assertIn("name: Run prepublish release gate\n        timeout-minutes: 15\n        run: python scripts/prepublish_check.py", ci)
        self.assertIn("name: Run staged plugin release smoke\n        timeout-minutes: 5\n        run: python scripts/release_smoke.py", ci)
        self.assertIn("name: Run prepublish release gate\n        timeout-minutes: 18\n        run: python scripts/prepublish_check.py", ci)
        self.assertIn("name: Run staged plugin release smoke\n        timeout-minutes: 8\n        run: python scripts/release_smoke.py", ci)


    def test_ci_release_gates_install_node_before_npm_checks(self):
        ci = read(".github/workflows/ci.yml")
        self.assertEqual(ci.count("actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e"), 2)
        self.assertEqual(ci.count('node-version: "22"'), 2)
        ubuntu_job, macos_job = ci.split("  test-and-prepublish-macos:", 1)
        for job in (ubuntu_job, macos_job):
            self.assertLess(job.index("name: Set up Node"), job.index("name: Run prepublish release gate"))
            self.assertLess(job.index("name: Set up Node"), job.index("name: Run staged plugin release smoke"))

    def test_homebrew_formula_template_uses_release_placeholders(self):
        template = read("packaging/homebrew/context-guard.rb.template")
        docs = read("docs/distribution.md")

        self.assertIn("v{{VERSION}}.tar.gz", template)
        self.assertIn("REPLACE_WITH_RELEASE_TARBALL_SHA256", template)
        self.assertNotIn("v0.4.8", template)
        self.assertIn("rendered", docs.lower())
        self.assertIn("Formula/context-guard.rb", docs)
        self.assertIn("Do not run Homebrew audit/install directly against the placeholder template", docs)
        self.assertIn("bare semver version", docs)

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
