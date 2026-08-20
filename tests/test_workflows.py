from __future__ import annotations

import os
import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FULL_SHA_ACTION_RE = re.compile(r"uses:\s+actions/[\w-]+@[0-9a-f]{40}(?:\s+#\s+v\d+)?")
UNPINNED_ACTION_RE = re.compile(r"uses:\s+actions/[\w-]+@v\d+\b")


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def workflow_job_blocks(workflow: str) -> dict[str, str]:
    jobs = workflow.split("\njobs:\n", 1)[1]
    return dict(re.findall(r"(?ms)^  ([\w-]+):\n(.*?)(?=^  [\w-]+:\n|\Z)", jobs))


def workflow_job_condition(job: str) -> str:
    match = re.search(r"(?m)^    if: \$\{\{ (.+) \}\}$", job)
    if match is None:
        raise AssertionError("workflow job has no condition")
    return match.group(1)


def evaluate_needs_condition(condition: str, **results: str) -> bool:
    expression = re.sub(
        r"needs\.([\w-]+)\.result",
        lambda match: repr(results[match.group(1)]),
        condition,
    )
    expression = expression.replace("always()", "True")
    expression = expression.replace("&&", " and ").replace("||", " or ")
    if re.search(r"[^A-Za-z0-9_ .'!=()\-]", expression):
        raise AssertionError(f"unsupported workflow expression: {condition}")
    return bool(eval(expression, {"__builtins__": {}}, {}))


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
            read(".github/workflows/npm-candidate.yml"),
            read(".github/workflows/npm-publish.yml"),
            read(".github/workflows/npm-promote.yml"),
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


    def test_npm_candidate_workflow_builds_and_attests_each_package_once(self):
        workflow = read(".github/workflows/npm-candidate.yml")

        self.assertIn("name: Build immutable npm candidates", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("id-token: write", workflow)
        self.assertIn("attestations: write", workflow)
        self.assertIn("python3 scripts/build_npm_candidates.py", workflow)
        self.assertIn("--npm-root-tarball", workflow)
        self.assertIn("--npm-receipt-tarball", workflow)
        self.assertEqual(workflow.count("npm pack "), 0)
        self.assertEqual(workflow.count("actions/attest-build-provenance@"), 3)
        self.assertIn(
            "subject-path: ${{ runner.temp }}/npm-candidates/candidate-manifest.json",
            workflow,
        )
        self.assertEqual(workflow.count("actions/upload-artifact@"), 2)
        self.assertIn("candidate-sha256sums.txt", workflow)
        self.assertIn("candidate-manifest.json", workflow)
        self.assertIn("WORKFLOW_COMMIT: ${{ github.sha }}", workflow)
        self.assertIn('test "$WORKFLOW_COMMIT" = "$CANDIDATE_COMMIT"', workflow)

    def test_npm_candidate_workflow_checks_gate_b_before_build_and_attestation(self):
        workflow = read(".github/workflows/npm-candidate.yml")

        checkout = workflow.index("- name: Checkout the exact candidate commit")
        checkout_end = workflow.index("\n      - name:", checkout + 1)
        checkout_step = workflow[checkout:checkout_end]
        self.assertIn("fetch-depth: 0", checkout_step)

        proof_step = workflow.index("- name: Verify Gate-B rollback proof")
        proof_step_end = workflow.index("\n      - name:", proof_step + 1)
        proof_step_text = workflow[proof_step:proof_step_end]
        gate_b = "python3 scripts/verify_gate_b_rollback.py --json"
        self.assertEqual(workflow.count(gate_b), 1)
        self.assertIn("CANDIDATE_COMMIT: ${{ github.event.inputs.commit_sha }}", proof_step_text)
        self.assertIn('proof.get("status") != "ok"', proof_step_text)
        self.assertIn('proof.get("source_head") != expected', proof_step_text)
        gate_b_index = workflow.index(gate_b)
        build_index = workflow.index("python3 scripts/build_npm_candidates.py")
        attestation_index = workflow.index("actions/attest-build-provenance@")
        self.assertLess(gate_b_index, build_index)
        self.assertLess(gate_b_index, attestation_index)

    def test_npm_candidate_normalizes_and_verifies_hosted_runtimes_before_release_gates(self):
        workflow = read(".github/workflows/npm-candidate.yml")

        setup_python = workflow.index("- name: Set up Python")
        setup_node = workflow.index("- name: Set up Node")
        normalize = workflow.index("- name: Normalize hosted runtime permissions")
        verify_trust = workflow.index("- name: Verify hosted runtime trust")
        release_gate = workflow.index("- name: Verify root package release gates")
        normalize_end = workflow.index("\n      - name:", normalize)
        normalize_step = workflow[normalize:normalize_end]
        self.assertLess(setup_python, normalize)
        self.assertLess(setup_node, normalize)
        self.assertLess(normalize, verify_trust)
        self.assertLess(verify_trust, release_gate)
        self.assertEqual(normalize_step.count("Linux:/opt/hostedtoolcache/*"), 2)
        self.assertIn('case "${RUNNER_OS}:${python_runtime}"', normalize_step)
        self.assertIn('case "${RUNNER_OS}:${node_runtime}"', normalize_step)
        self.assertIn('sudo chmod go-w "$python_runtime" "$node_runtime"', normalize_step)
        self.assertNotIn('sudo chmod go-w -- "$python_runtime" "$node_runtime"', workflow)
        self.assertIn(
            "tests.test_bash_reference_v1.BashReferenceV1Tests."
            "test_github_runner_python_runtime_is_policy_eligible",
            workflow,
        )
        self.assertIn(
            "tests.test_bash_reference_v1.BashReferenceV1Tests."
            "test_github_runner_node_runtime_is_policy_eligible",
            workflow,
        )

    def test_npm_publish_workflow_uses_approved_exact_candidate_assets(self):
        workflow = read(".github/workflows/npm-publish.yml")
        jobs = workflow_job_blocks(workflow)

        self.assertIn("name: Publish npm package", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("release:", workflow)
        self.assertIn("id-token: write", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("attestations: read", workflow)
        self.assertNotIn("NODE_AUTH_TOKEN", workflow)
        self.assertNotIn("NPM_TOKEN", workflow)
        self.assertIn('node-version: "24"', workflow)
        self.assertIn('registry-url: "https://registry.npmjs.org"', workflow)
        self.assertIn("package-manager-cache: false", workflow)
        self.assertNotIn("actions/checkout@", workflow)
        self.assertNotRegex(workflow, r"(?m)^\s*(?:run:\s*)?npm pack\b")
        self.assertIn("candidate_run_id", workflow)
        self.assertIn("candidate_artifact_id", workflow)
        self.assertIn("expected_sha256", workflow)
        self.assertIn("receipt_package_files_sha256", workflow)
        self.assertIn("actions/download-artifact@", workflow)
        self.assertIn("artifact-ids:", workflow)
        self.assertIn("gh attestation verify", workflow)
        self.assertEqual(workflow.count("Verify candidate manifest GitHub build provenance"), 2)
        self.assertEqual(
            workflow.count(
                'gh attestation verify "$RUNNER_TEMP/candidate/candidate-manifest.json"'
            ),
            2,
        )
        self.assertEqual(
            workflow.count("MAX_CANDIDATE_BYTES = 50 * 1024 * 1024"), 2,
        )
        self.assertEqual(workflow.count('record.get("size_bytes")'), 2)
        self.assertNotIn('record.get("size")', workflow)
        self.assertEqual(
            workflow.count("MAX_CANDIDATE_MANIFEST_BYTES = 256 * 1024"), 2,
        )
        self.assertEqual(workflow.count("MAX_TAR_MEMBERS = 4096"), 2)
        self.assertEqual(
            workflow.count("MAX_TAR_DECLARED_BYTES = 128 * 1024 * 1024"), 2,
        )
        self.assertEqual(
            workflow.count("MAX_TAR_STREAM_BYTES = 128 * 1024 * 1024"), 2,
        )
        self.assertEqual(
            workflow.count(
                "tarball_bytes = read_bounded_regular(tarball, MAX_CANDIDATE_BYTES)"
            ),
            2,
        )
        self.assertNotIn("tarball.read_bytes()", workflow)
        self.assertNotIn('.read_text(encoding="ascii")', workflow)
        self.assertNotIn("list(root.iterdir())", workflow)
        self.assertNotIn("archive.getmembers()", workflow)
        self.assertNotIn('mode="r|gz"', workflow)
        self.assertNotIn("json.load(member)", workflow)
        self.assertNotIn("hashlib.sha256(tarball.read_bytes())", workflow)
        self.assertNotIn("hashlib.sha512(tarball.read_bytes())", workflow)
        self.assertIn('npm publish "$CANDIDATE_TARBALL" --dry-run --access public --tag next', workflow)
        self.assertIn('npm publish "$CANDIDATE_TARBALL" --access public --tag next', workflow)
        self.assertIn("confirm_publish=true", workflow)
        self.assertEqual(set(jobs), {"publish-receipt", "publish-root"})
        self.assertIn("environment: npm-receipt-next", jobs["publish-receipt"])
        self.assertIn("environment: npm-root-next", jobs["publish-root"])
        self.assertIn("needs: publish-receipt", jobs["publish-root"])
        self.assertIn("@ictechgy/context-guard-receipt", jobs["publish-receipt"])
        self.assertIn("@ictechgy/context-guard", jobs["publish-root"])
        self.assertIn("dist.integrity", jobs["publish-root"])
        self.assertIn("EXPECTED_RECEIPT_INTEGRITY", jobs["publish-root"])
        self.assertLess(
            jobs["publish-root"].index("Verify root candidate manifest, dependency, and digest"),
            jobs["publish-root"].index("Verify exact published Receipt bytes"),
        )

    def test_npm_promotion_is_separate_and_never_repacks(self):
        workflow = read(".github/workflows/npm-promote.yml")
        jobs = workflow_job_blocks(workflow)

        self.assertIn("name: Promote exact npm versions", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertEqual(set(jobs), {"preflight", "promote-pair"})
        self.assertIn("environment: npm-pair-promote", jobs["promote-pair"])
        self.assertIn("npm dist-tag add", workflow)
        self.assertNotIn("npm pack", workflow)
        self.assertNotIn("npm publish", workflow)
        self.assertNotIn("actions/checkout@", workflow)
        self.assertIn("confirm_promote=true", workflow)
        self.assertNotIn("id-token: write", workflow)
        self.assertIn("secrets.NPM_RECEIPT_PROMOTION_TOKEN", workflow)
        self.assertIn("secrets.NPM_ROOT_PROMOTION_TOKEN", workflow)
        self.assertIn("  preflight:", workflow)
        self.assertIn('npm view "@ictechgy/context-guard-receipt" dist-tags.next', workflow)
        self.assertIn('npm view "@ictechgy/context-guard@$ROOT_VERSION" dependencies --json', workflow)
        self.assertIn("exact Receipt dependency mismatch", workflow)
        self.assertLess(workflow.index("  preflight:"), workflow.index("npm dist-tag add"))
        self.assertIn("needs: preflight", workflow)
        self.assertIn("previous_receipt_latest", workflow)
        self.assertIn("previous_root_latest", workflow)
        pair_job = jobs["promote-pair"]
        self.assertIn("trap compensate EXIT", pair_job)
        self.assertIn("trap 'exit 130' INT", pair_job)
        self.assertIn("trap 'exit 143' TERM", pair_job)
        self.assertIn("trap - EXIT INT TERM", pair_job)
        self.assertIn("receipt_maybe_changed=true", pair_job)
        self.assertIn("root_maybe_changed=true", pair_job)
        self.assertIn("previous_receipt_latest", pair_job)
        self.assertIn("previous_root_latest", pair_job)
        self.assertIn("secrets.NPM_RECEIPT_PROMOTION_TOKEN", pair_job)
        self.assertIn("secrets.NPM_ROOT_PROMOTION_TOKEN", pair_job)
        setup_prefix = pair_job.split(
            "- name: Promote the exact pair with in-process compensation", 1
        )[0]
        self.assertNotIn("NPM_RECEIPT_PROMOTION_TOKEN", setup_prefix)
        self.assertNotIn("NPM_ROOT_PROMOTION_TOKEN", setup_prefix)
        self.assertNotIn("rollback-root:", workflow)
        self.assertNotIn("rollback-receipt:", workflow)
        self.assertLess(
            pair_job.index('"@ictechgy/context-guard-receipt@$RECEIPT_VERSION"'),
            pair_job.index('"@ictechgy/context-guard@$ROOT_VERSION"'),
        )

    def test_pair_promotion_compensates_both_tags_in_the_same_approved_step(self):
        workflow = read(".github/workflows/npm-promote.yml")
        step_marker = "      - name: Promote the exact pair with in-process compensation\n"
        step = workflow.split(step_marker, 1)[1]
        script_lines = step.split("        run: |\n", 1)[1].splitlines()
        script = textwrap.dedent("\n".join(script_lines)) + "\n"

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            binary_dir = root / "bin"
            binary_dir.mkdir()
            log_path = root / "npm.log"
            npm = binary_dir / "npm"
            npm.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$*\" >> \"$NPM_LOG\"\n"
                "if [ \"$1\" = dist-tag ] && [ \"$2\" = add ] "
                "&& [ \"$3\" = '@ictechgy/context-guard@0.5.0' ]; then\n"
                "  exit 42\n"
                "fi\n"
                "exit 0\n",
                encoding="utf-8",
            )
            npm.chmod(0o755)
            timeout = binary_dir / "timeout"
            timeout.write_text(
                "#!/bin/sh\nshift\nexec \"$@\"\n",
                encoding="utf-8",
            )
            timeout.chmod(0o755)
            environment = {
                "DIST_TAG": "latest",
                "LANG": "C",
                "LC_ALL": "C",
                "NPM_LOG": str(log_path),
                "PATH": f"{binary_dir}{os.pathsep}{os.defpath}",
                "PREVIOUS_RECEIPT_VERSION": "0.1.9",
                "PREVIOUS_ROOT_VERSION": "0.4.16",
                "RECEIPT_AUTH_TOKEN": "fixture-receipt-credential",
                "RECEIPT_VERSION": "0.2.0",
                "ROOT_AUTH_TOKEN": "fixture-root-credential",
                "ROOT_VERSION": "0.5.0",
            }
            completed = subprocess.run(
                ["/bin/bash", "-c", script],
                cwd=root,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
                check=False,
            )

            self.assertEqual(completed.returncode, 42, completed.stderr)
            self.assertEqual(
                log_path.read_text(encoding="utf-8").splitlines(),
                [
                    "dist-tag add @ictechgy/context-guard-receipt@0.2.0 latest",
                    "dist-tag add @ictechgy/context-guard@0.5.0 latest",
                    "dist-tag add @ictechgy/context-guard@0.4.16 latest",
                    "dist-tag add @ictechgy/context-guard-receipt@0.1.9 latest",
                ],
            )

    def test_npm_publish_attestations_bind_source_commit_and_signer_revision(self):
        workflow = read(".github/workflows/npm-publish.yml")

        self.assertEqual(
            workflow.count('--source-digest "$CANDIDATE_COMMIT_SHA"'), 4,
        )
        self.assertEqual(
            workflow.count('--signer-digest "$CANDIDATE_COMMIT_SHA"'), 4,
        )
        self.assertEqual(
            workflow.count(
                "--signer-workflow "
                "ictechgy/context-guard/.github/workflows/npm-candidate.yml"
            ),
            4,
        )
        self.assertEqual(workflow.count("--repo ictechgy/context-guard"), 4)

    def test_ci_release_gates_have_explicit_timeouts(self):
        ci = read(".github/workflows/ci.yml")
        prepublish_check = read("scripts/prepublish_check.py")
        job_blocks = workflow_job_blocks(ci)
        ubuntu_job = job_blocks["test-and-prepublish"]
        macos_job = job_blocks["test-and-prepublish-macos"]

        self.assertIn("TEST_DISCOVERY_TIMEOUT_SECONDS = 1380", prepublish_check)
        self.assertIn("PROVIDER_LIVE_TEST_TIMEOUT_SECONDS = 600", prepublish_check)
        self.assertIn("name: Run prepublish release gate\n        timeout-minutes: 35\n        run: python scripts/prepublish_check.py", ubuntu_job)
        self.assertIn("name: Run staged plugin release smoke\n        timeout-minutes: 5\n        run: python scripts/release_smoke.py", ubuntu_job)
        self.assertIn("name: Run prepublish release gate\n        timeout-minutes: 35\n        run: python scripts/prepublish_check.py", macos_job)
        self.assertIn("name: Run staged plugin release smoke\n        timeout-minutes: 8\n        run: python scripts/release_smoke.py", macos_job)


    def test_ci_release_gates_install_node_before_npm_checks(self):
        ci = read(".github/workflows/ci.yml")
        self.assertEqual(ci.count("actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e"), 2)
        self.assertEqual(ci.count('node-version: "22"'), 2)
        ubuntu_job, macos_job = ci.split("  test-and-prepublish-macos:", 1)
        for job in (ubuntu_job, macos_job):
            self.assertLess(job.index("name: Set up Node"), job.index("name: Run prepublish release gate"))
            self.assertLess(job.index("name: Set up Node"), job.index("name: Run staged plugin release smoke"))

    def test_ci_normalizes_only_expected_hosted_runtime_targets_before_preflight(self):
        ci = read(".github/workflows/ci.yml")
        ubuntu_job, macos_job = ci.split("  test-and-prepublish-macos:", 1)

        self.assertEqual(ci.count("name: Normalize hosted runtime permissions"), 2)
        self.assertEqual(
            ci.count('sudo chmod go-w "$python_runtime" "$node_runtime"'),
            2,
        )
        self.assertEqual(ci.count("sudo chmod "), 2)
        self.assertNotIn("chmod -R", ci)
        self.assertIn("Linux:/opt/hostedtoolcache/*", ubuntu_job)
        self.assertNotIn("/Library/Frameworks", ubuntu_job)
        self.assertIn(
            "macOS:/Library/Frameworks/Python.framework/Versions/*",
            macos_job,
        )
        self.assertIn(
            "macOS:/opt/homebrew/*|macOS:/usr/local/*|macOS:/Users/runner/hostedtoolcache/*",
            macos_job,
        )
        for job in (ubuntu_job, macos_job):
            normalize = job.index("name: Normalize hosted runtime permissions")
            preflight = job.index("name: Verify hosted runtime trust")
            prepublish = job.index("name: Run prepublish release gate")
            self.assertLess(job.index("name: Set up Node"), normalize)
            self.assertLess(normalize, preflight)
            self.assertLess(preflight, prepublish)

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
