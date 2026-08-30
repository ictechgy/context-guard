from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FULL_SHA_ACTION_RE = re.compile(r"uses:\s+actions/[\w-]+@[0-9a-f]{40}(?:\s+#\s+v\d+)?")
UNPINNED_ACTION_RE = re.compile(r"uses:\s+actions/[\w-]+@v\d+\b")


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def load_ci_gate():
    path = ROOT / "scripts" / "ci_test_gate.py"
    spec = importlib.util.spec_from_file_location("ci_test_gate_test", path)
    if spec is None or spec.loader is None:
        raise AssertionError("CI test gate is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
    def test_ci_partitions_fast_pr_and_bounded_exhaustive_release_gates(self):
        ci = read(".github/workflows/ci.yml")
        jobs = workflow_job_blocks(ci)

        self.assertEqual(
            set(jobs),
            {
                "fast-pr",
                "core-pr",
                "security-pr",
                "exhaustive-linux",
                "exhaustive-macos",
            },
        )
        self.assertIn("github.event_name == 'pull_request'", jobs["fast-pr"])
        self.assertIn("python scripts/ci_test_gate.py fast", jobs["fast-pr"])
        self.assertIn("scripts/prepublish_check.py --skip-tests", jobs["fast-pr"])
        self.assertIn("github.event_name == 'pull_request'", jobs["core-pr"])
        self.assertIn("python scripts/ci_test_gate.py core", jobs["core-pr"])
        for partition in ("provider-free", "provider-live", "history", "serial"):
            self.assertIn(f"scripts/ci_test_gate.py {partition}", jobs["security-pr"])
        for name in ("exhaustive-linux", "exhaustive-macos"):
            self.assertIn("github.event_name == 'push'", jobs[name])
            self.assertIn("timeout-minutes:", jobs[name])
        self.assertIn("python scripts/prepublish_check.py", jobs["exhaustive-linux"])
        self.assertIn("python scripts/prepublish_check.py", jobs["exhaustive-macos"])

    def test_ci_partition_manifest_is_closed_nonempty_and_serializes_races(self):
        gate = read("scripts/ci_test_gate.py")

        self.assertIn("REQUIRED_TEST_IDS", gate)
        self.assertIn("refusing an empty test partition", gate)
        self.assertIn("missing required test IDs", gate)
        self.assertIn("provider-free", gate)
        self.assertIn("provider-live", gate)
        self.assertIn("history", gate)
        self.assertIn("SERIAL_TEST_IDS", gate)
        self.assertIn("test_experimental_registry_config_write_race_cannot_redirect_to_symlink", gate)
        self.assertIn("tests.test_release_assets", gate)
        self.assertIn("test_exact_two_package_release_asset_set_is_required", gate)
        self.assertNotIn(
            'os.environ["PYTHONDONTWRITEBYTECODE"] = "1"', gate
        )
        self.assertNotIn("ThreadPoolExecutor", gate)

    def test_provider_free_partition_uses_boundary_suite_on_unbound_python(self):
        gate = load_ci_gate()
        self.assertTrue(hasattr(gate, "frozen_python_matches"))
        with mock.patch.object(gate, "frozen_python_matches", return_value=False):
            collected = gate.test_ids(gate.discover_partition("provider-free"))
            required = gate.required_test_ids("provider-free")

        boundary = (
            "tests.test_provider_free_roadmap_boundary."
            "ProviderFreeRoadmapBoundaryTests."
            "test_g2_profile_bootstrap_injects_only_captured_verifier_and_lock_bytes"
        )
        direct = (
            "test_g2_ablation_contract.G2AblationContractTests."
            "test_graph_ordinary_miss_and_symbol_recovery_are_enforced"
        )
        self.assertIn(boundary, collected)
        self.assertIn(boundary, required)
        self.assertNotIn(direct, collected)

    def test_release_workflows_preflight_trust_before_expensive_or_mutating_steps(self):
        candidate = read(".github/workflows/npm-candidate.yml")
        publish = read(".github/workflows/npm-publish.yml")

        self.assertLess(
            candidate.index("Preflight GitHub OIDC and attestation trust"),
            candidate.index("Verify root package release gates"),
        )
        self.assertLess(
            publish.index("Preflight npm trusted publishing"),
            publish.index("actions/download-artifact@"),
        )
        self.assertEqual(publish.count("npm ping --registry=https://registry.npmjs.org"), 2)

    def test_github_release_and_homebrew_reuse_exact_release_provenance(self):
        release = read(".github/workflows/github-release.yml")
        homebrew = read(".github/workflows/homebrew.yml")

        self.assertIn("candidate_run_id", release)
        self.assertIn("candidate_artifact_ids", release)
        self.assertIn("actions/download-artifact@", release)
        self.assertNotIn("npm pack", release)
        self.assertLess(release.index("Preflight release credential and tag"), release.index("actions/download-artifact@"))
        self.assertIn("python3 scripts/verify_release_assets.py", release)
        self.assertLess(
            release.index("python3 scripts/verify_release_assets.py"),
            release.index("gh attestation verify"),
        )
        self.assertIn("gh attestation verify", release)
        self.assertIn("gh release create", release)
        self.assertIn("release_commit_sha", homebrew)
        self.assertIn("release_tarball_sha256", homebrew)
        self.assertIn("python3 scripts/verify_homebrew_formula.py", homebrew)
        self.assertLess(homebrew.index("Preflight Homebrew tap credential"), homebrew.index("verify_homebrew_formula.py"))

    def test_release_workflows_bind_main_push_ci_and_do_not_interpolate_string_inputs(self):
        candidate = read(".github/workflows/npm-candidate.yml")
        release = read(".github/workflows/github-release.yml")
        release_preflight = release.split(
            "- name: Preflight release credential and tag", 1
        )[1].split("- name: Download exact build-once candidate assets", 1)[0]

        self.assertIn("WORKFLOW_REF: ${{ github.ref }}", candidate)
        self.assertIn('test "$WORKFLOW_REF" = "refs/heads/main"', candidate)
        self.assertIn("python3 scripts/verify_release_commit.py", candidate)
        self.assertIn("WORKFLOW_REF: ${{ github.ref }}", release_preflight)
        self.assertIn('test "$WORKFLOW_REF" = "refs/heads/main"', release_preflight)
        self.assertIn("python3 scripts/verify_release_commit.py", release_preflight)
        self.assertIn(
            "CANDIDATE_RUN_ID: ${{ github.event.inputs.candidate_run_id }}",
            release_preflight,
        )
        self.assertIn(
            "CANDIDATE_ARTIFACT_IDS: ${{ github.event.inputs.candidate_artifact_ids }}",
            release_preflight,
        )
        self.assertNotIn(
            '[[ "${{ github.event.inputs.candidate_run_id }}"',
            release_preflight,
        )
        self.assertNotIn(
            '[[ "${{ github.event.inputs.candidate_artifact_ids }}"',
            release_preflight,
        )
        self.assertIn('--version "$VERSION"', release)

    def test_release_runbook_requires_all_three_pr_gates(self):
        runbook = read("docs/release-runbook.md")

        for check in ("fast-pr", "core-pr", "security-pr"):
            self.assertIn(check, runbook)

    def test_release_commit_verifier_requires_successful_main_push_ci(self):
        script = ROOT / "scripts" / "verify_release_commit.py"
        commit = "a" * 40
        valid = {
            "workflow_runs": [
                {
                    "conclusion": "success",
                    "event": "push",
                    "head_branch": "main",
                    "head_sha": commit,
                    "path": ".github/workflows/ci.yml",
                    "status": "completed",
                }
            ]
        }

        def run(payload):
            return subprocess.run(
                ["python3", str(script), "--commit-sha", commit],
                input=json.dumps(payload),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

        self.assertEqual(run(valid).returncode, 0)
        for field, changed in (
            ("conclusion", "failure"),
            ("event", "workflow_dispatch"),
            ("head_branch", "feature"),
            ("head_sha", "b" * 40),
            ("path", ".github/workflows/other.yml"),
            ("status", "in_progress"),
        ):
            invalid = json.loads(json.dumps(valid))
            invalid["workflow_runs"][0][field] = changed
            with self.subTest(field=field):
                self.assertNotEqual(run(invalid).returncode, 0)

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
            read(".github/workflows/github-release.yml"),
            read(".github/workflows/homebrew.yml"),
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
        self.assertIn(
            "- name: Verify root package release gates\n"
            "        timeout-minutes: 35\n"
            "        run: python3 scripts/prepublish_check.py",
            workflow,
        )

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
        self.assertEqual(
            workflow.count(
                'npm publish "$CANDIDATE_TARBALL" --dry-run --access public --tag latest'
            ),
            2,
        )
        self.assertEqual(
            workflow.count(
                'npm publish "$CANDIDATE_TARBALL" --access public --tag latest'
            ),
            2,
        )
        self.assertNotIn("--tag next", workflow)
        self.assertNotIn("npm dist-tag", workflow)
        self.assertNotIn("NODE_AUTH_TOKEN", workflow)
        self.assertNotIn("NPM_TOKEN", workflow)
        self.assertIn("group: npm-publish-latest", workflow)
        self.assertIn("Verify published Receipt latest binding", workflow)
        self.assertIn("Verify published root latest binding", workflow)
        self.assertIn("dist-tags.latest", workflow)
        self.assertEqual(
            workflow.count("for ((attempt = 1; attempt <= 30; attempt++)); do"),
            2,
        )
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
            jobs["publish-root"].index("Verify exact published Receipt latest binding"),
        )

    def test_token_authenticated_npm_promotion_workflow_is_retired(self):
        self.assertFalse((ROOT / ".github/workflows/npm-promote.yml").exists())

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
        job_blocks = workflow_job_blocks(ci)
        self.assertIn("timeout-minutes: 12", job_blocks["fast-pr"])
        self.assertIn("timeout-minutes: 35", job_blocks["core-pr"])
        self.assertIn("timeout-minutes: 35", job_blocks["security-pr"])
        self.assertIn("timeout-minutes: 45", job_blocks["exhaustive-linux"])
        self.assertIn("timeout-minutes: 40", job_blocks["exhaustive-macos"])
        self.assertIn("timeout-minutes: 25\n        run: python scripts/ci_test_gate.py core", job_blocks["exhaustive-linux"])
        self.assertIn("timeout-minutes: 25\n        run: python scripts/ci_test_gate.py core", job_blocks["exhaustive-macos"])


    def test_ci_release_gates_install_node_before_npm_checks(self):
        ci = read(".github/workflows/ci.yml")
        self.assertEqual(ci.count("actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e"), 4)
        self.assertEqual(ci.count('node-version: "22"'), 4)
        for name in ("fast-pr", "exhaustive-linux", "exhaustive-macos"):
            job = workflow_job_blocks(ci)[name]
            self.assertLess(job.index("name: Set up Node"), job.index("prepublish_check.py"))
            self.assertLess(job.index("name: Set up Node"), job.index("name: Run staged plugin release smoke"))

        fast = workflow_job_blocks(ci)["fast-pr"]
        self.assertIn("Normalize expected hosted runtime permissions", fast)
        self.assertIn("Verify hosted runtime trust", fast)
        self.assertLess(
            fast.index("Normalize expected hosted runtime permissions"),
            fast.index("name: Run staged plugin release smoke"),
        )

    def test_ci_normalizes_only_exact_hosted_runtime_files(self):
        ci = read(".github/workflows/ci.yml")
        self.assertEqual(ci.count("Normalize expected hosted runtime permissions"), 4)
        self.assertEqual(ci.count('sudo chmod go-w "$python_runtime" "$node_runtime"'), 4)
        self.assertNotIn("chmod -R", ci)
        self.assertIn("/opt/hostedtoolcache/*", ci)
        self.assertIn("/Library/Frameworks/Python.framework/Versions/*", ci)
        security = workflow_job_blocks(ci)["security-pr"]
        self.assertIn("Normalize expected hosted Python permissions", security)
        self.assertIn('sudo chmod go-w "$python_runtime"', security)
        self.assertLess(
            security.index("Normalize expected hosted Python permissions"),
            security.index("Run provider-free security partition"),
        )

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
        jobs = workflow_job_blocks(ci)
        ubuntu_job = jobs["exhaustive-linux"]
        macos_job = jobs["exhaustive-macos"]

        self.assertNotIn("swift test", ubuntu_job)
        self.assertIn("runs-on: macos-latest", macos_job)
        self.assertEqual(ci.count("run: swift test"), 1)
        self.assertIn("timeout-minutes: 15", macos_job)
        self.assertIn("working-directory: apps/contextguard-mac\n        run: swift test", macos_job)


if __name__ == "__main__":
    unittest.main()
