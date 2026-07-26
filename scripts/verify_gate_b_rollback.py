#!/usr/bin/env python3
"""Mechanically prove the Gate-B component apply/revert contract.

Gate B shipped as two feature commits followed by one shared integration
commit.  The feature commits must remain independently applicable and
revertible.  Shared integration is intentionally reverted only after both
dependent features.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE_COMMIT = "9a30266ab1626dcb3ac3ce7a4fac117f23798bac"
B1_COMMIT = "8f48ca9b010de3f05c9eef382dfe4e2864c88b87"
B2_COMMIT = "90989b24834e6d35a52b50d9e22b33080454bbd7"
SHARED_INTEGRATION_COMMIT = "5d63689590ae0c78ce2c38b874099234070e8169"

B1_PATHS = frozenset(
    {
        "context-guard-kit/failed_attempt_nudge.py",
        "plugins/context-guard/bin/context-guard-failed-nudge",
        "tests/test_context_guard_nudge_protocol.py",
    }
)
B2_PATHS = frozenset(
    {
        "context-guard-kit/claude_transcript_cost_audit.py",
        "context-guard-kit/statusline.sh",
        "context-guard-kit/transcript_usage_reducer.py",
        "plugins/context-guard/bin/context-guard-audit",
        "plugins/context-guard/bin/context-guard-statusline",
        "plugins/context-guard/lib/transcript_usage_reducer.py",
        "tests/test_context_guard_usage_reducer_v2.py",
    }
)
SHARED_INTEGRATION_PATHS = frozenset(
    {
        "context-guard-kit/context_guard_commands.py",
        "context-guard-kit/setup_wizard.py",
        "plugins/context-guard/bin/context-guard-setup",
        "plugins/context-guard/lib/context_guard_commands.py",
        "scripts/release_smoke.py",
        "tests/test_context_guard_kit.py",
    }
)


class ProofError(RuntimeError):
    """Raised when the immutable Gate-B rollback contract no longer holds."""


def run_git(
    repo: Path,
    *args: str,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )
    if check and proc.returncode:
        detail = (proc.stderr or proc.stdout).strip()
        raise ProofError(f"git {' '.join(args)} failed: {detail}")
    return proc


def commit_paths(repo: Path, commit: str) -> frozenset[str]:
    proc = run_git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", commit)
    return frozenset(line for line in proc.stdout.splitlines() if line)


def assert_history_contract(repo: Path) -> None:
    for commit in (BASE_COMMIT, B1_COMMIT, B2_COMMIT, SHARED_INTEGRATION_COMMIT):
        if run_git(repo, "cat-file", "-e", f"{commit}^{{commit}}", check=False).returncode:
            raise ProofError(
                f"required Gate-B commit {commit} is unavailable; use a full-history checkout"
            )

    expected_parents = {
        B1_COMMIT: BASE_COMMIT,
        B2_COMMIT: B1_COMMIT,
        SHARED_INTEGRATION_COMMIT: B2_COMMIT,
    }
    for commit, expected_parent in expected_parents.items():
        actual_parent = run_git(repo, "rev-parse", f"{commit}^").stdout.strip()
        if actual_parent != expected_parent:
            raise ProofError(
                f"Gate-B commit {commit} parent changed: {actual_parent} != {expected_parent}"
            )

    expected_paths = {
        B1_COMMIT: B1_PATHS,
        B2_COMMIT: B2_PATHS,
        SHARED_INTEGRATION_COMMIT: SHARED_INTEGRATION_PATHS,
    }
    for commit, expected in expected_paths.items():
        actual = commit_paths(repo, commit)
        if actual != expected:
            raise ProofError(
                f"Gate-B commit {commit} path set changed: "
                f"actual={sorted(actual)!r} expected={sorted(expected)!r}"
            )
    if B1_PATHS & B2_PATHS:
        raise ProofError("B1 and B2 feature-owned paths overlap")


def proof_environment() -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "ContextGuard rollback proof",
            "GIT_AUTHOR_EMAIL": "rollback-proof@example.invalid",
            "GIT_COMMITTER_NAME": "ContextGuard rollback proof",
            "GIT_COMMITTER_EMAIL": "rollback-proof@example.invalid",
        }
    )
    return env


def checkout(repo: Path, commit: str) -> None:
    run_git(repo, "checkout", "--quiet", "--detach", commit)


def apply_then_revert(repo: Path, base: str, feature: str, env: dict[str, str]) -> dict[str, str]:
    checkout(repo, base)
    base_tree = run_git(repo, "rev-parse", f"{base}^{{tree}}").stdout.strip()
    run_git(repo, "cherry-pick", feature, env=env)
    applied_commit = run_git(repo, "rev-parse", "HEAD").stdout.strip()
    applied_tree = run_git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()
    run_git(repo, "revert", "--no-edit", applied_commit, env=env)
    reverted_tree = run_git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()
    if reverted_tree != base_tree:
        raise ProofError(
            f"apply/revert tree mismatch for {feature}: {reverted_tree} != {base_tree}"
        )
    return {
        "source_commit": feature,
        "applied_tree": applied_tree,
        "reverted_tree": reverted_tree,
    }


def prove_current_revert_order(
    repo: Path,
    source_head: str,
    env: dict[str, str],
) -> dict[str, str]:
    checkout(repo, source_head)
    run_git(repo, "revert", "--no-edit", B1_COMMIT, env=env)
    b1_only = run_git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()

    checkout(repo, source_head)
    run_git(repo, "revert", "--no-edit", B2_COMMIT, env=env)
    b2_only = run_git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()

    checkout(repo, source_head)
    run_git(repo, "revert", "--no-edit", B1_COMMIT, env=env)
    after_b1 = run_git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()
    run_git(repo, "revert", "--no-edit", B2_COMMIT, env=env)
    after_b2 = run_git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()
    run_git(repo, "revert", "--no-edit", SHARED_INTEGRATION_COMMIT, env=env)
    after_shared = run_git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()
    return {
        "b1_only_revert_tree": b1_only,
        "b2_only_revert_tree": b2_only,
        "after_b1_revert_tree": after_b1,
        "after_b2_revert_tree": after_b2,
        "after_shared_revert_tree": after_shared,
    }


def run_proof(repo: Path = ROOT) -> dict[str, object]:
    repo = repo.resolve()
    assert_history_contract(repo)
    source_head = run_git(repo, "rev-parse", "HEAD").stdout.strip()
    env = proof_environment()
    with tempfile.TemporaryDirectory(prefix="context-guard-gate-b-proof-") as tmp:
        proof_repo = Path(tmp) / "repo"
        run_git(
            repo,
            "clone",
            "--quiet",
            "--no-hardlinks",
            str(repo),
            str(proof_repo),
        )
        b1 = apply_then_revert(proof_repo, BASE_COMMIT, B1_COMMIT, env)
        b2 = apply_then_revert(proof_repo, BASE_COMMIT, B2_COMMIT, env)
        revert_order = prove_current_revert_order(proof_repo, source_head, env)
    return {
        "schema_version": "contextguard.gate-b-rollback-proof.v1",
        "status": "ok",
        "source_head": source_head,
        "base_commit": BASE_COMMIT,
        "b1": b1,
        "b2": b2,
        "shared_integration_commit": SHARED_INTEGRATION_COMMIT,
        "revert_order": ["b1", "b2", "shared-integration"],
        **revert_order,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="prove independent Gate-B B1/B2 apply/revert history"
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable evidence")
    args = parser.parse_args()
    try:
        result = run_proof()
    except ProofError as exc:
        print(f"gate-b rollback proof: FAIL: {exc}")
        return 1
    if args.json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        print("gate-b rollback proof: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
