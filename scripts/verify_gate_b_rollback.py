#!/usr/bin/env python3
"""Mechanically prove the Gate-B component apply/revert contract.

The published PR may be squashed or cloned without unpublished intermediate
commits.  This proof therefore derives path-scoped component patches from the
immutable PR base and the checked-out source head instead of depending on local
development-history object IDs.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE_COMMIT = "6aac7d8e10d3e2bc8e6cc94973af142a68e911ec"

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
        "context-guard-kit/statusline_merged.sh",
        "context-guard-kit/transcript_usage_reducer.py",
        "plugins/context-guard/bin/context-guard-audit",
        "plugins/context-guard/bin/context-guard-statusline",
        "plugins/context-guard/bin/context-guard-statusline-merged",
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
COMPONENTS = (
    ("b1", B1_PATHS),
    ("b2", B2_PATHS),
    ("shared-integration", SHARED_INTEGRATION_PATHS),
)


class ProofError(RuntimeError):
    """Raised when the Gate-B rollback contract no longer holds."""


def proof_environment() -> dict[str, str]:
    env = os.environ.copy()
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        env.pop(key, None)
    env.update(
        {
            "GIT_AUTHOR_NAME": "ContextGuard rollback proof",
            "GIT_AUTHOR_EMAIL": "rollback-proof@example.invalid",
            "GIT_COMMITTER_NAME": "ContextGuard rollback proof",
            "GIT_COMMITTER_EMAIL": "rollback-proof@example.invalid",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
        }
    )
    return env


def run_git(
    repo: Path,
    *args: str,
    check: bool = True,
    env: dict[str, str] | None = None,
    input_data: str | None = None,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "-C",
            str(repo),
            *args,
        ],
        input=input_data,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env or proof_environment(),
        check=False,
    )
    if check and proc.returncode:
        detail = (proc.stderr or proc.stdout).strip()
        raise ProofError(f"git {' '.join(args)} failed: {detail}")
    return proc


def changed_paths(repo: Path, base: str, source: str, paths: frozenset[str]) -> frozenset[str]:
    proc = run_git(repo, "diff", "--name-only", base, source, "--", *sorted(paths))
    return frozenset(line for line in proc.stdout.splitlines() if line)


def component_patch(repo: Path, base: str, source: str, paths: frozenset[str]) -> str:
    patch = run_git(repo, "diff", "--binary", base, source, "--", *sorted(paths)).stdout
    if not patch:
        raise ProofError(f"component patch is empty: {sorted(paths)!r}")
    return patch


def assert_history_contract(repo: Path, source_head: str) -> None:
    for commit in (BASE_COMMIT, source_head):
        if run_git(repo, "cat-file", "-e", f"{commit}^{{commit}}", check=False).returncode:
            raise ProofError(f"required Gate-B commit {commit} is unavailable")
    if run_git(
        repo,
        "merge-base",
        "--is-ancestor",
        BASE_COMMIT,
        source_head,
        check=False,
    ).returncode:
        raise ProofError(f"Gate-B base {BASE_COMMIT} is not an ancestor of {source_head}")
    path_sets = [paths for _name, paths in COMPONENTS]
    for index, left in enumerate(path_sets):
        for right in path_sets[index + 1 :]:
            overlap = left & right
            if overlap:
                raise ProofError(f"Gate-B component path sets overlap: {sorted(overlap)!r}")
    for name, expected in COMPONENTS:
        actual = changed_paths(repo, BASE_COMMIT, source_head, expected)
        if actual != expected:
            raise ProofError(
                f"Gate-B {name} path set changed: actual={sorted(actual)!r} "
                f"expected={sorted(expected)!r}"
            )


def checkout(repo: Path, commit: str) -> None:
    run_git(repo, "checkout", "--quiet", "--detach", commit)


def commit_index(repo: Path, message: str) -> str:
    run_git(repo, "commit", "--quiet", "-m", message)
    return run_git(repo, "rev-parse", "HEAD").stdout.strip()


def apply_then_revert(
    repo: Path,
    *,
    name: str,
    base: str,
    patch: str,
) -> dict[str, str]:
    checkout(repo, base)
    base_tree = run_git(repo, "rev-parse", f"{base}^{{tree}}").stdout.strip()
    run_git(repo, "apply", "--index", "--binary", "-", input_data=patch)
    applied_commit = commit_index(repo, f"proof: apply Gate-B {name}")
    applied_tree = run_git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()
    run_git(repo, "revert", "--no-edit", applied_commit)
    reverted_tree = run_git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()
    if reverted_tree != base_tree:
        raise ProofError(
            f"apply/revert tree mismatch for {name}: {reverted_tree} != {base_tree}"
        )
    return {
        "applied_commit": applied_commit,
        "applied_tree": applied_tree,
        "reverted_tree": reverted_tree,
    }


def reverse_component(repo: Path, name: str, patch: str) -> str:
    run_git(repo, "apply", "--reverse", "--index", "--binary", "-", input_data=patch)
    commit_index(repo, f"proof: revert Gate-B {name}")
    return run_git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()


def prove_current_revert_order(
    repo: Path,
    source_head: str,
    patches: dict[str, str],
) -> dict[str, str]:
    checkout(repo, source_head)
    b1_only = reverse_component(repo, "b1", patches["b1"])
    checkout(repo, source_head)
    b2_only = reverse_component(repo, "b2", patches["b2"])

    checkout(repo, source_head)
    after_b1 = reverse_component(repo, "b1", patches["b1"])
    after_b2 = reverse_component(repo, "b2", patches["b2"])
    after_shared = reverse_component(
        repo,
        "shared-integration",
        patches["shared-integration"],
    )
    return {
        "b1_only_revert_tree": b1_only,
        "b2_only_revert_tree": b2_only,
        "after_b1_revert_tree": after_b1,
        "after_b2_revert_tree": after_b2,
        "after_shared_revert_tree": after_shared,
    }


def run_proof(repo: Path = ROOT) -> dict[str, object]:
    repo = repo.resolve()
    source_head = run_git(repo, "rev-parse", "HEAD").stdout.strip()
    assert_history_contract(repo, source_head)
    patches = {
        name: component_patch(repo, BASE_COMMIT, source_head, paths)
        for name, paths in COMPONENTS
    }
    with tempfile.TemporaryDirectory(prefix="context-guard-gate-b-proof-") as tmp:
        proof_repo = Path(tmp) / "repo"
        run_git(repo, "clone", "--quiet", "--no-hardlinks", str(repo), str(proof_repo))
        independent = {
            name: apply_then_revert(
                proof_repo,
                name=name,
                base=BASE_COMMIT,
                patch=patches[name],
            )
            for name in ("b1", "b2")
        }
        revert_order = prove_current_revert_order(proof_repo, source_head, patches)
    return {
        "schema_version": "contextguard.gate-b-rollback-proof.v2",
        "status": "ok",
        "source_head": source_head,
        "base_commit": BASE_COMMIT,
        **independent,
        "revert_order": ["b1", "b2", "shared-integration"],
        **revert_order,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="prove path-scoped Gate-B B1/B2 apply/revert behavior"
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable evidence")
    args = parser.parse_args()
    try:
        result = run_proof()
    except ProofError as exc:
        if args.json:
            print(
                json.dumps(
                    {"schema_version": "contextguard.gate-b-rollback-proof.v2", "status": "fail", "error": str(exc)},
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        else:
            print(f"gate-b rollback proof: FAIL: {exc}")
        return 1
    if args.json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        print("gate-b rollback proof: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
