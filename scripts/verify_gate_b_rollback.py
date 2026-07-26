#!/usr/bin/env python3
"""Mechanically prove durable Gate-B component apply/revert behavior.

The proof consumes a reachable, path-separated reapplication sequence carried
by the PR itself.  Its parent is a Gate-B-free residual that retains unrelated
hook-safety and quiet-narration work.  This avoids depending on unpublished
objects and avoids deriving destructive whole-path patches from ``base..HEAD``.
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
BLESS_SUBJECT = "proof: establish Gate-B-free residual"
B1_SUBJECT = "proof: reapply Gate-B nudge component"
B2_SUBJECT = "proof: reapply Gate-B usage component"
SHARED_SUBJECT = "proof: reapply Gate-B integration component"

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
ALL_COMPONENT_PATHS = B1_PATHS | B2_PATHS | SHARED_INTEGRATION_PATHS
RESIDUAL_MARKERS = {
    "context-guard-kit/setup_wizard.py": (
        "NARRATION_MODE_CHOICES",
        "def parse_managed_bytes",
    ),
    "scripts/release_smoke.py": ("def run_quiet_narration_smoke",),
}


class ProofError(RuntimeError):
    """Raised when the Gate-B rollback contract no longer holds."""


class ProofHistoryUnavailable(ProofError):
    """Raised when a checkout cannot inspect the durable proof history."""


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
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=proof_environment(),
        check=False,
    )
    if check and proc.returncode:
        detail = (proc.stderr or proc.stdout).strip()
        raise ProofError(f"git {' '.join(args)} failed: {detail}")
    return proc


def commit_paths(repo: Path, commit: str) -> frozenset[str]:
    proc = run_git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", commit)
    return frozenset(line for line in proc.stdout.splitlines() if line)


def commit_exists(repo: Path, commit: str) -> bool:
    return (
        run_git(repo, "cat-file", "-e", f"{commit}^{{commit}}", check=False).returncode
        == 0
    )


def changed_paths(repo: Path, left: str, right: str) -> frozenset[str]:
    proc = run_git(repo, "diff", "--name-only", left, right)
    return frozenset(line for line in proc.stdout.splitlines() if line)


def find_unique_subject(repo: Path, source_head: str, subject: str) -> str:
    proc = run_git(
        repo,
        "log",
        "--format=%H%x00%s",
        f"{BASE_COMMIT}..{source_head}",
    )
    matches = []
    for raw in proc.stdout.splitlines():
        commit, separator, actual_subject = raw.partition("\0")
        if separator and actual_subject == subject:
            matches.append(commit)
    if not matches:
        raise ProofHistoryUnavailable(
            "full Gate-B proof history is unavailable: "
            f"reachable commit {subject!r} was not found"
        )
    if len(matches) != 1:
        raise ProofError(
            f"expected exactly one reachable commit named {subject!r}, found {len(matches)}"
        )
    return matches[0]


def file_at(repo: Path, commit: str, path: str) -> str:
    return run_git(repo, "show", f"{commit}:{path}").stdout


def assert_residual_contract(repo: Path, bless: str) -> None:
    for path, markers in RESIDUAL_MARKERS.items():
        content = file_at(repo, bless, path)
        for marker in markers:
            if marker not in content:
                raise ProofError(
                    f"Gate-B-free residual lost unrelated feature marker {marker!r} in {path}"
                )


def resolve_history(repo: Path, source_head: str) -> dict[str, str]:
    commits = {
        "bless": find_unique_subject(repo, source_head, BLESS_SUBJECT),
        "b1": find_unique_subject(repo, source_head, B1_SUBJECT),
        "b2": find_unique_subject(repo, source_head, B2_SUBJECT),
        "shared-integration": find_unique_subject(repo, source_head, SHARED_SUBJECT),
    }
    expected_parents = (
        (commits["b1"], commits["bless"]),
        (commits["b2"], commits["b1"]),
        (commits["shared-integration"], commits["b2"]),
    )
    for commit, expected_parent in expected_parents:
        parent = run_git(repo, "rev-parse", f"{commit}^").stdout.strip()
        if parent != expected_parent:
            raise ProofError(f"Gate-B proof parent mismatch: {commit}^={parent}, expected {expected_parent}")
    expected_paths = {
        "bless": ALL_COMPONENT_PATHS,
        "b1": B1_PATHS,
        "b2": B2_PATHS,
        "shared-integration": SHARED_INTEGRATION_PATHS,
    }
    for name, expected in expected_paths.items():
        actual = commit_paths(repo, commits[name])
        if actual != expected:
            raise ProofError(
                f"Gate-B {name} path set changed: actual={sorted(actual)!r} "
                f"expected={sorted(expected)!r}"
            )
    post_component_changes = changed_paths(repo, commits["shared-integration"], source_head)
    overlap = post_component_changes & ALL_COMPONENT_PATHS
    if overlap:
        raise ProofError(f"component paths changed after durable reapplication: {sorted(overlap)!r}")
    assert_residual_contract(repo, commits["bless"])
    return commits


def checkout(repo: Path, commit: str) -> None:
    run_git(repo, "checkout", "--quiet", "--detach", commit)


def apply_then_revert(
    repo: Path,
    base: str,
    component: str,
) -> dict[str, str]:
    checkout(repo, base)
    base_tree = run_git(repo, "rev-parse", f"{base}^{{tree}}").stdout.strip()
    run_git(repo, "cherry-pick", component)
    applied_commit = run_git(repo, "rev-parse", "HEAD").stdout.strip()
    applied_tree = run_git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()
    run_git(repo, "revert", "--no-edit", applied_commit)
    reverted_tree = run_git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()
    if reverted_tree != base_tree:
        raise ProofError(
            f"apply/revert tree mismatch for {component}: {reverted_tree} != {base_tree}"
        )
    return {
        "source_commit": component,
        "applied_tree": applied_tree,
        "reverted_tree": reverted_tree,
    }


def prove_current_revert_order(
    repo: Path,
    source_head: str,
    commits: dict[str, str],
) -> dict[str, str]:
    checkout(repo, source_head)
    run_git(repo, "revert", "--no-edit", commits["b1"])
    b1_only = run_git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()

    checkout(repo, source_head)
    run_git(repo, "revert", "--no-edit", commits["b2"])
    b2_only = run_git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()

    checkout(repo, source_head)
    run_git(repo, "revert", "--no-edit", commits["b1"])
    after_b1 = run_git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()
    run_git(repo, "revert", "--no-edit", commits["b2"])
    after_b2 = run_git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()
    run_git(repo, "revert", "--no-edit", commits["shared-integration"])
    after_shared_commit = run_git(repo, "rev-parse", "HEAD").stdout.strip()
    after_shared = run_git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()

    residual_delta = run_git(
        repo,
        "diff",
        "--name-only",
        commits["bless"],
        after_shared_commit,
        "--",
        *sorted(ALL_COMPONENT_PATHS),
    ).stdout.splitlines()
    if residual_delta:
        raise ProofError(
            f"ordered Gate-B rollback does not restore durable residual: {residual_delta!r}"
        )
    rollback_delta = changed_paths(repo, source_head, after_shared_commit)
    if rollback_delta != ALL_COMPONENT_PATHS:
        raise ProofError(
            f"ordered rollback changed paths outside exact Gate-B set: "
            f"actual={sorted(rollback_delta)!r} expected={sorted(ALL_COMPONENT_PATHS)!r}"
        )
    assert_residual_contract(repo, after_shared_commit)
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
    if not commit_exists(repo, BASE_COMMIT):
        raise ProofHistoryUnavailable(
            "full Gate-B proof history is unavailable: "
            f"base commit {BASE_COMMIT} is missing; fetch full history or use a "
            "merge-preserved checkout"
        )
    ancestry = run_git(
        repo,
        "merge-base",
        "--is-ancestor",
        BASE_COMMIT,
        source_head,
        check=False,
    )
    if ancestry.returncode:
        if ancestry.returncode != 1:
            detail = (ancestry.stderr or ancestry.stdout).strip()
            raise ProofHistoryUnavailable(
                "full Gate-B proof history is unavailable: "
                f"could not inspect ancestry ({detail or f'exit {ancestry.returncode}'})"
            )
        raise ProofError(f"Gate-B base {BASE_COMMIT} is not an ancestor of {source_head}")
    commits = resolve_history(repo, source_head)
    with tempfile.TemporaryDirectory(prefix="context-guard-gate-b-proof-") as tmp:
        proof_repo = Path(tmp) / "repo"
        run_git(repo, "clone", "--quiet", "--no-hardlinks", str(repo), str(proof_repo))
        b1 = apply_then_revert(proof_repo, commits["bless"], commits["b1"])
        b2 = apply_then_revert(proof_repo, commits["bless"], commits["b2"])
        revert_order = prove_current_revert_order(proof_repo, source_head, commits)
    return {
        "schema_version": "contextguard.gate-b-rollback-proof.v3",
        "status": "ok",
        "source_head": source_head,
        "base_commit": BASE_COMMIT,
        "durable_commits": commits,
        "b1": b1,
        "b2": b2,
        "revert_order": ["b1", "b2", "shared-integration"],
        **revert_order,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="prove durable Gate-B component rollback")
    parser.add_argument("--json", action="store_true", help="emit machine-readable evidence")
    parser.add_argument(
        "--repo",
        type=Path,
        default=ROOT,
        help="repository checkout to inspect (defaults to the project root)",
    )
    args = parser.parse_args()
    try:
        result = run_proof(args.repo)
    except ProofHistoryUnavailable as exc:
        if args.json:
            print(
                json.dumps(
                    {
                        "schema_version": "contextguard.gate-b-rollback-proof.v3",
                        "status": "unavailable",
                        "error": str(exc),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        else:
            print(f"gate-b rollback proof: UNAVAILABLE: {exc}")
        return 2
    except ProofError as exc:
        if args.json:
            print(
                json.dumps(
                    {"schema_version": "contextguard.gate-b-rollback-proof.v3", "status": "fail", "error": str(exc)},
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
