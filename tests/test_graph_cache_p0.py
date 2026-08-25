"""Focused acceptance for the P0 graph-cache hardening spec in
research/graph-cache-advisory-integration-roadmap-20260825.md section 4.

Background: the `--graph-cache` flag landed in
context-guard-kit/context_pack.py keys cache records on
`(os.path.realpath(root), revision, seed_paths, query_terms)` (see
`_graph_cache_path`) and exposes an externally-overridable cache location via
the `CONTEXT_GUARD_GRAPH_CACHE_DIR` environment variable (`_graph_cache_directory`),
but neither the resolved absolute worktree path independence nor the
externally-supplied directory's symlink safety nor any machine-readable
cache receipt are covered by the existing focused suite
(tests/test_graph_rank_cache.py). This file pins the three P0 items from the
roadmap's section 4:

1. (roadmap A2) Cache key independence from the worktree's absolute path:
   two different checkouts of the identical commit and identical resolved
   file content must hit the same cache entry instead of each writing its
   own, path-keyed record.
2. (roadmap A3, re-scoped) Symlink safety on the externally-configured cache
   directory: `CONTEXT_GUARD_GRAPH_CACHE_DIR` pointing at (or through) a
   symlink must never be followed for a write - the existing "an unsafe
   condition means the cache is silently bypassed, not an error" contract
   (see the dirty-working-tree case in test_graph_rank_cache.py) extends to
   this case.
3. (roadmap A4) A machine-readable cache receipt: with `--graph-cache` and
   `--explain`, the CLI's `explain` block must carry a sibling
   `repo_map_cache` object reporting `hit` (bool), `graph_cache_key` (the
   cache record's own filename stem), `resolved_content_sha256` (the
   payload's content hash), and `ttl_expires_at` (ISO 8601, UTC). This key
   must be entirely absent when `--graph-cache` is omitted - the existing
   opt-in/default-off output-identity invariant (see
   test_flag_omitted_never_touches_the_cache_directory) is unaffected.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
KIT_DIR = REPO_ROOT / "context-guard-kit"
PLUGIN_BIN = REPO_ROOT / "plugins" / "context-guard" / "bin"
PACK_SCRIPTS = [KIT_DIR / "context_pack.py", PLUGIN_BIN / "context-guard-pack"]


def _init_git_repo(root: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=root, check=True)
    (root / "a.py").write_text("import os\n\ndef f():\n    return os.getcwd()\n", encoding="utf-8")
    (root / "b.py").write_text("from a import f\n\ndef g():\n    return f()\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=root, check=True)


def _head_sha(root: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()


def run_pack(
    script: Path, root: Path, *, cache_dir: Path, extra_args: list[str] | None = None
) -> subprocess.CompletedProcess[str]:
    args = [
        sys.executable, str(script), "auto", "--root", str(root),
        "--query", "explain the graph rank cache",
        "--explain", "--json",
    ]
    if extra_args:
        args.extend(extra_args)
    env = dict(os.environ)
    env["CONTEXT_GUARD_GRAPH_CACHE_DIR"] = str(cache_dir)
    return subprocess.run(args, text=True, capture_output=True, env=env)


def run_pack_from_cwd(
    script: Path, root: Path, *, cache_dir: Path, extra_args: list[str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Like run_pack, but invokes with `--root .` from inside `root`, so the
    literal --root argument text (embedded verbatim in the payload's
    suggested retrieval commands - see retrieval_for/repo_map_retrieval_for
    in context_pack.py) is identical across different worktree paths. This
    isolates the cache-key's use of the worktree path from that unrelated,
    legitimate content difference.
    """
    args = [
        sys.executable, str(script), "auto", "--root", ".",
        "--query", "explain the graph rank cache",
        "--explain", "--json",
    ]
    if extra_args:
        args.extend(extra_args)
    env = dict(os.environ)
    env["CONTEXT_GUARD_GRAPH_CACHE_DIR"] = str(cache_dir)
    return subprocess.run(args, text=True, capture_output=True, env=env, cwd=root)


class GraphCacheKeyIndependentOfWorktreePathTests(unittest.TestCase):
    def test_two_checkouts_of_the_identical_commit_share_one_cache_entry(self) -> None:
        for script in PACK_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as name:
                    root_a = Path(name) / "checkout-a"
                    root_a.mkdir()
                    _init_git_repo(root_a)

                    root_b = Path(name) / "an" / "entirely" / "different" / "checkout-b"
                    root_b.mkdir(parents=True)
                    shutil.copytree(root_a, root_b, dirs_exist_ok=True)
                    self.assertEqual(_head_sha(root_a), _head_sha(root_b))

                    cache_dir = Path(name) / "cache"

                    first = run_pack_from_cwd(script, root_a, cache_dir=cache_dir, extra_args=["--graph-cache"])
                    self.assertEqual(first.returncode, 0, first.stderr)
                    first_payload = json.loads(first.stdout)["explain"]["repo_map"]

                    cached_after_first = list(cache_dir.rglob("*.json"))
                    self.assertEqual(len(cached_after_first), 1)

                    second = run_pack_from_cwd(script, root_b, cache_dir=cache_dir, extra_args=["--graph-cache"])
                    self.assertEqual(second.returncode, 0, second.stderr)
                    second_payload = json.loads(second.stdout)["explain"]["repo_map"]
                    self.assertEqual(second_payload, first_payload)

                    cached_after_second = list(cache_dir.rglob("*.json"))
                    self.assertEqual(
                        len(cached_after_second),
                        1,
                        "a different absolute worktree path at the identical commit/content "
                        "must hit the existing record, not write a second one",
                    )


class GraphCacheDirectorySymlinkSafetyTests(unittest.TestCase):
    def test_symlinked_cache_directory_is_never_followed(self) -> None:
        for script in PACK_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as name:
                    root = Path(name) / "repo"
                    root.mkdir()
                    _init_git_repo(root)

                    real_target = Path(name) / "outside-target"
                    real_target.mkdir()
                    cache_link = Path(name) / "cache-link"
                    cache_link.symlink_to(real_target)

                    proc = run_pack(script, root, cache_dir=cache_link, extra_args=["--graph-cache"])
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    self.assertFalse(
                        any(real_target.rglob("*.json")),
                        "a symlinked cache directory must never be written through",
                    )


class GraphCacheReceiptTests(unittest.TestCase):
    def test_receipt_reports_miss_then_hit_and_is_absent_without_the_flag(self) -> None:
        for script in PACK_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as name:
                    root = Path(name) / "repo"
                    root.mkdir()
                    _init_git_repo(root)
                    cache_dir = Path(name) / "cache"

                    uncached = run_pack(script, root, cache_dir=cache_dir / "uncached")
                    self.assertEqual(uncached.returncode, 0, uncached.stderr)
                    self.assertNotIn("repo_map_cache", json.loads(uncached.stdout)["explain"])

                    first = run_pack(script, root, cache_dir=cache_dir, extra_args=["--graph-cache"])
                    self.assertEqual(first.returncode, 0, first.stderr)
                    first_explain = json.loads(first.stdout)["explain"]
                    receipt = first_explain["repo_map_cache"]
                    self.assertFalse(receipt["hit"])

                    cached_files = list(cache_dir.rglob("*.json"))
                    self.assertEqual(len(cached_files), 1)
                    self.assertEqual(receipt["graph_cache_key"], cached_files[0].stem)

                    record = json.loads(cached_files[0].read_text(encoding="utf-8"))
                    self.assertEqual(receipt["resolved_content_sha256"], record["content_sha256"])

                    expires_at = datetime.fromisoformat(receipt["ttl_expires_at"])
                    self.assertIsNotNone(expires_at.tzinfo)
                    self.assertGreater(expires_at, datetime.now(timezone.utc))

                    second = run_pack(script, root, cache_dir=cache_dir, extra_args=["--graph-cache"])
                    self.assertEqual(second.returncode, 0, second.stderr)
                    second_receipt = json.loads(second.stdout)["explain"]["repo_map_cache"]
                    self.assertTrue(second_receipt["hit"])
                    self.assertEqual(second_receipt["graph_cache_key"], receipt["graph_cache_key"])
                    self.assertEqual(
                        second_receipt["resolved_content_sha256"],
                        receipt["resolved_content_sha256"],
                    )


if __name__ == "__main__":
    unittest.main()
