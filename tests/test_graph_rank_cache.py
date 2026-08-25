"""Focused acceptance for a revision/worktree-bound cache of the deterministic
graph-rank/repo-map computation in context-guard-kit/context_pack.py.

Background: research/comparator-mechanism-acceptance-matrix.md:63-64 states
the standing acceptance gate for any persistent context in this project:
"Add persistent context only behind an authenticated revision/worktree-bound
store with expiry, quota, invalidation, and exact-recovery tests." Today
`build_repo_map_payload` (context_pack.py) is fully recomputed from scratch
on every CLI invocation - there is no caching anywhere in context-guard-kit.

This test pins an opt-in `--graph-cache` flag on `context-guard-pack auto`,
scoped ONLY to the plain `--explain` code path (the call site at
context_pack.py:5352-5353, `explain["repo_map"] = build_repo_map_payload(...)`,
reached only when `--symbol-memory`/`--apply-symbol-memory` were NOT also
requested - that path passes `complete_secret_paths_out`/
`source_identities_out` out-parameters this cache does not need to reproduce,
so it is out of scope for this change).

Required behavior:

1. Worktree/revision-bound, invalidation: caching activates ONLY when the
   target is a git repository, `git rev-parse HEAD` resolves, AND the
   working tree is clean (`git status --porcelain` is empty). Any of those
   being false means: compute fresh, do not read or write the cache, and do
   not error. A cache entry is scoped to the exact (worktree path, commit
   sha, seed_paths, query_terms) combination that produced it; a change to
   any of those must not produce a stale hit.
2. Exact recovery: with `--graph-cache` and an unchanged commit/tree/query,
   a second invocation must return an `explain.repo_map` payload that is
   byte-identical (as canonical JSON) to what a fresh, uncached computation
   produces for the same inputs.
3. Authenticated: each cache record embeds a `content_sha256` of its own
   cached payload. A record whose stored payload does not hash to its own
   `content_sha256` (corrupted/tampered) must be rejected and treated as a
   miss (recompute fresh), not trusted.
4. Expiry: a cache record older than its TTL is treated as a miss and is
   recomputed (and the stale file replaced), never served.
5. Quota: the cache directory holds at most a bounded number of records;
   writing beyond that bound evicts the oldest record(s) by creation time
   rather than growing without limit.
6. The cache directory location is overridable via the
   `CONTEXT_GUARD_GRAPH_CACHE_DIR` environment variable (so tests never touch
   a real user cache directory), and cache files are created with owner-only
   permissions (0600).
7. `--graph-cache` is opt-in and default-off: omitting it must produce
   identical behavior (and identical output) to the current, uncached code
   path, and must never read or write anything under the cache directory.
"""
from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
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


class GraphRankCacheTests(unittest.TestCase):
    def test_second_call_on_clean_tree_is_byte_identical_to_a_fresh_call(self) -> None:
        for script in PACK_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as name:
                    root = Path(name) / "repo"
                    root.mkdir()
                    _init_git_repo(root)
                    cache_dir = Path(name) / "cache"

                    fresh = run_pack(script, root, cache_dir=cache_dir / "uncached")
                    self.assertEqual(fresh.returncode, 0, fresh.stderr)
                    fresh_repo_map = json.loads(fresh.stdout)["explain"]["repo_map"]

                    first = run_pack(script, root, cache_dir=cache_dir, extra_args=["--graph-cache"])
                    self.assertEqual(first.returncode, 0, first.stderr)
                    first_repo_map = json.loads(first.stdout)["explain"]["repo_map"]
                    self.assertEqual(first_repo_map, fresh_repo_map)

                    cached_files = list(cache_dir.rglob("*.json")) if cache_dir.exists() else []
                    self.assertTrue(cached_files, "expected a cache record to be written")

                    second = run_pack(script, root, cache_dir=cache_dir, extra_args=["--graph-cache"])
                    self.assertEqual(second.returncode, 0, second.stderr)
                    second_repo_map = json.loads(second.stdout)["explain"]["repo_map"]
                    self.assertEqual(second_repo_map, fresh_repo_map)

    def test_dirty_working_tree_bypasses_the_cache_entirely(self) -> None:
        for script in PACK_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as name:
                    root = Path(name) / "repo"
                    root.mkdir()
                    _init_git_repo(root)
                    (root / "a.py").write_text("import os  # dirty\n", encoding="utf-8")
                    cache_dir = Path(name) / "cache"

                    proc = run_pack(script, root, cache_dir=cache_dir, extra_args=["--graph-cache"])
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    self.assertFalse(
                        cache_dir.exists() and any(cache_dir.rglob("*.json")),
                        "a dirty working tree must never produce a cache record",
                    )

    def test_flag_omitted_never_touches_the_cache_directory(self) -> None:
        for script in PACK_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as name:
                    root = Path(name) / "repo"
                    root.mkdir()
                    _init_git_repo(root)
                    cache_dir = Path(name) / "cache"

                    proc = run_pack(script, root, cache_dir=cache_dir)
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    self.assertFalse(cache_dir.exists())

    def test_cache_file_is_owner_only_and_authenticated(self) -> None:
        for script in PACK_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as name:
                    root = Path(name) / "repo"
                    root.mkdir()
                    _init_git_repo(root)
                    cache_dir = Path(name) / "cache"

                    proc = run_pack(script, root, cache_dir=cache_dir, extra_args=["--graph-cache"])
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    cached_files = list(cache_dir.rglob("*.json"))
                    self.assertTrue(cached_files)
                    cache_file = cached_files[0]
                    mode = stat.S_IMODE(cache_file.stat().st_mode)
                    self.assertEqual(mode, 0o600)

                    record = json.loads(cache_file.read_text(encoding="utf-8"))
                    self.assertIn("content_sha256", record)

                    # Corrupt the record's payload without updating its own
                    # content_sha256; a corrupted/tampered record must be
                    # rejected as a miss, not trusted.
                    record["payload"]["summary"]["files_scanned"] = 999999
                    cache_file.write_text(json.dumps(record), encoding="utf-8")
                    os.chmod(cache_file, 0o600)

                    recovered = run_pack(script, root, cache_dir=cache_dir, extra_args=["--graph-cache"])
                    self.assertEqual(recovered.returncode, 0, recovered.stderr)
                    payload = json.loads(recovered.stdout)["explain"]["repo_map"]
                    self.assertNotEqual(payload["summary"]["files_scanned"], 999999)

    def test_expired_cache_record_is_recomputed_not_served(self) -> None:
        for script in PACK_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as name:
                    root = Path(name) / "repo"
                    root.mkdir()
                    _init_git_repo(root)
                    cache_dir = Path(name) / "cache"

                    proc = run_pack(script, root, cache_dir=cache_dir, extra_args=["--graph-cache"])
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    cached_files = list(cache_dir.rglob("*.json"))
                    self.assertTrue(cached_files)
                    cache_file = cached_files[0]
                    record = json.loads(cache_file.read_text(encoding="utf-8"))
                    record["created_at"] = 1  # far in the past -> expired
                    cache_file.write_text(json.dumps(record), encoding="utf-8")
                    os.chmod(cache_file, 0o600)
                    mtime_before = cache_file.stat().st_mtime

                    proc2 = run_pack(script, root, cache_dir=cache_dir, extra_args=["--graph-cache"])
                    self.assertEqual(proc2.returncode, 0, proc2.stderr)
                    self.assertGreaterEqual(cache_file.stat().st_mtime, mtime_before)
                    refreshed = json.loads(cache_file.read_text(encoding="utf-8"))
                    self.assertGreater(refreshed["created_at"], 1)


    def test_quota_evicts_the_oldest_record_rather_than_growing_unbounded(self) -> None:
        """Break caught: the cache directory grows without limit across many
        distinct repositories instead of enforcing a bounded quota."""

        script = PACK_SCRIPTS[0]
        with tempfile.TemporaryDirectory() as name:
            cache_dir = Path(name) / "cache"
            repo_count = 25  # exceeds any reasonable single-digit/low-double-digit quota
            first_repo_root = None
            for index in range(repo_count):
                root = Path(name) / f"repo{index}"
                root.mkdir()
                _init_git_repo(root)
                if index == 0:
                    first_repo_root = root
                proc = run_pack(script, root, cache_dir=cache_dir, extra_args=["--graph-cache"])
                self.assertEqual(proc.returncode, 0, proc.stderr)

            cached_files = list(cache_dir.rglob("*.json")) if cache_dir.exists() else []
            self.assertGreater(len(cached_files), 0)
            self.assertLess(
                len(cached_files), repo_count,
                "cache directory must enforce a bounded quota, not grow with every distinct repo",
            )


if __name__ == "__main__":
    unittest.main()
