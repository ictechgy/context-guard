"""Advisory/default-off graph-cache correctness and filesystem hardening tests."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_SCRIPTS = [
    REPO_ROOT / "context-guard-kit" / "context_pack.py",
    REPO_ROOT / "plugins" / "context-guard" / "bin" / "context-guard-pack",
]


def init_repo(root: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
    (root / "a.py").write_text("def base():\n    return 1\n", encoding="utf-8")
    (root / "b.py").write_text(
        "from a import base\n\ndef middle():\n    return base()\n", encoding="utf-8"
    )
    (root / "c.py").write_text(
        "from b import middle\n\ndef top():\n    return middle()\n", encoding="utf-8"
    )
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
    (root / "a.py").write_text("def base():\n    return 2\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "change"], cwd=root, check=True)


def run_pack(
    script: Path,
    root: Path,
    cache_dir: Path | str,
    *extra: str,
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["CONTEXT_GUARD_GRAPH_CACHE_DIR"] = str(cache_dir)
    return subprocess.run(
        [
            sys.executable,
            str(script),
            "auto",
            "--root",
            ".",
            "--query",
            "base graph",
            "--diff",
            "HEAD^",
            "--budget-bytes",
            "8192",
            "--json",
            "--explain",
            "--graph-cache",
            "--no-artifact",
            *extra,
        ],
        cwd=root,
        env=env,
        text=True,
        capture_output=True,
    )


class GraphCacheAdvisoryHardeningTests(unittest.TestCase):
    def test_impact_scope_inputs_are_bound_into_the_cache_key(self) -> None:
        for script in PACK_SCRIPTS:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as name:
                root = Path(name) / "repo"
                root.mkdir()
                init_repo(root)
                cache = Path(name) / "cache"
                first = run_pack(script, root, cache)
                second = run_pack(
                    script,
                    root,
                    cache,
                    "--graph-impact-scope",
                    "--graph-impact-scope-depth",
                    "2",
                )
                self.assertEqual(first.returncode, 0, first.stderr)
                self.assertEqual(second.returncode, 0, second.stderr)
                first_explain = json.loads(first.stdout)["explain"]
                second_explain = json.loads(second.stdout)["explain"]
                self.assertNotEqual(
                    first_explain["repo_map_cache"]["graph_cache_key"],
                    second_explain["repo_map_cache"]["graph_cache_key"],
                )
                self.assertFalse(second_explain["repo_map_cache"]["hit"])
                self.assertEqual(
                    second_explain["repo_map"]["graph"]["impact_scope"]["depth"], 2
                )

    def test_cache_leaf_symlink_is_not_followed_or_overwritten(self) -> None:
        for script in PACK_SCRIPTS:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as name:
                root = Path(name) / "repo"
                root.mkdir()
                init_repo(root)
                cache = Path(name) / "cache"
                first = run_pack(script, root, cache)
                self.assertEqual(first.returncode, 0, first.stderr)
                cache_file = next(cache.glob("*.json"))
                target = Path(name) / "outside.txt"
                target.write_text("ORIGINAL", encoding="utf-8")
                cache_file.unlink()
                cache_file.symlink_to(target)

                second = run_pack(script, root, cache)
                self.assertEqual(second.returncode, 0, second.stderr)
                self.assertEqual(target.read_text(encoding="utf-8"), "ORIGINAL")
                receipt = json.loads(second.stdout)["explain"]["repo_map_cache"]
                self.assertFalse(receipt["active"])
                self.assertEqual(receipt["reason"], "cache_write_unavailable")

    def test_dirty_tree_reports_advisory_bypass_reason(self) -> None:
        for script in PACK_SCRIPTS:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as name:
                root = Path(name) / "repo"
                root.mkdir()
                init_repo(root)
                (root / "a.py").write_text("DIRTY = True\n", encoding="utf-8")
                cache = Path(name) / "cache"
                proc = run_pack(script, root, cache)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                receipt = json.loads(proc.stdout)["explain"]["repo_map_cache"]
                self.assertEqual(
                    receipt,
                    {
                        "active": False,
                        "advisory_only": True,
                        "hit": False,
                        "reason": "dirty_worktree",
                    },
                )
                self.assertFalse(cache.exists())

    def test_ttl_override_rejects_zero_negative_and_excessive_values(self) -> None:
        script = PACK_SCRIPTS[0]
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "repo"
            root.mkdir()
            init_repo(root)
            cache = Path(name) / "cache"
            for value in ("0", "-1", str(8 * 24 * 60 * 60)):
                with self.subTest(value=value):
                    proc = run_pack(script, root, cache, "--graph-cache-ttl-seconds", value)
                    self.assertEqual(proc.returncode, 2)
                    self.assertIn("graph-cache TTL must be between", proc.stderr)


if __name__ == "__main__":
    unittest.main()
