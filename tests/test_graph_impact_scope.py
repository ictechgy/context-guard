"""Focused acceptance for roadmap item B3: diff-scoped impact-radius metadata
(research/graph-cache-advisory-integration-roadmap-20260825.md section 3,
"B3 (impact-subgraph scoping)").

Background: `--diff` already seeds changed-file candidates into ordinary
selection ranking (`collect_diff_candidates`), but nothing in the repo_map
payload tells a reader which OTHER files are structurally connected to the
diff via import edges - the "impact radius" the roadmap idea describes.
This is deliberately scoped to exposing that radius as metadata, not
pruning the rest of the repo_map payload - a smaller, safer increment than
full subgraph filtering (see the roadmap's own "needs its own small
validation... before it's worth wiring into a live campaign" caveat for
this whole Later tier).

This test pins a new optional `--graph-impact-scope` flag (with an optional
`--graph-impact-scope-depth <int>`, default 1) on `context-guard-pack auto`:

1. Omitting the flag must leave `explain.repo_map.graph` exactly as it is
   today (no `impact_scope` key) - existing behavior unaffected.
2. With the flag and `--diff`, `explain.repo_map.graph.impact_scope` must
   report `changed_paths` (from the diff) and `scoped_paths` (every path
   within `depth` import-edge hops of a changed path, undirected, not
   including files with no edge path to a changed file).
3. A file that only shares no edge with the diff (fully unrelated) must
   never appear in `scoped_paths` regardless of depth.
4. Increasing `--graph-impact-scope-depth` must widen `scoped_paths` to
   include farther transitive neighbors that a smaller depth excludes.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
KIT_DIR = REPO_ROOT / "context-guard-kit"
PLUGIN_BIN = REPO_ROOT / "plugins" / "context-guard" / "bin"
PACK_SCRIPTS = [KIT_DIR / "context_pack.py", PLUGIN_BIN / "context-guard-pack"]


def _init_chain_repo(root: Path) -> None:
    """a.py <- b.py <- c.py (b imports a, c imports b), plus an unrelated d.py."""
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=root, check=True)
    (root / "a.py").write_text("def base():\n    return 1\n", encoding="utf-8")
    (root / "b.py").write_text("from a import base\n\ndef mid():\n    return base()\n", encoding="utf-8")
    (root / "c.py").write_text("from b import mid\n\ndef top():\n    return mid()\n", encoding="utf-8")
    (root / "d.py").write_text("def unrelated():\n    return 0\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=root, check=True)


def run_pack(
    script: Path, root: Path, *, extra_args: list[str] | None = None
) -> subprocess.CompletedProcess[str]:
    args = [
        sys.executable, str(script), "auto", "--root", str(root),
        "--query", "explain the impact scope",
        "--explain", "--json",
    ]
    if extra_args:
        args.extend(extra_args)
    env = dict(os.environ)
    return subprocess.run(args, text=True, capture_output=True, env=env)


class GraphImpactScopeTests(unittest.TestCase):
    def test_flag_omitted_never_adds_impact_scope(self) -> None:
        for script in PACK_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as name:
                    root = Path(name) / "repo"
                    root.mkdir()
                    _init_chain_repo(root)
                    (root / "b.py").write_text(
                        "from a import base\n\ndef mid():\n    return base() + 1\n",
                        encoding="utf-8",
                    )

                    proc = run_pack(script, root, extra_args=["--diff", "worktree"])
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    graph = json.loads(proc.stdout)["explain"]["repo_map"]["graph"]
                    self.assertNotIn("impact_scope", graph)

    def test_depth_one_scope_includes_direct_neighbors_only(self) -> None:
        for script in PACK_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as name:
                    root = Path(name) / "repo"
                    root.mkdir()
                    _init_chain_repo(root)
                    (root / "b.py").write_text(
                        "from a import base\n\ndef mid():\n    return base() + 1\n",
                        encoding="utf-8",
                    )

                    proc = run_pack(
                        script, root,
                        extra_args=["--diff", "worktree", "--graph-impact-scope"],
                    )
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    scope = json.loads(proc.stdout)["explain"]["repo_map"]["graph"]["impact_scope"]

                    self.assertEqual(scope["changed_paths"], ["b.py"])
                    self.assertEqual(scope["depth"], 1)
                    scoped = set(scope["scoped_paths"])
                    self.assertIn("a.py", scoped, "b.py imports a.py - one edge hop away")
                    self.assertIn("c.py", scoped, "c.py imports b.py - one edge hop away")
                    self.assertNotIn("d.py", scoped, "d.py has no import edge to the diff at all")

    def test_deeper_scope_widens_beyond_a_shallower_one(self) -> None:
        script = PACK_SCRIPTS[0]
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "repo"
            root.mkdir()
            _init_chain_repo(root)
            # Change a.py itself: at depth 1 only b.py (which imports a.py)
            # is in scope; c.py is two edge hops away (c -> b -> a) and only
            # appears once depth is widened to 2.
            (root / "a.py").write_text("def base():\n    return 2\n", encoding="utf-8")

            shallow = run_pack(
                script, root,
                extra_args=[
                    "--diff", "worktree", "--graph-impact-scope",
                    "--graph-impact-scope-depth", "1",
                ],
            )
            self.assertEqual(shallow.returncode, 0, shallow.stderr)
            shallow_scoped = set(
                json.loads(shallow.stdout)["explain"]["repo_map"]["graph"]["impact_scope"]["scoped_paths"]
            )
            self.assertIn("b.py", shallow_scoped)
            self.assertNotIn("c.py", shallow_scoped)

            deep = run_pack(
                script, root,
                extra_args=[
                    "--diff", "worktree", "--graph-impact-scope",
                    "--graph-impact-scope-depth", "2",
                ],
            )
            self.assertEqual(deep.returncode, 0, deep.stderr)
            deep_scoped = set(
                json.loads(deep.stdout)["explain"]["repo_map"]["graph"]["impact_scope"]["scoped_paths"]
            )
            self.assertIn("b.py", deep_scoped)
            self.assertIn("c.py", deep_scoped, "c.py -> b.py -> a.py is two edge hops from the diff")


if __name__ == "__main__":
    unittest.main()
