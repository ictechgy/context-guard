"""Focused acceptance for roadmap item B2: per-invocation graph-cache TTL
override (research/graph-cache-advisory-integration-roadmap-20260825.md
section 3, "B2 (per-stage TTL)").

Background: `--graph-cache` records currently always expire after the fixed
`GRAPH_CACHE_TTL_SECONDS` (3600s, see `_graph_cache_loaded_payload` in
context-guard-kit/context_pack.py). The roadmap's B2 idea is a per-stage TTL
policy for a wclass-advisory campaign (short TTL for a cheap-tier lane,
forced-fresh for the expensive tier) - the primitive this repository can
actually own is a CLI override of the expiry window; the campaign-side
per-stage policy is out of scope here (it lives in a wrapper/task-authoring
convention, not context-guard-kit).

This test pins a new optional `--graph-cache-ttl-seconds <N>` flag on
`context-guard-pack auto`:

1. Omitting the flag must behave identically to today (default TTL, existing
   test_graph_rank_cache.py / test_graph_cache_p0.py behavior unaffected).
2. A record created under a larger custom TTL must still be served (a cache
   hit) at an age that would already be expired under the fixed default
   3600s TTL, when the same larger custom TTL is passed again.
3. A record created under a SMALLER custom TTL must be treated as expired
   (recomputed, not served) at an age that is still well within the fixed
   default 3600s TTL.
4. The `repo_map_cache` receipt's `ttl_expires_at` must reflect the custom
   TTL actually used for that invocation (created_at + custom TTL), not the
   fixed default.
"""
from __future__ import annotations

import json
import os
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
DEFAULT_TTL_SECONDS = 3600


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
        "--explain", "--json", "--graph-cache",
    ]
    if extra_args:
        args.extend(extra_args)
    env = dict(os.environ)
    env["CONTEXT_GUARD_GRAPH_CACHE_DIR"] = str(cache_dir)
    return subprocess.run(args, text=True, capture_output=True, env=env)


class GraphCacheTtlOverrideTests(unittest.TestCase):
    def test_flag_omitted_uses_the_fixed_default_ttl(self) -> None:
        for script in PACK_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as name:
                    root = Path(name) / "repo"
                    root.mkdir()
                    _init_git_repo(root)
                    cache_dir = Path(name) / "cache"

                    proc = run_pack(script, root, cache_dir=cache_dir)
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    cached_files = list(cache_dir.rglob("*.json"))
                    self.assertEqual(len(cached_files), 1)
                    record = json.loads(cached_files[0].read_text(encoding="utf-8"))

                    receipt = json.loads(proc.stdout)["explain"]["repo_map_cache"]
                    expires_at = datetime.fromisoformat(receipt["ttl_expires_at"])
                    expected = datetime.fromtimestamp(
                        record["created_at"] + DEFAULT_TTL_SECONDS, tz=timezone.utc
                    )
                    self.assertAlmostEqual(
                        expires_at.timestamp(), expected.timestamp(), delta=2
                    )

    def test_larger_custom_ttl_serves_a_record_expired_under_the_default(self) -> None:
        for script in PACK_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as name:
                    root = Path(name) / "repo"
                    root.mkdir()
                    _init_git_repo(root)
                    cache_dir = Path(name) / "cache"

                    custom_ttl = DEFAULT_TTL_SECONDS * 10
                    first = run_pack(
                        script, root, cache_dir=cache_dir,
                        extra_args=["--graph-cache-ttl-seconds", str(custom_ttl)],
                    )
                    self.assertEqual(first.returncode, 0, first.stderr)
                    cached_files = list(cache_dir.rglob("*.json"))
                    self.assertEqual(len(cached_files), 1)
                    cache_file = cached_files[0]
                    record = json.loads(cache_file.read_text(encoding="utf-8"))
                    # Older than the fixed default TTL, but well within the custom one.
                    record["created_at"] = record["created_at"] - (DEFAULT_TTL_SECONDS + 60)
                    cache_file.write_text(json.dumps(record), encoding="utf-8")
                    os.chmod(cache_file, 0o600)

                    second = run_pack(
                        script, root, cache_dir=cache_dir,
                        extra_args=["--graph-cache-ttl-seconds", str(custom_ttl)],
                    )
                    self.assertEqual(second.returncode, 0, second.stderr)
                    receipt = json.loads(second.stdout)["explain"]["repo_map_cache"]
                    self.assertTrue(receipt["hit"], "custom TTL should have kept the record valid")

    def test_smaller_custom_ttl_expires_a_record_still_fresh_under_the_default(self) -> None:
        for script in PACK_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as name:
                    root = Path(name) / "repo"
                    root.mkdir()
                    _init_git_repo(root)
                    cache_dir = Path(name) / "cache"

                    custom_ttl = 5
                    first = run_pack(
                        script, root, cache_dir=cache_dir,
                        extra_args=["--graph-cache-ttl-seconds", str(custom_ttl)],
                    )
                    self.assertEqual(first.returncode, 0, first.stderr)
                    cached_files = list(cache_dir.rglob("*.json"))
                    self.assertEqual(len(cached_files), 1)
                    cache_file = cached_files[0]
                    record = json.loads(cache_file.read_text(encoding="utf-8"))
                    # Still well within the fixed default TTL, but past the custom one.
                    record["created_at"] = record["created_at"] - (custom_ttl + 5)
                    cache_file.write_text(json.dumps(record), encoding="utf-8")
                    os.chmod(cache_file, 0o600)

                    second = run_pack(
                        script, root, cache_dir=cache_dir,
                        extra_args=["--graph-cache-ttl-seconds", str(custom_ttl)],
                    )
                    self.assertEqual(second.returncode, 0, second.stderr)
                    receipt = json.loads(second.stdout)["explain"]["repo_map_cache"]
                    self.assertFalse(
                        receipt["hit"], "custom TTL should have expired the stale record"
                    )


if __name__ == "__main__":
    unittest.main()
