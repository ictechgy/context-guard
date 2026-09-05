from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.test_contextguard_stage2_feasibility import (
    PROVIDER_FREE_SUPPORT_PATHS,
    RECEIPT_COMPANION_INVENTORY,
    REPO_ROOT,
    historical_production_surface_inventory,
    provider_free_changed_paths,
    receipt_companion_surface_inventory,
    validate_receipt_companion_surface_inventory,
    validate_provider_free_changed_paths,
    validate_stage2_historical_baseline_identity,
)


RECEIPT_GUARD_PATH = (
    REPO_ROOT / "packages/context-guard-receipt/scripts/verify_protected_surfaces.py"
)


def load_guard_module():
    spec = importlib.util.spec_from_file_location("receipt_protected_surface_guard", RECEIPT_GUARD_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("receipt guard module is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ContextGuardReceiptBoundaryTests(unittest.TestCase):
    def test_receipt_companion_is_partitioned_from_historical_inventory(self) -> None:
        historical_inventory = historical_production_surface_inventory()
        validate_stage2_historical_baseline_identity(historical_inventory)
        self.assertTrue(
            all(
                not entry["path"].startswith("packages/context-guard-receipt/")
                for entry in historical_inventory
            )
        )

        companion_inventory = receipt_companion_surface_inventory()
        validate_receipt_companion_surface_inventory(companion_inventory)
        self.assertEqual(companion_inventory, RECEIPT_COMPANION_INVENTORY)

        changed_hash = copy.deepcopy(companion_inventory)
        changed_hash[0]["sha256"] = "0" * 64
        with self.assertRaises(AssertionError):
            validate_receipt_companion_surface_inventory(changed_hash)

    def test_changed_paths_allow_only_the_exact_receipt_companion_paths(self) -> None:
        allowed = {
            *(entry["path"] for entry in RECEIPT_COMPANION_INVENTORY),
            *PROVIDER_FREE_SUPPORT_PATHS,
        }
        validate_provider_free_changed_paths(allowed)

        rejected_paths = {
            "packages/context-guard-receipt/unknown.py",
            "packages/context-guard-receipt-copy/scripts/verify_protected_surfaces.py",
            "packages/context-guard-receipt/../context-guard-receipt/unknown.py",
            "/packages/context-guard-receipt/scripts/verify_protected_surfaces.py",
            "plugins/context-guard/bin/context-guard-stage2",
            ".claude/settings.json",
            ".claude/hooks/contextguard-observer",
            "research/contextguard-stage2/host-observability.json",
            "research/contextguard-broker/fixtures/positive/decision-receipt.json",
            "research/unrelated-user-notes.md",
            "tests/unrelated_receipt_test.py",
        }
        for path in rejected_paths:
            with self.subTest(path=path), self.assertRaises(AssertionError):
                validate_provider_free_changed_paths({path})

    def test_changed_path_scan_uses_only_the_committed_merge_base_range(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            subprocess.run(
                ["git", "init", "--quiet", "--initial-branch=main"],
                cwd=repository,
                check=True,
            )
            baseline = repository / "baseline.txt"
            baseline.write_text("baseline\n", encoding="utf-8")
            subprocess.run(["git", "add", "baseline.txt"], cwd=repository, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Context Guard Receipt Tests",
                    "-c",
                    "user.email=context-guard-receipt@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "baseline",
                ],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "update-ref", "refs/remotes/origin/main", "HEAD"],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "switch", "--quiet", "-c", "feature"],
                cwd=repository,
                check=True,
            )
            committed = repository / "packages/context-guard-receipt/README.md"
            committed.parent.mkdir(parents=True)
            committed.write_text("receipt\n", encoding="utf-8")
            subprocess.run(
                ["git", "add", "packages/context-guard-receipt/README.md"],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Context Guard Receipt Tests",
                    "-c",
                    "user.email=context-guard-receipt@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "feature",
                ],
                cwd=repository,
                check=True,
            )
            baseline.write_text("dirty worktree\n", encoding="utf-8")
            (repository / "untracked.txt").write_text("user owned\n", encoding="utf-8")

            self.assertEqual(
                provider_free_changed_paths(repo_root=repository),
                {"packages/context-guard-receipt/README.md"},
            )

    def test_changed_path_scan_rejects_ambiguous_criss_cross_merge_bases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            subprocess.run(["git", "init", "--quiet"], cwd=repository, check=True)

            def git_output(arguments: list[str], input_text: str = "") -> str:
                return subprocess.run(
                    [
                        "git",
                        "-c",
                        "user.name=Context Guard Receipt Tests",
                        "-c",
                        "user.email=context-guard-receipt@example.invalid",
                        *arguments,
                    ],
                    cwd=repository,
                    check=True,
                    input=input_text,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                ).stdout.strip()

            base_blob = git_output(["hash-object", "-w", "--stdin"], "base\n")
            changed_blob = git_output(["hash-object", "-w", "--stdin"], "forbidden\n")
            base_tree = git_output(
                ["mktree"], f"100644 blob {base_blob}\tforbidden.txt\n"
            )
            changed_tree = git_output(
                ["mktree"], f"100644 blob {changed_blob}\tforbidden.txt\n"
            )

            def commit(tree: str, parents: tuple[str, ...], message: str) -> str:
                arguments = ["commit-tree", tree]
                for parent in parents:
                    arguments.extend(("-p", parent))
                return git_output(arguments, f"{message}\n")

            base = commit(base_tree, (), "base")
            changed_parent = commit(changed_tree, (base,), "changed parent")
            unchanged_parent = commit(base_tree, (base,), "unchanged parent")
            head = commit(changed_tree, (changed_parent, unchanged_parent), "feature merge")
            origin_main = commit(base_tree, (unchanged_parent, changed_parent), "main merge")
            subprocess.run(
                ["git", "update-ref", "refs/heads/feature", head],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "symbolic-ref", "HEAD", "refs/heads/feature"],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "update-ref", "refs/remotes/origin/main", origin_main],
                cwd=repository,
                check=True,
            )
            merge_bases = git_output(
                ["merge-base", "--all", "origin/main", "HEAD"]
            ).splitlines()
            self.assertEqual(len(merge_bases), 2)

            with self.assertRaises(AssertionError):
                provider_free_changed_paths(repo_root=repository)

    def test_changed_path_scan_overrides_ignore_submodules_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            subprocess.run(["git", "init", "--quiet"], cwd=repository, check=True)

            def git_output(arguments: list[str], input_text: str = "") -> str:
                return subprocess.run(
                    [
                        "git",
                        "-c",
                        "user.name=Context Guard Receipt Tests",
                        "-c",
                        "user.email=context-guard-receipt@example.invalid",
                        *arguments,
                    ],
                    cwd=repository,
                    check=True,
                    input=input_text,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                ).stdout.strip()

            empty_tree = git_output(["mktree"])

            def commit(tree: str, parents: tuple[str, ...], message: str) -> str:
                arguments = ["commit-tree", tree]
                for parent in parents:
                    arguments.extend(("-p", parent))
                return git_output(arguments, f"{message}\n")

            submodule_base = commit(empty_tree, (), "submodule base")
            submodule_changed = commit(
                empty_tree, (submodule_base,), "submodule changed"
            )
            base_tree = git_output(
                ["mktree"],
                f"160000 commit {submodule_base}\tforbidden-submodule\n",
            )
            changed_tree = git_output(
                ["mktree"],
                f"160000 commit {submodule_changed}\tforbidden-submodule\n",
            )
            base = commit(base_tree, (), "base")
            head = commit(changed_tree, (base,), "feature")
            subprocess.run(
                ["git", "update-ref", "refs/heads/feature", head],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "symbolic-ref", "HEAD", "refs/heads/feature"],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "update-ref", "refs/remotes/origin/main", base],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "config", "diff.ignoreSubmodules", "all"],
                cwd=repository,
                check=True,
            )

            self.assertEqual(
                provider_free_changed_paths(repo_root=repository),
                {"forbidden-submodule"},
            )

    def test_protected_surface_guard_checks_live_manifest_and_unsupported_semantics(self) -> None:
        result = subprocess.run(
            [sys.executable, str(RECEIPT_GUARD_PATH)],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("protected surfaces verified", result.stdout)

    def test_post_stage2_hash_exemptions_are_exact_and_bounded(self) -> None:
        guard = load_guard_module()
        self.assertEqual(
            guard.POST_STAGE2_PROTECTED_SHA256,
            {
                ".claude-plugin/marketplace.json": "8f61b70bba4c1ea52c988b17db4348ccb81bee11b3ef46a8ea97ffb41ed04e59",
                "context-guard-kit/benchmark_runner.py": "716dc6710923401ca5a5ab171ca652bcf1fa0094fae567f6e7f6ee1eda24cf71",
                "context-guard-kit/context_pack.py": "6bc42070e4d3d0dea3e424388dbb02c352e2879bacf3788cb3df343f64cd5e75",
                "context-guard-kit/context_guard_commands.py": "0920128f013a8b5be62253fbf34aa917d2b30b7c6e99bc656067102d5fba727a",
                "context-guard-kit/guard_large_read.py": "81ddea324fdf927dc778b8d9466eb542f1941da40303a2ba4d16a6d68ab448e2",
                "context-guard-kit/setup_wizard.py": "c4352c4a19f4c9c30879898b6c762f03e799c4f2dc4ae5812393a7689686cde7",
                "package.json": "18811b92460edf141a379f325b989ca3559150b736191ae074056ef7a10fb3b5",
                "plugins/context-guard/.claude-plugin/plugin.json": "68d2bd26750767e6c22cc7076762223b6d324611433e957945f593bba7f9d016",
                "plugins/context-guard/bin/context-guard-bench": "716dc6710923401ca5a5ab171ca652bcf1fa0094fae567f6e7f6ee1eda24cf71",
                "plugins/context-guard/bin/context-guard-guard-read": "81ddea324fdf927dc778b8d9466eb542f1941da40303a2ba4d16a6d68ab448e2",
                "plugins/context-guard/bin/context-guard-pack": "6bc42070e4d3d0dea3e424388dbb02c352e2879bacf3788cb3df343f64cd5e75",
                "plugins/context-guard/bin/context-guard-setup": "c4352c4a19f4c9c30879898b6c762f03e799c4f2dc4ae5812393a7689686cde7",
                "plugins/context-guard/lib/context_guard_commands.py": "0920128f013a8b5be62253fbf34aa917d2b30b7c6e99bc656067102d5fba727a",
                "scripts/prepublish_check.py": "54a968be3a125cfa9fabac2a38f410120de61e470525423dee103a47d003317b",
                "scripts/release_smoke.py": "b18490bddd7d74e12a3405ceca22aaea0085dbbb688a21f143545796a9018102",
            },
        )

    def test_guard_rejects_empty_or_rewritten_manifest_shapes(self) -> None:
        guard = load_guard_module()
        manifest = json.loads(
            (REPO_ROOT / "research/contextguard-stage2/protected-surface-manifest.json").read_text(
                encoding="utf-8"
            )
        )
        rewritten = copy.deepcopy(manifest)
        rewritten["entries"] = list(reversed(rewritten["entries"]))

        for candidate in ({}, rewritten):
            with self.subTest(candidate="empty" if not candidate else "rewritten"), self.assertRaises(
                guard.VerificationError
            ):
                guard.validate_protected_manifest_shape(candidate)

    def test_guard_rejects_a_mutated_stage2_artifact_in_controlled_copy(self) -> None:
        guard = load_guard_module()
        with tempfile.TemporaryDirectory() as temporary_directory:
            copied_root = Path(temporary_directory)
            source_root = REPO_ROOT / "research/contextguard-stage2"
            copied_stage2_root = copied_root / "research/contextguard-stage2"
            copied_stage2_root.mkdir(parents=True)
            for artifact in source_root.glob("*.json"):
                shutil.copyfile(artifact, copied_stage2_root / artifact.name)
            host_record = copied_stage2_root / "host-observability.json"
            host_record.write_bytes(host_record.read_bytes() + b"\n")

            with self.assertRaises(guard.VerificationError):
                guard.verify_stage2_artifact_integrity(copied_root)


if __name__ == "__main__":
    unittest.main()
