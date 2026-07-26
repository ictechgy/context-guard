from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_gate_b_rollback.py"
SPEC = importlib.util.spec_from_file_location("verify_gate_b_rollback", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"unable to load rollback proof script: {SCRIPT}")
rollback_proof = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rollback_proof)


class GateBRollbackProofTests(unittest.TestCase):
    def make_snapshot_repo(self, root: Path) -> Path:
        repo = root / "snapshot"
        repo.mkdir()
        rollback_proof.run_git(repo, "init", "--quiet")
        (repo / "README.md").write_text("snapshot\n", encoding="utf-8")
        rollback_proof.run_git(repo, "add", "README.md")
        rollback_proof.run_git(repo, "commit", "--quiet", "-m", "snapshot")
        return repo

    def test_b1_b2_apply_and_revert_independently_before_shared_integration(self) -> None:
        try:
            result = rollback_proof.run_proof(ROOT)
        except rollback_proof.ProofHistoryUnavailable as exc:
            self.skipTest(str(exc))

        self.assertEqual(result["status"], "ok")
        self.assertEqual(
            result["schema_version"],
            "contextguard.gate-b-rollback-proof.v3",
        )
        self.assertEqual(
            set(result["durable_commits"]),
            {"bless", "b1", "b2", "shared-integration"},
        )
        self.assertEqual(
            result["revert_order"],
            ["b1", "b2", "shared-integration"],
        )
        self.assertEqual(
            result["b1"]["reverted_tree"],
            rollback_proof.run_git(
                ROOT,
                "rev-parse",
                f"{result['durable_commits']['bless']}^{{tree}}",
            ).stdout.strip(),
        )
        self.assertEqual(
            result["b2"]["reverted_tree"],
            result["b1"]["reverted_tree"],
        )
        self.assertNotEqual(
            result["b1_only_revert_tree"],
            result["b2_only_revert_tree"],
        )

    def test_snapshot_repo_reports_history_unavailable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-snapshot-") as tmp:
            repo = self.make_snapshot_repo(Path(tmp))
            with self.assertRaisesRegex(
                rollback_proof.ProofHistoryUnavailable,
                "full Gate-B proof history is unavailable",
            ):
                rollback_proof.run_proof(repo)

    def test_squashed_history_reports_missing_proof_commits_as_unavailable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-squash-") as tmp:
            repo = self.make_snapshot_repo(Path(tmp))
            base_commit = rollback_proof.run_git(repo, "rev-parse", "HEAD").stdout.strip()
            (repo / "README.md").write_text("squashed feature tree\n", encoding="utf-8")
            rollback_proof.run_git(repo, "add", "README.md")
            rollback_proof.run_git(repo, "commit", "--quiet", "-m", "squashed change")
            with mock.patch.object(rollback_proof, "BASE_COMMIT", base_commit):
                with self.assertRaisesRegex(
                    rollback_proof.ProofHistoryUnavailable,
                    "reachable commit 'proof: establish Gate-B-free residual' was not found",
                ):
                    rollback_proof.run_proof(repo)

    def test_cli_distinguishes_unavailable_history_from_failed_proof(self) -> None:
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-cli-") as tmp:
            repo = self.make_snapshot_repo(Path(tmp))
            proc = subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--json",
                    "--repo",
                    str(repo),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

        self.assertEqual(proc.returncode, 2, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "unavailable")
        self.assertIn("full Gate-B proof history is unavailable", payload["error"])


if __name__ == "__main__":
    unittest.main()
