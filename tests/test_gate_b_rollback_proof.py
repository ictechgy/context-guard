from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_gate_b_rollback.py"
SPEC = importlib.util.spec_from_file_location("verify_gate_b_rollback", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"unable to load rollback proof script: {SCRIPT}")
rollback_proof = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rollback_proof)


class GateBRollbackProofTests(unittest.TestCase):
    def test_b1_b2_apply_and_revert_independently_before_shared_integration(self) -> None:
        result = rollback_proof.run_proof(ROOT)

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


if __name__ == "__main__":
    unittest.main()
