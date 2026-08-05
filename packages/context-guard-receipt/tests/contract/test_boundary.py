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
    RECEIPT_COMPANION_INVENTORY,
    REPO_ROOT,
    production_surface_inventory,
    receipt_companion_surface_inventory,
    validate_production_surface_inventory,
    validate_receipt_companion_surface_inventory,
    validate_provider_free_changed_paths,
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
        historical_inventory = production_surface_inventory()
        validate_production_surface_inventory(historical_inventory)
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
        allowed = {entry["path"] for entry in RECEIPT_COMPANION_INVENTORY}
        validate_provider_free_changed_paths(allowed)

        rejected_paths = {
            "packages/context-guard-receipt/unknown.py",
            "packages/context-guard-receipt-copy/scripts/verify_protected_surfaces.py",
            "packages/context-guard-receipt/../context-guard-receipt/unknown.py",
            "/packages/context-guard-receipt/scripts/verify_protected_surfaces.py",
            "package.json",
            "plugins/context-guard/bin/context-guard-stage2",
            ".claude/settings.json",
            ".claude/hooks/contextguard-observer",
            "research/contextguard-stage2/host-observability.json",
            "research/contextguard-broker/fixtures/positive/decision-receipt.json",
        }
        for path in rejected_paths:
            with self.subTest(path=path), self.assertRaises(AssertionError):
                validate_provider_free_changed_paths({path})

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
