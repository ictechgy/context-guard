#!/usr/bin/env python3
"""Closed, provider-free CI test partitions with fail-closed discovery."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
try:
    sys.path.remove(str(ROOT))
except ValueError:
    pass
sys.path.insert(0, str(ROOT))

PARTITION_NAMES = ("fast", "core", "provider-free", "provider-live", "history", "serial")
FAST_MODULES = (
    "tests.test_workflows",
    "tests.test_release_assets",
    "tests.test_release_candidate_smoke",
    "tests.test_context_pack_p1_p2_hardening",
    "tests.test_context_guard_task_memory",
    "tests.test_longitudinal_study_protocol",
    "tests.test_contextguard_stage2_completion",
)
HISTORY_MODULES = (
    "tests.test_gate_b_rollback_proof",
    "tests.test_route_historical_baseline_proof",
)
SERIAL_TEST_IDS = (
    "test_context_guard_kit.ClaudeTokenKitTests."
    "test_experimental_registry_config_write_race_cannot_redirect_to_symlink",
)
BOUNDARY_PROVIDER_FREE_REQUIRED_TEST_IDS = frozenset(
    {
        "tests.test_provider_free_roadmap_boundary."
        "ProviderFreeRoadmapBoundaryTests."
        "test_g2_profile_bootstrap_injects_only_captured_verifier_and_lock_bytes",
    }
)
REQUIRED_TEST_IDS = {
    "fast": frozenset(
        {
            "tests.test_workflows.WorkflowSecurityTests."
            "test_first_party_actions_are_pinned_to_full_sha_with_non_persistent_checkout_credentials",
            "tests.test_context_pack_p1_p2_hardening.ContextPackP1P2HardeningTests."
            "test_graph_bind_rejection_is_reused_without_reopening_source",
            "tests.test_release_assets.ReleaseAssetVerificationTests."
            "test_exact_two_package_release_asset_set_is_required",
        }
    ),
    "core": frozenset(
        {
            "test_context_guard_kit.ClaudeTokenKitTests."
            "test_command_manifest_covers_release_and_runtime_surfaces",
        }
    ),
    "provider-free": frozenset(
        {
            "test_g2_ablation_contract.G2AblationContractTests."
            "test_graph_ordinary_miss_and_symbol_recovery_are_enforced",
        }
    ),
    "provider-live": frozenset(
        {
            "test_p3_anthropic_api_v4.P3AnthropicAPIV4Tests."
            "test_authorized_v2_envelopes_execute_each_unit_once",
            "test_p3_live_runner_conformance_v4.LiveRunnerConformanceTests."
            "test_unknown_receipt_and_timeout_stop_after_one_dispatch",
        }
    ),
    "history": frozenset(
        {
            "tests.test_gate_b_rollback_proof.GateBGenerationsTests."
            "test_active_generation_is_frozen_against_head",
            "tests.test_route_historical_baseline_proof.RouteHistoricalBaselineProofTests."
            "test_cli_executes_complete_pinned_deny_to_allow_inventory",
        }
    ),
    "serial": frozenset(SERIAL_TEST_IDS),
}


def filtered_suite(
    suite: unittest.TestSuite, *, excluded_prefixes: tuple[str, ...], excluded_ids: frozenset[str]
) -> unittest.TestSuite:
    selected = unittest.TestSuite()
    pending: list[unittest.TestSuite | unittest.TestCase] = [suite]
    while pending:
        item = pending.pop()
        if isinstance(item, unittest.TestSuite):
            pending.extend(reversed(list(item)))
            continue
        identity = item.id()
        if identity in excluded_ids or identity.startswith(excluded_prefixes):
            continue
        selected.addTest(item)
    return selected


def test_ids(suite: unittest.TestSuite) -> frozenset[str]:
    found: set[str] = set()
    pending: list[unittest.TestSuite | unittest.TestCase] = [suite]
    while pending:
        item = pending.pop()
        if isinstance(item, unittest.TestSuite):
            pending.extend(item)
            continue
        identity = item.id()
        if not isinstance(identity, str) or not identity:
            raise SystemExit("test discovery produced an unstable test ID")
        found.add(identity)
    return frozenset(found)


def frozen_python_matches() -> bool:
    try:
        lock = json.loads(
            (ROOT / "research/provider-free-roadmap/g2/freeze-lock.json").read_text(
                encoding="utf-8"
            )
        )
        expected = lock["python_binding"]
        executable = Path(sys.executable).resolve(strict=True)
        if (
            sys.implementation.name != expected.get("implementation")
            or f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
            != expected.get("version")
            or str(executable) != expected.get("path")
            or executable.stat().st_size != expected.get("bytes")
        ):
            return False
        digest = hashlib.sha256()
        with executable.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest() == expected.get("sha256")
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return False


def required_test_ids(name: str) -> frozenset[str]:
    if name == "provider-free" and not frozen_python_matches():
        return BOUNDARY_PROVIDER_FREE_REQUIRED_TEST_IDS
    return REQUIRED_TEST_IDS[name]


def discover_partition(name: str) -> unittest.TestSuite:
    loader = unittest.defaultTestLoader
    if name == "fast":
        return loader.loadTestsFromNames(FAST_MODULES)
    if name == "core":
        discovered = loader.discover(str(ROOT / "tests"), pattern="test_*.py")
        return filtered_suite(
            discovered,
            excluded_prefixes=(
                "test_gate_b_rollback_proof.",
                "test_route_historical_baseline_proof.",
            ),
            excluded_ids=frozenset(SERIAL_TEST_IDS),
        )
    if name == "provider-free":
        if not frozen_python_matches():
            return loader.loadTestsFromName(
                "tests.test_provider_free_roadmap_boundary"
            )
        return loader.discover(
            str(ROOT / "tests" / "provider-free-roadmap"), pattern="test_*.py"
        )
    if name == "provider-live":
        return loader.discover(
            str(ROOT / "tests" / "provider-live-roadmap"), pattern="test_p3_*v4.py"
        )
    if name == "history":
        return loader.loadTestsFromNames(HISTORY_MODULES)
    if name == "serial":
        discovered = loader.discover(str(ROOT / "tests"), pattern="test_context_guard_kit.py")
        return filtered_suite(
            discovered,
            excluded_prefixes=(),
            excluded_ids=test_ids(discovered) - frozenset(SERIAL_TEST_IDS),
        )
    raise SystemExit(f"unknown test partition: {name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("partition", choices=PARTITION_NAMES)
    args = parser.parse_args()
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

    suite = discover_partition(args.partition)
    collected = test_ids(suite)
    if not collected:
        raise SystemExit(f"refusing an empty test partition: {args.partition}")
    missing = sorted(required_test_ids(args.partition) - collected)
    if missing:
        raise SystemExit(
            f"{args.partition} partition is missing required test IDs: "
            + ", ".join(missing)
        )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
