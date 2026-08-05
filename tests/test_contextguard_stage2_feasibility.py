from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import subprocess
import unittest
from pathlib import Path, PurePosixPath

from tests.test_contextguard_stage2_protected_surfaces import portable_regular_mode


REPO_ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = REPO_ROOT / "research/contextguard-stage2/host-observability.json"
BROKER_ROOT = REPO_ROOT / "research/contextguard-broker"
BROKER_RESEARCH_PATHS = {
    path.relative_to(REPO_ROOT).as_posix()
    for path in BROKER_ROOT.rglob("*")
    if path.is_file()
}

EXPECTED_BLOCKERS = [
    "EXACT_FRAMING_UNPROVEN",
    "HOST_OBSERVER_CONTRACT_UNSUPPORTED",
    "INERT_RESPONSE_UNPROVEN",
    "PROVIDER_JOIN_MISSING",
    "REAL_HOST_PERMISSION_OUTCOME_UNPROVEN",
]
EXPECTED_EVIDENCE_KINDS = {
    "fake_self_authored_fixture_limitations",
    "hook_payload_shape",
    "inert_response_proof_absent",
    "lifecycle_parsing",
    "measurement_gap_requirements",
    "model_visible_framed_bytes_proof_absent",
    "real_host_permission_outcomes_absent",
}
EXPECTED_EVIDENCE_ANCHORS_SHA256 = (
    "0b7decab25063c9dacb25d0a1314273a2bbbacea8564f8c6a21d2a3c752c2a03"
)
EXPECTED_BROKER_RESEARCH_PATHS_COUNT = 30
EXPECTED_BROKER_RESEARCH_PATHS_SHA256 = (
    "c17061a0a8d7a674c515032a3aa65b20c67c3a78dc4909d4b235d4a63b75d4aa"
)
EXPECTED_STAGE2_BASELINE_COMMIT = "c0fd37880855bae7b7c8d539b91237348b0e01cb"
EXPECTED_STAGE2_BASELINE_PRODUCTION_INVENTORY_COUNT = 152
EXPECTED_STAGE2_BASELINE_PRODUCTION_INVENTORY_SHA256 = (
    "a9efec40b96e7778f62f552efc2c7ea049eb3a1fb564865f996ca47fd68858dc"
)
RECEIPT_PACKAGE_PREFIX = "packages/context-guard-receipt/"
RECEIPT_COMPANION_INVENTORY = [
    {
        "file_type": "regular",
        "mode": "0644",
        "path": "packages/context-guard-receipt/scripts/verify_protected_surfaces.py",
        "sha256": "04f40bb6ccc6b1f060475011507b3621666d6953793a7504770bd9c5f010fc10",
    },
    {
        "file_type": "regular",
        "mode": "0644",
        "path": "packages/context-guard-receipt/tests/contract/__init__.py",
        "sha256": "5075760cded34ab259a764674a6620d857ab3eb623e037bf5066abe132de88bd",
    },
    {
        "file_type": "regular",
        "mode": "0644",
        "path": "packages/context-guard-receipt/tests/contract/test_boundary.py",
        "sha256": "f7a175b8f639cb7b9c475137951f37431a457118b8b6952043c1eeaea4dbc952",
    }
]
FORBIDDEN_TOP_LEVEL_FIELDS = {
    "host_id",
    "host_version",
    "permission_outcome",
    "provider_attribution",
    "provider_turn_id",
    "settings_hash",
}
FORBIDDEN_RUNTIME_NAMES = {
    "host-observer.py",
    "runtime-observer.py",
    "stage2-runner.py",
    "transport.py",
}
EXPECTED_STAGE2_ARTIFACT_NAMES = {
    "S3D-ARF-charter.json",
    "host-observability.json",
    "protected-surface-manifest.json",
    "verification-record.json",
    "verification-record.schema.json",
}
EXPECTED_STAGE2_ARTIFACT_PATHS = {
    f"research/contextguard-stage2/{name}" for name in EXPECTED_STAGE2_ARTIFACT_NAMES
}
NON_PRODUCTION_TOP_LEVEL_DOCS = {
    "CHANGELOG.md",
    "LICENSE",
    "NOTICE",
    "README.ko.md",
    "README.md",
}


def provider_free_changed_paths() -> set[str]:
    tracked = subprocess.run(
        ["git", "diff", "--name-only", "HEAD", "--"],
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.splitlines()
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard"],
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.splitlines()
    return set(tracked) | set(untracked)


def validate_provider_free_changed_paths(paths: set[str]) -> None:
    for path_text in paths:
        path = PurePosixPath(path_text)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != path_text:
            raise AssertionError("changed paths must be normalized repository-relative paths")
        if path_text.startswith("tests/") and path.suffix == ".py":
            continue
        if path_text in {entry["path"] for entry in RECEIPT_COMPANION_INVENTORY}:
            continue
        if path_text.startswith("research/contextguard-broker/"):
            raise AssertionError(f"unexpected broker research surface changed: {path_text}")
        if path_text.startswith("research/contextguard-stage2/"):
            raise AssertionError(f"unexpected Stage 2 evidence surface changed: {path_text}")
        if path_text.startswith("research/") and path.suffix == ".md":
            continue
        raise AssertionError(f"production or undeclared surface changed: {path_text}")


def validate_broker_research_paths(paths: set[str]) -> None:
    encoded = json.dumps(
        sorted(paths), ensure_ascii=True, separators=(",", ":")
    ).encode()
    if len(paths) != EXPECTED_BROKER_RESEARCH_PATHS_COUNT:
        raise AssertionError("broker research path count drifted")
    if hashlib.sha256(encoded).hexdigest() != EXPECTED_BROKER_RESEARCH_PATHS_SHA256:
        raise AssertionError("broker research path set drifted")


def repository_visible_paths() -> list[str]:
    raw_paths = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    return sorted({item.decode("utf-8") for item in raw_paths.split(b"\0") if item})


def surface_inventory(visible_paths: list[str]) -> list[dict[str, str]]:
    inventory: list[dict[str, str]] = []
    for path_text in visible_paths:
        path = PurePosixPath(path_text)
        if path_text.startswith(("docs/", "tests/")) or path_text in NON_PRODUCTION_TOP_LEVEL_DOCS:
            continue
        if path_text in BROKER_RESEARCH_PATHS or path_text in EXPECTED_STAGE2_ARTIFACT_PATHS:
            continue
        if path_text.startswith("research/") and path.suffix == ".md":
            continue
        try:
            mode = (REPO_ROOT / path_text).lstat().st_mode
        except OSError as exc:
            raise AssertionError(f"production inventory path is unavailable: {path_text}") from exc
        if stat.S_ISREG(mode):
            file_type = "regular"
            content = (REPO_ROOT / path_text).read_bytes()
            portable_mode = portable_regular_mode(mode)
        elif stat.S_ISLNK(mode):
            file_type = "symlink"
            content = os.fsencode(os.readlink(REPO_ROOT / path_text))
            portable_mode = "symlink"
        else:
            raise AssertionError(f"unsupported production inventory type: {path_text}")
        inventory.append(
            {
                "file_type": file_type,
                "mode": portable_mode,
                "path": path_text,
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    return inventory


def is_legacy_production_path(path_text: str) -> bool:
    path = PurePosixPath(path_text)
    return not (
        path_text.startswith(RECEIPT_PACKAGE_PREFIX)
        or path_text.startswith(("docs/", "tests/"))
        or path_text in NON_PRODUCTION_TOP_LEVEL_DOCS
        or path_text in BROKER_RESEARCH_PATHS
        or path_text in EXPECTED_STAGE2_ARTIFACT_PATHS
        or (path_text.startswith("research/") and path.suffix == ".md")
    )


def production_surface_inventory() -> list[dict[str, str]]:
    visible_paths = [
        path_text
        for path_text in repository_visible_paths()
        if is_legacy_production_path(path_text)
    ]
    return surface_inventory(visible_paths)


def receipt_companion_surface_inventory() -> list[dict[str, str]]:
    return surface_inventory(
        [
            path_text
            for path_text in repository_visible_paths()
            if path_text.startswith(RECEIPT_PACKAGE_PREFIX)
        ]
    )


def historical_production_surface_inventory(
    revision: str = EXPECTED_STAGE2_BASELINE_COMMIT,
) -> list[dict[str, str]]:
    raw_tree = subprocess.run(
        ["git", "ls-tree", "-r", "-z", "--full-tree", revision],
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    inventory: list[dict[str, str]] = []
    for record in (item for item in raw_tree.split(b"\0") if item):
        metadata, raw_path = record.split(b"\t", maxsplit=1)
        mode_text, object_type, object_id = metadata.decode("ascii").split()
        path_text = raw_path.decode("utf-8")
        if object_type != "blob" or not is_legacy_production_path(path_text):
            continue
        content = subprocess.run(
            ["git", "cat-file", "blob", object_id],
            cwd=REPO_ROOT,
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        mode = int(mode_text, 8)
        if stat.S_ISREG(mode):
            file_type = "regular"
            portable_mode = portable_regular_mode(mode)
        elif stat.S_ISLNK(mode):
            file_type = "symlink"
            portable_mode = "symlink"
        else:
            raise AssertionError(f"unsupported historical inventory type: {path_text}")
        inventory.append(
            {
                "file_type": file_type,
                "mode": portable_mode,
                "path": path_text,
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    return sorted(inventory, key=lambda entry: entry["path"])


def validate_production_surface_inventory(inventory: list[dict[str, str]]) -> None:
    if inventory != sorted(inventory, key=lambda entry: entry.get("path", "")):
        raise AssertionError("production inventory must be sorted")
    for entry in inventory:
        if set(entry) != {"file_type", "mode", "path", "sha256"}:
            raise AssertionError("production inventory entries must be closed")
    canonical = json.dumps(
        inventory, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode()
    if len(inventory) != EXPECTED_STAGE2_BASELINE_PRODUCTION_INVENTORY_COUNT:
        raise AssertionError("production inventory path count drifted")
    if (
        hashlib.sha256(canonical).hexdigest()
        != EXPECTED_STAGE2_BASELINE_PRODUCTION_INVENTORY_SHA256
    ):
        raise AssertionError("production inventory path/type/mode digest drifted")


def validate_receipt_companion_surface_inventory(inventory: list[dict[str, str]]) -> None:
    if inventory != RECEIPT_COMPANION_INVENTORY:
        raise AssertionError("receipt companion inventory path/type/mode/hash drifted")


def validate_stage2_historical_baseline_identity(
    inventory: list[dict[str, str]] | None = None,
    revision: str = EXPECTED_STAGE2_BASELINE_COMMIT,
) -> None:
    if revision != EXPECTED_STAGE2_BASELINE_COMMIT:
        raise AssertionError("Stage 2 historical baseline revision drifted")
    historical_inventory = (
        historical_production_surface_inventory(revision) if inventory is None else inventory
    )
    validate_production_surface_inventory(historical_inventory)
    if historical_inventory != production_surface_inventory():
        raise AssertionError("current legacy inventory drifted from the Stage 2 baseline")


def validate_record(record: object) -> None:
    if not isinstance(record, dict):
        raise AssertionError("record must be an object")
    expected_keys = {
        "blockers",
        "claim_allowed",
        "evidence_anchors",
        "provider_join_status",
        "requested_mode",
        "runtime_observer_authorized",
        "schema_version",
        "selected_branch",
        "selected_transport",
    }
    if set(record) != expected_keys:
        raise AssertionError("record has missing or invented top-level fields")
    if FORBIDDEN_TOP_LEVEL_FIELDS & set(record):
        raise AssertionError("host/provider identifiers must not be invented or normalized")
    expected_scalars = {
        "schema_version": "contextguard-stage2-host-observability/v1",
        "requested_mode": "runtime_feasibility",
        "selected_branch": "S2-UNSUPPORTED",
        "selected_transport": "NONE",
        "runtime_observer_authorized": False,
        "provider_join_status": "missing",
        "claim_allowed": False,
    }
    for field, expected in expected_scalars.items():
        if record.get(field) != expected:
            raise AssertionError(f"{field} must be {expected!r}")
    if record.get("blockers") != EXPECTED_BLOCKERS:
        raise AssertionError("blockers must be the exact sorted closed set")

    anchors = record.get("evidence_anchors")
    if not isinstance(anchors, list) or not anchors:
        raise AssertionError("evidence anchors must be a non-empty list")
    if [anchor.get("kind") for anchor in anchors] != sorted(EXPECTED_EVIDENCE_KINDS):
        raise AssertionError("evidence kinds must be exact, unique, and sorted")
    anchor_digest = hashlib.sha256(
        json.dumps(anchors, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()
    if anchor_digest != EXPECTED_EVIDENCE_ANCHORS_SHA256:
        raise AssertionError("evidence authority, path, and support tuples must remain exact")
    for anchor in anchors:
        if set(anchor) != {"authority", "kind", "path", "supports"}:
            raise AssertionError("evidence anchor shape is closed")
        path_text = anchor["path"]
        path = PurePosixPath(path_text)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != path_text:
            raise AssertionError("evidence paths must be normalized repository-relative paths")
        if not (REPO_ROOT / path_text).is_file():
            raise AssertionError(f"missing evidence anchor: {path_text}")
        if anchor["authority"] not in {"repository_contract", "limitation_only"}:
            raise AssertionError("fake or provider authority is forbidden")
        if anchor["kind"] == "fake_self_authored_fixture_limitations":
            if anchor["authority"] != "limitation_only":
                raise AssertionError("self-authored fixtures cannot establish host authority")
        if not isinstance(anchor["supports"], str) or not anchor["supports"]:
            raise AssertionError("each anchor needs a bounded support statement")


class ContextGuardStage2FeasibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = RECORD_PATH.read_bytes()
        cls.record = json.loads(cls.raw)

    def test_canonical_unsupported_record_and_repository_anchors(self) -> None:
        canonical = json.dumps(
            self.record, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode() + b"\n"
        self.assertEqual(self.raw, canonical)
        validate_record(self.record)

    def test_rejects_degraded_or_invented_authority(self) -> None:
        mutations = {
            "framed branch": {"selected_branch": "S2-FRAMED"},
            "shape degradation": {"selected_branch": "S2-SHAPE"},
            "path fallback": {"selected_transport": "PATH"},
            "runtime observer": {"runtime_observer_authorized": True},
            "provider attribution": {"provider_join_status": "attributed"},
            "claim": {"claim_allowed": True},
            "invented host": {"host_id": "normalized-host"},
        }
        for label, changes in mutations.items():
            candidate = copy.deepcopy(self.record)
            candidate.update(changes)
            with self.subTest(label=label), self.assertRaises(AssertionError):
                validate_record(candidate)

        fake_authority = copy.deepcopy(self.record)
        fake_anchor = next(
            anchor
            for anchor in fake_authority["evidence_anchors"]
            if anchor["kind"] == "fake_self_authored_fixture_limitations"
        )
        fake_anchor["authority"] = "repository_contract"
        with self.assertRaises(AssertionError):
            validate_record(fake_authority)

        detached_anchor = copy.deepcopy(self.record)
        detached_anchor["evidence_anchors"][0]["path"] = "package.json"
        detached_anchor["evidence_anchors"][0]["supports"] = "x"
        with self.assertRaises(AssertionError):
            validate_record(detached_anchor)

    def test_historical_baseline_is_reconstructed_from_the_frozen_commit(self) -> None:
        historical_inventory = historical_production_surface_inventory()
        validate_stage2_historical_baseline_identity(historical_inventory)
        self.assertEqual(historical_inventory, production_surface_inventory())

        with self.assertRaises(AssertionError):
            validate_stage2_historical_baseline_identity(
                historical_production_surface_inventory(
                    f"{EXPECTED_STAGE2_BASELINE_COMMIT}^"
                ),
                revision=f"{EXPECTED_STAGE2_BASELINE_COMMIT}^",
            )

    def test_no_runtime_observer_or_transport_surface_exists(self) -> None:
        stage2_root = RECORD_PATH.parent
        present = {path.name for path in stage2_root.iterdir() if path.is_file()}
        self.assertEqual(present, EXPECTED_STAGE2_ARTIFACT_NAMES)
        self.assertTrue(FORBIDDEN_RUNTIME_NAMES.isdisjoint(present))
        self.assertFalse(any(path.suffix in {".py", ".sh"} for path in stage2_root.iterdir()))

        changed = provider_free_changed_paths()
        validate_stage2_historical_baseline_identity()
        validate_broker_research_paths(BROKER_RESEARCH_PATHS)
        validate_provider_free_changed_paths(changed)
        validate_provider_free_changed_paths(set())
        validate_provider_free_changed_paths(changed | {"research/unrelated-user-notes.md"})

        inventory = production_surface_inventory()
        self.assertTrue(
            all(set(entry) == {"file_type", "mode", "path", "sha256"} for entry in inventory)
        )
        validate_production_surface_inventory(inventory)
        content_mutation = copy.deepcopy(inventory)
        content_mutation[0]["sha256"] = "0" * 64
        with self.assertRaises(AssertionError):
            validate_production_surface_inventory(content_mutation)
        for committed_runtime_path in (
            ".claude/hooks/contextguard-observer",
            "src/contextguard_observer.rs",
            "tools/contextguard-observer",
        ):
            invented_inventory = inventory + [
                {
                    "file_type": "regular",
                    "mode": "0755",
                    "path": committed_runtime_path,
                    "sha256": "0" * 64,
                }
            ]
            with self.subTest(committed_runtime_path=committed_runtime_path):
                with self.assertRaises(AssertionError):
                    validate_production_surface_inventory(invented_inventory)
        for runtime_path in (
            "runtime_observer.py",
            "context-guard-kit/alternate_observer.py",
            "plugins/context-guard/bin/context-guard-stage2",
            "scripts/stage2-runner.py",
            "bench/contextguard-broker/canary-settings.json",
            "package.json",
            "research/canary-settings.json",
            "tools/contextguard-observer",
            "src/contextguard_observer.rs",
            ".claude/hooks/contextguard-observer",
        ):
            with self.subTest(runtime_path=runtime_path), self.assertRaises(AssertionError):
                validate_provider_free_changed_paths(changed | {runtime_path})


if __name__ == "__main__":
    unittest.main()
