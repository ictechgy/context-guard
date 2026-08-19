from __future__ import annotations

import ast
import copy
import hashlib
import json
import stat
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "research/contextguard-stage2/protected-surface-manifest.json"
BROKER_ROOT = REPO_ROOT / "research/contextguard-broker"

STAGE1_PATHS = {
    path.relative_to(REPO_ROOT).as_posix()
    for path in BROKER_ROOT.rglob("*")
    if path.is_file()
} | {"tests/test_contextguard_broker_contracts.py"}

R9_PUBLIC_PATHS = {
    "bench/token-savings-12task/hook-event-evidence.json",
    "bench/token-savings-12task/results/r9-dashboard.md",
    "bench/token-savings-12task/results/r9-summary.json",
    "bench/token-savings-12task/results/r9-summary.md",
    "bench/token-savings-12task/study-plan.json",
}

SETUP_AND_PLUGIN_OWNER_PATHS = {
    ".claude-plugin/marketplace.json",
    "context-guard-kit/benchmark_runner.py",
    "context-guard-kit/context_pack.py",
    "context-guard-kit/context_guard_commands.py",
    "context-guard-kit/guard_large_read.py",
    "context-guard-kit/settings.example.json",
    "context-guard-kit/setup_wizard.py",
    "package.json",
    "plugins/context-guard/.claude-plugin/plugin.json",
    "plugins/context-guard/bin/context-guard-bench",
    "plugins/context-guard/bin/context-guard-guard-read",
    "plugins/context-guard/bin/context-guard-pack",
    "plugins/context-guard/bin/context-guard-setup",
    "plugins/context-guard/examples/settings.example.json",
    "plugins/context-guard/lib/context_guard_commands.py",
    "scripts/prepublish_check.py",
    "scripts/release_smoke.py",
    "scripts/sync_plugin_copies.py",
}

# These paths were changed by the explicitly approved, provider-free Context
# Guard reference/benchmark release after the frozen Stage 2 decision.  The
# historical manifest remains byte-stable; unchanged entries are still checked
# against it below.
POST_STAGE2_PROTECTED_SHA256 = {
    ".claude-plugin/marketplace.json": "ce0592238f107bb933ac1cf652147001c5716311979a2e342c72e426c88e21e4",
    "context-guard-kit/benchmark_runner.py": "1743c6b53351d84394b4db15735b6dc0ea94f1bd16a6a8e45a277ae3fd014aea",
    "context-guard-kit/context_pack.py": "86f69c93d80ba6907e2131659f0e73dac0c24f45e09f304ea288c1558e08e08e",
    "context-guard-kit/context_guard_commands.py": "4fd1e83394787523eb1f3d946bf053c5b5a0fdd0b360be0d20839851edc21d70",
    "context-guard-kit/guard_large_read.py": "5fe265f5f133b45c596a6c4f9bbdd1eacbf8bbd4af27cff6399117fb63685dcc",
    "context-guard-kit/setup_wizard.py": "2208328d99391f3ce8f0e06bfb12665c4a10df1e8788af563899d4795a4c8be9",
    "package.json": "beca990740b52d8cf1829df340a9f1c4e30e2e5638be7f55e1393a5a2e9598f7",
    "plugins/context-guard/.claude-plugin/plugin.json": "edc30162d9466d8de3e6b1d44af8206ca46d0842b7f4b73c66a24679e1626a2d",
    "plugins/context-guard/bin/context-guard-bench": "1743c6b53351d84394b4db15735b6dc0ea94f1bd16a6a8e45a277ae3fd014aea",
    "plugins/context-guard/bin/context-guard-guard-read": "5fe265f5f133b45c596a6c4f9bbdd1eacbf8bbd4af27cff6399117fb63685dcc",
    "plugins/context-guard/bin/context-guard-pack": "86f69c93d80ba6907e2131659f0e73dac0c24f45e09f304ea288c1558e08e08e",
    "plugins/context-guard/bin/context-guard-setup": "2208328d99391f3ce8f0e06bfb12665c4a10df1e8788af563899d4795a4c8be9",
    "plugins/context-guard/lib/context_guard_commands.py": "4fd1e83394787523eb1f3d946bf053c5b5a0fdd0b360be0d20839851edc21d70",
    "scripts/prepublish_check.py": "99d7414816a6880ad13f9d4b6265cb5e33eb8c43ccf83de1d0500df43acc9382",
    "scripts/release_smoke.py": "5c1862a4861e6999547e076b852a38f93e68f4ac7a6bc2c38776121f5b141deb",
}
APPROVED_POST_STAGE2_PROTECTED_PATHS = frozenset(POST_STAGE2_PROTECTED_SHA256)

EXPECTED_PATHS = STAGE1_PATHS | R9_PUBLIC_PATHS | SETUP_AND_PLUGIN_OWNER_PATHS
CSV_COLUMNS_SHA256 = "b21bad1ec0eace7570ea93697a206ed30f9f93b6ae5b38219c4819f7b229866a"

MANIFEST_KEYS = {"entries", "invariants", "schema_version"}
ENTRY_KEYS = {"file_type", "mode", "path", "sha256", "tracked"}
INVARIANT_KEYS = {"artifact_transport", "csv_columns", "r9"}
ARTIFACT_TRANSPORT_KEYS = {"source_path", "status"}
CSV_COLUMNS_KEYS = {"sha256", "source_path"}
R9_KEYS = {"claim_allowed", "source_path", "verdict"}
EXPECTED_INVARIANT_SOURCE_PATHS = {
    "artifact_transport": "research/contextguard-broker/artifact-root-decision.json",
    "csv_columns": "context-guard-kit/benchmark_runner.py",
    "r9": "bench/token-savings-12task/results/r9-summary.json",
}
PORTABLE_REGULAR_MODES = {
    0o600: "0644",
    0o640: "0644",
    0o644: "0644",
    0o700: "0755",
    0o750: "0755",
    0o755: "0755",
}


def require_exact_keys(value: object, expected: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise AssertionError(f"{label} must contain only the expected fields")
    return value


def validate_manifest_shape(manifest: object) -> None:
    root = require_exact_keys(manifest, MANIFEST_KEYS, "manifest")
    if root["schema_version"] != "contextguard-stage2-protected-surfaces/v1":
        raise AssertionError("manifest schema version is not exact")

    entries = root["entries"]
    if not isinstance(entries, list) or not entries:
        raise AssertionError("manifest entries must be a non-empty list")
    for entry in entries:
        require_exact_keys(entry, ENTRY_KEYS, "manifest entry")

    invariants = require_exact_keys(root["invariants"], INVARIANT_KEYS, "invariants")
    require_exact_keys(
        invariants["artifact_transport"], ARTIFACT_TRANSPORT_KEYS, "artifact transport"
    )
    require_exact_keys(invariants["csv_columns"], CSV_COLUMNS_KEYS, "CSV columns")
    require_exact_keys(invariants["r9"], R9_KEYS, "R9")
    actual_source_paths = {
        name: invariants[name]["source_path"] for name in EXPECTED_INVARIANT_SOURCE_PATHS
    }
    if actual_source_paths != EXPECTED_INVARIANT_SOURCE_PATHS:
        raise AssertionError("invariant source paths must remain exact")


def portable_regular_mode(mode: int) -> str:
    permission_bits = stat.S_IMODE(mode)
    if permission_bits & 0o022:
        raise AssertionError("protected regular files must not be group/world writable")
    try:
        return PORTABLE_REGULAR_MODES[permission_bits]
    except KeyError as exc:
        raise AssertionError(
            f"unsupported protected regular-file mode: {permission_bits:04o}"
        ) from exc


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def csv_columns_digest(path: Path) -> str:
    module = ast.parse(path.read_text(encoding="utf-8"))
    for node in module.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(isinstance(target, ast.Name) and target.id == "CSV_COLUMNS" for target in node.targets):
            columns = ast.literal_eval(node.value)
            encoded = json.dumps(columns, ensure_ascii=True, separators=(",", ":")).encode()
            return hashlib.sha256(encoded).hexdigest()
    raise AssertionError("CSV_COLUMNS assignment is missing")


def tracked_paths(paths: set[str]) -> set[str]:
    result = subprocess.run(
        ["git", "ls-files", "--", *sorted(paths)],
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return set(result.stdout.splitlines())


class ContextGuardStage2ProtectedSurfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_manifest_is_canonical_and_has_exact_public_path_set(self) -> None:
        raw = MANIFEST_PATH.read_bytes()
        canonical = json.dumps(
            self.manifest, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode() + b"\n"
        self.assertEqual(raw, canonical)
        validate_manifest_shape(self.manifest)
        self.assertEqual(self.manifest["schema_version"], "contextguard-stage2-protected-surfaces/v1")
        entries = self.manifest["entries"]
        self.assertEqual([entry["path"] for entry in entries], sorted(EXPECTED_PATHS))
        self.assertEqual(len(entries), len(EXPECTED_PATHS))

    def test_portable_mode_contract_tolerates_umask_and_rejects_unsafe_bits(self) -> None:
        portable_modes = {
            0o600: "0644",
            0o640: "0644",
            0o644: "0644",
            0o700: "0755",
            0o750: "0755",
            0o755: "0755",
        }
        for actual_mode, expected_mode in portable_modes.items():
            with self.subTest(actual_mode=oct(actual_mode)):
                self.assertEqual(portable_regular_mode(actual_mode), expected_mode)

        for unsafe_mode in (0o400, 0o500, 0o641, 0o660, 0o711, 0o744, 0o777, 0o4644):
            with self.subTest(unsafe_mode=oct(unsafe_mode)), self.assertRaises(AssertionError):
                portable_regular_mode(unsafe_mode)

    def test_rejects_invented_manifest_metadata(self) -> None:
        mutations = []

        top_level = copy.deepcopy(self.manifest)
        top_level["efficacy_claim"] = True
        mutations.append(("top level", top_level))

        entry = copy.deepcopy(self.manifest)
        entry["entries"][0]["authorization"] = "invented"
        mutations.append(("entry", entry))

        invariants = copy.deepcopy(self.manifest)
        invariants["invariants"]["token_savings"] = {"claim_allowed": True}
        mutations.append(("invariants", invariants))

        for invariant_name in ("artifact_transport", "csv_columns", "r9"):
            candidate = copy.deepcopy(self.manifest)
            candidate["invariants"][invariant_name]["invented"] = True
            mutations.append((invariant_name, candidate))

        substituted_path = copy.deepcopy(self.manifest)
        substituted_path["invariants"]["csv_columns"]["source_path"] = (
            "plugins/context-guard/bin/context-guard-bench"
        )
        mutations.append(("substituted source path", substituted_path))

        absolute_path = copy.deepcopy(self.manifest)
        absolute_path["invariants"]["artifact_transport"]["source_path"] = "/tmp/decision.json"
        mutations.append(("absolute source path", absolute_path))

        traversing_path = copy.deepcopy(self.manifest)
        traversing_path["invariants"]["r9"]["source_path"] = "../r9-summary.json"
        mutations.append(("traversing source path", traversing_path))

        for label, candidate in mutations:
            with self.subTest(label=label), self.assertRaises(AssertionError):
                validate_manifest_shape(candidate)

    def test_hash_type_mode_and_tracking_status_are_frozen(self) -> None:
        tracked = tracked_paths(EXPECTED_PATHS)
        for entry in self.manifest["entries"]:
            path = REPO_ROOT / entry["path"]
            metadata = path.lstat()
            with self.subTest(path=entry["path"]):
                self.assertTrue(stat.S_ISREG(metadata.st_mode))
                self.assertEqual(entry["file_type"], "regular")
                self.assertEqual(entry["mode"], portable_regular_mode(metadata.st_mode))
                expected_sha256 = POST_STAGE2_PROTECTED_SHA256.get(
                    entry["path"], entry["sha256"]
                )
                self.assertEqual(expected_sha256, sha256(path))
                self.assertIs(entry["tracked"], entry["path"] in tracked)

    def test_semantic_and_stage1_stop_invariants_are_frozen(self) -> None:
        invariants = self.manifest["invariants"]
        benchmark = REPO_ROOT / invariants["csv_columns"]["source_path"]
        self.assertEqual(invariants["csv_columns"]["sha256"], CSV_COLUMNS_SHA256)
        self.assertEqual(csv_columns_digest(benchmark), CSV_COLUMNS_SHA256)

        decision = json.loads(
            (REPO_ROOT / invariants["artifact_transport"]["source_path"]).read_text(encoding="utf-8")
        )
        self.assertEqual(invariants["artifact_transport"]["status"], "transport_rejected")
        self.assertEqual(decision["status"], "transport_rejected")

        summary = json.loads(
            (REPO_ROOT / invariants["r9"]["source_path"]).read_text(encoding="utf-8")
        )
        self.assertEqual(invariants["r9"]["verdict"], "inconclusive")
        self.assertIs(invariants["r9"]["claim_allowed"], False)
        self.assertEqual(summary["verdict"], "inconclusive")
        self.assertIs(summary["claim_allowed"], False)
        self.assertIsNone(summary["claim"])


if __name__ == "__main__":
    unittest.main()
