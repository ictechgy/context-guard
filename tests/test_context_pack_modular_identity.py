from __future__ import annotations

import importlib.util
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "context-guard-kit"
PLUGIN = ROOT / "plugins" / "context-guard"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def ordinary_oracle(entrypoint: Path) -> str:
    digest = hashlib.sha256(b"contextguard.context-pack-ordinary-oracle/v1\0")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "sample.py").write_text("def answer():\n    return 42\n", encoding="utf-8")
        for arguments in (
            ["build", "--root", ".", "--source", "sample.py", "--no-artifact"],
            ["build", "--root", ".", "--source", "sample.py,lines=1:1", "--budget-bytes", "512", "--no-artifact"],
            ["slice", "--root", ".", "--path", "sample.py", "--lines", "1:1"],
        ):
            result = subprocess.run(
                [sys.executable, str(entrypoint), *arguments], cwd=root,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            for value in (result.returncode.to_bytes(4, "big", signed=True), result.stdout):
                digest.update(len(value).to_bytes(8, "big") + value)
    return digest.hexdigest()


class ContextPackModularIdentityTests(unittest.TestCase):
    def test_captured_identity_changes_without_refreezing_semantic_output(self) -> None:
        identity = load(KIT / "context_pack_identity.py", "context_pack_identity_test")
        first = identity.artifact_identity(
            path="context-guard-kit/context_pack.py",
            mode="0755",
            size=10,
            sha256="1" * 64,
            semantic_output_sha256="3" * 64,
        )
        rewritten = identity.artifact_identity(
            path="context-guard-kit/context_pack.py",
            mode="0755",
            size=11,
            sha256="2" * 64,
            semantic_output_sha256="3" * 64,
        )
        changed_behavior = identity.artifact_identity(
            path="context-guard-kit/context_pack.py",
            mode="0755",
            size=11,
            sha256="2" * 64,
            semantic_output_sha256="4" * 64,
        )
        self.assertNotEqual(first.captured_sha256, rewritten.captured_sha256)
        self.assertEqual(first.semantic_sha256, rewritten.semantic_sha256)
        self.assertNotEqual(rewritten.semantic_sha256, changed_behavior.semantic_sha256)

    def test_canonical_manifest_derives_plugin_modules_and_exact_mirrors(self) -> None:
        identity = load(KIT / "context_pack_identity.py", "context_pack_identity_manifest_test")
        manifest = json.loads((KIT / "context_pack_modules.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], "contextguard.context-pack-modules/v1")
        roles = {entry["role"] for entry in manifest["modules"]}
        self.assertEqual(roles, {"entrypoint", "git-boundary", "receipts", "rendering", "scanning", "selection"})
        self.assertEqual(
            manifest["semantic_oracle_sha256"], ordinary_oracle(KIT / "context_pack.py")
        )
        self.assertEqual(
            manifest["semantic_oracle_sha256"],
            ordinary_oracle(PLUGIN / "bin" / "context-guard-pack"),
        )
        for entry in manifest["modules"]:
            canonical = ROOT / entry["canonical_path"]
            mirror = ROOT / entry["plugin_path"]
            self.assertEqual(canonical.read_bytes(), mirror.read_bytes(), entry["role"])

        derived = identity.derive_manifest_identities(ROOT, manifest)
        for pair in derived:
            self.assertEqual(pair["canonical"]["sha256"], pair["plugin"]["sha256"])
            self.assertEqual(pair["canonical"]["size"], pair["plugin"]["size"])
            self.assertNotEqual(pair["canonical"]["captured_sha256"], pair["plugin"]["captured_sha256"])
            self.assertEqual(pair["canonical"]["semantic_sha256"], pair["plugin"]["semantic_sha256"])

        check = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "sync_plugin_copies.py"), "--check"],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertEqual(check.returncode, 0, check.stderr)

    def test_ordinary_pack_is_byte_identical_for_canonical_and_plugin_entrypoints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sample.py").write_text("def answer():\n    return 42\n", encoding="utf-8")
            args = ["build", "--root", str(root), "--source", "sample.py", "--no-artifact"]
            canonical = subprocess.run(
                [sys.executable, str(KIT / "context_pack.py"), *args], capture_output=True, check=True
            )
            packaged = subprocess.run(
                [sys.executable, str(PLUGIN / "bin" / "context-guard-pack"), *args], capture_output=True, check=True
            )
            self.assertEqual(canonical.stdout, packaged.stdout)
            self.assertEqual(canonical.stderr, packaged.stderr)


if __name__ == "__main__":
    unittest.main()
