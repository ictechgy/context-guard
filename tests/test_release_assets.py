from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_release_assets.py"


class ReleaseAssetVerificationTests(unittest.TestCase):
    def test_release_metadata_versions_and_receipt_payload_boundary_are_exact(
        self,
    ) -> None:
        root_package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        receipt_package = json.loads(
            (ROOT / "packages/context-guard-receipt/package.json").read_text(
                encoding="utf-8"
            )
        )
        root_version = root_package["version"]
        receipt_version = receipt_package["version"]
        self.assertEqual(receipt_version, "0.4.0")
        self.assertEqual(
            root_package["dependencies"]["@ictechgy/context-guard-receipt"],
            receipt_version,
        )
        receipt_file_patterns = set(receipt_package["files"])
        self.assertFalse(
            any(pattern.startswith("scripts") for pattern in receipt_file_patterns)
        )
        self.assertFalse(
            any(pattern.startswith("tests") for pattern in receipt_file_patterns)
        )

        plugin = json.loads(
            (ROOT / "plugins/context-guard/.claude-plugin/plugin.json").read_text(
                encoding="utf-8"
            )
        )
        marketplace = json.loads(
            (ROOT / ".claude-plugin/marketplace.json").read_text(encoding="utf-8")
        )
        self.assertEqual(plugin["version"], root_version)
        marketplace_entries = [
            entry
            for entry in marketplace["plugins"]
            if entry.get("name") == plugin["name"]
        ]
        self.assertEqual(len(marketplace_entries), 1)
        self.assertEqual(marketplace_entries[0]["version"], root_version)

        documents = {
            ROOT / "README.md": f"@ictechgy/context-guard-receipt@{receipt_version}",
            ROOT / "README.ko.md": f"@ictechgy/context-guard-receipt@{receipt_version}",
            ROOT / "docs/distribution.md": (
                f"@ictechgy/context-guard-receipt: {receipt_version}"
            ),
            ROOT / "plugins/context-guard/README.md": (
                f"@ictechgy/context-guard-receipt@{receipt_version}"
            ),
            ROOT / "plugins/context-guard/README.ko.md": (
                f"@ictechgy/context-guard-receipt@{receipt_version}"
            ),
        }
        root_pattern = re.compile(r"@ictechgy/context-guard@(\d+\.\d+\.\d+)")
        for document, receipt_reference in documents.items():
            content = document.read_text(encoding="utf-8")
            self.assertEqual(set(root_pattern.findall(content)), {root_version})
            self.assertIn(receipt_reference, content)

        inventory_path = ROOT / "packages/context-guard-receipt/package-files.json"
        inventory_bytes = inventory_path.read_bytes()
        self.assertEqual(
            hashlib.sha256(inventory_bytes).hexdigest(),
            "7634d3493884c787930fbffbf83ddedde588acfdf9728217613ee23a80c56ac9",
        )
        policy = runpy.run_path(
            str(ROOT / "context-guard-kit/bash_reference_policy.py"),
            run_name="release_asset_policy_test",
        )
        self.assertEqual(
            policy["EXPECTED_RECEIPT_PACKAGE_FILES_SHA256_BY_VERSION"][
                receipt_version
            ],
            hashlib.sha256(inventory_bytes).hexdigest(),
        )
        published_inventory = json.loads(inventory_bytes)
        receipt_root = ROOT / "packages/context-guard-receipt"
        for entry in published_inventory["files"]:
            content = (receipt_root / entry["path"]).read_bytes()
            self.assertEqual(hashlib.sha256(content).hexdigest(), entry["sha256"])
        published_paths = {entry["path"] for entry in published_inventory["files"]}
        self.assertFalse(any(path.startswith("scripts/") for path in published_paths))
        self.assertFalse(any(path.startswith("tests/") for path in published_paths))
        self.assertNotIn("scripts/verify_protected_surfaces.py", published_paths)
        self.assertNotIn("tests/contract/test_boundary.py", published_paths)

    def stage(self, root: Path) -> tuple[Path, dict[str, object]]:
        assets = root / "assets"
        assets.mkdir()
        packages = []
        for name, filename, content, version in (
            (
                "@ictechgy/context-guard-receipt",
                "ictechgy-context-guard-receipt-0.2.1.tgz",
                b"receipt-candidate",
                "0.2.1",
            ),
            (
                "@ictechgy/context-guard",
                "ictechgy-context-guard-0.6.0.tgz",
                b"root-candidate",
                "0.6.0",
            ),
        ):
            (assets / filename).write_bytes(content)
            packages.append(
                {
                    "filename": filename,
                    "integrity": "sha512-"
                    + base64.b64encode(hashlib.sha512(content).digest()).decode("ascii"),
                    "name": name,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size_bytes": len(content),
                    "version": version,
                }
            )
        manifest = {
            "build_policy": {
                "ignore_scripts": True,
                "lockfiles": [],
                "network": "offline",
                "package_build_count": 1,
            },
            "commit_sha": "a" * 40,
            "exact_dependency": {
                "name": "@ictechgy/context-guard-receipt",
                "version": "0.2.1",
            },
            "packages": packages,
            "policy_sha256": "b" * 64,
            "receipt_package_files_sha256": "c" * 64,
            "protocol": {"maximum": 1, "minimum": 1, "name": "bash_reference_v1"},
            "repository": "ictechgy/context-guard",
            "schema_version": "contextguard-npm-candidate-set/v1",
            "tool_versions": {"node": "v24", "npm": "11", "python": "3.12"},
        }
        manifest_text = json.dumps(
            manifest, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ) + "\n"
        (assets / "candidate-manifest.json").write_text(manifest_text, encoding="ascii")
        checksums = "".join(
            f'{package["sha256"]}  {package["filename"]}\n'
            for package in packages
        )
        (assets / "candidate-sha256sums.txt").write_text(checksums, encoding="ascii")
        return assets, manifest

    def run_verifier(self, assets: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--assets-dir",
                str(assets),
                "--commit-sha",
                "a" * 40,
                "--version",
                "0.6.0",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_exact_two_package_release_asset_set_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            assets, _manifest = self.stage(Path(name))
            self.assertEqual(self.run_verifier(assets).returncode, 0)

        mutations = (
            "extra",
            "digest",
            "checksum",
            "single-package",
            "version-mismatch",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as name:
                assets, manifest = self.stage(Path(name))
                if mutation == "extra":
                    (assets / "unexpected.txt").write_text("unexpected\n")
                elif mutation == "digest":
                    (assets / manifest["packages"][0]["filename"]).write_bytes(b"changed")
                elif mutation == "checksum":
                    (assets / "candidate-sha256sums.txt").write_text("not canonical\n")
                else:
                    if mutation == "single-package":
                        removed = manifest["packages"].pop()
                        (assets / removed["filename"]).unlink()
                    else:
                        root_package = next(
                            package
                            for package in manifest["packages"]
                            if package["name"] == "@ictechgy/context-guard"
                        )
                        root_package["version"] = "9.9.9"
                    (assets / "candidate-manifest.json").write_text(
                        json.dumps(
                            manifest,
                            ensure_ascii=True,
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                        + "\n",
                        encoding="ascii",
                    )
                    (assets / "candidate-sha256sums.txt").write_text(
                        "".join(
                            f'{package["sha256"]}  {package["filename"]}\n'
                            for package in manifest["packages"]
                        ),
                        encoding="ascii",
                    )
                self.assertNotEqual(self.run_verifier(assets).returncode, 0)


if __name__ == "__main__":
    unittest.main()
