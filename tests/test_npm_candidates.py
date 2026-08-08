from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILDER_PATH = ROOT / "scripts" / "build_npm_candidates.py"
PUBLISH_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "npm-publish.yml"


def load_builder():
    spec = importlib.util.spec_from_file_location("build_npm_candidates", BUILDER_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("candidate builder is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_tarball(path: Path, package: dict[str, object], extra: dict[str, bytes]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        files = {"package/package.json": json.dumps(package).encode("utf-8"), **extra}
        for name, content in files.items():
            member = tarfile.TarInfo(name)
            member.mode = 0o644
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))


def make_receipt_inventory(
    package: dict[str, object],
) -> tuple[bytes, dict[str, bytes]]:
    members = {
        "bin/context-guard-receipt.cjs": b"#!/usr/bin/env node\n",
        "bin/launcher.cjs": b"'use strict';\n",
        "package.json": json.dumps(package).encode("utf-8"),
    }
    inventory = (
        json.dumps(
            {
                "files": [
                    {"mode": "0644", "path": name, "sha256": hashlib.sha256(content).hexdigest()}
                    for name, content in sorted(members.items())
                ],
                "schema_version": "contextguard-receipt-package-files/v1",
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )
    return inventory, {
        "package/package-files.json": inventory,
        **{f"package/{name}": content for name, content in members.items() if name != "package.json"},
    }


def publish_verifier_blocks() -> list[str]:
    blocks: list[str] = []
    current: list[str] | None = None
    for line in PUBLISH_WORKFLOW_PATH.read_text(encoding="utf-8").splitlines():
        if line.strip() == "python3 - <<'PY'":
            if current is not None:
                raise AssertionError("nested publish verifier heredoc")
            current = []
            continue
        if current is not None and line.strip() == "PY":
            blocks.append(textwrap.dedent("\n".join(current)) + "\n")
            current = None
            continue
        if current is not None:
            current.append(line)
    if current is not None:
        raise AssertionError("unterminated publish verifier heredoc")
    return blocks


class NpmCandidateBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = load_builder()

    def _candidate_fixture(
        self, directory: Path,
    ) -> tuple[dict[str, object], Path, Path]:
        receipt = directory / "ictechgy-context-guard-receipt-0.2.0.tgz"
        package = directory / "ictechgy-context-guard-0.5.0.tgz"
        receipt_package = {
            "name": "@ictechgy/context-guard-receipt",
            "version": "0.2.0",
        }
        receipt_inventory, receipt_extra = make_receipt_inventory(receipt_package)
        receipt_inventory_sha256 = hashlib.sha256(receipt_inventory).hexdigest()
        policy = (
            "EXPECTED_RECEIPT_PACKAGE_FILES_SHA256_BY_VERSION = {\n"
            f'    "0.2.0": "{receipt_inventory_sha256}",\n'
            "}\n"
        ).encode("ascii")
        write_tarball(receipt, receipt_package, receipt_extra)
        write_tarball(
            package,
            {
                "name": "@ictechgy/context-guard",
                "version": "0.5.0",
                "dependencies": {"@ictechgy/context-guard-receipt": "0.2.0"},
            },
            {"package/plugins/context-guard/bin/bash_reference_policy.py": policy},
        )
        manifest = self.builder.candidate_manifest(
            receipt_tarball=receipt,
            root_tarball=package,
            commit_sha="a" * 40,
            tool_versions={"node": "v24", "npm": "11", "python": "3.12"},
        )
        return manifest, receipt, package

    def _run_publish_verifier(
        self,
        *,
        block: str,
        runner_temp: Path,
        package_name: str,
        package_version: str,
        receipt_version: str,
        expected_sha256: str,
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            "CANDIDATE_COMMIT_SHA": "a" * 40,
            "EXPECTED_PACKAGE": package_name,
            "EXPECTED_RECEIPT_VERSION": receipt_version,
            "EXPECTED_SHA256": expected_sha256,
            "EXPECTED_VERSION": package_version,
            "GITHUB_ENV": str(runner_temp / "github-env"),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.defpath,
            "PYTHONUTF8": "1",
            "RUNNER_TEMP": str(runner_temp),
        }
        return subprocess.run(
            [sys.executable, "-c", block],
            cwd=runner_temp,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )

    def test_manifest_binds_both_exact_tarballs_dependency_policy_and_toolchain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            receipt = root / "ictechgy-context-guard-receipt-0.2.0.tgz"
            package = root / "ictechgy-context-guard-0.5.0.tgz"
            receipt_package = {"name": "@ictechgy/context-guard-receipt", "version": "0.2.0"}
            receipt_inventory, receipt_extra = make_receipt_inventory(receipt_package)
            receipt_inventory_sha256 = hashlib.sha256(receipt_inventory).hexdigest()
            policy = (
                "EXPECTED_RECEIPT_PACKAGE_FILES_SHA256_BY_VERSION = {\n"
                f'    "0.2.0": "{receipt_inventory_sha256}",\n'
                "}\n"
            ).encode("ascii")
            write_tarball(
                receipt,
                receipt_package,
                receipt_extra,
            )
            write_tarball(
                package,
                {
                    "name": "@ictechgy/context-guard",
                    "version": "0.5.0",
                    "dependencies": {"@ictechgy/context-guard-receipt": "0.2.0"},
                },
                {"package/plugins/context-guard/bin/bash_reference_policy.py": policy},
            )

            manifest = self.builder.candidate_manifest(
                receipt_tarball=receipt,
                root_tarball=package,
                commit_sha="a" * 40,
                tool_versions={"node": "v24.1.0", "npm": "11.5.1", "python": "3.12.9"},
            )

            self.assertEqual(manifest["schema_version"], "contextguard-npm-candidate-set/v1")
            self.assertEqual(manifest["repository"], "ictechgy/context-guard")
            self.assertEqual(manifest["commit_sha"], "a" * 40)
            self.assertEqual(manifest["protocol"], {"maximum": 1, "minimum": 1, "name": "bash_reference_v1"})
            self.assertEqual(manifest["exact_dependency"], {"name": "@ictechgy/context-guard-receipt", "version": "0.2.0"})
            self.assertEqual(manifest["policy_sha256"], hashlib.sha256(policy).hexdigest())
            self.assertEqual(
                manifest["receipt_package_files_sha256"],
                receipt_inventory_sha256,
            )
            self.assertEqual(manifest["tool_versions"]["npm"], "11.5.1")
            self.assertEqual([item["name"] for item in manifest["packages"]], [
                "@ictechgy/context-guard-receipt",
                "@ictechgy/context-guard",
            ])
            for item, tarball in zip(manifest["packages"], (receipt, package), strict=True):
                self.assertEqual(item["filename"], tarball.name)
                self.assertEqual(item["sha256"], hashlib.sha256(tarball.read_bytes()).hexdigest())
                self.assertEqual(
                    item["integrity"],
                    "sha512-" + base64.b64encode(
                        hashlib.sha512(tarball.read_bytes()).digest()
                    ).decode("ascii"),
                )
                self.assertEqual(item["size_bytes"], tarball.stat().st_size)
            self.assertEqual(
                manifest["build_policy"],
                {
                    "ignore_scripts": True,
                    "lockfiles": [],
                    "network": "offline",
                    "package_build_count": 1,
                },
            )

    def test_manifest_rejects_unpinned_or_mismatched_receipt_dependency(self) -> None:
        invalid_versions = ("^0.2.0", "~0.2.0", ">=0.2.0", "file:../context-guard-receipt", "0.2.1")
        for invalid_version in invalid_versions:
            with self.subTest(version=invalid_version), tempfile.TemporaryDirectory() as temporary_directory:
                root = Path(temporary_directory)
                receipt = root / "receipt.tgz"
                package = root / "root.tgz"
                write_tarball(
                    receipt,
                    {"name": "@ictechgy/context-guard-receipt", "version": "0.2.0"},
                    {},
                )
                write_tarball(
                    package,
                    {
                        "name": "@ictechgy/context-guard",
                        "version": "0.5.0",
                        "dependencies": {"@ictechgy/context-guard-receipt": invalid_version},
                    },
                    {"package/plugins/context-guard/bin/bash_reference_policy.py": b"policy\n"},
                )
                with self.assertRaisesRegex(self.builder.CandidateBuildError, "exact Receipt dependency"):
                    self.builder.candidate_manifest(
                        receipt_tarball=receipt,
                        root_tarball=package,
                        commit_sha="b" * 40,
                        tool_versions={"node": "v24", "npm": "11.5.1", "python": "3.12"},
                    )

    def test_manifest_rejects_missing_required_tool_even_with_extra_tool(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            _, receipt, package = self._candidate_fixture(root)
            with self.assertRaisesRegex(
                self.builder.CandidateBuildError,
                "candidate tool versions are invalid",
            ):
                self.builder.candidate_manifest(
                    receipt_tarball=receipt,
                    root_tarball=package,
                    commit_sha="d" * 40,
                    tool_versions={"node": "v24", "npm": "11", "git": "2.4"},
                )

    def test_manifest_rejects_policy_that_does_not_pin_receipt_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            receipt = root / "receipt.tgz"
            package = root / "root.tgz"
            receipt_package = {"name": "@ictechgy/context-guard-receipt", "version": "0.2.0"}
            inventory, receipt_extra = make_receipt_inventory(receipt_package)
            write_tarball(
                receipt,
                receipt_package,
                receipt_extra,
            )
            write_tarball(
                package,
                {
                    "name": "@ictechgy/context-guard",
                    "version": "0.5.0",
                    "dependencies": {"@ictechgy/context-guard-receipt": "0.2.0"},
                },
                {
                    "package/plugins/context-guard/bin/bash_reference_policy.py": (
                        b'EXPECTED_RECEIPT_PACKAGE_FILES_SHA256_BY_VERSION = {"0.2.0": "'
                        + b"0" * 64
                        + b'"}\n'
                    ),
                },
            )
            with self.assertRaisesRegex(
                self.builder.CandidateBuildError,
                "Receipt package-files pin",
            ):
                self.builder.candidate_manifest(
                    receipt_tarball=receipt,
                    root_tarball=package,
                    commit_sha="c" * 40,
                    tool_versions={"node": "v24", "npm": "11.5.1", "python": "3.12"},
                )

    def test_checksum_file_is_canonical_and_covers_only_manifest_declared_files(self) -> None:
        manifest = {
            "packages": [
                {"filename": "receipt.tgz", "sha256": "1" * 64},
                {"filename": "root.tgz", "sha256": "2" * 64},
            ]
        }
        self.assertEqual(
            self.builder.checksum_document(manifest),
            f"{'1' * 64}  receipt.tgz\n{'2' * 64}  root.tgz\n",
        )

    def test_member_reader_refuses_unbounded_tar_header_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            tarball = Path(temporary_directory) / "many-members.tgz"
            with tarfile.open(tarball, "w:gz") as archive:
                package_json = b'{}\n'
                package_member = tarfile.TarInfo("package/package.json")
                package_member.size = len(package_json)
                archive.addfile(package_member, io.BytesIO(package_json))
                for index in range(self.builder.MAX_TAR_MEMBERS):
                    archive.addfile(tarfile.TarInfo(f"package/empty-{index}"))

            with self.assertRaisesRegex(
                self.builder.CandidateBuildError,
                "member limit",
            ):
                self.builder.read_member(tarball, "package/package.json")

    def test_member_reader_bounds_hidden_pax_extension_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            tarball = Path(temporary_directory) / "pax-extension.tgz"
            with tarfile.open(tarball, "w:gz", format=tarfile.PAX_FORMAT) as archive:
                package_json = b'{}\n'
                package_member = tarfile.TarInfo("package/package.json")
                package_member.size = len(package_json)
                package_member.pax_headers = {"comment": "x" * 4096}
                archive.addfile(package_member, io.BytesIO(package_json))

            original_limit = self.builder.MAX_TAR_STREAM_BYTES
            self.builder.MAX_TAR_STREAM_BYTES = 1024
            try:
                with self.assertRaisesRegex(
                    self.builder.CandidateBuildError,
                    "decompressed stream limit",
                ):
                    self.builder.read_member(tarball, "package/package.json")
            finally:
                self.builder.MAX_TAR_STREAM_BYTES = original_limit

    def test_publish_inline_verifiers_execute_builder_manifest_and_fail_closed(self) -> None:
        blocks = publish_verifier_blocks()
        self.assertEqual(len(blocks), 2)
        for index, block in enumerate(blocks):
            compile(block, f"npm-publish-inline-{index}", "exec")

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            manifest, receipt, package = self._candidate_fixture(root)

            def stage(
                runner_temp: Path,
                selected: Path,
                candidate_manifest: dict[str, object],
            ) -> None:
                candidate_dir = runner_temp / "candidate"
                candidate_dir.mkdir(parents=True)
                shutil.copyfile(selected, candidate_dir / selected.name)
                (candidate_dir / "candidate-manifest.json").write_text(
                    self.builder.canonical_json(candidate_manifest),
                    encoding="ascii",
                )
                (candidate_dir / "candidate-sha256sums.txt").write_text(
                    self.builder.checksum_document(candidate_manifest),
                    encoding="ascii",
                )

            cases = (
                (blocks[0], receipt, "@ictechgy/context-guard-receipt", "0.2.0"),
                (blocks[1], package, "@ictechgy/context-guard", "0.5.0"),
            )
            for index, (block, selected, name, version) in enumerate(cases):
                with self.subTest(valid=name):
                    runner_temp = root / f"valid-{index}"
                    stage(runner_temp, selected, manifest)
                    record = next(
                        item for item in manifest["packages"] if item["name"] == name
                    )
                    completed = self._run_publish_verifier(
                        block=block,
                        runner_temp=runner_temp,
                        package_name=name,
                        package_version=version,
                        receipt_version="0.2.0",
                        expected_sha256=record["sha256"],
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)

            wrong_size = json.loads(json.dumps(manifest))
            wrong_size_record = next(
                item
                for item in wrong_size["packages"]
                if item["name"] == "@ictechgy/context-guard-receipt"
            )
            wrong_size_record["size_bytes"] += 1
            wrong_size_temp = root / "wrong-size"
            stage(wrong_size_temp, receipt, wrong_size)
            wrong_size_result = self._run_publish_verifier(
                block=blocks[0],
                runner_temp=wrong_size_temp,
                package_name="@ictechgy/context-guard-receipt",
                package_version="0.2.0",
                receipt_version="0.2.0",
                expected_sha256=wrong_size_record["sha256"],
            )
            self.assertNotEqual(wrong_size_result.returncode, 0)
            self.assertIn("candidate size binding mismatch", wrong_size_result.stderr)

            bad_checksum_temp = root / "bad-checksum"
            stage(bad_checksum_temp, receipt, manifest)
            (bad_checksum_temp / "candidate" / "candidate-sha256sums.txt").write_text(
                f"{'0' * 64}  {receipt.name}\n",
                encoding="ascii",
            )
            receipt_record = next(
                item
                for item in manifest["packages"]
                if item["name"] == "@ictechgy/context-guard-receipt"
            )
            bad_checksum_result = self._run_publish_verifier(
                block=blocks[0],
                runner_temp=bad_checksum_temp,
                package_name="@ictechgy/context-guard-receipt",
                package_version="0.2.0",
                receipt_version="0.2.0",
                expected_sha256=receipt_record["sha256"],
            )
            self.assertNotEqual(bad_checksum_result.returncode, 0)
            self.assertIn("candidate checksum document is invalid", bad_checksum_result.stderr)

            many_members = root / "many-members.tgz"
            with tarfile.open(many_members, "w:gz") as archive:
                package_json = json.dumps(
                    {
                        "name": "@ictechgy/context-guard-receipt",
                        "version": "0.2.0",
                    }
                ).encode("utf-8")
                package_member = tarfile.TarInfo("package/package.json")
                package_member.size = len(package_json)
                archive.addfile(package_member, io.BytesIO(package_json))
                for index in range(self.builder.MAX_TAR_MEMBERS):
                    archive.addfile(tarfile.TarInfo(f"package/empty-{index}"))
            many_manifest = json.loads(json.dumps(manifest))
            many_record = next(
                item
                for item in many_manifest["packages"]
                if item["name"] == "@ictechgy/context-guard-receipt"
            )
            many_bytes = many_members.read_bytes()
            many_record.update(
                {
                    "filename": many_members.name,
                    "integrity": "sha512-"
                    + base64.b64encode(hashlib.sha512(many_bytes).digest()).decode("ascii"),
                    "sha256": hashlib.sha256(many_bytes).hexdigest(),
                    "size_bytes": len(many_bytes),
                }
            )
            many_temp = root / "many"
            stage(many_temp, many_members, many_manifest)
            many_result = self._run_publish_verifier(
                block=blocks[0],
                runner_temp=many_temp,
                package_name="@ictechgy/context-guard-receipt",
                package_version="0.2.0",
                receipt_version="0.2.0",
                expected_sha256=many_record["sha256"],
            )
            self.assertNotEqual(many_result.returncode, 0)
            self.assertIn("candidate tarball exceeds the member limit", many_result.stderr)

            pax_tarball = root / "pax-extension.tgz"
            with tarfile.open(
                pax_tarball, "w:gz", format=tarfile.PAX_FORMAT,
            ) as archive:
                package_json = json.dumps(
                    {
                        "name": "@ictechgy/context-guard-receipt",
                        "version": "0.2.0",
                    }
                ).encode("utf-8")
                package_member = tarfile.TarInfo("package/package.json")
                package_member.size = len(package_json)
                package_member.pax_headers = {"comment": "x" * 4096}
                archive.addfile(package_member, io.BytesIO(package_json))
            pax_manifest = json.loads(json.dumps(manifest))
            pax_record = next(
                item
                for item in pax_manifest["packages"]
                if item["name"] == "@ictechgy/context-guard-receipt"
            )
            pax_bytes = pax_tarball.read_bytes()
            pax_record.update(
                {
                    "filename": pax_tarball.name,
                    "integrity": "sha512-"
                    + base64.b64encode(hashlib.sha512(pax_bytes).digest()).decode("ascii"),
                    "sha256": hashlib.sha256(pax_bytes).hexdigest(),
                    "size_bytes": len(pax_bytes),
                }
            )
            pax_temp = root / "pax"
            stage(pax_temp, pax_tarball, pax_manifest)
            limited_block = blocks[0].replace(
                "MAX_TAR_STREAM_BYTES = 128 * 1024 * 1024",
                "MAX_TAR_STREAM_BYTES = 1024",
            )
            pax_result = self._run_publish_verifier(
                block=limited_block,
                runner_temp=pax_temp,
                package_name="@ictechgy/context-guard-receipt",
                package_version="0.2.0",
                receipt_version="0.2.0",
                expected_sha256=pax_record["sha256"],
            )
            self.assertNotEqual(pax_result.returncode, 0)
            self.assertIn("decompressed stream limit", pax_result.stderr)

    def test_repository_root_pins_the_independent_receipt_package_exactly(self) -> None:
        root_package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        receipt_package = json.loads(
            (ROOT / "packages" / "context-guard-receipt" / "package.json").read_text(encoding="utf-8")
        )

        self.assertEqual(
            root_package.get("dependencies"),
            {"@ictechgy/context-guard-receipt": receipt_package["version"]},
        )
        self.assertRegex(receipt_package["version"], r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$")

    def test_candidate_builder_uses_the_publish_size_ceiling(self) -> None:
        self.assertEqual(self.builder.MAX_TARBALL_BYTES, 50 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
