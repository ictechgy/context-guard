import base64
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import verify_npm_candidate as verifier


class NpmCandidateVerifierTests(unittest.TestCase):
    @staticmethod
    def tarball(package: dict[str, object]) -> bytes:
        package_raw = (
            json.dumps(
                package, ensure_ascii=True, separators=(",", ":"), sort_keys=True
            )
            + "\n"
        ).encode("ascii")
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            info = tarfile.TarInfo("package/package.json")
            info.mode = 0o644
            info.size = len(package_raw)
            archive.addfile(info, io.BytesIO(package_raw))
        return output.getvalue()

    def stage(
        self, root: Path, expected_package: str
    ) -> tuple[Path, str, str, str]:
        candidate = root / "candidate"
        candidate.mkdir()
        receipt_version = "0.3.0"
        root_version = "0.8.0"
        package_documents = {
            verifier.RECEIPT_NAME: {
                "name": verifier.RECEIPT_NAME,
                "version": receipt_version,
            },
            verifier.ROOT_NAME: {
                "dependencies": {verifier.RECEIPT_NAME: receipt_version},
                "name": verifier.ROOT_NAME,
                "version": root_version,
            },
        }
        filenames = {
            verifier.RECEIPT_NAME: "ictechgy-context-guard-receipt-0.3.0.tgz",
            verifier.ROOT_NAME: "ictechgy-context-guard-0.8.0.tgz",
        }
        package_records = []
        selected_digest = ""
        for name in (verifier.RECEIPT_NAME, verifier.ROOT_NAME):
            raw = self.tarball(package_documents[name])
            digest = hashlib.sha256(raw).hexdigest()
            package_records.append(
                {
                    "filename": filenames[name],
                    "integrity": "sha512-"
                    + base64.b64encode(hashlib.sha512(raw).digest()).decode("ascii"),
                    "name": name,
                    "sha256": digest,
                    "size_bytes": len(raw),
                    "version": (
                        receipt_version if name == verifier.RECEIPT_NAME else root_version
                    ),
                }
            )
            if name == expected_package:
                (candidate / filenames[name]).write_bytes(raw)
                selected_digest = digest
        manifest = {
            "build_policy": {
                "ignore_scripts": True,
                "lockfiles": [],
                "network": "offline",
                "package_build_count": 1,
            },
            "commit_sha": "a" * 40,
            "exact_dependency": {
                "name": verifier.RECEIPT_NAME,
                "version": receipt_version,
            },
            "packages": package_records,
            "policy_sha256": "b" * 64,
            "receipt_package_files_sha256": "c" * 64,
            "protocol": {"maximum": 1, "minimum": 1, "name": "bash_reference_v1"},
            "repository": "ictechgy/context-guard",
            "schema_version": "contextguard-npm-candidate-set/v1",
            "tool_versions": {"node": "v24", "npm": "11", "python": "3.12"},
        }
        (candidate / "candidate-manifest.json").write_text(
            verifier.canonical_json(manifest), encoding="ascii"
        )
        (candidate / "candidate-sha256sums.txt").write_text(
            "".join(
                f'{record["sha256"]}  {record["filename"]}\n'
                for record in package_records
            ),
            encoding="ascii",
        )
        version = receipt_version if expected_package == verifier.RECEIPT_NAME else root_version
        return candidate, selected_digest, version, receipt_version

    def test_run_metadata_requires_exact_successful_main_candidate_run(self) -> None:
        payload = {
            "conclusion": "success",
            "event": "workflow_dispatch",
            "head_branch": "main",
            "head_repository": {"full_name": "ictechgy/context-guard"},
            "head_sha": "a" * 40,
            "id": 123,
            "path": ".github/workflows/npm-candidate.yml",
            "repository": {"full_name": "ictechgy/context-guard"},
            "status": "completed",
        }
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("ascii")
        verifier.verify_run(raw, "123", "a" * 40)
        payload["head_branch"] = "feature"
        with self.assertRaises(verifier.CandidateVerificationError):
            verifier.verify_run(
                json.dumps(payload).encode("ascii"), "123", "a" * 40
            )

    def test_receipt_and_root_artifacts_share_one_exact_verifier(self) -> None:
        for package in (verifier.RECEIPT_NAME, verifier.ROOT_NAME):
            with self.subTest(package=package), tempfile.TemporaryDirectory() as directory:
                candidate, digest, version, receipt_version = self.stage(
                    Path(directory), package
                )
                tarball, receipt_integrity = verifier.verify_artifact(
                    candidate,
                    commit_sha="a" * 40,
                    expected_package=package,
                    expected_version=version,
                    expected_sha256=digest,
                    expected_receipt_version=receipt_version,
                )
                self.assertTrue(tarball.is_file())
                self.assertEqual(
                    receipt_integrity is not None, package == verifier.ROOT_NAME
                )

    def test_artifact_digest_and_closed_file_set_drift_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate, digest, version, receipt_version = self.stage(
                Path(directory), verifier.ROOT_NAME
            )
            (candidate / "unexpected").write_text("x")
            with self.assertRaisesRegex(
                verifier.CandidateVerificationError, "unexpected files"
            ):
                verifier.verify_artifact(
                    candidate,
                    commit_sha="a" * 40,
                    expected_package=verifier.ROOT_NAME,
                    expected_version=version,
                    expected_sha256=digest,
                    expected_receipt_version=receipt_version,
                )


if __name__ == "__main__":
    unittest.main()
