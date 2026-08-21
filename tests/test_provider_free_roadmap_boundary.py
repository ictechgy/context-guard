from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
VERIFY = REPO_ROOT / "scripts/verify_provider_free_roadmap.py"
MANIFEST = REPO_ROOT / "research/provider-free-roadmap/p1-v8-evidence-manifest.json"
BOUNDARY = REPO_ROOT / "research/provider-free-roadmap/boundary-contract.json"
PINNED_COMMIT = "96cfd58f82c02166c2749389a22dd1249712c92d"
LIVE_STUDY_ROOT = "/private/tmp/contextguard-p1-live-v8.rLM3P6/study"
G2_LOCK = REPO_ROOT / "research/provider-free-roadmap/g2/freeze-lock.json"
G2_TEST = REPO_ROOT / "tests/provider-free-roadmap/test_g2_ablation_contract.py"
G2_VERIFIER = REPO_ROOT / "research/provider-free-roadmap/g2/v1/verify.py"
G3_LOCK = REPO_ROOT / "research/provider-free-roadmap/g3/freeze-lock.json"
G3_TEST = REPO_ROOT / "tests/provider-free-roadmap/test_g3_rehearsal.py"
G3_RUNNER = REPO_ROOT / "research/provider-free-roadmap/g3/v1/rehearse.py"
G4_LOCK = REPO_ROOT / "research/provider-free-roadmap/g4/freeze-lock.json"
G4_TEST = REPO_ROOT / "tests/provider-free-roadmap/test_g4_claim_gates.py"
G5_LOCK = REPO_ROOT / "research/provider-free-roadmap/g5/freeze-lock.json"
G5_TEST = REPO_ROOT / "tests/provider-free-roadmap/test_g5_p2_preregistration.py"
G6_LOCK = REPO_ROOT / "research/provider-free-roadmap/g6/freeze-lock.json"
G6_TEST = REPO_ROOT / "tests/provider-free-roadmap/test_g6_approval_packet.py"
PINNED_G2_LOCK_SHA256 = "dfe0bf76f9dad2441d6d7e41ecec19cf936b9c6f47ef33c8e53e7da56a4cd552"
PINNED_G2_TREE_ROOT_SHA256 = "27568e5c8488c6dd5c99665d770d11115f8048e0787675a6574daf7328a13811"
PINNED_G2_VERIFIER_SHA256 = "7785decb9381fa9027138e2c6fa82ca98dbea33e3ab9e99c2a24872942b6c98f"
PINNED_G3_LOCK_SHA256 = "ad04a69d9600ce57ee23e0cd1a5e3b415f7947e3232fdcd55191da6f2e199c52"
PINNED_G3_TREE_ROOT_SHA256 = "f04f8374b2afa9621ee3719b80c295c75faa9bde2de5c286bcac1ffbce55299b"
PINNED_G4_LOCK_SHA256 = "4680432dc093982db2627d207e782f523bf3896e9562d14e220b798f473b7e51"
PINNED_G4_TREE_ROOT_SHA256 = "568b7630561ab6fe48b3cf702c0f9562a92aa24fca03064419d8812818545458"
PINNED_G5_LOCK_SHA256 = "4da399f445b2ff1d033c712083bd605b7cb0e6f210c7c24abe36d5f1df501f96"
PINNED_G5_TREE_ROOT_SHA256 = "de89fe567ccdaead27ff9853066108defbbab910f2a1fb42a005a2df2a7238be"
PINNED_G6_LOCK_SHA256 = "d623371ca4944847b528c270359b8c48970666c9b6215416bb1f630bb79d8578"
PINNED_G6_TREE_ROOT_SHA256 = "a59a00783dd3944181556b485279039a4110b3cd97c1961f96c6f3fde17fa645"


class ProviderFreeRoadmapBoundaryTests(unittest.TestCase):
    def clean_env(self, **updates: str) -> dict[str, str]:
        environment = {"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8"}
        environment.update(updates)
        return environment

    def run_verify(
        self, *args: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-I", "-B", str(VERIFY), *args],
            cwd=REPO_ROOT,
            env=self.clean_env() if env is None else env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def write_json(self, path: Path, value: dict) -> None:
        path.write_text(
            json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def assert_profile_honors_frozen_python_binding(
        self, result: subprocess.CompletedProcess[str]
    ) -> None:
        frozen = json.loads(G2_LOCK.read_text(encoding="utf-8"))["python_binding"]
        executable = Path(sys.executable).resolve(strict=True)
        raw = executable.read_bytes()
        current = {
            "bytes": len(raw),
            "implementation": sys.implementation.name,
            "path": str(executable),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "version": (
                f"{sys.version_info.major}.{sys.version_info.minor}."
                f"{sys.version_info.micro}"
            ),
        }
        if current == frozen:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr, "changed pinned Python executable\n")

    def mutated_manifest(self, root: Path, mutation) -> Path:
        value = json.loads(MANIFEST.read_text(encoding="utf-8"))
        mutation(value)
        path = root / "manifest.json"
        self.write_json(path, value)
        return path

    def test_repository_manifest_is_historical_and_git_anchored(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        boundary = json.loads(BOUNDARY.read_text(encoding="utf-8"))
        self.assertEqual(manifest["git_anchor_commit"], PINNED_COMMIT)
        self.assertEqual(
            manifest["evidence_scope"],
            {
                "current_or_later_roadmap": "out_of_scope",
                "historical_repository_evidence": "P1-v8",
                "private_study_files": "unavailable_claim_blocking",
            },
        )
        self.assertEqual(manifest["roadmap_output_roots"], boundary["new_output_roots"])
        self.assertTrue(manifest["roadmap_output_roots"])

        roadmap_entry = next(
            entry
            for entry in manifest["artifacts"]
            if entry["path"] == "research/token-savings-roadmap.md"
        )
        current_roadmap = (REPO_ROOT / roadmap_entry["path"]).read_bytes()
        self.assertNotEqual(hashlib.sha256(current_roadmap).hexdigest(), roadmap_entry["sha256"])

        result = self.run_verify("inventory", "--manifest", str(MANIFEST))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "P1-v8 Git evidence inventory: OK\n")

    def test_private_live_study_is_explicitly_unavailable_and_claim_blocking(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(
            manifest["unavailable_claim_blocking"],
            {
                "analytic_records": 121,
                "candidate_manifest_sha256": (
                    "39b02e542c83ac4f15d7761d9cf1b2b61a37cfbcb6eafe6a3580949857b26ca4"
                ),
                "candidate_run": 31464306133,
                "receipt_artifact": 9091361298,
                "report_sha256": (
                    "09eca0ff9953a7f45da2d373d568dff22e09abe19965bc58952d65822151a8a5"
                ),
                "root_artifact": 9091361857,
                "source": "fb2e177f3efb15e817f54f5742beacdbe5daf96a",
                "status": "unavailable_claim_blocking",
                "study_root": LIVE_STUDY_ROOT,
            },
        )
        self.assertFalse(
            any(
                entry["path"].startswith(LIVE_STUDY_ROOT)
                for entry in manifest["artifacts"]
            )
        )

    def test_inventory_rejects_invented_private_file_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = self.mutated_manifest(
                Path(temporary),
                lambda value: value.update(
                    private_file_entries=[
                        {
                            "path": f"{LIVE_STUDY_ROOT}/invented.json",
                            "sha256": "0" * 64,
                        }
                    ]
                ),
            )
            result = self.run_verify("inventory", "--manifest", str(manifest_path))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid P1-v8 evidence manifest shape", result.stderr)

    def test_inventory_rejects_synchronized_worktree_and_manifest_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)

            def rewrite_to_worktree(value: dict) -> None:
                entry = next(
                    artifact
                    for artifact in value["artifacts"]
                    if artifact["path"] == "research/token-savings-roadmap.md"
                )
                raw = (REPO_ROOT / entry["path"]).read_bytes()
                entry.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

            manifest_path = self.mutated_manifest(temporary_root, rewrite_to_worktree)
            result = self.run_verify("inventory", "--manifest", str(manifest_path))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("changed pinned Git artifact", result.stderr)

    def test_inventory_rejects_anchor_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = self.mutated_manifest(
                Path(temporary),
                lambda value: value.update(git_anchor_commit="HEAD"),
            )
            result = self.run_verify("inventory", "--manifest", str(manifest_path))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unexpected P1-v8 Git anchor", result.stderr)

    def test_inventory_rejects_missing_and_extra_pinned_tree_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            missing_manifest = self.mutated_manifest(
                temporary_root,
                lambda value: value["artifacts"].pop(),
            )
            missing = self.run_verify("inventory", "--manifest", str(missing_manifest))
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("unlisted pinned Git artifact", missing.stderr)

            def add_sorted_invented_artifact(value: dict) -> None:
                value["artifacts"].append(
                    {"bytes": 0, "path": "research/invented-private-entry", "sha256": "0" * 64}
                )
                value["artifacts"].sort(key=lambda entry: entry["path"])

            extra_manifest = self.mutated_manifest(
                temporary_root,
                add_sorted_invented_artifact,
            )
            extra = self.run_verify("inventory", "--manifest", str(extra_manifest))
            self.assertNotEqual(extra.returncode, 0)
            self.assertIn("artifact absent from pinned Git tree", extra.stderr)

    def test_inventory_requires_nonoverlapping_output_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            mutations = {
                "missing": lambda value: value.pop("roadmap_output_roots"),
                "empty": lambda value: value.update(roadmap_output_roots=[]),
                "overlap": lambda value: value.update(
                    roadmap_output_roots=["bench/token-savings-12task/new-roadmap"]
                ),
            }
            for label, mutation in mutations.items():
                with self.subTest(label=label):
                    manifest_path = self.mutated_manifest(temporary_root, mutation)
                    result = self.run_verify("inventory", "--manifest", str(manifest_path))
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("roadmap output roots", result.stderr)

    def test_inventory_git_children_disable_network_and_credential_helpers(self) -> None:
        spec = importlib.util.spec_from_file_location("provider_free_git_verifier", VERIFY)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        expected_environment = {
            "GIT_CONFIG_COUNT": "3",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_KEY_0": "credential.helper",
            "GIT_CONFIG_KEY_1": "core.askPass",
            "GIT_CONFIG_KEY_2": "protocol.allow",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_VALUE_0": "",
            "GIT_CONFIG_VALUE_1": "/usr/bin/false",
            "GIT_CONFIG_VALUE_2": "never",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C",
            "PATH": "/usr/bin:/bin",
        }
        inherited_credential_environment = {
            "GIT_ASKPASS": "/tmp/untrusted-askpass",
            "GIT_CONFIG_GLOBAL": "/tmp/untrusted-gitconfig",
            "GIT_SSH_COMMAND": "/tmp/untrusted-ssh",
            "HOME": "/tmp/untrusted-home",
            "SSH_ASKPASS": "/tmp/untrusted-ssh-askpass",
        }
        self.assertEqual(verifier.GIT_OBJECT_ENVIRONMENT, expected_environment)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment_log = root / "git-environments.jsonl"
            fake_git = root / "git"
            fake_git.write_text(
                f"#!{sys.executable}\n"
                "import json, os, sys\n"
                f"with open({json.dumps(str(environment_log))}, 'a', encoding='utf-8') as stream:\n"
                "    stream.write(json.dumps(dict(os.environ), sort_keys=True) + '\\n')\n"
                "if sys.argv[-2:] == ['cat-file', '--batch']:\n"
                "    for object_name in sys.stdin.buffer.read().splitlines():\n"
                "        sys.stdout.buffer.write(object_name + b' blob 1\\nx\\n')\n"
                "else:\n"
                "    sys.stdout.buffer.write(b'local-object\\n')\n",
                encoding="utf-8",
            )
            fake_git.chmod(0o755)

            with (
                mock.patch.object(verifier, "SYSTEM_GIT", fake_git),
                mock.patch.dict(os.environ, inherited_credential_environment),
            ):
                self.assertEqual(verifier.run_git(root, "rev-parse", "HEAD"), b"local-object\n")
                self.assertEqual(verifier.read_git_blobs(root, ["local-blob"]), [b"x"])

            observed = [
                json.loads(line)
                for line in environment_log.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(len(observed), 2)
            for child_environment in observed:
                for name, value in expected_environment.items():
                    self.assertEqual(child_environment.get(name), value)
                for name, inherited_value in inherited_credential_environment.items():
                    self.assertNotEqual(child_environment.get(name), inherited_value)

    def test_inventory_git_reads_are_bounded_and_do_not_expose_timeout_payload(self) -> None:
        spec = importlib.util.spec_from_file_location("provider_free_git_timeout_verifier", VERIFY)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        secret_payload = b"private-git-payload"
        cases = (
            ("object", verifier.run_git, "unable to read the pinned local Git object\n"),
            ("blobs", verifier.read_git_blobs, "unable to read the pinned local Git blobs\n"),
        )

        for label, operation, expected_stderr in cases:
            with self.subTest(label=label):
                def expire(*args, **kwargs):
                    self.assertEqual(kwargs.get("timeout"), 30)
                    raise subprocess.TimeoutExpired(
                        cmd=args[0],
                        timeout=30,
                        output=secret_payload,
                        stderr=secret_payload,
                    )

                stderr = io.StringIO()
                caught: BaseException | None = None
                with mock.patch.object(verifier.subprocess, "run", side_effect=expire):
                    with contextlib.redirect_stderr(stderr):
                        try:
                            if label == "object":
                                operation(Path(tempfile.gettempdir()), "rev-parse", "HEAD")
                            else:
                                operation(Path(tempfile.gettempdir()), ["deadbeef"])
                        except BaseException as exc:
                            caught = exc

                self.assertIsInstance(caught, SystemExit)
                self.assertEqual(stderr.getvalue(), expected_stderr)
                self.assertNotIn(secret_payload.decode("ascii"), stderr.getvalue())

    def test_bound_profile_child_uses_isolated_python_and_exact_environment(self) -> None:
        if sys.flags.isolated != 1:
            self.skipTest("asserted inside the bound execution profile child")
        self.assertEqual(sys.flags.dont_write_bytecode, 1)
        self.assertTrue(Path(sys.executable).resolve(strict=True).is_file())
        expected_environment = self.clean_env()
        for name, value in expected_environment.items():
            self.assertEqual(os.environ.get(name), value)
        self.assertTrue(
            set(os.environ) - set(expected_environment)
            <= {"__CF_USER_TEXT_ENCODING"}
        )

    def test_run_profile_binds_exact_test_module_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            test_path = root / "tests/test_provider_free_roadmap_boundary.py"
            test_path.parent.mkdir()
            test_path.write_bytes(b"# changed without changing the pinned contract\n")
            result = self.run_verify(
                "run",
                "--root",
                str(root),
                "--contract",
                str(BOUNDARY),
                "--profile",
                "boundary-tests",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("changed execution profile test artifact", result.stderr)

    def test_g2_freeze_is_independently_pinned_by_boundary_tests(self) -> None:
        raw = G2_LOCK.read_bytes()
        lock = json.loads(raw)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), PINNED_G2_LOCK_SHA256)
        self.assertEqual(lock["tree_root_sha256"], PINNED_G2_TREE_ROOT_SHA256)

    def test_g2_profile_rejects_synchronized_artifact_and_lock_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in (
                Path("research/provider-free-roadmap/g2"),
                Path("context-guard-kit"),
                Path("plugins/context-guard/bin/context-guard-pack"),
                Path("tests/provider-free-roadmap/test_g2_ablation_contract.py"),
            ):
                source = REPO_ROOT / relative
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                if source.is_dir():
                    shutil.copytree(source, destination)
                else:
                    shutil.copy2(source, destination)

            readme = root / "research/provider-free-roadmap/g2/v1/README.md"
            readme.write_text(
                readme.read_text(encoding="utf-8") + "\nSynchronized nonsemantic rewrite.\n",
                encoding="utf-8",
            )
            verifier_path = root / "research/provider-free-roadmap/g2/v1/verify.py"
            spec = importlib.util.spec_from_file_location("temporary_g2_verifier", verifier_path)
            self.assertIsNotNone(spec)
            self.assertIsNotNone(spec.loader)
            verifier = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(verifier)
            frozen_binding = copy.deepcopy(
                json.loads(G2_LOCK.read_text(encoding="utf-8"))["python_binding"]
            )
            verifier.python_binding = lambda: copy.deepcopy(frozen_binding)
            self.write_json(
                root / "research/provider-free-roadmap/g2/freeze-lock.json",
                verifier.rebuild_lock(root),
            )

            result = self.run_verify(
                "run",
                "--root",
                str(root),
                "--contract",
                str(BOUNDARY),
                "--profile",
                "g2-contract-tests",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("changed independently pinned g2 freeze lock", result.stderr)

    def test_bound_g2_contract_profile_uses_exact_test_artifact(self) -> None:
        contract = json.loads(BOUNDARY.read_text(encoding="utf-8"))
        profile = contract["execution_profiles"]["g2-contract-tests"]
        raw = G2_TEST.read_bytes()
        self.assertEqual(profile["module"], "g2_contract_tests")
        self.assertEqual(profile["test_artifact"]["path"], G2_TEST.relative_to(REPO_ROOT).as_posix())
        self.assertEqual(profile["test_artifact"]["bytes"], len(raw))
        self.assertEqual(profile["test_artifact"]["sha256"], hashlib.sha256(raw).hexdigest())
        verifier_raw = G2_VERIFIER.read_bytes()
        self.assertEqual(
            profile["verifier_artifact"]["path"],
            G2_VERIFIER.relative_to(REPO_ROOT).as_posix(),
        )
        self.assertEqual(profile["verifier_artifact"]["bytes"], len(verifier_raw))
        self.assertEqual(
            profile["verifier_artifact"]["sha256"],
            hashlib.sha256(verifier_raw).hexdigest(),
        )

        result = self.run_verify(
            "run",
            "--contract",
            str(BOUNDARY),
            "--profile",
            "g2-contract-tests",
        )
        self.assert_profile_honors_frozen_python_binding(result)

    def test_g3_freeze_and_profile_capture_every_consumed_artifact(self) -> None:
        contract = json.loads(BOUNDARY.read_text(encoding="utf-8"))
        profile = contract["execution_profiles"]["g3-rehearsal-tests"]
        raw = G3_LOCK.read_bytes()
        lock = json.loads(raw)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), PINNED_G3_LOCK_SHA256)
        self.assertEqual(lock["tree_root_sha256"], PINNED_G3_TREE_ROOT_SHA256)
        self.assertEqual(lock["g2_source"], {
            "lock_sha256": PINNED_G2_LOCK_SHA256,
            "tree_root_sha256": PINNED_G2_TREE_ROOT_SHA256,
            "verifier_sha256": PINNED_G2_VERIFIER_SHA256,
        })
        inventory = {entry["path"]: entry for entry in lock["inventory"]}
        expected = {
            path.relative_to(REPO_ROOT).as_posix()
            for path in (REPO_ROOT / "research/provider-free-roadmap/g3/v1").rglob("*")
            if path.is_file()
        } | {G3_TEST.relative_to(REPO_ROOT).as_posix()}
        self.assertEqual(set(inventory), expected)
        for relative, entry in inventory.items():
            self.assertEqual(set(entry), {"bytes", "mode", "path", "sha256"})
            artifact = REPO_ROOT / relative
            artifact_raw = artifact.read_bytes()
            self.assertEqual(entry["bytes"], len(artifact_raw))
            self.assertEqual(entry["sha256"], hashlib.sha256(artifact_raw).hexdigest())
            expected_mode = "0755" if artifact.stat().st_mode & 0o111 else "0644"
            self.assertEqual(entry["mode"], expected_mode)
        self.assertEqual(profile["g3_lock_artifact"], {
            "bytes": len(raw), "path": G3_LOCK.relative_to(REPO_ROOT).as_posix(),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
        self.assertEqual(profile["test_artifact"], {
            "bytes": len(G3_TEST.read_bytes()),
            "path": G3_TEST.relative_to(REPO_ROOT).as_posix(),
            "sha256": hashlib.sha256(G3_TEST.read_bytes()).hexdigest(),
        })

    def test_g3_profile_rejects_mode_drift_and_unlisted_or_symlink_extra(self) -> None:
        spec = importlib.util.spec_from_file_location("provider_free_verifier", VERIFY)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        lock = json.loads(G3_LOCK.read_text(encoding="utf-8"))
        for entry in lock["inventory"]:
            if entry["path"] == "tests/provider-free-roadmap/test_g3_rehearsal.py":
                current = G3_TEST.read_bytes()
                entry.update(bytes=len(current), sha256=hashlib.sha256(current).hexdigest())

        def copied_root() -> tuple[tempfile.TemporaryDirectory[str], Path]:
            temporary = tempfile.TemporaryDirectory()
            root = Path(temporary.name)
            shutil.copytree(
                REPO_ROOT / "research/provider-free-roadmap/g3/v1",
                root / "research/provider-free-roadmap/g3/v1",
            )
            test = root / "tests/provider-free-roadmap/test_g3_rehearsal.py"
            test.parent.mkdir(parents=True)
            shutil.copy2(G3_TEST, test)
            return temporary, root

        temporary, root = copied_root()
        with temporary:
            runner = root / "research/provider-free-roadmap/g3/v1/rehearse.py"
            runner.chmod(0o755)
            with self.assertRaises(SystemExit):
                verifier.capture_g3_inventory(root, lock)

        kinds = ("regular", "symlink", "hardlink", "special")
        self.assertEqual(set(kinds), {"regular", "symlink", "hardlink", "special"})
        for kind in kinds:
            with self.subTest(kind=kind):
                temporary, root = copied_root()
                with temporary:
                    extra = root / "research/provider-free-roadmap/g3/v1/extra.txt"
                    if kind == "regular":
                        extra.write_text("unlisted\n", encoding="utf-8")
                    elif kind == "symlink":
                        extra.symlink_to("manifest.json")
                    elif kind == "hardlink":
                        os.link(
                            root / "research/provider-free-roadmap/g3/v1/manifest.json",
                            extra,
                        )
                    else:
                        os.mkfifo(extra)
                    if kind == "hardlink":
                        self.assertFalse(extra.is_symlink())
                        self.assertGreater(extra.stat().st_nlink, 1)
                    elif kind == "special":
                        self.assertFalse(stat.S_ISREG(extra.lstat().st_mode))
                    with self.assertRaises(SystemExit):
                        verifier.capture_g3_inventory(root, lock)

    def test_bound_g3_rehearsal_profile_honors_frozen_python_binding(self) -> None:
        if sys.flags.isolated == 1 and Path(__file__).as_posix().endswith("test_g3_rehearsal.py"):
            self.skipTest("outer boundary test only")
        result = self.run_verify(
            "run", "--contract", str(BOUNDARY), "--profile", "g3-rehearsal-tests"
        )
        self.assert_profile_honors_frozen_python_binding(result)

    def test_g4_freeze_and_profile_capture_every_consumed_artifact(self) -> None:
        contract = json.loads(BOUNDARY.read_text(encoding="utf-8"))
        profile = contract["execution_profiles"]["g4-claim-gates"]
        raw = G4_LOCK.read_bytes()
        lock = json.loads(raw)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), PINNED_G4_LOCK_SHA256)
        self.assertEqual(lock["tree_root_sha256"], PINNED_G4_TREE_ROOT_SHA256)
        self.assertEqual(lock["g3_source"], {
            "lock_sha256": PINNED_G3_LOCK_SHA256,
            "manifest_sha256": "e9258b25e9af652196dc99401bfa053c3446f3241865639822db3a07ff139889",
            "runner_sha256": "6683de5244428714a273dd50f9b12a84c9a4c47e96f3cc97e1c18272c5b50f23",
            "schema_set_bytes": 25254,
            "schema_set_sha256": "2ad1c70def6011139ecc76d4761268d6534af564f39bcce381fcbcf9a1cc2a7c",
            "tree_root_sha256": PINNED_G3_TREE_ROOT_SHA256,
        })
        inventory = {entry["path"]: entry for entry in lock["inventory"]}
        expected = {
            path.relative_to(REPO_ROOT).as_posix()
            for path in (REPO_ROOT / "research/provider-free-roadmap/g4/v1").rglob("*")
            if path.is_file()
        } | {G4_TEST.relative_to(REPO_ROOT).as_posix()}
        self.assertEqual(set(inventory), expected)
        for relative, entry in inventory.items():
            self.assertEqual(set(entry), {"bytes", "mode", "path", "sha256"})
            artifact = REPO_ROOT / relative
            artifact_raw = artifact.read_bytes()
            self.assertEqual(entry["bytes"], len(artifact_raw))
            self.assertEqual(entry["sha256"], hashlib.sha256(artifact_raw).hexdigest())
            self.assertEqual(entry["mode"], f"{stat.S_IMODE(artifact.stat().st_mode):04o}")
        self.assertEqual(profile["g4_lock_artifact"], {
            "bytes": len(raw), "path": G4_LOCK.relative_to(REPO_ROOT).as_posix(),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })

    def test_g4_profile_rejects_mode_extra_symlink_and_capture_drift(self) -> None:
        spec = importlib.util.spec_from_file_location("provider_free_verifier_g4", VERIFY)
        self.assertIsNotNone(spec.loader)
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        lock = json.loads(G4_LOCK.read_text(encoding="utf-8"))

        def copied_root() -> tuple[tempfile.TemporaryDirectory[str], Path]:
            temporary = tempfile.TemporaryDirectory()
            root = Path(temporary.name)
            shutil.copytree(
                REPO_ROOT / "research/provider-free-roadmap/g4/v1",
                root / "research/provider-free-roadmap/g4/v1",
            )
            test = root / "tests/provider-free-roadmap/test_g4_claim_gates.py"
            test.parent.mkdir(parents=True)
            shutil.copy2(G4_TEST, test)
            return temporary, root

        temporary, root = copied_root()
        with temporary:
            (root / "research/provider-free-roadmap/g4/v1/verify.py").chmod(0o755)
            with self.assertRaises(SystemExit):
                verifier.capture_g4_inventory(root, lock)
        kinds = ("regular", "symlink", "hardlink")
        self.assertEqual(set(kinds), {"regular", "symlink", "hardlink"})
        for kind in kinds:
            with self.subTest(kind=kind):
                temporary, root = copied_root()
                with temporary:
                    extra = root / "research/provider-free-roadmap/g4/v1/extra.txt"
                    if kind == "regular":
                        extra.write_text("unlisted\n", encoding="utf-8")
                    elif kind == "symlink":
                        extra.symlink_to("claim-policy.json")
                    else:
                        os.link(
                            root / "research/provider-free-roadmap/g4/v1/claim-policy.json",
                            extra,
                        )
                    with self.assertRaises(SystemExit):
                        verifier.capture_g4_inventory(root, lock)
        temporary, root = copied_root()
        with temporary:
            original = verifier.capture_regular_file
            changed = False
            def mutate_after_capture(capture_root, relative, label):
                nonlocal changed
                raw = original(capture_root, relative, label)
                if not changed:
                    changed = True
                    policy = root / "research/provider-free-roadmap/g4/v1/claim-policy.json"
                    policy.write_bytes(policy.read_bytes() + b" ")
                return raw
            verifier.capture_regular_file = mutate_after_capture
            with self.assertRaises(SystemExit):
                verifier.capture_g4_inventory(root, lock)

    def test_bound_g4_claim_gate_profile_honors_frozen_python_binding(self) -> None:
        result = self.run_verify(
            "run", "--contract", str(BOUNDARY), "--profile", "g4-claim-gates"
        )
        self.assert_profile_honors_frozen_python_binding(result)

    def test_g5_freeze_and_profile_capture_every_consumed_artifact(self) -> None:
        contract = json.loads(BOUNDARY.read_text(encoding="utf-8"))
        profile = contract["execution_profiles"]["g5-p2-preregistration"]
        raw = G5_LOCK.read_bytes()
        lock = json.loads(raw)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), PINNED_G5_LOCK_SHA256)
        self.assertEqual(lock["tree_root_sha256"], PINNED_G5_TREE_ROOT_SHA256)
        self.assertEqual(lock["g4_source"], {
            "claim_policy_sha256": "522413abffa1a99ff74160d7f6055bffabf2a02eaded3bf3adc077d7ea19dee2",
            "lock_sha256": PINNED_G4_LOCK_SHA256,
            "schema_set_bytes": 6533,
            "schema_set_sha256": "c522aaca41495afaeb1430b830b6f038f96d25c47e783d004eb059f391124b3d",
            "tree_root_sha256": PINNED_G4_TREE_ROOT_SHA256,
            "verifier_sha256": "60296da05f0418287a7a74fe9d98e0c8e38befaf5dad59b9d11ff4ce07a2884b",
        })
        inventory = {entry["path"]: entry for entry in lock["inventory"]}
        expected = {
            path.relative_to(REPO_ROOT).as_posix()
            for path in (REPO_ROOT / "research/provider-free-roadmap/g5/v1").rglob("*")
            if path.is_file()
        } | {G5_TEST.relative_to(REPO_ROOT).as_posix()}
        self.assertEqual(set(inventory), expected)
        for relative, entry in inventory.items():
            artifact = REPO_ROOT / relative
            artifact_raw = artifact.read_bytes()
            self.assertEqual(entry, {
                "bytes": len(artifact_raw), "mode": f"{stat.S_IMODE(artifact.stat().st_mode):04o}",
                "path": relative, "sha256": hashlib.sha256(artifact_raw).hexdigest(),
            })
        self.assertEqual(profile["g5_lock_artifact"], {
            "bytes": len(raw), "path": G5_LOCK.relative_to(REPO_ROOT).as_posix(),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })

    def test_g5_profile_rejects_mode_extra_symlink_hardlink_and_capture_drift(self) -> None:
        spec = importlib.util.spec_from_file_location("provider_free_verifier_g5", VERIFY)
        self.assertIsNotNone(spec.loader)
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        lock = json.loads(G5_LOCK.read_text(encoding="utf-8"))

        def copied_root() -> tuple[tempfile.TemporaryDirectory[str], Path]:
            temporary = tempfile.TemporaryDirectory()
            root = Path(temporary.name)
            shutil.copytree(
                REPO_ROOT / "research/provider-free-roadmap/g5/v1",
                root / "research/provider-free-roadmap/g5/v1",
            )
            test = root / "tests/provider-free-roadmap/test_g5_p2_preregistration.py"
            test.parent.mkdir(parents=True)
            shutil.copy2(G5_TEST, test)
            return temporary, root

        temporary, root = copied_root()
        with temporary:
            (root / "research/provider-free-roadmap/g5/v1/verify.py").chmod(0o755)
            with self.assertRaises(SystemExit):
                verifier.capture_g5_inventory(root, lock)
        kinds = ("regular", "symlink", "hardlink", "special")
        self.assertEqual(set(kinds), {"regular", "symlink", "hardlink", "special"})
        for kind in kinds:
            with self.subTest(kind=kind):
                temporary, root = copied_root()
                with temporary:
                    extra = root / "research/provider-free-roadmap/g5/v1/results.json"
                    source = root / "research/provider-free-roadmap/g5/v1/preregistration.json"
                    if kind == "regular":
                        extra.write_text("{}\n", encoding="utf-8")
                    elif kind == "symlink":
                        extra.symlink_to("preregistration.json")
                    elif kind == "hardlink":
                        os.link(source, extra)
                    else:
                        os.mkfifo(extra)
                    with self.assertRaises(SystemExit):
                        verifier.capture_g5_inventory(root, lock)
        temporary, root = copied_root()
        with temporary:
            (root / "research/provider-free-roadmap/g5/v1/schedule.json").unlink()
            with self.assertRaises(SystemExit):
                verifier.capture_g5_inventory(root, lock)
        temporary, root = copied_root()
        with temporary:
            original = verifier.capture_regular_file
            changed = False
            def mutate_after_capture(capture_root, relative, label):
                nonlocal changed
                raw = original(capture_root, relative, label)
                if not changed:
                    changed = True
                    prereg = root / "research/provider-free-roadmap/g5/v1/preregistration.json"
                    prereg.write_bytes(prereg.read_bytes() + b" ")
                return raw
            verifier.capture_regular_file = mutate_after_capture
            with self.assertRaises(SystemExit):
                verifier.capture_g5_inventory(root, lock)

    def test_bound_g5_preregistration_profile_passes_with_lang_only_child(self) -> None:
        result = self.run_verify(
            "run", "--contract", str(BOUNDARY), "--profile", "g5-p2-preregistration"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_g6_freeze_and_profile_capture_every_consumed_artifact(self) -> None:
        contract = json.loads(BOUNDARY.read_text(encoding="utf-8"))
        profile = contract["execution_profiles"]["g6-prepared-unapproved"]
        raw = G6_LOCK.read_bytes()
        lock = json.loads(raw)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), PINNED_G6_LOCK_SHA256)
        self.assertEqual(lock["tree_root_sha256"], PINNED_G6_TREE_ROOT_SHA256)
        self.assertEqual(lock["g5_source"], {
            "lock_sha256": PINNED_G5_LOCK_SHA256,
            "preregistration_sha256": "6aed6f0818d5364d052eb98413be3cf57342f13374d1c421605b2bb4526654af",
            "schedule_sha256": "326fc47df7871e39b2f9af2d888b8385ab91fe4347c6467f08dd4a6e386e7965",
            "schema_set_bytes": 41710,
            "schema_set_sha256": "7667de85f2fb71ef84b57f4edf7544a30d5a171043567b30e49fdab1b5f161b6",
            "tree_root_sha256": PINNED_G5_TREE_ROOT_SHA256,
            "verifier_sha256": "0a6952142804247c443300d28dac6345175a61d19ceaa00273840459a46e6672",
        })
        inventory = {entry["path"]: entry for entry in lock["inventory"]}
        expected = {
            path.relative_to(REPO_ROOT).as_posix()
            for path in (REPO_ROOT / "research/provider-free-roadmap/g6/v1").rglob("*")
            if path.is_file()
        } | {G6_TEST.relative_to(REPO_ROOT).as_posix()}
        self.assertEqual(set(inventory), expected)
        for relative, entry in inventory.items():
            artifact = REPO_ROOT / relative
            artifact_raw = artifact.read_bytes()
            self.assertEqual(entry, {
                "bytes": len(artifact_raw),
                "mode": f"{stat.S_IMODE(artifact.stat().st_mode):04o}",
                "path": relative,
                "sha256": hashlib.sha256(artifact_raw).hexdigest(),
            })
        self.assertEqual(profile["g6_lock_artifact"], {
            "bytes": len(raw), "path": G6_LOCK.relative_to(REPO_ROOT).as_posix(),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })

    def test_g6_profile_rejects_mode_extra_links_missing_and_synchronized_relock(self) -> None:
        spec = importlib.util.spec_from_file_location("provider_free_verifier_g6", VERIFY)
        self.assertIsNotNone(spec.loader)
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        lock = json.loads(G6_LOCK.read_text(encoding="utf-8"))

        def copied_root() -> tuple[tempfile.TemporaryDirectory[str], Path]:
            temporary = tempfile.TemporaryDirectory()
            root = Path(temporary.name)
            shutil.copytree(
                REPO_ROOT / "research/provider-free-roadmap/g6/v1",
                root / "research/provider-free-roadmap/g6/v1",
            )
            test = root / "tests/provider-free-roadmap/test_g6_approval_packet.py"
            test.parent.mkdir(parents=True)
            shutil.copy2(G6_TEST, test)
            return temporary, root

        temporary, root = copied_root()
        with temporary:
            (root / "research/provider-free-roadmap/g6/v1/verify.py").chmod(0o755)
            with self.assertRaises(SystemExit):
                verifier.capture_g6_inventory(root, lock)
        for kind in ("regular", "symlink", "hardlink"):
            with self.subTest(kind=kind):
                temporary, root = copied_root()
                with temporary:
                    extra = root / "research/provider-free-roadmap/g6/v1/runner.py"
                    source = root / "research/provider-free-roadmap/g6/v1/verify.py"
                    if kind == "regular":
                        extra.write_text("pass\n", encoding="utf-8")
                    elif kind == "symlink":
                        extra.symlink_to("verify.py")
                    else:
                        os.link(source, extra)
                    with self.assertRaises(SystemExit):
                        verifier.capture_g6_inventory(root, lock)
        temporary, root = copied_root()
        with temporary:
            (root / "research/provider-free-roadmap/g6/v1/preparation-packet.json").unlink()
            with self.assertRaises(SystemExit):
                verifier.capture_g6_inventory(root, lock)
        changed_lock = copy.deepcopy(lock)
        changed_lock["inventory"][0]["sha256"] = "0" * 64
        encoded = json.dumps(
            changed_lock["inventory"], ensure_ascii=True, sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        changed_lock["tree_root_sha256"] = hashlib.sha256(
            b"contextguard.g6-freeze-tree/v1\x00" + encoded
        ).hexdigest()
        changed_raw = (
            json.dumps(changed_lock, ensure_ascii=True, indent=2) + "\n"
        ).encode("ascii")
        with self.assertRaises(SystemExit):
            verifier.verify_independently_pinned_g6_lock(
                REPO_ROOT,
                {"g6_lock_artifact": {
                    "bytes": len(changed_raw),
                    "path": "research/provider-free-roadmap/g6/freeze-lock.json",
                    "sha256": hashlib.sha256(changed_raw).hexdigest(),
                }},
            )

    def test_bound_g6_prepared_unapproved_profile_passes_with_lang_only_child(self) -> None:
        result = self.run_verify(
            "run", "--contract", str(BOUNDARY), "--profile", "g6-prepared-unapproved"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_g2_profile_bootstrap_injects_only_captured_verifier_and_lock_bytes(self) -> None:
        spec = importlib.util.spec_from_file_location("provider_free_verifier", VERIFY)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        spawn = getattr(verifier, "execute_verified_g2_profile_bytes", None)
        self.assertTrue(callable(spawn), "missing captured g2 profile bootstrap")
        test_bytes = (
            b"assert __G2_CAPTURED_VERIFIER_BYTES__ == b'captured-verifier'\n"
            b"assert __G2_CAPTURED_LOCK_BYTES__ == b'captured-lock'\n"
            b"assert __G2_EXPECTED_LOCK_SHA256__ == 'a' * 64\n"
            b"assert __G2_EXPECTED_TREE_ROOT__ == 'b' * 64\n"
            b"import os\n"
            b"assert sorted(os.environ) in [['LANG'], ['LANG', '__CF_USER_TEXT_ENCODING']]\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            result = spawn(
                Path(sys.executable).resolve(strict=True),
                Path(temporary),
                "tests/provider-free-roadmap/test_g2_ablation_contract.py",
                test_bytes,
                b"captured-verifier",
                b"captured-lock",
                "a" * 64,
                "b" * 64,
                {"LANG": "C.UTF-8"},
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_profile_capture_rejects_group_writable_source_mode(self) -> None:
        spec = importlib.util.spec_from_file_location("provider_free_verifier", VERIFY)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "tests/test_provider_free_roadmap_boundary.py"
            path.parent.mkdir()
            raw = b"pass\n"
            path.write_bytes(raw)
            path.chmod(0o664)
            profile = {
                "module": "tests.test_provider_free_roadmap_boundary",
                "test_artifact": {
                    "bytes": len(raw),
                    "path": "tests/test_provider_free_roadmap_boundary.py",
                    "sha256": hashlib.sha256(raw).hexdigest(),
                },
            }
            with self.assertRaises(SystemExit):
                verifier.verified_profile_test(root, profile)

    def test_verified_profile_spawn_never_reopens_replaced_source(self) -> None:
        spec = importlib.util.spec_from_file_location("provider_free_verifier", VERIFY)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        spawn_verified = getattr(verifier, "execute_verified_profile_bytes", None)
        self.assertTrue(callable(spawn_verified), "missing internal verified-byte spawn primitive")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "tests/profile_swap_probe.py"
            source_path.parent.mkdir()
            verified_marker = source_path.with_name("verified-bytes-ran")
            replacement_marker = source_path.with_name("replacement-path-ran")
            verified_bytes = (
                b"from pathlib import Path\n"
                b"Path(__file__).with_name('verified-bytes-ran').touch()\n"
            )
            replacement_bytes = (
                b"from pathlib import Path\n"
                b"Path(__file__).with_name('replacement-path-ran').touch()\n"
            )
            source_path.write_bytes(verified_bytes)
            profile = {
                "module": "tests.profile_swap_probe",
                "test_artifact": {
                    "bytes": len(verified_bytes),
                    "path": "tests/profile_swap_probe.py",
                    "sha256": hashlib.sha256(verified_bytes).hexdigest(),
                },
            }
            pinned_filename, captured_bytes = verifier.verified_profile_test(root, profile)
            source_path.write_bytes(replacement_bytes)

            result = spawn_verified(
                Path(sys.executable).resolve(strict=True),
                root,
                pinned_filename,
                captured_bytes,
                self.clean_env(),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(verified_marker.is_file())
            self.assertFalse(replacement_marker.exists())

    def test_verified_profile_timeout_is_bounded_and_does_not_expose_payload(self) -> None:
        spec = importlib.util.spec_from_file_location("provider_free_timeout_verifier", VERIFY)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        secret_payload = b"private-profile-payload"

        def expire(*args, **kwargs):
            self.assertEqual(kwargs.get("timeout"), 300)
            raise subprocess.TimeoutExpired(
                cmd=args[0], timeout=300, output=secret_payload, stderr=secret_payload
            )

        stderr = io.StringIO()
        caught: BaseException | None = None
        with mock.patch.object(verifier.subprocess, "run", side_effect=expire):
            with contextlib.redirect_stderr(stderr):
                try:
                    verifier.execute_verified_profile_bytes(
                        Path(sys.executable),
                        REPO_ROOT,
                        "tests/test_provider_free_roadmap_boundary.py",
                        secret_payload,
                        {"LANG": "C", "PATH": "/usr/bin:/bin"},
                    )
                except BaseException as exc:
                    caught = exc

        self.assertIsInstance(caught, SystemExit)
        self.assertEqual(stderr.getvalue(), "boundary-tests profile timed out\n")
        self.assertNotIn(secret_payload.decode("ascii"), stderr.getvalue())

    def test_run_rejects_synchronized_profile_contract_and_module_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tests_root = root / "tests"
            tests_root.mkdir()
            marker = tests_root / "synchronized-profile-ran"
            replacement_path = tests_root / "test_provider_free_roadmap_boundary.py"
            replacement_bytes = (
                b"from pathlib import Path\n"
                b"Path(__file__).with_name('synchronized-profile-ran').touch()\n"
            )
            replacement_path.write_bytes(replacement_bytes)
            contract = json.loads(BOUNDARY.read_text(encoding="utf-8"))
            contract["execution_profiles"]["boundary-tests"]["test_artifact"].update(
                bytes=len(replacement_bytes),
                sha256=hashlib.sha256(replacement_bytes).hexdigest(),
            )
            contract_path = root / "boundary-contract.json"
            self.write_json(contract_path, contract)

            result = self.run_verify(
                "run",
                "--root",
                str(root),
                "--contract",
                str(contract_path),
                "--profile",
                "boundary-tests",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("execution profiles do not match pinned profile", result.stderr)
            self.assertFalse(marker.exists())

    def test_caller_supplied_python_or_argv_is_not_expressible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            untrusted = root / "untrusted-python"
            marker = root / "untrusted-ran"
            untrusted.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
            untrusted.chmod(0o755)
            result = self.run_verify(
                "run",
                "--root",
                str(root),
                "--contract",
                str(BOUNDARY),
                "--profile",
                "boundary-tests",
                "--python",
                str(untrusted),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unrecognized arguments", result.stderr)
            self.assertFalse(marker.exists())

    def test_obsolete_argv_preflight_contract_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = json.loads(BOUNDARY.read_text(encoding="utf-8"))
            contract["execution_preflight"] = {
                "allowed_executables": ["python3"],
                "allowed_arguments": [["-c", "arbitrary"]],
            }
            contract_path = root / "boundary-contract.json"
            self.write_json(contract_path, contract)
            result = self.run_verify(
                "run",
                "--root",
                str(root),
                "--contract",
                str(contract_path),
                "--profile",
                "boundary-tests",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid provider-free boundary contract shape", result.stderr)

    def test_run_rejects_a_weakened_provider_free_prohibition(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = json.loads(BOUNDARY.read_text(encoding="utf-8"))
            contract["prohibitions"]["network_and_provider_calls"] = "Allowed"
            contract_path = root / "boundary-contract.json"
            self.write_json(contract_path, contract)
            result = self.run_verify(
                "run",
                "--root",
                str(root),
                "--contract",
                str(contract_path),
                "--profile",
                "boundary-tests",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid provider-free prohibitions", result.stderr)

    def test_run_rejects_every_nonallowlisted_environment_name_without_value_leakage(self) -> None:
        for name in (
            "PYTHONPATH",
            "PYTHONSTARTUP",
            "AWS_PROFILE",
        ):
            secret_value = f"do-not-disclose-{name.lower()}"
            with self.subTest(name=name):
                environment = self.clean_env(**{name: secret_value})
                result = self.run_verify(
                    "run",
                    "--contract",
                    str(BOUNDARY),
                    "--profile",
                    "boundary-tests",
                    env=environment,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertEqual(
                    result.stderr,
                    f"prohibited inherited environment name: {name}\n",
                )
                self.assertNotIn(secret_value, result.stdout + result.stderr)

    def test_run_rejects_loader_control_name_before_profile_execution(self) -> None:
        result = self.run_verify(
            "run",
            "--contract",
            str(BOUNDARY),
            "--profile",
            "boundary-tests",
            env=self.clean_env(LD_PRELOAD=""),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(
            result.stderr,
            "prohibited inherited environment name: LD_PRELOAD\n",
        )

    def test_environment_validator_does_not_disclose_loader_value(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "provider_free_environment_verifier", VERIFY
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)

        secret_value = "do-not-disclose-ld_preload"
        stderr = io.StringIO()
        with mock.patch.dict(
            os.environ, self.clean_env(LD_PRELOAD=secret_value), clear=True
        ):
            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit):
                    verifier.validate_inherited_environment()

        self.assertEqual(
            stderr.getvalue(),
            "prohibited inherited environment name: LD_PRELOAD\n",
        )
        self.assertNotIn(secret_value, stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
