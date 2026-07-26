import base64
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "context_guard_contracts"
SETUP_SCRIPTS = [
    ROOT / "context-guard-kit" / "setup_wizard.py",
    ROOT / "plugins" / "context-guard" / "bin" / "context-guard-setup",
]


def load_setup(path: Path, suffix: str):
    name = f"_managed_setup_{suffix}"
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ManagedByteContractTests(unittest.TestCase):
    def setUp(self):
        self.modules = [
            load_setup(path, f"{index}_{self._testMethodName}")
            for index, path in enumerate(SETUP_SCRIPTS)
        ]

    def test_exact_markers_fences_and_unsupported_mutations(self):
        for setup in self.modules:
            with self.subTest(script=setup.__file__):
                valid = (
                    b"header\r\n"
                    b"<!-- BEGIN context-guard:repo-rules version=1 -->\r\n"
                    b"owned\r\n"
                    b"<!-- END context-guard:repo-rules -->\r\n"
                    b"tail"
                )
                parsed = setup.parse_managed_bytes(valid, kind="repo-rules")
                self.assertEqual(parsed.status, "valid")
                self.assertEqual(parsed.spans[0].version, 1)

                fenced = (FIXTURE_DIR / "fenced-markers.bin").read_bytes()
                self.assertEqual(
                    setup.parse_managed_bytes(fenced, kind="repo-rules").status,
                    "absent",
                )
                inline = (
                    b"Example: <!-- BEGIN context-guard:repo-rules version=1 -->\n"
                    b"prefix\v<!-- BEGIN context-guard:repo-rules version=1 -->\n"
                    b"Example: <!-- END context-guard:repo-rules -->\n"
                )
                self.assertEqual(
                    setup.parse_managed_bytes(inline, kind="repo-rules").status,
                    "absent",
                )

                for mutated in (
                    b" <!-- BEGIN context-guard:repo-rules version=1 -->\n",
                    b"<!-- BEGIN context-guard:repo-rules version=2 -->\n",
                    b"<!-- BEGIN context-guard:repo-rules  version=1 -->\n",
                    b"<!-- BEGIN context-guard:repo-rules version=1 -->",
                ):
                    with self.subTest(mutated=mutated):
                        self.assertEqual(
                            setup.parse_managed_bytes(mutated, kind="repo-rules").status,
                            "unsupported",
                        )

                malformed = (
                    b"<!-- BEGIN context-guard:repo-rules version=1 -->\n"
                    b"<!-- BEGIN context-guard:repo-rules version=1 -->\n"
                    b"<!-- END context-guard:repo-rules -->\n"
                )
                self.assertEqual(
                    setup.parse_managed_bytes(malformed, kind="repo-rules").status,
                    "malformed",
                )
                for marker in setup.MANAGED_MARKERS:
                    exact = marker.begin + b"\nbody\n" + marker.end + b"\r\n"
                    parsed = setup.parse_managed_bytes(exact, kind=marker.kind)
                    self.assertEqual(parsed.status, "valid")
                    self.assertEqual(parsed.spans[0].version, marker.version)

                ambiguous = (
                    setup.REPO_RULE_MARKER_V1_BEGIN
                    + b"\na\n"
                    + setup.REPO_RULE_MARKER_V1_END
                    + b"\n"
                    + setup.REPO_RULE_MARKER_V1_BEGIN
                    + b"\nb\n"
                    + setup.REPO_RULE_MARKER_V1_END
                    + b"\n"
                )
                self.assertEqual(
                    setup.parse_managed_bytes(ambiguous, kind="repo-rules").status,
                    "ambiguous",
                )

    def test_composition_preserves_unowned_binary_bytes_and_migrates_legacy(self):
        for setup in self.modules:
            with self.subTest(script=setup.__file__):
                prefix = b"\xef\xbb\xbfuser\xff\x00\r\nleft\n"
                suffix = b"right\r\nno-final\x80"
                legacy = (
                    b"<!-- contextguard:begin -->\r\n"
                    b"old\r\n"
                    b"<!-- contextguard:end -->\n"
                )
                original = (FIXTURE_DIR / "legacy-mixed-invalid.bin").read_bytes()
                self.assertEqual(original, prefix + legacy + suffix)
                final, meta = setup.compose_rule_file_bytes(
                    original,
                    with_init=True,
                    brief_mode=None,
                )
                self.assertTrue(meta["changed"])
                self.assertTrue(meta["init_changed"])
                self.assertTrue(meta["init_migrated_legacy"])
                self.assertTrue(final.startswith(prefix))
                self.assertTrue(final.endswith(suffix))
                self.assertEqual(
                    hashlib.sha256(final[: len(prefix)]).digest(),
                    hashlib.sha256(prefix).digest(),
                )
                self.assertEqual(
                    hashlib.sha256(final[-len(suffix) :]).digest(),
                    hashlib.sha256(suffix).digest(),
                )
                self.assertIn(setup.REPO_RULE_MARKER_V1_BEGIN + b"\n", final)
                self.assertNotIn(setup.LEGACY_REPO_RULE_MARKER_BEGIN, final)

                absent = prefix + suffix
                appended, append_meta = setup.compose_rule_file_bytes(
                    absent,
                    with_init=True,
                    brief_mode=None,
                )
                self.assertTrue(append_meta["changed"])
                self.assertTrue(appended.startswith(absent))
                self.assertEqual(appended[: len(absent)], absent)

    def test_legacy_codex_whole_file_requires_exact_digest_allowlist(self):
        for setup in self.modules:
            with self.subTest(script=setup.__file__):
                legacy = setup.render_legacy_codex_skill_v0().encode("utf-8")
                digest = hashlib.sha256(legacy).hexdigest()
                self.assertIn(digest, setup.LEGACY_CODEX_SKILL_SHA256_ALLOWLIST)
                with tempfile.TemporaryDirectory() as tmp:
                    skill = Path(tmp) / "SKILL.md"
                    skill.write_bytes(legacy)
                    self.assertEqual(setup.codex_skill_status(skill), "update-needed")
                    result = setup.write_codex_project_skill(skill)
                    self.assertEqual(result["status"], "updated")
                    self.assertEqual(
                        setup.parse_managed_bytes(
                            skill.read_bytes(),
                            kind="codex-skill",
                        ).spans[0].version,
                        1,
                    )

                    variant = legacy + b" "
                    skill.write_bytes(variant)
                    self.assertEqual(setup.codex_skill_status(skill), "foreign")
                    result = setup.write_codex_project_skill(skill)
                    self.assertEqual(result["status"], "skipped")
                    self.assertEqual(skill.read_bytes(), variant)

    def test_cooperative_writer_serializes_two_barriered_processes(self):
        script = SETUP_SCRIPTS[0]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "AGENTS.md"
            target.write_bytes(b"user\n")
            target.chmod(0o640)
            setup = self.modules[0]
            initial = setup.read_managed_file_snapshot(target)
            desired, _ = setup.compose_rule_file_bytes(
                initial.data,
                with_init=True,
                brief_mode=None,
            )
            worker_code = r"""
import base64
import importlib.machinery
import importlib.util
import json
import os
import sys
import time
from pathlib import Path

name = "_managed_process_" + os.environ["WORKER_ID"]
loader = importlib.machinery.SourceFileLoader(name, os.environ["SETUP_SCRIPT"])
spec = importlib.util.spec_from_loader(name, loader)
module = importlib.util.module_from_spec(spec)
sys.modules[name] = module
loader.exec_module(module)
target = Path(os.environ["TARGET"])
expected = module.ManagedFileSnapshot(
    base64.b64decode(os.environ["EXPECTED_DATA"]),
    tuple(json.loads(os.environ["EXPECTED_METADATA"])),
)
desired = base64.b64decode(os.environ["DESIRED_DATA"])
Path(os.environ["READY"]).write_text("ready", encoding="ascii")
deadline = time.time() + 10
while not Path(os.environ["GO"]).exists():
    if time.time() >= deadline:
        raise SystemExit("barrier timeout")
    time.sleep(0.005)
result = module.write_managed_file(
    target,
    expected=expected,
    desired=desired,
    mode=0o644,
    dir_mode=0o755,
)
print(json.dumps(result, sort_keys=True))
"""
            go = root / "go"
            processes = []
            for index in range(2):
                env = {
                    **os.environ,
                    "WORKER_ID": str(index),
                    "SETUP_SCRIPT": str(script),
                    "TARGET": str(target),
                    "EXPECTED_DATA": base64.b64encode(initial.data or b"").decode("ascii"),
                    "EXPECTED_METADATA": json.dumps(initial.metadata),
                    "DESIRED_DATA": base64.b64encode(desired).decode("ascii"),
                    "READY": str(root / f"ready-{index}"),
                    "GO": str(go),
                }
                processes.append(
                    subprocess.Popen(
                        [sys.executable, "-c", worker_code],
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        env=env,
                    )
                )
            deadline = time.time() + 10
            while not all((root / f"ready-{index}").exists() for index in range(2)):
                if time.time() >= deadline:
                    self.fail("independent writer processes did not reach barrier")
                time.sleep(0.005)
            go.write_text("go", encoding="ascii")
            results = []
            for process in processes:
                stdout, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, stderr)
                results.append(json.loads(stdout))
            self.assertEqual(
                sorted(result["status"] for result in results),
                ["applied", "conflict"],
            )
            self.assertEqual(
                target.read_bytes().count(setup.REPO_RULE_MARKER_V1_BEGIN),
                1,
            )
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
            applied = next(result for result in results if result["status"] == "applied")
            backup = Path(applied["backup_path"])
            self.assertEqual(backup.read_bytes(), b"user\n")
            self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
            self.assertIn("non-cooperating", applied["residual_risk"])

    def test_detectable_edit_aborts_before_replace_and_lock_symlink_is_rejected(self):
        for setup in self.modules:
            with self.subTest(script=setup.__file__):
                with tempfile.TemporaryDirectory() as tmp:
                    target = Path(tmp) / "AGENTS.md"
                    target.write_bytes(b"before\n")
                    initial = setup.read_managed_file_snapshot(target)
                    desired, _ = setup.compose_rule_file_bytes(
                        initial.data,
                        with_init=True,
                        brief_mode=None,
                    )
                    original_verify = setup._verify_expected_snapshot
                    calls = 0

                    def mutate_on_second_verify(path, expected):
                        nonlocal calls
                        calls += 1
                        if calls == 2:
                            path.write_bytes(b"outside editor\n")
                        return original_verify(path, expected)

                    with mock.patch.object(
                        setup,
                        "_verify_expected_snapshot",
                        side_effect=mutate_on_second_verify,
                    ):
                        result = setup.write_managed_file(
                            target,
                            expected=initial,
                            desired=desired,
                            mode=0o644,
                            dir_mode=0o755,
                        )
                    self.assertEqual(result["status"], "conflict")
                    self.assertEqual(target.read_bytes(), b"outside editor\n")

                    target.write_bytes(b"again\n")
                    lock_path = setup.managed_lock_path(target)
                    lock_path.unlink()
                    lock_path.symlink_to(Path(tmp) / "elsewhere")
                    snapshot = setup.read_managed_file_snapshot(target)
                    result = setup.write_managed_file(
                        target,
                        expected=snapshot,
                        desired=b"replacement\n",
                        mode=0o644,
                        dir_mode=0o755,
                    )
                    self.assertEqual(result["status"], "skipped")
                    self.assertIn("lock", result["reason"])
                    self.assertEqual(target.read_bytes(), b"again\n")

    def test_rollback_uses_expected_post_image_and_same_authority(self):
        for setup in self.modules:
            with self.subTest(script=setup.__file__):
                with tempfile.TemporaryDirectory() as tmp:
                    target = Path(tmp) / "AGENTS.md"
                    original = b"prefix\xff\r\nsuffix"
                    target.write_bytes(original)
                    before = setup.read_managed_file_snapshot(target)
                    desired, _ = setup.compose_rule_file_bytes(
                        before.data,
                        with_init=True,
                        brief_mode=None,
                    )
                    applied = setup.write_managed_file(
                        target,
                        expected=before,
                        desired=desired,
                        mode=0o644,
                        dir_mode=0o755,
                    )
                    self.assertEqual(applied["status"], "applied")
                    post = setup.read_managed_file_snapshot(target)
                    rolled_back = setup.rollback_managed_file(
                        target,
                        expected_post=post,
                        restore=original,
                        kind="repo-rules",
                        mode=0o644,
                        dir_mode=0o755,
                    )
                    self.assertEqual(rolled_back["status"], "applied")
                    self.assertEqual(target.read_bytes(), original)

                    target.write_bytes(b"changed by user\n")
                    conflict = setup.rollback_managed_file(
                        target,
                        expected_post=post,
                        restore=original,
                        kind="repo-rules",
                        mode=0o644,
                        dir_mode=0o755,
                    )
                    self.assertEqual(conflict["status"], "conflict")
                    self.assertEqual(target.read_bytes(), b"changed by user\n")

    def test_failure_paths_abort_or_surface_durability_uncertainty(self):
        for setup in self.modules:
            with self.subTest(script=setup.__file__):
                with tempfile.TemporaryDirectory() as tmp:
                    target = Path(tmp) / "AGENTS.md"
                    target.write_bytes(b"old\n")
                    before = setup.read_managed_file_snapshot(target)
                    desired, _ = setup.compose_rule_file_bytes(
                        before.data,
                        with_init=True,
                        brief_mode=None,
                    )
                    with mock.patch.object(
                        setup,
                        "_managed_backup",
                        side_effect=OSError("forced backup failure"),
                    ):
                        result = setup.write_managed_file(
                            target,
                            expected=before,
                            desired=desired,
                            mode=0o644,
                            dir_mode=0o755,
                        )
                    self.assertEqual(result["status"], "skipped")
                    self.assertEqual(target.read_bytes(), b"old\n")

                with tempfile.TemporaryDirectory() as tmp:
                    target = Path(tmp) / "AGENTS.md"
                    missing = setup.read_managed_file_snapshot(target)
                    with mock.patch.object(
                        setup.os,
                        "fsync",
                        side_effect=OSError("forced temp fsync failure"),
                    ):
                        result = setup.write_managed_file(
                            target,
                            expected=missing,
                            desired=b"new\n",
                            mode=0o644,
                            dir_mode=0o755,
                        )
                    self.assertEqual(result["status"], "skipped")
                    self.assertFalse(target.exists())
                    self.assertFalse(list(Path(tmp).glob("*.tmp")))

                with tempfile.TemporaryDirectory() as tmp:
                    target = Path(tmp) / "AGENTS.md"
                    target.write_bytes(b"old\n")
                    before = setup.read_managed_file_snapshot(target)
                    desired, _ = setup.compose_rule_file_bytes(
                        before.data,
                        with_init=True,
                        brief_mode=None,
                    )
                    original_atomic_write_bytes = setup.atomic_write_bytes

                    def uncertain_target_write(path, data, mode=0o600, **kwargs):
                        result = original_atomic_write_bytes(path, data, mode, **kwargs)
                        if path == target:
                            raise setup.AtomicWriteDurabilityError(
                                "forced post-replace directory fsync failure"
                            )
                        return result

                    with mock.patch.object(
                        setup,
                        "atomic_write_bytes",
                        side_effect=uncertain_target_write,
                    ):
                        result = setup.write_managed_file(
                            target,
                            expected=before,
                            desired=desired,
                            mode=0o644,
                            dir_mode=0o755,
                        )
                    self.assertEqual(result["status"], "applied-durability-uncertain")
                    self.assertEqual(target.read_bytes(), desired)
                    self.assertTrue(Path(result["backup_path"]).is_file())

    def test_durability_uncertain_rule_write_blocks_codex_skill_follow_on(self):
        for setup in self.modules:
            with self.subTest(script=setup.__file__):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp).resolve()
                    target = root / "AGENTS.md"
                    target.write_bytes(b"user\n")
                    real_atomic_write = setup.atomic_write

                    def uncertain_target_write(
                        path,
                        content,
                        mode=0o600,
                        *,
                        dir_mode=setup.PRIVATE_DIR_MODE,
                    ):
                        real_atomic_write(path, content, mode, dir_mode=dir_mode)
                        if Path(path) == target:
                            raise setup.AtomicWriteDurabilityError(
                                "forced post-replace directory durability uncertainty"
                            )

                    with mock.patch.object(
                        setup,
                        "atomic_write",
                        side_effect=uncertain_target_write,
                    ):
                        plan = setup.build_adapter_plan(
                            root,
                            [setup.adapter_registry()["codex"]],
                            scope="project",
                            claude_actions=[],
                            claude_changed=False,
                            claude_applied=False,
                            with_init=True,
                            with_skill=True,
                            applied=True,
                        )
                    entry = plan[0]
                    self.assertEqual(entry["status"], "applied-durability-uncertain")
                    self.assertEqual(
                        entry["project_skill_status"],
                        "blocked-durability-uncertain",
                    )
                    self.assertFalse(
                        (root / setup.CODEX_SKILL_REL).exists(),
                        "uncertain rule durability must block automatic follow-on mutation",
                    )

    def test_cli_preserves_invalid_utf8_and_no_final_newline_outside_install(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    target = root / "AGENTS.md"
                    original = b"\xef\xbb\xbfuser\xff\r\nno-final\x80"
                    target.write_bytes(original)
                    proc = subprocess.run(
                        [
                            sys.executable,
                            str(script),
                            "--root",
                            str(root),
                            "--only",
                            "codex",
                            "--with-init",
                            "--yes",
                            "--no-diet-scan",
                            "--json",
                        ],
                        text=True,
                        capture_output=True,
                        check=True,
                    )
                    self.assertEqual(proc.stderr, "")
                    written = target.read_bytes()
                    self.assertEqual(written[: len(original)], original)
                    self.assertIn(b"\n\n" + b"<!-- BEGIN context-guard:repo-rules version=1 -->", written)
                    backups = list(root.glob("AGENTS.md.bak-*"))
                    self.assertEqual(len(backups), 1)
                    self.assertEqual(backups[0].read_bytes(), original)
                    self.assertEqual(stat.S_IMODE(backups[0].stat().st_mode), 0o600)

    def test_canonical_and_packaged_setup_are_exact_mirrors(self):
        self.assertEqual(SETUP_SCRIPTS[0].read_bytes(), SETUP_SCRIPTS[1].read_bytes())


if __name__ == "__main__":
    unittest.main()
