"""Focused S003 specification: real 12-task fixture suite + zero-cost rehearsal.

The module names real production boundaries in the canonical benchmark runner and
the shipped rehearsal harness. It contains no alternative implementation of those
boundaries, and it never invokes a provider, network socket, or credential path.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "context-guard-kit" / "benchmark_runner.py"
PACKAGED_RUNNER = ROOT / "plugins" / "context-guard" / "bin" / "context-guard-bench"
SUITE = ROOT / "bench" / "token-savings-12task"
HARNESS = ROOT / "scripts" / "rehearse_measurement_study.py"

REQUIRED_CATEGORIES = (
    "small_fix",
    "bugfix",
    "exploration",
    "review",
    "long_log",
    "migration",
    "docs",
    "refactor",
    "performance",
    "telemetry",
    "cache_layout",
    "artifact_receipt",
)
S003_BOUNDARIES = (
    "FixtureTreeEntry",
    "validate_fixture_tree_relpath",
    "load_task_fixture_tree",
    "load_task_fixture_trees",
    "fixture_tree_manifest_files",
    "fixture_tree_sha256",
    "reset_task_fixture_tree",
    "_study_task_manifest",
)


def load_runner(name: str = "s003_runner_under_test"):
    spec = importlib.util.spec_from_file_location(name, RUNNER)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load the canonical benchmark runner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_harness(name: str = "s003_harness_under_test"):
    spec = importlib.util.spec_from_file_location(name, HARNESS)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load the rehearsal harness")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


RUNNER_MODULE = load_runner()
SUITE_TASKS = json.loads((SUITE / "tasks.json").read_text(encoding="utf-8"))
SOLUTIONS = json.loads(
    (SUITE / "rehearsal" / "solutions.json").read_text(encoding="utf-8")
)["solutions"]


def write_task_file(root: Path, entries: list[dict]) -> Path:
    path = root / "tasks.json"
    path.write_text(json.dumps(entries), encoding="utf-8")
    return path


def sample_tree(root: Path, *, executable_checker: bool = True) -> Path:
    tree = root / "trees" / "sample"
    (tree / "src").mkdir(parents=True)
    (tree / "src" / "app.py").write_text("value = 1\n", encoding="utf-8")
    checker = tree / "check.py"
    checker.write_text("raise SystemExit(0)\n", encoding="utf-8")
    os.chmod(checker, 0o700 if executable_checker else 0o600)
    return tree


def sample_task(**overrides) -> dict:
    entry = {
        "id": "sample_task",
        "prompt": "sample prompt",
        "success_command": "python3 check.py",
        "success_cwd": ".",
        "fixture_tree": "trees/sample",
        "success_checker": "check.py",
    }
    entry.update(overrides)
    return entry


class S003BoundaryPresenceTest(unittest.TestCase):
    def test_named_production_boundaries_exist(self) -> None:
        for name in S003_BOUNDARIES:
            with self.subTest(boundary=name):
                self.assertTrue(
                    hasattr(RUNNER_MODULE, name),
                    f"missing S003 production boundary: {name}",
                )

    def test_packaged_runner_is_byte_identical(self) -> None:
        self.assertEqual(
            hashlib.sha256(RUNNER.read_bytes()).hexdigest(),
            hashlib.sha256(PACKAGED_RUNNER.read_bytes()).hexdigest(),
        )


class SuiteShapeTest(unittest.TestCase):
    def test_suite_has_twelve_real_tasks_covering_every_category(self) -> None:
        self.assertEqual(len(SUITE_TASKS), 12)
        ids = [entry["id"] for entry in SUITE_TASKS]
        self.assertEqual(len(set(ids)), 12)
        for index, (entry, category) in enumerate(
            zip(SUITE_TASKS, REQUIRED_CATEGORIES), start=1
        ):
            with self.subTest(task=entry["id"]):
                self.assertEqual(entry["id"], f"ts12_{index:02d}_{category}")

    def test_no_task_keeps_a_placeholder_success_command(self) -> None:
        for entry in SUITE_TASKS:
            with self.subTest(task=entry["id"]):
                self.assertFalse(
                    RUNNER_MODULE.is_placeholder_success_command(entry["success_command"])
                )
                self.assertEqual(entry["success_cwd"], ".")
                self.assertEqual(entry["success_checker"], "check.py")
                self.assertTrue(entry["fixture_tree"].startswith("trees/"))

    def test_shipped_examples_remain_placeholders(self) -> None:
        example = json.loads(
            (
                ROOT / "docs/benchmark-fixtures/token-savings-12task.tasks.example.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(len(example), 12)
        for entry in example:
            with self.subTest(task=entry["id"]):
                self.assertTrue(
                    RUNNER_MODULE.is_placeholder_success_command(entry["success_command"])
                )
                self.assertNotIn("fixture_tree", entry)

    def test_suite_loads_and_binds_every_fixture_tree(self) -> None:
        tasks = RUNNER_MODULE.parse_tasks(SUITE / "tasks.json")
        RUNNER_MODULE.load_task_fixture_trees(tasks, task_file_dir=SUITE)
        self.assertEqual(len(tasks), 12)
        for task in tasks:
            with self.subTest(task=task.id):
                entries = task.fixture_tree_entries
                self.assertIsNotNone(entries)
                assert entries is not None
                self.assertGreaterEqual(len(entries), 2)
                paths = [entry.path for entry in entries]
                self.assertEqual(paths, sorted(paths))
                self.assertIn("check.py", paths)
                checker = next(entry for entry in entries if entry.path == "check.py")
                self.assertTrue(checker.executable)

    def test_rehearsal_solutions_never_live_inside_a_fixture_tree(self) -> None:
        self.assertEqual(sorted(SOLUTIONS), sorted(entry["id"] for entry in SUITE_TASKS))
        for tree in (SUITE / "trees").iterdir():
            with self.subTest(tree=tree.name):
                names = {path.name for path in tree.rglob("*")}
                self.assertNotIn("solutions.json", names)


class FixtureTreePathValidationTest(unittest.TestCase):
    def test_unsafe_paths_are_refused(self) -> None:
        unsafe = [
            "/absolute/path",
            "../escape",
            "trees/../escape",
            ".hidden/tree",
            "trees/sample\x00",
            "trees\\sample",
            "",
            " trees/sample",
            "a/b/c/d/e/f/g",
        ]
        for raw in unsafe:
            with self.subTest(path=raw):
                with self.assertRaises(SystemExit):
                    RUNNER_MODULE.validate_fixture_tree_relpath(
                        raw, owner="task t", field="fixture_tree",
                    )

    def test_safe_relative_path_is_accepted(self) -> None:
        self.assertEqual(
            RUNNER_MODULE.validate_fixture_tree_relpath(
                "trees/01-small-fix", owner="task t", field="fixture_tree",
            ).as_posix(),
            "trees/01-small-fix",
        )


class TaskFixtureParsingTest(unittest.TestCase):
    def test_placeholder_success_command_is_refused_with_a_fixture_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample_tree(root)
            path = write_task_file(root, [sample_task(
                success_command=(
                    "python3 -c \"raise SystemExit('"
                    + RUNNER_MODULE.PLACEHOLDER_SUCCESS_COMMAND_MARKER
                    + "')\""
                ),
            )])
            with self.assertRaises(SystemExit):
                RUNNER_MODULE.parse_tasks(path)

    def test_missing_success_command_is_refused_with_a_fixture_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample_tree(root)
            entry = sample_task()
            entry.pop("success_command")
            with self.assertRaises(SystemExit):
                RUNNER_MODULE.parse_tasks(write_task_file(root, [entry]))

    def test_success_checker_requires_a_fixture_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = sample_task()
            entry.pop("fixture_tree")
            with self.assertRaises(SystemExit):
                RUNNER_MODULE.parse_tasks(write_task_file(root, [entry]))

    def test_fixture_tree_requires_workspace_relative_success_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample_tree(root)
            with self.assertRaises(SystemExit):
                RUNNER_MODULE.parse_tasks(
                    write_task_file(root, [sample_task(success_cwd="src")])
                )

    def test_task_without_a_fixture_tree_keeps_legacy_behaviour(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tasks = RUNNER_MODULE.parse_tasks(write_task_file(root, [{
                "id": "legacy", "prompt": "p", "success_command": "true",
            }]))
            self.assertIsNone(tasks[0].fixture_tree)
            self.assertIsNone(tasks[0].success_checker)
            self.assertIsNone(tasks[0].fixture_tree_entries)


class FixtureTreeLoadingTest(unittest.TestCase):
    def load_single(self, root: Path):
        tasks = RUNNER_MODULE.parse_tasks(write_task_file(root, [sample_task()]))
        RUNNER_MODULE.load_task_fixture_trees(tasks, task_file_dir=root)
        return tasks[0]

    def test_symlink_inside_the_tree_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tree = sample_tree(root)
            os.symlink(tree / "src" / "app.py", tree / "linked.py")
            with self.assertRaises(SystemExit):
                self.load_single(root)

    def test_non_executable_checker_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample_tree(root, executable_checker=False)
            with self.assertRaises(SystemExit):
                self.load_single(root)

    def test_checker_outside_the_tree_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample_tree(root)
            tasks = RUNNER_MODULE.parse_tasks(
                write_task_file(root, [sample_task(success_checker="absent.py")])
            )
            with self.assertRaises(SystemExit):
                RUNNER_MODULE.load_task_fixture_trees(tasks, task_file_dir=root)

    def test_oversize_file_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tree = sample_tree(root)
            (tree / "big.txt").write_bytes(
                b"x" * (RUNNER_MODULE.MAX_FIXTURE_TREE_FILE_BYTES + 1)
            )
            with self.assertRaises(SystemExit):
                self.load_single(root)

    def test_empty_tree_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "trees" / "sample").mkdir(parents=True)
            with self.assertRaises(SystemExit):
                self.load_single(root)

    def test_tree_hash_is_stable_and_mutation_sensitive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tree = sample_tree(root)
            first = RUNNER_MODULE.fixture_tree_sha256(
                self.load_single(root).fixture_tree_entries
            )
            # no-change control: re-reading the untouched tree keeps the hash.
            self.assertEqual(
                first,
                RUNNER_MODULE.fixture_tree_sha256(
                    self.load_single(root).fixture_tree_entries
                ),
            )
            (tree / "src" / "app.py").write_text("value = 2\n", encoding="utf-8")
            self.assertNotEqual(
                first,
                RUNNER_MODULE.fixture_tree_sha256(
                    self.load_single(root).fixture_tree_entries
                ),
            )

    def test_checker_mode_change_is_hash_visible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tree = sample_tree(root)
            entries = self.load_single(root).fixture_tree_entries
            baseline = RUNNER_MODULE.fixture_tree_sha256(entries)
            os.chmod(tree / "src" / "app.py", 0o755)
            mutated = RUNNER_MODULE.fixture_tree_sha256(
                self.load_single(root).fixture_tree_entries
            )
            self.assertNotEqual(baseline, mutated)


class DeterministicResetTest(unittest.TestCase):
    def entries(self, root: Path):
        sample_tree(root)
        tasks = RUNNER_MODULE.parse_tasks(write_task_file(root, [sample_task()]))
        RUNNER_MODULE.load_task_fixture_trees(tasks, task_file_dir=root)
        return tasks[0].fixture_tree_entries

    def test_reset_materializes_exact_bytes_and_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entries = self.entries(root)
            workspace = root / "workspace"
            workspace.mkdir(mode=0o700)
            RUNNER_MODULE.reset_task_fixture_tree(entries, workspace)
            self.assertEqual(
                (workspace / "src" / "app.py").read_text(encoding="utf-8"), "value = 1\n",
            )
            self.assertEqual((workspace / "check.py").stat().st_mode & 0o777, 0o700)
            self.assertEqual(
                (workspace / "src" / "app.py").stat().st_mode & 0o777, 0o600,
            )

    def test_reset_removes_stale_state_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entries = self.entries(root)
            workspace = root / "workspace"
            workspace.mkdir(mode=0o700)
            RUNNER_MODULE.reset_task_fixture_tree(entries, workspace)
            (workspace / "agent-output.txt").write_text("stale", encoding="utf-8")
            (workspace / "src" / "app.py").write_text("mutated\n", encoding="utf-8")
            RUNNER_MODULE.reset_task_fixture_tree(entries, workspace)
            self.assertFalse((workspace / "agent-output.txt").exists())
            self.assertEqual(
                (workspace / "src" / "app.py").read_text(encoding="utf-8"), "value = 1\n",
            )
            after = sorted(
                str(path.relative_to(workspace))
                for path in workspace.rglob("*") if path.is_file()
            )
            self.assertEqual(after, ["check.py", "src/app.py"])

    def test_reset_survives_short_writes(self) -> None:
        """A kernel short write must not silently truncate a materialized file."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entries = self.entries(root)
            workspace = root / "workspace"
            workspace.mkdir(mode=0o700)
            real_write = os.write
            state = {"calls": 0}

            def short_write(fd, data):
                state["calls"] += 1
                view = memoryview(data)
                if len(view) > 1:
                    return real_write(fd, view[:1])
                return real_write(fd, view)

            os.write = short_write
            try:
                RUNNER_MODULE.reset_task_fixture_tree(entries, workspace)
            finally:
                os.write = real_write
            self.assertGreater(state["calls"], len(entries))
            self.assertEqual(
                (workspace / "src" / "app.py").read_text(encoding="utf-8"), "value = 1\n",
            )
            self.assertEqual(
                (workspace / "check.py").read_text(encoding="utf-8"), "raise SystemExit(0)\n",
            )

    def test_reset_refuses_a_symlinked_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entries = self.entries(root)
            real = root / "real"
            real.mkdir(mode=0o700)
            link = root / "linked"
            os.symlink(real, link)
            with self.assertRaises(SystemExit):
                RUNNER_MODULE.reset_task_fixture_tree(entries, link)

    def test_reset_without_entries_leaves_the_workspace_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "workspace"
            workspace.mkdir(mode=0o700)
            (workspace / "keep.txt").write_text("keep", encoding="utf-8")
            RUNNER_MODULE.reset_task_fixture_tree((), workspace)
            self.assertEqual((workspace / "keep.txt").read_text(encoding="utf-8"), "keep")


class StudyManifestBindingTest(unittest.TestCase):
    def test_manifest_binds_tree_and_checker_hashes(self) -> None:
        tasks = RUNNER_MODULE.parse_tasks(SUITE / "tasks.json")
        RUNNER_MODULE.load_task_fixture_trees(tasks, task_file_dir=SUITE)
        for task in tasks:
            with self.subTest(task=task.id):
                manifest = RUNNER_MODULE._study_task_manifest(task, SUITE)
                tree = manifest["fixture_tree"]
                self.assertEqual(tree["root"], task.fixture_tree)
                self.assertEqual(tree["reset"], "deterministic_cold_workspace_materialization_v1")
                self.assertEqual(tree["file_count"], len(task.fixture_tree_entries or ()))
                self.assertEqual(
                    tree["tree_sha256"],
                    RUNNER_MODULE.fixture_tree_sha256(task.fixture_tree_entries or ()),
                )
                checker = manifest["success_checker"]
                self.assertEqual(checker["path"], "check.py")
                expected = next(
                    entry for entry in (task.fixture_tree_entries or ())
                    if entry.path == "check.py"
                )
                self.assertEqual(
                    checker["sha256"], hashlib.sha256(expected.data).hexdigest(),
                )
                self.assertEqual(
                    manifest["prompt_sha256"],
                    hashlib.sha256(task.prompt.encode("utf-8")).hexdigest(),
                )

    def test_legacy_task_manifest_keeps_null_tree_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tasks = RUNNER_MODULE.parse_tasks(write_task_file(root, [{
                "id": "legacy", "prompt": "p", "success_command": "true",
            }]))
            manifest = RUNNER_MODULE._study_task_manifest(tasks[0], root)
            self.assertIsNone(manifest["fixture_tree"])
            self.assertIsNone(manifest["success_checker"])


class ExecutableSuccessCheckTest(unittest.TestCase):
    """Every task's bounded checker must fail pristine and pass when solved."""

    def run_checker(self, tree: Path, solution: dict | None) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "workspace"
            shutil.copytree(tree, workspace)
            for rel, content in sorted((solution or {}).items()):
                target = workspace / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            return subprocess.run(
                [sys.executable, "check.py"], cwd=workspace,
                capture_output=True, text=True, timeout=120,
            )

    def test_pristine_tree_fails_and_solution_passes(self) -> None:
        for entry in SUITE_TASKS:
            tree = SUITE / entry["fixture_tree"]
            with self.subTest(task=entry["id"], state="pristine"):
                self.assertEqual(self.run_checker(tree, None).returncode, 1)
            with self.subTest(task=entry["id"], state="solved"):
                self.assertEqual(
                    self.run_checker(tree, SOLUTIONS[entry["id"]]).returncode, 0,
                )


class RehearsalHarnessContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = load_harness()

    def test_scripted_retry_units_are_bounded_and_real(self) -> None:
        units = self.harness.SCRIPTED_RETRY_UNITS
        known = {entry["id"] for entry in SUITE_TASKS}
        self.assertEqual(len(units), len(set(units)))
        self.assertGreaterEqual(len(units), 1)
        for task_id, arm, repetition in units:
            with self.subTest(unit=(task_id, arm, repetition)):
                self.assertIn(task_id, known)
                self.assertIn(arm, ("baseline", "treatment"))
                self.assertIn(repetition, (0, 1, 2))

    def test_claim_boundary_refuses_provider_measured_wording(self) -> None:
        claim = self.harness.CLAIM_BOUNDARY
        self.assertIn("Zero-cost rehearsal only", claim)
        self.assertIn("frozen 12-task suite", claim)
        for forbidden in ("product-wide", "default-on", "guaranteed", "proven savings"):
            self.assertNotIn(forbidden, claim)

    def test_fake_cli_performs_no_network_or_credential_access(self) -> None:
        fake = self.harness.FAKE_CLI
        for banned in (
            "import socket", "import http", "import urllib", "import ssl",
            "import subprocess", "requests", "keychain",
            "security find-generic-password",
        ):
            with self.subTest(token=banned):
                self.assertNotIn(banned, fake)

    def test_fake_cli_installs_a_fail_closed_runtime_audit_hook(self) -> None:
        fake = self.harness.FAKE_CLI
        self.assertIn("sys.addaudithook(_audit)", fake)
        self.assertIn("raise RuntimeError", fake)
        for prefix in ("socket.", "urllib.", "subprocess.", "os.exec", "ssl."):
            with self.subTest(prefix=prefix):
                self.assertIn(f'"{prefix}"', fake)

    def test_path_derived_analysis_fields_are_disclosed(self) -> None:
        fields = self.harness.PATH_DERIVED_ANALYSIS_FIELDS
        self.assertIn("manifest_sha256", fields)
        self.assertIn("observability.artifact_index_sha256", fields)
        self.assertIn("observability.attempt_index_sha256", fields)

    def test_forbidden_env_names_cover_provider_and_cloud_credentials(self) -> None:
        forbidden = set(self.harness.FORBIDDEN_ENV_NAMES)
        for name in (
            "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN", "NETRC", "KUBECONFIG",
        ):
            with self.subTest(name=name):
                self.assertIn(name, forbidden)

    def test_harness_refuses_a_non_empty_output_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "out"
            root.mkdir()
            (root / "stale").write_text("stale", encoding="utf-8")
            with self.assertRaises(SystemExit):
                self.harness.main(["--output-root", str(root)])


class RehearsalExecutionTest(unittest.TestCase):
    """Full zero-cost rehearsal: 72 initial attempts plus scripted retries."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        output_root = Path(cls.tmp.name) / "rehearsal"
        proc = subprocess.run(
            [sys.executable, str(HARNESS), "--output-root", str(output_root)],
            capture_output=True, text=True, timeout=1800,
        )
        if proc.returncode != 0:
            raise AssertionError(
                f"rehearsal failed: {proc.returncode}\n{proc.stdout[-3000:]}\n{proc.stderr[-3000:]}"
            )
        cls.output_root = output_root
        cls.report = json.loads(
            (output_root / "rehearsal-report.json").read_text(encoding="utf-8")
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def test_all_seventy_two_initial_attempts_plus_scripted_retries_are_terminal(self) -> None:
        attempts = self.report["deterministic"]["attempts"]
        self.assertEqual(attempts["terminal_initial_attempts"], 72)
        self.assertEqual(
            attempts["terminal_retry_attempts"],
            len(load_harness("s003_harness_counts").SCRIPTED_RETRY_UNITS),
        )
        self.assertEqual(
            attempts["terminal_classifications"],
            {"success": 72, "valid_task_failure_v1": 4},
        )
        for arm in ("baseline", "treatment"):
            with self.subTest(arm=arm):
                self.assertEqual(
                    attempts["terminal_classifications_by_arm"][arm],
                    {"success": 36, "valid_task_failure_v1": 2},
                )

    def test_report_records_zero_cost_evidence_and_claim_boundary(self) -> None:
        evidence = self.report["deterministic"]["zero_cost_evidence"]
        self.assertEqual(evidence["provider_calls"], 0)
        self.assertEqual(evidence["network_calls"], 0)
        self.assertEqual(evidence["usd_spent"], 0.0)
        self.assertEqual(evidence["credential_env_names_observed"], [])
        self.assertIn("Zero-cost rehearsal only", self.report["claim_boundary"])
        self.assertIn(
            "provider-measured token savings",
            self.report["deterministic"]["not_evidence_of"],
        )

    def test_report_binds_every_task_tree_and_checker(self) -> None:
        bindings = self.report["deterministic"]["suite"]["task_bindings"]
        self.assertEqual(len(bindings), 12)
        for binding in bindings:
            with self.subTest(task=binding["task_id"]):
                self.assertEqual(len(binding["fixture_tree_sha256"]), 64)
                self.assertEqual(len(binding["success_checker_sha256"]), 64)
                self.assertEqual(len(binding["prompt_sha256"]), 64)

    def test_overhead_ledger_records_local_engineering_cost_only(self) -> None:
        rows = [
            json.loads(line)
            for line in (self.output_root / "overhead-ledger.jsonl")
            .read_text(encoding="utf-8").splitlines() if line.strip()
        ]
        self.assertEqual(
            [row["phase"] for row in rows],
            ["study_prepare", "study_run", "study_analyze"],
        )
        for row in rows:
            with self.subTest(phase=row["phase"]):
                self.assertEqual(row["provider_calls"], 0)
                self.assertEqual(row["usd_spent"], 0.0)
                self.assertEqual(row["cost_class"], "local_engineering_overhead")

    def test_runtime_audit_proves_every_invocation_stayed_local(self) -> None:
        audit = self.report["deterministic"]["runtime_audit"]
        kinds = audit["fake_provider_invocation_kinds"]
        self.assertEqual(
            audit["audit_hook"], "fail_closed_blocked_network_and_process_events_v1",
        )
        self.assertEqual(kinds.get("provider"), 76)
        self.assertEqual(kinds.get("audit_clean"), 76)
        self.assertNotIn("audit_violation", kinds)

    def test_receipts_manifest_and_index_are_complete(self) -> None:
        completeness = self.report["deterministic"]["artifact_completeness"]
        for key in (
            "receipt_files", "artifact_index_rows", "terminal_runs",
            "terminal_attempts_with_verified_receipt",
        ):
            with self.subTest(key=key):
                self.assertEqual(completeness[key], 76)

    def test_same_path_rerun_reproduces_recorded_outputs_byte_for_byte(self) -> None:
        root = Path(self.tmp.name) / "same-path"
        digests = []
        for _ in range(2):
            shutil.rmtree(root, ignore_errors=True)
            proc = subprocess.run(
                [sys.executable, str(HARNESS), "--output-root", str(root)],
                capture_output=True, text=True, timeout=1800,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
            digests.append({
                name: hashlib.sha256((root / "study" / name).read_bytes()).hexdigest()
                for name in ("study-manifest.json", "study-report.json", "attempts.jsonl")
            })
        for name in digests[0]:
            with self.subTest(artifact=name):
                self.assertEqual(digests[0][name], digests[1][name])

    def test_deterministic_block_reproduces_byte_for_byte(self) -> None:
        second_root = Path(self.tmp.name) / "rehearsal-2"
        proc = subprocess.run(
            [sys.executable, str(HARNESS), "--output-root", str(second_root)],
            capture_output=True, text=True, timeout=1800,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        second = json.loads(
            (second_root / "rehearsal-report.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            self.report["deterministic_sha256"], second["deterministic_sha256"],
        )
        self.assertEqual(self.report["deterministic"], second["deterministic"])
        self.assertNotEqual(
            self.report["declared_timestamps"], second["declared_timestamps"],
        )


if __name__ == "__main__":
    unittest.main()
