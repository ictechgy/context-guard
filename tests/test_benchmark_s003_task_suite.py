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
RESULTS = SUITE / "results"
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
    "load_task_success_checker",
    "load_task_fixture_trees",
    "fixture_tree_manifest_files",
    "fixture_tree_sha256",
    "reset_task_fixture_tree",
    "run_task_checker_study",
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


def sample_tree(root: Path) -> Path:
    """Create a fixture tree plus a checker that lives outside that tree."""
    tree = root / "trees" / "sample"
    (tree / "src").mkdir(parents=True)
    (tree / "src" / "app.py").write_text("value = 1\n", encoding="utf-8")
    checkers = root / "checkers"
    checkers.mkdir(exist_ok=True)
    (checkers / "sample.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
    return tree


def sample_task(**overrides) -> dict:
    entry = {
        "id": "sample_task",
        "prompt": "sample prompt",
        "success_cwd": ".",
        "fixture_tree": "trees/sample",
        "success_checker": "checkers/sample.py",
    }
    entry.update(overrides)
    return entry


def run_bound_checker(tree: Path, checker_source: str, solution: dict | None) -> subprocess.CompletedProcess:
    """Run a checker exactly as the runner does: private copy, workspace cwd."""
    with tempfile.TemporaryDirectory() as tmp:
        workspace = Path(tmp) / "workspace"
        shutil.copytree(tree, workspace)
        for rel, content in sorted((solution or {}).items()):
            target = workspace / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        private = Path(tmp) / "private"
        private.mkdir()
        checker = private / "checker.py"
        checker.write_text(checker_source, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(checker)], cwd=workspace,
            capture_output=True, text=True, timeout=180,
        )


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

    def test_every_task_binds_a_checker_outside_its_fixture_tree(self) -> None:
        for entry in SUITE_TASKS:
            with self.subTest(task=entry["id"]):
                self.assertNotIn("success_command", entry)
                self.assertEqual(entry["success_cwd"], ".")
                self.assertTrue(entry["fixture_tree"].startswith("trees/"))
                self.assertTrue(entry["success_checker"].startswith("checkers/"))
                self.assertFalse(
                    entry["success_checker"].startswith(entry["fixture_tree"])
                )
                self.assertTrue((SUITE / entry["success_checker"]).is_file())

    def test_no_fixture_tree_ships_a_checker_the_agent_could_rewrite(self) -> None:
        """The measured agent must never see or be able to replace the checker."""
        for entry in SUITE_TASKS:
            tree = SUITE / entry["fixture_tree"]
            with self.subTest(task=entry["id"]):
                names = {path.name for path in tree.rglob("*") if path.is_file()}
                self.assertNotIn("check.py", names)
                self.assertNotIn("checker.py", names)
        self.assertEqual(list((SUITE / "trees").rglob("check.py")), [])

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
                self.assertGreaterEqual(len(entries), 1)
                paths = [entry.path for entry in entries]
                self.assertEqual(paths, sorted(paths))
                self.assertNotIn("check.py", paths)
                self.assertIsNone(task.success_command)
                self.assertTrue(task.success_checker_bytes)

    def test_rehearsal_solutions_never_live_inside_a_fixture_tree(self) -> None:
        self.assertEqual(sorted(SOLUTIONS), sorted(entry["id"] for entry in SUITE_TASKS))
        for tree in (SUITE / "trees").iterdir():
            with self.subTest(tree=tree.name):
                names = {path.name for path in tree.rglob("*")}
                self.assertNotIn("solutions.json", names)

    def test_allowed_tools_agree_across_tasks_and_both_arm_settings(self) -> None:
        """Arm comparability depends on one tool list; drift must be caught."""
        expected = SUITE_TASKS[0]["allowed_tools"]
        self.assertEqual(sorted(expected), expected)
        for entry in SUITE_TASKS:
            with self.subTest(task=entry["id"]):
                self.assertEqual(entry["allowed_tools"], expected)
        for arm in ("baseline", "treatment"):
            settings = json.loads(
                (SUITE / "settings" / f"{arm}.settings.json").read_text(encoding="utf-8")
            )
            with self.subTest(arm=arm):
                self.assertEqual(settings["permissions"]["allow"], expected)

    def test_study_plan_namespace_is_not_rehearsal_specific(self) -> None:
        plan = json.loads((SUITE / "study-plan.json").read_text(encoding="utf-8"))
        self.assertNotIn("rehearsal", plan["namespace"])

    def test_fixture_bytes_are_protected_from_eol_normalization(self) -> None:
        attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        self.assertIn("bench/token-savings-12task/** -text", attributes)

    def test_solution_paths_stay_inside_the_workspace(self) -> None:
        for task_id, files in sorted(SOLUTIONS.items()):
            for rel in sorted(files):
                with self.subTest(task=task_id, path=rel):
                    self.assertFalse(Path(rel).is_absolute())
                    self.assertNotIn("..", Path(rel).parts)


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
    def test_free_form_success_command_is_refused_with_a_fixture_tree(self) -> None:
        """The checker argv is derived, so no fixture may smuggle another command."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample_tree(root)
            with self.assertRaises(SystemExit):
                RUNNER_MODULE.parse_tasks(
                    write_task_file(root, [sample_task(success_command="python3 -c pass")])
                )

    def test_fixture_tree_requires_a_success_checker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample_tree(root)
            entry = sample_task()
            entry.pop("success_checker")
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
            self.assertEqual(tasks[0].success_command, "true")


class NormalBenchmarkFixtureBindingTest(unittest.TestCase):
    def test_normal_cli_binds_selected_fixture_before_provider_launch(self) -> None:
        for runner in (RUNNER, PACKAGED_RUNNER):
            with self.subTest(runner=runner):
                self._assert_selected_fixture_is_bound(runner)

    def _assert_selected_fixture_is_bound(self, runner: Path) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample_tree(root)
            tasks_path = write_task_file(
                root,
                [
                    sample_task(output_format="stream-json"),
                    sample_task(
                        id="unselected_broken_task",
                        fixture_tree="trees/missing",
                        success_checker="checkers/missing.py",
                        output_format="stream-json",
                    ),
                ],
            )
            for arm in ("baseline", "treatment"):
                shutil.copyfile(
                    SUITE / "settings" / f"{arm}.settings.json",
                    root / f"{arm}.settings.json",
                )
            artifacts = root / "artifacts"
            variants_text = (
                (SUITE / "variants.template.json").read_text(encoding="utf-8")
                .replace("{{CANDIDATE_HASH}}", "a" * 64)
                .replace("{{NAMESPACE}}", "normal-cli-fixture-binding")
                .replace("{{ARTIFACT_ROOT}}", str(artifacts))
            )
            variants_path = root / "variants.json"
            variants_path.write_text(variants_text, encoding="utf-8")
            provider_marker = root / "provider-launched"
            fake_cli = root / "fake-claude"
            fake_cli.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "from pathlib import Path\n"
                "if '--help' in sys.argv:\n"
                " print('--settings --setting-sources --include-hook-events --no-session-persistence stream-json')\n"
                " raise SystemExit(0)\n"
                "if '--version' in sys.argv:\n"
                " print('fake-claude-normal-binding 1.0')\n"
                " raise SystemExit(0)\n"
                f"Path({str(provider_marker)!r}).write_text('launched\\n')\n"
                "if Path('src/app.py').read_text() != 'value = 1\\n':\n"
                " raise SystemExit(22)\n"
                "print(json.dumps({'type':'result','subtype':'success','is_error':False,'usage':{'input_tokens':1,'cache_creation_input_tokens':0,'cache_read_input_tokens':0,'output_tokens':1},'total_cost_usd':0.0}))\n",
                encoding="utf-8",
            )
            fake_cli.chmod(0o700)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(runner),
                    "--tasks", str(tasks_path),
                    "--variants", str(variants_path),
                    "--csv", str(root / "results.csv"),
                    "--task-id", "sample_task",
                    "--variant", "baseline",
                    "--claude-bin", str(fake_cli),
                    "--project-root", str(root),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
            self.assertEqual(provider_marker.read_text(), "launched\n")


class CheckerIsolationTest(unittest.TestCase):
    """The success checker must be unreachable from the measured workspace."""

    def bind(self, root: Path):
        tasks = RUNNER_MODULE.parse_tasks(write_task_file(root, [sample_task()]))
        RUNNER_MODULE.load_task_fixture_trees(tasks, task_file_dir=root)
        return tasks[0]

    def test_checker_inside_the_fixture_tree_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tree = sample_tree(root)
            (tree / "check.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
            tasks = RUNNER_MODULE.parse_tasks(write_task_file(root, [sample_task()]))
            with self.assertRaises(SystemExit):
                RUNNER_MODULE.load_task_fixture_trees(tasks, task_file_dir=root)

    def test_checker_path_under_the_fixture_tree_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tree = sample_tree(root)
            (tree / "verify.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
            tasks = RUNNER_MODULE.parse_tasks(
                write_task_file(root, [sample_task(success_checker="trees/sample/verify.py")])
            )
            with self.assertRaises(SystemExit):
                RUNNER_MODULE.load_task_fixture_trees(tasks, task_file_dir=root)

    def test_missing_or_empty_checker_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample_tree(root)
            (root / "checkers" / "sample.py").write_text("", encoding="utf-8")
            tasks = RUNNER_MODULE.parse_tasks(write_task_file(root, [sample_task()]))
            with self.assertRaises(SystemExit):
                RUNNER_MODULE.load_task_fixture_trees(tasks, task_file_dir=root)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample_tree(root)
            (root / "checkers" / "sample.py").unlink()
            tasks = RUNNER_MODULE.parse_tasks(write_task_file(root, [sample_task()]))
            with self.assertRaises(SystemExit):
                RUNNER_MODULE.load_task_fixture_trees(tasks, task_file_dir=root)

    def test_bound_checker_bytes_are_used_even_if_the_workspace_copy_is_hostile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tree = sample_tree(root)
            (root / "checkers" / "sample.py").write_text(
                "from pathlib import Path\n"
                "raise SystemExit(0 if Path('src/app.py').read_text() == 'value = 2\\n' else 1)\n",
                encoding="utf-8",
            )
            task = self.bind(root)
            workspace = root / "workspace"
            workspace.mkdir(mode=0o700)
            RUNNER_MODULE.reset_task_fixture_tree(task.fixture_tree_entries, workspace)
            # 에이전트가 판정기 이름으로 자명 통과 파일을 심어도 무시되어야 한다.
            (workspace / "checker.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
            (workspace / "check.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
            env = {"PATH": os.defpath, "LANG": "C"}
            self.assertEqual(
                RUNNER_MODULE.run_task_checker_study(task, workspace, env=env),
                "valid_task_failure_v1",
            )
            (workspace / "src" / "app.py").write_text("value = 2\n", encoding="utf-8")
            self.assertEqual(
                RUNNER_MODULE.run_task_checker_study(task, workspace, env=env),
                "task_success",
            )

    def test_unbound_fixture_tree_fails_closed_instead_of_running_legacy(self) -> None:
        """An unbound declared tree must raise, not silently use the legacy path."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample_tree(root)
            tasks = RUNNER_MODULE.parse_tasks(write_task_file(root, [sample_task()]))
            task = tasks[0]
            self.assertIsNotNone(task.fixture_tree)
            self.assertIsNone(task.fixture_tree_entries)
            self.assertIsNone(task.success_checker_bytes)
            with self.assertRaises(SystemExit):
                RUNNER_MODULE._study_task_manifest(task, root)
            RUNNER_MODULE.load_task_fixture_trees(tasks, task_file_dir=root)
            task.success_checker_bytes = None
            with self.assertRaises(SystemExit):
                RUNNER_MODULE._study_task_manifest(task, root)

    def test_treatment_hook_bindings_are_documented_events(self) -> None:
        """PostToolUseFailure is a real event; pin it so the finding stops recurring."""
        documented = set(RUNNER_MODULE.MEASUREMENT_DOCUMENTED_HOOK_EVENTS)
        template = json.loads(
            (SUITE / "variants.template.json").read_text(encoding="utf-8")
        )
        treatment = next(item for item in template if item["name"] == "treatment")
        hooks = treatment["measurement"]["hook_events"]
        events = [binding["hook_event"] for binding in hooks["registered_bindings"]]
        self.assertNotIn("PostToolUseFailure", events)
        self.assertEqual(events, ["PreToolUse", "PostToolUse"])
        self.assertEqual(hooks["required_event_classes"], [])
        for event in events:
            with self.subTest(event=event):
                self.assertIn(event, documented)
        for event in hooks["required_event_classes"]:
            with self.subTest(required=event):
                self.assertIn(event, documented)
                self.assertIn(event, events)
        settings = json.loads(
            (SUITE / "settings" / "treatment.settings.json").read_text(encoding="utf-8")
        )
        self.assertEqual(sorted(settings["hooks"]), sorted(set(events)))

    def test_planted_sitecustomize_cannot_execute_inside_the_judge(self) -> None:
        """The judge runs isolated, so an agent-writable PYTHONPATH cannot hijack it."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tree = sample_tree(root)
            (root / "checkers" / "sample.py").write_text(
                "from pathlib import Path\n"
                "raise SystemExit(0 if Path('src/app.py').read_text() == 'value = 2\\n' else 1)\n",
                encoding="utf-8",
            )
            tasks = RUNNER_MODULE.parse_tasks(write_task_file(root, [sample_task()]))
            RUNNER_MODULE.load_task_fixture_trees(tasks, task_file_dir=root)
            task = tasks[0]
            workspace = root / "workspace"
            workspace.mkdir(mode=0o700)
            RUNNER_MODULE.reset_task_fixture_tree(task.fixture_tree_entries, workspace)
            # 에이전트가 판정기를 가로채려고 심는 전형적인 벡터.
            (workspace / "sitecustomize.py").write_text(
                "import os\nos._exit(0)\n", encoding="utf-8",
            )
            hostile_env = {
                "PATH": os.defpath,
                "LANG": "C",
                "PYTHONPATH": str(workspace),
                "PYTHONSTARTUP": str(workspace / "sitecustomize.py"),
            }
            self.assertEqual(
                RUNNER_MODULE.run_task_checker_study(task, workspace, env=hostile_env),
                "valid_task_failure_v1",
            )
            (workspace / "src" / "app.py").write_text("value = 2\n", encoding="utf-8")
            self.assertEqual(
                RUNNER_MODULE.run_task_checker_study(task, workspace, env=hostile_env),
                "task_success",
            )

    def test_hook_events_are_verified_against_the_installed_provider_cli(self) -> None:
        """Non-circular control: check the shipped CLI, not only our own frozen list."""
        evidence = json.loads(
            (SUITE / "hook-event-evidence.json").read_text(encoding="utf-8")
        )
        template = json.loads(
            (SUITE / "variants.template.json").read_text(encoding="utf-8")
        )
        treatment = next(item for item in template if item["name"] == "treatment")
        registered = [
            row["hook_event"]
            for row in treatment["measurement"]["hook_events"]["registered_bindings"]
        ]
        required = treatment["measurement"]["hook_events"]["required_event_classes"]
        self.assertEqual(evidence["events_registered_by_treatment"], registered)
        self.assertEqual(evidence["events_required_by_treatment"], required)
        for event in registered:
            with self.subTest(event=event, source="recorded evidence"):
                self.assertGreater(evidence["event_occurrences"][event], 0)
        which = shutil.which("claude")
        if which is None:
            self.skipTest("claude CLI is unavailable; recorded evidence is used instead")
        resolved = Path(os.path.realpath(which))
        if not resolved.is_file():
            self.skipTest("claude CLI does not resolve to a single readable bundle")
        raw = resolved.read_bytes()
        for event in registered:
            with self.subTest(event=event, source="installed CLI"):
                self.assertGreater(
                    raw.count(event.encode("ascii")), 0,
                    f"{event} is not present in the installed provider CLI",
                )

    def test_checker_runtime_reports_infra_invalid_without_bound_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample_tree(root)
            tasks = RUNNER_MODULE.parse_tasks(write_task_file(root, [sample_task()]))
            workspace = root / "workspace"
            workspace.mkdir(mode=0o700)
            self.assertEqual(
                RUNNER_MODULE.run_task_checker_study(
                    tasks[0], workspace, env={"PATH": os.defpath},
                ),
                "success_checker_infra_invalid",
            )


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

    def test_file_mode_change_is_hash_visible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tree = sample_tree(root)
            baseline = RUNNER_MODULE.fixture_tree_sha256(
                self.load_single(root).fixture_tree_entries
            )
            os.chmod(tree / "src" / "app.py", 0o755)
            mutated = RUNNER_MODULE.fixture_tree_sha256(
                self.load_single(root).fixture_tree_entries
            )
            self.assertNotEqual(baseline, mutated)

    def test_short_read_still_binds_complete_fixture_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tree = sample_tree(root)
            (tree / "src" / "app.py").write_text("value = 1\n" * 500, encoding="utf-8")
            expected = RUNNER_MODULE.fixture_tree_sha256(
                self.load_single(root).fixture_tree_entries
            )
            real_read = os.read

            def short_read(fd, size):
                return real_read(fd, 1 if size > 1 else size)

            os.read = short_read
            try:
                entries = self.load_single(root).fixture_tree_entries
            finally:
                os.read = real_read
            self.assertEqual(RUNNER_MODULE.fixture_tree_sha256(entries), expected)
            body = next(e for e in entries if e.path == "src/app.py")
            self.assertEqual(body.data.decode("utf-8"), "value = 1\n" * 500)


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
            self.assertEqual(
                (workspace / "src" / "app.py").stat().st_mode & 0o777, 0o600,
            )
            self.assertFalse((workspace / "check.py").exists())

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
            self.assertEqual(after, ["src/app.py"])

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
            self.assertEqual(len(entries), 1)

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
                self.assertEqual(checker["path"], task.success_checker)
                self.assertFalse(checker["inside_fixture_tree"])
                self.assertEqual(
                    checker["execution"],
                    "private_per_attempt_directory_outside_workspace_v1",
                )
                self.assertEqual(
                    checker["sha256"],
                    hashlib.sha256(task.success_checker_bytes or b"").hexdigest(),
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
    """Every checker must fail on the pristine tree and pass on the scripted end state."""

    def test_pristine_tree_fails_and_solution_passes(self) -> None:
        for entry in SUITE_TASKS:
            tree = SUITE / entry["fixture_tree"]
            source = (SUITE / entry["success_checker"]).read_text(encoding="utf-8")
            with self.subTest(task=entry["id"], state="pristine"):
                self.assertEqual(run_bound_checker(tree, source, None).returncode, 1)
            with self.subTest(task=entry["id"], state="solved"):
                self.assertEqual(
                    run_bound_checker(tree, source, SOLUTIONS[entry["id"]]).returncode, 0,
                )


class CheckerAdversarialControlTest(unittest.TestCase):
    """Negative controls for the failure modes the RA-S003 review round 2 found."""

    def checker_for(self, suffix: str) -> tuple[Path, str]:
        entry = next(
            item for item in SUITE_TASKS if item["fixture_tree"].endswith(suffix)
        )
        return (
            SUITE / entry["fixture_tree"],
            (SUITE / entry["success_checker"]).read_text(encoding="utf-8"),
        )

    def test_candidate_cannot_fake_success_by_exiting_or_forging(self) -> None:
        """Candidate code runs in a child process whose report the parent verifies."""
        tree, source = self.checker_for("09-performance")
        hostile = {
            "system_exit_at_import": "raise SystemExit(0)\n",
            "os_exit_at_import": "import os\nos._exit(0)\n",
            "rebind_parent_helpers": (
                "import __main__\n__main__.fail = __main__.ok\n"
                "def first_unique(rows):\n    return []\n"
            ),
            "forged_probe_line": (
                'print("PROBE {\\"missing\\": false, \\"cases\\": [[], [\\"a\\"], '
                '[\\"b\\",\\"a\\",\\"c\\"]], \\"order\\": [], \\"eq\\": 0}")\n'
                "import sys, os\nsys.stdout.flush()\nos._exit(0)\n"
            ),
            "system_exit_at_call_time": (
                "def first_unique(rows):\n    raise SystemExit(0)\n"
            ),
        }
        for label, payload in sorted(hostile.items()):
            with self.subTest(vector=label):
                result = run_bound_checker(tree, source, {"src/dedupe.py": payload})
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn("FAIL", result.stdout)

    def test_probe_line_must_carry_the_parent_nonce(self) -> None:
        for entry in SUITE_TASKS:
            source = (SUITE / entry["success_checker"]).read_text(encoding="utf-8")
            if "def probe(" not in source:
                continue
            with self.subTest(task=entry["id"]):
                self.assertIn("secrets.token_hex", source)
                self.assertIn("nonce-tagged PROBE line", source)
                self.assertIn("subprocess.run", source)

    def test_checkers_fail_closed_without_no_follow_support(self) -> None:
        """Behavioural control: remove O_NOFOLLOW and the checker must refuse to run."""
        entry = SUITE_TASKS[0]
        source = (SUITE / entry["success_checker"]).read_text(encoding="utf-8")
        for token in ('getattr(os, "O_NOFOLLOW", 0)', 'getattr(os, "O_DIRECTORY", 0)'):
            self.assertNotIn(token, source)
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "workspace"
            shutil.copytree(SUITE / entry["fixture_tree"], workspace)
            checker = Path(tmp) / "checker.py"
            checker.write_text(source, encoding="utf-8")
            shim = Path(tmp) / "sitecustomize.py"
            shim.write_text(
                "import os\n"
                "for name in ('O_NOFOLLOW', 'O_DIRECTORY'):\n"
                "    if hasattr(os, name):\n"
                "        delattr(os, name)\n",
                encoding="utf-8",
            )
            env = dict(os.environ)
            env["PYTHONPATH"] = str(tmp)
            result = subprocess.run(
                [sys.executable, str(checker)], cwd=workspace, env=env,
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertIn("platform lacks no-follow", result.stdout)

    def test_refactor_accepts_module_attribute_style(self) -> None:
        """`import shared` plus `shared.normalize_key(...)` is a valid refactor."""
        tree, source = self.checker_for("08-refactor")
        result = run_bound_checker(tree, source, {
            "src/shared.py": (
                "def normalize_key(raw):\n"
                "    return raw.strip().lower().replace(' ', '_')\n"
            ),
            "src/alpha.py": (
                "import shared\n\n\n"
                "def alpha_keys(rows):\n"
                "    return [shared.normalize_key(row) for row in rows]\n"
            ),
            "src/beta.py": (
                "import shared\n\n\n"
                "def beta_keys(rows):\n"
                "    return sorted(shared.normalize_key(row) for row in rows)\n"
            ),
        })
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_idiomatic_single_pass_solution_is_accepted(self) -> None:
        tree, source = self.checker_for("09-performance")
        result = run_bound_checker(tree, source, {
            "src/dedupe.py": "def first_unique(rows):\n    return list(dict.fromkeys(rows))\n",
        })
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_single_loop_quadratic_solution_is_rejected(self) -> None:
        tree, source = self.checker_for("09-performance")
        result = run_bound_checker(tree, source, {
            "src/dedupe.py": (
                "def first_unique(rows):\n"
                "    result = []\n"
                "    for row in rows:\n"
                "        if result.count(row) == 0:\n"
                "            result.append(row)\n"
                "    return result\n"
            ),
        })
        self.assertEqual(result.returncode, 1)
        self.assertIn("quadratically", result.stdout)

    def test_symlinked_workspace_file_is_rejected(self) -> None:
        tree, source = self.checker_for("01-small-fix")
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "workspace"
            shutil.copytree(tree, workspace)
            outside = Path(tmp) / "outside.py"
            outside.write_text("MAX_ITEMS = 10\nMIN_ITEMS = 1\n", encoding="utf-8")
            victim = workspace / "src" / "limits.py"
            victim.unlink()
            os.symlink(outside, victim)
            checker = Path(tmp) / "checker.py"
            checker.write_text(source, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(checker)], cwd=workspace,
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("FAIL", result.stdout)

    def test_symlinked_workspace_directory_is_rejected(self) -> None:
        tree, source = self.checker_for("01-small-fix")
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "workspace"
            shutil.copytree(tree, workspace)
            outside = Path(tmp) / "outsrc"
            outside.mkdir()
            (outside / "limits.py").write_text(
                "MAX_ITEMS = 10\nMIN_ITEMS = 1\n", encoding="utf-8",
            )
            shutil.rmtree(workspace / "src")
            os.symlink(outside, workspace / "src")
            checker = Path(tmp) / "checker.py"
            checker.write_text(source, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(checker)], cwd=workspace,
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("symlinked directory component", result.stdout)

    def test_refactor_task_accepts_the_idiomatic_import(self) -> None:
        """The 08 checker must not force a non-idiomatic sys.path hack."""
        tree, source = self.checker_for("08-refactor")
        result = run_bound_checker(tree, source, {
            "src/shared.py": (
                '"""Shared helpers."""\n\n\n'
                "def normalize_key(raw):\n"
                "    return raw.strip().lower().replace(' ', '_')\n"
            ),
            "src/alpha.py": (
                '"""Alpha report."""\n'
                "from shared import normalize_key\n\n\n"
                "def alpha_keys(rows):\n"
                "    return [normalize_key(row) for row in rows]\n"
            ),
            "src/beta.py": (
                '"""Beta report."""\n'
                "from shared import normalize_key\n\n\n"
                "def beta_keys(rows):\n"
                "    return sorted(normalize_key(row) for row in rows)\n"
            ),
        })
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_artifact_receipt_task_pins_the_full_log_bytes(self) -> None:
        tree, source = self.checker_for("12-artifact-receipt")
        solution = dict(SOLUTIONS["ts12_12_artifact_receipt"])
        solution["logs/full.log"] = "tampered\n" * 800
        result = run_bound_checker(tree, source, solution)
        self.assertEqual(result.returncode, 1)
        self.assertIn("byte-identical", result.stdout)


class SanitizedR9ResultContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.summary_path = RESULTS / "r9-summary.json"
        self.report_path = RESULTS / "r9-summary.md"
        self.dashboard_path = RESULTS / "r9-dashboard.md"
        self.summary = json.loads(self.summary_path.read_text(encoding="utf-8"))
        self.report = self.report_path.read_text(encoding="utf-8")
        self.dashboard = self.dashboard_path.read_text(encoding="utf-8")

    def test_result_is_explicitly_inconclusive_and_claimless(self) -> None:
        self.assertEqual(
            self.summary["schema_version"],
            "contextguard.bench.sanitized-study-summary.v1",
        )
        self.assertEqual(self.summary["suite"], "token-savings-12task")
        self.assertEqual(
            self.summary["candidate_commit"],
            "c311a208c731a5460c021c38577b68f909bc70b8",
        )
        self.assertEqual(
            self.summary["manifest_sha256"],
            "e5f4548371cf03fb80e134093d9a6113c7e4c29d578c267925bdb3c6f873f1df",
        )
        self.assertEqual(self.summary["verdict"], "inconclusive")
        self.assertFalse(self.summary["claim_allowed"])
        self.assertIsNone(self.summary["claim"])
        self.assertFalse(self.summary["gates"]["complete_pairs"])
        self.assertFalse(self.summary["subset_analysis_performed"])
        self.assertEqual(
            self.summary["methods"]["correction_severity"],
            "Theta_severity=mean_task(mean_repetition(S_treatment-S_baseline))",
        )
        self.assertEqual(
            self.summary["methods"]["correction_incidence"],
            "Theta_incidence=mean_task(mean_repetition(K_treatment-K_baseline)); K=1[S>0]",
        )
        self.assertEqual(
            self.summary["methods"]["inference_seed"],
            "0x434F4E5445585447",
        )
        self.assertEqual(
            self.summary["methods"]["correction_shuffle_seed"],
            "0x434F525245435433",
        )
        self.assertIn("rejection", self.summary["methods"]["bounded_draw"])
        self.assertIsNone(
            self.summary["correction_assessment"]["theta_severity"]
        )
        self.assertIsNone(
            self.summary["correction_assessment"]["theta_incidence"]
        )
        self.assertIsNone(
            self.summary["correction_assessment"]["theta_severity_q975"]
        )
        self.assertIsNone(
            self.summary["correction_assessment"]["theta_incidence_q975"]
        )
        self.assertIsNone(self.summary["cost_accounting"]["engineering_usd"])
        self.assertIsNone(self.summary["cost_accounting"]["review_usd"])

    def test_result_contains_no_private_execution_metadata(self) -> None:
        serialized = "\n".join((
            json.dumps(self.summary, sort_keys=True),
            self.report,
            self.dashboard,
        )).lower()
        for forbidden_key in (
            "run_id", "receipt_sha256", "artifact_index_sha256", "local_path",
            "raw_output", "credential", "access_token", "refresh_token",
        ):
            with self.subTest(forbidden_key=forbidden_key):
                self.assertNotIn(forbidden_key, serialized)
        self.assertNotIn("/users/", serialized)

    def test_human_report_discloses_methods_costs_and_stop_reason(self) -> None:
        for required in (
            "No token-savings claim",
            "inconclusive",
            "P = input + cache creation + cache read + output",
            "C = sum(P for every consumed attempt through success)",
            "D = C(treatment) - C(baseline)",
            "SplitMix64-v1",
            "Hyndman-Fan Type 7",
            "S(v,t,r)",
            "K(v,t,r) = 1[S(v,t,r) > 0]",
            "Theta_severity",
            "Theta_incidence",
            "0x434F4E5445585447",
            "0x434F525245435433",
            "rejection",
            "fixed retry",
            "correction assessment was not run",
            "client-reported diagnostic estimate",
            "canary",
            "engineering and review",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.report)
        for forbidden_claim in (
            "product-wide savings",
            "default-on savings",
            "proven savings",
            "guaranteed savings",
        ):
            with self.subTest(forbidden_claim=forbidden_claim):
                self.assertNotIn(forbidden_claim, self.report.lower())

    def test_dashboard_keeps_verdict_and_claim_boundary_visible(self) -> None:
        self.assertIn("Verdict | `inconclusive`", self.dashboard)
        self.assertIn("Claim allowed | `false`", self.dashboard)
        self.assertIn("Complete pairs | `false`", self.dashboard)
        self.assertIn("Correction assessment | Not run", self.dashboard)
        self.assertIn("No token-savings claim", self.dashboard)


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

    def test_report_records_its_own_validation_verdict(self) -> None:
        """A failed rehearsal must not leave an artifact that looks like a pass."""
        validation = self.report["deterministic"]["validation"]
        self.assertTrue(validation["passed"])
        self.assertEqual(validation["problems"], [])
        # 검증 결과가 deterministic 해시에 포함되어야 위조/혼동이 불가능하다.
        digest = hashlib.sha256(json.dumps(
            self.report["deterministic"], ensure_ascii=True, sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        self.assertEqual(digest, self.report["deterministic_sha256"])
        mutated = json.loads(json.dumps(self.report["deterministic"]))
        mutated["validation"]["problems"] = ["injected"]
        mutated_digest = hashlib.sha256(json.dumps(
            mutated, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        self.assertNotEqual(digest, mutated_digest)

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

    def test_reproduces_across_roots_and_byte_for_byte_on_the_same_root(self) -> None:
        """One extra pair of runs covers both determinism claims; three runs total."""
        second_root = Path(self.tmp.name) / "rehearsal-2"
        digests = []
        reports = []
        for _ in range(2):
            shutil.rmtree(second_root, ignore_errors=True)
            proc = subprocess.run(
                [sys.executable, str(HARNESS), "--output-root", str(second_root)],
                capture_output=True, text=True, timeout=1800,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
            digests.append({
                name: hashlib.sha256((second_root / "study" / name).read_bytes()).hexdigest()
                for name in ("study-manifest.json", "study-report.json", "attempts.jsonl")
            })
            reports.append(json.loads(
                (second_root / "rehearsal-report.json").read_text(encoding="utf-8")
            ))
        for name in digests[0]:
            with self.subTest(artifact=name, claim="same-root byte identity"):
                self.assertEqual(digests[0][name], digests[1][name])
        for index, second in enumerate(reports):
            with self.subTest(run=index, claim="cross-root determinism"):
                self.assertEqual(
                    self.report["deterministic_sha256"], second["deterministic_sha256"],
                )
                self.assertEqual(self.report["deterministic"], second["deterministic"])
                self.assertNotEqual(
                    self.report["declared_timestamps"], second["declared_timestamps"],
                )


if __name__ == "__main__":
    unittest.main()
