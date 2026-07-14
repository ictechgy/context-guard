"""Benchmark, setup/statusline, and escrow tests split from test_context_guard_kit.

This module intentionally imports only shared helpers/constants from the large
base test module instead of wildcard-importing TestCase classes, so unittest
discovery does not duplicate tests.
"""

import csv
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest

SELF_TOPLEVEL_MODULE = "test_context_guard_kit_benchmark_surfaces"
SELF_PACKAGE_MODULE = "tests.test_context_guard_kit_benchmark_surfaces"
BASE_TOPLEVEL_MODULE = "test_context_guard_kit"
BASE_PACKAGE_MODULE = "tests.test_context_guard_kit"


def canonicalize_current_module():
    module = sys.modules[__name__]
    sys.modules[SELF_TOPLEVEL_MODULE] = module
    sys.modules[SELF_PACKAGE_MODULE] = module
    package = sys.modules.get("tests")
    if package is None:
        try:
            package = importlib.import_module("tests")
        except ModuleNotFoundError:
            package = None
    if package is not None:
        setattr(package, "test_context_guard_kit_benchmark_surfaces", module)
    return module


canonicalize_current_module()


def load_base_test_module():
    # unittest discover -s tests imports test modules by top-level name, while
    # dotted invocations such as `python -m unittest tests.<module>` use the
    # package-qualified name.  Keep both sys.modules keys pointed at the same
    # object so shared fixtures/state are not duplicated by the split module.
    module = sys.modules.get(BASE_TOPLEVEL_MODULE) or sys.modules.get(BASE_PACKAGE_MODULE)
    if module is None:
        try:
            module = importlib.import_module(BASE_TOPLEVEL_MODULE)
        except ModuleNotFoundError:
            module = importlib.import_module(BASE_PACKAGE_MODULE)
    sys.modules[BASE_TOPLEVEL_MODULE] = module
    sys.modules[BASE_PACKAGE_MODULE] = module
    return module


base = load_base_test_module()

ARTIFACT_SCRIPTS = base.ARTIFACT_SCRIPTS
KIT_DIR = base.KIT_DIR
PLUGIN_BIN = base.PLUGIN_BIN
PLUGIN_DIR = base.PLUGIN_DIR
ROOT = base.ROOT
SETUP_SCRIPTS = base.SETUP_SCRIPTS
load_module_from_path = base.load_module_from_path
load_python_script_module = base.load_python_script_module

BENCH_SCRIPTS = [KIT_DIR / "benchmark_runner.py", PLUGIN_BIN / "context-guard-bench"]

# ---------------------------------------------------------------------------
# Image-context evaluation profile contract (PRD/test-spec phase 4/5).
#
# These are the *stable public* strings of the optional evaluation profile.  The
# tests below deliberately assert them through public surfaces (report JSON, CLI
# exit status, dashboard text) rather than through runner-private helper names,
# so the lane contract stays provable even if the runner refactors internally.
# ---------------------------------------------------------------------------
IMAGE_CONTEXT_EVALUATION_PROFILE_ID = "contextguard.bench.image-context-pack-evaluation.v1"
IMAGE_CONTEXT_READINESS_SCHEMA_VERSION = "contextguard.bench.image-context-pack-readiness.v1"
IMAGE_CONTEXT_PROFILE_REPORT_KEY = "image_context_pack"
IMAGE_CONTEXT_EVALUATION_ONLY_CLAIM_STATUS = "image_context_pack_evaluation_only_not_public_claim"

# reject_prewrite error ids, in the PRD's deterministic order.
PROFILE_REJECT_ERROR_IDS = (
    "profile_controls_missing",
    "profile_schema_invalid",
    "profile_binding_mismatch",
    "profile_batch_incomplete",
    "profile_fresh_output_required",
    "profile_prompt_binding_invalid",
    "profile_correction_inconsistent",
    "profile_measurement_inconsistent",
    "profile_fallback_claim_inconsistent",
    # A profiled task may only be replayed.  Selecting one without --evidence-jsonl
    # must reject before the provider runtime is reachable at all.
    "profile_replay_required",
)

# Lane gate ids, in the PRD's deterministic order.  The two regression gates carry
# the generic matched-pair quality verdict into lane readiness: a profiled batch may
# never reach bounded-pilot review while the generic quality gate is not `pass`.
IMAGE_CONTEXT_GATE_IDS = (
    "profile_and_prompt_binding",
    "protected_zone_deny_review",
    "exact_text_fallback_binding",
    "missed_context_review",
    "human_correction_consistency",
    "corrections_regression",
    "failure_rate_regression",
    "generic_matched_success_and_measurement",
    "evaluation_only_promotion_boundary",
)

# The imported proof-verifier projection binds to the *existing* verifier contract
# in context-guard-kit/experimental_registry.py; replay never re-runs the verifier.
PROOF_VERIFY_SCHEMA_VERSION = "contextguard.experiments.proof-carrying-context-verification.v1"
PROOF_VERIFICATION_CLAIM_BOUNDARY = (
    "Local receipt/hash/range/command binding only; no semantic-safety, protected-zone, freshness, replacement, "
    "omission, or hosted-savings authority."
)


class SplitModuleCompatibilityTests(unittest.TestCase):
    def test_base_module_aliases_share_one_module_object(self):
        self.assertIs(sys.modules[BASE_TOPLEVEL_MODULE], sys.modules[BASE_PACKAGE_MODULE])

    def test_split_module_aliases_share_one_module_object(self):
        top_level = importlib.import_module(SELF_TOPLEVEL_MODULE)
        package_qualified = importlib.import_module(SELF_PACKAGE_MODULE)
        self.assertIs(top_level, package_qualified)
        self.assertIs(top_level, sys.modules[__name__])

    def test_module_aliases_are_import_order_independent(self):
        pairs = (
            (BASE_TOPLEVEL_MODULE, BASE_PACKAGE_MODULE, BASE_TOPLEVEL_MODULE, BASE_PACKAGE_MODULE),
            (BASE_PACKAGE_MODULE, BASE_TOPLEVEL_MODULE, BASE_TOPLEVEL_MODULE, BASE_PACKAGE_MODULE),
            (SELF_TOPLEVEL_MODULE, SELF_PACKAGE_MODULE, SELF_TOPLEVEL_MODULE, SELF_PACKAGE_MODULE),
            (SELF_PACKAGE_MODULE, SELF_TOPLEVEL_MODULE, SELF_TOPLEVEL_MODULE, SELF_PACKAGE_MODULE),
        )
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        for first, second, top_name, package_name in pairs:
            with self.subTest(first=first, second=second):
                code = f"""
import importlib
import pathlib
import sys
import unittest
root = pathlib.Path.cwd()
sys.path.insert(0, str(root / 'tests'))
sys.path.insert(0, str(root))
first = importlib.import_module({first!r})
second = importlib.import_module({second!r})
assert first is second, (first, second)
assert sys.modules[{top_name!r}] is sys.modules[{package_name!r}]
import tests
assert getattr(tests, {package_name.rsplit('.', 1)[1]!r}) is sys.modules[{package_name!r}]
base_suite = unittest.defaultTestLoader.loadTestsFromName('tests.test_context_guard_kit.BenchmarkRunnerTests')
split_suite = unittest.defaultTestLoader.loadTestsFromName('tests.test_context_guard_kit_benchmark_surfaces.BenchmarkRunnerTests')
assert base_suite.countTestCases() == 75, base_suite
assert split_suite.countTestCases() == 75, split_suite
"""
                subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, check=True, text=True, capture_output=True)

    def test_legacy_dotted_test_paths_resolve_without_discovery_aliases(self):
        self.assertNotIn("BenchmarkRunnerTests", dir(base))
        suite = unittest.defaultTestLoader.loadTestsFromName(f"{BASE_TOPLEVEL_MODULE}.BenchmarkRunnerTests")
        self.assertEqual(suite.countTestCases(), 75)
        statusline_suite = unittest.defaultTestLoader.loadTestsFromName(f"{BASE_TOPLEVEL_MODULE}.StatuslineMergedWrapperTests")
        self.assertEqual(statusline_suite.countTestCases(), 10)


def _make_fake_claude(tmpdir: Path, usage: dict | None = None, exit_code: int = 0,
                     stdout: str | None = None) -> Path:
    """token usage 가 들어있는 JSON 을 print 하는 가짜 `claude` 바이너리를 만든다."""
    fake = tmpdir / "fake-claude"
    if stdout is None:
        payload = {"message": {"usage": usage or {}}, "total_cost_usd": 0.0123}
        stdout = json.dumps(payload)
    script_lines = [
        "#!/usr/bin/env python3",
        "import sys",
        f"sys.stdout.write({stdout!r})",
        f"sys.exit({exit_code})",
    ]
    fake.write_text("\n".join(script_lines), encoding="utf-8")
    fake.chmod(0o755)
    return fake


class BenchmarkRunnerTests(unittest.TestCase):
    """benchmark runner 의 fixture parsing, CSV append, fake claude 호출 시나리오 검증."""

    def test_fixture_readers_reject_symlink_targets_and_parents(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_nofollow_inputs_{index}")
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    real_dir = root / "real"
                    real_dir.mkdir()
                    tasks = real_dir / "tasks.json"
                    tasks.write_text(json.dumps([{"id": "t01", "prompt": "x"}]), encoding="utf-8")
                    variants = real_dir / "variants.json"
                    variants.write_text(json.dumps([{"name": "baseline", "extra_args": []}]), encoding="utf-8")
                    direct_link = root / "tasks-link.json"
                    parent_link = root / "tasks-link-dir"
                    try:
                        direct_link.symlink_to(tasks)
                        parent_link.symlink_to(real_dir, target_is_directory=True)
                    except (OSError, NotImplementedError) as exc:
                        self.skipTest(f"symlink unavailable: {exc}")

                    with self.assertRaises(OSError):
                        module.parse_tasks(direct_link)
                    with self.assertRaises(OSError):
                        module.parse_tasks(parent_link / "tasks.json")
                    with self.assertRaises(OSError):
                        module.parse_variants(parent_link / "variants.json")

    def test_benchmark_runner_bounds_fixture_prompt_and_resume_csv_reads(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_large_input_caps_{index}")
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    oversized_tasks = root / "tasks.json"
                    oversized_tasks.write_text(
                        json.dumps([{"id": "t01", "prompt": "x" * (module.MAX_FIXTURE_FILE_BYTES + 1)}]),
                        encoding="utf-8",
                    )
                    with self.assertRaises(SystemExit) as fixture_ctx:
                        module.parse_tasks(oversized_tasks)
                    self.assertIn("fixture file exceeds", str(fixture_ctx.exception))

                    prompt_tasks = root / "prompt-tasks.json"
                    module.MAX_FIXTURE_FILE_BYTES = 10_000
                    module.MAX_CLAUDE_PROMPT_ARG_BYTES = 8
                    prompt_tasks.write_text(
                        json.dumps([{"id": "t01", "prompt": "x" * 16}]),
                        encoding="utf-8",
                    )
                    prompt_fixtures = module.parse_tasks(prompt_tasks)
                    variant = module.Variant(name="baseline", extra_args=[])
                    with self.assertRaises(SystemExit) as prompt_ctx:
                        module.build_claude_argv("claude", prompt_fixtures[0], variant)
                    self.assertIn("prompt exceeds argv-safe limit", str(prompt_ctx.exception))

                    csv_path = root / "resume.csv"
                    task_id_index = module.CSV_COLUMNS.index("task_id")
                    variant_index = module.CSV_COLUMNS.index("variant")
                    csv_row_1 = [""] * len(module.CSV_COLUMNS)
                    csv_row_1[task_id_index] = "t01"
                    csv_row_1[variant_index] = "baseline"
                    csv_row_2 = [""] * len(module.CSV_COLUMNS)
                    csv_row_2[task_id_index] = "t02"
                    csv_row_2[variant_index] = "baseline"
                    csv_path.write_text(
                        ",".join(module.CSV_COLUMNS) + "\n"
                        + ",".join(csv_row_1) + "\n"
                        + ",".join(csv_row_2) + "\n",
                        encoding="utf-8",
                    )
                    module.MAX_CSV_ROWS = 1
                    with self.assertRaises(SystemExit) as csv_ctx:
                        module._read_existing_keys_unlocked(csv_path)
                    self.assertIn("CSV row limit exceeded", str(csv_ctx.exception))

    def test_variant_prompt_files_select_prompt_and_fallback(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_variant_prompt_select_{index}")
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    prompt_file = root / "digest.prompt.md"
                    prompt_file.write_text("digest prompt evidence", encoding="utf-8")
                    tasks_path = root / "tasks.json"
                    variants_path = root / "variants.json"
                    tasks_path.write_text(
                        json.dumps([
                            {
                                "id": "t01",
                                "prompt": "fallback prompt evidence",
                                "variant_prompt_files": {"digest": prompt_file.name},
                            }
                        ]),
                        encoding="utf-8",
                    )
                    variants_path.write_text(
                        json.dumps([
                            {"name": "baseline", "extra_args": []},
                            {"name": "digest", "extra_args": []},
                        ]),
                        encoding="utf-8",
                    )

                    variants = module.parse_variants(variants_path)
                    tasks = module.parse_tasks(tasks_path, variants=variants)
                    task = tasks[0]
                    baseline = next(variant for variant in variants if variant.name == "baseline")
                    digest = next(variant for variant in variants if variant.name == "digest")
                    task.variant_prompt_texts["digest"] = "stale inline prompt evidence"
                    module.load_variant_prompt_files_for_targets(
                        [(task, digest)],
                        task_file_dir=tasks_path.parent,
                    )
                    self.assertEqual(
                        module.build_claude_argv("claude", task, baseline)[-1],
                        "fallback prompt evidence",
                    )
                    self.assertEqual(
                        module.build_claude_argv("claude", task, digest)[-1],
                        "digest prompt evidence",
                    )

    def test_variant_prompt_files_reject_unsafe_and_unknown_before_read(self):
        cases = (
            (
                "absolute",
                {"variant_prompt_files": {"digest": "/tmp/never-read.prompt.md"}},
                "relative",
            ),
            (
                "parent",
                {"variant_prompt_files": {"digest": "../never-read.prompt.md"}},
                "must not contain",
            ),
            (
                "inline_unsupported",
                {"variant_prompts": {"digest": "inline prompt"}},
                "variant_prompts is not supported",
            ),
            (
                "unknown_before_read",
                {"variant_prompt_files": {"typo_variant": "/tmp/never-read.prompt.md"}},
                "unknown variant",
            ),
        )
        for index, script in enumerate(BENCH_SCRIPTS):
            module = load_python_script_module(script, f"_bench_runner_variant_prompt_reject_{index}")
            for name, extra, expected in cases:
                with self.subTest(script=script, case=name):
                    with tempfile.TemporaryDirectory() as tmp:
                        root = Path(tmp)
                        tasks_path = root / "tasks.json"
                        variants_path = root / "variants.json"
                        task = {"id": "t01", "prompt": "fallback prompt"}
                        task.update(extra)
                        tasks_path.write_text(json.dumps([task]), encoding="utf-8")
                        variants_path.write_text(
                            json.dumps([
                                {"name": "baseline", "extra_args": []},
                                {"name": "digest", "extra_args": []},
                            ]),
                            encoding="utf-8",
                        )
                        variants = module.parse_variants(variants_path)
                        with self.assertRaises(SystemExit) as ctx:
                            module.parse_tasks(tasks_path, variants=variants)
                        self.assertIn(expected, str(ctx.exception))
                        if name == "unknown_before_read":
                            self.assertNotIn("relative", str(ctx.exception))

    def test_variant_prompt_files_reject_symlink_prompt_files(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_variant_prompt_symlink_{index}")
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    real_prompt = root / "real.prompt.md"
                    real_prompt.write_text("digest prompt evidence", encoding="utf-8")
                    link_prompt = root / "link.prompt.md"
                    try:
                        link_prompt.symlink_to(real_prompt)
                    except (OSError, NotImplementedError) as exc:
                        self.skipTest(f"symlink unavailable: {exc}")
                    tasks_path = root / "tasks.json"
                    variants_path = root / "variants.json"
                    tasks_path.write_text(
                        json.dumps([
                            {
                                "id": "t01",
                                "prompt": "fallback prompt",
                                "variant_prompt_files": {"digest": link_prompt.name},
                            }
                        ]),
                        encoding="utf-8",
                    )
                    variants_path.write_text(
                        json.dumps([{"name": "digest", "extra_args": []}]),
                        encoding="utf-8",
                    )
                    variants = module.parse_variants(variants_path)
                    tasks = module.parse_tasks(tasks_path, variants=variants)
                    with self.assertRaises(SystemExit) as ctx:
                        module.load_variant_prompt_files_for_targets(
                            [(tasks[0], variants[0])],
                            task_file_dir=tasks_path.parent,
                        )
                    self.assertIn("could not read prompt file", str(ctx.exception))

    def test_variant_prompt_files_defer_unselected_reads_and_fail_selected_clearly(self):
        for script in BENCH_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    tasks_path = root / "tasks.json"
                    variants_path = root / "variants.json"
                    csv_path = root / "results.csv"
                    tasks_path.write_text(
                        json.dumps([
                            {
                                "id": "t01",
                                "prompt": "fallback prompt evidence",
                                "max_turns": 1,
                                "variant_prompt_files": {"digest": "missing-digest.prompt.md"},
                            }
                        ]),
                        encoding="utf-8",
                    )
                    variants_path.write_text(
                        json.dumps([
                            {"name": "baseline", "extra_args": []},
                            {"name": "digest", "extra_args": []},
                        ]),
                        encoding="utf-8",
                    )

                    baseline_proc = subprocess.run(
                        [
                            sys.executable,
                            str(script),
                            "--tasks",
                            str(tasks_path),
                            "--variants",
                            str(variants_path),
                            "--task-id",
                            "t01",
                            "--variant",
                            "baseline",
                            "--csv",
                            str(csv_path),
                            "--dry-run",
                        ],
                        text=True,
                        capture_output=True,
                        check=True,
                    )
                    self.assertIn("fallback prompt evidence", baseline_proc.stdout)
                    self.assertNotIn("Traceback", baseline_proc.stderr)

                    digest_proc = subprocess.run(
                        [
                            sys.executable,
                            str(script),
                            "--tasks",
                            str(tasks_path),
                            "--variants",
                            str(variants_path),
                            "--task-id",
                            "t01",
                            "--variant",
                            "digest",
                            "--csv",
                            str(root / "digest.csv"),
                            "--dry-run",
                        ],
                        text=True,
                        capture_output=True,
                    )
                    self.assertNotEqual(digest_proc.returncode, 0)
                    self.assertIn("could not read prompt file", digest_proc.stderr)
                    self.assertNotIn("Traceback", digest_proc.stderr)

    def test_variant_prompt_files_defer_unselected_task_reads(self):
        for script in BENCH_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    selected_prompt = root / "selected-digest.prompt.md"
                    selected_prompt.write_text("selected digest prompt evidence", encoding="utf-8")
                    tasks_path = root / "tasks.json"
                    variants_path = root / "variants.json"
                    tasks_path.write_text(
                        json.dumps([
                            {
                                "id": "selected",
                                "prompt": "selected fallback prompt evidence",
                                "max_turns": 1,
                                "variant_prompt_files": {"digest": selected_prompt.name},
                            },
                            {
                                "id": "unselected",
                                "prompt": "unselected fallback prompt",
                                "max_turns": 1,
                                "variant_prompt_files": {"digest": "missing-unselected.prompt.md"},
                            },
                        ]),
                        encoding="utf-8",
                    )
                    variants_path.write_text(
                        json.dumps([
                            {"name": "baseline", "extra_args": []},
                            {"name": "digest", "extra_args": []},
                        ]),
                        encoding="utf-8",
                    )

                    selected_proc = subprocess.run(
                        [
                            sys.executable,
                            str(script),
                            "--tasks",
                            str(tasks_path),
                            "--variants",
                            str(variants_path),
                            "--task-id",
                            "selected",
                            "--variant",
                            "digest",
                            "--csv",
                            str(root / "selected.csv"),
                            "--dry-run",
                        ],
                        text=True,
                        capture_output=True,
                        check=True,
                    )
                    self.assertIn("selected digest prompt evidence", selected_proc.stdout)
                    self.assertNotIn("selected fallback prompt evidence", selected_proc.stdout)
                    self.assertNotIn("missing-unselected", selected_proc.stderr)

                    unselected_digest_proc = subprocess.run(
                        [
                            sys.executable,
                            str(script),
                            "--tasks",
                            str(tasks_path),
                            "--variants",
                            str(variants_path),
                            "--task-id",
                            "unselected",
                            "--variant",
                            "digest",
                            "--csv",
                            str(root / "unselected.csv"),
                            "--dry-run",
                        ],
                        text=True,
                        capture_output=True,
                    )
                    self.assertNotEqual(unselected_digest_proc.returncode, 0)
                    self.assertIn("could not read prompt file", unselected_digest_proc.stderr)
                    self.assertNotIn("Traceback", unselected_digest_proc.stderr)

    def test_variant_prompt_files_defer_unselected_oversized_prompt_file(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_variant_prompt_defer_size_{index}")
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    oversized = root / "oversized.prompt.md"
                    oversized.write_text("x" * (module.MAX_VARIANT_PROMPT_FILE_BYTES + 1), encoding="utf-8")
                    tasks_path = root / "tasks.json"
                    variants_path = root / "variants.json"
                    tasks_path.write_text(
                        json.dumps([
                            {
                                "id": "t01",
                                "prompt": "fallback prompt evidence",
                                "max_turns": 1,
                                "variant_prompt_files": {"digest": oversized.name},
                            }
                        ]),
                        encoding="utf-8",
                    )
                    variants_path.write_text(
                        json.dumps([
                            {"name": "baseline", "extra_args": []},
                            {"name": "digest", "extra_args": []},
                        ]),
                        encoding="utf-8",
                    )
                    proc = subprocess.run(
                        [
                            sys.executable,
                            str(script),
                            "--tasks",
                            str(tasks_path),
                            "--variants",
                            str(variants_path),
                            "--task-id",
                            "t01",
                            "--variant",
                            "baseline",
                            "--csv",
                            str(root / "results.csv"),
                            "--dry-run",
                        ],
                        text=True,
                        capture_output=True,
                        check=True,
                    )
                    self.assertIn("fallback prompt evidence", proc.stdout)
                    self.assertNotIn("exceeds", proc.stderr)

    def test_variant_prompt_files_reject_oversized_selected_prompt_file(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_variant_prompt_size_{index}")
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    prompt_file = root / "oversized.prompt.md"
                    prompt_file.write_text(
                        "x" * (module.MAX_VARIANT_PROMPT_FILE_BYTES + 1),
                        encoding="utf-8",
                    )
                    tasks_path = root / "tasks.json"
                    variants_path = root / "variants.json"
                    tasks_path.write_text(
                        json.dumps([
                            {
                                "id": "t01",
                                "prompt": "fallback prompt",
                                "variant_prompt_files": {"digest": prompt_file.name},
                            }
                        ]),
                        encoding="utf-8",
                    )
                    variants_path.write_text(
                        json.dumps([{"name": "digest", "extra_args": []}]),
                        encoding="utf-8",
                    )
                    variants = module.parse_variants(variants_path)
                    tasks = module.parse_tasks(tasks_path, variants=variants)
                    with self.assertRaises(SystemExit) as ctx:
                        module.load_variant_prompt_files_for_targets(
                            [(tasks[0], variants[0])],
                            task_file_dir=tasks_path.parent,
                        )
                    self.assertIn("exceeds", str(ctx.exception))

    def test_variant_prompt_files_reject_non_utf8_selected_prompt_file(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_variant_prompt_utf8_{index}")
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    prompt_file = root / "binary.prompt.md"
                    prompt_file.write_bytes(b"\xff\xfe\x00")
                    tasks_path = root / "tasks.json"
                    variants_path = root / "variants.json"
                    tasks_path.write_text(
                        json.dumps([
                            {
                                "id": "t01",
                                "prompt": "fallback prompt",
                                "variant_prompt_files": {"digest": prompt_file.name},
                            }
                        ]),
                        encoding="utf-8",
                    )
                    variants_path.write_text(
                        json.dumps([{"name": "digest", "extra_args": []}]),
                        encoding="utf-8",
                    )
                    variants = module.parse_variants(variants_path)
                    tasks = module.parse_tasks(tasks_path, variants=variants)
                    with self.assertRaises(SystemExit) as ctx:
                        module.load_variant_prompt_files_for_targets(
                            [(tasks[0], variants[0])],
                            task_file_dir=tasks_path.parent,
                        )
                    self.assertIn("UTF-8", str(ctx.exception))

    def test_variant_prompt_files_reject_symlink_parent_directories(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_variant_prompt_parent_symlink_{index}")
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    real_dir = root / "real"
                    real_dir.mkdir()
                    (real_dir / "prompt.md").write_text("digest prompt evidence", encoding="utf-8")
                    link_dir = root / "linked"
                    try:
                        link_dir.symlink_to(real_dir, target_is_directory=True)
                    except (OSError, NotImplementedError) as exc:
                        self.skipTest(f"symlink unavailable: {exc}")
                    tasks_path = root / "tasks.json"
                    variants_path = root / "variants.json"
                    tasks_path.write_text(
                        json.dumps([
                            {
                                "id": "t01",
                                "prompt": "fallback prompt",
                                "variant_prompt_files": {"digest": "linked/prompt.md"},
                            }
                        ]),
                        encoding="utf-8",
                    )
                    variants_path.write_text(
                        json.dumps([{"name": "digest", "extra_args": []}]),
                        encoding="utf-8",
                    )
                    variants = module.parse_variants(variants_path)
                    tasks = module.parse_tasks(tasks_path, variants=variants)
                    with self.assertRaises(SystemExit) as ctx:
                        module.load_variant_prompt_files_for_targets(
                            [(tasks[0], variants[0])],
                            task_file_dir=tasks_path.parent,
                        )
                    self.assertIn("could not read prompt file", str(ctx.exception))

    def test_csv_access_rejects_symlink_targets_and_parents(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_nofollow_csv_{index}")
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    real_dir = root / "real"
                    real_dir.mkdir()
                    csv_path = real_dir / "results.csv"
                    csv_path.write_text("task_id,variant\nold,baseline\n", encoding="utf-8")
                    direct_link = root / "results-link.csv"
                    parent_link = root / "results-link-dir"
                    try:
                        direct_link.symlink_to(csv_path)
                        parent_link.symlink_to(real_dir, target_is_directory=True)
                    except (OSError, NotImplementedError) as exc:
                        self.skipTest(f"symlink unavailable: {exc}")
                    result = module.RunResult(
                        task_id="t01",
                        variant="baseline",
                        model="sonnet",
                        effort=None,
                        tokens={"input_tokens": 1, "output_tokens": 0, "cache_read": 0, "cache_creation": 0},
                        cost_usd=0.0,
                        success=True,
                        notes="ok",
                    )

                    with self.assertRaises(OSError):
                        module.existing_keys(direct_link)
                    with self.assertRaises(OSError):
                        module.append_csv(direct_link, "test", result)
                    with self.assertRaises(OSError):
                        module.append_csv(parent_link / "new.csv", "test", result)
                    lock_target = root / "lock-target"
                    lock_target.write_text("guard", encoding="utf-8")
                    locked_csv = real_dir / "locked.csv"
                    lock_link = real_dir / "locked.csv.lock"
                    lock_link.symlink_to(lock_target)
                    with self.assertRaises(OSError):
                        module.append_csv(locked_csv, "test", result)
                    self.assertFalse(locked_csv.exists())
                    self.assertEqual(lock_target.read_text(encoding="utf-8"), "guard")
                    self.assertEqual(csv_path.read_text(encoding="utf-8"), "task_id,variant\nold,baseline\n")

    def test_csv_notes_are_sanitized_before_write(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_csv_note_sanitize_{index}")
                with tempfile.TemporaryDirectory() as tmp:
                    csv_path = Path(tmp) / "results.csv"
                    for prefix in module.CSV_FORMULA_PREFIXES:
                        result = module.RunResult(
                            task_id=f"t{ord(prefix):02x}",
                            variant="baseline",
                            model="sonnet",
                            effort=None,
                            tokens={"input_tokens": 1, "output_tokens": 0, "cache_read": 0, "cache_creation": 0},
                            cost_usd=0.0,
                            success=False,
                            notes=(
                                f"{prefix}HYPERLINK(\"http://example.invalid\")\x00\x7f\u009b\u200b\n"
                                "Authorization: Bearer opaque-token-value "
                                "token=opaque-token-value "
                                "API_TOKEN=upper-token-value "
                                "access_token=access-secret-value "
                                "refresh_token=refresh-secret-value "
                                "DB_PASSWORD=db-secret-value "
                                "SECRET_KEY=secret-key-value "
                                "api_key=plain-api-key "
                                '"token": "json-secret-value" '
                                "X-Api-Key: header-secret-value "
                                "--api-key 'quoted secret value' "
                                "--user=admin:password "
                                "https://token@mirror.example.invalid/pkg "
                                "github_pat_" + ("B" * 24) + " "
                                "postgres://user:pass@example.invalid/db "
                                + ("x" * 800)
                            ),
                        )
                        module.append_csv(csv_path, "test", result)

                    with csv_path.open(encoding="utf-8", newline="") as f:
                        rows = list(csv.DictReader(f))
                    self.assertEqual(len(rows), len(module.CSV_FORMULA_PREFIXES))
                    for row, prefix in zip(rows, module.CSV_FORMULA_PREFIXES, strict=True):
                        with self.subTest(prefix=prefix):
                            note = row["notes"]
                            self.assertTrue(note.startswith("'" + prefix))
                            self.assertNotIn("\x00", note)
                            self.assertNotIn("\x7f", note)
                            self.assertNotIn("\u009b", note)
                            self.assertNotIn("\u200b", note)
                            self.assertNotIn("\n", note)
                            self.assertNotIn("opaque-token-value", note)
                            self.assertNotIn("upper-token-value", note)
                            self.assertNotIn("access-secret-value", note)
                            self.assertNotIn("refresh-secret-value", note)
                            self.assertNotIn("db-secret-value", note)
                            self.assertNotIn("secret-key-value", note)
                            self.assertNotIn("plain-api-key", note)
                            self.assertNotIn("json-secret-value", note)
                            self.assertNotIn("header-secret-value", note)
                            self.assertNotIn("quoted secret value", note)
                            self.assertNotIn("admin:password", note)
                            self.assertNotIn("token@mirror", note)
                            self.assertNotIn("github_pat_", note)
                            self.assertNotIn("user:pass", note)
                            self.assertIn("[REDACTED]", note)
                            self.assertLessEqual(len(note), module.MAX_CSV_NOTE_CHARS)
                            self.assertIn("…[truncated]", note)

    def test_note_secret_argument_redaction_preserves_surrounding_quotes(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_arg_note_sanitize_{index}")
                note = module.sanitize_note_text(
                    'prefix "--api-key secret-value" suffix '
                    '"--user=admin:password" '
                    '--token "quoted secret value" '
                    "-p --model sonnet"
                )
                self.assertIn('prefix "--api-key [REDACTED]" suffix', note)
                self.assertIn('"--user=[REDACTED]"', note)
                self.assertIn("--token [REDACTED]", note)
                self.assertIn("-p --model sonnet", note)
                self.assertNotIn("secret-value", note)
                self.assertNotIn("admin:password", note)
                self.assertNotIn("quoted secret value", note)

    def test_csv_access_uses_advisory_lock_file(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_csv_lock_{index}")
                if module.fcntl is None:
                    self.skipTest("fcntl unavailable")
                with tempfile.TemporaryDirectory() as tmp:
                    csv_path = Path(tmp) / "results.csv"
                    result = module.RunResult(
                        task_id="t01",
                        variant="baseline",
                        model="sonnet",
                        effort=None,
                        tokens={"input_tokens": 1, "output_tokens": 0, "cache_read": 0, "cache_creation": 0},
                        cost_usd=0.0,
                        success=True,
                        notes="ok",
                    )
                    operations: list[int] = []
                    real_flock = module.fcntl.flock

                    def recording_flock(fd, operation):
                        operations.append(operation)
                        return real_flock(fd, operation)

                    module.fcntl.flock = recording_flock
                    try:
                        module.append_csv(csv_path, "test", result)
                        self.assertEqual(module.existing_keys(csv_path), {("t01", "baseline")})
                    finally:
                        module.fcntl.flock = real_flock

                    lock_path = csv_path.with_name("results.csv.lock")
                    self.assertTrue(lock_path.exists())
                    lock_mode = lock_path.stat().st_mode & 0o777
                    self.assertEqual(lock_mode & 0o111, 0)
                    self.assertTrue(lock_mode & 0o600)
                    self.assertGreaterEqual(operations.count(module.fcntl.LOCK_EX), 2)
                    self.assertGreaterEqual(operations.count(module.fcntl.LOCK_UN), 2)

    def test_append_csv_skip_existing_suppresses_duplicate_rows(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_csv_dedupe_{index}")
                with tempfile.TemporaryDirectory() as tmp:
                    csv_path = Path(tmp) / "results.csv"
                    first = module.RunResult(
                        task_id="t01",
                        variant="baseline",
                        model="sonnet",
                        effort=None,
                        tokens={"input_tokens": 1, "output_tokens": 0, "cache_read": 0, "cache_creation": 0},
                        cost_usd=0.0,
                        success=True,
                        notes="first",
                    )
                    duplicate = module.RunResult(
                        task_id="t01",
                        variant="baseline",
                        model="sonnet",
                        effort=None,
                        tokens={"input_tokens": 999, "output_tokens": 999, "cache_read": 0, "cache_creation": 0},
                        cost_usd=999.0,
                        success=False,
                        notes="duplicate",
                    )
                    self.assertTrue(module.append_csv(csv_path, "test", first))
                    self.assertFalse(module.append_csv(csv_path, "test", duplicate, skip_existing=True))
                    with csv_path.open(encoding="utf-8") as f:
                        rows = list(csv.DictReader(f))
                    self.assertEqual(len(rows), 1)
                    self.assertEqual(rows[0]["notes"], "first")

    def test_append_csv_resume_key_cache_avoids_per_append_reread(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_csv_dedupe_cache_{index}")
                with tempfile.TemporaryDirectory() as tmp:
                    csv_path = Path(tmp) / "results.csv"
                    existing = {("t01", "baseline")}
                    duplicate = module.RunResult(
                        task_id="t01",
                        variant="baseline",
                        model="sonnet",
                        effort=None,
                        tokens={"input_tokens": 1, "output_tokens": 0, "cache_read": 0, "cache_creation": 0},
                        cost_usd=0.0,
                        success=True,
                        notes="duplicate",
                    )
                    fresh = module.RunResult(
                        task_id="t02",
                        variant="baseline",
                        model="sonnet",
                        effort=None,
                        tokens={"input_tokens": 2, "output_tokens": 0, "cache_read": 0, "cache_creation": 0},
                        cost_usd=0.0,
                        success=True,
                        notes="fresh",
                    )
                    original = module._read_existing_keys_unlocked
                    stamp = {"stamp": module.csv_file_stamp_unlocked(csv_path)}

                    def fail_read(_path):
                        raise AssertionError("resume writes should use the already-loaded key cache")

                    module._read_existing_keys_unlocked = fail_read
                    try:
                        self.assertFalse(
                            module.append_csv(
                                csv_path,
                                "test",
                                duplicate,
                                skip_existing=True,
                                existing_key_cache=existing,
                                existing_key_cache_stamp=stamp,
                            )
                        )
                        self.assertTrue(
                            module.append_csv(
                                csv_path,
                                "test",
                                fresh,
                                skip_existing=True,
                                existing_key_cache=existing,
                                existing_key_cache_stamp=stamp,
                            )
                        )
                    finally:
                        module._read_existing_keys_unlocked = original
                    self.assertIn(("t02", "baseline"), existing)
                    with csv_path.open(encoding="utf-8") as f:
                        rows = list(csv.DictReader(f))
                    self.assertEqual([row["task_id"] for row in rows], ["t02"])

    def test_append_csv_resume_key_cache_refreshes_when_csv_changes(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_csv_dedupe_cache_refresh_{index}")
                with tempfile.TemporaryDirectory() as tmp:
                    csv_path = Path(tmp) / "results.csv"
                    stale_cache: set[tuple[str, str]] = set()
                    stamp = {"stamp": module.csv_file_stamp_unlocked(csv_path)}
                    first = module.RunResult(
                        task_id="t01",
                        variant="baseline",
                        model="sonnet",
                        effort=None,
                        tokens={"input_tokens": 1, "output_tokens": 0, "cache_read": 0, "cache_creation": 0},
                        cost_usd=0.0,
                        success=True,
                        notes="first",
                    )
                    duplicate = module.RunResult(
                        task_id="t01",
                        variant="baseline",
                        model="sonnet",
                        effort=None,
                        tokens={"input_tokens": 999, "output_tokens": 999, "cache_read": 0, "cache_creation": 0},
                        cost_usd=999.0,
                        success=False,
                        notes="duplicate",
                    )
                    self.assertTrue(module.append_csv(csv_path, "test", first))
                    real_read = module._read_existing_keys_unlocked
                    read_count = 0

                    def counting_read(path):
                        nonlocal read_count
                        read_count += 1
                        return real_read(path)

                    module._read_existing_keys_unlocked = counting_read
                    try:
                        self.assertFalse(
                            module.append_csv(
                                csv_path,
                                "test",
                                duplicate,
                                skip_existing=True,
                                existing_key_cache=stale_cache,
                                existing_key_cache_stamp=stamp,
                            )
                        )
                    finally:
                        module._read_existing_keys_unlocked = real_read
                    self.assertEqual(read_count, 1)
                    self.assertIn(("t01", "baseline"), stale_cache)
                    with csv_path.open(encoding="utf-8") as f:
                        rows = list(csv.DictReader(f))
                    self.assertEqual(len(rows), 1)
                    self.assertEqual(rows[0]["notes"], "first")

    def test_append_csv_resume_key_cache_drops_keys_removed_by_rewrite(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_csv_dedupe_cache_rewrite_{index}")
                with tempfile.TemporaryDirectory() as tmp:
                    csv_path = Path(tmp) / "results.csv"
                    first = module.RunResult(
                        task_id="t01",
                        variant="baseline",
                        model="sonnet",
                        effort=None,
                        tokens={"input_tokens": 1, "output_tokens": 0, "cache_read": 0, "cache_creation": 0},
                        cost_usd=0.0,
                        success=True,
                        notes="first",
                    )
                    rerun = module.RunResult(
                        task_id="t01",
                        variant="baseline",
                        model="sonnet",
                        effort=None,
                        tokens={"input_tokens": 2, "output_tokens": 0, "cache_read": 0, "cache_creation": 0},
                        cost_usd=0.0,
                        success=True,
                        notes="rerun",
                    )
                    self.assertTrue(module.append_csv(csv_path, "test", first))
                    stale_cache, stale_stamp = module.existing_keys_snapshot(csv_path)
                    self.assertIn(("t01", "baseline"), stale_cache)
                    stamp = {"stamp": stale_stamp}
                    csv_path.write_text(",".join(module.CSV_COLUMNS) + "\n", encoding="utf-8")
                    self.assertFalse(module.resume_key_present(csv_path, ("t01", "baseline"), stale_cache, stamp))
                    self.assertNotIn(("t01", "baseline"), stale_cache)
                    self.assertTrue(
                        module.append_csv(
                            csv_path,
                            "test",
                            rerun,
                            skip_existing=True,
                            existing_key_cache=stale_cache,
                            existing_key_cache_stamp=stamp,
                        )
                    )
                    with csv_path.open(encoding="utf-8") as f:
                        rows = list(csv.DictReader(f))
                    self.assertEqual(len(rows), 1)
                    self.assertEqual(rows[0]["notes"], "rerun")

    def test_resume_runnable_targets_refreshes_before_preflight(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_resume_preflight_refresh_{index}")
                with tempfile.TemporaryDirectory() as tmp:
                    csv_path = Path(tmp) / "results.csv"
                    first = module.RunResult(
                        task_id="t01",
                        variant="baseline",
                        model="sonnet",
                        effort=None,
                        tokens={"input_tokens": 1, "output_tokens": 0, "cache_read": 0, "cache_creation": 0},
                        cost_usd=0.0,
                        success=True,
                        notes="first",
                    )
                    self.assertTrue(module.append_csv(csv_path, "test", first))
                    cache, loaded_stamp = module.existing_keys_snapshot(csv_path)
                    stamp = {"stamp": loaded_stamp}
                    self.assertIn(("t01", "baseline"), cache)

                    task_id_index = module.CSV_COLUMNS.index("task_id")
                    variant_index = module.CSV_COLUMNS.index("variant")
                    csv_row = [""] * len(module.CSV_COLUMNS)
                    csv_row[task_id_index] = "t02"
                    csv_row[variant_index] = "baseline"
                    csv_path.write_text(
                        ",".join(module.CSV_COLUMNS) + "\n"
                        + ",".join(csv_row) + "\n",
                        encoding="utf-8",
                    )
                    targets = [
                        (module.TaskFixture(id="t01", prompt="p1"), module.Variant(name="baseline")),
                        (module.TaskFixture(id="t02", prompt="p2"), module.Variant(name="baseline")),
                    ]
                    runnable = module.resume_runnable_targets(
                        csv_path,
                        targets,
                        resume=True,
                        existing_key_cache=cache,
                        existing_key_cache_stamp=stamp,
                    )
                    self.assertEqual([task.id for task, _variant in runnable], ["t01"])
                    self.assertEqual(cache, {("t02", "baseline")})
                    evidence = module.EvidenceReplayRow(
                        result=module.RunResult(
                            task_id="t01",
                            variant="baseline",
                            model="evidence",
                            effort="",
                            tokens={"input_tokens": 1, "output_tokens": 0, "cache_read": 0, "cache_creation": 0},
                            cost_usd=0.0,
                            success=True,
                            notes="ok",
                        ),
                        source_type="synthetic_fixture",
                        provider_name=None,
                        capture_command_or_export_id=None,
                        claim_scope="fixture_only",
                        provider_export_provenance_complete=False,
                        public_claim_eligible=False,
                        explicit_notes=True,
                        line_number=1,
                    )
                    coverage = module.validate_evidence_coverage([evidence], runnable)
                    self.assertEqual(set(coverage), {("t01", "baseline")})

    def test_benchmark_runner_rejects_incompatible_existing_csv_schema(self):
        shift_columns = {
            "turns",
            "hook_triggers",
            "bytes_before",
            "bytes_after",
            "artifacts_used",
            "primary_tokens_measured",
            "provider_cached_tokens",
            "provider_cached_tokens_measured",
            "cost_measured",
            "wall_time_seconds",
            "external_tokens",
            "external_tokens_measured",
            "external_cost_usd",
            "external_cost_measured",
            "total_cost_with_shift_usd",
        }
        legacy_columns = {
            "date",
            "claude_version",
            "task_id",
            "variant",
            "model",
            "effort",
            "total_tokens",
            "input_tokens",
            "output_tokens",
            "cache_read",
            "cache_creation",
            "cost_usd",
            "success",
            "corrections",
            "notes",
        }
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_csv_schema_{index}")
                self.assertEqual(set(module.CSV_COLUMNS) - shift_columns, legacy_columns)
                with tempfile.TemporaryDirectory() as tmp:
                    csv_path = Path(tmp) / "results.csv"
                    old_columns = [column for column in module.CSV_COLUMNS if column not in shift_columns]
                    old_row = [
                        "2026-05-01T00:00:00", "test", "t00", "baseline", "sonnet", "",
                        "10", "5", "5", "0", "0", "0.000000", "true", "0", "old schema",
                    ]
                    csv_path.write_text(",".join(old_columns) + "\n" + ",".join(old_row) + "\n", encoding="utf-8")
                    result = module.RunResult(
                        task_id="t01",
                        variant="optimized",
                        model="sonnet",
                        effort=None,
                        tokens={"input_tokens": 1, "output_tokens": 0, "cache_read": 0, "cache_creation": 0},
                        cost_usd=0.0,
                        success=True,
                        notes="ok",
                    )

                    with self.assertRaises(SystemExit) as append_ctx:
                        module.append_csv(csv_path, "test", result)
                    self.assertIn("CSV schema mismatch", str(append_ctx.exception))
                    with self.assertRaises(SystemExit) as report_ctx:
                        module.read_csv_rows(csv_path)
                    self.assertIn("CSV schema mismatch", str(report_ctx.exception))
                    with csv_path.open(encoding="utf-8") as f:
                        rows = list(csv.reader(f))
                    self.assertEqual(rows[0], old_columns)
                    self.assertEqual(len(rows), 2)

                    blank_header_csv = Path(tmp) / "blank-header-results.csv"
                    blank_header_csv.write_text("\nold,row\n", encoding="utf-8")
                    with self.assertRaises(SystemExit) as blank_append_ctx:
                        module.append_csv(blank_header_csv, "test", result)
                    self.assertIn("CSV schema mismatch", str(blank_append_ctx.exception))
                    with self.assertRaises(SystemExit) as blank_report_ctx:
                        module.read_csv_rows(blank_header_csv)
                    self.assertIn("CSV schema mismatch", str(blank_report_ctx.exception))

                    empty_csv = Path(tmp) / "empty-results.csv"
                    empty_csv.write_text("", encoding="utf-8")
                    self.assertEqual(module.read_csv_rows(empty_csv), [])
                    self.assertEqual(module._read_existing_keys_unlocked(empty_csv), set())
                    self.assertTrue(module.append_csv(empty_csv, "test", result))
                    with empty_csv.open(encoding="utf-8") as f:
                        rows = list(csv.DictReader(f))
                    self.assertEqual(len(rows), 1)
                    self.assertEqual(rows[0]["task_id"], "t01")

    def test_benchmark_report_does_not_claim_shifted_cost_when_cost_unmeasured(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_cost_unmeasured_{index}")
                report = module.summarize_benchmark_rows(
                    [
                        {
                            "task_id": "t01",
                            "variant": "baseline",
                            "success": "true",
                            "total_tokens": "100",
                            "primary_tokens_measured": "true",
                            "cost_usd": "0",
                            "cost_measured": "false",
                            "external_tokens": "0",
                            "external_tokens_measured": "true",
                            "external_cost_usd": "0",
                            "external_cost_measured": "false",
                            "total_cost_with_shift_usd": "0",
                            "corrections": "0",
                        },
                        {
                            "task_id": "t01",
                            "variant": "optimized",
                            "success": "true",
                            "total_tokens": "50",
                            "primary_tokens_measured": "true",
                            "cost_usd": "0",
                            "cost_measured": "false",
                            "external_tokens": "0",
                            "external_tokens_measured": "true",
                            "external_cost_usd": "0",
                            "external_cost_measured": "false",
                            "total_cost_with_shift_usd": "0",
                            "corrections": "0",
                        },
                    ],
                    "baseline",
                )
                self.assertEqual(report["claim_status"], "token_savings_observed_cost_unmeasured")
                self.assertIsNone(report["comparisons"][0]["cost_savings_pct_with_shift"])
                baseline = report["measurement_baseline"]
                self.assertEqual(baseline["schema_version"], "contextguard.bench.measurement-baseline.v1")
                self.assertTrue(baseline["csv_schema_unchanged"])
                self.assertIn("total_cost_with_shift_usd", baseline["csv_columns"])
                self.assertIn("primary_token_buckets", baseline["captured_fields"])
                self.assertIn("primary_tokens_measured", baseline["captured_fields"]["primary_token_buckets"])
                self.assertIn("repo_revision", baseline["missing_future_run_identity_fields"])
                self.assertFalse(baseline["claim_boundary"]["enables_savings_claims_by_itself"])
                self.assertTrue(baseline["claim_boundary"]["requires_matched_successful_tasks"])

    def test_benchmark_report_treats_missing_external_cost_as_unmeasured(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_external_cost_unknown_{index}")
                report = module.summarize_benchmark_rows(
                    [
                        {
                            "task_id": "t01",
                            "variant": "baseline",
                            "success": "true",
                            "total_tokens": "100",
                            "primary_tokens_measured": "true",
                            "cost_usd": "0.10",
                            "cost_measured": "true",
                            "external_tokens": "0",
                            "external_tokens_measured": "true",
                            "external_cost_usd": "0",
                            "external_cost_measured": "false",
                            "total_cost_with_shift_usd": "0.10",
                            "corrections": "0",
                        },
                        {
                            "task_id": "t01",
                            "variant": "optimized",
                            "success": "true",
                            "total_tokens": "50",
                            "primary_tokens_measured": "true",
                            "cost_usd": "0.05",
                            "cost_measured": "true",
                            "external_tokens": "9",
                            "external_tokens_measured": "true",
                            "external_cost_usd": "0",
                            "external_cost_measured": "false",
                            "total_cost_with_shift_usd": "",
                            "corrections": "0",
                        },
                    ],
                    "baseline",
                )
                self.assertEqual(report["claim_status"], "token_savings_observed_cost_unmeasured")
                self.assertIsNone(report["comparisons"][0]["cost_savings_pct_with_shift"])
                self.assertEqual(report["comparisons"][0]["paired_cost_task_count"], 0)

    def test_benchmark_runner_sums_multiple_external_shift_metrics(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_shift_sum_{index}")
                metrics = module.collect_shift_metrics(
                    {
                        "message": {"usage": {"input_tokens": 1}},
                        "aux_calls": [
                            {"auxiliary_tokens": 3, "auxiliary_cost_usd": 0.01},
                            {"subagent_tokens": 5, "subagent_cost_usd": 0.02},
                            {"provider_tokens": 7, "provider_cost_usd": 0.03},
                        ],
                    }
                )
                self.assertEqual(metrics["external_tokens"], 15)
                self.assertTrue(metrics["external_tokens_measured"])
                self.assertTrue(metrics["external_cost_measured"])
                self.assertAlmostEqual(metrics["external_cost_usd"], 0.06, places=6)
                aggregate = module.collect_shift_metrics(
                    {
                        "metrics": {
                            "external_tokens": 9,
                            "external_cost_usd": 0.09,
                            "calls": [{"subagent_tokens": 5, "subagent_cost_usd": 0.05}],
                        },
                    }
                )
                self.assertEqual(aggregate["external_tokens"], 9)
                self.assertTrue(aggregate["external_tokens_measured"])
                self.assertTrue(aggregate["external_cost_measured"])
                self.assertAlmostEqual(aggregate["external_cost_usd"], 0.09, places=6)
                partial = module.collect_shift_metrics({"metrics": {"auxiliary_tokens": 5}})
                self.assertEqual(partial["external_tokens"], 5)
                self.assertTrue(partial["external_tokens_measured"])
                self.assertFalse(partial["external_cost_measured"])
                leaf_only = module.collect_shift_metrics(
                    {
                        "metrics": {
                            "auxiliary_tokens": 99,
                            "auxiliary_cost_usd": 0.99,
                            "children": [{"auxiliary_tokens": 4, "auxiliary_cost_usd": 0.04}],
                        }
                    }
                )
                self.assertEqual(leaf_only["external_tokens"], 4)
                self.assertTrue(leaf_only["external_tokens_measured"])
                self.assertTrue(leaf_only["external_cost_measured"])
                self.assertAlmostEqual(leaf_only["external_cost_usd"], 0.04, places=6)

    def test_benchmark_cost_shift_requires_explicit_external_token_telemetry(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_shift_measured_{index}")
                result = module.RunResult(
                    task_id="t01",
                    variant="optimized",
                    model="sonnet",
                    effort=None,
                    tokens={"input_tokens": 1, "output_tokens": 1, "cache_read": 0, "cache_creation": 0},
                    cost_usd=0.01,
                    cost_measured=True,
                    success=True,
                    notes="ok",
                )
                self.assertFalse(module.cost_shift_measured(result))
                result.external_tokens_measured = True
                self.assertTrue(module.cost_shift_measured(result))

    def test_benchmark_report_quality_gate_catches_failed_or_unmatched_tasks(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_quality_gate_{index}")
                report = module.summarize_benchmark_rows(
                    [
                        {
                            "task_id": "t01",
                            "variant": "baseline",
                            "success": "true",
                            "total_tokens": "100",
                            "primary_tokens_measured": "true",
                        },
                        {
                            "task_id": "t02",
                            "variant": "baseline",
                            "success": "true",
                            "total_tokens": "100",
                            "primary_tokens_measured": "true",
                        },
                        {
                            "task_id": "t01",
                            "variant": "optimized",
                            "success": "true",
                            "total_tokens": "50",
                            "primary_tokens_measured": "true",
                        },
                        {
                            "task_id": "t02",
                            "variant": "optimized",
                            "success": "false",
                            "total_tokens": "25",
                            "primary_tokens_measured": "true",
                        },
                    ],
                    "baseline",
                )
                comparison = report["comparisons"][0]
                self.assertEqual(report["claim_status"], "quality_gate_watch")
                self.assertEqual(comparison["quality_gate"], "matched_task_regression")
                self.assertEqual(comparison["missing_baseline_success_tasks"], ["t02"])
                self.assertEqual(
                    report["summary_by_variant"]["optimized"]["tokens_per_task_including_failures"],
                    37.5,
                )

    def test_benchmark_report_quality_gate_catches_corrections_regression(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_corrections_gate_{index}")
                report = module.summarize_benchmark_rows(
                    [
                        {
                            "task_id": "t01",
                            "variant": "baseline",
                            "success": "true",
                            "total_tokens": "100",
                            "primary_tokens_measured": "true",
                            "corrections": "0",
                        },
                        {
                            "task_id": "t01",
                            "variant": "optimized",
                            "success": "true",
                            "total_tokens": "50",
                            "primary_tokens_measured": "true",
                            "corrections": "2",
                        },
                    ],
                    "baseline",
                )
                comparison = report["comparisons"][0]
                self.assertEqual(report["claim_status"], "quality_gate_watch")
                self.assertEqual(comparison["quality_gate"], "corrections_regression")
                self.assertEqual(comparison["corrections_delta_per_successful_task"], 2.0)

    def test_benchmark_report_quality_gate_requires_valid_corrections_data(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_corrections_missing_{index}")
                report = module.summarize_benchmark_rows(
                    [
                        {
                            "task_id": "t01",
                            "variant": "baseline",
                            "success": "true",
                            "total_tokens": "100",
                            "primary_tokens_measured": "true",
                            "corrections": "0",
                        },
                        {
                            "task_id": "t01",
                            "variant": "optimized",
                            "success": "true",
                            "total_tokens": "50",
                            "primary_tokens_measured": "true",
                            "corrections": "nan",
                        },
                    ],
                    "baseline",
                )
                comparison = report["comparisons"][0]
                self.assertEqual(report["claim_status"], "quality_gate_watch")
                self.assertEqual(comparison["quality_gate"], "insufficient_corrections_data")
                self.assertEqual(comparison["paired_corrections_task_count"], 0)

    def test_benchmark_runner_locks_ledger_and_report_outputs(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_output_locks_{index}")
                if module.fcntl is None:
                    self.skipTest("fcntl unavailable")
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    result = module.RunResult(
                        task_id="t01",
                        variant="baseline",
                        model="sonnet",
                        effort=None,
                        tokens={"input_tokens": 1, "output_tokens": 1, "cache_read": 0, "cache_creation": 0},
                        cost_usd=0.01,
                        cost_measured=True,
                        success=True,
                        notes="ok",
                    )
                    csv_path = root / "results.csv"
                    module.append_csv(csv_path, "test", result)
                    report_path = root / "report.json"
                    module.write_report_json(csv_path, report_path, "baseline")
                    self.assertTrue(report_path.exists())
                    self.assertTrue(csv_path.with_name("results.csv.lock").exists())
                    self.assertTrue(report_path.with_name("report.json.lock").exists())

                    ledger_path = root / "cost-shift.jsonl"
                    module.append_cost_shift_ledger(ledger_path, "test", result)
                    self.assertTrue(ledger_path.exists())
                    self.assertTrue(ledger_path.with_name("cost-shift.jsonl.lock").exists())

                    guarded = root / "guarded"
                    guarded.write_text("guard", encoding="utf-8")
                    bad_ledger = root / "bad-ledger.jsonl"
                    bad_ledger.with_name("bad-ledger.jsonl.lock").symlink_to(guarded)
                    with self.assertRaises(OSError):
                        module.append_cost_shift_ledger(bad_ledger, "test", result)
                    self.assertEqual(guarded.read_text(encoding="utf-8"), "guard")
                    self.assertFalse(bad_ledger.exists())

                    bad_report = root / "bad-report.json"
                    bad_report.with_name("bad-report.json.lock").symlink_to(guarded)
                    with self.assertRaises(OSError):
                        module.write_report_json(csv_path, bad_report, "baseline")
                    self.assertEqual(guarded.read_text(encoding="utf-8"), "guard")
                    self.assertFalse(bad_report.exists())

    def test_benchmark_runner_rejects_overlapping_output_paths(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_output_paths_{index}")
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    csv_path = root / "bench" / ".." / "results.csv"
                    with self.assertRaises(SystemExit) as report_ctx:
                        module.validate_distinct_output_paths(csv_path, None, root / "results.csv")
                    self.assertIn("--report-json must not point to the same path as --csv", str(report_ctx.exception))

                    with self.assertRaises(SystemExit) as ledger_ctx:
                        module.validate_distinct_output_paths(root / "results.csv", root / "results.csv", None)
                    self.assertIn("--ledger-jsonl must not point to the same path as --csv", str(ledger_ctx.exception))

                    module.validate_distinct_output_paths(
                        root / "results.csv",
                        root / "cost-shift.jsonl",
                        root / "report.json",
                        root / "dashboard.md",
                    )

                    with self.assertRaises(SystemExit) as dashboard_ctx:
                        module.validate_distinct_output_paths(
                            root / "results.csv",
                            root / "cost-shift.jsonl",
                            root / "report.json",
                            root / "bench" / ".." / "results.csv",
                        )
                    self.assertIn("--dashboard-md must not point to the same path as --csv", str(dashboard_ctx.exception))

    def test_benchmark_runner_replays_evidence_without_provider_and_writes_dashboard(self):
        for script in BENCH_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    placeholder = "python3 -c \"raise SystemExit('fixture-only placeholder: replace success_command before real benchmark runs')\""
                    tasks_path = root / "tasks.json"
                    variants_path = root / "variants.json"
                    evidence_path = root / "evidence.jsonl"
                    tasks_path.write_text(json.dumps([
                        {
                            "id": "t01",
                            "prompt": "fixture prompt",
                            "model": "sonnet",
                            "effort": "medium",
                            "max_turns": 1,
                            "success_command": placeholder,
                            "success_cwd": ".",
                        }
                    ]), encoding="utf-8")
                    variants_path.write_text(json.dumps([
                        {"name": "baseline", "extra_args": []},
                        {"name": "optimized", "extra_args": []},
                    ]), encoding="utf-8")

                    def evidence_row(variant: str, input_tokens: int, output_tokens: int, bytes_after: int) -> dict:
                        return {
                            "schema_version": "contextguard.bench.run-evidence.v1",
                            "task_id": "t01",
                            "variant": variant,
                            "model": "sonnet",
                            "effort": "medium",
                            "success": True,
                            "tokens": {"input_tokens": input_tokens, "output_tokens": output_tokens},
                            "primary_tokens_measured": True,
                            "cost_usd": 0.123,
                            "cost_measured": True,
                            "external_tokens": 0,
                            "external_tokens_measured": True,
                            "external_cost_usd": 0,
                            "external_cost_measured": True,
                            "bytes_before": 1000,
                            "bytes_after": bytes_after,
                            "corrections": 0,
                            "notes": f"synthetic {variant}",
                            "provenance": {
                                "evidence_source_type": "synthetic_fixture",
                                "capture_command_or_export_id": "unit-test-fixture",
                                "claim_scope": "local_replay_fixture_not_public_claim",
                            },
                        }

                    evidence_path.write_text(
                        "\n".join([
                            json.dumps(evidence_row("baseline", 100, 20, 1000)),
                            json.dumps(evidence_row("optimized", 50, 10, 200)),
                        ]) + "\n",
                        encoding="utf-8",
                    )
                    dry_csv = root / "dry-results.csv"
                    dry_proc = subprocess.run(
                        [
                            sys.executable,
                            str(script),
                            "--tasks",
                            str(tasks_path),
                            "--variants",
                            str(variants_path),
                            "--csv",
                            str(dry_csv),
                            "--evidence-jsonl",
                            str(evidence_path),
                            "--dry-run",
                            "--claude-bin",
                            str(root / "missing-claude"),
                        ],
                        text=True,
                        capture_output=True,
                        check=True,
                    )
                    self.assertIn("evidence replay dry-run", dry_proc.stdout)
                    self.assertFalse(dry_csv.exists())
                    self.assertFalse((root / "dry-results.csv.lock").exists())

                    csv_path = root / "results.csv"
                    ledger_path = root / "ledger.jsonl"
                    report_path = root / "report.json"
                    dashboard_path = root / "dashboard.md"
                    proc = subprocess.run(
                        [
                            sys.executable,
                            str(script),
                            "--tasks",
                            str(tasks_path),
                            "--variants",
                            str(variants_path),
                            "--csv",
                            str(csv_path),
                            "--evidence-jsonl",
                            str(evidence_path),
                            "--ledger-jsonl",
                            str(ledger_path),
                            "--report-json",
                            str(report_path),
                            "--dashboard-md",
                            str(dashboard_path),
                            "--claude-bin",
                            str(root / "missing-claude"),
                        ],
                        text=True,
                        capture_output=True,
                        check=True,
                    )
                    self.assertIn("replay t01/baseline", proc.stdout)
                    self.assertIn("dashboard", proc.stdout)
                    with csv_path.open(encoding="utf-8", newline="") as f:
                        rows = list(csv.DictReader(f))
                    self.assertEqual(len(rows), 2)
                    self.assertTrue(all(row["claude_version"] == "evidence-replay" for row in rows))
                    self.assertTrue(all(row["primary_tokens_measured"] == "false" for row in rows))
                    self.assertTrue(all(row["cost_measured"] == "false" for row in rows))

                    ledger_rows = [
                        json.loads(line)
                        for line in ledger_path.read_text(encoding="utf-8").splitlines()
                        if line.strip()
                    ]
                    self.assertEqual(len(ledger_rows), 2)
                    self.assertEqual(ledger_rows[0]["evidence_source_type"], "synthetic_fixture")
                    self.assertFalse(ledger_rows[0]["public_claim_eligible"])
                    self.assertIn("replay_provenance", ledger_rows[0])

                    report = json.loads(report_path.read_text(encoding="utf-8"))
                    self.assertEqual(report["claim_status"], "replay_only_not_public_claim")
                    self.assertEqual(report["raw_metric_claim_status"], "insufficient_paired_data")
                    self.assertEqual(report["public_claim_status"], "replay_only_not_public_claim")
                    self.assertFalse(report["public_claim_eligible"])
                    self.assertEqual(report["replay_evidence"]["source_types"], ["synthetic_fixture"])
                    readiness = report["public_claim_readiness"]
                    self.assertEqual(readiness["schema_version"], "contextguard.bench.public-claim-readiness.v1")
                    self.assertFalse(readiness["claim_allowed"])
                    self.assertTrue(readiness["claim_boundary"]["unsupported_claims_forbidden"])
                    self.assertIn("provider_export_provenance", readiness["blocking_gate_ids"])

                    dashboard = dashboard_path.read_text(encoding="utf-8")
                    self.assertIn("Claim boundary", dashboard)
                    self.assertIn("## Public claim readiness", dashboard)
                    self.assertIn("Quality gate", dashboard)
                    self.assertIn("context-guard-bench --tasks", dashboard)
                    self.assertIn("--evidence-jsonl", dashboard)

                    resumed_report = root / "resumed-report.json"
                    subprocess.run(
                        [
                            sys.executable,
                            str(script),
                            "--tasks",
                            str(tasks_path),
                            "--variants",
                            str(variants_path),
                            "--csv",
                            str(csv_path),
                            "--evidence-jsonl",
                            str(evidence_path),
                            "--report-json",
                            str(resumed_report),
                            "--resume",
                        ],
                        text=True,
                        capture_output=True,
                        check=True,
                    )
                    resumed = json.loads(resumed_report.read_text(encoding="utf-8"))
                    self.assertEqual(resumed["claim_status"], "unknown_mixed_csv")
                    self.assertFalse(resumed["public_claim_eligible"])

                    no_evidence_proc = subprocess.run(
                        [
                            sys.executable,
                            str(script),
                            "--tasks",
                            str(tasks_path),
                            "--variants",
                            str(variants_path),
                            "--csv",
                            str(root / "no-evidence.csv"),
                            "--claude-bin",
                            str(root / "missing-claude"),
                        ],
                        text=True,
                        capture_output=True,
                    )
                    self.assertEqual(no_evidence_proc.returncode, 2)
                    self.assertIn("fixture-only placeholder", no_evidence_proc.stderr)

    def test_benchmark_runner_evidence_replay_validation_fails_closed(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_evidence_validation_{index}")
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    evidence_path = root / "evidence.jsonl"

                    def good_row(**updates):
                        row = {
                            "schema_version": "contextguard.bench.run-evidence.v1",
                            "task_id": "t01",
                            "variant": "baseline",
                            "success": True,
                            "tokens": {"input_tokens": 100, "output_tokens": 20},
                            "primary_tokens_measured": False,
                            "cost_usd": 0.0,
                            "cost_measured": False,
                            "provenance": {
                                "evidence_source_type": "synthetic_fixture",
                                "claim_scope": "local_replay_fixture_not_public_claim",
                            },
                        }
                        row.update(updates)
                        return row

                    bad_cases = {
                        "schema": good_row(schema_version="wrong"),
                        "missing_provenance": {k: v for k, v in good_row().items() if k != "provenance"},
                        "negative_metric": good_row(bytes_after=-1),
                    }
                    for name, row in bad_cases.items():
                        with self.subTest(case=name):
                            evidence_path.write_text(json.dumps(row) + "\n", encoding="utf-8")
                            with self.assertRaises(SystemExit):
                                module.read_evidence_jsonl(evidence_path)

                    evidence_path.write_text(
                        json.dumps(good_row(cost_usd=float("nan"))) + "\n",
                        encoding="utf-8",
                    )
                    with self.assertRaises(SystemExit):
                        module.read_evidence_jsonl(evidence_path)

                    manual = good_row(
                        primary_tokens_measured=True,
                        cost_measured=True,
                        cost_usd=1.23,
                        provenance={
                            "evidence_source_type": "manual_audit",
                            "claim_scope": "manual_check_not_public_claim",
                        },
                    )
                    evidence_path.write_text(json.dumps(manual) + "\n", encoding="utf-8")
                    parsed = module.read_evidence_jsonl(evidence_path)[0]
                    self.assertFalse(parsed.result.primary_tokens_measured)
                    self.assertFalse(parsed.result.cost_measured)
                    self.assertFalse(parsed.public_claim_eligible)

                    def provider_row(variant, *, input_tokens, output_tokens, cost_usd, corrections=0,
                                     measured=True, notes="provider measured matched-task quality/failure notes"):
                        row = {
                            "schema_version": "contextguard.bench.run-evidence.v1",
                            "task_id": "t01",
                            "variant": variant,
                            "success": True,
                            "tokens": {"input_tokens": input_tokens, "output_tokens": output_tokens},
                            "primary_tokens_measured": measured,
                            "cost_usd": cost_usd,
                            "cost_measured": measured,
                            "external_tokens": 0,
                            "external_tokens_measured": True,
                            "external_cost_usd": 0,
                            "external_cost_measured": True,
                            "bytes_before": 1000,
                            "bytes_after": 800 if variant == "optimized" else 1000,
                            "corrections": corrections,
                            "provenance": {
                                "evidence_source_type": "provider_export",
                                "provider_name": "unit-provider",
                                "capture_command_or_export_id": "export-123",
                                "claim_scope": "provider_measured_matched_task_public_claim",
                            },
                        }
                        if notes is not None:
                            row["notes"] = notes
                        return row

                    def csv_rows_from_replay(replay_rows):
                        csv_rows = []
                        for replay in replay_rows:
                            result = replay.result
                            shifted = (
                                result.cost_measured
                                and result.external_tokens_measured
                                and (result.external_tokens == 0 or result.external_cost_measured)
                            )
                            csv_rows.append({
                                "task_id": result.task_id,
                                "variant": result.variant,
                                "success": "true" if result.success else "false",
                                "total_tokens": str(sum(result.tokens.values())),
                                "primary_tokens_measured": "true" if result.primary_tokens_measured else "false",
                                "cost_usd": f"{result.cost_usd:.6f}",
                                "cost_measured": "true" if result.cost_measured else "false",
                                "external_tokens": str(result.external_tokens),
                                "external_tokens_measured": "true" if result.external_tokens_measured else "false",
                                "external_cost_usd": f"{result.external_cost_usd:.6f}",
                                "external_cost_measured": "true" if result.external_cost_measured else "false",
                                "total_cost_with_shift_usd": (
                                    f"{(result.cost_usd + result.external_cost_usd):.6f}" if shifted else ""
                                ),
                                "bytes_before": str(result.bytes_before),
                                "bytes_after": str(result.bytes_after),
                                "corrections": str(result.corrections),
                            })
                        return csv_rows

                    evidence_path.write_text(
                        "\n".join([
                            json.dumps(provider_row("baseline", input_tokens=100, output_tokens=20, cost_usd=0.12, measured=False)),
                            json.dumps(provider_row("optimized", input_tokens=50, output_tokens=10, cost_usd=0.06, measured=False)),
                        ]) + "\n",
                        encoding="utf-8",
                    )
                    provider_incomplete = module.read_evidence_jsonl(evidence_path)
                    incomplete_report = module.annotate_replay_report(
                        module.summarize_benchmark_rows(csv_rows_from_replay(provider_incomplete), "baseline"),
                        provider_incomplete,
                        mixed_csv=False,
                    )
                    self.assertEqual(incomplete_report["raw_metric_claim_status"], "insufficient_paired_data")
                    self.assertEqual(incomplete_report["claim_status"], "provider_export_claim_gates_not_met")
                    self.assertFalse(incomplete_report["public_claim_eligible"])
                    incomplete_readiness = incomplete_report["public_claim_readiness"]
                    self.assertFalse(incomplete_readiness["claim_allowed"])
                    self.assertIn("provider_measured_token_cost", incomplete_readiness["blocking_gate_ids"])
                    self.assertIn("shifted_cost_accounting", incomplete_readiness["blocking_gate_ids"])

                    evidence_path.write_text(
                        "\n".join([
                            json.dumps(provider_row("baseline", input_tokens=100, output_tokens=20, cost_usd=0.12)),
                            json.dumps(provider_row("optimized", input_tokens=50, output_tokens=10, cost_usd=0.06, corrections=1)),
                        ]) + "\n",
                        encoding="utf-8",
                    )
                    provider_quality_regression = module.read_evidence_jsonl(evidence_path)
                    quality_report = module.annotate_replay_report(
                        module.summarize_benchmark_rows(csv_rows_from_replay(provider_quality_regression), "baseline"),
                        provider_quality_regression,
                        mixed_csv=False,
                    )
                    self.assertEqual(quality_report["raw_metric_claim_status"], "quality_gate_watch")
                    self.assertEqual(quality_report["claim_status"], "provider_export_claim_gates_not_met")
                    self.assertFalse(quality_report["public_claim_eligible"])
                    quality_readiness = quality_report["public_claim_readiness"]
                    self.assertFalse(quality_readiness["claim_allowed"])
                    self.assertIn("quality_non_inferiority", quality_readiness["blocking_gate_ids"])

                    evidence_path.write_text(
                        "\n".join([
                            json.dumps(provider_row("baseline", input_tokens=100, output_tokens=20, cost_usd=0.12, notes=None)),
                            json.dumps(provider_row("optimized", input_tokens=50, output_tokens=10, cost_usd=0.06, notes=None)),
                        ]) + "\n",
                        encoding="utf-8",
                    )
                    provider_missing_notes = module.read_evidence_jsonl(evidence_path)
                    missing_notes_report = module.annotate_replay_report(
                        module.summarize_benchmark_rows(csv_rows_from_replay(provider_missing_notes), "baseline"),
                        provider_missing_notes,
                        mixed_csv=False,
                    )
                    self.assertEqual(missing_notes_report["public_claim_status"], "provider_export_public_claim_candidate")
                    missing_notes_readiness = missing_notes_report["public_claim_readiness"]
                    self.assertFalse(missing_notes_readiness["claim_allowed"])
                    self.assertEqual(missing_notes_readiness["status"], "provider_export_claim_gates_not_met")
                    self.assertIn("confidence_failure_notes", missing_notes_readiness["blocking_gate_ids"])

                    evidence_path.write_text(
                        "\n".join([
                            json.dumps(provider_row("baseline", input_tokens=100, output_tokens=20, cost_usd=0.12)),
                            json.dumps(provider_row("optimized", input_tokens=50, output_tokens=10, cost_usd=0.06)),
                        ]) + "\n",
                        encoding="utf-8",
                    )
                    provider_complete = module.read_evidence_jsonl(evidence_path)
                    complete_report = module.annotate_replay_report(
                        module.summarize_benchmark_rows(csv_rows_from_replay(provider_complete), "baseline"),
                        provider_complete,
                        mixed_csv=False,
                    )
                    self.assertEqual(
                        complete_report["raw_metric_claim_status"],
                        "token_and_shifted_cost_savings_observed",
                    )
                    self.assertEqual(complete_report["claim_status"], "token_and_shifted_cost_savings_observed")
                    self.assertEqual(complete_report["public_claim_status"], "provider_export_public_claim_candidate")
                    self.assertTrue(complete_report["public_claim_eligible"])
                    complete_readiness = complete_report["public_claim_readiness"]
                    self.assertTrue(complete_readiness["claim_allowed"])
                    self.assertEqual(complete_readiness["status"], "provider_export_public_claim_candidate")
                    self.assertEqual(complete_readiness["blocking_gate_ids"], [])
                    self.assertTrue(all(gate["status"] == "pass" for gate in complete_readiness["gates"]))

                    duplicate = "\n".join([json.dumps(good_row()), json.dumps(good_row())]) + "\n"
                    evidence_path.write_text(duplicate, encoding="utf-8")
                    rows = module.read_evidence_jsonl(evidence_path)
                    with self.assertRaises(SystemExit):
                        module.validate_evidence_coverage(
                            rows,
                            [(module.TaskFixture(id="t01", prompt="x"), module.Variant(name="baseline"))],
                        )

                    evidence_path.write_text(json.dumps(good_row()) + "\n", encoding="utf-8")
                    rows = module.read_evidence_jsonl(evidence_path)
                    with self.assertRaises(SystemExit):
                        module.validate_evidence_coverage(
                            rows,
                            [
                                (module.TaskFixture(id="t01", prompt="x"), module.Variant(name="baseline")),
                                (module.TaskFixture(id="t01", prompt="x"), module.Variant(name="optimized")),
                            ],
                        )

    def test_benchmark_runner_preflight_fails_unsupported_platform_before_file_io(self):
        module = load_module_from_path(KIT_DIR / "benchmark_runner.py", "_bench_runner_unsupported_platform")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original_supported = module.no_follow_file_ops_supported
            original_argv = sys.argv
            module.no_follow_file_ops_supported = lambda: False
            sys.argv = [
                "benchmark_runner.py",
                "--tasks",
                str(root / "missing-tasks.json"),
                "--variants",
                str(root / "missing-variants.json"),
                "--csv",
                str(root / "missing-results.csv"),
                "--dry-run",
            ]
            try:
                with self.assertRaises(SystemExit) as ctx:
                    module.main()
            finally:
                module.no_follow_file_ops_supported = original_supported
                sys.argv = original_argv
            self.assertIn("requires POSIX no-follow file operations", str(ctx.exception))

    def test_dry_run_prints_argv_without_writing_csv(self):
        """dry-run 은 stdout 에 argv 만 출력하고 CSV 파일을 만들거나 수정하지 않아야 한다.

        이 분리가 없으면 dry-run row 가 (task_id, variant) 키를 차지해 --resume 시
        실제 측정값이 영구히 skip 되는 silent data loss 가 발생한다.
        """
        for script in BENCH_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    (root / "tasks.json").write_text(json.dumps([
                        {"id": "t01", "prompt": "echo hello", "model": "sonnet",
                         "effort": "medium", "max_turns": 1}
                    ]))
                    (root / "variants.json").write_text(json.dumps([
                        {"name": "baseline", "extra_args": []},
                        {"name": "hygiene", "extra_args": ["--strict-mcp-config"]},
                    ]))
                    csv_path = root / "results.csv"
                    proc = subprocess.run(
                        [sys.executable, str(script), "--tasks", str(root / "tasks.json"),
                         "--variants", str(root / "variants.json"),
                         "--csv", str(csv_path), "--dry-run", "--resume"],
                        text=True, capture_output=True, check=True,
                    )
                    self.assertIn("dry-run:", proc.stdout)
                    self.assertIn("--strict-mcp-config", proc.stdout)
                    self.assertIn("(dry-run; CSV not updated)", proc.stdout)
                    self.assertFalse(csv_path.exists(),
                                     "dry-run 은 CSV 를 만들지 않아야 한다")
                    self.assertFalse((root / "results.csv.lock").exists(),
                                     "dry-run --resume must not create a sidecar lock for a missing CSV")

    def test_dry_run_console_redacts_secrets_without_truncating_argv(self):
        for script in BENCH_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    long_arg = "x" * 900
                    secret = "quoted secret value"
                    generic_secret = "generic-dry-run-secret"
                    access_secret = "access-dry-run-secret"
                    (root / "tasks.json").write_text(json.dumps([
                        {"id": "t01", "prompt": "echo hello", "model": "sonnet", "max_turns": 1}
                    ]))
                    (root / "variants.json").write_text(json.dumps([
                        {"name": "hygiene", "extra_args": ["--api-key", secret, "--token", generic_secret, "--access_token", access_secret, "--long-arg", long_arg]},
                    ]))
                    proc = subprocess.run(
                        [sys.executable, str(script), "--tasks", str(root / "tasks.json"),
                         "--variants", str(root / "variants.json"),
                         "--csv", str(root / "results.csv"), "--dry-run"],
                        text=True, capture_output=True, check=True,
                    )
                    self.assertIn("dry-run:", proc.stdout)
                    self.assertIn("-p --model sonnet", proc.stdout)
                    self.assertIn("--long-arg", proc.stdout)
                    self.assertIn(long_arg, proc.stdout)
                    self.assertNotIn("…[truncated]", proc.stdout)
                    self.assertNotIn(secret, proc.stdout)
                    self.assertNotIn(generic_secret, proc.stdout)
                    self.assertNotIn(access_secret, proc.stdout)
                    self.assertIn("--api-key [REDACTED]", proc.stdout)
                    self.assertIn("--token [REDACTED]", proc.stdout)
                    self.assertIn("--access_token [REDACTED]", proc.stdout)

    def test_run_with_fake_claude_collects_usage_and_runs_success_command(self):
        for script in BENCH_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    fake = _make_fake_claude(root, usage={
                        "input_tokens": 100,
                        "output_tokens": 30,
                        "cache_read_input_tokens": 800,
                        "cache_creation_input_tokens": 50,
                        "prompt_tokens_details": {"cached_tokens": 64},
                    })
                    (root / "tasks.json").write_text(json.dumps([
                        {"id": "t01", "prompt": "echo hi", "model": "sonnet",
                         "effort": "medium", "max_turns": 1,
                         "success_command": "true", "success_cwd": "."}
                    ]))
                    (root / "variants.json").write_text(json.dumps([
                        {"name": "baseline", "extra_args": []},
                    ]))
                    csv_path = root / "results.csv"
                    proc = subprocess.run(
                        [sys.executable, str(script),
                         "--tasks", str(root / "tasks.json"),
                         "--variants", str(root / "variants.json"),
                         "--csv", str(csv_path),
                         "--claude-bin", str(fake),
                         "--project-root", str(root)],
                        text=True, capture_output=True, check=True,
                    )
                    self.assertIn("ok tokens=980", proc.stdout)  # 100+30+800+50
                    with csv_path.open(encoding="utf-8") as f:
                        rows = list(csv.DictReader(f))
                    self.assertEqual(len(rows), 1)
                    row = rows[0]
                    self.assertEqual(row["input_tokens"], "100")
                    self.assertEqual(row["output_tokens"], "30")
                    self.assertEqual(row["cache_read"], "800")
                    self.assertEqual(row["cache_creation"], "50")
                    self.assertEqual(row["provider_cached_tokens"], "64")
                    self.assertEqual(row["provider_cached_tokens_measured"], "true")
                    self.assertEqual(row["primary_tokens_measured"], "true")
                    self.assertEqual(row["total_tokens"], "980")
                    self.assertEqual(row["success"], "true")
                    self.assertGreater(float(row["wall_time_seconds"]), 0)
                    self.assertAlmostEqual(float(row["cost_usd"]), 0.0123, places=4)

    def test_benchmark_runner_writes_cost_shift_ledger_and_ab_report(self):
        for script in BENCH_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    fake = root / "fake-claude"
                    fake.write_text(
                        "#!/usr/bin/env python3\n"
                        "import json, sys\n"
                        "optimized = '--optimized' in sys.argv\n"
                        "usage = {'input_tokens': 50 if optimized else 100, 'output_tokens': 10 if optimized else 20, 'prompt_tokens_details': {'cached_tokens': 25 if optimized else 0}}\n"
                        "payload = {\n"
                        "    'message': {'usage': usage},\n"
                        "    'total_cost_usd': 0.06 if optimized else 0.12,\n"
                        "    'metrics': {\n"
                        "        'turns': 2 if optimized else 3,\n"
                        "        'hook_triggers': 4 if optimized else 0,\n"
                        "        'bytes_before': 1000 if optimized else 1000,\n"
                        "        'bytes_after': 120 if optimized else 1000,\n"
                        "        'artifacts_used': 1 if optimized else 0,\n"
                        "        'external_tokens': 5 if optimized else 0,\n"
                        "        'external_cost_usd': 0.01 if optimized else 0,\n"
                        "    },\n"
                        "}\n"
                        "sys.stdout.write(json.dumps(payload))\n",
                        encoding="utf-8",
                    )
                    fake.chmod(0o755)
                    (root / "tasks.json").write_text(json.dumps([
                        {"id": "t01", "prompt": "echo hi", "model": "sonnet",
                         "max_turns": 1, "success_command": "true", "success_cwd": "."}
                    ]))
                    (root / "variants.json").write_text(json.dumps([
                        {"name": "baseline", "extra_args": []},
                        {"name": "optimized", "extra_args": ["--optimized"]},
                    ]))
                    csv_path = root / "results.csv"
                    ledger_path = root / "cost-shift-ledger.jsonl"
                    report_path = root / "report.json"
                    proc = subprocess.run(
                        [sys.executable, str(script),
                         "--tasks", str(root / "tasks.json"),
                         "--variants", str(root / "variants.json"),
                         "--csv", str(csv_path),
                         "--ledger-jsonl", str(ledger_path),
                         "--report-json", str(report_path),
                         "--claude-bin", str(fake),
                         "--project-root", str(root)],
                        text=True, capture_output=True, check=True,
                    )
                    self.assertIn("report", proc.stdout)
                    with csv_path.open(encoding="utf-8", newline="") as f:
                        rows = {row["variant"]: row for row in csv.DictReader(f)}
                    optimized = rows["optimized"]
                    self.assertEqual(optimized["turns"], "2")
                    self.assertEqual(optimized["hook_triggers"], "4")
                    self.assertEqual(optimized["bytes_before"], "1000")
                    self.assertEqual(optimized["bytes_after"], "120")
                    self.assertEqual(optimized["artifacts_used"], "1")
                    self.assertEqual(optimized["external_tokens"], "5")
                    self.assertEqual(optimized["provider_cached_tokens"], "25")
                    self.assertEqual(optimized["provider_cached_tokens_measured"], "true")
                    self.assertEqual(optimized["primary_tokens_measured"], "true")
                    self.assertGreater(float(optimized["wall_time_seconds"]), 0)
                    self.assertEqual(optimized["external_tokens_measured"], "true")
                    self.assertEqual(optimized["cost_measured"], "true")
                    self.assertEqual(optimized["external_cost_measured"], "true")
                    self.assertAlmostEqual(float(optimized["external_cost_usd"]), 0.01, places=6)
                    self.assertAlmostEqual(float(optimized["total_cost_with_shift_usd"]), 0.07, places=6)

                    ledger_rows = [
                        json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()
                    ]
                    self.assertEqual(len(ledger_rows), 2)
                    optimized_ledger = next(item for item in ledger_rows if item["variant"] == "optimized")
                    self.assertEqual(optimized_ledger["schema_version"], "contextguard.bench.run-evidence.v1")
                    self.assertEqual(optimized_ledger["transform_id"], "optimized")
                    self.assertTrue(optimized_ledger["primary_cost_measured"])
                    self.assertTrue(optimized_ledger["primary_tokens_measured"])
                    self.assertTrue(optimized_ledger["external_tokens_measured"])
                    self.assertTrue(optimized_ledger["external_cost_measured"])
                    self.assertTrue(optimized_ledger["measurement_availability"]["shifted_cost"])
                    self.assertEqual(optimized_ledger["proxy_metrics"]["claim_boundary"], "proxy_only_not_hosted_token_savings")
                    self.assertEqual(optimized_ledger["provider_cached_tokens"], 25)
                    self.assertTrue(optimized_ledger["provider_cached_tokens_measured"])
                    self.assertGreater(optimized_ledger["wall_time_seconds"], 0)
                    self.assertAlmostEqual(optimized_ledger["total_cost_with_shift_usd"], 0.07, places=6)

                    report = json.loads(report_path.read_text(encoding="utf-8"))
                    self.assertEqual(report["schema"], "context-guard-bench-report-v1")
                    self.assertEqual(report["claim_status"], "token_and_shifted_cost_savings_observed")
                    self.assertEqual(
                        report["summary_by_variant"]["baseline"]["primary_tokens_measured_successful"],
                        1,
                    )
                    self.assertEqual(
                        report["summary_by_variant"]["optimized"]["primary_tokens_measured_successful"],
                        1,
                    )
                    comparison = next(item for item in report["comparisons"] if item["variant"] == "optimized")
                    self.assertEqual(comparison["quality_gate"], "pass")
                    self.assertEqual(comparison["matched_successful_task_count"], 1)
                    self.assertGreater(comparison["token_savings_pct"], 0)
                    pair = report["matched_pair_evidence"][0]
                    self.assertEqual(pair["schema_version"], "contextguard.bench.matched-pair.v1")
                    self.assertEqual(pair["task_id"], "t01")
                    self.assertEqual(pair["transform_id"], "optimized")
                    self.assertEqual(pair["measurements"]["baseline"]["run_count"], 1)
                    self.assertEqual(pair["measurements"]["variant"]["row_indices"], [2])
                    self.assertTrue(pair["claim_boundary"]["token_savings_claim_allowed"])
                    self.assertTrue(pair["claim_boundary"]["shifted_cost_claim_allowed"])
                    self.assertFalse(pair["claim_boundary"]["raw_estimate_only_claim_allowed"])
                    self.assertEqual(pair["delta"]["token_savings_pct"], comparison["token_savings_pct"])
                    self.assertLess(pair["delta"]["bytes_after_total"], 0)
                    self.assertEqual(comparison["paired_wall_time_task_count"], 1)
                    self.assertIn("wall_time_change_pct", comparison)
                    self.assertGreater(
                        report["summary_by_variant"]["optimized"]["external_cost_successful_usd"],
                        0,
                    )
                    self.assertEqual(
                        report["summary_by_variant"]["optimized"]["provider_cached_tokens_successful"],
                        25,
                    )
                    self.assertEqual(
                        report["summary_by_variant"]["baseline"]["provider_cached_tokens_successful"],
                        0,
                    )
                    self.assertEqual(
                        report["summary_by_variant"]["baseline"]["wall_time_seconds_measured_successful"],
                        1,
                    )
                    self.assertEqual(
                        report["summary_by_variant"]["optimized"]["wall_time_seconds_measured_successful"],
                        1,
                    )
                    self.assertEqual(
                        report["summary_by_variant"]["baseline"]["provider_cached_tokens_measured_successful"],
                        1,
                    )
                    self.assertEqual(
                        report["summary_by_variant"]["baseline"]["observed_telemetry"]["provider_cache"],
                        "observed",
                    )
                    self.assertEqual(
                        report["summary_by_variant"]["optimized"]["observed_telemetry"]["provider_cache"],
                        "observed",
                    )
                    self.assertEqual(
                        report["summary_by_variant"]["optimized"]["observed_telemetry"]["wall_time"],
                        "observed",
                    )
                    self.assertEqual(
                        report["summary_by_variant"]["optimized"]["external_tokens_successful"],
                        5,
                    )
                    self.assertIn("Wall time", report["caveat"])

    def test_benchmark_runner_self_hosted_metrics_ledger_sidecar(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_self_hosted_metrics_{index}")
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    fake = root / "fake-claude"
                    payload = {
                        "message": {"usage": {"input_tokens": 100, "output_tokens": 20}},
                        "total_cost_usd": 0.02,
                        "self_hosted_metrics": {
                            "model_server": "local dev sk-ant-secret-token",
                            "optimization": "prefix cache reuse",
                            "latency_ms": 123.5,
                            "peak_memory_mb": 2048,
                            "quality_score": 0.98,
                            "quality_metric": "golden task pass rate",
                        },
                    }
                    fake.write_text(
                        "#!/usr/bin/env python3\n"
                        "import json, sys\n"
                        f"sys.stdout.write({json.dumps(payload)!r})\n",
                        encoding="utf-8",
                    )
                    fake.chmod(0o755)
                    (root / "tasks.json").write_text(json.dumps([
                        {
                            "id": "t01",
                            "prompt": "echo hi",
                            "model": "sonnet",
                            "max_turns": 1,
                            "success_command": "true",
                            "success_cwd": ".",
                        }
                    ]))
                    (root / "variants.json").write_text(json.dumps([
                        {"name": "baseline", "extra_args": []},
                    ]))
                    csv_path = root / "results.csv"
                    ledger_path = root / "ledger.jsonl"
                    report_path = root / "report.json"
                    subprocess.run(
                        [
                            sys.executable,
                            str(script),
                            "--tasks",
                            str(root / "tasks.json"),
                            "--variants",
                            str(root / "variants.json"),
                            "--csv",
                            str(csv_path),
                            "--ledger-jsonl",
                            str(ledger_path),
                            "--report-json",
                            str(report_path),
                            "--claude-bin",
                            str(fake),
                            "--project-root",
                            str(root),
                        ],
                        text=True,
                        capture_output=True,
                        check=True,
                    )

                    with csv_path.open(encoding="utf-8", newline="") as f:
                        reader = csv.DictReader(f)
                        self.assertEqual(reader.fieldnames, module.CSV_COLUMNS)
                        rows = list(reader)
                    self.assertEqual(len(rows), 1)
                    self.assertNotIn("self_hosted_metrics", rows[0])

                    ledger_row = json.loads(ledger_path.read_text(encoding="utf-8"))
                    self.assertTrue(ledger_row["measurement_availability"]["self_hosted_metrics"])
                    sidecar = ledger_row["self_hosted_metrics"]
                    self.assertEqual(sidecar["schema_version"], "contextguard.bench.self-hosted-metrics.v1")
                    self.assertEqual(sidecar["source"], "explicit_provider_payload.self_hosted_metrics")
                    self.assertEqual(sidecar["metrics"]["latency_ms"], 123.5)
                    self.assertEqual(sidecar["metrics"]["peak_memory_mb"], 2048.0)
                    self.assertEqual(sidecar["metrics"]["quality_score"], 0.98)
                    self.assertTrue(sidecar["measurement_availability"]["latency_ms"])
                    self.assertTrue(sidecar["measurement_availability"]["peak_memory_mb"])
                    self.assertTrue(sidecar["measurement_availability"]["quality_score"])
                    self.assertIn("[REDACTED]", sidecar["labels"]["model_server"])
                    self.assertNotIn("sk-ant", json.dumps(sidecar))
                    self.assertEqual(
                        sidecar["claim_boundary"]["id"],
                        "self_hosted_metrics_only_not_hosted_api_token_or_cost_savings",
                    )
                    self.assertFalse(sidecar["claim_boundary"]["hosted_api_token_savings_claim_allowed"])
                    self.assertFalse(sidecar["claim_boundary"]["hosted_api_cost_savings_claim_allowed"])
                    self.assertTrue(
                        sidecar["claim_boundary"]["requires_provider_measured_matched_tasks_for_hosted_claims"]
                    )

                    report = json.loads(report_path.read_text(encoding="utf-8"))
                    self.assertEqual(report["schema"], "context-guard-bench-report-v1")
                    self.assertEqual(report["claim_status"], "baseline_only")
                    self.assertNotIn("self_hosted_metrics", json.dumps(report, sort_keys=True))

    def test_benchmark_runner_self_hosted_metrics_multi_row_ledger_sidecars(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_self_hosted_metrics_multi_{index}")
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    fake = root / "fake-claude"
                    fake.write_text(
                        "#!/usr/bin/env python3\n"
                        "import json, sys\n"
                        "prompt = sys.argv[-1]\n"
                        "is_second = 'task two' in prompt\n"
                        "payload = {\n"
                        "    'message': {'usage': {'input_tokens': 100 + (50 if is_second else 0), 'output_tokens': 20}},\n"
                        "    'total_cost_usd': 0.02,\n"
                        "    'self_hosted_metrics': {\n"
                        "        'model_server': 'local model server',\n"
                        "        'optimization': 'prefix cache reuse',\n"
                        "        'latency_ms': 456.0 if is_second else 123.0,\n"
                        "        'peak_memory_mb': 4096 if is_second else 2048,\n"
                        "        'quality_score': 0.97 if is_second else 0.99,\n"
                        "    },\n"
                        "}\n"
                        "sys.stdout.write(json.dumps(payload))\n",
                        encoding="utf-8",
                    )
                    fake.chmod(0o755)
                    (root / "tasks.json").write_text(json.dumps([
                        {
                            "id": "t01",
                            "prompt": "task one",
                            "model": "sonnet",
                            "max_turns": 1,
                            "success_command": "true",
                            "success_cwd": ".",
                        },
                        {
                            "id": "t02",
                            "prompt": "task two",
                            "model": "sonnet",
                            "max_turns": 1,
                            "success_command": "true",
                            "success_cwd": ".",
                        },
                    ]))
                    (root / "variants.json").write_text(json.dumps([
                        {"name": "baseline", "extra_args": []},
                    ]))
                    csv_path = root / "results.csv"
                    ledger_path = root / "ledger.jsonl"
                    report_path = root / "report.json"
                    subprocess.run(
                        [
                            sys.executable,
                            str(script),
                            "--tasks",
                            str(root / "tasks.json"),
                            "--variants",
                            str(root / "variants.json"),
                            "--csv",
                            str(csv_path),
                            "--ledger-jsonl",
                            str(ledger_path),
                            "--report-json",
                            str(report_path),
                            "--claude-bin",
                            str(fake),
                            "--project-root",
                            str(root),
                        ],
                        text=True,
                        capture_output=True,
                        check=True,
                    )

                    with csv_path.open(encoding="utf-8", newline="") as f:
                        reader = csv.DictReader(f)
                        self.assertEqual(reader.fieldnames, module.CSV_COLUMNS)
                        rows = list(reader)
                    self.assertEqual([row["task_id"] for row in rows], ["t01", "t02"])
                    self.assertTrue(all("self_hosted_metrics" not in row for row in rows))

                    ledger_rows = [
                        json.loads(line)
                        for line in ledger_path.read_text(encoding="utf-8").splitlines()
                        if line.strip()
                    ]
                    self.assertEqual([row["task_id"] for row in ledger_rows], ["t01", "t02"])
                    self.assertTrue(all(row["measurement_availability"]["self_hosted_metrics"] for row in ledger_rows))
                    self.assertEqual(
                        [row["self_hosted_metrics"]["metrics"]["latency_ms"] for row in ledger_rows],
                        [123.0, 456.0],
                    )
                    for ledger_row in ledger_rows:
                        sidecar = ledger_row["self_hosted_metrics"]
                        self.assertEqual(sidecar["schema_version"], "contextguard.bench.self-hosted-metrics.v1")
                        self.assertEqual(sidecar["source"], "explicit_provider_payload.self_hosted_metrics")
                        self.assertFalse(sidecar["claim_boundary"]["hosted_api_token_savings_claim_allowed"])
                        self.assertFalse(sidecar["claim_boundary"]["hosted_api_cost_savings_claim_allowed"])

                    report = json.loads(report_path.read_text(encoding="utf-8"))
                    self.assertNotIn("self_hosted_metrics", json.dumps(report, sort_keys=True))

    def test_benchmark_runner_self_hosted_metrics_strict_contract(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_self_hosted_contract_{index}")
                self.assertIsNone(module.collect_self_hosted_metrics({"self_hosted_latency_ms": 10}))
                self.assertIsNone(
                    module.collect_self_hosted_metrics({
                        "message": {
                            "content": [
                                {
                                    "self_hosted_metrics": {
                                        "latency_ms": 123,
                                        "peak_memory_mb": 456,
                                        "quality_score": 0.9,
                                    }
                                }
                            ]
                        }
                    })
                )
                self.assertIsNone(
                    module.collect_self_hosted_metrics({
                        "self_hosted_metrics": {
                            "model_server": "labels only",
                            "latency_ms": -1,
                            "peak_memory_mb": 10_000_001,
                            "quality_score": 1.1,
                        }
                    })
                )
                self.assertIsNone(
                    module.collect_self_hosted_metrics({
                        "outer": {"self_hosted_metrics": {"latency_ms": "123.5"}}
                    })
                )
                nested = module.collect_self_hosted_metrics({
                    "metrics": {
                        "self_hosted_metrics": {
                            "latency_ms": 321,
                            "peak_memory_mb": 4096,
                            "quality_score": 1.0,
                            "optimization": "=" + ("x" * 200),
                        }
                    }
                })
                self.assertIsNotNone(nested)
                self.assertEqual(nested["source"], "explicit_provider_payload.metrics.self_hosted_metrics")
                self.assertEqual(nested["metrics"]["latency_ms"], 321.0)
                self.assertLessEqual(len(nested["labels"]["optimization"]), 120)

    def test_benchmark_report_matched_pair_evidence_disables_claims_without_measurements(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_pair_unmeasured_{index}")
                report = module.summarize_benchmark_rows(
                    [
                        {
                            "task_id": "t01",
                            "variant": "baseline",
                            "success": "true",
                            "total_tokens": "100",
                            "primary_tokens_measured": "true",
                            "cost_usd": "0.10",
                            "cost_measured": "true",
                            "external_tokens": "0",
                            "external_tokens_measured": "true",
                            "external_cost_usd": "0",
                            "external_cost_measured": "true",
                            "total_cost_with_shift_usd": "0.10",
                            "bytes_before": "1000",
                            "bytes_after": "1000",
                            "corrections": "0",
                        },
                        {
                            "task_id": "t01",
                            "variant": "optimized",
                            "success": "true",
                            "total_tokens": "0",
                            "primary_tokens_measured": "false",
                            "cost_usd": "0.05",
                            "cost_measured": "true",
                            "external_tokens": "9",
                            "external_tokens_measured": "true",
                            "external_cost_usd": "0",
                            "external_cost_measured": "false",
                            "total_cost_with_shift_usd": "",
                            "bytes_before": "1000",
                            "bytes_after": "100",
                            "corrections": "0",
                        },
                    ],
                    "baseline",
                )
                pair = report["matched_pair_evidence"][0]
                self.assertEqual(pair["quality_gate"], "pass")
                self.assertEqual(pair["schema_version"], "contextguard.bench.matched-pair.v1")
                self.assertFalse(pair["claim_boundary"]["token_savings_claim_allowed"])
                self.assertFalse(pair["claim_boundary"]["shifted_cost_claim_allowed"])
                self.assertIsNone(pair["delta"]["token_savings_pct"])
                self.assertIsNone(pair["delta"]["cost_savings_pct_with_shift"])
                self.assertEqual(pair["delta"]["token_proxy_after_total"], -225)
                self.assertEqual(pair["delta"]["proxy_measurement"], "chars_div_4_proxy_only")

    def test_benchmark_report_matched_pair_evidence_requires_usable_values_for_claims(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_pair_unusable_values_{index}")
                report = module.summarize_benchmark_rows(
                    [
                        {
                            "task_id": "t01",
                            "variant": "baseline",
                            "success": "true",
                            "total_tokens": "100",
                            "primary_tokens_measured": "true",
                            "cost_usd": "0.10",
                            "cost_measured": "true",
                            "external_tokens": "0",
                            "external_tokens_measured": "true",
                            "external_cost_usd": "0",
                            "external_cost_measured": "true",
                            "total_cost_with_shift_usd": "0.10",
                            "bytes_before": "1000",
                            "bytes_after": "1000",
                            "corrections": "0",
                        },
                        {
                            "task_id": "t01",
                            "variant": "optimized",
                            "success": "true",
                            "total_tokens": "",
                            "primary_tokens_measured": "true",
                            "cost_usd": "0.05",
                            "cost_measured": "true",
                            "external_tokens": "0",
                            "external_tokens_measured": "true",
                            "external_cost_usd": "0",
                            "external_cost_measured": "true",
                            "total_cost_with_shift_usd": "",
                            "bytes_before": "1000",
                            "bytes_after": "100",
                            "corrections": "0",
                        },
                    ],
                    "baseline",
                )
                pair = report["matched_pair_evidence"][0]
                self.assertEqual(pair["schema_version"], "contextguard.bench.matched-pair.v1")
                self.assertTrue(pair["measurements"]["variant"]["primary_tokens"]["measured"])
                self.assertIsNone(pair["measurements"]["variant"]["primary_tokens"]["average"])
                self.assertFalse(pair["claim_boundary"]["token_savings_claim_allowed"])
                self.assertFalse(pair["claim_boundary"]["shifted_cost_claim_allowed"])
                self.assertIsNone(pair["delta"]["token_savings_pct"])
                self.assertIsNone(pair["delta"]["cost_savings_pct_with_shift"])

    def test_benchmark_report_matched_pair_evidence_handles_duplicate_rows_and_quality_gate(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_pair_duplicates_{index}")
                rows = [
                    {
                        "task_id": "t01",
                        "variant": "baseline",
                        "success": "true",
                        "total_tokens": "100",
                        "primary_tokens_measured": "true",
                        "cost_usd": "0.10",
                        "cost_measured": "true",
                        "external_tokens": "0",
                        "external_tokens_measured": "true",
                        "external_cost_usd": "0",
                        "external_cost_measured": "true",
                        "total_cost_with_shift_usd": "0.10",
                        "bytes_before": "1000",
                        "bytes_after": "1000",
                        "corrections": "0",
                    },
                    {
                        "task_id": "t01",
                        "variant": "baseline",
                        "success": "true",
                        "total_tokens": "120",
                        "primary_tokens_measured": "true",
                        "cost_usd": "0.12",
                        "cost_measured": "true",
                        "external_tokens": "0",
                        "external_tokens_measured": "true",
                        "external_cost_usd": "0",
                        "external_cost_measured": "true",
                        "total_cost_with_shift_usd": "0.12",
                        "bytes_before": "1000",
                        "bytes_after": "900",
                        "corrections": "0",
                    },
                    {
                        "task_id": "t01",
                        "variant": "optimized",
                        "success": "true",
                        "total_tokens": "50",
                        "primary_tokens_measured": "true",
                        "cost_usd": "0.05",
                        "cost_measured": "true",
                        "external_tokens": "0",
                        "external_tokens_measured": "true",
                        "external_cost_usd": "0",
                        "external_cost_measured": "true",
                        "total_cost_with_shift_usd": "0.05",
                        "bytes_before": "1000",
                        "bytes_after": "200",
                        "corrections": "1",
                    },
                    {
                        "task_id": "t01",
                        "variant": "optimized",
                        "success": "true",
                        "total_tokens": "60",
                        "primary_tokens_measured": "true",
                        "cost_usd": "0.06",
                        "cost_measured": "true",
                        "external_tokens": "0",
                        "external_tokens_measured": "true",
                        "external_cost_usd": "0",
                        "external_cost_measured": "true",
                        "total_cost_with_shift_usd": "0.06",
                        "bytes_before": "1000",
                        "bytes_after": "220",
                        "corrections": "1",
                    },
                ]
                report = module.summarize_benchmark_rows(rows, "baseline")
                comparison = report["comparisons"][0]
                self.assertEqual(comparison["quality_gate"], "corrections_regression")
                pair = report["matched_pair_evidence"][0]
                self.assertEqual(pair["measurements"]["baseline"]["run_count"], 2)
                self.assertEqual(pair["measurements"]["baseline"]["row_indices"], [1, 2])
                self.assertEqual(pair["measurements"]["variant"]["run_count"], 2)
                self.assertEqual(pair["measurements"]["variant"]["row_indices"], [3, 4])
                self.assertEqual(pair["quality_gate"], "corrections_regression")
                self.assertFalse(pair["claim_boundary"]["token_savings_claim_allowed"])
                self.assertFalse(pair["claim_boundary"]["shifted_cost_claim_allowed"])
                self.assertIsNone(pair["delta"]["token_savings_pct"])
                self.assertEqual(pair["measurements"]["variant"]["primary_tokens"]["average"], 55.0)

    def test_benchmark_default_matrix_rejects_regressions_and_clamps_advisory_lanes(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_default_matrix_{index}")
                regression_report = module.summarize_benchmark_rows(
                    [
                        {
                            "task_id": "token_savings_04_long_log_analysis",
                            "variant": "baseline",
                            "success": "true",
                            "total_tokens": "100",
                            "primary_tokens_measured": "true",
                            "cost_usd": "0.10",
                            "cost_measured": "true",
                            "external_tokens": "0",
                            "external_tokens_measured": "true",
                            "external_cost_usd": "0",
                            "external_cost_measured": "true",
                            "total_cost_with_shift_usd": "0.10",
                            "bytes_before": "1000",
                            "bytes_after": "1000",
                            "corrections": "0",
                        },
                        {
                            "task_id": "token_savings_04_long_log_analysis",
                            "variant": "trimmed",
                            "success": "true",
                            "total_tokens": "80",
                            "primary_tokens_measured": "true",
                            "cost_usd": "0.08",
                            "cost_measured": "true",
                            "external_tokens": "0",
                            "external_tokens_measured": "true",
                            "external_cost_usd": "0",
                            "external_cost_measured": "true",
                            "total_cost_with_shift_usd": "0.08",
                            "bytes_before": "1000",
                            "bytes_after": "600",
                            "corrections": "1",
                        },
                    ],
                    "baseline",
                )
                by_lane = {lane["lane"]: lane for lane in regression_report["default_matrix"]["lanes"]}
                self.assertEqual(by_lane["trimming"]["classification"], "reject/rework")
                self.assertIn("quality_gate_corrections_regression", by_lane["trimming"]["reason_codes"])
                self.assertFalse(by_lane["trimming"]["public_claim_allowed"])

                advisory_report = module.summarize_benchmark_rows(
                    [
                        {
                            "task_id": "token_savings_10_cache_layout",
                            "variant": "baseline",
                            "success": "true",
                            "total_tokens": "100",
                            "primary_tokens_measured": "true",
                            "cost_usd": "0.10",
                            "cost_measured": "true",
                            "external_tokens": "0",
                            "external_tokens_measured": "true",
                            "external_cost_usd": "0",
                            "external_cost_measured": "true",
                            "total_cost_with_shift_usd": "0.10",
                            "bytes_before": "1000",
                            "bytes_after": "1000",
                            "corrections": "0",
                        },
                        {
                            "task_id": "token_savings_10_cache_layout",
                            "variant": "cache_advice_measured",
                            "success": "true",
                            "total_tokens": "70",
                            "primary_tokens_measured": "true",
                            "cost_usd": "0.07",
                            "cost_measured": "true",
                            "external_tokens": "0",
                            "external_tokens_measured": "true",
                            "external_cost_usd": "0",
                            "external_cost_measured": "true",
                            "total_cost_with_shift_usd": "0.07",
                            "bytes_before": "1000",
                            "bytes_after": "650",
                            "corrections": "0",
                        },
                    ],
                    "baseline",
                )
                by_lane = {lane["lane"]: lane for lane in advisory_report["default_matrix"]["lanes"]}
                self.assertEqual(by_lane["cache_advice"]["classification"], "advisory")
                self.assertEqual(by_lane["cache_advice"]["policy_ceiling"], "advisory")
                self.assertTrue(by_lane["cache_advice"]["policy_clamped"])
                self.assertEqual(by_lane["cache_advice"]["lane_match_method"], "exact_key")
                self.assertEqual(by_lane["cache_advice"]["token_evidence"], "measured_positive")
                self.assertFalse(advisory_report["default_matrix"]["public_claim_allowed"])

    def test_benchmark_report_example_documents_diagnostic_shape(self):
        sample = json.loads((ROOT / "docs" / "benchmark-report.example.json").read_text(encoding="utf-8"))
        self.assertEqual(sample["schema"], "context-guard-bench-report-v1")
        baseline = sample["summary_by_variant"]["baseline"]
        optimized = sample["summary_by_variant"]["context_hygiene"]
        comparison = sample["comparisons"][0]
        pair = sample["matched_pair_evidence"][0]
        self.assertEqual(baseline["primary_tokens_measured_successful"], 1)
        self.assertEqual(baseline["provider_cached_tokens_successful"], 0)
        self.assertEqual(baseline["provider_cached_tokens_measured_successful"], 1)
        self.assertEqual(baseline["wall_time_seconds_measured_successful"], 1)
        self.assertEqual(optimized["primary_tokens_measured_successful"], 1)
        self.assertEqual(optimized["provider_cached_tokens_successful"], 120)
        self.assertEqual(optimized["provider_cached_tokens_measured_successful"], 1)
        self.assertEqual(optimized["wall_time_seconds_measured_successful"], 1)
        self.assertEqual(comparison["paired_token_task_count"], 1)
        self.assertEqual(comparison["paired_wall_time_task_count"], 1)
        self.assertEqual(pair["schema_version"], "contextguard.bench.matched-pair.v1")
        self.assertFalse(pair["claim_boundary"]["raw_estimate_only_claim_allowed"])
        self.assertEqual(pair["delta"]["proxy_measurement"], "chars_div_4_proxy_only")
        readiness = sample["public_claim_readiness"]
        self.assertEqual(readiness["schema_version"], "contextguard.bench.public-claim-readiness.v1")
        self.assertFalse(readiness["claim_allowed"])
        self.assertTrue(readiness["claim_boundary"]["unsupported_claims_forbidden"])
        self.assertIn("confidence_failure_notes", readiness["required_gate_ids"])
        matrix = sample["default_matrix"]
        self.assertEqual(matrix["schema_version"], "contextguard.bench.default-matrix.v1")
        self.assertEqual(
            [lane["lane"] for lane in matrix["lanes"]],
            ["trimming", "artifact_escrow", "tool_pruning", "cache_advice", "adaptive_k", "optional_compression"],
        )
        self.assertFalse(matrix["public_claim_allowed"])
        self.assertTrue(matrix["claim_boundary"]["reporting_only"])
        self.assertEqual(matrix["lanes"][0]["classification"], "default-on")
        self.assertTrue(all(lane["classification"] in {"default-on", "advisory", "experimental", "reject/rework"} for lane in matrix["lanes"]))
        self.assertIn("byte_proxy_only applies only", sample["caveat"])
        self.assertIn("matched_pair_evidence[*].claim_boundary", sample["caveat"])
        self.assertIn("default_matrix.lanes[*].claim_boundary", sample["caveat"])
        self.assertIn("diagnostic telemetry", sample["caveat"])
        self.assertIn("provider-cache discounts", sample["caveat"].lower())
        self.assertIn("report shape only", sample["caveat"].lower())

    def test_benchmark_workflow_examples_are_full_report_shaped_and_claim_safe(self):
        examples_dir = ROOT / "docs" / "benchmark-workflows"
        examples = {path.name: json.loads(path.read_text(encoding="utf-8")) for path in sorted(examples_dir.glob("*.example.json"))}
        self.assertEqual(
            set(examples),
            {
                "context-pack-byte-proxy.example.json",
                "measured-token-workflow.example.json",
                "provider-cache-telemetry.example.json",
            },
        )
        forbidden = ("guaranteed savings", "guarantees savings", "provider-cache proof", "pays off")
        for name, sample in examples.items():
            with self.subTest(example=name):
                self.assertEqual(sample["schema"], "context-guard-bench-report-v1")
                for key in ("baseline_variant", "row_count", "summary_by_variant", "comparisons", "claim_status", "caveat", "public_claim_readiness"):
                    self.assertIn(key, sample)
                self.assertFalse(sample["public_claim_readiness"]["claim_allowed"])
                self.assertTrue(sample["public_claim_readiness"]["claim_boundary"]["unsupported_claims_forbidden"])
                self.assertTrue(sample["comparisons"], name)
                for comparison in sample["comparisons"]:
                    self.assertIn("quality_gate", comparison)
                caveat = sample["caveat"].lower()
                self.assertIn("matched-task", caveat)
                self.assertIn("measured primary", caveat)
                self.assertNotIn("report shape only", caveat)
                combined = json.dumps(sample, sort_keys=True).lower()
                for phrase in forbidden:
                    self.assertNotIn(phrase, combined)

        module = load_module_from_path(KIT_DIR / "benchmark_runner.py", "_bench_runner_test_workflow_example_contract")
        canonical = module.summarize_benchmark_rows(
            [
                {
                    "task_id": "contract",
                    "variant": "baseline",
                    "success": "true",
                    "corrections": "0",
                    "total_tokens": "1000",
                    "primary_tokens_measured": "true",
                    "cost_usd": "0.01",
                    "external_tokens": "0",
                    "external_cost_usd": "0",
                    "bytes_before": "12000",
                    "bytes_after": "12000",
                    "provider_cached_tokens": "0",
                    "provider_cached_tokens_measured": "true",
                    "wall_time_seconds": "10.0",
                },
                {
                    "task_id": "contract",
                    "variant": "optimized",
                    "success": "true",
                    "corrections": "0",
                    "total_tokens": "760",
                    "primary_tokens_measured": "true",
                    "cost_usd": "0.008",
                    "external_tokens": "0",
                    "external_cost_usd": "0",
                    "bytes_before": "12000",
                    "bytes_after": "9000",
                    "provider_cached_tokens": "120",
                    "provider_cached_tokens_measured": "true",
                    "wall_time_seconds": "9.6",
                },
            ],
            "baseline",
        )
        canonical_top = set(canonical)
        canonical_summary = {key for summary in canonical["summary_by_variant"].values() for key in summary}
        canonical_comparison = {key for comparison in canonical["comparisons"] for key in comparison}
        for name, sample in examples.items():
            with self.subTest(canonical_shape=name):
                self.assertLessEqual(set(sample), canonical_top)
                for summary in sample["summary_by_variant"].values():
                    self.assertLessEqual(set(summary), canonical_summary)
                    self.assertNotIn("human_corrections_successful", summary)
                for comparison in sample["comparisons"]:
                    self.assertLessEqual(set(comparison), canonical_comparison)
                    self.assertNotIn("interpretation", comparison)

        context_pack = examples["context-pack-byte-proxy.example.json"]
        self.assertEqual(context_pack["claim_status"], "insufficient_paired_data")
        self.assertEqual(context_pack["comparisons"][0]["paired_token_task_count"], 0)
        self.assertIsNone(context_pack["comparisons"][0]["token_savings_pct"])
        optimized_context_pack = context_pack["summary_by_variant"]["context_pack_auto"]
        self.assertEqual(optimized_context_pack["bytes_saved_successful"], 18000)
        self.assertEqual(optimized_context_pack["token_proxy_saved_successful"], 4500)

        provider_cache = examples["provider-cache-telemetry.example.json"]
        self.assertEqual(provider_cache["summary_by_variant"]["cache_layout_check"]["observed_telemetry"]["provider_cache"], "observed")
        self.assertEqual(provider_cache["comparisons"][0]["token_savings_pct"], 0.0)

        self_hosted_path = examples_dir / "self-hosted-metrics-ledger.example.jsonl"
        self.assertTrue(self_hosted_path.is_file())
        self_hosted_rows = [
            json.loads(line)
            for line in self_hosted_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertEqual(len(self_hosted_rows), 1)
        self_hosted = self_hosted_rows[0]
        self.assertEqual(self_hosted["schema_version"], "contextguard.bench.run-evidence.v1")
        sidecar = self_hosted["self_hosted_metrics"]
        self.assertEqual(sidecar["schema_version"], "contextguard.bench.self-hosted-metrics.v1")
        self.assertTrue(self_hosted["measurement_availability"]["self_hosted_metrics"])
        self.assertFalse(sidecar["claim_boundary"]["hosted_api_token_savings_claim_allowed"])
        self.assertFalse(sidecar["claim_boundary"]["hosted_api_cost_savings_claim_allowed"])
        self.assertIn("not hosted api token or cost telemetry", sidecar["claim_boundary"]["reason"].lower())
        self.assertIn("latency_ms", sidecar["metrics"])
        self.assertIn("peak_memory_mb", sidecar["metrics"])
        self.assertIn("quality_score", sidecar["metrics"])
        for phrase in forbidden:
            self.assertNotIn(phrase, json.dumps(self_hosted, sort_keys=True).lower())

        measured = examples["measured-token-workflow.example.json"]
        self.assertEqual(measured["comparisons"][0]["paired_token_task_count"], 1)
        self.assertGreater(measured["comparisons"][0]["token_savings_pct"], 0)
        self.assertIn("corrections_successful", measured["summary_by_variant"]["brief_mode_standard"])

        guide = (ROOT / "docs" / "benchmark-workflow-examples.md").read_text(encoding="utf-8")
        self.assertIn("context-pack-byte-proxy.example.json", guide)
        self.assertIn("provider-cache", guide.lower())
        self.assertIn("provider-measured", guide)
        self.assertIn("matched successful", guide)
        self.assertIn("not independent savings proof", guide.lower())
        self.assertIn("not a general savings promise", guide.lower())
        self.assertIn("self-hosted-metrics-ledger.example.jsonl", guide)
        self.assertIn("local/model-server latency", guide)
        self.assertIn("do not fold them into hosted API token/cost savings claims", guide)

        for doc in (ROOT / "README.md", ROOT / "README.ko.md", PLUGIN_DIR / "README.md", PLUGIN_DIR / "README.ko.md"):
            self.assertIn("benchmark-workflow-examples.md", doc.read_text(encoding="utf-8"), str(doc))
        self.assertNotIn("workflow-specific before/after benchmark report examples", (ROOT / "README.md").read_text(encoding="utf-8"))
        self.assertNotIn("작업 유형별 전후 비교 벤치마크 예시 모음", (ROOT / "README.ko.md").read_text(encoding="utf-8"))

        package_files = set(json.loads((ROOT / "package.json").read_text(encoding="utf-8"))["files"])
        self.assertIn("docs/benchmark-workflow-examples.md", package_files)
        self.assertIn("docs/benchmark-workflows/*.example.json", package_files)
        self.assertIn("docs/benchmark-workflows/*.example.jsonl", package_files)
        prepublish = (ROOT / "scripts" / "prepublish_check.py").read_text(encoding="utf-8")
        for filename in examples:
            self.assertIn(f"docs/benchmark-workflows/{filename}", prepublish)
        self.assertIn("docs/benchmark-workflows/self-hosted-metrics-ledger.example.jsonl", prepublish)
        self.assertIn('ROOT / "docs" / "benchmark-workflow-examples.md"', prepublish)
        self.assertIn('ROOT / "docs" / "benchmark-workflows"', prepublish)

    def _experimental_benchmark_fixture_paths(self):
        fixture_dir = ROOT / "docs" / "benchmark-fixtures"
        guide = ROOT / "docs" / "experimental-benchmark-fixtures.md"
        fixture_pairs = {
            "image_context_pack": (
                fixture_dir / "image-context-pack.tasks.example.json",
                fixture_dir / "image-context-pack.variants.example.json",
            ),
            "visual_ocr": (
                fixture_dir / "visual-ocr.tasks.example.json",
                fixture_dir / "visual-ocr.variants.example.json",
            ),
            "learned_compression": (
                fixture_dir / "learned-compression.tasks.example.json",
                fixture_dir / "learned-compression.variants.example.json",
            ),
            "output_transform": (
                fixture_dir / "output-transform.tasks.example.json",
                fixture_dir / "output-transform.variants.example.json",
            ),
            "token_savings": (
                fixture_dir / "token-savings-12task.tasks.example.json",
                fixture_dir / "token-savings-12task.variants.example.json",
            ),
        }
        return fixture_dir, guide, fixture_pairs

    def _experimental_benchmark_prompt_fixture_names(self):
        return {
            "image-context-pack-full-evidence.prompt.example.md",
            "image-context-pack-packed-evidence.prompt.example.md",
            "learned-compression-baseline-context-pack.prompt.example.md",
            "learned-compression-candidate-digest.prompt.example.md",
            "output-transform-baseline-raw-output.prompt.example.md",
            "output-transform-digest-receipt.prompt.example.md",
            "visual-ocr-full-visual.prompt.example.md",
            "visual-ocr-cropped-ocr.prompt.example.md",
            "token-savings-12task-baseline.prompt.example.md",
            "token-savings-12task-contextguard.prompt.example.md",
        }

    def _experimental_benchmark_expected_prompt_fragments(self):
        return {
            "image_context_pack": {
                "baseline_full_evidence_fixture": "Full sanitized textual evidence",
                "fixture_only_image_context_pack": "Packed sanitized textual evidence",
            },
            "visual_ocr": {
                "baseline_full_visual_fixture": "Full visual evidence",
                "fixture_only_cropped_or_ocr_evidence": "Cropped or OCR-derived evidence",
            },
            "learned_compression": {
                "baseline_uncompressed_fixture": "Sanitized context pack",
                "fixture_only_learned_compression_candidate": "Compressed digest candidate",
            },
            "output_transform": {
                "baseline_raw_output_fixture": "Raw sanitized command output",
                "fixture_only_digest_artifact_receipt": "Digest of sanitized command output",
            },
            "token_savings": {
                "baseline_full_context_fixture": "unoptimized full-context",
                "fixture_only_contextguard_advisory_foundations": "ContextGuard advisory-foundations",
            },
        }

    def _experimental_benchmark_runner_modules(self):
        return {
            KIT_DIR / "benchmark_runner.py": load_module_from_path(
                KIT_DIR / "benchmark_runner.py",
                "_bench_runner_test_experimental_fixtures_kit",
            ),
            PLUGIN_BIN / "context-guard-bench": load_python_script_module(
                PLUGIN_BIN / "context-guard-bench",
                "_bench_runner_test_experimental_fixtures_plugin",
            ),
        }

    def _combined_experimental_benchmark_fixture_text(self, guide, fixture_dir, fixture_pairs):
        combined = guide.read_text(encoding="utf-8").lower()
        for task_path, variant_path in fixture_pairs.values():
            combined += "\n" + task_path.read_text(encoding="utf-8").lower()
            combined += "\n" + variant_path.read_text(encoding="utf-8").lower()
        for evidence_path in sorted(fixture_dir.glob("*.example.jsonl")):
            combined += "\n" + evidence_path.read_text(encoding="utf-8").lower()
        for prompt_path in sorted(fixture_dir.glob("*.prompt.example.md")):
            combined += "\n" + prompt_path.read_text(encoding="utf-8").lower()
        return combined

    def test_experimental_benchmark_fixtures_are_packaged_and_linked(self):
        fixture_dir, guide, fixture_pairs = self._experimental_benchmark_fixture_paths()
        self.assertTrue(guide.is_file())
        self.assertTrue(fixture_dir.is_dir())
        self.assertEqual(
            {path.name for path in fixture_dir.glob("*.example.json")},
            {path.name for pair in fixture_pairs.values() for path in pair},
        )
        self.assertEqual(
            {path.name for path in fixture_dir.glob("*.prompt.example.md")},
            self._experimental_benchmark_prompt_fixture_names(),
        )

        package_files = set(json.loads((ROOT / "package.json").read_text(encoding="utf-8"))["files"])
        self.assertIn("docs/experimental-benchmark-fixtures.md", package_files)
        self.assertIn("docs/benchmark-fixtures/*.example.json", package_files)
        self.assertIn("docs/benchmark-fixtures/*.example.jsonl", package_files)
        self.assertIn("docs/benchmark-fixtures/*.prompt.example.md", package_files)

        prepublish = (ROOT / "scripts" / "prepublish_check.py").read_text(encoding="utf-8")
        for expected in (
            "docs/experimental-benchmark-fixtures.md",
            "docs/benchmark-fixtures/image-context-pack.tasks.example.json",
            "docs/benchmark-fixtures/image-context-pack.variants.example.json",
            "docs/benchmark-fixtures/image-context-pack.evidence.example.jsonl",
            "docs/benchmark-fixtures/image-context-pack-full-evidence.prompt.example.md",
            "docs/benchmark-fixtures/image-context-pack-packed-evidence.prompt.example.md",
            "docs/benchmark-fixtures/learned-compression.tasks.example.json",
            "docs/benchmark-fixtures/learned-compression.variants.example.json",
            "docs/benchmark-fixtures/learned-compression-baseline-context-pack.prompt.example.md",
            "docs/benchmark-fixtures/learned-compression-candidate-digest.prompt.example.md",
            "docs/benchmark-fixtures/output-transform.tasks.example.json",
            "docs/benchmark-fixtures/output-transform.variants.example.json",
            "docs/benchmark-fixtures/output-transform-baseline-raw-output.prompt.example.md",
            "docs/benchmark-fixtures/output-transform-digest-receipt.prompt.example.md",
            "docs/benchmark-fixtures/visual-ocr.tasks.example.json",
            "docs/benchmark-fixtures/visual-ocr.variants.example.json",
            "docs/benchmark-fixtures/visual-ocr-full-visual.prompt.example.md",
            "docs/benchmark-fixtures/visual-ocr-cropped-ocr.prompt.example.md",
            "docs/benchmark-fixtures/token-savings-12task.tasks.example.json",
            "docs/benchmark-fixtures/token-savings-12task.variants.example.json",
            "docs/benchmark-fixtures/token-savings-12task.evidence.example.jsonl",
            "docs/benchmark-fixtures/token-savings-12task-baseline.prompt.example.md",
            "docs/benchmark-fixtures/token-savings-12task-contextguard.prompt.example.md",
            'ROOT / "docs" / "experimental-benchmark-fixtures.md"',
            'ROOT / "docs" / "benchmark-fixtures"',
        ):
            with self.subTest(prepublish_expected=expected):
                self.assertIn(expected, prepublish)

        for doc, expected_link in (
            (ROOT / "README.md", "docs/experimental-benchmark-fixtures.md"),
            (ROOT / "README.ko.md", "docs/experimental-benchmark-fixtures.md"),
            (PLUGIN_DIR / "README.md", "https://github.com/ictechgy/context-guard/blob/main/docs/experimental-benchmark-fixtures.md"),
            (PLUGIN_DIR / "README.ko.md", "https://github.com/ictechgy/context-guard/blob/main/docs/experimental-benchmark-fixtures.md"),
            (KIT_DIR / "README.md", "../docs/experimental-benchmark-fixtures.md"),
            (ROOT / "docs" / "benchmark-workflow-examples.md", "experimental-benchmark-fixtures.md"),
            (ROOT / "research" / "experimental-token-reduction-radar.md", "../docs/experimental-benchmark-fixtures.md"),
        ):
            with self.subTest(doc=doc):
                self.assertIn(expected_link, doc.read_text(encoding="utf-8"))

    def test_experimental_benchmark_fixtures_parse_and_bind_prompt_files(self):
        _, _, fixture_pairs = self._experimental_benchmark_fixture_paths()
        modules = self._experimental_benchmark_runner_modules()
        expected_prompt_fragments = self._experimental_benchmark_expected_prompt_fragments()

        for lane, (task_path, variant_path) in fixture_pairs.items():
            with self.subTest(lane=lane):
                task_raw = json.loads(task_path.read_text(encoding="utf-8"))
                variant_raw = json.loads(variant_path.read_text(encoding="utf-8"))
                self.assertIsInstance(task_raw, list)
                self.assertIsInstance(variant_raw, list)
                self.assertTrue(task_raw)
                self.assertTrue(variant_raw)
                if lane == "image_context_pack":
                    self.assertEqual(len(task_raw), 1)
                    self.assertEqual(task_raw[0]["id"], "image_context_pack_matched_correction_fixture")
                    self.assertEqual(task_raw[0]["allowed_tools"], [])
                    self.assertEqual(
                        task_raw[0]["variant_prompt_files"],
                        {
                            "baseline_full_evidence_fixture": "image-context-pack-full-evidence.prompt.example.md",
                            "fixture_only_image_context_pack": "image-context-pack-packed-evidence.prompt.example.md",
                        },
                    )
                    self.assertEqual(
                        variant_raw,
                        [
                            {"name": "baseline_full_evidence_fixture", "extra_args": []},
                            {"name": "fixture_only_image_context_pack", "extra_args": []},
                        ],
                    )
                for item in task_raw:
                    self.assertIn("id", item)
                    self.assertIn("prompt", item)
                    self.assertTrue(str(item["id"]).startswith(lane))
                    self.assertIsInstance(item.get("success_command"), str)
                    self.assertIn("fixture-only placeholder", item["success_command"])
                    self.assertIn("replace success_command", item["success_command"])
                for item in variant_raw:
                    self.assertIn("name", item)
                    self.assertIn("extra_args", item)
                    self.assertIsInstance(item["extra_args"], list)

                self.assertTrue(any("variant_prompt_files" in item for item in task_raw))
                variant_names = {item["name"] for item in variant_raw}
                for task_item in task_raw:
                    if "variant_prompt_files" in task_item:
                        self.assertEqual(set(task_item["variant_prompt_files"]), variant_names)

                for script, module in modules.items():
                    with self.subTest(script=script):
                        parsed_variants = module.parse_variants(variant_path)
                        parsed_tasks = module.parse_tasks(task_path, variants=parsed_variants)
                        module.load_variant_prompt_files_for_targets(
                            module.filter_targets(parsed_tasks, parsed_variants, None, None),
                            task_file_dir=task_path.parent,
                        )
                        self.assertEqual(len(parsed_tasks), len(task_raw))
                        self.assertEqual(len(parsed_variants), len(variant_raw))
                        self.assertTrue(any("baseline" in variant.name for variant in parsed_variants))
                        self.assertTrue(any("fixture_only" in variant.name for variant in parsed_variants))
                        tasks_by_id = {task.id: task for task in parsed_tasks}
                        for raw_task in task_raw:
                            task = tasks_by_id[raw_task["id"]]
                            self.assertIn("replace success_command", task.success_command)
                            placeholder_success, placeholder_note = module.run_success_command(task, ROOT)
                            self.assertFalse(placeholder_success)
                            self.assertIn("exit=", placeholder_note)

                            expected_mapping = raw_task.get("variant_prompt_files", {})
                            self.assertEqual(set(task.variant_prompt_texts), set(expected_mapping))
                            for variant in parsed_variants:
                                argv_prompt = module.build_claude_argv("claude", task, variant)[-1]
                                if variant.name in expected_mapping:
                                    self.assertEqual(argv_prompt, task.variant_prompt_texts[variant.name])
                                    expected_fragment = expected_prompt_fragments[lane][variant.name]
                                    self.assertIn(expected_fragment, task.variant_prompt_texts[variant.name])
                                else:
                                    self.assertEqual(argv_prompt, task.prompt)

                        for variant in parsed_variants:
                            self.assertEqual(variant.extra_args, [])

    def test_image_context_pack_fixture_replays_matched_claim_safe_evidence(self):
        fixture_dir, _guide, fixture_pairs = self._experimental_benchmark_fixture_paths()
        task_path, variant_path = fixture_pairs["image_context_pack"]
        evidence_path = fixture_dir / "image-context-pack.evidence.example.jsonl"
        full_prompt_path = fixture_dir / "image-context-pack-full-evidence.prompt.example.md"
        packed_prompt_path = fixture_dir / "image-context-pack-packed-evidence.prompt.example.md"

        expected_top_level_keys = {
            "artifacts_used", "byte_metrics", "bytes_after", "bytes_before", "claim_boundary",
            "corrections", "cost_measured", "cost_usd", "effort", "evaluation_controls",
            "evaluation_profile", "external_cost_measured",
            "external_cost_usd", "external_tokens", "external_tokens_measured", "hook_triggers",
            "human_correction", "missed_context", "model", "notes", "primary_tokens_measured",
            "provenance", "provider_cached_tokens", "provider_cached_tokens_measured",
            "provider_usage", "schema_version", "shifted_cost", "success", "task_id", "tokens",
            "turns", "variant", "wall_time_seconds",
        }
        rows = [
            json.loads(line)
            for line in evidence_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertEqual(len(rows), 2)
        self.assertEqual(
            {(row["task_id"], row["variant"]) for row in rows},
            {
                ("image_context_pack_matched_correction_fixture", "baseline_full_evidence_fixture"),
                ("image_context_pack_matched_correction_fixture", "fixture_only_image_context_pack"),
            },
        )
        by_variant = {row["variant"]: row for row in rows}
        for row in rows:
            self.assertEqual(set(row), expected_top_level_keys)
            self.assertEqual(row["schema_version"], "contextguard.bench.run-evidence.v1")
            self.assertEqual(row["task_id"], "image_context_pack_matched_correction_fixture")
            self.assertTrue(row["success"])
            self.assertEqual(row["model"], "fixture-only")
            self.assertEqual(row["effort"], "medium")
            self.assertEqual((row["turns"], row["hook_triggers"], row["wall_time_seconds"]), (0, 0, 0))
            self.assertEqual(
                row["provenance"],
                {
                    "evidence_source_type": "synthetic_fixture",
                    "claim_scope": "local_replay_fixture_not_public_claim",
                    "capture_command_or_export_id": "docs/benchmark-fixtures/image-context-pack.evidence.example.jsonl",
                },
            )
            self.assertEqual(row["tokens"], {"input_tokens": 0, "output_tokens": 0, "cache_creation": 0, "cache_read": 0})
            self.assertEqual(set(row["human_correction"]), {"count", "performed", "source", "reason"})
            self.assertEqual(row["human_correction"]["source"], "synthetic_fixture")
            self.assertEqual(set(row["missed_context"]), {"present", "summary", "human_correction_required", "exact_text_fallback_available", "exact_text_fallback_verified"})
            self.assertEqual(
                row["provider_usage"],
                {
                    "provider_called": False,
                    "source": "synthetic_fixture",
                    "primary_tokens_measured": False,
                    "primary_cost_measured": False,
                    "provider_cached_tokens_measured": False,
                },
            )
            self.assertEqual(
                row["shifted_cost"],
                {"status": "unmeasured", "external_tokens_measured": False, "external_cost_measured": False, "claim_allowed": False},
            )
            self.assertEqual(
                row["claim_boundary"],
                {
                    "hosted_api_token_savings_claim_allowed": False,
                    "hosted_api_cost_savings_claim_allowed": False,
                    "quality_non_inferiority_claim_allowed": False,
                    "reason": "synthetic_fixture_only_no_provider_measurement",
                },
            )
            self.assertEqual(
                row["byte_metrics"],
                {"source": "sanitized_textual_fixture", "unit": "utf8_bytes", "image_bytes": False, "provider_tokens": False, "proxy_only": True},
            )
            self.assertEqual(row["corrections"], row["human_correction"]["count"])
            for flag in ("primary_tokens_measured", "cost_measured", "provider_cached_tokens_measured", "external_tokens_measured", "external_cost_measured"):
                self.assertFalse(row[flag])
            for value in ("cost_usd", "external_tokens", "external_cost_usd", "provider_cached_tokens"):
                self.assertEqual(row[value], 0)
        baseline = by_variant["baseline_full_evidence_fixture"]
        full_prompt_bytes = len(full_prompt_path.read_bytes())
        packed_prompt_bytes = len(packed_prompt_path.read_bytes())
        self.assertEqual((baseline["bytes_before"], baseline["bytes_after"]), (full_prompt_bytes, full_prompt_bytes))
        self.assertEqual(baseline["artifacts_used"], 0)
        self.assertEqual(baseline["human_correction"], {"count": 0, "performed": False, "source": "synthetic_fixture", "reason": "none"})
        self.assertEqual(baseline["missed_context"], {"present": False, "summary": "none", "human_correction_required": False, "exact_text_fallback_available": True, "exact_text_fallback_verified": False})

        packed = by_variant["fixture_only_image_context_pack"]
        self.assertEqual((packed["bytes_before"], packed["bytes_after"]), (full_prompt_bytes, packed_prompt_bytes))
        self.assertEqual(packed["artifacts_used"], 1)
        self.assertEqual(packed["corrections"], 1)
        self.assertEqual(
            packed["human_correction"],
            {
                "count": 1,
                "performed": True,
                "source": "synthetic_fixture",
                "reason": "initial pack omitted the qualifying owner acknowledgement context and required full-text fallback review",
            },
        )
        self.assertEqual(
            packed["missed_context"],
            {
                "present": True,
                "summary": "initial packed evidence omitted the qualifying owner acknowledgement requirement and value",
                "human_correction_required": True,
                "exact_text_fallback_available": True,
                "exact_text_fallback_verified": False,
            },
        )
        self.assertTrue(packed["missed_context"]["summary"].strip())
        self.assertIn("declaration only", packed["notes"].lower())
        self.assertIn("no artifact read", packed["notes"].lower())
        self.assertIn("omitted the owner acknowledgement", packed["notes"].lower())
        self.assertIn("required one correction", packed["notes"].lower())

        full_prompt = full_prompt_path.read_text(encoding="utf-8").lower()
        packed_prompt = packed_prompt_path.read_text(encoding="utf-8").lower()
        common_prompt_boundaries = (
            "sanitized textual", "plan-only", "protected-zone deny", "verified=false", "no replacement",
            "no runtime", "no hosted claim", "full-text fallback", "no renderer call", "no ocr call",
            "no image-parser call", "no provider call", "no model call", "no network call", "no subprocess call",
            "not establish token savings", "cost savings", "quality non-inferiority",
        )
        for prompt_name, prompt_text in (("full", full_prompt), ("packed", packed_prompt)):
            for required in common_prompt_boundaries:
                with self.subTest(prompt=prompt_name, required=required):
                    self.assertIn(required, prompt_text)
        self.assertIn("missed context: none", full_prompt)
        self.assertIn("synthetic human correction", packed_prompt)
        self.assertIn("omitted qualifying context at first", packed_prompt)
        self.assertIn("missed context remains recorded", packed_prompt)
        self.assertIn("declaration only with no artifact read", packed_prompt)

        combined = "\n".join(path.read_text(encoding="utf-8").lower() for path in (task_path, variant_path, evidence_path, full_prompt_path, packed_prompt_path))
        for forbidden in ("http://", "https://", str(Path.home()).lower(), "provider endpoint", "model endpoint"):
            self.assertNotIn(forbidden, combined)
        binary_suffixes = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".heic", ".tiff", ".bmp", ".pdf"}
        self.assertFalse(any(path.suffix.lower() in binary_suffixes for path in fixture_dir.iterdir()))

        with tempfile.TemporaryDirectory() as tmp:
            outputs = []
            for script in BENCH_SCRIPTS:
                stem = "kit" if script == BENCH_SCRIPTS[0] else "plugin"
                csv_path = Path(tmp) / f"{stem}.csv"
                report_path = Path(tmp) / f"{stem}.report.json"
                dashboard_path = Path(tmp) / f"{stem}.dashboard.md"
                proc = subprocess.run(
                    [
                        sys.executable, str(script), "--tasks", str(task_path), "--variants", str(variant_path),
                        "--evidence-jsonl", str(evidence_path), "--baseline-variant", "baseline_full_evidence_fixture",
                        "--claude-bin", "/definitely/missing/contextguard-claude", "--csv", str(csv_path),
                        "--report-json", str(report_path), "--dashboard-md", str(dashboard_path),
                    ],
                    cwd=ROOT, text=True, capture_output=True, check=True,
                )
                self.assertNotIn("fixture-only placeholder", proc.stderr)
                with csv_path.open(newline="", encoding="utf-8") as handle:
                    csv_rows = list(csv.DictReader(handle))
                self.assertEqual(len(csv_rows), 2)
                normalized_csv_rows = [
                    {key: value for key, value in row.items() if key != "date"}
                    for row in csv_rows
                ]
                outputs.append((normalized_csv_rows, report_path.read_bytes(), dashboard_path.read_bytes()))
            self.assertEqual(outputs[0], outputs[1])
            report = json.loads(outputs[0][1])
            # The fixture now opts into the image-context evaluation profile, so every
            # public-authority surface is clamped to the evaluation-only non-candidate value.
            self.assertEqual(report["claim_status"], IMAGE_CONTEXT_EVALUATION_ONLY_CLAIM_STATUS)
            self.assertEqual(report["public_claim_status"], IMAGE_CONTEXT_EVALUATION_ONLY_CLAIM_STATUS)
            self.assertFalse(report["public_claim_eligible"])
            self.assertFalse(report["public_claim_readiness"]["claim_allowed"])
            self.assertEqual(len(report["matched_pair_evidence"]), 1)
            blockers = set(report["public_claim_readiness"]["blocking_gate_ids"])
            self.assertTrue({"provider_measured_token_cost", "quality_non_inferiority", "shifted_cost_accounting", "provider_export_provenance"}.issubset(blockers))
            lane = report["evaluation_profiles"][IMAGE_CONTEXT_PROFILE_REPORT_KEY]
            self.assertEqual(lane["schema_version"], IMAGE_CONTEXT_READINESS_SCHEMA_VERSION)
            self.assertEqual(lane["status"], "blocked")
            self.assertTrue(lane["evaluation_only"])
            self.assertFalse(lane["promotion_authority"])
            self.assertFalse(lane["public_claim_allowed"])
            # The shipped fixture is deliberately unverified-fallback with one correction.
            self.assertIn("exact_text_fallback_binding", lane["blocking_gate_ids"])
            self.assertIn("missed_context_review", lane["blocking_gate_ids"])
            self.assertEqual(lane["evidence_levels"]["provider_measurement"], "unmeasured")
            self.assertEqual(lane["evidence_levels"]["fallback_binding"], "missing")

    def test_token_savings_12task_fixture_parses_and_generates_claim_safe_report(self):
        fixture_dir, _guide, fixture_pairs = self._experimental_benchmark_fixture_paths()
        task_path, variant_path = fixture_pairs["token_savings"]
        evidence_path = fixture_dir / "token-savings-12task.evidence.example.jsonl"
        task_raw = json.loads(task_path.read_text(encoding="utf-8"))
        self.assertEqual(len(task_raw), 12)
        evidence_raw = [
            json.loads(line)
            for line in evidence_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertEqual(len(evidence_raw), 24)
        self.assertTrue(all(row["provenance"]["evidence_source_type"] == "synthetic_fixture" for row in evidence_raw))
        self.assertTrue(all(row["primary_tokens_measured"] is False for row in evidence_raw))
        expected_categories = {
            "bugfix",
            "exploration",
            "code_review",
            "long_log_analysis",
            "migration",
            "docs",
            "refactor",
            "performance",
            "telemetry",
            "cache_layout",
            "tool_schema",
            "artifact_receipt",
        }
        for category in expected_categories:
            with self.subTest(category=category):
                self.assertTrue(any(category in item["id"] for item in task_raw))
        combined_fixture = (fixture_dir / "token-savings-12task-baseline.prompt.example.md").read_text(encoding="utf-8").lower()
        combined_fixture += (fixture_dir / "token-savings-12task-contextguard.prompt.example.md").read_text(encoding="utf-8").lower()
        for required in (
            "tokens_per_successful_task",
            "total_cost_with_shift_usd",
            "external_cost_usd",
            "matched successful tasks",
            "10%p failure-rate guardrail",
            "char/4 token proxies",
        ):
            self.assertIn(required, combined_fixture)

        rows: list[dict[str, str]] = []
        for task in task_raw:
            task_id = task["id"]
            rows.append({
                "task_id": task_id,
                "variant": "baseline_full_context_fixture",
                "success": "true",
                "total_tokens": "1200",
                "primary_tokens_measured": "true",
                "cost_usd": "0.120",
                "cost_measured": "true",
                "external_tokens": "0",
                "external_tokens_measured": "true",
                "external_cost_usd": "0",
                "external_cost_measured": "true",
                "total_cost_with_shift_usd": "0.120",
                "bytes_before": "16000",
                "bytes_after": "16000",
                "corrections": "0",
            })
            rows.append({
                "task_id": task_id,
                "variant": "fixture_only_contextguard_advisory_foundations",
                "success": "true",
                "total_tokens": "900",
                "primary_tokens_measured": "true",
                "cost_usd": "0.080",
                "cost_measured": "true",
                "external_tokens": "40",
                "external_tokens_measured": "true",
                "external_cost_usd": "0.005",
                "external_cost_measured": "true",
                "total_cost_with_shift_usd": "0.085",
                "bytes_before": "16000",
                "bytes_after": "9000",
                "corrections": "0",
            })

        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_token_savings_12task_{index}")
                parsed_variants = module.parse_variants(variant_path)
                parsed_tasks = module.parse_tasks(task_path, variants=parsed_variants)
                self.assertEqual(len(parsed_tasks), 12)
                self.assertTrue(all(module.is_placeholder_success_command(task.success_command) for task in parsed_tasks))
                replay_rows = module.read_evidence_jsonl(evidence_path)
                replay_targets = module.filter_targets(parsed_tasks, parsed_variants, None, None)
                replay_by_key = module.validate_evidence_coverage(replay_rows, replay_targets)
                self.assertEqual(len(replay_by_key), 24)
                self.assertTrue(all(row.source_type == "synthetic_fixture" for row in replay_rows))
                self.assertTrue(all(not row.result.primary_tokens_measured for row in replay_rows))
                self.assertTrue(all(not row.result.cost_measured for row in replay_rows))
                replay_report = module.annotate_replay_report(
                    module.summarize_benchmark_rows(
                        [
                            {
                                "task_id": row.result.task_id,
                                "variant": row.result.variant,
                                "success": "true" if row.result.success else "false",
                                "total_tokens": str(sum(row.result.tokens.values())),
                                "primary_tokens_measured": "false",
                                "cost_usd": f"{row.result.cost_usd:.6f}",
                                "cost_measured": "false",
                                "external_tokens": str(row.result.external_tokens),
                                "external_tokens_measured": "true" if row.result.external_tokens_measured else "false",
                                "external_cost_usd": f"{row.result.external_cost_usd:.6f}",
                                "external_cost_measured": "true" if row.result.external_cost_measured else "false",
                                "total_cost_with_shift_usd": "",
                                "bytes_before": str(row.result.bytes_before),
                                "bytes_after": str(row.result.bytes_after),
                                "corrections": str(row.result.corrections),
                            }
                            for row in replay_rows
                        ],
                        "baseline_full_context_fixture",
                    ),
                    replay_rows,
                    mixed_csv=False,
                )
                self.assertEqual(replay_report["claim_status"], "replay_only_not_public_claim")
                self.assertEqual(replay_report["public_claim_status"], "replay_only_not_public_claim")
                replay_matrix = replay_report["default_matrix"]
                self.assertEqual(replay_matrix["schema_version"], "contextguard.bench.default-matrix.v1")
                self.assertEqual(replay_matrix["claim_status_observed"], "replay_only_not_public_claim")
                self.assertFalse(replay_matrix["public_claim_allowed"])
                replay_readiness = replay_report["public_claim_readiness"]
                self.assertFalse(replay_readiness["claim_allowed"])
                self.assertIn("provider_export_provenance", replay_readiness["blocking_gate_ids"])
                self.assertTrue(replay_matrix["claim_boundary"]["reporting_only"])
                self.assertTrue(all(not lane["public_claim_allowed"] for lane in replay_matrix["lanes"]))
                report = module.summarize_benchmark_rows(rows, "baseline_full_context_fixture")
                self.assertEqual(report["schema"], "context-guard-bench-report-v1")
                self.assertEqual(report["claim_status"], "token_and_shifted_cost_savings_observed")
                self.assertEqual(len(report["matched_pair_evidence"]), 12)
                measured_readiness = report["public_claim_readiness"]
                self.assertFalse(measured_readiness["claim_allowed"])
                self.assertEqual(
                    measured_readiness["status"],
                    "csv_provenance_unknown_requires_original_evidence_or_trusted_ledger",
                )
                matrix = report["default_matrix"]
                self.assertEqual(matrix["schema_version"], "contextguard.bench.default-matrix.v1")
                self.assertEqual(
                    [lane["lane"] for lane in matrix["lanes"]],
                    [
                        "trimming",
                        "artifact_escrow",
                        "tool_pruning",
                        "cache_advice",
                        "adaptive_k",
                        "optional_compression",
                    ],
                )
                by_lane = {lane["lane"]: lane for lane in matrix["lanes"]}
                self.assertEqual(by_lane["trimming"]["classification"], "default-on")
                self.assertEqual(by_lane["artifact_escrow"]["classification"], "default-on")
                self.assertEqual(by_lane["tool_pruning"]["classification"], "default-on")
                self.assertEqual(by_lane["cache_advice"]["classification"], "advisory")
                self.assertTrue(by_lane["cache_advice"]["policy_clamped"])
                self.assertEqual(by_lane["adaptive_k"]["classification"], "experimental")
                self.assertEqual(by_lane["adaptive_k"]["lane_match_method"], "absent")
                self.assertEqual(by_lane["optional_compression"]["classification"], "experimental")
                self.assertEqual(set(matrix["classification_set"]), {"default-on", "advisory", "experimental", "reject/rework"})
                self.assertFalse(matrix["public_claim_allowed"])
                dashboard = module.render_dashboard_markdown(report)
                self.assertIn("## Default matrix", dashboard)
                self.assertIn("| Lane | Classification | Matched Tasks | Quality Gate | Token Evidence | Public Claim | Reason |", dashboard)
                comparison = report["comparisons"][0]
                self.assertEqual(comparison["matched_successful_task_count"], 12)
                self.assertEqual(comparison["quality_gate"], "pass")
                self.assertIn("tokens_per_successful_task", report["summary_by_variant"]["baseline_full_context_fixture"])
                self.assertGreater(report["summary_by_variant"]["fixture_only_contextguard_advisory_foundations"]["external_cost_successful_usd"], 0)
                self.assertIn("Proxy byte reductions", report["caveat"])
                pair = report["matched_pair_evidence"][0]
                self.assertEqual(pair["schema_version"], "contextguard.bench.matched-pair.v1")
                self.assertTrue(pair["claim_boundary"]["token_savings_claim_allowed"])
                self.assertTrue(pair["claim_boundary"]["shifted_cost_claim_allowed"])

    def test_experimental_benchmark_fixtures_are_claim_safe(self):
        fixture_dir, guide, fixture_pairs = self._experimental_benchmark_fixture_paths()
        combined_fixture_text = self._combined_experimental_benchmark_fixture_text(guide, fixture_dir, fixture_pairs)
        for required in (
            "fixture-only",
            "synthetic",
            "not a shipped runtime feature",
            "dry-run-only",
            "provider-measured",
            "matched successful tasks",
            "failure-rate guardrail",
            "human corrections",
            "shifted-cost accounting",
            "artifact receipt",
            "exact re-expand",
            "sanitized evidence only",
            "exact retrieval",
            "receipt fallback",
            "protected evidence",
            "semantically rewritten",
            "runner-native variant prompt files",
            "variant_prompt_files",
            "file-backed",
            "missed context",
            "omitted context",
            "crop area",
            "image dimensions",
            "ocr confidence",
            "ocr error notes",
            "full visual fallback",
            "cache layout",
            "tool-schema deferral",
            "char/4 token proxies",
            "10%p failure-rate guardrail",
        ):
            with self.subTest(required=required):
                self.assertIn(required, combined_fixture_text)

        forbidden_claim_patterns = [
            r"guarantees?\s+(?:hosted\s+api\s+)?(?:token|cost)\s+savings",
            r"guaranteed\s+(?:hosted\s+api\s+)?(?:token|cost)\s+savings",
            r"fixed\s+\d+%\s+(?:token|cost)\s+savings",
            r"reduces?\s+tokens?\s+by\s+\d+%",
            r"cuts?\s+costs?\s+by\s+\d+%",
        ]
        public_docs = (
            ROOT / "README.md",
            ROOT / "README.ko.md",
            KIT_DIR / "README.md",
            PLUGIN_DIR / "README.md",
            PLUGIN_DIR / "README.ko.md",
            ROOT / "docs" / "benchmark-workflow-examples.md",
            ROOT / "research" / "benchmark-plan.md",
            ROOT / "research" / "experimental-token-reduction-radar.md",
            guide,
        )
        public_doc_text = "\n".join(
            re.sub(r"[*_`]+", "", path.read_text(encoding="utf-8").lower())
            for path in public_docs
        )
        korean_forbidden_claim_patterns = [
            r"(?:토큰|비용)\s*절감\s*보장(?!하지)",
            r"(?:토큰|비용)\s*절감(?:률)?(?:을|를)?\s*보장(?!하지|할\s+수)",
            r"(?:토큰|비용)\s*절감(?:을|를)?\s*보장합니다",
            r"고정\s*\d+%\s*(?:토큰|비용)\s*절감",
        ]
        for pattern in forbidden_claim_patterns:
            with self.subTest(forbidden_claim=pattern):
                self.assertNotRegex(combined_fixture_text, pattern)
                self.assertNotRegex(public_doc_text, pattern)
        for pattern in korean_forbidden_claim_patterns:
            with self.subTest(korean_forbidden_claim=pattern):
                self.assertNotRegex(public_doc_text, pattern)
        for forbidden in (
            "sk-ant-",
            "bearer ",
            "http://",
            "https://",
            str(Path.home()).lower(),
            ".png",
            ".jpg",
            ".jpeg",
            ".webp",
            ".gif",
            ".heic",
            ".tiff",
            "api_key",
            "client_secret",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, combined_fixture_text)

        for forbidden_helper in (
            "context-guard-ocr",
            "context-guard-crop",
            "context-guard-visual-token",
            "context-guard-learned-compression",
            "context-guard-kv-cache",
            "context-guard-latent",
        ):
            with self.subTest(forbidden_helper=forbidden_helper):
                self.assertFalse((PLUGIN_BIN / forbidden_helper).exists())
                self.assertNotIn(forbidden_helper, json.dumps(json.loads((ROOT / "package.json").read_text(encoding="utf-8"))))
                self.assertNotIn(forbidden_helper, public_doc_text)

        package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        package_metadata = " ".join(
            [str(package.get("description", ""))]
            + [str(keyword) for keyword in package.get("keywords", [])]
        ).lower()
        for pattern in (r"\blearned\b", r"\bocr\b", r"visual[-\s]+token", r"\bkv\b", r"\blatent\b"):
            with self.subTest(package_metadata_pattern=pattern):
                self.assertIsNone(re.search(pattern, package_metadata))

    def test_experimental_benchmark_fixtures_selected_dry_runs_and_placeholders(self):
        _, _, fixture_pairs = self._experimental_benchmark_fixture_paths()
        modules = self._experimental_benchmark_runner_modules()

        for script, module in modules.items():
            for lane, (task_path, variant_path) in fixture_pairs.items():
                with self.subTest(script=script, lane=lane):
                    task_raw = json.loads(task_path.read_text(encoding="utf-8"))
                    variant_raw = json.loads(variant_path.read_text(encoding="utf-8"))
                    target_task = task_raw[0]["id"]
                    target_variant = variant_raw[0]["name"]
                    profiled_fixture = task_raw[0].get("evaluation_profile") is not None
                    with tempfile.TemporaryDirectory() as tmp:
                        csv_path = Path(tmp) / "dry-run.csv"
                        base_argv = [
                            sys.executable,
                            str(script),
                            "--tasks",
                            str(task_path),
                            "--variants",
                            str(variant_path),
                            "--task-id",
                            target_task,
                            "--variant",
                            target_variant,
                            "--csv",
                            str(csv_path),
                        ]
                        if profiled_fixture:
                            # A profiled fixture is evaluation-only: the provider path is refused
                            # outright, --dry-run included, so it never reaches the placeholder
                            # guard and never renders a provider-path prompt preview. Its prompt
                            # swap and replay behavior are covered by
                            # ImageContextEvaluationProfileTests against --evidence-jsonl.
                            sentinel = Path(tmp) / "provider-called.txt"
                            fake = Path(tmp) / "fake-claude"
                            fake.write_text(
                                "#!/usr/bin/env python3\n"
                                "import pathlib, sys\n"
                                f"pathlib.Path({str(sentinel)!r}).write_text('called', encoding='utf-8')\n"
                                "sys.stdout.write('{}')\n",
                                encoding="utf-8",
                            )
                            fake.chmod(0o755)
                            for extra in (["--dry-run"], ["--claude-bin", str(fake)]):
                                refused = subprocess.run(
                                    base_argv + extra, text=True, capture_output=True,
                                )
                                self.assertNotEqual(refused.returncode, 0)
                                self.assertIn(
                                    "profile_replay_required", refused.stdout + refused.stderr,
                                )
                                self.assertFalse(sentinel.exists())
                                self.assertFalse(csv_path.exists())
                                self.assertFalse(
                                    csv_path.with_name(f"{csv_path.name}.lock").exists()
                                )
                            continue

                        proc = subprocess.run(
                            base_argv + ["--dry-run"],
                            text=True,
                            capture_output=True,
                            check=True,
                        )
                        self.assertIn("dry-run; CSV not updated", proc.stdout)
                        self.assertFalse(csv_path.exists())

                        dry_runs = {}
                        for variant_name in (item["name"] for item in variant_raw):
                            variant_proc = subprocess.run(
                                [
                                    sys.executable,
                                    str(script),
                                    "--tasks",
                                    str(task_path),
                                    "--variants",
                                    str(variant_path),
                                    "--task-id",
                                    target_task,
                                    "--variant",
                                    variant_name,
                                    "--csv",
                                    str(Path(tmp) / f"{variant_name}.csv"),
                                    "--dry-run",
                                ],
                                text=True,
                                capture_output=True,
                                check=True,
                            )
                            dry_runs[variant_name] = variant_proc.stdout
                        if lane == "visual_ocr":
                            self.assertIn("Full visual evidence", dry_runs["baseline_full_visual_fixture"])
                            self.assertIn("Cropped or OCR-derived evidence", dry_runs["fixture_only_cropped_or_ocr_evidence"])
                            self.assertNotEqual(
                                dry_runs["baseline_full_visual_fixture"],
                                dry_runs["fixture_only_cropped_or_ocr_evidence"],
                            )
                        elif lane == "learned_compression":
                            self.assertIn("Sanitized context pack", dry_runs["baseline_uncompressed_fixture"])
                            self.assertIn("Compressed digest candidate", dry_runs["fixture_only_learned_compression_candidate"])
                            self.assertNotEqual(
                                dry_runs["baseline_uncompressed_fixture"],
                                dry_runs["fixture_only_learned_compression_candidate"],
                            )
                        elif lane == "token_savings":
                            self.assertIn("unoptimized full-context", dry_runs["baseline_full_context_fixture"])
                            self.assertIn("ContextGuard advisory-foundations", dry_runs["fixture_only_contextguard_advisory_foundations"])
                            self.assertNotEqual(
                                dry_runs["baseline_full_context_fixture"],
                                dry_runs["fixture_only_contextguard_advisory_foundations"],
                            )
                        else:
                            self.assertIn("Raw sanitized command output", dry_runs["baseline_raw_output_fixture"])
                            self.assertIn("Digest of sanitized command output", dry_runs["fixture_only_digest_artifact_receipt"])
                            self.assertNotEqual(
                                dry_runs["baseline_raw_output_fixture"],
                                dry_runs["fixture_only_digest_artifact_receipt"],
                            )

                        fake = Path(tmp) / "fake-claude"
                        sentinel = Path(tmp) / "provider-called.txt"
                        fake.write_text(
                            "#!/usr/bin/env python3\n"
                            "import pathlib, sys\n"
                            f"pathlib.Path({str(sentinel)!r}).write_text('called', encoding='utf-8')\n"
                            "sys.stdout.write('{}')\n",
                            encoding="utf-8",
                        )
                        fake.chmod(0o755)
                        real_csv = Path(tmp) / "real-run.csv"
                        real_proc = subprocess.run(
                            [
                                sys.executable,
                                str(script),
                                "--tasks",
                                str(task_path),
                                "--variants",
                                str(variant_path),
                                "--task-id",
                                target_task,
                                "--variant",
                                target_variant,
                                "--csv",
                                str(real_csv),
                                "--claude-bin",
                                str(fake),
                            ],
                            text=True,
                            capture_output=True,
                        )
                        self.assertNotEqual(real_proc.returncode, 0)
                        self.assertIn("fixture-only placeholder", real_proc.stderr)
                        self.assertFalse(sentinel.exists())
                        self.assertFalse(real_csv.exists())

                        resume_csv = Path(tmp) / "resume.csv"
                        row = {column: "" for column in module.CSV_COLUMNS}
                        row.update({
                            "date": "2026-01-01T00:00:00Z",
                            "claude_version": "skipped",
                            "task_id": target_task,
                            "variant": target_variant,
                            "success": "true",
                        })
                        with resume_csv.open("w", encoding="utf-8", newline="") as handle:
                            writer = csv.DictWriter(handle, fieldnames=module.CSV_COLUMNS)
                            writer.writeheader()
                            writer.writerow(row)
                        sentinel.unlink(missing_ok=True)
                        resume_proc = subprocess.run(
                            [
                                sys.executable,
                                str(script),
                                "--tasks",
                                str(task_path),
                                "--variants",
                                str(variant_path),
                                "--task-id",
                                target_task,
                                "--variant",
                                target_variant,
                                "--csv",
                                str(resume_csv),
                                "--claude-bin",
                                str(fake),
                                "--resume",
                            ],
                            text=True,
                            capture_output=True,
                            check=True,
                        )
                        self.assertIn(f"skip {target_task}/{target_variant}", resume_proc.stdout)
                        self.assertIn("completed 0 run(s)", resume_proc.stdout)
                        self.assertFalse(sentinel.exists())

    def test_benchmark_report_keeps_provider_cache_telemetry_out_of_savings_claims(self):
        module = load_module_from_path(KIT_DIR / "benchmark_runner.py", "_bench_runner_test_provider_cache_claims")
        report = module.summarize_benchmark_rows(
            [
                {
                    "task_id": "t01",
                    "variant": "baseline",
                    "total_tokens": "100",
                    "primary_tokens_measured": "true",
                    "success": "true",
                    "corrections": "0",
                    "provider_cached_tokens": "0",
                    "provider_cached_tokens_measured": "true",
                },
                {
                    "task_id": "t01",
                    "variant": "cache_discount_only",
                    "total_tokens": "100",
                    "primary_tokens_measured": "true",
                    "success": "true",
                    "corrections": "0",
                    "provider_cached_tokens": "900",
                    "provider_cached_tokens_measured": "true",
                },
            ],
            "baseline",
        )
        comparison = report["comparisons"][0]
        self.assertEqual(report["claim_status"], "compare_variants")
        self.assertEqual(comparison["token_savings_pct"], 0.0)
        self.assertEqual(report["summary_by_variant"]["cache_discount_only"]["observed_telemetry"]["provider_cache"], "observed")
        self.assertIn("provider-cache discounts", report["caveat"].lower())

    def test_benchmark_report_marks_zero_wall_time_observed_and_missing_provider_cache_unavailable(self):
        module = load_module_from_path(KIT_DIR / "benchmark_runner.py", "_bench_runner_test_zero_wall_time_provider_cache")
        report = module.summarize_benchmark_rows(
            [
                {
                    "task_id": "t01",
                    "variant": "baseline",
                    "total_tokens": "100",
                    "primary_tokens_measured": "true",
                    "wall_time_seconds": "0.0",
                    "success": "true",
                    "corrections": "0",
                },
            ],
            "baseline",
        )
        baseline = report["summary_by_variant"]["baseline"]
        self.assertEqual(baseline["observed_telemetry"]["wall_time"], "observed")
        self.assertEqual(baseline["wall_time_seconds_per_successful_task"], 0.0)
        self.assertEqual(baseline["observed_telemetry"]["provider_cache"], "unavailable")

    def test_benchmark_report_marks_missing_wall_time_unavailable(self):
        module = load_module_from_path(KIT_DIR / "benchmark_runner.py", "_bench_runner_test_wall_time_availability")
        report = module.summarize_benchmark_rows(
            [
                {
                    "task_id": "t01",
                    "variant": "baseline",
                    "total_tokens": "100",
                    "success": "true",
                    "cost_measured": "false",
                },
            ],
            "baseline",
        )
        self.assertEqual(
            report["summary_by_variant"]["baseline"]["observed_telemetry"]["wall_time"],
            "unavailable",
        )
        self.assertEqual(report["summary_by_variant"]["baseline"]["wall_time_seconds_measured_successful"], 0)

    def test_benchmark_report_does_not_claim_token_savings_without_primary_token_telemetry(self):
        module = load_module_from_path(KIT_DIR / "benchmark_runner.py", "_bench_runner_test_primary_token_availability")
        report = module.summarize_benchmark_rows(
            [
                {
                    "task_id": "t01",
                    "variant": "baseline",
                    "success": "true",
                    "total_tokens": "100",
                    "primary_tokens_measured": "true",
                    "corrections": "0",
                },
                {
                    "task_id": "t01",
                    "variant": "optimized",
                    "success": "true",
                    "total_tokens": "0",
                    "primary_tokens_measured": "false",
                    "corrections": "0",
                },
            ],
            "baseline",
        )
        comparison = report["comparisons"][0]
        self.assertEqual(report["claim_status"], "insufficient_paired_data")
        self.assertEqual(comparison["quality_gate"], "pass")
        self.assertEqual(comparison["paired_token_task_count"], 0)
        self.assertIsNone(comparison["token_savings_pct"])
        self.assertEqual(
            report["summary_by_variant"]["optimized"]["observed_telemetry"]["tokens"],
            "unavailable",
        )
        self.assertIsNone(report["summary_by_variant"]["optimized"]["tokens_per_successful_task"])

    def test_benchmark_runner_bounds_claude_stdout_before_json_parse(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_claude_output_bound_{index}")
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    fake = root / "fake-claude"
                    fake.write_text(
                        "#!/usr/bin/env python3\n"
                        "import sys\n"
                        "sys.stdout.write('x' * 256)\n",
                        encoding="utf-8",
                    )
                    fake.chmod(0o755)
                    original_limit = module.CLAUDE_OUTPUT_MAX_BYTES
                    module.CLAUDE_OUTPUT_MAX_BYTES = 128
                    try:
                        result = module.run_fixture(
                            module.TaskFixture(id="t01", prompt="x", max_turns=1),
                            module.Variant(name="baseline", extra_args=[]),
                            str(fake),
                            root,
                            False,
                        )
                    finally:
                        module.CLAUDE_OUTPUT_MAX_BYTES = original_limit

                    self.assertFalse(result.success)
                    self.assertIn("claude output limit exceeded", result.notes)

    def test_benchmark_runner_bounds_success_command_output(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_success_output_bound_{index}")
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    loud_success = root / "loud-success"
                    loud_success.write_text(
                        "#!/usr/bin/env python3\n"
                        "import sys\n"
                        "sys.stdout.write('x' * 256)\n",
                        encoding="utf-8",
                    )
                    loud_success.chmod(0o755)
                    original_limit = module.SUCCESS_COMMAND_OUTPUT_MAX_BYTES
                    module.SUCCESS_COMMAND_OUTPUT_MAX_BYTES = 128
                    try:
                        ok, note = module.run_success_command(
                            module.TaskFixture(
                                id="t01",
                                prompt="x",
                                max_turns=1,
                                success_command=str(loud_success),
                                success_cwd=".",
                            ),
                            root,
                        )
                    finally:
                        module.SUCCESS_COMMAND_OUTPUT_MAX_BYTES = original_limit

                    self.assertFalse(ok)
                    self.assertIn("success_command output limit exceeded", note)

    def test_benchmark_runner_timeout_kills_process_group_children(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_pg_timeout_{index}")
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    sentinel = root / "child-survived.txt"
                    child_code = (
                        "import pathlib, sys, time; "
                        "time.sleep(2.0); "
                        "pathlib.Path(sys.argv[1]).write_text('survived', encoding='utf-8')"
                    )
                    parent_code = (
                        "import subprocess, sys, time; "
                        "subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]]); "
                        "time.sleep(10.0)"
                    )

                    result = module.run_bounded_command(
                        [sys.executable, "-c", parent_code, child_code, str(sentinel)],
                        cwd=root,
                        timeout_seconds=1,
                        max_output_bytes=1024,
                    )

                    self.assertTrue(result.timed_out)
                    self.assertEqual(result.returncode, 124)
                    time.sleep(1.5)
                    self.assertFalse(sentinel.exists())

    def test_benchmark_runner_timeout_kills_pipe_holding_child_after_parent_exit(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script):
                module = load_python_script_module(script, f"_bench_runner_pipe_child_timeout_{index}")
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    sentinel = root / "pipe-child-survived.txt"
                    child_code = (
                        "import pathlib, sys, time; "
                        "time.sleep(2.0); "
                        "pathlib.Path(sys.argv[1]).write_text('survived', encoding='utf-8')"
                    )
                    parent_code = (
                        "import subprocess, sys; "
                        "subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]])"
                    )

                    result = module.run_bounded_command(
                        [sys.executable, "-c", parent_code, child_code, str(sentinel)],
                        cwd=root,
                        timeout_seconds=1,
                        max_output_bytes=1024,
                    )

                    self.assertTrue(result.timed_out)
                    self.assertEqual(result.returncode, 124)
                    time.sleep(1.5)
                    self.assertFalse(sentinel.exists())

    def test_runner_uses_project_root_for_claude_and_redacts_failure_notes(self):
        for script in BENCH_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    project = root / "project"
                    project.mkdir()
                    caller = root / "caller"
                    caller.mkdir()
                    fake = root / "fake-claude"
                    auth_value = "opaque-token-value"
                    generic_token = "generic-secret-value"
                    env_token = "env-token-value"
                    access_token = "access-token-value"
                    refresh_token = "refresh-token-value"
                    db_password = "db-password-value"
                    secret_key = "secret-key-value"
                    json_secret = "json-secret-value"
                    header_secret = "header-secret-value"
                    fake.write_text(
                        "#!/usr/bin/env python3\n"
                        "import os, pathlib, sys\n"
                        "pathlib.Path('claude-cwd.txt').write_text(os.getcwd(), encoding='utf-8')\n"
                        f"sys.stderr.write('Authorization: Bearer {auth_value}\\n')\n"
                        f"sys.stderr.write('token={generic_token}\\n')\n"
                        f"sys.stderr.write('API_TOKEN={env_token}\\n')\n"
                        f"sys.stderr.write('access_token={access_token}\\n')\n"
                        f"sys.stderr.write('refresh_token={refresh_token}\\n')\n"
                        f"sys.stderr.write('DB_PASSWORD={db_password}\\n')\n"
                        f"sys.stderr.write('SECRET_KEY={secret_key}\\n')\n"
                        f"sys.stderr.write('{{\"token\": \"{json_secret}\"}}\\n')\n"
                        f"sys.stderr.write('X-Api-Key: {header_secret}\\n')\n"
                        "sys.exit(7)\n",
                        encoding="utf-8",
                    )
                    fake.chmod(0o755)
                    (project / "tasks.json").write_text(json.dumps([
                        {"id": "t01", "prompt": "x", "max_turns": 1, "success_command": "true", "success_cwd": "."}
                    ]))
                    (project / "variants.json").write_text(json.dumps([
                        {"name": "baseline", "extra_args": []}
                    ]))
                    csv_path = project / "results.csv"
                    nested_caller = caller / "nested" / "deeper"
                    nested_caller.mkdir(parents=True)
                    relative_fake = os.path.relpath(fake, nested_caller)
                    proc = subprocess.run(
                        [sys.executable, str(script),
                         "--tasks", str(project / "tasks.json"),
                         "--variants", str(project / "variants.json"),
                         "--csv", str(csv_path),
                         "--claude-bin", relative_fake,
                         "--project-root", str(project)],
                        cwd=nested_caller,
                        text=True, capture_output=True, check=True,
                    )

                    self.assertEqual((project / "claude-cwd.txt").read_text(encoding="utf-8"), str(project.resolve()))
                    self.assertNotIn(auth_value, proc.stdout)
                    self.assertNotIn(generic_token, proc.stdout)
                    self.assertNotIn(env_token, proc.stdout)
                    self.assertNotIn(access_token, proc.stdout)
                    self.assertNotIn(refresh_token, proc.stdout)
                    self.assertNotIn(db_password, proc.stdout)
                    self.assertNotIn(secret_key, proc.stdout)
                    self.assertNotIn(json_secret, proc.stdout)
                    self.assertNotIn(header_secret, proc.stdout)
                    self.assertNotIn(auth_value, proc.stderr)
                    self.assertNotIn(generic_token, proc.stderr)
                    self.assertNotIn(env_token, proc.stderr)
                    self.assertNotIn(access_token, proc.stderr)
                    self.assertNotIn(refresh_token, proc.stderr)
                    self.assertNotIn(db_password, proc.stderr)
                    self.assertNotIn(secret_key, proc.stderr)
                    self.assertNotIn(json_secret, proc.stderr)
                    self.assertNotIn(header_secret, proc.stderr)
                    with csv_path.open(encoding="utf-8") as f:
                        row = next(csv.DictReader(f))
                    self.assertEqual(row["success"], "false")
                    self.assertIn("claude exit=7", row["notes"])
                    self.assertIn("[REDACTED]", row["notes"])
                    self.assertNotIn(auth_value, row["notes"])
                    self.assertNotIn(generic_token, row["notes"])
                    self.assertNotIn(env_token, row["notes"])
                    self.assertNotIn(access_token, row["notes"])
                    self.assertNotIn(refresh_token, row["notes"])
                    self.assertNotIn(db_password, row["notes"])
                    self.assertNotIn(secret_key, row["notes"])
                    self.assertNotIn(json_secret, row["notes"])
                    self.assertNotIn(header_secret, row["notes"])

    def test_run_records_failure_when_success_command_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = _make_fake_claude(root, usage={"input_tokens": 5, "output_tokens": 5})
            (root / "tasks.json").write_text(json.dumps([
                {"id": "t01", "prompt": "x", "model": "sonnet", "max_turns": 1,
                 "success_command": "false", "success_cwd": "."}
            ]))
            (root / "variants.json").write_text(json.dumps([
                {"name": "baseline", "extra_args": []}
            ]))
            csv_path = root / "results.csv"
            subprocess.run(
                [sys.executable, str(KIT_DIR / "benchmark_runner.py"),
                 "--tasks", str(root / "tasks.json"),
                 "--variants", str(root / "variants.json"),
                 "--csv", str(csv_path),
                 "--claude-bin", str(fake),
                 "--project-root", str(root)],
                text=True, capture_output=True, check=True,
            )
            with csv_path.open(encoding="utf-8") as f:
                row = next(csv.DictReader(f))
            self.assertEqual(row["success"], "false")
            self.assertIn("exit=1", row["notes"])

    def test_resume_skips_already_recorded_combinations(self):
        """real run 으로 적재된 (task, variant) 만 --resume 이 skip 한다.

        dry-run 은 CSV 를 건드리지 않으므로 resume 의 skip 대상이 되지 않는다 — 이렇게
        해야 dry-run 후 real run 이 silent skip 되는 데이터 손실이 차단된다.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = _make_fake_claude(root, usage={"input_tokens": 7, "output_tokens": 3})
            (root / "tasks.json").write_text(json.dumps([
                {"id": "t01", "prompt": "x", "max_turns": 1, "success_command": "true", "success_cwd": "."},
                {"id": "t02", "prompt": "y", "max_turns": 1, "success_command": "true", "success_cwd": "."},
            ]))
            (root / "variants.json").write_text(json.dumps([
                {"name": "baseline", "extra_args": []},
            ]))
            csv_path = root / "results.csv"
            common = [
                sys.executable, str(KIT_DIR / "benchmark_runner.py"),
                "--tasks", str(root / "tasks.json"),
                "--variants", str(root / "variants.json"),
                "--csv", str(csv_path),
                "--claude-bin", str(fake),
                "--project-root", str(root),
            ]
            subprocess.run(common + ["--task-id", "t01"], check=True)
            second = subprocess.run(common + ["--resume"], text=True, capture_output=True, check=True)
            self.assertIn("skip t01/baseline", second.stdout)
            self.assertIn("run t02/baseline", second.stdout)
            with csv_path.open(encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(sorted((r["task_id"], r["variant"]) for r in rows),
                             [("t01", "baseline"), ("t02", "baseline")])

    def test_runner_refuses_shell_metacharacter_in_success_command(self):
        """fixture 의 success_command 가 shell injection surface 가 되지 않는다.

        `shlex.split + shell=False` 만으로는 `true ; echo pwned` 가 `["true", ";", "echo", "pwned"]`
        로 분해되어 /usr/bin/true 가 추가 인자를 무시하고 success=true 로 끝나는 false-positive
        가 생긴다. runner 는 분해된 토큰에 셸 합성 의도(`;`, `&&`, `|`, `$()`, 백틱) 가 보이면
        명시적으로 거부해 success=false 로 기록한다.
        """
        cases = [
            "true ; echo pwned",
            "true && echo pwned",
            "true | cat",
            "true `id`",
            "echo $(id)",
        ]
        for cmd in cases:
            with self.subTest(success_command=cmd):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    fake = _make_fake_claude(root, usage={"input_tokens": 1})
                    sentinel = root / "owned.txt"
                    sentinel.write_text("safe", encoding="utf-8")
                    (root / "tasks.json").write_text(json.dumps([
                        {"id": "t01", "prompt": "x", "max_turns": 1,
                         "success_command": cmd, "success_cwd": "."}
                    ]))
                    (root / "variants.json").write_text(json.dumps([
                        {"name": "baseline", "extra_args": []}
                    ]))
                    csv_path = root / "results.csv"
                    subprocess.run(
                        [sys.executable, str(KIT_DIR / "benchmark_runner.py"),
                         "--tasks", str(root / "tasks.json"),
                         "--variants", str(root / "variants.json"),
                         "--csv", str(csv_path),
                         "--claude-bin", str(fake),
                         "--project-root", str(root)],
                        text=True, capture_output=True, check=True,
                    )
                    self.assertEqual(sentinel.read_text(encoding="utf-8"), "safe",
                                     "shell metacharacter 가 fixture 에 들어와도 실행되면 안 된다")
                    with csv_path.open(encoding="utf-8") as f:
                        row = next(csv.DictReader(f))
                    self.assertEqual(row["success"], "false",
                                     f"shell metachar 가 있는 success_command 는 success=false 로 기록되어야 한다 ({cmd})")
                    self.assertIn("shell-composition", row["notes"])

    def test_runner_omits_unset_effort_from_claude_argv(self):
        """fixture 에 `effort` 가 명시되지 않으면 `--effort ...` 가 argv 에 들어가지 않는다.

        implicit default 가 strap 되면 effort-미지원 모델에서 silent failure 가 되고
        baseline variant 의 의미가 왜곡되므로, 명시 여부를 그대로 보존한다.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tasks.json").write_text(json.dumps([
                {"id": "t01", "prompt": "x", "max_turns": 1}
            ]))
            (root / "variants.json").write_text(json.dumps([
                {"name": "baseline", "extra_args": []}
            ]))
            proc = subprocess.run(
                [sys.executable, str(KIT_DIR / "benchmark_runner.py"),
                 "--tasks", str(root / "tasks.json"),
                 "--variants", str(root / "variants.json"),
                 "--csv", str(root / "results.csv"),
                 "--dry-run"],
                text=True, capture_output=True, check=True,
            )
            self.assertNotIn("--effort", proc.stdout,
                             "fixture 가 effort 를 명시하지 않으면 argv 에 빠져야 한다")
            self.assertNotIn("--max-budget-usd", proc.stdout,
                             "fixture 가 max_budget_usd 를 명시하지 않으면 argv 에 빠져야 한다")

    def test_runner_validates_max_budget_usd_value(self):
        """max_budget_usd 가 0 이하이거나 숫자가 아니면 즉시 SystemExit 으로 거부한다."""
        for bad in [0, -1, "abc", "nan", "inf", "-inf", "1e100000"]:
            with self.subTest(max_budget_usd=bad):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    (root / "tasks.json").write_text(json.dumps([
                        {"id": "t01", "prompt": "x", "max_turns": 1, "max_budget_usd": bad}
                    ]))
                    (root / "variants.json").write_text(json.dumps([
                        {"name": "baseline", "extra_args": []}
                    ]))
                    proc = subprocess.run(
                        [sys.executable, str(KIT_DIR / "benchmark_runner.py"),
                         "--tasks", str(root / "tasks.json"),
                         "--variants", str(root / "variants.json"),
                         "--csv", str(root / "results.csv"),
                         "--dry-run"],
                        text=True, capture_output=True,
                    )
                    self.assertNotEqual(proc.returncode, 0,
                                        f"max_budget_usd={bad} 는 거부되어야 한다")
                    self.assertIn("max_budget_usd", proc.stderr)

    def test_runner_validates_max_turns_value(self):
        """max_turns 는 양의 정수 fixture 필드여야 한다."""
        for bad in [0, -1, "0", "-1", "1.5", 1.5, "abc", True, None]:
            with self.subTest(max_turns=bad):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    (root / "tasks.json").write_text(json.dumps([
                        {"id": "t01", "prompt": "x", "max_turns": bad}
                    ]))
                    (root / "variants.json").write_text(json.dumps([
                        {"name": "baseline", "extra_args": []}
                    ]))
                    proc = subprocess.run(
                        [sys.executable, str(KIT_DIR / "benchmark_runner.py"),
                         "--tasks", str(root / "tasks.json"),
                         "--variants", str(root / "variants.json"),
                         "--csv", str(root / "results.csv"),
                         "--dry-run"],
                        text=True, capture_output=True,
                    )
                    self.assertNotEqual(proc.returncode, 0,
                                        f"max_turns={bad!r} 는 거부되어야 한다")
                    self.assertIn("max_turns", proc.stderr)

    def test_runner_validates_allowed_tools_schema(self):
        """allowed_tools 는 문자열 리스트여야 하며 문자열 한 글자씩 분해되면 안 된다."""
        cases = [
            "Bash(cat *)",
            ["Bash(cat *)", 123],
            ["Bash(cat *)", ""],
            None,
        ]
        for bad in cases:
            with self.subTest(allowed_tools=bad):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    (root / "tasks.json").write_text(json.dumps([
                        {"id": "t01", "prompt": "x", "max_turns": 1, "allowed_tools": bad}
                    ]))
                    (root / "variants.json").write_text(json.dumps([
                        {"name": "baseline", "extra_args": []}
                    ]))
                    proc = subprocess.run(
                        [sys.executable, str(KIT_DIR / "benchmark_runner.py"),
                         "--tasks", str(root / "tasks.json"),
                         "--variants", str(root / "variants.json"),
                         "--csv", str(root / "results.csv"),
                         "--dry-run"],
                        text=True, capture_output=True,
                    )
                    self.assertNotEqual(proc.returncode, 0)
                    self.assertIn("allowed_tools", proc.stderr)

    def test_runner_validates_variant_extra_args_schema(self):
        """extra_args 는 문자열 리스트여야 하며 문자열/숫자 coercion 으로 CLI argv 가 변형되면 안 된다."""
        cases = [
            "--strict-mcp-config",
            ["--strict-mcp-config", 123],
            ["--strict-mcp-config", ""],
            ["--output-format", "text"],
            None,
        ]
        for bad in cases:
            with self.subTest(extra_args=bad):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    (root / "tasks.json").write_text(json.dumps([
                        {"id": "t01", "prompt": "x", "max_turns": 1}
                    ]))
                    (root / "variants.json").write_text(json.dumps([
                        {"name": "baseline", "extra_args": bad}
                    ]))
                    proc = subprocess.run(
                        [sys.executable, str(KIT_DIR / "benchmark_runner.py"),
                         "--tasks", str(root / "tasks.json"),
                         "--variants", str(root / "variants.json"),
                         "--csv", str(root / "results.csv"),
                         "--dry-run"],
                        text=True, capture_output=True,
                    )
                    self.assertNotEqual(proc.returncode, 0)
                    self.assertIn("extra_args", proc.stderr)

    def test_runner_rejects_success_cwd_that_escapes_project_root(self):
        """success_cwd 가 project_root 밖으로 escape 하면 success=false 로 거부한다."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            outside = root / "outside"
            outside.mkdir()
            fake = _make_fake_claude(project, usage={"input_tokens": 1})
            (project / "tasks.json").write_text(json.dumps([
                {"id": "t01", "prompt": "x", "max_turns": 1,
                 "success_command": "true", "success_cwd": "../outside"}
            ]))
            (project / "variants.json").write_text(json.dumps([
                {"name": "baseline", "extra_args": []}
            ]))
            csv_path = project / "results.csv"
            subprocess.run(
                [sys.executable, str(KIT_DIR / "benchmark_runner.py"),
                 "--tasks", str(project / "tasks.json"),
                 "--variants", str(project / "variants.json"),
                 "--csv", str(csv_path),
                 "--claude-bin", str(fake),
                 "--project-root", str(project)],
                text=True, capture_output=True, check=True,
            )
            with csv_path.open(encoding="utf-8") as f:
                row = next(csv.DictReader(f))
            self.assertEqual(row["success"], "false")
            self.assertIn("escapes project_root", row["notes"])

    def test_collect_usage_does_not_double_count_top_level_and_nested(self):
        """top-level usage 와 nested message.usage 가 동시에 있는 응답에서 중복 합산되지 않는다.

        BFS 로 walk 하며 각 token bucket 의 첫 매칭만 채택하므로 top-level 값이 사용된다.
        """
        module = load_module_from_path(KIT_DIR / "benchmark_runner.py", "_bench_runner_test_load")
        payload = {
            "usage": {
                "input_tokens": 100,
                "output_tokens": 30,
                "cache_read_input_tokens": 800,
                "cache_creation_input_tokens": 50,
            },
            "total_cost_usd": 0.05,
            "messages": [
                {"usage": {
                    "input_tokens": 9_000,  # nested duplicate; must NOT be added
                    "output_tokens": 9_000,
                    "cache_read_input_tokens": 9_000,
                    "cache_creation_input_tokens": 9_000,
                }, "cost_usd": 9.0},
            ],
        }
        tokens, cost, cost_measured, primary_tokens_measured = module.collect_usage(payload)
        self.assertEqual(tokens["input_tokens"], 100)
        self.assertEqual(tokens["output_tokens"], 30)
        self.assertEqual(tokens["cache_read"], 800)
        self.assertEqual(tokens["cache_creation"], 50)
        self.assertAlmostEqual(cost, 0.05, places=6)
        self.assertTrue(cost_measured)
        self.assertTrue(primary_tokens_measured)

    def test_collect_provider_cached_tokens_tracks_openai_prompt_cache_separately(self):
        """OpenAI cached_tokens 는 진단 텔레메트리이며 primary token 합계에 섞지 않는다."""
        module = load_module_from_path(KIT_DIR / "benchmark_runner.py", "_bench_runner_test_provider_cache")
        payload = {
            "usage": {
                "prompt_tokens": 120,
                "completion_tokens": 30,
                "prompt_tokens_details": {"cached_tokens": 64},
            },
            "messages": [
                {"usage": {"prompt_tokens_details": {"cached_tokens": 999}}},
            ],
        }
        tokens, _cost, _cost_measured, primary_tokens_measured = module.collect_usage(payload)
        self.assertEqual(tokens["input_tokens"], 120)
        self.assertEqual(tokens["output_tokens"], 30)
        self.assertEqual(tokens["cache_read"], 0)
        self.assertTrue(primary_tokens_measured)
        self.assertEqual(module.collect_provider_cached_tokens(payload), 64)
        self.assertEqual(module.collect_provider_cache_telemetry(payload), (64, True))
        input_details_payload = {
            "usage": {
                "prompt_tokens": 88,
                "completion_tokens": 12,
                "input_tokens_details": {"cached_tokens": 7},
            },
        }
        self.assertEqual(module.collect_provider_cache_telemetry(input_details_payload), (7, True))

    def test_collect_usage_skips_nonfinite_negative_and_huge_metrics(self):
        """Claude JSON 의 비정상 metric 은 CSV 에 NaN/Infinity/거대값으로 전파되면 안 된다."""
        module = load_module_from_path(KIT_DIR / "benchmark_runner.py", "_bench_runner_test_usage_sanitizer")
        payload = {
            "usage": {
                "input_tokens": float("nan"),
                "output_tokens": -1,
                "cache_read_input_tokens": 10**30,
                "cache_creation_input_tokens": False,
            },
            "total_cost_usd": float("inf"),
            "messages": [
                {
                    "usage": {
                        "input_tokens": 7,
                        "output_tokens": 3,
                        "cache_read_input_tokens": 2,
                        "cache_creation_input_tokens": 1,
                    },
                    "cost_usd": 0.25,
                }
            ],
        }
        tokens, cost, cost_measured, primary_tokens_measured = module.collect_usage(payload)
        self.assertEqual(tokens["input_tokens"], 7)
        self.assertEqual(tokens["output_tokens"], 3)
        self.assertEqual(tokens["cache_read"], 2)
        self.assertEqual(tokens["cache_creation"], 1)
        self.assertAlmostEqual(cost, 0.25, places=6)
        self.assertTrue(cost_measured)
        self.assertTrue(primary_tokens_measured)

    def test_collect_usage_leaves_missing_or_all_invalid_metrics_zero(self):
        """모든 metric 후보가 비정상이면 safe zero 로 남겨 CSV 직렬화를 안정화한다."""
        module = load_module_from_path(KIT_DIR / "benchmark_runner.py", "_bench_runner_test_usage_zero")
        payload = {
            "usage": {
                "input_tokens": True,
                "output_tokens": float("-inf"),
            },
            "cost_usd": -5,
        }
        tokens, cost, cost_measured, primary_tokens_measured = module.collect_usage(payload)
        self.assertEqual(tokens, {
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_read": 0,
            "cache_creation": 0,
        })
        self.assertEqual(cost, 0.0)
        self.assertFalse(cost_measured)
        self.assertFalse(primary_tokens_measured)

    def test_collect_usage_requires_core_input_and_output_token_buckets(self):
        """부분 token bucket 만 있으면 savings 근거로 쓰지 않는다."""
        module = load_module_from_path(KIT_DIR / "benchmark_runner.py", "_bench_runner_test_usage_partial")
        partial_payloads = [
            {"usage": {"completion_tokens": 100}},
            {"usage": {"prompt_tokens": 100}},
            {"usage": {"cache_read_input_tokens": 100}},
        ]
        for payload in partial_payloads:
            with self.subTest(payload=payload):
                tokens, _cost, _cost_measured, primary_tokens_measured = module.collect_usage(payload)
                self.assertFalse(primary_tokens_measured)
                self.assertEqual(
                    tokens["input_tokens"] + tokens["output_tokens"] + tokens["cache_read"] + tokens["cache_creation"],
                    100,
                )

        tokens, _cost, _cost_measured, primary_tokens_measured = module.collect_usage(
            {"usage": {"prompt_tokens": 100, "completion_tokens": 25}}
        )
        self.assertTrue(primary_tokens_measured)
        self.assertEqual(tokens["input_tokens"], 100)
        self.assertEqual(tokens["output_tokens"], 25)


class StatuslineMergedWrapperTests(unittest.TestCase):
    """결합 wrapper 의 4 분기 출력 시나리오 검증.

    OMC HUD 와 context-guard-statusline 의 존재 조합에 따라 출력이 달라진다:
      - 둘 다 있음: OMC HUD 라인 뒤에 cost/cache 만 추출해 결합
      - OMC 만:    OMC HUD 단독
      - token 만:  token-statusline 단독
      - 둘 다 없음: 진단 메시지
    """

    SAMPLE_PAYLOAD = json.dumps({
        "model": {"display_name": "Opus 4.7", "id": "claude-opus-4-7"},
        "workspace": {"current_dir": "/tmp/wrapper-test"},
        "context_window": {"used_percentage": 47},
        "cost": {"total_cost_usd": 0.123},
        "transcript_path": "",
        "session_id": "wrapper-test",
    })

    def _run_wrapper(self, *, omc_script: Path | None, tok_bin: Path | None) -> str:
        """Run the merged wrapper with explicit OMC HUD and token-statusline overrides."""
        env = os.environ.copy()
        # 항상 명시적으로 set/unset 하여 실제 사용자 머신의 OMC HUD가 끼어들지 않도록 한다.
        if omc_script is None:
            env["OMC_HUD_SCRIPT"] = "/nonexistent/__missing_omc_hud__.mjs"
        else:
            env["OMC_HUD_SCRIPT"] = str(omc_script)
        if tok_bin is None:
            # PATH에서 실제 context-guard-statusline 도 못 찾도록 PATH 를 비운다.
            # node 는 OMC HUD 실행에 필요하므로 시스템 경로는 유지.
            env["CLAUDE_TOKEN_STATUSLINE_BIN"] = "/nonexistent/__missing_token_statusline__"
        else:
            env["CLAUDE_TOKEN_STATUSLINE_BIN"] = str(tok_bin)
        proc = subprocess.run(
            ["bash", str(KIT_DIR / "statusline_merged.sh")],
            input=self.SAMPLE_PAYLOAD,
            text=True,
            capture_output=True,
            env=env,
            check=True,
        )
        return proc.stdout.rstrip("\n")

    def _make_fake_omc_hud(self, tmp: Path, line: str) -> Path:
        """tmp/omc-hud.mjs 를 생성: stdin 을 무시하고 line 한 줄을 stdout 으로 흘린다."""
        path = tmp / "omc-hud.mjs"
        # node 가 stdin 을 읽지 않으면 wrapper 의 printf "$input" | node ... 에서
        # EPIPE 가 날 수 있으므로 명시적으로 stdin 을 drain 한 뒤 출력한다.
        path.write_text(
            "process.stdin.resume();\n"
            "process.stdin.on('data', () => {});\n"
            "process.stdin.on('end', () => {\n"
            f"  process.stdout.write({json.dumps(line)});\n"
            "});\n",
            encoding="utf-8",
        )
        return path

    def _make_fake_token_statusline(self, tmp: Path, line: str) -> Path:
        """tmp/fake-token-statusline 을 생성: stdin 을 무시하고 line 한 줄을 출력한다."""
        path = tmp / "fake-token-statusline"
        path.write_text(
            "#!/usr/bin/env bash\n"
            "cat >/dev/null\n"
            f"printf '%s\\n' {shlex.quote(line)}\n",
            encoding="utf-8",
        )
        os.chmod(path, stat.S_IRWXU)
        return path

    def test_merges_omc_hud_with_cost_and_cache_when_both_available(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            omc = self._make_fake_omc_hud(tmp, "[OMC#test] | 5h:10% | session:5m | ctx:47%")
            tok = self._make_fake_token_statusline(
                tmp,
                "[Opus 4.7] dir | main | ctx 47% | cost $0.123 | cache 27% | reuse 4.0x",
            )
            out = self._run_wrapper(omc_script=omc, tok_bin=tok)
        # OMC HUD 라인이 그대로 보존되고 compact token extras 만 뒤에 붙는다.
        self.assertTrue(out.startswith("[OMC#test] | 5h:10% | session:5m | ctx:47%"), out)
        self.assertIn(" | cost $0.123", out)
        self.assertIn(" | cache 27%", out)
        self.assertIn(" | reuse 4.0x", out)
        # token 출력의 model/dir/branch/ctx 는 OMC HUD 와 중복이라 결합 시 제거되어야 한다.
        self.assertNotIn("[Opus 4.7]", out)
        self.assertNotIn(" | main ", out)

    def test_omc_hud_alone_when_token_statusline_unavailable(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            omc = self._make_fake_omc_hud(tmp, "[OMC#test] | session:9m | ctx:33%")
            out = self._run_wrapper(omc_script=omc, tok_bin=None)
        self.assertEqual(out, "[OMC#test] | session:9m | ctx:33%")

    def test_token_statusline_alone_when_omc_hud_unavailable(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            tok = self._make_fake_token_statusline(
                tmp,
                "[Opus 4.7] dir | main | ctx 47% | cost $0.001 | cache 5%",
            )
            out = self._run_wrapper(omc_script=None, tok_bin=tok)
        # OMC HUD 가 없으면 token-statusline 출력이 그대로 (cost/cache 추출하지 않고 원본).
        self.assertEqual(out, "[Opus 4.7] dir | main | ctx 47% | cost $0.001 | cache 5%")

    def test_diagnostic_fallback_when_neither_available(self):
        out = self._run_wrapper(omc_script=None, tok_bin=None)
        self.assertEqual(out, "[hud unavailable]")

    def test_workspace_plugin_statusline_is_not_executed_as_fallback(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            wrapper = tmp / "statusline_merged.sh"
            wrapper.write_bytes((KIT_DIR / "statusline_merged.sh").read_bytes())
            os.chmod(wrapper, stat.S_IRWXU)
            workspace_bin = tmp / "workspace" / "plugins" / "context-guard" / "bin"
            workspace_bin.mkdir(parents=True)
            evil = workspace_bin / "context-guard-statusline"
            marker = tmp / "executed"
            evil.write_text(f"#!/usr/bin/env bash\ntouch {shlex.quote(str(marker))}\necho evil\n", encoding="utf-8")
            os.chmod(evil, stat.S_IRWXU)
            env = os.environ.copy()
            env["OMC_HUD_SCRIPT"] = str(tmp / "missing-omc.mjs")
            env["PATH"] = "/usr/bin:/bin:/opt/homebrew/bin"
            env.pop("CLAUDE_TOKEN_STATUSLINE_BIN", None)
            payload = json.dumps({"workspace": {"current_dir": str(tmp / "workspace")}})
            proc = subprocess.run(
                ["bash", str(wrapper)],
                input=payload,
                text=True,
                capture_output=True,
                env=env,
                check=True,
            )
            self.assertEqual(proc.stdout.strip(), "[hud unavailable]")
            self.assertFalse(marker.exists())

    def test_path_statusline_is_not_executed_as_fallback(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            wrapper = tmp / "statusline_merged.sh"
            wrapper.write_bytes((KIT_DIR / "statusline_merged.sh").read_bytes())
            os.chmod(wrapper, stat.S_IRWXU)
            path_bin = tmp / "path-bin"
            path_bin.mkdir()
            evil = path_bin / "context-guard-statusline"
            marker = tmp / "path-executed"
            evil.write_text(f"#!/usr/bin/env bash\ntouch {shlex.quote(str(marker))}\necho evil\n", encoding="utf-8")
            os.chmod(evil, stat.S_IRWXU)
            env = os.environ.copy()
            env["OMC_HUD_SCRIPT"] = str(tmp / "missing-omc.mjs")
            env["PATH"] = f"{path_bin}:/usr/bin:/bin:/opt/homebrew/bin"
            env.pop("CLAUDE_TOKEN_STATUSLINE_BIN", None)
            proc = subprocess.run(
                ["bash", str(wrapper)],
                input=self.SAMPLE_PAYLOAD,
                text=True,
                capture_output=True,
                env=env,
                check=True,
            )
            self.assertEqual(proc.stdout.strip(), "[hud unavailable]")
            self.assertFalse(marker.exists())

    def test_statusline_output_is_single_bounded_line(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            omc = self._make_fake_omc_hud(tmp, "[OMC]\n\x1b[31mred\x1b[0m")
            tok = self._make_fake_token_statusline(
                tmp,
                "[Opus]\nbranch | cost $0.123 | cache 42% | reuse 2.5x",
            )
            out = self._run_wrapper(omc_script=omc, tok_bin=tok)
        self.assertNotIn("\n", out)
        self.assertNotIn("\x1b", out)
        self.assertLessEqual(len(out), 1000 + len(" | cost $0.123 | cache 42% | reuse 2.5x"))
        self.assertIn("[OMC] red", out)
        self.assertIn(" | cost $0.123", out)
        self.assertIn(" | cache 42%", out)
        self.assertIn(" | reuse 2.5x", out)

    def test_relative_missing_tmpdir_does_not_block_wrapper_input(self):
        for script in [KIT_DIR / "statusline_merged.sh", PLUGIN_BIN / "context-guard-statusline-merged"]:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as td:
                    tmp = Path(td)
                    for tmpdir in ("relative-missing-tmp", "/", "//"):
                        with self.subTest(tmpdir=tmpdir):
                            env = os.environ.copy()
                            env["OMC_HUD_SCRIPT"] = str(tmp / "missing-omc.mjs")
                            env["CLAUDE_TOKEN_STATUSLINE_BIN"] = str(tmp / "missing-token-statusline")
                            env["TMPDIR"] = tmpdir
                            proc = subprocess.run(
                                ["bash", str(script)],
                                input=self.SAMPLE_PAYLOAD,
                                text=True,
                                capture_output=True,
                                env=env,
                                cwd=tmp,
                                check=True,
                            )
                            self.assertEqual(proc.stdout.strip(), "[hud unavailable]")
                            self.assertFalse((tmp / "relative-missing-tmp").exists())

    def test_rejects_oversized_stdin_without_invoking_helpers(self):
        for script in [KIT_DIR / "statusline_merged.sh", PLUGIN_BIN / "context-guard-statusline-merged"]:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as td:
                    tmp = Path(td)
                    omc_marker = tmp / "omc-executed"
                    tok_marker = tmp / "token-executed"
                    omc = tmp / "omc-hud.mjs"
                    omc.write_text(
                        f"require('fs').writeFileSync({json.dumps(str(omc_marker))}, 'ran');\n"
                        "process.stdin.resume();\n",
                        encoding="utf-8",
                    )
                    tok = tmp / "fake-token-statusline"
                    tok.write_text(
                        "#!/usr/bin/env bash\n"
                        f"touch {shlex.quote(str(tok_marker))}\n"
                        "cat >/dev/null\n"
                        "echo token\n",
                        encoding="utf-8",
                    )
                    os.chmod(tok, stat.S_IRWXU)
                    env = os.environ.copy()
                    env["OMC_HUD_SCRIPT"] = str(omc)
                    env["CLAUDE_TOKEN_STATUSLINE_BIN"] = str(tok)
                    env["CLAUDE_TOKEN_STATUSLINE_INPUT_MAX_BYTES"] = "32"
                    proc = subprocess.run(
                        ["bash", str(script)],
                        input="{" + ("x" * 128),
                        text=True,
                        capture_output=True,
                        env=env,
                        check=True,
                    )
                    self.assertIn("[input-too-large]", proc.stdout)
                    self.assertFalse(omc_marker.exists())
                    self.assertFalse(tok_marker.exists())

    def test_rejects_trailing_newline_oversize_without_invoking_helpers(self):
        for script in [KIT_DIR / "statusline_merged.sh", PLUGIN_BIN / "context-guard-statusline-merged"]:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as td:
                    tmp = Path(td)
                    tok_marker = tmp / "token-executed"
                    tok = tmp / "fake-token-statusline"
                    tok.write_text(
                        "#!/usr/bin/env bash\n"
                        f"touch {shlex.quote(str(tok_marker))}\n"
                        "cat >/dev/null\n"
                        "echo token\n",
                        encoding="utf-8",
                    )
                    os.chmod(tok, stat.S_IRWXU)
                    env = os.environ.copy()
                    env["OMC_HUD_SCRIPT"] = "/nonexistent/__missing_omc_hud__.mjs"
                    env["CLAUDE_TOKEN_STATUSLINE_BIN"] = str(tok)
                    env["CLAUDE_TOKEN_STATUSLINE_INPUT_MAX_BYTES"] = "32"
                    proc = subprocess.run(
                        ["bash", str(script)],
                        input=("x" * 32) + "\n",
                        text=True,
                        capture_output=True,
                        env=env,
                        check=True,
                    )
                    self.assertIn("[input-too-large]", proc.stdout)
                    self.assertFalse(tok_marker.exists())


class CrossAgentAdapterTests(unittest.TestCase):
    """Fixture tests for the cross-agent adapter registry and dry-run planner."""

    def _run(self, script: Path, root: Path, extra: list[str]) -> dict:
        proc = subprocess.run(
            [sys.executable, str(script), "--root", str(root), "--json", *extra],
            text=True,
            capture_output=True,
            check=True,
        )
        return json.loads(proc.stdout)

    def test_list_adapters_reports_expanded_registry_and_capability_classes(self):
        expected = {
            "claude": "native-plugin",
            "codex": "repo-rule",
            "gemini": "repo-rule",
            "cursor": "repo-rule",
            "windsurf": "repo-rule",
            "cline": "repo-rule",
            "copilot": "repo-rule",
            "opencode": "native-skill",
            "forgecode": "report-only",
            "generic": "report-only",
        }
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                proc = subprocess.run(
                    [sys.executable, str(script), "--list-adapters", "--json"],
                    text=True,
                    capture_output=True,
                    check=True,
                )
                data = json.loads(proc.stdout)
                adapters = {adapter["key"]: adapter for adapter in data["adapters"]}
                for key, capability in expected.items():
                    self.assertIn(key, adapters)
                    self.assertEqual(adapters[key]["capability"], capability)
                self.assertEqual(
                    {adapter["capability"] for adapter in adapters.values()},
                    {"native-plugin", "native-skill", "repo-rule", "report-only"},
                )

    def test_default_plan_preserves_claude_only_compatibility(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    data = self._run(script, root, ["--plan"])
                    self.assertFalse(data["applied"])
                    self.assertTrue(data["changed"])
                    plan = data["adapter_plan"]
                    self.assertEqual([entry["key"] for entry in plan], ["claude"])
                    self.assertEqual(plan[0]["capability"], "native-plugin")
                    self.assertFalse((root / ".claude" / "settings.json").exists())

    def test_only_codex_with_init_writes_idempotent_repo_rule_without_touching_claude(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    data = self._run(script, root, ["--only", "codex", "--with-init", "--yes", "--no-diet-scan"])
                    self.assertTrue(data["applied"])
                    self.assertFalse(data["changed"])  # Claude settings untouched.
                    entry = data["adapter_plan"][0]
                    self.assertEqual(entry["key"], "codex")
                    self.assertEqual(entry["status"], "applied")
                    agents_md = root / "AGENTS.md"
                    self.assertTrue(agents_md.is_file())
                    self.assertFalse((root / ".claude").exists())
                    text = agents_md.read_text(encoding="utf-8")
                    self.assertEqual(text.count("<!-- contextguard:begin -->"), 1)
                    self.assertIn("do not guarantee", text.lower())

                    again = self._run(script, root, ["--only", "codex", "--with-init", "--yes", "--no-diet-scan"])
                    self.assertEqual(again["adapter_plan"][0]["status"], "exists")
                    self.assertEqual(again["actions"], [])
                    self.assertEqual(
                        agents_md.read_text(encoding="utf-8").count("<!-- contextguard:begin -->"),
                        1,
                    )

    def test_codex_with_skill_generates_project_skill_idempotently(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    data = self._run(
                        script,
                        root,
                        ["--agent", "codex", "--with-init", "--with-skill", "--yes", "--no-diet-scan"],
                    )
                    entry = data["adapter_plan"][0]
                    self.assertEqual(entry["key"], "codex")
                    self.assertEqual(entry["status"], "applied")
                    self.assertEqual(entry["project_skill_file"], ".agents/skills/context-guard/SKILL.md")
                    self.assertEqual(entry["project_skill_status"], "applied")
                    skill = root / ".agents" / "skills" / "context-guard" / "SKILL.md"
                    self.assertTrue(skill.is_file())
                    text = skill.read_text(encoding="utf-8")
                    self.assertIn("name: context-guard", text)
                    self.assertIn("description:", text)
                    self.assertIn("contextguard:codex-skill:begin", text)
                    self.assertIn("context-guard setup --agent codex --scope project", text)
                    self.assertIn("Do not claim fixed token or cost savings", text)
                    self.assertTrue((root / "AGENTS.md").is_file())
                    self.assertFalse((root / ".claude").exists())

                    again = self._run(
                        script,
                        root,
                        ["--agent", "codex", "--with-init", "--with-skill", "--yes", "--no-diet-scan"],
                    )
                    again_entry = again["adapter_plan"][0]
                    self.assertEqual(again_entry["status"], "exists")
                    self.assertEqual(again_entry["project_skill_status"], "exists")
                    self.assertEqual(again["actions"], [])

    def test_codex_skill_plan_is_read_only_and_foreign_skill_is_not_overwritten(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    planned = self._run(script, root, ["--agent", "codex", "--with-skill", "--plan"])
                    self.assertEqual(planned["adapter_plan"][0]["project_skill_status"], "missing")
                    self.assertFalse((root / ".agents" / "skills" / "context-guard" / "SKILL.md").exists())

                    skill = root / ".agents" / "skills" / "context-guard" / "SKILL.md"
                    skill.parent.mkdir(parents=True)
                    skill.write_text("# user skill\n", encoding="utf-8")
                    applied = self._run(
                        script,
                        root,
                        ["--agent", "codex", "--with-skill", "--yes", "--no-diet-scan"],
                    )
                    entry = applied["adapter_plan"][0]
                    self.assertEqual(entry["project_skill_status"], "skipped")
                    self.assertIn("refused to overwrite", "\n".join(entry["planned_actions"]))
                    self.assertEqual(skill.read_text(encoding="utf-8"), "# user skill\n")

    def test_codex_setup_skips_unreadable_rule_and_skill_files(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    agents = root / "AGENTS.md"
                    agents.write_text("Existing private rules.\n", encoding="utf-8")
                    skill = root / ".agents" / "skills" / "context-guard" / "SKILL.md"
                    skill.parent.mkdir(parents=True)
                    skill.write_text("# private skill\n", encoding="utf-8")
                    old_agents_mode = stat.S_IMODE(agents.stat().st_mode)
                    old_skill_mode = stat.S_IMODE(skill.stat().st_mode)
                    try:
                        agents.chmod(0)
                        skill.chmod(0)
                        data = self._run(
                            script,
                            root,
                            ["--agent", "codex", "--with-init", "--with-skill", "--yes", "--no-diet-scan"],
                        )
                    finally:
                        agents.chmod(old_agents_mode)
                        skill.chmod(old_skill_mode)
                    entry = data["adapter_plan"][0]
                    self.assertEqual(entry["status"], "skipped")
                    self.assertEqual(entry["project_skill_status"], "unsafe")
                    self.assertIn("could not read", "\n".join(entry["planned_actions"]))
                    self.assertEqual(agents.read_text(encoding="utf-8"), "Existing private rules.\n")
                    self.assertEqual(skill.read_text(encoding="utf-8"), "# private skill\n")

    def test_codex_setup_skips_broken_symlink_rule_and_skill_files(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    try:
                        (root / "AGENTS.md").symlink_to(root / "missing-rules.md")
                        skill = root / ".agents" / "skills" / "context-guard" / "SKILL.md"
                        skill.parent.mkdir(parents=True)
                        skill.symlink_to(root / "missing-skill.md")
                    except (OSError, NotImplementedError):
                        self.skipTest("symlink creation unsupported on this filesystem")
                    data = self._run(
                        script,
                        root,
                        ["--agent", "codex", "--with-init", "--with-skill", "--yes", "--no-diet-scan"],
                    )
                    entry = data["adapter_plan"][0]
                    self.assertEqual(entry["status"], "skipped")
                    self.assertEqual(entry["project_skill_status"], "unsafe")
                    self.assertTrue((root / "AGENTS.md").is_symlink())
                    self.assertTrue((root / ".agents" / "skills" / "context-guard" / "SKILL.md").is_symlink())

    def test_with_init_dry_run_does_not_write_rule_file(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    data = self._run(script, root, ["--only", "codex", "--with-init", "--plan"])
                    self.assertEqual(data["adapter_plan"][0]["status"], "planned")
                    self.assertFalse((root / "AGENTS.md").exists())

    def test_with_init_existing_rule_backs_up_even_with_no_backup(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    agents = root / "AGENTS.md"
                    original = "Existing Codex rules.\n"
                    agents.write_text(original, encoding="utf-8")
                    data = self._run(
                        script,
                        root,
                        ["--only", "codex", "--with-init", "--yes", "--no-backup", "--no-diet-scan"],
                    )
                    entry = data["adapter_plan"][0]
                    backup_path = Path(entry["rule_backup_path"])
                    self.assertTrue(data["applied"])
                    self.assertEqual(entry["status"], "applied")
                    self.assertTrue(backup_path.is_file())
                    self.assertEqual(backup_path.read_text(encoding="utf-8"), original)
                    self.assertEqual(len(list(root.glob("AGENTS.md.bak-*"))), 1)
                    self.assertIn("<!-- contextguard:begin -->", agents.read_text(encoding="utf-8"))

    def test_with_init_uncertain_atomic_write_still_reports_backup_path(self):
        for index, script in enumerate(SETUP_SCRIPTS):
            with self.subTest(script=script):
                setup = load_python_script_module(script, f"setup_uncertain_rule_init_{index}")
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp).resolve()
                    agents = root / "AGENTS.md"
                    original = "Existing Codex rules.\n"
                    agents.write_text(original, encoding="utf-8")
                    real_atomic_write = setup.atomic_write

                    def uncertain_target_write(path: Path, text: str, mode: int = 0o600, *, dir_mode: int = setup.PRIVATE_DIR_MODE) -> None:
                        real_atomic_write(path, text, mode, dir_mode=dir_mode)
                        if Path(path) == agents:
                            raise setup.AtomicWriteDurabilityError(
                                f"write committed but parent directory durability is uncertain: {path}"
                            )

                    setup.atomic_write = uncertain_target_write
                    try:
                        plan = setup.build_adapter_plan(
                            root,
                            [setup.adapter_registry()["codex"]],
                            scope="project",
                            claude_actions=[],
                            claude_changed=False,
                            claude_applied=False,
                            with_init=True,
                            with_skill=False,
                            applied=True,
                        )
                    finally:
                        setup.atomic_write = real_atomic_write

                    entry = plan[0]
                    backup_path = Path(entry["rule_backup_path"])
                    self.assertEqual(entry["status"], "applied-durability-uncertain")
                    self.assertTrue(backup_path.is_file())
                    self.assertEqual(backup_path.read_text(encoding="utf-8"), original)
                    self.assertIn("durability is uncertain", "\n".join(entry["planned_actions"]))
                    self.assertIn("<!-- contextguard:begin -->", agents.read_text(encoding="utf-8"))

    def test_agent_alias_and_project_scope_keep_setup_project_local(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp) / "project"
                    home = Path(tmp) / "home"
                    root.mkdir()
                    home.mkdir()
                    env = os.environ.copy()
                    env["HOME"] = str(home)
                    proc = subprocess.run(
                        [
                            sys.executable,
                            str(script),
                            "--root",
                            str(root),
                            "--scope",
                            "project",
                            "--agent",
                            "codex",
                            "--with-init",
                            "--plan",
                            "--json",
                        ],
                        text=True,
                        capture_output=True,
                        env=env,
                        check=True,
                    )
                    data = json.loads(proc.stdout)
                    self.assertEqual(data["scope"], "project")
                    self.assertEqual(data["root"], str(root.resolve()))
                    self.assertEqual([entry["key"] for entry in data["adapter_plan"]], ["codex"])
                    self.assertEqual(data["adapter_plan"][0]["scope"], "project")
                    self.assertFalse((home / ".claude" / "settings.json").exists())
                    self.assertFalse((root / "AGENTS.md").exists())

    def test_codex_only_setup_ignores_malformed_or_symlinked_claude_settings(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    claude_settings = root / ".claude" / "settings.json"
                    claude_settings.parent.mkdir()
                    claude_settings.write_text("{", encoding="utf-8")
                    data = self._run(script, root, ["--agent", "codex", "--with-init", "--plan"])
                    self.assertEqual(data["adapter_plan"][0]["key"], "codex")
                    self.assertFalse(data["applied"])

                    claude_settings.unlink()
                    try:
                        claude_settings.symlink_to(root / "outside-settings.json")
                    except (OSError, NotImplementedError):
                        self.skipTest("symlink creation unsupported on this filesystem")
                    data = self._run(script, root, ["--agent", "codex", "--with-init", "--plan"])
                    self.assertEqual(data["adapter_plan"][0]["key"], "codex")
                    self.assertFalse(data["applied"])

    def test_user_scope_rejects_apply_without_explicit_agent(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    home = Path(tmp) / "home"
                    home.mkdir()
                    env = os.environ.copy()
                    env["HOME"] = str(home)
                    proc = subprocess.run(
                        [sys.executable, str(script), "--scope", "user", "--yes", "--json"],
                        text=True,
                        capture_output=True,
                        env=env,
                    )
                    self.assertNotEqual(proc.returncode, 0)
                    self.assertIn("explicit agent", proc.stderr)
                    self.assertFalse((home / ".claude" / "settings.json").exists())
                    self.assertFalse((home / ".context-guard").exists())

    def test_user_scope_claude_writes_home_settings_with_rollback_record(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    home = Path(tmp) / "home"
                    home.mkdir()
                    settings = home / ".claude" / "settings.json"
                    settings.parent.mkdir()
                    settings.write_text(json.dumps({"permissions": {"deny": ["Read(./custom/**)"]}}), encoding="utf-8")
                    os.chmod(settings, 0o600)
                    env = os.environ.copy()
                    env["HOME"] = str(home)
                    proc = subprocess.run(
                        [
                            sys.executable,
                            str(script),
                            "--scope",
                            "user",
                            "--agent",
                            "claude",
                            "--yes",
                            "--no-diet-scan",
                            "--json",
                        ],
                        text=True,
                        capture_output=True,
                        env=env,
                        check=True,
                    )
                    data = json.loads(proc.stdout)
                    self.assertTrue(data["applied"])
                    self.assertEqual(data["scope"], "user")
                    self.assertEqual(data["root"], str(home.resolve()))
                    self.assertEqual(data["settings_path"], str(settings.resolve()))
                    self.assertTrue(data["backup_path"])
                    self.assertTrue(Path(data["backup_path"]).is_file())
                    self.assertTrue(data["rollback_id"])
                    rollback_path = Path(data["rollback_path"])
                    self.assertTrue(rollback_path.is_file())
                    rollback = json.loads(rollback_path.read_text(encoding="utf-8"))
                    self.assertEqual(rollback["schema_version"], "contextguard.rollback.v1")
                    self.assertEqual(rollback["target_path"], str(settings.resolve()))
                    self.assertEqual(rollback["backup_path"], data["backup_path"])
                    self.assertTrue(rollback["restore_requires_no_follow"])
                    self.assertIn("no-follow", rollback["restore"])
                    self.assertIn("atomically replaces", rollback["restore"])
                    self.assertIn(str(settings.resolve()), rollback["restore"])
                    self.assertIn("generic shell copy/delete commands", rollback["restore"])
                    self.assertNotIn("cp ", rollback["restore"])
                    self.assertNotIn("rm -f", rollback["restore"])
                    self.assertNotIn("cp/rm", rollback["restore"])
                    self.assertIn("--yes and explicit --agent", " ".join(data["warnings"]))
                    self.assertIn("Read(./custom/**)", json.loads(settings.read_text(encoding="utf-8"))["permissions"]["deny"])

    def test_npm_publish_workflow_dispatch_verifies_release_tag_and_sha(self):
        workflow = (ROOT / ".github" / "workflows" / "npm-publish.yml").read_text(encoding="utf-8")
        self.assertIn("release_sha:", workflow)
        self.assertIn("Expected 40-character commit SHA", workflow)
        self.assertIn("EXPECTED_RELEASE_SHA", workflow)
        self.assertIn("workflow_dispatch requires release_sha to be a 40-character commit SHA", workflow)
        self.assertIn("git", workflow)
        self.assertIn("ls-remote", workflow)
        self.assertIn("refs/tags/{tag_name}^{{}}", workflow)
        self.assertIn("checked-out HEAD", workflow)
        self.assertIn("origin tag", workflow)
        self.assertIn("https://api.github.com/repos/{repo}/releases/tags/{url_tag}", workflow)
        self.assertIn("published GitHub release not found", workflow)
        self.assertLess(workflow.index("Verify publish target and OIDC toolchain"), workflow.index("Publish npm package with trusted publishing"))

    def test_user_scope_existing_claude_settings_rejects_no_backup(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    home = Path(tmp) / "home"
                    home.mkdir()
                    settings = home / ".claude" / "settings.json"
                    settings.parent.mkdir()
                    settings.write_text("{}", encoding="utf-8")
                    env = os.environ.copy()
                    env["HOME"] = str(home)
                    proc = subprocess.run(
                        [
                            sys.executable,
                            str(script),
                            "--scope",
                            "user",
                            "--agent",
                            "claude",
                            "--yes",
                            "--no-backup",
                            "--json",
                        ],
                        text=True,
                        capture_output=True,
                        env=env,
                    )
                    self.assertNotEqual(proc.returncode, 0)
                    self.assertIn("Refusing --no-backup for user-scope", proc.stderr)
                    self.assertFalse((home / ".context-guard" / "rollback").exists())

    def test_user_scope_rollback_failure_does_not_modify_settings(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    home = Path(tmp) / "home"
                    home.mkdir()
                    settings = home / ".claude" / "settings.json"
                    settings.parent.mkdir()
                    original = {"permissions": {"deny": ["Read(./custom/**)"]}}
                    settings.write_text(json.dumps(original), encoding="utf-8")
                    blocker = home / ".context-guard"
                    blocker.write_text("not a directory\n", encoding="utf-8")
                    env = os.environ.copy()
                    env["HOME"] = str(home)
                    proc = subprocess.run(
                        [
                            sys.executable,
                            str(script),
                            "--scope",
                            "user",
                            "--agent",
                            "claude",
                            "--yes",
                            "--no-diet-scan",
                            "--json",
                        ],
                        text=True,
                        capture_output=True,
                        env=env,
                    )
                    self.assertNotEqual(proc.returncode, 0)
                    self.assertEqual(json.loads(settings.read_text(encoding="utf-8")), original)

    def test_user_scope_non_claude_adapter_is_precise_noop(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    home = Path(tmp) / "home"
                    home.mkdir()
                    env = os.environ.copy()
                    env["HOME"] = str(home)
                    proc = subprocess.run(
                        [
                            sys.executable,
                            str(script),
                            "--scope",
                            "user",
                            "--agent",
                            "codex",
                            "--with-init",
                            "--yes",
                            "--json",
                        ],
                        text=True,
                        capture_output=True,
                        env=env,
                        check=True,
                    )
                    data = json.loads(proc.stdout)
                    self.assertFalse(data["applied"])
                    self.assertTrue(data["apply_requested"])
                    entry = data["adapter_plan"][0]
                    self.assertEqual(entry["key"], "codex")
                    self.assertEqual(entry["scope"], "user")
                    self.assertEqual(entry["status"], "unsupported")
                    self.assertFalse(entry["writable"])
                    self.assertIn("not implemented/verified", entry["unsupported_reason"])
                    self.assertEqual(data["actions"], [])
                    self.assertFalse((home / "AGENTS.md").exists())
                    self.assertFalse((home / ".claude").exists())
                    self.assertFalse((home / ".context-guard").exists())

    def test_codex_project_skill_dirs_are_shared_repo_readable(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    data = self._run(
                        script,
                        root,
                        ["--agent", "codex", "--with-skill", "--yes", "--no-diet-scan"],
                    )
                    self.assertTrue(data["applied"])
                    self.assertEqual(stat.S_IMODE((root / ".agents").stat().st_mode), 0o755)
                    self.assertEqual(stat.S_IMODE((root / ".agents" / "skills").stat().st_mode), 0o755)
                    self.assertEqual(
                        stat.S_IMODE((root / ".agents" / "skills" / "context-guard").stat().st_mode),
                        0o755,
                    )

    def test_codex_root_rule_write_preserves_existing_project_root_mode(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp) / "private-project"
                    root.mkdir()
                    root.chmod(0o700)
                    data = self._run(script, root, ["--agent", "codex", "--with-init", "--yes", "--no-diet-scan"])
                    self.assertTrue(data["applied"])
                    self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
                    self.assertTrue((root / "AGENTS.md").is_file())

    def test_default_plan_detects_repo_rule_agents_present_in_repo(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    (root / "AGENTS.md").write_text("# repo rules\n", encoding="utf-8")
                    (root / ".windsurf").mkdir()
                    data = self._run(script, root, ["--plan"])
                    by_key = {entry["key"]: entry for entry in data["adapter_plan"]}
                    self.assertIn("codex", by_key)
                    self.assertIn("windsurf", by_key)
                    self.assertEqual(by_key["codex"]["capability"], "repo-rule")
                    self.assertEqual(by_key["windsurf"]["capability"], "repo-rule")
                    self.assertTrue(by_key["codex"]["detected"])
                    self.assertTrue(by_key["windsurf"]["detected"])
                    # Without --with-init nothing is written.
                    self.assertNotIn(
                        "<!-- contextguard:begin -->",
                        (root / "AGENTS.md").read_text(encoding="utf-8"),
                    )
                    self.assertFalse((root / ".windsurf" / "rules" / "contextguard.md").exists())

    def test_with_init_writes_nested_repo_rule_file(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    data = self._run(script, root, ["--only", "windsurf", "--with-init", "--yes", "--no-diet-scan"])
                    entry = data["adapter_plan"][0]
                    self.assertEqual(entry["key"], "windsurf")
                    self.assertEqual(entry["status"], "applied")
                    rule_path = root / ".windsurf" / "rules" / "contextguard.md"
                    self.assertTrue(rule_path.is_file())
                    self.assertIn("ContextGuard", rule_path.read_text(encoding="utf-8"))
                    self.assertFalse((root / ".claude").exists())

    def test_cline_existing_file_rule_appends_without_crashing(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    rule_path = root / ".clinerules"
                    rule_path.write_text("Existing Cline rule.\n", encoding="utf-8")
                    data = self._run(script, root, ["--only", "cline", "--with-init", "--yes", "--no-diet-scan"])
                    entry = data["adapter_plan"][0]
                    self.assertEqual(entry["key"], "cline")
                    self.assertEqual(entry["status"], "applied")
                    self.assertEqual(entry["rule_file"], ".clinerules")
                    text = rule_path.read_text(encoding="utf-8")
                    self.assertIn("Existing Cline rule.", text)
                    self.assertEqual(text.count("<!-- contextguard:begin -->"), 1)
                    self.assertFalse((root / ".clinerules" / "contextguard.md").exists())
                    self.assertFalse((root / ".claude").exists())

    def test_cline_existing_directory_rule_writes_nested_file(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    (root / ".clinerules").mkdir()
                    data = self._run(script, root, ["--only", "cline", "--with-init", "--yes", "--no-diet-scan"])
                    entry = data["adapter_plan"][0]
                    self.assertEqual(entry["key"], "cline")
                    self.assertEqual(entry["status"], "applied")
                    self.assertEqual(entry["rule_file"], ".clinerules/contextguard.md")
                    rule_path = root / ".clinerules" / "contextguard.md"
                    self.assertTrue(rule_path.is_file())
                    self.assertIn("ContextGuard", rule_path.read_text(encoding="utf-8"))

    def test_native_skill_and_report_only_adapters_never_write(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    data = self._run(
                        script,
                        root,
                        ["--only", "opencode,forgecode,generic", "--with-init", "--yes", "--no-diet-scan"],
                    )
                    statuses = {entry["key"]: entry["status"] for entry in data["adapter_plan"]}
                    self.assertEqual(statuses["opencode"], "report-only")
                    self.assertEqual(statuses["forgecode"], "report-only")
                    self.assertEqual(statuses["generic"], "report-only")
                    self.assertEqual(data["actions"], [])
                    self.assertFalse((root / ".claude").exists())
                    self.assertEqual(list(root.iterdir()), [])  # nothing written

    def test_brief_mode_plan_is_read_only_and_apply_is_idempotent(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    planned = self._run(script, root, ["--agent", "codex", "--brief-mode", "standard", "--plan"])
                    entry = planned["adapter_plan"][0]
                    self.assertFalse(planned["applied"])
                    self.assertEqual(entry["brief_mode_status"], "planned")
                    self.assertEqual(entry["brief_mode_level"], "standard")
                    self.assertIn("would add advisory brief-mode standard", "\n".join(entry["planned_actions"]))
                    self.assertFalse((root / "AGENTS.md").exists())

                    applied = self._run(
                        script,
                        root,
                        ["--agent", "codex", "--brief-mode", "standard", "--yes", "--no-diet-scan"],
                    )
                    entry = applied["adapter_plan"][0]
                    self.assertTrue(applied["applied"])
                    self.assertEqual(entry["status"], "applied")
                    self.assertEqual(entry["brief_mode_status"], "applied")
                    agents_md = root / "AGENTS.md"
                    text = agents_md.read_text(encoding="utf-8")
                    self.assertEqual(text.count("<!-- BEGIN context-guard:brief-mode level=standard version=1 -->"), 1)
                    self.assertIn("does not promise", text)
                    self.assertIn("Always preserve this evidence", text)
                    self.assertFalse((root / ".claude").exists())

                    again = self._run(
                        script,
                        root,
                        ["--agent", "codex", "--brief-mode", "standard", "--yes", "--no-diet-scan"],
                    )
                    again_entry = again["adapter_plan"][0]
                    self.assertFalse(again["applied"])
                    self.assertEqual(again_entry["brief_mode_status"], "exists")
                    self.assertEqual(again["actions"], [])
                    self.assertEqual(agents_md.read_text(encoding="utf-8").count("<!-- BEGIN context-guard:brief-mode"), 1)

    def test_brief_mode_replaces_and_removes_without_stacking(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    agents_md = root / "AGENTS.md"
                    agents_md.write_text("User rules.\n", encoding="utf-8")
                    self._run(script, root, ["--agent", "codex", "--brief-mode", "standard", "--yes", "--no-diet-scan"])
                    replaced = self._run(
                        script,
                        root,
                        ["--agent", "codex", "--brief-mode", "ultra", "--yes", "--no-diet-scan"],
                    )
                    entry = replaced["adapter_plan"][0]
                    text = agents_md.read_text(encoding="utf-8")
                    self.assertEqual(entry["brief_mode_status"], "replaced")
                    self.assertTrue(entry["brief_mode_backup_path"])
                    self.assertEqual(text.count("<!-- BEGIN context-guard:brief-mode"), 1)
                    self.assertIn("level=ultra", text)
                    self.assertNotIn("level=standard", text)
                    self.assertIn("User rules.", text)

                    removed = self._run(
                        script,
                        root,
                        ["--agent", "codex", "--brief-mode", "off", "--yes", "--no-diet-scan"],
                    )
                    removed_entry = removed["adapter_plan"][0]
                    text = agents_md.read_text(encoding="utf-8")
                    self.assertEqual(removed_entry["brief_mode_status"], "removed")
                    self.assertNotIn("<!-- BEGIN context-guard:brief-mode", text)
                    self.assertIn("User rules.", text)

    def test_brief_mode_combines_with_init_skill_and_backs_up_original_once(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    agents_md = root / "AGENTS.md"
                    original = "Existing Codex rules.\n"
                    agents_md.write_text(original, encoding="utf-8")
                    data = self._run(
                        script,
                        root,
                        [
                            "--agent",
                            "codex",
                            "--with-init",
                            "--with-skill",
                            "--brief-mode",
                            "lite",
                            "--yes",
                            "--no-diet-scan",
                        ],
                    )
                    entry = data["adapter_plan"][0]
                    text = agents_md.read_text(encoding="utf-8")
                    self.assertTrue(data["applied"])
                    self.assertEqual(text.count("<!-- contextguard:begin -->"), 1)
                    self.assertEqual(text.count("<!-- BEGIN context-guard:brief-mode level=lite version=1 -->"), 1)
                    self.assertEqual(entry["project_skill_status"], "applied")
                    backup_path = Path(entry["brief_mode_backup_path"])
                    self.assertTrue(backup_path.is_file())
                    self.assertEqual(backup_path.read_text(encoding="utf-8"), original)
                    backups = list(root.glob("AGENTS.md.bak-*"))
                    self.assertEqual(len(backups), 1)

    def test_brief_mode_repo_rule_backup_ignores_no_backup_for_original_file(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    agents_md = root / "AGENTS.md"
                    original = "Original Codex rules must be restorable.\n"
                    agents_md.write_text(original, encoding="utf-8")

                    data = self._run(
                        script,
                        root,
                        [
                            "--agent",
                            "codex",
                            "--with-init",
                            "--brief-mode",
                            "lite",
                            "--yes",
                            "--no-backup",
                            "--no-diet-scan",
                        ],
                    )

                    entry = data["adapter_plan"][0]
                    backup_path = Path(entry["brief_mode_backup_path"])
                    self.assertTrue(data["applied"])
                    self.assertTrue(backup_path.is_file())
                    self.assertEqual(backup_path.read_text(encoding="utf-8"), original)
                    self.assertEqual(len(list(root.glob("AGENTS.md.bak-*"))), 1)

    def test_brief_mode_plan_reports_same_level_custom_block_refresh(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    agents_md = root / "AGENTS.md"
                    custom = "\n".join(
                        [
                            "User rules.",
                            "<!-- BEGIN context-guard:brief-mode level=standard version=1 -->",
                            "CUSTOM SAME-LEVEL CONTENT",
                            "<!-- END context-guard:brief-mode -->",
                            "",
                        ]
                    )
                    agents_md.write_text(custom, encoding="utf-8")

                    planned = self._run(script, root, ["--agent", "codex", "--brief-mode", "standard", "--plan"])
                    plan_entry = planned["adapter_plan"][0]
                    self.assertFalse(planned["applied"])
                    self.assertEqual(plan_entry["brief_mode_status"], "planned")
                    self.assertIn("would refresh advisory brief-mode standard", "\n".join(plan_entry["planned_actions"]))
                    self.assertEqual(agents_md.read_text(encoding="utf-8"), custom)

                    applied = self._run(
                        script,
                        root,
                        ["--agent", "codex", "--brief-mode", "standard", "--yes", "--no-diet-scan"],
                    )
                    apply_entry = applied["adapter_plan"][0]
                    rewritten = agents_md.read_text(encoding="utf-8")
                    self.assertTrue(applied["applied"])
                    self.assertEqual(apply_entry["brief_mode_status"], "updated")
                    self.assertTrue(Path(apply_entry["brief_mode_backup_path"]).is_file())
                    self.assertNotIn("CUSTOM SAME-LEVEL CONTENT", rewritten)
                    self.assertIn("does not promise", rewritten)

    def test_brief_mode_text_output_surfaces_rule_backup_path(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    (root / "AGENTS.md").write_text("Existing rules.\n", encoding="utf-8")
                    proc = subprocess.run(
                        [
                            sys.executable,
                            str(script),
                            "--root",
                            str(root),
                            "--agent",
                            "codex",
                            "--brief-mode",
                            "lite",
                            "--yes",
                            "--no-diet-scan",
                        ],
                        text=True,
                        capture_output=True,
                        check=True,
                    )
                    self.assertIn("backup=", proc.stdout)
                    self.assertEqual(len(list(root.glob("AGENTS.md.bak-*"))), 1)

    def test_brief_mode_uncertain_atomic_write_still_reports_backup_path(self):
        for index, script in enumerate(SETUP_SCRIPTS):
            with self.subTest(script=script):
                setup = load_python_script_module(script, f"setup_uncertain_brief_mode_{index}")
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp).resolve()
                    agents_md = root / "AGENTS.md"
                    original = "Existing Codex rules.\n"
                    agents_md.write_text(original, encoding="utf-8")
                    real_atomic_write = setup.atomic_write

                    def uncertain_target_write(path: Path, text: str, mode: int = 0o600, *, dir_mode: int = setup.PRIVATE_DIR_MODE) -> None:
                        real_atomic_write(path, text, mode, dir_mode=dir_mode)
                        if Path(path) == agents_md:
                            raise setup.AtomicWriteDurabilityError(
                                f"write committed but parent directory durability is uncertain: {path}"
                            )

                    setup.atomic_write = uncertain_target_write
                    try:
                        result = setup.plan_or_write_rule_file_blocks(
                            agents_md,
                            with_init=False,
                            brief_mode="lite",
                            applied=True,
                        )
                    finally:
                        setup.atomic_write = real_atomic_write

                    backup_path = Path(result["brief_mode_backup_path"])
                    self.assertEqual(result["status"], "applied-durability-uncertain")
                    self.assertEqual(result["brief_mode_status"], "applied")
                    self.assertTrue(backup_path.is_file())
                    self.assertEqual(backup_path.read_text(encoding="utf-8"), original)
                    self.assertIn("durability is uncertain", "\n".join(result["planned_actions"]))
                    self.assertIn("level=lite", agents_md.read_text(encoding="utf-8"))

    def test_claude_project_brief_mode_targets_claude_md(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    planned = self._run(script, root, ["--agent", "claude", "--brief-mode", "lite", "--plan"])
                    entry = planned["adapter_plan"][0]
                    self.assertEqual(entry["key"], "claude")
                    self.assertEqual(entry["brief_mode_file"], "CLAUDE.md")
                    self.assertEqual(entry["brief_mode_status"], "planned")
                    self.assertFalse((root / "CLAUDE.md").exists())

                    applied = self._run(
                        script,
                        root,
                        [
                            "--agent",
                            "claude",
                            "--brief-mode",
                            "lite",
                            "--yes",
                            "--no-diet-scan",
                            "--no-denies",
                            "--no-statusline",
                            "--no-bash-hook",
                            "--no-read-guard",
                            "--no-model-defaults",
                            "--no-failed-attempt-nudge",
                        ],
                    )
                    entry = applied["adapter_plan"][0]
                    self.assertTrue(applied["applied"])
                    self.assertEqual(entry["brief_mode_status"], "applied")
                    self.assertIn("level=lite", (root / "CLAUDE.md").read_text(encoding="utf-8"))

    def test_brief_mode_user_scope_and_report_only_adapters_never_write(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    home = Path(tmp) / "home"
                    home.mkdir()
                    env = os.environ.copy()
                    env["HOME"] = str(home)
                    proc = subprocess.run(
                        [
                            sys.executable,
                            str(script),
                            "--scope",
                            "user",
                            "--agent",
                            "codex",
                            "--brief-mode",
                            "standard",
                            "--yes",
                            "--json",
                        ],
                        text=True,
                        capture_output=True,
                        env=env,
                        check=True,
                    )
                    data = json.loads(proc.stdout)
                    entry = data["adapter_plan"][0]
                    self.assertFalse(data["applied"])
                    self.assertEqual(entry["brief_mode_status"], "unsupported")
                    self.assertFalse((home / "AGENTS.md").exists())
                    self.assertFalse((home / ".claude").exists())

                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    data = self._run(
                        script,
                        root,
                        ["--only", "opencode,forgecode,generic", "--brief-mode", "standard", "--yes", "--no-diet-scan"],
                    )
                    self.assertFalse(data["applied"])
                    for entry in data["adapter_plan"]:
                        self.assertEqual(entry["brief_mode_status"], "unsupported")
                    self.assertEqual(list(root.iterdir()), [])

    def test_brief_mode_skips_symlinked_rule_file(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    try:
                        (root / "AGENTS.md").symlink_to(root / "outside.md")
                    except (OSError, NotImplementedError):
                        self.skipTest("symlink creation unsupported on this filesystem")
                    data = self._run(script, root, ["--agent", "codex", "--brief-mode", "standard", "--yes", "--no-diet-scan"])
                    entry = data["adapter_plan"][0]
                    self.assertFalse(data["applied"])
                    self.assertEqual(entry["brief_mode_status"], "skipped")
                    self.assertTrue((root / "AGENTS.md").is_symlink())
                    self.assertFalse((root / "outside.md").exists())

    def test_brief_mode_plan_skips_symlinked_rule_parent(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    outside = root / "outside-windsurf"
                    outside.mkdir()
                    try:
                        (root / ".windsurf").symlink_to(outside, target_is_directory=True)
                    except (OSError, NotImplementedError):
                        self.skipTest("symlink creation unsupported on this filesystem")
                    data = self._run(script, root, ["--only", "windsurf", "--brief-mode", "standard", "--plan"])
                    entry = data["adapter_plan"][0]
                    self.assertFalse(data["applied"])
                    self.assertEqual(entry["brief_mode_status"], "skipped")
                    self.assertIn("symlink", entry["brief_mode_reason"])
                    self.assertFalse((outside / "rules" / "contextguard.md").exists())

    def test_unknown_adapter_key_is_rejected(self):
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    proc = subprocess.run(
                        [sys.executable, str(script), "--root", tmp, "--only", "nope", "--plan", "--json"],
                        text=True,
                        capture_output=True,
                    )
                    self.assertNotEqual(proc.returncode, 0)
                    self.assertIn("Unknown adapter key", proc.stderr)


class ContextEscrowCcrMetadataTests(unittest.TestCase):
    """CCR/artifact UX: content-type classification, retrieval strategy hints,
    redaction-count metadata, and exact line/pattern retrieval round-trips."""

    def _load(self) -> object:
        return load_python_script_module(KIT_DIR / "context_escrow.py", "context_escrow_ccr_meta")

    def test_classify_content_type_is_deterministic_per_kind(self):
        artifact = self._load()
        cases = {
            "json": '{"a": 1, "b": [1, 2, 3]}',
            "json_array": "[1, 2, 3, 4]",
            "diff": "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n",
            "log": (
                "2026-06-02T10:00:01 INFO start\n"
                "2026-06-02T10:00:02 ERROR boom\n"
                "2026-06-02T10:00:03 INFO done\n"
            ),
            "search": "src/app.py:10:def foo():\nsrc/app.py:20:    return 1\nsrc/util.py:5:x = 1\n",
            "code": "def foo():\n    return 1\n\nclass Bar:\n    def baz(self):\n        return 2\n",
            "prose": "The quick brown fox jumps over the lazy dog. It was a fine day indeed.\n",
            "empty": "",
        }
        expected = {
            "json": "json",
            "json_array": "json",
            "diff": "diff",
            "log": "log",
            "search": "search",
            "code": "code",
            "prose": "prose",
            "empty": "text",
        }
        for name, text in cases.items():
            with self.subTest(kind=name):
                label = artifact.classify_content_type(text)
                self.assertEqual(label, expected[name])
                self.assertIn(label, artifact.CONTENT_TYPE_VALUES)
                self.assertEqual(label, artifact.classify_content_type(text))
                self.assertIn(
                    artifact.recommended_strategy(label),
                    {"lines", "pattern", "head"},
                )

    def test_first_error_anchor_returns_present_substring_or_none(self):
        artifact = self._load()
        self.assertIsNone(artifact.first_error_anchor("just calm words here\nnothing wrong\n"))
        content = "ok line\nFAILED to build target\nok line\n"
        anchor = artifact.first_error_anchor(content)
        self.assertIsNotNone(anchor)
        self.assertIn(anchor, content)

    def test_retrieval_hints_round_trip_exactly(self):
        artifact = self._load()
        content = "alpha line\nERROR middle line\nbeta line\ngamma line\n"
        total_lines = content.count("\n")
        hints = artifact.build_retrieval_hints(
            "a" * 20,
            content,
            content_type="prose",
            strategy="lines",
            total_lines=total_lines,
        )
        by_type = {hint["type"]: hint for hint in hints}
        self.assertIn("lines", by_type)
        self.assertIn("head", by_type)
        self.assertIn("pattern", by_type)

        lines_selector = by_type["lines"]["selector"]
        self.assertEqual(lines_selector, {"start": 1, "end": total_lines})
        recovered, _meta = artifact.query_content(
            content,
            line_range=(lines_selector["start"], lines_selector["end"]),
            pattern=None,
            max_lines=5_000,
        )
        self.assertEqual(recovered, content)

        token = by_type["pattern"]["selector"]["pattern"]
        matched, meta = artifact.query_content(
            content,
            line_range=None,
            pattern=token,
            max_lines=5_000,
        )
        self.assertTrue(matched)
        self.assertTrue(all(token in line for line in matched.splitlines()))
        self.assertEqual(meta["matched_lines"], len([row for row in content.splitlines() if token in row]))

    def test_store_records_content_type_strategy_and_redaction_counts(self):
        secret = "ghp_" + ("A" * 36)
        raw = "{\n  \"status\": \"ok\"\n}\nAPI_TOKEN=" + secret + "\n"
        for script in ARTIFACT_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    artifact_dir = Path(tmp) / "artifacts"
                    store = subprocess.run(
                        [sys.executable, str(script), "--dir", str(artifact_dir), "store", "--json"],
                        input=raw,
                        text=True,
                        capture_output=True,
                        check=True,
                    )
                    receipt = json.loads(store.stdout)
                    self.assertIn(receipt["content_type"], {"json", "prose", "text", "code"})
                    retrieve = receipt["retrieval"]
                    self.assertIn(retrieve["strategy"], {"lines", "pattern", "head"})
                    self.assertTrue(retrieve["deterministic"])
                    self.assertTrue(retrieve["hints"])
                    counts = receipt["digest"]["redaction_counts"]
                    self.assertGreaterEqual(counts["lines"], 1)
                    self.assertGreaterEqual(counts["markers"], 1)
                    self.assertEqual(counts["lines"], receipt["digest"]["redacted_lines"])
                    self.assertNotIn(secret, store.stdout)
                    metadata_text = (artifact_dir / f"{receipt['artifact_id']}.json").read_text(encoding="utf-8")
                    self.assertNotIn(secret, metadata_text)

    def test_get_round_trip_uses_stored_hints_for_exact_retrieval(self):
        raw = "first row\nERROR exact target\nthird row\nfourth row\n"
        for script in ARTIFACT_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    artifact_dir = Path(tmp) / "artifacts"
                    store = subprocess.run(
                        [sys.executable, str(script), "--dir", str(artifact_dir), "store", "--json"],
                        input=raw,
                        text=True,
                        capture_output=True,
                        check=True,
                    )
                    receipt = json.loads(store.stdout)
                    artifact_id = receipt["artifact_id"]
                    hints = {hint["type"]: hint for hint in receipt["retrieval"]["hints"]}

                    lines_sel = hints["lines"]["selector"]
                    full = subprocess.run(
                        [
                            sys.executable,
                            str(script),
                            "--dir",
                            str(artifact_dir),
                            "get",
                            artifact_id,
                            "--lines",
                            f"{lines_sel['start']}:{lines_sel['end']}",
                            "--json",
                        ],
                        text=True,
                        capture_output=True,
                        check=True,
                    )
                    full_payload = json.loads(full.stdout)
                    self.assertEqual(full_payload["content"], raw)
                    self.assertEqual(full_payload["content_type"], receipt["content_type"])
                    self.assertEqual(full_payload["retrieval"]["strategy"], receipt["retrieval"]["strategy"])

                    token = hints["pattern"]["selector"]["pattern"]
                    pat = subprocess.run(
                        [
                            sys.executable,
                            str(script),
                            "--dir",
                            str(artifact_dir),
                            "get",
                            artifact_id,
                            "--pattern",
                            token,
                            "--json",
                        ],
                        text=True,
                        capture_output=True,
                        check=True,
                    )
                    pat_payload = json.loads(pat.stdout)
                    self.assertTrue(pat_payload["content"])
                    self.assertTrue(all(token in line for line in pat_payload["content"].splitlines()))

class ImageContextEvaluationProfileTests(unittest.TestCase):
    """Contract tests for the optional image-context evaluation profile.

    The profile is evaluation-only: no fixture in this class may ever produce a
    public claim, promotion authority, or a savings claim.  Structurally invalid
    evidence must fail closed *before any output byte is written*; well-formed
    negative evidence must stay replayable and score the lane as blocked.

    Kept in its own TestCase because ``BenchmarkRunnerTests`` has a hardcoded
    ``countTestCases() == 75`` assertion in the split-module compatibility tests.
    """

    TASK_ID = "image_context_profile_case"
    BASELINE = "baseline_full_evidence"
    CANDIDATE = "packed_image_context"

    # ---------- fixture construction -------------------------------------

    def _prompt_text(self, kind):
        # Bounded, sanitized, claim-safe prompt bodies.  Never echoed into reports.
        return (
            f"# {kind} sanitized textual evidence fixture\n"
            "Plan-only; protected-zone deny; no renderer call; no OCR call; no provider call.\n"
            "This fixture does not establish token savings, cost savings, or quality non-inferiority.\n"
        )

    def _write_prompts(self, root):
        paths = {}
        for variant, kind in ((self.BASELINE, "full"), (self.CANDIDATE, "packed")):
            path = root / f"{variant}.prompt.md"
            path.write_text(self._prompt_text(kind), encoding="utf-8")
            paths[variant] = path
        return paths

    def _sha256_file(self, path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _proof_projection(self, *, receipt_id, content_sha256, retrieval_command, **overrides):
        """A passing bounded projection of one imported local-verifier result.

        Mirrors the real verifier payload contract; replay validates the projection
        against the outer fallback binding but never re-authenticates the artifact.
        """
        unit = {
            "status": "verified",
            "receipt_id": receipt_id,
            "receipt_verified": True,
            "content_hash_declared_value": content_sha256,
            "content_hash_verified": True,
            "retrieval_command": retrieval_command,
            "rehydration_receipt_bound": True,
            "rehydration_syntax_valid": True,
            "rehydration_verified": True,
            "rehydration_executed": False,
        }
        unit.update(overrides.pop("proof_unit", {}))
        projection = {
            "schema": PROOF_VERIFY_SCHEMA_VERSION,
            "status": "verified",
            "blockers": [],
            "candidate_replacement": None,
            "claim_boundary": PROOF_VERIFICATION_CLAIM_BOUNDARY,
            "proof_unit": unit,
        }
        projection.update(overrides)
        return projection

    def _controls(self, *, prompt_path, omission, verified_fallback, corrections, correction_reason,
                  missed_present, measured, **overrides):
        """Build a well-formed ``evaluation_controls`` block, then apply overrides."""
        receipt_id = "receipt-fixture-0001"
        content_sha256 = hashlib.sha256(b"exact-source-text-fixture").hexdigest()
        retrieval_command = "context-guard experiments verify proof-carrying-context --artifact-dir ./fixture-receipts"
        if omission and verified_fallback:
            fallback = {
                "available": True,
                "verified": True,
                "receipt_id": receipt_id,
                "content_sha256": content_sha256,
                "retrieval_command": retrieval_command,
                "verifier_projection": self._proof_projection(
                    receipt_id=receipt_id,
                    content_sha256=content_sha256,
                    retrieval_command=retrieval_command,
                ),
            }
        elif omission:
            # Omission declared but never bound to a passing verifier record.
            fallback = {
                "available": True, "verified": False,
                "receipt_id": "none", "content_sha256": "none",
                "retrieval_command": "none", "verifier_projection": None,
            }
        else:
            fallback = {
                "available": False, "verified": False,
                "receipt_id": "none", "content_sha256": "none",
                "retrieval_command": "none", "verifier_projection": None,
            }
        controls = {
            "control_provenance": {
                "review_source": "synthetic_fixture",
                "verifier_label": "local_proof_verifier_fixture" if (omission and verified_fallback) else "none",
            },
            "exact_text_fallback": fallback,
            "human_correction": {"count": corrections, "reason": correction_reason},
            "missed_context_review": {
                "correction_required": bool(corrections),
                "present": missed_present,
                "review_completed": True,
                "summary": "packed evidence omitted the qualifying acknowledgement" if missed_present else "none",
            },
            "prompt_evidence": {
                "sha256": self._sha256_file(prompt_path),
                "source_label": prompt_path.name,
            },
            "protected_zone_review": {
                "included_prompt_like_regions": 0,
                "included_protected_regions": 0,
                "policy": "deny",
                "review_completed": True,
                "review_note": "deny policy declared; no protected or prompt-like region included",
                "reviewer_label": "synthetic_fixture_reviewer",
            },
            "provider_usage": {
                "primary_cost_measured": measured,
                "primary_tokens_measured": measured,
                "provider_called": measured,
            },
            "shifted_cost": {
                "external_cost_measured": measured,
                "external_tokens_measured": measured,
                "status": "measured" if measured else "unmeasured",
            },
            "source_omission": {
                "present": omission,
                "transform": "packed_textual_summary" if omission else "none",
            },
        }
        for key, value in overrides.items():
            if isinstance(value, dict) and isinstance(controls.get(key), dict):
                controls[key] = {**controls[key], **value}
            else:
                controls[key] = value
        return controls

    def _row(self, *, variant, prompt_path, measured, omission, verified_fallback=False, corrections=0,
             correction_reason="none", missed_present=False, input_tokens=1000, output_tokens=200,
             cost_usd=0.05, bytes_before=1000, bytes_after=1000, profile=IMAGE_CONTEXT_EVALUATION_PROFILE_ID,
             controls=None, control_overrides=None, drop_controls=False):
        """One evidence row.  ``measured`` switches synthetic_fixture vs provider_export."""
        if measured:
            provenance = {
                "evidence_source_type": "provider_export",
                "provider_name": "fixture-provider",
                "capture_command_or_export_id": "fixture-export-0001",
                "claim_scope": "provider_measured_matched_task",
            }
        else:
            provenance = {
                "evidence_source_type": "synthetic_fixture",
                "capture_command_or_export_id": "unit-test-fixture",
                "claim_scope": "local_replay_fixture_not_public_claim",
            }
        row = {
            "schema_version": "contextguard.bench.run-evidence.v1",
            "task_id": self.TASK_ID,
            "variant": variant,
            "success": True,
            "provenance": provenance,
            "tokens": {
                "input_tokens": input_tokens, "output_tokens": output_tokens,
                "cache_read": 0, "cache_creation": 0,
            },
            "primary_tokens_measured": measured,
            "cost_usd": cost_usd,
            "cost_measured": measured,
            "external_tokens": 0,
            "external_tokens_measured": measured,
            "external_cost_usd": 0,
            "external_cost_measured": measured,
            "bytes_before": bytes_before,
            "bytes_after": bytes_after,
            "corrections": corrections,
            "notes": f"sanitized fixture row for {variant}; no provider call in replay",
        }
        if profile is not None:
            row["evaluation_profile"] = profile
        if not drop_controls:
            built = controls if controls is not None else self._controls(
                prompt_path=prompt_path, omission=omission, verified_fallback=verified_fallback,
                corrections=corrections, correction_reason=correction_reason,
                missed_present=missed_present, measured=measured,
            )
            if control_overrides:
                for key, value in control_overrides.items():
                    if isinstance(value, dict) and isinstance(built.get(key), dict):
                        built[key] = {**built[key], **value}
                    else:
                        built[key] = value
            row["evaluation_controls"] = built
        return row

    def _write_case(self, root, rows, *, task_profile=IMAGE_CONTEXT_EVALUATION_PROFILE_ID,
                    variant_prompt_files=True, success_command=None):
        """Write tasks/variants/evidence for one profiled case.

        ``success_command`` defaults to the placeholder, which the runner already
        refuses outside a dry run.  Hostile direct-run tests pass a *real* command
        so the placeholder guard cannot be mistaken for the profile guard.
        """
        prompts = self._write_prompts(root)
        task = {
            "id": self.TASK_ID,
            "prompt": "sanitized fixture task; no renderer, OCR, provider, network, or subprocess call",
            "model": "sonnet",
            "effort": "medium",
            "max_turns": 1,
            "allowed_tools": [],
            "success_command": success_command or (
                "python3 -c \"raise SystemExit('fixture-only placeholder: "
                "replace success_command before real benchmark runs')\""
            ),
            "success_cwd": ".",
        }
        if variant_prompt_files:
            task["variant_prompt_files"] = {v: p.name for v, p in prompts.items()}
        if task_profile is not None:
            task["evaluation_profile"] = task_profile

        tasks_path = root / "tasks.json"
        variants_path = root / "variants.json"
        evidence_path = root / "evidence.jsonl"
        tasks_path.write_text(json.dumps([task]), encoding="utf-8")
        variants_path.write_text(json.dumps([
            {"name": self.BASELINE, "extra_args": []},
            {"name": self.CANDIDATE, "extra_args": []},
        ]), encoding="utf-8")
        evidence_path.write_text(
            "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
            encoding="utf-8",
        )
        return {
            "tasks": tasks_path, "variants": variants_path, "evidence": evidence_path,
            "prompts": prompts,
        }

    def _default_rows(self, prompts, *, measured=False, verified_fallback=False):
        """Baseline (no omission) + candidate (omission) pair."""
        return [
            self._row(
                variant=self.BASELINE, prompt_path=prompts[self.BASELINE], measured=measured,
                omission=False, input_tokens=1000, output_tokens=200, cost_usd=0.05,
                bytes_before=1000, bytes_after=1000,
            ),
            self._row(
                variant=self.CANDIDATE, prompt_path=prompts[self.CANDIDATE], measured=measured,
                omission=True, verified_fallback=verified_fallback, input_tokens=400,
                output_tokens=120, cost_usd=0.02, bytes_before=1000, bytes_after=400,
            ),
        ]

    # ---------- invocation + zero-write helpers ---------------------------

    def _output_paths(self, root, stem):
        return {
            "csv": root / f"{stem}.csv",
            "ledger": root / f"{stem}.ledger.jsonl",
            "report": root / f"{stem}.report.json",
            "dashboard": root / f"{stem}.dashboard.md",
        }

    # replay 경로가 기본값이다. claude_bin 을 주면 --evidence-jsonl 없이 평범한 provider
    # 경로로 같은 CLI 를 호출한다(= 예전 _run_direct). 두 경로의 argv 는 이 한 곳에서만
    # 만들어지므로 복사본이 서로 어긋날 수 없다.
    def _run(self, script, case, outputs, *, claude_bin=None, extra_args=(), baseline_variant=None):
        replay_args = () if claude_bin else ("--evidence-jsonl", str(case["evidence"]))
        argv = [
            sys.executable, str(script),
            "--tasks", str(case["tasks"]),
            "--variants", str(case["variants"]),
            *replay_args,
            "--baseline-variant", baseline_variant or self.BASELINE,
            "--claude-bin", str(claude_bin or "/definitely/missing/contextguard-claude"),
            "--csv", str(outputs["csv"]),
            "--ledger-jsonl", str(outputs["ledger"]),
            "--report-json", str(outputs["report"]),
            "--dashboard-md", str(outputs["dashboard"]),
            *extra_args,
        ]
        return subprocess.run(argv, cwd=ROOT, text=True, capture_output=True)

    def _recording_claude(self, root, marker):
        """A *working* fake provider that records the fact it was executed.

        The profile guard must reject before this can ever run; the marker file is
        the only proof that distinguishes "never invoked" from "invoked and failed".
        """
        fake = root / "recording-claude"
        payload = json.dumps({
            "message": {"usage": {"input_tokens": 10, "output_tokens": 5}},
            "total_cost_usd": 0.0123,
        })
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import pathlib, sys\n"
            f"pathlib.Path({str(marker)!r}).write_text('provider invoked', encoding='utf-8')\n"
            f"sys.stdout.write({payload!r})\n"
            "sys.exit(0)\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        return fake

    def _assert_zero_writes(self, outputs):
        """No output *and* no lock sidecar may exist after a reject_prewrite."""
        for label, path in outputs.items():
            self.assertFalse(path.exists(), f"{label} must not be written on reject_prewrite: {path}")
            lock = path.with_name(path.name + ".lock")
            self.assertFalse(lock.exists(), f"{label} lock sidecar must not be created: {lock}")

    def _assert_no_leakage(self, text, case):
        """Reports/errors must never echo prompts, artifact dirs, or secret-shaped values."""
        lowered = text.lower()
        for forbidden in ("sanitized textual evidence fixture", "-----begin", "sk-", "http://", "https://"):
            self.assertNotIn(forbidden, lowered)
        self.assertNotIn(str(Path.home()).lower(), lowered)
        for prompt_path in case["prompts"].values():
            self.assertNotIn(prompt_path.read_text(encoding="utf-8").strip().lower(), lowered)

    # ---------- success + clamp -------------------------------------------

    def test_complete_provider_export_pilot_reaches_bounded_pilot_review_without_public_authority(self):
        """PRD AC10: the strongest possible evidence still cannot buy public authority.

        Every generic gate passes (measured provider tokens/cost, measured shifted
        cost, verified fallback, clean protection review, zero corrections), yet the
        lane may only reach ``ready_for_bounded_pilot_review`` and every public-claim
        surface stays clamped false.
        """
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script.name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                prompts = self._write_prompts(root)
                rows = self._default_rows(prompts, measured=True, verified_fallback=True)
                case = self._write_case(root, rows)
                outputs = self._output_paths(root, f"pilot{index}")
                proc = self._run(script, case, outputs)
                self.assertEqual(proc.returncode, 0, proc.stderr)

                report = json.loads(outputs["report"].read_text(encoding="utf-8"))
                lane = report["evaluation_profiles"][IMAGE_CONTEXT_PROFILE_REPORT_KEY]

                self.assertEqual(lane["schema_version"], IMAGE_CONTEXT_READINESS_SCHEMA_VERSION)
                self.assertEqual(lane["status"], "ready_for_bounded_pilot_review")
                self.assertEqual(lane["blocking_gate_ids"], [])
                self.assertEqual(list(lane["gate_ids"]), list(IMAGE_CONTEXT_GATE_IDS))
                self.assertEqual(lane["matched_task_count"], 1)
                self.assertEqual(lane["evidence_levels"], {
                    "provider_measurement": "measured",
                    "fallback_binding": "imported_local_verifier_attestation",
                    "protected_zone": "review_attested",
                    "missed_context": "reviewed",
                })

                # Evaluation-only invariants -- the whole point of the lane.
                self.assertTrue(lane["evaluation_only"])
                self.assertFalse(lane["promotion_authority"])
                self.assertFalse(lane["public_claim_allowed"])
                self.assertEqual(report["claim_status"], IMAGE_CONTEXT_EVALUATION_ONLY_CLAIM_STATUS)
                self.assertEqual(report["public_claim_status"], IMAGE_CONTEXT_EVALUATION_ONLY_CLAIM_STATUS)
                self.assertFalse(report["public_claim_eligible"])
                self.assertFalse(report["public_claim_readiness"]["claim_allowed"])
                for pair in report["matched_pair_evidence"]:
                    self.assertFalse(pair["claim_boundary"]["token_savings_claim_allowed"])
                    self.assertFalse(pair["claim_boundary"]["shifted_cost_claim_allowed"])

                # Pre-clamp measurement survives only in explicitly non-authoritative fields.
                self.assertEqual(
                    report["raw_metric_claim_status"], "token_and_shifted_cost_savings_observed"
                )

                # Non-promotional sample adequacy never grants readiness.
                self.assertEqual(
                    lane["sample_adequacy"]["policy_status"], "not_defined_for_promotion"
                )

                dashboard = outputs["dashboard"].read_text(encoding="utf-8")
                self.assertIn("Image-context evaluation", dashboard)
                self.assertNotIn("promotion ready", dashboard.lower())
                self.assertNotIn("runtime authorized", dashboard.lower())
                self._assert_no_leakage(dashboard, case)
                self._assert_no_leakage(outputs["report"].read_text(encoding="utf-8"), case)

    # ---------- reject_prewrite taxonomy ----------------------------------

    def _reject_cases(self, root, prompts):
        """(case_id, expected_error_id, rows, task_profile) for every reject_prewrite row."""
        other_sha = hashlib.sha256(b"not-the-prompt").hexdigest()
        cases = []

        # profile_controls_missing -- required control block absent.
        rows = self._default_rows(prompts)
        rows[1] = self._row(
            variant=self.CANDIDATE, prompt_path=prompts[self.CANDIDATE], measured=False,
            omission=True, drop_controls=True,
        )
        cases.append(("controls_missing", "profile_controls_missing", rows, IMAGE_CONTEXT_EVALUATION_PROFILE_ID))

        # profile_schema_invalid -- unknown nested key for this v1 profile.
        rows = self._default_rows(prompts)
        rows[1]["evaluation_controls"]["unexpected_future_key"] = True
        cases.append(("unknown_key", "profile_schema_invalid", rows, IMAGE_CONTEXT_EVALUATION_PROFILE_ID))

        # profile_schema_invalid -- wrong type.
        rows = self._default_rows(prompts)
        rows[1]["evaluation_controls"]["protected_zone_review"]["included_protected_regions"] = "zero"
        cases.append(("wrong_type", "profile_schema_invalid", rows, IMAGE_CONTEXT_EVALUATION_PROFILE_ID))

        # profile_schema_invalid -- oversized policy value.  Bounds run BEFORE semantic
        # policy classification, so this must reject rather than fall through to the
        # accepted_blocked protected-zone branch.
        rows = self._default_rows(prompts)
        rows[1]["evaluation_controls"]["protected_zone_review"]["policy"] = "x" * 100_000
        cases.append(("oversize_policy", "profile_schema_invalid", rows, IMAGE_CONTEXT_EVALUATION_PROFILE_ID))

        # profile_schema_invalid -- unknown profile version on the task.
        rows = self._default_rows(prompts)
        for row in rows:
            row["evaluation_profile"] = "contextguard.bench.image-context-pack-evaluation.v999"
        cases.append((
            "unknown_version", "profile_schema_invalid", rows,
            "contextguard.bench.image-context-pack-evaluation.v999",
        ))

        # profile_binding_mismatch -- row omits the profile the task declares.
        rows = self._default_rows(prompts)
        rows[1].pop("evaluation_profile")
        cases.append(("row_profile_missing", "profile_binding_mismatch", rows, IMAGE_CONTEXT_EVALUATION_PROFILE_ID))

        # profile_binding_mismatch -- profiled row on an unprofiled task.
        rows = self._default_rows(prompts)
        cases.append(("profiled_row_unprofiled_task", "profile_binding_mismatch", rows, None))

        # profile_batch_incomplete -- mixed profiled/unprofiled rows for one task.
        rows = self._default_rows(prompts)
        rows[1].pop("evaluation_profile")
        rows[1].pop("evaluation_controls")
        cases.append(("mixed_batch", "profile_batch_incomplete", rows, IMAGE_CONTEXT_EVALUATION_PROFILE_ID))

        # profile_prompt_binding_invalid -- candidate carries the wrong prompt hash.
        rows = self._default_rows(prompts)
        rows[1]["evaluation_controls"]["prompt_evidence"]["sha256"] = other_sha
        cases.append(("prompt_sha_mismatch", "profile_prompt_binding_invalid", rows, IMAGE_CONTEXT_EVALUATION_PROFILE_ID))

        # profile_prompt_binding_invalid -- baseline hash used for the candidate row.
        rows = self._default_rows(prompts)
        rows[1]["evaluation_controls"]["prompt_evidence"]["sha256"] = self._sha256_file(prompts[self.BASELINE])
        cases.append(("prompt_sha_swapped", "profile_prompt_binding_invalid", rows, IMAGE_CONTEXT_EVALUATION_PROFILE_ID))

        # profile_correction_inconsistent -- nested count disagrees with top-level corrections.
        rows = self._default_rows(prompts)
        rows[1]["corrections"] = 1
        rows[1]["evaluation_controls"]["human_correction"] = {"count": 0, "reason": "none"}
        cases.append(("correction_count_mismatch", "profile_correction_inconsistent", rows, IMAGE_CONTEXT_EVALUATION_PROFILE_ID))

        # profile_correction_inconsistent -- positive count with no reason.
        rows = self._default_rows(prompts)
        rows[1]["corrections"] = 1
        rows[1]["evaluation_controls"]["human_correction"] = {"count": 1, "reason": ""}
        cases.append(("correction_without_reason", "profile_correction_inconsistent", rows, IMAGE_CONTEXT_EVALUATION_PROFILE_ID))

        # profile_measurement_inconsistent -- lane metadata claims measured while the
        # generic synthetic_fixture row is provably unmeasured.  Lane metadata must
        # never be able to upgrade a generic measurement flag.
        rows = self._default_rows(prompts)
        rows[1]["evaluation_controls"]["provider_usage"] = {
            "primary_cost_measured": True, "primary_tokens_measured": True, "provider_called": True,
        }
        cases.append(("lane_upgrades_measurement", "profile_measurement_inconsistent", rows, IMAGE_CONTEXT_EVALUATION_PROFILE_ID))

        # profile_measurement_inconsistent -- lane shifted-cost claims measured while generic is not.
        rows = self._default_rows(prompts)
        rows[1]["evaluation_controls"]["shifted_cost"] = {
            "external_cost_measured": True, "external_tokens_measured": True, "status": "measured",
        }
        cases.append(("lane_upgrades_shifted_cost", "profile_measurement_inconsistent", rows, IMAGE_CONTEXT_EVALUATION_PROFILE_ID))

        # profile_fallback_claim_inconsistent -- claims verified but the projection contradicts it.
        contradictions = {
            "blockers_present": {"blockers": ["proof_content_hash_mismatch"]},
            "non_null_replacement": {"candidate_replacement": {"unit_id": "u1"}},
            "verifier_status_failed": {"status": "verification_failed"},
            "wrong_schema": {"schema": "contextguard.experiments.some-other-schema.v1"},
            "unit_not_verified": {"proof_unit": {"status": "verification_failed", "receipt_verified": False}},
            "content_hash_mismatch": {"proof_unit": {"content_hash_declared_value": other_sha}},
            "command_not_bound": {"proof_unit": {"rehydration_receipt_bound": False}},
        }
        for name, override in contradictions.items():
            rows = self._default_rows(prompts, verified_fallback=True)
            fallback = rows[1]["evaluation_controls"]["exact_text_fallback"]
            projection = dict(fallback["verifier_projection"])
            unit_override = override.pop("proof_unit", None)
            if unit_override:
                projection["proof_unit"] = {**projection["proof_unit"], **unit_override}
            projection.update(override)
            fallback["verifier_projection"] = projection
            cases.append((
                f"fallback_{name}", "profile_fallback_claim_inconsistent", rows,
                IMAGE_CONTEXT_EVALUATION_PROFILE_ID,
            ))

        # profile_fallback_claim_inconsistent -- receipt id disagrees with the projection.
        rows = self._default_rows(prompts, verified_fallback=True)
        rows[1]["evaluation_controls"]["exact_text_fallback"]["receipt_id"] = "receipt-does-not-match"
        cases.append(("fallback_receipt_mismatch", "profile_fallback_claim_inconsistent", rows, IMAGE_CONTEXT_EVALUATION_PROFILE_ID))

        # --- G002 blocker 6: duplicate profile evidence needs a *stable* id ------
        # A duplicate must be caught by profile preflight with profile_batch_incomplete,
        # not fall through to the generic un-prefixed "duplicate evidence row" error.
        rows = self._default_rows(prompts)
        rows.append(self._row(
            variant=self.CANDIDATE, prompt_path=prompts[self.CANDIDATE], measured=False, omission=True,
        ))
        cases.append(("duplicate_candidate_row", "profile_batch_incomplete", rows, IMAGE_CONTEXT_EVALUATION_PROFILE_ID))

        # --- G002 blocker 2: every bounded attestation field must be *bound* ------
        # Each case below is a proof that currently "looks" passing: the projection
        # itself is internally consistent, so only an explicit binding rule catches it.

        # available=false while verification is claimed: an unavailable fallback is not proof.
        rows = self._default_rows(prompts, verified_fallback=True)
        rows[1]["evaluation_controls"]["exact_text_fallback"]["available"] = False
        cases.append(("fallback_available_false", "profile_fallback_claim_inconsistent", rows, IMAGE_CONTEXT_EVALUATION_PROFILE_ID))

        # Empty / placeholder receipt id, bound identically on both sides so that only
        # an explicit "must be exact and non-empty" rule can reject it.
        for label, placeholder in (("empty", ""), ("placeholder", "none")):
            rows = self._default_rows(prompts, verified_fallback=True)
            fallback = rows[1]["evaluation_controls"]["exact_text_fallback"]
            fallback["receipt_id"] = placeholder
            fallback["verifier_projection"]["proof_unit"]["receipt_id"] = placeholder
            cases.append((
                f"fallback_{label}_receipt_id", "profile_fallback_claim_inconsistent", rows,
                IMAGE_CONTEXT_EVALUATION_PROFILE_ID,
            ))

        # Empty / placeholder retrieval command: an exact retrieval handle is required.
        for label, placeholder in (("empty", ""), ("placeholder", "none")):
            rows = self._default_rows(prompts, verified_fallback=True)
            rows[1]["evaluation_controls"]["exact_text_fallback"]["retrieval_command"] = placeholder
            cases.append((
                f"fallback_{label}_retrieval_command", "profile_fallback_claim_inconsistent", rows,
                IMAGE_CONTEXT_EVALUATION_PROFILE_ID,
            ))

        # The imported proof may only ever carry the local-only claim boundary.
        rows = self._default_rows(prompts, verified_fallback=True)
        rows[1]["evaluation_controls"]["exact_text_fallback"]["verifier_projection"]["claim_boundary"] = (
            "Semantic safety, freshness, replacement, and hosted-savings authority granted."
        )
        cases.append((
            "fallback_claim_boundary_widened", "profile_fallback_claim_inconsistent", rows,
            IMAGE_CONTEXT_EVALUATION_PROFILE_ID,
        ))

        # Replay may never accept a proof that claims the artifact was rehydrated:
        # replay does not execute, re-read, or re-authenticate the artifact.
        rows = self._default_rows(prompts, verified_fallback=True)
        rows[1]["evaluation_controls"]["exact_text_fallback"]["verifier_projection"]["proof_unit"][
            "rehydration_executed"
        ] = True
        cases.append((
            "fallback_rehydration_executed", "profile_fallback_claim_inconsistent", rows,
            IMAGE_CONTEXT_EVALUATION_PROFILE_ID,
        ))

        # --- G002 blocker 7: an attacker-chosen key name must not be echoed ------
        # _assert_no_leakage (applied to every reject case) proves the secret-shaped
        # key never reaches stdout/stderr.
        rows = self._default_rows(prompts)
        rows[1]["evaluation_controls"]["sk-live-AKIAIOSFODNN7EXAMPLE-not-a-real-key"] = True
        cases.append((
            "unknown_key_secret_shaped", "profile_schema_invalid", rows,
            IMAGE_CONTEXT_EVALUATION_PROFILE_ID,
        ))

        # The same rule applies to a nested block and to the imported projection.
        rows = self._default_rows(prompts)
        rows[1]["evaluation_controls"]["protected_zone_review"][
            "sk-live-AKIAIOSFODNN7EXAMPLE-not-a-real-key"
        ] = True
        cases.append((
            "unknown_nested_key_secret_shaped", "profile_schema_invalid", rows,
            IMAGE_CONTEXT_EVALUATION_PROFILE_ID,
        ))

        return cases

    def test_profile_reject_cases_fail_closed_with_stable_ids_and_zero_writes(self):
        """Structurally invalid/contradictory evidence rejects before any output byte.

        Asserts the exact stable error id, a non-zero exit, and that CSV, ledger,
        report, dashboard, and all four lock sidecars remain absent.
        """
        with tempfile.TemporaryDirectory() as shared:
            probe_prompts = self._write_prompts(Path(shared))
            case_specs = self._reject_cases(Path(shared), probe_prompts)
        self.assertGreaterEqual(len(case_specs), len(PROFILE_REJECT_ERROR_IDS))

        covered = set()
        for index, script in enumerate(BENCH_SCRIPTS):
            for case_id, expected_id, _rows, _profile in case_specs:
                with self.subTest(script=script.name, case=case_id), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    prompts = self._write_prompts(root)
                    # Rebuild rows against this temp dir so prompt hashes bind correctly.
                    rebuilt = {
                        cid: (eid, rws, prof)
                        for cid, eid, rws, prof in self._reject_cases(root, prompts)
                    }
                    expected_id, rows, task_profile = rebuilt[case_id]
                    case = self._write_case(root, rows, task_profile=task_profile)
                    outputs = self._output_paths(root, f"reject{index}")

                    proc = self._run(script, case, outputs)

                    self.assertNotEqual(proc.returncode, 0, f"{case_id} must fail closed")
                    combined = proc.stdout + proc.stderr
                    self.assertIn(expected_id, combined, f"{case_id} must report {expected_id}: {combined}")
                    self._assert_zero_writes(outputs)
                    self._assert_no_leakage(combined, case)
                    covered.add(expected_id)

        # Every reject id in the PRD taxonomy that this suite claims to cover is exercised.
        # The two flag-driven ids cannot be provoked by an evidence row, so each owns a
        # dedicated CLI test: profile_fresh_output_required (resume/pre-existing CSV) and
        # profile_replay_required (profiled task on the direct provider path).
        self.assertEqual(
            covered,
            set(PROFILE_REJECT_ERROR_IDS) - {"profile_fresh_output_required", "profile_replay_required"},
            "fresh-output and replay-required rejections are covered by their own CLI tests",
        )

    def test_profile_replay_rejects_resume_preexisting_csv_and_partial_selection(self):
        """v1 profiled replay requires a fresh, empty CSV and a complete batch."""
        for index, script in enumerate(BENCH_SCRIPTS):
            # --resume is forbidden for a profiled replay.
            with self.subTest(script=script.name, case="resume"), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                prompts = self._write_prompts(root)
                case = self._write_case(root, self._default_rows(prompts))
                outputs = self._output_paths(root, f"resume{index}")
                proc = self._run(script, case, outputs, extra_args=("--resume",))
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("profile_fresh_output_required", proc.stdout + proc.stderr)
                self._assert_zero_writes(outputs)

            # A pre-existing, non-empty CSV is forbidden.
            with self.subTest(script=script.name, case="preexisting_csv"), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                prompts = self._write_prompts(root)
                case = self._write_case(root, self._default_rows(prompts))
                outputs = self._output_paths(root, f"pre{index}")
                module = load_python_script_module(script, f"_bench_profile_freshcsv_{index}")
                with outputs["csv"].open("w", encoding="utf-8", newline="") as handle:
                    writer = csv.DictWriter(handle, fieldnames=module.CSV_COLUMNS)
                    writer.writeheader()
                    writer.writerow({column: "" for column in module.CSV_COLUMNS})
                before = outputs["csv"].read_bytes()

                proc = self._run(script, case, outputs)
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("profile_fresh_output_required", proc.stdout + proc.stderr)
                # The pre-existing CSV must be byte-unchanged, and no other output appears.
                self.assertEqual(outputs["csv"].read_bytes(), before)
                for label in ("ledger", "report", "dashboard"):
                    self.assertFalse(outputs[label].exists())
                    self.assertFalse(outputs[label].with_name(outputs[label].name + ".lock").exists())

            # A partial variant selection cannot cover the full profiled batch.
            with self.subTest(script=script.name, case="partial_selection"), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                prompts = self._write_prompts(root)
                case = self._write_case(root, self._default_rows(prompts))
                outputs = self._output_paths(root, f"partial{index}")
                proc = self._run(script, case, outputs, extra_args=("--variant", self.CANDIDATE))
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("profile_batch_incomplete", proc.stdout + proc.stderr)
                self._assert_zero_writes(outputs)

    # ---------- accepted_blocked taxonomy ---------------------------------

    def test_profile_accepted_blocked_cases_replay_and_emit_stable_lane_blockers(self):
        """Well-formed negative evidence stays reviewable and blocks the lane.

        These must NOT reject: they replay successfully, write outputs, and score
        the lane ``blocked`` with a deterministic blocker id.
        """
        def unverified_fallback(prompts):
            return self._default_rows(prompts, measured=True, verified_fallback=False)

        def protection_not_deny(prompts):
            rows = self._default_rows(prompts, measured=True, verified_fallback=True)
            rows[1]["evaluation_controls"]["protected_zone_review"]["policy"] = "allow"
            return rows

        def protection_review_incomplete(prompts):
            rows = self._default_rows(prompts, measured=True, verified_fallback=True)
            rows[1]["evaluation_controls"]["protected_zone_review"]["review_completed"] = False
            return rows

        def protection_included_region(prompts):
            rows = self._default_rows(prompts, measured=True, verified_fallback=True)
            rows[1]["evaluation_controls"]["protected_zone_review"]["included_protected_regions"] = 1
            return rows

        def missed_context_present(prompts):
            rows = self._default_rows(prompts, measured=True, verified_fallback=True)
            controls = rows[1]["evaluation_controls"]
            controls["missed_context_review"] = {
                "correction_required": False, "present": True, "review_completed": True,
                "summary": "packed evidence omitted one qualifying acknowledgement",
            }
            return rows

        def missed_context_review_incomplete(prompts):
            rows = self._default_rows(prompts, measured=True, verified_fallback=True)
            rows[1]["evaluation_controls"]["missed_context_review"]["review_completed"] = False
            return rows

        def provider_unmeasured(prompts):
            # Internally consistent synthetic evidence: unmeasured everywhere.
            return self._default_rows(prompts, measured=False, verified_fallback=True)

        cases = (
            ("unverified_fallback", unverified_fallback, "exact_text_fallback_binding"),
            ("protection_not_deny", protection_not_deny, "protected_zone_deny_review"),
            ("protection_review_incomplete", protection_review_incomplete, "protected_zone_deny_review"),
            ("protection_included_region", protection_included_region, "protected_zone_deny_review"),
            ("missed_context_present", missed_context_present, "missed_context_review"),
            ("missed_context_incomplete", missed_context_review_incomplete, "missed_context_review"),
            ("provider_unmeasured", provider_unmeasured, "generic_matched_success_and_measurement"),
        )

        for index, script in enumerate(BENCH_SCRIPTS):
            for case_id, build_rows, expected_blocker in cases:
                with self.subTest(script=script.name, case=case_id), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    prompts = self._write_prompts(root)
                    case = self._write_case(root, build_rows(prompts))
                    outputs = self._output_paths(root, f"blocked{index}")

                    proc = self._run(script, case, outputs)
                    self.assertEqual(proc.returncode, 0, f"{case_id} must replay, not reject: {proc.stderr}")

                    report = json.loads(outputs["report"].read_text(encoding="utf-8"))
                    lane = report["evaluation_profiles"][IMAGE_CONTEXT_PROFILE_REPORT_KEY]
                    self.assertEqual(lane["status"], "blocked")
                    self.assertIn(expected_blocker, lane["blocking_gate_ids"])
                    # Blocked can never be dressed up as authority.
                    self.assertFalse(lane["public_claim_allowed"])
                    self.assertFalse(lane["promotion_authority"])
                    self.assertTrue(lane["evaluation_only"])
                    self.assertFalse(report["public_claim_eligible"])
                    self.assertEqual(report["claim_status"], IMAGE_CONTEXT_EVALUATION_ONLY_CLAIM_STATUS)
                    self._assert_no_leakage(outputs["report"].read_text(encoding="utf-8"), case)

    def test_secret_shaped_non_deny_policy_is_blocked_and_redacted_not_echoed(self):
        """Bounded but secret-shaped policy text blocks the lane without ever being echoed."""
        secret = "sk-live-AKIAIOSFODNN7EXAMPLE-not-a-real-key"
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script.name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                prompts = self._write_prompts(root)
                rows = self._default_rows(prompts, measured=True, verified_fallback=True)
                rows[1]["evaluation_controls"]["protected_zone_review"]["policy"] = secret
                case = self._write_case(root, rows)
                outputs = self._output_paths(root, f"secret{index}")

                proc = self._run(script, case, outputs)
                # Within limits -> structurally valid -> accepted_blocked, not a reject.
                self.assertEqual(proc.returncode, 0, proc.stderr)

                report_text = outputs["report"].read_text(encoding="utf-8")
                dashboard_text = outputs["dashboard"].read_text(encoding="utf-8")
                lane = json.loads(report_text)["evaluation_profiles"][IMAGE_CONTEXT_PROFILE_REPORT_KEY]
                self.assertEqual(lane["status"], "blocked")
                self.assertIn("protected_zone_deny_review", lane["blocking_gate_ids"])

                # Raw policy text never reaches any output surface.
                for surface in (report_text, dashboard_text, proc.stdout, proc.stderr):
                    self.assertNotIn(secret, surface)
                    self.assertNotIn("AKIAIOSFODNN7EXAMPLE", surface)

    # ---------- generic compatibility -------------------------------------

    def test_unprofiled_replay_keeps_existing_schema_and_claim_semantics(self):
        """Absence of the profile preserves current generic behavior exactly."""
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script.name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                prompts = self._write_prompts(root)
                rows = [
                    self._row(variant=self.BASELINE, prompt_path=prompts[self.BASELINE], measured=False,
                              omission=False, profile=None, drop_controls=True),
                    self._row(variant=self.CANDIDATE, prompt_path=prompts[self.CANDIDATE], measured=False,
                              omission=True, profile=None, drop_controls=True,
                              input_tokens=400, output_tokens=120, bytes_after=400),
                ]
                case = self._write_case(root, rows, task_profile=None)
                outputs = self._output_paths(root, f"generic{index}")

                proc = self._run(script, case, outputs)
                self.assertEqual(proc.returncode, 0, proc.stderr)

                report = json.loads(outputs["report"].read_text(encoding="utf-8"))
                # No profile -> no lane block, and the pre-existing statuses are untouched.
                self.assertNotIn("evaluation_profiles", report)
                self.assertEqual(report["claim_status"], "replay_only_not_public_claim")
                self.assertEqual(report["public_claim_status"], "replay_only_not_public_claim")
                self.assertFalse(report["public_claim_eligible"])
                self.assertIn("public_claim_readiness", report)
                dashboard = outputs["dashboard"].read_text(encoding="utf-8")
                self.assertNotIn("Image-context evaluation", dashboard)

    def test_profiled_dry_run_stays_write_free(self):
        """--dry-run must not write outputs or locks, profiled or not."""
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script.name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                prompts = self._write_prompts(root)
                case = self._write_case(root, self._default_rows(prompts))
                outputs = self._output_paths(root, f"dry{index}")
                proc = self._run(script, case, outputs, extra_args=("--dry-run",))
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self._assert_zero_writes(outputs)

    # ---------- hostile regressions for the G002 architect blockers --------
    #
    # One test per blocking finding in .omx/reports/g002-architect-block-20260714.md.
    # Each one is an *observable bypass* of an invariant the PRD already promises, so
    # each must fail on the pre-repair runner and pass afterwards.  Every case runs on
    # both the kit source and the packaged CLI (BENCH_SCRIPTS).

    def test_profiled_task_rejects_the_direct_provider_path_before_any_invocation(self):
        """Blocker 1 (CRITICAL): profile opt-in must not be ignorable by dropping --evidence-jsonl.

        Profile validation only ever ran inside the ``--evidence-jsonl`` branch, so a
        profiled task selected on the normal provider path executed the provider and
        emitted a generic ``claim_status`` with no ``evaluation_profiles`` block at all.
        The fixture below is armed to make that bypass observable: a *real*
        ``success_command`` (so the placeholder guard cannot fire instead) and a *working*
        provider binary that records its own execution.
        """
        real_success_command = "python3 -c \"raise SystemExit(0)\""
        for index, script in enumerate(BENCH_SCRIPTS):
            for dry_run in (False, True):
                with self.subTest(script=script.name, dry_run=dry_run), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    prompts = self._write_prompts(root)
                    case = self._write_case(
                        root, self._default_rows(prompts), success_command=real_success_command,
                    )
                    outputs = self._output_paths(root, f"direct{index}")
                    marker = root / "provider-was-invoked"
                    claude_bin = self._recording_claude(root, marker)

                    proc = self._run(
                        script, case, outputs, claude_bin=claude_bin,
                        extra_args=("--dry-run",) if dry_run else (),
                    )

                    self.assertNotEqual(
                        proc.returncode, 0,
                        "a profiled task must never run outside evidence replay",
                    )
                    combined = proc.stdout + proc.stderr
                    self.assertIn("profile_replay_required", combined, combined)
                    # The provider runtime must be unreachable, not merely unsuccessful.
                    self.assertFalse(
                        marker.exists(),
                        "the provider binary was executed for a profiled task",
                    )
                    self._assert_zero_writes(outputs)
                    self._assert_no_leakage(combined, case)

    def test_unprofiled_direct_run_still_invokes_the_provider_and_writes(self):
        """The blocker-1 repair must not amputate the ordinary provider path.

        Same fixture, same real success_command, same working provider -- but with no
        ``evaluation_profile`` declared.  This must still run end to end, or the fix
        for the profiled bypass has broken every generic benchmark run.
        """
        real_success_command = "python3 -c \"raise SystemExit(0)\""
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script.name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                prompts = self._write_prompts(root)
                rows = [
                    self._row(variant=self.BASELINE, prompt_path=prompts[self.BASELINE], measured=False,
                              omission=False, profile=None, drop_controls=True),
                    self._row(variant=self.CANDIDATE, prompt_path=prompts[self.CANDIDATE], measured=False,
                              omission=True, profile=None, drop_controls=True),
                ]
                case = self._write_case(
                    root, rows, task_profile=None, success_command=real_success_command,
                )
                outputs = self._output_paths(root, f"unprofiled{index}")
                marker = root / "provider-was-invoked"
                claude_bin = self._recording_claude(root, marker)

                proc = self._run(script, case, outputs, claude_bin=claude_bin)

                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertTrue(marker.exists(), "the unprofiled provider path must still invoke the provider")
                self.assertTrue(outputs["csv"].exists(), "the unprofiled provider path must still write its CSV")
                report = json.loads(outputs["report"].read_text(encoding="utf-8"))
                self.assertNotIn("evaluation_profiles", report)

    def test_profiled_resume_with_preexisting_csv_rejects_before_creating_a_lock_sidecar(self):
        """Blocker 5 (HIGH): --resume read keys and took a CSV lock *before* profile preflight.

        The combined hostile input is ``--resume`` **and** a pre-existing non-empty CSV.
        Rejection must happen before the resume key snapshot, so the CSV stays
        byte-identical and no ``.lock`` sidecar is ever created.  A lock sidecar left
        behind is a write, and the profile contract promises zero writes on reject.
        """
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script.name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                prompts = self._write_prompts(root)
                case = self._write_case(root, self._default_rows(prompts))
                outputs = self._output_paths(root, f"resumepre{index}")
                module = load_python_script_module(script, f"_bench_profile_resume_lock_{index}")

                with outputs["csv"].open("w", encoding="utf-8", newline="") as handle:
                    writer = csv.DictWriter(handle, fieldnames=module.CSV_COLUMNS)
                    writer.writeheader()
                    writer.writerow({column: "" for column in module.CSV_COLUMNS})
                before = outputs["csv"].read_bytes()

                proc = self._run(script, case, outputs, extra_args=("--resume",))

                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("profile_fresh_output_required", proc.stdout + proc.stderr)
                self.assertEqual(outputs["csv"].read_bytes(), before, "the pre-existing CSV was mutated")
                csv_lock = outputs["csv"].with_name(outputs["csv"].name + ".lock")
                self.assertFalse(
                    csv_lock.exists(),
                    "a CSV lock sidecar was created before the profile preflight rejected",
                )
                for label in ("ledger", "report", "dashboard"):
                    self.assertFalse(outputs[label].exists())
                    self.assertFalse(outputs[label].with_name(outputs[label].name + ".lock").exists())

    def test_profiled_replay_aborts_on_locked_freshness_recheck_without_partial_batch(self):
        """Blocker 5 (HIGH), second half: no single locked batch freshness recheck existed.

        Pure preflight passes against a fresh, absent CSV; then a concurrent writer
        creates the CSV before the first batch write.  Without a locked freshness
        recheck the runner happily appends replay rows onto a CSV it never validated,
        silently mixing profiled and foreign rows.  The recheck must abort the batch
        with the same stable id and leave the concurrent writer's CSV untouched.
        """
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script.name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                prompts = self._write_prompts(root)
                case = self._write_case(root, self._default_rows(prompts))
                outputs = self._output_paths(root, f"race{index}")
                module = load_python_script_module(script, f"_bench_profile_freshness_race_{index}")

                real_preflight = module.preflight_evaluation_profiles

                def racing_preflight(*args, **kwargs):
                    # Pure preflight sees a clean slate and passes...
                    real_preflight(*args, **kwargs)
                    # ...and only then does a concurrent writer create the results CSV.
                    with outputs["csv"].open("w", encoding="utf-8", newline="") as handle:
                        writer = csv.DictWriter(handle, fieldnames=module.CSV_COLUMNS)
                        writer.writeheader()
                        writer.writerow({column: "" for column in module.CSV_COLUMNS})

                argv = [
                    str(script),
                    "--tasks", str(case["tasks"]),
                    "--variants", str(case["variants"]),
                    "--evidence-jsonl", str(case["evidence"]),
                    "--baseline-variant", self.BASELINE,
                    "--claude-bin", "/definitely/missing/contextguard-claude",
                    "--csv", str(outputs["csv"]),
                    "--ledger-jsonl", str(outputs["ledger"]),
                    "--report-json", str(outputs["report"]),
                    "--dashboard-md", str(outputs["dashboard"]),
                ]
                saved_argv = sys.argv
                module.preflight_evaluation_profiles = racing_preflight
                sys.argv = argv
                try:
                    with self.assertRaises(SystemExit) as ctx:
                        module.main()
                finally:
                    sys.argv = saved_argv
                    module.preflight_evaluation_profiles = real_preflight

                self.assertIn("profile_fresh_output_required", str(ctx.exception))
                # Header + the concurrent writer's single row, and nothing appended after it.
                surviving = outputs["csv"].read_text(encoding="utf-8").strip().splitlines()
                self.assertEqual(
                    len(surviving), 2,
                    f"a partial profiled batch was appended to the raced CSV: {surviving}",
                )
                self.assertFalse(
                    outputs["csv"].with_name(outputs["csv"].name + ".lock").exists(),
                    "a rejected raced batch must not leave a CSV lock sidecar",
                )
                for label in ("ledger", "report", "dashboard"):
                    self.assertFalse(outputs[label].exists(), f"{label} was written after a raced CSV")

    def test_profiled_csv_rows_are_one_atomic_batch_against_lock_respecting_writers(self):
        """Freshness validation and every profiled row share one transaction lock.

        The hostile writer uses the runner's public ``append_csv`` path, so it obeys
        the same lock protocol as a real concurrent runner.  Triggering it on the
        first logical row models a writer immediately after the freshness gate;
        triggering it on the second models a writer between the two profile rows.
        In both cases it must remain blocked until the complete profile batch lands.
        """
        placements = (("after_freshness_gate", 1), ("between_logical_rows", 2))
        for index, script in enumerate(BENCH_SCRIPTS):
            for placement, trigger_call in placements:
                with self.subTest(script=script.name, placement=placement), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    prompts = self._write_prompts(root)
                    case = self._write_case(root, self._default_rows(prompts))
                    outputs = self._output_paths(root, f"atomic{index}-{placement}")
                    module = load_python_script_module(
                        script, f"_bench_profile_atomic_{index}_{placement}",
                    )

                    real_run_evidence_fixture = module.run_evidence_fixture
                    call_count = 0
                    attempted = threading.Event()
                    completed = threading.Event()
                    completed_inside_batch = []
                    writer_errors = []
                    writer_threads = []

                    def instrumented_run_evidence_fixture(task, variant, evidence):
                        nonlocal call_count
                        result = real_run_evidence_fixture(task, variant, evidence)
                        call_count += 1
                        if call_count == trigger_call:
                            foreign_result = module.RunResult(**{
                                **result.__dict__,
                                "task_id": "foreign-writer-task",
                                "variant": "foreign-writer-variant",
                            })

                            def foreign_writer():
                                attempted.set()
                                try:
                                    module.append_csv(outputs["csv"], "foreign-writer", foreign_result)
                                except BaseException as exc:  # captured for assertion on the main thread
                                    writer_errors.append(exc)
                                finally:
                                    completed.set()

                            thread = threading.Thread(target=foreign_writer, daemon=True)
                            writer_threads.append(thread)
                            thread.start()
                            self.assertTrue(attempted.wait(1), "foreign writer never attempted its append")
                            completed_inside_batch.append(completed.wait(0.15))
                        return result

                    argv = [
                        str(script),
                        "--tasks", str(case["tasks"]),
                        "--variants", str(case["variants"]),
                        "--evidence-jsonl", str(case["evidence"]),
                        "--baseline-variant", self.BASELINE,
                        "--claude-bin", "/definitely/missing/contextguard-claude",
                        "--csv", str(outputs["csv"]),
                        "--ledger-jsonl", str(outputs["ledger"]),
                        "--report-json", str(outputs["report"]),
                        "--dashboard-md", str(outputs["dashboard"]),
                    ]
                    saved_argv = sys.argv
                    module.run_evidence_fixture = instrumented_run_evidence_fixture
                    sys.argv = argv
                    try:
                        self.assertEqual(module.main(), 0)
                    finally:
                        sys.argv = saved_argv
                        module.run_evidence_fixture = real_run_evidence_fixture
                    for thread in writer_threads:
                        thread.join(2)

                    self.assertEqual(writer_errors, [])
                    self.assertTrue(completed.is_set(), "foreign writer stayed blocked after the batch completed")
                    self.assertEqual(completed_inside_batch, [False], placement)
                    with outputs["csv"].open(newline="", encoding="utf-8") as handle:
                        task_ids = [row["task_id"] for row in csv.DictReader(handle)]
                    self.assertEqual(
                        task_ids[:2], [self.TASK_ID, self.TASK_ID],
                        f"{placement} split the profiled batch: {task_ids}",
                    )
                    self.assertEqual(task_ids[2:], ["foreign-writer-task"])

    def test_profiled_batch_requires_real_baseline_and_candidate_before_writes(self):
        """A one-variant or ghost-baseline batch cannot pass on empty matched pairs."""
        for index, script in enumerate(BENCH_SCRIPTS):
            for case_id in ("baseline_only", "ghost_baseline"):
                with self.subTest(script=script.name, case=case_id), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    prompts = self._write_prompts(root)
                    if case_id == "baseline_only":
                        rows = [self._row(
                            variant=self.BASELINE,
                            prompt_path=prompts[self.BASELINE],
                            measured=True,
                            omission=False,
                        )]
                    else:
                        rows = self._default_rows(prompts, measured=True, verified_fallback=False)
                    case = self._write_case(root, rows)
                    if case_id == "baseline_only":
                        case["variants"].write_text(
                            json.dumps([{"name": self.BASELINE, "extra_args": []}]),
                            encoding="utf-8",
                        )
                        task = json.loads(case["tasks"].read_text(encoding="utf-8"))[0]
                        task["variant_prompt_files"] = {
                            self.BASELINE: task["variant_prompt_files"][self.BASELINE],
                        }
                        case["tasks"].write_text(json.dumps([task]), encoding="utf-8")
                    outputs = self._output_paths(root, f"empty-pairs{index}-{case_id}")

                    proc = self._run(
                        script,
                        case,
                        outputs,
                        baseline_variant=("ghost-profile-baseline" if case_id == "ghost_baseline" else None),
                    )

                    self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                    self.assertIn("profile_batch_incomplete", proc.stdout + proc.stderr)
                    self._assert_zero_writes(outputs)

    def test_profile_fallback_retrieval_command_matches_imported_verifier_projection(self):
        """The exact outer retrieval command is part of the verifier-bound proof unit."""
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script.name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                prompts = self._write_prompts(root)
                rows = self._default_rows(prompts, measured=True, verified_fallback=True)
                rows[1]["evaluation_controls"]["exact_text_fallback"]["retrieval_command"] = (
                    "echo unrelated-command-not-in-verifier-record"
                )
                module = load_python_script_module(script, f"_bench_retrieval_contract_{index}")
                if "retrieval_command" not in module.PROFILE_PROOF_UNIT_KEYS:
                    # Preserve the old valid projection shape so this regression proves
                    # the actual pre-fix acceptance gap rather than failing on a future
                    # field that the old schema does not yet recognize.
                    rows[1]["evaluation_controls"]["exact_text_fallback"][
                        "verifier_projection"
                    ]["proof_unit"].pop("retrieval_command")
                case = self._write_case(root, rows)
                outputs = self._output_paths(root, f"retrieval-mismatch{index}")

                proc = self._run(script, case, outputs)

                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("profile_fallback_claim_inconsistent", proc.stdout + proc.stderr)
                self._assert_zero_writes(outputs)

    def test_unsupported_profile_error_redacts_secret_shaped_task_id(self):
        """Task parsing must sanitize an attacker-controlled id before error output."""
        secret = "sk-live-AKIAIOSFODNN7EXAMPLE-task"
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script.name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                prompts = self._write_prompts(root)
                case = self._write_case(root, self._default_rows(prompts))
                task = json.loads(case["tasks"].read_text(encoding="utf-8"))[0]
                task["id"] = secret
                task["evaluation_profile"] = "contextguard.bench.image-context-pack-evaluation.v999"
                case["tasks"].write_text(json.dumps([task]), encoding="utf-8")
                outputs = self._output_paths(root, f"task-id-redaction{index}")

                proc = self._run(script, case, outputs)

                combined = proc.stdout + proc.stderr
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("profile_schema_invalid", combined)
                self.assertNotIn(secret, combined)
                self.assertNotIn("AKIAIOSFODNN7EXAMPLE", combined)
                self.assertNotIn("sk-", combined)
                self.assertIn("[REDACTED]", combined)
                self._assert_zero_writes(outputs)

    def test_generic_quality_gate_regression_blocks_lane_readiness(self):
        """Blocker 3 (HIGH): lane readiness hard-coded correction consistency to True.

        The lane never read the generic quality verdict, so a profiled batch whose every
        lane control is clean could reach ``ready_for_bounded_pilot_review`` while the
        generic matched-pair gate reported ``corrections_regression``.  The invariant is
        broader than any single gate name: a non-``pass`` generic quality gate must always
        block the lane, whichever gate fired.
        """
        def corrections_regression(prompts):
            # Every lane control is deliberately clean: verified fallback, deny review,
            # completed missed-context review, measured provider and shifted cost.  The
            # *only* defect is that the candidate needed two human corrections.
            return [
                self._row(
                    variant=self.BASELINE, prompt_path=prompts[self.BASELINE], measured=True,
                    omission=False, corrections=0, correction_reason="none", missed_present=False,
                ),
                self._row(
                    variant=self.CANDIDATE, prompt_path=prompts[self.CANDIDATE], measured=True,
                    omission=True, verified_fallback=True, corrections=2,
                    correction_reason="reviewer twice restored the omitted acknowledgement context",
                    missed_present=False, input_tokens=400, output_tokens=120, cost_usd=0.02,
                    bytes_before=1000, bytes_after=400,
                ),
            ]

        def candidate_failure(prompts):
            rows = self._default_rows(prompts, measured=True, verified_fallback=True)
            rows[1]["success"] = False
            return rows

        cases = (
            ("corrections_regression", corrections_regression, "corrections_regression"),
            # A failed candidate cannot reach failure_rate_regression in a one-task v1
            # batch (insufficient_success precedes it), so only the invariant is asserted.
            ("candidate_failure", candidate_failure, None),
        )

        for index, script in enumerate(BENCH_SCRIPTS):
            for case_id, build_rows, expected_blocker in cases:
                with self.subTest(script=script.name, case=case_id), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    prompts = self._write_prompts(root)
                    case = self._write_case(root, build_rows(prompts))
                    outputs = self._output_paths(root, f"quality{index}")

                    proc = self._run(script, case, outputs)
                    # Well-formed negative evidence stays replayable: block, never reject.
                    self.assertEqual(proc.returncode, 0, f"{case_id} must replay, not reject: {proc.stderr}")

                    report = json.loads(outputs["report"].read_text(encoding="utf-8"))
                    lane = report["evaluation_profiles"][IMAGE_CONTEXT_PROFILE_REPORT_KEY]
                    quality_gate = report["comparisons"][0]["quality_gate"]

                    self.assertNotEqual(quality_gate, "pass", f"{case_id} must trip a generic quality gate")
                    if expected_blocker is not None:
                        self.assertEqual(quality_gate, expected_blocker)
                        self.assertIn(expected_blocker, lane["blocking_gate_ids"])
                    # The invariant behind the blocker, independent of which gate fired.
                    self.assertEqual(
                        lane["status"], "blocked",
                        f"lane reached {lane['status']} while the generic quality gate was {quality_gate}",
                    )
                    self.assertNotEqual(lane["status"], "ready_for_bounded_pilot_review")
                    self.assertFalse(lane["public_claim_allowed"])
                    self.assertFalse(lane["promotion_authority"])
                    self.assertFalse(report["public_claim_eligible"])

    def test_nested_replay_authority_is_clamped_in_every_report_surface(self):
        """Blocker 4 (HIGH): nested replay_evidence claim authority stayed unclamped.

        The clamp rewrote the top-level claim surfaces but not
        ``replay_evidence.public_claim_status`` / ``public_claim_eligible``, so the
        strongest profiled fixture still shipped a nested
        ``provider_export_public_claim_candidate`` / ``true`` pair in the report JSON.
        No authority-bearing key may survive anywhere in the document.
        """
        authority_false_keys = {
            "public_claim_eligible",
            "public_claim_allowed",
            "promotion_authority",
            "claim_allowed",
            "report_claim_gates_allow_public_claim",
            "token_savings_claim_allowed",
            "shifted_cost_claim_allowed",
            "hosted_api_token_savings_claim_allowed",
            "hosted_api_cost_savings_claim_allowed",
            "quality_non_inferiority_claim_allowed",
        }

        def walk(node, path="$"):
            if isinstance(node, dict):
                for key, value in node.items():
                    yield path, key, value
                    yield from walk(value, f"{path}.{key}")
            elif isinstance(node, list):
                for position, value in enumerate(node):
                    yield from walk(value, f"{path}[{position}]")

        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script.name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                prompts = self._write_prompts(root)
                # The strongest possible evidence: fully measured provider export with a
                # verified fallback.  Pre-clamp this is a public-claim candidate.
                case = self._write_case(root, self._default_rows(prompts, measured=True, verified_fallback=True))
                outputs = self._output_paths(root, f"nested{index}")

                proc = self._run(script, case, outputs)
                self.assertEqual(proc.returncode, 0, proc.stderr)

                report_text = outputs["report"].read_text(encoding="utf-8")
                report = json.loads(report_text)
                replay_evidence = report["replay_evidence"]

                self.assertEqual(
                    replay_evidence["public_claim_status"], IMAGE_CONTEXT_EVALUATION_ONLY_CLAIM_STATUS
                )
                self.assertFalse(replay_evidence["public_claim_eligible"])
                self.assertFalse(replay_evidence["report_claim_gates_allow_public_claim"])

                # Nothing anywhere in the document may still read as public-claim authority.
                self.assertNotIn("provider_export_public_claim_candidate", report_text)
                for path, key, value in walk(report):
                    if key in authority_false_keys:
                        self.assertIs(
                            value, False,
                            f"{path}.{key} grants authority for a profiled run: {value!r}",
                        )
                    if key == "public_claim_status":
                        self.assertEqual(
                            value, IMAGE_CONTEXT_EVALUATION_ONLY_CLAIM_STATUS,
                            f"{path}.{key} is not clamped",
                        )

    def test_profile_schema_errors_fully_redact_secret_shaped_unknown_keys(self):
        """Blocker 7 (MEDIUM): unknown *key names* are attacker-controlled and were echoed raw.

        ``profile_reject`` interpolates ``', '.join(unknown)`` straight into stderr, so a
        key named after a credential leaks it.  Partial redaction is not enough: the
        generic secret patterns rewrite the ``AKIA...`` body but leave the ``sk-live-``
        prefix standing, which is still a credential shape.  The whole offending key must
        collapse to the redaction placeholder while the stable id survives.
        """
        secret = "sk-live-AKIAIOSFODNN7EXAMPLE-not-a-real-key"
        placements = (
            ("top_level_block", lambda controls: controls.__setitem__(secret, True)),
            ("nested_block", lambda controls: controls["protected_zone_review"].__setitem__(secret, True)),
        )
        for index, script in enumerate(BENCH_SCRIPTS):
            for case_id, place in placements:
                with self.subTest(script=script.name, case=case_id), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    prompts = self._write_prompts(root)
                    rows = self._default_rows(prompts)
                    place(rows[1]["evaluation_controls"])
                    case = self._write_case(root, rows)
                    outputs = self._output_paths(root, f"redact{index}")

                    proc = self._run(script, case, outputs)

                    self.assertNotEqual(proc.returncode, 0)
                    combined = proc.stdout + proc.stderr
                    self.assertIn("profile_schema_invalid", combined)
                    # No fragment of the credential-shaped key may survive.
                    self.assertNotIn(secret, combined)
                    self.assertNotIn("AKIAIOSFODNN7EXAMPLE", combined)
                    self.assertNotIn("sk-", combined)
                    self.assertIn("[REDACTED]", combined)
                    self._assert_zero_writes(outputs)

    # ---------- determinism + source/package parity -----------------------

    def test_profiled_replay_outputs_are_identical_across_source_and_package(self):
        """Kit and packaged CLI must agree byte-for-byte on a profiled replay."""
        rendered = []
        for index, script in enumerate(BENCH_SCRIPTS):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                prompts = self._write_prompts(root)
                case = self._write_case(root, self._default_rows(prompts, measured=True, verified_fallback=True))
                outputs = self._output_paths(root, "parity")
                proc = self._run(script, case, outputs)
                self.assertEqual(proc.returncode, 0, proc.stderr)

                with outputs["csv"].open(newline="", encoding="utf-8") as handle:
                    csv_rows = [
                        {key: value for key, value in row.items() if key != "date"}
                        for row in csv.DictReader(handle)
                    ]
                report = json.loads(outputs["report"].read_text(encoding="utf-8"))
                rendered.append((csv_rows, report, outputs["dashboard"].read_text(encoding="utf-8")))

        self.assertEqual(rendered[0][0], rendered[1][0])
        self.assertEqual(rendered[0][1], rendered[1][1])
        self.assertEqual(rendered[0][2], rendered[1][2])

    def test_profile_gate_and_error_id_ordering_is_deterministic_in_both_copies(self):
        """Stable, identically ordered lane/error id constants in source and package."""
        for index, script in enumerate(BENCH_SCRIPTS):
            with self.subTest(script=script.name):
                module = load_python_script_module(script, f"_bench_profile_constants_{index}")
                self.assertEqual(
                    module.IMAGE_CONTEXT_EVALUATION_PROFILE_ID, IMAGE_CONTEXT_EVALUATION_PROFILE_ID
                )
                self.assertEqual(
                    module.IMAGE_CONTEXT_READINESS_SCHEMA_VERSION, IMAGE_CONTEXT_READINESS_SCHEMA_VERSION
                )
                self.assertEqual(
                    module.IMAGE_CONTEXT_EVALUATION_ONLY_CLAIM_STATUS,
                    IMAGE_CONTEXT_EVALUATION_ONLY_CLAIM_STATUS,
                )
                self.assertEqual(tuple(module.PROFILE_REJECT_ERROR_IDS), PROFILE_REJECT_ERROR_IDS)
                self.assertEqual(tuple(module.IMAGE_CONTEXT_GATE_IDS), IMAGE_CONTEXT_GATE_IDS)


if __name__ == "__main__":
    unittest.main()
