from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
PACK_SCRIPT = ROOT / "context-guard-kit" / "context_pack.py"


def load_pack_module(name: str):
    spec = importlib.util.spec_from_file_location(name, PACK_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load context pack module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def descendant_pipe_command(pid_path: Path, marker_path: Path) -> list[str]:
    child_code = (
        "import os, pathlib, sys, time; "
        "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()), encoding='utf-8'); "
        "time.sleep(1.0); "
        "pathlib.Path(sys.argv[2]).write_text('survived', encoding='utf-8')"
    )
    parent_code = (
        "import pathlib, subprocess, sys, time; "
        "pid_path = pathlib.Path(sys.argv[1]); "
        "subprocess.Popen([sys.executable, '-c', sys.argv[3], sys.argv[1], sys.argv[2]], "
        "stdout=sys.stdout.buffer, stderr=sys.stderr); "
        "deadline = time.monotonic() + 0.5; "
        "\nwhile not pid_path.exists() and time.monotonic() < deadline: time.sleep(0.01); "
        "\nsys.stdout.buffer.write(b'x' * 4096); sys.stdout.buffer.flush(); time.sleep(5.0)"
    )
    return [sys.executable, "-c", parent_code, str(pid_path), str(marker_path), child_code]


class ContextPackP1P2HardeningTests(unittest.TestCase):
    def test_markdown_block_uses_content_derived_fence_and_escapes_metadata(self):
        module = load_pack_module("_context_pack_fence_red")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = "odd`name.txt"
            (root / path).write_text("before\n```\n# CONTENT_HEADING\nafter\n", encoding="utf-8")
            result = module.build_pack(
                root,
                [module.SourceSpec(path=path, label="title`\n# METADATA_HEADING\x07")],
                budget_bytes=8_000,
                root_arg=".",
                store_artifact=False,
            )

        pack = result["pack"]
        self.assertNotIn("\n# METADATA_HEADING", pack)
        self.assertNotIn("\x07", pack)
        self.assertIn("\n````text\nbefore\n```\n# CONTENT_HEADING\nafter\n````\n", pack)
        self.assertEqual(pack.count("\n````text\n"), 1)
        self.assertIn("odd`name.txt", pack)

    def test_markdown_metadata_and_path_code_spans_are_inert(self):
        module = load_pack_module("_context_pack_markdown_inert_red")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = "odd```[link](javascript:alert(1))&entity.txt"
            (root / path).write_text("safe\n", encoding="utf-8")
            result = module.build_pack(
                root,
                [
                    module.SourceSpec(
                        path=path,
                        label="<img src=x onerror=alert(1)> [click](javascript:alert(1)) &#10;",
                    )
                ],
                budget_bytes=8_000,
                root_arg=".",
                store_artifact=False,
            )

        pack = result["pack"]
        title = next(line for line in pack.splitlines() if line.startswith("## "))
        source = next(line for line in pack.splitlines() if line.startswith("Source: "))
        self.assertNotIn("<img", title)
        self.assertNotIn("[click](javascript:", title)
        self.assertNotIn("&#10;", title)
        self.assertIn("&lt;img", title)
        self.assertIn("\\[click\\]\\(javascript:alert\\(1\\)\\)", title)
        self.assertIn("&amp;#10;", title)
        self.assertTrue(source.startswith("Source: ````"), source)
        self.assertTrue(source.endswith("````"), source)
        self.assertIn(path, source)

    def test_ranged_source_sanitizes_only_through_requested_end_and_reports_bounded_tail_scan(self):
        module = load_pack_module("_context_pack_range_red")

        class StatefulSanitizer:
            def __init__(self):
                self.active = False
                self.calls = 0

            def sanitize(self, line: str):
                self.calls += 1
                if "BEGIN_PRIVATE" in line:
                    self.active = True
                if self.active and "SECRET_BODY" in line:
                    return "[REDACTED-BODY]\n", True
                return line, False

        sanitizer = StatefulSanitizer()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "long.txt").write_text(
                "BEGIN_PRIVATE\nkeep\nSECRET_BODY\nend\n" + "tail\n" * 200,
                encoding="utf-8",
            )
            with mock.patch.object(module, "load_line_sanitizer", return_value=sanitizer):
                source, omitted = module.resolve_source(
                    root,
                    module.SourceSpec(path="long.txt", lines=module.LineRange(2, 4)),
                )

        self.assertIsNone(omitted)
        self.assertIsNotNone(source)
        self.assertEqual(sanitizer.calls, 4)
        self.assertEqual(source.selected_lines, ["keep\n", "[REDACTED-BODY]\n", "end\n"])
        self.assertTrue(source.total_lines_exact)
        self.assertEqual(source.total_lines, 204)
        self.assertEqual(source.sanitized_through_line, 4)

    def test_source_and_cumulative_limits_fail_closed_with_cap_metadata(self):
        module = load_pack_module("_context_pack_limits_red")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "wide.txt").write_text("x" * 64 + "\n", encoding="utf-8")
            with mock.patch.object(module, "MAX_SOURCE_LINE_BYTES", 16, create=True):
                wide = module.build_pack(
                    root,
                    [module.SourceSpec(path="wide.txt")],
                    budget_bytes=8_000,
                    root_arg=".",
                    store_artifact=False,
                )
            self.assertIn("source_line_bytes_exceeded", {item["reason"] for item in wide["omitted_sources"]})
            wide_omission = next(item for item in wide["omitted_sources"] if item["reason"] == "source_line_bytes_exceeded")
            self.assertEqual(wide_omission["input_limit"]["cap_bytes"], 16)

            (root / "one.txt").write_text("12345\n", encoding="utf-8")
            (root / "two.txt").write_text("abcde\n", encoding="utf-8")
            with (
                mock.patch.object(module, "MAX_SOURCE_INPUT_BYTES", 100, create=True),
                mock.patch.object(module, "MAX_TOTAL_SOURCE_INPUT_BYTES", 8, create=True),
            ):
                cumulative = module.build_pack(
                    root,
                    [module.SourceSpec(path="one.txt"), module.SourceSpec(path="two.txt")],
                    budget_bytes=8_000,
                    root_arg=".",
                    store_artifact=False,
                )
            self.assertIn(
                "cumulative_input_bytes_exceeded",
                {item["reason"] for item in cumulative["omitted_sources"]},
            )
            capped = next(
                item
                for item in cumulative["omitted_sources"]
                if item["reason"] == "cumulative_input_bytes_exceeded"
            )
            self.assertEqual(capped["input_limit"]["cap_bytes"], 8)

    def test_rejected_overlong_read_charges_cumulative_budget_before_next_source(self):
        module = load_pack_module("_context_pack_attempted_budget_red")
        read_attempts = 0
        original_open = module.open_regular_under_root

        class CountedHandle:
            def __init__(self, handle):
                self.handle = handle

            def __enter__(self):
                return self

            def __exit__(self, *_exc):
                self.handle.close()
                return False

            def __getattr__(self, name):
                return getattr(self.handle, name)

            def readline(self, *args, **kwargs):
                nonlocal read_attempts
                value = self.handle.readline(*args, **kwargs)
                if value:
                    read_attempts += 1
                return value

        def counted_open(root, rel):
            handle, reason = original_open(root, rel)
            return (CountedHandle(handle), reason) if handle is not None else (None, reason)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            specs = []
            for index in range(4):
                path = f"wide-{index}.txt"
                (root / path).write_text("ABCDE\n", encoding="utf-8")
                specs.append(module.SourceSpec(path=path))
            with (
                mock.patch.object(module, "open_regular_under_root", side_effect=counted_open),
                mock.patch.object(module, "MAX_SOURCE_LINE_BYTES", 4),
                mock.patch.object(module, "MAX_SOURCE_INPUT_BYTES", 100),
                mock.patch.object(module, "MAX_TOTAL_SOURCE_INPUT_BYTES", 5),
            ):
                result = module.build_pack(
                    root,
                    specs,
                    budget_bytes=8_000,
                    root_arg=".",
                    store_artifact=False,
                )

        self.assertEqual(read_attempts, 1)
        self.assertEqual(result["input"]["bytes_read"], 5)
        self.assertEqual(result["input"]["bytes_attempted"], 5)
        self.assertEqual(result["input"]["lines_attempted"], 1)
        self.assertTrue(result["input"]["capped"])
        reasons = [item["reason"] for item in result["omitted_sources"]]
        self.assertEqual(reasons.count("source_line_bytes_exceeded"), 1)
        self.assertEqual(reasons.count("cumulative_input_bytes_exceeded"), 3)
        first = next(item for item in result["omitted_sources"] if item["reason"] == "source_line_bytes_exceeded")
        self.assertEqual(first["input_observed"]["bytes"], 5)
        self.assertEqual(first["input_observed"]["lines"], 1)

    def test_graph_bind_rejection_is_reused_without_reopening_source(self):
        module = load_pack_module("_context_pack_graph_rejection_cache_red")
        original_open = module.open_regular_under_root
        original_apply = module.apply_symbol_memory_graph
        count_graph_opens = False
        helper_opens = 0

        def counted_open(root, rel):
            nonlocal helper_opens
            if count_graph_opens and rel.as_posix() == "src/helper.py":
                helper_opens += 1
            return original_open(root, rel)

        def tighten_line_cap_after_repo_map(manifest, repo_map, **kwargs):
            nonlocal count_graph_opens
            result = original_apply(manifest, repo_map, **kwargs)
            module.MAX_SOURCE_LINE_BYTES = 4
            count_graph_opens = True
            return result

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "one.py").write_text(
                "from .helper import helper\n\ndef one():\n    return helper()\n",
                encoding="utf-8",
            )
            (root / "src" / "helper.py").write_text(
                "def helper():\n    return 'too-wide-after-map'\n",
                encoding="utf-8",
            )
            args = module.build_parser().parse_args(
                [
                    "auto",
                    "--root",
                    str(root),
                    "--files",
                    "src/one.py",
                    "--top",
                    "1",
                    "--budget-bytes",
                    "8000",
                    "--no-artifact",
                    "--json",
                    "--apply-symbol-memory",
                ]
            )
            with (
                mock.patch.object(module, "open_regular_under_root", side_effect=counted_open),
                mock.patch.object(module, "apply_symbol_memory_graph", side_effect=tighten_line_cap_after_repo_map),
            ):
                payload, rc = module.auto_pack(root, args, root_arg=str(root))

        self.assertEqual(rc, 0)
        self.assertEqual(helper_opens, 1)
        self.assertIn(
            "source_line_bytes_exceeded",
            {item["reason"] for item in payload["build"]["omitted_sources"]},
        )
        self.assertNotIn("too-wide-after-map", payload["build"]["pack"])

    def test_exact_input_caps_are_inclusive_for_a_complete_regular_file(self):
        module = load_pack_module("_context_pack_exact_caps_red")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "exact.txt").write_text("12345\n", encoding="utf-8")
            with (
                mock.patch.object(module, "MAX_SOURCE_INPUT_BYTES", 6),
                mock.patch.object(module, "MAX_SOURCE_INPUT_LINES", 1),
                mock.patch.object(module, "MAX_TOTAL_SOURCE_INPUT_BYTES", 6),
                mock.patch.object(module, "MAX_TOTAL_SOURCE_INPUT_LINES", 1),
            ):
                result = module.build_pack(
                    root,
                    [module.SourceSpec(path="exact.txt")],
                    budget_bytes=8_000,
                    root_arg=".",
                    store_artifact=False,
                )

        self.assertEqual(result["sources"]["included"], 1)
        self.assertEqual(result["omitted_sources"], [])
        self.assertTrue(result["included_sources"][0]["input"]["total_lines_exact"])

    def test_ranged_source_discloses_inexact_total_when_tail_count_hits_cap(self):
        module = load_pack_module("_context_pack_tail_cap_red")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "many.txt").write_text("".join(f"line-{index}\n" for index in range(20)), encoding="utf-8")
            with mock.patch.object(module, "MAX_SOURCE_INPUT_LINES", 5, create=True):
                result = module.build_pack(
                    root,
                    [module.SourceSpec(path="many.txt", lines=module.LineRange(1, 2))],
                    budget_bytes=8_000,
                    root_arg=".",
                    store_artifact=False,
                )

        item = result["included_sources"][0]
        self.assertIn("input", item)
        self.assertTrue(item["input"]["truncated"])
        self.assertFalse(item["input"]["total_lines_exact"])
        self.assertEqual(item["input"]["total_lines_lower_bound"], 5)
        self.assertEqual(item["input"]["limit_reason"], "source_input_lines_exceeded")
        self.assertEqual(item["input"]["limits"]["source_lines"], 5)
        self.assertIn("redacted_lines_exact", result["redaction"])
        self.assertFalse(result["redaction"]["redacted_lines_exact"])

    def test_git_diff_rejects_capped_output_instead_of_capturing_unbounded_result(self):
        git = shutil_which("git")
        if git is None:
            self.skipTest("git unavailable")
        module = load_pack_module("_context_pack_diff_red")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run([git, "init", "-q"], cwd=root, check=True)
            subprocess.run([git, "config", "user.email", "test@example.invalid"], cwd=root, check=True)
            subprocess.run([git, "config", "user.name", "Context Pack Test"], cwd=root, check=True)
            (root / "large.txt").write_text("before\n", encoding="utf-8")
            subprocess.run([git, "add", "large.txt"], cwd=root, check=True)
            subprocess.run([git, "commit", "-qm", "init"], cwd=root, check=True)
            (root / "large.txt").write_text("".join(f"changed-{index:04d}\n" for index in range(200)), encoding="utf-8")
            with mock.patch.object(module, "MAX_SUGGEST_INPUT_BYTES", 128):
                with self.assertRaisesRegex(module.PackError, "diff output exceeds cap"):
                    module.run_git_diff(root, "HEAD")

    def test_git_diff_and_listing_disable_repository_fsmonitor_execution(self):
        git = shutil_which("git")
        if git is None:
            self.skipTest("git unavailable")
        module = load_pack_module("_context_pack_repo_fsmonitor_red")
        for operation in ("diff", "ls-files"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                marker = root / "fsmonitor-ran"
                monitor = root / "fsmonitor.sh"
                monitor.write_text(
                    "#!/bin/sh\n"
                    f": > {str(marker)!r}\n"
                    "exit 0\n",
                    encoding="utf-8",
                )
                monitor.chmod(0o700)
                subprocess.run([git, "init", "-q"], cwd=root, check=True)
                subprocess.run([git, "config", "user.email", "test@example.invalid"], cwd=root, check=True)
                subprocess.run([git, "config", "user.name", "Context Pack Test"], cwd=root, check=True)
                (root / "tracked.txt").write_text("before\n", encoding="utf-8")
                subprocess.run([git, "add", "tracked.txt"], cwd=root, check=True)
                subprocess.run([git, "commit", "-qm", "init"], cwd=root, check=True)
                subprocess.run([git, "config", "core.fsmonitor", str(monitor)], cwd=root, check=True)
                (root / "tracked.txt").write_text("after\n", encoding="utf-8")

                if operation == "diff":
                    module.run_git_diff(root, "HEAD")
                else:
                    module.git_ls_files(root)

                self.assertFalse(marker.exists(), f"{operation} executed repository fsmonitor")

    def test_git_diff_and_listing_scrub_ambient_config_injection(self):
        git = shutil_which("git")
        if git is None:
            self.skipTest("git unavailable")
        module = load_pack_module("_context_pack_ambient_git_config_red")
        for operation in ("diff", "ls-files"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                marker = root / "ambient-fsmonitor-ran"
                monitor = root / "ambient-fsmonitor.sh"
                monitor.write_text(
                    "#!/bin/sh\n"
                    f": > {str(marker)!r}\n"
                    "exit 0\n",
                    encoding="utf-8",
                )
                monitor.chmod(0o700)
                global_config = root / "ambient.gitconfig"
                global_config.write_text(
                    "[core]\n"
                    f"\tfsmonitor = {monitor}\n",
                    encoding="utf-8",
                )
                subprocess.run([git, "init", "-q"], cwd=root, check=True)
                subprocess.run([git, "config", "user.email", "test@example.invalid"], cwd=root, check=True)
                subprocess.run([git, "config", "user.name", "Context Pack Test"], cwd=root, check=True)
                (root / "tracked.txt").write_text("before\n", encoding="utf-8")
                subprocess.run([git, "add", "tracked.txt"], cwd=root, check=True)
                subprocess.run([git, "commit", "-qm", "init"], cwd=root, check=True)
                (root / "tracked.txt").write_text("after\n", encoding="utf-8")
                injected_environment = {
                    "GIT_CONFIG_COUNT": "1",
                    "GIT_CONFIG_KEY_0": "core.fsmonitor",
                    "GIT_CONFIG_VALUE_0": str(monitor),
                    "GIT_CONFIG_GLOBAL": str(global_config),
                    "GIT_CONFIG_SYSTEM": str(global_config),
                    "GIT_ASKPASS": str(monitor),
                    "SSH_ASKPASS": str(monitor),
                }

                with mock.patch.dict(os.environ, injected_environment, clear=False):
                    if operation == "diff":
                        module.run_git_diff(root, "HEAD")
                    else:
                        module.git_ls_files(root)

                self.assertFalse(marker.exists(), f"{operation} honored ambient Git config")

    def test_git_diff_rejects_worktree_and_info_attribute_filters_before_execution(self):
        git = shutil_which("git")
        if git is None:
            self.skipTest("git unavailable")
        module = load_pack_module("_context_pack_git_filter_attr_red")
        for driver_kind, attribute_source in (("clean", "worktree"), ("process", "info")):
            with (
                self.subTest(driver_kind=driver_kind, attribute_source=attribute_source),
                tempfile.TemporaryDirectory() as tmp,
            ):
                root = Path(tmp)
                marker = root / f"{driver_kind}-filter-ran"
                driver = root / f"{driver_kind}-filter.sh"
                driver.write_text(
                    "#!/bin/sh\n"
                    f": > {str(marker)!r}\n"
                    + ("cat\n" if driver_kind == "clean" else "exit 1\n"),
                    encoding="utf-8",
                )
                driver.chmod(0o700)
                subprocess.run([git, "init", "-q"], cwd=root, check=True)
                subprocess.run([git, "config", "user.email", "test@example.invalid"], cwd=root, check=True)
                subprocess.run([git, "config", "user.name", "Context Pack Test"], cwd=root, check=True)
                (root / "tracked.txt").write_text("before\n", encoding="utf-8")
                subprocess.run([git, "add", "tracked.txt"], cwd=root, check=True)
                subprocess.run([git, "commit", "-qm", "init"], cwd=root, check=True)
                if attribute_source == "worktree":
                    (root / ".gitattributes").write_text("*.txt filter=evil\n", encoding="utf-8")
                else:
                    (root / ".git" / "info" / "attributes").write_text(
                        "*.txt filter=evil\n",
                        encoding="utf-8",
                    )
                subprocess.run(
                    [git, "config", f"filter.evil.{driver_kind}", str(driver)],
                    cwd=root,
                    check=True,
                )
                subprocess.run([git, "config", "filter.evil.required", "true"], cwd=root, check=True)
                (root / "tracked.txt").write_text("after\n", encoding="utf-8")

                blocked = False
                try:
                    module.run_git_diff(root, "HEAD")
                except module.PackError:
                    blocked = True

                self.assertTrue(blocked, f"{driver_kind} filter was not rejected")
                self.assertFalse(marker.exists(), f"{driver_kind} filter executed before rejection")

    def test_git_diff_neutralizes_filter_drivers_named_like_check_attr_sentinels(self):
        git = shutil_which("git")
        if git is None:
            self.skipTest("git unavailable")
        module = load_pack_module("_context_pack_git_filter_sentinel_red")
        for driver_name in ("unset", "unspecified"):
            for driver_kind in ("clean", "process"):
                with (
                    self.subTest(driver_name=driver_name, driver_kind=driver_kind),
                    tempfile.TemporaryDirectory() as tmp,
                ):
                    root = Path(tmp)
                    marker = root / f"{driver_name}-{driver_kind}-ran"
                    driver = root / f"{driver_name}-{driver_kind}.sh"
                    driver.write_text(
                        "#!/bin/sh\n"
                        f": > {str(marker)!r}\n"
                        + ("cat\n" if driver_kind == "clean" else "exit 1\n"),
                        encoding="utf-8",
                    )
                    driver.chmod(0o700)
                    subprocess.run([git, "init", "-q"], cwd=root, check=True)
                    subprocess.run([git, "config", "user.email", "test@example.invalid"], cwd=root, check=True)
                    subprocess.run([git, "config", "user.name", "Context Pack Test"], cwd=root, check=True)
                    (root / "tracked.txt").write_text("before\n", encoding="utf-8")
                    subprocess.run([git, "add", "tracked.txt"], cwd=root, check=True)
                    subprocess.run([git, "commit", "-qm", "init"], cwd=root, check=True)
                    (root / ".gitattributes").write_text(
                        f"*.txt filter={driver_name}\n",
                        encoding="utf-8",
                    )
                    subprocess.run(
                        [git, "config", f"filter.{driver_name}.{driver_kind}", str(driver)],
                        cwd=root,
                        check=True,
                    )
                    subprocess.run(
                        [git, "config", f"filter.{driver_name}.required", "true"],
                        cwd=root,
                        check=True,
                    )
                    (root / "tracked.txt").write_text("after\n", encoding="utf-8")

                    error = None
                    try:
                        module.run_git_diff(root, "HEAD")
                    except module.PackError as exc:
                        error = exc

                    self.assertIsNone(error, f"neutralized {driver_name}.{driver_kind} failed")
                    self.assertFalse(marker.exists(), f"{driver_name}.{driver_kind} executed")

    def test_git_diff_preserves_genuine_unset_filter_attribute(self):
        git = shutil_which("git")
        if git is None:
            self.skipTest("git unavailable")
        module = load_pack_module("_context_pack_git_filter_genuine_unset")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root / "unset-driver-ran"
            driver = root / "unset-driver.sh"
            driver.write_text(
                "#!/bin/sh\n"
                f": > {str(marker)!r}\n"
                "cat\n",
                encoding="utf-8",
            )
            driver.chmod(0o700)
            subprocess.run([git, "init", "-q"], cwd=root, check=True)
            subprocess.run([git, "config", "user.email", "test@example.invalid"], cwd=root, check=True)
            subprocess.run([git, "config", "user.name", "Context Pack Test"], cwd=root, check=True)
            (root / "tracked.txt").write_text("before\n", encoding="utf-8")
            subprocess.run([git, "add", "tracked.txt"], cwd=root, check=True)
            subprocess.run([git, "commit", "-qm", "init"], cwd=root, check=True)
            (root / ".gitattributes").write_text("*.txt -filter\n", encoding="utf-8")
            subprocess.run([git, "config", "filter.unset.clean", str(driver)], cwd=root, check=True)
            subprocess.run([git, "config", "filter.unset.required", "true"], cwd=root, check=True)
            (root / "tracked.txt").write_text("after\n", encoding="utf-8")

            diff_text = module.run_git_diff(root, "HEAD")

        self.assertIn("tracked.txt", diff_text)
        self.assertFalse(marker.exists())

    def test_filter_preflight_accepts_2001_short_paths_while_query_listing_stays_capped(self):
        git = shutil_which("git")
        if git is None:
            self.skipTest("git unavailable")
        module = load_pack_module("_context_pack_filter_preflight_many_paths_red")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run([git, "init", "-q"], cwd=root, check=True)
            subprocess.run([git, "config", "user.email", "test@example.invalid"], cwd=root, check=True)
            subprocess.run([git, "config", "user.name", "Context Pack Test"], cwd=root, check=True)
            for index in range(2001):
                (root / f"f{index:04d}.txt").write_text("x\n", encoding="utf-8")
            subprocess.run([git, "add", "."], cwd=root, check=True)
            subprocess.run([git, "commit", "-qm", "many paths"], cwd=root, check=True)
            (root / "f2000.txt").write_text("changed\n", encoding="utf-8")

            error = None
            diff_text = ""
            try:
                diff_text = module.run_git_diff(root, "HEAD")
            except module.PackError as exc:
                error = exc
            diagnostics: dict[str, object] = {}
            query_paths = module.git_ls_files(root, diagnostics)

        self.assertIsNone(error)
        self.assertIn("f2000.txt", diff_text)
        self.assertEqual(len(query_paths), 2000)
        self.assertTrue(diagnostics["truncated"])
        self.assertEqual(diagnostics["truncation_reason"], "file_cap")

    def test_git_diff_does_not_descend_into_repo_controlled_submodule(self):
        git = shutil_which("git")
        if git is None:
            self.skipTest("git unavailable")
        module = load_pack_module("_context_pack_submodule_no_descend_red")
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            child_origin = workspace / "child-origin"
            root = workspace / "root"
            child_origin.mkdir()
            root.mkdir()
            for repo in (child_origin, root):
                subprocess.run([git, "init", "-q"], cwd=repo, check=True)
                subprocess.run([git, "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
                subprocess.run([git, "config", "user.name", "Context Pack Test"], cwd=repo, check=True)
            (child_origin / "child.txt").write_text("before\n", encoding="utf-8")
            subprocess.run([git, "add", "child.txt"], cwd=child_origin, check=True)
            subprocess.run([git, "commit", "-qm", "child init"], cwd=child_origin, check=True)
            (root / "root.txt").write_text("root\n", encoding="utf-8")
            subprocess.run([git, "add", "root.txt"], cwd=root, check=True)
            subprocess.run([git, "commit", "-qm", "root init"], cwd=root, check=True)
            subprocess.run(
                [git, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(child_origin), "sub"],
                cwd=root,
                check=True,
            )
            subprocess.run([git, "commit", "-qam", "add submodule"], cwd=root, check=True)
            submodule = root / "sub"
            marker = workspace / "submodule-fsmonitor-ran"
            monitor = workspace / "submodule-fsmonitor.sh"
            monitor.write_text(
                "#!/bin/sh\n"
                f": > {str(marker)!r}\n"
                "exit 0\n",
                encoding="utf-8",
            )
            monitor.chmod(0o700)
            subprocess.run([git, "config", "core.fsmonitor", str(monitor)], cwd=submodule, check=True)
            (submodule / "child.txt").write_text("dirty submodule\n", encoding="utf-8")

            module.run_git_diff(root, "HEAD")

        self.assertFalse(marker.exists(), "parent diff descended into submodule fsmonitor")

    def test_non_posix_git_paths_fail_closed_before_resolve_or_spawn(self):
        module = load_pack_module("_context_pack_non_posix_git_red")

        class NonPosixOS:
            name = "nt"

            def __init__(self, real_os, search_path: str):
                self._real_os = real_os
                self.defpath = search_path
                self.pathsep = real_os.pathsep
                self.devnull = real_os.devnull
                self.X_OK = real_os.X_OK

            def __getattr__(self, name):
                return getattr(self._real_os, name)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root / "fake-git-ran"
            fake_git = root / "git.exe"
            fake_git.write_text(
                "#!/bin/sh\n"
                f": > {str(marker)!r}\n"
                "exit 0\n",
                encoding="utf-8",
            )
            fake_git.chmod(0o700)
            (root / "tracked.txt").write_text("local fallback\n", encoding="utf-8")
            popen_calls = 0

            def marker_popen(*_args, **_kwargs):
                nonlocal popen_calls
                popen_calls += 1
                marker.write_text("spawned", encoding="utf-8")
                raise OSError("fake git spawn")

            with (
                mock.patch.object(module, "os", NonPosixOS(os, str(root))),
                mock.patch.object(module.subprocess, "Popen", side_effect=marker_popen),
            ):
                with self.assertRaises(module.PackError):
                    module.run_git_diff(root, "HEAD")
                diagnostics: dict[str, object] = {}
                files = module.git_ls_files(root, diagnostics)

        self.assertEqual(popen_calls, 0)
        self.assertFalse(marker.exists())
        self.assertIn("tracked.txt", files)
        self.assertEqual(diagnostics["mode"], "walk")

    def test_capped_process_kills_descendants_that_inherit_output_pipes(self):
        if os.name != "posix" or not hasattr(os, "killpg"):
            self.skipTest("POSIX process groups unavailable")
        module = load_pack_module("_context_pack_process_group_red")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pid_path = root / "child.pid"
            marker_path = root / "child-survived"
            started = time.monotonic()
            _returncode, _stdout, _stderr, stdout_capped, _failed = module._run_process_capped(
                descendant_pipe_command(pid_path, marker_path),
                stdout_cap=64,
                stderr_cap=64,
                timeout_seconds=2.0,
            )
            elapsed = time.monotonic() - started
            time.sleep(1.1)

            self.assertTrue(stdout_capped)
            self.assertLess(elapsed, 1.0)
            self.assertTrue(pid_path.exists())
            self.assertFalse(marker_path.exists())
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pid_path.read_text(encoding="utf-8")), 0)

    def test_git_file_listing_kills_capped_descendants_and_starts_new_session(self):
        if os.name != "posix" or not hasattr(os, "killpg"):
            self.skipTest("POSIX process groups unavailable")
        module = load_pack_module("_context_pack_git_listing_group_red")
        real_popen = module.subprocess.Popen
        observed_new_sessions: list[object] = []
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pid_path = root / "listing-child.pid"
            marker_path = root / "listing-child-survived"

            def replacement_popen(_command, *args, **kwargs):
                observed_new_sessions.append(kwargs.get("start_new_session"))
                return real_popen(descendant_pipe_command(pid_path, marker_path), *args, **kwargs)

            started = time.monotonic()
            with (
                mock.patch.object(module.subprocess, "Popen", side_effect=replacement_popen),
                mock.patch.object(module, "MAX_GIT_LS_FILES_OUTPUT_BYTES", 64),
            ):
                diagnostics: dict[str, object] = {}
                module.git_ls_files(root, diagnostics)
            elapsed = time.monotonic() - started
            time.sleep(1.1)

            self.assertEqual(observed_new_sessions, [True])
            self.assertLess(elapsed, 1.0)
            self.assertTrue(pid_path.exists())
            self.assertFalse(marker_path.exists())
            self.assertTrue(diagnostics["truncated"])
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pid_path.read_text(encoding="utf-8")), 0)

    def test_non_git_walk_caps_are_disclosed_in_suggest_payload(self):
        module = load_pack_module("_context_pack_walk_red")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(4):
                directory = root / f"d{index}"
                directory.mkdir()
                (directory / "match.txt").write_text("needle\n", encoding="utf-8")
            args = module.build_parser().parse_args(
                ["suggest", "--root", str(root), "--query", "needle", "--json"]
            )
            with mock.patch.object(module, "MAX_QUERY_WALK_DIRS", 1, create=True):
                payload, rc = module.suggest_pack(root, args, root_arg=str(root))

        self.assertEqual(rc, 0)
        self.assertIn("query_scan", payload)
        self.assertTrue(payload["query_scan"]["truncated"])
        self.assertEqual(payload["query_scan"]["truncation_reason"], "directory_cap")
        self.assertIn("query_scan_truncated", {item["reason"] for item in payload["omitted_sources"]})

    def test_auto_reuses_each_source_sanitization_and_rejects_identity_drift(self):
        module = load_pack_module("_context_pack_auto_snapshot_red")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "one.txt").write_text("one\n", encoding="utf-8")
            (root / "two.txt").write_text("two\n", encoding="utf-8")
            args = module.build_parser().parse_args(
                [
                    "auto",
                    "--root",
                    str(root),
                    "--files",
                    "one.txt,two.txt",
                    "--budget-bytes",
                    "8000",
                    "--no-artifact",
                    "--json",
                ]
            )
            original_loader = module.load_line_sanitizer
            source_sanitizers = 0

            def counted_loader(*args, **kwargs):
                nonlocal source_sanitizers
                if kwargs.get("context", "unknown_text") == "source_code":
                    source_sanitizers += 1
                return original_loader(*args, **kwargs)

            with mock.patch.object(module, "load_line_sanitizer", side_effect=counted_loader):
                payload, rc = module.auto_pack(root, args, root_arg=str(root))

            self.assertEqual(rc, 0)
            self.assertEqual(payload["sources"]["included"], 2)
            self.assertEqual(source_sanitizers, 2)

            drift_args = module.build_parser().parse_args(
                [
                    "auto",
                    "--root",
                    str(root),
                    "--files",
                    "one.txt",
                    "--budget-bytes",
                    "8000",
                    "--no-artifact",
                    "--json",
                ]
            )
            original_manifest_to_specs = module.manifest_to_source_specs

            def drift_before_build(manifest):
                specs = original_manifest_to_specs(manifest)
                (root / "one.txt").write_text("changed after suggest\n", encoding="utf-8")
                os.utime(root / "one.txt", None)
                return specs

            with mock.patch.object(module, "manifest_to_source_specs", side_effect=drift_before_build):
                drifted, drift_rc = module.auto_pack(root, drift_args, root_arg=str(root))

        self.assertEqual(drift_rc, 0)
        self.assertEqual(drifted["sources"]["included"], 0)
        self.assertIn(
            "source_changed_during_auto",
            {item["reason"] for item in drifted["build"]["omitted_sources"]},
        )
        self.assertNotIn("changed after suggest", drifted["build"]["pack"])

    def test_apply_symbol_memory_final_build_reuses_snapshot_and_rejects_seed_drift(self):
        module = load_pack_module("_context_pack_symbol_seed_snapshot_red")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            seed = root / "src" / "one.py"
            seed.write_text(
                "from .helper import helper\n\ndef one():\n    return helper()\n",
                encoding="utf-8",
            )
            (root / "src" / "helper.py").write_text(
                "def helper():\n    return 'snapshot-helper'\n",
                encoding="utf-8",
            )
            args = module.build_parser().parse_args(
                [
                    "auto",
                    "--root",
                    str(root),
                    "--files",
                    "src/one.py",
                    "--top",
                    "1",
                    "--budget-bytes",
                    "8000",
                    "--no-artifact",
                    "--json",
                    "--apply-symbol-memory",
                ]
            )
            original_apply = module.apply_symbol_memory_graph
            original_loader = module.load_line_sanitizer
            source_sanitizers = 0

            def mutate_seed_during_apply(manifest, repo_map, **kwargs):
                result = original_apply(manifest, repo_map, **kwargs)
                seed.write_text("MUTATED_DURING_GRAPH_APPLY\n", encoding="utf-8")
                os.utime(seed, None)
                return result

            def counted_loader(*loader_args, **loader_kwargs):
                nonlocal source_sanitizers
                if loader_kwargs.get("context", "unknown_text") == "source_code":
                    source_sanitizers += 1
                return original_loader(*loader_args, **loader_kwargs)

            with (
                mock.patch.object(module, "apply_symbol_memory_graph", side_effect=mutate_seed_during_apply),
                mock.patch.object(module, "load_line_sanitizer", side_effect=counted_loader),
            ):
                payload, rc = module.auto_pack(root, args, root_arg=str(root))

        self.assertEqual(rc, 0)
        self.assertEqual(source_sanitizers, 2)
        self.assertNotIn("MUTATED_DURING_GRAPH_APPLY", payload["build"]["pack"])
        self.assertIn(
            "source_changed_during_auto",
            {item["reason"] for item in payload["build"]["omitted_sources"]},
        )
        self.assertIn("snapshot-helper", payload["build"]["pack"])

    def test_apply_symbol_memory_rejects_source_added_after_repo_map_snapshot(self):
        module = load_pack_module("_context_pack_symbol_addition_snapshot_red")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "one.py").write_text("def one():\n    return 'one'\n", encoding="utf-8")
            injected = root / "src" / "injected.py"
            args = module.build_parser().parse_args(
                [
                    "auto",
                    "--root",
                    str(root),
                    "--files",
                    "src/one.py",
                    "--top",
                    "1",
                    "--budget-bytes",
                    "8000",
                    "--no-artifact",
                    "--json",
                    "--apply-symbol-memory",
                ]
            )
            original_apply = module.apply_symbol_memory_graph

            def add_source_during_apply(manifest, repo_map, **kwargs):
                result_manifest, application = original_apply(manifest, repo_map, **kwargs)
                injected.write_text("ADDED_AFTER_REPO_MAP\n", encoding="utf-8")
                sources = list(result_manifest["sources"])
                added = {
                    "path": "src/injected.py",
                    "priority": 1,
                    "label": "graph:src/injected.py",
                    "lines": {"start": 1, "end": 1},
                }
                sources.append(added)
                application = copy_dict(application)
                application["selected_source_count"] = int(application["selected_source_count"]) + 1
                application["selected_sources"] = list(application["selected_sources"]) + [
                    {
                        "path": "src/injected.py",
                        "priority": 1,
                        "lines": {"start": 1, "end": 1},
                        "reason": "direct_import_neighbor",
                    }
                ]
                return module.build_suggest_manifest(sources), application

            with mock.patch.object(module, "apply_symbol_memory_graph", side_effect=add_source_during_apply):
                payload, rc = module.auto_pack(root, args, root_arg=str(root))

        self.assertEqual(rc, 0)
        self.assertNotIn("ADDED_AFTER_REPO_MAP", payload["build"]["pack"])
        self.assertIn(
            "graph_source_not_in_repo_map_snapshot",
            {item["reason"] for item in payload["build"]["omitted_sources"]},
        )


def copy_dict(value: dict[str, object]) -> dict[str, object]:
    return {key: item for key, item in value.items()}


def shutil_which(command: str) -> str | None:
    from shutil import which

    return which(command)


if __name__ == "__main__":
    unittest.main()
