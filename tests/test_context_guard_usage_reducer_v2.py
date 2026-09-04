from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import random
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
KIT_DIR = ROOT / "context-guard-kit"
PLUGIN_DIR = ROOT / "plugins" / "context-guard"
PLUGIN_BIN = PLUGIN_DIR / "bin"
PLUGIN_LIB = PLUGIN_DIR / "lib"
REDUCER_PATH = KIT_DIR / "transcript_usage_reducer.py"
PLUGIN_REDUCER_PATH = PLUGIN_LIB / "transcript_usage_reducer.py"
AUDIT_PATHS = (
    KIT_DIR / "claude_transcript_cost_audit.py",
    PLUGIN_BIN / "context-guard-audit",
)
STATUSLINE_PATHS = (
    KIT_DIR / "statusline.sh",
    PLUGIN_BIN / "context-guard-statusline",
)
MERGED_STATUSLINE_PATH = KIT_DIR / "statusline_merged.sh"


def load_reducer(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load reducer: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def usage_row(
    message_id: str | None,
    *,
    input_tokens: int = 0,
    output_tokens: int = 0,
    cache_read: int = 0,
    cache_creation: int = 0,
    model: str = "claude-test",
    timestamp: object = "2026-07-23T00:00:00Z",
    session_id: str = "session-a",
    extra: dict[str, object] | None = None,
) -> dict[str, object]:
    message: dict[str, object] = {
        "model": model,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cache_read_input_tokens": cache_read,
            "cache_creation_input_tokens": cache_creation,
            "iterations": [
                {
                    "input_tokens": 900_000,
                    "output_tokens": 900_000,
                }
            ],
        },
    }
    if message_id is not None:
        message["id"] = message_id
    row: dict[str, object] = {
        "session_id": session_id,
        "timestamp": timestamp,
        "message": message,
    }
    if extra:
        row.update(extra)
    return row


def run_audit(script: Path, *paths: Path) -> dict[str, object]:
    proc = subprocess.run(
        [sys.executable, str(script), *(str(path) for path in paths), "--json"],
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(proc.stdout)


def run_statusline(
    script: Path,
    transcript: Path,
    *,
    home: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    payload = {
        "model": {"display_name": "Sonnet"},
        "context_window": {"used_percentage": 42},
        "cost": {"total_cost_usd": 0.123},
        "workspace": {"current_dir": str(transcript.parent)},
        "transcript_path": str(transcript),
    }
    env = os.environ.copy()
    env["CONTEXT_GUARD_STATUSLINE_CACHE_TTL_SECONDS"] = "30"
    if home is not None:
        env["HOME"] = str(home)
    return subprocess.run(
        [
            "bash",
            str(script),
            "--approved-python",
            str(Path(sys.executable).resolve()),
        ],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=True,
        env=env,
    )


class UsageReducerV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.reducer = load_reducer(REDUCER_PATH, "_context_guard_usage_reducer_v2_tests")

    def reduce(self, rows: list[dict[str, object]], *, file_identity: str = "f" * 64):
        reducer = self.reducer.UsageReducer()
        for ordinal, row in enumerate(rows):
            reducer.observe(row, file_identity=file_identity, row_ordinal=ordinal)
        return reducer.finalize()

    def test_golden_repeated_message_counts_selected_usage_once(self):
        rows = [
            usage_row("response-1", input_tokens=100, output_tokens=20),
            usage_row(
                "response-1",
                input_tokens=100,
                output_tokens=20,
                timestamp="2026-07-23T00:00:01Z",
            ),
        ]
        result = self.reduce(rows)
        self.assertEqual(result.tokens, {"input": 100, "output": 20})
        self.assertEqual(result.by_model, {"claude-test": {"input": 100, "output": 20}})
        self.assertEqual(result.counters["usage_conflict"], 0)
        self.assertFalse(result.partial)
        self.assertEqual(len(result.selections), 1)
        self.assertEqual(result.selections[0].row_ordinal, 1)

    def test_scope_includes_file_and_session(self):
        reducer = self.reducer.UsageReducer()
        reducer.observe(
            usage_row("same-id", input_tokens=10, session_id="session-a"),
            file_identity="a" * 64,
            row_ordinal=0,
        )
        reducer.observe(
            usage_row("same-id", input_tokens=20, session_id="session-b"),
            file_identity="a" * 64,
            row_ordinal=1,
        )
        reducer.observe(
            usage_row("same-id", input_tokens=30, session_id="session-a"),
            file_identity="b" * 64,
            row_ordinal=2,
        )
        result = reducer.finalize()
        self.assertEqual(result.tokens["input"], 60)
        self.assertEqual(len(result.selections), 3)

    def test_timestamp_then_ordinal_precedence_and_conflict(self):
        rows = [
            usage_row("valid-wins", input_tokens=10, timestamp="2026-07-23T00:00:02Z"),
            usage_row("valid-wins", input_tokens=99, timestamp=None),
            usage_row("later-valid", input_tokens=20, timestamp="2026-07-23T00:00:00Z"),
            usage_row("later-valid", input_tokens=30, timestamp="2026-07-23T00:00:01Z"),
            usage_row("ordinal", input_tokens=40, timestamp="bad"),
            usage_row("ordinal", input_tokens=50, timestamp=None),
            usage_row("equal", input_tokens=60, timestamp="2026-07-23T00:00:03Z"),
            usage_row("equal", input_tokens=70, timestamp="2026-07-23T00:00:03Z"),
        ]
        result = self.reduce(rows)
        self.assertEqual(result.tokens["input"], 10 + 30 + 50 + 70)
        self.assertEqual(result.counters["usage_conflict"], 4)
        self.assertTrue(result.partial)

    def test_invalid_uint63_candidates_and_checked_total_overflow(self):
        maximum = self.reducer.UINT63_MAX
        rows = [
            usage_row("a", input_tokens=maximum),
            usage_row("b", input_tokens=1),
            usage_row("negative", input_tokens=-1),
            usage_row("too-large", input_tokens=maximum + 1),
            usage_row("bool", input_tokens=True),  # type: ignore[arg-type]
            usage_row("float", input_tokens=1.5),  # type: ignore[arg-type]
        ]
        result = self.reduce(rows)
        self.assertEqual(result.tokens["input"], maximum)
        self.assertEqual(result.counters["numeric_overflow"], 1)
        self.assertEqual(result.counters["invalid_numeric"], 4)
        self.assertTrue(result.partial)

    def test_no_id_content_hash_dedupes_exact_rows_only(self):
        first = usage_row(None, input_tokens=7, extra={"content": "a"})
        second = usage_row(None, input_tokens=7, extra={"content": "b"})
        result = self.reduce([first, first, second])
        self.assertEqual(result.tokens["input"], 14)
        self.assertEqual(result.counters["no_id_fallback"], 2)
        self.assertEqual(len(result.selections), 2)

    def test_no_id_non_utf8_canonical_row_is_rejected_without_crashing(self):
        row = usage_row(None, input_tokens=7, extra={"content": "\ud800"})
        result = self.reduce([row])
        self.assertEqual(result.tokens, {})
        self.assertEqual(result.counters["invalid_row"], 1)
        self.assertTrue(result.partial)

    def test_aliases_normalize_before_conflict_comparison(self):
        canonical = usage_row("same", input_tokens=10)
        alias = usage_row("same", input_tokens=10)
        canonical_usage = canonical["message"]["usage"]  # type: ignore[index]
        alias_usage = alias["message"]["usage"]  # type: ignore[index]
        canonical_usage["cache_read_input_tokens"] = 5  # type: ignore[index]
        alias_usage.pop("cache_read_input_tokens")  # type: ignore[union-attr]
        alias_usage["cacheRead"] = 5  # type: ignore[index]
        result = self.reduce([canonical, alias])
        self.assertEqual(result.tokens, {"cache_read": 5, "input": 10})
        self.assertEqual(result.counters["usage_conflict"], 0)
        self.assertFalse(result.partial)

    def test_only_message_usage_is_eligible(self):
        rows = [
            {"usage": {"input_tokens": 10}},
            {"response": {"usage": {"input_tokens": 20}}},
            {"metric": {"name": "claude_code.token.usage", "value": 30}},
            {
                "message": {
                    "id": "content-only",
                    "content": {"usage": {"input_tokens": 40}},
                }
            },
            usage_row("eligible", input_tokens=50),
        ]
        result = self.reduce(rows)
        self.assertEqual(result.tokens, {"input": 50})
        self.assertEqual(result.counters["eligible_candidates"], 1)
        self.assertEqual(result.counters["ineligible_usage_shape"], 4)
        self.assertTrue(result.partial)

    def test_properties_duplication_permutation_idempotence_and_content_invariance(self):
        rng = random.Random(3272)
        rows = [
            usage_row(
                f"id-{index}",
                input_tokens=rng.randint(0, 1000),
                output_tokens=rng.randint(0, 1000),
                timestamp=f"2026-07-23T00:00:{index:02d}Z",
            )
            for index in range(20)
        ]
        baseline = self.reduce(rows)
        duplicate = self.reduce(rows + rows)
        shuffled_rows = list(rows)
        rng.shuffle(shuffled_rows)
        shuffled = self.reduce(shuffled_rows)
        with_content = self.reduce(rows + [{"content": "no usage"}, {"message": {"content": "x"}}])
        self.assertEqual(duplicate.tokens, baseline.tokens)
        self.assertEqual(shuffled.tokens, baseline.tokens)
        self.assertEqual(with_content.tokens, baseline.tokens)
        self.assertEqual(self.reduce(rows).tokens, baseline.tokens)

    def test_canonical_and_plugin_reducers_are_byte_identical(self):
        self.assertEqual(REDUCER_PATH.read_bytes(), PLUGIN_REDUCER_PATH.read_bytes())
        self.assertEqual(
            hashlib.sha256(REDUCER_PATH.read_bytes()).hexdigest(),
            hashlib.sha256(PLUGIN_REDUCER_PATH.read_bytes()).hexdigest(),
        )


class UsageReducerConsumerTests(unittest.TestCase):
    def test_audit_directory_discovers_jsonl_only_and_explicit_json_parses_once(self):
        for script in AUDIT_PATHS:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                jsonl_path = root / "session.jsonl"
                ignored_json = root / "metadata.json"
                explicit_json = root / "pretty.json"
                jsonl_path.write_text(
                    json.dumps(usage_row("jsonl", input_tokens=100, output_tokens=20)) + "\n",
                    encoding="utf-8",
                )
                ignored_json.write_text(
                    json.dumps(usage_row("ignored", input_tokens=9000), indent=2),
                    encoding="utf-8",
                )
                explicit_json.write_text(
                    json.dumps(
                        [
                            usage_row("json-a", input_tokens=30),
                            usage_row("json-b", input_tokens=40),
                        ],
                        indent=2,
                    ),
                    encoding="utf-8",
                )

                directory_data = run_audit(script, root)
                self.assertEqual(directory_data["tokens"], {"input": 100, "output": 20})
                self.assertEqual(directory_data["files"], 1)

                explicit_data = run_audit(script, explicit_json)
                self.assertEqual(explicit_data["tokens"], {"input": 70})
                self.assertEqual(explicit_data["records"], 2)
                self.assertEqual(explicit_data["skipped_records"], 0)
                self.assertEqual(explicit_data["usage_reducer"]["schema"], "usage-reducer-v2")

    def test_explicit_json_mixed_array_is_bounded_and_partial(self):
        for script in AUDIT_PATHS:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as tmp:
                sample = Path(tmp) / "mixed.json"
                sample.write_text(
                    json.dumps(
                        [
                            usage_row("ok", input_tokens=10),
                            7,
                            "invalid",
                            {"message": {"id": "content", "content": "no usage"}},
                        ],
                        indent=2,
                    ),
                    encoding="utf-8",
                )
                data = run_audit(script, sample)
                self.assertEqual(data["tokens"], {"input": 10})
                self.assertEqual(data["records"], 2)
                self.assertEqual(data["skipped_records"], 2)
                self.assertEqual(data["usage_reducer"]["invalid_row"], 2)
                self.assertTrue(data["usage_reducer"]["partial"])
                self.assertEqual(data["scan_integrity"]["status"], "partial")

    def test_noncanonical_usage_shape_is_excluded_and_disclosed_as_partial(self):
        for script in AUDIT_PATHS:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as tmp:
                transcript = Path(tmp) / "schema-drift.jsonl"
                transcript.write_text(
                    json.dumps({"response": {"usage": {"input_tokens": 900}}})
                    + "\n"
                    + json.dumps(usage_row("canonical", input_tokens=50))
                    + "\n",
                    encoding="utf-8",
                )
                data = run_audit(script, transcript)
                self.assertEqual(data["tokens"], {"input": 50})
                self.assertEqual(data["usage_reducer"]["ineligible_usage_shape"], 1)
                self.assertTrue(data["usage_reducer"]["partial"])
                self.assertEqual(data["scan_integrity"]["status"], "partial")

    def test_statusline_discloses_ineligible_usage_shape_as_partial(self):
        for script in STATUSLINE_PATHS:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                transcript = root / "schema-drift.jsonl"
                rows = [
                    {"response": {"usage": {"input_tokens": 900}}},
                    usage_row(
                        "canonical",
                        input_tokens=100,
                        cache_read=800,
                        cache_creation=100,
                    ),
                ]
                transcript.write_text(
                    "".join(json.dumps(row) + "\n" for row in rows),
                    encoding="utf-8",
                )
                proc = run_statusline(script, transcript, home=root / "home")
                self.assertIn("cache 80%", proc.stdout)
                self.assertIn("usage_tail_v2 window_partial=true", proc.stdout)

    def test_audit_and_statusline_share_selected_usage(self):
        for audit_script, statusline_script in zip(AUDIT_PATHS, STATUSLINE_PATHS):
            with (
                self.subTest(audit=audit_script, statusline=statusline_script),
                tempfile.TemporaryDirectory() as tmp,
            ):
                root = Path(tmp)
                transcript = root / "session.jsonl"
                rows = [
                    usage_row(
                        "same",
                        input_tokens=100,
                        cache_read=800,
                        cache_creation=100,
                        timestamp="2026-07-23T00:00:00Z",
                    ),
                    usage_row(
                        "same",
                        input_tokens=100,
                        cache_read=50,
                        cache_creation=50,
                        timestamp="2026-07-23T00:00:01Z",
                    ),
                ]
                transcript.write_text(
                    "".join(json.dumps(row) + "\n" for row in rows),
                    encoding="utf-8",
                )

                audit = run_audit(audit_script, transcript)
                self.assertEqual(
                    audit["tokens"],
                    {"cache_creation": 50, "cache_read": 50, "input": 100},
                )
                self.assertEqual(audit["usage_reducer"]["usage_conflict"], 1)
                self.assertTrue(audit["usage_reducer"]["partial"])

                statusline = run_statusline(statusline_script, transcript, home=root / "home")
                self.assertIn("cache 25%", statusline.stdout)
                self.assertIn("reuse 1.0x", statusline.stdout)
                self.assertIn("usage_tail_v2", statusline.stdout)
                self.assertIn("window_partial=true", statusline.stdout)

    def test_statusline_marks_bounded_record_window_and_v2_cache(self):
        for script in STATUSLINE_PATHS:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                workspace = root / "workspace"
                workspace.mkdir()
                transcript = workspace / "session.jsonl"
                rows = [
                    usage_row(
                        f"id-{index}",
                        input_tokens=1,
                        cache_read=8,
                        cache_creation=1,
                        timestamp=f"2026-07-23T00:{index // 60:02d}:{index % 60:02d}Z",
                    )
                    for index in range(301)
                ]
                transcript.write_text(
                    "".join(json.dumps(row) + "\n" for row in rows),
                    encoding="utf-8",
                )
                home = root / "home"
                proc = run_statusline(script, transcript, home=home)
                self.assertIn("usage_tail_v2", proc.stdout)
                self.assertIn("window_partial=true", proc.stdout)
                cache_files = list((home / ".cache" / "context-guard" / "statusline").glob("*.json"))
                self.assertEqual(len(cache_files), 1)
                cache_file = cache_files[0]
                cached = json.loads(cache_file.read_text(encoding="utf-8"))
                self.assertEqual(cached["reducer_schema"], "usage-reducer-v2")
                self.assertEqual(cached["metric_label"], "usage_tail_v2")
                self.assertTrue(cached["window_partial"])
                self.assertEqual(stat.S_IMODE(cache_file.stat().st_mode), 0o600)
                cache_text = cache_file.read_text(encoding="utf-8")
                self.assertNotIn(str(transcript), cache_text)
                self.assertNotIn(str(root), cache_text)

    def test_statusline_marks_byte_tail_partial_and_replaces_v1_cache(self):
        for script in STATUSLINE_PATHS:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                workspace = root / "workspace"
                workspace.mkdir()
                transcript = workspace / "session.jsonl"
                final_row = usage_row("final", input_tokens=100, cache_read=800, cache_creation=100)
                transcript.write_text(
                    json.dumps({"content": "x" * (1024 * 1024 + 128)})
                    + "\n"
                    + json.dumps(final_row)
                    + "\n",
                    encoding="utf-8",
                )
                home = root / "home"
                cache_dir = home / ".cache" / "context-guard" / "statusline"
                cache_dir.mkdir(parents=True, mode=0o700)
                os.chmod(cache_dir, 0o700)
                path_hash = hashlib.sha256(os.fsencode(os.path.abspath(transcript))).hexdigest()
                old_cache = cache_dir / f"{path_hash}.json"
                old_cache.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "computed_at": 9_999_999_999,
                            "cache_pct": "99",
                            "reuse_x": "99.0",
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                os.chmod(old_cache, 0o600)

                proc = run_statusline(script, transcript, home=home)
                self.assertIn("cache 80%", proc.stdout)
                self.assertNotIn("cache 99%", proc.stdout)
                self.assertIn("window_partial=true", proc.stdout)
                replaced = json.loads(old_cache.read_text(encoding="utf-8"))
                self.assertEqual(replaced["schema_version"], 2)
                self.assertEqual(replaced["reducer_schema"], "usage-reducer-v2")

    def test_statusline_without_local_reducer_omits_metrics_with_bounded_diagnostic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "statusline.sh"
            script.write_bytes((KIT_DIR / "statusline.sh").read_bytes())
            os.chmod(script, 0o755)
            transcript = root / "session.jsonl"
            transcript.write_text(
                json.dumps(usage_row("id", input_tokens=100, cache_read=800, cache_creation=100)) + "\n",
                encoding="utf-8",
            )
            proc = run_statusline(script, transcript, home=root / "home")
            self.assertNotIn("cache ", proc.stdout)
            self.assertIn("usage reducer unavailable", proc.stderr)
            self.assertLessEqual(len(proc.stderr.encode("utf-8")), 160)

    def test_npm_style_statusline_symlink_loads_only_packaged_reducer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            bin_dir = project / "node_modules" / ".bin"
            bin_dir.mkdir(parents=True)
            linked = bin_dir / "context-guard-statusline"
            linked.symlink_to(PLUGIN_BIN / "context-guard-statusline")
            canary = project / "untrusted-imported"
            (project / "transcript_usage_reducer.py").write_text(
                "from pathlib import Path\n"
                f"Path({str(canary)!r}).write_text('imported')\n"
                "raise RuntimeError('untrusted cwd module imported')\n",
                encoding="utf-8",
            )
            transcript = project / "session.jsonl"
            transcript.write_text(
                json.dumps(
                    usage_row(
                        "id",
                        input_tokens=100,
                        cache_read=800,
                        cache_creation=100,
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            payload = {
                "model": {"display_name": "Sonnet"},
                "context_window": {"used_percentage": 42},
                "cost": {"total_cost_usd": 0.123},
                "workspace": {"current_dir": str(project)},
                "transcript_path": str(transcript),
            }
            env = os.environ.copy()
            env["HOME"] = str(root / "home")
            proc = subprocess.run(
                [
                    "bash",
                    str(linked),
                    "--approved-python",
                    str(Path(sys.executable).resolve()),
                ],
                cwd=project,
                input=json.dumps(payload),
                text=True,
                capture_output=True,
                check=True,
                env=env,
            )
            self.assertIn("cache 80%", proc.stdout)
            self.assertIn("usage_tail_v2 window_partial=false", proc.stdout)
            self.assertFalse(canary.exists())
            self.assertNotIn("UNTRUSTED", proc.stderr)

    def test_merged_statusline_preserves_usage_window_disclosure(self):
        for partial in ("true", "false"):
            with self.subTest(partial=partial), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                fake_bin = root / "bin"
                fake_bin.mkdir()
                node = fake_bin / "node"
                node.write_text("#!/usr/bin/env bash\nprintf '[omc] hud\\n'\n", encoding="utf-8")
                node.chmod(0o755)
                omc = root / "omc-hud.mjs"
                omc.write_text("// test fixture\n", encoding="utf-8")
                token_statusline = root / "context-guard-statusline"
                token_statusline.write_text(
                    "#!/usr/bin/env bash\n"
                    "cat >/dev/null\n"
                    f"printf '[Sonnet] project | ctx 42%% | cost $0.123 | cache 80%% | reuse 8.0x | usage_tail_v2 window_partial={partial}\\n'\n",
                    encoding="utf-8",
                )
                token_statusline.chmod(0o755)
                proc = subprocess.run(
                    [
                        "/bin/bash",
                        "--noprofile",
                        "--norc",
                        str(MERGED_STATUSLINE_PATH),
                        "--approved-node",
                        str(node),
                        "--approved-omc-script",
                        str(omc),
                        "--approved-token-statusline",
                        str(token_statusline),
                    ],
                    input='{"session_id":"test"}',
                    text=True,
                    capture_output=True,
                    check=True,
                )
                self.assertIn("[omc] hud", proc.stdout)
                self.assertIn("cache 80%", proc.stdout)
                self.assertIn(
                    f"usage_tail_v2 window_partial={partial}",
                    proc.stdout,
                )

    def test_consumer_pairs_are_byte_identical(self):
        self.assertEqual(AUDIT_PATHS[0].read_bytes(), AUDIT_PATHS[1].read_bytes())
        self.assertEqual(STATUSLINE_PATHS[0].read_bytes(), STATUSLINE_PATHS[1].read_bytes())


if __name__ == "__main__":
    unittest.main()
