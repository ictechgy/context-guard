from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KIT_DIR = ROOT / "context-guard-kit"
PLUGIN_DIR = ROOT / "plugins" / "context-guard"
PACK_SCRIPTS = [
    KIT_DIR / "context_pack.py",
    PLUGIN_DIR / "bin" / "context-guard-pack",
]


class ContextGuardProgressiveContextTests(unittest.TestCase):
    def _run_pack(
        self,
        script: Path,
        cwd: Path,
        *args: str,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(script), *args],
            cwd=cwd,
            text=True,
            capture_output=True,
            check=check,
        )

    def test_auto_explicitly_applies_adaptive_k_without_pruning_explicit_files(
        self,
    ) -> None:
        for script in PACK_SCRIPTS:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "src").mkdir()
                (root / "src" / "alpha_failure.py").write_text(
                    "alpha failure alpha failure alpha failure\n",
                    encoding="utf-8",
                )
                (root / "src" / "alpha_helper.py").write_text(
                    "alpha helper\n",
                    encoding="utf-8",
                )
                (root / "src" / "alpha_notes.py").write_text(
                    "alpha notes\n",
                    encoding="utf-8",
                )
                (root / "KEEP.md").write_text(
                    "explicit source\n",
                    encoding="utf-8",
                )

                common = [
                    "auto",
                    "--root",
                    ".",
                    "--query",
                    "alpha failure",
                    "--files",
                    "KEEP.md",
                    "--top",
                    "4",
                    "--budget-bytes",
                    "4000",
                    "--json",
                    "--no-artifact",
                ]
                advisory = json.loads(
                    self._run_pack(script, root, *common, "--adaptive-k").stdout
                )
                applied = json.loads(
                    self._run_pack(script, root, *common, "--apply-adaptive-k").stdout
                )

                recommended = advisory["adaptive_k"]["recommended_k"]
                self.assertGreater(
                    len(advisory["manifest"]["sources"]),
                    recommended,
                )
                self.assertLess(
                    len(applied["manifest"]["sources"]),
                    len(advisory["manifest"]["sources"]),
                )
                self.assertIn(
                    "KEEP.md",
                    [item["path"] for item in applied["manifest"]["sources"]],
                )
                application = applied["adaptive_k_application"]
                self.assertEqual(application["mode"], "explicit_opt_in")
                self.assertEqual(application["recommended_k"], recommended)
                self.assertEqual(
                    application["applied_source_count"],
                    len(applied["manifest"]["sources"]),
                )
                self.assertEqual(
                    len(applied["suggest"]["sources"]),
                    len(applied["manifest"]["sources"]),
                )
                self.assertGreater(application["omitted_source_count"], 0)
                self.assertTrue(application["regression_gates_passed"])
                self.assertTrue(application["explicit_sources_retained"])
                self.assertFalse(
                    application["claim_boundary"][
                        "provider_token_or_cost_savings_claim_allowed"
                    ]
                )
                self.assertLess(applied["pack_bytes"], advisory["pack_bytes"])
                self.assertIn("KEEP.md", applied["build"]["pack"])
                applied_text = self._run_pack(
                    script,
                    root,
                    *(arg for arg in common if arg != "--json"),
                    "--apply-adaptive-k",
                ).stdout
                self.assertIn("apply=true", applied_text)

                gated = json.loads(
                    self._run_pack(
                        script,
                        root,
                        *common,
                        "--apply-adaptive-k",
                        "--adaptive-k-min-precision-proxy",
                        "1.0",
                    ).stdout
                )
                self.assertEqual(
                    gated["adaptive_k_application"]["status"],
                    "gate_failed",
                )
                self.assertFalse(
                    gated["adaptive_k_application"]["regression_gates_passed"]
                )
                self.assertEqual(gated["manifest"], advisory["manifest"])
                gated_text = self._run_pack(
                    script,
                    root,
                    *(arg for arg in common if arg != "--json"),
                    "--apply-adaptive-k",
                    "--adaptive-k-min-precision-proxy",
                    "1.0",
                ).stdout
                self.assertIn("apply=false", gated_text)
                self.assertNotIn("apply=true", gated_text)

    def test_auto_explicitly_applies_direct_graph_neighbors(self) -> None:
        for script in PACK_SCRIPTS:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "src").mkdir()
                (root / "src" / "app.py").write_text(
                    "from .helper import helper\n\n"
                    "def entrypoint():\n"
                    "    return helper()\n",
                    encoding="utf-8",
                )
                (root / "src" / "helper.py").write_text(
                    "def helper():\n"
                    "    return 'graph-selected'\n",
                    encoding="utf-8",
                )
                common = [
                    "auto",
                    "--root",
                    ".",
                    "--files",
                    "src/app.py",
                    "--query",
                    "entrypoint",
                    "--top",
                    "1",
                    "--budget-bytes",
                    "5000",
                    "--json",
                    "--no-artifact",
                ]
                baseline = json.loads(
                    self._run_pack(script, root, *common).stdout
                )
                applied = json.loads(
                    self._run_pack(
                        script,
                        root,
                        *common,
                        "--apply-symbol-memory",
                    ).stdout
                )

                self.assertEqual(
                    [item["path"] for item in baseline["manifest"]["sources"]],
                    ["src/app.py"],
                )
                self.assertEqual(
                    [item["path"] for item in applied["manifest"]["sources"]],
                    ["src/app.py", "src/helper.py"],
                )
                self.assertIn("graph-selected", applied["build"]["pack"])
                self.assertEqual(
                    applied["suggest"]["estimated_pack_bytes"],
                    applied["pack_bytes"],
                )
                self.assertEqual(
                    applied["suggest"]["token_proxy"],
                    applied["token_proxy"],
                )
                graph = applied["graph_application"]
                self.assertEqual(
                    graph["schema_version"],
                    "contextguard.pack-graph-application.v1",
                )
                self.assertEqual(graph["mode"], "explicit_opt_in")
                self.assertEqual(graph["selected_source_count"], 1)
                self.assertEqual(
                    graph["selected_sources"][0]["path"],
                    "src/helper.py",
                )
                self.assertEqual(
                    graph["selected_sources"][0]["reason"],
                    "direct_import_neighbor",
                )
                self.assertTrue(graph["exact_source_fallback_retained"])
                self.assertFalse(
                    graph["provider_token_or_cost_savings_claim_allowed"]
                )
                self.assertEqual(applied["symbol_memory"]["mode"], "applied")

                explained = json.loads(
                    self._run_pack(
                        script,
                        root,
                        *common,
                        "--apply-symbol-memory",
                        "--explain",
                    ).stdout
                )
                self.assertEqual(
                    explained["explain"]["graph_application"],
                    explained["graph_application"],
                )

    def test_graph_application_excludes_secret_risk_neighbors(self) -> None:
        secret = "ghp_" + ("A" * 36)
        for script in PACK_SCRIPTS:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "src").mkdir()
                (root / "src" / "app.py").write_text(
                    "from .credentials import value\n\n"
                    "def entrypoint():\n"
                    "    return value\n",
                    encoding="utf-8",
                )
                (root / "src" / "credentials.py").write_text(
                    f"value = {secret!r}\n",
                    encoding="utf-8",
                )
                proc = self._run_pack(
                    script,
                    root,
                    "auto",
                    "--root",
                    ".",
                    "--files",
                    "src/app.py",
                    "--top",
                    "1",
                    "--budget-bytes",
                    "5000",
                    "--json",
                    "--no-artifact",
                    "--apply-symbol-memory",
                )
                applied = json.loads(proc.stdout)

                self.assertNotIn(secret, proc.stdout + proc.stderr)
                self.assertEqual(
                    [item["path"] for item in applied["manifest"]["sources"]],
                    ["src/app.py"],
                )
                graph = applied["graph_application"]
                self.assertEqual(graph["selected_source_count"], 0)
                self.assertEqual(graph["excluded_secret_risk_count"], 1)

    def test_graph_application_excludes_risk_neighbor_beyond_public_file_cap(self) -> None:
        secret = "ghp_" + ("B" * 36)
        for script in PACK_SCRIPTS:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source_dir = root / "src"
                source_dir.mkdir()
                (source_dir / "app.py").write_text(
                    "from .z_credentials import value\n\n"
                    "def entrypoint():\n"
                    "    return value\n",
                    encoding="utf-8",
                )
                for index in range(20):
                    (source_dir / f"a_risk_{index:02d}.py").write_text(
                        f"value = {secret!r}\n",
                        encoding="utf-8",
                    )
                (source_dir / "z_credentials.py").write_text(
                    f"value = {secret!r}\n",
                    encoding="utf-8",
                )

                proc = self._run_pack(
                    script,
                    root,
                    "auto",
                    "--root",
                    ".",
                    "--files",
                    "src/app.py",
                    "--top",
                    "1",
                    "--budget-bytes",
                    "5000",
                    "--json",
                    "--no-artifact",
                    "--apply-symbol-memory",
                    "--explain",
                )
                applied = json.loads(proc.stdout)
                public_scan = applied["explain"]["repo_map"]["secret_scan"]

                self.assertNotIn(secret, proc.stdout + proc.stderr)
                self.assertEqual(len(public_scan["files_with_risks"]), 20)
                self.assertEqual(public_scan["files_omitted_by_cap"], 1)
                self.assertNotIn(
                    "src/z_credentials.py",
                    [item["path"] for item in public_scan["files_with_risks"]],
                )
                self.assertEqual(
                    [item["path"] for item in applied["manifest"]["sources"]],
                    ["src/app.py"],
                )
                graph = applied["graph_application"]
                self.assertEqual(graph["selected_source_count"], 0)
                self.assertEqual(graph["excluded_secret_risk_count"], 1)

    def test_adaptive_k_text_reports_no_change_as_not_applied(self) -> None:
        for script in PACK_SCRIPTS:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "src").mkdir()
                (root / "src" / "entry.py").write_text(
                    "def entrypoint():\n    return 'entry'\n",
                    encoding="utf-8",
                )
                common = [
                    "auto",
                    "--root",
                    ".",
                    "--files",
                    "src/entry.py",
                    "--top",
                    "1",
                    "--budget-bytes",
                    "5000",
                    "--no-artifact",
                    "--apply-adaptive-k",
                ]

                no_change = self._run_pack(script, root, *common).stdout
                no_change_json = json.loads(
                    self._run_pack(script, root, *common, "--json").stdout
                )
                self.assertEqual(
                    no_change_json["adaptive_k_application"]["status"],
                    "no_change",
                )
                self.assertIn("adaptive-k:", no_change)
                self.assertIn("apply=false", no_change)
                self.assertNotIn("apply=true", no_change)

    def test_help_and_docs_expose_progressive_context_opt_in_flags(self) -> None:
        for script in PACK_SCRIPTS:
            with self.subTest(script=script):
                help_proc = self._run_pack(script, ROOT, "auto", "--help")
                self.assertIn("--apply-adaptive-k", help_proc.stdout)
                self.assertIn("--apply-symbol-memory", help_proc.stdout)

        docs = [
            ROOT / "README.md",
            ROOT / "README.ko.md",
            PLUGIN_DIR / "README.md",
            PLUGIN_DIR / "README.ko.md",
            KIT_DIR / "README.md",
        ]
        for doc in docs:
            with self.subTest(doc=doc):
                text = doc.read_text(encoding="utf-8")
                self.assertIn("--apply-adaptive-k", text)
                self.assertIn("--apply-symbol-memory", text)


if __name__ == "__main__":
    unittest.main()
