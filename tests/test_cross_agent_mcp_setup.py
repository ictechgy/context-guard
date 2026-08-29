from __future__ import annotations

import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
SETUP_SCRIPTS = (
    ROOT / "context-guard-kit" / "setup_wizard.py",
    ROOT / "plugins" / "context-guard" / "bin" / "context-guard-setup",
)


class CrossAgentMcpSetupTests(unittest.TestCase):
    def run_setup(self, script: Path, root: Path, *arguments: str) -> dict[str, object]:
        completed = subprocess.run(
            [
                sys.executable,
                str(script),
                "--root",
                str(root),
                "--agent",
                arguments[0],
                "--json",
                *arguments[1:],
            ],
            text=True,
            capture_output=True,
            check=True,
        )
        return json.loads(completed.stdout)

    def test_registry_exposes_composable_capabilities(self) -> None:
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                completed = subprocess.run(
                    [sys.executable, str(script), "--list-adapters", "--json"],
                    text=True,
                    capture_output=True,
                    check=True,
                )
                adapters = {
                    item["key"]: item for item in json.loads(completed.stdout)["adapters"]
                }
                self.assertEqual(
                    adapters["codex"]["capabilities"],
                    ["project-mcp", "project-skill", "repo-rule", "shell-cli"],
                )
                self.assertIn("native-hooks", adapters["claude"]["capabilities"])
                self.assertEqual(adapters["generic"]["capabilities"], ["shell-cli"])
                for key in ("gemini", "cursor", "copilot", "opencode", "forgecode"):
                    self.assertIn("project-mcp", adapters[key]["capabilities"])
                for key in ("windsurf", "cline"):
                    self.assertNotIn("project-mcp", adapters[key]["capabilities"])

    def test_codex_project_mcp_preserves_toml_and_is_idempotent(self) -> None:
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                config = root / ".codex" / "config.toml"
                config.parent.mkdir()
                original = b'model = "example-model"\n'
                config.write_bytes(original)

                result = self.run_setup(
                    script,
                    root,
                    "codex",
                    "--with-mcp",
                    "--yes",
                    "--no-diet-scan",
                )
                entry = result["adapter_plan"][0]
                self.assertTrue(result["applied"])
                self.assertEqual(entry["mcp_status"], "applied")
                self.assertEqual(entry["mcp_config_file"], ".codex/config.toml")
                written = config.read_bytes()
                self.assertTrue(written.startswith(original))
                self.assertEqual(
                    written.count(b"# BEGIN context-guard:codex-mcp version=1"), 1
                )
                parsed = tomllib.loads(written.decode("utf-8"))
                server = parsed["mcp_servers"]["context_guard"]
                self.assertTrue(Path(server["command"]).is_absolute())
                self.assertEqual(server["command"], "/usr/bin/env")
                self.assertEqual(
                    server["args"][-4:],
                    ["--root", str(root), "--namespace", "codex-context-guard"],
                )
                self.assertIn("-i", server["args"])
                self.assertIn("LC_ALL=C", server["args"])
                backup = Path(entry["mcp_backup_path"])
                self.assertEqual(backup.read_bytes(), original)
                self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)

                again = self.run_setup(
                    script,
                    root,
                    "codex",
                    "--with-mcp",
                    "--yes",
                    "--no-diet-scan",
                )
                self.assertEqual(again["adapter_plan"][0]["mcp_status"], "exists")
                self.assertEqual(config.read_bytes(), written)

    def test_codex_mcp_plan_is_read_only_and_foreign_entry_is_preserved(self) -> None:
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                planned = self.run_setup(
                    script,
                    root,
                    "codex",
                    "--with-mcp",
                    "--plan",
                )
                self.assertEqual(planned["adapter_plan"][0]["mcp_status"], "planned")
                config = root / ".codex" / "config.toml"
                self.assertFalse(config.exists())

                config.parent.mkdir()
                foreign = (
                    b"[mcp_servers.context_guard]\n"
                    b'command = "user-owned-server"\n'
                )
                config.write_bytes(foreign)
                applied = self.run_setup(
                    script,
                    root,
                    "codex",
                    "--with-mcp",
                    "--yes",
                    "--no-diet-scan",
                )
                entry = applied["adapter_plan"][0]
                self.assertEqual(entry["mcp_status"], "conflict")
                self.assertIn("user-owned", entry["mcp_reason"])
                self.assertEqual(config.read_bytes(), foreign)
                self.assertEqual(list(config.parent.glob("config.toml.bak-*")), [])

    def test_codex_mcp_rejects_symlink_invalid_toml_and_unknown_marker(self) -> None:
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                for case, content in (
                    ("invalid", b"value = [\n"),
                    (
                        "unknown-marker",
                        b"# BEGIN context-guard:codex-mcp version=2\n"
                        b"# END context-guard:codex-mcp\n",
                    ),
                ):
                    with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                        root = Path(temporary).resolve()
                        config = root / ".codex" / "config.toml"
                        config.parent.mkdir()
                        config.write_bytes(content)
                        result = self.run_setup(
                            script,
                            root,
                            "codex",
                            "--with-mcp",
                            "--yes",
                            "--no-diet-scan",
                        )
                        self.assertIn(
                            result["adapter_plan"][0]["mcp_status"],
                            {"unsafe", "skipped"},
                        )
                        self.assertEqual(config.read_bytes(), content)

                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary).resolve()
                    outside = root / "outside.toml"
                    outside.write_text('model = "outside"\n', encoding="utf-8")
                    config = root / ".codex" / "config.toml"
                    config.parent.mkdir()
                    try:
                        config.symlink_to(outside)
                    except (OSError, NotImplementedError):
                        continue
                    result = self.run_setup(
                        script,
                        root,
                        "codex",
                        "--with-mcp",
                        "--yes",
                        "--no-diet-scan",
                    )
                    self.assertIn(
                        result["adapter_plan"][0]["mcp_status"],
                        {"unsafe", "skipped"},
                    )
                    self.assertEqual(outside.read_text(encoding="utf-8"), 'model = "outside"\n')

    def test_unknown_vendor_mcp_is_report_only(self) -> None:
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                result = self.run_setup(
                    script,
                    root,
                    "generic",
                    "--with-mcp",
                    "--yes",
                    "--no-diet-scan",
                )
                entry = result["adapter_plan"][0]
                self.assertFalse(result["applied"])
                self.assertEqual(entry["mcp_status"], "unsupported")
                self.assertIn("not implemented/verified", entry["mcp_reason"])
                self.assertEqual(list(root.iterdir()), [])

    def test_verified_json_vendor_mcp_shapes_preserve_config_and_are_idempotent(self) -> None:
        cases = {
            "gemini": (Path(".gemini/settings.json"), ("mcpServers",), "command-args"),
            "cursor": (Path(".cursor/mcp.json"), ("mcpServers",), "command-args"),
            "copilot": (Path(".vscode/mcp.json"), ("servers",), "vscode"),
            "opencode": (Path("opencode.json"), ("mcp", "servers"), "opencode"),
            "forgecode": (Path(".mcp.json"), ("mcpServers",), "command-args"),
        }
        for script in SETUP_SCRIPTS:
            for adapter, (relative, key_path, style) in cases.items():
                with self.subTest(script=script, adapter=adapter), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary).resolve()
                    config = root / relative
                    config.parent.mkdir(parents=True, exist_ok=True)
                    original = {"existing": {"preserved": True}}
                    config.write_text(json.dumps(original), encoding="utf-8")
                    extra = ["--with-mcp", "--yes", "--no-diet-scan"]
                    if adapter == "opencode":
                        extra.insert(0, "--with-skill")
                    result = self.run_setup(script, root, adapter, *extra)
                    entry = result["adapter_plan"][0]
                    self.assertEqual(entry["mcp_status"], "applied")
                    document = json.loads(config.read_text(encoding="utf-8"))
                    self.assertEqual(document["existing"], original["existing"])
                    servers = document
                    for key in key_path:
                        servers = servers[key]
                    server = servers["context_guard"]
                    if style == "opencode":
                        argv = server["command"]
                        self.assertEqual(server["type"], "local")
                    else:
                        argv = [server["command"], *server["args"]]
                        if style == "vscode":
                            self.assertEqual(server["type"], "stdio")
                    self.assertEqual(
                        argv[-4:],
                        ["--root", str(root), "--namespace", f"{adapter}-context-guard"],
                    )
                    backup = Path(entry["mcp_backup_path"])
                    self.assertEqual(json.loads(backup.read_text(encoding="utf-8")), original)
                    again = self.run_setup(script, root, adapter, *extra)
                    self.assertEqual(again["adapter_plan"][0]["mcp_status"], "exists")
                    if adapter in {"opencode", "forgecode"}:
                        self.assertEqual(again["adapter_plan"][0]["status"], "exists")
                    if adapter == "opencode":
                        self.assertEqual(entry["project_skill_status"], "applied")

    def test_json_vendor_mcp_refuses_foreign_duplicate_and_split_config(self) -> None:
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                config = root / ".cursor" / "mcp.json"
                config.parent.mkdir()
                foreign = {"mcpServers": {"context_guard": {"command": "user-server"}}}
                config.write_text(json.dumps(foreign), encoding="utf-8")
                result = self.run_setup(
                    script, root, "cursor", "--with-mcp", "--yes", "--no-diet-scan"
                )
                self.assertEqual(result["adapter_plan"][0]["mcp_status"], "conflict")
                self.assertEqual(json.loads(config.read_text(encoding="utf-8")), foreign)

                config.write_text('{"mcpServers":{},"mcpServers":{}}', encoding="utf-8")
                duplicate = self.run_setup(
                    script, root, "cursor", "--with-mcp", "--yes", "--no-diet-scan"
                )
                self.assertEqual(duplicate["adapter_plan"][0]["mcp_status"], "unsafe")

            with self.subTest(script=script, adapter="opencode"), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                (root / "opencode.jsonc").write_text("{}\n", encoding="utf-8")
                result = self.run_setup(
                    script, root, "opencode", "--with-mcp", "--yes", "--no-diet-scan"
                )
                self.assertEqual(result["adapter_plan"][0]["mcp_status"], "unsupported")
                self.assertFalse((root / "opencode.json").exists())

    def test_windsurf_and_cline_mcp_remain_report_only(self) -> None:
        for script in SETUP_SCRIPTS:
            for adapter in ("windsurf", "cline"):
                with self.subTest(script=script, adapter=adapter), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary).resolve()
                    result = self.run_setup(
                        script, root, adapter, "--with-mcp", "--yes", "--no-diet-scan"
                    )
                    entry = result["adapter_plan"][0]
                    self.assertEqual(entry["mcp_status"], "unsupported")
                    self.assertEqual(list(root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
