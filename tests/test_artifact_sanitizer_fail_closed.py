from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ARTIFACT_SCRIPTS = (
    ROOT / "context-guard-kit" / "context_escrow.py",
    ROOT / "plugins" / "context-guard" / "bin" / "context-guard-artifact",
)


def load_script(path: Path, name: str) -> types.ModuleType:
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    if spec is None:
        raise RuntimeError("artifact module spec unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


@unittest.skipUnless(
    os.environ.get("CONTEXT_GUARD_CAMPAIGN_ACCEPTANCE") == "1",
    "prospective campaign acceptance only",
)
class ArtifactSanitizerFailClosedTests(unittest.TestCase):
    def test_isolated_artifact_module_rejects_missing_canonical_sanitizer(self) -> None:
        for index, source in enumerate(ARTIFACT_SCRIPTS):
            with (
                self.subTest(source=source.name),
                tempfile.TemporaryDirectory() as directory,
            ):
                isolated = Path(directory) / source.name
                shutil.copy2(source, isolated)
                module = load_script(isolated, f"isolated_artifact_{index}")

                with self.assertRaisesRegex(
                    RuntimeError, "canonical sanitizer is unavailable"
                ):
                    module.load_line_sanitizer(False)

    def test_isolated_store_fails_before_creating_artifact_state(self) -> None:
        private_input = "PRIVATE-TASK-MATERIAL api_token=ghp_" + ("A" * 36)
        for source in ARTIFACT_SCRIPTS:
            with (
                self.subTest(source=source.name),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                isolated = root / source.name
                artifact_dir = root / "artifacts"
                shutil.copy2(source, isolated)
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(isolated),
                        "--dir",
                        str(artifact_dir),
                        "store",
                        "--json",
                    ],
                    input=private_input,
                    text=True,
                    capture_output=True,
                    cwd=root,
                    check=False,
                )

                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("canonical sanitizer is unavailable", completed.stderr)
                self.assertNotIn(private_input, completed.stdout + completed.stderr)
                self.assertFalse(artifact_dir.exists())


if __name__ == "__main__":
    unittest.main()
