from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "scripts" / "generate_setup_reference.py"
REFERENCE = ROOT / "docs" / "setup-reference.md"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class SetupReferenceTests(unittest.TestCase):
    def test_generated_reference_is_current(self) -> None:
        generator = load(GENERATOR, "setup_reference_generator_test")
        self.assertEqual(REFERENCE.read_text(encoding="utf-8"), generator.render())
        completed = subprocess.run(
            [sys.executable, str(GENERATOR), "--check"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("setup reference: OK", completed.stdout)

    def test_agent_rows_cover_exact_registry(self) -> None:
        generator = load(GENERATOR, "setup_reference_registry_test")
        setup = generator.load_setup()
        expected = [item["key"] for item in setup.adapter_registry_payload()]
        document = REFERENCE.read_text(encoding="utf-8")
        observed = re.findall(r"^\| `([a-z]+)` \|", document, flags=re.MULTILINE)
        self.assertEqual(observed, expected)
        self.assertIn("Only Claude Code currently has a verified user-scope write path", document)

    def test_flag_rows_cover_every_public_parser_option(self) -> None:
        generator = load(GENERATOR, "setup_reference_flags_test")
        setup = generator.load_setup()
        document = REFERENCE.read_text(encoding="utf-8")
        for action in setup.build_parser()._actions:
            for option in action.option_strings:
                if option in {"-h", "--help"}:
                    continue
                with self.subTest(option=option):
                    self.assertIn(f"`{option}`", document)

    def test_reference_contains_no_maintainer_absolute_path(self) -> None:
        document = REFERENCE.read_text(encoding="utf-8")
        self.assertNotIn(str(ROOT), document)
        self.assertNotRegex(document, r"/(?:Users|home)/[^/]+/")


if __name__ == "__main__":
    unittest.main()
