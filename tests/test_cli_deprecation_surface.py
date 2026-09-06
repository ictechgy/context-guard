"""The dispatcher's deprecation list must match what the helpers themselves say.

`context-guard --help` is the first surface a new user reads, and until now it
listed every subcommand flat under "Common subcommands" — including the five
helpers 0.14.0 deprecated. Each helper already carries a `[deprecated]` marker in
its own source, but the dispatcher deliberately never imports or executes helper
code (it reads a bounded command manifest as data), so the list has to be a
constant. These tests are what keeps that constant from drifting away from the
helpers it describes.
"""

from __future__ import annotations

import importlib.util
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "context-guard-kit"
PLUGIN_BIN = ROOT / "plugins" / "context-guard" / "bin"

# A helper declares its own status; the dispatcher only mirrors it.
DEPRECATED_MARKER = "[deprecated]"


def load_cli():
    path = KIT / "context_guard_cli.py"
    spec = importlib.util.spec_from_file_location("context_guard_cli_test", path)
    if spec is None or spec.loader is None:
        raise AssertionError("dispatcher module is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def helper_declares_deprecated(helper_name: str) -> bool:
    """True when the shipped helper marks itself deprecated.

    Read the packaged copy under plugins/context-guard/bin, because that is the
    file the npm package and the marketplace plugin actually install.
    """
    path = PLUGIN_BIN / helper_name
    if not path.is_file():
        raise AssertionError(f"packaged helper is missing: {helper_name}")
    return DEPRECATED_MARKER in path.read_text(encoding="utf-8", errors="replace")


class CliDeprecationSurfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cli = load_cli()

    def test_deprecated_set_is_a_subset_of_the_dispatcher_manifest(self) -> None:
        unknown = self.cli.DEPRECATED_SUBCOMMANDS - set(self.cli.HELPER_SUBCOMMANDS)
        self.assertEqual(unknown, set(), "deprecated names not in the command manifest")

    def test_deprecated_set_matches_what_each_shipped_helper_declares(self) -> None:
        """The list in the dispatcher and the markers in the helpers cannot drift.

        A helper that gains or loses its own `[deprecated]` marker fails here
        until the dispatcher list is updated in the same change.
        """
        declared: set[str] = set()
        for subcommand, mapping in self.cli.HELPER_SUBCOMMANDS.items():
            # A mapping is (helper, *fixed args) — `doctor` is setup --verify.
            # Only the helper carries the marker.
            self.assertTrue(mapping, f"{subcommand} has an empty mapping")
            if helper_declares_deprecated(mapping[0]):
                declared.add(subcommand)
        self.assertEqual(
            declared,
            set(self.cli.DEPRECATED_SUBCOMMANDS),
            "dispatcher deprecation list disagrees with the shipped helpers",
        )

    def test_help_separates_deprecated_from_common_and_names_the_guide(self) -> None:
        import io
        import contextlib

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.cli.print_help()
        text = buffer.getvalue()

        common = text.split("Common subcommands:\n", 1)[1].split("\n\n", 1)[0]
        common_names = {line.strip() for line in common.splitlines() if line.strip()}
        self.assertTrue(common_names)
        self.assertEqual(
            common_names & set(self.cli.DEPRECATED_SUBCOMMANDS),
            set(),
            "a deprecated subcommand is still listed as common",
        )

        self.assertIn("Deprecated, still shipped", text)
        deprecated_block = text.split("Deprecated, still shipped", 1)[1].split("\n\n", 1)[0]
        listed = {line.strip() for line in deprecated_block.splitlines()[1:] if line.strip()}
        self.assertEqual(listed, set(self.cli.DEPRECATED_SUBCOMMANDS))
        self.assertIn("docs/guide.md", text)

    def test_help_still_lists_every_subcommand_exactly_once(self) -> None:
        import io
        import contextlib

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.cli.print_help()
        text = buffer.getvalue()

        for name in self.cli.HELPER_SUBCOMMANDS:
            listed = re.findall(rf"(?m)^  {re.escape(name)}$", text)
            self.assertEqual(len(listed), 1, f"{name} should appear exactly once")


if __name__ == "__main__":  # pragma: no cover - manual invocation
    unittest.main()
