"""Focused reliability tests for ContextGuard MCP helper supervision."""

import importlib.util
import os
from pathlib import Path
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
MCP_SCRIPT = ROOT / "context-guard-kit" / "context_guard_mcp.py"


def load_mcp_module():
    spec = importlib.util.spec_from_file_location("_context_guard_mcp_reliability_test", MCP_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(hasattr(os, "fork") and hasattr(os, "killpg"), "requires POSIX process groups")
class ContextGuardMcpReliabilityTests(unittest.TestCase):
    def test_timeout_escalates_before_term_ignoring_descendant_can_continue(self):
        module = load_mcp_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            helper = root / "term_ignoring_helper.py"
            helper.write_text(
                "import os, signal, time\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "child = os.fork()\n"
                "if child == 0:\n"
                "    def survive_term(signum, frame):\n"
                "        time.sleep(0.25)\n"
                "        open('descendant-survived-grace', 'w').write('yes')\n"
                "    signal.signal(signal.SIGTERM, survive_term)\n"
                "    open('descendant-ready', 'w').write('yes')\n"
                "    time.sleep(5)\n"
                "    os._exit(0)\n"
                "else:\n"
                "    time.sleep(5)\n",
                encoding="utf-8",
            )
            server = module.Server(root, "timeout-escalation")
            old_timeout = module.HELPER_TIMEOUT
            module.HELPER_TIMEOUT = 2.0
            try:
                self.assertIsNone(server.run_helper([str(helper)], b"", 1024))
                # The survivor delay starts when SIGTERM is delivered, so
                # interpreter startup cannot hide a late SIGKILL escalation.
                time.sleep(0.3)
                self.assertTrue((root / "descendant-ready").exists())
                self.assertFalse((root / "descendant-survived-grace").exists())
            finally:
                module.HELPER_TIMEOUT = old_timeout
                server.close()


if __name__ == "__main__":
    unittest.main()
