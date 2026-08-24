"""Focused acceptance tests for a broad, multi-angle advisory audit of
context-guard-kit's live hook surface (security angle - the architecture
and performance findings from the same audit were deferred; see the audit
task file / session notes for the full triage).

Three independently-verified findings, each fixed here:

1. `_discover_git_filter_config_keys()` / `run_guarded_git()` in
   `rewrite_bash_for_token_budget.py` resolve the `git` executable through
   the inherited `PATH` (bare `"git"` argv[0] for both `subprocess.run` and
   `os.execvpe`), even though this exact file already has an established,
   tested pattern (`_approved_runtime_executable`) for resolving trusted
   runtimes (`env`, `bash`) from a fixed OS command path instead. A hostile
   PATH entry ahead of the real `git` binary could execute before the
   "neutralize Git execution configuration" guard ever runs.

2. `FallbackLineSanitizer` in `trim_command_output.py` (used only when the
   adjacent strong sanitizer, `sanitize_output.py`, fails to load) is
   missing PEM private-key block redaction and Cookie-header redaction that
   the strong sanitizer has, and its URL-userinfo pattern requires a
   `user:pass@` pair - the exact pre-FIX-6 regression `credential_policy.py`
   already fixed for the strong path (`scheme://TOKEN@` with no colon must
   also redact). The fallback silently degrades redaction quality instead
   of failing closed or matching the strong policy.

3. `_isolated_wrapper_prefix()` in `rewrite_bash_for_token_budget.py`
   resolves the adjacent sanitize/trim wrapper via `os.path.realpath`
   without any no-follow/regular-file validation, unlike this same file's
   sibling helper for adjacent-module loading elsewhere in the codebase
   (`trim_command_output.py`'s `read_adjacent_module_source`, which uses
   `O_NOFOLLOW` explicitly) - an inconsistent trust boundary for what
   should be the same class of adjacent-file trust decision.
"""
from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
KIT_ROOT = REPO_ROOT / "context-guard-kit"
if str(KIT_ROOT) not in sys.path:
    sys.path.insert(0, str(KIT_ROOT))

import rewrite_bash_for_token_budget as rewrite_bash  # noqa: E402
import trim_command_output as trim_output  # noqa: E402


class GitExecutableResolutionTests(unittest.TestCase):
    """The guarded-git path must resolve `git` the same trusted way the
    file already resolves `env`/`bash`, not through inherited PATH."""

    def test_discover_git_filter_config_keys_accepts_an_executable_argument(self) -> None:
        # The fixed function signature must take the resolved git
        # executable as an explicit argument rather than hardcoding the
        # literal "git" string internally.
        import inspect

        signature = inspect.signature(rewrite_bash._discover_git_filter_config_keys)
        self.assertIn(
            "git_executable",
            signature.parameters,
            "_discover_git_filter_config_keys must accept the resolved git "
            "executable path as a parameter instead of hardcoding \"git\"",
        )

    def test_run_guarded_git_execs_the_approved_executable_not_bare_git(self) -> None:
        approved_calls: list[str] = []
        exec_calls: list[tuple[str, list[str]]] = []
        sentinel_git = "/approved/fixed/path/git"
        original_approved = rewrite_bash._approved_runtime_executable

        def fake_approved_runtime_executable(name: str) -> str:
            approved_calls.append(name)
            if name == "git":
                return sentinel_git
            return original_approved(name)

        def fake_execve(path: str, argv: list[str], env: dict[str, str]) -> None:
            exec_calls.append((path, list(argv)))
            raise SystemExit(0)  # stand in for process replacement

        def fake_discover(git_executable: str) -> tuple[str, ...]:
            approved_calls.append(f"discover:{git_executable}")
            return ()

        original_execve = os.execve
        original_discover = rewrite_bash._discover_git_filter_config_keys
        rewrite_bash._approved_runtime_executable = fake_approved_runtime_executable  # type: ignore[assignment]
        rewrite_bash._discover_git_filter_config_keys = fake_discover  # type: ignore[assignment]
        os.execve = fake_execve  # type: ignore[assignment]
        try:
            with self.assertRaises(SystemExit):
                rewrite_bash.run_guarded_git(("git", "log", "--no-ext-diff", "--no-textconv"))
        finally:
            rewrite_bash._approved_runtime_executable = original_approved  # type: ignore[assignment]
            rewrite_bash._discover_git_filter_config_keys = original_discover  # type: ignore[assignment]
            os.execve = original_execve  # type: ignore[assignment]

        self.assertIn("git", approved_calls, "must resolve \"git\" through _approved_runtime_executable")
        self.assertTrue(exec_calls, "must call os.execve, not os.execvpe (which does a PATH search)")
        exec_path, exec_argv = exec_calls[0]
        self.assertEqual(
            exec_path,
            sentinel_git,
            "must os.execve the resolved fixed-path executable, not a bare \"git\" argv[0]",
        )


class FallbackSanitizerCoverageTests(unittest.TestCase):
    """The fallback line sanitizer must not silently regress below the
    strong sanitizer's credential-redaction coverage."""

    def _sanitize_all(self, lines: list[str]) -> list[str]:
        sanitizer = trim_output.FallbackLineSanitizer()
        return [sanitizer.sanitize(line)[0] for line in lines]

    def test_token_only_userinfo_url_is_redacted(self) -> None:
        # The exact FIX-6 regression: scheme://TOKEN@host (no colon/password
        # part) must be redacted, not just user:pass@host.
        line = "cloning https://ghp_abcdEXAMPLETOKEN1234567890@github.com/org/repo.git\n"
        sanitized, redacted = trim_output.FallbackLineSanitizer().sanitize(line)
        self.assertTrue(redacted)
        self.assertNotIn("ghp_abcdEXAMPLETOKEN1234567890", sanitized)

    def test_private_key_block_is_redacted_across_lines(self) -> None:
        sanitizer = trim_output.FallbackLineSanitizer()
        lines = [
            "-----BEGIN RSA PRIVATE KEY-----\n",
            "MIIEpAIBAAKCAQEAmiddlebase64contentthatlookslikekeybytesxyz\n",
            "-----END RSA PRIVATE KEY-----\n",
        ]
        outputs = [sanitizer.sanitize(line)[0] for line in lines]
        self.assertNotIn(
            "MIIEpAIBAAKCAQEAmiddlebase64contentthatlookslikekeybytesxyz",
            outputs[1],
            "the PEM body line must be redacted while inside a private-key block",
        )

    def test_cookie_header_is_redacted(self) -> None:
        line = "Set-Cookie: session=abcdef1234567890; Path=/; HttpOnly\n"
        sanitized, redacted = trim_output.FallbackLineSanitizer().sanitize(line)
        self.assertTrue(redacted)
        self.assertNotIn("abcdef1234567890", sanitized)


class WrapperSymlinkResolutionTests(unittest.TestCase):
    """Adjacent wrapper resolution must apply the same no-follow discipline
    used elsewhere in the codebase for adjacent-file trust decisions."""

    def test_isolated_wrapper_prefix_rejects_a_symlinked_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            real_target = Path(tmp) / "real_target.py"
            real_target.write_text("# not a real wrapper\n")
            symlinked_wrapper = Path(tmp) / "sanitize_output.py"
            symlinked_wrapper.symlink_to(real_target)
            with self.assertRaises((rewrite_bash.__dict__.get("UnsafeAdjacentWrapperError", RuntimeError), OSError, RuntimeError)):
                rewrite_bash._isolated_wrapper_prefix(str(symlinked_wrapper))

    def test_isolated_wrapper_prefix_accepts_a_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            wrapper = Path(tmp) / "sanitize_output.py"
            wrapper.write_text("# a regular wrapper file\n")
            prefix = rewrite_bash._isolated_wrapper_prefix(str(wrapper))
            self.assertEqual(prefix[-1], str(wrapper.resolve()))


class MirroredFileIdentityTests(unittest.TestCase):
    def test_rewrite_bash_mirrors_stay_byte_identical(self) -> None:
        canonical = KIT_ROOT / "rewrite_bash_for_token_budget.py"
        mirror = REPO_ROOT / "plugins" / "context-guard" / "bin" / "context-guard-rewrite-bash"
        self.assertEqual(canonical.read_bytes(), mirror.read_bytes())

    def test_trim_command_output_mirrors_stay_byte_identical(self) -> None:
        canonical = KIT_ROOT / "trim_command_output.py"
        mirror = REPO_ROOT / "plugins" / "context-guard" / "bin" / "context-guard-trim-output"
        self.assertEqual(canonical.read_bytes(), mirror.read_bytes())


if __name__ == "__main__":
    unittest.main()
