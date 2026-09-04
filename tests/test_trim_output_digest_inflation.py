"""S003-F1: the opt-in digest must never inflate a small command output.

Measured before the fix: a 19-byte command output produced a 461-byte markdown
digest and a 755-byte JSON digest, so enabling digest mode on quiet commands
increased context instead of reducing it. These tests pin the passthrough
fallback, the explicit override, and the absence of a regression on the large
outputs digest mode exists for.
"""
from __future__ import annotations

import functools
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TRIM = ROOT / "context-guard-kit" / "trim_command_output.py"
PACKAGED_TRIM = ROOT / "plugins" / "context-guard" / "bin" / "context-guard-trim-output"

SMALL_SCRIPT = "print('ok: 3 tests passed')\n"
# 큰 출력은 digest 보다 훨씬 크기만 하면 되므로, CI 스텝 예산을 아끼기 위해 최소 크기로 둔다.
LARGE_SCRIPT = (
    "for index in range(1200):\n"
    "    print('build step %04d ok bundle=chunk-%04d' % (index, index))\n"
)


def run_trim(script_source: str, *extra: str) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as tmp:
        script = Path(tmp) / "producer.py"
        script.write_text(script_source, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(TRIM), *extra, "--", sys.executable, str(script)],
            capture_output=True, text=True, timeout=300,
        )


@functools.lru_cache(maxsize=8)
def raw_bytes(script_source: str) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        script = Path(tmp) / "producer.py"
        script.write_text(script_source, encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(script)], capture_output=True, text=True, timeout=300,
        )
        return len(result.stdout.encode("utf-8"))


class DigestInflationTest(unittest.TestCase):
    def test_small_output_is_passed_through_instead_of_inflated(self) -> None:
        baseline = raw_bytes(SMALL_SCRIPT)
        for fmt in ("markdown", "json"):
            with self.subTest(digest=fmt):
                result = run_trim(SMALL_SCRIPT, "--digest", fmt)
                self.assertEqual(result.returncode, 0, result.stderr[-500:])
                emitted = len(result.stdout.encode("utf-8"))
                forced = run_trim(SMALL_SCRIPT, "--digest", fmt, "--digest-always")
                forced_bytes = len(forced.stdout.encode("utf-8"))
                self.assertLess(
                    emitted, forced_bytes,
                    "digest mode must not be larger than the passthrough fallback",
                )
                self.assertIn("digest skipped", result.stdout)
                self.assertIn("ok: 3 tests passed", result.stdout)
                # 폴백은 원본에 짧은 표식 한 줄만 더한다.
                self.assertLess(emitted - baseline, 120)

    def test_digest_always_keeps_the_structured_digest(self) -> None:
        result = run_trim(SMALL_SCRIPT, "--digest", "markdown", "--digest-always")
        self.assertEqual(result.returncode, 0, result.stderr[-500:])
        self.assertNotIn("digest skipped", result.stdout)
        self.assertGreater(len(result.stdout.encode("utf-8")), 200)

    def test_large_output_still_uses_the_digest(self) -> None:
        baseline = raw_bytes(LARGE_SCRIPT)
        self.assertGreater(baseline, 40_000)
        for fmt in ("markdown", "json"):
            with self.subTest(digest=fmt):
                result = run_trim(LARGE_SCRIPT, "--digest", fmt)
                self.assertEqual(result.returncode, 0, result.stderr[-500:])
                emitted = len(result.stdout.encode("utf-8"))
                self.assertNotIn("digest skipped", result.stdout)
                self.assertLess(emitted, baseline // 20)

    def test_truncated_output_never_masquerades_as_passthrough(self) -> None:
        """The fallback only fires when the full output fits, so nothing is silently lost."""
        source = "for index in range(120):\n    print('noise %d' % index)\n"
        result = run_trim(source, "--digest", "markdown", "--max-lines", "18")
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("digest skipped", result.stdout)
        self.assertIn("semantic digest", result.stdout)

    def _run_receipt(self, source: str, *extra: str) -> tuple[subprocess.CompletedProcess, Path]:
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        script = tmp / "producer.py"
        script.write_text(source, encoding="utf-8")
        artifacts = tmp / "artifacts"
        result = subprocess.run(
            [
                sys.executable, str(TRIM), "--digest", "json",
                "--artifact-receipt", "--artifact-dir", str(artifacts), *extra,
                "--", sys.executable, str(script),
            ],
            capture_output=True, text=True, timeout=300,
        )
        return result, artifacts

    def test_artifact_receipt_escrows_only_when_the_output_overflows(self) -> None:
        """escrow 는 넘친 출력에만 쓴다.

        예전에는 `--artifact-receipt` 가 무조건 digest 를 강제했다. 그 규칙이 기본
        Bash 래퍼의 기본값이 되면 한 줄짜리 출력에도 1KB digest 가 붙어 이 도구가
        줄이려던 컨텍스트를 도리어 늘린다.
        """
        small, small_artifacts = self._run_receipt(SMALL_SCRIPT)
        self.assertEqual(small.returncode, 0, small.stderr[-500:])
        self.assertNotIn("artifact_receipt", small.stdout)
        self.assertNotIn("digest skipped", small.stdout)
        self.assertEqual(small.stdout, "ok: 3 tests passed\n")
        self.assertFalse(small_artifacts.exists(), "small output must not write an artifact")

        noisy = "for index in range(400):\n    print('noise %d' % index)\n"
        big, big_artifacts = self._run_receipt(noisy)
        self.assertEqual(big.returncode, 0, big.stderr[-500:])
        self.assertIn("artifact_receipt", big.stdout)
        self.assertTrue(any(big_artifacts.glob("*.txt")))

    def test_digest_always_keeps_the_receipt_for_a_small_output(self) -> None:
        """작은 출력에도 handle 이 꼭 필요한 호출자를 위한 명시적 탈출구."""
        result, artifacts = self._run_receipt(SMALL_SCRIPT, "--digest-always")
        self.assertEqual(result.returncode, 0, result.stderr[-500:])
        self.assertIn("artifact_receipt", result.stdout)
        self.assertTrue(any(artifacts.glob("*.txt")))

    def test_default_trim_mode_never_inflates_a_small_output(self) -> None:
        baseline = raw_bytes(SMALL_SCRIPT)
        result = run_trim(SMALL_SCRIPT, "--max-lines", "220")
        self.assertEqual(result.returncode, 0, result.stderr[-500:])
        self.assertEqual(len(result.stdout.encode("utf-8")), baseline)

    def test_failing_command_keeps_the_digest_diagnostics(self) -> None:
        """A digest carries exit code and failure signature, so failures never fall back."""
        source = "for index in range(18):\n    print('noise %d' % index)\nraise SystemExit(3)\n"
        result = run_trim(source, "--digest", "markdown")
        self.assertEqual(result.returncode, 3)
        self.assertNotIn("digest skipped", result.stdout)
        self.assertIn("status", result.stdout)

    def test_wrapped_exit_code_is_preserved_in_the_fallback(self) -> None:
        result = run_trim(SMALL_SCRIPT, "--digest", "markdown")
        self.assertEqual(result.returncode, 0)
        self.assertIn("digest skipped", result.stdout)

    def test_packaged_mirror_carries_the_fallback(self) -> None:
        self.assertIn("--digest-always", PACKAGED_TRIM.read_text(encoding="utf-8"))
        self.assertIn("digest skipped", PACKAGED_TRIM.read_text(encoding="utf-8"))


class EscrowPassthroughIgnoresExitStatus(unittest.TestCase):
    """예산 안의 실패 출력(rc≠0)도 digest 없이 원문 그대로 통과해야 한다 (GLM 리뷰 A1)."""

    def test_failed_small_output_passes_through_without_digest(self) -> None:
        import subprocess, sys, tempfile
        from pathlib import Path
        script = Path(__file__).resolve().parents[1] / "context-guard-kit" / "trim_command_output.py"
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [sys.executable, str(script), "--max-lines", "220", "--digest", "markdown", "--artifact-receipt",
                 "--artifact-dir", str(Path(tmp) / "artifacts"), "--", "sh", "-c", "echo no-match; exit 1"],
                capture_output=True, text=True, cwd=tmp,
            )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("no-match", proc.stdout)
        self.assertNotIn("semantic digest", proc.stdout)
        self.assertNotIn("artifact_receipt", proc.stdout)


if __name__ == "__main__":
    unittest.main()
