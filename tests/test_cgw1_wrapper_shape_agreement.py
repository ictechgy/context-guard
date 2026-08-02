from __future__ import annotations

import importlib.util
import os
import shlex
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KIT_DIR = ROOT / "context-guard-kit"
REWRITE_BASH_SCRIPT = KIT_DIR / "rewrite_bash_for_token_budget.py"
NUDGE_SCRIPT = KIT_DIR / "failed_attempt_nudge.py"
SANITIZE_OUTPUT_SCRIPT = KIT_DIR / "sanitize_output.py"
TRIM_OUTPUT_SCRIPT = KIT_DIR / "trim_command_output.py"


def _load_module(name: str, path: Path) -> types.ModuleType:
    """단일 스크립트 파일을 importlib으로 로드한다.

    ``test_context_guard_nudge_protocol.py``의 ``load_script`` 헬퍼와 동일하게
    ``sys.modules``에 먼저 등록한 뒤 실행한다 — 로드 대상이 ``dataclass``를
    쓰면 실행 중 ``sys.modules[cls.__module__]``를 조회하므로 미리 등록해
    두지 않으면 ``rewrite_bash_for_token_budget.py``의 ``@dataclass`` 정의에서
    깨진다.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load script: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


rewrite_bash = _load_module("rewrite_bash_for_token_budget", REWRITE_BASH_SCRIPT)
nudge = _load_module("failed_attempt_nudge", NUDGE_SCRIPT)


class Cgw1WrapperShapeAgreementTests(unittest.TestCase):
    """CGW1 producer(rewrite_bash_for_token_budget)와 recognizer
    (failed_attempt_nudge.command_identity, sanitize_output.py:1170)가
    trim/sanitize 두 플레이버 모두에서 같은 envelope 모양에 합의하는지 고정한다.

    PM-2(부분 FIX-7 지름길)의 유일한 침묵 다리 — producer와
    sanitize_output.py는 뒤집었지만 failed_attempt_nudge.py는 동결이라
    남겨둔 경우 — 를 조기에 잡기 위한 신규 전용 파일이다. 두 동결 경로
    (test_context_guard_nudge_protocol.py는 B1_PATHS, test_context_guard_shell_contract.py는
    7개 미머지 브랜치 중 6개가 건드림) 어디에도 넣을 수 없어 새 파일로 분리했다.
    """

    def _wrapper_path(self, name: str) -> str:
        """producer/recognizer 양쪽이 같은 디렉터리(context-guard-kit/)에서
        스크립트를 찾으므로, 두 쪽이 합의하는 절대경로를 하나만 만들어 재사용한다.
        """
        return str(KIT_DIR / name)

    def test_cgw1_round_trip_for_both_flavors(self) -> None:
        """U-10a — producer가 만든 wrapped 명령을 recognizer가 두 플레이버 모두
        FOREIGN이 아닌 것으로 왕복 인식하는지 검사한다.

        trim 쪽은 CGW1_MAX_LINES(rewrite_bash)와 LEGACY_V0_MAX_LINES(nudge)가
        오늘 우연히 같은 값("220")이라 legacy-v0 경로로 인식된다 — 이는 trim
        플레이버의 유일한 형태 합의 방어선이다(trim_command_output.py 자체에는
        형태 검사가 없다).
        """
        logical_command = "pytest tests/example.py -k some_case"

        self.assertEqual(rewrite_bash.CGW1_SHELL_ARGV, ("bash", "-c"))
        self.assertEqual(nudge.CGW1_SHELL_ARGV, ("bash", "-c"))

        trim_wrapper = self._wrapper_path("trim_command_output.py")
        wrapped_trim = rewrite_bash.build_wrapped_command(trim_wrapper, logical_command)
        identity_trim = nudge.command_identity(wrapped_trim)
        self.assertNotEqual(
            identity_trim.protocol,
            nudge.PROTOCOL_FOREIGN,
            f"trim envelope not recognized by command_identity: {wrapped_trim!r}",
        )

        sanitize_wrapper = self._wrapper_path("sanitize_output.py")
        wrapped_sanitize = rewrite_bash.build_sanitized_command(
            sanitize_wrapper, logical_command
        )
        identity_sanitize = nudge.command_identity(wrapped_sanitize)
        self.assertEqual(identity_sanitize.protocol, nudge.PROTOCOL_CGW1)

    def test_sanitize_output_rejects_mismatched_wrapper_shape(self) -> None:
        """U-10b — ``sanitize_output.py:1170``은 ``main()`` 안이라 모듈 로드로는
        도달 불가하므로 실제 subprocess로 검사한다.

        올바른 CGW1 envelope(현재 producer가 실제로 내보내는 모양)는 rc != 2여야
        하고, 모양이 어긋난 login-shell envelope(``bash -lc``)는 rc == 2로
        큰 소리로 실패해야 한다. sanitize 플레이버 전용 방어선이다.
        """
        matching = subprocess.run(
            [
                sys.executable,
                str(SANITIZE_OUTPUT_SCRIPT),
                "--context-guard-wrapper-v1",
                "command_search_diff",
                "--",
                "bash",
                "-c",
                "echo shape-ok",
            ],
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertNotEqual(
            matching.returncode,
            2,
            f"correctly shaped CGW1 envelope was rejected: {matching.stderr!r}",
        )

        mismatched = subprocess.run(
            [
                sys.executable,
                str(SANITIZE_OUTPUT_SCRIPT),
                "--context-guard-wrapper-v1",
                "command_search_diff",
                "--",
                "bash",
                "-lc",
                "echo shape-mismatch",
            ],
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(mismatched.returncode, 2, mismatched.stdout)
        self.assertIn("invalid context-guard wrapper v1 shape", mismatched.stderr)

    def test_trim_wrapper_preserves_inherited_path_without_login_profile(self) -> None:
        """F-2 — 내부 래퍼는 호출 환경의 PATH를 그대로 사용하고 login profile을
        읽지 않는다. 같은 이름의 두 실행 파일과 의도적으로 PATH를 바꾸는
        ``.bash_profile``을 만들어 문자열 모양이 아니라 실제 해석 결과를 고정한다.
        """
        with tempfile.TemporaryDirectory(prefix="context-guard-f2-path-") as tmp:
            root = Path(tmp)
            inherited_bin = root / "inherited-bin"
            login_bin = root / "login-bin"
            home = root / "home"
            for directory in (inherited_bin, login_bin, home):
                directory.mkdir()

            for directory, marker in (
                (inherited_bin, "INHERITED_PATH"),
                (login_bin, "LOGIN_PROFILE_PATH"),
            ):
                probe = directory / "contextguard-path-probe"
                probe.write_text(
                    f"#!/bin/sh\nprintf '%s\\n' {marker}\n",
                    encoding="utf-8",
                )
                probe.chmod(0o755)

            (home / ".bash_profile").write_text(
                f"export PATH={shlex.quote(str(login_bin))}:$PATH\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["HOME"] = str(home)
            env["PATH"] = os.pathsep.join(
                (
                    str(inherited_bin),
                    str(Path(sys.executable).parent),
                    "/usr/bin",
                    "/bin",
                )
            )
            wrapped = rewrite_bash.build_wrapped_command(
                str(TRIM_OUTPUT_SCRIPT),
                "contextguard-path-probe",
            )

            proc = subprocess.run(
                shlex.split(wrapped),
                env=env,
                text=True,
                capture_output=True,
                timeout=30,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, "INHERITED_PATH\n")


if __name__ == "__main__":
    unittest.main()
