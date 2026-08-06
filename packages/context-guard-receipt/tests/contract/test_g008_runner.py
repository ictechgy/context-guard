from __future__ import annotations

import importlib
import errno
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))


def runner_module():
    try:
        return importlib.import_module("context_guard_receipt.runner")
    except ModuleNotFoundError as error:
        raise AssertionError("G008 command runner implementation is missing") from error


EVIDENCE_BOUNDARY = {
    "evidence_class": "companion_local_receipt_only",
    "host_request_owned": False,
    "provider_claim_authority": False,
    "provider_join_status": "missing",
    "runtime_observer_present": False,
    "schema_version": "contextguard-receipt-evidence-boundary/v1",
    "selected_branch": "S2-UNSUPPORTED",
    "selected_transport": "NONE",
    "stage1_evidence": False,
    "stage2_evidence": False,
}


def captured_snapshot(identity: str = "a" * 64, state: str = "0" * 64):
    return {
        "artifact_kind": "repository_snapshot",
        "disposition": "captured",
        "evidence_boundary": dict(EVIDENCE_BOUNDARY),
        "instance": {"identity_sha256": identity, "kind": "worktree"},
        "logical_state": {"kind": "git_worktree", "state_sha256": state},
        "reason": "git_worktree_state",
        "schema_version": "contextguard-receipt-repository-snapshot/v1",
    }


class Snapshotter:
    def __init__(self, snapshots=None) -> None:
        self.snapshots = list(snapshots or (captured_snapshot(), captured_snapshot()))
        self.calls = []

    def __call__(self, root, *, root_fd=None):
        self.calls.append(root)
        return self.snapshots.pop(0)


class StoreSpy:
    def __init__(self, *, error=None, issued=None) -> None:
        self.error = error
        self.issued = issued or (
            SimpleNamespace(handle="cgr1p_" + "h" * 43, namespace_id="b" * 64),
        )
        self.calls = []
        self.closed = False

    def issue_batch(self, requests):
        self.calls.append(requests)
        if self.error is not None:
            raise self.error
        return self.issued

    def close(self):
        self.closed = True


class Harness:
    def __init__(self, testcase: unittest.TestCase, snapshots=None, store=None) -> None:
        self.testcase = testcase
        self.directory = tempfile.TemporaryDirectory()
        self.root = str(Path(self.directory.name).resolve())
        self.snapshotter = Snapshotter(snapshots)
        self.store = store or StoreSpy()
        self.factory_calls = 0

    def factory(self):
        self.factory_calls += 1
        return self.store

    def run(self, code: str, *, arguments=(), **kwargs):
        module = runner_module()
        return module.run_command(
            (str(Path(sys.executable).resolve()), "-c", code, *arguments),
            self.root,
            store_factory=self.factory,
            snapshotter=self.snapshotter,
            **kwargs,
        )

    def close(self):
        self.directory.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def _process_is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _wait_for_process_exit(pid: int, timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _process_is_alive(pid):
            return True
        time.sleep(0.01)
    return not _process_is_alive(pid)


def _wait_for_process_group_quiescence(module, pgid: int, timeout: float = 3.0) -> bool:
    """Return once a process group has no live, non-zombie members."""

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            records = module._read_process_table(deadline=deadline, clock=time.monotonic)
        except module._RunnerAbort as error:
            if error.code is module.RunnerErrorCode.TIMEOUT:
                return False
            raise
        if not any(
            record.pgid == pgid and not record.state.startswith(b"Z")
            for record in records.values()
        ):
            return True
        time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
    return False


def _kill_test_process_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


class _ExactPinFake:
    exact_signals = True

    def __init__(self, *, pid: int, ppid: int, pgid: int, uid: int) -> None:
        self.pid = pid
        self.ppid = ppid
        self.pgid = pgid
        self.uid = uid
        self.live = True
        self.closed = False
        self.signal_calls = []
        self.signal_error = None
        self.ignore_term = False

    def current(self):
        if not self.live:
            return None
        return SimpleNamespace(
            pid=self.pid,
            ppid=self.ppid,
            pgid=self.pgid,
            uid=self.uid,
            status=2,
            birth=(123456789, 123456),
        )

    def send_signal(self, signal_number):
        self.signal_calls.append(signal_number)
        if self.signal_error is not None:
            raise self.signal_error
        if signal_number != signal.SIGTERM or not self.ignore_term:
            self.live = False
        return True

    def close(self):
        self.closed = True


class G008RunnerContractTests(unittest.TestCase):
    def test_runner_module_exists(self) -> None:
        self.assertEqual(runner_module().FRAME_MAGIC, b"CGRF1\x00")

    def test_cgrf_golden_big_endian_greedy_and_empty(self) -> None:
        module = runner_module()
        self.assertEqual(module.frame_sanitized_capture(b"", b""), b"CGRF1\x00")
        self.assertEqual(
            module.frame_sanitized_capture(b"x", b""),
            b"CGRF1\x00" + (0).to_bytes(8, "big") + b"\x01" + (1).to_bytes(4, "big") + b"x",
        )
        framed = module.frame_sanitized_capture(b"a" * 4097, b"z")
        frames = module.validate_framed_capture(framed)
        self.assertEqual(
            [(item.sequence, item.channel, len(item.payload)) for item in frames],
            [(0, 1, 4096), (1, 1, 1), (2, 2, 1)],
        )
        self.assertEqual(framed[6:14], (0).to_bytes(8, "big"))
        self.assertEqual(framed[15:19], (4096).to_bytes(4, "big"))

    def test_validator_rejects_every_noncanonical_shape(self) -> None:
        module = runner_module()
        valid = module.frame_sanitized_capture(b"a" * 4097, b"b")
        mutations = [
            b"",
            valid[:-1],
            valid + b"x",
            valid[:6] + (9).to_bytes(8, "big") + valid[14:],
            valid[:14] + b"\x03" + valid[15:],
            valid[:15] + (0).to_bytes(4, "big") + valid[19:],
            valid[:15] + (4097).to_bytes(4, "big") + valid[19:],
        ]
        for candidate in mutations:
            with self.subTest(length=len(candidate)):
                with self.assertRaises(ValueError):
                    module.validate_framed_capture(candidate)
        # A short stdout frame followed by another stdout frame is non-greedy.
        non_greedy = (
            module.FRAME_MAGIC
            + (0).to_bytes(8, "big") + b"\x01" + (1).to_bytes(4, "big") + b"a"
            + (1).to_bytes(8, "big") + b"\x01" + (1).to_bytes(4, "big") + b"b"
        )
        with self.assertRaises(ValueError):
            module.validate_framed_capture(non_greedy)

    def test_real_process_drains_stderr_before_stdout_without_deadlock(self) -> None:
        with Harness(self) as harness:
            result = harness.run(
                "import os; os.write(2, b'e\\n' * 50000); os.write(1, b'done\\n')"
            )
            self.assertTrue(result.succeeded)
            request = harness.store.calls[0][0]
            frames = runner_module().validate_framed_capture(request.payload)
            channels = [frame.channel for frame in frames]
            self.assertEqual(channels, sorted(channels))
            self.assertIn(b"done", b"".join(f.payload for f in frames if f.channel == 1))

    def test_spawn_is_literal_with_exact_isolated_popen_kwargs(self) -> None:
        calls = []

        def recording_popen(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.Popen(argv, **kwargs)

        literal = "; touch SHOULD_NOT_EXIST"
        with Harness(self) as harness:
            result = harness.run(
                "import os,sys; os.write(1, sys.argv[1].encode())",
                arguments=(literal, ""),
                popen_factory=recording_popen,
            )
            self.assertTrue(result.succeeded)
            argv, kwargs = calls[0]
            self.assertIs(type(argv), tuple)
            self.assertEqual(argv[-2:], (literal, ""))
            self.assertEqual(argv[1:5], ("-I", "-S", "-B", "-c"))
            self.assertIn("os.fchdir(root_fd)", argv[5])
            self.assertEqual(
                set(kwargs),
                {
                    "bufsize",
                    "close_fds",
                    "cwd",
                    "env",
                    "pass_fds",
                    "shell",
                    "start_new_session",
                    "stderr",
                    "stdin",
                    "stdout",
                },
            )
            self.assertEqual(kwargs["cwd"], "/")
            self.assertEqual(
                kwargs["env"], {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
            )
            self.assertIs(kwargs["shell"], False)
            self.assertIs(kwargs["close_fds"], True)
            self.assertIs(kwargs["start_new_session"], True)
            self.assertEqual(kwargs["bufsize"], 0)
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            self.assertEqual(kwargs["stdout"], subprocess.PIPE)
            self.assertEqual(kwargs["stderr"], subprocess.PIPE)
            self.assertEqual(len(kwargs["pass_fds"]), 3)
            self.assertTrue(all(type(fd) is int and fd >= 0 for fd in kwargs["pass_fds"]))
            self.assertFalse((Path(harness.root) / "SHOULD_NOT_EXIST").exists())

    def test_argv_echo_never_enters_receipt_or_capture_even_after_sanitizer_transforms(self) -> None:
        for argument in (
            "opaque-argument-value",
            "a",
            "[",
            r"opaque\argument",
            "line\rreturn",
            "\x1b[31mcolored",
            "api_key=argument-secret",
        ):
            with self.subTest(argument=argument), Harness(self) as harness:
                result = harness.run(
                    "import os,sys; os.write(1, sys.argv[1].encode())",
                    arguments=(argument,),
                )
                self.assertTrue(result.succeeded)
                stdout_summary = result.to_receipt()["stdout"]
                self.assertEqual(stdout_summary["excerpt"], "")
                self.assertIs(stdout_summary["argument_derived_output_redacted"], True)
                captured = harness.store.calls[0][0].payload
                frames = runner_module().validate_framed_capture(captured)
                captured_stdout = b"".join(
                    frame.payload for frame in frames if frame.channel == 1
                )
                self.assertEqual(captured_stdout, b"")

    def test_spawn_cwd_stays_bound_to_the_snapshotted_directory_object(self) -> None:
        """Break caught: a swapped root pathname selects a different child cwd."""

        with Harness(self) as harness:
            root = Path(harness.root)
            held_root = root.with_name(root.name + "-held")
            alternate_root = root.with_name(root.name + "-alternate")
            alternate_root.mkdir(mode=0o700)
            (root / "marker.bin").write_bytes(b"ORIGINAL")
            (alternate_root / "marker.bin").write_bytes(b"ALTERNATE")

            def swapping_popen(argv, **kwargs):
                os.rename(root, held_root)
                os.rename(alternate_root, root)
                try:
                    return subprocess.Popen(argv, **kwargs)
                finally:
                    os.rename(root, alternate_root)
                    os.rename(held_root, root)

            result = harness.run(
                "import os; os.write(1,open('marker.bin','rb').read())",
                popen_factory=swapping_popen,
            )
            self.assertTrue(result.succeeded)
            frames = runner_module().validate_framed_capture(
                harness.store.calls[0][0].payload
            )
            stdout = b"".join(frame.payload for frame in frames if frame.channel == 1)
            self.assertEqual(stdout, b"ORIGINAL")
            self.assertNotIn(b"ALTERNATE", stdout)

    def test_ancestor_symlink_swap_cannot_split_snapshot_from_pinned_cwd(self) -> None:
        """Break caught: snapshots bind B while the command executes in pinned A."""

        module = runner_module()
        with Harness(self) as harness:
            sandbox = Path(harness.root)
            original_parent = sandbox / "original-parent"
            alternate_parent = sandbox / "alternate-parent"
            original_root = original_parent / "repo"
            alternate_root = alternate_parent / "repo"
            original_root.mkdir(parents=True)
            alternate_root.mkdir(parents=True)
            (original_root / "marker.bin").write_bytes(b"ORIGINAL")
            (alternate_root / "marker.bin").write_bytes(b"ALTERNATE")

            route = sandbox / "route"
            route.symlink_to(original_parent, target_is_directory=True)
            routed_root = str(route / "repo")
            original_key = (os.stat(original_root).st_dev, os.stat(original_root).st_ino)
            alternate_key = (
                os.stat(alternate_root).st_dev,
                os.stat(alternate_root).st_ino,
            )
            original_identity = "a" * 64
            alternate_identity = "c" * 64
            identities = {
                original_key: original_identity,
                alternate_key: alternate_identity,
            }
            observations = []

            def retarget(target: Path) -> None:
                replacement = sandbox / "route-next"
                replacement.symlink_to(target, target_is_directory=True)
                os.replace(replacement, route)

            def adversarial_snapshotter(root, *, root_fd=None):
                retarget(alternate_parent)
                try:
                    if root_fd is None:
                        status = os.stat(root, follow_symlinks=False)
                        source = "path"
                    else:
                        status = os.fstat(root_fd)
                        source = "fd"
                    observed_key = (status.st_dev, status.st_ino)
                    observations.append((source, observed_key))
                    return captured_snapshot(identity=identities[observed_key])
                finally:
                    retarget(original_parent)

            result = module.run_command(
                (
                    str(Path(sys.executable).resolve()),
                    "-c",
                    "import os; os.write(1,open('marker.bin','rb').read())",
                ),
                routed_root,
                store_factory=harness.factory,
                snapshotter=adversarial_snapshotter,
            )

            self.assertTrue(result.succeeded)
            self.assertEqual(
                observations,
                [("fd", original_key), ("fd", original_key)],
            )
            request = harness.store.calls[0][0]
            self.assertEqual(request.root_identity_sha256, original_identity)
            frames = module.validate_framed_capture(request.payload)
            stdout = b"".join(frame.payload for frame in frames if frame.channel == 1)
            self.assertEqual(stdout, b"ORIGINAL")
            self.assertEqual(
                (os.stat(routed_root).st_dev, os.stat(routed_root).st_ino),
                original_key,
            )

    def test_legacy_one_argument_snapshotter_remains_supported(self) -> None:
        """Break caught: the FD-aware seam silently rejects existing callbacks."""

        module = runner_module()
        with Harness(self) as harness:
            calls = []
            snapshots = [captured_snapshot(), captured_snapshot()]

            def legacy_snapshotter(root):
                calls.append(root)
                return snapshots.pop(0)

            result = module.run_command(
                (str(Path(sys.executable).resolve()), "-c", "pass"),
                harness.root,
                store_factory=harness.factory,
                snapshotter=legacy_snapshotter,
            )

            self.assertTrue(result.succeeded)
            self.assertEqual(calls, [harness.root, harness.root])

    def test_unrestored_root_replacement_refuses_before_store(self) -> None:
        """Break caught: a pinned run publishes after the pathname stays replaced."""

        with Harness(self) as harness:
            root = Path(harness.root)
            held_root = root.with_name(root.name + "-held")
            alternate_root = root.with_name(root.name + "-alternate")
            alternate_root.mkdir(mode=0o700)
            (root / "marker.bin").write_bytes(b"ORIGINAL")
            (alternate_root / "marker.bin").write_bytes(b"ALTERNATE")

            def replacing_popen(argv, **kwargs):
                os.rename(root, held_root)
                os.rename(alternate_root, root)
                return subprocess.Popen(argv, **kwargs)

            try:
                result = harness.run(
                    "import os; os.write(1,open('marker.bin','rb').read())",
                    popen_factory=replacing_popen,
                )
            finally:
                if root.exists() and held_root.exists():
                    os.rename(root, alternate_root)
                    os.rename(held_root, root)

            self.assertEqual(
                result.error_code, runner_module().RunnerErrorCode.REPOSITORY_REPLACED
            )
            self.assertIsNone(result.receipt)
            self.assertEqual(harness.factory_calls, 0)
            self.assertEqual(harness.store.calls, [])

    def test_pinned_root_descriptor_is_closed_in_the_final_target(self) -> None:
        """Break caught: the repository directory capability leaks across target exec."""

        with Harness(self) as harness:
            root = Path(harness.root)

            def recording_popen(argv, **kwargs):
                pinned_descriptor = kwargs["pass_fds"][0]
                (root / "pinned-fd.txt").write_text(
                    str(pinned_descriptor), encoding="ascii"
                )
                return subprocess.Popen(argv, **kwargs)

            code = (
                "import os; "
                "fd=int(open('pinned-fd.txt').read()); "
                "leaked=False; "
                "\ntry:\n"
                " opened=os.fstat(fd); current=os.stat('.'); "
                "leaked=(opened.st_dev,opened.st_ino)==(current.st_dev,current.st_ino)\n"
                "except OSError: pass\n"
                "os.write(1,b'LEAKED' if leaked else b'CLOSED')"
            )
            result = harness.run(code, popen_factory=recording_popen)
            self.assertTrue(result.succeeded)
            frames = runner_module().validate_framed_capture(
                harness.store.calls[0][0].payload
            )
            stdout = b"".join(frame.payload for frame in frames if frame.channel == 1)
            self.assertEqual(stdout, b"CLOSED")

    def test_invalid_invocations_and_spawn_failure_are_authority_free(self) -> None:
        module = runner_module()
        with Harness(self) as harness:
            candidates = [
                ((), harness.root),
                (("relative",), harness.root),
                (("/bin/echo", "bad\x00arg"), harness.root),
                (("/bin/echo",), harness.root + "/.."),
            ]
            for argv, root in candidates:
                with self.subTest(argv=argv):
                    result = module.run_command(
                        argv,
                        root,
                        store_factory=harness.factory,
                        snapshotter=harness.snapshotter,
                    )
                    self.assertFalse(result.succeeded)
                    self.assertIsNone(result.receipt)
            self.assertEqual(harness.factory_calls, 0)
        with Harness(self) as harness:
            result = harness.run("pass", popen_factory=lambda *_a, **_k: (_ for _ in ()).throw(OSError()))
            self.assertEqual(result.error_code, module.RunnerErrorCode.SPAWN_FAILED)
            self.assertEqual(harness.factory_calls, 0)

        with Harness(self) as harness:
            result = module.run_command(
                ("/contextguard-definitely-missing-command",),
                harness.root,
                store_factory=harness.factory,
                snapshotter=harness.snapshotter,
            )
            self.assertEqual(result.error_code, module.RunnerErrorCode.SPAWN_FAILED)
            self.assertIsNone(result.receipt)
            self.assertEqual(harness.factory_calls, 0)

        for private_roots in (("relative-private-root",), (123,), ["/tmp"]):
            with self.subTest(private_roots=private_roots), Harness(self) as harness:
                spawn_calls = []
                result = harness.run(
                    "pass",
                    private_roots=private_roots,
                    popen_factory=lambda *_args, **_kwargs: spawn_calls.append(True),
                )
                self.assertEqual(result.error_code, module.RunnerErrorCode.INVALID_ARGUMENT)
                self.assertEqual(spawn_calls, [])
                self.assertEqual(harness.factory_calls, 0)

        oversized_argv = (
            ("/bin/echo", *("x" for _ in range(256))),
            ("/bin/echo", "x" * (256 * 1024)),
        )
        for argv in oversized_argv:
            with self.subTest(argv_items=len(argv)), Harness(self) as harness:
                spawn_calls = []
                result = module.run_command(
                    argv,
                    harness.root,
                    store_factory=harness.factory,
                    snapshotter=harness.snapshotter,
                    popen_factory=lambda *_args, **_kwargs: spawn_calls.append(True),
                )
                self.assertEqual(result.error_code, module.RunnerErrorCode.INVALID_ARGUMENT)
                self.assertEqual(spawn_calls, [])
                self.assertEqual(harness.factory_calls, 0)

    def test_non_main_thread_refuses_before_spawning(self) -> None:
        """Break caught: a thread cannot install process signal cleanup safely."""

        results = []
        spawn_calls = []
        with Harness(self) as harness:
            worker = threading.Thread(
                target=lambda: results.append(
                    harness.run(
                        "import time; time.sleep(30)",
                        popen_factory=lambda *_args, **_kwargs: spawn_calls.append(True),
                    )
                )
            )
            worker.start()
            worker.join(timeout=5.0)
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(results), 1)
            self.assertEqual(
                results[0].error_code,
                runner_module().RunnerErrorCode.UNSUPPORTED_PLATFORM,
            )
            self.assertIsNone(results[0].receipt)
            self.assertEqual(spawn_calls, [])
            self.assertEqual(harness.factory_calls, 0)
            self.assertEqual(harness.snapshotter.calls, [])

    def test_signal_installation_restores_prior_handlers_after_injected_interrupt(self) -> None:
        """Break caught: an install-time signal leaves a bound guard installed."""

        module = runner_module()
        guard = module._SignalGuard()
        native_signal = signal.signal
        injected = []

        def signal_with_interrupt(signum, handler):
            previous = native_signal(signum, handler)
            if signum == signal.SIGTERM and not injected:
                injected.append(True)
                os.kill(os.getpid(), signal.SIGTERM)
            return previous

        try:
            with mock.patch.object(
                module.signal, "signal", side_effect=signal_with_interrupt
            ):
                with self.assertRaises(SystemExit) as raised:
                    guard.install()
                self.assertEqual(raised.exception.code, 128 + signal.SIGTERM)
        finally:
            guard.begin_cleanup()
            guard.restore()
        self.assertEqual(injected, [True])
        self.assertIs(signal.getsignal(signal.SIGINT), signal.default_int_handler)
        self.assertEqual(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)

    def test_raw_channel_and_combined_limits_are_exact(self) -> None:
        module = runner_module()
        exact_limits = module.RunnerLimits(
            raw_per_channel_bytes=16,
            raw_total_bytes=16,
            sanitized_per_channel_bytes=64,
            sanitized_total_bytes=64,
            framed_bytes=128,
        )
        with Harness(self) as harness:
            self.assertTrue(harness.run("import os; os.write(1,b'x'*16)", limits=exact_limits).succeeded)
        with Harness(self) as harness:
            result = harness.run("import os; os.write(1,b'x'*17)", limits=exact_limits)
            self.assertEqual(result.error_code, module.RunnerErrorCode.RAW_LIMIT_EXCEEDED)
            self.assertEqual(harness.factory_calls, 0)
        combined = module.RunnerLimits(
            raw_per_channel_bytes=16,
            raw_total_bytes=16,
            sanitized_per_channel_bytes=64,
            sanitized_total_bytes=64,
            framed_bytes=128,
        )
        with Harness(self) as harness:
            result = harness.run("import os; os.write(1,b'x'*9); os.write(2,b'y'*8)", limits=combined)
            self.assertEqual(result.error_code, module.RunnerErrorCode.RAW_LIMIT_EXCEEDED)

    def test_limits_reject_non_finite_timeout(self) -> None:
        module = runner_module()
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.RunnerLimits(timeout_seconds=value)

    def test_sanitized_expansion_and_framed_caps_fail_before_store(self) -> None:
        module = runner_module()
        sanitize_cap = module.RunnerLimits(
            raw_per_channel_bytes=16,
            raw_total_bytes=16,
            sanitized_per_channel_bytes=3,
            sanitized_total_bytes=3,
            framed_bytes=64,
        )
        with Harness(self) as harness:
            result = harness.run("import os; os.write(1,b'\\xff')", limits=sanitize_cap)
            self.assertEqual(result.error_code, module.RunnerErrorCode.SANITIZATION_INCOMPLETE)
            self.assertEqual(harness.factory_calls, 0)
        frame_cap = module.RunnerLimits(
            raw_per_channel_bytes=16,
            raw_total_bytes=16,
            sanitized_per_channel_bytes=16,
            sanitized_total_bytes=16,
            framed_bytes=6,
        )
        with Harness(self) as harness:
            result = harness.run("import os; os.write(1,b'x')", limits=frame_cap)
            self.assertEqual(result.error_code, module.RunnerErrorCode.FRAMED_LIMIT_EXCEEDED)
            self.assertEqual(harness.factory_calls, 0)

    def test_timeout_uses_exact_signals_and_never_numeric_group_signaling(self) -> None:
        module = runner_module()
        limits = module.RunnerLimits(timeout_seconds=0.15)
        for code in (
            "import time; time.sleep(5)",
            "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(5)",
        ):
            with self.subTest(code=code), Harness(self) as harness:
                spawned = []

                def recording_popen(*args, **kwargs):
                    process = subprocess.Popen(*args, **kwargs)
                    spawned.append(process)
                    return process

                with mock.patch.object(
                    module.os,
                    "killpg",
                    side_effect=AssertionError("numeric killpg was called"),
                ) as numeric_killpg:
                    result = harness.run(
                        code,
                        limits=limits,
                        popen_factory=recording_popen,
                    )
                numeric_killpg.assert_not_called()
                self.assertEqual(result.error_code, module.RunnerErrorCode.TIMEOUT)
                self.assertEqual(harness.factory_calls, 0)
                self.assertEqual(len(spawned), 1)
                self.assertIsNotNone(spawned[0].poll())

    def test_child_exit_124_nonzero_and_signal_are_captured_outcomes(self) -> None:
        module = runner_module()
        cases = (
            ("import sys; sys.exit(124)", "exited", 124),
            ("import sys; sys.exit(125)", "exited", 125),
            ("import sys; sys.exit(126)", "exited", 126),
            ("import sys; sys.exit(127)", "exited", 127),
            ("import sys; sys.exit(255)", "exited", 255),
            ("import os,signal; os.kill(os.getpid(), signal.SIGTERM)", "signaled", signal.SIGTERM),
        )
        for code, kind, value in cases:
            with self.subTest(kind=kind), Harness(self) as harness:
                result = harness.run(code)
                self.assertTrue(result.succeeded)
                outcome = result.receipt.outcome
                self.assertEqual(outcome.kind.value, kind)
                self.assertEqual(outcome.exit_code if kind == "exited" else outcome.signal, value)
                self.assertEqual(
                    module.map_cli_exit_code(result),
                    value if kind == "exited" else 128 + value,
                )

    def test_snapshots_must_be_captured_same_instance_but_may_be_dirty(self) -> None:
        module = runner_module()
        unresolved = captured_snapshot()
        unresolved["disposition"] = "pass_through"
        with Harness(self, snapshots=[unresolved]) as harness:
            result = harness.run("pass")
            self.assertEqual(result.error_code, module.RunnerErrorCode.SNAPSHOT_UNRESOLVED)
            self.assertEqual(harness.factory_calls, 0)
        with Harness(
            self,
            snapshots=[captured_snapshot(), captured_snapshot("b" * 64)],
        ) as harness:
            result = harness.run("pass")
            self.assertEqual(result.error_code, module.RunnerErrorCode.REPOSITORY_REPLACED)
            self.assertEqual(harness.factory_calls, 0)
        with Harness(
            self,
            snapshots=[captured_snapshot(state="1" * 64), captured_snapshot(state="2" * 64)],
        ) as harness:
            result = harness.run("pass")
            self.assertTrue(result.succeeded)
            self.assertNotEqual(
                result.receipt.before_observation_sha256,
                result.receipt.after_observation_sha256,
            )

    def test_store_is_opened_last_and_called_once_with_exact_artifact(self) -> None:
        module = runner_module()
        with Harness(self) as harness:
            result = harness.run("import os; os.write(1,b'ok')")
            self.assertTrue(result.succeeded)
            self.assertEqual(harness.factory_calls, 1)
            self.assertEqual(len(harness.store.calls), 1)
            requests = harness.store.calls[0]
            self.assertIs(type(requests), tuple)
            self.assertEqual(len(requests), 1)
            request = requests[0]
            self.assertEqual(request.artifact_type, module.ArtifactType.COMMAND_CAPTURE_BYTES)
            self.assertEqual(request.root_identity_sha256, "a" * 64)
            self.assertEqual(request.subject_identity_sha256, result.receipt.subject_identity_sha256)
            self.assertEqual(len(request.payload), result.receipt.artifact_bytes)
            module.validate_framed_capture(request.payload)
            self.assertTrue(harness.store.closed)

    def test_receipt_validator_closes_cross_field_arithmetic(self) -> None:
        module = runner_module()
        with Harness(self) as harness:
            result = harness.run("import os; os.write(1,b'ok')")
            self.assertTrue(result.succeeded)
            receipt = result.to_receipt()
            self.assertTrue(module.validate_command_capture_receipt(receipt))

        receipt["artifact"]["byte_length"] += 1
        self.assertFalse(module.validate_command_capture_receipt(receipt))
        receipt["artifact"]["byte_length"] -= 1
        receipt["stdout"]["frame_count"] += 1
        self.assertFalse(module.validate_command_capture_receipt(receipt))
        receipt["stdout"]["frame_count"] -= 1
        receipt["stdout"]["sanitized_bytes"] = 900_000
        receipt["stdout"]["frame_count"] = 220
        receipt["stderr"]["sanitized_bytes"] = 900_000
        receipt["stderr"]["frame_count"] = 220
        self.assertFalse(module.validate_command_capture_receipt(receipt))

    def test_store_failures_publish_no_authority_or_candidate_metadata(self) -> None:
        module = runner_module()
        store_module = importlib.import_module("context_guard_receipt.store")
        for store_code, runner_code in (
            (store_module.StoreErrorCode.WRITE_FAILED, module.RunnerErrorCode.STORE_FAILED),
            (store_module.StoreErrorCode.COMMIT_UNCERTAIN, module.RunnerErrorCode.COMMIT_UNCERTAIN),
        ):
            store = StoreSpy(error=store_module.StoreError(store_code))
            with self.subTest(code=store_code.value), Harness(self, store=store) as harness:
                result = harness.run("import os; os.write(1,b'sensitive-candidate')")
                self.assertEqual(result.error_code, runner_code)
                self.assertIsNone(result.receipt)
                rendered = repr(result) + repr(result.to_receipt())
                self.assertNotIn("sensitive-candidate", rendered)
                self.assertNotIn("cgr1p_", rendered)
                for forbidden in ("digest", "frame", "hash", "handle"):
                    self.assertNotIn(forbidden, repr(result.to_receipt()))

    def test_real_store_enospc_is_closed_and_publishes_no_authority(self) -> None:
        """Break caught: a disk-full write escapes or publishes candidate authority."""

        module = runner_module()
        store_module = importlib.import_module("context_guard_receipt.store")
        with Harness(self) as harness, tempfile.TemporaryDirectory() as state_parent:
            state_dir = str((Path(state_parent) / "state").resolve())

            def store_factory():
                return store_module.CapabilityStore.open(
                    state_dir=state_dir,
                    repository_root=harness.root,
                    create=True,
                )

            disk_full = OSError(errno.ENOSPC, "synthetic-private-disk-detail")
            with mock.patch.object(store_module.os, "write", side_effect=disk_full):
                result = module.run_command(
                    (
                        str(Path(sys.executable).resolve()),
                        "-c",
                        "import os; os.write(1,b'disk-candidate')",
                    ),
                    harness.root,
                    store_factory=store_factory,
                    snapshotter=harness.snapshotter,
                )

            self.assertIn(
                result.error_code,
                {module.RunnerErrorCode.STORE_FAILED, module.RunnerErrorCode.COMMIT_UNCERTAIN},
            )
            self.assertIsNone(result.receipt)
            rendered = repr(result) + repr(result.to_receipt())
            self.assertNotIn("synthetic-private-disk-detail", rendered)
            self.assertNotIn("disk-candidate", rendered)
            self.assertNotIn("cgr1p_", rendered)

    def test_keyboard_interrupt_always_terminates_and_reaps_the_child_group(self) -> None:
        """Break caught: BaseException leaves the isolated command session running."""

        with Harness(self) as harness:
            pid_path = Path(harness.root) / "child.pid"

            def interrupt_after_child_starts() -> None:
                deadline = time.monotonic() + 5.0
                while time.monotonic() < deadline:
                    if pid_path.exists():
                        os.kill(os.getpid(), signal.SIGINT)
                        return
                    time.sleep(0.01)

            interrupter = threading.Thread(target=interrupt_after_child_starts)
            interrupter.start()
            try:
                with self.assertRaises(KeyboardInterrupt):
                    harness.run(
                        "import os,time; "
                        "open('child.pid','w').write(str(os.getpid())); "
                        "time.sleep(30)"
                    )
            finally:
                interrupter.join(timeout=5.0)

            self.assertTrue(pid_path.is_file())
            child_pid = int(pid_path.read_text(encoding="ascii"))
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                child_alive = False
            else:
                child_alive = True
                try:
                    os.killpg(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            self.assertFalse(child_alive)
            self.assertEqual(harness.factory_calls, 0)

    def test_interrupt_between_spawn_return_and_assignment_still_reaps_child(self) -> None:
        """Break caught: a signal loses the child before Popen is assigned."""

        spawned = []

        def interrupting_popen(*args, **kwargs):
            process = subprocess.Popen(*args, **kwargs)
            spawned.append(process)
            os.kill(os.getpid(), signal.SIGINT)
            return process

        with Harness(self) as harness:
            with self.assertRaises(KeyboardInterrupt):
                harness.run(
                    "import signal,time; "
                    "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                    "time.sleep(30)",
                    popen_factory=interrupting_popen,
                )
            self.assertEqual(len(spawned), 1)
            self.assertIsNotNone(spawned[0].poll())
            self.assertTrue(spawned[0].stdout.closed)
            self.assertTrue(spawned[0].stderr.closed)
            with self.assertRaises(ProcessLookupError):
                os.killpg(spawned[0].pid, 0)
            self.assertEqual(harness.factory_calls, 0)

    def test_first_signal_during_normal_cleanup_is_delivered_after_cleanup(self) -> None:
        """Break caught: cleanup mode silently drops the first cancellation signal."""

        module = runner_module()
        original_close = module._PinnedRoot.close
        delivered = []

        def interrupting_close(pin):
            original_close(pin)
            if not delivered:
                delivered.append(True)
                os.kill(os.getpid(), signal.SIGTERM)

        with Harness(self) as harness, mock.patch.object(
            module._PinnedRoot, "close", interrupting_close
        ):
            with self.assertRaises(SystemExit) as raised:
                harness.run("import os; os.write(1,b'candidate')")
            self.assertEqual(raised.exception.code, 128 + signal.SIGTERM)
            self.assertEqual(delivered, [True])
            self.assertEqual(len(harness.store.calls), 1)
            self.assertTrue(harness.store.closed)
        self.assertIs(signal.getsignal(signal.SIGINT), signal.default_int_handler)
        self.assertEqual(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)

    def test_sigterm_runs_cleanup_before_the_wrapper_exits(self) -> None:
        """Break caught: default SIGTERM bypasses Python cleanup and orphans the child."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = str(Path(temporary_directory).resolve())
            pid_path = Path(root) / "term-child.pid"
            child_code = (
                "import os,signal,sys,time; "
                "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                "open(sys.argv[1],'w').write(str(os.getpid())); "
                "time.sleep(30)"
            )
            wrapper_code = (
                "import sys\n"
                "sys.path.insert(0,sys.argv[1])\n"
                "from context_guard_receipt.runner import run_command\n"
                f"snapshot={captured_snapshot()!r}\n"
                "run_command((sys.argv[2],'-c',sys.argv[3],sys.argv[4]),sys.argv[5],"
                "store_factory=lambda:None,snapshotter=lambda _root,root_fd=None:snapshot)\n"
            )
            wrapper = subprocess.Popen(
                (
                    str(Path(sys.executable).resolve()),
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    wrapper_code,
                    str(PYTHON_ROOT),
                    str(Path(sys.executable).resolve()),
                    child_code,
                    str(pid_path),
                    root,
                ),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
            )
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and not pid_path.exists():
                if wrapper.poll() is not None:
                    break
                time.sleep(0.01)
            self.assertTrue(pid_path.is_file())
            child_pid = int(pid_path.read_text(encoding="ascii"))
            wrapper.send_signal(signal.SIGTERM)
            time.sleep(0.05)
            if wrapper.poll() is None:
                wrapper.send_signal(signal.SIGTERM)
            stdout, stderr = wrapper.communicate(timeout=5.0)
            self.assertEqual(wrapper.returncode, 128 + signal.SIGTERM, stderr)
            self.assertEqual(stdout, b"")
            self.assertEqual(stderr, b"")
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                child_alive = False
            else:
                child_alive = True
                try:
                    os.killpg(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            self.assertFalse(child_alive)

    def test_post_issue_close_lookup_failure_is_commit_uncertain(self) -> None:
        module = runner_module()

        class CloseLookupFailureStore(StoreSpy):
            @property
            def close(self):
                raise RuntimeError("synthetic-private-close-detail")

        store = CloseLookupFailureStore()
        with Harness(self, store=store) as harness:
            result = harness.run("import os; os.write(1,b'candidate')")
            self.assertEqual(result.error_code, module.RunnerErrorCode.COMMIT_UNCERTAIN)
            self.assertIsNone(result.receipt)
            self.assertEqual(len(store.calls), 1)
            rendered = repr(result) + repr(result.to_receipt())
            self.assertNotIn("synthetic-private-close-detail", rendered)
            self.assertNotIn("candidate", rendered)
            for forbidden in ("digest", "frame", "hash", "handle"):
                self.assertNotIn(forbidden, repr(result.to_receipt()))

    def test_store_time_root_replacement_withholds_committed_authority(self) -> None:
        """Break caught: a store-time root swap publishes a stale-bound receipt."""

        with Harness(self) as harness:
            root = Path(harness.root)
            held_root = root.with_name(root.name + "-held")
            alternate_root = root.with_name(root.name + "-alternate")
            alternate_root.mkdir(mode=0o700)

            class ReplacingStore(StoreSpy):
                def issue_batch(self, requests):
                    issued = super().issue_batch(requests)
                    os.rename(root, held_root)
                    os.rename(alternate_root, root)
                    return issued

            store = ReplacingStore()
            harness.store = store
            try:
                result = harness.run("import os; os.write(1,b'candidate')")
            finally:
                if root.exists() and held_root.exists():
                    os.rename(root, alternate_root)
                    os.rename(held_root, root)

            self.assertEqual(
                result.error_code, runner_module().RunnerErrorCode.COMMIT_UNCERTAIN
            )
            self.assertIsNone(result.receipt)
            self.assertEqual(len(store.calls), 1)
            self.assertTrue(store.closed)
            rendered = repr(result) + repr(result.to_receipt())
            self.assertNotIn("candidate", rendered)
            self.assertNotIn("cgr1p_", rendered)

    def test_success_privacy_sanitizes_secret_and_hides_handle_from_repr(self) -> None:
        secret = "api_key=synthetic-sensitive-value"
        with Harness(self) as harness:
            result = harness.run(f"import os; os.write(1,{secret!r}.encode())")
            self.assertTrue(result.succeeded)
            self.assertNotIn(secret, repr(result))
            self.assertNotIn("cgr1p_" + "h" * 43, repr(result))
            receipt = result.to_receipt()
            self.assertNotIn(secret, repr(receipt))
            self.assertIn("REDACTED SECRET", receipt["stdout"]["excerpt"])

    def test_no_inherited_descriptor_and_fixed_environment(self) -> None:
        read_fd, write_fd = os.pipe()
        try:
            os.set_inheritable(write_fd, True)
            code = (
                "import os,sys; fd=int(sys.argv[1]); "
                "\ntry: os.fstat(fd); out=b'open'"
                "\nexcept OSError: out=b'closed'"
                "\nos.write(1,out)"
            )
            with Harness(self) as harness:
                result = harness.run(code, arguments=(str(write_fd),))
                self.assertTrue(result.succeeded)
                frames = runner_module().validate_framed_capture(harness.store.calls[0][0].payload)
                stdout = b"".join(frame.payload for frame in frames if frame.channel == 1)
                self.assertEqual(stdout, b"closed")
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_runner_source_has_no_network_settings_or_raw_logging_surface(self) -> None:
        source = (PYTHON_ROOT / "context_guard_receipt" / "runner.py").read_text(encoding="utf-8")
        for forbidden in ("import socket", "requests", "urllib", ".env", "settings", "logger."):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("argv", repr(runner_module().CommandRunResult(error_code=runner_module().RunnerErrorCode.INTERNAL).to_receipt()))

    def test_runner_uses_current_sanitizer_types_after_module_reload(self) -> None:
        sanitizer = importlib.import_module("context_guard_receipt.sanitizer")
        importlib.reload(sanitizer)
        with Harness(self) as harness:
            result = harness.run("import os; os.write(1,b'ok')")
            self.assertTrue(result.succeeded)

    def test_maximum_canonical_frame_is_bounded_below_store_ceiling(self) -> None:
        module = runner_module()
        framed = module.frame_sanitized_capture(b"x", b"y" * 899_999)
        self.assertEqual(len(framed), 902_879)
        self.assertLess(len(framed), 1024 * 1024)
        self.assertEqual(len(module.validate_framed_capture(framed)), 221)

    def test_read_failure_is_closed_and_terminates_without_store(self) -> None:
        module = runner_module()

        class BrokenSelector:
            def __init__(self):
                self.delegate = __import__("selectors").DefaultSelector()

            def register(self, *args):
                return self.delegate.register(*args)

            def get_map(self):
                return self.delegate.get_map()

            def select(self, _timeout):
                raise OSError("synthetic-private-read-detail")

            def unregister(self, *args):
                return self.delegate.unregister(*args)

            def close(self):
                return self.delegate.close()

        with Harness(self) as harness:
            result = harness.run("import time; time.sleep(5)", selector_factory=BrokenSelector)
            self.assertEqual(result.error_code, module.RunnerErrorCode.READ_FAILED)
            self.assertEqual(harness.factory_calls, 0)
            self.assertNotIn("synthetic-private-read-detail", repr(result.to_receipt()))

    def test_selector_factory_failure_closes_pipes_and_reaps_child(self) -> None:
        module = runner_module()
        spawned = []

        def recording_popen(*args, **kwargs):
            process = subprocess.Popen(*args, **kwargs)
            spawned.append(process)
            return process

        def broken_selector():
            raise RuntimeError("synthetic-private-selector-detail")

        with Harness(self) as harness:
            result = harness.run(
                "import time; time.sleep(5)",
                popen_factory=recording_popen,
                selector_factory=broken_selector,
            )
            self.assertEqual(result.error_code, module.RunnerErrorCode.INTERNAL)
            self.assertEqual(harness.factory_calls, 0)
            self.assertEqual(len(spawned), 1)
            self.assertIsNotNone(spawned[0].poll())
            self.assertTrue(spawned[0].stdout.closed)
            self.assertTrue(spawned[0].stderr.closed)
            self.assertNotIn(
                "synthetic-private-selector-detail", repr(result.to_receipt())
            )

    def test_descendant_held_pipes_are_killed_after_leader_exit(self) -> None:
        module = runner_module()
        limits = module.RunnerLimits(timeout_seconds=0.2)
        child_code = (
            "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(5)"
        )
        parent_code = (
            "import subprocess,sys; "
            f"subprocess.Popen([sys.executable,'-c',{child_code!r}],stdout=sys.stdout,stderr=sys.stderr)"
        )
        with Harness(self) as harness:
            spawned = []

            def recording_popen(*args, **kwargs):
                process = subprocess.Popen(*args, **kwargs)
                spawned.append(process)
                return process

            with mock.patch.object(
                module.os,
                "killpg",
                side_effect=AssertionError("numeric killpg was called"),
            ) as numeric_killpg:
                result = harness.run(
                    parent_code,
                    limits=limits,
                    popen_factory=recording_popen,
                )
            numeric_killpg.assert_not_called()
            self.assertEqual(result.error_code, module.RunnerErrorCode.TIMEOUT)
            self.assertEqual(harness.factory_calls, 0)
            self.assertEqual(len(spawned), 1)
            self.assertIsNotNone(spawned[0].poll())
            self.assertTrue(
                _wait_for_process_group_quiescence(module, spawned[0].pid)
            )

    def test_descendant_that_closes_pipes_must_quiesce_before_deadline(self) -> None:
        module = runner_module()

        def parent_code(child_delay: float) -> str:
            child = f"import time; time.sleep({child_delay!r})"
            return (
                "import subprocess,sys; "
                f"subprocess.Popen((sys.executable,'-c',{child!r}),"
                "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
                "stderr=subprocess.DEVNULL,close_fds=True)"
            )

        with Harness(self) as harness:
            result = harness.run(
                parent_code(0.05), limits=module.RunnerLimits(timeout_seconds=1.0)
            )
            self.assertTrue(result.succeeded)
            self.assertEqual(harness.factory_calls, 1)

        spawned = []

        def recording_popen(*args, **kwargs):
            process = subprocess.Popen(*args, **kwargs)
            spawned.append(process)
            return process

        with Harness(self) as harness:
            result = harness.run(
                parent_code(5.0),
                limits=module.RunnerLimits(timeout_seconds=0.15),
                popen_factory=recording_popen,
            )
            self.assertEqual(result.error_code, module.RunnerErrorCode.TIMEOUT)
            self.assertEqual(harness.factory_calls, 0)
            self.assertEqual(len(spawned), 1)
            with self.assertRaises(ProcessLookupError):
                os.killpg(spawned[0].pid, 0)

    def test_setsid_descendant_that_closes_stdio_blocks_normal_publication(self) -> None:
        """Break caught: a detached new group outlives its normally exited leader."""

        module = runner_module()
        detached_pid = None
        with Harness(self) as harness:
            pid_path = Path(harness.root) / "detached.pid"
            code = (
                "import os,signal,sys,time\n"
                "child=os.fork()\n"
                "if child == 0:\n"
                " os.setsid()\n"
                " for descriptor in (0,1,2):\n"
                "  try: os.close(descriptor)\n"
                "  except OSError: pass\n"
                " signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
                " with open(sys.argv[1],'w') as stream:\n"
                "  stream.write(str(os.getpid())); stream.flush(); os.fsync(stream.fileno())\n"
                " time.sleep(30)\n"
                " os._exit(0)\n"
                "deadline=time.monotonic()+3\n"
                "while not os.path.exists(sys.argv[1]) and time.monotonic()<deadline:\n"
                " time.sleep(0.005)\n"
                "time.sleep(0.15)\n"
            )
            try:
                result = harness.run(
                    code,
                    arguments=(str(pid_path),),
                    limits=module.RunnerLimits(timeout_seconds=0.4),
                )
                self.assertTrue(pid_path.is_file())
                detached_pid = int(pid_path.read_text(encoding="ascii"))
                self.assertEqual(result.error_code, module.RunnerErrorCode.TIMEOUT)
                self.assertIsNone(result.receipt)
                self.assertEqual(harness.factory_calls, 0)
                self.assertTrue(_wait_for_process_exit(detached_pid))
            finally:
                if detached_pid is None and pid_path.is_file():
                    detached_pid = int(pid_path.read_text(encoding="ascii"))
                if detached_pid is not None:
                    _kill_test_process_group(detached_pid)

    def test_sigterm_cleanup_reaps_tracked_setsid_descendant(self) -> None:
        """Break caught: wrapper cancellation cleans only the leader's old group."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = str(Path(temporary_directory).resolve())
            pid_path = Path(root) / "detached-signal.pid"
            command_code = (
                "import os,signal,sys,time\n"
                "child=os.fork()\n"
                "if child == 0:\n"
                " os.setsid()\n"
                " for descriptor in (0,1,2):\n"
                "  try: os.close(descriptor)\n"
                "  except OSError: pass\n"
                " signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
                " with open(sys.argv[1],'w') as stream:\n"
                "  stream.write(str(os.getpid())); stream.flush(); os.fsync(stream.fileno())\n"
                " time.sleep(30)\n"
                " os._exit(0)\n"
                "time.sleep(30)\n"
            )
            wrapper_code = (
                "import sys\n"
                "sys.path.insert(0,sys.argv[1])\n"
                "from context_guard_receipt.runner import run_command\n"
                f"snapshot={captured_snapshot()!r}\n"
                "run_command((sys.argv[2],'-c',sys.argv[3],sys.argv[4]),sys.argv[5],"
                "store_factory=lambda:None,snapshotter=lambda _root,root_fd=None:snapshot)\n"
            )
            wrapper = subprocess.Popen(
                (
                    str(Path(sys.executable).resolve()),
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    wrapper_code,
                    str(PYTHON_ROOT),
                    str(Path(sys.executable).resolve()),
                    command_code,
                    str(pid_path),
                    root,
                ),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
            )
            detached_pid = None
            try:
                deadline = time.monotonic() + 5.0
                while time.monotonic() < deadline and not pid_path.is_file():
                    if wrapper.poll() is not None:
                        break
                    time.sleep(0.01)
                self.assertTrue(pid_path.is_file())
                detached_pid = int(pid_path.read_text(encoding="ascii"))
                time.sleep(0.2)
                wrapper.send_signal(signal.SIGTERM)
                stdout, stderr = wrapper.communicate(timeout=5.0)
                self.assertEqual(wrapper.returncode, 128 + signal.SIGTERM, stderr)
                self.assertEqual(stdout, b"")
                self.assertEqual(stderr, b"")
                self.assertTrue(_wait_for_process_exit(detached_pid))
            finally:
                if wrapper.poll() is None:
                    wrapper.kill()
                    wrapper.communicate(timeout=5.0)
                if detached_pid is None and pid_path.is_file():
                    detached_pid = int(pid_path.read_text(encoding="ascii"))
                if detached_pid is not None:
                    _kill_test_process_group(detached_pid)

    def test_missing_fixed_process_table_tool_fails_closed_before_store(self) -> None:
        """Break caught: lifecycle discovery silently degrades when unavailable."""

        module = runner_module()
        with Harness(self) as harness, mock.patch.object(
            module,
            "_PROCESS_TABLE_EXECUTABLE",
            "/contextguard-missing-process-table-tool",
            create=True,
        ):
            result = harness.run("pass")
            self.assertEqual(
                result.error_code, module.RunnerErrorCode.UNSUPPORTED_PLATFORM
            )
            self.assertIsNone(result.receipt)
            self.assertEqual(harness.factory_calls, 0)

    def test_unavailable_exact_pin_backend_refuses_before_target_start(self) -> None:
        """Break caught: a command starts before exact pin support is established."""

        module = runner_module()
        spawn_calls = []
        with Harness(self) as harness, mock.patch.object(
            module,
            "_pin_process",
            side_effect=module._RunnerAbort(module.RunnerErrorCode.UNSUPPORTED_PLATFORM),
        ):
            result = harness.run(
                "pass",
                popen_factory=lambda *_args, **_kwargs: spawn_calls.append(True),
            )
            self.assertEqual(
                result.error_code, module.RunnerErrorCode.UNSUPPORTED_PLATFORM
            )
            self.assertEqual(spawn_calls, [])
            self.assertEqual(harness.snapshotter.calls, [])
            self.assertEqual(harness.factory_calls, 0)

    def test_process_identity_includes_real_uid(self) -> None:
        """Break caught: lineage enumeration omits the real security principal."""

        module = runner_module()
        try:
            records = module._parse_process_table(
                b"123 1 123 501 R\n"
            )
        except module._RunnerAbort:
            self.fail("numeric real-UID process identity was rejected")
        self.assertEqual(records[123].uid, 501)

    def test_process_table_exact_pin_mismatch_refuses_publication(self) -> None:
        """Break caught: ps lineage fields override an exact current process pin."""

        module = runner_module()
        native_read = module._read_process_table
        observations = 0

        def identity_changing_read(**kwargs):
            nonlocal observations
            records = native_read(**kwargs)
            observations += 1
            if observations == 1:
                return records
            return {
                pid: SimpleNamespace(
                    pid=record.pid,
                    ppid=record.ppid,
                    pgid=record.pgid + 1,
                    uid=getattr(record, "uid", os.getuid()),
                    state=record.state,
                )
                for pid, record in records.items()
            }

        with Harness(self) as harness, mock.patch.object(
            module, "_read_process_table", side_effect=identity_changing_read
        ):
            result = harness.run("import time; time.sleep(0.3)")
            self.assertEqual(result.error_code, module.RunnerErrorCode.INTERNAL)
            self.assertIsNone(result.receipt)
            self.assertEqual(harness.factory_calls, 0)

    def test_unrelated_same_uid_process_group_is_never_signaled(self) -> None:
        """Break caught: same-user process-table entries become signal targets."""

        module = runner_module()
        unrelated = subprocess.Popen(
            (str(Path(sys.executable).resolve()), "-c", "import time; time.sleep(30)"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
        )
        try:
            with Harness(self) as harness:
                with mock.patch.object(
                    module.os,
                    "killpg",
                    side_effect=AssertionError("numeric killpg was called"),
                ) as numeric_killpg:
                    result = harness.run(
                        "import time; time.sleep(30)",
                        limits=module.RunnerLimits(timeout_seconds=0.15),
                    )
                self.assertEqual(result.error_code, module.RunnerErrorCode.TIMEOUT)
                numeric_killpg.assert_not_called()
                self.assertIsNone(unrelated.poll())
        finally:
            if unrelated.poll() is None:
                os.killpg(unrelated.pid, signal.SIGKILL)
            unrelated.wait(timeout=5.0)

    def test_same_uid_same_second_pid_reuse_never_signals_replacement_group(self) -> None:
        """Break caught: coarse ps start text authorizes a reused PID group signal."""

        module = runner_module()
        uid = os.getuid()
        root_pid = 51001
        root_record = SimpleNamespace(
            pid=root_pid, ppid=os.getpid(), pgid=root_pid, uid=uid, state=b"R"
        )
        original_pin = _ExactPinFake(
            pid=root_pid, ppid=os.getpid(), pgid=root_pid, uid=uid
        )
        pin_calls = []

        def pin_factory(pid):
            pin_calls.append(pid)
            if pid != root_pid or len(pin_calls) != 1:
                raise AssertionError("a replacement PID must never be adopted")
            return original_pin

        try:
            tracker = module._DescendantTracker(
                root_pid, pin_factory=pin_factory
            )
        except TypeError:
            self.fail("descendant tracker has no exact process-pin boundary")
        process = SimpleNamespace(
            pid=root_pid,
            poll=lambda: 0,
            wait=lambda **_kwargs: 0,
        )
        try:
            with mock.patch.object(
                module,
                "_read_process_table",
                side_effect=(
                    {root_pid: root_record},
                    {root_pid: root_record},
                    module._RunnerAbort(module.RunnerErrorCode.INTERNAL),
                ),
            ):
                tracker.establish(deadline=time.monotonic() + 1, clock=time.monotonic)
                original_pin.live = False
                with self.assertRaises(module._RunnerAbort):
                    tracker.observe(
                        deadline=time.monotonic() + 1, clock=time.monotonic
                    )
                module._terminate_process(process, tracker)
            self.assertEqual(original_pin.signal_calls, [])
            self.assertEqual(pin_calls, [root_pid])
        finally:
            tracker.close()
        self.assertTrue(original_pin.closed)

    def test_mutable_topology_transition_retries_one_fresh_exact_observation(self) -> None:
        """Break caught: an ordinary setsid race discards the exact child pin."""

        module = runner_module()
        uid = os.getuid()
        root_pid = 51501
        child_pid = 51502
        root_record = SimpleNamespace(
            pid=root_pid, ppid=os.getpid(), pgid=root_pid, uid=uid, state=b"R"
        )
        stale_child_record = SimpleNamespace(
            pid=child_pid, ppid=root_pid, pgid=root_pid, uid=uid, state=b"R"
        )
        fresh_child_record = SimpleNamespace(
            pid=child_pid, ppid=root_pid, pgid=child_pid, uid=uid, state=b"R"
        )
        root_pin = _ExactPinFake(
            pid=root_pid, ppid=os.getpid(), pgid=root_pid, uid=uid
        )
        stale_candidate_pin = _ExactPinFake(
            pid=child_pid, ppid=root_pid, pgid=child_pid, uid=uid
        )
        fresh_candidate_pin = _ExactPinFake(
            pid=child_pid, ppid=root_pid, pgid=child_pid, uid=uid
        )
        candidate_pins = iter((stale_candidate_pin, fresh_candidate_pin))

        def pin_factory(pid):
            if pid == root_pid:
                return root_pin
            if pid == child_pid:
                return next(candidate_pins)
            raise AssertionError("only the reachable child may be pinned")

        tracker = module._DescendantTracker(root_pid, pin_factory=pin_factory)
        try:
            with mock.patch.object(
                module,
                "_read_process_table",
                side_effect=(
                    {root_pid: root_record},
                    {root_pid: root_record, child_pid: stale_child_record},
                    {root_pid: root_record, child_pid: fresh_child_record},
                ),
            ):
                tracker.establish(deadline=time.monotonic() + 1, clock=time.monotonic)
                try:
                    observed = tracker.observe(
                        deadline=time.monotonic() + 1, clock=time.monotonic
                    )
                except module._RunnerAbort as error:
                    self.fail(f"ordinary topology transition was not retried: {error.code}")
            self.assertEqual([item.pid for item in observed], [root_pid, child_pid])
            self.assertEqual(observed[1].pgid, child_pid)
            self.assertIs(tracker.pins[child_pid], fresh_candidate_pin)
            self.assertTrue(stale_candidate_pin.closed)
            self.assertFalse(fresh_candidate_pin.closed)
        finally:
            tracker.close()
        self.assertTrue(root_pin.closed)
        self.assertTrue(fresh_candidate_pin.closed)

    def test_repeated_topology_transition_closes_all_uncommitted_pins(self) -> None:
        """Break caught: a failed fresh observation retains candidate pin authority."""

        module = runner_module()
        uid = os.getuid()
        root_pid = 51701
        child_pid = 51702
        root_record = SimpleNamespace(
            pid=root_pid, ppid=os.getpid(), pgid=root_pid, uid=uid, state=b"R"
        )
        stale_child_record = SimpleNamespace(
            pid=child_pid, ppid=root_pid, pgid=root_pid, uid=uid, state=b"R"
        )
        fresh_child_record = SimpleNamespace(
            pid=child_pid, ppid=root_pid, pgid=child_pid, uid=uid, state=b"R"
        )
        root_pin = _ExactPinFake(
            pid=root_pid, ppid=os.getpid(), pgid=root_pid, uid=uid
        )
        candidate_pins = (
            _ExactPinFake(pid=child_pid, ppid=root_pid, pgid=child_pid, uid=uid),
            _ExactPinFake(pid=child_pid, ppid=root_pid, pgid=child_pid + 1, uid=uid),
        )
        pending_candidates = iter(candidate_pins)

        def pin_factory(pid):
            if pid == root_pid:
                return root_pin
            if pid == child_pid:
                return next(pending_candidates)
            raise AssertionError("only the reachable child may be pinned")

        tracker = module._DescendantTracker(root_pid, pin_factory=pin_factory)
        try:
            with mock.patch.object(
                module,
                "_read_process_table",
                side_effect=(
                    {root_pid: root_record},
                    {root_pid: root_record, child_pid: stale_child_record},
                    {root_pid: root_record, child_pid: fresh_child_record},
                ),
            ):
                tracker.establish(deadline=time.monotonic() + 1, clock=time.monotonic)
                with self.assertRaises(module._RunnerAbort) as raised:
                    tracker.observe(
                        deadline=time.monotonic() + 1, clock=time.monotonic
                    )
            self.assertEqual(raised.exception.code, module.RunnerErrorCode.INTERNAL)
            self.assertEqual(set(tracker.pins), {root_pid})
            self.assertEqual(tracker.active_groups, {root_pid})
            self.assertTrue(all(pin.closed for pin in candidate_pins))
        finally:
            tracker.close()
        self.assertTrue(root_pin.closed)

    def test_cleanup_ps_failure_uses_exact_pins_for_observed_detached_group(self) -> None:
        """Break caught: cleanup loses a safe detached target when ps later fails."""

        module = runner_module()
        uid = os.getuid()
        root_pid = 52001
        child_pid = 52002
        root_record = SimpleNamespace(
            pid=root_pid, ppid=os.getpid(), pgid=root_pid, uid=uid, state=b"R"
        )
        child_record = SimpleNamespace(
            pid=child_pid, ppid=root_pid, pgid=child_pid, uid=uid, state=b"R"
        )
        pins = {
            root_pid: _ExactPinFake(
                pid=root_pid, ppid=os.getpid(), pgid=root_pid, uid=uid
            ),
            child_pid: _ExactPinFake(
                pid=child_pid, ppid=root_pid, pgid=child_pid, uid=uid
            ),
        }
        try:
            tracker = module._DescendantTracker(
                root_pid, pin_factory=lambda pid: pins[pid]
            )
        except TypeError:
            self.fail("descendant tracker has no exact process-pin boundary")
        process = SimpleNamespace(
            pid=root_pid,
            poll=lambda: None,
            wait=lambda **_kwargs: 0,
        )
        try:
            with mock.patch.object(
                module,
                "_read_process_table",
                side_effect=(
                    {root_pid: root_record},
                    {root_pid: root_record, child_pid: child_record},
                    module._RunnerAbort(module.RunnerErrorCode.INTERNAL),
                ),
            ):
                tracker.establish(deadline=time.monotonic() + 1, clock=time.monotonic)
                tracker.observe(deadline=time.monotonic() + 1, clock=time.monotonic)
                module._terminate_process(process, tracker)
            self.assertEqual(pins[root_pid].signal_calls, [signal.SIGTERM])
            self.assertEqual(pins[child_pid].signal_calls, [signal.SIGTERM])
        finally:
            tracker.close()
        self.assertTrue(all(pin.closed for pin in pins.values()))

    def test_non_exact_pin_refuses_without_numeric_signal_fallback(self) -> None:
        """Break caught: a non-exact pin reaches legacy killpg authority."""

        module = runner_module()
        uid = os.getuid()
        root_pid = 53001
        pin = _ExactPinFake(
            pid=root_pid, ppid=os.getpid(), pgid=root_pid, uid=uid
        )
        pin.exact_signals = False
        tracker = module._DescendantTracker(
            root_pid, pin_factory=lambda _pid: pin
        )
        tracker.pins[root_pid] = pin
        try:
            with self.assertRaises(module._RunnerAbort) as raised:
                tracker.signal(signal.SIGKILL)
            self.assertEqual(raised.exception.code, module.RunnerErrorCode.INTERNAL)
        finally:
            tracker.close()

    def test_darwin_exact_signal_never_uses_numeric_pid_after_check(self) -> None:
        """Break caught: PID reuse between identity check and os.kill hits a replacement."""

        module = runner_module()
        pid = 53501
        info = module._ExactProcessInfo(
            pid=pid,
            ppid=os.getpid(),
            pgid=pid,
            uid=os.getuid(),
            status=2,
            birth=(123456789, 123456),
        )
        audit_token = (501, 501, 20, os.getuid(), 20, pid, 7, 91)
        exact_snapshot = getattr(module, "_darwin_exact_process_snapshot", None)
        self.assertTrue(callable(exact_snapshot), "missing exact Darwin task-port bracket")
        exact_signal = getattr(module, "_darwin_signal_audit_token", None)
        self.assertTrue(callable(exact_signal), "missing audit-token signal boundary")

        with mock.patch.object(
            module, "_darwin_exact_process_snapshot", return_value=(audit_token, info)
        ), mock.patch.object(
            module, "_darwin_signal_audit_token", return_value=True
        ) as delivered, mock.patch.object(
            module.os,
            "kill",
            side_effect=AssertionError("numeric PID signaling is forbidden"),
        ) as numeric_kill:
            pin = module._DarwinProcessPin(pid)
            try:
                self.assertTrue(pin.exact_signals)
                self.assertTrue(pin.send_signal(signal.SIGTERM))
            finally:
                pin.close()
        numeric_kill.assert_not_called()
        delivered.assert_called_once_with(audit_token, signal.SIGTERM)

    def test_darwin_changed_task_token_retries_without_signaling_and_deallocates(self) -> None:
        """Break caught: an exec/reuse transition turns a stale audit token into authority."""

        module = runner_module()
        pid = 53601
        info = module._ExactProcessInfo(
            pid=pid,
            ppid=os.getpid(),
            pgid=pid,
            uid=os.getuid(),
            status=2,
            birth=(123456789, 123456),
        )
        first = (501, 501, 20, os.getuid(), 20, pid, 7, 101)
        second = (501, 501, 20, os.getuid(), 20, pid, 7, 102)
        deallocated = []
        exact_signal = mock.Mock(side_effect=AssertionError("stale token was signaled"))
        with mock.patch.object(
            module, "_darwin_open_task_name", return_value=(700, 800)
        ), mock.patch.object(
            module,
            "_darwin_task_audit_token",
            side_effect=(first, second, first, second, first, second),
        ), mock.patch.object(
            module, "_darwin_proc_pidinfo", return_value=info
        ), mock.patch.object(
            module,
            "_darwin_deallocate_task_name",
            side_effect=lambda task_self, task_name: deallocated.append(
                (task_self, task_name)
            ),
        ), mock.patch.object(module, "_darwin_signal_audit_token", exact_signal):
            with self.assertRaises(module._RunnerAbort) as raised:
                module._darwin_exact_process_snapshot(pid)
        self.assertEqual(raised.exception.code, module.RunnerErrorCode.INTERNAL)
        self.assertEqual(deallocated, [(700, 800), (700, 800), (700, 800)])
        exact_signal.assert_not_called()

    def test_darwin_old_token_esrch_has_no_numeric_fallback(self) -> None:
        """Break caught: an exited exact token falls back to signaling its reused PID."""

        module = runner_module()
        pid = 53701
        info = module._ExactProcessInfo(
            pid=pid,
            ppid=os.getpid(),
            pgid=pid,
            uid=os.getuid(),
            status=2,
            birth=(123456789, 123456),
        )
        old_token = (501, 501, 20, os.getuid(), 20, pid, 7, 111)
        with mock.patch.object(
            module,
            "_darwin_exact_process_snapshot",
            side_effect=((old_token, info), (old_token, info), None),
        ), mock.patch.object(
            module, "_darwin_signal_audit_token", return_value=False
        ) as delivered, mock.patch.object(
            module.os,
            "kill",
            side_effect=AssertionError("numeric PID signaling is forbidden"),
        ) as numeric_kill:
            pin = module._DarwinProcessPin(pid)
            try:
                self.assertFalse(pin.send_signal(signal.SIGKILL))
            finally:
                pin.close()
        numeric_kill.assert_not_called()
        delivered.assert_called_once_with(old_token, signal.SIGKILL)

    def test_darwin_audit_signal_treats_direct_esrch_result_as_gone(self) -> None:
        """Break caught: libproc returns ESRCH directly while ctypes errno stays zero."""

        module = runner_module()
        pid = 53751
        audit_token = (501, 501, 20, os.getuid(), 20, pid, 7, 116)

        def stale_signal(_token, _signal_number):
            module.ctypes.set_errno(0)
            return errno.ESRCH

        with mock.patch.object(
            module,
            "_DARWIN_LIBPROC_HANDLE",
            SimpleNamespace(proc_signal_with_audittoken=stale_signal),
        ):
            try:
                delivered = module._darwin_signal_audit_token(
                    audit_token, signal.SIGKILL
                )
            except module._RunnerAbort as error:
                self.fail(f"direct ESRCH was not treated as gone: {error.code}")
        self.assertFalse(delivered)

    def test_darwin_invalidated_retained_port_retries_exact_bracket(self) -> None:
        """Break caught: a normal exec invalidates T2 and becomes an internal failure."""

        module = runner_module()
        transition_type = getattr(module, "_DarwinTaskTransition", None)
        self.assertTrue(
            isinstance(transition_type, type), "missing bounded Mach transition marker"
        )
        pid = 53761
        info = module._ExactProcessInfo(
            pid=pid,
            ppid=os.getpid(),
            pgid=pid,
            uid=os.getuid(),
            status=2,
            birth=(123456789, 123456),
        )
        audit_token = (501, 501, 20, os.getuid(), 20, pid, 7, 117)
        deallocated = []
        with mock.patch.object(
            module, "_darwin_open_task_name", return_value=(702, 802)
        ), mock.patch.object(
            module,
            "_darwin_task_audit_token",
            side_effect=(transition_type(), audit_token, audit_token),
        ), mock.patch.object(
            module, "_darwin_proc_pidinfo", return_value=info
        ), mock.patch.object(
            module,
            "_darwin_deallocate_task_name",
            side_effect=lambda task_self, task_name: deallocated.append(
                (task_self, task_name)
            ),
        ):
            snapshot = module._darwin_exact_process_snapshot(pid)
        self.assertEqual(snapshot, (audit_token, info))
        self.assertEqual(deallocated, [(702, 802), (702, 802)])

    def test_darwin_task_port_is_deallocated_when_bracket_fails(self) -> None:
        """Break caught: a failed numeric cross-check leaks its task-name send right."""

        module = runner_module()
        pid = 53801
        audit_token = (501, 501, 20, os.getuid(), 20, pid, 7, 121)
        deallocated = []
        with mock.patch.object(
            module, "_darwin_open_task_name", return_value=(701, 801)
        ), mock.patch.object(
            module, "_darwin_task_audit_token", return_value=audit_token
        ), mock.patch.object(
            module,
            "_darwin_proc_pidinfo",
            side_effect=module._RunnerAbort(module.RunnerErrorCode.INTERNAL),
        ), mock.patch.object(
            module,
            "_darwin_deallocate_task_name",
            side_effect=lambda task_self, task_name: deallocated.append(
                (task_self, task_name)
            ),
        ):
            with self.assertRaises(module._RunnerAbort):
                module._darwin_exact_process_snapshot(pid)
        self.assertEqual(deallocated, [(701, 801)])

    def test_darwin_task_name_success_with_zero_port_retries_without_deallocation(self) -> None:
        """A successful task_name_for_pid call with no send right is a transition."""

        module = runner_module()
        pid = 53811
        info = module._ExactProcessInfo(
            pid=pid,
            ppid=os.getpid(),
            pgid=pid,
            uid=os.getuid(),
            status=2,
            birth=(123456789, 123456),
        )
        calls = []

        def task_name_for_pid(_task_self, _pid, output):
            calls.append(True)
            module.ctypes.cast(
                output, module.ctypes.POINTER(module.ctypes.c_uint32)
            ).contents.value = 0
            return 0

        handle = SimpleNamespace(
            mach_task_self=lambda: 703,
            task_name_for_pid=task_name_for_pid,
        )
        with mock.patch.object(module, "_DARWIN_MACH_HANDLE", handle), mock.patch.object(
            module, "_darwin_proc_pidinfo", return_value=info
        ), mock.patch.object(module, "_darwin_deallocate_task_name") as deallocate:
            with self.assertRaises(module._RunnerAbort) as raised:
                module._darwin_exact_process_snapshot(pid)
        self.assertEqual(raised.exception.code, module.RunnerErrorCode.INTERNAL)
        self.assertEqual(len(calls), module._DARWIN_EXACT_ATTEMPTS)
        deallocate.assert_not_called()

    def test_darwin_live_task_name_open_failure_retries_without_deallocation(self) -> None:
        """A live task can return KERN_FAILURE while crossing exec."""

        module = runner_module()
        pid = 538115
        info = module._ExactProcessInfo(
            pid=pid,
            ppid=os.getpid(),
            pgid=pid,
            uid=os.getuid(),
            status=2,
            birth=(123456789, 123456),
        )
        calls = []

        def task_name_for_pid(_task_self, _pid, _output):
            calls.append(True)
            return 5  # KERN_FAILURE during an exec transition

        handle = SimpleNamespace(
            mach_task_self=lambda: 703,
            task_name_for_pid=task_name_for_pid,
        )
        with mock.patch.object(module, "_DARWIN_MACH_HANDLE", handle), mock.patch.object(
            module, "_darwin_proc_pidinfo", return_value=info
        ), mock.patch.object(module, "_darwin_deallocate_task_name") as deallocate:
            with self.assertRaises(module._RunnerAbort) as raised:
                module._darwin_exact_process_snapshot(pid)
        self.assertEqual(raised.exception.code, module.RunnerErrorCode.INTERNAL)
        self.assertEqual(len(calls), module._DARWIN_EXACT_ATTEMPTS)
        deallocate.assert_not_called()

    def test_darwin_task_info_invalid_argument_retries_and_deallocates(self) -> None:
        """KERN_INVALID_ARGUMENT from task_info marks an exec transition."""

        module = runner_module()
        pid = 53812
        calls = []

        def task_info(*_args):
            calls.append(True)
            return 4  # KERN_INVALID_ARGUMENT

        handle = SimpleNamespace(task_info=task_info)
        deallocated = []
        with mock.patch.object(module, "_DARWIN_MACH_HANDLE", handle), mock.patch.object(
            module, "_darwin_open_task_name", return_value=(704, 804)
        ), mock.patch.object(
            module,
            "_darwin_deallocate_task_name",
            side_effect=lambda task_self, task_name: deallocated.append(
                (task_self, task_name)
            ),
        ):
            with self.assertRaises(module._RunnerAbort) as raised:
                module._darwin_exact_process_snapshot(pid)
        self.assertEqual(raised.exception.code, module.RunnerErrorCode.INTERNAL)
        self.assertEqual(len(calls), module._DARWIN_EXACT_ATTEMPTS)
        self.assertEqual(deallocated, [(704, 804)] * module._DARWIN_EXACT_ATTEMPTS)

    def test_process_table_timeout_uses_pinned_signal_without_numeric_fallback(self) -> None:
        """The ps helper is terminated only through its exact process pin."""

        module = runner_module()

        class FakePipe:
            def __init__(self):
                self.closed = False

            def fileno(self):
                return 701

            def close(self):
                self.closed = True

        class FakeSelector:
            def register(self, *_args):
                return None

            def get_map(self):
                return {1: object()}

            def close(self):
                return None

        class FakeProcess:
            pid = 53813

            def __init__(self):
                self.stdout = FakePipe()
                self.kill = mock.Mock()
                self.wait = mock.Mock(return_value=0)

            def poll(self):
                return None

        process = FakeProcess()
        pin = _ExactPinFake(pid=process.pid, ppid=os.getpid(), pgid=process.pid, uid=os.getuid())
        with mock.patch.object(module.subprocess, "Popen", return_value=process), mock.patch.object(
            module, "_pin_process", return_value=pin
        ), mock.patch.object(module.selectors, "DefaultSelector", return_value=FakeSelector()), mock.patch.object(
            module.os, "set_blocking"
        ), mock.patch.object(module.os, "kill") as numeric_kill, mock.patch.object(
            module, "_PROCESS_TABLE_SCAN_SECONDS", 0
        ):
            with self.assertRaises(module._RunnerAbort) as raised:
                clock_values = iter((0, 2))
                module._read_process_table(deadline=1, clock=lambda: next(clock_values))
        self.assertEqual(raised.exception.code, module.RunnerErrorCode.TIMEOUT)
        self.assertEqual(pin.signal_calls, [signal.SIGKILL])
        self.assertTrue(pin.closed)
        process.kill.assert_not_called()
        numeric_kill.assert_not_called()
        self.assertTrue(process.stdout.closed)

    def test_process_table_pin_failure_still_validates_completed_helper_output(self) -> None:
        """Pinning is cleanup-only; a valid, already-completed ps result remains usable."""

        module = runner_module()
        with mock.patch.object(
            module,
            "_pin_process",
            side_effect=module._RunnerAbort(module.RunnerErrorCode.INTERNAL),
        ):
            records = module._read_process_table(
                deadline=time.monotonic() + 2,
                clock=time.monotonic,
            )
        self.assertTrue(records)

    def test_process_table_pin_failure_timeout_has_no_numeric_kill_fallback(self) -> None:
        """An unpinned live helper is only bounded-waited during timeout cleanup."""

        module = runner_module()

        class FakePipe:
            def __init__(self):
                self.closed = False

            def fileno(self):
                return 702

            def close(self):
                self.closed = True

        class FakeSelector:
            def register(self, *_args):
                return None

            def get_map(self):
                return {1: object()}

            def close(self):
                return None

        class FakeProcess:
            pid = 53814

            def __init__(self):
                self.stdout = FakePipe()
                self.kill = mock.Mock()
                self.wait = mock.Mock(return_value=0)

            def poll(self):
                return None

        process = FakeProcess()
        with mock.patch.object(module.subprocess, "Popen", return_value=process), mock.patch.object(
            module,
            "_pin_process",
            side_effect=module._RunnerAbort(module.RunnerErrorCode.UNSUPPORTED_PLATFORM),
        ), mock.patch.object(module.selectors, "DefaultSelector", return_value=FakeSelector()), mock.patch.object(
            module.os, "set_blocking"
        ), mock.patch.object(module.os, "kill") as numeric_kill, mock.patch.object(
            module, "_PROCESS_TABLE_SCAN_SECONDS", 0
        ):
            with self.assertRaises(module._RunnerAbort):
                clock_values = iter((0, 2))
                module._read_process_table(deadline=1, clock=lambda: next(clock_values))
        process.kill.assert_not_called()
        process.wait.assert_called_once()
        numeric_kill.assert_not_called()
        self.assertTrue(process.stdout.closed)

    def test_linux_pidfd_open_facility_failures_refuse_before_target_spawn(self) -> None:
        """Break caught: an unusable pidfd_open is discovered after target release."""

        module = runner_module()
        for error_number in (errno.ENOSYS, errno.EPERM, errno.EINVAL):
            with self.subTest(error_number=error_number), Harness(self) as harness:
                spawn_calls = []
                with mock.patch.object(
                    module.sys, "platform", "linux"
                ), mock.patch.object(
                    module.os,
                    "pidfd_open",
                    side_effect=OSError(error_number, "unusable pidfd_open"),
                    create=True,
                ), mock.patch.object(
                    module.signal, "pidfd_send_signal", return_value=None, create=True
                ):
                    result = harness.run(
                        "open('target-marker','w').write('ran')",
                        popen_factory=lambda *_args, **_kwargs: spawn_calls.append(True),
                    )
                self.assertEqual(
                    result.error_code, module.RunnerErrorCode.UNSUPPORTED_PLATFORM
                )
                self.assertEqual(spawn_calls, [])
                self.assertFalse((Path(harness.root) / "target-marker").exists())

    def test_linux_pidfd_signal_probe_failures_refuse_before_target_spawn(self) -> None:
        """Break caught: pidfd_send_signal availability is inferred without a syscall."""

        module = runner_module()
        pid = os.getpid()
        current = module._ExactProcessInfo(
            pid=pid,
            ppid=os.getppid(),
            pgid=os.getpgid(0),
            uid=os.getuid(),
            status=0,
            birth=(123456789, 0),
        )
        for error_number in (errno.ENOSYS, errno.EPERM, errno.EINVAL):
            with self.subTest(error_number=error_number), Harness(self) as harness:
                descriptor = os.open("/dev/null", os.O_RDONLY)
                spawn_calls = []
                try:
                    with mock.patch.object(
                        module.sys, "platform", "linux"
                    ), mock.patch.object(
                        module.os, "pidfd_open", return_value=descriptor, create=True
                    ), mock.patch.object(
                        module.signal,
                        "pidfd_send_signal",
                        side_effect=OSError(
                            error_number, "unusable pidfd_send_signal"
                        ),
                        create=True,
                    ), mock.patch.object(
                        module, "_pidfd_is_dead", return_value=False
                    ), mock.patch.object(
                        module, "_linux_numeric_proc_pidinfo", return_value=current
                    ):
                        result = harness.run(
                            "open('target-marker','w').write('ran')",
                            popen_factory=lambda *_args, **_kwargs: spawn_calls.append(
                                True
                            ),
                        )
                    self.assertEqual(
                        result.error_code, module.RunnerErrorCode.UNSUPPORTED_PLATFORM
                    )
                    self.assertEqual(spawn_calls, [])
                    self.assertFalse((Path(harness.root) / "target-marker").exists())
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
                finally:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass

    def test_gated_exact_signal_probe_refuses_before_target_marker(self) -> None:
        """Break caught: a failed exact signal probe releases the target exec gate."""

        module = runner_module()
        spawned = []

        def recording_popen(*args, **kwargs):
            process = subprocess.Popen(*args, **kwargs)
            spawned.append(process)
            return process

        with Harness(self) as harness, mock.patch.object(
            module._DescendantTracker,
            "probe_root_signal",
            side_effect=module._RunnerAbort(
                module.RunnerErrorCode.UNSUPPORTED_PLATFORM
            ),
        ):
            result = harness.run(
                "open('target-marker','w').write('ran')",
                popen_factory=recording_popen,
            )
            self.assertEqual(
                result.error_code, module.RunnerErrorCode.UNSUPPORTED_PLATFORM
            )
            self.assertFalse((Path(harness.root) / "target-marker").exists())
            self.assertEqual(harness.factory_calls, 0)
        self.assertEqual(len(spawned), 1)
        self.assertIsNotNone(spawned[0].poll())

    @unittest.skipUnless(sys.platform == "darwin", "requires Darwin libproc")
    def test_darwin_exact_pin_abi_matches_current_process(self) -> None:
        """Break caught: the fixed proc_bsdinfo ABI reads shifted identity fields."""

        module = runner_module()
        self.assertEqual(module.ctypes.sizeof(module._DarwinProcBsdInfo), 136)
        current = module._darwin_proc_pidinfo(os.getpid())
        self.assertIsNotNone(current)
        self.assertEqual(current.pid, os.getpid())
        self.assertEqual(current.ppid, os.getppid())
        self.assertEqual(current.pgid, os.getpgid(0))
        self.assertEqual(current.uid, os.getuid())
        self.assertGreater(current.birth[0], 0)
        self.assertGreaterEqual(current.birth[1], 0)
        self.assertLess(current.birth[1], 1_000_000)

    @unittest.skipUnless(sys.platform == "darwin", "requires Darwin libproc")
    def test_darwin_exact_pin_rejects_short_or_malformed_abi_results(self) -> None:
        """Break caught: partial or malformed libproc data becomes signal authority."""

        module = runner_module()

        def proc_result(*, result=136, pid_delta=0, usec=1):
            def fake(pid, _flavor, _arg, buffer, _size):
                raw = module.ctypes.cast(
                    buffer, module.ctypes.POINTER(module._DarwinProcBsdInfo)
                ).contents
                raw.pbi_pid = pid + pid_delta
                raw.pbi_ppid = os.getppid()
                raw.pbi_pgid = os.getpgid(0)
                raw.pbi_ruid = os.getuid()
                raw.pbi_status = 2
                raw.pbi_start_tvsec = 1
                raw.pbi_start_tvusec = usec
                return result

            return fake

        for fake in (
            proc_result(result=135),
            proc_result(pid_delta=1),
            proc_result(usec=1_000_000),
        ):
            with self.subTest(fake=fake), mock.patch.object(
                module,
                "_DARWIN_LIBPROC_HANDLE",
                SimpleNamespace(proc_pidinfo=fake),
            ):
                with self.assertRaises(module._RunnerAbort):
                    module._darwin_proc_pidinfo(os.getpid())

        def permission_failure(*_args):
            module.ctypes.set_errno(errno.EPERM)
            return 0

        with mock.patch.object(
            module,
            "_DARWIN_LIBPROC_HANDLE",
            SimpleNamespace(proc_pidinfo=permission_failure),
        ):
            with self.assertRaises(module._RunnerAbort):
                module._darwin_proc_pidinfo(os.getpid())

    def test_tracked_process_cap_fails_closed_before_opening_another_pin(self) -> None:
        """Break caught: process-table size permits unbounded retained pin handles."""

        module = runner_module()
        uid = os.getuid()
        root_pid = 54001
        child_pid = 54002
        root_record = SimpleNamespace(
            pid=root_pid,
            ppid=os.getpid(),
            pgid=root_pid,
            uid=uid,
            state=b"R",
        )
        child_record = SimpleNamespace(
            pid=child_pid,
            ppid=root_pid,
            pgid=root_pid,
            uid=uid,
            state=b"R",
        )
        root_pin = _ExactPinFake(
            pid=root_pid, ppid=os.getpid(), pgid=root_pid, uid=uid
        )
        pin_calls = []

        def pin_factory(pid):
            pin_calls.append(pid)
            if pid != root_pid:
                raise AssertionError("cap must reject before another pin opens")
            return root_pin

        tracker = module._DescendantTracker(root_pid, pin_factory=pin_factory)
        try:
            with mock.patch.object(module, "_MAX_TRACKED_PROCESSES", 1), mock.patch.object(
                module,
                "_read_process_table",
                side_effect=(
                    {root_pid: root_record},
                    {root_pid: root_record, child_pid: child_record},
                ),
            ):
                tracker.establish(deadline=time.monotonic() + 1, clock=time.monotonic)
                with self.assertRaises(module._RunnerAbort):
                    tracker.observe(
                        deadline=time.monotonic() + 1, clock=time.monotonic
                    )
            self.assertEqual(pin_calls, [root_pid])
        finally:
            tracker.close()
        self.assertTrue(root_pin.closed)

    def test_chunk_boundaries_do_not_change_sanitized_framing(self) -> None:
        first_code = "import os; os.write(1,b'api_'); os.write(1,b'key=value\\nend\\n')"
        second_code = "import os; os.write(1,b'api_key=value\\nend\\n')"
        payloads = []
        for code in (first_code, second_code):
            with Harness(self) as harness:
                result = harness.run(code)
                self.assertTrue(result.succeeded)
                payloads.append(harness.store.calls[0][0].payload)
        self.assertEqual(payloads[0], payloads[1])
        self.assertNotIn(b"value", payloads[0])

    def test_excerpts_are_utf8_safe_bounded_and_private_roots_are_redacted(self) -> None:
        with Harness(self) as harness:
            encoded = ("한" * 100).encode("utf-8")
            code = f"import os; os.write(1,{encoded!r})"
            result = harness.run(code)
            self.assertTrue(result.succeeded)
            excerpt = result.to_receipt()["stdout"]["excerpt"]
            self.assertLessEqual(len(excerpt.encode("utf-8")), 256)
            excerpt.encode("utf-8", errors="strict")
        with Harness(self) as harness:
            code = f"import os; os.write(1,{harness.root.encode()!r})"
            result = harness.run(code, private_roots=(harness.root,))
            self.assertTrue(result.succeeded)
            self.assertEqual(result.to_receipt()["stdout"]["excerpt"], "[REDACTED PATH]")

    def test_exception_details_never_enter_failure_receipt(self) -> None:
        private_detail = "synthetic-private-exception-detail"
        with Harness(self) as harness:
            result = harness.run(
                "pass",
                popen_factory=lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError(private_detail)),
            )
            self.assertEqual(result.error_code, runner_module().RunnerErrorCode.SPAWN_FAILED)
            serialized = repr(result) + repr(result.to_receipt())
            self.assertNotIn(private_detail, serialized)
            for forbidden in ("artifact", "digest", "frame", "handle", "hash"):
                self.assertNotIn(forbidden, repr(result.to_receipt()))


if __name__ == "__main__":
    unittest.main()
