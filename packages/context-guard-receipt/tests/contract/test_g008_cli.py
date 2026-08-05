from __future__ import annotations

import copy
import io
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
BOOTSTRAP = PYTHON_ROOT / "context_guard_receipt/bootstrap.py"
SCHEMA_PATH = PACKAGE_ROOT / "schemas/command-capture-receipt.schema.json"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))

from context_guard_receipt import cli as cli_module
from context_guard_receipt import runner
from context_guard_receipt.canonical import canonical_json_bytes, parse_canonical_json_bytes
from context_guard_receipt.cli_io import CliIOError


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


def run_cli(*arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            str(Path(sys.executable).resolve()),
            "-I",
            "-S",
            "-B",
            str(BOOTSTRAP),
            "receipt",
            *arguments,
        ],
        cwd=PACKAGE_ROOT,
        env={
            "LANG": "C",
            "PATH": os.defpath,
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def valid_run_arguments(state_dir: Path, *command: str) -> tuple[str, ...]:
    return (
        "run",
        "--escrow",
        "--root",
        str(PACKAGE_ROOT.resolve()),
        "--state-dir",
        str(state_dir.resolve()),
        "--",
        *command,
    )


def success_result(*, exit_code: int = 0) -> runner.CommandRunResult:
    summary = runner._ChannelSummary(  # type: ignore[attr-defined]
        sanitized_bytes=0,
        frame_count=0,
        argument_derived_output_redacted=False,
        excerpt="",
    )
    receipt = runner.CommandCaptureReceipt(
        handle="cgr1p_" + "A" * 43,
        namespace_id="b" * 64,
        artifact_bytes=6,
        artifact_digest_sha256="c" * 64,
        subject_identity_sha256="d" * 64,
        before_observation_sha256="e" * 64,
        after_observation_sha256="f" * 64,
        outcome=runner.CommandOutcome(
            kind=runner.CommandOutcomeKind.EXITED,
            exit_code=exit_code,
        ),
        stdout=summary,
        stderr=summary,
    )
    return runner.CommandRunResult(error_code=None, receipt=receipt)


def schema_accepts(
    root: dict[str, object], schema: dict[str, object], value: object
) -> bool:
    """Evaluate the bounded JSON Schema vocabulary used by the G008 contract."""

    reference = schema.get("$ref")
    if isinstance(reference, str):
        prefix = "#/$defs/"
        if not reference.startswith(prefix):
            raise AssertionError("only local G008 schema definitions are supported")
        definitions = root.get("$defs")
        if not isinstance(definitions, dict):
            raise AssertionError("schema definitions are unavailable")
        resolved = definitions.get(reference.removeprefix(prefix))
        if not isinstance(resolved, dict):
            raise AssertionError("schema definition is unavailable")
        return schema_accepts(root, resolved, value)

    expected = schema.get("const", _MISSING)
    if expected is not _MISSING and value != expected:
        return False
    enum = schema.get("enum")
    if isinstance(enum, list) and value not in enum:
        return False

    one_of = schema.get("oneOf")
    if isinstance(one_of, list):
        if sum(
            isinstance(branch, dict) and schema_accepts(root, branch, value)
            for branch in one_of
        ) != 1:
            return False
    any_of = schema.get("anyOf")
    if isinstance(any_of, list) and not any(
        isinstance(branch, dict) and schema_accepts(root, branch, value)
        for branch in any_of
    ):
        return False
    all_of = schema.get("allOf")
    if isinstance(all_of, list) and not all(
        isinstance(branch, dict) and schema_accepts(root, branch, value)
        for branch in all_of
    ):
        return False
    negated = schema.get("not")
    if isinstance(negated, dict) and schema_accepts(root, negated, value):
        return False

    expected_type = schema.get("type")
    if expected_type == "object" or (
        expected_type is None and ("properties" in schema or "required" in schema)
    ):
        if type(value) is not dict:
            return False
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(properties, dict) or not isinstance(required, list):
            raise AssertionError("unsupported object schema")
        if not set(required).issubset(value):
            return False
        if schema.get("additionalProperties") is False and not set(value).issubset(
            properties
        ):
            return False
        if not all(
            key not in value
            or (
                isinstance(child_schema, dict)
                and schema_accepts(root, child_schema, value[key])
            )
            for key, child_schema in properties.items()
        ):
            return False
        condition = schema.get("if")
        consequence = schema.get("then")
        if (
            isinstance(condition, dict)
            and schema_accepts(root, condition, value)
            and isinstance(consequence, dict)
            and not schema_accepts(root, consequence, value)
        ):
            return False
    elif expected_type == "string":
        if type(value) is not str:
            return False
        minimum = schema.get("minLength")
        maximum = schema.get("maxLength")
        pattern = schema.get("pattern")
        if isinstance(minimum, int) and len(value) < minimum:
            return False
        if isinstance(maximum, int) and len(value) > maximum:
            return False
        if isinstance(pattern, str) and re.search(pattern, value) is None:
            return False
    elif expected_type == "integer":
        if type(value) is not int:
            return False
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, int) and value < minimum:
            return False
        if isinstance(maximum, int) and value > maximum:
            return False
    elif expected_type == "boolean" and type(value) is not bool:
        return False
    return True


_MISSING = object()


class G008CliContractTests(unittest.TestCase):
    def test_exact_grammar_rejects_legacy_unsafe_duplicate_and_bad_limit_options(self) -> None:
        """Break caught: run admits sidecars, reflection options, or ambiguous bounds."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            state = base / "state"
            root = str(PACKAGE_ROOT.resolve())
            command = str(Path(sys.executable).resolve())
            invalid = (
                ("run", "--escrow", "--root", root, "--state-dir", str(state), "--receipt-out", str(base / "receipt"), "--", command),
                ("run", "--escrow", "--root", root, "--state-dir", str(state), "--emit", "json", "--", command),
                ("run", "--escrow", "--root", root, "--state-dir", str(state), "--persist", "--", command),
                ("run", "--escrow", "--root", root, "--root", root, "--state-dir", str(state), "--", command),
                ("run", "--root", root, "--state-dir", str(state), "--", command),
                ("run", "--escrow", "--root", ".", "--state-dir", str(state), "--", command),
                ("run", "--escrow", "--root", root, "--state-dir", "state", "--", command),
                ("run", "--escrow", "--root", root + "/..", "--state-dir", str(state), "--", command),
                ("run", "--escrow", "--root", root, "--state-dir", str(state) + "/../state", "--", command),
                ("run", "--escrow", "--root", root, "--state-dir", str(state), command),
                ("run", "--escrow", "--root", root, "--state-dir", str(state), "--"),
                ("run", "--escrow", "--root", root, "--state-dir", str(state), "--", "relative"),
                ("run", "--escrow", "--root", root, "--state-dir", str(state), "--timeout-seconds", "0", "--", command),
                ("run", "--escrow", "--root", root, "--state-dir", str(state), "--timeout-seconds", "01", "--", command),
                ("run", "--escrow", "--root", root, "--state-dir", str(state), "--timeout-seconds", "301", "--", command),
                ("run", "--escrow", "--root", root, "--state-dir", str(state), "--max-channel-bytes", "900001", "--", command),
                ("run", "--escrow", "--root", root, "--state-dir", str(state), "--max-total-bytes", "900001", "--", command),
                ("run", "--escrow", "--root", root, "--state-dir", str(state), "--max-channel-bytes", "11", "--max-total-bytes", "10", "--", command),
            )
            for arguments in invalid:
                with self.subTest(arguments=arguments):
                    response = run_cli(*arguments)
                    self.assertEqual(response.returncode, 64, response.stderr)
                    self.assertEqual(response.stdout, b"")
                    error = parse_canonical_json_bytes(response.stderr)
                    self.assertEqual(error["reason"], "usage")
                    self.assertFalse(state.exists())

    def test_valid_grammar_passes_opaque_argv_and_consistent_limits_to_runner(self) -> None:
        """Break caught: CLI reinterprets child arguments or forks raw/sanitized caps."""

        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve() / "state"
            arguments = valid_run_arguments(
                state,
                "/bin/echo",
                "",
                "--receipt-out",
                "opaque-value",
                "--",
            )
            arguments = arguments[:6] + (
                "--timeout-seconds",
                "9",
                "--max-channel-bytes",
                "123",
                "--max-total-bytes",
                "456",
            ) + arguments[6:]
            captured: list[bytes] = []
            with mock.patch.object(
                runner, "run_command", return_value=success_result()
            ) as run_command, mock.patch.object(
                cli_module, "write_stdout", side_effect=captured.append
            ):
                code = cli_module.receipt_main(arguments)

            self.assertEqual(code, 0)
            self.assertEqual(len(captured), 1)
            parse_canonical_json_bytes(captured[0])
            positional, keywords = run_command.call_args
            self.assertEqual(
                positional,
                (("/bin/echo", "", "--receipt-out", "opaque-value", "--"), str(PACKAGE_ROOT.resolve())),
            )
            self.assertEqual(
                keywords["private_roots"],
                (str(PACKAGE_ROOT.resolve()), str(state)),
            )
            self.assertTrue(callable(keywords["store_factory"]))
            limits = keywords["limits"]
            self.assertEqual(limits.timeout_seconds, 9)
            self.assertEqual(limits.raw_per_channel_bytes, 123)
            self.assertEqual(limits.sanitized_per_channel_bytes, 123)
            self.assertEqual(limits.raw_total_bytes, 456)
            self.assertEqual(limits.sanitized_total_bytes, 456)
            self.assertFalse(state.exists(), "constructing the lazy factory created state")

    def test_non_normalized_root_or_state_never_reaches_runner(self) -> None:
        root = str(PACKAGE_ROOT.resolve())
        command = str(Path(sys.executable).resolve())
        for arguments in (
            (
                "run", "--escrow", "--root", root + "/..", "--state-dir",
                "/tmp/context-guard-state", "--", command,
            ),
            (
                "run", "--escrow", "--root", root, "--state-dir",
                "/tmp/context-guard-state/../context-guard-state", "--", command,
            ),
        ):
            with self.subTest(arguments=arguments), mock.patch.object(
                runner, "run_command"
            ) as run_command:
                stdout = io.StringIO()
                stderr = io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    code = cli_module.receipt_main(arguments)
                self.assertEqual(code, 64)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(
                    parse_canonical_json_bytes(stderr.getvalue().encode("ascii"))["reason"],
                    "usage",
                )
                run_command.assert_not_called()

    def test_total_only_limit_lowers_the_implicit_channel_limit(self) -> None:
        """Break caught: a valid total-only bound creates an impossible channel cap."""

        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve() / "state"
            arguments = valid_run_arguments(state, "/bin/true")
            arguments = arguments[:6] + (
                "--max-total-bytes",
                "321",
            ) + arguments[6:]
            with mock.patch.object(
                runner, "run_command", return_value=success_result()
            ) as run_command, mock.patch.object(cli_module, "write_stdout"):
                code = cli_module.receipt_main(arguments)

            self.assertEqual(code, 0)
            limits = run_command.call_args.kwargs["limits"]
            self.assertEqual(limits.raw_per_channel_bytes, 321)
            self.assertEqual(limits.sanitized_per_channel_bytes, 321)
            self.assertEqual(limits.raw_total_bytes, 321)
            self.assertEqual(limits.sanitized_total_bytes, 321)
            self.assertFalse(state.exists())

    def test_success_emits_one_canonical_receipt_and_persists_only_capture_state(self) -> None:
        """Break caught: successful capture emits a wrapper/sidecar or omits core fields."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            state = base / "state"
            response = run_cli(
                *valid_run_arguments(
                    state,
                    str(Path(sys.executable).resolve()),
                    "-c",
                    "import os; os.write(1,b'captured-output')",
                )
            )
            self.assertEqual(response.returncode, 0, response.stderr)
            self.assertEqual(response.stderr, b"")
            receipt = parse_canonical_json_bytes(response.stdout)
            self.assertEqual(response.stdout, canonical_json_bytes(receipt))
            self.assertEqual(
                set(receipt),
                {
                    "artifact",
                    "evidence_boundary",
                    "handle",
                    "namespace_id",
                    "observation",
                    "outcome",
                    "schema_version",
                    "status",
                    "stderr",
                    "stdout",
                },
            )
            self.assertEqual(receipt["evidence_boundary"], EVIDENCE_BOUNDARY)
            self.assertEqual(receipt["schema_version"], "contextguard-receipt-command-capture/v1")
            self.assertEqual(receipt["status"], "captured")
            self.assertEqual(receipt["outcome"], {"exit_code": 0, "kind": "exited"})
            self.assertEqual(
                set(receipt["stdout"]),
                {
                    "argument_derived_output_redacted",
                    "excerpt",
                    "frame_count",
                    "sanitized_bytes",
                },
            )
            self.assertTrue(state.is_dir())
            self.assertEqual(list(base.iterdir()), [state])

    def test_success_handle_expands_the_exact_stored_cgrf_capture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve() / "state"
            captured = run_cli(
                *valid_run_arguments(
                    state,
                    str(Path(sys.executable).resolve()),
                    "-c",
                    "import os; os.write(1,b'captured-output')",
                )
            )
            self.assertEqual(captured.returncode, 0, captured.stderr)
            receipt = parse_canonical_json_bytes(captured.stdout)
            expanded = run_cli(
                "expand",
                receipt["handle"],
                "--root",
                str(PACKAGE_ROOT.resolve()),
                "--state-dir",
                str(state),
                "--emit",
                "bytes",
            )

        self.assertEqual(expanded.returncode, 0, expanded.stderr)
        self.assertEqual(expanded.stderr, b"")
        frames = runner.validate_framed_capture(expanded.stdout)
        stdout = b"".join(frame.payload for frame in frames if frame.channel == 1)
        stderr = b"".join(frame.payload for frame in frames if frame.channel == 2)
        self.assertEqual(stdout, b"captured-output")
        self.assertEqual(stderr, b"")
        self.assertEqual(len(expanded.stdout), receipt["artifact"]["byte_length"])

    def test_child_nonzero_signal_and_124_are_receipted_but_timeout_is_closed(self) -> None:
        """Break caught: child 124 is confused with timeout or signal exits are flattened."""

        cases = (
            ("import sys; sys.exit(7)", 7, {"exit_code": 7, "kind": "exited"}),
            ("import sys; sys.exit(124)", 124, {"exit_code": 124, "kind": "exited"}),
            ("import sys; sys.exit(125)", 125, {"exit_code": 125, "kind": "exited"}),
            ("import sys; sys.exit(126)", 126, {"exit_code": 126, "kind": "exited"}),
            ("import sys; sys.exit(127)", 127, {"exit_code": 127, "kind": "exited"}),
            ("import sys; sys.exit(255)", 255, {"exit_code": 255, "kind": "exited"}),
            (
                "import os,signal; os.kill(os.getpid(), signal.SIGTERM)",
                128 + signal.SIGTERM,
                {"kind": "signaled", "signal": signal.SIGTERM},
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            for index, (program, expected_code, expected_outcome) in enumerate(cases):
                with self.subTest(expected_code=expected_code):
                    response = run_cli(
                        *valid_run_arguments(
                            base / f"state-{index}",
                            str(Path(sys.executable).resolve()),
                            "-c",
                            program,
                        )
                    )
                    self.assertEqual(response.returncode, expected_code, response.stderr)
                    self.assertEqual(response.stderr, b"")
                    receipt = parse_canonical_json_bytes(response.stdout)
                    self.assertEqual(receipt["outcome"], expected_outcome)

            timeout_state = base / "timeout-state"
            timed_out = run_cli(
                "run",
                "--escrow",
                "--root",
                str(PACKAGE_ROOT.resolve()),
                "--state-dir",
                str(timeout_state),
                "--timeout-seconds",
                "1",
                "--",
                str(Path(sys.executable).resolve()),
                "-c",
                "import time; time.sleep(5)",
            )
            self.assertEqual(timed_out.returncode, 124)
            self.assertEqual(timed_out.stdout, b"")
            self.assertEqual(
                parse_canonical_json_bytes(timed_out.stderr)["reason"],
                "command_capture_failed",
            )
            self.assertFalse(timeout_state.exists())

    def test_all_runner_failures_are_the_same_nonreflective_stderr_only_error(self) -> None:
        """Break caught: failure diagnostics disclose an error class or candidate authority."""

        forbidden = (
            "private-argv-secret",
            str(PACKAGE_ROOT.resolve()),
            "state",
            "path",
            "raw",
            "exception",
            "handle",
            "hash",
            "frame",
        )
        rendered_errors: set[str] = set()
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve() / "private-state"
            arguments = valid_run_arguments(
                state, "/not/a/real/private-argv-secret", "private-argv-secret"
            )
            for error_code, expected_exit in (
                (runner.RunnerErrorCode.SPAWN_FAILED, 70),
                (runner.RunnerErrorCode.READ_FAILED, 70),
                (runner.RunnerErrorCode.SANITIZATION_INCOMPLETE, 70),
                (runner.RunnerErrorCode.FRAMED_LIMIT_EXCEEDED, 70),
                (runner.RunnerErrorCode.SNAPSHOT_UNRESOLVED, 70),
                (runner.RunnerErrorCode.STORE_FAILED, 74),
                (runner.RunnerErrorCode.COMMIT_UNCERTAIN, 74),
            ):
                with self.subTest(error_code=error_code):
                    stdout = io.StringIO()
                    stderr = io.StringIO()
                    with mock.patch.object(
                        runner,
                        "run_command",
                        return_value=runner.CommandRunResult(error_code=error_code),
                    ), redirect_stdout(stdout), redirect_stderr(stderr):
                        code = cli_module.receipt_main(arguments)
                    self.assertEqual(code, expected_exit)
                    self.assertEqual(stdout.getvalue(), "")
                    error = stderr.getvalue()
                    parse_canonical_json_bytes(error.encode("ascii"))
                    rendered_errors.add(error)
                    lowered = error.lower()
                    for value in forbidden:
                        self.assertNotIn(value.lower(), lowered)
            self.assertEqual(len(rendered_errors), 1)
            self.assertFalse(state.exists())

    def test_stdout_delivery_failure_maps_to_74_without_printing_receipt_authority(self) -> None:
        """Break caught: delivery failure leaks the durable handle or attempts rollback."""

        result = success_result()
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve() / "state"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with mock.patch.object(
                runner, "run_command", return_value=result
            ), mock.patch.object(
                cli_module, "write_stdout", side_effect=CliIOError("stdout_unwritable")
            ), redirect_stdout(stdout), redirect_stderr(stderr):
                code = cli_module.receipt_main(
                    valid_run_arguments(state, "/bin/true")
                )
        self.assertEqual(code, 74)
        self.assertEqual(stdout.getvalue(), "")
        error = stderr.getvalue()
        self.assertEqual(
            parse_canonical_json_bytes(error.encode("ascii"))["reason"],
            "command_capture_failed",
        )
        self.assertNotIn(result.receipt.handle, error)

    def test_semantically_invalid_success_receipt_is_not_delivered(self) -> None:
        result = success_result()
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve() / "state"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with mock.patch.object(
                runner, "run_command", return_value=result
            ), mock.patch.object(
                runner, "validate_command_capture_receipt", return_value=False
            ) as validate, mock.patch.object(
                cli_module, "write_stdout"
            ) as write_stdout_call, redirect_stdout(stdout), redirect_stderr(stderr):
                code = cli_module.receipt_main(
                    valid_run_arguments(state, "/bin/true")
                )
        self.assertEqual(code, 74)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            parse_canonical_json_bytes(stderr.getvalue().encode("ascii"))["reason"],
            "command_capture_failed",
        )
        validate.assert_called_once()
        write_stdout_call.assert_not_called()

    def test_pre_store_runner_failure_creates_no_state_and_reflects_no_input(self) -> None:
        """Break caught: spawn failure opens state or echoes private command details."""

        secret = "synthetic-private-command-secret"
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve() / "state"
            response = run_cli(
                *valid_run_arguments(
                    state,
                    f"/definitely/missing/{secret}",
                    secret,
                )
            )
            self.assertEqual(response.returncode, 70)
            self.assertEqual(response.stdout, b"")
            self.assertFalse(state.exists())
            self.assertNotIn(secret.encode(), response.stderr)
            self.assertNotIn(str(state).encode(), response.stderr)
            self.assertEqual(
                parse_canonical_json_bytes(response.stderr)["reason"],
                "command_capture_failed",
            )

    def test_schema_accepts_core_receipt_and_rejects_open_or_privacy_invalid_shapes(self) -> None:
        """Break caught: distributable schema is weaker than the core receipt contract."""

        self.assertTrue(SCHEMA_PATH.is_file(), "missing G008 receipt schema")
        raw = SCHEMA_PATH.read_bytes()
        self.assertTrue(raw.endswith(b"\n"))
        schema = json.loads(raw)
        receipt = success_result().to_receipt()
        self.assertTrue(schema_accepts(schema, schema, receipt))

        mutations: list[dict[str, object]] = []
        for path, value in (
            (("provider",), "forbidden"),
            (("artifact", "path"), "/private/path"),
            (("observation", "argv"), ["/bin/true"]),
            (("stdout", "metadata"), {}),
            (("stdout", "excerpt"), "x" * 257),
            (("stdout", "argument_derived_output_redacted"), "false"),
            (("handle",), "cgr1p_invalid"),
            (("namespace_id",), "A" * 64),
            (("outcome",), {"kind": "exited", "signal": 9}),
        ):
            candidate = copy.deepcopy(receipt)
            target: dict[str, object] = candidate
            for part in path[:-1]:
                child = target[part]
                if not isinstance(child, dict):
                    raise AssertionError("invalid test mutation")
                target = child
            target[path[-1]] = value
            mutations.append(candidate)

        redaction_inconsistent = copy.deepcopy(receipt)
        redaction_inconsistent["stdout"] = {
            "argument_derived_output_redacted": True,
            "excerpt": "leaked",
            "frame_count": 1,
            "sanitized_bytes": 6,
        }
        mutations.append(redaction_inconsistent)
        for candidate in mutations:
            with self.subTest(candidate=candidate):
                self.assertFalse(schema_accepts(schema, schema, candidate))

        object_nodes: list[dict[str, object]] = []

        def visit(value: object) -> None:
            if isinstance(value, dict):
                if value.get("type") == "object":
                    object_nodes.append(value)
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(schema)
        self.assertTrue(object_nodes)
        for node in object_nodes:
            self.assertIs(node.get("additionalProperties"), False)

    def test_help_states_explicit_local_capture_and_claim_boundaries(self) -> None:
        """Break caught: help implies provider/host/network observation or savings proof."""

        response = run_cli("--help")
        self.assertEqual(response.returncode, 0)
        self.assertEqual(response.stderr, b"")
        help_text = response.stdout.decode("utf-8").lower()
        self.assertIn("run --escrow --root <absolute> --state-dir <absolute>", help_text)
        self.assertNotIn("--receipt-out <file> -- <command>", help_text)
        for phrase in (
            "explicit local capture",
            "provider-free",
            "no host-request, network, or token-saving claim",
        ):
            self.assertIn(phrase, help_text)


if __name__ == "__main__":
    unittest.main()
