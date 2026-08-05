from __future__ import annotations

import ast
import builtins
from dataclasses import FrozenInstanceError
import hashlib
import importlib
import logging
import random
import sys
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))


def sanitizer_module():
    try:
        return importlib.import_module("context_guard_receipt.sanitizer")
    except ModuleNotFoundError as error:
        raise AssertionError("G007 sanitizer implementation is missing") from error


def sanitize_in_two_chunks(
    module,
    payload: bytes,
    split: int,
    *,
    private_roots: tuple[str, ...] = (),
):
    sanitizer = module.StreamingSanitizer(private_roots=private_roots)
    sanitizer.feed(payload[:split])
    sanitizer.feed(payload[split:])
    return sanitizer.finish()


class G007SanitizerApiTests(unittest.TestCase):
    def test_minimal_public_api_sanitizes_only_at_finish(self) -> None:
        """Break caught: the G007 module or finish-only output API is absent."""

        module = sanitizer_module()
        sanitizer = module.StreamingSanitizer()

        self.assertIsNone(sanitizer.feed(b"visible"))
        result = sanitizer.finish()

        self.assertEqual(result.payload, b"visible")
        self.assertEqual(result.summary.input_bytes, 7)
        self.assertEqual(result.summary.output_bytes, 7)

    def test_custom_input_limit_accepts_exact_aggregate_and_aborts_on_plus_one(self) -> None:
        """Break caught: aggregate feeds bypass or prematurely trip the input bound."""

        module = sanitizer_module()
        limits = module.SanitizerLimits(max_input_bytes=5)

        exact = module.StreamingSanitizer(limits=limits)
        self.assertIsNone(exact.feed(b"ab"))
        self.assertIsNone(exact.feed(b"cde"))
        self.assertEqual(exact.finish().payload, b"abcde")

        overflow = module.StreamingSanitizer(limits=limits)
        self.assertIsNone(overflow.feed(b"ab"))
        self.assertIsNone(overflow.feed(b"cde"))
        self.assertIsNone(overflow.feed(b""))
        with self.assertRaises(module.SanitizationError) as caught:
            overflow.feed(b"f")
        self.assertEqual(
            caught.exception.code,
            module.SanitizationErrorCode.INPUT_LIMIT_EXCEEDED,
        )
        with self.assertRaises(module.SanitizationError) as invalid_state:
            overflow.finish()
        self.assertEqual(
            invalid_state.exception.code,
            module.SanitizationErrorCode.INVALID_STATE,
        )

    def test_line_count_handles_empty_lf_only_trailing_and_nontrailing_records(self) -> None:
        """Break caught: LF delimiters create or discard a logical receipt line."""

        module = sanitizer_module()
        cases = (
            (b"", 0),
            (b"\n", 1),
            (b"\n\n", 2),
            (b"alpha", 1),
            (b"alpha\n", 1),
            (b"alpha\nbeta", 2),
            (b"alpha\nbeta\n", 2),
        )

        for payload, expected_lines in cases:
            with self.subTest(payload=payload):
                result = module.sanitize_bytes(payload)
                self.assertEqual(result.summary.line_count, expected_lines)

    def test_custom_line_limit_accepts_exact_and_aborts_on_plus_one(self) -> None:
        """Break caught: trailing or empty records evade the configured line cap."""

        module = sanitizer_module()
        limits = module.SanitizerLimits(max_lines=2)
        accepted = (b"\n\n", b"alpha\nbeta", b"alpha\nbeta\n")
        rejected = (b"\n\n\n", b"alpha\nbeta\ngamma", b"alpha\nbeta\ngamma\n")

        for payload in accepted:
            with self.subTest(outcome="exact", payload=payload):
                result = module.sanitize_bytes(payload, limits=limits)
                self.assertEqual(result.summary.line_count, 2)

        for payload in rejected:
            with self.subTest(outcome="plus one", payload=payload):
                sanitizer = module.StreamingSanitizer(limits=limits)
                sanitizer.feed(payload)
                with self.assertRaises(module.SanitizationError) as caught:
                    sanitizer.finish()
                self.assertEqual(
                    caught.exception.code,
                    module.SanitizationErrorCode.LINE_LIMIT_EXCEEDED,
                )
                with self.assertRaises(module.SanitizationError) as invalid_state:
                    sanitizer.finish()
                self.assertEqual(
                    invalid_state.exception.code,
                    module.SanitizationErrorCode.INVALID_STATE,
                )

    def test_wrong_feed_types_abort_and_bytes_subclasses_are_not_coerced(self) -> None:
        """Break caught: a bytes-like or subclass value crosses the strict byte boundary."""

        module = sanitizer_module()

        class BytesSubclass(bytes):
            pass

        wrong_values = (bytearray(b"x"), memoryview(b"x"), BytesSubclass(b"x"))
        for value in wrong_values:
            with self.subTest(value_type=type(value).__name__):
                sanitizer = module.StreamingSanitizer()
                with self.assertRaises(module.SanitizationError) as caught:
                    sanitizer.feed(value)
                self.assertEqual(
                    caught.exception.code,
                    module.SanitizationErrorCode.INVALID_INPUT_TYPE,
                )
                with self.assertRaises(module.SanitizationError) as invalid_state:
                    sanitizer.feed(b"valid-but-too-late")
                self.assertEqual(
                    invalid_state.exception.code,
                    module.SanitizationErrorCode.INVALID_STATE,
                )

    def test_finished_state_is_frozen_across_reuse_and_late_abort(self) -> None:
        """Break caught: a late abort mutates FINISHED or a terminal instance is reused."""

        module = sanitizer_module()
        sanitizer = module.StreamingSanitizer()
        sanitizer.feed(b"visible")
        self.assertEqual(sanitizer.finish().payload, b"visible")
        finished_state = sanitizer._state
        self.assertEqual(finished_state.value, "finished")

        self.assertIsNone(sanitizer.abort())
        self.assertIs(sanitizer._state, finished_state)
        with self.assertRaises(module.SanitizationError) as finish_error:
            sanitizer.finish()
        self.assertEqual(
            finish_error.exception.code,
            module.SanitizationErrorCode.INVALID_STATE,
        )
        with self.assertRaises(module.SanitizationError) as feed_error:
            sanitizer.feed(b"reuse")
        self.assertEqual(
            feed_error.exception.code,
            module.SanitizationErrorCode.INVALID_STATE,
        )

    def test_abort_is_active_to_aborted_idempotent_and_refuses_reuse(self) -> None:
        """Break caught: abort retains captured bytes, changes twice, or permits reuse."""

        module = sanitizer_module()
        sanitizer = module.StreamingSanitizer()
        self.assertEqual(sanitizer._state.value, "active")
        sanitizer.feed(b"discard-me")

        self.assertIsNone(sanitizer.abort())
        aborted_state = sanitizer._state
        self.assertEqual(aborted_state.value, "aborted")
        self.assertEqual(sanitizer._buffer, bytearray())
        self.assertIsNone(sanitizer.abort())
        self.assertIs(sanitizer._state, aborted_state)

        for operation in (lambda: sanitizer.feed(b"reuse"), sanitizer.finish):
            with self.subTest(operation=operation.__name__):
                with self.assertRaises(module.SanitizationError) as caught:
                    operation()
                self.assertEqual(
                    caught.exception.code,
                    module.SanitizationErrorCode.INVALID_STATE,
                )

    def test_empty_finish_returns_an_empty_zero_summary(self) -> None:
        """Break caught: finishing without feeds invents a line or nonzero counter."""

        module = sanitizer_module()

        result = module.StreamingSanitizer().finish()

        self.assertEqual(result.payload, b"")
        self.assertEqual(
            result.summary,
            module.SanitizationSummary(input_bytes=0, output_bytes=0, line_count=0),
        )

    def test_zero_output_limit_still_accepts_empty_output(self) -> None:
        """Break caught: the inclusive zero output boundary rejects empty output."""

        module = sanitizer_module()
        limits = module.SanitizerLimits(max_output_bytes=0)

        result = module.sanitize_bytes(b"", limits=limits)

        self.assertEqual(result.payload, b"")
        self.assertEqual(result.summary.output_bytes, 0)

    def test_limit_defaults_and_constructor_hard_boundaries_are_exact(self) -> None:
        """Break caught: a limit default drifts or a non-exact integer crosses a hard cap."""

        module = sanitizer_module()
        expected_caps = {
            "max_input_bytes": 1024 * 1024,
            "max_output_bytes": 1024 * 1024,
            "max_pending_bytes": 64 * 1024,
            "max_lines": 65_536,
            "max_control_sequence_bytes": 4_096,
        }
        defaults = module.SanitizerLimits()
        self.assertEqual(
            {name: getattr(defaults, name) for name in expected_caps},
            expected_caps,
        )

        class IntSubclass(int):
            pass

        for name, hard_cap in expected_caps.items():
            for accepted in (0, hard_cap):
                with self.subTest(field=name, outcome="accepted", value=accepted):
                    limits = module.SanitizerLimits(**{name: accepted})
                    self.assertEqual(getattr(limits, name), accepted)

            rejected = (-1, hard_cap + 1, False, True, 0.0, IntSubclass(1))
            for value in rejected:
                with self.subTest(
                    field=name,
                    outcome="rejected",
                    value_type=type(value).__name__,
                    value=value,
                ):
                    with self.assertRaises(module.SanitizationError) as caught:
                        module.SanitizerLimits(**{name: value})
                    self.assertEqual(
                        caught.exception.code,
                        module.SanitizationErrorCode.INVALID_LIMITS,
                    )

    def test_default_input_hard_cap_accepts_one_mib_and_aborts_on_plus_one(self) -> None:
        """Break caught: the aggregate default input cap is off by one or fails open."""

        module = sanitizer_module()
        sanitizer = module.StreamingSanitizer()

        self.assertIsNone(sanitizer.feed(b"x" * (1024 * 1024)))
        with self.assertRaises(module.SanitizationError) as caught:
            sanitizer.feed(b"x")
        self.assertEqual(
            caught.exception.code,
            module.SanitizationErrorCode.INPUT_LIMIT_EXCEEDED,
        )
        with self.assertRaises(module.SanitizationError) as invalid_state:
            sanitizer.finish()
        self.assertEqual(
            invalid_state.exception.code,
            module.SanitizationErrorCode.INVALID_STATE,
        )

    def test_public_all_is_the_exact_minimal_api(self) -> None:
        """Break caught: an internal implementation detail becomes a public API."""

        module = sanitizer_module()

        self.assertEqual(
            module.__all__,
            [
                "SANITIZER_POLICY_VERSION",
                "SanitizationError",
                "SanitizationErrorCode",
                "SanitizationSummary",
                "SanitizedOutput",
                "SanitizerLimits",
                "StreamingSanitizer",
                "sanitize_bytes",
            ],
        )

    def test_production_ast_has_only_the_closed_standard_library_import_surface(self) -> None:
        """Break caught: sanitizer code gains filesystem, process, network, or product coupling."""

        module = sanitizer_module()
        source = Path(module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports: set[tuple[str, tuple[str, ...]]] = set()
        identifiers: set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIsNone(alias.asname)
                    imports.add((alias.name, ()))
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0)
                for alias in node.names:
                    self.assertIsNone(alias.asname)
                imports.add((node.module or "", tuple(alias.name for alias in node.names)))
            elif isinstance(node, ast.Name):
                identifiers.add(node.id.casefold())
            elif isinstance(node, ast.Attribute):
                identifiers.add(node.attr.casefold())

        self.assertEqual(
            imports,
            {
                ("__future__", ("annotations",)),
                ("re", ()),
                ("dataclasses", ("dataclass", "field")),
                ("enum", ("Enum",)),
                ("typing", ("Final",)),
            },
        )
        self.assertTrue(
            identifiers.isdisjoint(
                {
                    "__import__",
                    "cli",
                    "environ",
                    "getenv",
                    "http",
                    "legacy",
                    "logging",
                    "open",
                    "os",
                    "pathlib",
                    "plugin",
                    "provider",
                    "requests",
                    "socket",
                    "store",
                    "subprocess",
                    "urllib",
                }
            )
        )

    def test_module_reload_opens_nothing_and_emits_no_logs(self) -> None:
        """Break caught: importing the sanitizer performs ambient I/O or logging."""

        module = sanitizer_module()
        opened: list[tuple[object, ...]] = []
        original_open = builtins.open

        def tracked_open(*args, **kwargs):
            opened.append(args)
            return original_open(*args, **kwargs)

        builtins.open = tracked_open
        try:
            with self.assertNoLogs(level=logging.DEBUG):
                reloaded = importlib.reload(module)
        finally:
            builtins.open = original_open

        self.assertIs(reloaded, module)
        self.assertEqual(opened, [])

    def test_public_dataclasses_are_frozen_slotted_and_privacy_safe(self) -> None:
        """Break caught: result state becomes mutable or captured payload enters repr/str."""

        module = sanitizer_module()
        private_payload = b"opaque-private-payload"
        summary = module.SanitizationSummary(
            input_bytes=len(private_payload),
            output_bytes=len(private_payload),
            line_count=1,
        )
        objects_and_mutations = (
            (module.SanitizerLimits(), "max_input_bytes", 1),
            (summary, "line_count", 2),
            (module.SanitizedOutput(private_payload, summary), "payload", b"changed"),
        )

        for instance, attribute, replacement in objects_and_mutations:
            with self.subTest(class_name=type(instance).__name__):
                self.assertFalse(hasattr(instance, "__dict__"))
                self.assertIn("__slots__", type(instance).__dict__)
                with self.assertRaises(FrozenInstanceError):
                    setattr(instance, attribute, replacement)

        result = module.SanitizedOutput(private_payload, summary)
        self.assertNotIn(private_payload.decode("ascii"), repr(result))
        self.assertNotIn(private_payload.decode("ascii"), str(result))

    def test_private_roots_and_payload_never_enter_object_or_error_surfaces(self) -> None:
        """Break caught: captured bytes or a configured root leak through diagnostic text."""

        module = sanitizer_module()
        private_root = "/ultra-private-root"
        private_payload = b"/ultra-private-root/private-file.txt"
        sanitizer = module.StreamingSanitizer(
            private_roots=(private_root,),
            limits=module.SanitizerLimits(max_output_bytes=14),
        )
        sanitizer.feed(private_payload)

        for surface in (repr(sanitizer), str(sanitizer), repr(sanitizer._private_roots)):
            self.assertNotIn(private_root, surface)
            self.assertNotIn(private_payload.decode("ascii"), surface)

        with self.assertRaises(module.SanitizationError) as caught:
            sanitizer.finish()
        self.assertEqual(
            caught.exception.code,
            module.SanitizationErrorCode.OUTPUT_LIMIT_EXCEEDED,
        )
        for surface in (str(caught.exception), repr(caught.exception)):
            self.assertNotIn(private_root, surface)
            self.assertNotIn(private_payload.decode("ascii"), surface)

    def test_final_payload_sha256_is_identical_across_all_chunkings(self) -> None:
        """Break caught: feed boundaries alter the exact final receipt bytes."""

        module = sanitizer_module()
        payload = (
            b"visible\r\n"
            b"/var/project/a.py:1\n"
            b"api_key=synthetic-value\n"
            b"\x1b[31mcolor\x1b[0m \xff\x00"
        )
        expected = (
            b"visible\n"
            b"[REDACTED PATH]:1\n"
            b"[REDACTED SECRET]\n"
            b"color \\xFF\\x00"
        )
        expected_digest = "9c68c3d112f0fab548aab45393e809174a2566caf8de7714a6d280d35bd61177"
        baseline = module.sanitize_bytes(payload)
        self.assertEqual(baseline.payload, expected)
        self.assertEqual(hashlib.sha256(baseline.payload).hexdigest(), expected_digest)

        for split in range(len(payload) + 1):
            with self.subTest(mode="two chunks", split=split):
                result = sanitize_in_two_chunks(module, payload, split)
                self.assertEqual(hashlib.sha256(result.payload).hexdigest(), expected_digest)

        bytewise = module.StreamingSanitizer()
        for byte in payload:
            bytewise.feed(bytes((byte,)))
        self.assertEqual(
            hashlib.sha256(bytewise.finish().payload).hexdigest(),
            expected_digest,
        )

        generator = random.Random(7011)
        for trial in range(32):
            sanitizer = module.StreamingSanitizer()
            cursor = 0
            while cursor < len(payload):
                chunk_size = generator.randint(1, 13)
                sanitizer.feed(payload[cursor : cursor + chunk_size])
                cursor += chunk_size
            with self.subTest(mode="seeded random", trial=trial):
                self.assertEqual(
                    hashlib.sha256(sanitizer.finish().payload).hexdigest(),
                    expected_digest,
                )

    def test_uri_userinfo_secrets_and_local_scheme_paths_fail_closed(self) -> None:
        """Break caught: URI shielding leaks password userinfo or a local absolute path."""

        module = sanitizer_module()
        password_uri = b"https://alice:synthetic-password@host.example/repo"
        secret_result = module.sanitize_bytes(password_uri)
        self.assertTrue(
            secret_result.payload == b"[REDACTED SECRET]",
            "password-bearing URI record was not redacted",
        )
        self.assertEqual(secret_result.summary.secret_redactions, 1)

        ordinary = (
            b"http://host.example/a\n"
            b"https://host.example/b\n"
            b"ssh://host.example/c"
        )
        self.assertEqual(module.sanitize_bytes(ordinary).payload, ordinary)
        self.assertEqual(
            module.sanitize_bytes(b"file:///Users/alice/private.txt").payload,
            b"[REDACTED PATH]",
        )
        self.assertEqual(
            module.sanitize_bytes(b"x:///Users/alice/private.txt").payload,
            b"[REDACTED PATH]",
        )

        invariant_payload = password_uri + b"\nfile:///Users/alice/private.txt"
        baseline = module.sanitize_bytes(invariant_payload)
        for split in range(len(invariant_payload) + 1):
            with self.subTest(split=split):
                self.assertEqual(
                    sanitize_in_two_chunks(module, invariant_payload, split),
                    baseline,
                )
        bytewise = module.StreamingSanitizer()
        for byte in invariant_payload:
            bytewise.feed(bytes((byte,)))
        self.assertEqual(bytewise.finish(), baseline)

    def test_ambiguous_path_terminators_never_leave_filename_like_suffixes(self) -> None:
        """Break caught: punctuation or whitespace lets a path-adjacent filename survive."""

        module = sanitizer_module()
        ambiguous = (
            b"prefix=/var/private/file.py tail.py",
            b"prefix=/var/private/file.py,tail.py",
            b"prefix=/var/private/file.py;tail.py",
            b"prefix=[/var/private/file.py]tail.py",
            b"prefix=/var/private/file.py!tail.py",
        )
        for payload in ambiguous:
            result = module.sanitize_bytes(payload)
            self.assertEqual(result.payload, b"[REDACTED PATH]")
            self.assertEqual(result.summary.path_redactions, 1)

        explicit = module.sanitize_bytes(
            b"prefix=/private/root/file.py,tail.py",
            private_roots=("/private/root",),
        )
        self.assertEqual(explicit.payload, b"[REDACTED PATH]")
        self.assertEqual(explicit.summary.path_redactions, 1)
        self.assertEqual(
            module.sanitize_bytes(b"/var/private/file.py:12:3: matched").payload,
            b"[REDACTED PATH]:12:3: matched",
        )
        self.assertEqual(
            module.sanitize_bytes(b'Traceback File "/var/private/file.py", line 7').payload,
            b'Traceback File "[REDACTED PATH]", line 7',
        )

        split_payload = b"prefix=/var/private/file.py,tail.py"
        baseline = module.sanitize_bytes(split_payload)
        for split in range(len(split_payload) + 1):
            with self.subTest(split=split):
                self.assertEqual(sanitize_in_two_chunks(module, split_payload, split), baseline)

    def test_quoted_paths_only_close_on_an_unescaped_matching_quote(self) -> None:
        """Break caught: an escaped quote leaves a filename suffix outside redaction."""

        module = sanitizer_module()
        cases = (
            (
                b'quoted="/Users/alice/Secret\\"Plan.txt", next',
                b'quoted="[REDACTED PATH]", next',
                ("/Users/alice",),
            ),
            (
                b"quoted='/Users/alice/Secret\\'Plan.txt', next",
                b"quoted='[REDACTED PATH]', next",
                ("/Users/alice",),
            ),
            (
                b'quoted="/var/private/Secret\\"Plan.txt", next',
                b'quoted="[REDACTED PATH]", next',
                (),
            ),
            (
                b'quoted="/var/private/Secret\\"Plan.txt',
                b'quoted="[REDACTED PATH]',
                (),
            ),
        )
        for payload, expected, private_roots in cases:
            with self.subTest(private_roots=private_roots, terminated=payload.endswith(b'next')):
                result = module.sanitize_bytes(payload, private_roots=private_roots)
                self.assertEqual(result.payload, expected)
                self.assertNotIn(b"Plan.txt", result.payload)

        invariant_payload = cases[0][0]
        baseline = module.sanitize_bytes(invariant_payload, private_roots=cases[0][2])
        for split in range(len(invariant_payload) + 1):
            with self.subTest(split=split):
                self.assertEqual(
                    sanitize_in_two_chunks(
                        module,
                        invariant_payload,
                        split,
                        private_roots=cases[0][2],
                    ),
                    baseline,
                )
        bytewise = module.StreamingSanitizer(private_roots=cases[0][2])
        for byte in invariant_payload:
            bytewise.feed(bytes((byte,)))
        self.assertEqual(bytewise.finish(), baseline)

    def test_secret_keys_support_repeated_qualifiers_and_bounded_json_escapes(self) -> None:
        """Break caught: key spelling or JSON escaping bypasses sensitive assignment detection."""

        module = sanitizer_module()
        valid = (
            b"secret_key=synthetic-one",
            b"secretKey=synthetic-two",
            b"SECRET_KEY=synthetic-three",
            b"API_KEY_PROD_V2=synthetic-four",
            b"API_KEY_PROD_PROD_PROD_PROD_PROD_PROD_PROD_PROD=synthetic-many",
            b'{"\\u0061pi_key": "synthetic-five"}',
            b'{"secret\\u005fkey": "synthetic-six"}',
        )
        for payload in valid:
            result = module.sanitize_bytes(payload)
            self.assertTrue(
                result.payload == b"[REDACTED SECRET]",
                "supported sensitive key was not redacted",
            )
            self.assertEqual(result.summary.secret_redactions, 1)
            self.assertTrue(
                all(fragment not in result.payload for fragment in payload.split(b"synthetic-")),
                "raw sensitive material survived",
            )

        malformed = (
            b'{"\\uZZZZapi_key": "benign"}',
            b'{"\\uD800api_key": "benign"}',
            b'{"\\uDC00api_key": "benign"}',
        )
        for payload in malformed:
            result = module.sanitize_bytes(payload)
            self.assertEqual(result.summary.secret_redactions, 0)

    def test_lone_cr_progress_groups_are_tainted_by_secret_or_private_records(self) -> None:
        """Break caught: CR normalization publishes siblings from a tainted progress group."""

        module = sanitizer_module()
        payload = b"before\rapi_key=synthetic-value\rafter\nvisible\r\n"
        expected = (
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"visible\n"
        )
        baseline = module.sanitize_bytes(payload)
        self.assertEqual(baseline.payload, expected)
        self.assertEqual(baseline.summary.secret_redactions, 3)
        for split in range(len(payload) + 1):
            with self.subTest(split=split):
                self.assertEqual(sanitize_in_two_chunks(module, payload, split), baseline)

        private = module.sanitize_bytes(
            b"before\r-----BEGIN PRIVATE KEY-----\rafter\nvisible"
        )
        self.assertEqual(
            private.payload,
            b"[REDACTED PRIVATE KEY]\n"
            b"[REDACTED PRIVATE KEY]\n"
            b"[REDACTED PRIVATE KEY]\n"
            b"[REDACTED PRIVATE KEY]",
        )
        self.assertEqual(private.summary.private_key_redactions, 4)

    def test_yaml_and_shell_multiline_secrets_redact_until_proven_termination(self) -> None:
        """Break caught: YAML or shell continuation records escape sensitive assignment state."""

        module = sanitizer_module()
        for indicator in (b"|", b"|-", b"|+", b">", b">-", b">+"):
            payload = b"api_key: " + indicator + b"\n  first\n  second\nvisible"
            result = module.sanitize_bytes(payload)
            self.assertEqual(
                result.payload,
                b"[REDACTED SECRET]\n"
                b"[REDACTED SECRET]\n"
                b"[REDACTED SECRET]\n"
                b"visible",
            )
            self.assertEqual(result.summary.secret_redactions, 3)

        empty = module.sanitize_bytes(b"secretKey:\n  continued\ndedented")
        self.assertEqual(
            empty.payload,
            b"[REDACTED SECRET]\n[REDACTED SECRET]\ndedented",
        )
        shell = module.sanitize_bytes(
            b"API_KEY=synthetic\\\ncontinued\\\nlast\nvisible"
        )
        self.assertTrue(
            shell.payload
            == b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"visible",
            "shell continuation leaked sensitive material",
        )
        unrelated_cli = module.sanitize_bytes(b"tool --api-key synthetic\nvisible")
        self.assertTrue(
            unrelated_cli.payload == b"[REDACTED SECRET]\nvisible",
            "ordinary CLI value incorrectly consumed the next record",
        )

    def test_cli_values_with_odd_backslashes_taint_the_continuation_chain(self) -> None:
        """Break caught: a CLI secret continued by the shell publishes later records."""

        module = sanitizer_module()
        payload = (
            b"tool --api-key prefix\\\n"
            b"continued\n"
            b"visible-one\n"
            b"tool --api-key \\\n"
            b"continued\\\n"
            b"last\n"
            b"visible-two"
        )
        expected = (
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"visible-one\n"
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"visible-two"
        )

        result = module.sanitize_bytes(payload)

        self.assertTrue(result.payload == expected, "CLI continuation was not fully tainted")
        self.assertEqual(result.summary.secret_redactions, 5)

    def test_cr_groups_widen_after_one_cross_boundary_classification_pass(self) -> None:
        """Break caught: pre-redacting CR groups destroys private or delimiter state."""

        module = sanitizer_module()
        private_payload = (
            b"before\r"
            b"-----BEGIN PRIVATE KEY-----\r"
            b"inside\n"
            b"continued\n"
            b"-----END PRIVATE KEY-----\n"
            b"visible"
        )
        private_expected = (
            b"[REDACTED PRIVATE KEY]\n"
            b"[REDACTED PRIVATE KEY]\n"
            b"[REDACTED PRIVATE KEY]\n"
            b"[REDACTED PRIVATE KEY]\n"
            b"[REDACTED PRIVATE KEY]\n"
            b"visible"
        )
        secret_payload = (
            b"before\rapi_key={\rinside\n"
            b"continued\n"
            b"}\n"
            b"visible"
        )
        secret_expected = (
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"visible"
        )

        private_result = module.sanitize_bytes(private_payload)
        secret_result = module.sanitize_bytes(secret_payload)

        self.assertTrue(
            private_result.payload == private_expected,
            "private-key state was lost after a lone-CR group",
        )
        self.assertEqual(private_result.summary.private_key_redactions, 5)
        self.assertTrue(
            secret_result.payload == secret_expected,
            "delimiter state was lost after a lone-CR group",
        )
        self.assertEqual(secret_result.summary.secret_redactions, 5)

    def test_private_key_blocks_cannot_close_an_outer_secret_continuation(self) -> None:
        """Break caught: private records mutate and close suspended secret state."""

        module = sanitizer_module()
        payload = (
            b"api_key=[\n"
            b"-----BEGIN PRIVATE KEY-----\n"
            b"]\n"
            b"-----END PRIVATE KEY-----\n"
            b"continued-secret\n"
            b"]\n"
            b"visible"
        )
        expected = (
            b"[REDACTED SECRET]\n"
            b"[REDACTED PRIVATE KEY]\n"
            b"[REDACTED PRIVATE KEY]\n"
            b"[REDACTED PRIVATE KEY]\n"
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"visible"
        )

        baseline = module.sanitize_bytes(payload)
        self.assertEqual(baseline.payload, expected)
        self.assertEqual(baseline.summary.secret_redactions, 3)
        self.assertEqual(baseline.summary.private_key_redactions, 3)
        for split in range(len(payload) + 1):
            with self.subTest(split=split):
                self.assertEqual(sanitize_in_two_chunks(module, payload, split), baseline)

    def test_nested_private_key_boundaries_redact_until_the_outer_end(self) -> None:
        """Break caught: an inner END prematurely publishes an outer private block."""

        module = sanitizer_module()
        payload = (
            b"visible-before\n"
            b"-----BEGIN PRIVATE KEY-----\n"
            b"-----BEGIN PRIVATE KEY-----\n"
            b"-----END PRIVATE KEY-----\n"
            b"continued-private\n"
            b"-----END PRIVATE KEY-----\n"
            b"visible-after"
        )
        expected = (
            b"visible-before\n"
            b"[REDACTED PRIVATE KEY]\n"
            b"[REDACTED PRIVATE KEY]\n"
            b"[REDACTED PRIVATE KEY]\n"
            b"[REDACTED PRIVATE KEY]\n"
            b"[REDACTED PRIVATE KEY]\n"
            b"visible-after"
        )

        result = module.sanitize_bytes(payload)
        self.assertEqual(result.payload, expected)
        self.assertEqual(result.summary.private_key_redactions, 5)

    def test_cr_group_counters_use_final_classification_and_ignore_literal_markers(self) -> None:
        """Break caught: marker input taints siblings or inflates redaction counters."""

        module = sanitizer_module()
        literal_only = module.sanitize_bytes(b"[REDACTED PRIVATE KEY]\rvisible")
        mixed = module.sanitize_bytes(
            b"[REDACTED SECRET]\rbefore\rtoken=synthetic"
        )
        private_wins = module.sanitize_bytes(
            b"api_key=synthetic\r-----BEGIN PRIVATE KEY-----\rinside\n"
            b"-----END PRIVATE KEY-----"
        )

        self.assertTrue(
            literal_only.payload == b"[REDACTED PRIVATE KEY]\nvisible",
            "literal marker input tainted a progress sibling",
        )
        self.assertEqual(literal_only.summary.private_key_redactions, 0)
        self.assertTrue(
            mixed.payload
            == b"[REDACTED SECRET]\n[REDACTED SECRET]\n[REDACTED SECRET]",
            "secret progress group was not widened",
        )
        self.assertEqual(mixed.summary.secret_redactions, 2)
        self.assertEqual(private_wins.summary.secret_redactions, 0)
        self.assertEqual(private_wins.summary.private_key_redactions, 4)

    def test_pending_limit_applies_to_ansi_stripped_raw_cr_records(self) -> None:
        """Break caught: CR-group redaction shrinks or expands bytes before pending checks."""

        module = sanitizer_module()
        exact_limits = module.SanitizerLimits(max_pending_bytes=7)
        exact = module.sanitize_bytes(
            b"ok\rto\x1b[31mken=x",
            limits=exact_limits,
        )
        self.assertTrue(
            exact.payload == b"[REDACTED SECRET]\n[REDACTED SECRET]",
            "an exact raw record was rejected because its marker is longer",
        )

        overflow = module.StreamingSanitizer(
            limits=module.SanitizerLimits(max_pending_bytes=17)
        )
        overflow.feed(b"ok\rtoken=123456789012")
        with self.assertRaises(module.SanitizationError) as caught:
            overflow.finish()
        self.assertEqual(
            caught.exception.code,
            module.SanitizationErrorCode.PENDING_LIMIT_EXCEEDED,
        )
        self.assertEqual(len(overflow._buffer), 0)
        with self.assertRaises(module.SanitizationError) as terminal:
            overflow.finish()
        self.assertEqual(terminal.exception.code, module.SanitizationErrorCode.INVALID_STATE)

    def test_yaml_extended_headers_sequences_and_doubled_quotes_stay_tainted(self) -> None:
        """Break caught: valid YAML multiline forms terminate redaction early."""

        module = sanitizer_module()
        indicators = (b"|2-", b"|-2", b"| # comment", b">9+ # comment", b">+9")
        expected_block = (
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"visible: true"
        )
        for indicator in indicators:
            payload = b"api_key: " + indicator + b"\n  first\n  second\nvisible: true"
            with self.subTest(indicator=indicator):
                result = module.sanitize_bytes(payload)
                self.assertTrue(result.payload == expected_block, "YAML block header leaked")

        sequence = module.sanitize_bytes(
            b"api_key:\n- first\n- second\nvisible: true"
        )
        quoted = module.sanitize_bytes(
            b"api_key: 'first\nsecond '' quoted\nlast'\nvisible"
        )
        self.assertTrue(
            sequence.payload == expected_block,
            "indentationless YAML sequence leaked",
        )
        self.assertTrue(
            quoted.payload
            == b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"visible",
            "doubled YAML single quote closed multiline state",
        )

    def test_yaml_plain_multiline_and_comment_only_values_stay_tainted(self) -> None:
        """Break caught: a valid plain or deferred YAML value publishes continuation bytes."""

        module = sanitizer_module()
        plain = module.sanitize_bytes(
            b"api_key: first-part\n  continued-part\nvisible: true"
        )
        comment_only = module.sanitize_bytes(
            b"client_secret: # deferred node\n- first\n- second\nvisible: true"
        )

        self.assertEqual(
            plain.payload,
            b"[REDACTED SECRET]\n[REDACTED SECRET]\nvisible: true",
        )
        self.assertEqual(plain.summary.secret_redactions, 2)
        self.assertEqual(
            comment_only.payload,
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"visible: true",
        )
        self.assertEqual(comment_only.summary.secret_redactions, 3)

    def test_quoted_colon_keys_defer_json_or_yaml_continuation_choice(self) -> None:
        """Break caught: a quoted YAML key is prematurely committed to JSON rules."""

        module = sanitizer_module()
        marker = b"[REDACTED SECRET]"
        cases = (
            (
                b'"api_key": |2-\n  first\n  second\nvisible: true',
                b"\n".join((marker, marker, marker, b"visible: true")),
            ),
            (
                b'"api_key": plain\n  continued\nvisible: true',
                b"\n".join((marker, marker, b"visible: true")),
            ),
            (
                b'"api_key": # deferred\n  indented\n- sequence\nvisible: true',
                b"\n".join((marker, marker, marker, b"visible: true")),
            ),
            (
                b'"api_key":\n  indented\n  continued\nvisible: true',
                b"\n".join((marker, marker, marker, b"visible: true")),
            ),
            (
                b'"api_key":\n- first\n- second\nvisible: true',
                b"\n".join((marker, marker, marker, b"visible: true")),
            ),
        )
        for payload, expected in cases:
            with self.subTest(lines=payload.count(b"\n") + 1):
                result = module.sanitize_bytes(payload)
                self.assertTrue(
                    result.payload == expected,
                    "quoted-colon YAML continuation leaked",
                )

        closed = (
            b'"api_key": "synthetic"\nvisible-one\n'
            b'"client_secret": ["synthetic"]\nvisible-two'
        )
        self.assertTrue(
            module.sanitize_bytes(closed).payload
            == b"[REDACTED SECRET]\nvisible-one\n[REDACTED SECRET]\nvisible-two",
            "closed quoted or flow value consumed a following record",
        )

        same_indent_json = module.sanitize_bytes(
            b'"api_key":\n"synthetic"\n"visible": 1'
        )
        self.assertTrue(
            same_indent_json.payload
            == b'[REDACTED SECRET]\n[REDACTED SECRET]\n"visible": 1',
            "ambiguous empty key stopped before the first JSON value",
        )

    def test_quoted_key_decoder_accepts_bounded_json_and_yaml_escapes(self) -> None:
        """Break caught: a valid quoted-key escape bypasses sensitive-key detection."""

        module = sanitizer_module()
        valid = (
            br'{"\"\b\f\n\r\t\\\/_api_key": "synthetic"}',
            br'{"\0\a\v\e\ \N\_\L\P_api_key": "synthetic"}',
            br'{"\\\u005f\u0061\u0070\u0069\u005f\u006b\u0065\u0079": "synthetic"}',
            br'{"\uD83D\uDE00\u005f\u0061\u0070\u0069\u005f\u006b\u0065\u0079": "synthetic"}',
            br'{"\x61pi_key": "synthetic"}',
            br'{"\U00000061pi_key": "synthetic"}',
            br'{"\x61\x70\x69\x5f\x6b\x65\x79": "synthetic"}',
        )
        for payload in valid:
            result = module.sanitize_bytes(payload)
            self.assertTrue(result.payload == b"[REDACTED SECRET]", "valid key escape leaked")
            self.assertEqual(result.summary.secret_redactions, 1)

        exact_key = (br"\uD83D\uDE00" * 120) + br"\u005fapi_key"
        exact_payload = b'{"' + exact_key + b'": "synthetic"}'
        self.assertTrue(
            module.sanitize_bytes(exact_payload).payload == b"[REDACTED SECRET]",
            "128-codepoint escaped key exceeded the decoder bound",
        )

        malformed = (
            br'{"\uD83D\u0041_api_key": "benign"}',
            br'{"\uDE00_api_key": "benign"}',
            br'{"\U00110000_api_key": "benign"}',
            br'{"\U0000D800_api_key": "benign"}',
            br'{"\xG1api_key": "benign"}',
            br'{"\q_api_key": "benign"}',
        )
        for payload in malformed:
            result = module.sanitize_bytes(payload)
            self.assertTrue(
                result.payload != b"[REDACTED SECRET]",
                "malformed key escape was accepted",
            )
            self.assertEqual(result.summary.secret_redactions, 0)

        oversized_key = (br"\uD83D\uDE00" * 121) + br"\u005fapi_key"
        oversized_payload = b'{"' + oversized_key + b'": "benign"}'
        oversized = module.sanitize_bytes(oversized_payload)
        self.assertTrue(
            oversized.payload != b"[REDACTED SECRET]",
            "129-codepoint key was accepted",
        )
        self.assertEqual(oversized.summary.secret_redactions, 0)

    def test_json_empty_assignment_consumes_the_first_same_indent_value(self) -> None:
        """Break caught: YAML indentation rules expose a next-record JSON value."""

        module = sanitizer_module()
        same_indent = module.sanitize_bytes(
            b'"api_key":\n"synthetic"\n"visible": 1'
        )
        multiline = module.sanitize_bytes(
            b'"api_key":\n\n   \n[\n"first",\n"last"\n]\n"visible": 1'
        )

        self.assertTrue(
            same_indent.payload == b'[REDACTED SECRET]\n[REDACTED SECRET]\n"visible": 1',
            "same-indent JSON value leaked",
        )
        self.assertTrue(
            multiline.payload
            == b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b'"visible": 1',
            "multiline JSON value leaked",
        )
        self.assertEqual(multiline.summary.secret_redactions, 7)

    def test_url_path_fail_closed_rules_preserve_only_ordinary_remote_routes(self) -> None:
        """Break caught: URI authority shielding exposes local or embedded absolute paths."""

        module = sanitizer_module()
        secret = module.sanitize_bytes(b"https://:synthetic@host.example/repo")
        path_vectors = (
            b"file://host.example/Users/alice/private.txt",
            b"git+ssh://host.example/var/private/repo",
            b"x://host.example/absolute/path",
            b"https://host.example/repo?next=/Users/alice/private.txt",
            b"ssh://host.example/repo#source=C:\\private\\file.txt",
        )
        ordinary = (
            b"http://host.example/a\n"
            b"https://host.example/b?next=relative/path\n"
            b"ssh://host.example/c#source=relative/path"
        )

        self.assertTrue(secret.payload == b"[REDACTED SECRET]", "empty userinfo leaked")
        for payload in path_vectors:
            with self.subTest(scheme=payload.split(b":", 1)[0]):
                result = module.sanitize_bytes(payload)
                self.assertTrue(result.payload == b"[REDACTED PATH]", "URI path leaked")
                self.assertEqual(result.summary.path_redactions, 1)
        self.assertEqual(module.sanitize_bytes(ordinary).payload, ordinary)

    def test_nested_remote_url_values_are_inspected_iteratively_and_bounded(self) -> None:
        """Break caught: an outer remote URL shields a nested local scheme path."""

        module = sanitizer_module()
        path_vectors = (
            b"https://outer.example/?next=file:///Users/alice/private.txt",
            b"https://outer.example/#next=file:/private/file.txt",
            b"https://outer.example/?next=x://host.example/absolute/path",
            b"https://outer.example/?next=https://middle.example/?target=file:///private",
            b"https://outer.example/file:///Users/alice/private.txt",
            b"https://outer.example/x://host.example/absolute/path",
            b"https://outer.example/https://middle.example/file:///private",
            b"https://file:///Users/alice/private.txt",
            b"https://outer.example/file:/private/file.txt",
            b"https://file:/private/file.txt",
            b"https://outer.example/x:/absolute/path",
            b"https://outer.example/https://middle.example/file:/private",
        )
        for payload in path_vectors:
            result = module.sanitize_bytes(payload)
            self.assertTrue(result.payload == b"[REDACTED PATH]", "nested URL path leaked")
            self.assertEqual(result.summary.path_redactions, 1)

        ordinary = (
            b"https://outer.example/route?next="
            b"https://middle.example/route?target=relative/path"
        )
        self.assertEqual(module.sanitize_bytes(ordinary).payload, ordinary)

        within_cap = b"relative/path"
        for index in range(32):
            within_cap = (
                f"https://h{index}.example/?next=".encode("ascii") + within_cap
            )
        beyond_cap = b"relative/path"
        for index in range(33):
            beyond_cap = (
                f"https://h{index}.example/?next=".encode("ascii") + beyond_cap
            )
        self.assertEqual(module.sanitize_bytes(within_cap).payload, within_cap)
        self.assertTrue(
            module.sanitize_bytes(beyond_cap).payload == b"[REDACTED PATH]",
            "nested URL inspection cap did not fail closed",
        )

        within_path_cap = b"relative/path"
        for index in range(32):
            within_path_cap = (
                f"https://p{index}.example/".encode("ascii") + within_path_cap
            )
        beyond_path_cap = b"relative/path"
        for index in range(33):
            beyond_path_cap = (
                f"https://p{index}.example/".encode("ascii") + beyond_path_cap
            )
        self.assertEqual(
            module.sanitize_bytes(within_path_cap).payload,
            within_path_cap,
        )
        self.assertEqual(
            module.sanitize_bytes(beyond_path_cap).payload,
            b"[REDACTED PATH]",
        )

        invariant_payload = path_vectors[-1]
        baseline = module.sanitize_bytes(invariant_payload)
        for split in range(len(invariant_payload) + 1):
            with self.subTest(split=split):
                self.assertEqual(
                    sanitize_in_two_chunks(module, invariant_payload, split),
                    baseline,
                )
        bytewise = module.StreamingSanitizer()
        for byte in invariant_payload:
            bytewise.feed(bytes((byte,)))
        self.assertEqual(bytewise.finish(), baseline)

    def test_final_blocker_vectors_are_chunk_invariant(self) -> None:
        """Break caught: feed boundaries alter the new multiline and URI decisions."""

        module = sanitizer_module()
        payload = (
            b"tool --api-key prefix\\\ncontinued\nvisible\n"
            b"before\rapi_key={\rinside\ncontinued\n}\n"
            b'"client_secret":\n[\n"first"\n]\n'
            b"api_key: |2-\n  yaml\nvisible: true\n"
            b"https://host.example/repo?next=/private/file"
        )
        baseline = module.sanitize_bytes(payload)
        for split in range(len(payload) + 1):
            with self.subTest(mode="two chunks", split=split):
                self.assertEqual(sanitize_in_two_chunks(module, payload, split), baseline)

        bytewise = module.StreamingSanitizer()
        for byte in payload:
            bytewise.feed(bytes((byte,)))
        self.assertEqual(bytewise.finish(), baseline)

    def test_delimiter_stack_is_mutated_in_place_with_linear_operation_count(self) -> None:
        """Break caught: each multiline scan copies the accumulated delimiter stack."""

        module = sanitizer_module()

        class CountingStack(list):
            def __init__(self) -> None:
                super().__init__()
                self.appends = 0
                self.pops = 0
                self.iterations = 0

            def append(self, value) -> None:
                self.appends += 1
                super().append(value)

            def pop(self, index=-1):
                self.pops += 1
                return super().pop(index)

            def __iter__(self):
                self.iterations += 1
                return super().__iter__()

        stack = CountingStack()
        state = module._DelimiterState(stack=stack)
        result = module._scan_delimiters(("(" * 58_000) + (")" * 58_000), state)
        self.assertIsNone(result)
        self.assertIs(state.stack, stack)
        self.assertEqual(stack.appends, 58_000)
        self.assertEqual(stack.pops, 58_000)
        self.assertEqual(stack.iterations, 0)

    def test_every_active_sanitization_error_clears_bytes_and_aborts(self) -> None:
        """Break caught: an error retains candidate bytes or leaves the sanitizer reusable."""

        module = sanitizer_module()
        cases = (
            (
                module.StreamingSanitizer(limits=module.SanitizerLimits(max_input_bytes=1)),
                lambda sanitizer: (sanitizer.feed(b"x"), sanitizer.feed(b"y")),
                module.SanitizationErrorCode.INPUT_LIMIT_EXCEEDED,
            ),
            (
                module.StreamingSanitizer(limits=module.SanitizerLimits(max_pending_bytes=1)),
                lambda sanitizer: (sanitizer.feed(b"private-value"), sanitizer.finish()),
                module.SanitizationErrorCode.PENDING_LIMIT_EXCEEDED,
            ),
            (
                module.StreamingSanitizer(limits=module.SanitizerLimits(max_output_bytes=1)),
                lambda sanitizer: (sanitizer.feed(b"private-value"), sanitizer.finish()),
                module.SanitizationErrorCode.OUTPUT_LIMIT_EXCEEDED,
            ),
            (
                module.StreamingSanitizer(limits=module.SanitizerLimits(max_lines=0)),
                lambda sanitizer: (sanitizer.feed(b"x"), sanitizer.finish()),
                module.SanitizationErrorCode.LINE_LIMIT_EXCEEDED,
            ),
            (
                module.StreamingSanitizer(
                    limits=module.SanitizerLimits(max_control_sequence_bytes=1)
                ),
                lambda sanitizer: (sanitizer.feed(b"\x1b["), sanitizer.finish()),
                module.SanitizationErrorCode.CONTROL_SEQUENCE_LIMIT_EXCEEDED,
            ),
        )
        for sanitizer, operation, expected_code in cases:
            with self.assertRaises(module.SanitizationError) as caught:
                operation(sanitizer)
            self.assertEqual(caught.exception.code, expected_code)
            self.assertEqual(sanitizer._state.value, "aborted")
            self.assertEqual(sanitizer._buffer, bytearray())
            self.assertNotIn("private-value", repr(caught.exception))

    def test_cr_lf_and_crlf_are_normalized_to_lf(self) -> None:
        """Break caught: platform newline forms produce different receipt bytes."""

        module = sanitizer_module()

        cases = (
            (b"", b"", 0),
            (b"alpha\rbeta\r\ngamma\n", b"alpha\nbeta\ngamma\n", 3),
            (b"\r\r\n\n", b"\n\n\n", 3),
        )
        for payload, expected, expected_lines in cases:
            with self.subTest(payload=payload):
                result = module.sanitize_bytes(payload)
                self.assertEqual(result.payload, expected)
                self.assertEqual(result.summary.input_bytes, len(payload))
                self.assertEqual(result.summary.output_bytes, len(expected))
                self.assertEqual(result.summary.line_count, expected_lines)

    def test_newline_normalization_is_equivalent_at_every_chunk_split(self) -> None:
        """Break caught: CRLF split between feeds is treated as two newlines."""

        module = sanitizer_module()
        payload = b"first\rsecond\r\nthird\nfourth\r\n"
        expected = b"first\nsecond\nthird\nfourth\n"

        for split in range(len(payload) + 1):
            with self.subTest(split=split):
                result = sanitize_in_two_chunks(module, payload, split)
                self.assertEqual(result.payload, expected)
                self.assertEqual(result.summary.line_count, 4)

        bytewise = module.StreamingSanitizer()
        for byte in payload:
            bytewise.feed(bytes((byte,)))
        self.assertEqual(bytewise.finish().payload, expected)

    def test_recognized_ansi_sequences_are_stripped_at_the_byte_level(self) -> None:
        """Break caught: a recognized ANSI family reaches captured output."""

        module = sanitizer_module()
        cases = (
            ("CSI", b"left\x1b[31;1mright"),
            ("OSC BEL", b"left\x1b]0;title\x07right"),
            ("OSC ST", b"left\x1b]8;;https://invalid.example\x1b\\right"),
            ("DCS", b"left\x1bP1;2|data\x1b\\right"),
            ("SOS", b"left\x1bXdata\x1b\\right"),
            ("PM", b"left\x1b^data\x1b\\right"),
            ("APC", b"left\x1b_data\x1b\\right"),
            ("general Fe", b"left\x1bMright"),
        )
        for family, payload in cases:
            with self.subTest(family=family):
                result = module.sanitize_bytes(payload)
                self.assertEqual(result.payload, b"leftright")
                self.assertEqual(result.summary.ansi_sequences_stripped, 1)
                self.assertEqual(result.summary.incomplete_ansi_sequences, 0)

    def test_ansi_stripping_is_equivalent_at_every_chunk_split(self) -> None:
        """Break caught: an ANSI introducer or ST split across feeds leaks bytes."""

        module = sanitizer_module()
        payload = (
            b"a\x1b[32mb\x1b]title\x07c\x1b]link\x1b\\d\x1bPdata\x1b\\e"
            b"\x1bXsos\x1b\\f\x1b^pm\x1b\\g\x1b_apc\x1b\\h\x1bMi"
        )

        for split in range(len(payload) + 1):
            with self.subTest(split=split):
                result = sanitize_in_two_chunks(module, payload, split)
                self.assertEqual(result.payload, b"abcdefghi")
                self.assertEqual(result.summary.ansi_sequences_stripped, 8)

        bytewise = module.StreamingSanitizer()
        for byte in payload:
            bytewise.feed(bytes((byte,)))
        bytewise_result = bytewise.finish()
        self.assertEqual(bytewise_result.payload, b"abcdefghi")
        self.assertEqual(bytewise_result.summary.ansi_sequences_stripped, 8)

    def test_malformed_or_unrecognized_escape_replays_with_escaped_esc(self) -> None:
        """Break caught: malformed or non-Fe ESC bytes remain terminal-active."""

        module = sanitizer_module()
        payload = b"pre\x1b[ 1mmid\x1bcpost"

        result = module.sanitize_bytes(payload)

        self.assertEqual(result.payload, b"pre\\x1B[ 1mmid\\x1Bcpost")
        self.assertEqual(result.summary.ansi_sequences_stripped, 0)
        self.assertEqual(result.summary.incomplete_ansi_sequences, 0)
        self.assertEqual(result.summary.escaped_control_characters, 2)

    def test_recognized_incomplete_ansi_at_eof_is_stripped_and_counted(self) -> None:
        """Break caught: a recognized but unterminated ANSI prefix leaks at EOF."""

        module = sanitizer_module()
        cases = (
            ("ESC", b"visible\x1b"),
            ("CSI", b"visible\x1b[31"),
            ("OSC", b"visible\x1b]title"),
            ("OSC partial ST", b"visible\x1b]title\x1b"),
            ("DCS", b"visible\x1bPdata"),
            ("SOS", b"visible\x1bXdata"),
            ("PM", b"visible\x1b^data"),
            ("APC", b"visible\x1b_data"),
        )
        for family, payload in cases:
            with self.subTest(family=family):
                result = module.sanitize_bytes(payload)
                self.assertEqual(result.payload, b"visible")
                self.assertEqual(result.summary.ansi_sequences_stripped, 0)
                self.assertEqual(result.summary.incomplete_ansi_sequences, 1)

    def test_control_sequence_limit_is_inclusive_and_aborts_without_output(self) -> None:
        """Break caught: an over-limit control sequence is stripped instead of rejected."""

        module = sanitizer_module()
        accepted = module.sanitize_bytes(
            b"a\x1b[31mb",
            limits=module.SanitizerLimits(max_control_sequence_bytes=5),
        )
        self.assertEqual(accepted.payload, b"ab")
        self.assertEqual(accepted.summary.ansi_sequences_stripped, 1)

        for split in range(7):
            with self.subTest(split=split):
                sanitizer = module.StreamingSanitizer(
                    limits=module.SanitizerLimits(max_control_sequence_bytes=5)
                )
                sanitizer.feed(b"\x1b[123m"[:split])
                sanitizer.feed(b"\x1b[123m"[split:])
                with self.assertRaises(module.SanitizationError) as caught:
                    sanitizer.finish()
                self.assertEqual(
                    caught.exception.code,
                    module.SanitizationErrorCode.CONTROL_SEQUENCE_LIMIT_EXCEEDED,
                )
                with self.assertRaises(module.SanitizationError) as invalid_state:
                    sanitizer.finish()
                self.assertEqual(
                    invalid_state.exception.code,
                    module.SanitizationErrorCode.INVALID_STATE,
                )

    def test_pending_limit_is_per_normalized_post_ansi_record_and_inclusive(self) -> None:
        """Break caught: pending bytes count ANSI or LF, or allow a record one byte over."""

        module = sanitizer_module()
        limits = module.SanitizerLimits(max_pending_bytes=5)

        accepted = module.sanitize_bytes(
            b"12\x1b[31m345\r\n\xc3\xa9x\r",
            limits=limits,
        )
        self.assertEqual(accepted.payload, b"12345\n\xc3\xa9x\n")
        self.assertEqual(accepted.summary.line_count, 2)

        sanitizer = module.StreamingSanitizer(limits=limits)
        self.assertIsNone(sanitizer.feed(b"12\x1b[31m3456\r\nok"))
        with self.assertRaises(module.SanitizationError) as caught:
            sanitizer.finish()
        self.assertEqual(
            caught.exception.code,
            module.SanitizationErrorCode.PENDING_LIMIT_EXCEEDED,
        )
        with self.assertRaises(module.SanitizationError) as invalid_state:
            sanitizer.feed(b"must not be accepted")
        self.assertEqual(
            invalid_state.exception.code,
            module.SanitizationErrorCode.INVALID_STATE,
        )

    def test_invalid_utf8_bytes_render_as_uppercase_byte_escapes(self) -> None:
        """Break caught: invalid UTF-8 is replaced, dropped, or rendered ambiguously."""

        module = sanitizer_module()

        result = module.sanitize_bytes(b"before\x80\x9b\xff\xc3(after")

        self.assertEqual(result.payload, b"before\\x80\\x9B\\xFF\\xC3(after")
        self.assertEqual(result.summary.invalid_utf8_bytes, 4)
        self.assertEqual(result.summary.escaped_control_characters, 0)

    def test_literal_backslashes_are_doubled_without_changing_counters(self) -> None:
        """Break caught: literal text can masquerade as a sanitizer escape."""

        module = sanitizer_module()

        result = module.sanitize_bytes(b"path\\name\\\\tail")

        self.assertEqual(result.payload, b"path\\\\name\\\\\\\\tail")
        self.assertEqual(result.summary.invalid_utf8_bytes, 0)
        self.assertEqual(result.summary.escaped_control_characters, 0)

    def test_all_c0_del_and_valid_utf8_c1_render_with_exact_counters(self) -> None:
        """Break caught: a control code remains active or valid Unicode is corrupted."""

        module = sanitizer_module()
        printable = (
            b"A caf\xc3\xa9 \xed\x95\x9c\xea\xb5\xad\xec\x96\xb4 "
            b"\xf0\x9f\x98\x80 "
        )
        c0_and_del = (
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c"
            b"\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19"
            b"\x1a\x1b\x1c\x1d\x1e\x1f\x7f"
        )
        valid_c1 = b"".join(b"\xc2" + bytes((byte,)) for byte in range(0x80, 0xA0))
        expected_c0_and_del = (
            b"\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09"
            b"\\x0B\\x0C\\x0E\\x0F\\x10\\x11\\x12\\x13\\x14\\x15"
            b"\\x16\\x17\\x18\\x19\\x1A\\x1B\\x1C\\x1D\\x1E\\x1F\\x7F"
        )
        expected_c1 = (
            b"\\u0080\\u0081\\u0082\\u0083\\u0084\\u0085\\u0086\\u0087"
            b"\\u0088\\u0089\\u008A\\u008B\\u008C\\u008D\\u008E\\u008F"
            b"\\u0090\\u0091\\u0092\\u0093\\u0094\\u0095\\u0096\\u0097"
            b"\\u0098\\u0099\\u009A\\u009B\\u009C\\u009D\\u009E\\u009F"
        )

        result = module.sanitize_bytes(printable + c0_and_del + valid_c1)

        self.assertEqual(result.payload, printable + expected_c0_and_del + expected_c1)
        self.assertEqual(result.summary.invalid_utf8_bytes, 0)
        self.assertEqual(result.summary.escaped_control_characters, 63)

    def test_rendering_is_invariant_for_all_splits_bytewise_and_seeded_chunks(self) -> None:
        """Break caught: a split UTF-8, CRLF, ANSI, or escape token changes the receipt."""

        module = sanitizer_module()
        payload = (
            b"A\\B\r\n\x1b[31mred\x1b[0m \xe2\x98\x83 "
            b"\xff\x00 \xc2\x85\r"
        )
        expected = b"A\\\\B\nred \xe2\x98\x83 \\xFF\\x00 \\u0085\n"
        baseline = module.sanitize_bytes(payload)
        self.assertEqual(baseline.payload, expected)
        self.assertEqual(baseline.summary.ansi_sequences_stripped, 2)
        self.assertEqual(baseline.summary.invalid_utf8_bytes, 1)
        self.assertEqual(baseline.summary.escaped_control_characters, 2)

        for split in range(len(payload) + 1):
            with self.subTest(mode="two chunks", split=split):
                self.assertEqual(sanitize_in_two_chunks(module, payload, split), baseline)

        bytewise = module.StreamingSanitizer()
        for byte in payload:
            bytewise.feed(bytes((byte,)))
        self.assertEqual(bytewise.finish(), baseline)

        generator = random.Random(7007)
        for trial in range(32):
            sanitizer = module.StreamingSanitizer()
            cursor = 0
            while cursor < len(payload):
                chunk_size = generator.randint(1, 7)
                sanitizer.feed(payload[cursor : cursor + chunk_size])
                cursor += chunk_size
            with self.subTest(mode="seeded random", trial=trial):
                self.assertEqual(sanitizer.finish(), baseline)

    def test_rendering_inflation_obeys_inclusive_output_limit_and_aborts(self) -> None:
        """Break caught: output limits are checked before escape rendering expands bytes."""

        module = sanitizer_module()
        limits = module.SanitizerLimits(max_output_bytes=6)

        accepted = module.sanitize_bytes(b"\\\x00", limits=limits)
        self.assertEqual(accepted.payload, b"\\\\" + b"\\x00")
        self.assertEqual(accepted.summary.output_bytes, 6)

        sanitizer = module.StreamingSanitizer(limits=limits)
        sanitizer.feed(b"\\\x00A")
        with self.assertRaises(module.SanitizationError) as caught:
            sanitizer.finish()
        self.assertEqual(
            caught.exception.code,
            module.SanitizationErrorCode.OUTPUT_LIMIT_EXCEEDED,
        )
        with self.assertRaises(module.SanitizationError) as invalid_state:
            sanitizer.finish()
        self.assertEqual(
            invalid_state.exception.code,
            module.SanitizationErrorCode.INVALID_STATE,
        )

    def test_high_confidence_credential_vectors_replace_the_whole_record(self) -> None:
        """Break caught: a supported credential form or value tail survives redaction."""

        module = sanitizer_module()
        marker = b"[REDACTED SECRET]"
        sensitive_keys = (
            "authorization",
            "cookie",
            "password",
            "passwd",
            "secret",
            "api_key",
            "apikey",
            "access_token",
            "auth_token",
            "session_token",
            "client_secret",
            "credential",
            "private_key",
            "service.api-key-prod",
            "database-password_backup",
        )
        token_vectors = (
            b"Authorization: Bearer header-credential-123",
            b"Set-Cookie: session=header-cookie-123",
            b"GET /callback?access_token=query-credential-123&state=visible",
            b"tool --client-secret cli-credential-123 --verbose",
            b"standalone Bearer bearer-credential-123",
            b"standalone Basic dXNlcjpwYXNzd29yZA==",
            b"prefix ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 suffix",
            b"prefix github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456 suffix",
            b"prefix glpat-ABCDEFGHIJKLMNOPQRST suffix",
            b"prefix xoxb-1234567890-ABCDEFGHIJ suffix",
            b'prefix sk_' + b'live_ABCDEFGHIJKLMNOPQRSTUVWX suffix',
            b"prefix sk-proj-ABCDEFGHIJKLMNOPQRST suffix",
            b"prefix npm_ABCDEFGHIJKLMNOPQRSTUVWX suffix",
            b"prefix AIzaABCDEFGHIJKLMNOPQRSTUVWX suffix",
            b"prefix SG.ABCDEFGHIJKLMNOPQRST.UVWXYZABCDEFGHIJKLMN suffix",
            b"prefix eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature123 suffix",
            b"prefix AKIAABCDEFGHIJKLMNOP suffix",
        )

        for key in sensitive_keys:
            with self.subTest(kind="assignment", key=key):
                result = module.sanitize_bytes(
                    f'prefix {key}="synthetic-credential-123" trailing'.encode("ascii")
                )
                self.assertEqual(result.payload, marker)
                self.assertEqual(result.summary.secret_redactions, 1)
                self.assertEqual(result.summary.private_key_redactions, 0)

        for payload in token_vectors:
            with self.subTest(kind="token", payload=payload[:20]):
                result = module.sanitize_bytes(payload)
                self.assertEqual(result.payload, marker)
                self.assertEqual(result.summary.secret_redactions, 1)

    def test_false_positive_boundaries_remain_visible(self) -> None:
        """Break caught: benign token vocabulary is classified as a credential."""

        module = sanitizer_module()
        payload = (
            b"token_count=12\n"
            b"signature_algorithm=ed25519\n"
            b"secretary = employee\n"
            b"public_key=ed25519\n"
            b"description = secret token words\n"
            b"password authentication failed\n"
            b"token refresh pending\n"
            b"api_key=synthetic-credential-123"
        )
        expected = (
            b"token_count=12\n"
            b"signature_algorithm=ed25519\n"
            b"secretary = employee\n"
            b"public_key=ed25519\n"
            b"description = secret token words\n"
            b"password authentication failed\n"
            b"token refresh pending\n"
            b"[REDACTED SECRET]"
        )

        result = module.sanitize_bytes(payload)

        self.assertEqual(result.payload, expected)
        self.assertEqual(result.summary.secret_redactions, 1)

    def test_detection_projection_closes_ansi_control_and_invalid_byte_splices(self) -> None:
        """Break caught: terminal or malformed byte splicing bypasses secret detection."""

        module = sanitizer_module()
        payload = (
            b"api\x00\xc2\x85\xff\x1b[31m_key=synthetic-value\n"
            b"prefix gh\x1b[0mp_ABCDEFGHIJKL\x00MNOPQRSTUVWX\x80 suffix"
        )

        result = module.sanitize_bytes(payload)

        self.assertEqual(
            result.payload,
            b"[REDACTED SECRET]\n[REDACTED SECRET]",
        )
        self.assertEqual(result.summary.ansi_sequences_stripped, 2)
        self.assertEqual(result.summary.invalid_utf8_bytes, 2)
        self.assertEqual(result.summary.escaped_control_characters, 3)
        self.assertEqual(result.summary.secret_redactions, 2)

    def test_private_key_blocks_replace_each_record_and_preserve_delimiters(self) -> None:
        """Break caught: a private-key boundary or enclosed record reaches output."""

        module = sanitizer_module()
        payload = (
            b"before\r\n"
            b"-----BEGIN RSA PRIVATE KEY-----\r"
            b"synthetic-private-material\n"
            b"-----END RSA PRIVATE KEY-----\r\n"
            b"after"
        )
        expected = (
            b"before\n"
            b"[REDACTED PRIVATE KEY]\n"
            b"[REDACTED PRIVATE KEY]\n"
            b"[REDACTED PRIVATE KEY]\n"
            b"after"
        )

        result = module.sanitize_bytes(payload)

        self.assertEqual(result.payload, expected)
        self.assertEqual(result.summary.private_key_redactions, 3)
        self.assertEqual(result.summary.secret_redactions, 0)
        standalone_end = module.sanitize_bytes(b"-----END PRIVATE KEY-----")
        self.assertEqual(standalone_end.payload, b"[REDACTED PRIVATE KEY]")
        self.assertEqual(standalone_end.summary.private_key_redactions, 1)

    def test_unclosed_private_key_and_multiline_credentials_redact_through_eof(self) -> None:
        """Break caught: EOF publishes unterminated private or credential material."""

        module = sanitizer_module()
        private_payload = (
            b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
            b"synthetic-private-line\n"
            b"unterminated-private-tail"
        )
        secret_payload = (
            b"password = [\n"
            b"synthetic-secret-line\n"
            b"unterminated-secret-tail"
        )

        private_result = module.sanitize_bytes(private_payload)
        secret_result = module.sanitize_bytes(secret_payload)

        self.assertEqual(
            private_result.payload,
            b"[REDACTED PRIVATE KEY]\n"
            b"[REDACTED PRIVATE KEY]\n"
            b"[REDACTED PRIVATE KEY]",
        )
        self.assertEqual(private_result.summary.private_key_redactions, 3)
        self.assertEqual(
            secret_result.payload,
            b"[REDACTED SECRET]\n[REDACTED SECRET]\n[REDACTED SECRET]",
        )
        self.assertEqual(secret_result.summary.secret_redactions, 3)

    def test_quoted_and_bracketed_multiline_credentials_close_after_balancing(self) -> None:
        """Break caught: a multiline credential publishes an interior or closing record."""

        module = sanitizer_module()
        payload = (
            b"api_key = \"first-part\n"
            b"second-part with \\\" escaped quote\n"
            b"closing-part\"\n"
            b"visible-one\n"
            b"client_secret = {\n"
            b"  \"nested\": [\"synthetic\"],\n"
            b"}\n"
            b"visible-two"
        )
        expected = (
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"visible-one\n"
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"visible-two"
        )

        result = module.sanitize_bytes(payload)

        self.assertEqual(result.payload, expected)
        self.assertEqual(result.summary.secret_redactions, 6)

    def test_secret_and_private_key_processing_is_chunk_invariant(self) -> None:
        """Break caught: chunk boundaries reset secret or private-key record state."""

        module = sanitizer_module()
        payload = (
            b"visible\r\n"
            b"api\x00_key=synthetic-value\n"
            b"-----BEGIN PRIVATE KEY-----\n"
            b"private-material\n"
            b"-----END PRIVATE KEY-----\n"
            b"auth_token = {\n"
            b"synthetic-token-part\n"
            b"}\r"
            b"tail"
        )
        expected = (
            b"visible\n"
            b"[REDACTED SECRET]\n"
            b"[REDACTED PRIVATE KEY]\n"
            b"[REDACTED PRIVATE KEY]\n"
            b"[REDACTED PRIVATE KEY]\n"
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]\n"
            b"[REDACTED SECRET]"
        )
        baseline = module.sanitize_bytes(payload)
        self.assertEqual(baseline.payload, expected)
        self.assertEqual(baseline.summary.secret_redactions, 5)
        self.assertEqual(baseline.summary.private_key_redactions, 3)

        for split in range(len(payload) + 1):
            with self.subTest(mode="two chunks", split=split):
                self.assertEqual(sanitize_in_two_chunks(module, payload, split), baseline)

        bytewise = module.StreamingSanitizer()
        for byte in payload:
            bytewise.feed(bytes((byte,)))
        self.assertEqual(bytewise.finish(), baseline)

        generator = random.Random(7008)
        for trial in range(32):
            sanitizer = module.StreamingSanitizer()
            cursor = 0
            while cursor < len(payload):
                chunk_size = generator.randint(1, 11)
                sanitizer.feed(payload[cursor : cursor + chunk_size])
                cursor += chunk_size
            with self.subTest(mode="seeded random", trial=trial):
                self.assertEqual(sanitizer.finish(), baseline)

    def test_final_markers_obey_pending_output_and_line_limits_without_leaks(self) -> None:
        """Break caught: redaction bypasses limits or an error reflects secret bytes."""

        module = sanitizer_module()
        threat = b"api_key=synthetic-threat-value"

        baseline = module.sanitize_bytes(threat)
        self.assertEqual(baseline.payload, b"[REDACTED SECRET]")
        self.assertNotIn(threat.decode("ascii"), repr(baseline))

        accepted = module.sanitize_bytes(
            threat,
            limits=module.SanitizerLimits(max_output_bytes=17),
        )
        self.assertEqual(accepted.payload, b"[REDACTED SECRET]")
        self.assertEqual(accepted.summary.output_bytes, 17)

        output_limited = module.StreamingSanitizer(
            limits=module.SanitizerLimits(max_output_bytes=16)
        )
        output_limited.feed(threat)
        with self.assertRaises(module.SanitizationError) as output_error:
            output_limited.finish()
        self.assertEqual(
            output_error.exception.code,
            module.SanitizationErrorCode.OUTPUT_LIMIT_EXCEEDED,
        )
        self.assertNotIn(threat.decode("ascii"), str(output_error.exception))
        self.assertNotIn(threat.decode("ascii"), repr(output_error.exception))
        with self.assertRaises(module.SanitizationError) as invalid_state:
            output_limited.finish()
        self.assertEqual(
            invalid_state.exception.code,
            module.SanitizationErrorCode.INVALID_STATE,
        )

        pending_limited = module.StreamingSanitizer(
            limits=module.SanitizerLimits(max_pending_bytes=16)
        )
        pending_limited.feed(threat)
        with self.assertRaises(module.SanitizationError) as pending_error:
            pending_limited.finish()
        self.assertEqual(
            pending_error.exception.code,
            module.SanitizationErrorCode.PENDING_LIMIT_EXCEEDED,
        )

        line_limited = module.StreamingSanitizer(
            limits=module.SanitizerLimits(max_lines=1)
        )
        line_limited.feed(b"api_key=first\npassword=second")
        with self.assertRaises(module.SanitizationError) as line_error:
            line_limited.finish()
        self.assertEqual(
            line_error.exception.code,
            module.SanitizationErrorCode.LINE_LIMIT_EXCEEDED,
        )

    def test_private_roots_reject_invalid_shapes_without_reflection(self) -> None:
        """Break caught: malformed roots enter matching state or leak through errors."""

        module = sanitizer_module()

        class RootString(str):
            pass

        class RootTuple(tuple):
            pass

        invalid_values = (
            ["/private/root"],
            "/private/root",
            RootTuple(("/private/root",)),
            (RootString("/private/root"),),
            (b"/private/root",),
            (1,),
            ("",),
            ("relative/root",),
            ("./relative",),
            ("../relative",),
            ("/",),
            ("C:\\",),
            ("C:/",),
            ("C:relative",),
            (r"\\server\share",),
            ("\\\\server\\share\\",),
            ("//server/share",),
            ("/private\x00root",),
            ("/" + ("a" * 4096),),
        )
        for private_roots in invalid_values:
            with self.subTest(private_roots_type=type(private_roots).__name__):
                with self.assertRaises(module.SanitizationError) as caught:
                    module.StreamingSanitizer(private_roots=private_roots)
                self.assertEqual(
                    caught.exception.code,
                    module.SanitizationErrorCode.INVALID_PRIVATE_ROOT,
                )
                self.assertEqual(str(caught.exception), "invalid_private_root")
                self.assertNotIn("private/root", repr(caught.exception))

    def test_private_root_valid_forms_and_utf8_byte_boundary_are_accepted(self) -> None:
        """Break caught: a valid absolute root form or exact byte limit is rejected."""

        module = sanitizer_module()
        roots = (
            "/private/root",
            r"C:\Private\Root",
            r"\\server\share\folder",
            "//server/share/folder",
            "/사용자/비밀 폴더",
            "/" + ("a" * 4095),
        )

        sanitizer = module.StreamingSanitizer(private_roots=roots)
        self.assertNotIn("private/root", repr(sanitizer))
        sanitizer.feed(b"visible")
        self.assertEqual(sanitizer.finish().payload, b"visible")

    def test_private_root_raw_tuple_limit_is_16_and_duplicates_are_allowed(self) -> None:
        """Break caught: root count checks canonical entries instead of the raw tuple."""

        module = sanitizer_module()
        sixteen = tuple(f"/private/root-{index}" for index in range(16))
        duplicate_sixteen = ("/private/duplicate",) * 16

        accepted = module.StreamingSanitizer(private_roots=sixteen)
        accepted.feed(b"/private/root-15/file.txt")
        self.assertEqual(accepted.finish().payload, b"[REDACTED PATH]")
        duplicates = module.StreamingSanitizer(private_roots=duplicate_sixteen)
        duplicates.feed(b"/private/duplicate/file.txt")
        duplicate_result = duplicates.finish()
        self.assertEqual(duplicate_result.payload, b"[REDACTED PATH]")
        self.assertEqual(duplicate_result.summary.path_redactions, 1)

        seventeen = sixteen + ("/private/root-16",)
        with self.assertRaises(module.SanitizationError) as caught:
            module.StreamingSanitizer(private_roots=seventeen)
        self.assertEqual(
            caught.exception.code,
            module.SanitizationErrorCode.TOO_MANY_PRIVATE_ROOTS,
        )
        self.assertEqual(str(caught.exception), "too_many_private_roots")

    def test_explicit_roots_redact_descendants_and_preserve_location_suffixes(self) -> None:
        """Break caught: a declared root, descendant, or location suffix is mishandled."""

        module = sanitizer_module()
        roots = (
            "/srv/private",
            "/srv/private/deeper",
            "/srv/private/",
            r"C:\Private\Root",
            r"\\server\share\folder",
            "/사용자/비밀 폴더",
        )
        payload = (
            b"/srv/private/deeper/file.py:12:7: hit\n"
            b'quoted="/srv/private/file.py", line 4\n'
            b"c:/private/root/repo/file.py:8:2\n"
            b"\\\\SERVER\\SHARE\\FOLDER\\repo\\file.py:9\n"
            b"/\xec\x82\xac\xec\x9a\xa9\xec\x9e\x90/\xeb\xb9\x84\xeb\xb0\x80 \xed\x8f\xb4\xeb\x8d\x94/\xed\x8c\x8c\xec\x9d\xbc.py:3\n"
            b"sibling=/srv/privateer/file.py"
        )
        expected = (
            b"[REDACTED PATH]:12:7: hit\n"
            b'quoted="[REDACTED PATH]", line 4\n'
            b"[REDACTED PATH]:8:2\n"
            b"[REDACTED PATH]:9\n"
            b"[REDACTED PATH]:3\n"
            b"sibling=[REDACTED PATH]"
        )

        result = module.sanitize_bytes(payload, private_roots=roots)

        self.assertEqual(result.payload, expected)
        self.assertEqual(result.summary.path_redactions, 6)

    def test_explicit_root_redaction_is_chunk_invariant(self) -> None:
        """Break caught: a root split across feeds survives or changes counters."""

        module = sanitizer_module()
        roots = (
            "/private/root",
            r"C:\Private\Root",
            r"\\server\share\folder",
            "/사용자/비밀",
        )
        payload = (
            b"/private/root/a.py:1\r\n"
            b"C:\\Private\\Root\\b.py:2\n"
            b"\\\\server\\share\\folder\\c.py:3\r"
            b"/\xec\x82\xac\xec\x9a\xa9\xec\x9e\x90/\xeb\xb9\x84\xeb\xb0\x80/d.py:4"
        )
        expected = (
            b"[REDACTED PATH]:1\n"
            b"[REDACTED PATH]:2\n"
            b"[REDACTED PATH]:3\n"
            b"[REDACTED PATH]:4"
        )
        baseline = module.sanitize_bytes(payload, private_roots=roots)
        self.assertEqual(baseline.payload, expected)
        self.assertEqual(baseline.summary.path_redactions, 4)

        for split in range(len(payload) + 1):
            with self.subTest(mode="two chunks", split=split):
                self.assertEqual(
                    sanitize_in_two_chunks(
                        module,
                        payload,
                        split,
                        private_roots=roots,
                    ),
                    baseline,
                )

        bytewise = module.StreamingSanitizer(private_roots=roots)
        for byte in payload:
            bytewise.feed(bytes((byte,)))
        self.assertEqual(bytewise.finish(), baseline)

        generator = random.Random(7009)
        for trial in range(32):
            sanitizer = module.StreamingSanitizer(private_roots=roots)
            cursor = 0
            while cursor < len(payload):
                chunk_size = generator.randint(1, 9)
                sanitizer.feed(payload[cursor : cursor + chunk_size])
                cursor += chunk_size
            with self.subTest(mode="seeded random", trial=trial):
                self.assertEqual(sanitizer.finish(), baseline)

    def test_explicit_root_never_leaks_from_result_or_failure(self) -> None:
        """Break caught: a declared root appears in a result repr or stable error."""

        module = sanitizer_module()
        root = "/ultra-sensitive-root"
        payload = b"/ultra-sensitive-root/file.txt"
        result = module.sanitize_bytes(payload, private_roots=(root,))

        self.assertEqual(result.payload, b"[REDACTED PATH]")
        self.assertNotIn(root, repr(result))

        sanitizer = module.StreamingSanitizer(
            private_roots=(root,),
            limits=module.SanitizerLimits(max_output_bytes=14),
        )
        sanitizer.feed(payload)
        with self.assertRaises(module.SanitizationError) as caught:
            sanitizer.finish()
        self.assertEqual(
            caught.exception.code,
            module.SanitizationErrorCode.OUTPUT_LIMIT_EXCEEDED,
        )
        self.assertNotIn(root, str(caught.exception))
        self.assertNotIn(root, repr(caught.exception))
        with self.assertRaises(module.SanitizationError) as invalid_state:
            sanitizer.finish()
        self.assertEqual(
            invalid_state.exception.code,
            module.SanitizationErrorCode.INVALID_STATE,
        )

    def test_generic_absolute_path_forms_are_redacted_as_exact_tokens(self) -> None:
        """Break caught: a supported absolute path form reaches rendered output."""

        module = sanitizer_module()
        cases = (
            ("short POSIX", b"/a", b"[REDACTED PATH]"),
            ("POSIX descendant", b"/var/log/app.log", b"[REDACTED PATH]"),
            ("Windows backslash", b"C:\\Users\\Alice\\app.py", b"[REDACTED PATH]"),
            ("Windows slash", b"d:/work/project/app.py", b"[REDACTED PATH]"),
            ("UNC backslash", b"\\\\server\\share\\folder\\app.py", b"[REDACTED PATH]"),
            ("UNC slash", b"//server/share/folder/app.py", b"[REDACTED PATH]"),
            (
                "Unicode POSIX",
                b"/\xec\x82\xac\xec\x9a\xa9\xec\x9e\x90/\xed\x94\x84\xeb\xa1\x9c\xec\xa0\x9d\xed\x8a\xb8/\xed\x8c\x8c\xec\x9d\xbc.py",
                b"[REDACTED PATH]",
            ),
        )
        for name, payload, expected in cases:
            with self.subTest(name=name):
                result = module.sanitize_bytes(payload)
                self.assertEqual(result.payload, expected)
                self.assertEqual(result.summary.path_redactions, 1)

    def test_generic_paths_cover_traceback_grep_and_absolute_diff_headers(self) -> None:
        """Break caught: context punctuation hides a path or gets consumed with it."""

        module = sanitizer_module()
        payload = (
            b'Traceback File "/Users/alice/project/app.py", line 7, in main\n'
            b"/tmp/project/app.py:12:3:matched text\n"
            b"/tmp/other.py:9: message with spaces\n"
            b"--- /old/project/app.py\n"
            b"+++ C:\\new\\project\\app.py\n"
            b"prefix=/\xec\x82\xac\xec\x9a\xa9\xec\x9e\x90/\xed\x94\x84\xeb\xa1\x9c\xec\xa0\x9d\xed\x8a\xb8/\xed\x8c\x8c\xec\x9d\xbc.py:4"
        )
        expected = (
            b'Traceback File "[REDACTED PATH]", line 7, in main\n'
            b"[REDACTED PATH]:12:3:matched text\n"
            b"[REDACTED PATH]:9: message with spaces\n"
            b"--- [REDACTED PATH]\n"
            b"+++ [REDACTED PATH]\n"
            b"prefix=[REDACTED PATH]:4"
        )

        result = module.sanitize_bytes(payload)

        self.assertEqual(result.payload, expected)
        self.assertEqual(result.summary.path_redactions, 6)

    def test_generic_path_negatives_remain_visible_with_closed_boundaries(self) -> None:
        """Break caught: a URL, root, relative path, or division is over-redacted."""

        module = sanitizer_module()
        payload = (
            b"http://example.test/a/b\n"
            b"https://example.test/private/file\n"
            b"file:///tmp/local.txt\n"
            b"ssh://host.example/var/repo\n"
            b"git+ssh://host.example/var/repo\n"
            b"/\n"
            b"//\n"
            b"C:\\\n"
            b"C:/\n"
            b"\\\\server\\share\n"
            b"//server/share\n"
            b"file.py\n"
            b"src/file.py\n"
            b"./x\n"
            b"../x\n"
            b"1/2\n"
            b"a / b\n"
            b"--- a/file.py\n"
            b"+++ b/file.py\n"
            b"/positive/path"
        )
        expected = (
            b"http://example.test/a/b\n"
            b"https://example.test/private/file\n"
            b"[REDACTED PATH]\n"
            b"ssh://host.example/var/repo\n"
            b"[REDACTED PATH]\n"
            b"/\n"
            b"//\n"
            b"C:\\\\\n"
            b"C:/\n"
            b"\\\\\\\\server\\\\share\n"
            b"//server/share\n"
            b"file.py\n"
            b"src/file.py\n"
            b"./x\n"
            b"../x\n"
            b"1/2\n"
            b"a / b\n"
            b"--- a/file.py\n"
            b"+++ b/file.py\n"
            b"[REDACTED PATH]"
        )

        result = module.sanitize_bytes(payload)

        self.assertEqual(result.payload, expected)
        self.assertEqual(result.summary.path_redactions, 3)

    def test_generic_paths_consume_invalid_and_control_splices_and_skip_markers(self) -> None:
        """Break caught: malformed-byte splicing leaks a path or markers inflate counts."""

        module = sanitizer_module()
        payload = (
            b"/private/\x00\xc2\x85\xff\x1b[31mfile.py:4\n"
            b"C\x00:\x1f\\private\\file.py:5\n"
            b"\\\x00\\server\\share\\file.py:6\n"
            b"api_key=/secret/path\n"
            b"-----BEGIN PRIVATE KEY-----\n"
            b"/private/key/material\n"
            b"-----END PRIVATE KEY-----"
        )
        expected = (
            b"[REDACTED PATH]:4\n"
            b"[REDACTED PATH]:5\n"
            b"[REDACTED PATH]:6\n"
            b"[REDACTED SECRET]\n"
            b"[REDACTED PRIVATE KEY]\n"
            b"[REDACTED PRIVATE KEY]\n"
            b"[REDACTED PRIVATE KEY]"
        )

        result = module.sanitize_bytes(payload)

        self.assertEqual(result.payload, expected)
        self.assertEqual(result.summary.ansi_sequences_stripped, 1)
        self.assertEqual(result.summary.invalid_utf8_bytes, 1)
        self.assertEqual(result.summary.escaped_control_characters, 5)
        self.assertEqual(result.summary.secret_redactions, 1)
        self.assertEqual(result.summary.private_key_redactions, 3)
        self.assertEqual(result.summary.path_redactions, 3)

    def test_generic_path_redaction_is_chunk_invariant(self) -> None:
        """Break caught: a generic absolute path split across feeds survives detection."""

        module = sanitizer_module()
        payload = (
            b"/var/project/a.py:1\r\n"
            b'Traceback File "C:\\work\\b.py", line 2\n'
            b"\\\\server\\share\\folder\\c.py:3:message\r"
            b"https://example.test/not/redacted\n"
            b"/\xec\x82\xac\xec\x9a\xa9\xec\x9e\x90/\xed\x94\x84\xeb\xa1\x9c\xec\xa0\x9d\xed\x8a\xb8/d.py:4"
        )
        expected = (
            b"[REDACTED PATH]:1\n"
            b'Traceback File "[REDACTED PATH]", line 2\n'
            b"[REDACTED PATH]:3:message\n"
            b"https://example.test/not/redacted\n"
            b"[REDACTED PATH]:4"
        )
        baseline = module.sanitize_bytes(payload)
        self.assertEqual(baseline.payload, expected)
        self.assertEqual(baseline.summary.path_redactions, 4)

        for split in range(len(payload) + 1):
            with self.subTest(mode="two chunks", split=split):
                self.assertEqual(sanitize_in_two_chunks(module, payload, split), baseline)

        bytewise = module.StreamingSanitizer()
        for byte in payload:
            bytewise.feed(bytes((byte,)))
        self.assertEqual(bytewise.finish(), baseline)

        generator = random.Random(7010)
        for trial in range(32):
            sanitizer = module.StreamingSanitizer()
            cursor = 0
            while cursor < len(payload):
                chunk_size = generator.randint(1, 10)
                sanitizer.feed(payload[cursor : cursor + chunk_size])
                cursor += chunk_size
            with self.subTest(mode="seeded random", trial=trial):
                self.assertEqual(sanitizer.finish(), baseline)


if __name__ == "__main__":
    unittest.main()
