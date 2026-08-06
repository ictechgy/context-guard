from __future__ import annotations

import importlib.util
import io
import json
import shlex
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SMOKE_PATH = ROOT / "scripts" / "release_smoke.py"


def load_smoke():
    spec = importlib.util.spec_from_file_location("release_candidate_smoke", SMOKE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("release smoke is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_package_tarball(path: Path, document: dict[str, object]) -> None:
    payload = json.dumps(document).encode("utf-8")
    with tarfile.open(path, "w:gz") as archive:
        member = tarfile.TarInfo("package/package.json")
        member.mode = 0o644
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))


def write_members(path: Path, members: list[tuple[str, bytes]]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, payload in members:
            member = tarfile.TarInfo(name)
            member.mode = 0o644
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))


class ReleaseCandidateSmokeTests(unittest.TestCase):
    def test_candidate_tarball_cap_is_exactly_fifty_mib(self) -> None:
        """Break caught: smoke accepts a candidate the publisher refuses."""

        smoke = load_smoke()
        self.assertEqual(smoke.MAX_CANDIDATE_TARBALL_BYTES, 50 * 1024 * 1024)
        self.assertEqual(
            smoke.MAX_CANDIDATE_DECLARED_UNCOMPRESSED_BYTES,
            128 * 1024 * 1024,
        )
        self.assertEqual(
            smoke.MAX_CANDIDATE_DECOMPRESSED_ARCHIVE_BYTES,
            128 * 1024 * 1024,
        )
        self.assertEqual(smoke.MAX_CANDIDATE_ARCHIVE_MEMBERS, 4096)
        self.assertEqual(smoke.MAX_CANDIDATE_DECOMPRESSED_READ_BYTES, 64 * 1024)
        with tempfile.TemporaryDirectory() as temporary_directory:
            at_limit = Path(temporary_directory) / "at-limit.tgz"
            over_limit = Path(temporary_directory) / "over-limit.tgz"
            with at_limit.open("wb") as stream:
                stream.truncate(smoke.MAX_CANDIDATE_TARBALL_BYTES)
            with over_limit.open("wb") as stream:
                stream.truncate(smoke.MAX_CANDIDATE_TARBALL_BYTES + 1)
            with self.assertRaisesRegex(SystemExit, "candidate tarball is invalid"):
                smoke._candidate_package_document(at_limit)
            with self.assertRaisesRegex(
                SystemExit, "candidate tarball must be a bounded regular file"
            ):
                smoke._candidate_package_document(over_limit)

    def test_candidate_archive_rejects_too_many_streamed_members(self) -> None:
        """Break caught: archive.getmembers materializes an unbounded member list."""

        smoke = load_smoke()
        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate = Path(temporary_directory) / "many.tgz"
            write_members(
                candidate,
                [
                    ("package/package.json", b'{"name":"x"}'),
                    ("package/a", b""),
                    ("package/b", b""),
                    ("package/c", b""),
                ],
            )
            with (
                mock.patch.object(smoke, "MAX_CANDIDATE_ARCHIVE_MEMBERS", 3),
                self.assertRaisesRegex(SystemExit, "archive limits"),
            ):
                smoke._candidate_package_document(candidate)

    def test_candidate_archive_rejects_excess_declared_uncompressed_bytes(self) -> None:
        """Break caught: a small gzip expands beyond the declared-byte budget."""

        smoke = load_smoke()
        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate = Path(temporary_directory) / "large.tgz"
            write_members(
                candidate,
                [
                    ("package/package.json", b'{"name":"x"}'),
                    ("package/padding", b"x" * 64),
                ],
            )
            with (
                mock.patch.object(
                    smoke, "MAX_CANDIDATE_DECLARED_UNCOMPRESSED_BYTES", 32
                ),
                self.assertRaisesRegex(SystemExit, "archive limits"),
            ):
                smoke._candidate_package_document(candidate)

    def test_candidate_archive_counts_hidden_pax_extension_payload(self) -> None:
        """Break caught: tar PAX records bypass yielded-member byte accounting."""

        smoke = load_smoke()
        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate = Path(temporary_directory) / "pax.tgz"
            baseline = Path(temporary_directory) / "baseline.tgz"
            payload = b'{"name":"x"}'
            write_members(baseline, [("package/package.json", payload)])
            with tarfile.open(candidate, "w:gz", format=tarfile.PAX_FORMAT) as archive:
                member = tarfile.TarInfo("package/package.json")
                member.mode = 0o644
                member.size = len(payload)
                member.pax_headers = {"comment": "x" * (20 * 1024)}
                archive.addfile(member, io.BytesIO(payload))
            with mock.patch.object(
                smoke, "MAX_CANDIDATE_DECOMPRESSED_ARCHIVE_BYTES", 15 * 1024
            ):
                _, document = smoke._candidate_package_document(baseline)
                self.assertEqual(document, {"name": "x"})
                with self.assertRaisesRegex(SystemExit, "archive limits"):
                    smoke._candidate_package_document(candidate)

    def test_candidate_package_json_read_uses_max_plus_one_cap(self) -> None:
        """Break caught: json.load reads an oversized manifest without a byte cap."""

        smoke = load_smoke()
        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate = Path(temporary_directory) / "manifest.tgz"
            write_members(
                candidate,
                [("package/package.json", b'{"padding":"' + b"x" * 64 + b'"}')],
            )
            with (
                mock.patch.object(smoke, "MAX_CANDIDATE_PACKAGE_JSON_BYTES", 32),
                self.assertRaisesRegex(SystemExit, "manifest.*oversized"),
            ):
                smoke._candidate_package_document(candidate)

    def test_cli_accepts_only_an_explicit_root_and_receipt_candidate_pair(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SMOKE_PATH), "--help"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--npm-root-tarball", result.stdout)
        self.assertIn("--npm-receipt-tarball", result.stdout)

    def test_candidate_pair_requires_matching_exact_dependency(self) -> None:
        smoke = load_smoke()
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            receipt = root / "receipt.tgz"
            package = root / "root.tgz"
            write_package_tarball(
                receipt,
                {"name": "@ictechgy/context-guard-receipt", "version": "0.2.0"},
            )
            write_package_tarball(
                package,
                {
                    "name": "@ictechgy/context-guard",
                    "version": "0.5.0",
                    "dependencies": {"@ictechgy/context-guard-receipt": "0.2.0"},
                },
            )

            resolved_root, resolved_receipt = smoke.validate_candidate_tarball_pair(package, receipt)
            self.assertEqual(resolved_root, package.resolve())
            self.assertEqual(resolved_receipt, receipt.resolve())

            write_package_tarball(
                package,
                {
                    "name": "@ictechgy/context-guard",
                    "version": "0.5.0",
                    "dependencies": {"@ictechgy/context-guard-receipt": "^0.2.0"},
                },
            )
            with self.assertRaisesRegex(SystemExit, "exact Receipt dependency"):
                smoke.validate_candidate_tarball_pair(package, receipt)

    def test_installed_candidate_must_discover_the_real_receipt_adapter(self) -> None:
        smoke = load_smoke()
        with tempfile.TemporaryDirectory() as temporary_directory:
            project = Path(temporary_directory)
            context_guard = project / "node_modules" / ".bin" / "context-guard"
            context_guard.parent.mkdir(parents=True)
            context_guard.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            context_guard.chmod(0o755)
            policy = (
                project
                / "node_modules"
                / "@ictechgy"
                / "context-guard"
                / "plugins"
                / "context-guard"
                / "bin"
                / "bash_reference_policy.py"
            )
            policy.parent.mkdir(parents=True)
            rewrite_hook = policy.parent / "context-guard-rewrite-bash"
            trim_helper = policy.parent / "context-guard-trim-output"
            for helper in (rewrite_hook, trim_helper):
                helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                helper.chmod(0o755)
            expected_rewrite_hook = str(rewrite_hook.resolve())
            expected_trim_helper = str(trim_helper.resolve())
            policy.write_text(
                "from pathlib import Path\n"
                "class Result:\n"
                "    status = 'success'\n"
                "    actionable = True\n"
                "    reference = 'cgr1p_' + ('a' * 43)\n"
                "class Broker:\n"
                "    def __init__(self, marker): self.marker = marker\n"
                "    def commit(self): self.marker.write_text('committed'); return Result()\n"
                "    def abort(self): self.marker.write_text('aborted')\n"
                "    def close(self): pass\n"
                "class Adapter:\n"
                "    def __init__(self, root): self.root = root\n"
                "    def start_broker(self, capture_fd, **kwargs):\n"
                "        return Broker(Path(self.root) / 'broker-started'), 'receipt_broker_ready'\n"
                "def discover_adapter(root):\n"
                "    return (Adapter(root), 'receipt_adapter_available')\n",
                encoding="utf-8",
            )
            payload = smoke.REFERENCE_SMOKE_PAYLOAD
            pi_offset = payload.index("\u03c0".encode("utf-8"))
            self.assertEqual(pi_offset + 1, smoke.REFERENCE_PAGE_MAX_BYTES)
            launch_calls: list[list[str]] = []
            hook_calls: list[list[str]] = []

            def mocked_reference_command(
                argv: list[str],
                *,
                cwd: Path,
                env: dict[str, str],
                timeout: float,
                input_text: str | None = None,
                max_output_bytes: int | None = None,
            ) -> object:
                del cwd, timeout, max_output_bytes
                launch_calls.append(argv)
                if argv[0] == expected_rewrite_hook:
                    hook_calls.append(argv)
                    self.assertEqual(argv[1:], ["--bash-reference-v1"])
                    self.assertEqual(
                        json.loads(input_text or ""),
                        {
                            "tool_input": {
                                "command": "./node_modules/.bin/context-guard reference "
                                + "cgr1p_"
                                + ("a" * 43)
                            }
                        },
                    )
                    return smoke.BoundedCommandResult(
                        proc=subprocess.CompletedProcess(
                            argv,
                            0,
                            json.dumps(
                                {
                                    "hookSpecificOutput": {
                                        "hookEventName": "PreToolUse",
                                        "updatedInput": {
                                            "command": shlex.join(
                                                [
                                                    expected_trim_helper,
                                                    "--expand-bash-reference",
                                                    "cgr1p_" + ("a" * 43),
                                                ]
                                            )
                                        },
                                    }
                                }
                            ),
                            "",
                        ),
                        timed_out=False,
                        output_truncated=False,
                    )
                self.assertEqual(argv[0], str(context_guard))
                self.assertEqual(argv[1:3], ["reference", "cgr1p_" + ("a" * 43)])
                self.assertTrue(env["PATH"].startswith("/fake-path-bin"))
                offset = 0
                if len(argv) == 5:
                    self.assertEqual(argv[3], "--offset")
                    offset = int(argv[4])
                page = payload[offset : offset + smoke.REFERENCE_PAGE_MAX_BYTES]
                while page:
                    try:
                        page.decode("utf-8", errors="strict")
                        break
                    except UnicodeDecodeError:
                        page = page[:-1]
                next_offset = offset + len(page)
                stderr = (
                    f"context-guard: more bytes available; continue with --offset {next_offset}\n"
                    if next_offset < len(payload)
                    else f"context-guard: reference complete at offset {next_offset}\n"
                )
                return smoke.BoundedCommandResult(
                    proc=subprocess.CompletedProcess(argv, 0, page.decode("utf-8"), stderr),
                    timed_out=False,
                    output_truncated=False,
                )

            with mock.patch.object(smoke, "run_bounded_command", side_effect=mocked_reference_command):
                smoke.verify_installed_reference_adapter(
                    package_root=project / "node_modules" / "@ictechgy" / "context-guard",
                    project_root=project,
                    context_guard=context_guard,
                    env={"PATH": "/fake-path-bin:/trusted"},
                    timeout=1.0,
                )
            self.assertEqual(
                (project / "broker-started").read_text(encoding="utf-8"),
                "committed",
            )
            self.assertGreaterEqual(len(launch_calls), 3)
            self.assertEqual(len(hook_calls), 1)
            self.assertEqual(hook_calls[0][0], expected_rewrite_hook)
            reference_calls = [call for call in launch_calls if call[0] == str(context_guard)]
            self.assertEqual(
                reference_calls[0][1:],
                ["reference", "cgr1p_" + ("a" * 43)],
            )
            self.assertNotIn("PATH-SHADOWED-CONTEXT-GUARD", "\n".join(" ".join(call) for call in launch_calls))
            policy.write_text(
                "def discover_adapter(root):\n"
                "    return (None, 'receipt_package_manifest_pin_unavailable')\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(SystemExit, "reference adapter discovery"):
                smoke.verify_installed_reference_adapter(
                    package_root=project / "node_modules" / "@ictechgy" / "context-guard",
                    project_root=project,
                    context_guard=context_guard,
                    env={"PATH": "/fake-path-bin:/trusted"},
                    timeout=1.0,
                )


if __name__ == "__main__":
    unittest.main()
