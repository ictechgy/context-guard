from __future__ import annotations

import gzip
import importlib.util
import hashlib
import io
import shutil
import stat
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_CHECK_PATH = PACKAGE_ROOT / "dev" / "package_check.py"


def load_package_check():
    spec = importlib.util.spec_from_file_location("g013_package_check", PACKAGE_CHECK_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("package check module is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PACKAGE_CHECK = load_package_check()


class G013PackageAuditTests(unittest.TestCase):
    def write_archive(
        self,
        entries: list[tuple[str, bytes, int, bytes | None]],
        *,
        pax_path: str | None = None,
    ) -> Path:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        archive_path = Path(temporary_directory.name) / "receipt.tgz"
        with tarfile.open(archive_path, "w:gz") as archive:
            for name, member_type, mode, content in entries:
                member = tarfile.TarInfo(name)
                member.type = member_type
                member.mode = mode
                if name == pax_path:
                    member.pax_headers = {"comment": "synthetic-private-metadata"}
                if content is not None:
                    payload = content or b"{}\n"
                    member.size = len(payload)
                    archive.addfile(member, io.BytesIO(payload))
                else:
                    member.linkname = "package/README.md"
                    archive.addfile(member)
        return archive_path

    def valid_entries(self) -> list[tuple[str, bytes, int, bytes | None]]:
        return [
            (
                f"package/{path}",
                tarfile.REGTYPE,
                int(PACKAGE_CHECK.EXPECTED_MODES[path], 8),
                b"{}\n",
            )
            for path in sorted(PACKAGE_CHECK.EXPECTED_PACKAGE_PATHS)
        ]

    def expected_hashes(
        self, entries: list[tuple[str, bytes, int, bytes | None]]
    ) -> dict[str, str]:
        expected: dict[str, str] = {}
        for name, _member_type, _mode, content in entries:
            prefix = "package/"
            relative = name[len(prefix) :] if name.startswith(prefix) else ""
            if relative in PACKAGE_CHECK.EXPECTED_PACKAGE_PATHS and content is not None:
                expected[relative] = hashlib.sha256(content).hexdigest()
        return expected

    def validate_entries(
        self,
        entries: list[tuple[str, bytes, int, bytes | None]],
        *,
        expected_entries: list[tuple[str, bytes, int, bytes | None]] | None = None,
        pax_path: str | None = None,
    ) -> None:
        expected_source = entries if expected_entries is None else expected_entries
        PACKAGE_CHECK.validate_tarball(
            self.write_archive(entries, pax_path=pax_path),
            expected_hashes=self.expected_hashes(expected_source),
        )

    def test_archive_audit_accepts_the_closed_regular_file_set(self) -> None:
        """Break caught: the audit rejects npm's normalized regular archive layout."""

        self.validate_entries(self.valid_entries())

    def test_archive_audit_rejects_links_and_special_members(self) -> None:
        """Break caught: a link, FIFO, or device member is treated as package data."""

        for member_type in (
            tarfile.SYMTYPE,
            tarfile.LNKTYPE,
            tarfile.FIFOTYPE,
            tarfile.CHRTYPE,
            tarfile.CONTTYPE,
            tarfile.GNUTYPE_SPARSE,
        ):
            with self.subTest(member_type=member_type):
                entries = self.valid_entries()
                entries[0] = (entries[0][0], member_type, entries[0][2], entries[0][3])
                with self.assertRaisesRegex(PACKAGE_CHECK.PackageCheckError, "archive member type"):
                    self.validate_entries(entries)

    def test_archive_audit_rejects_unsafe_or_duplicate_member_names(self) -> None:
        """Break caught: path traversal, private/generated names, or duplicates enter the tarball."""

        unsafe_names = (
            "package/../README.md",
            "/package/README.md",
            "package/python//context_guard_receipt/cli.py",
            "package/.env",
            "package/python/context_guard_receipt/__pycache__/cli.pyc",
            "package/credentials.txt",
            "package/private/README.md",
        )
        for unsafe_name in unsafe_names:
            with self.subTest(member_name=unsafe_name):
                entries = self.valid_entries()
                entries.append((unsafe_name, tarfile.REGTYPE, 0o644, b"{}\n"))
                with self.assertRaisesRegex(PACKAGE_CHECK.PackageCheckError, "archive member"):
                    self.validate_entries(entries)

        entries = self.valid_entries()
        entries.append(entries[0])
        with self.assertRaisesRegex(PACKAGE_CHECK.PackageCheckError, "duplicate archive member"):
            self.validate_entries(entries)

    def test_archive_audit_scans_only_allowlisted_regular_content_for_secret_markers(self) -> None:
        """Break caught: a secret marker in an allowed packaged file is not rejected."""

        entries = self.valid_entries()
        entries[0] = (entries[0][0], tarfile.REGTYPE, entries[0][2], b"NPM_TOKEN=synthetic-test-value\n")
        with self.assertRaisesRegex(PACKAGE_CHECK.PackageCheckError, "secret-like content"):
            self.validate_entries(entries)

    def test_archive_audit_binds_every_payload_to_the_frozen_source_snapshot(self) -> None:
        expected_entries = self.valid_entries()
        changed_entries = self.valid_entries()
        changed_entries[0] = (
            changed_entries[0][0],
            tarfile.REGTYPE,
            changed_entries[0][2],
            b"marker-free concurrent replacement\n",
        )
        with self.assertRaisesRegex(PACKAGE_CHECK.PackageCheckError, "content hash"):
            self.validate_entries(changed_entries, expected_entries=expected_entries)

    def test_archive_audit_rejects_extended_metadata_and_bounded_content_overflow(self) -> None:
        entries = self.valid_entries()
        with self.assertRaisesRegex(PACKAGE_CHECK.PackageCheckError, "metadata"):
            self.validate_entries(entries, pax_path=entries[0][0])

        readme = next(entry for entry in entries if entry[0] == "package/README.md")
        gnu_longname = [
            (
                "././@LongLink",
                tarfile.GNUTYPE_LONGNAME,
                0o644,
                b"package/README.md\x00",
            ),
            ("placeholder", tarfile.REGTYPE, readme[2], readme[3]),
            *(entry for entry in entries if entry is not readme),
        ]
        with self.assertRaisesRegex(PACKAGE_CHECK.PackageCheckError, "metadata"):
            self.validate_entries(gnu_longname, expected_entries=entries)

        padded_header = self.write_archive(entries)
        decompressed = bytearray(gzip.decompress(padded_header.read_bytes()))
        readme_name = b"package/README.md"
        header_offset = next(
            offset
            for offset in range(0, len(decompressed), tarfile.BLOCKSIZE)
            if decompressed[offset : offset + len(readme_name)] == readme_name
        )
        marker_offset = header_offset + len(readme_name) + 1
        hidden_marker = b"NPM_TOKEN=synthetic-header"
        decompressed[marker_offset : marker_offset + len(hidden_marker)] = hidden_marker
        checksum_offset = header_offset + 148
        decompressed[checksum_offset : checksum_offset + 8] = b"        "
        checksum = sum(decompressed[header_offset : header_offset + tarfile.BLOCKSIZE])
        decompressed[checksum_offset : checksum_offset + 8] = (
            f"{checksum:06o}\x00 ".encode("ascii")
        )
        padded_header.write_bytes(gzip.compress(bytes(decompressed), mtime=0))
        with self.assertRaisesRegex(PACKAGE_CHECK.PackageCheckError, "secret-like content"):
            PACKAGE_CHECK.validate_tarball(
                padded_header,
                expected_hashes=self.expected_hashes(entries),
            )

        oversized = self.valid_entries()
        oversized[0] = (
            oversized[0][0],
            tarfile.REGTYPE,
            oversized[0][2],
            b"x" * (PACKAGE_CHECK.MAX_CONTENT_SCAN_BYTES + 1),
        )
        with self.assertRaisesRegex(PACKAGE_CHECK.PackageCheckError, "content audit limit"):
            self.validate_entries(oversized)

        aggregate = self.valid_entries()
        bounded_payload = b"x" * (PACKAGE_CHECK.MAX_CONTENT_SCAN_BYTES - 1)
        overflowing_member_count = (
            PACKAGE_CHECK.MAX_TOTAL_CONTENT_SCAN_BYTES // len(bounded_payload)
        ) + 1
        for index in range(overflowing_member_count):
            name, member_type, mode, _content = aggregate[index]
            aggregate[index] = (name, member_type, mode, bounded_payload)
        with self.assertRaisesRegex(PACKAGE_CHECK.PackageCheckError, "total audit limit"):
            self.validate_entries(aggregate)

    def test_archive_audit_rejects_nonportable_archive_modes(self) -> None:
        """Break caught: executable data or a non-executable command ships in the archive."""

        data_entries = self.valid_entries()
        data_index = next(index for index, entry in enumerate(data_entries) if entry[0] == "package/README.md")
        data_entries[data_index] = ("package/README.md", tarfile.REGTYPE, 0o755, b"{}\n")
        with self.assertRaisesRegex(PACKAGE_CHECK.PackageCheckError, "archive member mode"):
            self.validate_entries(data_entries)

        command_entries = self.valid_entries()
        command_index = next(index for index, entry in enumerate(command_entries) if entry[0] == "package/bin/context-guard-receipt.cjs")
        command_entries[command_index] = ("package/bin/context-guard-receipt.cjs", tarfile.REGTYPE, 0o644, b"{}\n")
        with self.assertRaisesRegex(PACKAGE_CHECK.PackageCheckError, "archive member mode"):
            self.validate_entries(command_entries)

        with self.assertRaisesRegex(PACKAGE_CHECK.PackageCheckError, "archive member mode"):
            PACKAGE_CHECK.validate_archive_mode("README.md", 0o100644)

    def test_source_modes_accept_clean_umasks_but_reject_unsafe_roles(self) -> None:
        """Break caught: clean umask 077 sources fail, or unsafe executable/data modes pass."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            data_file = root / "README.md"
            command_file = root / "command.cjs"
            data_file.write_text("data\n", encoding="utf-8")
            command_file.write_text("command\n", encoding="utf-8")

            for data_mode, command_mode in ((0o644, 0o755), (0o600, 0o700)):
                data_file.chmod(data_mode)
                command_file.chmod(command_mode)
                self.assertEqual(PACKAGE_CHECK.portable_source_mode(data_file, "0644"), f"{data_mode:04o}")
                self.assertEqual(PACKAGE_CHECK.portable_source_mode(command_file, "0755"), f"{command_mode:04o}")

            data_file.chmod(0o755)
            with self.assertRaisesRegex(PACKAGE_CHECK.PackageCheckError, "source mode"):
                PACKAGE_CHECK.portable_source_mode(data_file, "0644")
            command_file.chmod(0o600)
            with self.assertRaisesRegex(PACKAGE_CHECK.PackageCheckError, "source mode"):
                PACKAGE_CHECK.portable_source_mode(command_file, "0755")

    def test_restricted_source_modes_pack_through_a_normalized_real_staging_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            restricted_root = Path(temporary_directory) / "restricted-package"
            for relative_path, archive_mode in PACKAGE_CHECK.EXPECTED_MODES.items():
                source = PACKAGE_ROOT / relative_path
                destination = restricted_root / relative_path
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
                destination.chmod(0o700 if archive_mode == "0755" else 0o600)

            snapshot = PACKAGE_CHECK.validate_source(package_root=restricted_root)
            PACKAGE_CHECK.validate_npm_tarball(snapshot)

    def test_pack_subprocess_is_stopped_on_output_overflow_or_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cwd = Path(temporary_directory)
            with self.assertRaisesRegex(PACKAGE_CHECK.PackageCheckError, "output"):
                PACKAGE_CHECK.run_bounded_process(
                    [
                        sys.executable,
                        "-c",
                        "import sys; sys.stdout.buffer.write(b'x' * 65)",
                    ],
                    cwd=cwd,
                    max_output_bytes=64,
                    timeout_seconds=5,
                )
            with self.assertRaisesRegex(PACKAGE_CHECK.PackageCheckError, "timed out"):
                PACKAGE_CHECK.run_bounded_process(
                    [sys.executable, "-c", "import time; time.sleep(1)"],
                    cwd=cwd,
                    max_output_bytes=64,
                    timeout_seconds=0.05,
                )


if __name__ == "__main__":
    unittest.main()
