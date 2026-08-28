"""Build and audit a normalized package tarball without lifecycle scripts."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Mapping


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PACKAGE_PATHS = {
    "LICENSE",
    "NOTICE",
    "README.md",
    "bin/context-guard-receipt.cjs",
    "bin/context-guard-receipt-mcp.cjs",
    "bin/launcher.cjs",
    "package-files.json",
    "package.json",
    "python/context_guard_receipt/__init__.py",
    "python/context_guard_receipt/assembly.py",
    "python/context_guard_receipt/blueprint.py",
    "python/context_guard_receipt/bootstrap.py",
    "python/context_guard_receipt/canonical.py",
    "python/context_guard_receipt/cli.py",
    "python/context_guard_receipt/cli_io.py",
    "python/context_guard_receipt/contracts.py",
    "python/context_guard_receipt/cost_optimization.py",
    "python/context_guard_receipt/diagnostic_ledger.py",
    "python/context_guard_receipt/diagnostics.py",
    "python/context_guard_receipt/execution_twin.py",
    "python/context_guard_receipt/evidence_pack.py",
    "python/context_guard_receipt/expansion.py",
    "python/context_guard_receipt/external_approval.py",
    "python/context_guard_receipt/external_approval_v2.py",
    "python/context_guard_receipt/identity.py",
    "python/context_guard_receipt/mcp.py",
    "python/context_guard_receipt/merged_capture.py",
    "python/context_guard_receipt/phase_evaluation.py",
    "python/context_guard_receipt/protection.py",
    "python/context_guard_receipt/reference_expiry.py",
    "python/context_guard_receipt/receipts.py",
    "python/context_guard_receipt/router.py",
    "python/context_guard_receipt/runner.py",
    "python/context_guard_receipt/sanitizer.py",
    "python/context_guard_receipt/store.py",
    "python/context_guard_receipt/tool_schemas.py",
    "schemas/assembly-receipt.schema.json",
    "schemas/blueprint-descriptor.schema.json",
    "schemas/capability-record.schema.json",
    "schemas/command-capture-receipt.schema.json",
    "schemas/diagnostic-ledger-entry.schema.json",
    "schemas/diagnostic-ledger-inspection.schema.json",
    "schemas/diagnostic-ledger-metadata.schema.json",
    "schemas/diagnostics-report.schema.json",
    "schemas/diagnostics-request.schema.json",
    "schemas/evidence-boundary.schema.json",
    "schemas/evidence-descriptor.schema.json",
    "schemas/evidence-pack.schema.json",
    "schemas/evidence-reference.schema.json",
    "schemas/external-approval.schema.json",
    "schemas/external-approval-v2.schema.json",
    "schemas/expansion-envelope.schema.json",
    "schemas/expansion-refusal.schema.json",
    "schemas/phase-evaluation-p2.schema.json",
    "schemas/phase-evaluation-p3.schema.json",
    "schemas/phase-evaluation-p4.schema.json",
    "schemas/phase-evaluation-p5.schema.json",
    "schemas/phase-evaluation-p6.schema.json",
    "schemas/phase-evaluation-result.schema.json",
    "schemas/protection-decision.schema.json",
    "schemas/reference-expiry-inspection.schema.json",
    "schemas/reference-expiry-metadata.schema.json",
    "schemas/reference-expiry-record.schema.json",
    "schemas/reference-expiry-request.schema.json",
    "schemas/reference-expiry-result.schema.json",
    "schemas/shadow-firewall-report.schema.json",
    "schemas/source-identity.schema.json",
    "schemas/store-commit.schema.json",
    "schemas/store-metadata.schema.json",
    "schemas/twin-event.schema.json",
    "schemas/twin-metadata.schema.json",
    "schemas/twin-request.schema.json",
    "schemas/twin-result.schema.json",
    "schemas/twin-snapshot.schema.json",
    "schemas/typed-blueprint.schema.json",
    "schemas/tool-schema-bundle.schema.json",
    "schemas/tool-schema-catalog-reference.schema.json",
    "schemas/tool-schema-descriptor.schema.json",
    "schemas/tool-schema-expansion-envelope.schema.json",
    "schemas/tool-schema-expansion-refusal.schema.json",
    "schemas/tool-schema-expansion-request.schema.json",
    "schemas/tool-schema-receipt.schema.json",
    "schemas/tool-schema-reference.schema.json",
}
EXPECTED_MODES = {
    path: "0755" if path.startswith("bin/context-guard-receipt") else "0644"
    for path in EXPECTED_PACKAGE_PATHS
}
FORBIDDEN_CONTENT_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"ANTHROPIC_API_KEY=",
    b"AWS_SECRET_ACCESS_KEY=",
    b"NPM_TOKEN=",
    b"OPENAI_API_KEY=",
    b"_authToken=",
)
FORBIDDEN_ARCHIVE_PARTS = frozenset(
    {
        ".env",
        ".git",
        ".npmrc",
        ".pypirc",
        "__pycache__",
        "auth.json",
        "cache",
        "node_modules",
        "settings.json",
        "state",
    }
)
SECRET_LIKE_ARCHIVE_NAME_TOKENS = (
    "credential",
    "password",
    "private",
    "secret",
    "token",
)
SECRET_LIKE_ARCHIVE_NAME_SUFFIXES = (".key", ".pem", ".p12", ".pfx")
MAX_CONTENT_SCAN_BYTES = 1024 * 1024
MAX_TOTAL_CONTENT_SCAN_BYTES = 8 * 1024 * 1024
MAX_TARBALL_BYTES = 4 * 1024 * 1024
MAX_DECOMPRESSED_TAR_BYTES = 16 * 1024 * 1024
MAX_NPM_OUTPUT_CHARS = 64 * 1024
NPM_TIMEOUT_SECONDS = 60


class PackageCheckError(RuntimeError):
    """Raised when a distribution invariant is violated."""


def regular_mode(path: Path) -> str:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise PackageCheckError("package file is unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise PackageCheckError("non-regular package file")
    return f"{stat.S_IMODE(metadata.st_mode):04o}"


def portable_source_mode(path: Path, expected_archive_mode: str) -> str:
    """Return a safe source mode that npm can normalize for the archive."""

    observed_mode = regular_mode(path)
    allowed_modes = {
        "0644": {"0600", "0640", "0644"},
        "0755": {"0700", "0750", "0755"},
    }.get(expected_archive_mode)
    if allowed_modes is None or observed_mode not in allowed_modes:
        raise PackageCheckError("source mode is not portable for its package role")
    return observed_mode


def bounded_regular_content(
    path: Path, *, subject: str, expected_archive_mode: str
) -> bytes:
    """Freeze one no-follow regular source file within the audit budget."""

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOCTTY", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise PackageCheckError(f"{subject} is not a regular file")
        observed_mode = f"{stat.S_IMODE(before.st_mode):04o}"
        allowed_modes = {
            "0644": {"0600", "0640", "0644"},
            "0755": {"0700", "0750", "0755"},
        }.get(expected_archive_mode)
        if allowed_modes is None or observed_mode not in allowed_modes:
            raise PackageCheckError(f"{subject} mode is not portable")
        if before.st_size > MAX_CONTENT_SCAN_BYTES:
            raise PackageCheckError(f"{subject} exceeds the content audit limit")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, MAX_CONTENT_SCAN_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_CONTENT_SCAN_BYTES:
                raise PackageCheckError(f"{subject} exceeds the content audit limit")
        after = os.fstat(descriptor)
    except OSError as exc:
        raise PackageCheckError(f"{subject} is unreadable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise PackageCheckError(f"{subject} changed during the audit")
    content = b"".join(chunks)
    if len(content) != before.st_size:
        raise PackageCheckError(f"{subject} changed during the audit")
    return content


def is_forbidden_archive_path(path: PurePosixPath) -> bool:
    parts = path.parts
    if any(part in FORBIDDEN_ARCHIVE_PARTS for part in parts):
        return True
    filename = path.name.lower()
    return (
        filename.endswith((".pyc", ".pyo"))
        or filename.endswith(SECRET_LIKE_ARCHIVE_NAME_SUFFIXES)
        or any(
            token in part.lower()
            for part in parts
            for token in SECRET_LIKE_ARCHIVE_NAME_TOKENS
        )
    )


def validated_archive_path(member_name: str) -> str:
    """Return an allowlisted relative path for one normalized npm tar member."""

    path = PurePosixPath(member_name)
    if (
        not member_name
        or path.is_absolute()
        or path.parts[:1] != ("package",)
        or len(path.parts) < 2
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise PackageCheckError("archive member path is unsafe")
    relative = PurePosixPath(*path.parts[1:])
    if member_name != f"package/{relative.as_posix()}":
        raise PackageCheckError("archive member path is not normalized")
    if is_forbidden_archive_path(relative):
        raise PackageCheckError("archive member name is private, generated, or secret-like")
    relative_text = relative.as_posix()
    if relative_text not in EXPECTED_PACKAGE_PATHS:
        raise PackageCheckError("archive member is not in the package allowlist")
    return relative_text


def validate_archive_mode(relative_path: str, observed_mode: int) -> str:
    expected_mode = int(EXPECTED_MODES[relative_path], 8)
    if observed_mode != expected_mode:
        raise PackageCheckError("archive member mode is not portable")
    return f"{observed_mode:04o}"


def archive_member_content(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    """Read a validated archive member without unbounded secret-content scanning."""

    if member.size > MAX_CONTENT_SCAN_BYTES:
        raise PackageCheckError("archive member exceeds the content audit limit")
    extracted = archive.extractfile(member)
    if extracted is None:
        raise PackageCheckError("archive member content is unreadable")
    with extracted:
        content = extracted.read(MAX_CONTENT_SCAN_BYTES + 1)
    if len(content) != member.size or len(content) > MAX_CONTENT_SCAN_BYTES:
        raise PackageCheckError("archive member content is unreadable")
    return content


def bounded_tarball_bytes(tarball: Path) -> bytes:
    descriptor = -1
    try:
        metadata = tarball.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_TARBALL_BYTES:
            raise PackageCheckError("npm tarball type or size is unsafe")
        descriptor = os.open(
            tarball,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOCTTY", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size != metadata.st_size
            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
        ):
            raise PackageCheckError("npm tarball changed before the audit")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, MAX_TARBALL_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_TARBALL_BYTES:
                raise PackageCheckError("npm tarball exceeds the audit limit")
        after = os.fstat(descriptor)
    except OSError as exc:
        raise PackageCheckError("npm tarball is unreadable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        opened.st_dev,
        opened.st_ino,
        opened.st_size,
        opened.st_mtime_ns,
        opened.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise PackageCheckError("npm tarball changed during the audit")
    content = b"".join(chunks)
    if len(content) != opened.st_size:
        raise PackageCheckError("npm tarball changed during the audit")
    return content


def decompress_bounded_tarball(raw_tarball: bytes) -> bytes:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw_tarball), mode="rb") as compressed:
            content = compressed.read(MAX_DECOMPRESSED_TAR_BYTES + 1)
    except (EOFError, OSError) as exc:
        raise PackageCheckError("npm tarball compression is invalid") from exc
    if len(content) > MAX_DECOMPRESSED_TAR_BYTES:
        raise PackageCheckError("npm tarball expands beyond the audit limit")
    return content


def validate_tarball(tarball: Path, *, expected_hashes: Mapping[str, str]) -> None:
    """Audit the regular, normalized, closed file set in an actual npm tarball."""

    if set(expected_hashes) != EXPECTED_PACKAGE_PATHS:
        raise PackageCheckError("frozen source snapshot is not the closed package set")
    raw_tarball = bounded_tarball_bytes(tarball)
    decompressed = decompress_bounded_tarball(raw_tarball)
    try:
        with tarfile.open(fileobj=io.BytesIO(decompressed), mode="r:") as archive:
            if archive.pax_headers:
                raise PackageCheckError("archive contains extended metadata")
            actual: dict[str, str] = {}
            total_content_bytes = 0
            for member_count, member in enumerate(archive, start=1):
                if member.type != tarfile.REGTYPE:
                    raise PackageCheckError("archive member type is not a regular file")
                relative_path = validated_archive_path(member.name)
                if relative_path in actual:
                    raise PackageCheckError("duplicate archive member")
                if member_count > len(EXPECTED_PACKAGE_PATHS):
                    raise PackageCheckError("archive member count exceeds the closed package set")
                if (
                    member.uid != 0
                    or member.gid != 0
                    or member.uname
                    or member.gname
                    or member.linkname
                    or member.pax_headers
                    or member.sparse is not None
                    or member.offset_data != member.offset + tarfile.BLOCKSIZE
                ):
                    raise PackageCheckError("archive contains extended metadata")
                actual[relative_path] = validate_archive_mode(relative_path, member.mode)
                total_content_bytes += member.size
                if total_content_bytes > MAX_TOTAL_CONTENT_SCAN_BYTES:
                    raise PackageCheckError("archive content exceeds the total audit limit")
                content = archive_member_content(archive, member)
                if any(marker in content for marker in FORBIDDEN_CONTENT_MARKERS):
                    raise PackageCheckError("secret-like content detected in archive")
                if hashlib.sha256(content).hexdigest() != expected_hashes[relative_path]:
                    raise PackageCheckError("archive member content hash drifted")
            trailing = decompressed[archive.offset :]
            if len(trailing) < 1024 or any(trailing):
                raise PackageCheckError("archive has non-canonical trailing data")
    except (OSError, tarfile.TarError) as exc:
        raise PackageCheckError("npm tarball is unreadable") from exc
    if set(actual) != EXPECTED_PACKAGE_PATHS:
        raise PackageCheckError("npm tarball file set drifted")
    if any(
        marker in archive_bytes
        for archive_bytes in (raw_tarball, decompressed)
        for marker in FORBIDDEN_CONTENT_MARKERS
    ):
        raise PackageCheckError("secret-like content detected in archive metadata")


def load_manifest(raw_manifest: bytes) -> dict[str, object]:
    try:
        manifest = json.loads(raw_manifest)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackageCheckError("package-files manifest is unreadable") from exc
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"files", "schema_version"}
        or manifest["schema_version"] != "contextguard-receipt-package-files/v1"
    ):
        raise PackageCheckError("package-files manifest shape is invalid")
    return manifest


def launcher_payload_digests(launcher_bytes: bytes) -> dict[str, str]:
    """Parse the launcher's closed embedded payload trust table."""

    try:
        source = launcher_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PackageCheckError("launcher source is not UTF-8") from exc
    marker = "const TRUSTED_PAYLOAD_DIGESTS = {\n"
    if source.count(marker) != 1:
        raise PackageCheckError("launcher trusted payload table is unavailable")
    start = source.index(marker) + len(marker)
    end = source.find("};\n", start)
    if end < 0:
        raise PackageCheckError("launcher trusted payload table is malformed")
    block = source[start:end]
    pattern = re.compile(r"  '([^'\n]+)': '([0-9a-f]{64})',\n")
    matches = pattern.findall(block)
    if block != "".join(
        f"  '{path}': '{digest}',\n" for path, digest in matches
    ):
        raise PackageCheckError("launcher trusted payload table is malformed")
    result = dict(matches)
    if len(result) != len(matches):
        raise PackageCheckError("launcher trusted payload table has duplicate paths")
    return result


def validate_source(*, package_root: Path = PACKAGE_ROOT) -> dict[str, bytes]:
    manifest_bytes = bounded_regular_content(
        package_root / "package-files.json",
        subject="package source file",
        expected_archive_mode=EXPECTED_MODES["package-files.json"],
    )
    manifest = load_manifest(manifest_bytes)
    entries = manifest["files"]
    if not isinstance(entries, list):
        raise PackageCheckError("package-files entries are invalid")
    paths: list[str] = []
    snapshot: dict[str, bytes] = {"package-files.json": manifest_bytes}
    expected_manifest_paths = EXPECTED_PACKAGE_PATHS - {"package-files.json"}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"mode", "path", "sha256"}:
            raise PackageCheckError("package-files entry shape is invalid")
        path_text = entry["path"]
        if not isinstance(path_text, str):
            raise PackageCheckError("package-files path is invalid")
        path = PurePosixPath(path_text)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != path_text:
            raise PackageCheckError("package-files path is unsafe")
        if path_text not in expected_manifest_paths or entry["mode"] != EXPECTED_MODES[path_text]:
            raise PackageCheckError("package-files entry is not an allowlisted package file")
        content = bounded_regular_content(
            package_root / path_text,
            subject="package source file",
            expected_archive_mode=entry["mode"],
        )
        if hashlib.sha256(content).hexdigest() != entry["sha256"]:
            raise PackageCheckError(f"package-files entry drifted: {path_text}")
        if any(marker in content for marker in FORBIDDEN_CONTENT_MARKERS):
            raise PackageCheckError(f"secret-like content detected: {path_text}")
        snapshot[path_text] = content
        paths.append(path_text)
    if paths != sorted(paths) or set(paths) != expected_manifest_paths:
        raise PackageCheckError("package-files list is not the closed runtime set")
    trusted_payload_paths = EXPECTED_PACKAGE_PATHS - {
        "bin/launcher.cjs",
        "package-files.json",
    }
    expected_launcher_digests = {
        path: hashlib.sha256(snapshot[path]).hexdigest()
        for path in trusted_payload_paths
    }
    if launcher_payload_digests(snapshot["bin/launcher.cjs"]) != expected_launcher_digests:
        raise PackageCheckError("launcher trusted payload digest drifted")
    if any(marker in manifest_bytes for marker in FORBIDDEN_CONTENT_MARKERS):
        raise PackageCheckError("secret-like content detected in package source manifest")
    if sum(len(content) for content in snapshot.values()) > MAX_TOTAL_CONTENT_SCAN_BYTES:
        raise PackageCheckError("package source exceeds the total content audit limit")
    return snapshot


def write_normalized_staging_tree(
    snapshot: Mapping[str, bytes], staging_root: Path
) -> None:
    if set(snapshot) != EXPECTED_PACKAGE_PATHS:
        raise PackageCheckError("frozen source snapshot is not the closed package set")
    staging_root.mkdir(mode=0o700)
    for relative_path in sorted(EXPECTED_PACKAGE_PATHS):
        content = snapshot[relative_path]
        if not isinstance(content, bytes) or len(content) > MAX_CONTENT_SCAN_BYTES:
            raise PackageCheckError("frozen source snapshot content is invalid")
        destination = staging_root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor = -1
        try:
            descriptor = os.open(
                destination,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                int(EXPECTED_MODES[relative_path], 8),
            )
            offset = 0
            while offset < len(content):
                written = os.write(descriptor, content[offset:])
                if written <= 0:
                    raise OSError("short staging write")
                offset += written
            os.fchmod(descriptor, int(EXPECTED_MODES[relative_path], 8))
            os.fsync(descriptor)
        except OSError as exc:
            raise PackageCheckError("normalized package staging failed") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)


def run_bounded_process(
    command: list[str],
    *,
    cwd: Path,
    max_output_bytes: int = MAX_NPM_OUTPUT_CHARS,
    timeout_seconds: float = NPM_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[bytes]:
    if max_output_bytes < 1 or timeout_seconds <= 0:
        raise PackageCheckError("bounded process limits are invalid")
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        raise PackageCheckError("offline npm pack could not start") from exc
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise PackageCheckError("offline npm pack pipes are unavailable")

    selector = selectors.DefaultSelector()
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    deadline = time.monotonic() + timeout_seconds

    def stop_process_group() -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    try:
        for stream in streams:
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            remaining_seconds = deadline - time.monotonic()
            if remaining_seconds <= 0:
                raise PackageCheckError("offline npm pack timed out")
            events = selector.select(min(remaining_seconds, 0.1))
            for key, _mask in events:
                stream = key.fileobj
                buffer = streams[stream]
                remaining_bytes = max_output_bytes - len(buffer)
                chunk = os.read(stream.fileno(), min(64 * 1024, remaining_bytes + 1))
                if not chunk:
                    selector.unregister(stream)
                    continue
                if len(chunk) > remaining_bytes:
                    raise PackageCheckError("npm pack output exceeds the audit limit")
                buffer.extend(chunk)
        remaining_seconds = deadline - time.monotonic()
        if remaining_seconds <= 0:
            raise PackageCheckError("offline npm pack timed out")
        try:
            returncode = process.wait(timeout=remaining_seconds)
        except subprocess.TimeoutExpired as exc:
            raise PackageCheckError("offline npm pack timed out") from exc
    except (OSError, PackageCheckError):
        stop_process_group()
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
        if process.poll() is None:
            stop_process_group()
    return subprocess.CompletedProcess(
        command,
        returncode,
        stdout=bytes(streams[process.stdout]),
        stderr=bytes(streams[process.stderr]),
    )


def validate_npm_tarball(snapshot: Mapping[str, bytes]) -> None:
    npm = shutil.which("npm")
    if npm is None:
        raise PackageCheckError("npm is required for package validation")
    with tempfile.TemporaryDirectory() as temporary_directory:
        temporary_root = Path(temporary_directory)
        staging_root = temporary_root / "source"
        pack_destination = temporary_root / "output"
        pack_destination.mkdir(mode=0o700)
        frozen_snapshot = dict(snapshot)
        write_normalized_staging_tree(frozen_snapshot, staging_root)
        result = run_bounded_process(
            [
                npm,
                "pack",
                "--json",
                "--offline",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
                "--pack-destination",
                str(pack_destination),
            ],
            cwd=staging_root,
        )
        if result.returncode != 0:
            raise PackageCheckError("offline npm pack failed")
        try:
            records = json.loads(result.stdout)
            if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict):
                raise PackageCheckError("npm pack response is invalid")
            filename = records[0]["filename"]
        except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise PackageCheckError("npm pack response is invalid") from exc
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise PackageCheckError("npm pack returned an unsafe tarball name")
        tarball = pack_destination / filename
        if set(pack_destination.iterdir()) != {tarball}:
            raise PackageCheckError("npm pack produced an unexpected artifact set")
        expected_hashes = {
            relative_path: hashlib.sha256(content).hexdigest()
            for relative_path, content in frozen_snapshot.items()
        }
        validate_tarball(tarball, expected_hashes=expected_hashes)


def main() -> int:
    try:
        snapshot = validate_source()
        validate_npm_tarball(snapshot)
    except PackageCheckError as exc:
        print(f"package check failed: {exc}", file=sys.stderr)
        return 1
    print("package check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
