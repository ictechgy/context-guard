"""Verify the source package and npm's dry-run view without lifecycle scripts."""

from __future__ import annotations

import hashlib
import json
import shutil
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath


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
    "python/context_guard_receipt/diagnostic_ledger.py",
    "python/context_guard_receipt/diagnostics.py",
    "python/context_guard_receipt/execution_twin.py",
    "python/context_guard_receipt/evidence_pack.py",
    "python/context_guard_receipt/expansion.py",
    "python/context_guard_receipt/identity.py",
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
    "schemas/expansion-envelope.schema.json",
    "schemas/expansion-refusal.schema.json",
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


class PackageCheckError(RuntimeError):
    """Raised when a distribution invariant is violated."""


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def regular_mode(path: Path) -> str:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise PackageCheckError(f"non-regular package file: {path.relative_to(PACKAGE_ROOT)}")
    return f"{stat.S_IMODE(metadata.st_mode):04o}"


def load_manifest() -> dict[str, object]:
    try:
        manifest = json.loads((PACKAGE_ROOT / "package-files.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PackageCheckError("package-files manifest is unreadable") from exc
    if set(manifest) != {"files", "schema_version"} or manifest["schema_version"] != "contextguard-receipt-package-files/v1":
        raise PackageCheckError("package-files manifest shape is invalid")
    return manifest


def validate_source() -> None:
    manifest = load_manifest()
    entries = manifest["files"]
    if not isinstance(entries, list):
        raise PackageCheckError("package-files entries are invalid")
    paths: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"mode", "path", "sha256"}:
            raise PackageCheckError("package-files entry shape is invalid")
        path_text = entry["path"]
        if not isinstance(path_text, str):
            raise PackageCheckError("package-files path is invalid")
        path = PurePosixPath(path_text)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != path_text:
            raise PackageCheckError("package-files path is unsafe")
        source = PACKAGE_ROOT / path_text
        if source.is_symlink() or regular_mode(source) != entry["mode"] or sha256(source) != entry["sha256"]:
            raise PackageCheckError(f"package-files entry drifted: {path_text}")
        paths.append(path_text)
    if paths != sorted(paths) or set(paths) != EXPECTED_PACKAGE_PATHS - {"package-files.json"}:
        raise PackageCheckError("package-files list is not the closed runtime set")
    for path_text, expected_mode in EXPECTED_MODES.items():
        source = PACKAGE_ROOT / path_text
        if source.is_symlink() or regular_mode(source) != expected_mode:
            raise PackageCheckError(f"package mode drifted: {path_text}")
        content = source.read_bytes()
        if any(marker in content for marker in FORBIDDEN_CONTENT_MARKERS):
            raise PackageCheckError(f"secret-like content detected: {path_text}")


def validate_npm_dry_run() -> None:
    npm = shutil.which("npm")
    if npm is None:
        raise PackageCheckError("npm is required for package validation")
    result = subprocess.run(
        [
            npm,
            "pack",
            "--json",
            "--dry-run",
            "--offline",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ],
        cwd=PACKAGE_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise PackageCheckError("npm pack dry-run failed")
    try:
        records = json.loads(result.stdout)
        files = records[0]["files"]
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise PackageCheckError("npm pack dry-run response is invalid") from exc
    actual = {entry.get("path"): f"{entry.get('mode'):04o}" for entry in files if isinstance(entry, dict)}
    if set(actual) != EXPECTED_PACKAGE_PATHS:
        raise PackageCheckError("npm pack file set drifted")
    if actual != EXPECTED_MODES:
        raise PackageCheckError("npm pack file mode drifted")


def main() -> int:
    try:
        validate_source()
        validate_npm_dry_run()
    except PackageCheckError as exc:
        print(f"package check failed: {exc}", file=sys.stderr)
        return 1
    print("package check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
