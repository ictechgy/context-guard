"""Exercise an installed tarball without importing checkout test modules."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_NAME = "@ictechgy/context-guard-receipt"
PYTHON_ENV = "CONTEXT_GUARD_RECEIPT_PYTHON"
EXPECTED_BOUNDARY = {
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


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"


def run(command: list[str], *, cwd: Path, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def distribution() -> None:
    npm = shutil.which("npm")
    node = shutil.which("node")
    if npm is None or node is None:
        raise RuntimeError("npm and node are required")
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        pack_directory, install_directory, poisoned_bin = root / "pack", root / "install", root / "poisoned-bin"
        pack_directory.mkdir()
        install_directory.mkdir()
        poisoned_bin.mkdir()
        packed = run([npm, "pack", "--json", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", "--pack-destination", str(pack_directory), str(PACKAGE_ROOT)], cwd=pack_directory)
        if packed.returncode != 0:
            raise RuntimeError("offline npm pack failed")
        records = json.loads(packed.stdout)
        tarball = pack_directory / records[0]["filename"]
        with tarfile.open(tarball, "r:gz") as archive:
            if any(member.issym() for member in archive.getmembers()):
                raise RuntimeError("tarball contains a symlink")
        installed = run([npm, "install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", str(tarball)], cwd=install_directory)
        if installed.returncode != 0:
            raise RuntimeError("offline npm install failed")
        installed_root = install_directory / "node_modules" / PACKAGE_NAME
        receipt_bin = installed_root / "bin/context-guard-receipt.cjs"
        mcp_bin = installed_root / "bin/context-guard-receipt-mcp.cjs"
        sentinel = root / "poisoned-helper-used"
        for name in ("context-guard", "context-guard-mcp", "python", "python3"):
            helper = poisoned_bin / name
            helper.write_text(f"#!/bin/sh\ntouch '{sentinel}'\nexit 99\n", encoding="utf-8")
            helper.chmod(0o755)
        environment = {"LANG": "C", "PATH": str(poisoned_bin), "PYTHONDONTWRITEBYTECODE": "1", PYTHON_ENV: str(Path(sys.executable).resolve())}
        response = run([str(Path(node).resolve()), str(receipt_bin), "inspect", "boundary"], cwd=install_directory, environment=environment)
        expected = {"evidence_boundary": EXPECTED_BOUNDARY, "operation": "inspect_boundary", "schema_version": "contextguard-receipt-cli-response/v1", "status": "ok"}
        if response.returncode != 0 or response.stdout != canonical_json(expected) or response.stderr or sentinel.exists():
            raise RuntimeError("installed receipt command failed its closed-boundary smoke test")
        mcp = run([str(Path(node).resolve()), str(mcp_bin), "--root", str(install_directory)], cwd=install_directory, environment=environment)
        if mcp.returncode != 69 or sentinel.exists():
            raise RuntimeError("installed MCP command did not remain unavailable")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", choices=("distribution", "all"), default="all")
    arguments = parser.parse_args()
    try:
        distribution()
    except (OSError, RuntimeError, json.JSONDecodeError, tarfile.TarError) as exc:
        print(f"packaged acceptance failed: {exc}", file=sys.stderr)
        return 1
    print("packaged acceptance passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
