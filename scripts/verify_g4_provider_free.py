#!/usr/bin/env python3
"""Clean provider-free P1/G2/G3/G4 validation command."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BOUNDARY = ROOT / "research/provider-free-roadmap/boundary-contract.json"
MANIFEST = ROOT / "research/provider-free-roadmap/p1-v8-evidence-manifest.json"
DRIVER = ROOT / "scripts/verify_provider_free_roadmap.py"


def run(arguments: list[str]) -> None:
    environment = {"LANG": os.environ.get("LANG", "C.UTF-8"), "PATH": os.environ["PATH"]}
    completed = subprocess.run(
        [sys.executable, "-I", "-B", *arguments], cwd=ROOT, env=environment,
        stdin=subprocess.DEVNULL,
    )
    if completed.returncode:
        raise SystemExit(completed.returncode)


def main() -> int:
    run([str(DRIVER), "inventory", "--manifest", str(MANIFEST)])
    # G2 and G3 each execute their authenticated contract/boundary checks.  The
    # separate mutation-heavy boundary self-test is intentionally not nested in
    # this clean aggregate command because it rewrites shared fixture modes.
    for profile in (
        "g2-contract-tests", "g3-rehearsal-tests", "g4-claim-gates",
        "g5-p2-preregistration",
        "g6-prepared-unapproved",
    ):
        run([str(DRIVER), "run", "--contract", str(BOUNDARY), "--profile", profile])
    print("P1-v8 + frozen G2/G3/G4/G5/G6 authenticated profiles: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
