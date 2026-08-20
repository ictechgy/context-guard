#!/usr/bin/env python3
"""Render and optionally exercise the exact ContextGuard Homebrew formula."""
from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "packaging" / "homebrew" / "context-guard.rb.template"
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?")
DIGEST_RE = re.compile(r"[0-9a-f]{64}")


def render(version: str, digest: str) -> str:
    if VERSION_RE.fullmatch(version) is None:
        raise SystemExit("version must be a bare canonical semver")
    if DIGEST_RE.fullmatch(digest) is None:
        raise SystemExit("sha256 must be 64 lowercase hexadecimal characters")
    source = TEMPLATE.read_text(encoding="utf-8")
    if source.count("{{VERSION}}") != 1 or source.count("REPLACE_WITH_RELEASE_TARBALL_SHA256") != 1:
        raise SystemExit("Homebrew template placeholders are not closed and unique")
    rendered = source.replace("{{VERSION}}", version).replace(
        "REPLACE_WITH_RELEASE_TARBALL_SHA256", digest
    )
    if "{{" in rendered or "REPLACE_WITH_" in rendered:
        raise SystemExit("Homebrew formula contains an unresolved placeholder")
    return rendered


def write_regular_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise SystemExit("formula output must be a regular non-symlink path")
    fd, temporary = tempfile.mkstemp(prefix=".context-guard-formula-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--no-brew", action="store_true")
    args = parser.parse_args()
    write_regular_atomic(args.output, render(args.version, args.sha256))
    if not args.no_brew:
        brew = next(
            (
                candidate.resolve(strict=True)
                for candidate in (Path("/opt/homebrew/bin/brew"), Path("/usr/local/bin/brew"))
                if candidate.exists()
            ),
            None,
        )
        if brew is None:
            raise SystemExit("trusted Homebrew executable unavailable")
        metadata = brew.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o022:
            raise SystemExit("trusted Homebrew executable is unsafe")
        environment = {
            "CI": "1", "HOME": str(Path.home()), "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8", "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
        }
        commands = (
            [str(brew), "style", str(args.output)],
            [str(brew), "audit", "--strict", "--new", "--formula", str(args.output)],
            [str(brew), "install", "--build-from-source", str(args.output)],
            [str(brew), "test", str(args.output)],
        )
        for command in commands:
            subprocess.run(
                command, cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
                check=True, timeout=900,
            )
    print(f"homebrew formula verification: OK ({args.output.name})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
