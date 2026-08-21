#!/usr/bin/env python3
"""Render and optionally exercise the exact ContextGuard Homebrew formula."""
from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Callable


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
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def homebrew_commands(
    brew: Path, output: Path, formula_name: str
) -> tuple[list[str], ...]:
    return (
        [
            str(brew),
            "style",
            "--except-cops",
            "Lint/DuplicateMethods",
            str(output),
        ],
        [str(brew), "audit", "--strict", "--new", "--formula", formula_name],
        [str(brew), "install", "--build-from-source", formula_name],
        [str(brew), "test", formula_name],
    )


def context_guard_is_installed(
    brew: Path,
    environment: dict[str, str],
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> bool:
    completed = runner(
        [str(brew), "list", "--versions", "context-guard"],
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        check=False,
        timeout=60,
        text=True,
        capture_output=True,
    )
    output = completed.stdout.strip()
    if completed.returncode == 0 and output:
        return True
    if completed.returncode == 1 and not output:
        return False
    raise SystemExit("could not determine whether context-guard is installed")


def verify_with_homebrew(
    brew: Path,
    output: Path,
    formula: str,
    environment: dict[str, str],
    *,
    tap_name: str,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    if context_guard_is_installed(brew, environment, runner):
        raise SystemExit(
            "context-guard is already installed; use --no-brew or a clean runner"
        )
    formula_name = f"{tap_name}/context-guard"
    tap_created = False
    install_attempted = False
    primary_error: BaseException | None = None
    cleanup_errors: list[BaseException] = []
    try:
        runner(
            [str(brew), "tap-new", "--no-git", tap_name],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            check=True,
            timeout=900,
        )
        tap_created = True
        tap_repository = runner(
            [str(brew), "--repo", tap_name],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            check=True,
            timeout=60,
            text=True,
            capture_output=True,
        )
        tap_root_text = tap_repository.stdout.strip()
        if not tap_root_text or not Path(tap_root_text).is_absolute():
            raise SystemExit("Homebrew returned an invalid temporary tap path")
        tap_root = Path(tap_root_text).resolve(strict=True)
        tap_formula = tap_root / "Formula" / "context-guard.rb"
        write_regular_atomic(tap_formula, formula)
        for index, command in enumerate(
            homebrew_commands(brew, output, formula_name)
        ):
            if index == 2:
                install_attempted = True
            runner(
                command,
                cwd=ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                check=True,
                timeout=900,
            )
    except BaseException as error:
        primary_error = error
    finally:
        if install_attempted:
            try:
                if context_guard_is_installed(brew, environment, runner):
                    runner(
                        [str(brew), "uninstall", "--force", formula_name],
                        cwd=ROOT,
                        env=environment,
                        stdin=subprocess.DEVNULL,
                        check=True,
                        timeout=900,
                    )
            except BaseException as error:
                cleanup_errors.append(error)
        if tap_created:
            try:
                runner(
                    [str(brew), "untap", tap_name],
                    cwd=ROOT,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    check=True,
                    timeout=900,
                )
            except BaseException as error:
                cleanup_errors.append(error)
    if primary_error is not None:
        for cleanup_error in cleanup_errors:
            primary_error.add_note(
                f"Homebrew cleanup also failed: {type(cleanup_error).__name__}"
            )
        raise primary_error
    if cleanup_errors:
        raise cleanup_errors[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--no-brew", action="store_true")
    args = parser.parse_args()
    formula = render(args.version, args.sha256)
    write_regular_atomic(args.output, formula)
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
            "HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_ENV_HINTS": "1",
            "LC_ALL": "C.UTF-8", "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
        }
        tap_name = f"contextguard/release-verification-{uuid.uuid4().hex[:12]}"
        verify_with_homebrew(
            brew, args.output, formula, environment, tap_name=tap_name
        )
    print(f"homebrew formula verification: OK ({args.output.name})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
