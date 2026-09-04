#!/usr/bin/env python3
"""Dependency-free smoke gate for the packaged ContextGuard plugin."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import json
import os
import queue
import re
import shlex
import signal
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, NamedTuple, NoReturn


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_DIR = ROOT / "plugins" / "context-guard"
PLUGIN_BIN = ROOT / "plugins" / "context-guard" / "bin"
KIT_DIR = ROOT / "context-guard-kit"
MAX_MANIFEST_HELPER_BYTES = 128 * 1024
PACKAGE_REQUIRED_FILES = (".claude-plugin/plugin.json",)
PACKAGE_REQUIRED_DIRS = ("bin", "lib", "skills")
PACKAGE_COPY_IGNORE_NAMES = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".DS_Store",
}
REQUIRED_COMMANDS = (
    "context-guard-setup",
    "context-guard-diet",
    "context-guard-audit",
)


def trusted_source_open_flags() -> int | None:
    if not hasattr(os, "O_NOFOLLOW"):
        return None
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_NOCTTY"):
        flags |= os.O_NOCTTY
    return flags


def read_manifest_helper_source(path: Path) -> str | None:
    flags = trusted_source_open_flags()
    if flags is None:
        return None
    fd = -1
    try:
        fd = os.open(path, flags)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_MANIFEST_HELPER_BYTES:
            return None
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(64 * 1024, MAX_MANIFEST_HELPER_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_MANIFEST_HELPER_BYTES:
                return None
        return b"".join(chunks).decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def load_manifest_helper() -> dict[str, Any]:
    helper_path = KIT_DIR / "context_guard_command_manifest_loader.py"
    source = read_manifest_helper_source(helper_path)
    if source is None:
        raise SystemExit(f"could not load trusted command manifest helper source: {helper_path}")
    namespace: dict[str, Any] = {
        "__builtins__": __builtins__,
        "__file__": str(helper_path),
        "__name__": "_context_guard_command_manifest_loader",
    }
    try:
        exec(compile(source, str(helper_path), "exec"), namespace)
    except Exception as exc:
        raise SystemExit(f"could not load trusted command manifest helper: {helper_path}: {exc}") from exc
    required = (
        "COMMAND_MANIFEST_LITERAL_NAMES",
        "MAX_COMMAND_MANIFEST_BYTES",
        "command_manifest_namespace",
        "literal_command_manifest_from_source",
        "manifest_open_flags",
        "read_manifest_source",
    )
    missing = [name for name in required if name not in namespace]
    if missing:
        raise SystemExit(f"trusted command manifest helper missing required API: {', '.join(missing)}")
    return namespace


COMMAND_MANIFEST_HELPER = load_manifest_helper()
MAX_COMMAND_MANIFEST_BYTES = COMMAND_MANIFEST_HELPER["MAX_COMMAND_MANIFEST_BYTES"]
COMMAND_MANIFEST_LITERAL_NAMES = COMMAND_MANIFEST_HELPER["COMMAND_MANIFEST_LITERAL_NAMES"]
manifest_open_flags = COMMAND_MANIFEST_HELPER["manifest_open_flags"]
read_manifest_source = COMMAND_MANIFEST_HELPER["read_manifest_source"]
literal_command_manifest_from_source = COMMAND_MANIFEST_HELPER["literal_command_manifest_from_source"]
command_manifest_namespace = COMMAND_MANIFEST_HELPER["command_manifest_namespace"]


def load_command_manifest():
    manifest_path = ROOT / "context-guard-kit" / "context_guard_commands.py"
    source = read_manifest_source(manifest_path)
    if source is None:
        raise SystemExit(f"could not load trusted command manifest source: {manifest_path}")
    try:
        values = literal_command_manifest_from_source(source)
    except ValueError as exc:
        raise SystemExit(f"could not parse trusted command manifest literals: {manifest_path}: {exc}") from exc
    required = {"ENTRYPOINT_SMOKE_CASES", "DISPATCHER_SMOKE_CASES"}
    try:
        return command_manifest_namespace(values, required=required)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc


COMMAND_MANIFEST = load_command_manifest()
ENTRYPOINT_SMOKE_COMMANDS: dict[str, dict[str, Any]] = {
    name: {"args": list(plan["args"]), "mode": str(plan["mode"])}
    for name, plan in COMMAND_MANIFEST.ENTRYPOINT_SMOKE_CASES.items()
}

DISPATCHER_SMOKE_COMMANDS: tuple[dict[str, Any], ...] = tuple(
    {"entrypoint": str(plan["entrypoint"]), "args": list(plan["args"]), "mode": str(plan["mode"])}
    for plan in COMMAND_MANIFEST.DISPATCHER_SMOKE_CASES
)

HOOK_STDIN = "{}"
STATUSLINE_STDIN = json.dumps({"cwd": ".", "session_id": "release-smoke", "transcript_path": ""})
STATUSLINE_MAX_CHARS = 1_000
COMMAND_OUTPUT_MAX_BYTES = 64_000
COMMAND_READ_CHUNK_BYTES = 65_536
PROCESS_TERMINATE_GRACE_SECONDS = 2.0
REFERENCE_PAGE_MAX_BYTES = 20_000
REFERENCE_HANDLE_RE = re.compile(r"^cgr1p_[A-Za-z0-9_-]{43}$")
# The first byte of π lands at the final byte of a nominal 20,000-byte page.
# A valid response must therefore end before it and resume with the complete
# UTF-8 codepoint on the next page.
REFERENCE_SMOKE_PAYLOAD = (
    b"prefix:" + (b"x" * 19_992) + "π".encode("utf-8") + b":suffix\n" + (b"z" * 20_010)
)
PROCESS_SELECT_TIMEOUT_SECONDS = 0.05
ENTRYPOINT_SHEBANG_MAX_BYTES = 512
TRUSTED_PATH_CANDIDATES = (
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
    "/opt/homebrew/bin",
    "/usr/local/bin",
)
TRUSTED_CI_TOOLCACHE_ENV_KEYS = (
    "RUNNER_TOOL_CACHE",
    "AGENT_TOOLSDIRECTORY",
)
TRUSTED_CI_TOOLCACHE_PREFIXES = (
    "/opt/hostedtoolcache",
    "/Users/runner/hostedtoolcache",
    "/hostedtoolcache",
)
PRESERVED_ENV_KEYS = (
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
)
NPM_PACKAGE_JSON = ROOT / "package.json"
RECEIPT_PACKAGE_ROOT = ROOT / "packages" / "context-guard-receipt"
MAX_CANDIDATE_TARBALL_BYTES = 50 * 1024 * 1024
MAX_CANDIDATE_ARCHIVE_MEMBERS = 4096
MAX_CANDIDATE_DECLARED_UNCOMPRESSED_BYTES = 128 * 1024 * 1024
MAX_CANDIDATE_DECOMPRESSED_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_CANDIDATE_DECOMPRESSED_READ_BYTES = 64 * 1024
MAX_CANDIDATE_PACKAGE_JSON_BYTES = 128 * 1024
FORBIDDEN_NPM_LIFECYCLE_SCRIPTS = {
    "dependencies",
    "preinstall",
    "install",
    "postinstall",
    "prepack",
    "postpack",
    "prepublish",
    "prepublishOnly",
    "publish",
    "postpublish",
    "preprepare",
    "prepare",
    "postprepare",
    "preversion",
    "version",
    "postversion",
}


def running_in_ci() -> bool:
    return os.environ.get("CI", "").lower() == "true" or os.environ.get("GITHUB_ACTIONS", "").lower() == "true"


def fail(message: str) -> NoReturn:
    raise SystemExit(f"release smoke failed: {message}")


class _ArchiveLimitExceeded(OSError):
    pass


class _BoundedDecompressedReader:
    """Expose bounded gzip output to tarfile without an unbounded read mode."""

    def __init__(self, source: object, *, maximum_bytes: int) -> None:
        self._source = source
        self._maximum_bytes = maximum_bytes
        self._total = 0

    def read(self, size: int = -1) -> bytes:
        if (
            type(size) is not int
            or size < 0
            or size > MAX_CANDIDATE_DECOMPRESSED_READ_BYTES
        ):
            raise _ArchiveLimitExceeded("unbounded decompressed archive read")
        remaining = self._maximum_bytes - self._total
        if remaining < 0:
            raise _ArchiveLimitExceeded("decompressed archive limit exceeded")
        request = min(size, remaining + 1)
        try:
            chunk = self._source.read(request)  # type: ignore[attr-defined]
        except AttributeError:
            raise _ArchiveLimitExceeded("decompressed archive read failed") from None
        if type(chunk) is not bytes or len(chunk) > remaining:
            raise _ArchiveLimitExceeded("decompressed archive limit exceeded")
        self._total += len(chunk)
        return chunk


def _candidate_package_document(tarball: Path) -> tuple[Path, dict[str, object]]:
    try:
        metadata = tarball.lstat()
    except OSError as exc:
        fail(f"candidate tarball is unavailable: {exc.__class__.__name__}")
    if (
        tarball.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size < 1
        or metadata.st_size > MAX_CANDIDATE_TARBALL_BYTES
    ):
        fail("candidate tarball must be a bounded regular file")
    resolved = tarball.resolve()
    package_json_raw: bytes | None = None
    package_json_matches = 0
    try:
        with resolved.open("rb", buffering=0) as compressed_source:
            with gzip.GzipFile(fileobj=compressed_source, mode="rb") as decompressed:
                bounded_source = _BoundedDecompressedReader(
                    decompressed,
                    maximum_bytes=MAX_CANDIDATE_DECOMPRESSED_ARCHIVE_BYTES,
                )
                with tarfile.open(fileobj=bounded_source, mode="r|") as archive:
                    member_count = 0
                    declared_bytes = 0
                    while True:
                        member = archive.next()
                        if member is None:
                            break
                        member_count += 1
                        if (
                            member_count > MAX_CANDIDATE_ARCHIVE_MEMBERS
                            or type(member.size) is not int
                            or member.size < 0
                        ):
                            fail("candidate archive limits exceeded")
                        declared_bytes += member.size
                        if declared_bytes > MAX_CANDIDATE_DECLARED_UNCOMPRESSED_BYTES:
                            fail("candidate archive limits exceeded")
                        if member.name != "package/package.json":
                            continue
                        package_json_matches += 1
                        if (
                            package_json_matches != 1
                            or not member.isreg()
                            or member.size > MAX_CANDIDATE_PACKAGE_JSON_BYTES
                        ):
                            fail(
                                "candidate package manifest is missing, ambiguous, or oversized"
                            )
                        source = archive.extractfile(member)
                        if source is None:
                            fail("candidate package manifest is missing, ambiguous, or oversized")
                        package_json_raw = source.read(
                            MAX_CANDIDATE_PACKAGE_JSON_BYTES + 1
                        )
                        if len(package_json_raw) > MAX_CANDIDATE_PACKAGE_JSON_BYTES:
                            fail(
                                "candidate package manifest is missing, ambiguous, or oversized"
                            )
        if package_json_matches != 1 or package_json_raw is None:
            fail("candidate package manifest is missing, ambiguous, or oversized")
        document = json.loads(package_json_raw.decode("utf-8", errors="strict"))
    except _ArchiveLimitExceeded:
        fail("candidate archive limits exceeded")
    except (EOFError, OSError, UnicodeDecodeError, tarfile.TarError, json.JSONDecodeError) as exc:
        fail(f"candidate tarball is invalid: {exc.__class__.__name__}")
    if not isinstance(document, dict):
        fail("candidate package manifest is invalid")
    return resolved, document


def validate_candidate_tarball_pair(root_tarball: Path, receipt_tarball: Path) -> tuple[Path, Path]:
    """Bind an already-built root candidate to its exact Receipt candidate."""
    resolved_root, root_package = _candidate_package_document(root_tarball)
    resolved_receipt, receipt_package = _candidate_package_document(receipt_tarball)
    if resolved_root == resolved_receipt:
        fail("candidate root and Receipt tarballs must be distinct")
    if root_package.get("name") != "@ictechgy/context-guard":
        fail("candidate root package identity is invalid")
    if receipt_package.get("name") != "@ictechgy/context-guard-receipt":
        fail("candidate Receipt package identity is invalid")
    receipt_version = receipt_package.get("version")
    dependencies = root_package.get("dependencies")
    if (
        not isinstance(receipt_version, str)
        or not isinstance(dependencies, dict)
        or dependencies.get("@ictechgy/context-guard-receipt") != receipt_version
    ):
        fail("candidate root package must declare the exact Receipt dependency")
    return resolved_root, resolved_receipt


def verify_installed_reference_adapter(
    *,
    package_root: Path,
    project_root: Path,
    context_guard: Path,
    env: dict[str, str],
    timeout: float,
) -> None:
    """Exercise installed-package discovery with the exact paired Receipt bytes."""
    try:
        if package_root.is_symlink() or project_root.is_symlink():
            fail("installed reference roots must not be symlinks")
        package_root = package_root.resolve(strict=True)
        project_root = project_root.resolve(strict=True)
    except OSError as exc:
        fail(f"installed reference roots are unavailable: {exc.__class__.__name__}")
    policy_path = package_root / "plugins" / "context-guard" / "bin" / "bash_reference_policy.py"
    require_path_inside(policy_path, project_root, label="installed reference policy")
    try:
        metadata = policy_path.lstat()
    except OSError as exc:
        fail(f"installed reference policy is unavailable: {exc.__class__.__name__}")
    if policy_path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 512 * 1024:
        fail("installed reference policy must be a bounded regular file")
    module_name = "_context_guard_release_smoke_reference_policy"
    spec = importlib.util.spec_from_file_location(module_name, policy_path)
    if spec is None or spec.loader is None:
        fail("installed reference policy could not be loaded")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(module_name)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
        discover = getattr(module, "discover_adapter", None)
        if not callable(discover):
            fail("installed reference policy is missing adapter discovery")
        adapter, reason = discover(project_root)
    except SystemExit:
        raise
    except Exception as exc:
        fail(f"installed reference adapter discovery failed: {exc.__class__.__name__}")
    finally:
        if previous is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous
    if adapter is None or reason != "receipt_adapter_available":
        fail("installed reference adapter discovery did not accept the exact candidate pair")
    broker: object | None = None
    committed = False
    try:
        with tempfile.TemporaryFile("w+b", buffering=0) as capture:
            os.fchmod(capture.fileno(), 0o600)
            broker, broker_reason = adapter.start_broker(
                capture.fileno(),
                root=str(project_root),
                transaction_id=os.urandom(32).hex(),
                disclosure_days=7,
                timeout_seconds=8,
            )
            if broker is None or broker_reason != "receipt_broker_ready":
                fail("installed reference broker did not reach READY")
            capture.write(REFERENCE_SMOKE_PAYLOAD)
            result = broker.commit()
            committed = True
            if (
                getattr(result, "status", None) != "success"
                or getattr(result, "actionable", False) is not True
                or not isinstance(getattr(result, "reference", None), str)
                or REFERENCE_HANDLE_RE.fullmatch(result.reference) is None
            ):
                fail("installed reference broker did not return actionable authority")
            reference = result.reference

            rewrite_hook = (
                package_root
                / "plugins"
                / "context-guard"
                / "bin"
                / "context-guard-rewrite-bash"
            )
            trim_helper = rewrite_hook.with_name("context-guard-trim-output")
            for entrypoint, label in (
                (rewrite_hook, "installed reference rewrite hook"),
                (trim_helper, "installed reference trim helper"),
            ):
                require_path_inside(entrypoint, project_root, label=label)
                try:
                    metadata = entrypoint.lstat()
                except OSError as exc:
                    fail(f"{label} is unavailable: {exc.__class__.__name__}")
                if (
                    entrypoint.is_symlink()
                    or not stat.S_ISREG(metadata.st_mode)
                    or not (stat.S_IMODE(metadata.st_mode) & stat.S_IXUSR)
                ):
                    fail(f"{label} must be an executable regular file")

            hook_input = json.dumps(
                {
                    "tool_input": {
                        "command": (
                            "./node_modules/.bin/context-guard reference "
                            f"{reference}"
                        )
                    }
                },
                separators=(",", ":"),
            )
            hook_command = run_bounded_command(
                entrypoint_launch_argv(
                    rewrite_hook,
                    ["--bash-reference-v1"],
                    trusted_root=project_root,
                ),
                cwd=project_root,
                env=env,
                timeout=timeout,
                input_text=hook_input,
                max_output_bytes=16_384,
            )
            if hook_command.timed_out:
                fail("installed reference rewrite hook timed out")
            if hook_command.output_truncated or hook_command.proc.returncode != 0:
                fail("installed reference rewrite hook did not return a bounded successful response")
            if (
                "PATH-SHADOWED-CONTEXT-GUARD" in hook_command.proc.stdout
                or "PATH-SHADOWED-CONTEXT-GUARD" in hook_command.proc.stderr
            ):
                fail("installed reference rewrite hook used the PATH shadow")
            hook_response = load_json(hook_command.proc.stdout, "installed reference rewrite hook")
            try:
                updated_input = hook_response["hookSpecificOutput"]["updatedInput"]
                rewritten = updated_input["command"]
            except (KeyError, TypeError):
                fail("installed reference rewrite hook did not return updatedInput.command")
            if not isinstance(rewritten, str) or len(rewritten) > 8_192:
                fail("installed reference rewrite hook returned an invalid command")
            try:
                rewritten_argv = shlex.split(rewritten, posix=True)
            except ValueError:
                fail("installed reference rewrite hook returned an unparsable command")
            if rewritten_argv != [
                str(trim_helper),
                "--expand-bash-reference",
                reference,
            ]:
                fail("installed reference rewrite hook did not rebind to the package-local trim helper")

            reconstructed = bytearray()
            offset = 0
            # The bounded payload must fit in this many pages; keep a fixed
            # guard so a compromised candidate cannot spin the release gate.
            max_pages = (
                (len(REFERENCE_SMOKE_PAYLOAD) + REFERENCE_PAGE_MAX_BYTES - 1)
                // REFERENCE_PAGE_MAX_BYTES
            ) + 1
            for _ in range(max_pages):
                args = ["reference", reference]
                if offset:
                    args.extend(["--offset", str(offset)])
                command = run_bounded_command(
                    entrypoint_launch_argv(context_guard, args, trusted_root=project_root),
                    cwd=project_root,
                    env=env,
                    timeout=timeout,
                    max_output_bytes=REFERENCE_PAGE_MAX_BYTES + 4_096,
                )
                if command.timed_out:
                    fail("installed reference command timed out")
                if command.output_truncated or command.proc.returncode != 0:
                    fail("installed reference command did not return a bounded successful page")
                if "PATH-SHADOWED-CONTEXT-GUARD" in command.proc.stdout or "PATH-SHADOWED-CONTEXT-GUARD" in command.proc.stderr:
                    fail("installed reference command used the PATH shadow")
                try:
                    page = command.proc.stdout.encode("utf-8", errors="strict")
                except UnicodeEncodeError:
                    fail("installed reference command returned non-UTF-8 output")
                if not page or len(page) > REFERENCE_PAGE_MAX_BYTES:
                    fail("installed reference command returned an invalid page size")
                expected = REFERENCE_SMOKE_PAYLOAD[offset : offset + len(page)]
                if page != expected:
                    fail("installed reference command did not return exact capture bytes")
                next_offset = offset + len(page)
                if next_offset < len(REFERENCE_SMOKE_PAYLOAD):
                    expected_stderr = (
                        "context-guard: more bytes available; "
                        f"continue with --offset {next_offset}\n"
                    )
                else:
                    expected_stderr = f"context-guard: reference complete at offset {next_offset}\n"
                if command.proc.stderr != expected_stderr:
                    fail("installed reference command returned an invalid progress response")
                reconstructed.extend(page)
                offset = next_offset
                if offset == len(REFERENCE_SMOKE_PAYLOAD):
                    break
            if bytes(reconstructed) != REFERENCE_SMOKE_PAYLOAD:
                fail("installed reference command did not reconstruct the exact capture")
            if offset != len(REFERENCE_SMOKE_PAYLOAD):
                fail("installed reference command did not complete within bounded pages")
    except SystemExit:
        raise
    except Exception as exc:
        fail(f"installed reference broker smoke failed: {exc.__class__.__name__}")
    finally:
        if broker is not None:
            try:
                if not committed:
                    broker.abort()
            except Exception:
                pass
            try:
                broker.close()
            except Exception:
                pass


class BoundedCommandResult(NamedTuple):
    proc: subprocess.CompletedProcess[str]
    timed_out: bool
    output_truncated: bool


def validate_plugin_package(plugin_dir: Path) -> Path:
    raw_root = plugin_dir.expanduser()
    if raw_root.is_symlink():
        fail(f"plugin package directory must not be a symlink: {plugin_dir}")
    try:
        root = raw_root.resolve(strict=True)
    except OSError as exc:
        fail(f"plugin package directory could not be resolved: {exc}")
    if not root.is_dir():
        fail(f"plugin package path is not a directory: {plugin_dir}")

    for rel in PACKAGE_REQUIRED_FILES:
        if not (root / rel).is_file():
            fail(f"plugin package missing required file: {rel}")
    for rel in PACKAGE_REQUIRED_DIRS:
        if not (root / rel).is_dir():
            fail(f"plugin package missing required directory: {rel}")

    for current, dirs, files in os.walk(root):
        current_path = Path(current)
        for name in dirs + files:
            path = current_path / name
            if path.is_symlink():
                fail(f"plugin package must not contain symlink: {path.relative_to(root)}")
    return root


def copy_plugin_package_for_smoke(plugin_dir: Path, destination: Path) -> Path:
    source = validate_plugin_package(plugin_dir)

    def ignore(_directory: str, names: list[str]) -> set[str]:
        return {
            name
            for name in names
            if name in PACKAGE_COPY_IGNORE_NAMES or name.endswith((".pyc", ".pyo"))
        }

    shutil.copytree(source, destination, symlinks=True, ignore=ignore)
    return validate_plugin_package(destination)


def load_json(stdout: str, command: str) -> dict[str, Any]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        fail(f"{command} did not emit valid JSON: line {exc.lineno}: {exc.msg}")
    if not isinstance(data, dict):
        fail(f"{command} JSON output must be an object")
    return data


def check_npm_package_lifecycle_scripts(package_json: Path) -> None:
    try:
        data = json.loads(package_json.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"package.json did not emit valid JSON: line {exc.lineno}: {exc.msg}")
    if not isinstance(data, dict):
        fail("package.json JSON output must be an object")
    scripts = data.get("scripts", {})
    if scripts is None:
        scripts = {}
    if not isinstance(scripts, dict):
        fail("package.json scripts must be an object when present")
    forbidden = sorted(FORBIDDEN_NPM_LIFECYCLE_SCRIPTS & set(scripts))
    if forbidden:
        fail(f"package.json contains npm lifecycle scripts that release smoke must not run: {', '.join(forbidden)}")


def npm_package_version(package_json: Path) -> str:
    try:
        data = json.loads(package_json.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"package.json did not emit valid JSON: line {exc.lineno}: {exc.msg}")
    if not isinstance(data, dict):
        fail("package.json JSON output must be an object")
    version = data.get("version")
    if not isinstance(version, str) or not version.strip():
        fail("package.json missing non-empty version")
    return version.strip()


def require_path_inside(child: Path, parent: Path, *, label: str) -> None:
    try:
        child.resolve().relative_to(parent.resolve())
    except (OSError, ValueError) as exc:
        fail(f"{label} resolved outside isolated npm prefix: {child}")


def trusted_ci_toolcache_roots() -> list[Path]:
    roots: list[Path] = []
    if not running_in_ci():
        return roots
    candidates = list(TRUSTED_CI_TOOLCACHE_PREFIXES)
    candidates.extend(os.environ.get(key, "") for key in TRUSTED_CI_TOOLCACHE_ENV_KEYS)
    for raw in candidates:
        if not raw:
            continue
        try:
            root = Path(raw).resolve(strict=True)
        except OSError:
            continue
        if not root.is_dir() or root in roots:
            continue
        if not path_is_under(root, [Path(prefix).resolve() for prefix in TRUSTED_CI_TOOLCACHE_PREFIXES if Path(prefix).exists()]):
            continue
        roots.append(root)
    return roots


def path_is_under(path: Path, roots: list[Path]) -> bool:
    for root in roots:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def trusted_smoke_path() -> str:
    """Build a narrow PATH for smoke children without inheriting ambient order.

    The packaged entrypoints intentionally run via their real shebangs so the
    smoke gate still validates what users execute.  The PATH they see is
    constrained to the current Python, fixed system/package directories, and
    setup-node-style CI toolcache paths; it never trusts arbitrary ambient PATH
    entries.
    """
    dirs: list[str] = []
    seen: set[str] = set()

    def add_dir(path: str | Path | None) -> None:
        if not path:
            return
        try:
            directory = Path(path).resolve(strict=True)
        except OSError:
            return
        if directory.is_file():
            directory = directory.parent
        value = str(directory)
        if value not in seen:
            seen.add(value)
            dirs.append(value)

    add_dir(Path(sys.executable))

    toolcache_roots = trusted_ci_toolcache_roots()
    if toolcache_roots:
        for raw in os.environ.get("PATH", "").split(os.pathsep):
            if not raw:
                continue
            try:
                directory = Path(raw).resolve(strict=True)
            except OSError:
                continue
            if directory.is_dir() and path_is_under(directory, toolcache_roots):
                add_dir(directory)

    for directory in TRUSTED_PATH_CANDIDATES:
        add_dir(directory)
    return os.pathsep.join(dirs)


def trusted_which(name: str) -> str | None:
    return shutil.which(name, path=trusted_smoke_path())


def read_entrypoint_shebang(path: Path) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        fd = os.open(str(path), flags)
    except OSError as exc:
        fail(f"could not inspect entrypoint shebang without following symlinks: {path}: {exc}")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            fail(f"entrypoint is not a regular file: {path}")
        data = os.read(fd, ENTRYPOINT_SHEBANG_MAX_BYTES)
    finally:
        os.close(fd)
    first = data.split(b"\n", 1)[0].rstrip(b"\r")
    return first.decode("utf-8", errors="replace")


def entrypoint_launch_argv(path: Path, args: list[str], *, trusted_root: Path | None = None) -> list[str]:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        fail(f"entrypoint could not be resolved: {path}: {exc}")
    if trusted_root is not None:
        require_path_inside(resolved, trusted_root, label=f"{path.name} entrypoint target")
    inspected = resolved if path.is_symlink() else path
    read_entrypoint_shebang(inspected)
    return [str(path), *args]


def write_fake_context_guard_shadow(fake_bin: Path) -> None:
    fake_bin.mkdir(parents=True, exist_ok=True)
    fake = fake_bin / "context-guard"
    fake.write_text("#!/bin/sh\necho PATH-SHADOWED-CONTEXT-GUARD\n", encoding="utf-8")
    fake.chmod(0o755)


def command_path(plugin_bin: Path, name: str) -> Path:
    path = plugin_bin / name
    if not path.is_file():
        fail(f"missing plugin entrypoint: {path}")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & stat.S_IXUSR == 0:
        fail(f"plugin entrypoint is not owner-executable: {path} mode={oct(mode)}")
    return path


def entrypoint_smoke_plan(plugin_bin: Path) -> dict[str, dict[str, Any]]:
    files = {
        path.name
        for path in plugin_bin.iterdir()
        if path.is_file() and stat.S_IMODE(path.stat().st_mode) & stat.S_IXUSR
    }
    unexpected = sorted(files - set(ENTRYPOINT_SMOKE_COMMANDS))
    if unexpected:
        fail(f"release smoke has no launch plan for plugin entrypoints: {', '.join(unexpected)}")
    missing = sorted(set(ENTRYPOINT_SMOKE_COMMANDS) - files)
    if missing:
        fail(f"release smoke planned entrypoints are missing from plugin bin: {', '.join(missing)}")
    return {name: ENTRYPOINT_SMOKE_COMMANDS[name] for name in sorted(ENTRYPOINT_SMOKE_COMMANDS)}


def smoke_environment(home: Path, tmp: Path) -> dict[str, str]:
    env = {key: value for key in PRESERVED_ENV_KEYS if (value := os.environ.get(key))}
    if os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
        # Installed hooks re-evaluate the same fixed-root toolcache policy in a
        # child process. Preserve only the normalized CI marker; PATH remains
        # independently narrowed by trusted_smoke_path().
        env["GITHUB_ACTIONS"] = "true"
    env.update(
        {
            "PATH": trusted_smoke_path(),
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "XDG_DATA_HOME": str(home / ".local" / "share"),
            "TMPDIR": str(tmp),
            "TEMP": str(tmp),
            "TMP": str(tmp),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    return env


def command_name(argv: list[str]) -> str:
    return Path(argv[0]).name


def process_group_kwargs() -> dict[str, Any]:
    if os.name == "posix":
        return {"start_new_session": True}
    creation_flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    if os.name == "nt" and creation_flags:
        return {"creationflags": creation_flags}
    return {}


def process_group_id(proc: subprocess.Popen[bytes]) -> int | None:
    if os.name != "posix":
        return None
    try:
        return os.getpgid(proc.pid)
    except OSError:
        return None


def signal_process_group(proc: subprocess.Popen[bytes], sig: int, pgid: int | None) -> None:
    if os.name == "posix" and pgid is not None:
        try:
            os.killpg(pgid, sig)
            return
        except (ProcessLookupError, OSError):
            pass
    if os.name == "nt" and sig == signal.SIGTERM:
        ctrl_break = getattr(signal, "CTRL_BREAK_EVENT", None)
        if ctrl_break is not None:
            try:
                os.kill(proc.pid, ctrl_break)
                return
            except OSError:
                pass
    try:
        if sig == getattr(signal, "SIGKILL", signal.SIGTERM):
            proc.kill()
        else:
            proc.terminate()
    except OSError:
        pass


def write_child_input(stream: Any, input_text: str | None) -> None:
    if input_text is None or stream is None:
        return
    try:
        stream.write(input_text.encode("utf-8"))
    except (BrokenPipeError, OSError):
        pass
    finally:
        close_pipe(stream)


def close_pipe(stream: Any) -> None:
    if stream is None:
        return
    try:
        stream.close()
    except OSError:
        pass


def read_child_stream(
    name: str,
    stream: Any,
    chunks: queue.Queue[tuple[str, bytes | None]],
) -> None:
    try:
        while True:
            chunk = stream.read(COMMAND_READ_CHUNK_BYTES)
            if not chunk:
                break
            chunks.put((name, chunk))
    except OSError:
        pass
    finally:
        chunks.put((name, None))
        close_pipe(stream)


def run_bounded_command(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: float,
    input_text: str | None = None,
    max_output_bytes: int | None = None,
) -> BoundedCommandResult:
    if max_output_bytes is None:
        max_output_bytes = COMMAND_OUTPUT_MAX_BYTES
    stdin = subprocess.DEVNULL if input_text is None else subprocess.PIPE
    try:
        proc = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **process_group_kwargs(),
        )
    except OSError as exc:
        fail(f"{command_name(argv)} could not be launched: {exc}")

    pgid = process_group_id(proc)
    chunks: queue.Queue[tuple[str, bytes | None]] = queue.Queue(maxsize=32)
    buffers: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    live_streams = 0
    for name, stream in (("stdout", proc.stdout), ("stderr", proc.stderr)):
        if stream is None:
            continue
        live_streams += 1
        threading.Thread(
            target=read_child_stream,
            args=(name, stream, chunks),
            daemon=True,
        ).start()
    if input_text is not None:
        threading.Thread(
            target=write_child_input,
            args=(proc.stdin, input_text),
            daemon=True,
        ).start()

    timed_out = False
    output_truncated = False
    terminated_at: float | None = None
    sent_kill = False
    deadline = time.monotonic() + timeout
    while live_streams > 0 or proc.poll() is None:
        now = time.monotonic()
        if now >= deadline:
            timed_out = True
            if terminated_at is None:
                signal_process_group(proc, signal.SIGTERM, pgid)
                terminated_at = now
        if terminated_at is not None and not sent_kill:
            if now - terminated_at >= PROCESS_TERMINATE_GRACE_SECONDS:
                signal_process_group(proc, getattr(signal, "SIGKILL", signal.SIGTERM), pgid)
                sent_kill = True
        if sent_kill and terminated_at is not None:
            if now - terminated_at >= PROCESS_TERMINATE_GRACE_SECONDS * 2:
                break

        wait_timeout = PROCESS_SELECT_TIMEOUT_SECONDS
        if terminated_at is None:
            wait_timeout = min(wait_timeout, max(0.0, deadline - now))
        try:
            name, chunk = chunks.get(timeout=wait_timeout)
        except queue.Empty:
            continue
        if chunk is None:
            live_streams = max(0, live_streams - 1)
            continue
        remaining = max_output_bytes - len(buffers[name])
        if remaining > 0:
            buffers[name].extend(chunk[:remaining])
        if len(chunk) > remaining:
            output_truncated = True
            if terminated_at is None:
                signal_process_group(proc, signal.SIGTERM, pgid)
                terminated_at = time.monotonic()

    try:
        returncode = proc.wait(timeout=PROCESS_TERMINATE_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        timed_out = True
        signal_process_group(proc, getattr(signal, "SIGKILL", signal.SIGTERM), pgid)
        try:
            returncode = proc.wait(timeout=PROCESS_TERMINATE_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            returncode = 124
    if timed_out:
        returncode = 124
    elif output_truncated:
        returncode = 125

    # Reader/writer daemon threads own pipe cleanup. Drop Popen's references so
    # Popen finalization cannot contend with a thread blocked in pipe IO.
    proc.stdin = None
    proc.stdout = None
    proc.stderr = None
    return BoundedCommandResult(
        proc=subprocess.CompletedProcess(
            argv,
            returncode,
            stdout=bytes(buffers["stdout"]).decode("utf-8", "replace"),
            stderr=bytes(buffers["stderr"]).decode("utf-8", "replace"),
        ),
        timed_out=timed_out,
        output_truncated=output_truncated,
    )


def run_command(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: float,
    expect: Callable[[subprocess.CompletedProcess[str]], None],
    input_text: str | None = None,
) -> None:
    result = run_bounded_command(
        argv,
        cwd=cwd,
        env=env,
        timeout=timeout,
        input_text=input_text,
    )
    proc = result.proc
    if result.timed_out:
        fail(f"{command_name(argv)} timed out after {timeout:g}s")
    if result.output_truncated:
        fail(f"{command_name(argv)} output exceeded {COMMAND_OUTPUT_MAX_BYTES} bytes per stream")
    if proc.returncode != 0:
        fail(
            f"{command_name(argv)} exited {proc.returncode}: "
            f"{(proc.stderr or proc.stdout).strip()[:500]}"
        )
    expect(proc)


def check_json_field(data: dict[str, Any], key: str, expected: Any, command: str) -> None:
    if data.get(key) != expected:
        fail(f"{command} JSON field {key!r} was {data.get(key)!r}, expected {expected!r}")


def check_brief_mode_apply_smoke(proc: subprocess.CompletedProcess[str], project: Path, command: str) -> None:
    data = load_json(proc.stdout, command)
    check_json_field(data, "applied", True, command)
    rule_file = project / "AGENTS.md"
    if not rule_file.is_file():
        fail(f"{command} did not write AGENTS.md")
    text = rule_file.read_text(encoding="utf-8")
    if "<!-- BEGIN context-guard:brief-mode level=lite version=1 -->" not in text:
        fail(f"{command} did not write the lite brief-mode block")
    adapter_plan = data.get("adapter_plan")
    if not isinstance(adapter_plan, list) or not adapter_plan:
        fail(f"{command} JSON missing adapter_plan")
    status = adapter_plan[0].get("brief_mode_status")
    if status not in {"applied", "updated", "exists"}:
        fail(f"{command} unexpected brief_mode_status: {status!r}")


def run_quiet_narration_smoke(
    *,
    command: Path,
    project: Path,
    cwd: Path,
    env: dict[str, str],
    timeout: float,
    dispatcher: bool = False,
    trusted_root: Path | None = None,
    label: str,
) -> None:
    """Prove staged quiet plan/apply/default rollback without touching settings."""
    project.mkdir()
    settings = project / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings_bytes = b"{ malformed settings that rules-only must not parse"
    settings.write_bytes(settings_bytes)
    rule_file = project / "CLAUDE.md"
    original = b"Release smoke user rules without final newline"
    rule_file.write_bytes(original)
    prefix = ["setup"] if dispatcher else []
    common = [
        *prefix,
        "--root",
        str(project),
        "--rules-only",
        "--agent",
        "claude",
        "--scope",
        "project",
    ]

    def launch(args: list[str], expect: Callable[[subprocess.CompletedProcess[str]], None]) -> None:
        run_command(
            entrypoint_launch_argv(command, [*common, *args], trusted_root=trusted_root),
            cwd=cwd,
            env=env,
            timeout=timeout,
            expect=expect,
        )

    def check_plan(proc: subprocess.CompletedProcess[str]) -> None:
        data = load_json(proc.stdout, f"{label} quiet plan")
        check_json_field(data, "status", "planned", f"{label} quiet plan")
        check_json_field(data, "applied", False, f"{label} quiet plan")
        if rule_file.read_bytes() != original or settings.read_bytes() != settings_bytes:
            fail(f"{label} quiet plan changed project files")

    launch(["--narration-mode", "quiet", "--plan", "--json"], check_plan)

    def check_apply(proc: subprocess.CompletedProcess[str]) -> None:
        data = load_json(proc.stdout, f"{label} quiet apply")
        check_json_field(data, "status", "applied", f"{label} quiet apply")
        check_json_field(data, "applied", True, f"{label} quiet apply")
        written = rule_file.read_bytes()
        marker = b"<!-- BEGIN context-guard:narration-mode mode=quiet version=1 -->"
        if not written.startswith(original) or written.count(marker) != 1:
            fail(f"{label} quiet apply did not preserve user bytes and install one marker")
        if settings.read_bytes() != settings_bytes:
            fail(f"{label} quiet apply read or changed settings content")
        backup = Path(str(data.get("backup_path") or ""))
        if not backup.is_file() or backup.read_bytes() != original:
            fail(f"{label} quiet apply did not create the expected backup")
        if stat.S_IMODE(backup.stat().st_mode) != 0o600:
            fail(f"{label} quiet apply backup is not mode 0600")

    launch(["--narration-mode", "quiet", "--yes", "--json"], check_apply)

    def check_default_rollback(proc: subprocess.CompletedProcess[str]) -> None:
        data = load_json(proc.stdout, f"{label} default rollback")
        check_json_field(data, "status", "removed", f"{label} default rollback")
        check_json_field(data, "applied", True, f"{label} default rollback")
        if rule_file.read_bytes() != original:
            fail(f"{label} default rollback did not restore exact user bytes")
        if settings.read_bytes() != settings_bytes:
            fail(f"{label} default rollback changed settings content")
        backup = Path(str(data.get("backup_path") or ""))
        if not backup.is_file() or stat.S_IMODE(backup.stat().st_mode) != 0o600:
            fail(f"{label} default rollback did not create a private backup")

    launch(["--narration-mode", "default", "--yes", "--json"], check_default_rollback)


def check_doctor_smoke(proc: subprocess.CompletedProcess[str], command: str) -> None:
    data = load_json(proc.stdout, command)
    check_json_field(data, "schema_version", "contextguard.doctor.v1", command)
    check_json_field(data, "read_only", True, command)
    if data.get("status") not in {"ok", "warning", "error"}:
        fail(f"{command} unexpected doctor status: {data.get('status')!r}")
    checks = data.get("checks")
    if not isinstance(checks, list) or not checks:
        fail(f"{command} JSON missing checks")


def check_auto_explain_smoke(proc: subprocess.CompletedProcess[str], command: str) -> None:
    data = load_json(proc.stdout, command)
    check_json_field(data, "schema_version", "contextguard.pack-auto.v1", command)
    explain = data.get("explain")
    if not isinstance(explain, dict):
        fail(f"{command} JSON missing explain object")
    check_json_field(explain, "schema_version", "contextguard.pack-auto-explain.v1", command)
    repo_map = explain.get("repo_map")
    if not isinstance(repo_map, dict):
        fail(f"{command} JSON missing explain.repo_map object")
    check_json_field(repo_map, "schema_version", "contextguard.pack-repo-map.v1", command)
    if repo_map.get("safety", {}).get("explain_only") is not True:
        fail(f"{command} repo_map should be explain-only")
    if data.get("build", {}).get("artifact", {}).get("stored") is not False:
        fail(f"{command} should not store an artifact in release smoke")
    if data.get("manifest", {}).get("version") != 1:
        fail(f"{command} JSON missing build-compatible manifest")
    adaptive = data.get("adaptive_k")
    if not isinstance(adaptive, dict):
        fail(f"{command} JSON missing adaptive_k object")
    check_json_field(adaptive, "schema_version", "contextguard.pack-adaptive-k.v1", command)
    if adaptive.get("policy", {}).get("name") != "recall":
        fail(f"{command} adaptive_k policy should be recall")
    if adaptive.get("regression_gates", {}).get("status") not in {"pass", "failed"}:
        fail(f"{command} adaptive_k missing gate status")
    if adaptive.get("source_verification", {}).get("requires_exact_source_before_edits") is not True:
        fail(f"{command} adaptive_k missing source verification safeguard")


def check_pack_content_address(data: dict[str, Any], command: str) -> None:
    pack = data.get("pack")
    address = data.get("content_address")
    if not isinstance(pack, str) or not isinstance(address, dict):
        fail(f"{command} JSON missing pack/content_address")
    pack_bytes = pack.encode("utf-8")
    if address.get("schema_version") != "contextguard.pack-content-address.v1":
        fail(f"{command} content_address schema mismatch")
    digest = address.get("digest")
    if address.get("algorithm") != "sha256":
        fail(f"{command} content_address algorithm mismatch")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        fail(f"{command} content_address digest format mismatch")
    if address.get("id") != f"sha256:{digest}":
        fail(f"{command} content_address id mismatch")
    if hashlib.sha256(pack_bytes).hexdigest() != digest:
        fail(f"{command} content_address digest does not match pack")
    if address.get("bytes") != len(pack_bytes) or address.get("bytes") != data.get("pack_bytes"):
        fail(f"{command} content_address byte count mismatch")


def check_pack_delta_smoke(proc: subprocess.CompletedProcess[str], baseline: dict[str, Any], command: str) -> None:
    data = load_json(proc.stdout, command)
    check_pack_content_address(data, command)
    for key in ("pack", "pack_bytes", "pack_id", "token_proxy", "sources", "included_sources", "omitted_sources"):
        if data.get(key) != baseline.get(key):
            fail(f"{command} changed legacy build field {key!r}")
    delta = data.get("rolling_delta")
    if not isinstance(delta, dict) or delta.get("status") != "available":
        fail(f"{command} missing available rolling_delta")
    if delta.get("schema_version") != "contextguard.pack-rolling-delta.v1":
        fail(f"{command} rolling_delta schema mismatch")
    boundary = delta.get("claim_boundary", {})
    if boundary != {
        "diagnostic_only": True,
        "changes_manifest_selection_or_pack": False,
        "provider_token_or_cost_savings_claim_allowed": False,
    }:
        fail(f"{command} rolling_delta claim boundary mismatch")
    if data.get("artifact", {}).get("stored") is not False:
        fail(f"{command} --no-artifact unexpectedly stored a receipt")


def run_entrypoint_launch_smokes(
    *,
    plugin_bin: Path,
    launch_plan: dict[str, dict[str, Any]],
    cwd: Path,
    env: dict[str, str],
    timeout: float,
) -> None:
    for name, plan in launch_plan.items():
        mode = str(plan["mode"])
        run_command(
            entrypoint_launch_argv(command_path(plugin_bin, name), list(plan["args"])),
            cwd=cwd,
            env=env,
            timeout=timeout,
            input_text=launch_stdin(mode),
            expect=lambda proc, command=name, launch_mode=mode: check_launch_smoke(proc, command, launch_mode),
        )


def run_dispatcher_launch_smokes(
    *,
    bin_dir: Path,
    plans: tuple[dict[str, Any], ...],
    cwd: Path,
    env: dict[str, str],
    timeout: float,
    trusted_root: Path | None = None,
    label_prefix: str = "",
) -> None:
    for plan in plans:
        entrypoint = str(plan["entrypoint"])
        mode = str(plan["mode"])
        args = [str(arg) for arg in plan["args"]]
        entrypoint_path = bin_dir / entrypoint
        if not entrypoint_path.is_file():
            fail(f"{label_prefix}{entrypoint} dispatcher bin missing: {entrypoint_path}")
        if trusted_root is None:
            argv = entrypoint_launch_argv(command_path(bin_dir, entrypoint), args)
        else:
            require_path_inside(entrypoint_path, trusted_root, label=f"{entrypoint} npm bin")
            argv = entrypoint_launch_argv(entrypoint_path, args, trusted_root=trusted_root)
        command_label = " ".join([label_prefix.rstrip(), entrypoint, *args]).strip()
        run_command(
            argv,
            cwd=cwd,
            env=env,
            timeout=timeout,
            input_text=launch_stdin(mode),
            expect=lambda proc, command=command_label, launch_mode=mode: check_launch_smoke(proc, command, launch_mode),
        )


def run_mcp_namespace_smoke(
    mcp: Path,
    *,
    project: Path,
    env: dict[str, str],
    timeout: float,
    label: str,
    trusted_root: Path | None = None,
) -> None:
    """Exercise two clean local MCP sessions and prove namespace separation."""
    if trusted_root is not None:
        require_path_inside(mcp, trusted_root, label=f"{label} MCP entrypoint")
    argv_base = entrypoint_launch_argv(mcp, [], trusted_root=trusted_root)

    raw_secret = "sk-proj-abcdefghijklmnopqrstuvwxyz"
    sanitized_accepted_input = "release smoke secret=[REDACTED]"
    expected_artifact_id = hashlib.sha256(json.dumps(
        {
            "content_sha256": hashlib.sha256(sanitized_accepted_input.encode("utf-8")).hexdigest(),
            "command_preview": "context-guard-mcp compress",
            "input_truncated": False,
        },
        sort_keys=True,
    ).encode("utf-8")).hexdigest()[:20]
    private_markers = (
        raw_secret,
        str(project),
        str(project / ".context-guard" / "mcp"),
        ".context-guard/mcp",
    )

    def session(namespace: str, requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
        wire = "".join(json.dumps(request, separators=(",", ":")) + "\n" for request in requests)
        result = run_bounded_command(
            [*argv_base, "--root", str(project), "--namespace", namespace],
            cwd=project,
            env=env,
            timeout=timeout,
            input_text=wire,
            max_output_bytes=COMMAND_OUTPUT_MAX_BYTES,
        )
        if result.timed_out or result.output_truncated or result.proc.returncode != 0:
            fail(f"{label} MCP namespace {namespace} did not close cleanly")
        if result.proc.stderr:
            fail(f"{label} MCP namespace {namespace} emitted stderr")
        transcript = result.proc.stdout + result.proc.stderr
        if any(marker in transcript for marker in private_markers):
            fail(f"{label} MCP namespace {namespace} leaked private input or paths")
        response_lines = result.proc.stdout.splitlines()
        if any(not line for line in response_lines):
            fail(f"{label} MCP namespace {namespace} emitted a blank response")
        try:
            messages = [json.loads(line) for line in response_lines]
        except json.JSONDecodeError as exc:
            fail(f"{label} MCP emitted invalid JSON: {exc}")
        expected_ids = [request["id"] for request in requests if "id" in request]
        if len(messages) != len(expected_ids) or [message.get("id") for message in messages] != expected_ids:
            fail(f"{label} MCP emitted an unexpected response count")
        return messages

    initialize = {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "release-smoke", "version": "1"}},
    }
    ready = {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
    stored = session("A", [
        initialize, ready,
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "context_guard_compress", "arguments": {"content": "release smoke secret=" + raw_secret}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "context_guard_retrieve", "arguments": {"artifact_id": expected_artifact_id}}},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "context_guard_stats", "arguments": {}}},
    ])
    try:
        if stored[0]["result"]["protocolVersion"] != "2025-11-25":
            fail(f"{label} MCP A did not initialize")
        names_a = [tool["name"] for tool in stored[1]["result"]["tools"]]
        if names_a != ["context_guard_compress", "context_guard_retrieve", "context_guard_stats"]:
            fail(f"{label} MCP A exposed an unexpected tool set")
        compressed = stored[2]["result"]["structuredContent"]
        artifact_id = compressed["artifact"]["artifact_id"]
        retrieved = stored[3]["result"]["structuredContent"]
        stats_a = stored[4]["result"]["structuredContent"]
    except (KeyError, TypeError):
        fail(f"{label} MCP A did not return the expected tool results")
    if not isinstance(artifact_id, str) or artifact_id != expected_artifact_id:
        fail(f"{label} MCP A leaked a secret or omitted its artifact id")
    if compressed["artifact"].get("exact_scope") != "sanitized_accepted_input":
        fail(f"{label} MCP A artifact did not declare its sanitized accepted-input scope")
    if retrieved.get("artifact_id") != artifact_id or retrieved.get("content") != sanitized_accepted_input:
        fail(f"{label} MCP A did not retrieve its exact sanitized accepted input")
    if stats_a.get("storage", {}).get("artifacts_observed") != 1:
        fail(f"{label} MCP A did not observe its stored artifact")
    checked = session("B", [
        initialize, ready,
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "context_guard_retrieve", "arguments": {"artifact_id": artifact_id}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "context_guard_stats", "arguments": {}}},
    ])
    try:
        if checked[0]["result"]["protocolVersion"] != "2025-11-25":
            fail(f"{label} MCP B did not initialize")
        names_b = [tool["name"] for tool in checked[1]["result"]["tools"]]
        if names_b != ["context_guard_compress", "context_guard_retrieve", "context_guard_stats"]:
            fail(f"{label} MCP B exposed an unexpected tool set")
        rejected = checked[2]["result"]
        stats_b = checked[3]["result"]["structuredContent"]
    except (KeyError, TypeError):
        fail(f"{label} MCP B did not return the expected tool results")
    if rejected.get("isError") is not True or rejected.get("structuredContent", {}).get("error", {}).get("code") != "artifact_not_found":
        fail(f"{label} MCP namespace isolation did not reject A's artifact id")
    if stats_b.get("storage", {}).get("artifacts_observed") != 0:
        fail(f"{label} MCP B observed artifacts from namespace A")


def run_smoke(plugin_bin: Path, timeout: float) -> None:
    plugin_bin = plugin_bin.resolve()
    commands = {name: command_path(plugin_bin, name) for name in REQUIRED_COMMANDS}
    launch_plan = entrypoint_smoke_plan(plugin_bin)

    with tempfile.TemporaryDirectory(prefix="context-guard-release-smoke-") as td:
        project = Path(td) / "project"
        smoke_home = Path(td) / "home"
        smoke_tmp = Path(td) / "tmp"
        project.mkdir()
        smoke_home.mkdir()
        smoke_tmp.mkdir()
        (project / ".claude").mkdir()
        (project / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
        (project / "CLAUDE.md").write_text("Keep project context short.\n", encoding="utf-8")
        pack_tokens = [f"evidence{number:03d}" for number in range(100)]
        pack_original = " ".join(pack_tokens) + "\n"
        pack_variant = " ".join([*pack_tokens[:-1], "variant-terminal-token"]) + "\n"
        if pack_original.encode("utf-8") == pack_variant.encode("utf-8"):
            fail("pack smoke fixtures must have distinct bytes")
        (project / "smoke-pack.txt").write_text(pack_original, encoding="utf-8")
        (project / "smoke-pack-copy.txt").write_text(pack_variant, encoding="utf-8")
        mcp_project = Path(td) / "mcp-project"
        mcp_project.mkdir()
        (project / "release-smoke.jsonl").write_text(
            json.dumps(
                {
                    "session_id": "release-smoke",
                    "timestamp": "2026-07-23T00:00:00Z",
                    "message": {
                        "id": "release-smoke-response",
                        "model": "claude-release-smoke",
                        "usage": {"input_tokens": 1},
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        env = smoke_environment(smoke_home, smoke_tmp)
        run_mcp_namespace_smoke(
            command_path(plugin_bin, "context-guard-mcp"), project=mcp_project, env=env,
            timeout=timeout, label="staged plugin",
        )

        pack_baseline: dict[str, Any] = {}
        run_command(
            entrypoint_launch_argv(
                command_path(plugin_bin, "context-guard-pack"),
                ["build", "--root", str(project), "--source", "smoke-pack.txt", "--json"],
            ),
            cwd=project,
            env=env,
            timeout=timeout,
            expect=lambda proc: pack_baseline.update(load_json(proc.stdout, "context-guard-pack build")),
        )
        check_pack_content_address(pack_baseline, "context-guard-pack build")
        run_command(
            entrypoint_launch_argv(
                command_path(plugin_bin, "context-guard-pack"),
                [
                    "build", "--root", str(project), "--source", "smoke-pack.txt", "--json", "--no-artifact",
                    "--delta-from-pack-id", str(pack_baseline["pack_id"]),
                ],
            ),
            cwd=project,
            env=env,
            timeout=timeout,
            expect=lambda proc: check_pack_delta_smoke(proc, pack_baseline, "context-guard-pack build --delta-from-pack-id"),
        )

        duplicate_sources = [
            "--source", "path=smoke-pack.txt,priority=10",
            "--source", "path=smoke-pack-copy.txt,priority=5",
        ]

        zero_plain: dict[str, Any] = {}
        run_command(
            entrypoint_launch_argv(
                command_path(plugin_bin, "context-guard-pack"),
                ["build", "--root", str(project), *duplicate_sources, "--budget-bytes", "0", "--json", "--no-artifact"],
            ),
            cwd=project,
            env=env,
            timeout=timeout,
            expect=lambda proc: zero_plain.update(
                load_json(proc.stdout, "context-guard-pack zero-budget plain")
            ),
        )
        if not isinstance(zero_plain.get("content_address"), dict):
            fail("context-guard-pack zero-budget plain missing typed content_address")
        check_pack_content_address(zero_plain, "context-guard-pack zero-budget plain")

        unsafe_project = project / "unsafe-artifact"
        unsafe_project.mkdir()
        (unsafe_project / "source.txt").write_text("safe local smoke\n", encoding="utf-8")
        (unsafe_project / ".context-guard").write_text("not a directory\n", encoding="utf-8")
        run_command(
            entrypoint_launch_argv(
                command_path(plugin_bin, "context-guard-pack"),
                ["build", "--root", str(unsafe_project), "--source", "source.txt"],
            ),
            cwd=unsafe_project,
            env=env,
            timeout=timeout,
            expect=lambda proc: (
                None if "[context-guard-pack] pack_id=" in proc.stderr
                else fail("fail-soft artifact build text lost the pack telemetry line")
            ),
        )

        run_command(
            entrypoint_launch_argv(commands["context-guard-setup"], ["--root", str(project), "--plan", "--json"]),
            cwd=project,
            env=env,
            timeout=timeout,
            expect=lambda proc: (
                check_json_field(load_json(proc.stdout, "context-guard-setup"), "applied", False, "context-guard-setup")
            ),
        )
        run_command(
            entrypoint_launch_argv(commands["context-guard-setup"], ["--root", str(project), "--verify", "--json"]),
            cwd=project,
            env=env,
            timeout=timeout,
            expect=lambda proc: check_doctor_smoke(proc, "context-guard-setup --verify"),
        )
        run_command(
            entrypoint_launch_argv(
                command_path(plugin_bin, "context-guard"),
                ["doctor", "--root", str(project), "--json"],
            ),
            cwd=project,
            env=env,
            timeout=timeout,
            expect=lambda proc: check_doctor_smoke(proc, "context-guard doctor"),
        )
        run_command(
            entrypoint_launch_argv(
                commands["context-guard-setup"],
                [
                "--root",
                str(project),
                "--agent",
                "codex",
                "--brief-mode",
                "lite",
                "--plan",
                "--json",
                ],
            ),
            cwd=project,
            env=env,
            timeout=timeout,
            expect=lambda proc: (
                check_json_field(load_json(proc.stdout, "context-guard-setup brief-mode"), "applied", False, "context-guard-setup brief-mode")
            ),
        )
        brief_apply_project = Path(td) / "brief-apply-project"
        brief_apply_project.mkdir()
        run_command(
            entrypoint_launch_argv(
                commands["context-guard-setup"],
                [
                "--root",
                str(brief_apply_project),
                "--agent",
                "codex",
                "--brief-mode",
                "lite",
                "--yes",
                "--no-diet-scan",
                "--json",
                ],
            ),
            cwd=brief_apply_project,
            env=env,
            timeout=timeout,
            expect=lambda proc: check_brief_mode_apply_smoke(
                proc,
                brief_apply_project,
                "context-guard-setup brief-mode apply",
            ),
        )
        run_quiet_narration_smoke(
            command=commands["context-guard-setup"],
            project=Path(td) / "quiet-narration-project",
            cwd=project,
            env=env,
            timeout=timeout,
            label="staged plugin setup",
        )
        run_command(
            entrypoint_launch_argv(commands["context-guard-diet"], ["scan", str(project), "--json"]),
            cwd=project,
            env=env,
            timeout=timeout,
            expect=lambda proc: (
                check_json_field(load_json(proc.stdout, "context-guard-diet"), "tool", "context-guard-diet", "context-guard-diet")
            ),
        )
        run_command(
            entrypoint_launch_argv(
                command_path(plugin_bin, "context-guard-pack"),
                [
                "auto",
                "--root",
                str(project),
                "--files",
                "smoke-pack.txt",
                "--json",
                "--explain",
                "--adaptive-k",
                "--adaptive-k-policy",
                "recall",
                "--adaptive-k-min-recall-proxy",
                "0.0",
                "--no-artifact",
                ],
            ),
            cwd=project,
            env=env,
            timeout=timeout,
            expect=lambda proc: check_auto_explain_smoke(proc, "context-guard-pack auto --explain"),
        )
        run_command(
            entrypoint_launch_argv(commands["context-guard-audit"], [str(project), "--json"]),
            cwd=project,
            env=env,
            timeout=timeout,
            expect=lambda proc: (
                check_json_field(load_json(proc.stdout, "context-guard-audit"), "records", 1, "context-guard-audit")
            ),
        )
        run_entrypoint_launch_smokes(plugin_bin=plugin_bin, launch_plan=launch_plan, cwd=project, env=env, timeout=timeout)
        run_dispatcher_launch_smokes(
            bin_dir=plugin_bin,
            plans=DISPATCHER_SMOKE_COMMANDS,
            cwd=project,
            env=env,
            timeout=timeout,
        )


def _npm_pack_tarball(
    npm: str,
    *,
    package_root: Path,
    pack_dir: Path,
    environment: dict[str, str],
    timeout: float,
) -> Path:
    before = set(pack_dir.iterdir())
    pack = run_bounded_command(
        [npm, "pack", "--json", "--offline", "--ignore-scripts", "--no-audit", "--fund=false", "--pack-destination", str(pack_dir)],
        cwd=package_root,
        env=environment,
        timeout=timeout,
    )
    if pack.timed_out:
        fail(f"npm pack timed out after {timeout:g}s")
    if pack.output_truncated:
        fail("npm pack output exceeded smoke bounds")
    if pack.proc.returncode != 0:
        fail(f"npm pack exited {pack.proc.returncode}: {(pack.proc.stderr or pack.proc.stdout).strip()[:500]}")
    try:
        parsed = json.loads(pack.proc.stdout)
        filename = parsed[0]["filename"]
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        fail(f"npm pack did not emit one valid package object: {exc.__class__.__name__}")
    if not isinstance(parsed, list) or len(parsed) != 1 or not isinstance(filename, str) or Path(filename).name != filename:
        fail("npm pack JSON contains an unsafe package filename")
    tarball = pack_dir / filename
    if set(pack_dir.iterdir()) - before != {tarball} or not tarball.is_file() or tarball.is_symlink():
        fail("npm pack produced an unexpected artifact set")
    return tarball


def run_npm_package_smoke(
    timeout: float,
    *,
    root_tarball: Path | None = None,
    receipt_tarball: Path | None = None,
) -> None:
    if not NPM_PACKAGE_JSON.is_file():
        print("npm package smoke: skipped (package.json not found)")
        return
    npm = trusted_which("npm")
    if npm is None:
        if running_in_ci():
            fail("npm package smoke requires npm in CI; ensure actions/setup-node ran before release gates")
        print("npm package smoke: skipped (npm not found)")
        return
    check_npm_package_lifecycle_scripts(NPM_PACKAGE_JSON)
    expected_version = npm_package_version(NPM_PACKAGE_JSON)
    with tempfile.TemporaryDirectory(prefix="context-guard-npm-smoke-") as td:
        root = Path(td)
        pack_dir = root / "pack"
        project = root / "project"
        home = root / "home"
        tmp = root / "tmp"
        install_prefix = root / "isolated-install"
        fake_bin = root / "fake-path-bin"
        pack_dir.mkdir()
        project.mkdir()
        mcp_project = root / "mcp-project"
        mcp_project.mkdir()
        home.mkdir()
        tmp.mkdir()
        write_fake_context_guard_shadow(fake_bin)
        env = smoke_environment(home, tmp)
        env["PATH"] = str(fake_bin) + os.pathsep + env.get("PATH", "")
        if (root_tarball is None) != (receipt_tarball is None):
            fail("exact candidate smoke requires both root and Receipt tarballs")
        if root_tarball is not None and receipt_tarball is not None:
            tarball, receipt_candidate = validate_candidate_tarball_pair(root_tarball, receipt_tarball)
        else:
            receipt_candidate = _npm_pack_tarball(
                npm,
                package_root=RECEIPT_PACKAGE_ROOT,
                pack_dir=pack_dir,
                environment=env,
                timeout=timeout,
            )
            tarball = _npm_pack_tarball(
                npm,
                package_root=ROOT,
                pack_dir=pack_dir,
                environment=env,
                timeout=timeout,
            )
            tarball, receipt_candidate = validate_candidate_tarball_pair(tarball, receipt_candidate)

        install = run_bounded_command(
            [
                npm,
                "install",
                "--offline",
                "--ignore-scripts",
                "--no-audit",
                "--fund=false",
                "--prefix",
                str(install_prefix),
                str(receipt_candidate),
                str(tarball),
            ],
            cwd=project,
            env=env,
            timeout=timeout,
        )
        if install.timed_out:
            fail(f"npm install isolated package smoke timed out after {timeout:g}s")
        if install.output_truncated:
            fail("npm install isolated package smoke output exceeded bounds")
        if install.proc.returncode != 0:
            fail(f"npm install isolated package smoke exited {install.proc.returncode}: {(install.proc.stderr or install.proc.stdout).strip()[:500]}")

        isolated_bin = install_prefix / "node_modules" / ".bin"
        package_root = install_prefix / "node_modules" / "@ictechgy" / "context-guard"
        context_guard = isolated_bin / "context-guard"
        if not context_guard.is_file():
            fail(f"isolated npm install missing context-guard bin: {context_guard}")
        require_path_inside(context_guard, install_prefix, label="context-guard npm bin")
        verify_installed_reference_adapter(
            package_root=package_root,
            project_root=install_prefix,
            context_guard=context_guard,
            env=env,
            timeout=timeout,
        )
        npm_mcp = isolated_bin / "context-guard-mcp"
        if not npm_mcp.is_file():
            fail("isolated npm install missing context-guard-mcp bin")
        run_mcp_namespace_smoke(
            npm_mcp, project=mcp_project, env=env, timeout=timeout,
            label="isolated npm", trusted_root=install_prefix,
        )

        run_command(
            entrypoint_launch_argv(context_guard, ["--help"], trusted_root=install_prefix),
            cwd=project,
            env=env,
            timeout=timeout,
            expect=lambda proc: (
                None
                if "  setup" in proc.stdout and "  experiments" in proc.stdout
                else fail("isolated context-guard --help did not include expected manifest-derived subcommands")
            ),
        )
        run_command(
            entrypoint_launch_argv(context_guard, ["--version"], trusted_root=install_prefix),
            cwd=project,
            env=env,
            timeout=timeout,
            expect=lambda proc: (
                None
                if proc.stdout.strip() == expected_version
                else fail(f"isolated context-guard --version emitted {proc.stdout.strip()!r}, expected {expected_version!r}")
            ),
        )
        run_command(
            entrypoint_launch_argv(
                context_guard,
                [
                "setup",
                "--root",
                str(project),
                "--agent",
                "codex",
                "--scope",
                "project",
                "--with-init",
                "--with-skill",
                "--plan",
                "--json",
                ],
                trusted_root=install_prefix,
            ),
            cwd=project,
            env=env,
            timeout=timeout,
            expect=lambda proc: (
                check_json_field(load_json(proc.stdout, "isolated npm context-guard setup"), "applied", False, "isolated npm context-guard setup")
            ),
        )
        run_command(
            entrypoint_launch_argv(
                context_guard,
                [
                "setup",
                "--root",
                str(project),
                "--agent",
                "codex",
                "--scope",
                "project",
                "--brief-mode",
                "lite",
                "--yes",
                "--no-diet-scan",
                "--json",
                ],
                trusted_root=install_prefix,
            ),
            cwd=project,
            env=env,
            timeout=timeout,
            expect=lambda proc: check_brief_mode_apply_smoke(
                proc,
                project,
                "isolated npm context-guard setup brief-mode apply",
            ),
        )
        run_quiet_narration_smoke(
            command=context_guard,
            project=root / "quiet-narration-project",
            cwd=project,
            env=env,
            timeout=timeout,
            dispatcher=True,
            trusted_root=install_prefix,
            label="isolated npm setup",
        )
        run_dispatcher_launch_smokes(
            bin_dir=isolated_bin,
            plans=npm_dispatcher_smoke_plan(),
            cwd=project,
            env=env,
            timeout=timeout,
            trusted_root=install_prefix,
            label_prefix="isolated npm ",
        )


def npm_dispatcher_smoke_plan() -> tuple[dict[str, Any], ...]:
    return DISPATCHER_SMOKE_COMMANDS


def launch_stdin(mode: str) -> str | None:
    if mode == "hook-json":
        return HOOK_STDIN
    if mode == "statusline":
        return STATUSLINE_STDIN
    return None


def check_launch_smoke(proc: subprocess.CompletedProcess[str], command: str, mode: str) -> None:
    raw_stdout = proc.stdout
    if not raw_stdout.strip():
        fail(f"{command} launch smoke emitted no stdout")
    if mode in {"hook-json", "json"}:
        load_json(raw_stdout, command)
    elif mode == "statusline":
        line = raw_stdout[:-1] if raw_stdout.endswith("\n") else raw_stdout
        if "\n" in line or "\r" in line:
            fail(f"{command} statusline smoke emitted multiple lines")
        if len(line) > STATUSLINE_MAX_CHARS:
            fail(f"{command} statusline smoke exceeded {STATUSLINE_MAX_CHARS} characters")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plugin-dir", type=Path, default=PLUGIN_DIR)
    parser.add_argument(
        "--plugin-bin",
        type=Path,
        default=None,
        help="test an already-staged plugin bin directory without package copy validation",
    )
    parser.add_argument(
        "--npm-root-tarball",
        type=Path,
        default=None,
        help="exercise this already-built root npm candidate without repacking it",
    )
    parser.add_argument(
        "--npm-receipt-tarball",
        type=Path,
        default=None,
        help="exact Receipt candidate paired with --npm-root-tarball",
    )
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()

    if args.timeout <= 0:
        fail("--timeout must be positive")
    if (args.npm_root_tarball is None) != (args.npm_receipt_tarball is None):
        parser.error("--npm-root-tarball and --npm-receipt-tarball must be supplied together")
    if args.plugin_bin is not None and args.npm_root_tarball is not None:
        parser.error("exact npm candidates cannot be combined with --plugin-bin")
    if args.plugin_bin is not None:
        run_smoke(args.plugin_bin, args.timeout)
    else:
        with tempfile.TemporaryDirectory(prefix="context-guard-package-smoke-") as td:
            staged = copy_plugin_package_for_smoke(args.plugin_dir, Path(td) / "context-guard")
            run_smoke(staged / "bin", args.timeout)
        run_npm_package_smoke(
            args.timeout,
            root_tarball=args.npm_root_tarball,
            receipt_tarball=args.npm_receipt_tarball,
        )
    print("release smoke: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
