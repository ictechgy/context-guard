#!/usr/bin/env python3
"""Dependency-free smoke gate for the packaged ContextGuard plugin."""
from __future__ import annotations

import argparse
import json
import os
import queue
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, NamedTuple, NoReturn


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_DIR = ROOT / "plugins" / "context-guard"
PLUGIN_BIN = ROOT / "plugins" / "context-guard" / "bin"
MAX_COMMAND_MANIFEST_BYTES = 128 * 1024
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


def manifest_open_flags() -> int | None:
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


def read_manifest_source(path: Path) -> str | None:
    flags = manifest_open_flags()
    if flags is None:
        return None
    fd = -1
    try:
        fd = os.open(path, flags)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_COMMAND_MANIFEST_BYTES:
            return None
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(64 * 1024, MAX_COMMAND_MANIFEST_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_COMMAND_MANIFEST_BYTES:
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


def load_command_manifest():
    manifest_path = ROOT / "context-guard-kit" / "context_guard_commands.py"
    source = read_manifest_source(manifest_path)
    if source is None:
        raise SystemExit(f"could not load trusted command manifest source: {manifest_path}")
    namespace: dict[str, object] = {}
    try:
        exec(compile(source, str(manifest_path), "exec"), namespace)
    except Exception as exc:
        raise SystemExit(f"could not execute trusted command manifest source: {manifest_path}: {exc}") from exc
    return type("CommandManifest", (), namespace)


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
        if root.is_dir() and root not in roots:
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
    files = {path.name for path in plugin_bin.iterdir() if path.is_file()}
    unexpected = sorted(files - set(ENTRYPOINT_SMOKE_COMMANDS))
    if unexpected:
        fail(f"release smoke has no launch plan for plugin entrypoints: {', '.join(unexpected)}")
    missing = sorted(set(ENTRYPOINT_SMOKE_COMMANDS) - files)
    if missing:
        fail(f"release smoke planned entrypoints are missing from plugin bin: {', '.join(missing)}")
    return {name: ENTRYPOINT_SMOKE_COMMANDS[name] for name in sorted(ENTRYPOINT_SMOKE_COMMANDS)}


def smoke_environment(home: Path, tmp: Path) -> dict[str, str]:
    env = {key: value for key in PRESERVED_ENV_KEYS if (value := os.environ.get(key))}
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
        (project / "smoke-pack.txt").write_text("context guard pack explain smoke\n", encoding="utf-8")
        env = smoke_environment(smoke_home, smoke_tmp)

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
        for name, plan in launch_plan.items():
            mode = str(plan["mode"])
            run_command(
                entrypoint_launch_argv(command_path(plugin_bin, name), list(plan["args"])),
                cwd=project,
                env=env,
                timeout=timeout,
                input_text=launch_stdin(mode),
                expect=lambda proc, command=name, launch_mode=mode: check_launch_smoke(proc, command, launch_mode),
            )
        for plan in DISPATCHER_SMOKE_COMMANDS:
            entrypoint = str(plan["entrypoint"])
            mode = str(plan["mode"])
            args = [str(arg) for arg in plan["args"]]
            command_label = " ".join([entrypoint, *args])
            run_command(
                entrypoint_launch_argv(command_path(plugin_bin, entrypoint), args),
                cwd=project,
                env=env,
                timeout=timeout,
                input_text=launch_stdin(mode),
                expect=lambda proc, command=command_label, launch_mode=mode: check_launch_smoke(proc, command, launch_mode),
            )


def run_npm_package_smoke(timeout: float) -> None:
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
        home.mkdir()
        tmp.mkdir()
        write_fake_context_guard_shadow(fake_bin)
        env = smoke_environment(home, tmp)
        env["PATH"] = str(fake_bin) + os.pathsep + env.get("PATH", "")
        pack = run_bounded_command(
            [npm, "pack", "--json", "--ignore-scripts", "--pack-destination", str(pack_dir)],
            cwd=ROOT,
            env=env,
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
        except json.JSONDecodeError as exc:
            fail(f"npm pack did not emit valid JSON: line {exc.lineno}: {exc.msg}")
        if not isinstance(parsed, list) or not parsed or not isinstance(parsed[0], dict):
            fail("npm pack JSON must contain one package object")
        filename = parsed[0].get("filename")
        if not isinstance(filename, str) or not filename:
            fail("npm pack JSON missing filename")
        tarball = pack_dir / filename
        if not tarball.is_file():
            fail(f"npm pack tarball missing: {tarball}")

        install = run_bounded_command(
            [
                npm,
                "install",
                "--ignore-scripts",
                "--no-audit",
                "--fund=false",
                "--prefix",
                str(install_prefix),
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
        context_guard = isolated_bin / "context-guard"
        if not context_guard.is_file():
            fail(f"isolated npm install missing context-guard bin: {context_guard}")
        require_path_inside(context_guard, install_prefix, label="context-guard npm bin")

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
        for plan in npm_dispatcher_smoke_plan():
            entrypoint = str(plan["entrypoint"])
            mode = str(plan["mode"])
            args = [str(arg) for arg in plan["args"]]
            entrypoint_path = isolated_bin / entrypoint
            if not entrypoint_path.is_file():
                fail(f"isolated npm install missing dispatcher bin: {entrypoint_path}")
            require_path_inside(entrypoint_path, install_prefix, label=f"{entrypoint} npm bin")
            command_label = " ".join(["isolated npm", entrypoint, *args])
            run_command(
                entrypoint_launch_argv(entrypoint_path, args, trusted_root=install_prefix),
                cwd=project,
                env=env,
                timeout=timeout,
                input_text=launch_stdin(mode),
                expect=lambda proc, command=command_label, launch_mode=mode: check_launch_smoke(proc, command, launch_mode),
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
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()

    if args.timeout <= 0:
        fail("--timeout must be positive")
    if args.plugin_bin is not None:
        run_smoke(args.plugin_bin, args.timeout)
    else:
        with tempfile.TemporaryDirectory(prefix="context-guard-package-smoke-") as td:
            staged = copy_plugin_package_for_smoke(args.plugin_dir, Path(td) / "context-guard")
            run_smoke(staged / "bin", args.timeout)
        run_npm_package_smoke(args.timeout)
    print("release smoke: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
