#!/usr/bin/env python3
"""Dependency-free smoke gate for the packaged Claude token optimizer plugin."""
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
PLUGIN_DIR = ROOT / "plugins" / "claude-token-optimizer"
PLUGIN_BIN = ROOT / "plugins" / "claude-token-optimizer" / "bin"
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
    "claude-token-setup",
    "claude-token-diet",
    "claude-token-audit",
)
ENTRYPOINT_SMOKE_COMMANDS: dict[str, dict[str, Any]] = {
    "claude-read-symbol": {"args": ["--help"], "mode": "text"},
    "claude-sanitize-output": {"args": ["--help"], "mode": "text"},
    "claude-token-artifact": {"args": ["--help"], "mode": "text"},
    "claude-token-audit": {"args": ["--help"], "mode": "text"},
    "claude-token-bench": {"args": ["--help"], "mode": "text"},
    "claude-token-diet": {"args": ["--help"], "mode": "text"},
    "claude-token-failed-nudge": {"args": [], "mode": "hook-json"},
    "claude-token-guard-read": {"args": [], "mode": "hook-json"},
    "claude-token-rewrite-bash": {"args": [], "mode": "hook-json"},
    "claude-token-setup": {"args": ["--help"], "mode": "text"},
    "claude-token-statusline": {"args": [], "mode": "statusline"},
    "claude-token-statusline-merged": {"args": [], "mode": "statusline"},
    "claude-trim-output": {"args": ["--help"], "mode": "text"},
}
HOOK_STDIN = "{}"
STATUSLINE_STDIN = json.dumps({"cwd": ".", "session_id": "release-smoke", "transcript_path": ""})
STATUSLINE_MAX_CHARS = 1_000
COMMAND_OUTPUT_MAX_BYTES = 64_000
COMMAND_READ_CHUNK_BYTES = 65_536
PROCESS_TERMINATE_GRACE_SECONDS = 2.0
PROCESS_SELECT_TIMEOUT_SECONDS = 0.05
PRESERVED_ENV_KEYS = (
    "PATH",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
)


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


def run_smoke(plugin_bin: Path, timeout: float) -> None:
    plugin_bin = plugin_bin.resolve()
    commands = {name: command_path(plugin_bin, name) for name in REQUIRED_COMMANDS}
    launch_plan = entrypoint_smoke_plan(plugin_bin)

    with tempfile.TemporaryDirectory(prefix="claude-token-release-smoke-") as td:
        project = Path(td) / "project"
        smoke_home = Path(td) / "home"
        smoke_tmp = Path(td) / "tmp"
        project.mkdir()
        smoke_home.mkdir()
        smoke_tmp.mkdir()
        (project / ".claude").mkdir()
        (project / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
        (project / "CLAUDE.md").write_text("Keep project context short.\n", encoding="utf-8")
        env = smoke_environment(smoke_home, smoke_tmp)

        run_command(
            [str(commands["claude-token-setup"]), "--root", str(project), "--plan", "--json"],
            cwd=project,
            env=env,
            timeout=timeout,
            expect=lambda proc: (
                check_json_field(load_json(proc.stdout, "claude-token-setup"), "applied", False, "claude-token-setup")
            ),
        )
        run_command(
            [str(commands["claude-token-diet"]), "scan", str(project), "--json"],
            cwd=project,
            env=env,
            timeout=timeout,
            expect=lambda proc: (
                check_json_field(load_json(proc.stdout, "claude-token-diet"), "tool", "claude-token-diet", "claude-token-diet")
            ),
        )
        run_command(
            [str(commands["claude-token-audit"]), str(project), "--json"],
            cwd=project,
            env=env,
            timeout=timeout,
            expect=lambda proc: (
                check_json_field(load_json(proc.stdout, "claude-token-audit"), "records", 1, "claude-token-audit")
            ),
        )
        for name, plan in launch_plan.items():
            mode = str(plan["mode"])
            run_command(
                [str(command_path(plugin_bin, name)), *plan["args"]],
                cwd=project,
                env=env,
                timeout=timeout,
                input_text=launch_stdin(mode),
                expect=lambda proc, command=name, launch_mode=mode: check_launch_smoke(proc, command, launch_mode),
            )


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
    if mode == "hook-json":
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
        with tempfile.TemporaryDirectory(prefix="claude-token-package-smoke-") as td:
            staged = copy_plugin_package_for_smoke(args.plugin_dir, Path(td) / "claude-token-optimizer")
            run_smoke(staged / "bin", args.timeout)
    print("release smoke: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
