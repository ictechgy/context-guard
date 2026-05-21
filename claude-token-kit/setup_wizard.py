#!/usr/bin/env python3
"""Interactive project setup for the Claude token optimizer plugin.

The wizard applies only project-local, opt-in settings. It can run interactively
in a terminal, or non-interactively with --yes/--plan for Claude Code skills and
CI tests.
"""
from __future__ import annotations

import argparse
import copy
import datetime as _dt
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SETTINGS_REL = Path(".claude/settings.json")
STATE_DIR_REL = Path(".claude-token-optimizer")
CONFIG_REL = STATE_DIR_REL / "config.json"

RECOMMENDED_DENIES = [
    "Read(./node_modules/**)",
    "Read(./dist/**)",
    "Read(./build/**)",
    "Read(./coverage/**)",
    "Read(./logs/**)",
    "Read(./tmp/**)",
    "Read(./target/**)",
    "Read(./.next/**)",
    "Read(./.venv/**)",
    "Read(./vendor/**)",
    "Read(./.claude-token-optimizer/**)",
    "Read(./.env)",
    "Read(./.env.*)",
    "Read(./.npmrc)",
    "Read(./.pypirc)",
    "Read(./.netrc)",
    "Read(~/.ssh/**)",
    "Read(~/.aws/**)",
    "Read(~/.gnupg/**)",
    "Read(~/.kube/**)",
    "Read(~/.docker/**)",
]
HELPER_STATUSLINE = "claude-token-statusline"
HELPER_REWRITE_BASH = "claude-token-rewrite-bash"
HELPER_GUARD_READ = "claude-token-guard-read"
HELPER_FAILED_NUDGE = "claude-token-failed-nudge"
DEFAULT_MODEL = "sonnet"
DEFAULT_EFFORT = "medium"
GIT_TRUST_CHECK_TIMEOUT_SECONDS = 2
ALLOWED_FIRST_ABSOLUTE_SYMLINKS = {
    "tmp": Path("/private/tmp"),
    "var": Path("/private/var"),
}


@dataclass
class Choices:
    denies: bool = True
    statusline: bool = True
    bash_hook: bool = True
    read_guard: bool = True
    model_defaults: bool = True
    aux_provider: str = "none"
    auto_delegate: bool = False
    # 동일 Bash 명령이 두 번 연속 실패하면 /clear 권유 — 새 기능이라 기본 OFF.
    failed_attempt_nudge: bool = False


@dataclass
class SetupResult:
    root: Path
    settings_path: Path
    changed: bool
    applied: bool
    choices: Choices
    actions: list[str]
    backup_path: Path | None = None
    aux_config_path: Path | None = None
    aux_backup_path: Path | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "settings_path": str(self.settings_path),
            "changed": self.changed,
            "applied": self.applied,
            "backup_path": str(self.backup_path) if self.backup_path else None,
            "aux_config_path": str(self.aux_config_path) if self.aux_config_path else None,
            "aux_backup_path": str(self.aux_backup_path) if self.aux_backup_path else None,
            "choices": self.choices.__dict__,
            "actions": self.actions,
        }


def find_project_root(start: Path | None = None) -> Path:
    current = (start or Path.cwd()).expanduser().resolve()
    if current.is_file():
        current = current.parent
    for candidate in [current, *current.parents]:
        if (candidate / ".git").exists():
            return candidate
    return current


def resolve_setup_root(raw_root: str | None) -> Path:
    if raw_root is None:
        return find_project_root()
    root = Path(raw_root).expanduser().resolve()
    return root.parent if root.is_file() else root


def validate_settings_target(root: Path, settings_path: Path, *, allow_home_settings: bool) -> None:
    root = root.resolve()
    home_settings = Path.home().expanduser().resolve() / SETTINGS_REL
    if settings_path.expanduser().resolve() == home_settings and not allow_home_settings:
        raise SystemExit(
            "Refusing to modify global ~/.claude/settings.json. Run from a project directory, "
            "pass --root <project>, or use --allow-home-settings if you intentionally want this."
        )
    claude_dir = root / ".claude"
    if claude_dir.exists() and claude_dir.is_symlink():
        raise SystemExit(f"Refusing to use symlinked Claude settings directory: {claude_dir}")
    if settings_path.exists() and settings_path.is_symlink():
        raise SystemExit(f"Refusing to write through symlinked settings file: {settings_path}")
    if claude_dir.exists():
        try:
            claude_dir.resolve().relative_to(root)
        except ValueError as exc:
            raise SystemExit(f"Claude settings directory resolves outside project root: {claude_dir}") from exc


def _base_open_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _no_follow_flag() -> int:
    if hasattr(os, "O_NOFOLLOW"):
        return os.O_NOFOLLOW
    raise OSError("platform does not support no-follow file opens")


def _directory_flag() -> int:
    return getattr(os, "O_DIRECTORY", 0)


def _normalized_link_target(parent: Path, raw_target: str) -> Path:
    target = Path(raw_target)
    if not target.is_absolute():
        target = parent / target
    return Path(os.path.normpath(str(target)))


def _normalize_allowed_first_absolute_symlink(path: Path) -> Path:
    """Rewrite narrow platform-owned absolute aliases before no-follow traversal."""
    if not path.is_absolute() or len(path.parts) < 2:
        return path
    first = path.parts[1]
    expected = ALLOWED_FIRST_ABSOLUTE_SYMLINKS.get(first)
    if expected is None:
        return path
    link = Path(path.anchor) / first
    try:
        if not stat.S_ISLNK(os.lstat(link).st_mode):
            return path
        if _normalized_link_target(Path(path.anchor), os.readlink(link)) != expected:
            return path
    except OSError:
        return path
    return expected.joinpath(*path.parts[2:])


def _open_directory_at(dir_fd: int, component: str, path: Path) -> int:
    flags = _base_open_flags() | _directory_flag() | _no_follow_flag()
    fd = os.open(component, flags, dir_fd=dir_fd)
    try:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(f"not a directory: {path}")
        return fd
    except Exception:
        os.close(fd)
        raise


def _open_regular_no_symlink(path: Path) -> int:
    if os.open not in os.supports_dir_fd:
        raise OSError("platform does not support directory-relative no-follow opens")
    path = _normalize_allowed_first_absolute_symlink(path)
    components = list(path.parts)
    if path.is_absolute() and components:
        components = components[1:]
    if not components:
        raise OSError(f"not a regular file: {path}")

    root = path.anchor if path.is_absolute() else "."
    dir_fd = os.open(root or ".", _base_open_flags() | _directory_flag())
    try:
        for component in components[:-1]:
            next_fd = _open_directory_at(dir_fd, component, path)
            os.close(dir_fd)
            dir_fd = next_fd

        fd = os.open(components[-1], _base_open_flags() | _no_follow_flag(), dir_fd=dir_fd)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError(f"not a regular file: {path}")
            return fd
        except Exception:
            os.close(fd)
            raise
    finally:
        os.close(dir_fd)


def _read_text_no_follow(path: Path) -> str:
    fd = _open_regular_no_symlink(path)
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            return handle.read()
    finally:
        if fd != -1:
            os.close(fd)


def load_json_object(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(_read_text_no_follow(path))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: line {exc.lineno}: {exc.msg}") from exc
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise SystemExit(f"Could not read {path} without following symlinks: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"Settings file must contain a JSON object: {path}")
    return data


def ensure_permissions(settings: dict[str, Any], actions: list[str]) -> None:
    permissions = settings.get("permissions")
    if permissions is None:
        permissions = {}
        settings["permissions"] = permissions
    if not isinstance(permissions, dict):
        raise SystemExit("Refusing to replace non-object settings.permissions; repair it manually first.")
    deny = permissions.get("deny")
    if deny is None:
        deny = []
        permissions["deny"] = deny
    if not isinstance(deny, list):
        raise SystemExit("Refusing to replace non-list settings.permissions.deny; repair it manually first.")
    added = 0
    for rule in RECOMMENDED_DENIES:
        if rule not in deny:
            deny.append(rule)
            added += 1
    if added:
        actions.append(f"added {added} permissions.deny rules for bulky/sensitive paths")


def command_values(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "command" and isinstance(item, str):
                found.append(item)
            found.extend(command_values(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(command_values(item))
    return found


def matcher_covers(existing: Any, desired: str) -> bool:
    if not isinstance(existing, str):
        return False
    parts = {part.strip().lower() for part in existing.split("|") if part.strip()}
    return not parts or "*" in parts or desired.lower() in parts


def helper_command(helper_name: str, kit_script: str, *, shell: str | None = None) -> str:
    """hook 에 기록할 단일 셸 명령 문자열을 반환한다.

    경로에 공백이나 셸 메타문자가 들어와도 안전하도록 모든 분기에서 `shlex.join` 으로
    quote 한다 (PATH 에서 찾은 bare helper name 만 quote 불필요).
    """
    script_dir = Path(__file__).resolve().parent
    colocated = script_dir / helper_name
    if colocated.exists() and os.access(colocated, os.X_OK):
        return shlex.join([str(colocated)])
    repo_plugin = script_dir.parent / "plugins" / "claude-token-optimizer" / "bin" / helper_name
    if repo_plugin.exists() and os.access(repo_plugin, os.X_OK):
        return shlex.join([str(repo_plugin)])
    kit_path = script_dir / kit_script
    if kit_path.exists():
        prefix = [shell] if shell else [sys.executable]
        return shlex.join([*prefix, str(kit_path)])
    found = shutil.which(helper_name)
    if found:
        return helper_name
    return helper_name


def statusline_setting() -> dict[str, str]:
    return {"type": "command", "command": helper_command(HELPER_STATUSLINE, "statusline.sh", shell="bash")}


def bash_hook_setting() -> dict[str, Any]:
    return {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": helper_command(HELPER_REWRITE_BASH, "rewrite_bash_for_token_budget.py")}],
    }


def read_hook_setting() -> dict[str, Any]:
    return {
        "matcher": "Read",
        "hooks": [{"type": "command", "command": helper_command(HELPER_GUARD_READ, "guard_large_read.py")}],
    }


def failed_nudge_setting() -> dict[str, Any]:
    return {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": helper_command(HELPER_FAILED_NUDGE, "failed_attempt_nudge.py")}],
    }


def command_matches(existing: str, desired: str) -> bool:
    if existing == desired:
        return True
    existing_parts = shlex.split(existing) if existing else []
    desired_parts = shlex.split(desired) if desired else []
    if not existing_parts or not desired_parts:
        return False
    return Path(existing_parts[-1]).name == Path(desired_parts[-1]).name


def has_hook_command(pre_tool_use: list[Any], matcher: str, command: str) -> bool:
    for entry in pre_tool_use:
        if not isinstance(entry, dict) or not matcher_covers(entry.get("matcher"), matcher):
            continue
        if any(command_matches(value, command) for value in command_values(entry)):
            return True
    return False


def ensure_pre_tool_hook(settings: dict[str, Any], hook: dict[str, Any], command: str, label: str, actions: list[str]) -> None:
    _ensure_tool_hook(settings, hook, command, label, actions, event="PreToolUse")


def ensure_post_tool_hook(settings: dict[str, Any], hook: dict[str, Any], command: str, label: str, actions: list[str]) -> None:
    _ensure_tool_hook(settings, hook, command, label, actions, event="PostToolUse")


def _ensure_tool_hook(
    settings: dict[str, Any],
    hook: dict[str, Any],
    command: str,
    label: str,
    actions: list[str],
    *,
    event: str,
) -> None:
    hooks = settings.get("hooks")
    if hooks is None:
        hooks = {}
        settings["hooks"] = hooks
    if not isinstance(hooks, dict):
        raise SystemExit("Refusing to replace non-object settings.hooks; repair it manually first.")
    bucket = hooks.get(event)
    if bucket is None:
        bucket = []
        hooks[event] = bucket
    if not isinstance(bucket, list):
        raise SystemExit(f"Refusing to replace non-list settings.hooks.{event}; repair it manually first.")
    matcher = str(hook.get("matcher") or "")
    if has_hook_command(bucket, matcher, command):
        return
    bucket.append(copy.deepcopy(hook))
    actions.append(f"enabled {label} hook via {command}")


def apply_choices(settings: dict[str, Any], choices: Choices) -> list[str]:
    actions: list[str] = []
    if choices.model_defaults:
        if not settings.get("model"):
            settings["model"] = DEFAULT_MODEL
            actions.append(f"set default model to {DEFAULT_MODEL}")
        if not settings.get("effortLevel"):
            settings["effortLevel"] = DEFAULT_EFFORT
            actions.append(f"set default effortLevel to {DEFAULT_EFFORT}")
    if choices.statusline:
        statusline = statusline_setting()
        if "statusLine" not in settings:
            settings["statusLine"] = statusline
            actions.append("enabled token statusline")
        elif settings.get("statusLine") != statusline:
            actions.append("kept existing statusLine; add claude-token-statusline manually if desired")
    if choices.denies:
        ensure_permissions(settings, actions)
    if choices.bash_hook:
        bash_hook = bash_hook_setting()
        bash_command = bash_hook["hooks"][0]["command"]
        ensure_pre_tool_hook(settings, bash_hook, bash_command, "Bash trim/sanitize", actions)
    if choices.read_guard:
        read_hook = read_hook_setting()
        read_command = read_hook["hooks"][0]["command"]
        ensure_pre_tool_hook(settings, read_hook, read_command, "large Read guard", actions)
    if choices.failed_attempt_nudge:
        nudge_hook = failed_nudge_setting()
        nudge_command = nudge_hook["hooks"][0]["command"]
        ensure_post_tool_hook(settings, nudge_hook, nudge_command, "failed-attempt /clear nudge", actions)
    return actions


def ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        # owner-only directory access — 디렉터리에 자격증명/세션 상태가 들어갈 수 있어
        # 의도적으로 가장 좁은 권한을 적용한다.
        os.chmod(path, stat.S_IRWXU)
    except OSError:
        pass


def atomic_write(path: Path, text: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    fd = os.open(tmp, flags, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = -1
            f.write(text)
        os.replace(tmp, path)
        os.chmod(path, mode)
    finally:
        if fd != -1:
            os.close(fd)
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def write_private_gitignore(state_dir: Path) -> None:
    ensure_private_dir(state_dir)
    atomic_write(state_dir / ".gitignore", "*\n!.gitignore\n", 0o600)


def existing_mode_or_default(path: Path, default: int = 0o600) -> int:
    if not path.exists():
        return default
    return os.stat(path, follow_symlinks=False).st_mode & 0o777


def load_aux_config(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(_read_text_no_follow(path))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: line {exc.lineno}: {exc.msg}") from exc
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise SystemExit(f"Could not read {path} without following symlinks: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"Auxiliary config must contain a JSON object: {path}")
    return data


class GitTrustCheckTimeout(RuntimeError):
    pass


def run_git_trust_check(args: list[str]) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            args,
            text=True,
            capture_output=True,
            check=False,
            timeout=GIT_TRUST_CHECK_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitTrustCheckTimeout("git trust check timed out") from exc
    except OSError:
        return None


def git_root_for(path: Path) -> Path | None:
    proc = run_git_trust_check(
        ["git", "-C", str(path if path.is_dir() else path.parent), "rev-parse", "--show-toplevel"]
    )
    if proc is None:
        return None
    if proc.returncode != 0:
        return None
    root = proc.stdout.strip()
    return Path(root).resolve() if root else None


def is_git_tracked(path: Path) -> bool:
    root = git_root_for(path)
    if root is None:
        return False
    try:
        rel = path.resolve().relative_to(root)
    except ValueError:
        return False
    proc = run_git_trust_check(
        ["git", "-C", str(root), "ls-files", "--error-unmatch", "--", str(rel)],
    )
    if proc is None:
        return False
    return proc.returncode == 0


def has_private_file_mode(path: Path) -> bool:
    try:
        st = path.stat()
    except OSError:
        return False
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        return False
    return stat.S_IMODE(st.st_mode) & 0o077 == 0


def aux_config_trust_error(path: Path) -> str | None:
    if not path.exists():
        return None
    try:
        if is_git_tracked(path):
            return f"tracked by git: {path}"
    except GitTrustCheckTimeout:
        return f"git tracking check timed out: {path}"
    if not has_private_file_mode(path):
        return f"not owner-only 0600: {path}"
    return None


def write_aux_config(
    root: Path,
    provider: str,
    actions: list[str],
    *,
    auto_delegate: bool,
    dry_run: bool,
    backup: bool,
) -> tuple[Path | None, Path | None]:
    if provider == "none":
        return None, None
    config_path = root / CONFIG_REL
    actions.append(f"enabled auxiliary AI delegation default_provider={provider}")
    if auto_delegate:
        actions.append("enabled automatic safe delegation for plugin skills")
    trust_error = aux_config_trust_error(config_path)
    if trust_error:
        actions.append(f"reset untrusted auxiliary config instead of preserving it ({trust_error})")
    if dry_run:
        return config_path, None
    if config_path.parent.exists() and config_path.parent.is_symlink():
        raise SystemExit(f"Refusing to use symlinked optimizer state directory: {config_path.parent}")
    if config_path.is_symlink():
        raise SystemExit(f"Refusing to write through symlinked auxiliary config: {config_path}")
    write_private_gitignore(config_path.parent)
    if trust_error:
        config: dict[str, Any] = {}
    else:
        config = load_aux_config(config_path)
    policy = config.get("context_policy")
    if policy is None:
        config["context_policy"] = {"allow_sensitive_paths": [], "allow_outside_project_paths": []}
    elif not isinstance(policy, dict):
        raise SystemExit("Refusing to replace non-object aux context_policy; repair it manually first.")
    config["aux_ai_enabled"] = True
    config["default_provider"] = provider
    config["auto_delegate_enabled"] = bool(auto_delegate)
    if auto_delegate:
        config["auto_delegate_provider"] = provider
    else:
        config.pop("auto_delegate_provider", None)
    backup_path = backup_existing(config_path) if backup else None
    atomic_write(config_path, json.dumps(config, indent=2, sort_keys=True) + "\n", 0o600)
    return config_path, backup_path


def backup_existing(path: Path) -> Path | None:
    if not path.exists():
        return None
    stamp = _dt.datetime.now().strftime("%Y%m%d%H%M%S%f")
    backup = path.with_name(f"{path.name}.bak-{stamp}-{uuid.uuid4().hex[:8]}")
    shutil.copy2(path, backup)
    return backup


def prompt_bool(question: str, default: bool) -> bool:
    suffix = "Y/n" if default else "y/N"
    while True:
        answer = input(f"{question} [{suffix}] ").strip().lower()
        if not answer:
            return default
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        print("Please answer y or n.")


def prompt_provider() -> str:
    while True:
        answer = input("Auxiliary AI provider [gemini/codex, default gemini] ").strip().lower()
        if not answer:
            return "gemini"
        if answer in {"gemini", "codex"}:
            return answer
        print("Please choose gemini or codex.")


def interactive_choices(defaults: Choices) -> Choices:
    print("Claude Token Optimizer setup wizard")
    print("Project-local changes only. Existing settings are merged, not replaced.\n")
    choices = Choices(
        denies=prompt_bool("Add deny rules for bulky/sensitive paths?", defaults.denies),
        statusline=prompt_bool("Enable token/cost statusline?", defaults.statusline),
        bash_hook=prompt_bool("Enable Bash output trim + grep/diff sanitizer hook?", defaults.bash_hook),
        read_guard=prompt_bool("Enable large Read guard?", defaults.read_guard),
        model_defaults=prompt_bool("Set missing defaults to model=sonnet and effortLevel=medium?", defaults.model_defaults),
        aux_provider="none",
        failed_attempt_nudge=prompt_bool(
            "Enable failed-attempt /clear nudge? (PostToolUse hook on Bash; off by default)",
            defaults.failed_attempt_nudge,
        ),
    )
    if prompt_bool("Enable auxiliary AI delegation now? This may send selected context to Gemini/Codex.", False):
        choices.aux_provider = prompt_provider()
        choices.auto_delegate = prompt_bool(
            "Allow plugin skills to auto-delegate safe read-only project context when it saves Claude tokens?",
            False,
        )
    return choices


def choices_from_args(args: argparse.Namespace) -> Choices:
    return Choices(
        denies=not args.no_denies,
        statusline=not args.no_statusline,
        bash_hook=not args.no_bash_hook,
        read_guard=not args.no_read_guard,
        model_defaults=not args.no_model_defaults,
        aux_provider=args.aux_provider,
        auto_delegate=args.auto_delegate,
        failed_attempt_nudge=args.failed_attempt_nudge,
    )


def render_text(result: SetupResult) -> str:
    mode = "applied" if result.applied else "plan only"
    lines = [
        f"Claude Token Optimizer setup ({mode})",
        f"root={result.root}",
        f"settings={result.settings_path}",
    ]
    if result.backup_path:
        lines.append(f"backup={result.backup_path}")
    if result.aux_config_path:
        lines.append(f"aux_config={result.aux_config_path}")
    lines.append("actions:")
    if result.actions:
        lines.extend(f"- {action}" for action in result.actions)
    else:
        lines.append("- no settings changes needed")
    if not result.applied:
        lines.append("Run with --yes to apply the selected plan non-interactively.")
    return "\n".join(lines) + "\n"


def run(args: argparse.Namespace) -> SetupResult:
    root = resolve_setup_root(args.root)
    settings_path = root / SETTINGS_REL
    validate_settings_target(root, settings_path, allow_home_settings=args.allow_home_settings)
    original = load_json_object(settings_path)
    settings = json.loads(json.dumps(original))

    choices = choices_from_args(args)
    interactive = sys.stdin.isatty() and not args.yes and not args.plan and not args.dry_run
    if interactive:
        choices = interactive_choices(choices)
    if choices.auto_delegate and choices.aux_provider == "none":
        raise SystemExit("--auto-delegate requires --aux-provider gemini|codex")

    actions = apply_choices(settings, choices)
    aux_actions: list[str] = []
    aux_path, aux_backup_path = write_aux_config(
        root,
        choices.aux_provider,
        aux_actions,
        auto_delegate=choices.auto_delegate,
        dry_run=True,
        backup=False,
    )
    actions.extend(aux_actions)
    changed = settings != original or choices.aux_provider != "none"

    applied = bool(args.yes and not args.dry_run and not args.plan)
    if interactive and changed:
        preview = SetupResult(root, settings_path, changed, False, choices, actions, aux_config_path=aux_path)
        print("\n" + render_text(preview))
        applied = prompt_bool("Apply these project-local changes now?", True)

    backup_path = None
    if applied and changed:
        if settings_path.exists() and not args.no_backup and settings != original:
            backup_path = backup_existing(settings_path)
        if settings != original:
            atomic_write(
                settings_path,
                json.dumps(settings, indent=2, sort_keys=False) + "\n",
                existing_mode_or_default(settings_path, 0o600),
            )
        aux_path, aux_backup_path = write_aux_config(
            root,
            choices.aux_provider,
            [],
            auto_delegate=choices.auto_delegate,
            dry_run=False,
            backup=not args.no_backup,
        )

    return SetupResult(root, settings_path, changed, applied, choices, actions, backup_path, aux_path, aux_backup_path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Interactively configure Claude token optimizer project settings.")
    parser.add_argument("--root", default=None, help="project root to configure (default: nearest git root, else current directory)")
    parser.add_argument(
        "--allow-home-settings",
        action="store_true",
        help="allow writing ~/.claude/settings.json; off by default to keep setup project-local",
    )
    parser.add_argument("--yes", action="store_true", help="apply the recommended/selected setup without prompts")
    parser.add_argument("--plan", action="store_true", help="show the setup plan without writing files")
    parser.add_argument("--dry-run", action="store_true", help="alias for --plan")
    parser.add_argument("--json", action="store_true", help="print machine-readable result")
    parser.add_argument("--no-backup", action="store_true", help="do not create .bak-* before modifying existing settings")
    parser.add_argument("--no-denies", action="store_true", help="skip recommended permissions.deny rules")
    parser.add_argument("--no-statusline", action="store_true", help="skip token statusline")
    parser.add_argument("--no-bash-hook", action="store_true", help="skip Bash trim/sanitize hook")
    parser.add_argument("--no-read-guard", action="store_true", help="skip large Read guard hook")
    parser.add_argument("--no-model-defaults", action="store_true", help="skip model/effort defaults")
    parser.add_argument(
        "--aux-provider",
        choices=["none", "gemini", "codex"],
        default="none",
        help="optionally enable auxiliary AI delegation with this default provider",
    )
    parser.add_argument(
        "--auto-delegate",
        action="store_true",
        help="also allow enabled plugin skills to auto-delegate safe read-only context; requires --aux-provider",
    )
    parser.add_argument(
        "--failed-attempt-nudge",
        action="store_true",
        help="enable PostToolUse Bash hook that suggests /clear when the same command fails twice in a row (off by default)",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.dry_run:
        args.plan = True
    # Safety default for non-interactive Claude Code Bash calls: do not write
    # unless --yes is explicit.
    if not sys.stdin.isatty() and not args.yes:
        args.plan = True
    result = run(args)
    if args.json:
        print(json.dumps(result.as_dict(), indent=2, sort_keys=True))
    else:
        print(render_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
