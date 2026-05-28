#!/usr/bin/env python3
"""Claude Code PreToolUse hook: wrap noisy Bash commands.

Reads hook JSON from stdin and prints a JSON response understood by Claude Code.
Install via `.claude/settings.json` hooks. Keep this script project-local during
experiments so it can be versioned and reviewed.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sys

# Reject actual shell control operators after shlex tokenization. Quoted search
# patterns such as `rg "token|password"` and `grep "^foo$"` are safe to wrap,
# but real pipes, redirects, command substitutions, and sequencing are not.
SHELL_OPERATOR_TOKENS = {";", ";;", ";&", ";;&", "&", "&&", "|", "||", "<", ">", "<<", ">>", "<>", "(", ")"}
SHELL_OPERATOR_CHARS = frozenset(";&|<>()")
ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*")
WRAPPER_BASENAMES = frozenset({
    "trim_command_output.py",
    "claude-trim-output",
    "sanitize_output.py",
    "claude-sanitize-output",
})
FAIL_OPEN_ENV = "CLAUDE_TOKEN_SANITIZER_FAIL_OPEN"
FAIL_OPEN_VALUES = {"1", "true", "yes", "on"}
UNPARSEABLE_SANITIZER_RISK_RE = re.compile(
    r"(?i)(?:^|[\s;&|()])"
    r"(?:rg|grep|egrep|fgrep|journalctl|kubectl|oc|docker|podman|docker-compose|git|find)"
    r"(?:$|[\s;&|()])"
)

# kubectl/docker/podman/oc 글로벌 옵션 중 다음 토큰을 value로 소비하는 형태.
# `-n prod`, `--context=prod`, `-f file.yml` 같은 케이스를 hub로 흡수해
# `kubectl -n prod logs api`, `docker --context prod logs api`,
# `docker compose -f compose.yml logs web` 가 sanitize wrapper를 거치도록 한다.
_VALUE_TAKING_FLAGS = frozenset({
    "-n", "--namespace",
    "--context",
    "--kubeconfig",
    "--cluster",
    "--user", "--token",
    "--as", "--as-group",
    "-s", "--server",
    "-c",
    "-H", "--host",
    "--config",
    "--log-level",
    "-f", "--file",
    "-p", "--project-name",
})

# find 가 단순 path listing 이 아니라 임의 명령 출력을 발생시킬 수 있는 액션.
# 이 액션들은 .env / 자격증명 파일 내용까지 노출 가능하므로 trim 대신 sanitize 로 라우팅한다.
_FIND_OUTPUT_RISK_ACTIONS = frozenset({
    "-delete",
    "-exec", "-execdir",
    "-ok", "-okdir",
    "-fprint", "-fprint0", "-fprintf", "-fls",
})


def find_wrapper(kind: str) -> str | None:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if kind == "sanitize":
        candidates = [
            os.path.join(script_dir, "claude-sanitize-output"),
            os.path.join(script_dir, "sanitize_output.py"),
        ]
    else:
        candidates = [
            os.path.join(script_dir, "claude-trim-output"),
            os.path.join(script_dir, "trim_command_output.py"),
        ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def fail_open_enabled() -> bool:
    return os.environ.get(FAIL_OPEN_ENV, "").strip().lower() in FAIL_OPEN_VALUES


def print_noop() -> None:
    print("{}")


def deny(reason: str) -> None:
    print(f"claude-token-rewrite-bash: {reason}", file=sys.stderr)
    if fail_open_enabled():
        print(
            f"claude-token-rewrite-bash: {FAIL_OPEN_ENV}=1 active; leaving command unchanged intentionally",
            file=sys.stderr,
        )
        print_noop()
        return
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }, ensure_ascii=False))


def unparseable_command_needs_sanitizer(command: str) -> bool:
    """Return True for shell-compound commands likely to print secret-bearing output."""
    if not UNPARSEABLE_SANITIZER_RISK_RE.search(command):
        return False
    lowered = command.lower()
    if re.search(r"(?:^|[\s;&|()])(?:rg|grep|egrep|fgrep)(?:$|[\s;&|()])", lowered):
        return True
    if re.search(r"(?:^|[\s;&|()])(?:journalctl|kubectl|oc|docker|podman|docker-compose)(?:$|[\s;&|()])", lowered):
        return any(word in lowered for word in (" logs", " log ", "journalctl"))
    if re.search(r"(?:^|[\s;&|()])git(?:$|[\s;&|()])", lowered):
        return any(word in lowered for word in (" diff", " show", " grep", " log")) and (
            " diff" in lowered or " show" in lowered or " grep" in lowered or " -p" in lowered or " --patch" in lowered
        )
    if re.search(r"(?:^|[\s;&|()])find(?:$|[\s;&|()])", lowered):
        return any(action in lowered for action in (" -exec", " -execdir", " -ok", " -okdir", " -delete", " -fprint", " -fls"))
    return False


def split_single_safe_command(command: str) -> list[str] | None:
    if not command.strip():
        return None
    if any(char in command for char in "\n\r\t"):
        return None
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        argv = list(lexer)
    except ValueError:
        return None
    if not argv:
        return None
    for token in argv:
        if token in SHELL_OPERATOR_TOKENS or (
            any(char in SHELL_OPERATOR_CHARS for char in token)
            and all(char in SHELL_OPERATOR_CHARS for char in token)
        ):
            return None
        if any(char in token for char in "`\n\r\t"):
            return None
        if "$(" in token or "${" in token:
            return None
    return argv


def command_basename(command: str) -> str:
    return os.path.basename(command)


def strip_env_prefix(argv: list[str]) -> list[str]:
    """Return the executable argv after leading `KEY=VALUE` or `env` wrappers."""
    i = 0
    while i < len(argv) and ENV_ASSIGNMENT_RE.match(argv[i]):
        i += 1
    if i < len(argv) and argv[i] == "env":
        i += 1
        while i < len(argv):
            token = argv[i]
            if token in {"-i", "--ignore-environment"}:
                i += 1
                continue
            if token in {"-u", "--unset"} and i + 1 < len(argv):
                i += 2
                continue
            if token.startswith("-u") and token != "-u":
                i += 1
                continue
            if token.startswith("--unset="):
                i += 1
                continue
            if token.startswith("-"):
                i += 1
                continue
            if ENV_ASSIGNMENT_RE.match(token):
                i += 1
                continue
            break
    return argv[i:]


def npm_script_args(rest: list[str]) -> list[str]:
    value_options = {"--prefix", "--workspace", "-w", "--filter", "--cwd", "-C"}
    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg in value_options:
            i += 2
            continue
        if arg.startswith("-"):
            i += 1
            continue
        break
    return rest[i:]


def is_noisy_command(argv: list[str]) -> bool:
    argv = strip_env_prefix(argv)
    if not argv:
        return False
    first = command_basename(argv[0])
    rest = argv[1:]

    if first in {"npm", "pnpm", "yarn", "bun"}:
        script_args = npm_script_args(rest)
        if not script_args:
            return False
        command = script_args[0]
        if command == "test":
            return True
        if command in {"run", "run-script"} and len(script_args) > 1:
            script = script_args[1]
            return script == "build" or script == "lint" or script.startswith("test")
        return command in {"build", "lint"}
    if first in {"pytest", "tox", "jest", "vitest"}:
        return True
    if first == "npx" and any(arg in {"jest", "vitest"} for arg in rest):
        return True
    if re.fullmatch(r"python(?:\d+(?:\.\d+)?)?", first) and len(argv) > 2 and argv[1] == "-m" and argv[2] in {"pytest", "unittest"}:
        return True
    if first == "go" and "test" in rest:
        return True
    if first == "cargo" and "test" in rest:
        return True
    if first in {"mvn", "mvnw", "./mvnw"} and "test" in rest:
        return True
    if first in {"gradle", "gradlew", "./gradlew"} and "test" in rest:
        return True
    if first == "make" and any(arg in {"test", "build", "lint"} for arg in rest):
        return True
    return False


def _skip_leading_flags(rest: list[str]) -> list[str]:
    """rest 의 앞쪽 `-`/`--` 플래그(와 value-taking 플래그의 다음 토큰)를 건너뛴다.

    value-taking flag 목록(`_VALUE_TAKING_FLAGS`)에 들지 않은 `-`-시작 토큰은 boolean
    이라고 가정한다. 알 수 없는 value flag 는 매칭 누락으로 이어지지만, 그래도
    upper layer 가 미가공 명령으로 떨어뜨리는 안전한 degrade 이므로 보수적으로 처리.
    """
    i = 0
    while i < len(rest):
        token = rest[i]
        if not token.startswith("-"):
            break
        if "=" in token:
            i += 1
            continue
        if token in _VALUE_TAKING_FLAGS and i + 1 < len(rest):
            i += 2
        else:
            i += 1
    return rest[i:]


def is_dir_traversal_command(argv: list[str]) -> bool:
    """순수 path-listing 형태의 `find` / `tree` 만 trim wrapper 라우팅 대상.

    `find` 가 `-exec` / `-delete` / `-fprint*` 등 임의 명령 출력을 만들어내는 액션을
    포함하면 `.env` 같은 자격증명 내용을 흘릴 수 있으므로 본 함수는 False 를 반환하고,
    `is_log_streaming_command` 가 sanitize 라우팅으로 대신 잡는다. `tree` 는 본질적으로
    출력 형식이 fixed 이라 별도 분기가 없다.
    """
    argv = strip_env_prefix(argv)
    if not argv:
        return False
    first = command_basename(argv[0])
    rest = argv[1:]
    if first == "tree":
        return True
    if first == "find":
        return not any(arg in _FIND_OUTPUT_RISK_ACTIONS for arg in rest)
    if first == "fd":
        return True
    if first == "rg" and any(arg == "--files" for arg in rest):
        return True
    return False


def is_log_streaming_command(argv: list[str]) -> bool:
    """Production 로그 스트림 / 자격증명을 흘릴 수 있는 명령은 sanitize wrapper 로 라우팅.

    대상:
    - `kubectl logs` / `oc logs` / `podman logs`
    - `docker logs` / `docker compose logs` / `docker stack logs` / `podman compose|stack logs`
    - `docker-compose logs` (v1)
    - `journalctl` (systemd 로그, secret bearing 가능)
    - `find` 가 `-exec` / `-delete` / `-fprint` 같은 임의 출력 액션을 포함하는 형태

    글로벌 옵션 (`-n prod`, `--context=stage`, `-f compose.yml`) 도 `_skip_leading_flags`
    로 흡수한다. 한계: `kubectl exec ... -- cat /var/log/...` 같은 우회는 별도 룰이
    필요하며 여기서는 처리하지 않는다.
    """
    argv = strip_env_prefix(argv)
    if not argv:
        return False
    first = command_basename(argv[0])
    rest = argv[1:]

    if first == "journalctl":
        return True
    if first == "find" and any(arg in _FIND_OUTPUT_RISK_ACTIONS for arg in rest):
        return True
    if first in {"kubectl", "oc"}:
        rest = _skip_leading_flags(rest)
        return bool(rest) and rest[0] == "logs"
    if first == "docker-compose":
        rest = _skip_leading_flags(rest)
        return bool(rest) and rest[0] == "logs"
    if first in {"docker", "podman"}:
        rest = _skip_leading_flags(rest)
        if not rest:
            return False
        sub = rest[0]
        if sub == "logs":
            return True
        if sub in {"compose", "stack"}:
            rest = _skip_leading_flags(rest[1:])
            return bool(rest) and rest[0] == "logs"
    return False


def is_already_wrapped(argv: list[str]) -> bool:
    """argv 가 이미 trim/sanitize wrapper 호출이면 True.

    bare 호출 (`claude-trim-output ...`), python wrapper 호출
    (`python3 .../trim_command_output.py ...`), 절대경로 호출 모두 흡수한다.
    명령 raw 문자열에 substring 검색을 하면 컨테이너 이름이 우연히
    `claude-sanitize-output` 같으면 false-bypass 되므로 argv 기반으로 판단한다.
    """
    argv = strip_env_prefix(argv)
    if not argv:
        return False
    head = argv[0]
    if re.fullmatch(r"python(?:\d+(?:\.\d+)?)?", os.path.basename(head)) and len(argv) > 1:
        head = argv[1]
    return os.path.basename(head) in WRAPPER_BASENAMES


def is_sanitizable_output_command(argv: list[str]) -> bool:
    argv = strip_env_prefix(argv)
    if not argv:
        return False
    first = command_basename(argv[0])
    rest = argv[1:]

    if first in {"rg", "grep", "egrep", "fgrep"}:
        # `rg --files` is path listing rather than content search; the large
        # read/diet guards are better fits there.
        return not any(arg == "--files" for arg in rest)
    if first == "git" and rest:
        rest = git_subcommand_args(rest)
        if not rest:
            return False
        subcommand = rest[0]
        if subcommand == "grep":
            return True
        if subcommand in {"diff", "show"}:
            return True
        if subcommand == "log" and any(arg == "-p" or arg.startswith("--patch") for arg in rest[1:]):
            return True
    return False


def git_subcommand_args(rest: list[str]) -> list[str]:
    value_options = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"}
    i = 0
    while i < len(rest):
        token = rest[i]
        if token == "--":
            return rest[i + 1:]
        if token in value_options and i + 1 < len(rest):
            i += 2
            continue
        if any(token.startswith(prefix + "=") for prefix in value_options if prefix.startswith("--")):
            i += 1
            continue
        if token in {"--no-pager", "--paginate", "--bare", "--literal-pathspecs", "--no-optional-locks"}:
            i += 1
            continue
        if token.startswith("-"):
            i += 1
            continue
        break
    return rest[i:]


def build_wrapped_command(wrapper: str, command: str) -> str:
    if wrapper.endswith(".py"):
        prefix = ["python3", wrapper]
    else:
        prefix = [wrapper]
    wrapped_argv = prefix + ["--max-lines", "220", "--", "bash", "-lc", command]
    return shlex.join(wrapped_argv)


def build_sanitized_command(wrapper: str, command: str) -> str:
    if wrapper.endswith(".py"):
        prefix = ["python3", wrapper]
    else:
        prefix = [wrapper]
    wrapped_argv = prefix + ["--max-lines", "220", "--", "bash", "-lc", command]
    return shlex.join(wrapped_argv)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(f"claude-token-rewrite-bash: invalid hook JSON: {exc}", file=sys.stderr)
        print("{}")
        return 0

    if not isinstance(payload, dict):
        print("{}")
        return 0
    tool_input = payload.get("tool_input") or payload.get("toolInput") or {}
    if not isinstance(tool_input, dict):
        print("{}")
        return 0
    command = tool_input.get("command") or ""

    if not command:
        print("{}")
        return 0

    argv = split_single_safe_command(command)
    if not argv:
        if unparseable_command_needs_sanitizer(command):
            deny(
                "Search/diff/log command contains shell operators that cannot be safely rewritten. "
                "Run the command through claude-sanitize-output explicitly, simplify it, or set "
                f"{FAIL_OPEN_ENV}=1 to run unsanitized intentionally."
            )
            return 0
        print_noop()
        return 0

    # argv 기반으로 이미 wrap 된 명령인지 검사한다. 단순 substring 매칭은 컨테이너명 등이
    # 우연히 wrapper 이름과 일치할 때 false-bypass 를 일으킬 수 있다.
    if is_already_wrapped(argv):
        print("{}")
        return 0

    if is_noisy_command(argv) or is_dir_traversal_command(argv):
        wrapper = find_wrapper("trim")
        if wrapper is None:
            deny(
                "Noisy command blocked because claude-trim-output is not installed next to "
                "claude-token-rewrite-bash. Install the trim wrapper or set "
                f"{FAIL_OPEN_ENV}=1 to run untrimmed intentionally."
            )
            return 0
        wrapped = build_wrapped_command(wrapper, command)
    elif is_sanitizable_output_command(argv) or is_log_streaming_command(argv):
        wrapper = find_wrapper("sanitize")
        if wrapper is None:
            reason = (
                "Search/diff command blocked because claude-sanitize-output is not installed next to "
                "claude-token-rewrite-bash. Install the sanitizer or set "
                f"{FAIL_OPEN_ENV}=1 to run unsanitized intentionally."
            )
            deny(reason)
            return 0
        wrapped = build_sanitized_command(wrapper, command)
    else:
        print("{}")
        return 0

    response = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "updatedInput": {"command": wrapped},
        }
    }
    print(json.dumps(response, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
