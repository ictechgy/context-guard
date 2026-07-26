#!/usr/bin/env python3
"""Claude Code PreToolUse hook: wrap noisy Bash commands.

Reads hook JSON from stdin and prints a JSON response understood by Claude Code.
Install via `.claude/settings.json` hooks. Keep this script project-local during
experiments so it can be versioned and reviewed.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
import json
import os
import re
import sys

ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*")
WRAPPER_BASENAMES = frozenset({
    "trim_command_output.py",
    "context-guard-trim-output",
    "claude-trim-output",
    "sanitize_output.py",
    "context-guard-sanitize-output",
    "claude-sanitize-output",
})
MINISHELL_ROUTE_POLICY_VERSION = "minishell-route-v1"
MINISHELL_MAX_COMMAND_BYTES = 65_536
MINISHELL_MAX_LEXICAL_ITEMS = 4_096
MINISHELL_MAX_SEGMENTS = 8
MINISHELL_MAX_WORDS_PER_SEGMENT = 256
MINISHELL_MAX_HEREDOC_DELIMITER_BYTES = 64
MINISHELL_DENIED_ACTIVE_CHARS = frozenset(";&>()`*?[]{}")
MINISHELL_DENIED_COMMAND_WORDS = frozenset({
    "!",
    "case",
    "coproc",
    "do",
    "done",
    "elif",
    "else",
    "esac",
    "fi",
    "for",
    "function",
    "if",
    "in",
    "select",
    "then",
    "time",
    "until",
    "while",
})
MINISHELL_DENIED_COMMAND_BASENAMES = frozenset({
    "curl",
    "eval",
    "exec",
    "fetch",
    "ftp",
    "nc",
    "ncat",
    "netcat",
    "scp",
    "sftp",
    "socat",
    "ssh",
    "tee",
    "telnet",
    "wget",
})
MINISHELL_DENIED_SHELL_BASENAMES = frozenset({
    "bash",
    "dash",
    "fish",
    "ksh",
    "sh",
    "zsh",
})
MINISHELL_HEREDOC_STDIN_CONSUMERS = frozenset({
    "cut",
    "sed",
    "sort",
    "uniq",
    "wc",
})
MINISHELL_HEREDOC_DELIMITER_RE = re.compile(r"^[A-Za-z0-9_]+$")
CGW1_MAX_LINES = "220"
CGW1_SHELL_ARGV = ("bash", "-lc")
CGW1_SENTINEL = "--context-guard-wrapper-v1"
CGW1_COMMAND_SEARCH_DIFF = "command_search_diff"
FAIL_OPEN_ENV = "CONTEXT_GUARD_SANITIZER_FAIL_OPEN"
LEGACY_FAIL_OPEN_ENV = "CLAUDE_TOKEN_SANITIZER_FAIL_OPEN"
FAIL_OPEN_VALUES = {"1", "true", "yes", "on"}
MAX_HOOK_ENVELOPE_BYTES = 1_048_576
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


@dataclass(frozen=True)
class MiniShellWord:
    value: str
    source_value: str
    active: tuple[bool, ...]
    barriers: frozenset[int]
    assignment_index: int | None
    active_tilde_sites: tuple[int, ...]


@dataclass(frozen=True)
class MiniShellParse:
    words: tuple[MiniShellWord, ...]
    segments: tuple[tuple[MiniShellWord, ...], ...]
    argv: tuple[str, ...]
    consumed: int
    denial_reason: str | None = None
    lexical_items: int = 0
    heredoc_delimiter: str | None = None


@dataclass(frozen=True)
class CommandDecision:
    action: str
    parsed: MiniShellParse
    reason: str | None = None
    reason_code: str | None = None
    route_code: str | None = None
    policy_version: str = MINISHELL_ROUTE_POLICY_VERSION


class HookInputError(ValueError):
    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    decoded: dict[str, object] = {}
    for key, value in pairs:
        if key in decoded:
            raise HookInputError("duplicate_json_key")
        decoded[key] = value
    return decoded


def reject_nonfinite_json_number(value: str) -> object:
    raise HookInputError(f"non_finite_json_number_{value.lower()}")


def load_hook_payload() -> dict[str, object]:
    raw_payload = sys.stdin.buffer.read(MAX_HOOK_ENVELOPE_BYTES + 1)
    if len(raw_payload) > MAX_HOOK_ENVELOPE_BYTES:
        raise HookInputError("envelope_too_large")
    try:
        payload_text = raw_payload.decode("utf-8")
        payload = json.loads(
            payload_text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite_json_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HookInputError("malformed_json") from exc
    except RecursionError as exc:
        raise HookInputError("json_nesting_too_deep") from exc
    if not isinstance(payload, dict):
        raise HookInputError("top_level_not_object")
    return payload


def select_tool_input(payload: dict[str, object]) -> dict[str, object]:
    has_snake_case = "tool_input" in payload
    has_camel_case = "toolInput" in payload
    if has_snake_case and has_camel_case:
        if payload["tool_input"] != payload["toolInput"]:
            raise HookInputError("conflicting_tool_input_aliases")
        tool_input = payload["tool_input"]
    elif has_snake_case:
        tool_input = payload["tool_input"]
    elif has_camel_case:
        tool_input = payload["toolInput"]
    else:
        raise HookInputError("missing_tool_input")
    if not isinstance(tool_input, dict):
        raise HookInputError("tool_input_not_object")

    command = tool_input.get("command")
    if not isinstance(command, str) or not command:
        raise HookInputError("missing_or_invalid_command")
    return tool_input


def find_wrapper(kind: str) -> str | None:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if kind == "sanitize":
        candidates = [
            os.path.join(script_dir, "context-guard-sanitize-output"),
            os.path.join(script_dir, "sanitize_output.py"),
        ]
    else:
        candidates = [
            os.path.join(script_dir, "context-guard-trim-output"),
            os.path.join(script_dir, "trim_command_output.py"),
        ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def fail_open_source_env() -> str | None:
    canonical_value = os.environ.get(FAIL_OPEN_ENV)
    if canonical_value is not None:
        return FAIL_OPEN_ENV if canonical_value.strip().lower() in FAIL_OPEN_VALUES else None
    if os.environ.get(LEGACY_FAIL_OPEN_ENV, "").strip().lower() in FAIL_OPEN_VALUES:
        return LEGACY_FAIL_OPEN_ENV
    return None


def fail_open_enabled() -> bool:
    return fail_open_source_env() is not None


def print_noop() -> None:
    print("{}")


def print_deny_response(reason: str) -> None:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }, ensure_ascii=False))


def deny_invalid_hook_input(reason_code: str) -> None:
    reason = f"Invalid Bash hook input ({reason_code})."
    print(f"context-guard-rewrite-bash: {reason}", file=sys.stderr)
    print_deny_response(reason)


def deny(reason: str) -> None:
    print(f"context-guard-rewrite-bash: {reason}", file=sys.stderr)
    fail_open_env = fail_open_source_env()
    if fail_open_env is not None:
        print(
            f"context-guard-rewrite-bash: {fail_open_env}=1 active; leaving command unchanged intentionally",
            file=sys.stderr,
        )
        print_noop()
        return
    print_deny_response(reason)


def deny_boundary(reason: str) -> None:
    """Hard-deny invalid shell structure without consulting fail-open state."""
    print(f"context-guard-rewrite-bash: {reason}", file=sys.stderr)
    print_deny_response(reason)


def _exact_assignment_index(
    value: str,
    active: tuple[bool, ...],
    barriers: frozenset[int],
) -> int | None:
    for index, char in enumerate(value):
        if char != "=" or not active[index]:
            continue
        name = value[:index]
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            return None
        if not all(active[:index]):
            return None
        if any(boundary <= index for boundary in barriers):
            return None
        return index
    return None


def _tilde_prefix_end(word: MiniShellWord, start: int, assignment_site: bool) -> int | None:
    source = word.source_value
    if start >= len(source) or source[start] != "~" or not word.active[start]:
        return None
    if start in word.barriers:
        return None
    index = start + 1
    while index < len(source):
        char = source[index]
        if word.active[index] and (char == "/" or (assignment_site and char == ":")):
            break
        if not word.active[index] or index in word.barriers:
            return None
        index += 1
    if any(start < boundary <= index for boundary in word.barriers):
        return None
    return index


def _assignment_tilde_sites(word: MiniShellWord) -> tuple[tuple[int, int], ...]:
    assignment_index = word.assignment_index
    if assignment_index is None:
        return ()
    sites: list[tuple[int, int]] = []
    delimiters = [assignment_index]
    delimiters.extend(
        index
        for index in range(assignment_index + 1, len(word.source_value))
        if word.source_value[index] == ":" and word.active[index]
    )
    for delimiter in delimiters:
        start = delimiter + 1
        if start in word.barriers:
            continue
        end = _tilde_prefix_end(word, start, assignment_site=True)
        if end is not None:
            sites.append((start, end))
    return tuple(sites)


def _annotate_word_tildes(word: MiniShellWord) -> MiniShellWord:
    sites = list(_assignment_tilde_sites(word))
    if word.source_value.startswith("~"):
        end = _tilde_prefix_end(word, 0, assignment_site=False)
        if end is not None:
            sites.append((0, end))
    return MiniShellWord(
        value=word.source_value,
        source_value=word.source_value,
        active=word.active,
        barriers=word.barriers,
        assignment_index=word.assignment_index,
        active_tilde_sites=tuple(start for start, _end in sorted(set(sites))),
    )


def _denied_minishell(command: str, consumed: int, reason: str) -> MiniShellParse:
    return MiniShellParse(
        words=(),
        segments=(),
        argv=(),
        consumed=consumed,
        denial_reason=reason,
    )


def _dollar_starts_expansion(command: str, index: int) -> bool:
    if index + 1 >= len(command):
        return False
    return command[index + 1] in "({$0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz?!#*@-"


def parse_minishell(command: str) -> MiniShellParse:
    """Parse the fully consumed bounded MiniShell-v1 grammar.

    The parser intentionally keeps quote/escape provenance instead of
    reconstructing it from decoded argv. Only backslash-newline is removed
    without leaving a provenance barrier; every retained quote or escape can
    therefore suppress a local Bash assignment-style tilde site.
    """
    try:
        command_bytes = len(command.encode("utf-8"))
    except UnicodeEncodeError:
        return _denied_minishell(command, 0, "invalid_utf8")
    if command_bytes > MINISHELL_MAX_COMMAND_BYTES:
        return _denied_minishell(
            command,
            min(len(command), MINISHELL_MAX_COMMAND_BYTES),
            "command_bytes_exceeded",
        )
    if "\0" in command:
        return _denied_minishell(command, command.index("\0"), "nul_denied")

    raw_segments: list[list[MiniShellWord]] = [[]]
    chars: list[str] = []
    active: list[bool] = []
    barriers: set[int] = set()
    in_word = False
    quote: str | None = None
    fragment_kind: str | None = None
    lexical_items = 0
    heredoc_delimiter: str | None = None
    index = 0

    def bump_item() -> bool:
        nonlocal lexical_items
        lexical_items += 1
        return lexical_items <= MINISHELL_MAX_LEXICAL_ITEMS

    def finish_word() -> str | None:
        nonlocal chars, active, barriers, in_word, fragment_kind
        if not in_word:
            return None
        if len(raw_segments[-1]) >= MINISHELL_MAX_WORDS_PER_SEGMENT:
            return "segment_words_exceeded"
        source_value = "".join(chars)
        active_tuple = tuple(active)
        barrier_set = frozenset(barriers)
        raw_segments[-1].append(MiniShellWord(
            value=source_value,
            source_value=source_value,
            active=active_tuple,
            barriers=barrier_set,
            assignment_index=_exact_assignment_index(
                source_value,
                active_tuple,
                barrier_set,
            ),
            active_tilde_sites=(),
        ))
        chars = []
        active = []
        barriers = set()
        in_word = False
        fragment_kind = None
        return None

    def deny(reason: str, at: int | None = None) -> MiniShellParse:
        return _denied_minishell(command, index if at is None else at, reason)

    while index < len(command):
        char = command[index]
        if quote is None:
            if char == " ":
                error = finish_word()
                if error is not None:
                    return deny(error)
                index += 1
                continue
            if char in "\t\r\n":
                return deny("forbidden_whitespace")
            if char == "\\":
                if index + 1 >= len(command):
                    return deny("trailing_escape")
                escaped = command[index + 1]
                if escaped == "\n":
                    index += 2
                    fragment_kind = None
                    continue
                if escaped in "\t\r":
                    return deny("forbidden_escaped_character")
                if not bump_item():
                    return deny("lexical_items_exceeded")
                in_word = True
                chars.append(escaped)
                active.append(False)
                fragment_kind = None
                index += 2
                continue
            if char in {"'", '"'}:
                if not bump_item():
                    return deny("lexical_items_exceeded")
                in_word = True
                barriers.add(len(chars))
                quote = char
                fragment_kind = f"quote:{char}"
                index += 1
                continue
            if char == "#" and not in_word:
                if not raw_segments[-1]:
                    return deny("comment_without_command")
                if not bump_item():
                    return deny("lexical_items_exceeded")
                newline = command.find("\n", index)
                if newline < 0:
                    index = len(command)
                    break
                if any(tail != " " for tail in command[newline + 1:]):
                    return deny("leftover_after_comment", newline + 1)
                index = len(command)
                break
            if char == "|":
                error = finish_word()
                if error is not None:
                    return deny(error)
                if not bump_item():
                    return deny("lexical_items_exceeded")
                if (
                    not raw_segments[-1]
                    or len(raw_segments) >= MINISHELL_MAX_SEGMENTS
                    or command.startswith("|&", index)
                ):
                    return deny("invalid_pipeline")
                raw_segments.append([])
                index += 1
                continue
            if char == "<":
                error = finish_word()
                if error is not None:
                    return deny(error)
                if (
                    heredoc_delimiter is not None
                    or len(raw_segments) != 1
                    or not raw_segments[-1]
                    or not command.startswith("<<", index)
                    or command.startswith(("<<<", "<<-"), index)
                ):
                    return deny("unsupported_redirect")
                if not bump_item():
                    return deny("lexical_items_exceeded")
                delimiter_quote_index = index + 2
                if (
                    delimiter_quote_index >= len(command)
                    or command[delimiter_quote_index] not in {"'", '"'}
                ):
                    return deny("unquoted_heredoc_delimiter")
                delimiter_quote = command[delimiter_quote_index]
                delimiter_end = command.find(
                    delimiter_quote,
                    delimiter_quote_index + 1,
                )
                if delimiter_end < 0:
                    return deny("unterminated_heredoc_delimiter")
                delimiter = command[delimiter_quote_index + 1:delimiter_end]
                if (
                    not delimiter
                    or len(delimiter.encode("ascii", "ignore"))
                    != len(delimiter)
                    or len(delimiter) > MINISHELL_MAX_HEREDOC_DELIMITER_BYTES
                    or MINISHELL_HEREDOC_DELIMITER_RE.fullmatch(delimiter) is None
                ):
                    return deny("invalid_heredoc_delimiter")
                if not bump_item():
                    return deny("lexical_items_exceeded")
                header_end = delimiter_end + 1
                while header_end < len(command) and command[header_end] == " ":
                    header_end += 1
                if header_end >= len(command) or command[header_end] != "\n":
                    return deny("heredoc_header_not_terminated", header_end)

                body_start = header_end + 1
                line_start = body_start
                terminator_end: int | None = None
                while line_start <= len(command):
                    line_end = command.find("\n", line_start)
                    if line_end < 0:
                        if command[line_start:] == delimiter:
                            terminator_end = len(command)
                        break
                    if command[line_start:line_end] == delimiter:
                        terminator_end = line_end + 1
                        break
                    line_start = line_end + 1
                if terminator_end is None:
                    return deny("unterminated_heredoc", body_start)
                if terminator_end != len(command):
                    return deny("leftover_after_heredoc", terminator_end)
                if not bump_item():
                    return deny("lexical_items_exceeded")
                heredoc_delimiter = delimiter
                index = len(command)
                break
            if char in MINISHELL_DENIED_ACTIVE_CHARS:
                return deny(f"active_{ord(char):02x}")
            if char == "$" and _dollar_starts_expansion(command, index):
                return deny("active_24")
            if fragment_kind != "unquoted":
                if not bump_item():
                    return deny("lexical_items_exceeded")
                fragment_kind = "unquoted"
            in_word = True
            chars.append(char)
            active.append(True)
            index += 1
            continue

        if char in "\t\r\n":
            if quote == '"' and char == "\n" and index > 0 and command[index - 1] == "\\":
                index += 1
                continue
            return deny("forbidden_quoted_whitespace")
        if char == quote:
            barriers.add(len(chars))
            quote = None
            fragment_kind = None
            index += 1
            continue
        if quote == "'":
            chars.append(char)
            active.append(False)
            index += 1
            continue
        if char == "`" or (char == "$" and _dollar_starts_expansion(command, index)):
            return deny("active_double_quote_expansion")
        if char == "\\":
            if index + 1 >= len(command):
                return deny("trailing_double_quote_escape")
            escaped = command[index + 1]
            if escaped == "\n":
                index += 2
                continue
            if escaped in "\t\r":
                return deny("forbidden_escaped_character")
            if escaped in {'$', '`', '"', "\\"}:
                chars.append(escaped)
                active.append(False)
            else:
                chars.extend(("\\", escaped))
                active.extend((False, False))
            index += 2
            continue
        chars.append(char)
        active.append(False)
        index += 1

    if quote is not None:
        return _denied_minishell(command, len(command), "unterminated_quote")
    error = finish_word()
    if error is not None:
        return _denied_minishell(command, len(command), error)
    if not raw_segments[-1]:
        return _denied_minishell(command, len(command), "empty_command")
    segments = tuple(
        tuple(_annotate_word_tildes(word) for word in segment)
        for segment in raw_segments
    )
    words = tuple(word for segment in segments for word in segment)
    return MiniShellParse(
        words=words,
        segments=segments,
        argv=tuple(word.value for word in words),
        consumed=len(command),
        lexical_items=lexical_items,
        heredoc_delimiter=heredoc_delimiter,
    )


def split_single_safe_command(command: str) -> list[str] | None:
    parsed = parse_minishell(command)
    if parsed.denial_reason is not None:
        return None
    return list(parsed.argv)


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


def _routing_start(
    words: tuple[MiniShellWord, ...],
    argv: tuple[str, ...],
) -> int:
    index = 0
    while index < len(words) and words[index].assignment_index is not None:
        index += 1
    if index >= len(words) or command_basename(argv[index]) != "env":
        return index

    index += 1
    while index < len(words) and words[index].assignment_index is not None:
        index += 1
    if index < len(words) and argv[index] == "--":
        index += 1
    if index >= len(words) or argv[index].startswith("-"):
        return -1
    return index


def _routing_start_index(parsed: MiniShellParse) -> int:
    return _routing_start(parsed.words, parsed.argv)


def _routing_argv(parsed: MiniShellParse) -> tuple[str, ...]:
    return parsed.argv[_routing_start_index(parsed):]


def _wrapper_invocation(argv: tuple[str, ...]) -> tuple[str, int] | None:
    if not argv:
        return None
    head_basename = command_basename(argv[0])
    if head_basename in WRAPPER_BASENAMES:
        return head_basename, 0
    if (
        re.fullmatch(r"python(?:\d+(?:\.\d+)?)?", head_basename)
        and len(argv) > 1
        and command_basename(argv[1]) in WRAPPER_BASENAMES
    ):
        return command_basename(argv[1]), 1
    return None


def _wrapper_kind(basename: str) -> str:
    return "sanitize" if "sanitize" in basename else "trim"


def _expected_cgw1_prefix(kind: str) -> tuple[str, ...]:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.basename(__file__) == "rewrite_bash_for_token_budget.py":
        helper = "sanitize_output.py" if kind == "sanitize" else "trim_command_output.py"
        return ("python3", os.path.join(script_dir, helper))
    helper = (
        "context-guard-sanitize-output"
        if kind == "sanitize"
        else "context-guard-trim-output"
    )
    return (os.path.join(script_dir, helper),)


def classify_incoming_wrapper(
    parsed: MiniShellParse,
) -> tuple[str, str | None, str | None] | None:
    """Classify raw wrapper input without probing the filesystem.

    Direct wrapper CLI use is not an execution envelope. A known wrapper
    combined with the reserved CGW1 sentinel or an exact v0 shell envelope is
    always incoming execution syntax and therefore denied at PreToolUse.
    """
    if len(parsed.segments) != 1:
        return None
    route_start = _routing_start_index(parsed)
    if route_start < 0:
        return None
    route_argv = parsed.argv[route_start:]
    invocation = _wrapper_invocation(route_argv)
    if invocation is None:
        return None
    basename, wrapper_index = invocation
    kind = _wrapper_kind(basename)
    envelope_argv = route_argv[wrapper_index + 1:]
    sentinel_tokens = [
        token for token in envelope_argv if CGW1_SENTINEL in token
    ]
    if sentinel_tokens:
        code = (
            "nested_wrapper_denied"
            if len(sentinel_tokens) > 1
            or any(token != CGW1_SENTINEL for token in sentinel_tokens)
            else "incoming_wrapper_denied"
        )
        return (code, kind, None)

    legacy_prefixes = (
        ("--max-lines", CGW1_MAX_LINES),
        (CGW1_COMMAND_SEARCH_DIFF,),
        ("--mode", CGW1_COMMAND_SEARCH_DIFF),
    )
    for prefix in legacy_prefixes:
        fixed = (*prefix, "--", *CGW1_SHELL_ARGV)
        if (
            len(envelope_argv) == len(fixed) + 1
            and envelope_argv[:-1] == fixed
        ):
            return ("incoming_wrapper_denied", kind, envelope_argv[-1])
    return None


def is_already_wrapped(argv: list[str]) -> bool:
    """Compatibility helper: only exact CGW1 argv counts as already wrapped."""
    command = shell_join(argv)
    parsed = parse_minishell(command)
    if parsed.denial_reason is not None:
        return False
    wrapper = classify_incoming_wrapper(parsed)
    return wrapper is not None and wrapper[0] == "exact"


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


def _valid_n(value: str) -> bool:
    return value.isascii() and value.isdigit() and 1 <= int(value) <= 1_000_000


def _valid_range(value: str) -> bool:
    if (
        not value
        or len(value.encode("utf-8")) > 64
        or not value.isascii()
    ):
        return False
    return all(
        (
            _valid_n(item)
            if "-" not in item
            else (
                item.count("-") == 1
                and _valid_n(item.split("-", 1)[0])
                and (
                    not item.split("-", 1)[1]
                    or _valid_n(item.split("-", 1)[1])
                )
            )
        )
        for item in value.split(",")
    )


def _valid_key(value: str) -> bool:
    parts = value.split(",")
    return (
        1 <= len(parts) <= 2
        and all(
            part.isascii()
            and part.isdigit()
            and 1 <= len(part) <= 6
            and int(part) >= 1
            for part in parts
        )
    )


def _printf_is_safe(argv: tuple[str, ...]) -> bool:
    if len(argv) < 2:
        return False
    index = 1
    if argv[index] == "--":
        index += 1
    elif argv[index].startswith("-"):
        return False
    return index < len(argv)


def _cat_is_safe(argv: tuple[str, ...], *, allow_files: bool) -> bool:
    operands = 0
    options_done = False
    for argument in argv[1:]:
        if not options_done and argument == "--":
            options_done = True
            continue
        if (
            not options_done
            and argument.startswith("-")
            and argument != "-"
        ):
            if (
                argument.startswith("--")
                or not argument[1:]
                or not set(argument[1:]).issubset(set("bnsETAvet"))
            ):
                return False
            continue
        operands += 1
    return allow_files or operands == 0


def _cut_is_safe(argv: tuple[str, ...]) -> bool:
    selector: str | None = None
    delimiter = False
    index = 1
    while index < len(argv):
        argument = argv[index]
        if argument == "--":
            return selector is not None and index == len(argv) - 1
        if argument in {"-s", "--complement"}:
            index += 1
            continue
        if argument in {"-f", "-c", "-b", "-d"}:
            if index + 1 >= len(argv):
                return False
            value = argv[index + 1]
            if argument == "-d":
                if delimiter or len(value.encode("utf-8")) != 1:
                    return False
                delimiter = True
            else:
                if selector is not None or not _valid_range(value):
                    return False
                selector = argument
            index += 2
            continue
        if (
            len(argument) > 2
            and argument[:2] in {"-f", "-c", "-b", "-d"}
        ):
            option, value = argument[:2], argument[2:]
            if option == "-d":
                if delimiter or len(value.encode("utf-8")) != 1:
                    return False
                delimiter = True
            else:
                if selector is not None or not _valid_range(value):
                    return False
                selector = option
            index += 1
            continue
        return False
    return selector is not None and (not delimiter or selector == "-f")


def _sed_is_safe(argv: tuple[str, ...]) -> bool:
    if len(argv) not in {3, 4} or argv[1] != "-n":
        return False
    if len(argv) == 3:
        script = argv[2]
    elif argv[2] in {"--", "-e"}:
        script = argv[3]
    else:
        return False
    return re.fullmatch(
        r"(?:[1-9]\d*|[1-9]\d*,(?:[1-9]\d*|\$))p",
        script,
    ) is not None and all(
        _valid_n(number)
        for number in re.findall(r"\d+", script)
    )


def _sort_is_safe(argv: tuple[str, ...]) -> bool:
    index = 1
    while index < len(argv):
        argument = argv[index]
        if argument == "--":
            return index == len(argv) - 1
        if argument in {"-k", "-t"}:
            if index + 1 >= len(argv):
                return False
            value = argv[index + 1]
            if (
                argument == "-k" and not _valid_key(value)
            ) or (
                argument == "-t" and len(value.encode("utf-8")) != 1
            ):
                return False
            index += 2
            continue
        if argument in {"-r", "-u", "-n", "-f", "-s"}:
            index += 1
            continue
        if argument.startswith(("-k", "-t")) and len(argument) > 2:
            value = argument[2:]
            if (
                argument.startswith("-k") and not _valid_key(value)
            ) or (
                argument.startswith("-t") and len(value.encode("utf-8")) != 1
            ):
                return False
            index += 1
            continue
        return False
    return True


def _uniq_is_safe(argv: tuple[str, ...]) -> bool:
    index = 1
    while index < len(argv):
        argument = argv[index]
        if argument == "--":
            return index == len(argv) - 1
        if argument in {"-c", "-d", "-u", "-i"}:
            index += 1
            continue
        if argument in {"-f", "-s", "-w"}:
            if index + 1 >= len(argv) or not _valid_n(argv[index + 1]):
                return False
            index += 2
            continue
        if (
            len(argument) > 2
            and argument[:2] in {"-f", "-s", "-w"}
            and _valid_n(argument[2:])
        ):
            index += 1
            continue
        return False
    return True


def _wc_is_safe(argv: tuple[str, ...]) -> bool:
    for index, argument in enumerate(argv[1:], start=1):
        if argument == "--":
            return index == len(argv) - 1
        if (
            argument.startswith("-")
            and not argument.startswith("--")
            and bool(argument[1:])
            and set(argument[1:]).issubset({"c", "l", "m", "w"})
        ):
            continue
        return False
    return True


def _head_tail_is_safe(argv: tuple[str, ...], *, allow_files: bool) -> bool:
    first = command_basename(argv[0])
    index = 1
    count_seen = False
    while index < len(argv):
        argument = argv[index]
        if argument == "--":
            index += 1
            break
        if first == "tail" and argument in {"-f", "-F"}:
            return False
        if argument in {"-n", "--lines"}:
            if count_seen or index + 1 >= len(argv) or not _valid_n(argv[index + 1]):
                return False
            count_seen = True
            index += 2
            continue
        attached = re.fullmatch(r"(?:-|(?:-n)|(?:--lines=))([1-9]\d*)", argument)
        if attached is not None:
            if count_seen or not _valid_n(attached.group(1)):
                return False
            count_seen = True
            index += 1
            continue
        if argument.startswith("-"):
            return False
        break
    return count_seen and (allow_files or index == len(argv))


def _grep_is_safe(argv: tuple[str, ...], *, allow_files: bool) -> bool:
    pattern_seen = False
    files = 0
    allowed_flags = set("nHhivEFGPwxc lLrR".replace(" ", ""))
    index = 1
    while index < len(argv):
        argument = argv[index]
        if argument == "--":
            index += 1
            break
        if argument in {"-f", "--file"} or argument.startswith(("--file=", "--binary-files=")):
            return False
        if argument == "-e":
            if index + 1 >= len(argv):
                return False
            pattern_seen = True
            index += 2
            continue
        if argument in {"-m", "--max-count", "-A", "-B", "-C"}:
            if index + 1 >= len(argv) or not _valid_n(argv[index + 1]):
                return False
            index += 2
            continue
        if argument.startswith("--max-count="):
            if not _valid_n(argument.split("=", 1)[1]):
                return False
            index += 1
            continue
        if re.fullmatch(r"-(?:m|A|B|C)([1-9]\d*)", argument):
            if not _valid_n(argument[2:]):
                return False
            index += 1
            continue
        if argument == "--recursive":
            index += 1
            continue
        if argument.startswith("-") and argument != "-":
            if (
                argument.startswith("--")
                or not argument[1:]
                or not set(argument[1:]).issubset(allowed_flags)
            ):
                return False
            index += 1
            continue
        if not pattern_seen:
            pattern_seen = True
        else:
            files += 1
        index += 1
    while index < len(argv):
        if not pattern_seen:
            pattern_seen = True
        else:
            files += 1
        index += 1
    return pattern_seen and (allow_files or files == 0)


def _rg_is_safe(argv: tuple[str, ...]) -> bool:
    pattern_seen = False
    options_done = False
    index = 1
    allowed_short = {
        "-n", "-H", "-h", "-i", "-S", "-F", "-w", "-x", "-l", "-c",
    }
    allowed_long = {
        "--line-number", "--with-filename", "--no-filename", "--ignore-case",
        "--smart-case", "--fixed-strings", "--word-regexp", "--line-regexp",
        "--files-with-matches", "--count", "--hidden", "--no-ignore",
    }
    while index < len(argv):
        argument = argv[index]
        if not options_done and argument == "--":
            options_done = True
            index += 1
            continue
        if not options_done and argument in allowed_short | allowed_long:
            index += 1
            continue
        if not options_done and argument in {"-g", "--glob"}:
            if index + 1 >= len(argv):
                return False
            index += 2
            continue
        if not options_done and (
            (argument.startswith("-g") and len(argument) > 2)
            or argument.startswith("--glob=")
        ):
            index += 1
            continue
        if not options_done and argument.startswith("-"):
            return False
        pattern_seen = True
        index += 1
    return pattern_seen


def _git_is_safe(argv: tuple[str, ...]) -> bool:
    if len(argv) < 2:
        return False
    subcommand = argv[1]
    arguments = argv[2:]
    if subcommand == "grep":
        return _grep_is_safe(("grep", *arguments), allow_files=True)
    if subcommand not in {"diff", "show", "log"}:
        return False
    patch_output = subcommand != "log"
    index = 0
    options_done = False
    while index < len(arguments):
        argument = arguments[index]
        if not options_done and argument == "--":
            options_done = True
            index += 1
            continue
        if not options_done and argument in {
            "-p", "--patch",
            "--stat", "--name-only", "--name-status", "--no-color",
            "--color=never", "--cached", "--staged", "--oneline",
        }:
            if argument in {"-p", "--patch"}:
                patch_output = True
            index += 1
            continue
        if not options_done and argument in {"-U", "--unified"}:
            if index + 1 >= len(arguments) or not _valid_n(arguments[index + 1]):
                return False
            index += 2
            continue
        if (
            not options_done
            and subcommand == "log"
            and argument in {"-n", "--max-count"}
        ):
            if index + 1 >= len(arguments) or not _valid_n(arguments[index + 1]):
                return False
            index += 2
            continue
        if (
            not options_done
            and subcommand == "log"
            and (
                re.fullmatch(r"-[1-9]\d*", argument)
                or (
                    argument.startswith("--max-count=")
                    and _valid_n(argument.split("=", 1)[1])
                )
            )
        ):
            index += 1
            continue
        if not options_done and (
            re.fullmatch(r"-U[1-9]\d*", argument)
            or re.fullmatch(r"--unified=[1-9]\d*", argument)
        ):
            value = argument[2:] if argument.startswith("-U") else argument.split("=", 1)[1]
            if not _valid_n(value):
                return False
            index += 1
            continue
        if not options_done and argument.startswith("-"):
            return False
        index += 1
    return patch_output


def _package_script_route(argv: tuple[str, ...]) -> str:
    value_options = {"--prefix", "--workspace", "-w", "--filter", "--cwd", "-C"}
    long_value_options = {"--prefix", "--workspace", "--filter", "--cwd"}
    index = 1
    while index < len(argv) and argv[index].startswith("-"):
        option = argv[index]
        if option in value_options and index + 1 < len(argv):
            index += 2
            continue
        if any(option.startswith(name + "=") for name in long_value_options):
            index += 1
            continue
        return "deny"
    if index >= len(argv):
        return "noop"
    command = argv[index]
    if command in {"test", "build", "lint"}:
        return (
            "trim"
            if index + 1 == len(argv)
            or argv[index + 1] == "--"
            else "deny"
        )
    if command in {"run", "run-script"} and index + 1 < len(argv):
        script = argv[index + 1]
        if script == "build" or script == "lint" or script.startswith("test"):
            return (
                "trim"
                if index + 2 == len(argv)
                or argv[index + 2] == "--"
                else "deny"
            )
    return "noop"


def _npx_route(argv: tuple[str, ...]) -> str:
    index = 1
    while index < len(argv) and argv[index].startswith("-"):
        option = argv[index]
        if option in {"--no-install", "--yes", "-y"}:
            index += 1
            continue
        if option in {"-p", "--package"} and index + 1 < len(argv):
            index += 2
            continue
        if option.startswith("--package="):
            index += 1
            continue
        return "deny"
    if index < len(argv) and command_basename(argv[index]) in {"jest", "vitest"}:
        return "trim"
    return "noop"


def _make_route(argv: tuple[str, ...]) -> str:
    index = 1
    while index < len(argv) and argv[index].startswith("-"):
        option = argv[index]
        if option == "-C" and index + 1 < len(argv):
            index += 2
            continue
        if option.startswith("-C") and len(option) > 2:
            index += 1
            continue
        if option == "--directory" and index + 1 < len(argv):
            index += 2
            continue
        if option.startswith("--directory="):
            index += 1
            continue
        if option in {"-s", "--silent", "--no-print-directory"}:
            index += 1
            continue
        return "deny"
    if index < len(argv) and argv[index] in {"test", "build", "lint"}:
        return "trim"
    return "noop"


def command_search_diff(
    argv: tuple[str, ...],
    *,
    role: str = "standalone",
) -> str:
    """Classify one boundary-checked simple command for the A1 route table."""
    if not argv:
        return "deny"
    first = command_basename(argv[0])
    if _forbidden_command_basename(argv):
        return "deny"
    if first == "printf":
        if role == "filter" or not _printf_is_safe(argv):
            return "deny"
        return "trim" if role == "first" else ("noop" if role == "standalone" else "deny")
    if first == "cat":
        if not _cat_is_safe(argv, allow_files=role != "filter"):
            return "deny"
        return "trim" if role in {"first", "filter"} else "noop"
    if first == "cut":
        if role == "first" or not _cut_is_safe(argv):
            return "deny"
        return "trim" if role == "filter" else "noop"
    if first == "sed":
        if role == "first" or not _sed_is_safe(argv):
            return "deny"
        return "trim" if role == "filter" else "noop"
    if first == "sort":
        if role == "first" or not _sort_is_safe(argv):
            return "deny"
        return "trim" if role == "filter" else "noop"
    if first == "uniq":
        if role == "first" or not _uniq_is_safe(argv):
            return "deny"
        return "trim" if role == "filter" else "noop"
    if first == "wc":
        if role == "first" or not _wc_is_safe(argv):
            return "deny"
        return "trim" if role == "filter" else "noop"
    if first in {"head", "tail"}:
        return (
            "trim"
            if _head_tail_is_safe(argv, allow_files=role != "filter")
            else "deny"
        )
    if first in {"grep", "egrep", "fgrep"}:
        return (
            "sanitize"
            if _grep_is_safe(argv, allow_files=role != "filter")
            else "deny"
        )
    if first == "rg":
        return (
            "sanitize"
            if role != "filter" and _rg_is_safe(argv)
            else "deny"
        )
    if first == "git":
        return (
            "sanitize"
            if role != "filter" and _git_is_safe(argv)
            else "deny"
        )
    if first in {"npm", "pnpm", "yarn", "bun"}:
        route = _package_script_route(argv)
    elif first == "npx":
        route = _npx_route(argv)
    elif first == "make":
        route = _make_route(argv)
    elif re.fullmatch(r"python(?:\d+(?:\.\d+)?)?", first):
        route = (
            "trim"
            if len(argv) > 2 and argv[1] == "-m" and argv[2] in {"pytest", "unittest"}
            else "noop"
        )
    elif first == "go":
        route = "trim" if len(argv) > 1 and argv[1] == "test" else "noop"
    elif first == "cargo":
        route = "trim" if len(argv) > 1 and argv[1] == "test" else "noop"
    elif first in {"mvn", "mvnw", "gradle", "gradlew"}:
        index = 1
        if index < len(argv) and argv[index] in {"-q", "--quiet"}:
            index += 1
        if index < len(argv) and argv[index] == "test":
            route = "trim"
        else:
            route = "noop"
    elif first in {"pytest", "tox", "jest", "vitest"}:
        route = "trim"
    elif first in {"find", "tree", "fd"}:
        route = "trim"
    elif is_log_streaming_command(list(argv)):
        route = "sanitize"
    else:
        route = "noop"
    if role == "standalone":
        return route
    if role == "first":
        return route if route in {"trim", "sanitize"} else "deny"
    return "deny"


def _find_command_is_side_effecting(argv: tuple[str, ...]) -> bool:
    if not argv or argv[0].rsplit("/", 1)[-1] != "find":
        return False
    return any(argument in _FIND_OUTPUT_RISK_ACTIONS for argument in argv[1:])


def _prefix_overrides_path(
    segment: tuple[MiniShellWord, ...],
    route_start: int,
) -> bool:
    return any(
        word.assignment_index == 4 and word.source_value.startswith("PATH=")
        for word in segment[:route_start]
    )


def _forbidden_command_basename(argv: tuple[str, ...]) -> bool:
    if not argv:
        return False
    basename = command_basename(argv[0])
    if basename in MINISHELL_DENIED_COMMAND_BASENAMES:
        return True
    if basename not in MINISHELL_DENIED_SHELL_BASENAMES:
        return False
    return any(
        re.fullmatch(r"-[^-]*c[^-]*", argument) is not None
        for argument in argv[1:]
    )


def classify_command(command: str, *, allow_cgw1: bool = True) -> CommandDecision:
    """Make a side-effect-free shell-boundary and routing decision."""
    parsed = parse_minishell(command)
    if parsed.denial_reason is not None:
        return CommandDecision(
            action="deny",
            parsed=parsed,
            reason=f"MiniShell-v1 rejected command ({parsed.denial_reason}).",
            reason_code=parsed.denial_reason,
        )
    if any(word.active_tilde_sites for word in parsed.words):
        return CommandDecision(
            action="deny",
            parsed=parsed,
            reason="MiniShell-v1 denied active shell expansion (active_shell_expansion_denied).",
            reason_code="active_shell_expansion_denied",
        )

    wrapper = classify_incoming_wrapper(parsed)
    if wrapper is not None:
        wrapper_status, _wrapper_kind_name, _payload = wrapper
        return CommandDecision(
            action="deny",
            parsed=parsed,
            reason=f"Incoming ContextGuard execution wrapper denied ({wrapper_status}).",
            reason_code=wrapper_status,
        )

    segment_routes: list[str] = []
    for segment_index, segment in enumerate(parsed.segments):
        segment_argv = tuple(word.value for word in segment)
        route_start = _routing_start(segment, segment_argv)
        if route_start < 0:
            return CommandDecision(
                action="deny",
                parsed=parsed,
                reason="Restricted env prefix denied (restricted_env_denied).",
                reason_code="restricted_env_denied",
            )
        if route_start < len(segment):
            command_word = segment[route_start]
            if (
                command_word.source_value in MINISHELL_DENIED_COMMAND_WORDS
                and all(command_word.active)
                and not command_word.barriers
            ):
                return CommandDecision(
                    action="deny",
                    parsed=parsed,
                    reason="MiniShell-v1 rejected an active shell reserved word.",
                    reason_code="reserved_word_denied",
                )
        route_argv = segment_argv[route_start:]
        if not route_argv:
            return CommandDecision(
                action="deny",
                parsed=parsed,
                reason="Assignment-only input denied (assignment_only_denied).",
                reason_code="assignment_only_denied",
            )
        if _forbidden_command_basename(route_argv):
            return CommandDecision(
                action="deny",
                parsed=parsed,
                reason="Forbidden command denied (forbidden_command_denied).",
                reason_code="forbidden_command_denied",
            )
        if parsed.heredoc_delimiter is not None and (
            len(parsed.segments) != 1
            or command_basename(route_argv[0])
            not in MINISHELL_HEREDOC_STDIN_CONSUMERS
        ):
            return CommandDecision(
                action="deny",
                parsed=parsed,
                reason="Quoted heredoc consumer denied (heredoc_consumer_denied).",
                reason_code="heredoc_consumer_denied",
            )
        if (
            len(parsed.segments) > 1
            and _prefix_overrides_path(segment, route_start)
        ):
            return CommandDecision(
                action="deny",
                parsed=parsed,
                reason="Pipeline PATH overrides are outside the immutable MiniShell-v1 route allowlist.",
                reason_code="route_operand_denied",
            )
        if _find_command_is_side_effecting(route_argv):
            return CommandDecision(
                action="deny",
                parsed=parsed,
                reason="Side-effecting find actions are outside the MiniShell-v1 read-only boundary.",
                reason_code="route_operand_denied",
            )
        role = (
            "standalone"
            if len(parsed.segments) == 1
            else ("first" if segment_index == 0 else "filter")
        )
        route = command_search_diff(route_argv, role=role)
        if route == "deny":
            return CommandDecision(
                action="deny",
                parsed=parsed,
                reason="Command is outside the immutable MiniShell-v1 route allowlist.",
                reason_code="route_policy_denied",
            )
        segment_routes.append(route)

    if len(parsed.segments) == 1:
        action = segment_routes[0]
        route_code = {
            "noop": "noop",
            "trim": "rewrite_trim",
            "sanitize": "rewrite_sanitize",
        }[action]
        return CommandDecision(action=action, parsed=parsed, route_code=route_code)
    route = "sanitize" if "sanitize" in segment_routes else "trim"
    return CommandDecision(
        action=route,
        parsed=parsed,
        route_code=(
            "rewrite_sanitize" if route == "sanitize" else "rewrite_trim"
        ),
    )


_SHELL_SAFE_WORD_RE = re.compile(r"^[A-Za-z0-9_@%+=:,./-]+$")


def shell_quote(value: str) -> str:
    if not value:
        return "''"
    if _SHELL_SAFE_WORD_RE.fullmatch(value):
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"


def shell_join(argv: list[str] | tuple[str, ...]) -> str:
    return " ".join(shell_quote(value) for value in argv)


def build_wrapped_command(wrapper: str, command: str) -> str:
    if wrapper.endswith(".py"):
        prefix = ["python3", wrapper]
    else:
        prefix = [wrapper]
    wrapped_argv = prefix + ["--max-lines", CGW1_MAX_LINES, "--", *CGW1_SHELL_ARGV, command]
    return shell_join(wrapped_argv)


def build_sanitized_command(wrapper: str, command: str) -> str:
    if wrapper.endswith(".py"):
        prefix = ["python3", wrapper]
    else:
        prefix = [wrapper]
    wrapped_argv = prefix + [
        CGW1_SENTINEL,
        CGW1_COMMAND_SEARCH_DIFF,
        "--",
        *CGW1_SHELL_ARGV,
        command,
    ]
    return shell_join(wrapped_argv)


def build_updated_input(tool_input: dict[str, object], wrapped: str) -> dict[str, object]:
    updated_input = copy.deepcopy(tool_input)
    updated_input["command"] = wrapped
    return updated_input


def print_updated_command(wrapped: str, tool_input: dict[str, object]) -> None:
    response = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "updatedInput": build_updated_input(tool_input, wrapped),
        }
    }
    print(json.dumps(response, ensure_ascii=False))


def main() -> int:
    if any(arg in {"-h", "--help"} for arg in sys.argv[1:]):
        print("ContextGuard helper: context-guard-rewrite-bash")
        return 0
    try:
        payload = load_hook_payload()
        tool_input = select_tool_input(payload)
    except HookInputError as exc:
        deny_invalid_hook_input(exc.reason_code)
        return 0
    except RecursionError:
        deny_invalid_hook_input("payload_nesting_too_deep")
        return 0
    except OSError:
        deny_invalid_hook_input("input_read_failed")
        return 0
    command = tool_input["command"]
    assert isinstance(command, str)

    decision = classify_command(command)
    if decision.action == "deny":
        deny_boundary(decision.reason or "MiniShell-v1 rejected command.")
        return 0
    if decision.action == "noop":
        print_noop()
        return 0

    if decision.action == "trim":
        wrapper = find_wrapper("trim")
        if wrapper is None:
            deny(
                "Noisy command blocked because context-guard-trim-output is not installed next to "
                "context-guard-rewrite-bash. Install the trim wrapper or set "
                f"{FAIL_OPEN_ENV}=1 to run untrimmed intentionally."
            )
            return 0
        wrapped = build_wrapped_command(wrapper, command)
    elif decision.action == "sanitize":
        wrapper = find_wrapper("sanitize")
        if wrapper is None:
            reason = (
                "Search/diff command blocked because context-guard-sanitize-output is not installed next to "
                "context-guard-rewrite-bash. Install the sanitizer or set "
                f"{FAIL_OPEN_ENV}=1 to run unsanitized intentionally."
            )
            deny(reason)
            return 0
        wrapped = build_sanitized_command(wrapper, command)
    else:
        raise AssertionError(f"unknown command action: {decision.action}")

    try:
        print_updated_command(wrapped, tool_input)
    except RecursionError:
        deny_invalid_hook_input("payload_copy_too_deep")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
