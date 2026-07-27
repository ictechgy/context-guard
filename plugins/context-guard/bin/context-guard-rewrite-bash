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
# bash 가 접두사 할당으로 적용하는 `NAME+=VALUE` 형태 — MiniShell 은 이를 할당으로
# 표시하지 않으므로(§_is_unmodeled_assignment_prefix) 라우팅 접두사 구간에서 거부한다.
MINISHELL_APPEND_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+=")
# 환경변수 접두사(`KEY=VALUE cmd`) 이름 화이트리스트 — FIX-5, 원칙 4의 유일한 예외.
# denylist 는 구조적으로 종료하지 않는다(실측: 최소 denylist가 PAGER/EDITOR/VISUAL/
# PERL5LIB/RUBYOPT/PYTHONPATH/PYTHONSTARTUP/NODE_OPTIONS 8종을 놓침). 이 15개는
# "값을 실행 가능한 코드 경로로 해석하지 않는다"는 기준을 통과한 것만 포함한다.
# 정확 이름 일치만 허용 — 접두사/글롭 매칭 금지(`TERM*`는 `TERMINFO`를 재승인시킨다).
# TERM 은 TERMINFO/TERMINFO_DIRS 가, LANG/LC_* 는 LOCPATH/NLSPATH 가 배제되었기
# 때문에만 안전하다 — 이 조건부 안전성을 확장 심사 시 반드시 재확인할 것.
MINISHELL_ALLOWED_ENV_PREFIX_NAMES = frozenset({
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_NUMERIC",
    "LC_TIME",
    "LC_COLLATE",
    "LC_MESSAGES",
    "TZ",
    "NO_COLOR",
    "CLICOLOR",
    "CI",
    "COLUMNS",
    "LINES",
    "TERM",
    "NODE_ENV",
})
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


def _dollar_starts_expansion(
    command: str,
    index: int,
    *,
    allow_quoted_literal: bool = False,
) -> bool:
    cursor = index + 1
    while command.startswith("\\\n", cursor):
        cursor += 2
    if cursor >= len(command):
        return False
    following = command[cursor]
    if allow_quoted_literal and following in {'"', "'"}:
        return True
    return following in "({$0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz?!#*@-"


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
            if char == "$" and _dollar_starts_expansion(
                command,
                index,
                allow_quoted_literal=True,
            ):
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


def _env_prefix_name(word: MiniShellWord) -> str | None:
    """할당 word 의 소스 텍스트에서 `=` 앞 변수 이름만 뽑아낸다.

    `word.assignment_index` 는 `_exact_assignment_index` 가 `source_value` 기준으로
    확정한 활성(비인용) `=` 의 위치다. 그 교차 필드 불변식이 깨진 word 는 이름을
    신뢰할 수 없으므로 `None` 을 돌려 호출자가 fail-closed 로 처리하게 한다.
    `source_value[:None]` 이 토큰 전체를 조용히 돌려주는 파이썬 슬라이스 특성 때문에
    불변식 위반이 무증상으로 통과하지 않도록 명시적으로 막는다.
    """
    index = word.assignment_index
    if index is None or not 0 <= index < len(word.source_value):
        return None
    if word.source_value[index] != "=":
        return None
    return word.source_value[:index]


def _is_unmodeled_assignment_prefix(word: MiniShellWord) -> bool:
    """bash 는 환경 접두사로 적용하지만 MiniShell 이 할당으로 표시하지 않는 형태인가.

    `NAME+=VALUE` 는 bash 가 접두사 할당으로 실제 적용하지만(실측 확인),
    `_exact_assignment_index` 는 `=` 앞이 `NAME+` 라서 이름 문법을 만족하지 못해
    `assignment_index` 를 남기지 않는다. 그 결과 이 word 는 할당이 아니라 명령어로
    취급되어 FIX-5 이름 검사를 통째로 건너뛴다. 모델링하지 못하는 할당 형태는
    안전을 증명할 수 없으므로 fail-closed 로 거부한다.

    인용된 형태(`"FOO"+=x`)는 bash 가 할당으로 보지 않으므로 대상이 아니다 —
    `_exact_assignment_index` 와 동일한 활성/배리어 규칙을 적용한다.
    """
    if word.assignment_index is not None:
        return False
    match = MINISHELL_APPEND_ASSIGNMENT_RE.match(word.source_value)
    if match is None:
        return False
    equals_index = match.end() - 1
    if not all(word.active[: equals_index + 1]):
        return False
    return not any(boundary <= equals_index for boundary in word.barriers)


def _env_operand_name(word: MiniShellWord) -> str | None:
    """`env` 피연산자에서 환경변수 이름을 뽑는다 — 셸 인용을 무시한다.

    coreutils `env` 는 셸 할당 문법을 검사하지 않는다. 인용 제거가 끝난 argv 원소가
    `=` 를 포함하기만 하면 그대로 putenv() 한다. 따라서 셸이 할당으로 보지 않는
    `env 'GIT_EXTERNAL_DIFF'=/tmp/evil.sh git diff` 나 `env NAME\\=v cmd` 도 실제로는
    환경에 적용된다(실측 확인). `assignment_index` 는 인용된 문자를 비활성으로 보고
    할당 표시를 남기지 않으므로, `env` 피연산자 구간에서는 인용이 제거된
    `word.value` 를 기준으로 이름을 다시 판정해야 한다.

    `=` 가 없으면 그 word 가 곧 실행할 명령어이므로 `None` 을 돌려 소비를 멈춘다.
    """
    equals_index = word.value.find("=")
    if equals_index <= 0:
        return None
    return word.value[:equals_index]


def _has_unsafe_env_prefix_name(
    words: tuple[MiniShellWord, ...],
    start: int,
    end: int,
) -> bool:
    """[start, end) 구간의 환경변수 할당 이름이 시드 화이트리스트 밖이면 True.

    정확 이름 일치만 검사한다(접두사/글롭 금지) — `TERM*` 글롭이 `TERMINFO` 를
    재승인시키는 실패 형태를 피하기 위함(AC-5.6). 이름을 추출할 수 없는 word 는
    안전을 증명할 수 없으므로 unsafe 로 간주한다(fail-closed).
    """
    for index in range(start, end):
        name = _env_prefix_name(words[index])
        if name is None or name not in MINISHELL_ALLOWED_ENV_PREFIX_NAMES:
            return True
    return False


def _routing_start(
    words: tuple[MiniShellWord, ...],
    argv: tuple[str, ...],
) -> int:
    """라우팅이 시작되는 word 인덱스를 계산한다.

    반환값 의미: `>= 0` 은 라우팅 시작 인덱스, `-1` 은 기존 `restricted_env_denied`
    (`env` 뒤에 알 수 없는 플래그가 오거나, `env` 뒤에 명령어 word 자체가 없는 경우),
    `-2` 는 신규 `unsafe_env_name_denied`(FIX-5 — 접두사 변수 이름이 화이트리스트 밖
    이거나, 모델링하지 못하는 접두사 할당 형태). 두 원인은 §5.4/§5.6 측정이
    `reason_code` 로 필터링하므로 호출자가 구분해서 처리해야 한다(classify_command 참고).

    음수 센티넬을 인덱스로 다시 쓰면 파이썬 음수 인덱싱 때문에 조용히 잘못된 word 를
    가리키므로, 모든 호출부는 인덱싱 전에 `< 0` 을 먼저 검사해야 한다.
    """
    index = 0
    saw_env = False
    # 각 반복은 `env` 또는 `--` 를 최소 한 개 소비하므로 word 수만큼이면 충분하다.
    # PreToolUse 훅 안에서 도는 코드라 구조적 종료 보장을 명시한다(무한 루프 = 행).
    for _ in range(len(words) + 1):
        assignment_start = index
        while index < len(words) and words[index].assignment_index is not None:
            index += 1
        # 이름 검사는 어떤 조기 반환보다도 먼저 수행한다. 명령어 없는 할당 전용
        # 세그먼트(`PATH=/tmp/evil`)도 `assignment_only_denied` 라는 다른 백스톱에
        # 의존하지 않고 자신의 원인 코드로 거부되어야 §5.4/§5.6 측정이 눈을 뜬다.
        if _has_unsafe_env_prefix_name(words, assignment_start, index):
            return -2
        # 모델링하지 못하는 접두사 할당(`NAME+=VALUE`)이 라우팅 헤드 자리에 오면
        # 이름 검사를 건너뛴 채 명령어로 취급되므로 여기서 fail-closed 로 막는다.
        if index < len(words) and _is_unmodeled_assignment_prefix(words[index]):
            return -2
        if saw_env:
            # coreutils `env` 문법은 `env [옵션]... [--] [NAME=VALUE]... [명령]` 이며
            # `--` 는 할당 목록의 앞뒤 어느 쪽에도 올 수 있다. `--` 를 소비한 뒤에도
            # 할당이 이어질 수 있으므로 루프 선두로 돌아가 이름 검사를 다시 수행한다.
            if index < len(words) and argv[index] == "--":
                index += 1
                continue
            # `env` 피연산자는 셸 할당 문법이 아니라 "`=` 를 포함한 argv 원소" 규칙을
            # 따른다. 인용으로 셸 할당 표시를 피한 형태도 env 가 그대로 적용하므로
            # 인용 제거된 value 기준으로 한 번 더 검사한다(§_env_operand_name).
            if index < len(words):
                operand_name = _env_operand_name(words[index])
                if operand_name is not None:
                    if operand_name not in MINISHELL_ALLOWED_ENV_PREFIX_NAMES:
                        return -2
                    index += 1
                    continue
            # 이름 문제가 아닌 미지의 `env` 플래그는 기존 원인을 유지한다.
            if index >= len(words) or argv[index].startswith("-"):
                return -1
        if index >= len(words):
            return index
        if command_basename(argv[index]) != "env":
            return index

        # `env env NAME=VALUE cmd` 같은 중첩 호출도 각 단계마다 할당 구간을 검사한다.
        index += 1
        saw_env = True

    # 도달 불가(매 반복이 word 를 최소 하나 소비한다). 방어적으로 fail-closed.
    return -1


def _routing_start_index(parsed: MiniShellParse) -> int:
    return _routing_start(parsed.words, parsed.argv)


def _routing_argv(parsed: MiniShellParse) -> tuple[str, ...]:
    """라우팅 대상 argv. 거부 센티넬(`-1`/`-2`)은 빈 튜플로 fail-closed 처리한다.

    센티넬을 그대로 슬라이스하면 파이썬 음수 인덱싱 때문에 `argv[-2:]` 가 마지막 두
    토큰을 조용히 돌려주어, 불변식 위반이 예외가 아니라 "잘못된 word 에 대한 라우팅
    결정"으로 둔갑한다.
    """
    route_start = _routing_start_index(parsed)
    if route_start < 0:
        return ()
    return parsed.argv[route_start:]


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


def _wc_is_safe(argv: tuple[str, ...], *, allow_files: bool) -> bool:
    """wc 인자가 안전한 라우팅 대상인지 판정한다.

    플래그는 -c/-l/-m/-w 조합만 허용한다. 파일 피연산자는 `_cat_is_safe`(:1138)와
    대칭으로 `allow_files`가 True일 때만 허용한다 — role이 "filter"(파이프 중간)면
    stdin만 읽어야 하므로 파일 인자를 거부해야 한다. `--` 이후 토큰은 전부
    피연산자로 취급한다(pathspec 구분자와 동일한 관례).
    """
    operands = 0
    options_done = False
    for argument in argv[1:]:
        if not options_done and argument == "--":
            options_done = True
            continue
        if not options_done and argument.startswith("-") and argument != "-":
            if (
                argument.startswith("--")
                or not argument[1:]
                or not set(argument[1:]).issubset({"c", "l", "m", "w"})
            ):
                return False
            continue
        operands += 1
    return allow_files or operands == 0


def _head_tail_is_safe(argv: tuple[str, ...], *, allow_files: bool) -> bool:
    """head/tail 인자가 안전한 라우팅 대상인지 판정한다.

    `-n`/`--lines`(및 `-N`/`-nN`/`--lines=N` 축약형)는 최대 1회만 허용하며 유효한
    양의 정수여야 한다. **`-n` 미지정도 허용한다** — bare `head`/`tail`은 기본
    10줄 상한이 이미 적용되므로 무제한 출력 위험이 없다. `tail -f`/`-F`는 무제한
    스트림이므로 allow_files 여부와 무관하게 항상 거부한다(`bash -lc` 내부에서
    프로세스가 종결되지 않는 것을 방지). `-c`(바이트 단위)는 지원하지 않는다 —
    trim 예산 단위는 줄(line)이라 바이트 상한과 섞일 수 없다.
    """
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
    return allow_files or index == len(argv)


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


GIT_TABLE_SUBCOMMANDS = frozenset({
    "status", "log", "branch", "tag", "rev-parse", "describe", "ls-files",
    "shortlog", "blame", "stash", "diff", "show", "grep",
})
"""§6.1b 11행 쌍 화이트리스트가 다루는 git 서브커맨드 집합 — `diff`/`show`/`grep`은
한 표 행을 공유하므로 13개 서브커맨드가 11행이 된다. 오라클 `git-*` family 집합과의
동치 검증(AC-1b.3, R-11)이 이 상수를 그대로 참조한다 — 행을 늘리고 family를
빠뜨리면 그 테스트가 실패한다."""


def _git_flags_and_positionals(
    arguments: tuple[str, ...],
    *,
    long_flags: frozenset[str],
    short_flags: frozenset[str],
) -> int | None:
    """옵션을 소비하며 위치 인자 개수를 반환한다. 미지 플래그면 `None`.

    `--` 토큰 자체는 위치 인자로 계수하지 않되, 그 이후 토큰은 옵션 파싱을 끄고
    전부 위치 인자로 계수한다(AC-1.10 — `git log a..b -- p1 p2 p3`는 `--`를
    빼면 정확히 4개다. 과거 결함은 오버플로가 아니라 이 규칙의 부재였다).
    묶음 단축 플래그(`-ad` 등)는 `-`로 시작하는 각 글자가 모두 `short_flags`에
    속해야 허용된다(분해 없이 집합 매칭 — AC-1.9). `git branch -ad`는 `{a,d}`로
    분해되고 `d`가 branch의 허용 집합에 없어 거부된다(D1 완화가 다시 쓰기를
    재승인하지 않는지 확인하는 회귀 핀).
    """
    positionals = 0
    options_done = False
    for argument in arguments:
        if not options_done and argument == "--":
            options_done = True
            continue
        if options_done:
            positionals += 1
            continue
        if argument in long_flags:
            continue
        if (
            argument.startswith("-")
            and not argument.startswith("--")
            and argument != "-"
            and set(argument[1:]).issubset(short_flags)
        ):
            continue
        if argument.startswith("-"):
            return None
        positionals += 1
    return positionals


_GIT_STATUS_LONG_FLAGS = frozenset({
    "--short", "--branch", "--porcelain", "--long", "--no-color",
    "--untracked-files",
})
_GIT_STATUS_SHORT_FLAGS = frozenset("sb")


def _git_status_is_safe(arguments: tuple[str, ...]) -> bool:
    """`git status`: 위치 인자 0개(§6.1b 표). `.git/index` stat-cache 갱신은
    허용된 부작용이다(AC-1.4 각주) — 이 함수의 쓰기 판정 대상이 아니다."""
    positionals = _git_flags_and_positionals(
        arguments,
        long_flags=_GIT_STATUS_LONG_FLAGS,
        short_flags=_GIT_STATUS_SHORT_FLAGS,
    )
    return positionals == 0


_GIT_BRANCH_LONG_FLAGS = frozenset({
    "--all", "--remotes", "--verbose", "--list", "--show-current",
    "--no-color", "--sort",
})
_GIT_BRANCH_SHORT_FLAGS = frozenset("arv")


def _git_branch_is_safe(arguments: tuple[str, ...]) -> bool:
    """`git branch`: 위치 인자 0개 엄격 — arity가 조회(0개)를 생성(1개+)으로
    뒤집는 서브커맨드다(D2 반증 사례, plan §6.1b). `--edit-description` 등
    쓰기 플래그는 표에 없어 미지 플래그로 거부된다."""
    positionals = _git_flags_and_positionals(
        arguments,
        long_flags=_GIT_BRANCH_LONG_FLAGS,
        short_flags=_GIT_BRANCH_SHORT_FLAGS,
    )
    return positionals == 0


_GIT_TAG_LONG_FLAGS = frozenset({"--list", "--sort", "--no-color"})


def _git_tag_is_safe(arguments: tuple[str, ...]) -> bool:
    """`git tag`: 위치 인자 0개 엄격 — branch와 동일하게 arity가 조회↔생성을
    뒤집는다(§6.1b 표). `-n`은 부착형 주석 줄 수만 허용한다 — 분리형 `-n 5`는
    다음 토큰 `5`가 미지 위치 인자로 남아 이미 안전하게 거부된다(subcommand별
    `-n` 의미 차이, AC-1.9 — log는 분리형 값, tag는 부착형, shortlog는 순수
    불리언)."""
    positionals = 0
    for argument in arguments:
        if argument == "--":
            continue
        if argument in _GIT_TAG_LONG_FLAGS or argument in {"-l", "-n"}:
            continue
        if re.fullmatch(r"-n[1-9]\d*", argument):
            continue
        if argument.startswith("-"):
            return False
        positionals += 1
    return positionals == 0


_GIT_REV_PARSE_LONG_FLAGS = frozenset({
    "--abbrev-ref", "--short", "--verify", "--show-toplevel", "--git-dir",
    "--is-inside-work-tree", "--quiet",
})


def _git_rev_parse_is_safe(arguments: tuple[str, ...]) -> bool:
    """`git rev-parse`: 위치 인자 무제한(revision 문자열, §6.1b 표) — 쓰기가
    되지 않는다."""
    positionals = _git_flags_and_positionals(
        arguments,
        long_flags=_GIT_REV_PARSE_LONG_FLAGS,
        short_flags=frozenset(),
    )
    return positionals is not None


_GIT_DESCRIBE_LONG_FLAGS = frozenset({
    "--tags", "--always", "--dirty", "--long", "--abbrev",
})


def _git_describe_is_safe(arguments: tuple[str, ...]) -> bool:
    """`git describe`: 위치 인자 무제한(§6.1b 표) — 쓰기가 되지 않는다."""
    positionals = _git_flags_and_positionals(
        arguments,
        long_flags=_GIT_DESCRIBE_LONG_FLAGS,
        short_flags=frozenset(),
    )
    return positionals is not None


_GIT_LS_FILES_LONG_FLAGS = frozenset({
    "--cached", "--modified", "--others", "--exclude-standard", "--stage",
    "--deleted",
})
_GIT_LS_FILES_SHORT_FLAGS = frozenset("cmos")


def _git_ls_files_is_safe(arguments: tuple[str, ...]) -> bool:
    """`git ls-files`: 위치 인자 무제한(pathspec 필터, §6.1b 표) — 쓰기가
    되지 않는다."""
    positionals = _git_flags_and_positionals(
        arguments,
        long_flags=_GIT_LS_FILES_LONG_FLAGS,
        short_flags=_GIT_LS_FILES_SHORT_FLAGS,
    )
    return positionals is not None


_GIT_SHORTLOG_LONG_FLAGS = frozenset({
    "--summary", "--numbered", "--email", "--no-color",
})
_GIT_SHORTLOG_SHORT_FLAGS = frozenset("sne")


def _git_shortlog_is_safe(arguments: tuple[str, ...]) -> bool:
    """`git shortlog`: 위치 인자 무제한(§6.1b 표). `-n`은 여기서 `--numbered`
    (값을 취하지 않는 순수 불리언)다 — log의 max-count `-n`과 의미가 다르다
    (subcommand별 `-n` 의미 차이, AC-1.9)."""
    positionals = _git_flags_and_positionals(
        arguments,
        long_flags=_GIT_SHORTLOG_LONG_FLAGS,
        short_flags=_GIT_SHORTLOG_SHORT_FLAGS,
    )
    return positionals is not None


def _git_blame_is_safe(arguments: tuple[str, ...]) -> bool:
    """`git blame`: 위치 인자 무제한이나 경로 1개 이상 필수(§6.1b 표).
    `-L`은 값을 취한다(부착 `-L10,20` 또는 분리 `-L 10,20` 모두 허용 — 범위
    문자열 자체를 검증하지 않아도 안전하다, sanitize 240줄 상한이 출력을
    이미 유계화한다)."""
    positionals = 0
    options_done = False
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if not options_done and argument == "--":
            options_done = True
            index += 1
            continue
        if not options_done and argument in {"--porcelain", "--line-porcelain", "-w"}:
            index += 1
            continue
        if not options_done and argument == "-L":
            if index + 1 >= len(arguments):
                return False
            index += 2
            continue
        if not options_done and argument.startswith("-L") and len(argument) > 2:
            index += 1
            continue
        if not options_done and argument.startswith("-"):
            return False
        positionals += 1
        index += 1
    return positionals >= 1


def _git_stash_is_safe(arguments: tuple[str, ...]) -> bool:
    """`git stash`: `list`/`show`만 허용, 부가 인자 없는 정확히 그 형태만
    — 맨 `git stash`(0-arity writer, D2 반증 사례)와 그 밖의 서브커맨드
    (`push`/`pop`/`apply`/`drop`/`clear`/`branch`/`save`)는 표에 없어
    거부된다(§6.1b 표)."""
    return len(arguments) == 1 and arguments[0] in {"list", "show"}


_GIT_DIFF_SHOW_BOOLEAN_FLAGS = frozenset({
    "-p", "--patch", "--stat", "--name-only", "--name-status", "--no-color",
    "--color=never", "--cached", "--staged", "--oneline",
})


def _git_diff_show_is_safe(arguments: tuple[str, ...]) -> bool:
    """`git diff`/`git show`: 기존 `_git_is_safe` 경로를 그대로 보존한다
    (§6.1b 표 — "기존대로"). 개조 전 `patch_output`은 diff/show에서
    항상 `True`로 시작해 끝까지 `False`로 바뀌는 경로가 없었으므로(오직
    log에서만 `-p` 요구가 의미 있었다) 여기서는 제거했다 — 동작은 동일하다."""
    index = 0
    options_done = False
    while index < len(arguments):
        argument = arguments[index]
        if not options_done and argument == "--":
            options_done = True
            index += 1
            continue
        if options_done:
            index += 1
            continue
        if argument in _GIT_DIFF_SHOW_BOOLEAN_FLAGS:
            index += 1
            continue
        if argument in {"-U", "--unified"}:
            if index + 1 >= len(arguments) or not _valid_n(arguments[index + 1]):
                return False
            index += 2
            continue
        if re.fullmatch(r"-U[1-9]\d*", argument) or (
            argument.startswith("--unified=")
            and _valid_n(argument.split("=", 1)[1])
        ):
            index += 1
            continue
        if argument.startswith("-"):
            return False
        index += 1
    return True


_GIT_LOG_BOOLEAN_FLAGS = frozenset({
    "--oneline", "--stat", "--name-only", "--name-status", "--graph",
    "--decorate", "--no-color", "-p", "--patch", "--reverse",
})
_GIT_LOG_VALUE_FLAGS = frozenset({
    "--pretty", "--format", "--author", "--since", "--until",
})


def _git_log_attached_value_ok(argument: str) -> bool:
    """`-<N>`/`-U<N>`/`--unified=<N>`/`--max-count=<N>`/`--<value-flag>=…`
    부착형이 안전한지 판정한다(AC-1.9 — `git log --oneline -20` 같은 부착형이
    거짓 거부되지 않도록 분해 전에 먼저 인식한다)."""
    if re.fullmatch(r"-[1-9]\d*", argument):
        return True
    if re.fullmatch(r"-U[1-9]\d*", argument):
        return True
    if argument.startswith("--unified=") and _valid_n(argument.split("=", 1)[1]):
        return True
    if argument.startswith("--max-count=") and _valid_n(argument.split("=", 1)[1]):
        return True
    return any(argument.startswith(f"{flag}=") for flag in _GIT_LOG_VALUE_FLAGS)


def _git_log_is_safe(arguments: tuple[str, ...]) -> bool:
    """`git log`: 위치 인자 무제한(revision/pathspec, §6.1b 표) — arity가
    쓰기로 뒤집히지 않으므로 상한이 불필요하다. 출력 증폭은 sanitize 240줄
    상한(`sanitize_output.py:295`)으로 이미 유계다. 개조 전에는 `-p` 없이
    `git log`/`git log --oneline`이 거부됐다(§0 정정 1) — 이 요구를 제거한
    것이 이 함수의 핵심 완화다."""
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            return True
        if argument in _GIT_LOG_BOOLEAN_FLAGS:
            index += 1
            continue
        if argument in {"-n", "--max-count", "-U", "--unified"}:
            if index + 1 >= len(arguments) or not _valid_n(arguments[index + 1]):
                return False
            index += 2
            continue
        if argument in _GIT_LOG_VALUE_FLAGS:
            if index + 1 >= len(arguments):
                return False
            index += 2
            continue
        if _git_log_attached_value_ok(argument):
            index += 1
            continue
        if argument.startswith("-"):
            return False
        index += 1
    return True


def _git_is_safe(argv: tuple[str, ...]) -> bool:
    """git (서브커맨드, 인자 형태) 쌍 화이트리스트(D1, plan §6.1b, 11행).

    R-5 불변식(표 전체를 지탱하는 단일 지점) — `argv[1]`을 리터럴로만
    서브커맨드로 인정한다. `-`로 시작하면 무조건 거부하고, 서브커맨드를
    찾기 위해 선행 전역 옵션(`-c`/`-C`/`-p`/`--paginate`/`--no-pager`/
    `--exec-path`/`--git-dir` 등)을 절대 건너뛰지 않는다.
    **경고**: `_package_script_route:1436`의
    `while index < len(argv) and argv[index].startswith("-")` 패턴을 이
    함수에 재사용하지 말 것 — 그 패턴을 쓰면 `git -c alias.zz='!echo pwned' zz`
    가 임의 셸을 실행한다(3라운드 레드팀 실증, plan §4 시나리오 1). 현재
    9개 전역 옵션 우회(AC-1b.2)가 전부 막히는 이유는 오직 이 리터럴 비교
    하나다.

    R-1 불변식 — 서브커맨드 이름만으로도, "위치 인자 0개면 거부"만으로도
    승인하지 않는다. 전자는 쓰기 6/6 누수, 후자는 0-arity 쓰기 8건 누수를
    실증했다(`git stash`/`gc`/`prune`/`repack`/`clean -fd`/`reset --hard`/
    `commit --amend --no-edit`/`branch --edit-description`; 뒤 둘은 데이터
    손실이다). 반드시 (서브커맨드, 허용 플래그, 위치 인자 상한) 삼중으로
    판정한다. 표에 없는 서브커맨드(`config`/`remote`/`gc`/`prune`/`repack`/
    `clean`/`reset`/`commit`/`push`/`pull`/`fetch`/`merge`/`rebase`/
    `checkout`/`switch`/`restore` 등)는 아래 분기에 없어 자동으로 폴스루
    거부된다 — never-list는 두지 않는다(이미 deny인 폴스루에 목록을 얹으면
    "목록에 없으면 안전"이라는 오독만 유발할 뿐 방어를 강화하지 않는다,
    plan 결정 D1). `config`/`remote`는 키 없이 값만 출력하거나 자격증명이
    임베드된 URL을 출력해 구조적으로 리댁션이 불가능하므로(원칙 6, R-13)
    표에서 삭제되었다 — `remote`는 FIX-6에서 `credential_policy.py` 확장
    후 재도입 심사 대상이다.
    """
    if len(argv) < 2 or argv[1].startswith("-"):
        return False
    subcommand = argv[1]
    arguments = argv[2:]
    if subcommand == "status":
        return _git_status_is_safe(arguments)
    if subcommand == "log":
        return _git_log_is_safe(arguments)
    if subcommand == "branch":
        return _git_branch_is_safe(arguments)
    if subcommand == "tag":
        return _git_tag_is_safe(arguments)
    if subcommand == "rev-parse":
        return _git_rev_parse_is_safe(arguments)
    if subcommand == "describe":
        return _git_describe_is_safe(arguments)
    if subcommand == "ls-files":
        return _git_ls_files_is_safe(arguments)
    if subcommand == "shortlog":
        return _git_shortlog_is_safe(arguments)
    if subcommand == "blame":
        return _git_blame_is_safe(arguments)
    if subcommand == "stash":
        return _git_stash_is_safe(arguments)
    if subcommand == "grep":
        return _grep_is_safe(("grep", *arguments), allow_files=True)
    if subcommand in {"diff", "show"}:
        return _git_diff_show_is_safe(arguments)
    return False


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
        if role == "first" or not _wc_is_safe(argv, allow_files=role != "filter"):
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
        if route_start == -2:
            return CommandDecision(
                action="deny",
                parsed=parsed,
                reason="MiniShell-v1 denied an unsafe environment prefix name (unsafe_env_name_denied).",
                reason_code="unsafe_env_name_denied",
            )
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
