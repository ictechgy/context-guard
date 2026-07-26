#!/usr/bin/env python3
"""Sanitize grep/diff/log output before it enters Claude context.

The helper can wrap a command while preserving its exit code, or sanitize stdin.
It redacts common credential patterns, anonymizes absolute paths by default, and
keeps only bounded head/anchor/tail context when output is too large.
"""
from __future__ import annotations

import argparse
import codecs
import collections
from dataclasses import dataclass
import hashlib
import importlib.util
import os
from pathlib import Path, PurePosixPath
import queue
import re
import signal
import subprocess
import sys
import threading
import time
from types import ModuleType
from typing import BinaryIO, Iterable, Iterator, TextIO


def load_credential_policy() -> ModuleType:
    script_dir = Path(__file__).resolve().parent
    candidate = (
        script_dir.parent / "lib" / "credential_policy.py"
        if script_dir.name == "bin"
        else script_dir / "credential_policy.py"
    )
    spec = importlib.util.spec_from_file_location(
        "_context_guard_sanitize_credential_policy",
        candidate,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load credential policy: {candidate}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_CREDENTIAL_POLICY = load_credential_policy()
SECRET_KEY = _CREDENTIAL_POLICY.SECRET_KEY
CAMEL_ACRONYM_BOUNDARY_RE = _CREDENTIAL_POLICY.CAMEL_ACRONYM_BOUNDARY_RE
CAMEL_WORD_BOUNDARY_RE = _CREDENTIAL_POLICY.CAMEL_WORD_BOUNDARY_RE
normalize_sensitive_key = _CREDENTIAL_POLICY.normalize_sensitive_key
is_sensitive_key = _CREDENTIAL_POLICY.is_sensitive_key
redact_url_like_secret_params = _CREDENTIAL_POLICY.redact_url_like_secret_params
redact_high_confidence_credentials = _CREDENTIAL_POLICY.redact_high_confidence_credentials

TERMINAL_CONTROL_RE = re.compile(
    r"(?:"
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|"  # OSC title/clipboard controls
    r"\x1b[@-_][0-?]*[ -/]*[@-~]|"          # CSI and other ESC sequences
    r"[\x00-\x08\x0b\x0c\x0d\x0e-\x1f\x7f-\x9f]"
    r")"
)
# Match plausible absolute file paths without treating operators (`//`) or
# tiny string literals (`"/"`) as paths. Requiring at least one directory plus
# one leaf keeps the sanitizer from corrupting code while still anonymizing
# common grep/test output like /Users/me/project/app.py:12.
PATH_SEGMENT = r"[A-Za-z0-9._~+\-]+"
ABSOLUTE_PATH_RE = re.compile(
    rf"(?P<prefix>^|[\s('\"=])(?P<path>/(?:{PATH_SEGMENT}/)+{PATH_SEGMENT})"
)
WINDOWS_PATH_RE = re.compile(
    rf"(?P<prefix>^|[\s('\"=])(?P<path>[A-Za-z]:\\(?:{PATH_SEGMENT}\\)+{PATH_SEGMENT})"
)
TRACEBACK_PATH_RE = re.compile(
    rf"(?P<prefix>\bFile\s+[\"'])(?P<path>/(?:{PATH_SEGMENT}/)+{PATH_SEGMENT})"
    r"(?P<suffix>[\"'],\s+line\s+\d+)"
)
LOCATION_PATH_RE = re.compile(
    rf"(?P<prefix>^(?:\s*[+-]\s*)?)(?P<path>/(?:{PATH_SEGMENT}/)+{PATH_SEGMENT})"
    r"(?P<suffix>:\d+(?::\d+)?(?=[:\s]|$))"
)
DIFF_PATH_RE = re.compile(
    rf"(?P<prefix>^(?:---|\+\+\+)\s+)(?P<path>/(?:{PATH_SEGMENT}/)+{PATH_SEGMENT})"
    r"(?P<suffix>(?:\t.*)?$)"
)
LISTING_PATH_RE = re.compile(
    rf"(?P<prefix>^\s*)(?P<path>/(?:{PATH_SEGMENT}/)+{PATH_SEGMENT})"
    r"(?P<suffix>/?(?:\s+->\s+\S+)?\s*$)"
)
PRIVATE_KEY_BEGIN_RE = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|OPENSSH PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----"
)
PRIVATE_KEY_END_RE = re.compile(
    r"-----END (?:[A-Z0-9 ]*PRIVATE KEY|OPENSSH PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----"
)
AUTH_HEADER_RE = re.compile(
    r"(?i)^(?P<prefix>\s*(?:(?:[^:\n]+):\d+(?::\d+)?:)?\s*(?:[+-]\s*)?(?:Proxy-)?Authorization\s*:\s*).+$"
)
COOKIE_HEADER_RE = re.compile(
    r"(?i)^(?P<prefix>\s*(?:(?:[^:\n]+):\d+(?::\d+)?:)?\s*(?:[+-]\s*)?(?:Set-)?Cookie\s*:\s*).+$"
)
INLINE_QUOTED_SECRET_ASSIGNMENT_RE = re.compile(
    rf"(?i)(?P<lead>^|[\s;{{\[,])"
    rf"(?P<prefix>(?:(?:[^:\n]+):\d+(?::\d+)?:)?\s*(?:[+-]\s*)?(?:export\s+)?"
    rf"[\"']?(?:{SECRET_KEY})[\"']?\s*[:=]\s*)"
    rf"(?P<quote>[\"'])(?P<value>(?:\\.|(?!(?P=quote)).)*)(?P=quote)(?P<tail>[^\s,;}}\]]*)"
)
CODE_IDENTIFIER = r"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*"
CALL_ARGUMENT_CHUNK = r"(?:[^()\"'\n;]+|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|\([^()]*\))*"
INLINE_UNQUOTED_CALL_SECRET_ASSIGNMENT_RE = re.compile(
    rf"(?i)(?P<lead>^|[\s;{{\[,])"
    rf"(?P<prefix>(?:(?:[^:\n]+):\d+(?::\d+)?:)?\s*(?:[+-]\s*)?(?:export\s+)?"
    rf"[\"']?(?:{SECRET_KEY})[\"']?\s*[:=]\s*)"
    rf"(?P<value>(?![\"']){CODE_IDENTIFIER}\({CALL_ARGUMENT_CHUNK}\))"
)
SECRET_IDENTIFIER_PART = (
    r"(?:[A-Za-z_$][A-Za-z0-9_$]*(?:api_?key|apikey|token|secret|password|passwd|pwd|"
    r"private_?key|access_?key|client_?secret|sessionid|session_id|session_token|"
    r"csrf_token|xsrf_token)[A-Za-z0-9_$]*|session|sid|csrf|xsrf)"
)
FALLBACK_SECRET_OPERAND = rf"(?:[A-Za-z_$][A-Za-z0-9_$]*\.)*{SECRET_IDENTIFIER_PART}"
INLINE_UNQUOTED_FALLBACK_SECRET_ASSIGNMENT_RE = re.compile(
    rf"(?i)(?P<lead>^|[\s;{{\[,])"
    rf"(?P<prefix>(?:(?:[^:\n]+):\d+(?::\d+)?:)?\s*(?:[+-]\s*)?(?:export\s+)?"
    rf"[\"']?(?:{SECRET_KEY})[\"']?\s*[:=]\s*)"
    rf"(?P<value>(?![\"']|\[REDACTED\])"
    rf"[^;\n]*?(?:\bor\b|\|\||\?\?|\belse\b|\?[^:\n;]*:)\s*"
    rf"(?:[\"'](?:\\.|[^\"'\\])*[\"']|{FALLBACK_SECRET_OPERAND})[^;\n]*)"
)
INLINE_UNQUOTED_BRACKETED_SECRET_ASSIGNMENT_RE = re.compile(
    rf"(?i)(?P<lead>^|[\s;{{\[,])"
    rf"(?P<prefix>(?:(?:[^:\n]+):\d+(?::\d+)?:)?\s*(?:[+-]\s*)?(?:export\s+)?"
    rf"[\"']?(?:{SECRET_KEY})[\"']?\s*[:=]\s*)"
    rf"(?P<value>(?![\"']|\[REDACTED\])"
    rf"[^\s,;}}\]]*(?:\([^;\n]*?\)|\{{[^;\n]*?\}}|\[[^;\n]*?\])[^\s,;}}\]]*)"
)
INLINE_UNQUOTED_SECRET_ASSIGNMENT_RE = re.compile(
    rf"(?i)(?P<lead>^|[\s;{{\[,])"
    rf"(?P<prefix>(?:(?:[^:\n]+):\d+(?::\d+)?:)?\s*(?:[+-]\s*)?(?:export\s+)?"
    rf"[\"']?(?:{SECRET_KEY})[\"']?\s*[:=]\s*)"
    rf"(?P<value>(?![\"']|\[REDACTED\])[^\s,;}}\]]+)"
)
UNQUOTED_MULTILINE_SECRET_ASSIGNMENT_RE = re.compile(
    rf"(?i)(?:^|[\s;{{\[,])"
    rf"(?:(?:[^:\n]+):\d+(?::\d+)?:)?\s*(?:[+-]\s*)?(?:export\s+)?"
    rf"[\"']?(?:{SECRET_KEY})[\"']?\s*[:=]\s*(?P<value>(?![\"']).*)$"
)
CONTINUATION_OPERATOR_RE = re.compile(
    r"(?i)(?:\\|\|\||&&|\?\?|[+*/%&|^?,]|\?|:|\bor\b|\band\b|\belse\b)\s*(?://.*|#.*)?$"
)
SAFE_UNQUOTED_VALUES = {
    "[redacted]",
    "bool",
    "boolean",
    "bytes",
    "false",
    "float",
    "int",
    "integer",
    "none",
    "null",
    "object",
    "os.getenv",
    "process.env",
    "str",
    "string",
    "true",
    "undefined",
    "unknown",
}
IDENTIFIER_CHAIN_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+$")
SAFE_ENV_LOOKUP_CALL_RE = re.compile(r"^(?:os\.getenv|os\.environ\.get)\(\s*[\"'][A-Za-z0-9_.-]{1,80}[\"']\s*\)$")
SAFE_RE_COMPILE_CALL_RE = re.compile(r"^re\.compile\([^;\n]*\)$")
SAFE_CODE_EXPRESSION_CALL_RE = re.compile(rf"^{CODE_IDENTIFIER}\(\s*(?:{CODE_IDENTIFIER}(?:\s*,\s*{CODE_IDENTIFIER})*)?\s*\)$")
GETTER_CALL_RE = re.compile(rf"^{CODE_IDENTIFIER}\.get\(\s*[\"'](?P<key>[A-Za-z0-9_.-]{{1,80}})[\"']\s*\)$")
SAFE_GETTER_KEY_NAMES = {
    "access_key",
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "aws_access_key_id",
    "aws_secret_access_key",
    "aws_session_token",
    "azure_client_secret",
    "client_id",
    "client_secret",
    "cookie",
    "credential",
    "credentials",
    "csrf",
    "google_application_credentials",
    "jwt",
    "password",
    "passwd",
    "private_key",
    "pwd",
    "refresh_token",
    "secret",
    "session",
    "session_id",
    "sessionid",
    "sid",
    "token",
}
ASSIGNMENT_KEY_RE = re.compile(
    r"(?P<key>[A-Za-z_$][A-Za-z0-9_$.-]*)[\"']?\s*[:=]\s*$"
)
SOURCE_SAFE_VALUE_RE = re.compile(
    r"^(?:"
    r"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*|"
    r"[A-Za-z_$][A-Za-z0-9_$]*(?:\[[A-Za-z0-9_$., |]+\])+|"
    r"\d+(?:\.\d+)?|"
    r"\$\{[A-Za-z0-9_.-]+\}|"
    r"<[A-Za-z0-9_.-]+>|"
    r"(?:YOUR|REPLACE|EXAMPLE|PLACEHOLDER)_[A-Z0-9_]+"
    r")$"
)
ANCHOR_RE = re.compile(
    r"^(?:diff --git |index [0-9a-f]|--- |\+\+\+ |@@ |Binary files |(?:[^:\n]+):\d+(?::\d+)?:)",
    re.IGNORECASE,
)
SECRET_WORD_RE = re.compile(r"(?i)\b(api[_-]?key|token|secret|password|private[_-]?key|client[_-]?secret)\b")
MAX_LINES_LIMIT = 5_000
MAX_CHARS_LIMIT = 1_000_000
MAX_LINE_CHARS_LIMIT = 100_000
MAX_SECTION_LINES_LIMIT = 2_000
DEFAULT_TIMEOUT_SECONDS = 600
MAX_TIMEOUT_SECONDS = 86_400
TIMEOUT_EXIT_CODE = 124
COMMAND_READ_CHUNK_BYTES = 64 * 1024
COMMAND_MAX_UNTERMINATED_LINE_CHARS = 4_096
RAW_TRUNCATION_REDACTION_HOLDBACK_CHARS = 1_024


SANITIZATION_MODES = (
    "unknown_text",
    "command_search_diff",
    "filesystem_listing",
    "source_code",
)


@dataclass(frozen=True)
class SanitizationContext:
    mode: str = "unknown_text"
    private_roots: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.mode not in SANITIZATION_MODES:
            raise ValueError(f"unsupported sanitization context: {self.mode}")
        object.__setattr__(
            self,
            "private_roots",
            tuple(str(root) for root in self.private_roots),
        )


def coerce_sanitization_context(
    value: SanitizationContext | str,
    *,
    private_roots: Iterable[str] = (),
) -> SanitizationContext:
    if isinstance(value, SanitizationContext):
        supplied_roots = tuple(str(root) for root in private_roots)
        normalized_context_roots = _normalized_private_roots(value.private_roots)
        if supplied_roots and _normalized_private_roots(
            supplied_roots
        ) != normalized_context_roots:
            raise ValueError(
                "private_roots must be declared inside SanitizationContext "
                "when a context object is supplied"
            )
        roots = normalized_context_roots
        mode = value.mode
    else:
        roots = tuple(str(root) for root in private_roots)
        mode = str(value)
    return SanitizationContext(
        mode=mode,
        private_roots=_normalized_private_roots(roots),
    )


def bounded_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return min(max(number, minimum), maximum)


def normalize_budgets(args: argparse.Namespace) -> None:
    args.max_lines = bounded_int(args.max_lines, 240, 1, MAX_LINES_LIMIT)
    args.max_chars = bounded_int(args.max_chars, 24000, 1, MAX_CHARS_LIMIT)
    args.max_line_chars = bounded_int(args.max_line_chars, 3000, 1, MAX_LINE_CHARS_LIMIT)
    args.head_lines = bounded_int(args.head_lines, 50, 0, MAX_SECTION_LINES_LIMIT)
    args.tail_lines = bounded_int(args.tail_lines, 90, 0, MAX_SECTION_LINES_LIMIT)
    args.anchor_lines = bounded_int(args.anchor_lines, 80, 0, MAX_SECTION_LINES_LIMIT)
    args.timeout_seconds = bounded_int(
        args.timeout_seconds,
        DEFAULT_TIMEOUT_SECONDS,
        1,
        MAX_TIMEOUT_SECONDS,
    )


def strip_ansi(text: str) -> str:
    return TERMINAL_CONTROL_RE.sub("", text)


def stable_hash(value: str, length: int = 12) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:length]


def anonymized_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    name = PurePosixPath(normalized).name or "path"
    return f"{name}#path:{stable_hash(path)}"


def anonymize_absolute_paths_with_count(text: str) -> tuple[str, int]:
    count = 0

    def repl(match: re.Match[str]) -> str:
        nonlocal count
        prefix = match.group("prefix")
        path = match.group("path")
        count += 1
        return f"{prefix}{anonymized_path(path)}"

    text = ABSOLUTE_PATH_RE.sub(repl, text)
    return WINDOWS_PATH_RE.sub(repl, text), count


def anonymize_absolute_paths(text: str) -> str:
    return anonymize_absolute_paths_with_count(text)[0]


def _replace_named_paths(text: str, pattern: re.Pattern[str]) -> tuple[str, int]:
    count = 0

    def repl(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return (
            match.group("prefix")
            + anonymized_path(match.group("path"))
            + match.group("suffix")
        )

    return pattern.sub(repl, text), count


def _normalized_private_roots(private_roots: Iterable[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for root in private_roots:
        value = os.path.normpath(os.path.abspath(os.path.expanduser(str(root))))
        if value not in normalized:
            normalized.append(value)
    return tuple(normalized)


def _is_under_private_root(path: str, private_roots: tuple[str, ...]) -> bool:
    normalized = os.path.normpath(os.path.abspath(os.path.expanduser(path)))
    return any(
        normalized == root or normalized.startswith(root.rstrip(os.sep) + os.sep)
        for root in private_roots
    )


def anonymize_private_root_paths(
    text: str,
    private_roots: tuple[str, ...],
) -> tuple[str, int]:
    if not private_roots:
        return text, 0
    count = 0

    def repl(match: re.Match[str]) -> str:
        nonlocal count
        path = match.group("path")
        if not _is_under_private_root(path, private_roots):
            return match.group(0)
        count += 1
        return match.group("prefix") + anonymized_path(path)

    return ABSOLUTE_PATH_RE.sub(repl, text), count


def anonymize_paths_for_context(
    text: str,
    *,
    context: SanitizationContext,
) -> tuple[str, int]:
    if context.mode in {"unknown_text", "source_code"}:
        return text, 0

    total = 0
    if context.mode == "filesystem_listing":
        text, count = anonymize_private_root_paths(text, context.private_roots)
        total += count

    for pattern in (TRACEBACK_PATH_RE, LOCATION_PATH_RE, DIFF_PATH_RE):
        text, count = _replace_named_paths(text, pattern)
        total += count
    return text, total


def cap_line(line: str, max_line_chars: int) -> tuple[str, bool]:
    if max_line_chars <= 0 or len(line) <= max_line_chars:
        return line, False
    newline = "\n" if line.endswith("\n") else ""
    body = line[:-1] if newline else line
    marker = f"...[line trimmed: {len(body)} chars]"
    keep = max(0, max_line_chars - len(marker) - len(newline))
    return body[:keep] + marker + newline, True


def normalize_getter_key(key: str) -> str:
    key = CAMEL_ACRONYM_BOUNDARY_RE.sub("_", key)
    key = CAMEL_WORD_BOUNDARY_RE.sub("_", key)
    key = re.sub(r"[_.-]+", "_", key)
    return re.sub(r"_+", "_", key).strip("_").lower()


def assignment_key(prefix: str) -> str | None:
    match = ASSIGNMENT_KEY_RE.search(prefix)
    return match.group("key") if match is not None else None


def is_safe_getter_key(key: str) -> bool:
    return normalize_getter_key(key) in SAFE_GETTER_KEY_NAMES


def should_redact_unquoted_secret_value(
    line: str,
    match: re.Match[str],
    *,
    context: SanitizationContext,
) -> bool:
    value = match.group("value").strip()
    prefix = match.group("prefix")
    if not value:
        return False
    if value.lower() in SAFE_UNQUOTED_VALUES:
        return False
    if re.search(r":\s*$", prefix):
        return not (
            context.mode == "source_code"
            and SOURCE_SAFE_VALUE_RE.match(value) is not None
        )
    if IDENTIFIER_CHAIN_RE.match(value):
        return False
    if SAFE_ENV_LOOKUP_CALL_RE.match(value) or SAFE_RE_COMPILE_CALL_RE.match(value):
        return False
    if context.mode == "source_code" and SOURCE_SAFE_VALUE_RE.match(value):
        return False
    getter_match = GETTER_CALL_RE.match(value)
    if re.search(r"\s[:=]\s*$", prefix) and (
        SAFE_CODE_EXPRESSION_CALL_RE.match(value)
        or (getter_match is not None and is_safe_getter_key(getter_match.group("key")))
    ):
        return False
    return True


def redact_secret_assignments(
    line: str,
    *,
    context: SanitizationContext,
) -> tuple[str, bool]:
    line, redacted = redact_url_like_secret_params(line)

    def quoted_repl(match: re.Match[str]) -> str:
        nonlocal redacted
        key = assignment_key(match.group("prefix"))
        if key is None or not is_sensitive_key(key):
            return match.group(0)
        redacted = True
        return f"{match.group('lead')}{match.group('prefix')}{match.group('quote')}[REDACTED]{match.group('quote')}"

    def unquoted_repl(match: re.Match[str]) -> str:
        nonlocal redacted
        key = assignment_key(match.group("prefix"))
        if key is None or not is_sensitive_key(key):
            return match.group(0)
        if not should_redact_unquoted_secret_value(line, match, context=context):
            return match.group(0)
        redacted = True
        return f"{match.group('lead')}{match.group('prefix')}[REDACTED]"

    line = INLINE_QUOTED_SECRET_ASSIGNMENT_RE.sub(quoted_repl, line)
    line = INLINE_UNQUOTED_FALLBACK_SECRET_ASSIGNMENT_RE.sub(unquoted_repl, line)
    line = INLINE_UNQUOTED_CALL_SECRET_ASSIGNMENT_RE.sub(unquoted_repl, line)
    line = INLINE_UNQUOTED_BRACKETED_SECRET_ASSIGNMENT_RE.sub(unquoted_repl, line)
    line = INLINE_UNQUOTED_SECRET_ASSIGNMENT_RE.sub(unquoted_repl, line)
    return line, redacted


MULTILINE_SECRET_ASSIGNMENT_RE = re.compile(
    rf"(?i)(?:^|[\s;{{\[,])(?:(?:[^:\n]+):\d+(?::\d+)?:)?\s*(?:[+-]\s*)?(?:export\s+)?"
    rf"[\"']?(?P<key>{SECRET_KEY})[\"']?\s*[:=]\s*(?P<quote>[\"'])"
)


def find_unescaped_quote_end(text: str, quote: str, start: int = 0) -> int | None:
    """Return the index after the first unescaped quote delimiter, if present."""
    escaped = False
    for index, char in enumerate(text[start:], start=start):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == quote:
            return index + 1
    return None


def has_unescaped_quote(text: str, quote: str, start: int = 0) -> bool:
    """Return True when text contains an unescaped quote delimiter."""
    return find_unescaped_quote_end(text, quote, start) is not None


def detect_multiline_secret_assignment(line: str) -> str | None:
    """Return the quote delimiter when any secret assignment starts a multiline value."""
    for marker in MULTILINE_SECRET_ASSIGNMENT_RE.finditer(line):
        if not is_sensitive_key(marker.group("key")):
            continue
        quote = marker.group("quote")
        if not has_unescaped_quote(line, quote, marker.end("quote")):
            return quote
    return None


def expression_bracket_delta(text: str) -> int:
    delta = 0
    quote: str | None = None
    escaped = False
    for char in text:
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char in "([{":
            delta += 1
        elif char in ")}]":
            delta -= 1
    return delta


def ends_with_continuation_operator(text: str) -> bool:
    return bool(CONTINUATION_OPERATOR_RE.search(text.rstrip()))


def detect_multiline_secret_expression(line: str) -> int | None:
    marker = UNQUOTED_MULTILINE_SECRET_ASSIGNMENT_RE.search(line)
    if marker is None:
        return None
    prefix = line[: marker.start("value")]
    key = assignment_key(prefix)
    if key is None or not is_sensitive_key(key):
        return None
    value = marker.group("value").strip()
    if not value:
        return 0
    delta = expression_bracket_delta(value)
    if delta > 0:
        return delta
    if ends_with_continuation_operator(value):
        return max(delta, 0)
    return None


def update_multiline_secret_expression_state(line: str, depth: int) -> int | None:
    next_depth = max(0, depth + expression_bracket_delta(line))
    if next_depth == 0 and not ends_with_continuation_operator(line):
        return None
    return next_depth


def private_key_state_after_line(line: str) -> bool | None:
    """Return updated private-key state for a line, or None when no marker appears."""
    if PRIVATE_KEY_BEGIN_RE.search(line):
        return not bool(PRIVATE_KEY_END_RE.search(line))
    if PRIVATE_KEY_END_RE.search(line):
        return False
    return None


def secret_or_private_key_redaction_label(line: str) -> str:
    if PRIVATE_KEY_BEGIN_RE.search(line) or PRIVATE_KEY_END_RE.search(line):
        return "[REDACTED PRIVATE KEY BLOCK]\n"
    return "[REDACTED MULTILINE SECRET]\n"


class LineSanitizer:
    def __init__(
        self,
        *,
        show_paths: bool = False,
        context: SanitizationContext | str = "unknown_text",
        private_roots: Iterable[str] = (),
    ) -> None:
        self.show_paths = show_paths
        self.context = coerce_sanitization_context(
            context,
            private_roots=private_roots,
        )
        self.in_private_key_block = False
        self.multiline_secret_quote: str | None = None
        self.multiline_secret_expression_depth: int | None = None
        self.redactions = 0
        self.path_redactions = 0

    def sanitize(self, raw_line: str) -> tuple[str, bool]:
        line = strip_ansi(raw_line)
        redacted = False
        diff_prefix = ""
        stripped_for_key = line.lstrip()
        if stripped_for_key.startswith(('+', '-')):
            diff_prefix = stripped_for_key[0]

        if self.multiline_secret_quote is not None:
            redacted = True
            label = "[REDACTED PRIVATE KEY BLOCK]\n" if (
                self.in_private_key_block or PRIVATE_KEY_BEGIN_RE.search(line) or PRIVATE_KEY_END_RE.search(line)
            ) else "[REDACTED MULTILINE SECRET]\n"
            key_state = private_key_state_after_line(line)
            if key_state is not None:
                self.in_private_key_block = key_state
            closing_index = find_unescaped_quote_end(line, self.multiline_secret_quote)
            if closing_index is not None:
                self.multiline_secret_quote = detect_multiline_secret_assignment(line[closing_index:])
            return self._finish(diff_prefix + label, redacted)

        if self.in_private_key_block:
            redacted = True
            multiline_quote = detect_multiline_secret_assignment(line)
            if multiline_quote is not None:
                self.multiline_secret_quote = multiline_quote
            if PRIVATE_KEY_END_RE.search(line):
                self.in_private_key_block = False
            return self._finish(diff_prefix + "[REDACTED PRIVATE KEY BLOCK]\n", redacted)

        if self.multiline_secret_expression_depth is not None:
            self.multiline_secret_expression_depth = update_multiline_secret_expression_state(
                line, self.multiline_secret_expression_depth
            )
            return self._finish(diff_prefix + "[REDACTED MULTILINE SECRET]\n", True)

        multiline_quote = detect_multiline_secret_assignment(line)
        if multiline_quote is not None:
            self.multiline_secret_quote = multiline_quote
            key_state = private_key_state_after_line(line)
            if key_state is not None:
                self.in_private_key_block = key_state
            return self._finish(diff_prefix + secret_or_private_key_redaction_label(line), True)

        if PRIVATE_KEY_BEGIN_RE.search(line):
            redacted = True
            if not PRIVATE_KEY_END_RE.search(line):
                self.in_private_key_block = True
            return self._finish(diff_prefix + "[REDACTED PRIVATE KEY BLOCK]\n", redacted)

        expression_depth = detect_multiline_secret_expression(line)
        if expression_depth is not None:
            self.multiline_secret_expression_depth = expression_depth
            return self._finish(diff_prefix + "[REDACTED MULTILINE SECRET]\n", True)

        new_line, count = AUTH_HEADER_RE.subn(r"\g<prefix>[REDACTED]", line)
        if count:
            redacted = True
            line = new_line

        new_line, count = COOKIE_HEADER_RE.subn(r"\g<prefix>[REDACTED]", line)
        if count:
            redacted = True
            line = new_line

        line, assignment_redacted = redact_secret_assignments(
            line,
            context=self.context,
        )
        if assignment_redacted:
            redacted = True

        line, credential_redactions = redact_high_confidence_credentials(line)
        if credential_redactions:
            redacted = True

        return self._finish(line, redacted)

    def _finish(self, line: str, redacted: bool) -> tuple[str, bool]:
        if not self.show_paths:
            line, path_redactions = anonymize_paths_for_context(
                line,
                context=self.context,
            )
            if path_redactions:
                self.path_redactions += path_redactions
                redacted = True
        if redacted:
            self.redactions += 1
        return line, redacted


class BoundedOutput:
    def __init__(
        self,
        *,
        max_lines: int,
        max_chars: int,
        max_line_chars: int,
        head_lines: int,
        tail_lines: int,
        anchor_lines: int,
    ) -> None:
        self.max_lines = max_lines
        self.max_chars = max_chars
        self.max_line_chars = max_line_chars
        self.head_limit = max(0, head_lines)
        self.tail = collections.deque(maxlen=max(0, tail_lines))
        self.anchor_limit = max(0, anchor_lines)
        self.head: list[str] = []
        self.anchors: list[str] = []
        self.anchor_seen: set[str] = set()
        self.full: list[str] = []
        self.line_count = 0
        self.raw_chars = 0
        self.visible_chars = 0
        self.line_caps = 0
        self.trimmed = False

    def add(self, raw_line: str, sanitized_line: str, *, redacted: bool) -> None:
        self.line_count += 1
        self.raw_chars += len(raw_line)
        capped, was_capped = cap_line(sanitized_line, self.max_line_chars)
        if was_capped:
            self.line_caps += 1
        self.visible_chars += len(capped)

        if len(self.head) < self.head_limit:
            self.head.append(capped)
        self.tail.append(capped)
        if self._is_anchor(capped, redacted):
            key = capped.rstrip("\n")
            if key not in self.anchor_seen and len(self.anchors) < self.anchor_limit:
                self.anchor_seen.add(key)
                self.anchors.append(capped)

        if not self.trimmed:
            self.full.append(capped)
            if (self.max_lines > 0 and self.line_count > self.max_lines) or (
                self.max_chars > 0 and self.visible_chars > self.max_chars
            ):
                self.trimmed = True

    def _is_anchor(self, line: str, redacted: bool) -> bool:
        return redacted or bool(ANCHOR_RE.search(line)) or bool(SECRET_WORD_RE.search(line))

    def render(self, redactions: int) -> str:
        if not self.trimmed:
            return "".join(self.full)

        lines_budget = self.max_lines if self.max_lines > 0 else 240
        remaining = max(0, lines_budget - 8)
        head_n = min(len(self.head), max(1, remaining // 3) if remaining else 0)
        anchor_n = min(len(self.anchors), max(0, remaining // 3))
        tail_n = min(len(self.tail), max(0, remaining - head_n - anchor_n))

        rendered: list[str] = [
            (
                "[context-guard-kit] sanitized output trimmed: "
                f"lines={self.line_count} raw_chars={self.raw_chars} "
                f"sanitized_chars={self.visible_chars} redacted_lines={redactions} "
                f"line_caps={self.line_caps}\n"
            )
        ]
        if head_n:
            rendered.append(f"--- head ({head_n} lines) ---\n")
            rendered.extend(self.head[:head_n])
        if anchor_n:
            rendered.append(f"--- grep/diff/security anchors ({anchor_n} lines) ---\n")
            rendered.extend(self.anchors[:anchor_n])
        if tail_n:
            rendered.append(f"--- tail ({tail_n} lines) ---\n")
            rendered.extend(list(self.tail)[-tail_n:])
        text = "".join(rendered)
        if self.max_chars > 0 and len(text) > self.max_chars:
            marker = f"\n[context-guard-kit] rendered sanitized summary capped: {len(text)} chars\n"
            keep = max(0, self.max_chars - len(marker))
            text = text[:keep].rstrip() + marker
        return text


def sanitize_stream(stream: Iterable[str], args: argparse.Namespace) -> tuple[str, int, int]:
    sanitizer = LineSanitizer(
        show_paths=args.show_paths,
        context=getattr(args, "context", "unknown_text"),
        private_roots=getattr(args, "private_root", ()),
    )
    bounded = BoundedOutput(
        max_lines=args.max_lines,
        max_chars=args.max_chars,
        max_line_chars=args.max_line_chars,
        head_lines=args.head_lines,
        tail_lines=args.tail_lines,
        anchor_lines=args.anchor_lines,
    )
    for raw_line in stream:
        sanitized, redacted = sanitizer.sanitize(raw_line)
        bounded.add(raw_line, sanitized, redacted=redacted)
    return bounded.render(sanitizer.redactions), sanitizer.redactions, bounded.line_count


_STREAM_END = object()


def process_group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def terminate_process_tree(
    proc: subprocess.Popen[str],
    *,
    process_group_id: int | None = None,
    include_exited_group: bool = False,
) -> None:
    if os.name != "nt":
        pgid = process_group_id if process_group_id is not None else proc.pid
        if proc.poll() is not None and not include_exited_group:
            return
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if proc.poll() is None:
                try:
                    proc.wait(timeout=0.05)
                except subprocess.TimeoutExpired:
                    pass
            if not process_group_exists(pgid):
                return
            time.sleep(0.05)
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            return
        return

    if proc.poll() is not None:
        return
    try:
        proc.terminate()
    except ProcessLookupError:
        return
    except OSError:
        try:
            proc.kill()
        except OSError:
            return
    try:
        proc.wait(timeout=2)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        proc.kill()
    except ProcessLookupError:
        return
    except OSError:
        return


class TimedCommandStream:
    def __init__(
        self,
        proc: subprocess.Popen[bytes],
        stdout: BinaryIO,
        *,
        timeout_seconds: int,
        max_line_chars: int = MAX_LINE_CHARS_LIMIT,
        process_group_id: int | None = None,
    ) -> None:
        self.proc = proc
        self.timeout_seconds = timeout_seconds
        self.max_unterminated_line_chars = max(1, max_line_chars)
        self.process_group_id = process_group_id
        self.deadline = time.monotonic() + timeout_seconds
        self.timed_out = False
        self.timeout_reported = False
        self._stream_closed = False
        self._queue: queue.Queue[str | object] = queue.Queue(maxsize=1024)
        self._thread = threading.Thread(target=self._read_stdout, args=(stdout,), daemon=True)
        self._thread.start()

    def _truncated_raw_line(self, text: str) -> str:
        holdback = min(RAW_TRUNCATION_REDACTION_HOLDBACK_CHARS, self.max_unterminated_line_chars)
        safe_keep = max(0, self.max_unterminated_line_chars - holdback)
        return (
            text[:safe_keep]
            + (
                "...[context-guard-kit: raw line truncated before newline "
                f"after {self.max_unterminated_line_chars} chars; "
                f"withheld {holdback} boundary chars for redaction safety]\n"
            )
        )

    def _read_stdout(self, stdout: BinaryIO) -> None:
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        pending = ""
        discarding_oversized_line = False

        def feed(text: str) -> None:
            nonlocal pending, discarding_oversized_line
            if not text:
                return
            pending += text
            while pending:
                if discarding_oversized_line:
                    newline_index = pending.find("\n")
                    if newline_index == -1:
                        pending = ""
                        return
                    pending = pending[newline_index + 1 :]
                    discarding_oversized_line = False
                    continue

                newline_index = pending.find("\n")
                if newline_index != -1:
                    if newline_index > self.max_unterminated_line_chars:
                        self._queue.put(self._truncated_raw_line(pending))
                    else:
                        self._queue.put(pending[: newline_index + 1])
                    pending = pending[newline_index + 1 :]
                    continue

                if len(pending) > self.max_unterminated_line_chars:
                    self._queue.put(self._truncated_raw_line(pending))
                    pending = ""
                    discarding_oversized_line = True
                return

        try:
            while True:
                chunk = stdout.read(COMMAND_READ_CHUNK_BYTES)
                if not chunk:
                    break
                feed(decoder.decode(chunk, final=False))
            feed(decoder.decode(b"", final=True))
            if pending and not discarding_oversized_line:
                self._queue.put(pending)
        finally:
            self._stream_closed = True
            self._queue.put(_STREAM_END)

    def timeout_message(self) -> str:
        return (
            f"[context-guard-kit] command timed out after {self.timeout_seconds}s; "
            "terminated wrapped process\n"
        )

    def _mark_timed_out(self) -> None:
        if not self.timed_out:
            self.timed_out = True
            terminate_process_tree(
                self.proc,
                process_group_id=self.process_group_id,
                include_exited_group=True,
            )

    def _timeout_line(self) -> str:
        self._mark_timed_out()
        self.timeout_reported = True
        return self.timeout_message()

    def __iter__(self) -> Iterator[str]:
        while True:
            remaining = self.deadline - time.monotonic()
            wait_time = 0.05 if self.proc.poll() is not None or self.timed_out else min(0.05, max(0.0, remaining))
            try:
                item = self._queue.get(timeout=wait_time)
            except queue.Empty:
                if remaining <= 0 and not self._stream_closed:
                    if not self.timeout_reported:
                        yield self._timeout_line()
                    break
                continue
            if item is _STREAM_END:
                break
            if not isinstance(item, str):
                continue
            yield item
            if not self._stream_closed and time.monotonic() >= self.deadline:
                if not self.timeout_reported:
                    yield self._timeout_line()
                break

    def returncode(self) -> int:
        if self.timed_out:
            return TIMEOUT_EXIT_CODE
        remaining = self.deadline - time.monotonic()
        try:
            return self.proc.wait(timeout=max(0.0, remaining))
        except subprocess.TimeoutExpired:
            self._mark_timed_out()
            return TIMEOUT_EXIT_CODE


def process_group_id_for(proc: subprocess.Popen[str]) -> int | None:
    if os.name == "nt":
        return None
    try:
        return os.getpgid(proc.pid)
    except ProcessLookupError:
        # start_new_session=True makes the child the group leader; if it exits
        # before getpgid(), the group id is still the leader pid while inherited
        # stdout descendants remain alive.
        return proc.pid


def run_command(
    command: list[str],
    timeout_seconds: int,
    *,
    max_line_chars: int = MAX_LINE_CHARS_LIMIT,
) -> tuple[Iterable[str], subprocess.Popen[bytes] | None, int | None]:
    popen_kwargs: dict[str, object] = {}
    if os.name != "nt":
        popen_kwargs["start_new_session"] = True
    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=False,
            bufsize=0,
            **popen_kwargs,
        )
    except OSError as exc:
        print(f"context-guard-sanitize-output: command failed to start: {exc}", file=sys.stderr)
        return [], None, 127
    if proc.stdout is None:
        print("context-guard-sanitize-output: subprocess produced no stdout pipe", file=sys.stderr)
        return [], proc, 1
    return (
        TimedCommandStream(
            proc,
            proc.stdout,
            timeout_seconds=timeout_seconds,
            max_line_chars=max_line_chars,
            process_group_id=process_group_id_for(proc),
        ),
        proc,
        None,
    )


def stdin_has_data(stdin: TextIO) -> bool:
    return not stdin.isatty()


def command_uses_search_diff_output(command: list[str]) -> bool:
    if not command:
        return False
    executable = os.path.basename(command[0])
    if executable in {"grep", "rg"}:
        return True
    if executable != "git":
        return False
    value_options = {"-C", "-c", "--git-dir", "--work-tree", "--namespace"}
    skip_next = False
    for arg in command[1:]:
        if skip_next:
            skip_next = False
            continue
        if arg == "--":
            break
        if arg in value_options:
            skip_next = True
            continue
        if any(arg.startswith(option + "=") for option in value_options if option.startswith("--")):
            continue
        if arg.startswith("-"):
            continue
        return arg in {"diff", "grep", "log", "show"}
    return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Redact secrets and budget grep/diff/log output before sending it to Claude."
    )
    parser.add_argument("--max-lines", type=int, default=240)
    parser.add_argument("--max-chars", type=int, default=24000)
    parser.add_argument("--max-line-chars", type=int, default=3000)
    parser.add_argument("--head-lines", type=int, default=50)
    parser.add_argument("--tail-lines", type=int, default=90)
    parser.add_argument("--anchor-lines", type=int, default=80)
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=(
            "maximum runtime for wrapped commands before terminating the process group "
            f"(default: {DEFAULT_TIMEOUT_SECONDS}, max: {MAX_TIMEOUT_SECONDS})"
        ),
    )
    parser.add_argument(
        "--show-paths",
        action="store_true",
        help="show raw absolute paths instead of basename#path:<hash>; local debugging only because private paths may be exposed",
    )
    parser.add_argument(
        "--context",
        choices=SANITIZATION_MODES,
        default="unknown_text",
        help=(
            "sanitization origin policy (default: unknown_text); path-aware modes "
            "only anonymize structurally proven locations"
        ),
    )
    parser.add_argument(
        "--private-root",
        action="append",
        default=[],
        help=(
            "private root eligible for path anonymization in filesystem_listing "
            "mode; may be repeated"
        ),
    )
    parser.add_argument(
        "--context-guard-wrapper-v1",
        choices=("command_search_diff",),
        dest="wrapper_context",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    normalize_budgets(args)
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if args.wrapper_context is not None:
        if len(command) != 3 or command[0:2] != ["bash", "-lc"] or not command[2]:
            print(
                "context-guard-sanitize-output: invalid context-guard wrapper v1 shape",
                file=sys.stderr,
            )
            return 2
        context = coerce_sanitization_context(
            args.wrapper_context,
            private_roots=args.private_root,
        )
    else:
        context = coerce_sanitization_context(
            args.context,
            private_roots=args.private_root,
        )
        if (
            context.mode == "unknown_text"
            and command_uses_search_diff_output(command)
        ):
            context = SanitizationContext(
                mode="command_search_diff",
                private_roots=context.private_roots,
            )

    proc: subprocess.Popen[bytes] | None = None
    command_stream: TimedCommandStream | None = None
    early_rc: int | None = None
    if command:
        stream, proc, early_rc = run_command(
            command,
            args.timeout_seconds,
            max_line_chars=COMMAND_MAX_UNTERMINATED_LINE_CHARS,
        )
        if isinstance(stream, TimedCommandStream):
            command_stream = stream
        if early_rc is not None and proc is None:
            return early_rc
    elif stdin_has_data(sys.stdin):
        stream = sys.stdin
    else:
        print("context-guard-sanitize-output: missing command or stdin", file=sys.stderr)
        return 2

    args.context = context
    output, _redactions, _line_count = sanitize_stream(stream, args)
    rc: int | None = None
    if proc is not None:
        rc = command_stream.returncode() if command_stream is not None else proc.wait()
        if command_stream is not None and command_stream.timed_out and not command_stream.timeout_reported:
            timeout_line, _redacted = LineSanitizer(
                show_paths=args.show_paths,
                context=context,
                private_roots=args.private_root,
            ).sanitize(command_stream.timeout_message())
            command_stream.timeout_reported = True
            output = output + timeout_line

    if output:
        sys.stdout.write(output)
        if not output.endswith("\n"):
            sys.stdout.write("\n")

    if proc is not None:
        return early_rc if early_rc is not None else rc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
