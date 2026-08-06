"""Bounded, transactional sanitization for captured command bytes."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Final


__all__ = [
    "SANITIZER_POLICY_VERSION",
    "SanitizationError",
    "SanitizationErrorCode",
    "SanitizationSummary",
    "SanitizedOutput",
    "SanitizerLimits",
    "StreamingSanitizer",
    "sanitize_bytes",
]


SANITIZER_POLICY_VERSION: Final = "contextguard-receipt-sanitizer/v1"
_MAX_BYTES: Final = 1024 * 1024
_MAX_PENDING_BYTES: Final = 64 * 1024
_MAX_LINES: Final = 65_536
_MAX_CONTROL_SEQUENCE_BYTES: Final = 4_096
_MAX_PRIVATE_ROOTS: Final = 16
_MAX_PRIVATE_ROOT_BYTES: Final = 4_096
_ESC: Final = 0x1B
_BEL: Final = 0x07
_CSI_INTRODUCER: Final = 0x5B
_OSC_INTRODUCER: Final = 0x5D
_STRING_CONTROL_INTRODUCERS: Final = frozenset((0x50, 0x58, 0x5E, 0x5F))
_SECRET_MARKER: Final = b"[REDACTED SECRET]"
_PRIVATE_KEY_MARKER: Final = b"[REDACTED PRIVATE KEY]"
_PATH_MARKER: Final = b"[REDACTED PATH]"
_CAMEL_ACRONYM_BOUNDARY_RE: Final = re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])")
_CAMEL_WORD_BOUNDARY_RE: Final = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_EXACT_SENSITIVE_KEYS: Final = frozenset(
    {
        "access_key",
        "access_key_id",
        "access_token",
        "api_key",
        "apikey",
        "auth",
        "auth_token",
        "authorization",
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_session_token",
        "azure_client_secret",
        "client_secret",
        "cookie",
        "credential",
        "credentials",
        "id_token",
        "password",
        "passwd",
        "private_key",
        "proxy_authorization",
        "refresh_token",
        "secret",
        "secret_key",
        "session_token",
        "set_cookie",
        "sig",
        "signature",
        "token",
        "x_amz_credential",
        "x_amz_security_token",
        "x_amz_signature",
    }
)
_SENSITIVE_KEY_SUFFIXES: Final = (
    "_access_key",
    "_access_token",
    "_api_key",
    "_auth_token",
    "_client_secret",
    "_credential",
    "_credentials",
    "_password",
    "_private_key",
    "_refresh_token",
    "_secret",
    "_secret_key",
    "_session_token",
    "_token",
)
_SENSITIVE_KEY_QUALIFIER_RE: Final = re.compile(
    r"_(?:v\d+|prod|production|dev|test|backup)$"
)
_ASSIGNMENT_RE: Final = re.compile(
    r"(?<![A-Za-z0-9_$.-])[\"']?"
    r"(?P<key>[A-Za-z_$][A-Za-z0-9_$.-]{0,127})[\"']?"
    r"[ \t]*(?P<separator>[:=])[ \t]*"
)
_CLI_SECRET_RE: Final = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])--"
    r"(?P<key>[A-Za-z][A-Za-z0-9_-]{0,127})"
    r"(?:[ \t]*=[ \t]*|[ \t]+)(?P<value>\S)"
)
_AUTH_SCHEME_RE: Final = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:Bearer|Basic)[ \t]+[A-Za-z0-9._~+/=-]+"
)
_PRIVATE_TOKEN_PATTERNS: Final = (
    re.compile(r"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9_]{20,}(?![A-Za-z0-9_])"),
    re.compile(r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{20,}(?![A-Za-z0-9_])"),
    re.compile(r"(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{12,}(?![A-Za-z0-9_-])"),
    re.compile(r"(?<![A-Za-z0-9-])xox[abprs]-[A-Za-z0-9-]{10,}(?![A-Za-z0-9-])"),
    re.compile(r"(?<![0-9A-Z])(?:AKIA|ASIA)[0-9A-Z]{16}(?![0-9A-Z])"),
    re.compile(r"(?<![A-Za-z0-9_])(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9_-])sk-(?:ant|proj)-[A-Za-z0-9_-]{12,}(?![A-Za-z0-9_-])"),
    re.compile(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9][A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"),
    re.compile(r"(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{20,}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{20,}(?![0-9A-Za-z_-])"),
    re.compile(r"(?<![A-Za-z0-9_.-])SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}(?![A-Za-z0-9_-])"),
    re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?![A-Za-z0-9_-])"),
)
_PRIVATE_KEY_BEGIN_RE: Final = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|OPENSSH PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----",
    re.IGNORECASE,
)
_PRIVATE_KEY_END_RE: Final = re.compile(
    r"-----END (?:[A-Z0-9 ]*PRIVATE KEY|OPENSSH PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----",
    re.IGNORECASE,
)
_WINDOWS_DRIVE_ROOT_RE: Final = re.compile(
    r"^(?P<drive>[A-Za-z]):[\\/](?P<tail>.*)$"
)
_PATH_LINE_SUFFIX_RE: Final = re.compile(r"(:[0-9]+(?::[0-9]+)?(?::)?)$")
_GENERIC_LOCATION_SUFFIX_RE: Final = re.compile(
    r":[0-9]+(?::[0-9]+)?(?=:|$)"
)
_SCHEME_URL_RE: Final = re.compile(
    r"(?<![A-Za-z0-9+.-])(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://[^\s\"'<>]*"
)
_PATH_BEARING_SCHEME_REFERENCE_RE: Final = re.compile(
    r"(?i)(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*:[/\\]+[^\s\"'<>]*"
)
_PASSWORD_URI_RE: Final = re.compile(
    r"(?i)(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*://"
    r"[^/?#\s:@]*:[^@/?#\s]+@"
)
_QUOTED_COLON_KEY_RE: Final = re.compile(
    r'"(?P<key>(?:[^"\\]|\\.){1,1536})"[ \t]*:[ \t]*'
)
_REMOTE_URL_SCHEMES: Final = frozenset(("http", "https", "ssh"))
_MAX_DECODED_KEY_CODEPOINTS: Final = 128
_MAX_NESTED_URLS: Final = 32
_QUOTED_KEY_SINGLE_ESCAPES: Final = {
    '"': '"',
    "/": "/",
    "0": "\x00",
    "N": "\u0085",
    "L": "\u2028",
    "P": "\u2029",
    "_": "\u00A0",
    "\\": "\\",
    " ": " ",
    "a": "\x07",
    "b": "\x08",
    "e": "\x1B",
    "f": "\x0C",
    "n": "\x0A",
    "r": "\x0D",
    "t": "\x09",
    "v": "\x0B",
}
_YAML_BLOCK_HEADER_RE: Final = re.compile(
    r"^[|>](?:(?:[+-][1-9])|(?:[1-9][+-])|[+-]|[1-9])?"
    r"[ \t]*(?:#.*)?$"
)


class SanitizationErrorCode(str, Enum):
    """Closed, non-reflective sanitizer failure reasons."""

    INVALID_INPUT_TYPE = "invalid_input_type"
    INVALID_LIMITS = "invalid_limits"
    INVALID_PRIVATE_ROOT = "invalid_private_root"
    TOO_MANY_PRIVATE_ROOTS = "too_many_private_roots"
    INPUT_LIMIT_EXCEEDED = "input_limit_exceeded"
    OUTPUT_LIMIT_EXCEEDED = "output_limit_exceeded"
    PENDING_LIMIT_EXCEEDED = "pending_limit_exceeded"
    LINE_LIMIT_EXCEEDED = "line_limit_exceeded"
    CONTROL_SEQUENCE_LIMIT_EXCEEDED = "control_sequence_limit_exceeded"
    INVALID_STATE = "invalid_state"


class SanitizationError(ValueError):
    """A stable sanitizer failure that never reflects captured bytes."""

    __slots__ = ("code",)

    def __init__(self, code: SanitizationErrorCode) -> None:
        self.code = code
        super().__init__(code.value)


def _bounded_limit(value: object, hard_cap: int) -> int:
    if type(value) is not int or value < 0 or value > hard_cap:
        raise SanitizationError(SanitizationErrorCode.INVALID_LIMITS)
    return value


@dataclass(frozen=True, slots=True)
class SanitizerLimits:
    """Caller-lowerable limits capped by the fixed sanitizer policy."""

    max_input_bytes: int = _MAX_BYTES
    max_output_bytes: int = _MAX_BYTES
    max_pending_bytes: int = _MAX_PENDING_BYTES
    max_lines: int = _MAX_LINES
    max_control_sequence_bytes: int = _MAX_CONTROL_SEQUENCE_BYTES

    def __post_init__(self) -> None:
        object.__setattr__(self, "max_input_bytes", _bounded_limit(self.max_input_bytes, _MAX_BYTES))
        object.__setattr__(self, "max_output_bytes", _bounded_limit(self.max_output_bytes, _MAX_BYTES))
        object.__setattr__(
            self,
            "max_pending_bytes",
            _bounded_limit(self.max_pending_bytes, _MAX_PENDING_BYTES),
        )
        object.__setattr__(self, "max_lines", _bounded_limit(self.max_lines, _MAX_LINES))
        object.__setattr__(
            self,
            "max_control_sequence_bytes",
            _bounded_limit(self.max_control_sequence_bytes, _MAX_CONTROL_SEQUENCE_BYTES),
        )


@dataclass(frozen=True, slots=True)
class SanitizationSummary:
    """Bounded counters only; no payload-derived strings or digests."""

    input_bytes: int
    output_bytes: int
    line_count: int
    ansi_sequences_stripped: int = 0
    incomplete_ansi_sequences: int = 0
    invalid_utf8_bytes: int = 0
    escaped_control_characters: int = 0
    secret_redactions: int = 0
    private_key_redactions: int = 0
    path_redactions: int = 0


@dataclass(frozen=True, slots=True)
class SanitizedOutput:
    """Finished sanitized bytes and privacy-safe counters."""

    payload: bytes = field(repr=False)
    summary: SanitizationSummary


class _State(Enum):
    ACTIVE = "active"
    FINISHED = "finished"
    ABORTED = "aborted"


class _AnsiStatus(Enum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    MALFORMED = "malformed"


@dataclass(frozen=True, slots=True)
class _PrivateRoot:
    kind: str
    canonical: str = field(repr=False)
    pattern: re.Pattern[str] = field(repr=False)


def _root_pattern(kind: str, canonical: str) -> re.Pattern[str]:
    if kind == "posix":
        return re.compile(re.escape(canonical))

    if kind == "drive":
        drive, tail = canonical.split(":/", 1)
        components = tail.split("/")
        source = re.escape(drive + ":") + r"[\\/]" + r"[\\/]".join(
            re.escape(component) for component in components
        )
    else:
        components = canonical[2:].split("/")
        source = r"[\\/]{2}" + r"[\\/]".join(
            re.escape(component) for component in components
        )
    return re.compile(source, re.IGNORECASE)


def _canonical_private_root(value: str) -> _PrivateRoot:
    if not value or "\x00" in value:
        raise SanitizationError(SanitizationErrorCode.INVALID_PRIVATE_ROOT)
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise SanitizationError(SanitizationErrorCode.INVALID_PRIVATE_ROOT) from None
    if len(encoded) > _MAX_PRIVATE_ROOT_BYTES:
        raise SanitizationError(SanitizationErrorCode.INVALID_PRIVATE_ROOT)

    if value.startswith(("//", "\\\\")):
        components = tuple(
            component
            for component in re.split(r"[\\/]+", value[2:])
            if component
        )
        if len(components) < 3:
            raise SanitizationError(SanitizationErrorCode.INVALID_PRIVATE_ROOT)
        kind = "unc"
        canonical = "//" + "/".join(components)
    else:
        drive_match = _WINDOWS_DRIVE_ROOT_RE.match(value)
        if drive_match is not None:
            components = tuple(
                component
                for component in re.split(r"[\\/]+", drive_match.group("tail"))
                if component
            )
            if not components:
                raise SanitizationError(SanitizationErrorCode.INVALID_PRIVATE_ROOT)
            kind = "drive"
            canonical = drive_match.group("drive").upper() + ":/" + "/".join(components)
        elif value.startswith("/"):
            components = tuple(component for component in value.split("/") if component)
            if not components:
                raise SanitizationError(SanitizationErrorCode.INVALID_PRIVATE_ROOT)
            kind = "posix"
            canonical = "/" + "/".join(components)
        else:
            raise SanitizationError(SanitizationErrorCode.INVALID_PRIVATE_ROOT)

    return _PrivateRoot(
        kind=kind,
        canonical=canonical,
        pattern=_root_pattern(kind, canonical),
    )


def _validated_private_roots(value: object) -> tuple[_PrivateRoot, ...]:
    if type(value) is not tuple:
        raise SanitizationError(SanitizationErrorCode.INVALID_PRIVATE_ROOT)
    if len(value) > _MAX_PRIVATE_ROOTS:
        raise SanitizationError(SanitizationErrorCode.TOO_MANY_PRIVATE_ROOTS)

    unique: list[_PrivateRoot] = []
    seen: set[tuple[str, str]] = set()
    for item in value:
        if type(item) is not str:
            raise SanitizationError(SanitizationErrorCode.INVALID_PRIVATE_ROOT)
        root = _canonical_private_root(item)
        comparison = root.canonical if root.kind == "posix" else root.canonical.casefold()
        key = root.kind, comparison
        if key not in seen:
            seen.add(key)
            unique.append(root)

    unique.sort(key=lambda root: -len(root.canonical))
    return tuple(unique)


def _check_control_sequence_length(length: int, limit: int) -> None:
    if length > limit:
        raise SanitizationError(SanitizationErrorCode.CONTROL_SEQUENCE_LIMIT_EXCEEDED)


def _consume_csi(payload: bytes, start: int, limit: int) -> tuple[_AnsiStatus, int]:
    cursor = start + 2
    _check_control_sequence_length(2, limit)
    in_intermediates = False

    while cursor < len(payload):
        _check_control_sequence_length(cursor - start + 1, limit)
        byte = payload[cursor]
        if not in_intermediates and 0x30 <= byte <= 0x3F:
            cursor += 1
            continue
        if 0x20 <= byte <= 0x2F:
            in_intermediates = True
            cursor += 1
            continue
        if 0x40 <= byte <= 0x7E:
            return _AnsiStatus.COMPLETE, cursor + 1
        return _AnsiStatus.MALFORMED, start + 1

    return _AnsiStatus.INCOMPLETE, len(payload)


def _consume_control_string(
    payload: bytes,
    start: int,
    limit: int,
    *,
    allow_bel: bool,
) -> tuple[_AnsiStatus, int]:
    cursor = start + 2
    _check_control_sequence_length(2, limit)

    while cursor < len(payload):
        _check_control_sequence_length(cursor - start + 1, limit)
        byte = payload[cursor]
        if allow_bel and byte == _BEL:
            return _AnsiStatus.COMPLETE, cursor + 1
        if byte == _ESC and cursor + 1 < len(payload) and payload[cursor + 1] == 0x5C:
            _check_control_sequence_length(cursor - start + 2, limit)
            return _AnsiStatus.COMPLETE, cursor + 2
        cursor += 1

    return _AnsiStatus.INCOMPLETE, len(payload)


def _strip_ansi(payload: bytes, limit: int) -> tuple[bytes, int, int]:
    output = bytearray()
    stripped = 0
    incomplete = 0
    cursor = 0

    while cursor < len(payload):
        if payload[cursor] != _ESC:
            output.append(payload[cursor])
            cursor += 1
            continue

        if cursor + 1 == len(payload):
            _check_control_sequence_length(1, limit)
            incomplete += 1
            cursor += 1
            continue

        introducer = payload[cursor + 1]
        if introducer == _CSI_INTRODUCER:
            status, end = _consume_csi(payload, cursor, limit)
        elif introducer == _OSC_INTRODUCER:
            status, end = _consume_control_string(
                payload,
                cursor,
                limit,
                allow_bel=True,
            )
        elif introducer in _STRING_CONTROL_INTRODUCERS:
            status, end = _consume_control_string(
                payload,
                cursor,
                limit,
                allow_bel=False,
            )
        elif 0x40 <= introducer <= 0x5F:
            _check_control_sequence_length(2, limit)
            status, end = _AnsiStatus.COMPLETE, cursor + 2
        else:
            status, end = _AnsiStatus.MALFORMED, cursor + 1

        if status is _AnsiStatus.COMPLETE:
            stripped += 1
            cursor = end
        elif status is _AnsiStatus.INCOMPLETE:
            incomplete += 1
            cursor = end
        else:
            output.append(_ESC)
            cursor = end

    return bytes(output), stripped, incomplete


def _split_normalized_records(
    payload: bytes,
    pending_limit: int,
) -> tuple[list[bytes], list[int], bool]:
    records: list[bytes] = []
    group_ids: list[int] = []
    current = bytearray()
    current_group = 0
    cursor = 0
    ended_with_delimiter = False

    def append_record() -> None:
        if len(current) > pending_limit:
            raise SanitizationError(SanitizationErrorCode.PENDING_LIMIT_EXCEEDED)
        records.append(bytes(current))
        group_ids.append(current_group)
        current.clear()

    while cursor < len(payload):
        byte = payload[cursor]
        if byte == 0x0D:
            append_record()
            if cursor + 1 < len(payload) and payload[cursor + 1] == 0x0A:
                cursor += 2
                current_group += 1
            else:
                cursor += 1
            ended_with_delimiter = True
            continue
        if byte == 0x0A:
            append_record()
            cursor += 1
            current_group += 1
            ended_with_delimiter = True
            continue
        current.append(byte)
        cursor += 1
        ended_with_delimiter = False

    if current or (payload and not ended_with_delimiter):
        append_record()
    return records, group_ids, ended_with_delimiter


def _join_normalized_records(records: list[bytes], has_final_lf: bool) -> bytes:
    payload = b"\n".join(records)
    if has_final_lf:
        payload += b"\n"
    return payload


def _normalize_sensitive_key(key: str) -> str:
    key = _CAMEL_ACRONYM_BOUNDARY_RE.sub("_", key)
    key = _CAMEL_WORD_BOUNDARY_RE.sub("_", key)
    key = re.sub(r"[_.-]+", "_", key)
    return re.sub(r"_+", "_", key).strip("_").lower()


def _is_sensitive_key(key: str) -> bool:
    normalized = _normalize_sensitive_key(key.strip().strip("\"'"))
    while normalized:
        if normalized in _EXACT_SENSITIVE_KEYS or normalized.endswith(_SENSITIVE_KEY_SUFFIXES):
            return True
        stripped = _SENSITIVE_KEY_QUALIFIER_RE.sub("", normalized)
        if stripped == normalized:
            return False
        normalized = stripped
    return False


def _detection_projection(record: bytes) -> str:
    projected: list[str] = []
    for character in record.decode("utf-8", errors="surrogateescape"):
        if _is_detection_ignored(character):
            continue
        projected.append(character)
    return "".join(projected)


def _is_detection_ignored(character: str) -> bool:
    codepoint = ord(character)
    return (
        0xDC80 <= codepoint <= 0xDCFF
        or codepoint < 0x20
        or 0x7F <= codepoint <= 0x9F
    )


def _decoded_quoted_key(value: str) -> str | None:
    output: list[str] = []
    cursor = 0
    while cursor < len(value):
        if value[cursor] != "\\":
            decoded = value[cursor]
            cursor += 1
        else:
            if cursor + 1 >= len(value):
                return None
            escape = value[cursor + 1]
            if escape in _QUOTED_KEY_SINGLE_ESCAPES:
                decoded = _QUOTED_KEY_SINGLE_ESCAPES[escape]
                cursor += 2
            elif escape == "x":
                end = cursor + 4
                if end > len(value):
                    return None
                digits = value[cursor + 2 : end]
                if len(digits) != 2 or any(
                    character not in "0123456789abcdefABCDEF" for character in digits
                ):
                    return None
                decoded = chr(int(digits, 16))
                cursor = end
            elif escape == "u":
                end = cursor + 6
                if end > len(value):
                    return None
                digits = value[cursor + 2 : end]
                if len(digits) != 4 or any(
                    character not in "0123456789abcdefABCDEF" for character in digits
                ):
                    return None
                codepoint = int(digits, 16)
                cursor = end
                if 0xD800 <= codepoint <= 0xDBFF:
                    pair_end = cursor + 6
                    if pair_end > len(value) or value[cursor : cursor + 2] != "\\u":
                        return None
                    low_digits = value[cursor + 2 : pair_end]
                    if any(
                        character not in "0123456789abcdefABCDEF"
                        for character in low_digits
                    ):
                        return None
                    low = int(low_digits, 16)
                    if not 0xDC00 <= low <= 0xDFFF:
                        return None
                    codepoint = 0x10000 + ((codepoint - 0xD800) << 10) + (low - 0xDC00)
                    cursor = pair_end
                elif 0xDC00 <= codepoint <= 0xDFFF:
                    return None
                decoded = chr(codepoint)
            elif escape == "U":
                end = cursor + 10
                if end > len(value):
                    return None
                digits = value[cursor + 2 : end]
                if len(digits) != 8 or any(
                    character not in "0123456789abcdefABCDEF" for character in digits
                ):
                    return None
                codepoint = int(digits, 16)
                if codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
                    return None
                decoded = chr(codepoint)
                cursor = end
            else:
                return None
        if len(output) >= _MAX_DECODED_KEY_CODEPOINTS:
            return None
        output.append(decoded)
    return "".join(output)


class _AssignmentKind(Enum):
    QUOTED_COLON = "quoted_colon"
    YAML = "yaml"
    EQUALS = "equals"


@dataclass(frozen=True, slots=True)
class _SensitiveAssignment:
    end: int
    kind: _AssignmentKind


def _find_sensitive_assignment(text: str) -> _SensitiveAssignment | None:
    quoted_matches = tuple(_QUOTED_COLON_KEY_RE.finditer(text))
    for match in quoted_matches:
        decoded = _decoded_quoted_key(match.group("key"))
        if decoded is not None and _is_sensitive_key(decoded):
            return _SensitiveAssignment(match.end(), _AssignmentKind.QUOTED_COLON)
    quoted_index = 0
    for match in _ASSIGNMENT_RE.finditer(text):
        while (
            quoted_index < len(quoted_matches)
            and quoted_matches[quoted_index].end() <= match.start()
        ):
            quoted_index += 1
        if (
            quoted_index < len(quoted_matches)
            and quoted_matches[quoted_index].start() <= match.start()
            and match.end() <= quoted_matches[quoted_index].end()
        ):
            continue
        if not _is_sensitive_key(match.group("key")):
            continue
        value = text[match.end() :]
        if not value or value[0] not in ",;&}]":
            kind = (
                _AssignmentKind.YAML
                if match.group("separator") == ":"
                else _AssignmentKind.EQUALS
            )
            return _SensitiveAssignment(match.end(), kind)
    return None


def _find_sensitive_cli(text: str) -> re.Match[str] | None:
    for match in _CLI_SECRET_RE.finditer(text):
        if _is_sensitive_key(match.group("key")):
            return match
    return None


def _contains_private_token(text: str) -> bool:
    if _AUTH_SCHEME_RE.search(text) is not None or _PASSWORD_URI_RE.search(text) is not None:
        return True
    return any(pattern.search(text) is not None for pattern in _PRIVATE_TOKEN_PATTERNS)


@dataclass(slots=True)
class _DelimiterState:
    quote: str | None = None
    escaped: bool = False
    stack: list[str] = field(default_factory=list)


@dataclass(slots=True)
class _IndentedState:
    base_indent: int


@dataclass(slots=True)
class _ShellState:
    pass


@dataclass(slots=True)
class _AmbiguousColonState:
    base_indent: int


def _scan_delimiters(text: str, state: _DelimiterState) -> _DelimiterState | None:
    quote = state.quote
    escaped = state.escaped
    stack = state.stack
    closing = {"(": ")", "[": "]", "{": "}"}
    cursor = 0

    while cursor < len(text):
        character = text[cursor]
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif (
                quote == "'"
                and character == "'"
                and cursor + 1 < len(text)
                and text[cursor + 1] == "'"
            ):
                cursor += 2
                continue
            elif character == quote:
                quote = None
            cursor += 1
            continue

        if character in "([{":
            stack.append(closing[character])
        elif character in "'\"" and stack:
            quote = character
            escaped = False
        elif character in ")]}":
            if stack and character == stack[-1]:
                stack.pop()
        cursor += 1

    if quote is None and not stack:
        return None
    state.quote = quote
    state.escaped = escaped
    return state


def _initial_multiline_state(value: str) -> _DelimiterState | None:
    stripped = value.lstrip()
    if not stripped:
        return None
    if stripped[0] in "'\"":
        return _scan_delimiters(
            stripped[1:],
            _DelimiterState(quote=stripped[0]),
        )
    return _scan_delimiters(stripped, _DelimiterState())


def _leading_indent(text: str) -> int:
    return len(text) - len(text.lstrip(" \t"))


def _odd_trailing_backslash(text: str) -> bool:
    count = 0
    for character in reversed(text.rstrip(" \t")):
        if character != "\\":
            break
        count += 1
    return count % 2 == 1


def _initial_assignment_state(
    record: str,
    value: str,
    kind: _AssignmentKind,
) -> object | None:
    stripped = value.strip()
    if kind is _AssignmentKind.QUOTED_COLON:
        if not stripped:
            return _AmbiguousColonState(_leading_indent(record))
        delimiters = _initial_multiline_state(value)
        if delimiters is not None:
            return delimiters
        if stripped[0] in "'\"[{":
            return None
        return _IndentedState(_leading_indent(record))
    if not stripped or _YAML_BLOCK_HEADER_RE.fullmatch(stripped) is not None:
        return _IndentedState(_leading_indent(record))
    delimiters = _initial_multiline_state(value)
    if delimiters is not None:
        return delimiters
    if kind is _AssignmentKind.YAML and stripped[0] not in "'\"[{":
        return _IndentedState(_leading_indent(record))
    return _ShellState() if _odd_trailing_backslash(value) else None


def _initial_cli_state(value: str) -> object | None:
    delimiters = _initial_multiline_state(value)
    if delimiters is not None:
        return delimiters
    return _ShellState() if _odd_trailing_backslash(value) else None


def _consume_continuation(record: str, state: object) -> tuple[bool, object | None]:
    if isinstance(state, _DelimiterState):
        return True, _scan_delimiters(record, state)
    if isinstance(state, _AmbiguousColonState):
        if not record.strip():
            return True, state
        stripped = record.lstrip(" \t")
        is_sequence_item = stripped == "-" or stripped.startswith("- ")
        if (
            _leading_indent(record) > state.base_indent
            or is_sequence_item
            or _YAML_BLOCK_HEADER_RE.fullmatch(stripped) is not None
            or stripped.startswith("#")
        ):
            return True, _IndentedState(state.base_indent)
        return True, _initial_multiline_state(record)
    if isinstance(state, _IndentedState):
        stripped = record.lstrip(" \t")
        is_sequence_item = stripped == "-" or stripped.startswith("- ")
        if (
            not record.strip()
            or _leading_indent(record) > state.base_indent
            or is_sequence_item
        ):
            return True, state
        return False, None
    return True, state if _odd_trailing_backslash(record) else None


class _RecordKind(Enum):
    VISIBLE = "visible"
    SECRET = "secret"
    PRIVATE = "private"


def _redact_sensitive_records(
    records: list[bytes],
    group_ids: list[int],
) -> tuple[list[bytes], int, int]:
    kinds = [_RecordKind.VISIBLE] * len(records)
    literal_markers = [
        record in {_SECRET_MARKER, _PRIVATE_KEY_MARKER, _PATH_MARKER}
        for record in records
    ]
    private_key_depth = 0
    multiline_state: object | None = None

    for index, record in enumerate(records):
        projection = _detection_projection(record)
        private_events = [
            (match.start(), 1) for match in _PRIVATE_KEY_BEGIN_RE.finditer(projection)
        ]
        private_events.extend(
            (match.start(), -1) for match in _PRIVATE_KEY_END_RE.finditer(projection)
        )
        private_events.sort()
        private_record = private_key_depth > 0 or bool(private_events)
        for _, direction in private_events:
            if direction > 0:
                private_key_depth += 1
            elif private_key_depth > 0:
                private_key_depth -= 1

        if private_record:
            kinds[index] = _RecordKind.PRIVATE
            continue

        continuation_consumed = False
        if multiline_state is not None:
            consumed, multiline_state = _consume_continuation(projection, multiline_state)
            if consumed:
                continuation_consumed = True
        if continuation_consumed:
            kinds[index] = _RecordKind.SECRET
            continue

        assignment = _find_sensitive_assignment(projection)
        cli_assignment = _find_sensitive_cli(projection)
        if assignment is not None or cli_assignment is not None or _contains_private_token(projection):
            kinds[index] = _RecordKind.SECRET
            if assignment is not None:
                multiline_state = _initial_assignment_state(
                    projection,
                    projection[assignment.end :],
                    assignment.kind,
                )
            elif cli_assignment is not None:
                multiline_state = _initial_cli_state(
                    projection[cli_assignment.start("value") :]
                )

    group_kinds: dict[int, _RecordKind] = {}
    for index, kind in enumerate(kinds):
        if literal_markers[index] or kind is _RecordKind.VISIBLE:
            continue
        group_id = group_ids[index]
        current = group_kinds.get(group_id)
        if kind is _RecordKind.PRIVATE or current is None:
            group_kinds[group_id] = kind

    output: list[bytes] = []
    secret_redactions = 0
    private_key_redactions = 0
    for index, record in enumerate(records):
        final_kind = group_kinds.get(group_ids[index], kinds[index])
        if final_kind is _RecordKind.PRIVATE:
            output.append(_PRIVATE_KEY_MARKER)
            if not literal_markers[index]:
                private_key_redactions += 1
        elif final_kind is _RecordKind.SECRET:
            output.append(_SECRET_MARKER)
            if not literal_markers[index]:
                secret_redactions += 1
        else:
            output.append(record)

    return output, secret_redactions, private_key_redactions


def _has_path_left_boundary(text: str, start: int) -> bool:
    if start == 0:
        return True
    previous = text[start - 1]
    return not (previous.isalnum() or previous in "_./\\-")


def _find_unescaped_quote(text: str, quote: str, start: int) -> int:
    cursor = start
    while cursor < len(text):
        candidate = text.find(quote, cursor)
        if candidate < 0:
            return -1
        backslashes = 0
        previous = candidate - 1
        while previous >= start and text[previous] == "\\":
            backslashes += 1
            previous -= 1
        if backslashes % 2 == 0:
            return candidate
        cursor = candidate + 1
    return -1


def _explicit_path_end(text: str, start: int, root_end: int) -> int | None:
    if not _has_path_left_boundary(text, start):
        return None
    if root_end == len(text):
        return root_end

    following = text[root_end]
    boundary_characters = " \t\"'<>[]{}|,;!?="
    if following not in "/\\:" and following not in boundary_characters:
        return None
    if following in boundary_characters:
        return root_end

    quote = text[start - 1] if start > 0 and text[start - 1] in "\"'" else None
    if quote is not None:
        closing_quote = _find_unescaped_quote(text, quote, root_end)
        return len(text) if closing_quote < 0 else closing_quote

    cursor = root_end
    while cursor < len(text):
        character = text[cursor]
        if character.isspace() or character in "\"'<>[]{}|,;!?=":
            break
        cursor += 1
    return cursor


def _replace_explicit_root(text: str, root: _PrivateRoot) -> tuple[str, int]:
    output: list[str] = []
    cursor = 0
    replacements = 0
    marker = _PATH_MARKER.decode("ascii")

    for match in root.pattern.finditer(text):
        if match.start() < cursor:
            continue
        path_end = _explicit_path_end(text, match.start(), match.end())
        if path_end is None:
            continue
        matched_path = text[match.start() : path_end]
        suffix_match = _PATH_LINE_SUFFIX_RE.search(matched_path)
        suffix = suffix_match.group(1) if suffix_match is not None else ""
        quoted = match.start() > 0 and text[match.start() - 1] in "\"'"
        if path_end < len(text) and not suffix and not quoted:
            return marker, 1
        output.append(text[cursor : match.start()])
        output.append(marker + suffix)
        cursor = path_end
        replacements += 1

    if replacements == 0:
        return text, 0
    output.append(text[cursor:])
    return "".join(output), replacements


def _redact_explicit_roots(
    payload: bytes,
    roots: tuple[_PrivateRoot, ...],
) -> tuple[bytes, int]:
    if not roots:
        return payload, 0

    has_final_lf = payload.endswith(b"\n")
    records = payload.split(b"\n")
    if has_final_lf:
        records = records[:-1]

    output: list[bytes] = []
    path_redactions = 0
    for record in records:
        if record in {_SECRET_MARKER, _PRIVATE_KEY_MARKER}:
            output.append(record)
            continue
        text = record.decode("utf-8", errors="surrogateescape")
        for root in roots:
            text, count = _replace_explicit_root(text, root)
            path_redactions += count
        output.append(text.encode("utf-8", errors="surrogateescape"))

    redacted = b"\n".join(output)
    if has_final_lf:
        redacted += b"\n"
    return redacted, path_redactions


def _next_detection_index(text: str, start: int) -> int:
    cursor = start
    while cursor < len(text) and _is_detection_ignored(text[cursor]):
        cursor += 1
    return cursor


def _generic_path_kind(text: str, start: int) -> str | None:
    if not _has_path_left_boundary(text, start) and not (
        start >= 3 and text[start - 3 : start] == "://"
    ):
        return None
    if text[start].isascii() and text[start].isalpha():
        colon = _next_detection_index(text, start + 1)
        separator = _next_detection_index(text, colon + 1)
        if (
            colon < len(text)
            and text[colon] == ":"
            and separator < len(text)
            and text[separator] in "/\\"
        ):
            return "drive"
    if text[start] == "/":
        second = _next_detection_index(text, start + 1)
        if second < len(text) and text[second] == "/":
            return "unc"
        return "posix"
    if text[start] == "\\":
        second = _next_detection_index(text, start + 1)
        if second < len(text) and text[second] == "\\":
            return "unc"
    return None


def _generic_token_end(text: str, start: int) -> int:
    quote = text[start - 1] if start > 0 and text[start - 1] in "\"'" else None
    if quote is not None:
        closing_quote = _find_unescaped_quote(text, quote, start)
        return len(text) if closing_quote < 0 else closing_quote

    cursor = start
    while cursor < len(text):
        character = text[cursor]
        if character in " \t\"'<>[]{}|,;!?=":
            break
        cursor += 1
    return cursor


def _generic_path_body_end(text: str, start: int, token_end: int) -> int:
    token = text[start:token_end]
    suffix = _GENERIC_LOCATION_SUFFIX_RE.search(token)
    return token_end if suffix is None else start + suffix.start()


def _is_valid_generic_path(text: str, start: int, end: int, kind: str) -> bool:
    path = "".join(
        character
        for character in text[start:end]
        if not _is_detection_ignored(character)
    )
    if kind == "posix":
        return len(path) > 1
    if kind == "drive":
        return len(path) > 3
    components = tuple(
        component
        for component in re.split(r"[\\/]+", path[2:])
        if component
    )
    return len(components) >= 3


def _replace_generic_paths(text: str) -> tuple[str, int]:
    protected_urls: dict[int, int] = {}
    for match in _SCHEME_URL_RE.finditer(text):
        scheme = match.group("scheme")
        protected_urls[match.start()] = (
            match.end()
            if scheme.casefold() in _REMOTE_URL_SCHEMES
            else match.start() + len(scheme) + 3
        )
    output: list[str] = []
    marker = _PATH_MARKER.decode("ascii")
    replacements = 0
    cursor = 0

    while cursor < len(text):
        protected_end = protected_urls.get(cursor)
        if protected_end is not None:
            output.append(text[cursor:protected_end])
            cursor = protected_end
            continue

        kind = _generic_path_kind(text, cursor)
        if kind is None:
            output.append(text[cursor])
            cursor += 1
            continue

        token_end = _generic_token_end(text, cursor)
        path_end = _generic_path_body_end(text, cursor, token_end)
        if not _is_valid_generic_path(text, cursor, path_end, kind):
            output.append(text[cursor])
            cursor += 1
            continue

        quoted = cursor > 0 and text[cursor - 1] in "\"'"
        if path_end == token_end and token_end < len(text) and not quoted:
            return marker, 1

        output.append(marker)
        replacements += 1
        cursor = path_end

    return "".join(output), replacements


def _looks_like_raw_absolute_path(value: str) -> bool:
    if value.startswith(("/", "\\\\")):
        return True
    return (
        len(value) >= 3
        and value[0].isascii()
        and value[0].isalpha()
        and value[1] == ":"
        and value[2] in "/\\"
    )


def _remote_url_values(url: str) -> tuple[str, ...]:
    query = url.find("?")
    fragment = url.find("#")
    starts = tuple(index for index in (query, fragment) if index >= 0)
    if not starts:
        return ()
    suffix = url[min(starts) + 1 :]
    values: list[str] = []
    for field in re.split(r"[&;#]", suffix):
        value = field.split("=", 1)[1] if "=" in field else field
        values.append(value)
    return tuple(values)


def _remote_url_remainder(url: str) -> str:
    authority_start = url.find("://") + 3
    return "" if authority_start < 3 else url[authority_start:]


def _nested_scheme_value_requires_path_redaction(value: str) -> bool:
    match = re.match(r"(?i)^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*):(?P<body>.*)$", value)
    if match is None:
        return False
    scheme = match.group("scheme").casefold()
    if scheme == "file":
        return True
    if scheme in _REMOTE_URL_SCHEMES:
        return False
    body = match.group("body")
    return body.startswith(("/", "\\"))


def _url_record_requires_path_redaction(text: str) -> bool:
    pending_urls = [match.group(0) for match in _SCHEME_URL_RE.finditer(text)]
    if len(pending_urls) > _MAX_NESTED_URLS:
        return True
    inspected = 0
    while inspected < len(pending_urls):
        if inspected >= _MAX_NESTED_URLS:
            return True
        url = pending_urls[inspected]
        inspected += 1
        match = _SCHEME_URL_RE.match(url)
        if match is None:
            return True
        scheme = match.group("scheme").casefold()
        if scheme == "file":
            return True
        if scheme in _REMOTE_URL_SCHEMES:
            for value in _remote_url_values(url):
                if (
                    _looks_like_raw_absolute_path(value)
                    or _nested_scheme_value_requires_path_redaction(value)
                ):
                    return True
            pending_urls.extend(
                nested.group(0)
                for nested in _PATH_BEARING_SCHEME_REFERENCE_RE.finditer(
                    _remote_url_remainder(url)
                )
            )
            if len(pending_urls) > _MAX_NESTED_URLS:
                return True
            continue
        authority_and_path = url[len(match.group("scheme")) + 3 :]
        if "/" in authority_and_path or "\\" in authority_and_path:
            return True
    return False


def _redact_generic_paths(payload: bytes) -> tuple[bytes, int]:
    has_final_lf = payload.endswith(b"\n")
    records = payload.split(b"\n")
    if has_final_lf:
        records = records[:-1]

    output: list[bytes] = []
    path_redactions = 0
    markers = {_SECRET_MARKER, _PRIVATE_KEY_MARKER, _PATH_MARKER}
    for record in records:
        if record in markers:
            output.append(record)
            continue
        text = record.decode("utf-8", errors="surrogateescape")
        if _url_record_requires_path_redaction(text):
            output.append(_PATH_MARKER)
            path_redactions += 1
            continue
        text, count = _replace_generic_paths(text)
        path_redactions += count
        output.append(text.encode("utf-8", errors="surrogateescape"))

    redacted = b"\n".join(output)
    if has_final_lf:
        redacted += b"\n"
    return redacted, path_redactions


def _encoding_event_counts(payload: bytes) -> tuple[int, int]:
    invalid_utf8_bytes = 0
    escaped_control_characters = 0
    for character in payload.decode("utf-8", errors="surrogateescape"):
        codepoint = ord(character)
        if 0xDC80 <= codepoint <= 0xDCFF:
            invalid_utf8_bytes += 1
        elif character != "\n" and (codepoint < 0x20 or 0x7F <= codepoint <= 0x9F):
            escaped_control_characters += 1
    return invalid_utf8_bytes, escaped_control_characters


def _render_bytes(payload: bytes, limit: int) -> tuple[bytes, int, int]:
    output = bytearray()
    invalid_utf8_bytes = 0
    escaped_control_characters = 0

    for character in payload.decode("utf-8", errors="surrogateescape"):
        codepoint = ord(character)
        if 0xDC80 <= codepoint <= 0xDCFF:
            fragment = f"\\x{codepoint - 0xDC00:02X}".encode("ascii")
            invalid_utf8_bytes += 1
        elif character == "\\":
            fragment = b"\\\\"
        elif character == "\n":
            fragment = b"\n"
        elif codepoint < 0x20 or codepoint == 0x7F:
            fragment = f"\\x{codepoint:02X}".encode("ascii")
            escaped_control_characters += 1
        elif 0x80 <= codepoint <= 0x9F:
            fragment = f"\\u00{codepoint:02X}".encode("ascii")
            escaped_control_characters += 1
        else:
            fragment = character.encode("utf-8")

        if len(output) + len(fragment) > limit:
            raise SanitizationError(SanitizationErrorCode.OUTPUT_LIMIT_EXCEEDED)
        output.extend(fragment)

    return bytes(output), invalid_utf8_bytes, escaped_control_characters


class StreamingSanitizer:
    """Accumulate bounded bytes and release output only from ``finish``."""

    __slots__ = ("_buffer", "_limits", "_private_roots", "_state")

    def __init__(
        self,
        *,
        limits: SanitizerLimits | None = None,
        private_roots: tuple[str, ...] = (),
    ) -> None:
        self._limits = limits if limits is not None else SanitizerLimits()
        if type(self._limits) is not SanitizerLimits:
            raise SanitizationError(SanitizationErrorCode.INVALID_LIMITS)
        self._private_roots = _validated_private_roots(private_roots)
        self._buffer = bytearray()
        self._state = _State.ACTIVE

    def feed(self, chunk: bytes) -> None:
        if self._state is not _State.ACTIVE:
            raise SanitizationError(SanitizationErrorCode.INVALID_STATE)
        if type(chunk) is not bytes:
            self._abort_with(SanitizationErrorCode.INVALID_INPUT_TYPE)
        if len(self._buffer) + len(chunk) > self._limits.max_input_bytes:
            self._abort_with(SanitizationErrorCode.INPUT_LIMIT_EXCEEDED)
        self._buffer.extend(chunk)

    def finish(self) -> SanitizedOutput:
        if self._state is not _State.ACTIVE:
            raise SanitizationError(SanitizationErrorCode.INVALID_STATE)
        input_bytes = len(self._buffer)
        try:
            payload, ansi_sequences_stripped, incomplete_ansi_sequences = _strip_ansi(
                bytes(self._buffer),
                self._limits.max_control_sequence_bytes,
            )
            records, group_ids, has_final_lf = _split_normalized_records(
                payload,
                self._limits.max_pending_bytes,
            )
            if len(records) > self._limits.max_lines:
                raise SanitizationError(SanitizationErrorCode.LINE_LIMIT_EXCEEDED)
            payload = _join_normalized_records(records, has_final_lf)
            invalid_utf8_bytes, escaped_control_characters = _encoding_event_counts(payload)
            records, secret_redactions, private_key_redactions = _redact_sensitive_records(
                records,
                group_ids,
            )
            payload = _join_normalized_records(records, has_final_lf)
            payload, path_redactions = _redact_explicit_roots(
                payload,
                self._private_roots,
            )
            payload, generic_path_redactions = _redact_generic_paths(payload)
            path_redactions += generic_path_redactions
            payload, _, _ = _render_bytes(
                payload,
                self._limits.max_output_bytes,
            )
        except SanitizationError:
            self.abort()
            raise
        line_count = len(records)
        self._buffer.clear()
        self._state = _State.FINISHED
        return SanitizedOutput(
            payload=payload,
            summary=SanitizationSummary(
                input_bytes=input_bytes,
                output_bytes=len(payload),
                line_count=int(line_count),
                ansi_sequences_stripped=ansi_sequences_stripped,
                incomplete_ansi_sequences=incomplete_ansi_sequences,
                invalid_utf8_bytes=invalid_utf8_bytes,
                escaped_control_characters=escaped_control_characters,
                secret_redactions=secret_redactions,
                private_key_redactions=private_key_redactions,
                path_redactions=path_redactions,
            ),
        )

    def abort(self) -> None:
        if self._state is not _State.ACTIVE:
            return
        self._buffer.clear()
        self._state = _State.ABORTED

    def _abort_with(self, code: SanitizationErrorCode) -> None:
        self.abort()
        raise SanitizationError(code)


def sanitize_bytes(
    payload: bytes,
    *,
    limits: SanitizerLimits | None = None,
    private_roots: tuple[str, ...] = (),
) -> SanitizedOutput:
    """Sanitize one bounded byte payload through the streaming contract."""

    sanitizer = StreamingSanitizer(limits=limits, private_roots=private_roots)
    sanitizer.feed(payload)
    return sanitizer.finish()
