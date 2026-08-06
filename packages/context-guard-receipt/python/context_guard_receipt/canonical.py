"""Bounded canonical JSON and unambiguous domain-separated hashing."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass, fields
from typing import Any, Final


__all__ = [
    "CANONICAL_KEY_ORDER",
    "CANONICAL_UNICODE_PROFILE",
    "CanonicalJSONError",
    "JSONLimits",
    "canonical_json_bytes",
    "parse_canonical_json_bytes",
    "framed_sha256_hex",
]


CANONICAL_UNICODE_PROFILE: Final = "ucd-3.2.0-nfc"
CANONICAL_KEY_ORDER: Final = "unicode-scalar-value"
_FROZEN_UNICODE_DATABASE = unicodedata.ucd_3_2_0


_SIGNED_64_MIN = -(2**63)
_SIGNED_64_MAX = 2**63 - 1
_MAX_DOMAIN_BYTES = 128
_MAX_HASH_PARTS = 64
_MAX_HASH_PART_BYTES = 1024 * 1024
_MAX_HASH_TOTAL_BYTES = 4 * 1024 * 1024


class CanonicalJSONError(ValueError):
    """A bounded, non-reflective canonical-data validation failure."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"canonical JSON rejected: {code}")


@dataclass(frozen=True, slots=True)
class JSONLimits:
    """Resource limits shared by canonical JSON encoding and parsing."""

    max_document_bytes: int = 64 * 1024
    max_depth: int = 32
    max_total_values: int = 1024
    max_object_members: int = 256
    max_string_bytes: int = 16 * 1024

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or value <= 0:
                raise CanonicalJSONError("invalid_limits")


_DEFAULT_LIMITS = JSONLimits()


def _require_limits(limits: JSONLimits) -> JSONLimits:
    if type(limits) is not JSONLimits:
        raise CanonicalJSONError("invalid_limits")
    for field in fields(limits):
        value = getattr(limits, field.name)
        if type(value) is not int or value <= 0:
            raise CanonicalJSONError("invalid_limits")
    return limits


def _validate_string(value: str, limits: JSONLimits) -> None:
    if len(value) > limits.max_string_bytes:
        raise CanonicalJSONError("max_string_bytes_exceeded")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise CanonicalJSONError("invalid_unicode") from None
    if any(_FROZEN_UNICODE_DATABASE.category(character) == "Cn" for character in value):
        raise CanonicalJSONError("unsupported_unicode_repertoire")
    if _FROZEN_UNICODE_DATABASE.normalize("NFC", value) != value:
        raise CanonicalJSONError("non_nfc")
    if len(encoded) > limits.max_string_bytes:
        raise CanonicalJSONError("max_string_bytes_exceeded")


def _validate_json_value(value: object, limits: JSONLimits) -> None:
    total_values = 0
    active_containers: set[int] = set()

    def visit(current: object, depth: int) -> None:
        nonlocal total_values

        current_type = type(current)
        if current_type is float:
            raise CanonicalJSONError("float_not_allowed")
        if current is not None and current_type not in (bool, int, str, list, dict):
            raise CanonicalJSONError("unsupported_type")

        total_values += 1
        if total_values > limits.max_total_values:
            raise CanonicalJSONError("max_total_values_exceeded")

        if current is None or current_type is bool:
            pass
        elif current_type is int:
            if current < _SIGNED_64_MIN or current > _SIGNED_64_MAX:  # type: ignore[operator]
                raise CanonicalJSONError("integer_out_of_range")
        elif current_type is str:
            _validate_string(current, limits)  # type: ignore[arg-type]
        elif current_type is list:
            container_depth = depth + 1
            if container_depth > limits.max_depth:
                raise CanonicalJSONError("max_depth_exceeded")
            identity = id(current)
            if identity in active_containers:
                raise CanonicalJSONError("unsupported_type")
            active_containers.add(identity)
            try:
                for item in current:  # type: ignore[union-attr]
                    visit(item, container_depth)
            finally:
                active_containers.remove(identity)
        elif current_type is dict:
            container_depth = depth + 1
            if container_depth > limits.max_depth:
                raise CanonicalJSONError("max_depth_exceeded")
            if len(current) > limits.max_object_members:  # type: ignore[arg-type]
                raise CanonicalJSONError("max_object_members_exceeded")
            identity = id(current)
            if identity in active_containers:
                raise CanonicalJSONError("unsupported_type")
            active_containers.add(identity)
            try:
                for key, item in current.items():  # type: ignore[union-attr]
                    if type(key) is not str:
                        raise CanonicalJSONError("non_string_key")
                    _validate_string(key, limits)
                    visit(item, container_depth)
            finally:
                active_containers.remove(identity)
    visit(value, 0)


def _encode_validated(value: object, limits: JSONLimits) -> bytes:
    text = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    try:
        raw = text.encode("utf-8", errors="strict") + b"\n"
    except UnicodeEncodeError:
        raise CanonicalJSONError("invalid_unicode") from None
    if len(raw) > limits.max_document_bytes:
        raise CanonicalJSONError("document_too_large")
    return raw


def canonical_json_bytes(
    value: object, limits: JSONLimits = _DEFAULT_LIMITS
) -> bytes:
    """Encode a value as one bounded canonical UTF-8 JSON document."""

    checked_limits = _require_limits(limits)
    _validate_json_value(value, checked_limits)
    return _encode_validated(value, checked_limits)


def _reject_float(_token: str) -> Any:
    raise CanonicalJSONError("float_not_allowed")


def _parse_signed_64_integer(token: str) -> int:
    negative = token.startswith("-")
    digits = token[1:] if negative else token
    maximum = "9223372036854775808" if negative else "9223372036854775807"
    if len(digits) > len(maximum) or (len(digits) == len(maximum) and digits > maximum):
        raise CanonicalJSONError("integer_out_of_range")
    value = int(token, 10)
    if value < _SIGNED_64_MIN or value > _SIGNED_64_MAX:
        raise CanonicalJSONError("integer_out_of_range")
    return value


def _object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalJSONError("duplicate_key")
        result[key] = value
    return result


def _check_raw_nesting(raw: bytes, max_depth: int) -> None:
    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte == 0x5B or byte == 0x7B:
            depth += 1
            if depth > max_depth:
                raise CanonicalJSONError("max_depth_exceeded")
        elif byte == 0x5D or byte == 0x7D:
            depth -= 1


def parse_canonical_json_bytes(
    raw: bytes, limits: JSONLimits = _DEFAULT_LIMITS
) -> object:
    """Parse bytes only when they are the unique bounded canonical encoding."""

    checked_limits = _require_limits(limits)
    if type(raw) is not bytes:
        raise CanonicalJSONError("invalid_raw_type")
    if len(raw) > checked_limits.max_document_bytes:
        raise CanonicalJSONError("document_too_large")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise CanonicalJSONError("invalid_framing")
    if not raw.endswith(b"\n"):
        raise CanonicalJSONError("invalid_framing")
    body = raw[:-1]
    if b"\n" in body or b"\r" in raw:
        raise CanonicalJSONError("invalid_framing")
    try:
        text = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise CanonicalJSONError("invalid_utf8") from None

    _check_raw_nesting(body, checked_limits.max_depth)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_float,
            parse_float=_reject_float,
            parse_int=_parse_signed_64_integer,
        )
    except CanonicalJSONError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError, UnicodeError):
        raise CanonicalJSONError("malformed_json") from None

    _validate_json_value(value, checked_limits)
    if _encode_validated(value, checked_limits) != raw:
        raise CanonicalJSONError("noncanonical_json")
    return value


def framed_sha256_hex(domain: str, *parts: bytes) -> str:
    """Hash an ASCII domain and U64BE-length-framed byte parts."""

    if type(domain) is not str or not domain or "\x00" in domain:
        raise CanonicalJSONError("invalid_domain")
    try:
        domain_bytes = domain.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        raise CanonicalJSONError("invalid_domain") from None
    if len(domain_bytes) > _MAX_DOMAIN_BYTES:
        raise CanonicalJSONError("domain_too_large")
    if len(parts) > _MAX_HASH_PARTS:
        raise CanonicalJSONError("too_many_parts")

    digest = hashlib.sha256()
    digest.update(domain_bytes)
    digest.update(b"\x00")
    total_bytes = 0
    for part in parts:
        if type(part) is not bytes:
            raise CanonicalJSONError("invalid_part")
        if len(part) > _MAX_HASH_PART_BYTES:
            raise CanonicalJSONError("part_too_large")
        total_bytes += len(part)
        if total_bytes > _MAX_HASH_TOTAL_BYTES:
            raise CanonicalJSONError("parts_too_large")
        digest.update(len(part).to_bytes(8, byteorder="big", signed=False))
        digest.update(part)
    return digest.hexdigest()
