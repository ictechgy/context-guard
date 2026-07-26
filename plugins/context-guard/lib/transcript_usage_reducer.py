#!/usr/bin/env python3
"""Deterministic transcript usage reduction shared by audit and statusline.

The reducer intentionally recognizes one Claude transcript shape:
``row.message.usage`` with the model at ``row.message.model``.  It groups
repeated response rows before summing so snapshots, streaming updates, and
nested usage lookalikes cannot be counted as independent usage.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import datetime as _dt
import hashlib
import json
import math
import os
import re
from typing import Any, Iterable


REDUCER_SCHEMA = "usage-reducer-v2"
UINT63_MAX = (1 << 63) - 1
FILE_IDENTITY_RE = re.compile(r"^[0-9a-fA-F]{64}$")
TOKEN_FIELDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("input", ("input_tokens",)),
    ("output", ("output_tokens",)),
    ("cache_creation", ("cache_creation_input_tokens", "cacheCreation")),
    ("cache_read", ("cache_read_input_tokens", "cacheRead")),
)
TIMESTAMP_KEYS = ("timestamp", "created_at", "createdAt", "time", "ts")
COUNTER_KEYS = (
    "observed_rows",
    "eligible_candidates",
    "selected_candidates",
    "usage_conflict",
    "numeric_overflow",
    "invalid_numeric",
    "invalid_row",
    "no_id_fallback",
)


def hash_file_identity(path: str | os.PathLike[str]) -> str:
    """Hash a canonical local transcript identity without returning its path."""
    canonical = os.path.realpath(os.path.abspath(os.fspath(path)))
    return hashlib.sha256(os.fsencode(canonical)).hexdigest()


def canonical_row_sha256(row: Any) -> str | None:
    """Hash a complete canonical JSON row, rejecting non-JSON numeric values."""
    try:
        encoded = json.dumps(
            row,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError):
        return None
    return hashlib.sha256(encoded).hexdigest()


def _canonical_file_identity(value: str) -> str:
    text = str(value)
    if FILE_IDENTITY_RE.fullmatch(text):
        return text.lower()
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


def _session_id(row: dict[str, Any]) -> str:
    for key in ("session_id", "sessionId"):
        value = row.get(key)
        if isinstance(value, str):
            return value
    return ""


def _message_id(message: dict[str, Any]) -> str | None:
    value = message.get("id")
    if isinstance(value, str) and value:
        return value
    return None


def _model(message: dict[str, Any]) -> str:
    value = message.get("model")
    if not isinstance(value, str):
        return "unknown"
    safe_value = value.encode("utf-8", errors="replace").decode("utf-8")
    compact = " ".join(safe_value.strip().split())
    return compact[:120] or "unknown"


def _parse_timestamp(value: Any) -> _dt.datetime | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            parsed = _dt.datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_dt.timezone.utc)
        try:
            return parsed.astimezone(_dt.timezone.utc)
        except (OverflowError, ValueError):
            return None
    if isinstance(value, (int, float)) and math.isfinite(float(value)) and value >= 0:
        seconds = float(value)
        if seconds > 10_000_000_000:
            seconds /= 1000.0
        try:
            return _dt.datetime.fromtimestamp(seconds, tz=_dt.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    return None


def _row_timestamp(row: dict[str, Any], message: dict[str, Any]) -> _dt.datetime | None:
    for container in (row, message):
        for key in TIMESTAMP_KEYS:
            if key in container:
                parsed = _parse_timestamp(container.get(key))
                if parsed is not None:
                    return parsed
    return None


def _usage_values(usage: dict[str, Any]) -> tuple[tuple[str, int], ...] | None:
    values: list[tuple[str, int]] = []
    found = False
    for bucket, aliases in TOKEN_FIELDS:
        raw: Any = None
        present = False
        for alias in aliases:
            if alias in usage:
                raw = usage.get(alias)
                present = True
                break
        if not present:
            continue
        found = True
        if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0 or raw > UINT63_MAX:
            return None
        values.append((bucket, raw))
    if not found:
        return ()
    return tuple(values)


@dataclass(frozen=True)
class UsageSelection:
    file_identity: str
    row_ordinal: int
    tokens: dict[str, int]
    present_buckets: tuple[str, ...]
    model: str
    timestamp: _dt.datetime | None
    used_no_id_fallback: bool


@dataclass(frozen=True)
class UsageReduction:
    schema: str
    tokens: dict[str, int]
    by_model: dict[str, dict[str, int]]
    counters: dict[str, int]
    partial: bool
    selections: tuple[UsageSelection, ...]


@dataclass(frozen=True)
class _Candidate:
    file_identity: str
    row_ordinal: int
    usage_items: tuple[tuple[str, int], ...]
    model: str
    timestamp: _dt.datetime | None
    used_no_id_fallback: bool

    @property
    def value(self) -> tuple[tuple[str, int], ...]:
        return self.usage_items

    @property
    def precedence(self) -> tuple[int, _dt.datetime, int]:
        minimum = _dt.datetime.min.replace(tzinfo=_dt.timezone.utc)
        return (1 if self.timestamp is not None else 0, self.timestamp or minimum, self.row_ordinal)


class UsageReducer:
    """Collect response candidates and finalize their selected aggregate."""

    def __init__(self) -> None:
        self._groups: dict[tuple[str, str, str], list[_Candidate]] = defaultdict(list)
        self._counters = {key: 0 for key in COUNTER_KEYS}
        self._partial = False
        self._next_ordinal = 0

    def note_invalid_row(self, count: int = 1) -> None:
        amount = max(0, int(count))
        if amount:
            self._counters["invalid_row"] += amount
            self._partial = True

    def observe(
        self,
        row: Any,
        *,
        file_identity: str,
        row_ordinal: int | None = None,
    ) -> bool:
        ordinal = self._next_ordinal if row_ordinal is None else int(row_ordinal)
        self._next_ordinal = max(self._next_ordinal + 1, ordinal + 1)
        self._counters["observed_rows"] += 1
        if not isinstance(row, dict):
            self.note_invalid_row()
            return False
        message = row.get("message")
        if not isinstance(message, dict):
            return False
        usage = message.get("usage")
        if not isinstance(usage, dict):
            return False
        usage_items = _usage_values(usage)
        if usage_items is None:
            self._counters["invalid_numeric"] += 1
            self._partial = True
            return False
        if not usage_items:
            return False

        canonical_file = _canonical_file_identity(file_identity)
        message_id = _message_id(message)
        used_no_id_fallback = message_id is None
        if message_id is None:
            row_digest = canonical_row_sha256(row)
            if row_digest is None:
                self.note_invalid_row()
                return False
            group_suffix = f"row:{row_digest}"
        else:
            group_suffix = f"id:{message_id}"
        group_key = (canonical_file, _session_id(row), group_suffix)
        first_for_group = group_key not in self._groups
        candidate = _Candidate(
            file_identity=canonical_file,
            row_ordinal=ordinal,
            usage_items=usage_items,
            model=_model(message),
            timestamp=_row_timestamp(row, message),
            used_no_id_fallback=used_no_id_fallback,
        )
        self._groups[group_key].append(candidate)
        self._counters["eligible_candidates"] += 1
        if used_no_id_fallback and first_for_group:
            self._counters["no_id_fallback"] += 1
        return True

    def extend(
        self,
        rows: Iterable[Any],
        *,
        file_identity: str,
        start_ordinal: int | None = None,
    ) -> None:
        ordinal = self._next_ordinal if start_ordinal is None else int(start_ordinal)
        for row in rows:
            self.observe(row, file_identity=file_identity, row_ordinal=ordinal)
            ordinal += 1

    def finalize(self) -> UsageReduction:
        totals: dict[str, int] = defaultdict(int)
        by_model: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        counters = dict(self._counters)
        partial = self._partial
        selections: list[UsageSelection] = []

        for group_key in sorted(self._groups):
            candidates = self._groups[group_key]
            if len({candidate.value for candidate in candidates}) > 1:
                counters["usage_conflict"] += 1
                partial = True
            selected = max(candidates, key=lambda candidate: candidate.precedence)
            values = dict(selected.usage_items)
            if any(totals[bucket] > UINT63_MAX - value for bucket, value in values.items()):
                counters["numeric_overflow"] += 1
                partial = True
                continue
            for bucket, value in values.items():
                totals[bucket] += value
                by_model[selected.model][bucket] += value
            selections.append(
                UsageSelection(
                    file_identity=selected.file_identity,
                    row_ordinal=selected.row_ordinal,
                    tokens={bucket: value for bucket, value in values.items() if value},
                    present_buckets=tuple(bucket for bucket, _value in selected.usage_items),
                    model=selected.model,
                    timestamp=selected.timestamp,
                    used_no_id_fallback=selected.used_no_id_fallback,
                )
            )

        counters["selected_candidates"] = len(selections)
        stable_totals = {key: totals[key] for key in sorted(totals) if totals[key]}
        stable_by_model = {
            model: {key: buckets[key] for key in sorted(buckets) if buckets[key]}
            for model, buckets in sorted(by_model.items())
            if any(buckets.values())
        }
        return UsageReduction(
            schema=REDUCER_SCHEMA,
            tokens=stable_totals,
            by_model=stable_by_model,
            counters={key: counters.get(key, 0) for key in COUNTER_KEYS},
            partial=partial,
            selections=tuple(selections),
        )


def reduce_rows(
    rows: Iterable[Any],
    *,
    file_identity: str,
    start_ordinal: int = 0,
) -> UsageReduction:
    reducer = UsageReducer()
    reducer.extend(rows, file_identity=file_identity, start_ordinal=start_ordinal)
    return reducer.finalize()
