#!/usr/bin/env python3
"""Deterministic shared property/privacy oracles for the ContextGuard A2 gate.

The A2 implementation has two mirrored entrypoints.  These fixtures deliberately
import neither one: feature tests can evaluate the canonical and packaged hooks
against the same independently generated expectations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import random
import stat
from typing import Callable, Iterable, Mapping, Sequence
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = (
    ROOT
    / "tests"
    / "fixtures"
    / "context_guard_contracts"
    / "a2-property-oracle-v1.json"
)
FIXTURE_SCHEMA_VERSION = 1
POLICY_VERSION = "a2-read-env-v1"
BYTE_RANGE_SEED = 0xA20001
ENV_PATH_SEED = 0xA20002
PROOF_RACE_SEED = 0xA20003
PRIVACY_SEED = 0xA20004
PROOF_BUDGET_ENV_SEED = 0xA20005
MIGRATION_SEED = 0xA20006
SURFACE_SEED = 0xA20007
ENTRYPOINTS = ("canonical", "packaged")
ENV_EXAMPLE_BASENAMES = frozenset(
    {".env.example", ".env.sample", ".env.template"}
)
PRODUCT_OWNED_ENV_READ_DENIES = frozenset(
    {"Read(./.env)", "Read(./.env.*)"}
)
DEFAULT_MAX_LINE_RANGE = 400
DEFAULT_READ_PROOF_BYTES = 8 * 1024 * 1024
MIN_READ_PROOF_BYTES = 64 * 1024
MAX_READ_PROOF_BYTES = 64 * 1024 * 1024
MAX_READ_RANGE_INTEGER = (1 << 63) - 1


def _slug(value: str) -> str:
    return "".join(
        char if char.isalnum() else "-" for char in value.lower()
    ).strip("-") or "case"


def _case_id(prefix: str, *parts: object) -> str:
    basis = "\0".join(str(part) for part in parts).encode("utf-8", "replace")
    digest = hashlib.sha256(basis).hexdigest()[:10]
    readable = "-".join(_slug(str(part))[:20] for part in parts[:3])
    return f"{prefix}-{readable}-{digest}"


def _strict_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized:
        return None
    signless = normalized[1:] if normalized[:1] in {"+", "-"} else normalized
    if not signless.isascii() or not signless.isdigit():
        return None
    try:
        return int(normalized)
    except (TypeError, ValueError, OverflowError):
        return None


def range_proof_oracle(
    data: bytes,
    *,
    offset: object,
    limit: object,
    max_range_bytes: int,
    max_proof_bytes: int,
    max_line_range: int = DEFAULT_MAX_LINE_RANGE,
) -> dict[str, object]:
    """Evaluate the A2 raw-byte range contract without decoding file content.

    LF terminates a line and consumes proof budget but is not content-charged.
    CR is an ordinary charged byte, including the CR in CRLF.  A final non-LF
    line is charged through EOF.  A range is admitted only when its start/end
    and content-byte charge are proven within the bounded prefix.
    """
    parsed_offset = _strict_int(offset)
    parsed_limit = _strict_int(limit)
    if (
        parsed_offset is None
        or parsed_limit is None
        or parsed_offset < 0
        or parsed_limit <= 0
        or parsed_limit > max_line_range
        or parsed_offset > MAX_READ_RANGE_INTEGER
        or parsed_limit > MAX_READ_RANGE_INTEGER - parsed_offset
    ):
        return {
            "expected_decision": "deny",
            "expected_reason": "invalid_range",
            "expected_range_bytes": None,
            "expected_proof_bytes": 0,
            "expected_selected_hex": None,
        }
    if max_range_bytes < 0 or max_proof_bytes <= 0:
        return {
            "expected_decision": "deny",
            "expected_reason": "invalid_proof_limits",
            "expected_range_bytes": None,
            "expected_proof_bytes": 0,
            "expected_selected_hex": None,
        }

    scan_limit = min(len(data), max_proof_bytes)
    selected_end = parsed_offset + parsed_limit
    line_index = 0
    charged = bytearray()
    for index, byte in enumerate(data[:scan_limit], start=1):
        if byte == 0x0A:
            line_index += 1
            if line_index >= selected_end:
                return {
                    "expected_decision": "allow",
                    "expected_reason": "range_proven",
                    "expected_range_bytes": len(charged),
                    "expected_proof_bytes": index,
                    "expected_selected_hex": bytes(charged).hex(),
                }
            continue
        if parsed_offset <= line_index < selected_end:
            charged.append(byte)
            if len(charged) > max_range_bytes:
                return {
                    "expected_decision": "deny",
                    "expected_reason": "range_byte_limit_exceeded",
                    "expected_range_bytes": len(charged),
                    "expected_proof_bytes": index,
                    "expected_selected_hex": bytes(charged).hex(),
                }

    if scan_limit == len(data):
        return {
            "expected_decision": "allow",
            "expected_reason": "range_proven",
            "expected_range_bytes": len(charged),
            "expected_proof_bytes": scan_limit,
            "expected_selected_hex": bytes(charged).hex(),
        }
    return {
        "expected_decision": "deny",
        "expected_reason": "proof_budget_exceeded",
        "expected_range_bytes": None,
        "expected_proof_bytes": scan_limit,
        "expected_selected_hex": None,
    }


def _fixed_byte_range_templates() -> list[dict[str, object]]:
    return [
        {
            "name": "lf-first-line",
            "data": b"alpha\nbeta\n",
            "offset": 0,
            "limit": 1,
            "max_range_bytes": 5,
            "max_proof_bytes": 64,
            "coverage": ["lf_charge", "zero_based_offset"],
        },
        {
            "name": "lf-second-line",
            "data": b"alpha\nbeta\n",
            "offset": 1,
            "limit": 1,
            "max_range_bytes": 4,
            "max_proof_bytes": 64,
            "coverage": ["lf_charge", "zero_based_offset"],
        },
        {
            "name": "crlf-charges-both-bytes",
            "data": b"a\r\nbb\r\n",
            "offset": 0,
            "limit": 1,
            "max_range_bytes": 2,
            "max_proof_bytes": 64,
            "coverage": ["cr_charge", "lf_charge"],
        },
        {
            "name": "bare-cr-is-not-line-break",
            "data": b"a\rb\nc",
            "offset": 0,
            "limit": 1,
            "max_range_bytes": 3,
            "max_proof_bytes": 64,
            "coverage": ["cr_charge", "lf_charge"],
        },
        {
            "name": "eof-without-lf",
            "data": b"abc",
            "offset": 0,
            "limit": 1,
            "max_range_bytes": 3,
            "max_proof_bytes": 64,
            "coverage": ["eof_charge"],
        },
        {
            "name": "empty-line",
            "data": b"\n\nx",
            "offset": 1,
            "limit": 1,
            "max_range_bytes": 0,
            "max_proof_bytes": 64,
            "coverage": ["lf_charge", "empty_line"],
        },
        {
            "name": "utf8-counted-as-raw-bytes",
            "data": "\ud55c\nz".encode("utf-8"),
            "offset": 0,
            "limit": 1,
            "max_range_bytes": 3,
            "max_proof_bytes": 64,
            "coverage": ["raw_bytes", "lf_charge"],
        },
        {
            "name": "invalid-utf8-remains-raw",
            "data": b"\xff\xfe\nz",
            "offset": 0,
            "limit": 1,
            "max_range_bytes": 2,
            "max_proof_bytes": 64,
            "coverage": ["raw_bytes", "invalid_utf8"],
        },
        {
            "name": "single-line-over-byte-limit",
            "data": (b"x" * 17) + b"\n",
            "offset": 0,
            "limit": 1,
            "max_range_bytes": 16,
            "max_proof_bytes": 64,
            "coverage": ["range_byte_limit"],
        },
        {
            "name": "proof-budget-before-offset",
            "data": b"a\n" * 50,
            "offset": 40,
            "limit": 1,
            "max_range_bytes": 16,
            "max_proof_bytes": 32,
            "coverage": ["proof_budget", "offset_proof"],
        },
        {
            "name": "proof-budget-before-line-end",
            "data": (b"x" * 64) + b"\n",
            "offset": 0,
            "limit": 1,
            "max_range_bytes": 128,
            "max_proof_bytes": 32,
            "coverage": ["proof_budget", "range_end_proof"],
        },
        {
            "name": "newline-at-proof-boundary",
            "data": (b"x" * 31) + b"\nTAIL",
            "offset": 0,
            "limit": 1,
            "max_range_bytes": 31,
            "max_proof_bytes": 32,
            "coverage": ["proof_boundary", "lf_charge"],
        },
        {
            "name": "eof-at-proof-boundary",
            "data": b"x" * 32,
            "offset": 0,
            "limit": 1,
            "max_range_bytes": 32,
            "max_proof_bytes": 32,
            "coverage": ["proof_boundary", "eof_charge"],
        },
        {
            "name": "negative-offset",
            "data": b"x\n",
            "offset": -1,
            "limit": 1,
            "max_range_bytes": 16,
            "max_proof_bytes": 32,
            "coverage": ["invalid_range"],
        },
        {
            "name": "zero-limit",
            "data": b"x\n",
            "offset": 0,
            "limit": 0,
            "max_range_bytes": 16,
            "max_proof_bytes": 32,
            "coverage": ["invalid_range"],
        },
        {
            "name": "decimal-string-offset",
            "data": b"x\n",
            "offset": "0",
            "limit": 1,
            "max_range_bytes": 16,
            "max_proof_bytes": 32,
            "coverage": ["decimal_string", "compatibility"],
        },
        {
            "name": "nonnumeric-string-offset",
            "data": b"x\n",
            "offset": "zero",
            "limit": 1,
            "max_range_bytes": 16,
            "max_proof_bytes": 32,
            "coverage": ["invalid_range", "type_confusion"],
        },
        {
            "name": "boolean-limit",
            "data": b"x\n",
            "offset": 0,
            "limit": True,
            "max_range_bytes": 16,
            "max_proof_bytes": 32,
            "coverage": ["invalid_range", "type_confusion"],
        },
        {
            "name": "line-limit-over-policy",
            "data": b"x\n",
            "offset": 0,
            "limit": DEFAULT_MAX_LINE_RANGE + 1,
            "max_range_bytes": 16,
            "max_proof_bytes": 32,
            "coverage": ["invalid_range", "line_limit"],
        },
        {
            "name": "offset-at-eof",
            "data": b"x\n",
            "offset": 1,
            "limit": 1,
            "max_range_bytes": 16,
            "max_proof_bytes": 32,
            "coverage": ["empty_range", "eof_charge"],
        },
    ]


def _generated_byte_range_templates(seed: int) -> list[dict[str, object]]:
    rng = random.Random(seed)
    templates: list[dict[str, object]] = []
    alphabet = (0x00, 0x0D, 0x20, 0x41, 0x7F, 0x80, 0xFE, 0xFF)
    for ordinal in range(24):
        line_count = rng.randint(1, 6)
        lines = [
            bytes(rng.choice(alphabet) for _ in range(rng.randint(0, 18)))
            for _ in range(line_count)
        ]
        trailing_lf = ordinal % 3 != 0
        data = b"\n".join(lines) + (b"\n" if trailing_lf else b"")
        if not data:
            data = b"\x00"
        offset = rng.randrange(line_count)
        limit = rng.randint(1, max(1, line_count - offset))
        generous = range_proof_oracle(
            data,
            offset=offset,
            limit=limit,
            max_range_bytes=max(1, len(data)),
            max_proof_bytes=max(1, len(data)),
        )
        selected_bytes = int(generous["expected_range_bytes"] or 0)
        proof_bytes = int(generous["expected_proof_bytes"] or 0)
        if ordinal % 3 == 0:
            max_range_bytes = max(1, selected_bytes - 1)
            max_proof_bytes = max(1, len(data))
            mutation = "range_limit_minus_one"
        elif ordinal % 3 == 1:
            max_range_bytes = max(1, selected_bytes)
            max_proof_bytes = max(1, proof_bytes - 1)
            mutation = "proof_limit_minus_one"
        else:
            max_range_bytes = max(1, selected_bytes)
            max_proof_bytes = max(1, proof_bytes)
            mutation = "exact_boundaries"
        templates.append(
            {
                "name": f"seeded-{ordinal:02d}-{mutation}",
                "data": data,
                "offset": offset,
                "limit": limit,
                "max_range_bytes": max_range_bytes,
                "max_proof_bytes": max_proof_bytes,
                "coverage": ["seeded_property", mutation, "raw_bytes"],
                "generated": True,
            }
        )
    return templates


def byte_range_cases(seed: int = BYTE_RANGE_SEED) -> list[dict[str, object]]:
    templates = [
        *_fixed_byte_range_templates(),
        *_generated_byte_range_templates(seed),
    ]
    cases: list[dict[str, object]] = []
    for entrypoint in ENTRYPOINTS:
        for ordinal, template in enumerate(templates):
            data = template["data"]
            assert isinstance(data, bytes)
            expectation = range_proof_oracle(
                data,
                offset=template["offset"],
                limit=template["limit"],
                max_range_bytes=int(template["max_range_bytes"]),
                max_proof_bytes=int(template["max_proof_bytes"]),
            )
            cases.append(
                {
                    "case_id": _case_id(
                        "range",
                        entrypoint,
                        template["name"],
                        data.hex(),
                    ),
                    "seed": seed,
                    "ordinal": ordinal,
                    "entrypoint": entrypoint,
                    "name": template["name"],
                    "payload_hex": data.hex(),
                    "payload_bytes": len(data),
                    "offset": template["offset"],
                    "limit": template["limit"],
                    "max_line_range": DEFAULT_MAX_LINE_RANGE,
                    "max_range_bytes": template["max_range_bytes"],
                    "max_proof_bytes": template["max_proof_bytes"],
                    **expectation,
                    **{
                        key: value
                        for key, value in template.items()
                        if key not in {"name", "data", "offset", "limit"}
                    },
                }
            )
    return cases


def classify_env_path(
    raw_path: str, *, symlink_ambiguous: bool = False
) -> tuple[str, str]:
    """Classify the normalized basename under the exact A2 ``.env*`` policy."""
    if symlink_ambiguous:
        return "deny", "symlink_ambiguous"
    normalized = raw_path.replace("\\", "/").rstrip("/")
    basename = normalized.rsplit("/", 1)[-1]
    if basename in ENV_EXAMPLE_BASENAMES:
        return "allow", "exact_example_exception"
    if basename.casefold().startswith(".env"):
        return "deny", "protected_env_basename"
    return "allow", "not_protected_env_basename"


def _env_path_templates() -> list[dict[str, object]]:
    return [
        {"path": ".env", "coverage": ["root", "protected"]},
        {"path": ".env.local", "coverage": ["root", "protected"]},
        {"path": ".env.production", "coverage": ["root", "protected"]},
        {"path": ".environment", "coverage": ["prefix", "protected"]},
        {"path": ".envrc", "coverage": ["prefix", "protected"]},
        {"path": ".env_example", "coverage": ["near_miss", "protected"]},
        {"path": ".env.example.bak", "coverage": ["near_miss", "protected"]},
        {"path": ".env.example", "coverage": ["root", "exception"]},
        {"path": ".env.sample", "coverage": ["root", "exception"]},
        {"path": ".env.template", "coverage": ["root", "exception"]},
        {"path": "config/.env", "coverage": ["nested", "protected"]},
        {"path": "config/../secrets/.env.test", "coverage": ["nested", "protected"]},
        {"path": "config/.env.sample", "coverage": ["nested", "exception"]},
        {"path": r"config\.env.template", "coverage": ["separator", "exception"]},
        {"path": "env", "coverage": ["benign"]},
        {"path": "example.env", "coverage": ["benign"]},
        {"path": ".venv", "coverage": ["benign"]},
        {"path": ".ENV", "coverage": ["casefold", "protected"]},
        {
            "path": ".ENV.EXAMPLE",
            "coverage": ["casefold", "exact_exception_near_miss", "protected"],
        },
        {
            "path": "linked/.env.example",
            "symlink_ambiguous": True,
            "coverage": ["symlink", "exception_precedence"],
        },
        {
            "path": "linked/.env.production",
            "symlink_ambiguous": True,
            "coverage": ["symlink", "protected"],
        },
        {
            "path": "linked/README.md",
            "symlink_ambiguous": True,
            "coverage": ["symlink", "benign_basename"],
        },
    ]


def env_path_cases(seed: int = ENV_PATH_SEED) -> list[dict[str, object]]:
    templates = _env_path_templates()
    random.Random(seed).shuffle(templates)
    cases: list[dict[str, object]] = []
    for entrypoint in ENTRYPOINTS:
        for ordinal, template in enumerate(templates):
            raw_path = str(template["path"])
            symlink_ambiguous = bool(template.get("symlink_ambiguous", False))
            decision, reason = classify_env_path(
                raw_path, symlink_ambiguous=symlink_ambiguous
            )
            cases.append(
                {
                    "case_id": _case_id(
                        "env",
                        entrypoint,
                        raw_path,
                        symlink_ambiguous,
                    ),
                    "seed": seed,
                    "ordinal": ordinal,
                    "entrypoint": entrypoint,
                    "path": raw_path,
                    "basename": raw_path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1],
                    "symlink_ambiguous": symlink_ambiguous,
                    "expected_decision": decision,
                    "expected_reason": reason,
                    **{
                        key: value
                        for key, value in template.items()
                        if key not in {"path", "symlink_ambiguous"}
                    },
                }
            )
    return cases


def proof_budget_env_oracle(
    canonical: str | None, legacy: str | None
) -> tuple[int, str]:
    """Resolve canonical/legacy proof-budget env values with A2 precedence."""
    if canonical is not None:
        raw = canonical
        source = "canonical"
    elif legacy is not None:
        raw = legacy
        source = "legacy"
    else:
        return DEFAULT_READ_PROOF_BYTES, "default"
    if not raw:
        return DEFAULT_READ_PROOF_BYTES, f"{source}_invalid_default"
    try:
        parsed = int(raw)
    except (TypeError, ValueError, OverflowError):
        return DEFAULT_READ_PROOF_BYTES, f"{source}_invalid_default"
    bounded = min(
        max(parsed, MIN_READ_PROOF_BYTES), MAX_READ_PROOF_BYTES
    )
    if bounded != parsed:
        suffix = "clamped_min" if parsed < MIN_READ_PROOF_BYTES else "clamped_max"
        return bounded, f"{source}_{suffix}"
    return bounded, source


def _proof_budget_env_templates() -> list[dict[str, object]]:
    return [
        {
            "name": "unset-default",
            "canonical": None,
            "legacy": None,
            "coverage": ["default"],
        },
        {
            "name": "canonical-minimum",
            "canonical": str(MIN_READ_PROOF_BYTES),
            "legacy": None,
            "coverage": ["canonical", "minimum"],
        },
        {
            "name": "canonical-below-minimum",
            "canonical": str(MIN_READ_PROOF_BYTES - 1),
            "legacy": None,
            "coverage": ["canonical", "clamp_min"],
        },
        {
            "name": "canonical-negative",
            "canonical": "-1",
            "legacy": None,
            "coverage": ["canonical", "clamp_min", "negative"],
        },
        {
            "name": "canonical-maximum",
            "canonical": str(MAX_READ_PROOF_BYTES),
            "legacy": None,
            "coverage": ["canonical", "maximum"],
        },
        {
            "name": "canonical-above-maximum",
            "canonical": str(MAX_READ_PROOF_BYTES + 1),
            "legacy": None,
            "coverage": ["canonical", "clamp_max"],
        },
        {
            "name": "canonical-precedes-legacy",
            "canonical": str(2 * 1024 * 1024),
            "legacy": str(4 * 1024 * 1024),
            "coverage": ["canonical", "precedence"],
        },
        {
            "name": "invalid-canonical-still-precedes-legacy",
            "canonical": "invalid",
            "legacy": str(4 * 1024 * 1024),
            "coverage": ["canonical", "precedence", "invalid"],
        },
        {
            "name": "empty-canonical-still-precedes-legacy",
            "canonical": "",
            "legacy": str(4 * 1024 * 1024),
            "coverage": ["canonical", "precedence", "invalid"],
        },
        {
            "name": "legacy-fallback",
            "canonical": None,
            "legacy": str(4 * 1024 * 1024),
            "coverage": ["legacy"],
        },
        {
            "name": "legacy-invalid-default",
            "canonical": None,
            "legacy": "not-an-integer",
            "coverage": ["legacy", "invalid"],
        },
        {
            "name": "canonical-whitespace-integer",
            "canonical": f"  {3 * 1024 * 1024}  ",
            "legacy": None,
            "coverage": ["canonical", "whitespace"],
        },
        {
            "name": "canonical-zero-clamps-minimum",
            "canonical": "0",
            "legacy": None,
            "coverage": ["canonical", "clamp_min", "zero"],
        },
    ]


def proof_budget_env_cases(
    seed: int = PROOF_BUDGET_ENV_SEED,
) -> list[dict[str, object]]:
    templates = _proof_budget_env_templates()
    random.Random(seed).shuffle(templates)
    cases: list[dict[str, object]] = []
    for entrypoint in ENTRYPOINTS:
        for ordinal, template in enumerate(templates):
            canonical = template["canonical"]
            legacy = template["legacy"]
            assert canonical is None or isinstance(canonical, str)
            assert legacy is None or isinstance(legacy, str)
            expected_bytes, expected_source = proof_budget_env_oracle(
                canonical, legacy
            )
            cases.append(
                {
                    "case_id": _case_id(
                        "proof-env",
                        entrypoint,
                        template["name"],
                        canonical,
                        legacy,
                    ),
                    "seed": seed,
                    "ordinal": ordinal,
                    "entrypoint": entrypoint,
                    "name": template["name"],
                    "canonical_env": canonical,
                    "legacy_env": legacy,
                    "default_bytes": DEFAULT_READ_PROOF_BYTES,
                    "minimum_bytes": MIN_READ_PROOF_BYTES,
                    "maximum_bytes": MAX_READ_PROOF_BYTES,
                    "expected_bytes": expected_bytes,
                    "expected_source": expected_source,
                    "coverage": template["coverage"],
                }
            )
    return cases


def migrate_env_read_denies(
    deny: Sequence[object],
    *,
    denies_enabled: bool,
    read_guard: bool,
) -> tuple[list[object], int]:
    """Model the exact setup-owned migration without appending other rules."""
    before = list(deny)
    if not denies_enabled or not read_guard:
        return before, 0
    retained = [
        rule
        for rule in before
        if not (
            isinstance(rule, str)
            and rule in PRODUCT_OWNED_ENV_READ_DENIES
        )
    ]
    return retained, len(before) - len(retained)


def _migration_templates() -> list[dict[str, object]]:
    exact = ["Read(./.env)", "Read(./.env.*)"]
    similar = [
        "Read(.env)",
        "Read(./.env**)",
        "Read(./.env.example)",
        "Read(./nested/.env)",
        "read(./.env)",
        "Read(./.env) ",
    ]
    return [
        {
            "name": "remove-two-exact-rules",
            "before": ["Read(./dist/**)", *exact, "Read(./logs/**)"],
            "denies_enabled": True,
            "read_guard": True,
            "coverage": ["exact_removal", "order"],
        },
        {
            "name": "preserve-similar-user-rules",
            "before": similar,
            "denies_enabled": True,
            "read_guard": True,
            "coverage": ["similar_preserved", "order"],
        },
        {
            "name": "remove-duplicates",
            "before": [
                "Read(./.env)",
                "Read(./src/**)",
                "Read(./.env)",
                "Read(./.env.*)",
            ],
            "denies_enabled": True,
            "read_guard": True,
            "coverage": ["exact_removal", "duplicates", "order"],
        },
        {
            "name": "preserve-non-string-values",
            "before": [
                {"rule": "Read(./.env)"},
                7,
                None,
                "Read(./.env)",
            ],
            "denies_enabled": True,
            "read_guard": True,
            "coverage": ["non_string_preserved", "exact_removal"],
        },
        {
            "name": "read-guard-disabled",
            "before": exact,
            "denies_enabled": True,
            "read_guard": False,
            "coverage": ["gating", "read_guard_disabled"],
        },
        {
            "name": "denies-disabled",
            "before": exact,
            "denies_enabled": False,
            "read_guard": True,
            "coverage": ["gating", "denies_disabled"],
        },
        {
            "name": "already-migrated-idempotent",
            "before": ["Read(./dist/**)", "Read(./logs/**)"],
            "denies_enabled": True,
            "read_guard": True,
            "coverage": ["idempotence", "order"],
        },
        {
            "name": "empty-idempotent",
            "before": [],
            "denies_enabled": True,
            "read_guard": True,
            "coverage": ["idempotence", "empty"],
        },
    ]


def migration_cases(seed: int = MIGRATION_SEED) -> list[dict[str, object]]:
    templates = _migration_templates()
    random.Random(seed).shuffle(templates)
    cases: list[dict[str, object]] = []
    for entrypoint in ENTRYPOINTS:
        for ordinal, template in enumerate(templates):
            before = list(template["before"])
            after, removed = migrate_env_read_denies(
                before,
                denies_enabled=bool(template["denies_enabled"]),
                read_guard=bool(template["read_guard"]),
            )
            cases.append(
                {
                    "case_id": _case_id(
                        "migration",
                        entrypoint,
                        template["name"],
                        json.dumps(before, sort_keys=True),
                    ),
                    "seed": seed,
                    "ordinal": ordinal,
                    "entrypoint": entrypoint,
                    "name": template["name"],
                    "before": before,
                    "denies_enabled": template["denies_enabled"],
                    "read_guard": template["read_guard"],
                    "product_owned_exact_rules": sorted(
                        PRODUCT_OWNED_ENV_READ_DENIES
                    ),
                    "expected_after": after,
                    "expected_removed_count": removed,
                    "expected_changed": before != after,
                    "expected_action": (
                        f"removed {removed} obsolete permissions.deny rules "
                        "now enforced by the Claude Read hook"
                        if removed
                        else None
                    ),
                    "coverage": template["coverage"],
                }
            )
    return cases


def _surface_templates() -> list[dict[str, object]]:
    return [
        {
            "name": "claude-read-env-policy",
            "surface": "Claude Read",
            "enforced": True,
            "mechanism": "PreToolUse Read hook",
            "claim_scope": (
                "case-insensitive .env* basename protection with exact lowercase "
                ".env.example/.env.sample/.env.template exceptions"
            ),
            "required_phrases": [
                "Read-only environment-file policy",
                "protects Claude Read only",
                "Glob name listings, Grep, and Bash/process access are out of scope",
            ],
            "forbidden_claims": [
                "universal environment-file protection",
                "all tools are protected",
            ],
            "coverage": ["read", "exact_scope"],
        },
        {
            "name": "glob-not-content-protected",
            "surface": "Claude Glob",
            "enforced": False,
            "mechanism": "out of scope",
            "claim_scope": "Glob name listings are not blocked by the Read hook",
            "required_phrases": ["Glob name listings"],
            "forbidden_claims": ["Glob is protected by the Read hook"],
            "coverage": ["glob", "limitation"],
        },
        {
            "name": "grep-not-protected",
            "surface": "Claude Grep",
            "enforced": False,
            "mechanism": "out of scope",
            "claim_scope": "Grep access is not blocked by the Read hook",
            "required_phrases": ["Grep"],
            "forbidden_claims": ["Grep is protected by the Read hook"],
            "coverage": ["grep", "limitation"],
        },
        {
            "name": "bash-not-protected",
            "surface": "Claude Bash/process",
            "enforced": False,
            "mechanism": "out of scope",
            "claim_scope": "Bash and process access are not blocked by the Read hook",
            "required_phrases": ["Bash/process access are out of scope"],
            "forbidden_claims": [
                "Bash is protected by the Read hook",
                "process access is universally blocked",
            ],
            "coverage": ["bash", "limitation", "no_universal_protection"],
        },
        {
            "name": "proof-race-boundary",
            "surface": "raw Read range proof",
            "enforced": True,
            "mechanism": "anchored no-follow fd plus initial/final fstat",
            "claim_scope": (
                "detects proof-time dev/inode/size/mtime changes and short reads"
            ),
            "required_phrases": [
                "initial/final",
                "dev/inode/size/mtime",
            ],
            "forbidden_claims": [
                "eliminates every filesystem race",
                "universal TOCTOU protection",
            ],
            "coverage": ["proof", "race", "toctou_caveat"],
        },
        {
            "name": "setup-exact-migration",
            "surface": "Claude setup migration",
            "enforced": True,
            "mechanism": "managed settings transaction",
            "claim_scope": (
                "removes only exact Read(./.env) and Read(./.env.*) product-owned "
                "deny strings when denies and the Read guard are enabled"
            ),
            "required_phrases": [
                "Read(./.env)",
                "Read(./.env.*)",
                "exact",
            ],
            "forbidden_claims": [
                "removes all env-like deny rules",
                "rewrites similar user rules",
            ],
            "coverage": ["migration", "exact_scope", "user_rules_preserved"],
        },
    ]


def surface_claim_cases(seed: int = SURFACE_SEED) -> list[dict[str, object]]:
    templates = _surface_templates()
    random.Random(seed).shuffle(templates)
    cases: list[dict[str, object]] = []
    for entrypoint in ENTRYPOINTS:
        for ordinal, template in enumerate(templates):
            cases.append(
                {
                    "case_id": _case_id(
                        "surface",
                        entrypoint,
                        template["name"],
                        template["surface"],
                    ),
                    "seed": seed,
                    "ordinal": ordinal,
                    "entrypoint": entrypoint,
                    **template,
                    "package_parity_required": True,
                }
            )
    return cases


def _snapshot(
    *,
    dev: int = 11,
    ino: int = 101,
    mode: int = stat.S_IFREG | 0o600,
    size: int = 64,
    mtime_ns: int = 1_700_000_000_000_000_001,
) -> dict[str, int]:
    return {
        "dev": dev,
        "ino": ino,
        "mode": mode,
        "size": size,
        "mtime_ns": mtime_ns,
    }


def proof_snapshot_oracle(
    initial: Mapping[str, int],
    final: Mapping[str, int],
    *,
    bytes_read: int,
    required_proof_bytes: int,
) -> tuple[str, str]:
    if not stat.S_ISREG(int(initial["mode"])) or not stat.S_ISREG(int(final["mode"])):
        return "deny", "not_regular_file"
    if (int(initial["dev"]), int(initial["ino"])) != (
        int(final["dev"]),
        int(final["ino"]),
    ):
        return "deny", "identity_changed"
    if int(initial["size"]) != int(final["size"]):
        return "deny", "size_changed"
    if int(initial["mtime_ns"]) != int(final["mtime_ns"]):
        return "deny", "mtime_changed"
    if bytes_read < required_proof_bytes:
        return "deny", "short_proof_read"
    return "allow", "stable_proof"


def _proof_race_templates() -> list[dict[str, object]]:
    stable = _snapshot()
    return [
        {
            "name": "stable",
            "initial": stable,
            "final": dict(stable),
            "bytes_read": 64,
            "required_proof_bytes": 64,
            "coverage": ["stable_proof"],
        },
        {
            "name": "inode-replaced",
            "initial": stable,
            "final": _snapshot(ino=102),
            "bytes_read": 64,
            "required_proof_bytes": 64,
            "coverage": ["race", "identity"],
        },
        {
            "name": "device-replaced",
            "initial": stable,
            "final": _snapshot(dev=12),
            "bytes_read": 64,
            "required_proof_bytes": 64,
            "coverage": ["race", "identity"],
        },
        {
            "name": "size-grew",
            "initial": stable,
            "final": _snapshot(size=65),
            "bytes_read": 64,
            "required_proof_bytes": 64,
            "coverage": ["race", "size"],
        },
        {
            "name": "size-shrank",
            "initial": stable,
            "final": _snapshot(size=63),
            "bytes_read": 63,
            "required_proof_bytes": 64,
            "coverage": ["race", "size", "short_read"],
        },
        {
            "name": "mtime-changed",
            "initial": stable,
            "final": _snapshot(mtime_ns=int(stable["mtime_ns"]) + 1),
            "bytes_read": 64,
            "required_proof_bytes": 64,
            "coverage": ["race", "mtime"],
        },
        {
            "name": "initial-directory",
            "initial": _snapshot(mode=stat.S_IFDIR | 0o700),
            "final": stable,
            "bytes_read": 64,
            "required_proof_bytes": 64,
            "coverage": ["file_type"],
        },
        {
            "name": "final-directory",
            "initial": stable,
            "final": _snapshot(mode=stat.S_IFDIR | 0o700),
            "bytes_read": 64,
            "required_proof_bytes": 64,
            "coverage": ["race", "file_type"],
        },
        {
            "name": "short-read-stable-metadata",
            "initial": stable,
            "final": dict(stable),
            "bytes_read": 63,
            "required_proof_bytes": 64,
            "coverage": ["short_read", "proof"],
        },
    ]


def proof_race_cases(seed: int = PROOF_RACE_SEED) -> list[dict[str, object]]:
    templates = _proof_race_templates()
    random.Random(seed).shuffle(templates)
    cases: list[dict[str, object]] = []
    for entrypoint in ENTRYPOINTS:
        for ordinal, template in enumerate(templates):
            initial = template["initial"]
            final = template["final"]
            assert isinstance(initial, Mapping) and isinstance(final, Mapping)
            decision, reason = proof_snapshot_oracle(
                initial,
                final,
                bytes_read=int(template["bytes_read"]),
                required_proof_bytes=int(template["required_proof_bytes"]),
            )
            cases.append(
                {
                    "case_id": _case_id(
                        "proof",
                        entrypoint,
                        template["name"],
                        reason,
                    ),
                    "seed": seed,
                    "ordinal": ordinal,
                    "entrypoint": entrypoint,
                    "name": template["name"],
                    "initial": dict(initial),
                    "final": dict(final),
                    "bytes_read": template["bytes_read"],
                    "required_proof_bytes": template["required_proof_bytes"],
                    "expected_decision": decision,
                    "expected_reason": reason,
                    "coverage": template["coverage"],
                }
            )
    return cases


def privacy_findings(
    output: str, forbidden_fragments: Iterable[str]
) -> list[str]:
    """Return stable labels for raw or URL-encoded synthetic output leaks."""
    findings: list[str] = []
    for fragment in forbidden_fragments:
        if not fragment:
            continue
        encoded = quote(fragment, safe="")
        if fragment in output:
            findings.append(f"raw:{fragment}")
        if encoded != fragment and encoded in output:
            findings.append(f"url:{fragment}")
    return findings


def _privacy_templates() -> list[dict[str, object]]:
    secret = "sk-a2-fixture-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
    assignment = "api_key=A2_SYNTHETIC_SECRET_0123456789"
    auth = "Authorization: Bearer A2_SYNTHETIC_BEARER_0123456789"
    private_path = "/Users/a2-fixture/private/.env.production"
    secret_path = "/home/a2-fixture/secrets/client_secret.txt"
    return [
        {
            "name": "secret-redaction",
            "source": secret,
            "forbidden_fragments": [secret],
            "safe_output": "[context-guard-kit] Read blocked: sensitive value [redacted].",
            "coverage": ["secret", "stdout", "stderr"],
        },
        {
            "name": "assignment-redaction",
            "source": assignment,
            "forbidden_fragments": [
                assignment,
                "A2_SYNTHETIC_SECRET_0123456789",
            ],
            "safe_output": "[context-guard-kit] Read blocked: credential [redacted].",
            "coverage": ["secret", "assignment", "hook_reason"],
        },
        {
            "name": "authorization-redaction",
            "source": auth,
            "forbidden_fragments": [
                auth,
                "A2_SYNTHETIC_BEARER_0123456789",
            ],
            "safe_output": "[context-guard-kit] Read blocked: authorization [redacted].",
            "coverage": ["secret", "authorization", "hook_reason"],
        },
        {
            "name": "private-path-redaction",
            "source": private_path,
            "forbidden_fragments": [private_path],
            "safe_output": (
                "[context-guard-kit] Read blocked for "
                "redacted-path#path:0123456789ab: protected env file."
            ),
            "coverage": ["path", "env", "hook_reason"],
        },
        {
            "name": "sensitive-basename-redaction",
            "source": secret_path,
            "forbidden_fragments": [secret_path, "client_secret.txt"],
            "safe_output": (
                "[context-guard-kit] Read blocked for "
                "redacted-path#path:abcdef012345: proof unavailable."
            ),
            "coverage": ["path", "sensitive_basename", "stderr"],
        },
        {
            "name": "control-character-path",
            "source": "/tmp/a2-private\napi_key=A2_CONTROL_SECRET",
            "forbidden_fragments": [
                "/tmp/a2-private\napi_key=A2_CONTROL_SECRET",
                "A2_CONTROL_SECRET",
            ],
            "safe_output": (
                "[context-guard-kit] Read blocked for "
                "redacted-path#path:deadbeefcafe: invalid path."
            ),
            "coverage": ["path", "control_character", "secret"],
        },
    ]


def privacy_scan_cases(seed: int = PRIVACY_SEED) -> list[dict[str, object]]:
    templates = _privacy_templates()
    random.Random(seed).shuffle(templates)
    cases: list[dict[str, object]] = []
    for entrypoint in ENTRYPOINTS:
        for ordinal, template in enumerate(templates):
            forbidden = [str(value) for value in template["forbidden_fragments"]]
            safe_output = str(template["safe_output"])
            safe_outputs = {
                "stdout": safe_output,
                "stderr": safe_output,
                "hook_json": json.dumps(
                    {"permissionDecisionReason": safe_output},
                    sort_keys=True,
                ),
                "state_tree": json.dumps(
                    {"attempts": {"redacted-fingerprint": {"count": 1}}},
                    sort_keys=True,
                ),
            }
            cases.append(
                {
                    "case_id": _case_id(
                        "privacy",
                        entrypoint,
                        template["name"],
                        template["source"],
                    ),
                    "seed": seed,
                    "ordinal": ordinal,
                    "entrypoint": entrypoint,
                    "name": template["name"],
                    "synthetic_only": True,
                    "source": template["source"],
                    "forbidden_fragments": forbidden,
                    "safe_output": safe_output,
                    "safe_outputs": safe_outputs,
                    "expected_findings": [],
                    "expected_findings_by_surface": {
                        surface: [] for surface in safe_outputs
                    },
                    "coverage": template["coverage"],
                }
            )
    return cases


def format_minimized_failure(
    case: Mapping[str, object],
    actual: object,
    *,
    expected_field: str,
) -> str:
    keep = (
        "case_id",
        "seed",
        "entrypoint",
        "name",
        "path",
        "offset",
        "limit",
        "max_range_bytes",
        "max_proof_bytes",
        "initial",
        "final",
        expected_field,
    )
    payload = {key: case[key] for key in keep if key in case}
    payload["expected_field"] = expected_field
    payload["actual"] = actual
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def assert_oracle_cases(
    cases: Iterable[Mapping[str, object]],
    evaluator: Callable[[Mapping[str, object]], object],
    *,
    expected_field: str,
) -> None:
    for case in cases:
        actual = evaluator(case)
        expected = case[expected_field]
        if actual != expected:
            raise AssertionError(
                format_minimized_failure(
                    case,
                    actual,
                    expected_field=expected_field,
                )
            )


def oracle_document() -> dict[str, object]:
    ranges = byte_range_cases()
    env_paths = env_path_cases()
    proof_budget_env = proof_budget_env_cases()
    migration = migration_cases()
    surfaces = surface_claim_cases()
    proof_races = proof_race_cases()
    privacy = privacy_scan_cases()
    return {
        "schema_version": FIXTURE_SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "entrypoints": list(ENTRYPOINTS),
        "seeds": {
            "byte_range": BYTE_RANGE_SEED,
            "env_path": ENV_PATH_SEED,
            "proof_budget_env": PROOF_BUDGET_ENV_SEED,
            "migration": MIGRATION_SEED,
            "surface": SURFACE_SEED,
            "proof_race": PROOF_RACE_SEED,
            "privacy": PRIVACY_SEED,
        },
        "counts": {
            "byte_range": len(ranges),
            "env_path": len(env_paths),
            "proof_budget_env": len(proof_budget_env),
            "migration": len(migration),
            "surface": len(surfaces),
            "proof_race": len(proof_races),
            "privacy": len(privacy),
        },
        "byte_range_cases": ranges,
        "env_path_cases": env_paths,
        "proof_budget_env_cases": proof_budget_env,
        "migration_cases": migration,
        "surface_claim_cases": surfaces,
        "proof_race_cases": proof_races,
        "privacy_scan_cases": privacy,
    }


def render_fixture() -> str:
    return json.dumps(
        oracle_document(), ensure_ascii=False, indent=2, sort_keys=True
    ) + "\n"


def write_fixture(path: Path = FIXTURE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_fixture(), encoding="utf-8")


def check_fixture(path: Path = FIXTURE_PATH) -> bool:
    return path.is_file() and path.read_text(encoding="utf-8") == render_fixture()


def validate_document(document: Mapping[str, object]) -> None:
    collection_names = (
        "byte_range_cases",
        "env_path_cases",
        "proof_budget_env_cases",
        "migration_cases",
        "surface_claim_cases",
        "proof_race_cases",
        "privacy_scan_cases",
    )
    for collection_name in collection_names:
        collection = document[collection_name]
        if not isinstance(collection, list) or not collection:
            raise AssertionError(f"{collection_name} must be a non-empty list")
        ids = [case["case_id"] for case in collection]
        if len(ids) != len(set(ids)):
            raise AssertionError(f"{collection_name} contains duplicate case IDs")
        seen_entrypoints = {case["entrypoint"] for case in collection}
        if seen_entrypoints != set(ENTRYPOINTS):
            raise AssertionError(
                f"{collection_name} entrypoint cross-product is incomplete"
            )
        per_entrypoint = {
            entrypoint: sum(
                case["entrypoint"] == entrypoint for case in collection
            )
            for entrypoint in ENTRYPOINTS
        }
        if len(set(per_entrypoint.values())) != 1:
            raise AssertionError(
                f"{collection_name} entrypoint counts differ: {per_entrypoint}"
            )

    range_coverage = {
        tag
        for case in document["byte_range_cases"]
        for tag in case["coverage"]
    }
    for required in (
        "raw_bytes",
        "lf_charge",
        "cr_charge",
        "eof_charge",
        "proof_budget",
        "invalid_range",
        "seeded_property",
    ):
        if required not in range_coverage:
            raise AssertionError(f"missing byte-range coverage tag: {required}")

    env_rows = {
        (
            case["basename"],
            case["symlink_ambiguous"],
            case["expected_decision"],
        )
        for case in document["env_path_cases"]
    }
    for required in (
        (".env", False, "deny"),
        (".env.example", False, "allow"),
        (".env.sample", False, "allow"),
        (".env.template", False, "allow"),
        (".env.example", True, "deny"),
    ):
        if required not in env_rows:
            raise AssertionError(f"missing env classifier row: {required}")

    proof_budget_coverage = {
        tag
        for case in document["proof_budget_env_cases"]
        for tag in case["coverage"]
    }
    for required in (
        "default",
        "canonical",
        "legacy",
        "precedence",
        "clamp_min",
        "clamp_max",
        "invalid",
    ):
        if required not in proof_budget_coverage:
            raise AssertionError(
                f"missing proof-budget env coverage tag: {required}"
            )

    migration_coverage = {
        tag
        for case in document["migration_cases"]
        for tag in case["coverage"]
    }
    for required in (
        "exact_removal",
        "similar_preserved",
        "non_string_preserved",
        "gating",
        "idempotence",
        "order",
    ):
        if required not in migration_coverage:
            raise AssertionError(f"missing migration coverage tag: {required}")

    surface_rows = {
        (case["surface"], case["enforced"])
        for case in document["surface_claim_cases"]
    }
    for required in (
        ("Claude Read", True),
        ("Claude Glob", False),
        ("Claude Grep", False),
        ("Claude Bash/process", False),
        ("raw Read range proof", True),
        ("Claude setup migration", True),
    ):
        if required not in surface_rows:
            raise AssertionError(f"missing surface claim row: {required}")

    proof_reasons = {
        case["expected_reason"] for case in document["proof_race_cases"]
    }
    for required in (
        "stable_proof",
        "identity_changed",
        "size_changed",
        "mtime_changed",
        "short_proof_read",
        "not_regular_file",
    ):
        if required not in proof_reasons:
            raise AssertionError(f"missing proof/race reason: {required}")

    for case in document["privacy_scan_cases"]:
        for surface, output in case["safe_outputs"].items():
            findings = privacy_findings(
                str(output),
                [str(value) for value in case["forbidden_fragments"]],
            )
            if findings:
                raise AssertionError(
                    format_minimized_failure(
                        case,
                        {surface: findings},
                        expected_field="expected_findings_by_surface",
                    )
                )

    all_ids = [
        case["case_id"]
        for collection_name in collection_names
        for case in document[collection_name]
    ]
    if len(all_ids) != len(set(all_ids)):
        raise AssertionError("oracle document contains cross-matrix duplicate IDs")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-fixture", action="store_true")
    parser.add_argument("--check-fixture", action="store_true")
    args = parser.parse_args(argv)

    validate_document(oracle_document())
    if args.write_fixture:
        write_fixture()
    if args.check_fixture and not check_fixture():
        print(f"stale or missing A2 oracle fixture: {FIXTURE_PATH}")
        return 1
    if not args.write_fixture and not args.check_fixture:
        print(render_fixture(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
