#!/usr/bin/env python3
"""Static prompt cacheability lint for ContextGuard.

``context-guard-cache-score`` is advisory-only: it does not call provider APIs,
does not estimate price, does not observe cache hits, and does not write raw
prompts to disk.  It only inspects a prompt/request fixture for stable-prefix
shape, common dynamic markers, deterministic ordering hints, and provider cache
eligibility using a tokenizer-free char/4 proxy.
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, NoReturn

TOOL_NAME = "context-guard-cache-score"
SCHEMA_VERSION = "contextguard.cache-score.v1"
DEFAULT_MAX_INPUT_BYTES = 1_000_000
TOKEN_PROXY_CHARS_PER_TOKEN = 4
DEFAULT_EXPECTED_REUSES = 1
MAX_EXPECTED_REUSES = 1_000_000
MAX_CACHE_MULTIPLIER = 1_000_000.0
PROVIDER_MINIMUM_CACHEABLE_TOKENS = {
    # Provider and model minimums move over time.  These defaults are advisory
    # and can be overridden with --minimum-cacheable-tokens.
    "openai": 1024,
    "anthropic": 1024,
    "gemini": 2048,
    "generic": 1024,
}
PROVIDER_CAVEATS = {
    "openai": (
        "OpenAI prompt caching is automatic for eligible prompts; verify real "
        "hits with provider usage.prompt_tokens_details.cached_tokens."
    ),
    "anthropic": (
        "Anthropic prompt caching is model/platform-specific and usually needs "
        "cache_control around the reusable prefix; verify cache_creation/read "
        "usage fields."
    ),
    "gemini": (
        "Gemini context caching thresholds vary by model/platform; verify with "
        "provider cached-content usage fields and override the threshold when "
        "your model differs."
    ),
    "generic": (
        "Generic cache scoring uses a conservative threshold only; check your "
        "provider documentation before claiming cache eligibility."
    ),
}
ALLOWED_FIRST_ABSOLUTE_SYMLINKS = {
    "tmp": Path("/private/tmp"),
    "var": Path("/private/var"),
}
MAX_JSON_PATH_SEGMENT_CHARS = 64
SAFE_JSON_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")
DYNAMIC_JSON_KEY_RE = re.compile(r"(?i)(request|trace|nonce|random|timestamp|created[_-]?at|updated[_-]?at|date)")
SENSITIVE_JSON_KEY_RE = re.compile(
    r"(?i)(authorization|api[_-]?key|apikey|token|secret|password|passwd|pwd|client[_-]?secret|credential|signature|sig|private[_-]?key|privatekey|ssh[_-]?key|sshkey)"
)

DYNAMIC_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("iso_timestamp", re.compile(r"\b20\d{2}-\d{2}-\d{2}[T ][0-2]\d:[0-5]\d(?::[0-5]\d(?:\.\d{1,9})?)?(?:Z|[+-][0-2]\d:?[0-5]\d)?\b")),
    ("uuid", re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b")),
    ("unix_epoch_ms", re.compile(r"\b1[6-9]\d{11}\b")),
    ("request_id_key", re.compile(r"(?i)\b(?:request[_-]?id|trace[_-]?id|nonce|random[_-]?(?:id|seed)?|timestamp|created[_-]?at|updated[_-]?at|date_now)\b")),
)


class CacheScoreError(ValueError):
    """User-facing fail-closed error."""


def fail(message: str) -> NoReturn:
    raise CacheScoreError(message)


def byte_len_text(text: str) -> int:
    return len(text.encode("utf-8", errors="replace"))


def json_bytes(data: Any, *, indent: int | None = None) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":") if indent is None else None, indent=indent)


def json_path_child(path: str, key: object) -> str:
    """Return a JSON warning path segment without echoing sensitive/dynamic keys."""
    text = str(key)
    if DYNAMIC_JSON_KEY_RE.search(text) or SENSITIVE_JSON_KEY_RE.search(text):
        return f"{path}.[redacted-key]"
    if SAFE_JSON_PATH_SEGMENT_RE.fullmatch(text):
        return f"{path}.{text}"
    if len(text) > MAX_JSON_PATH_SEGMENT_CHARS:
        return f"{path}.[key:{len(text)} chars]"
    return f"{path}.[key]"


def bounded_int(value: object, *, default: int, minimum: int, maximum: int, name: str) -> int:
    try:
        number = int(default if value is None else value)
    except (TypeError, ValueError, OverflowError):
        fail(f"{name} must be an integer")
    if number < minimum:
        fail(f"{name} must be >= {minimum}")
    if number > maximum:
        fail(f"{name} must be <= {maximum}")
    return number


def bounded_float(
    value: object,
    *,
    minimum: float,
    maximum: float,
    name: str,
) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        fail(f"{name} must be a finite number")
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        fail(f"{name} must be a finite number")
    if not math.isfinite(number):
        fail(f"{name} must be finite")
    if number < minimum:
        fail(f"{name} must be >= {minimum:g}")
    if number > maximum:
        fail(f"{name} must be <= {maximum:g}")
    return number


def normalized_link_target(parent: Path, raw_target: str) -> Path:
    target = Path(raw_target)
    if not target.is_absolute():
        target = parent / target
    return Path(os.path.normpath(str(target)))


def normalize_allowed_first_absolute_symlink(path: Path) -> Path:
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
        if normalized_link_target(Path(path.anchor), os.readlink(link)) != expected:
            return path
    except OSError:
        return path
    return expected.joinpath(*path.parts[2:])


def reject_symlink_components(path: Path) -> None:
    path = normalize_allowed_first_absolute_symlink(path)
    current = Path(path.anchor) if path.is_absolute() else Path()
    for part in path.parts:
        if path.is_absolute() and part == path.anchor:
            continue
        current = current / part
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(st.st_mode):
            fail(f"refusing path with symlink component: {current}")
        if not stat.S_ISDIR(st.st_mode) and current != path:
            fail(f"refusing path through non-directory component: {current}")


def read_limited_path(path: Path, max_bytes: int) -> str:
    reject_symlink_components(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError as exc:
        fail(f"input read failed: {exc}")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            fail("input must be a regular file")
        if st.st_size > max_bytes:
            fail(f"input exceeds --max-input-bytes: {st.st_size} > {max_bytes}")
        data = os.read(fd, max_bytes + 1)
    finally:
        os.close(fd)
    if len(data) > max_bytes:
        fail(f"input exceeds --max-input-bytes: > {max_bytes}")
    return data.decode("utf-8", errors="replace")


def read_limited_stdin(max_bytes: int) -> str:
    data = sys.stdin.buffer.read(max_bytes + 1)
    if len(data) > max_bytes:
        fail(f"input exceeds --max-input-bytes: > {max_bytes}")
    return data.decode("utf-8", errors="replace")


def estimate_tokens(text: str) -> int:
    if not text:
        return 0
    return int(math.ceil(len(text) / TOKEN_PROXY_CHARS_PER_TOKEN))


def first_dynamic_marker(text: str) -> tuple[int | None, str | None]:
    best_offset: int | None = None
    best_name: str | None = None
    for name, pattern in DYNAMIC_MARKERS:
        match = pattern.search(text)
        if match and (best_offset is None or match.start() < best_offset):
            best_offset = match.start()
            best_name = name
    return best_offset, best_name


def _walk_json(value: Any, path: str = "$") -> list[dict[str, Any]]:
    warnings: list[dict[str, Any]] = []
    if isinstance(value, dict):
        keys = [str(key) for key in value]
        if keys != sorted(keys):
            warnings.append({
                "code": "json_object_key_order_not_sorted",
                "path": path,
                "severity": "info",
                "message": "Object keys are not in deterministic sorted order; keep generated JSON stable across runs.",
            })
        for key, item in value.items():
            child_path = json_path_child(path, key)
            if DYNAMIC_JSON_KEY_RE.search(str(key)):
                warnings.append({
                    "code": "dynamic_json_key",
                    "path": child_path,
                    "severity": "warn",
                    "message": "Dynamic-looking JSON key appears in the prompt/request; place dynamic values after the reusable prefix.",
                })
            warnings.extend(_walk_json(item, child_path))
    elif isinstance(value, list):
        if path.endswith(".tools") and all(isinstance(item, dict) and "name" in item for item in value):
            names = [str(item.get("name")) for item in value]
            if names != sorted(names):
                warnings.append({
                    "code": "tool_order_not_sorted",
                    "path": path,
                    "severity": "info",
                    "message": "Tool definitions are not sorted by name; deterministic ordering improves prefix reuse.",
                })
        for index, item in enumerate(value):
            warnings.extend(_walk_json(item, f"{path}[{index}]"))
    return warnings


def json_shape_warnings(text: str) -> tuple[str, list[dict[str, Any]]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return "text", []
    if not isinstance(data, (dict, list)):
        return "json-scalar", []
    warnings = _walk_json(data)
    canonical = json_bytes(data, indent=2) + "\n"
    if canonical != text:
        warnings.append({
            "code": "json_not_canonical",
            "path": "$",
            "severity": "info",
            "message": "JSON input is parseable but not canonical sort-key formatting; generated prompt JSON should be byte-stable.",
        })
    return "json", warnings


def build_amortization_report(
    *,
    eligible: bool,
    prefix_tokens: int,
    expected_reuses: int,
    cache_write_multiplier: float | None,
    cache_read_multiplier: float | None,
) -> dict[str, Any]:
    """Return advisory cache amortization math using user-supplied multipliers.

    ``expected_reuses`` means future cache reads after the initial cache write.
    Multipliers are relative to uncached prefix input cost = 1.0.  Provider
    pricing/cache policies change, so ContextGuard intentionally does not ship
    provider-specific multiplier defaults.
    """
    supplied = cache_write_multiplier is not None and cache_read_multiplier is not None
    break_even_reuses: int | None = None
    status = "multipliers_not_supplied"
    risk = "unknown"

    if not eligible:
        status = "not_cacheable"
        risk = "high"
    elif not supplied:
        status = "multipliers_not_supplied"
        risk = "unknown"
    elif cache_write_multiplier <= 1.0:
        break_even_reuses = 0
        status = "already_break_even_on_write"
        risk = "low"
    elif cache_read_multiplier >= 1.0:
        status = "no_read_discount"
        risk = "high"
    else:
        break_even_reuses = int(math.ceil((cache_write_multiplier - 1.0) / (1.0 - cache_read_multiplier)))
        if expected_reuses >= break_even_reuses:
            status = "amortizes_with_expected_reuses"
            risk = "low"
        elif expected_reuses > 0:
            status = "not_enough_expected_reuses"
            risk = "medium"
        else:
            status = "not_enough_expected_reuses"
            risk = "high"

    return {
        "expected_reuses": expected_reuses,
        "expected_reuses_semantics": "future_cache_reads_after_initial_write",
        "cacheable_prefix_tokens": prefix_tokens,
        "break_even_reuses": break_even_reuses,
        "status": status,
        "risk": risk,
        "cache_write_multiplier": cache_write_multiplier,
        "cache_read_multiplier": cache_read_multiplier,
        "multiplier_baseline": "uncached_prefix_input_cost_equals_1.0",
        "user_supplied_multipliers": supplied,
        "formula": "ceil((write_multiplier - 1.0) / (1.0 - read_multiplier)) when write>1 and read<1",
        "claim_boundary": {
            "advisory_only": True,
            "provider_pricing_defaults_included": False,
            "provider_measured_cache_hit": False,
            "hosted_api_token_or_cost_savings_claim_allowed": False,
            "requires_user_supplied_or_provider_documented_multipliers": True,
        },
    }


def score_prompt(
    text: str,
    *,
    provider: str,
    minimum_cacheable_tokens: int,
    expected_reuses: int = DEFAULT_EXPECTED_REUSES,
    cache_write_multiplier: float | None = None,
    cache_read_multiplier: float | None = None,
) -> dict[str, Any]:
    prompt_kind, shape_warnings = json_shape_warnings(text)
    dynamic_offset, dynamic_marker = first_dynamic_marker(text)
    prefix_text = text if dynamic_offset is None else text[:dynamic_offset]
    estimated = estimate_tokens(text)
    prefix_estimated = estimate_tokens(prefix_text)
    total_chars = len(text)
    static_ratio = 1.0 if total_chars == 0 else len(prefix_text) / total_chars
    warnings = list(shape_warnings)
    if dynamic_offset is not None:
        warnings.append({
            "code": "dynamic_marker_in_prompt",
            "severity": "warn",
            "message": "Dynamic-looking content appears before the end of the prompt; move timestamps/request IDs/user-specific values later.",
            "offset": dynamic_offset,
            "marker": dynamic_marker,
        })
    if prefix_estimated < minimum_cacheable_tokens:
        warnings.append({
            "code": "below_minimum_cacheable_tokens",
            "severity": "warn",
            "message": "Static prefix token proxy is below the selected provider threshold.",
        })
    if provider == "anthropic" and "cache_control" not in text:
        warnings.append({
            "code": "anthropic_cache_control_not_detected",
            "severity": "info",
            "message": "Anthropic caching usually requires cache_control around the reusable prefix.",
        })

    eligible = prefix_estimated >= minimum_cacheable_tokens
    return {
        "tool": TOOL_NAME,
        "schema_version": SCHEMA_VERSION,
        "provider": provider,
        "prompt_kind": prompt_kind,
        "minimum_cacheable_tokens": minimum_cacheable_tokens,
        "eligible": eligible,
        "estimated_tokens": estimated,
        "cacheable_prefix_tokens": prefix_estimated,
        "token_estimate": {
            "method": "char4_proxy",
            "chars_per_token": TOKEN_PROXY_CHARS_PER_TOKEN,
            "estimated_tokens": estimated,
            "cacheable_prefix_tokens": prefix_estimated,
            "label": "provider_tokenizer_free_proxy_not_billed_tokens",
        },
        "input_chars": total_chars,
        "cacheable_prefix_chars": len(prefix_text),
        "first_dynamic_offset": dynamic_offset,
        "first_dynamic_marker": dynamic_marker,
        "static_prefix_ratio": round(static_ratio, 6),
        "warnings": warnings,
        "provider_caveat": PROVIDER_CAVEATS[provider],
        "amortization": build_amortization_report(
            eligible=eligible,
            prefix_tokens=prefix_estimated,
            expected_reuses=expected_reuses,
            cache_write_multiplier=cache_write_multiplier,
            cache_read_multiplier=cache_read_multiplier,
        ),
        "raw_prompt_stored": False,
        "claim_boundary": {
            "advisory_only": True,
            "provider_measured_cache_hit": False,
            "hosted_api_token_or_cost_savings_claim_allowed": False,
            "requires_provider_usage_fields_for_claims": True,
            "token_estimate_is_provider_tokenizer_free_proxy": True,
        },
    }


def render_text(report: dict[str, Any]) -> str:
    status = "eligible" if report.get("eligible") else "not eligible"
    warnings = report.get("warnings") if isinstance(report.get("warnings"), list) else []
    warning_codes = ", ".join(str(item.get("code")) for item in warnings if isinstance(item, dict)) or "none"
    amortization = report.get("amortization") if isinstance(report.get("amortization"), dict) else {}
    return (
        f"{TOOL_NAME}: {status} for {report['provider']} "
        f"(static_prefix≈{report['cacheable_prefix_tokens']} char/4 tokens, "
        f"minimum={report['minimum_cacheable_tokens']})\n"
        f"warnings: {warning_codes}\n"
        f"amortization: {amortization.get('status', 'unknown')} "
        f"(risk={amortization.get('risk', 'unknown')}, "
        f"break_even_reuses={amortization.get('break_even_reuses')})\n"
        "claim boundary: advisory static lint only; not a measured provider cache hit or cost saving.\n"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Static prompt cacheability lint. No provider calls, no pricing ledger, "
            "and no measured cache-hit claims."
        )
    )
    parser.add_argument("--input", help="prompt/request text or JSON path; stdin is used when omitted")
    parser.add_argument("--provider", choices=sorted(PROVIDER_MINIMUM_CACHEABLE_TOKENS), default="generic")
    parser.add_argument(
        "--minimum-cacheable-tokens",
        default=None,
        help="override provider threshold for model/platform-specific cache minimums",
    )
    parser.add_argument("--max-input-bytes", default=DEFAULT_MAX_INPUT_BYTES, help=f"maximum input bytes (default: {DEFAULT_MAX_INPUT_BYTES})")
    parser.add_argument(
        "--expected-reuses",
        default=DEFAULT_EXPECTED_REUSES,
        help=(
            "future cache reads expected after the initial write; advisory only "
            f"(default: {DEFAULT_EXPECTED_REUSES})"
        ),
    )
    parser.add_argument(
        "--cache-write-multiplier",
        default=None,
        help="optional user-supplied cache write multiplier relative to uncached prefix input cost=1.0",
    )
    parser.add_argument(
        "--cache-read-multiplier",
        default=None,
        help="optional user-supplied cache read multiplier relative to uncached prefix input cost=1.0",
    )
    parser.add_argument("--json", action="store_true", help="emit stable JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        max_input_bytes = bounded_int(args.max_input_bytes, default=DEFAULT_MAX_INPUT_BYTES, minimum=1, maximum=100_000_000, name="--max-input-bytes")
        provider = str(args.provider)
        default_minimum = PROVIDER_MINIMUM_CACHEABLE_TOKENS[provider]
        minimum = bounded_int(
            args.minimum_cacheable_tokens,
            default=default_minimum,
            minimum=1,
            maximum=10_000_000,
            name="--minimum-cacheable-tokens",
        )
        expected_reuses = bounded_int(
            args.expected_reuses,
            default=DEFAULT_EXPECTED_REUSES,
            minimum=0,
            maximum=MAX_EXPECTED_REUSES,
            name="--expected-reuses",
        )
        cache_write_multiplier = bounded_float(
            args.cache_write_multiplier,
            minimum=0.0,
            maximum=MAX_CACHE_MULTIPLIER,
            name="--cache-write-multiplier",
        )
        cache_read_multiplier = bounded_float(
            args.cache_read_multiplier,
            minimum=0.0,
            maximum=MAX_CACHE_MULTIPLIER,
            name="--cache-read-multiplier",
        )
        text = read_limited_path(Path(args.input), max_input_bytes) if args.input else read_limited_stdin(max_input_bytes)
        report = score_prompt(
            text,
            provider=provider,
            minimum_cacheable_tokens=minimum,
            expected_reuses=expected_reuses,
            cache_write_multiplier=cache_write_multiplier,
            cache_read_multiplier=cache_read_multiplier,
        )
        if args.json:
            sys.stdout.write(json_bytes(report, indent=2) + "\n")
        else:
            sys.stdout.write(render_text(report))
        return 0
    except CacheScoreError as exc:
        print(f"{TOOL_NAME}: {exc}", file=sys.stderr)
        return 1
    except BrokenPipeError:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
