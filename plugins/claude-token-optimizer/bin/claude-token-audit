#!/usr/bin/env python3
"""Best-effort Claude Code transcript usage auditor.

Claude Code transcript schemas may change. This script scans JSONL objects for
common token/cost fields rather than relying on one exact schema. It reports
parse/read skips so totals are not mistaken for billing-authoritative data.
"""
from __future__ import annotations

import argparse
import json
import os
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

TOKEN_KEY_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("input", ("input_tokens",)),
    ("output", ("output_tokens",)),
    ("cache_creation", ("cache_creation_input_tokens", "cacheCreation")),
    ("cache_read", ("cache_read_input_tokens", "cacheRead")),
)
COST_KEYS = ("total_cost_usd", "cost_usd", "costUSD")
MODEL_KEYS = ("model", "model_id", "modelId")
QUERY_SOURCE_KEYS = ("query_source", "querySource")
MAX_ERROR_EXAMPLES = 20


@dataclass
class UsageSummary:
    files: int = 0
    records: int = 0
    skipped_files: int = 0
    skipped_records: int = 0
    parse_errors: list[str] = field(default_factory=list)
    tokens: Counter[str] = field(default_factory=Counter)
    cost_usd: float = 0.0
    by_model: dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))
    by_query_source: dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))

    @property
    def total_tokens(self) -> int:
        return sum(self.tokens.values())

    def note_error(self, message: str) -> None:
        if len(self.parse_errors) < MAX_ERROR_EXAMPLES:
            self.parse_errors.append(message)


def iter_jsonl_files(paths: Iterable[str]) -> Iterable[Path]:
    seen: set[Path] = set()
    for raw in paths:
        path = Path(raw).expanduser()
        candidates: Iterable[Path]
        if path.is_file() and path.suffix in {".jsonl", ".json"}:
            candidates = [path]
        elif path.is_dir():
            candidates = list(path.rglob("*.jsonl")) + list(path.rglob("*.json"))
        else:
            continue
        for candidate in candidates:
            resolved = candidate.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            yield candidate


def walk(obj: Any) -> Iterable[dict[str, Any]]:
    stack = [obj]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            yield current
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)


def first_string(obj: dict[str, Any], keys: Iterable[str]) -> str | None:
    for key in keys:
        val = obj.get(key)
        if isinstance(val, str):
            return val
        if isinstance(val, dict):
            nested = val.get("id") or val.get("name")
            if isinstance(nested, str):
                return nested
    return None


def add_token_groups(local_tokens: Counter[str], d: dict[str, Any]) -> None:
    for bucket, keys in TOKEN_KEY_GROUPS:
        for raw_key in keys:
            val = d.get(raw_key)
            if isinstance(val, bool):
                continue
            if isinstance(val, (int, float)):
                local_tokens[bucket] += int(val)
                break


def add_usage(summary: UsageSummary, root: Any) -> None:
    root_model = None
    root_query_source = None
    if isinstance(root, dict):
        root_model = first_string(root, MODEL_KEYS)
        root_query_source = first_string(root, QUERY_SOURCE_KEYS)

    for d in walk(root):
        local_tokens: Counter[str] = Counter()
        add_token_groups(local_tokens, d)

        # OpenTelemetry-style records sometimes use {name, value, attributes.type}.
        name = d.get("name") or d.get("metric")
        if name == "claude_code.token.usage":
            value = d.get("value")
            if value is None:
                value = d.get("sum")
            if value is None:
                value = d.get("count")
            attrs = d.get("attributes") or {}
            token_type = attrs.get("type", "unknown") if isinstance(attrs, dict) else "unknown"
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                local_tokens[str(token_type)] += int(value)

        if local_tokens:
            summary.tokens.update(local_tokens)
            model = first_string(d, MODEL_KEYS) or root_model or "unknown"
            query_source = first_string(d, QUERY_SOURCE_KEYS) or root_query_source or "unknown"
            summary.by_model[model].update(local_tokens)
            summary.by_query_source[query_source].update(local_tokens)

        for key in COST_KEYS:
            val = d.get(key)
            if isinstance(val, bool):
                continue
            if isinstance(val, (int, float)):
                summary.cost_usd += float(val)
                break


def scan(paths: list[str]) -> UsageSummary:
    summary = UsageSummary()
    for file in iter_jsonl_files(paths):
        summary.files += 1
        try:
            with file.open("r", encoding="utf-8", errors="replace") as f:
                for line_no, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError as exc:
                        summary.skipped_records += 1
                        summary.note_error(f"{file}:{line_no}: JSON parse error: {exc.msg}")
                        continue
                    summary.records += 1
                    add_usage(summary, obj)
        except OSError as exc:
            summary.skipped_files += 1
            summary.note_error(f"{file}: read error: {exc}")
            continue
    return summary


def print_counter(title: str, counter: Counter[str], top: int) -> None:
    print(f"\n{title}")
    for key, val in counter.most_common(top):
        print(f"  {key:24s} {val:12d}")


def summary_json(summary: UsageSummary) -> dict[str, Any]:
    return {
        "files": summary.files,
        "records": summary.records,
        "skipped_files": summary.skipped_files,
        "skipped_records": summary.skipped_records,
        "parse_errors": summary.parse_errors,
        "total_tokens": summary.total_tokens,
        "tokens": dict(summary.tokens),
        "cost_usd_observed": summary.cost_usd,
        "by_model": {k: dict(v) for k, v in summary.by_model.items()},
        "by_query_source": {k: dict(v) for k, v in summary.by_query_source.items()},
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", default=[os.path.expanduser("~/.claude/projects")])
    parser.add_argument("--top", type=int, default=15)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    summary = scan(args.paths)

    if args.json:
        print(json.dumps(summary_json(summary), indent=2, sort_keys=True))
        return 0

    print("Claude Code transcript usage audit")
    print(
        f"files_scanned={summary.files} records={summary.records} "
        f"skipped_files={summary.skipped_files} skipped_records={summary.skipped_records}"
    )
    print(f"observed_total_tokens={summary.total_tokens}")
    if summary.cost_usd:
        print(f"observed_cost_usd={summary.cost_usd:.4f}")
    if summary.parse_errors:
        print("\nWarnings")
        for warning in summary.parse_errors:
            print(f"  - {warning}")
    print_counter("Token buckets", summary.tokens, args.top)

    model_totals = Counter({model: sum(tokens.values()) for model, tokens in summary.by_model.items()})
    print_counter("By model", model_totals, args.top)

    source_totals = Counter({src: sum(tokens.values()) for src, tokens in summary.by_query_source.items()})
    print_counter("By query_source", source_totals, args.top)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
