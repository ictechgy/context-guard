#!/usr/bin/env python3
"""Best-effort Claude Code transcript usage auditor.

Claude Code transcript schemas may change. This script scans JSONL objects for
common token/cost fields rather than relying on one exact schema. It reports
parse/read skips so totals are not mistaken for billing-authoritative data.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
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
SECRET_VALUE_RE = re.compile(
    r"(?i)(gh[pousr]_[A-Za-z0-9_]{8,}|xox[abprs]-[A-Za-z0-9-]{8,}|AKIA[0-9A-Z]{8,}|"
    r"AIza[0-9A-Za-z_\-]{8,}|Bearer\s+[A-Za-z0-9._~+/=-]+|"
    r"Basic\s+[A-Za-z0-9._~+/=-]+|"
    r"sk-ant-[A-Za-z0-9_-]{12,}|sk-[A-Za-z0-9_-]{12,}|glpat-[A-Za-z0-9_-]{12,}|"
    r"npm_[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|"
    r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@|"
    r"(?:--password|-p)\s+\S+|(?:-u|--user)\s+\S+:\S+|"
    r"(api[_-]?key|token|secret|password)=\S+)"
)
COMMAND_KEYS = ("command", "cmd")
TOOL_NAME_KEYS = ("tool_name", "toolName", "tool")


@dataclass
class RecordUsage:
    tokens: Counter[str] = field(default_factory=Counter)
    cost_usd: float = 0.0
    commands: set[str] = field(default_factory=set)
    tools: set[str] = field(default_factory=set)


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
    by_file: Counter[str] = field(default_factory=Counter)
    cost_by_file: Counter[str] = field(default_factory=Counter)
    by_command: Counter[str] = field(default_factory=Counter)
    by_tool: Counter[str] = field(default_factory=Counter)

    @property
    def total_tokens(self) -> int:
        return sum(self.tokens.values())

    @property
    def cache_hit_rate(self) -> float:
        """cache_read의 입력 측 비중 = cache_read / (input + cache_read + cache_creation).

        cache_creation이 분모에 포함되므로 신규 prefix를 막 만든 세션에서는 비율이 낮게
        나타날 수 있다. 고전적 hit-rate(cache 가능 풀 대비 hit)가 아니라 입력 비용 절감
        지표로 해석해야 한다. denom == 0이면 0.0.
        """
        cr = self.tokens.get("cache_read", 0)
        cc = self.tokens.get("cache_creation", 0)
        inp = self.tokens.get("input", 0)
        denom = cr + cc + inp
        return (cr / denom) if denom > 0 else 0.0

    @property
    def cache_amortization(self) -> float:
        """cache_read / cache_creation. 토큰 단위로 본 평균 재사용 배수의 근사.

        cache_creation == 0인 경우 의미가 정의되지 않으므로 0.0을 반환한다 (정의되지 않음을
        표현하기 위해 cache_amortization_defined 플래그를 함께 노출한다). 같은 prefix가
        길이 변화 없이 N회 재사용되면 토큰 비도 약 N배가 되지만, prefix 길이가 변하는
        세션에서는 정확히 호출 횟수가 아닌 토큰 비율로 본 근사값임에 주의.
        """
        cc = self.tokens.get("cache_creation", 0)
        cr = self.tokens.get("cache_read", 0)
        return (cr / cc) if cc > 0 else 0.0

    @property
    def cache_amortization_defined(self) -> bool:
        """cache_amortization이 의미를 갖는지 여부. cache_creation > 0일 때만 True."""
        return self.tokens.get("cache_creation", 0) > 0

    def note_error(self, message: str) -> None:
        if len(self.parse_errors) < MAX_ERROR_EXAMPLES:
            self.parse_errors.append(message)


def iter_jsonl_files(paths: Iterable[str]) -> Iterable[Path]:
    seen: set[Path] = set()
    for raw in paths:
        path = Path(raw).expanduser()
        root = path.resolve()
        candidates: Iterable[Path]
        if path.is_file() and path.suffix in {".jsonl", ".json"}:
            candidates = [path]
        elif path.is_dir():
            candidates = (
                candidate
                for pattern in ("*.jsonl", "*.json")
                for candidate in path.rglob(pattern)
            )
        else:
            continue
        for candidate in candidates:
            resolved = candidate.resolve()
            try:
                resolved.relative_to(root if path.is_dir() else root.parent)
            except ValueError:
                continue
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


def sanitize_label(value: str, limit: int = 120) -> str:
    compact = " ".join(value.strip().split())
    compact = SECRET_VALUE_RE.sub("[REDACTED]", compact)
    if len(compact) > limit:
        compact = compact[: limit - 15].rstrip() + " ...[truncated]"
    return compact


def stable_hash(value: str, length: int = 12) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:length]


def path_label(path: Path, show_paths: bool = False) -> str:
    if show_paths:
        return str(path)
    name = path.name or "transcript"
    return f"{name}#path:{stable_hash(str(path.resolve()))}"


def command_label(command: str, show_commands: bool = False) -> str:
    sanitized = sanitize_label(command)
    if show_commands:
        return sanitized
    try:
        argv = shlex.split(sanitized)
    except ValueError:
        argv = sanitized.split()
    if not argv:
        category = "command"
    elif len(argv) >= 3 and argv[0] in {"python", "python3"} and argv[1] == "-m":
        category = " ".join(argv[:3])
    elif len(argv) >= 2 and argv[0] in {"npm", "pnpm", "yarn", "bun"} and argv[1] in {"run", "run-script"}:
        category = " ".join(argv[:3]) if len(argv) >= 3 else " ".join(argv[:2])
    else:
        category = argv[0]
    return f"{category}#cmd:{stable_hash(sanitized)}"


def collect_record_hints(root: Any, show_commands: bool = False) -> tuple[set[str], set[str]]:
    commands: set[str] = set()
    tools: set[str] = set()
    for d in walk(root):
        for key in COMMAND_KEYS:
            value = d.get(key)
            if isinstance(value, str) and value.strip():
                commands.add(command_label(value, show_commands=show_commands))
        for key in TOOL_NAME_KEYS:
            value = d.get(key)
            if isinstance(value, str) and value.strip():
                name = sanitize_label(value, 80)
                if name and len(name.split()) <= 4:
                    tools.add(name)
    return commands, tools


def add_usage(
    summary: UsageSummary,
    root: Any,
    file: Path | None = None,
    show_paths: bool = False,
    show_commands: bool = False,
) -> RecordUsage:
    root_model = None
    root_query_source = None
    if isinstance(root, dict):
        root_model = first_string(root, MODEL_KEYS)
        root_query_source = first_string(root, QUERY_SOURCE_KEYS)

    record = RecordUsage()
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
            record.tokens.update(local_tokens)
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
                record.cost_usd += float(val)
                break
    commands, tools = collect_record_hints(root, show_commands=show_commands)
    record.commands = commands
    record.tools = tools
    record_total = sum(record.tokens.values())
    if file is not None and (record_total or record.cost_usd):
        file_key = path_label(file, show_paths=show_paths)
        summary.by_file[file_key] += record_total
        summary.cost_by_file[file_key] += record.cost_usd
    for command in commands:
        summary.by_command[command] += 1
    for tool in tools:
        summary.by_tool[tool] += 1
    return record


def scan(paths: list[str], show_paths: bool = False, show_commands: bool = False) -> UsageSummary:
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
                        summary.note_error(f"{path_label(file, show_paths=show_paths)}:{line_no}: JSON parse error: {exc.msg}")
                        continue
                    summary.records += 1
                    add_usage(summary, obj, file, show_paths=show_paths, show_commands=show_commands)
        except OSError as exc:
            summary.skipped_files += 1
            summary.note_error(f"{path_label(file, show_paths=show_paths)}: read error: {exc}")
            continue
    return summary


def print_counter(title: str, counter: Counter[str], top: int) -> None:
    print(f"\n{title}")
    for key, val in counter.most_common(top):
        print(f"  {key:24s} {val:12d}")


def counter_json(counter: Counter[str], top: int) -> list[dict[str, Any]]:
    return [{"name": key, "value": val} for key, val in counter.most_common(top)]


def recommendation(
    ident: str,
    title: str,
    reason: str,
    action: str,
    priority: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": ident,
        "priority": priority,
        "title": title,
        "reason": reason,
        "action": action,
        "evidence": evidence,
    }


def build_recommendations(summary: UsageSummary, top: int) -> list[dict[str, Any]]:
    recs: list[dict[str, Any]] = []
    total = max(0, summary.total_tokens)
    if total == 0:
        recs.append(recommendation(
            "no-usage-found",
            "No token usage found in scanned transcripts",
            "The scanner did not find recognizable Claude Code usage fields.",
            "Verify the transcript path or run again against ~/.claude/projects after more Claude Code activity.",
            "P2",
            {"files_scanned": summary.files, "records": summary.records},
        ))
        return recs

    output_tokens = summary.tokens.get("output", 0)
    input_tokens = summary.tokens.get("input", 0)
    cache_creation = summary.tokens.get("cache_creation", 0)
    cache_read = summary.tokens.get("cache_read", 0)
    output_ratio = output_tokens / total
    input_ratio = input_tokens / total
    if output_tokens >= 5_000 or output_ratio >= 0.35:
        recs.append(recommendation(
            "trim-output-heavy-sessions",
            "Output tokens are a major hotspot",
            f"Output accounts for {output_ratio:.0%} of observed tokens.",
            "Enable/keep Bash output trimming and add runner-aware failure extraction for repeated test/build commands.",
            "P0",
            {"output_tokens": output_tokens, "total_tokens": total},
        ))
    if input_tokens >= 5_000 or input_ratio >= 0.45:
        recs.append(recommendation(
            "reduce-large-reads",
            "Input tokens are a major hotspot",
            f"Input accounts for {input_ratio:.0%} of observed tokens.",
            "Prefer diff-first review, symbol-scoped reads, and large-file read guards before sending whole files to Claude.",
            "P0",
            {"input_tokens": input_tokens, "total_tokens": total},
        ))
    if (
        cache_creation >= 10_000
        and cache_read >= 1
        and summary.cache_amortization < 0.5
    ):
        recs.append(recommendation(
            "improve-prompt-cache-reuse",
            "Prompt cache reuse looks low",
            (
                f"Cache amortization is {summary.cache_amortization:.2f}x "
                f"(cache_read={cache_read}, cache_creation={cache_creation}); each cached prefix is barely re-served."
            ),
            "Keep stable instructions early, move volatile context later, and avoid editing large instruction files during active sessions.",
            "P1",
            {
                "cache_creation": cache_creation,
                "cache_read": cache_read,
                "cache_amortization": round(summary.cache_amortization, 4),
                "cache_hit_rate": round(summary.cache_hit_rate, 4),
            },
        ))
    if cache_creation >= 50_000 and 1.0 <= summary.cache_amortization < 5.0:
        recs.append(recommendation(
            "evaluate-1h-ttl-cache",
            "Cache writes are large; evaluate the 1h TTL cache beta",
            (
                f"Heuristic only — cache amortization {summary.cache_amortization:.2f}x with "
                f"{cache_creation} write tokens; absolute write cost is high and reuse is moderate. "
                "This metric does not inspect timestamps, so confirm reuse spans >5min in a sample "
                "session before enabling 1h TTL."
            ),
            (
                "If sessions reuse the same prefix beyond the 5-minute default TTL, evaluate the 1h prompt cache "
                "beta (write 2x, read 0.1x). It pays off when reuse spans the gap between two 5-min cache writes."
            ),
            "P2",
            {
                "cache_creation": cache_creation,
                "cache_read": cache_read,
                "cache_amortization": round(summary.cache_amortization, 4),
                "cache_hit_rate": round(summary.cache_hit_rate, 4),
                "heuristic": True,
            },
        ))

    for command, record_count in summary.by_command.most_common(top):
        lowered = command.lower()
        if any(marker in lowered for marker in ("pytest", "jest", "vitest", "go test", "cargo test", "npm test", "pnpm test", "yarn test")):
            recs.append(recommendation(
                "runner-aware-test-summary",
                "Test command appears in transcript records",
                "A test command category was observed in transcript records; token totals are session-level, not precise per-command billing.",
                "Route this command through runner-aware failure extraction so Claude sees failing test names, file:line, assertion text, and rerun commands only.",
                "P0",
                {"command_hint": command, "record_count": record_count},
            ))
            break

    top_files = summary.by_file.most_common(3)
    if top_files:
        largest_file, largest_tokens = top_files[0]
        if largest_tokens >= max(1_000, total * 0.25):
            recs.append(recommendation(
                "inspect-costliest-transcript",
                "One transcript file dominates observed usage",
                "A single transcript file accounts for a large share of observed tokens.",
                "Inspect this session first, then use /clear between unrelated tasks or /compact during long-running work.",
                "P1",
                {"file": largest_file, "tokens": largest_tokens, "share": round(largest_tokens / total, 3)},
            ))

    if summary.by_model:
        model_totals = Counter({model: sum(tokens.values()) for model, tokens in summary.by_model.items()})
        model, model_tokens = model_totals.most_common(1)[0]
        if model != "unknown" and model_tokens >= max(2_000, total * 0.5):
            recs.append(recommendation(
                "route-heavy-work-by-model",
                "One model carries most observed token usage",
                "A single model dominates the observed transcript tokens.",
                "Use lower-cost/auxiliary models for broad search, logs, and first-pass summaries; reserve Claude for final reasoning and edits.",
                "P1",
                {"model": model, "tokens": model_tokens, "share": round(model_tokens / total, 3)},
            ))

    if summary.skipped_files or summary.skipped_records:
        recs.append(recommendation(
            "fix-transcript-scan-gaps",
            "Some transcript data was skipped",
            "Skipped records can hide token hotspots and make recommendations less reliable.",
            "Review parse warnings and rerun with a narrower path if malformed or unrelated JSON files are mixed in.",
            "P2",
            {"skipped_files": summary.skipped_files, "skipped_records": summary.skipped_records},
        ))
    return recs


def summary_json(summary: UsageSummary, top: int = 15, include_recommendations: bool = False) -> dict[str, Any]:
    data = {
        "files": summary.files,
        "records": summary.records,
        "skipped_files": summary.skipped_files,
        "skipped_records": summary.skipped_records,
        "parse_errors": summary.parse_errors,
        "total_tokens": summary.total_tokens,
        "tokens": dict(summary.tokens),
        "cache_metrics": {
            "cache_hit_rate": round(summary.cache_hit_rate, 4),
            "cache_amortization": round(summary.cache_amortization, 4),
            "cache_amortization_defined": summary.cache_amortization_defined,
            "cache_read_tokens": summary.tokens.get("cache_read", 0),
            "cache_creation_tokens": summary.tokens.get("cache_creation", 0),
            "input_tokens": summary.tokens.get("input", 0),
        },
        "cost_usd_observed": summary.cost_usd,
        "by_model": {k: dict(v) for k, v in summary.by_model.items()},
        "by_query_source": {k: dict(v) for k, v in summary.by_query_source.items()},
        "top_files": counter_json(summary.by_file, top),
        "top_commands": counter_json(summary.by_command, top),
        "top_tools": counter_json(summary.by_tool, top),
    }
    if include_recommendations:
        data["recommendations"] = build_recommendations(summary, top)
    return data


def print_recommendations(summary: UsageSummary, top: int) -> None:
    print("\nRecommendations")
    for idx, rec in enumerate(build_recommendations(summary, top), 1):
        print(f"{idx}. [{rec['priority']}] {rec['title']}")
        print(f"   reason: {rec['reason']}")
        print(f"   action: {rec['action']}")
        if rec.get("evidence"):
            print(f"   evidence: {json.dumps(rec['evidence'], ensure_ascii=False, sort_keys=True)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", default=[os.path.expanduser("~/.claude/projects")])
    parser.add_argument("--top", type=int, default=15)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--recommend", action="store_true", help="Print concrete token-saving recommendations")
    parser.add_argument("--show-paths", action="store_true", help="Show raw transcript paths instead of basename+hash labels")
    parser.add_argument("--show-commands", action="store_true", help="Show redacted command strings instead of command category+hash labels")
    args = parser.parse_args()

    summary = scan(args.paths, show_paths=args.show_paths, show_commands=args.show_commands)

    if args.json:
        print(json.dumps(summary_json(summary, args.top, include_recommendations=args.recommend), indent=2, sort_keys=True))
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

    print("\nCache reuse")
    print(f"  cache_hit_rate           {summary.cache_hit_rate:.2%}")
    if summary.cache_amortization_defined:
        print(f"  cache_amortization       {summary.cache_amortization:.2f}x")
    else:
        print("  cache_amortization       n/a (no cache writes observed)")
    print(f"  cache_read_tokens        {summary.tokens.get('cache_read', 0):12d}")
    print(f"  cache_creation_tokens    {summary.tokens.get('cache_creation', 0):12d}")

    model_totals = Counter({model: sum(tokens.values()) for model, tokens in summary.by_model.items()})
    print_counter("By model", model_totals, args.top)

    source_totals = Counter({src: sum(tokens.values()) for src, tokens in summary.by_query_source.items()})
    print_counter("By query_source", source_totals, args.top)
    print_counter("Top transcript files", summary.by_file, args.top)
    print_counter("Top command hints observed", summary.by_command, args.top)
    print_counter("Top tools observed", summary.by_tool, args.top)
    if args.recommend:
        print_recommendations(summary, args.top)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
