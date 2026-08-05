"""Inert receipt-companion command grammar."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Sequence

from .contracts import EVIDENCE_BOUNDARY, canonical_json, response


HELP = """usage: context-guard-receipt <command>\n\nCommands:\n  inspect boundary\n  assemble --kind <kind> --descriptor <file|-> [options]\n  run --escrow --root <absolute> --state-dir <absolute> --receipt-out <file> -- <command>\n  expand <handle> --state-dir <absolute> [options]\n  inspect <receipt|diagnostics|firewall|diagnostic-ledger|twin|lease|state> [options]\n\nOnly inspect boundary is available in this release.\n"""
MCP_HELP = """usage: context-guard-receipt-mcp --root <absolute-directory>\n\nThe MCP transport is intentionally unavailable in this local-only companion.\n"""

ASSEMBLY_KINDS = frozenset({"evidence", "blueprint", "tool-schemas"})
INSPECT_TARGETS = frozenset(
    {"receipt", "diagnostics", "firewall", "diagnostic-ledger", "twin", "lease", "state"}
)


def emit_error(operation: str, status: str, reason: str, code: int) -> int:
    print(canonical_json(response(operation=operation, status=status, reason=reason)), end="", file=sys.stderr)
    return code


def _is_absolute(value: str) -> bool:
    return bool(value) and os.path.isabs(value)


def _is_file_argument(value: str) -> bool:
    return bool(value) and not value.startswith("--")


def _is_positive_integer(value: str) -> bool:
    try:
        return int(value, 10) > 0 and str(int(value, 10)) == value
    except ValueError:
        return False


def _parse_options(
    arguments: Sequence[str],
    *,
    values: dict[str, Callable[[str], bool]],
    flags: frozenset[str] = frozenset(),
) -> frozenset[str] | None:
    seen: set[str] = set()
    index = 0
    while index < len(arguments):
        option = arguments[index]
        if option in seen:
            return None
        if option in flags:
            seen.add(option)
            index += 1
            continue
        validator = values.get(option)
        if validator is None or index + 1 >= len(arguments):
            return None
        value = arguments[index + 1]
        if not validator(value):
            return None
        seen.add(option)
        index += 2
    return frozenset(seen)


def _valid_assemble(arguments: Sequence[str]) -> bool:
    seen = _parse_options(
        arguments,
        values={
            "--kind": lambda value: value in ASSEMBLY_KINDS,
            "--descriptor": _is_file_argument,
            "--root": _is_absolute,
            "--state-dir": _is_absolute,
            "--emit": lambda value: value in {"bytes", "json"},
            "--receipt-out": _is_file_argument,
        },
        flags=frozenset({"--persist"}),
    )
    return (
        seen is not None
        and {"--kind", "--descriptor"}.issubset(seen)
        and (("--persist" in seen) == ("--state-dir" in seen))
    )


def _valid_run(arguments: Sequence[str]) -> bool:
    try:
        separator = arguments.index("--")
    except ValueError:
        return False
    if separator + 1 >= len(arguments):
        return False
    command = arguments[separator + 1 :]
    if not command[0]:
        return False
    seen = _parse_options(
        arguments[:separator],
        values={
            "--root": _is_absolute,
            "--state-dir": _is_absolute,
            "--receipt-out": _is_file_argument,
            "--timeout-seconds": _is_positive_integer,
            "--max-channel-bytes": _is_positive_integer,
            "--max-total-bytes": _is_positive_integer,
        },
        flags=frozenset({"--escrow"}),
    )
    required = {"--escrow", "--root", "--state-dir", "--receipt-out"}
    return seen is not None and required.issubset(seen)


def _valid_expand(arguments: Sequence[str]) -> bool:
    if not arguments or not arguments[0].startswith("cgr1p_") or len(arguments[0]) <= len("cgr1p_"):
        return False
    seen = _parse_options(
        arguments[1:],
        values={
            "--state-dir": _is_absolute,
            "--root": _is_absolute,
            "--emit": lambda value: value in {"bytes", "json"},
        },
        flags=frozenset({"--require-current"}),
    )
    return seen is not None and "--state-dir" in seen


def _valid_inspect(arguments: Sequence[str]) -> bool:
    if not arguments or arguments[0] not in INSPECT_TARGETS:
        return False
    return _parse_options(
        arguments[1:],
        values={"--state-dir": _is_absolute, "--input": _is_file_argument},
    ) is not None


def receipt_main(arguments: Sequence[str]) -> int:
    arguments = tuple(arguments)
    if arguments == ("--help",):
        print(HELP, end="")
        return 0
    if arguments == ("inspect", "boundary"):
        print(canonical_json(response(operation="inspect_boundary", status="ok")), end="")
        return 0
    if arguments and arguments[0] == "assemble" and _valid_assemble(arguments[1:]):
        return emit_error("assemble", "unavailable", "feature_not_available", 69)
    if arguments and arguments[0] == "run" and _valid_run(arguments[1:]):
        return emit_error("run", "unavailable", "feature_not_available", 69)
    if arguments and arguments[0] == "expand" and _valid_expand(arguments[1:]):
        return emit_error("expand", "unavailable", "feature_not_available", 69)
    if arguments and arguments[0] == "inspect" and _valid_inspect(arguments[1:]):
        operation = f"inspect_{arguments[1].replace('-', '_')}"
        return emit_error(operation, "unavailable", "feature_not_available", 69)
    return emit_error("cli", "error", "usage", 64)


def mcp_main(arguments: Sequence[str]) -> int:
    arguments = tuple(arguments)
    if arguments == ("--help",):
        print(MCP_HELP, end="")
        return 0
    if len(arguments) == 2 and arguments[0] == "--root" and _is_absolute(arguments[1]):
        return emit_error("mcp", "unavailable", "feature_not_available", 69)
    return emit_error("mcp", "error", "usage", 64)
