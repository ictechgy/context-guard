"""Closed receipt-companion command grammar and local exact expansion."""

from __future__ import annotations

import base64
import os
import sys
from collections.abc import Callable, Sequence

from .assembly import (
    DESCRIPTOR_LIMITS,
    AssemblyDisposition,
    AssemblyError,
    assemble_blueprint,
    assemble_evidence,
    assemble_evidence_pack,
)
from .canonical import CanonicalJSONError, canonical_json_bytes, parse_canonical_json_bytes
from .cli_io import CliIOError, read_descriptor, write_receipt, write_stdout
from .contracts import canonical_json, evidence_boundary, response
from .expansion import ExpansionDisposition, expand_capability
from .store import CapabilityStore


HELP = """usage: context-guard-receipt <command>\n\nCommands:\n  inspect boundary\n  assemble --kind <kind> --descriptor <file|-> --root <absolute> [options]\n  run --escrow --root <absolute> --state-dir <absolute> --receipt-out <file> -- <command>\n  expand <handle> --root <absolute> --state-dir <absolute> [options]\n  inspect <receipt|diagnostics|firewall|diagnostic-ledger|twin|lease|state> [options]\n\nEvidence/blueprint assembly and exact local expansion are available; other commands remain inert.\n"""
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
            "--receipt-out": _is_absolute,
        },
        flags=frozenset({"--persist"}),
    )
    return (
        seen is not None
        and {"--kind", "--descriptor", "--root"}.issubset(seen)
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
    return seen is not None and {"--root", "--state-dir"}.issubset(seen)


def _valid_inspect(arguments: Sequence[str]) -> bool:
    if not arguments or arguments[0] not in INSPECT_TARGETS:
        return False
    return _parse_options(
        arguments[1:],
        values={"--state-dir": _is_absolute, "--input": _is_file_argument},
    ) is not None


def _option_values(arguments: Sequence[str], *, flags: frozenset[str]) -> dict[str, object]:
    values: dict[str, object] = {}
    index = 0
    while index < len(arguments):
        option = arguments[index]
        if option in flags:
            values[option] = True
            index += 1
        else:
            values[option] = arguments[index + 1]
            index += 2
    return values


class _LazyIssuanceStore:
    """Delay all state creation until the core has passed every pre-store gate."""

    __slots__ = ("repository_root", "state_dir")

    def __init__(self, *, state_dir: str, repository_root: str) -> None:
        self.state_dir = state_dir
        self.repository_root = repository_root

    def issue_batch(self, requests: tuple[object, ...]) -> tuple[object, ...]:
        with CapabilityStore.open(
            state_dir=self.state_dir,
            repository_root=self.repository_root,
            create=True,
        ) as store:
            return store.issue_batch(requests)  # type: ignore[arg-type]


class _LazyResolutionStore:
    """Open an existing private store only for one closed capability lookup."""

    __slots__ = ("repository_root", "state_dir")

    def __init__(self, *, state_dir: str, repository_root: str) -> None:
        self.state_dir = state_dir
        self.repository_root = repository_root

    def resolve(self, handle: str, *, expected_root_identity_sha256: str) -> object:
        with CapabilityStore.open(
            state_dir=self.state_dir,
            repository_root=self.repository_root,
            create=False,
        ) as store:
            return store.resolve(
                handle,
                expected_root_identity_sha256=expected_root_identity_sha256,
            )


def _emit_payload(
    payload: bytes,
    *,
    operation: str,
    emit: str,
    receipt: dict[str, object] | None,
) -> None:
    if emit == "bytes":
        write_stdout(payload)
        return
    envelope = {
        "artifact_kind": "cli_output",
        "evidence_boundary": evidence_boundary(),
        "operation": operation,
        "output_b64u": base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii"),
        "receipt": receipt,
        "schema_version": "contextguard-receipt-cli-output/v1",
        "status": "ok",
    }
    write_stdout(canonical_json_bytes(envelope, limits=DESCRIPTOR_LIMITS))


def _assemble(arguments: Sequence[str]) -> int:
    options = _option_values(arguments, flags=frozenset({"--persist"}))
    kind = options["--kind"]
    descriptor_argument = options["--descriptor"]
    root = options["--root"]
    emit = options.get("--emit", "bytes")
    if type(kind) is not str or type(descriptor_argument) is not str or type(root) is not str:
        return emit_error("assemble", "error", "usage", 64)
    if type(emit) is not str:
        return emit_error("assemble", "error", "usage", 64)
    if kind == "tool-schemas":
        return emit_error("assemble", "unavailable", "feature_not_available", 69)
    try:
        descriptor_raw = read_descriptor(descriptor_argument)
        store: object = None
        if options.get("--persist") is True:
            state_dir = options["--state-dir"]
            if type(state_dir) is not str:
                return emit_error("assemble", "error", "usage", 64)
            store = _LazyIssuanceStore(state_dir=state_dir, repository_root=root)

        if kind == "blueprint":
            result = assemble_blueprint(descriptor_raw, root=root, store=store)
        else:
            try:
                document = parse_canonical_json_bytes(
                    descriptor_raw, limits=DESCRIPTOR_LIMITS
                )
            except CanonicalJSONError:
                raise AssemblyError("invalid_descriptor") from None
            version = document.get("schema_version") if type(document) is dict else None
            if version == "contextguard-receipt-evidence-pack-descriptor/v1":
                result = assemble_evidence_pack(descriptor_raw, root=root, store=store)
            else:
                result = assemble_evidence(descriptor_raw, root=root, store=store)

        receipt_path = options.get("--receipt-out")
        if receipt_path is not None and type(receipt_path) is not str:
            return emit_error("assemble", "error", "usage", 64)
        if result.disposition is AssemblyDisposition.REFUSED:
            if type(receipt_path) is str:
                write_receipt(receipt_path, canonical_json_bytes(result.receipt))
            reason = result.receipt.get("reason", "content_refused")
            if type(reason) is not str:
                reason = "content_refused"
            return emit_error("assemble", "refused", reason, 65)
        _emit_payload(
            result.output_bytes,
            operation="assemble",
            emit=emit,
            receipt=result.receipt,
        )
        if type(receipt_path) is str:
            try:
                write_receipt(receipt_path, canonical_json_bytes(result.receipt))
            except CliIOError as error:
                return emit_error("assemble", "error", error.code, 74)
        return 0
    except AssemblyError:
        return emit_error("assemble", "error", "invalid_descriptor", 65)
    except CliIOError as error:
        return emit_error("assemble", "error", error.code, 74)
    except Exception:
        return emit_error("assemble", "error", "internal_failure", 70)


def _expand(arguments: Sequence[str]) -> int:
    handle = arguments[0]
    options = _option_values(arguments[1:], flags=frozenset({"--require-current"}))
    root = options["--root"]
    state_dir = options["--state-dir"]
    emit = options.get("--emit", "bytes")
    if type(root) is not str or type(state_dir) is not str or type(emit) is not str:
        return emit_error("expand", "error", "usage", 64)
    try:
        result = expand_capability(
            handle,
            root=root,
            store=_LazyResolutionStore(state_dir=state_dir, repository_root=root),
        )
        if result.disposition is not ExpansionDisposition.EXACT:
            refusal = result.refusal
            if type(refusal) is not dict:
                return emit_error("expand", "refused", "artifact_invalid", 65)
            print(canonical_json(refusal), end="", file=sys.stderr)
            return 65
        _emit_payload(
            result.output_bytes,
            operation="expand",
            emit=emit,
            receipt=None,
        )
        return 0
    except CliIOError as error:
        return emit_error("expand", "error", error.code, 74)
    except Exception:
        return emit_error("expand", "error", "internal_failure", 70)


def receipt_main(arguments: Sequence[str]) -> int:
    arguments = tuple(arguments)
    if arguments == ("--help",):
        print(HELP, end="")
        return 0
    if arguments == ("inspect", "boundary"):
        print(canonical_json(response(operation="inspect_boundary", status="ok")), end="")
        return 0
    if arguments and arguments[0] == "assemble" and _valid_assemble(arguments[1:]):
        return _assemble(arguments[1:])
    if arguments and arguments[0] == "run" and _valid_run(arguments[1:]):
        return emit_error("run", "unavailable", "feature_not_available", 69)
    if arguments and arguments[0] == "expand" and _valid_expand(arguments[1:]):
        return _expand(arguments[1:])
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
