"""Closed receipt-companion command grammar and local exact expansion."""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import BinaryIO

from . import runner
from .assembly import (
    DESCRIPTOR_LIMITS,
    AssemblyDisposition,
    AssemblyError,
    assemble_blueprint,
    assemble_evidence,
    assemble_evidence_pack,
)
from .canonical import (
    CanonicalJSONError,
    JSONLimits,
    canonical_json_bytes,
    parse_canonical_json_bytes,
)
from .cli_io import CliIOError, read_descriptor, write_receipt, write_stdout
from .contracts import (
    RESPONSE_SCHEMA_VERSION,
    canonical_json,
    evidence_boundary,
    response,
)
from .diagnostics import DiagnosticsError, analyze_request, parse_diagnostics_request
from .diagnostic_ledger import (
    DiagnosticLedger,
    DiagnosticLedgerError,
    DiagnosticLedgerErrorCode,
)
from .expansion import ExpansionDisposition, expand_capability
from .store import CapabilityStore, StoreError, StoreErrorCode
from .tool_schemas import (
    ToolSchemaDisposition,
    ToolSchemaError,
    ToolSchemaExpansionDisposition,
    assemble_tool_schemas,
    expand_tool_schema_catalog,
    expand_tool_schema_item,
)


HELP = """usage: context-guard-receipt <command>\n\nCommands:\n  inspect boundary\n  assemble --kind <kind> --descriptor <file|-> --root <absolute> [options]\n  run --escrow --root <absolute> --state-dir <absolute> [--timeout-seconds <positive-decimal> --max-channel-bytes <positive-decimal> --max-total-bytes <positive-decimal>] -- <absolute-command> [args...]\n  expand <handle> --root <absolute> --state-dir <absolute> [options]\n  expand tool-schema --request <file|-> --root <absolute> --state-dir <absolute> [options]\n  import merged-capture --spool <absolute> --transaction-id <64hex> --root <absolute> --state-dir <absolute> [--disclosure-days 7]\n  recover merged-capture --transaction-id <64hex> --root <absolute> --state-dir <absolute>\n  inspect merged-capture-import --root <absolute> --state-dir <absolute>\n  inspect diagnostics --input <file|-> [--state-scope durable --root <absolute> --state-dir <absolute>]\n  inspect firewall --input <file|->\n  inspect diagnostic-ledger --state-scope durable --root <absolute> --state-dir <absolute> [--limit <positive-decimal>]\n  inspect twin --experimental-twin --input <file|-> --root <absolute> --state-dir <absolute>\n  inspect twin --experimental-twin --root <absolute> --state-dir <absolute> [--limit <positive-decimal>]\n  inspect reference-expiry --experimental-reference-expiry --input <file|-> --root <absolute> --state-dir <absolute>\n  inspect reference-expiry --experimental-reference-expiry --root <absolute> --state-dir <absolute> [--limit <positive-decimal>]\n  inspect <receipt|lease|state> [options]\n\nEvidence, blueprint, and tool-schema assembly plus exact local expansion are available. Run is explicit local capture only. Merged-capture import accepts only a completed private canonical sanitized UTF-8 spool and applies a fixed seven-day reference deadline. Diagnostics, firewall findings, and the experimental twin are advisory and non-applying. Experimental reference expiry revokes only compact local references and retains artifacts. The companion is provider-free and makes no host-request, network, or token-saving claim. Remaining commands are inert.\n"""
MCP_HELP = """usage: context-guard-receipt-mcp --root <absolute-directory>\n\nRun the bounded local stdio MCP surface for one fixed repository root. Capabilities are process-local and expire when the process exits. No registration, provider, model, credential, or network access is performed.\n"""

ASSEMBLY_KINDS = frozenset({"evidence", "blueprint", "tool-schemas"})
TOOL_SCHEMA_EXPANSION_REQUEST_VERSION = (
    "contextguard-receipt-tool-schema-expansion-request/v1"
)
TOOL_SCHEMA_EXPANSION_REQUEST_LIMITS = JSONLimits(
    max_document_bytes=256 * 1024,
    max_depth=16,
    max_total_values=512,
    max_object_members=32,
    max_string_bytes=1024,
)
INSPECT_TARGETS = frozenset(
    {
        "receipt",
        "diagnostics",
        "firewall",
        "diagnostic-ledger",
        "twin",
        "reference-expiry",
        "merged-capture-import",
        "lease",
        "state",
    }
)
_RUN_MAX_TIMEOUT_SECONDS = 300
_RUN_MAX_CAPTURE_BYTES = 900_000
_TWIN_REQUEST_MAX_BYTES = 64 * 1024
_REFERENCE_EXPIRY_REQUEST_MAX_BYTES = 4096
_BASH_REFERENCE_BROKER_READY = (
    b"READY contextguard-bash-reference-broker/v1\n"
)
_BASH_REFERENCE_BROKER_FINAL_MAX_BYTES = 4096
_BASH_REFERENCE_QUERY_SCHEMA_VERSION = (
    "contextguard-receipt-bash-reference-query/v1"
)
_BASH_REFERENCE_QUERY_MAX_PAYLOAD_BYTES = 20_000
_BASH_REFERENCE_QUERY_MAX_RESPONSE_BYTES = 28_000
_BASH_REFERENCE_QUERY_JSON_LIMITS = JSONLimits(
    max_document_bytes=_BASH_REFERENCE_QUERY_MAX_RESPONSE_BYTES,
    max_depth=4,
    max_total_values=32,
    max_object_members=8,
    max_string_bytes=27_000,
)
_BASH_REFERENCE_STATE_DIRECTORY_PREFIX = ".context-guard-receipt-state-"
_BASH_REFERENCE_STATE_SELECTOR_DOMAIN = (
    b"contextguard/bash-reference-state-selector/v1\0"
)
_CAPABILITY_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def emit_error(operation: str, status: str, reason: str, code: int) -> int:
    print(canonical_json(response(operation=operation, status=status, reason=reason)), end="", file=sys.stderr)
    return code


def _is_absolute(value: str) -> bool:
    return (
        type(value) is str
        and bool(value)
        and "\x00" not in value
        and os.path.isabs(value)
        and os.path.normpath(value) == value
    )


def _is_file_argument(value: str) -> bool:
    return bool(value) and not value.startswith("--")


def _is_positive_integer(value: str) -> bool:
    try:
        return int(value, 10) > 0 and str(int(value, 10)) == value
    except ValueError:
        return False


def _is_capability_handle(value: object) -> bool:
    return bool(
        type(value) is str
        and len(value) == 49
        and value.startswith("cgr1p_")
        and all(character in _CAPABILITY_ALPHABET for character in value[6:])
    )


def _is_nonnegative_decimal(value: object) -> bool:
    return bool(
        type(value) is str
        and bool(value)
        and len(value) <= 20
        and (value == "0" or (value[0] in "123456789" and value.isascii() and value.isdecimal()))
    )


def _bash_reference_state_directory(repository_root: str) -> str | None:
    """Derive the private sibling used by the verified npm adapter."""

    if not _is_absolute(repository_root):
        return None
    root = Path(repository_root)
    try:
        if os.path.realpath(repository_root) != repository_root or root.is_symlink():
            return None
        status = root.lstat()
        if not root.is_dir():
            return None
    except OSError:
        return None
    selector = hashlib.sha256()
    selector.update(_BASH_REFERENCE_STATE_SELECTOR_DOMAIN)
    for field in (
        os.fsencode(repository_root),
        str(status.st_dev).encode("ascii"),
        str(status.st_ino).encode("ascii"),
    ):
        selector.update(len(field).to_bytes(8, "big"))
        selector.update(field)
    return str(
        root.parent
        / f"{_BASH_REFERENCE_STATE_DIRECTORY_PREFIX}{selector.hexdigest()}"
    )


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


def _parse_run_invocation(
    arguments: Sequence[str],
) -> tuple[dict[str, object], tuple[str, ...]] | None:
    try:
        separator = arguments.index("--")
    except ValueError:
        return None
    if separator + 1 >= len(arguments):
        return None
    command = tuple(arguments[separator + 1 :])
    if not _is_absolute(command[0]):
        return None
    seen = _parse_options(
        arguments[:separator],
        values={
            "--root": _is_absolute,
            "--state-dir": _is_absolute,
            "--timeout-seconds": _is_positive_integer,
            "--max-channel-bytes": _is_positive_integer,
            "--max-total-bytes": _is_positive_integer,
        },
        flags=frozenset({"--escrow"}),
    )
    required = {"--escrow", "--root", "--state-dir"}
    if seen is None or not required.issubset(seen):
        return None
    options = _option_values(
        arguments[:separator], flags=frozenset({"--escrow"})
    )
    timeout_seconds = int(str(options.get("--timeout-seconds", "30")), 10)
    total_bytes = int(
        str(options.get("--max-total-bytes", str(_RUN_MAX_CAPTURE_BYTES))), 10
    )
    channel_bytes = int(
        str(options.get("--max-channel-bytes", str(total_bytes))), 10
    )
    if (
        timeout_seconds > _RUN_MAX_TIMEOUT_SECONDS
        or channel_bytes > _RUN_MAX_CAPTURE_BYTES
        or total_bytes > _RUN_MAX_CAPTURE_BYTES
        or channel_bytes > total_bytes
    ):
        return None
    return options, command


def _valid_run(arguments: Sequence[str]) -> bool:
    return _parse_run_invocation(arguments) is not None


def _valid_expand(arguments: Sequence[str]) -> bool:
    if arguments and arguments[0] == "tool-schema":
        seen = _parse_options(
            arguments[1:],
            values={
                "--request": _is_file_argument,
                "--state-dir": _is_absolute,
                "--root": _is_absolute,
                "--emit": lambda value: value in {"bytes", "json"},
            },
        )
        return seen is not None and {
            "--request",
            "--root",
            "--state-dir",
        }.issubset(seen)
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


def _is_transaction_id(value: str) -> bool:
    return bool(
        len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _valid_import(arguments: Sequence[str]) -> bool:
    if not arguments or arguments[0] != "merged-capture":
        return False
    seen = _parse_options(
        arguments[1:],
        values={
            "--spool": _is_absolute,
            "--transaction-id": _is_transaction_id,
            "--root": _is_absolute,
            "--state-dir": _is_absolute,
            "--disclosure-days": lambda value: value == "7",
        },
    )
    return seen is not None and {
        "--spool",
        "--transaction-id",
        "--root",
        "--state-dir",
    }.issubset(seen)


def _valid_recover(arguments: Sequence[str]) -> bool:
    if not arguments or arguments[0] != "merged-capture":
        return False
    seen = _parse_options(
        arguments[1:],
        values={
            "--transaction-id": _is_transaction_id,
            "--root": _is_absolute,
            "--state-dir": _is_absolute,
        },
    )
    return seen == frozenset({"--transaction-id", "--root", "--state-dir"})


def _valid_inspect(arguments: Sequence[str]) -> bool:
    if not arguments or arguments[0] not in INSPECT_TARGETS:
        return False
    target = arguments[0]
    if target == "merged-capture-import":
        seen = _parse_options(
            arguments[1:],
            values={"--root": _is_absolute, "--state-dir": _is_absolute},
        )
        return seen == frozenset({"--root", "--state-dir"})
    if target == "firewall":
        seen = _parse_options(
            arguments[1:], values={"--input": _is_file_argument}
        )
        return seen == frozenset({"--input"})
    if target == "diagnostics":
        seen = _parse_options(
            arguments[1:],
            values={
                "--input": _is_file_argument,
                "--root": _is_absolute,
                "--state-dir": _is_absolute,
                "--state-scope": lambda value: value == "durable",
            },
        )
        return seen in {
            frozenset({"--input"}),
            frozenset({"--input", "--root", "--state-dir", "--state-scope"}),
        }
    if target == "diagnostic-ledger":
        seen = _parse_options(
            arguments[1:],
            values={
                "--limit": lambda value: _is_positive_integer(value)
                and int(value, 10) <= 256,
                "--root": _is_absolute,
                "--state-dir": _is_absolute,
                "--state-scope": lambda value: value == "durable",
            },
        )
        return seen in {
            frozenset({"--root", "--state-dir", "--state-scope"}),
            frozenset({"--limit", "--root", "--state-dir", "--state-scope"}),
        }
    if target == "twin":
        twin_arguments = tuple(arguments[1:])
        if not twin_arguments:
            return True
        if (
            len(twin_arguments) in {5, 7}
            and twin_arguments[0] == "--experimental-twin"
            and twin_arguments[1] == "--root"
            and _is_absolute(twin_arguments[2])
            and twin_arguments[3] == "--state-dir"
            and _is_absolute(twin_arguments[4])
        ):
            return len(twin_arguments) == 5 or (
                twin_arguments[5] == "--limit"
                and _is_positive_integer(twin_arguments[6])
                and int(twin_arguments[6], 10) <= 256
            )
        return (
            len(twin_arguments) == 7
            and twin_arguments[0] == "--experimental-twin"
            and twin_arguments[1] == "--input"
            and _is_file_argument(twin_arguments[2])
            and twin_arguments[3] == "--root"
            and _is_absolute(twin_arguments[4])
            and twin_arguments[5] == "--state-dir"
            and _is_absolute(twin_arguments[6])
        )
    if target == "reference-expiry":
        expiry_arguments = tuple(arguments[1:])
        if not expiry_arguments:
            return True
        if (
            len(expiry_arguments) in {5, 7}
            and expiry_arguments[0] == "--experimental-reference-expiry"
            and expiry_arguments[1] == "--root"
            and _is_absolute(expiry_arguments[2])
            and expiry_arguments[3] == "--state-dir"
            and _is_absolute(expiry_arguments[4])
        ):
            return len(expiry_arguments) == 5 or (
                expiry_arguments[5] == "--limit"
                and _is_positive_integer(expiry_arguments[6])
                and int(expiry_arguments[6], 10) <= 256
            )
        return (
            len(expiry_arguments) == 7
            and expiry_arguments[0] == "--experimental-reference-expiry"
            and expiry_arguments[1] == "--input"
            and _is_file_argument(expiry_arguments[2])
            and expiry_arguments[3] == "--root"
            and _is_absolute(expiry_arguments[4])
            and expiry_arguments[5] == "--state-dir"
            and _is_absolute(expiry_arguments[6])
        )
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
            try:
                artifact = store.resolve(
                    handle,
                    expected_root_identity_sha256=expected_root_identity_sha256,
                )
            except StoreError as error:
                if error.code is not StoreErrorCode.CAPABILITY_REJECTED:
                    raise
                artifact = None
            inaccessible = self._reference_is_inaccessible(store.namespace_id, handle)
            if artifact is None or inaccessible:
                raise StoreError(StoreErrorCode.CAPABILITY_REJECTED)
            return artifact

    def retrieve(
        self,
        handle: str,
        *,
        expected_namespace_id: str,
        expected_root_identity_sha256: str,
        expected_subject_identity_sha256: str,
        expected_artifact_type: object,
    ) -> object:
        with CapabilityStore.open(
            state_dir=self.state_dir,
            repository_root=self.repository_root,
            create=False,
        ) as store:
            try:
                artifact = store.retrieve(
                    handle,
                    expected_namespace_id=expected_namespace_id,
                    expected_root_identity_sha256=expected_root_identity_sha256,
                    expected_subject_identity_sha256=expected_subject_identity_sha256,
                    expected_artifact_type=expected_artifact_type,  # type: ignore[arg-type]
                )
            except StoreError as error:
                if error.code is not StoreErrorCode.CAPABILITY_REJECTED:
                    raise
                artifact = None
            inaccessible = self._reference_is_inaccessible(store.namespace_id, handle)
            if artifact is None or inaccessible:
                raise StoreError(StoreErrorCode.CAPABILITY_REJECTED)
            return artifact

    def _reference_is_inaccessible(self, namespace_id: str, handle: str) -> bool:
        try:
            from .reference_expiry import (
                ReferenceExpiryError,
                ReferenceExpiryErrorCode,
                ReferenceExpiryRegistry,
            )
        except ModuleNotFoundError as error:
            return error.name != "context_guard_receipt.reference_expiry"
        except Exception:
            return True
        try:
            with ReferenceExpiryRegistry.open(
                state_dir=self.state_dir,
                repository_root=self.repository_root,
                store_namespace_id=namespace_id,
                create=False,
            ) as registry:
                return registry.is_inaccessible(
                    handle, observed_at_unix_ms=time.time_ns() // 1_000_000
                )
        except ReferenceExpiryError as error:
            if error.code is ReferenceExpiryErrorCode.REGISTRY_UNINITIALIZED:
                return False
            return True
        except Exception:
            return True

    def is_reference_active(self, handle: str) -> bool:
        """Require a positive active registry record for merged imports only."""

        try:
            from .merged_capture import is_registered_reference

            return is_registered_reference(
                handle=handle,
                state_dir=self.state_dir,
                repository_root=self.repository_root,
                observed_at_unix_ms=time.time_ns() // 1_000_000,
            )
        except Exception:
            return False


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
    try:
        descriptor_raw = read_descriptor(descriptor_argument)
        store: object = None
        if options.get("--persist") is True:
            state_dir = options["--state-dir"]
            if type(state_dir) is not str:
                return emit_error("assemble", "error", "usage", 64)
            store = _LazyIssuanceStore(state_dir=state_dir, repository_root=root)

        if kind == "tool-schemas":
            result = assemble_tool_schemas(descriptor_raw, store=store)
        elif kind == "blueprint":
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
        refused = (
            result.disposition is ToolSchemaDisposition.REFUSED
            if kind == "tool-schemas"
            else result.disposition is AssemblyDisposition.REFUSED
        )
        if refused:
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
    except (AssemblyError, ToolSchemaError):
        return emit_error("assemble", "error", "invalid_descriptor", 65)
    except CliIOError as error:
        return emit_error("assemble", "error", error.code, 74)
    except Exception:
        return emit_error("assemble", "error", "internal_failure", 70)


def _expand(arguments: Sequence[str]) -> int:
    if arguments[0] == "tool-schema":
        return _expand_tool_schema(arguments[1:])
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


def _expand_tool_schema(arguments: Sequence[str]) -> int:
    options = _option_values(arguments, flags=frozenset())
    request_argument = options["--request"]
    root = options["--root"]
    state_dir = options["--state-dir"]
    emit = options.get("--emit", "bytes")
    if (
        type(request_argument) is not str
        or type(root) is not str
        or type(state_dir) is not str
        or type(emit) is not str
    ):
        return emit_error("expand_tool_schema", "error", "usage", 64)
    try:
        request_raw = read_descriptor(
            request_argument,
            maximum_bytes=TOOL_SCHEMA_EXPANSION_REQUEST_LIMITS.max_document_bytes,
        )
        try:
            request = parse_canonical_json_bytes(
                request_raw, limits=TOOL_SCHEMA_EXPANSION_REQUEST_LIMITS
            )
        except CanonicalJSONError:
            raise ToolSchemaError("invalid_descriptor") from None
        if (
            type(request) is not dict
            or frozenset(request)
            != frozenset(
                {"catalog_reference", "item_reference", "schema_version"}
            )
            or request["schema_version"] != TOOL_SCHEMA_EXPANSION_REQUEST_VERSION
            or type(request["catalog_reference"]) is not dict
            or (
                request["item_reference"] is not None
                and type(request["item_reference"]) is not dict
            )
        ):
            raise ToolSchemaError("invalid_descriptor")
        backend = _LazyResolutionStore(state_dir=state_dir, repository_root=root)
        if request["item_reference"] is None:
            result = expand_tool_schema_catalog(
                request["catalog_reference"], store=backend
            )
        else:
            result = expand_tool_schema_item(
                request["catalog_reference"],
                request["item_reference"],
                store=backend,
            )
        if result.disposition is not ToolSchemaExpansionDisposition.EXACT:
            refusal = result.refusal
            if type(refusal) is not dict:
                return emit_error(
                    "expand_tool_schema", "refused", "artifact_invalid", 65
                )
            print(canonical_json(refusal), end="", file=sys.stderr)
            return 65
        _emit_payload(
            result.output_bytes,
            operation="expand_tool_schema",
            emit=emit,
            receipt=None,
        )
        return 0
    except ToolSchemaError:
        return emit_error(
            "expand_tool_schema", "error", "invalid_descriptor", 65
        )
    except CliIOError as error:
        return emit_error("expand_tool_schema", "error", error.code, 74)
    except Exception:
        return emit_error(
            "expand_tool_schema", "error", "internal_failure", 70
        )


def _emit_run_failure(code: int) -> int:
    return emit_error("run", "error", "command_capture_failed", code)


def _run(arguments: Sequence[str]) -> int:
    invocation = _parse_run_invocation(arguments)
    if invocation is None:
        return emit_error("cli", "error", "usage", 64)
    options, command = invocation
    root = options["--root"]
    state_dir = options["--state-dir"]
    if type(root) is not str or type(state_dir) is not str:
        return emit_error("cli", "error", "usage", 64)

    timeout_seconds = int(str(options.get("--timeout-seconds", "30")), 10)
    total_bytes = int(
        str(options.get("--max-total-bytes", str(_RUN_MAX_CAPTURE_BYTES))), 10
    )
    channel_bytes = int(
        str(options.get("--max-channel-bytes", str(total_bytes))), 10
    )
    limits = runner.RunnerLimits(
        raw_per_channel_bytes=channel_bytes,
        raw_total_bytes=total_bytes,
        sanitized_per_channel_bytes=channel_bytes,
        sanitized_total_bytes=total_bytes,
        timeout_seconds=timeout_seconds,
    )

    def open_store() -> CapabilityStore:
        return CapabilityStore.open(
            state_dir=state_dir,
            repository_root=root,
            create=True,
        )

    try:
        result = runner.run_command(
            command,
            root,
            store_factory=open_store,
            limits=limits,
            private_roots=(root, state_dir),
        )
        exit_code = runner.map_cli_exit_code(result)
        if not result.succeeded:
            return _emit_run_failure(exit_code)
        receipt = result.to_receipt()
        if not runner.validate_command_capture_receipt(receipt):
            return _emit_run_failure(74)
        payload = canonical_json_bytes(receipt)
    except Exception:
        return _emit_run_failure(70)

    try:
        write_stdout(payload)
    except Exception:
        return _emit_run_failure(74)
    return exit_code


def _read_diagnostic_request(arguments: Sequence[str]):
    options = _option_values(arguments, flags=frozenset())
    try:
        raw = read_descriptor(str(options["--input"]))
    except KeyError:
        raise DiagnosticsError("invalid_request") from None
    return parse_diagnostics_request(raw)


def _write_diagnostic_payload(
    payload: dict[str, object], *, operation: str
) -> int:
    try:
        encoded = canonical_json_bytes(payload)
    except Exception:
        return emit_error(
            operation, "error", "diagnostic_internal_failure", 70
        )
    try:
        write_stdout(encoded)
    except Exception:
        return emit_error(
            operation, "error", "diagnostic_delivery_failed", 74
        )
    return 0


def _inspect_process_diagnostics(
    target: str, arguments: Sequence[str]
) -> int:
    operation = f"inspect_{target.replace('-', '_')}"
    try:
        request = _read_diagnostic_request(arguments)
    except CliIOError:
        return emit_error(
            operation, "error", "diagnostic_input_unavailable", 74
        )
    except DiagnosticsError:
        return emit_error(operation, "error", "diagnostic_input_rejected", 65)
    try:
        fingerprint_key = secrets.token_bytes(32)
        result = analyze_request(request, fingerprint_key=fingerprint_key)
        del fingerprint_key
        payload = (
            result.firewall_report()
            if target == "firewall"
            else result.report(state_scope="process")
        )
    except Exception:
        return emit_error(operation, "error", "diagnostic_internal_failure", 70)
    return _write_diagnostic_payload(payload, operation=operation)


def _inspect_durable_diagnostics(arguments: Sequence[str]) -> int:
    operation = "inspect_diagnostics"
    try:
        request = _read_diagnostic_request(arguments)
    except CliIOError:
        return emit_error(
            operation, "error", "diagnostic_input_unavailable", 74
        )
    except DiagnosticsError:
        return emit_error(operation, "error", "diagnostic_input_rejected", 65)
    options = _option_values(arguments, flags=frozenset())
    root = options.get("--root")
    state_dir = options.get("--state-dir")
    if type(root) is not str or type(state_dir) is not str:
        return emit_error("cli", "error", "usage", 64)
    try:
        with DiagnosticLedger.open(
            state_dir=state_dir, repository_root=root, create=True
        ) as ledger:
            fingerprint_key = ledger.fingerprint_key
            result = analyze_request(request, fingerprint_key=fingerprint_key)
            del fingerprint_key
            ledger.append(
                result.ledger_fields(),
                observed_at_unix_ms=time.time_ns() // 1_000_000,
            )
            payload = result.report(state_scope="durable")
    except DiagnosticLedgerError:
        return emit_error(
            operation, "error", "diagnostic_persistence_failed", 74
        )
    except Exception:
        return emit_error(operation, "error", "diagnostic_internal_failure", 70)
    return _write_diagnostic_payload(payload, operation=operation)


def _inspect_diagnostic_ledger(arguments: Sequence[str]) -> int:
    operation = "inspect_diagnostic_ledger"
    options = _option_values(arguments, flags=frozenset())
    root = options.get("--root")
    state_dir = options.get("--state-dir")
    limit_value = options.get("--limit", "256")
    if (
        type(root) is not str
        or type(state_dir) is not str
        or type(limit_value) is not str
    ):
        return emit_error("cli", "error", "usage", 64)
    try:
        with DiagnosticLedger.open(
            state_dir=state_dir, repository_root=root, create=False
        ) as ledger:
            payload = ledger.inspect(limit=int(limit_value, 10))
    except DiagnosticLedgerError as error:
        if error.code is DiagnosticLedgerErrorCode.LEDGER_UNINITIALIZED:
            return emit_error(
                operation, "unavailable", "diagnostic_ledger_uninitialized", 69
            )
        return emit_error(
            operation, "error", "diagnostic_ledger_unavailable", 74
        )
    except Exception:
        return emit_error(operation, "error", "diagnostic_internal_failure", 70)
    return _write_diagnostic_payload(payload, operation=operation)


def _write_twin_payload(payload: dict[str, object]) -> int:
    operation = "inspect_twin"
    try:
        encoded = canonical_json_bytes(payload)
    except Exception:
        return emit_error(operation, "error", "twin_internal_failure", 70)
    try:
        write_stdout(encoded)
    except Exception:
        return emit_error(operation, "error", "twin_delivery_failed", 74)
    return 0


def _inspect_twin(arguments: Sequence[str]) -> int:
    operation = "inspect_twin"
    append_mode = len(arguments) == 7 and arguments[1] == "--input"
    if append_mode:
        input_argument = arguments[2]
        root = arguments[4]
        state_dir = arguments[6]
    else:
        input_argument = None
        root = arguments[2]
        state_dir = arguments[4]
    try:
        from .execution_twin import (
            ExecutionTwin,
            ExecutionTwinError,
            parse_twin_request,
        )
    except Exception:
        return emit_error(operation, "error", "twin_internal_failure", 70)

    try:
        if append_mode:
            raw = read_descriptor(
                input_argument, maximum_bytes=_TWIN_REQUEST_MAX_BYTES
            )
            request = parse_twin_request(raw)
            with ExecutionTwin.open(
                state_dir=state_dir,
                repository_root=root,
                create=True,
            ) as twin:
                payload = twin.append(
                    request,
                    observed_at_unix_ms=time.time_ns() // 1_000_000,
                )
        else:
            limit = 256 if len(arguments) == 5 else int(arguments[6], 10)
            with ExecutionTwin.open(
                state_dir=state_dir,
                repository_root=root,
                create=False,
            ) as twin:
                payload = twin.inspect(limit=limit)
    except CliIOError:
        return emit_error(operation, "error", "twin_input_unavailable", 74)
    except ExecutionTwinError as error:
        code = getattr(error.code, "value", "")
        if code == "invalid_request":
            return emit_error(operation, "error", "twin_input_rejected", 65)
        if code == "twin_uninitialized":
            return emit_error(operation, "unavailable", "twin_uninitialized", 69)
        return emit_error(operation, "error", "twin_unavailable", 74)
    except Exception:
        return emit_error(operation, "error", "twin_internal_failure", 70)
    return _write_twin_payload(payload)


def _write_reference_expiry_payload(payload: dict[str, object]) -> int:
    operation = "inspect_reference_expiry"
    try:
        encoded = canonical_json_bytes(payload)
    except Exception:
        return emit_error(
            operation, "error", "reference_expiry_internal_failure", 70
        )
    try:
        write_stdout(encoded)
    except Exception:
        return emit_error(
            operation, "error", "reference_expiry_delivery_failed", 74
        )
    return 0


def _inspect_reference_expiry(arguments: Sequence[str]) -> int:
    operation = "inspect_reference_expiry"
    mutation_mode = len(arguments) == 7 and arguments[1] == "--input"
    if mutation_mode:
        input_argument = arguments[2]
        root = arguments[4]
        state_dir = arguments[6]
    else:
        input_argument = None
        root = arguments[2]
        state_dir = arguments[4]
    try:
        from .reference_expiry import (
            ReferenceExpiryError,
            ReferenceExpiryErrorCode,
            ReferenceExpiryRegistry,
            parse_reference_expiry_request,
        )
    except Exception:
        return emit_error(
            operation, "error", "reference_expiry_internal_failure", 70
        )

    try:
        request = None
        if mutation_mode:
            raw = read_descriptor(
                input_argument, maximum_bytes=_REFERENCE_EXPIRY_REQUEST_MAX_BYTES
            )
            request = parse_reference_expiry_request(raw)

        with CapabilityStore.open(
            state_dir=state_dir,
            repository_root=root,
            create=False,
        ) as store:
            namespace_id = store.namespace_id

        if request is None:
            limit = 256 if len(arguments) == 5 else int(arguments[6], 10)
            with ReferenceExpiryRegistry.open(
                state_dir=state_dir,
                repository_root=root,
                store_namespace_id=namespace_id,
                create=False,
            ) as registry:
                payload = registry.inspect(
                    observed_at_unix_ms=time.time_ns() // 1_000_000,
                    limit=limit,
                )
        else:
            create = request["operation"] == "register"
            with ReferenceExpiryRegistry.open(
                state_dir=state_dir,
                repository_root=root,
                store_namespace_id=namespace_id,
                create=create,
            ) as registry:
                observed_at = time.time_ns() // 1_000_000
                if request["operation"] == "register":
                    payload = registry.register(
                        request["capability"],
                        expires_at_unix_ms=request["expires_at_unix_ms"],
                        observed_at_unix_ms=observed_at,
                    )
                else:
                    payload = registry.revoke(
                        request["capability"],
                        expected_generation=request["expected_generation"],
                        observed_at_unix_ms=observed_at,
                    )
    except CliIOError:
        return emit_error(
            operation, "error", "reference_expiry_input_unavailable", 74
        )
    except (KeyError, TypeError):
        return emit_error(
            operation, "error", "reference_expiry_input_rejected", 65
        )
    except StoreError as error:
        if error.code is StoreErrorCode.CAPABILITY_REJECTED:
            return emit_error(
                operation, "error", "reference_expiry_input_rejected", 65
            )
        return emit_error(
            operation, "error", "reference_expiry_store_unavailable", 74
        )
    except ReferenceExpiryError as error:
        if error.code is ReferenceExpiryErrorCode.REGISTRY_UNINITIALIZED:
            return emit_error(
                operation, "unavailable", "reference_expiry_uninitialized", 69
            )
        if error.code in {
            ReferenceExpiryErrorCode.INVALID_REQUEST,
            ReferenceExpiryErrorCode.INVALID_ARGUMENT,
            ReferenceExpiryErrorCode.REFERENCE_ALREADY_REGISTERED,
            ReferenceExpiryErrorCode.REFERENCE_NOT_REGISTERED,
            ReferenceExpiryErrorCode.REFERENCE_INACCESSIBLE,
            ReferenceExpiryErrorCode.CAS_MISMATCH,
            ReferenceExpiryErrorCode.REFERENCE_COUNT_QUOTA_EXCEEDED,
            ReferenceExpiryErrorCode.RECORD_BYTES_QUOTA_EXCEEDED,
        }:
            return emit_error(
                operation, "error", "reference_expiry_input_rejected", 65
            )
        return emit_error(
            operation, "error", "reference_expiry_unavailable", 74
        )
    except Exception:
        return emit_error(
            operation, "error", "reference_expiry_internal_failure", 70
        )
    return _write_reference_expiry_payload(payload)


def _write_merged_import_result(result: dict[str, object]) -> int:
    import_result = {
        key: result[key]
        for key in (
            "actionable",
            "expires_at_unix_ms",
            "reason",
            "reference",
            "status",
            "transaction_id",
        )
    }
    envelope = {
        "evidence_boundary": evidence_boundary(),
        "import_result": import_result,
        "operation": "import_merged_capture",
        "schema_version": RESPONSE_SCHEMA_VERSION,
        "status": "ok",
    }
    try:
        write_stdout(canonical_json_bytes(envelope))
    except Exception:
        return emit_error(
            "import_merged_capture", "error", "delivery_failed", 74
        )
    return 0


def _run_bash_reference_broker(
    arguments: Sequence[str],
    *,
    capture_fd: int = 3,
    control: BinaryIO | None = None,
    output: BinaryIO | None = None,
) -> int:
    """Run the exact private, single-transaction descriptor protocol."""

    arguments = tuple(arguments)
    if (
        len(arguments) != 8
        or arguments[0] != "--transaction-id"
        or arguments[2] != "--root"
        or arguments[4] != "--state-dir"
        or arguments[6:] != ("--disclosure-days", "7")
    ):
        return 64
    transaction_id = arguments[1]
    repository_root = arguments[3]
    state_dir = arguments[5]
    control_stream = sys.stdin.buffer if control is None else control
    output_stream = sys.stdout.buffer if output is None else output
    try:
        # Importing this module eagerly loads the complete merged-capture store,
        # expiry, identity, canonicalization, and contract dependency graph.
        from .merged_capture import MergedCaptureError, prepare_broker

        prepared = prepare_broker(
            capture_fd=capture_fd,
            transaction_id=transaction_id,
            repository_root=repository_root,
            state_dir=state_dir,
            disclosure_days=7,
        )
    except Exception:
        return 74
    try:
        output_stream.write(_BASH_REFERENCE_BROKER_READY)
        output_stream.flush()
        command = control_stream.readline(8)
        if command not in {b"COMMIT\n", b"ABORT\n"}:
            return 65
        if control_stream.read(1) != b"":
            return 65
        if command == b"ABORT\n":
            return 0
        try:
            result = prepared.commit()
        except MergedCaptureError:
            return 74
        payload = b"FINAL " + canonical_json_bytes(result)
        if len(payload) > _BASH_REFERENCE_BROKER_FINAL_MAX_BYTES:
            return 74
        output_stream.write(payload)
        output_stream.flush()
        return 0
    except (OSError, ValueError):
        return 74
    finally:
        prepared.close()


def _run_bash_reference_query(arguments: Sequence[str]) -> int:
    """Return one exact bounded UTF-8 page for a live merged capability."""

    operation = "query_bash_reference"
    arguments = tuple(arguments)
    if (
        len(arguments) != 7
        or arguments[1] != "--root"
        or arguments[3] != "--state-dir"
        or arguments[5] != "--offset"
        or not _is_capability_handle(arguments[0])
        or not _is_nonnegative_decimal(arguments[6])
    ):
        return emit_error(operation, "error", "usage", 64)
    handle, repository_root, state_dir = arguments[0], arguments[2], arguments[4]
    expected_state_dir = _bash_reference_state_directory(repository_root)
    if (
        expected_state_dir is None
        or not _is_absolute(state_dir)
        or state_dir != expected_state_dir
    ):
        return emit_error(operation, "refused", "capability_rejected", 65)
    offset = int(arguments[6], 10)
    backend = _LazyResolutionStore(
        state_dir=state_dir,
        repository_root=repository_root,
    )
    try:
        result = expand_capability(
            handle,
            root=repository_root,
            store=backend,
        )
    except Exception:
        return emit_error(operation, "refused", "capability_rejected", 65)
    if (
        result.disposition is not ExpansionDisposition.EXACT
        or not backend.is_reference_active(handle)
    ):
        return emit_error(operation, "refused", "capability_rejected", 65)
    payload = result.output_bytes
    try:
        payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return emit_error(operation, "refused", "artifact_invalid", 65)
    total_bytes = len(payload)
    if (
        offset > total_bytes
        or (
            0 < offset < total_bytes
            and payload[offset] & 0xC0 == 0x80
        )
    ):
        return emit_error(operation, "refused", "offset_rejected", 65)
    next_offset = min(total_bytes, offset + _BASH_REFERENCE_QUERY_MAX_PAYLOAD_BYTES)
    while (
        next_offset > offset
        and next_offset < total_bytes
        and payload[next_offset] & 0xC0 == 0x80
    ):
        next_offset -= 1
    page = payload[offset:next_offset]
    response_payload = {
        "next_offset": next_offset,
        "offset": offset,
        "payload_b64u": base64.urlsafe_b64encode(page).rstrip(b"=").decode("ascii"),
        "request": {"offset": offset, "reference": handle},
        "schema_version": _BASH_REFERENCE_QUERY_SCHEMA_VERSION,
        "status": "exact",
        "total_bytes": total_bytes,
    }
    try:
        encoded = canonical_json_bytes(
            response_payload, limits=_BASH_REFERENCE_QUERY_JSON_LIMITS
        )
        if len(encoded) > _BASH_REFERENCE_QUERY_MAX_RESPONSE_BYTES:
            raise ValueError("reference response exceeds fixed bound")
        write_stdout(encoded)
    except Exception:
        return emit_error(operation, "error", "delivery_failed", 74)
    return 0


def _merged_import_error(
    error: object, *, operation: str = "import_merged_capture"
) -> int:
    code = getattr(getattr(error, "code", None), "value", "state_unavailable")
    refused = {
        "invalid_argument",
        "deadline_overflow",
        "unsafe_spool",
        "spool_too_large",
        "noncanonical_spool",
        "transaction_not_found",
        "transaction_abandoned",
        "transaction_conflict",
        "transaction_quota_exceeded",
        "pending_quota_exceeded",
        "pending_bytes_quota_exceeded",
        "artifact_missing",
        "artifact_invalid",
        "reference_inaccessible",
    }
    if code in refused:
        return emit_error(operation, "refused", code, 65)
    return emit_error(operation, "error", code, 74)


def _import_merged_capture(arguments: Sequence[str], *, recovery: bool) -> int:
    options = _option_values(arguments[1:], flags=frozenset())
    try:
        from .merged_capture import MergedCaptureError, publish, recover

        if recovery:
            result = recover(
                transaction_id=options["--transaction-id"],
                repository_root=options["--root"],
                state_dir=options["--state-dir"],
            )
        else:
            result = publish(
                spool_path=options["--spool"],
                transaction_id=options["--transaction-id"],
                repository_root=options["--root"],
                state_dir=options["--state-dir"],
                disclosure_days=int(str(options.get("--disclosure-days", "7")), 10),
            )
    except MergedCaptureError as error:
        return _merged_import_error(error)
    except Exception:
        return emit_error(
            "import_merged_capture", "error", "internal_failure", 70
        )
    return _write_merged_import_result(result)


def _inspect_merged_capture(arguments: Sequence[str]) -> int:
    options = _option_values(arguments[1:], flags=frozenset())
    try:
        from .merged_capture import MergedCaptureError, inspect

        result = inspect(
            repository_root=options["--root"], state_dir=options["--state-dir"]
        )
        write_stdout(canonical_json_bytes(result))
    except MergedCaptureError as error:
        return _merged_import_error(
            error, operation="inspect_merged_capture_import"
        )
    except Exception:
        return emit_error(
            "inspect_merged_capture_import", "error", "internal_failure", 70
        )
    return 0


def receipt_main(arguments: Sequence[str]) -> int:
    arguments = tuple(arguments)
    if arguments and arguments[0] == "--private-bash-reference-broker-v1":
        return _run_bash_reference_broker(arguments[1:])
    if arguments and arguments[0] == "--private-bash-reference-query-v1":
        return _run_bash_reference_query(arguments[1:])
    if arguments == ("--help",):
        print(HELP, end="")
        return 0
    if arguments == ("inspect", "boundary"):
        print(canonical_json(response(operation="inspect_boundary", status="ok")), end="")
        return 0
    if arguments and arguments[0] == "assemble" and _valid_assemble(arguments[1:]):
        return _assemble(arguments[1:])
    if arguments and arguments[0] == "run" and _valid_run(arguments[1:]):
        return _run(arguments[1:])
    if arguments and arguments[0] == "expand" and _valid_expand(arguments[1:]):
        return _expand(arguments[1:])
    if arguments and arguments[0] == "import" and _valid_import(arguments[1:]):
        return _import_merged_capture(arguments[1:], recovery=False)
    if arguments and arguments[0] == "recover" and _valid_recover(arguments[1:]):
        return _import_merged_capture(arguments[1:], recovery=True)
    if arguments and arguments[0] == "inspect" and _valid_inspect(arguments[1:]):
        if arguments[1] in {"diagnostics", "firewall"}:
            options = _option_values(arguments[2:], flags=frozenset())
            if "--state-scope" not in options:
                return _inspect_process_diagnostics(arguments[1], arguments[2:])
            return _inspect_durable_diagnostics(arguments[2:])
        if arguments[1] == "diagnostic-ledger":
            return _inspect_diagnostic_ledger(arguments[2:])
        if arguments[1] == "twin":
            if len(arguments) == 2:
                return emit_error(
                    "inspect_twin", "unavailable", "feature_not_available", 69
                )
            return _inspect_twin(arguments[2:])
        if arguments[1] == "reference-expiry":
            if len(arguments) == 2:
                return emit_error(
                    "inspect_reference_expiry",
                    "unavailable",
                    "feature_not_available",
                    69,
                )
            return _inspect_reference_expiry(arguments[2:])
        if arguments[1] == "merged-capture-import":
            return _inspect_merged_capture(arguments[1:])
        operation = f"inspect_{arguments[1].replace('-', '_')}"
        return emit_error(operation, "unavailable", "feature_not_available", 69)
    return emit_error("cli", "error", "usage", 64)


def mcp_main(arguments: Sequence[str]) -> int:
    arguments = tuple(arguments)
    if arguments == ("--help",):
        print(MCP_HELP, end="")
        return 0
    if len(arguments) == 2 and arguments[0] == "--root" and _is_absolute(arguments[1]):
        from .mcp import serve_stdio

        return serve_stdio(arguments[1])
    return emit_error("mcp", "error", "usage", 64)
