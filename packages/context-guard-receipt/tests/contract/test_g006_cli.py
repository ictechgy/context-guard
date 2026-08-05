from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
BOOTSTRAP = PYTHON_ROOT / "context_guard_receipt/bootstrap.py"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))

from context_guard_receipt.canonical import canonical_json_bytes, parse_canonical_json_bytes
from context_guard_receipt.tool_schemas import DESCRIPTOR_LIMITS


def b64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


def tool_descriptor(
    catalog: list[dict[str, object]],
    *,
    classifications: tuple[str, ...] | None = None,
    signals: tuple[tuple[str, ...], ...] | None = None,
    retain_count: int = 1,
) -> tuple[bytes, bytes]:
    payload = canonical_json_bytes(catalog)
    callers = classifications or tuple("eligible" for _item in catalog)
    item_signals = signals or tuple(() for _item in catalog)
    return (
        canonical_json_bytes(
            {
                "catalog_format": "anthropic_tools/v1",
                "items": [
                    {
                        "caller_classification": caller,
                        "detector_signals": list(item_signals[index]),
                        "priority": len(catalog) - index,
                        "required": False,
                    }
                    for index, caller in enumerate(callers)
                ],
                "payload_b64u": b64url(payload),
                "retain_count": retain_count,
                "schema_version": "contextguard-receipt-tool-schema-descriptor/v1",
            },
            limits=DESCRIPTOR_LIMITS,
        ),
        payload,
    )


def expansion_request(catalog_reference: object, item_reference: object = None) -> bytes:
    return canonical_json_bytes(
        {
            "catalog_reference": catalog_reference,
            "item_reference": item_reference,
            "schema_version": "contextguard-receipt-tool-schema-expansion-request/v1",
        },
        limits=DESCRIPTOR_LIMITS,
    )


def run_cli(*arguments: str, input_bytes: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    environment = {
        "LANG": "C",
        "PATH": os.defpath,
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    return subprocess.run(
        [
            str(Path(sys.executable).resolve()),
            "-I",
            "-S",
            "-B",
            str(BOOTSTRAP),
            "receipt",
            *arguments,
        ],
        cwd=PACKAGE_ROOT,
        env=environment,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def large_catalog(prefix: str = "") -> list[dict[str, object]]:
    return [
        {
            "description": (prefix + "inline") * 800,
            "input_schema": {"type": "object"},
            "name": prefix + "inline",
        },
        {
            "description": (prefix + "deferred") * 800,
            "input_schema": {"type": "object"},
            "name": prefix + "deferred",
        },
    ]


class G006CliTests(unittest.TestCase):
    def test_persisted_bundle_expands_exact_catalog_and_item_from_closed_requests(self) -> None:
        """Break caught: public G006 issuance cannot be expanded through its closed request."""

        catalog = large_catalog()
        descriptor, payload = tool_descriptor(catalog)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state = base / "private-state"
            root.mkdir(mode=0o700)
            assembled = run_cli(
                "assemble",
                "--kind",
                "tool-schemas",
                "--descriptor",
                "-",
                "--root",
                str(root),
                "--state-dir",
                str(state),
                "--persist",
                "--emit",
                "bytes",
                input_bytes=descriptor,
            )
            self.assertEqual(assembled.returncode, 0, assembled.stderr)
            bundle = parse_canonical_json_bytes(assembled.stdout)
            whole = run_cli(
                "expand",
                "tool-schema",
                "--request",
                "-",
                "--root",
                str(root),
                "--state-dir",
                str(state),
                "--emit",
                "bytes",
                input_bytes=expansion_request(bundle["catalog_reference"]),
            )
            selected = run_cli(
                "expand",
                "tool-schema",
                "--request",
                "-",
                "--root",
                str(root),
                "--state-dir",
                str(state),
                "--emit",
                "bytes",
                input_bytes=expansion_request(
                    bundle["catalog_reference"], bundle["deferred"][0]
                ),
            )
        self.assertEqual(whole.returncode, 0, whole.stderr)
        self.assertEqual(whole.stdout, payload)
        self.assertEqual(selected.returncode, 0, selected.stderr)
        self.assertEqual(selected.stdout, canonical_json_bytes(catalog[1])[:-1])

    def test_json_output_and_sidecar_publish_the_same_tool_schema_receipt(self) -> None:
        """Break caught: public G006 output omits or forks shifted-byte accounting."""

        descriptor, _payload = tool_descriptor(large_catalog())
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state = base / "private-state"
            receipt_path = base / "receipt.json"
            root.mkdir(mode=0o700)
            response = run_cli(
                "assemble",
                "--kind",
                "tool-schemas",
                "--descriptor",
                "-",
                "--root",
                str(root),
                "--state-dir",
                str(state),
                "--persist",
                "--emit",
                "json",
                "--receipt-out",
                str(receipt_path),
                input_bytes=descriptor,
            )
            self.assertEqual(response.returncode, 0, response.stderr)
            envelope = parse_canonical_json_bytes(response.stdout)
            sidecar = parse_canonical_json_bytes(receipt_path.read_bytes())

        self.assertEqual(envelope["receipt"], sidecar)
        self.assertEqual(sidecar["artifact_kind"], "tool_schema_receipt")
        self.assertGreater(sidecar["shifted_bytes"]["deferred_raw_bytes"], 0)
        artifact = parse_canonical_json_bytes(
            base64.urlsafe_b64decode(envelope["output_b64u"] + "===")
        )
        self.assertEqual(artifact["artifact_kind"], "tool_schema_bundle")

    def test_nonpersistent_tool_schema_assembly_is_exact_and_creates_no_state(self) -> None:
        """Break caught: no-state assembly emits an unusable bundle or creates storage."""

        descriptor, payload = tool_descriptor(large_catalog())
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            root.mkdir(mode=0o700)
            response = run_cli(
                "assemble",
                "--kind",
                "tool-schemas",
                "--descriptor",
                "-",
                "--root",
                str(root),
                "--emit",
                "bytes",
                input_bytes=descriptor,
            )
            self.assertEqual(response.returncode, 0, response.stderr)
            self.assertEqual(response.stdout, payload)
            self.assertEqual(list(base.iterdir()), [root])

    def test_secret_refusal_writes_no_payload_or_state(self) -> None:
        """Break caught: a secret catalog is reflected or storage is opened before refusal."""

        catalog = large_catalog()
        descriptor, payload = tool_descriptor(
            catalog, signals=((), ("secret",))
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state = base / "private-state"
            root.mkdir(mode=0o700)
            response = run_cli(
                "assemble",
                "--kind",
                "tool-schemas",
                "--descriptor",
                "-",
                "--root",
                str(root),
                "--state-dir",
                str(state),
                "--persist",
                input_bytes=descriptor,
            )
            self.assertEqual(response.returncode, 65)
            self.assertEqual(response.stdout, b"")
            self.assertFalse(state.exists())
            self.assertNotIn(payload, response.stderr)
            error = json.loads(response.stderr)
            self.assertEqual((error["status"], error["reason"]), ("refused", "secret"))

    def test_mixed_reference_and_malformed_request_fail_closed_without_reflection(self) -> None:
        """Break caught: expansion accepts confused authority or reflects malformed input."""

        hostile = "HOSTILE_REQUEST_/private/detail"
        first_descriptor, _first_payload = tool_descriptor(large_catalog("first_"))
        second_descriptor, _second_payload = tool_descriptor(large_catalog("second_"))
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state = base / "private-state"
            root.mkdir(mode=0o700)

            def issue(descriptor: bytes):
                response = run_cli(
                    "assemble",
                    "--kind",
                    "tool-schemas",
                    "--descriptor",
                    "-",
                    "--root",
                    str(root),
                    "--state-dir",
                    str(state),
                    "--persist",
                    input_bytes=descriptor,
                )
                self.assertEqual(response.returncode, 0, response.stderr)
                return parse_canonical_json_bytes(response.stdout)

            first = issue(first_descriptor)
            second = issue(second_descriptor)
            mixed = run_cli(
                "expand",
                "tool-schema",
                "--request",
                "-",
                "--root",
                str(root),
                "--state-dir",
                str(state),
                input_bytes=expansion_request(
                    first["catalog_reference"], second["deferred"][0]
                ),
            )
            malformed = run_cli(
                "expand",
                "tool-schema",
                "--request",
                "-",
                "--root",
                str(root),
                "--state-dir",
                str(state),
                input_bytes=canonical_json_bytes(
                    {
                        "catalog_reference": first["catalog_reference"],
                        "hostile_extra": hostile,
                        "item_reference": None,
                        "schema_version": "contextguard-receipt-tool-schema-expansion-request/v1",
                    },
                    limits=DESCRIPTOR_LIMITS,
                ),
            )
        for response in (mixed, malformed):
            self.assertEqual(response.returncode, 65)
            self.assertEqual(response.stdout, b"")
            self.assertNotIn(hostile.encode(), response.stderr)
            self.assertNotIn(b"first_deferred", response.stderr)
            self.assertNotIn(b"second_deferred", response.stderr)


if __name__ == "__main__":
    unittest.main()
