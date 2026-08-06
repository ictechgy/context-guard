from __future__ import annotations

import importlib
import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from multiprocessing import get_context
from pathlib import Path
from unittest import mock
from urllib.parse import urljoin


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
ENTRY_SCHEMA_PATH = PACKAGE_ROOT / "schemas/diagnostic-ledger-entry.schema.json"
METADATA_SCHEMA_PATH = PACKAGE_ROOT / "schemas/diagnostic-ledger-metadata.schema.json"
INSPECTION_SCHEMA_PATH = PACKAGE_ROOT / "schemas/diagnostic-ledger-inspection.schema.json"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))


def ledger_module():
    try:
        return importlib.import_module("context_guard_receipt.diagnostic_ledger")
    except ModuleNotFoundError as error:
        raise AssertionError("G009 diagnostic ledger implementation is missing") from error


def valid_fields(**overrides: object) -> dict[str, object]:
    fields: dict[str, object] = {
        "advisory_lane": "surgeon",
        "advisory_only": True,
        "advisory_reason": "bounded_stable_benefit",
        "applied": False,
        "blueprint_bytes": 32,
        "current_prefix_bytes": 64,
        "current_prefix_hmac_sha256": "1" * 64,
        "current_reuse_basis_points": 10_000,
        "current_sample_bytes": 64,
        "current_truncated": False,
        "current_window_count": 1,
        "efficacy_claim_authority": False,
        "evidence_hmac_sha256": "2" * 64,
        "firewall_reason": "beneficial",
        "handle_bytes": 24,
        "input_bytes": 2_560,
        "live_observation_authority": False,
        "mandatory_expansion_bytes": 0,
        "matched_window_count": 1,
        "policy_sha256": "a6e00501858586d80afcd465c5a0fe65c85d2c6d74089cfe14bf347b670eb5cf",
        "predicted_cost_bytes": 120,
        "predicted_savings_bytes": 2_440,
        "previous_prefix_bytes": 64,
        "previous_prefix_hmac_sha256": "4" * 64,
        "previous_prefix_present": True,
        "previous_retention_basis_points": 10_000,
        "previous_sample_bytes": 64,
        "previous_truncated": False,
        "previous_window_count": 1,
        "provider_claim_authority": False,
        "provider_routing_authority": False,
        "retained_wire_bytes": 0,
        "rolling_status": "complete",
        "savings_basis_points": 9_531,
        "subject_kind": "evidence",
        "prefix_delta_bytes": 0,
        "would_block": False,
        "wrapper_bytes": 64,
    }
    fields.update(overrides)
    return fields


def auxiliary_metadata_bytes() -> bytes:
    value = {
        "evidence_boundary": {
            "evidence_class": "companion_local_receipt_only",
            "host_request_owned": False,
            "provider_claim_authority": False,
            "provider_join_status": "missing",
            "runtime_observer_present": False,
            "schema_version": "contextguard-receipt-evidence-boundary/v1",
            "selected_branch": "S2-UNSUPPORTED",
            "selected_transport": "NONE",
            "stage1_evidence": False,
            "stage2_evidence": False,
        },
        "schema_version": "contextguard-receipt-auxiliary-metadata/v1",
    }
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8") + b"\n"


def create_metadata_only_auxiliary(base: Path) -> tuple[Path, Path]:
    root = base / "repository"
    state_dir = base / "private-state"
    auxiliary = state_dir / "auxiliary-v1"
    root.mkdir(mode=0o700)
    state_dir.mkdir(mode=0o700)
    top_lock = state_dir / "lock"
    top_lock.write_bytes(b"")
    top_lock.chmod(0o600)
    auxiliary.mkdir(mode=0o700)
    metadata = auxiliary / "metadata.json"
    metadata.write_bytes(auxiliary_metadata_bytes())
    metadata.chmod(0o600)
    return root, state_dir


def append_in_process(arguments: tuple[str, str, int]) -> str:
    python_root, state_dir, observed_at = arguments
    if python_root not in sys.path:
        sys.path.insert(0, python_root)
    module = importlib.import_module("context_guard_receipt.diagnostic_ledger")
    root = str(Path(state_dir).parent / "repository")
    try:
        with module.DiagnosticLedger.open(
            state_dir=state_dir, repository_root=root
        ) as ledger:
            ledger.append(valid_fields(), observed_at_unix_ms=observed_at)
        return "appended"
    except module.DiagnosticLedgerError as error:
        return error.code.value


class LedgerFixture:
    def __init__(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary_directory.name).resolve()
        self.root = self.base / "repository"
        self.state_dir = self.base / "private-state"
        self.root.mkdir(mode=0o700)
        self.ledger = ledger_module().DiagnosticLedger.open(
            state_dir=str(self.state_dir),
            repository_root=str(self.root),
            create=True,
        )

    @property
    def diagnostic_dir(self) -> Path:
        return self.state_dir / "auxiliary-v1" / "diagnostics-v1"

    def close(self) -> None:
        self.ledger.close()
        self.temporary_directory.cleanup()

    def __enter__(self) -> "LedgerFixture":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class G009DiagnosticLedgerTests(unittest.TestCase):
    def assert_ledger_error(self, code: str, operation) -> None:
        module = ledger_module()
        with self.assertRaises(module.DiagnosticLedgerError) as caught:
            operation()
        self.assertEqual(caught.exception.code.value, code)

    def test_layout_restart_chain_and_bounded_inspection_are_exact(self) -> None:
        """Break caught: the diagnostic axis is coupled, ephemeral, unchained, or unbounded."""

        with LedgerFixture() as fixture:
            self.assertEqual(
                set(path.name for path in fixture.state_dir.iterdir()),
                {"lock", "auxiliary-v1"},
            )
            auxiliary = fixture.state_dir / "auxiliary-v1"
            self.assertEqual(
                set(path.name for path in auxiliary.iterdir()),
                {"metadata.json", "diagnostics-v1"},
            )
            self.assertEqual(
                set(path.name for path in fixture.diagnostic_dir.iterdir()),
                {"lock", "key", "metadata.json", "entries", "tmp"},
            )
            for directory in (
                fixture.state_dir,
                auxiliary,
                fixture.diagnostic_dir,
                fixture.diagnostic_dir / "entries",
                fixture.diagnostic_dir / "tmp",
            ):
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            for file_path in (
                fixture.state_dir / "lock",
                auxiliary / "metadata.json",
                fixture.diagnostic_dir / "lock",
                fixture.diagnostic_dir / "key",
                fixture.diagnostic_dir / "metadata.json",
            ):
                status = file_path.stat()
                self.assertEqual(stat.S_IMODE(status.st_mode), 0o600)
                self.assertEqual(status.st_nlink, 1)
            self.assertEqual((fixture.diagnostic_dir / "key").stat().st_size, 32)

            first = fixture.ledger.append(valid_fields(), observed_at_unix_ms=1_700_000_000_000)
            second = fixture.ledger.append(
                valid_fields(evidence_hmac_sha256="5" * 64),
                observed_at_unix_ms=1_700_000_000_001,
            )
            self.assertEqual((first["sequence"], second["sequence"]), (1, 2))
            self.assertEqual(second["previous_entry_hmac_sha256"], first["entry_hmac_sha256"])
            self.assertEqual(
                sorted(path.name for path in (fixture.diagnostic_dir / "entries").iterdir()),
                ["0000000000000001.json", "0000000000000002.json"],
            )
            fixture.ledger.close()
            fixture.ledger = ledger_module().DiagnosticLedger.open(
                state_dir=str(fixture.state_dir), repository_root=str(fixture.root)
            )
            inspection = fixture.ledger.inspect(limit=1)
            self.assertEqual(
                set(inspection),
                {
                    "entries",
                    "entry_count",
                    "evidence_boundary",
                    "recovery_required",
                    "schema_version",
                    "state_scope",
                    "total_canonical_bytes",
                },
            )
            self.assertEqual(inspection["entry_count"], 2)
            self.assertEqual(inspection["entries"], [second])
            self.assertFalse(inspection["recovery_required"])
            self.assertEqual(inspection["state_scope"], "durable")

    def test_uninitialized_read_and_invalid_paths_create_nothing_and_errors_are_closed(self) -> None:
        """Break caught: inspection implicitly creates state or reflects hostile paths."""

        module = ledger_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            root.mkdir(mode=0o700)
            state_dir = base / "not-created"
            self.assert_ledger_error(
                "ledger_uninitialized",
                lambda: module.DiagnosticLedger.open(
                    state_dir=str(state_dir), repository_root=str(root), create=False
                ),
            )
            self.assertFalse(state_dir.exists())
            for path, code in (
                ("relative-HOSTILE", "state_dir_not_absolute"),
                (str(base / "x/../HOSTILE"), "state_dir_not_normalized"),
                (str(root / "HOSTILE"), "state_dir_forbidden"),
            ):
                with self.subTest(code=code):
                    try:
                        module.DiagnosticLedger.open(
                            state_dir=path, repository_root=str(root), create=True
                        )
                    except module.DiagnosticLedgerError as error:
                        self.assertEqual(error.code.value, code)
                        self.assertNotIn("HOSTILE", str(error) + repr(error))
                    else:
                        self.fail("unsafe state path was accepted")

    def test_metadata_only_auxiliary_is_completed_only_by_create_true(self) -> None:
        """Break caught: a valid staged auxiliary root cannot complete its diagnostic axis."""

        module = ledger_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root, state_dir = create_metadata_only_auxiliary(base)
            auxiliary = state_dir / "auxiliary-v1"
            self.assert_ledger_error(
                "ledger_uninitialized",
                lambda: module.DiagnosticLedger.open(
                    state_dir=str(state_dir),
                    repository_root=str(root),
                    create=False,
                ),
            )
            self.assertEqual(
                set(path.name for path in auxiliary.iterdir()), {"metadata.json"}
            )

            with module.DiagnosticLedger.open(
                state_dir=str(state_dir),
                repository_root=str(root),
                create=True,
            ) as ledger:
                self.assertEqual(ledger.inspect(limit=1)["entry_count"], 0)
            self.assertEqual(
                set(path.name for path in auxiliary.iterdir()),
                {"metadata.json", "diagnostics-v1"},
            )

    def test_create_true_does_not_add_a_lock_to_hostile_existing_state(self) -> None:
        """Break caught: rejecting unknown topology still mutates caller state."""

        module = ledger_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state_dir = base / "private-state"
            root.mkdir(mode=0o700)
            state_dir.mkdir(mode=0o700)
            hostile = state_dir / "HOSTILE"
            hostile.write_bytes(b"x")
            hostile.chmod(0o600)
            self.assertEqual(set(path.name for path in state_dir.iterdir()), {"HOSTILE"})

            self.assert_ledger_error(
                "recovery_required",
                lambda: module.DiagnosticLedger.open(
                    state_dir=str(state_dir),
                    repository_root=str(root),
                    create=True,
                ),
            )
            self.assertEqual(set(path.name for path in state_dir.iterdir()), {"HOSTILE"})

    def test_lock_creation_race_preserves_residue_without_conditional_unlink(self) -> None:
        """Break caught: unsafe inode-check-then-unlink deletes a replacement file."""

        module = ledger_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state_dir = base / "private-state"
            root.mkdir(mode=0o700)
            state_dir.mkdir(mode=0o700)
            real_open_lock_at = module.DiagnosticLedger._open_lock_at

            def inject_hostile_before_lock(
                instance: object, parent_fd: int, name: str, *, create: bool
            ) -> tuple[int, bool]:
                if name == "lock":
                    hostile = state_dir / "HOSTILE"
                    hostile.write_bytes(b"x")
                    hostile.chmod(0o600)
                return real_open_lock_at(
                    instance, parent_fd, name, create=create
                )

            with mock.patch.object(
                module.DiagnosticLedger,
                "_open_lock_at",
                autospec=True,
                side_effect=inject_hostile_before_lock,
            ), mock.patch.object(
                module.os,
                "unlink",
                side_effect=AssertionError("conditional unlink is not portable"),
            ):
                self.assert_ledger_error(
                    "commit_uncertain",
                    lambda: module.DiagnosticLedger.open(
                        state_dir=str(state_dir),
                        repository_root=str(root),
                        create=True,
                    ),
                )
            self.assertEqual(
                set(path.name for path in state_dir.iterdir()), {"HOSTILE", "lock"}
            )

    def test_metadata_only_auxiliary_initialization_is_atomic_and_residue_is_preserved(self) -> None:
        """Break caught: staged diagnostics publish in place or erase failed initialization."""

        module = ledger_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root, state_dir = create_metadata_only_auxiliary(base)
            auxiliary = state_dir / "auxiliary-v1"
            real_rename = module.os.rename

            def fail_diagnostics_rename(source, destination, **kwargs) -> None:
                if destination == "diagnostics-v1":
                    raise OSError("HOSTILE-diagnostics-rename")
                real_rename(source, destination, **kwargs)

            with mock.patch.object(
                module, "_require_filesystem_features", return_value=None
            ), mock.patch.object(
                module.os, "rename", side_effect=fail_diagnostics_rename
            ):
                self.assert_ledger_error(
                    "write_failed",
                    lambda: module.DiagnosticLedger.open(
                        state_dir=str(state_dir),
                        repository_root=str(root),
                        create=True,
                    ),
                )
            names = {path.name for path in auxiliary.iterdir()}
            self.assertNotIn("diagnostics-v1", names)
            self.assertEqual(
                len(
                    [
                        name
                        for name in names
                        if re.fullmatch(r"\.diagnostics-v1\.tmp-[0-9a-f]{32}", name)
                    ]
                ),
                1,
            )
            self.assert_ledger_error(
                "recovery_required",
                lambda: module.DiagnosticLedger.open(
                    state_dir=str(state_dir),
                    repository_root=str(root),
                    create=True,
                ),
            )

    def test_auxiliary_unknown_or_internally_incomplete_state_is_never_repaired(self) -> None:
        """Break caught: create=True mutates an unrecognized or corrupt auxiliary tree."""

        module = ledger_module()
        for mutation in ("unknown", "incomplete-diagnostics"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                base = Path(directory).resolve()
                root, state_dir = create_metadata_only_auxiliary(base)
                auxiliary = state_dir / "auxiliary-v1"
                if mutation == "unknown":
                    hostile = auxiliary / "HOSTILE"
                    hostile.write_bytes(b"x")
                    hostile.chmod(0o600)
                else:
                    (auxiliary / "diagnostics-v1").mkdir(mode=0o700)
                self.assert_ledger_error(
                    "ledger_corrupt",
                    lambda: module.DiagnosticLedger.open(
                        state_dir=str(state_dir),
                        repository_root=str(root),
                        create=True,
                    ),
                )
                if mutation == "unknown":
                    self.assertFalse((auxiliary / "diagnostics-v1").exists())
                    self.assertTrue((auxiliary / "HOSTILE").exists())
                else:
                    self.assertEqual(list((auxiliary / "diagnostics-v1").iterdir()), [])

    def test_fingerprint_key_is_derived_independently_and_repr_hidden(self) -> None:
        """Break caught: a persisted master/store key is reused or exposed as fingerprint authority."""

        module = ledger_module()
        with LedgerFixture() as fixture:
            master_key = (fixture.diagnostic_dir / "key").read_bytes()
            fingerprint_key = fixture.ledger.fingerprint_key
            ledger_key = hmac.new(
                master_key,
                b"contextguard-receipt/diagnostic-ledger-mac-key/v1\0",
                hashlib.sha256,
            ).digest()
            self.assertEqual(len(fingerprint_key), 32)
            self.assertNotEqual(fingerprint_key, master_key)
            self.assertNotEqual(fingerprint_key, ledger_key)
            self.assertNotIn(master_key.hex(), repr(fixture.ledger))
            self.assertNotIn(fingerprint_key.hex(), repr(fixture.ledger))
            self.assertNotIn("fingerprint", json.dumps(fixture.ledger.inspect(limit=1)))
            fixture.ledger.close()
            fixture.ledger = module.DiagnosticLedger.open(
                state_dir=str(fixture.state_dir), repository_root=str(fixture.root)
            )
            self.assertEqual(fixture.ledger.fingerprint_key, fingerprint_key)

    def test_lock_creation_failure_closes_the_new_descriptor(self) -> None:
        """Break caught: a failed private-mode transition leaks lock authority."""

        if not Path("/dev/fd").is_dir():
            self.skipTest("descriptor inventory is unavailable")
        module = ledger_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state_dir = base / "private-state"
            root.mkdir(mode=0o700)
            before = len(os.listdir("/dev/fd"))
            real_fchmod = module.os.fchmod

            def fail_regular_file(descriptor: int, mode: int) -> None:
                if stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise OSError("HOSTILE-lock-chmod")
                real_fchmod(descriptor, mode)

            with mock.patch.object(module.os, "fchmod", side_effect=fail_regular_file):
                self.assert_ledger_error(
                    "write_failed",
                    lambda: module.DiagnosticLedger.open(
                        state_dir=str(state_dir),
                        repository_root=str(root),
                        create=True,
                    ),
                )
            self.assertEqual(len(os.listdir("/dev/fd")), before)

    def test_append_rejects_unknown_sensitive_nested_null_and_bool_as_int_fields(self) -> None:
        """Break caught: arbitrary diagnostics or Python coercions enter durable state."""

        with LedgerFixture() as fixture:
            cases = (
                ({**valid_fields(), "path": "/HOSTILE/private"}, "invalid_argument"),
                ({**valid_fields(), "metadata": "HOSTILE"}, "invalid_argument"),
                ({**valid_fields(), "unknown_key": 1}, "invalid_argument"),
                (valid_fields(input_bytes={"nested": True}), "invalid_argument"),
                (valid_fields(input_bytes=[1]), "invalid_argument"),
                (valid_fields(input_bytes=None), "invalid_argument"),
                (valid_fields(input_bytes=True), "invalid_argument"),
                (valid_fields(handle_bytes=True), "invalid_argument"),
            )
            for fields, code in cases:
                with self.subTest(field_names=sorted(fields)):
                    self.assert_ledger_error(
                        code,
                        lambda fields=fields: fixture.ledger.append(
                            fields, observed_at_unix_ms=1
                        ),
                    )
            self.assertEqual(fixture.ledger.inspect(limit=1)["entry_count"], 0)

    def test_append_enforces_closed_enums_bounds_authorities_and_semantics(self) -> None:
        """Break caught: a plausible-looking row widens claim authority or contradicts itself."""

        with LedgerFixture() as fixture:
            invalid_fields = (
                valid_fields(advisory_lane="operator"),
                valid_fields(advisory_reason="free text"),
                valid_fields(firewall_reason="maybe"),
                valid_fields(rolling_status="streaming"),
                valid_fields(subject_kind="prompt"),
                valid_fields(applied=True),
                valid_fields(advisory_only=False),
                valid_fields(provider_claim_authority=True),
                valid_fields(provider_routing_authority=True),
                valid_fields(live_observation_authority=True),
                valid_fields(efficacy_claim_authority=True),
                valid_fields(input_bytes=900_001),
                valid_fields(prefix_delta_bytes=-900_001),
                valid_fields(predicted_savings_bytes=900_001),
                valid_fields(savings_basis_points=10_001),
                valid_fields(current_reuse_basis_points=-1),
                valid_fields(current_sample_bytes=65_537),
                valid_fields(current_window_count=1_025),
                valid_fields(policy_sha256="A" * 64),
                valid_fields(current_sample_bytes=63),
                valid_fields(current_prefix_bytes=65_537, current_sample_bytes=65_536, current_truncated=False),
                valid_fields(matched_window_count=2),
                valid_fields(previous_prefix_present=False),
                valid_fields(would_block=True),
                valid_fields(advisory_lane="surgeon", advisory_reason="prefix_churn_high"),
            )
            for fields in invalid_fields:
                with self.subTest(fields=fields):
                    self.assert_ledger_error(
                        "invalid_argument",
                        lambda fields=fields: fixture.ledger.append(
                            fields, observed_at_unix_ms=1
                        ),
                    )

    def test_advisory_lane_reason_and_surgeon_preconditions_are_closed(self) -> None:
        """Break caught: durable rows claim a diagnostics state the runtime cannot produce."""

        invalid_fields = (
            valid_fields(advisory_lane="scout", advisory_reason="bounded_stable_benefit"),
            valid_fields(advisory_lane="none", advisory_reason="prefix_churn_high"),
            valid_fields(
                advisory_lane="none",
                advisory_reason="protection_refused",
                firewall_reason="beneficial",
            ),
            valid_fields(
                advisory_lane="none",
                advisory_reason="exact_path_required",
                firewall_reason="secret",
                would_block=True,
            ),
            valid_fields(
                advisory_lane="scout",
                advisory_reason="input_too_small",
                firewall_reason="savings_too_small",
                would_block=True,
            ),
            valid_fields(
                advisory_lane="scout",
                advisory_reason="prior_prefix_missing",
                firewall_reason="input_too_small",
                would_block=True,
            ),
            valid_fields(
                advisory_lane="surgeon",
                advisory_reason="bounded_stable_benefit",
                firewall_reason="input_too_small",
                would_block=True,
            ),
            valid_fields(
                current_prefix_bytes=65_537,
                current_sample_bytes=65_536,
                current_truncated=True,
                current_window_count=1_024,
                matched_window_count=1_024,
                previous_prefix_bytes=65_537,
                previous_sample_bytes=65_536,
                previous_truncated=True,
                previous_window_count=1_024,
                rolling_status="partial",
            ),
            valid_fields(
                current_prefix_bytes=63,
                current_sample_bytes=63,
                previous_prefix_bytes=63,
                previous_sample_bytes=63,
            ),
            valid_fields(
                current_prefix_bytes=65,
                current_reuse_basis_points=5_000,
                current_sample_bytes=65,
                current_window_count=2,
                matched_window_count=1,
                prefix_delta_bytes=1,
            ),
            valid_fields(
                matched_window_count=1,
                prefix_delta_bytes=-1,
                previous_prefix_bytes=65,
                previous_retention_basis_points=5_000,
                previous_sample_bytes=65,
                previous_window_count=2,
            ),
        )
        with LedgerFixture() as fixture:
            for fields in invalid_fields:
                with self.subTest(
                    lane=fields["advisory_lane"], reason=fields["advisory_reason"]
                ):
                    self.assert_ledger_error(
                        "invalid_argument",
                        lambda fields=fields: fixture.ledger.append(
                            fields, observed_at_unix_ms=1
                        ),
                    )

    def test_derived_cost_policy_route_and_prefix_advice_are_recomputed(self) -> None:
        """Break caught: a caller obtains a MAC over a row diagnostics cannot emit."""

        impossible_rows = (
            valid_fields(blueprint_bytes=33),
            valid_fields(policy_sha256="f" * 64),
            valid_fields(
                advisory_lane="scout",
                advisory_reason="input_too_small",
                firewall_reason="input_too_small",
                would_block=True,
            ),
            valid_fields(
                advisory_lane="scout",
                advisory_reason="prefix_evidence_empty",
            ),
            valid_fields(
                advisory_lane="scout",
                advisory_reason="prior_prefix_missing",
            ),
            valid_fields(
                advisory_lane="scout",
                advisory_reason="rolling_sample_partial",
            ),
            valid_fields(
                advisory_lane="scout",
                advisory_reason="prefix_churn_high",
            ),
        )
        with LedgerFixture() as fixture:
            for fields in impossible_rows:
                with self.subTest(fields=fields):
                    self.assert_ledger_error(
                        "invalid_argument",
                        lambda fields=fields: fixture.ledger.append(
                            fields, observed_at_unix_ms=1
                        ),
                    )
            self.assertEqual(fixture.ledger.inspect(limit=1)["entry_count"], 0)
            for timestamp in (-1, 4_102_444_800_001, True):
                with self.subTest(timestamp=timestamp):
                    self.assert_ledger_error(
                        "invalid_argument",
                        lambda timestamp=timestamp: fixture.ledger.append(
                            valid_fields(), observed_at_unix_ms=timestamp
                        ),
                    )

    def test_absent_previous_prefix_zero_state_is_accepted(self) -> None:
        """Break caught: the unavailable rolling state cannot be recorded consistently."""

        with LedgerFixture() as fixture:
            row = fixture.ledger.append(
                valid_fields(
                    advisory_lane="scout",
                    advisory_reason="prior_prefix_missing",
                    current_reuse_basis_points=0,
                    matched_window_count=0,
                    previous_prefix_bytes=0,
                    previous_prefix_hmac_sha256="0" * 64,
                    previous_prefix_present=False,
                    previous_retention_basis_points=0,
                    previous_sample_bytes=0,
                    previous_truncated=False,
                    previous_window_count=0,
                    rolling_status="unavailable",
                ),
                observed_at_unix_ms=0,
            )
            self.assertEqual(row["rolling_status"], "unavailable")

    def test_partial_prefix_window_is_counted_and_authenticated(self) -> None:
        """Break caught: a trailing partial window is dropped by ledger semantics."""

        with LedgerFixture() as fixture:
            row = fixture.ledger.append(
                valid_fields(
                    current_prefix_bytes=65,
                    current_sample_bytes=65,
                    current_window_count=2,
                    matched_window_count=2,
                    previous_prefix_bytes=65,
                    previous_sample_bytes=65,
                    previous_window_count=2,
                ),
                observed_at_unix_ms=1,
            )

            self.assertEqual(row["current_window_count"], 2)
            self.assertEqual(row["previous_window_count"], 2)

    def test_tmp_residue_is_reported_and_blocks_append_without_deletion(self) -> None:
        """Break caught: a prepublication residue is silently deleted or overwritten."""

        with LedgerFixture() as fixture:
            residue = fixture.diagnostic_dir / "tmp" / "0123456789abcdef0123456789abcdef.json"
            residue.write_bytes(b"incomplete")
            residue.chmod(0o600)
            self.assertTrue(fixture.ledger.inspect(limit=1)["recovery_required"])
            self.assert_ledger_error(
                "recovery_required",
                lambda: fixture.ledger.append(valid_fields(), observed_at_unix_ms=1),
            )
            self.assertTrue(residue.exists())

    def test_scan_rejects_gap_reorder_tamper_unknown_names_modes_links_and_symlinks(self) -> None:
        """Break caught: committed history can be removed, rebound, or modified undetected."""

        mutations = ("gap", "tamper", "unknown", "mode", "hardlink", "symlink")
        for mutation in mutations:
            with self.subTest(mutation=mutation), LedgerFixture() as fixture:
                fixture.ledger.append(valid_fields(), observed_at_unix_ms=1)
                fixture.ledger.append(
                    valid_fields(evidence_hmac_sha256="5" * 64), observed_at_unix_ms=2
                )
                entries = fixture.diagnostic_dir / "entries"
                first = entries / "0000000000000001.json"
                second = entries / "0000000000000002.json"
                expected = "ledger_tampered"
                if mutation == "gap":
                    first.unlink()
                elif mutation == "tamper":
                    row = json.loads(first.read_text(encoding="utf-8"))
                    row["input_bytes"] += 1
                    first.write_bytes(
                        json.dumps(
                            row,
                            ensure_ascii=False,
                            separators=(",", ":"),
                            sort_keys=True,
                        ).encode("utf-8")
                        + b"\n"
                    )
                    first.chmod(0o600)
                elif mutation == "unknown":
                    (entries / "HOSTILE").write_bytes(b"x")
                    (entries / "HOSTILE").chmod(0o600)
                    expected = "ledger_corrupt"
                elif mutation == "mode":
                    first.chmod(0o640)
                    expected = "unsafe_state"
                elif mutation == "hardlink":
                    os.link(first, entries / "0000000000000003.json")
                    expected = "unsafe_state"
                else:
                    second.unlink()
                    second.symlink_to(first)
                    expected = "ledger_corrupt"
                self.assert_ledger_error(expected, lambda: fixture.ledger.inspect(limit=2))

    def test_committed_tail_deletion_is_detected_before_inspect_or_sequence_reuse(self) -> None:
        """Break caught: deleting the authenticated tail rewinds the append sequence."""

        for operation in ("inspect", "append"):
            with self.subTest(operation=operation), LedgerFixture() as fixture:
                fixture.ledger.append(valid_fields(), observed_at_unix_ms=1)
                fixture.ledger.append(
                    valid_fields(evidence_hmac_sha256="5" * 64),
                    observed_at_unix_ms=2,
                )
                tail = (
                    fixture.diagnostic_dir
                    / "entries"
                    / "0000000000000002.json"
                )
                tail.unlink()
                if operation == "inspect":
                    self.assert_ledger_error(
                        "ledger_tampered", lambda: fixture.ledger.inspect(limit=2)
                    )
                else:
                    self.assert_ledger_error(
                        "ledger_tampered",
                        lambda: fixture.ledger.append(
                            valid_fields(evidence_hmac_sha256="6" * 64),
                            observed_at_unix_ms=3,
                        ),
                    )
                    self.assertFalse(tail.exists())

    def test_exact_1024_row_quota_refuses_1025_without_eviction(self) -> None:
        """Break caught: the hard count quota is off by one or evicts authenticated history."""

        with LedgerFixture() as fixture:
            master_key = (fixture.diagnostic_dir / "key").read_bytes()
            ledger_key = hmac.new(
                master_key,
                b"contextguard-receipt/diagnostic-ledger-mac-key/v1\0",
                hashlib.sha256,
            ).digest()
            metadata = json.loads(
                (fixture.diagnostic_dir / "metadata.json").read_text(encoding="utf-8")
            )
            previous_hmac = metadata["genesis_hmac_sha256"]
            total_canonical_bytes = 0
            for sequence in range(1, 1_025):
                row = {
                    **valid_fields(),
                    "entry_hmac_sha256": "",
                    "observed_at_unix_ms": sequence,
                    "previous_entry_hmac_sha256": previous_hmac,
                    "schema_version": "contextguard-receipt-diagnostic-ledger-entry/v1",
                    "sequence": sequence,
                    "state_scope": "durable",
                }
                unsigned = dict(row)
                unsigned.pop("entry_hmac_sha256")
                unsigned_raw = json.dumps(
                    unsigned,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8") + b"\n"
                row["entry_hmac_sha256"] = hmac.new(
                    ledger_key,
                    b"contextguard-receipt/diagnostic-ledger-entry-mac/v1\0"
                    + unsigned_raw,
                    hashlib.sha256,
                ).hexdigest()
                raw = json.dumps(
                    row,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8") + b"\n"
                entry_path = (
                    fixture.diagnostic_dir
                    / "entries"
                    / f"{sequence:016d}.json"
                )
                entry_path.write_bytes(raw)
                entry_path.chmod(0o600)
                previous_hmac = row["entry_hmac_sha256"]
                total_canonical_bytes += len(raw)
            metadata.update(
                {
                    "committed_entry_count": 1_024,
                    "committed_head_hmac_sha256": previous_hmac,
                    "committed_total_canonical_bytes": total_canonical_bytes,
                    "integrity_hmac_sha256": "",
                }
            )
            unsigned_metadata = dict(metadata)
            unsigned_metadata.pop("integrity_hmac_sha256")
            unsigned_metadata_raw = json.dumps(
                unsigned_metadata,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8") + b"\n"
            metadata["integrity_hmac_sha256"] = hmac.new(
                ledger_key,
                b"contextguard-receipt/diagnostic-ledger-metadata-mac/v1\0"
                + unsigned_metadata_raw,
                hashlib.sha256,
            ).hexdigest()
            metadata_path = fixture.diagnostic_dir / "metadata.json"
            metadata_path.write_bytes(
                json.dumps(
                    metadata,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
                + b"\n"
            )
            metadata_path.chmod(0o600)
            self.assert_ledger_error(
                "entry_count_quota_exceeded",
                lambda: fixture.ledger.append(valid_fields(), observed_at_unix_ms=1_025),
            )
            inspection = fixture.ledger.inspect(limit=1)
            self.assertEqual(inspection["entry_count"], 1_024)
            self.assertEqual(inspection["entries"][0]["sequence"], 1_024)
            self.assertTrue((fixture.diagnostic_dir / "entries" / "0000000000000001.json").is_file())

    def test_threads_and_processes_append_contiguous_sequences(self) -> None:
        """Break caught: flock-only thread sharing or process races lose a sequence."""

        with LedgerFixture() as fixture:
            def append_thread(observed_at: int) -> int:
                return fixture.ledger.append(
                    valid_fields(evidence_hmac_sha256=f"{observed_at:064x}"),
                    observed_at_unix_ms=observed_at,
                )["sequence"]

            with ThreadPoolExecutor(max_workers=4) as executor:
                thread_sequences = list(executor.map(append_thread, range(1, 9)))
            self.assertEqual(sorted(thread_sequences), list(range(1, 9)))

            arguments = (
                str(PYTHON_ROOT),
                str(fixture.state_dir),
                100,
            )
            with ProcessPoolExecutor(
                max_workers=2, mp_context=get_context("spawn")
            ) as executor:
                results = list(executor.map(append_in_process, [arguments] * 4))
            self.assertEqual(results, ["appended"] * 4)
            inspection = fixture.ledger.inspect(limit=16)
            self.assertEqual(inspection["entry_count"], 12)
            self.assertEqual(
                [row["sequence"] for row in inspection["entries"]], list(range(1, 13))
            )

    def test_independent_instances_read_fresh_committed_metadata_under_lock(self) -> None:
        """Break caught: an already-open instance appends from a cached tail anchor."""

        module = ledger_module()
        with LedgerFixture() as fixture:
            second = module.DiagnosticLedger.open(
                state_dir=str(fixture.state_dir), repository_root=str(fixture.root)
            )
            try:
                first_row = fixture.ledger.append(
                    valid_fields(), observed_at_unix_ms=1
                )
                second_row = second.append(
                    valid_fields(evidence_hmac_sha256="5" * 64),
                    observed_at_unix_ms=2,
                )
            finally:
                second.close()
            self.assertEqual(second_row["sequence"], 2)
            self.assertEqual(
                second_row["previous_entry_hmac_sha256"],
                first_row["entry_hmac_sha256"],
            )

    def test_pre_rename_failure_requires_recovery_and_post_rename_failure_is_uncertain(self) -> None:
        """Break caught: crash injection misreports whether an entry may be committed."""

        module = ledger_module()
        with LedgerFixture() as fixture:
            real_fsync = module.os.fsync
            failed = False

            def fail_entry_fsync(descriptor: int) -> None:
                nonlocal failed
                status = os.fstat(descriptor)
                if not failed and stat.S_ISREG(status.st_mode) and status.st_size > 100:
                    failed = True
                    raise OSError("HOSTILE-before-rename")
                real_fsync(descriptor)

            with mock.patch.object(module.os, "fsync", side_effect=fail_entry_fsync):
                self.assert_ledger_error(
                    "write_failed",
                    lambda: fixture.ledger.append(valid_fields(), observed_at_unix_ms=1),
                )
            self.assertTrue(fixture.ledger.inspect(limit=1)["recovery_required"])

        with LedgerFixture() as fixture:
            def fail_entry_rename(*_args, **_kwargs) -> None:
                raise OSError("HOSTILE-before-publish-rename")

            with mock.patch.object(module.os, "rename", side_effect=fail_entry_rename):
                self.assert_ledger_error(
                    "write_failed",
                    lambda: fixture.ledger.append(valid_fields(), observed_at_unix_ms=1),
                )
            inspection = fixture.ledger.inspect(limit=1)
            self.assertEqual(inspection["entry_count"], 0)
            self.assertTrue(inspection["recovery_required"])

        for parent_attribute in ("_temp_fd", "_entries_fd"):
            with self.subTest(parent_attribute=parent_attribute), LedgerFixture() as fixture:
                real_fsync = module.os.fsync
                failed_parent = getattr(fixture.ledger, parent_attribute)

                def fail_row_parent(descriptor: int) -> None:
                    if descriptor == failed_parent:
                        raise OSError("HOSTILE-after-row-rename")
                    real_fsync(descriptor)

                with mock.patch.object(module.os, "fsync", side_effect=fail_row_parent):
                    self.assert_ledger_error(
                        "commit_uncertain",
                        lambda: fixture.ledger.append(
                            valid_fields(), observed_at_unix_ms=1
                        ),
                    )
                inspection = fixture.ledger.inspect(limit=1)
                self.assertEqual(inspection["entry_count"], 0)
                self.assertEqual(inspection["entries"], [])
                self.assertTrue(inspection["recovery_required"])

    def test_metadata_publish_failure_leaves_only_prior_committed_rows_visible(self) -> None:
        """Break caught: a row becomes committed before its authenticated tail anchor."""

        module = ledger_module()
        with LedgerFixture() as fixture:
            prior = fixture.ledger.append(valid_fields(), observed_at_unix_ms=1)
            real_rename = module.os.rename

            def fail_metadata_rename(source, destination, **kwargs) -> None:
                if destination == "metadata.json":
                    raise OSError("HOSTILE-metadata-rename")
                real_rename(source, destination, **kwargs)

            with mock.patch.object(
                module.os, "rename", side_effect=fail_metadata_rename
            ):
                self.assert_ledger_error(
                    "commit_uncertain",
                    lambda: fixture.ledger.append(
                        valid_fields(evidence_hmac_sha256="5" * 64),
                        observed_at_unix_ms=2,
                    ),
                )
            inspection = fixture.ledger.inspect(limit=1)
            self.assertEqual(inspection["entry_count"], 1)
            self.assertEqual(inspection["entries"], [prior])
            self.assertTrue(inspection["recovery_required"])

    def test_post_metadata_rename_fsync_failure_is_committed_but_uncertain(self) -> None:
        """Break caught: metadata replacement durability failure loses the logical commit."""

        module = ledger_module()
        with LedgerFixture() as fixture:
            real_fsync = module.os.fsync
            failed_parent = fixture.ledger._diagnostics_fd

            def fail_metadata_parent(descriptor: int) -> None:
                if descriptor == failed_parent:
                    raise OSError("HOSTILE-metadata-parent-fsync")
                real_fsync(descriptor)

            with mock.patch.object(module.os, "fsync", side_effect=fail_metadata_parent):
                self.assert_ledger_error(
                    "commit_uncertain",
                    lambda: fixture.ledger.append(valid_fields(), observed_at_unix_ms=1),
                )
            inspection = fixture.ledger.inspect(limit=1)
            self.assertEqual(inspection["entry_count"], 1)
            self.assertEqual(inspection["entries"][0]["sequence"], 1)
            self.assertFalse(inspection["recovery_required"])

    def test_fork_inherited_instance_is_rejected_and_parent_remains_usable(self) -> None:
        """Break caught: a child reuses inherited mutex and flock open-file authority."""

        if not hasattr(os, "fork"):
            self.skipTest("fork is unavailable")
        with LedgerFixture() as fixture:
            read_fd, write_fd = os.pipe()
            child_pid = os.fork()
            if child_pid == 0:
                os.close(read_fd)
                try:
                    try:
                        fixture.ledger.inspect(limit=1)
                        result = b"accepted"
                    except ledger_module().DiagnosticLedgerError as error:
                        result = error.code.value.encode("ascii")
                    os.write(write_fd, result)
                finally:
                    os.close(write_fd)
                    os._exit(0)
            os.close(write_fd)
            try:
                result = os.read(read_fd, 64)
            finally:
                os.close(read_fd)
            _waited, wait_status = os.waitpid(child_pid, 0)
            self.assertEqual(os.waitstatus_to_exitcode(wait_status), 0)
            self.assertEqual(result, b"unsafe_state")
            self.assertEqual(
                fixture.ledger.append(valid_fields(), observed_at_unix_ms=1)["sequence"], 1
            )

    def test_auxiliary_removal_does_not_modify_independent_store_v1(self) -> None:
        """Break caught: diagnostics reuse or mutate store-v1 key/commit state."""

        store = importlib.import_module("context_guard_receipt.store")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state_dir = base / "private-state"
            root.mkdir(mode=0o700)
            capability = store.CapabilityStore.open(
                state_dir=str(state_dir), repository_root=str(root), create=True
            )
            issued = capability.issue(
                payload=b"independent",
                root_identity_sha256="1" * 64,
                subject_identity_sha256="2" * 64,
                artifact_type=store.ArtifactType.RAW_EVIDENCE_BYTES,
            )
            capability.close()
            store_key_before = (state_dir / "store-v1" / "integrity-key").read_bytes()
            with ledger_module().DiagnosticLedger.open(
                state_dir=str(state_dir), repository_root=str(root), create=True
            ) as ledger:
                ledger.append(valid_fields(), observed_at_unix_ms=1)
                self.assertNotEqual(store_key_before, (state_dir / "auxiliary-v1/diagnostics-v1/key").read_bytes())
            shutil.rmtree(state_dir / "auxiliary-v1")
            reopened = store.CapabilityStore.open(
                state_dir=str(state_dir), repository_root=str(root)
            )
            retrieved = reopened.retrieve(
                issued.handle,
                expected_namespace_id=issued.namespace_id,
                expected_root_identity_sha256="1" * 64,
                expected_subject_identity_sha256="2" * 64,
                expected_artifact_type=store.ArtifactType.RAW_EVIDENCE_BYTES,
            )
            self.assertEqual(retrieved.payload, b"independent")
            reopened.close()

    def test_inspection_entry_reference_resolves_to_packaged_schema_id(self) -> None:
        """Break caught: a packaged cross-schema ref resolves to an absent URI."""

        entry = json.loads(ENTRY_SCHEMA_PATH.read_text(encoding="utf-8"))
        inspection = json.loads(INSPECTION_SCHEMA_PATH.read_text(encoding="utf-8"))
        entry_reference = inspection["properties"]["entries"]["items"]["$ref"]

        self.assertEqual(urljoin(inspection["$id"], entry_reference), entry["$id"])

    def test_schemas_are_closed_exact_and_forbid_sensitive_vocabulary(self) -> None:
        """Break caught: durable/inspection schemas drift open or acquire identifying fields."""

        entry = json.loads(ENTRY_SCHEMA_PATH.read_text(encoding="utf-8"))
        metadata = json.loads(METADATA_SCHEMA_PATH.read_text(encoding="utf-8"))
        inspection = json.loads(INSPECTION_SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertIs(entry["additionalProperties"], False)
        self.assertEqual(set(entry["required"]), set(valid_fields()) | {
            "entry_hmac_sha256", "observed_at_unix_ms", "previous_entry_hmac_sha256",
            "schema_version", "sequence", "state_scope",
        })
        self.assertEqual(
            set(metadata["required"]),
            {
                "committed_entry_count",
                "committed_head_hmac_sha256",
                "committed_total_canonical_bytes",
                "evidence_boundary",
                "genesis_hmac_sha256",
                "integrity_hmac_sha256",
                "schema_version",
            },
        )
        self.assertEqual(
            set(inspection["required"]),
            {"entries", "entry_count", "evidence_boundary", "recovery_required", "schema_version", "state_scope", "total_canonical_bytes"},
        )
        self.assertIs(metadata["additionalProperties"], False)
        self.assertIs(inspection["additionalProperties"], False)
        self.assertEqual(
            entry["properties"]["policy_sha256"],
            {
                "const": "a6e00501858586d80afcd465c5a0fe65c85d2c6d74089cfe14bf347b670eb5cf"
            },
        )
        advisory_branches = entry["oneOf"]
        self.assertEqual(len(advisory_branches), 3)
        self.assertEqual(
            [branch["properties"]["advisory_lane"]["const"] for branch in advisory_branches],
            ["none", "scout", "surgeon"],
        )
        surgeon_properties = advisory_branches[2]["properties"]
        self.assertEqual(
            surgeon_properties["advisory_reason"],
            {"const": "bounded_stable_benefit"},
        )
        self.assertEqual(surgeon_properties["firewall_reason"], {"const": "beneficial"})
        self.assertEqual(surgeon_properties["current_sample_bytes"]["minimum"], 64)
        self.assertEqual(surgeon_properties["previous_sample_bytes"]["minimum"], 64)
        self.assertEqual(surgeon_properties["previous_prefix_present"], {"const": True})
        self.assertEqual(surgeon_properties["current_reuse_basis_points"]["minimum"], 9_000)
        self.assertEqual(
            surgeon_properties["previous_retention_basis_points"]["minimum"], 9_000
        )
        none_pairs = advisory_branches[0]["oneOf"]
        self.assertEqual(
            [branch["properties"] for branch in none_pairs],
            [
                {
                    "advisory_reason": {"const": "protection_refused"},
                    "firewall_reason": {"enum": ["secret", "refuse"]},
                },
                {
                    "advisory_reason": {"const": "exact_path_required"},
                    "firewall_reason": {
                        "enum": [
                            "exact_required",
                            "protected",
                            "unknown",
                            "ambiguous",
                            "security_sensitive",
                        ]
                    },
                },
            ],
        )
        scout_pairs = advisory_branches[1]["oneOf"]
        scout_by_reason = {
            branch["properties"]["advisory_reason"]["const"]: branch
            for branch in scout_pairs
        }
        self.assertEqual(
            set(scout_by_reason),
            {
                "input_too_small",
                "savings_too_small",
                "savings_ratio_too_small",
                "mandatory_expansion_cost",
                "prefix_evidence_empty",
                "prior_prefix_missing",
                "rolling_sample_partial",
                "prefix_churn_high",
            },
        )
        for reason in (
            "input_too_small",
            "savings_too_small",
            "savings_ratio_too_small",
            "mandatory_expansion_cost",
        ):
            self.assertEqual(
                scout_by_reason[reason]["properties"]["firewall_reason"],
                {"const": reason},
            )
        self.assertEqual(
            scout_by_reason["prefix_evidence_empty"]["properties"][
                "current_prefix_bytes"
            ],
            {"const": 0},
        )
        self.assertEqual(
            scout_by_reason["prior_prefix_missing"]["properties"][
                "previous_prefix_present"
            ],
            {"const": False},
        )
        self.assertEqual(
            scout_by_reason["rolling_sample_partial"]["anyOf"],
            [
                {"properties": {"current_truncated": {"const": True}}},
                {"properties": {"previous_truncated": {"const": True}}},
            ],
        )
        self.assertEqual(
            scout_by_reason["prefix_churn_high"]["anyOf"],
            [
                {"properties": {"current_sample_bytes": {"maximum": 63}}},
                {"properties": {"previous_sample_bytes": {"maximum": 63}}},
                {
                    "properties": {
                        "current_reuse_basis_points": {"maximum": 8_999}
                    }
                },
                {
                    "properties": {
                        "previous_retention_basis_points": {"maximum": 8_999}
                    }
                },
            ],
        )
        serialized = json.dumps((entry, metadata, inspection), sort_keys=True)
        for forbidden in (
            '"metadata"', '"detail"', '"details"', '"error"', '"errors"',
            '"diagnostics"', '"filename"', '"filenames"', '"path"', '"argv"',
            '"prompt"', '"payload"', '"description"', '"exception"', '"handle"',
            '"capability"', '"token"', '"tokens"', '"cost"', '"price"', '"usd"', '"krw"',
        ):
            self.assertNotIn(forbidden, serialized)


if __name__ == "__main__":
    unittest.main()
