"""Generic observation helpers for the candidate-blind S002 contract.

This module intentionally contains no scheduling, accounting, bootstrap, or
correction implementation. It only materializes bytes/files, records calls,
and validates the two absent-capability boundaries that have no production
owner: offline access and the S002 diff allowlist.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import stat
from typing import Any, Callable, Mapping, Sequence


FORBIDDEN_ACCESS_KINDS = frozenset(
    {"provider_process", "task_process", "network", "keychain", "auth", "credential_env"}
)
S002_OWNED_PATHS = frozenset(
    {
        "context-guard-kit/benchmark_runner.py",
        "plugins/context-guard/bin/context-guard-bench",
        "tests/test_benchmark_measurement_inference.py",
        "tests/s002_contract_harness.py",
        "tests/fixtures/s002_direct_behavior_cases_v2.json",
    }
)


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize fixture/artifact values without adding candidate semantics."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def load_canonical_fixture(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise AssertionError("S002 fixture root must be an object")
    if canonical_json_bytes(value) != raw:
        raise AssertionError("S002 fixture must be canonical JSON without a trailing newline")
    return value


@dataclass
class TraceRecorder:
    """Record real seam calls in occurrence order; never infer their outcome."""

    calls: list[dict[str, Any]] = field(default_factory=list)

    def record(self, kind: str, **fields: Any) -> None:
        self.calls.append({"kind": kind, **fields})

    def callback(self, kind: str, *, result: Any = None, failure: BaseException | None = None) -> Callable[..., Any]:
        def observed(*args: Any, **kwargs: Any) -> Any:
            self.record(kind, args=list(args), kwargs=kwargs)
            if failure is not None:
                raise failure
            return result

        return observed


@dataclass
class ProcessDouble:
    """Minimal process object for bounded-runner trace tests."""

    pid: int = 41002
    returncode: int | None = None
    stdout: Any = None
    stderr: Any = None

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        self.returncode = 0 if self.returncode is None else self.returncode
        return self.returncode


class EnvironmentSpy(Mapping[str, str]):
    """Record attempted credential-shaped environment reads."""

    def __init__(self, values: Mapping[str, str], forbidden_names: Sequence[str]) -> None:
        self._values = dict(values)
        self._forbidden_names = frozenset(forbidden_names)
        self.forbidden_reads: list[str] = []

    def _observe(self, key: str) -> None:
        if key in self._forbidden_names:
            self.forbidden_reads.append(key)

    def __getitem__(self, key: str) -> str:
        self._observe(key)
        return self._values[key]

    def __iter__(self):
        for key in self._values:
            self._observe(key)
            yield key

    def __len__(self) -> int:
        return len(self._values)

    def __contains__(self, key: object) -> bool:
        if isinstance(key, str):
            self._observe(key)
        return key in self._values

    def copy(self) -> dict[str, str]:
        return dict(self)


def materialize_tree(root: Path, files: Mapping[str, bytes | str], *, mode: int = 0o600) -> dict[str, Path]:
    """Create explicit fixture files beneath ``root`` and return their paths."""
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    materialized: dict[str, Path] = {}
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
        target.chmod(mode)
        materialized[relative] = target
    return materialized


def file_observation(path: Path) -> dict[str, Any]:
    info = path.lstat()
    raw = path.read_bytes() if stat.S_ISREG(info.st_mode) else b""
    return {
        "is_directory": stat.S_ISDIR(info.st_mode),
        "is_regular": stat.S_ISREG(info.st_mode),
        "is_symlink": stat.S_ISLNK(info.st_mode),
        "mode": stat.S_IMODE(info.st_mode),
        "size": len(raw),
        "sha256": sha256_hex(raw),
    }


def validate_offline_access_trace(trace: Sequence[Mapping[str, Any]]) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Validate the observable offline seam, returning a canonical projection."""
    projection: list[tuple[str, tuple[str, ...]]] = []
    probe_argv: list[tuple[str, ...]] = []
    for event in trace:
        kind = event.get("kind")
        if not isinstance(kind, str):
            raise AssertionError("offline trace event kind must be a string")
        if kind in FORBIDDEN_ACCESS_KINDS:
            raise AssertionError(f"forbidden offline access: {kind}")
        argv_raw = event.get("argv", ())
        if not isinstance(argv_raw, (list, tuple)) or not all(isinstance(item, str) for item in argv_raw):
            raise AssertionError("offline trace argv must be a string sequence")
        argv = tuple(argv_raw)
        projection.append((kind, argv))
        if kind == "metadata_probe":
            probe_argv.append(argv)
    if probe_argv != [("claude", "--version"), ("claude", "--help")]:
        raise AssertionError("offline trace must contain exactly the ordered version/help probes")
    if [kind for kind, _ in projection] != ["metadata_probe", "metadata_probe", "artifact_write"]:
        raise AssertionError("offline trace contains work outside the bounded prepare/analyze seam")
    return tuple(projection)


def validate_s002_diff_bundle(bundle: Mapping[str, Any]) -> tuple[str, ...]:
    """Reject changes outside the five-file S002 boundary or frozen invariants."""
    changed = bundle.get("changed_paths")
    if not isinstance(changed, list) or not all(isinstance(path, str) for path in changed):
        raise AssertionError("changed_paths must be a string list")
    if len(changed) != len(set(changed)):
        raise AssertionError("changed_paths must not contain duplicates")
    outside = sorted(set(changed) - S002_OWNED_PATHS)
    if outside:
        raise AssertionError(f"S002 scope contains forbidden paths: {outside}")
    if bundle.get("read_threshold_before") != 48000 or bundle.get("read_threshold_after") != 48000:
        raise AssertionError("S002 must preserve the 48,000-byte Read threshold")
    if bundle.get("phase5_touched") is not False:
        raise AssertionError("S002 must not touch Phase 5")
    access = bundle.get("access_trace")
    if not isinstance(access, list):
        raise AssertionError("access_trace must be a list")
    for event in access:
        if not isinstance(event, Mapping) or event.get("kind") in FORBIDDEN_ACCESS_KINDS:
            raise AssertionError("S002 diff records forbidden credential/provider access")
    return tuple(changed)
