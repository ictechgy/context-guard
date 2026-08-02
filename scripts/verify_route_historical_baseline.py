#!/usr/bin/env python3
"""Execute the immutable pre-route baseline against every relaxation case."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter
from collections.abc import Sequence
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASELINE_COMMIT = "ed46287ee03710d4df6003d52f4eeee60bcd1f4e"
BASELINE_TREE = "3f9ee86abd2b3b79775421529290822eb829a238"
BASELINE_RUNTIME_BLOB = "2439e99c6e7388ad330d6d74b003aeff5df9b90a"
BASELINE_RUNTIME_PATH = "context-guard-kit/rewrite_bash_for_token_budget.py"
BASELINE_CACHE_SCHEMA = "contextguard.route-historical-baseline.v1"
BASELINE_INVENTORY_CASE_COUNT = 57
BASELINE_INVENTORY_CASES_SHA256 = (
    "3df5ab65f3d18ca3d79f6015a137b86aefbf888fbda64e5efc0bb28981edfd3b"
)
BASELINE_CANDIDATE_EXPECTATIONS_SHA256 = (
    "ae7fafa6d6499016e919f2c79f15c651ba5a5e705ec7bac8a5c009c6f1248244"
)
CORPUS_PATH = ROOT / "tests" / "corpus_adversarial_pins.py"
BASELINE_CACHE_PATH = (
    ROOT
    / "tests"
    / "fixtures"
    / "context_guard_contracts"
    / f"route-historical-baseline-{BASELINE_TREE}.json"
)
CANDIDATE_ENTRYPOINTS = (
    ("canonical", ROOT / "context-guard-kit" / "rewrite_bash_for_token_budget.py"),
    ("plugin", ROOT / "plugins" / "context-guard" / "bin" / "context-guard-rewrite-bash"),
)


class ProofError(RuntimeError):
    """Raised when historical or candidate route evidence does not match."""


_ISOLATED_CLASSIFIER = r"""
from __future__ import annotations
import importlib.util
import json
import sys

runtime_path = sys.argv[1]
spec = importlib.util.spec_from_file_location("context_guard_historical_runtime", runtime_path)
if spec is None or spec.loader is None:
    raise RuntimeError("could not load runtime")
runtime = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = runtime
spec.loader.exec_module(runtime)
requests = json.load(sys.stdin)
results = []
for request in requests:
    decision = runtime.classify_command(request["command"])
    results.append(
        {
            "case_id": request["case_id"],
            "action": decision.action,
            "reason_code": decision.reason_code,
        }
    )
json.dump(results, sys.stdout, ensure_ascii=False, separators=(",", ":"))
"""

_ISOLATED_CORPUS_LOADER = r"""
from __future__ import annotations
import importlib.util
import json
import sys

corpus_path = sys.argv[1]
spec = importlib.util.spec_from_file_location("context_guard_route_baseline_corpus", corpus_path)
if spec is None or spec.loader is None:
    raise RuntimeError("could not load corpus")
corpus = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = corpus
spec.loader.exec_module(corpus)
selectors = []
for name, value in sorted(vars(corpus).items()):
    if name.endswith("_route_predicate_relaxations") and callable(value):
        selectors.append({"name": name, "cases": value()})
json.dump(selectors, sys.stdout, ensure_ascii=False, separators=(",", ":"))
"""


def _proof_environment(home: Path) -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
    }


def _run_git(repo: Path, *args: str) -> bytes:
    proc = subprocess.run(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            str(repo),
            *args,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env={**_proof_environment(repo), "GIT_LITERAL_PATHSPECS": "1"},
    )
    if proc.returncode:
        detail = proc.stderr.decode("utf-8", errors="replace").strip()
        raise ProofError(f"git object lookup failed: {detail or f'exit {proc.returncode}'}")
    return proc.stdout


def load_route_relaxation_cases(corpus_path: Path = CORPUS_PATH) -> list[dict[str, object]]:
    with tempfile.TemporaryDirectory(prefix="context-guard-route-corpus-") as temp_dir:
        private_root = Path(temp_dir)
        private_corpus_path = private_root / "corpus.py"
        runner_path = private_root / "load_corpus.py"
        private_corpus_path.write_bytes(corpus_path.read_bytes())
        runner_path.write_text(_ISOLATED_CORPUS_LOADER, encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, "-I", "-S", str(runner_path), str(private_corpus_path)],
            cwd=private_root,
            text=True,
            encoding="utf-8",
            errors="strict",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=_proof_environment(private_root),
            timeout=30,
        )
    if proc.returncode:
        detail = proc.stderr.strip()
        raise ProofError(
            f"isolated corpus loader failed: {detail or f'exit {proc.returncode}'}"
        )
    try:
        selectors = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ProofError("isolated corpus loader returned invalid JSON") from exc
    if not isinstance(selectors, list):
        raise ProofError("isolated corpus loader returned invalid selectors")
    if not selectors:
        raise ProofError("route relaxation inventory is empty")

    cases: list[dict[str, object]] = []
    for selector in selectors:
        if not isinstance(selector, dict) or not isinstance(selector.get("name"), str):
            raise ProofError("isolated corpus loader returned an invalid selector")
        selector_name = str(selector["name"])
        selected = selector.get("cases")
        if not isinstance(selected, list):
            raise ProofError(f"{selector_name} did not return a list")
        for case in selected:
            if not isinstance(case, dict):
                raise ProofError(f"{selector_name} returned a non-object case")
            required_strings = ("case_id", "fix", "command", "expected_decision")
            missing_strings = [
                key for key in required_strings if not isinstance(case.get(key), str)
            ]
            if missing_strings:
                raise ProofError(
                    f"{selector_name} case is missing string fields: {missing_strings}"
                )
            required_fields = ("baseline_reason_code", "expected_reason_code")
            missing_fields = [key for key in required_fields if key not in case]
            if missing_fields:
                raise ProofError(
                    f"{selector_name} case is missing required fields: {missing_fields}"
                )
            if case["expected_decision"] == "deny":
                raise ProofError(f"{case['case_id']} is not a relaxation candidate")
            cases.append(dict(case))

    case_ids = [str(case["case_id"]) for case in cases]
    duplicate_ids = sorted({case_id for case_id in case_ids if case_ids.count(case_id) > 1})
    if duplicate_ids:
        raise ProofError(f"duplicate route relaxation case ids: {duplicate_ids}")
    return cases


def _classify_isolated(
    runtime_source: bytes,
    cases: Sequence[dict[str, object]],
) -> list[dict[str, object]]:
    requests = [
        {"case_id": case["case_id"], "command": case["command"]}
        for case in cases
    ]
    with tempfile.TemporaryDirectory(prefix="context-guard-route-baseline-") as temp_dir:
        private_root = Path(temp_dir)
        runtime_path = private_root / "runtime.py"
        runner_path = private_root / "runner.py"
        runtime_path.write_bytes(runtime_source)
        runner_path.write_text(_ISOLATED_CLASSIFIER, encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, "-I", "-S", str(runner_path), str(runtime_path)],
            cwd=private_root,
            input=json.dumps(requests, ensure_ascii=False, separators=(",", ":")),
            text=True,
            encoding="utf-8",
            errors="strict",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=_proof_environment(private_root),
            timeout=30,
        )
    if proc.returncode:
        detail = proc.stderr.strip()
        raise ProofError(f"isolated classifier failed: {detail or f'exit {proc.returncode}'}")
    try:
        results = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ProofError("isolated classifier returned invalid JSON") from exc
    if not isinstance(results, list) or len(results) != len(cases):
        raise ProofError("isolated classifier returned an incomplete result set")
    return results


def _resolve_baseline_source(repo: Path) -> bytes:
    resolved_commit = _run_git(repo, "rev-parse", "--verify", f"{BASELINE_COMMIT}^{{commit}}")
    if resolved_commit.decode().strip() != BASELINE_COMMIT:
        raise ProofError("baseline commit did not resolve to the pinned revision")
    resolved_tree = _run_git(repo, "rev-parse", f"{BASELINE_COMMIT}^{{tree}}")
    if resolved_tree.decode().strip() != BASELINE_TREE:
        raise ProofError("baseline tree does not match the pinned tree")
    resolved_blob = _run_git(repo, "rev-parse", f"{BASELINE_COMMIT}:{BASELINE_RUNTIME_PATH}")
    if resolved_blob.decode().strip() != BASELINE_RUNTIME_BLOB:
        raise ProofError("baseline runtime blob does not match the pinned blob")
    runtime_source = _run_git(repo, "cat-file", "blob", BASELINE_RUNTIME_BLOB)
    object_bytes = f"blob {len(runtime_source)}\0".encode("ascii") + runtime_source
    resolved_source_blob = hashlib.sha1(
        object_bytes,
        usedforsecurity=False,
    ).hexdigest()
    if resolved_source_blob != BASELINE_RUNTIME_BLOB:
        raise ProofError("baseline runtime bytes do not match the pinned blob")
    return runtime_source


def _result_map(
    results: Sequence[dict[str, object]],
    expected_case_ids: Sequence[str],
) -> dict[str, dict[str, object]]:
    mapped: dict[str, dict[str, object]] = {}
    for result in results:
        if not isinstance(result, dict):
            raise ProofError("classifier returned a non-object result")
        case_id = result.get("case_id")
        if not isinstance(case_id, str) or case_id in mapped:
            raise ProofError("classifier returned invalid or duplicate case ids")
        mapped[case_id] = result
    if set(mapped) != set(expected_case_ids):
        raise ProofError("classifier returned unexpected case ids")
    return mapped


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _load_baseline_cache(cache_path: Path) -> tuple[bytes, dict[str, object]]:
    cache_bytes = cache_path.read_bytes()
    try:
        cache = json.loads(cache_bytes)
    except json.JSONDecodeError as exc:
        raise ProofError("baseline cache is not valid JSON") from exc
    if not isinstance(cache, dict):
        raise ProofError("baseline cache is not a JSON object")
    if cache.get("schema_version") != BASELINE_CACHE_SCHEMA:
        raise ProofError("baseline cache schema mismatch")
    baseline = cache.get("baseline")
    inventory = cache.get("inventory")
    if not isinstance(baseline, dict) or not isinstance(inventory, dict):
        raise ProofError("baseline cache is missing identity or inventory")
    expected_identity = {
        "commit": BASELINE_COMMIT,
        "tree": BASELINE_TREE,
        "runtime_path": BASELINE_RUNTIME_PATH,
        "runtime_blob": BASELINE_RUNTIME_BLOB,
    }
    for field, expected in expected_identity.items():
        if baseline.get(field) != expected:
            raise ProofError(f"cache baseline {field.replace('_', ' ')} mismatch")
    return cache_bytes, cache


def _assert_cache_inventory(
    cache_inventory: dict[str, object],
    cases: Sequence[dict[str, object]],
    baseline_results: dict[str, dict[str, object]],
) -> None:
    actual_records = []
    for case in cases:
        case_id = str(case["case_id"])
        result = baseline_results[case_id]
        actual_records.append(
            {
                "case_id": case_id,
                "fix": case["fix"],
                "command_sha256": hashlib.sha256(
                    str(case["command"]).encode("utf-8")
                ).hexdigest(),
                "baseline_action": result["action"],
                "baseline_reason_code": result.get("reason_code"),
            }
        )
    actual_records.sort(key=lambda record: str(record["case_id"]))
    if len(actual_records) != BASELINE_INVENTORY_CASE_COUNT:
        raise ProofError("pinned deny-to-allow inventory count mismatch")
    if _canonical_sha256(actual_records) != BASELINE_INVENTORY_CASES_SHA256:
        raise ProofError("pinned deny-to-allow inventory digest mismatch")

    cached_records = cache_inventory.get("cases")
    if not isinstance(cached_records, list):
        raise ProofError("cache inventory cases are missing")
    cached_count = cache_inventory.get("case_count")
    if cached_count != len(cached_records) or cached_count != len(actual_records):
        raise ProofError("cache inventory case count mismatch")
    cached_digest = cache_inventory.get("cases_sha256")
    if cached_digest != _canonical_sha256(cached_records):
        raise ProofError("cache inventory digest mismatch")
    if cached_records != actual_records:
        raise ProofError("cache inventory does not match executable observations")


def _assert_candidate_expectations(cases: Sequence[dict[str, object]]) -> None:
    records = [
        {
            "case_id": str(case["case_id"]),
            "expected_decision": case["expected_decision"],
            "expected_reason_code": case["expected_reason_code"],
        }
        for case in cases
    ]
    records.sort(key=lambda record: str(record["case_id"]))
    if _canonical_sha256(records) != BASELINE_CANDIDATE_EXPECTATIONS_SHA256:
        raise ProofError("pinned candidate expectation digest mismatch")


def verify_route_historical_baseline(
    repo: Path = ROOT,
    *,
    corpus_path: Path = CORPUS_PATH,
    cache_path: Path = BASELINE_CACHE_PATH,
    candidate_entrypoints: Sequence[tuple[str, Path]] = CANDIDATE_ENTRYPOINTS,
) -> dict[str, object]:
    if not candidate_entrypoints:
        raise ProofError("candidate entrypoint inventory is empty")
    cache_bytes, cache = _load_baseline_cache(cache_path)
    cache_baseline = cache["baseline"]
    cache_inventory = cache["inventory"]
    if not isinstance(cache_baseline, dict) or not isinstance(cache_inventory, dict):
        raise ProofError("baseline cache is missing identity or inventory")
    cases = load_route_relaxation_cases(corpus_path)
    baseline_source = _resolve_baseline_source(repo)
    case_ids = [str(case["case_id"]) for case in cases]
    baseline_results = _result_map(
        _classify_isolated(baseline_source, cases),
        case_ids,
    )
    deny_to_allow_cases = [
        case
        for case in cases
        if baseline_results[str(case["case_id"])]["action"] == "deny"
    ]
    if not deny_to_allow_cases:
        raise ProofError("executable baseline found no deny-to-allow cases")

    baseline_reasons: Counter[str] = Counter()
    for case in deny_to_allow_cases:
        result = baseline_results[str(case["case_id"])]
        reason_code = result.get("reason_code")
        if reason_code != "route_policy_denied":
            raise ProofError(
                f"{case['case_id']} baseline reason is {reason_code!r}, not route_policy_denied"
            )
        if case.get("baseline_reason_code") != reason_code:
            raise ProofError(
                f"fixture baseline reason mismatch for {case['case_id']}: "
                "the executable observation is authoritative"
            )
        baseline_reasons[str(reason_code)] += 1

    _assert_cache_inventory(cache_inventory, deny_to_allow_cases, baseline_results)
    _assert_candidate_expectations(deny_to_allow_cases)

    entrypoint_names: list[str] = []
    reference_results: dict[str, dict[str, object]] | None = None
    deny_to_allow_case_ids = [str(case["case_id"]) for case in deny_to_allow_cases]
    for entrypoint_name, entrypoint_path in candidate_entrypoints:
        candidate_results = _result_map(
            _classify_isolated(entrypoint_path.read_bytes(), deny_to_allow_cases),
            deny_to_allow_case_ids,
        )
        for case in deny_to_allow_cases:
            result = candidate_results[str(case["case_id"])]
            if result.get("action") != case["expected_decision"]:
                raise ProofError(
                    f"{entrypoint_name} candidate action mismatch for {case['case_id']}"
                )
            if result.get("reason_code") != case.get("expected_reason_code"):
                raise ProofError(
                    f"{entrypoint_name} candidate reason mismatch for {case['case_id']}"
                )
        if reference_results is not None and candidate_results != reference_results:
            raise ProofError(f"{entrypoint_name} candidate results differ from canonical")
        reference_results = candidate_results
        entrypoint_names.append(entrypoint_name)

    return {
        "status": "ok",
        "baseline_commit": BASELINE_COMMIT,
        "baseline_tree": BASELINE_TREE,
        "baseline_runtime_blob": BASELINE_RUNTIME_BLOB,
        "relaxation_case_count": len(cases),
        "deny_to_allow_case_count": len(deny_to_allow_cases),
        "baseline_reason_counts": dict(sorted(baseline_reasons.items())),
        "baseline_cache_tree": cache_baseline["tree"],
        "baseline_cache_case_count": cache_inventory["case_count"],
        "baseline_cache_sha256": hashlib.sha256(cache_bytes).hexdigest(),
        "candidate_entrypoints": entrypoint_names,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit a JSON proof summary")
    args = parser.parse_args(argv)
    try:
        proof = verify_route_historical_baseline()
    except (OSError, ProofError, subprocess.TimeoutExpired) as exc:
        if args.json:
            print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
        else:
            print(f"route historical baseline proof failed: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(proof, ensure_ascii=False, sort_keys=True))
    else:
        print(
            "route historical baseline proof: ok "
            f"({proof['deny_to_allow_case_count']} deny-to-allow cases)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
