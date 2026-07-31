#!/usr/bin/env python3
"""Zero-cost S003 rehearsal for the real 12-task measurement suite.

This harness proves the full measurement path end to end without any provider,
network, credential, or keychain access. It generates an official-shaped fake
Claude CLI, materializes cold local/session roots, executes all 72 initial
scheduled attempts plus the scripted retry cases, then writes a deterministic
rehearsal report and an engineering overhead ledger.

Boundaries that are intentional and must not be relaxed:

- No provider call, no network socket, no credential read, and no USD spend.
- Fake token counts are scripted local fixtures. They are never evidence of
  provider-measured token or cost savings.
- The rehearsal proves substrate readiness only. Token savings remain claimable
  only for the exact frozen 12-task suite under its hashed manifest, and only
  from a real authorized study.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CANONICAL_RUNNER = REPO_ROOT / "context-guard-kit/benchmark_runner.py"
PACKAGED_RUNNER = REPO_ROOT / "plugins/context-guard/bin/context-guard-bench"
DEFAULT_SUITE = REPO_ROOT / "bench/token-savings-12task"
REHEARSAL_REPORT_SCHEMA = "contextguard.bench.rehearsal-report.v1"
OVERHEAD_LEDGER_SCHEMA = "contextguard.bench.rehearsal-overhead.v1"
CLAIM_BOUNDARY = (
    "Zero-cost rehearsal only. Token savings demonstrated only for the exact "
    "frozen 12-task suite under manifest <sha256>, and only from an authorized "
    "provider-measured study."
)
# 자격증명/키체인 계열 이름은 fake CLI 자식 환경에 절대 나타나면 안 된다.
FORBIDDEN_ENV_NAMES = (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "GITHUB_PAT",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "KUBECONFIG",
    "NETRC",
    "NPM_TOKEN",
    "OPENAI_API_KEY",
)
# 스크립트된 재시도 단위: attempt 0 은 valid_task_failure_v1, attempt 1 은 성공.
SCRIPTED_RETRY_UNITS = (
    ("ts12_01_small_fix", "baseline", 0),
    ("ts12_02_bugfix", "treatment", 1),
    ("ts12_07_docs", "baseline", 2),
    ("ts12_12_artifact_receipt", "treatment", 0),
)

FAKE_CLI = '''#!/usr/bin/env python3
"""Official-shaped fake Claude CLI for the S003 zero-cost rehearsal.

No network, no provider, no credential access. Scripted workspace writes come
from a rehearsal-only solutions file that is never part of a task fixture tree.
"""
import hashlib
import json
import os
import sys
from pathlib import Path

# 실행 시점 fail-closed 증거: 네트워크/외부 실행/브라우저 계열 audit 이벤트가 발생하면
# 즉시 중단한다. 정적 소스 검사와 달리 이 훅은 우회된 호출도 실제로 막는다.
BLOCKED_AUDIT_PREFIXES = (
    "socket.", "urllib.", "http.", "ssl.", "ftplib.", "smtplib.", "imaplib.",
    "poplib.", "telnetlib.", "webbrowser.", "subprocess.", "os.exec", "os.fork",
    "os.posix_spawn", "os.system", "os.spawn", "pty.spawn",
)
AUDIT_VIOLATIONS = []


def _audit(event, args):
    if event.startswith(BLOCKED_AUDIT_PREFIXES):
        AUDIT_VIOLATIONS.append(event)
        raise RuntimeError("fake provider blocked a non-local operation: " + event)


sys.addaudithook(_audit)

CAPABILITIES = (
    "--settings --setting-sources --include-hook-events "
    "--no-session-persistence stream-json"
)
# --version/--help 메타데이터 probe 는 rehearsal override 없이 실행되므로, provider 모드에서만
# 이 경로들을 요구한다.
STATE_PATH = os.environ.get("CG_S003_STATE")
INDEX_PATH = os.environ.get("CG_S003_INDEX")
ENV_LOG_PATH = os.environ.get("CG_S003_ENV_LOG")
OBSERVED_ENV_KEYS = (
    "HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
    "TMPDIR", "CLAUDE_CONFIG_DIR", "PATH", "LANG",
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
    "GITHUB_PAT", "GITHUB_TOKEN", "GH_TOKEN", "KUBECONFIG", "NETRC", "NPM_TOKEN",
    "OPENAI_API_KEY",
)


def log_env(kind):
    if not ENV_LOG_PATH:
        return
    record = {
        "kind": kind,
        "env": {key: bool(os.environ.get(key)) for key in OBSERVED_ENV_KEYS if key in os.environ},
    }
    with open(ENV_LOG_PATH, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\\n")


if "--help" in sys.argv:
    log_env("help")
    print(CAPABILITIES)
    raise SystemExit(0)
if "--version" in sys.argv:
    log_env("version")
    print("fake-claude-s003 1.0")
    raise SystemExit(0)

if not STATE_PATH or not INDEX_PATH:
    print(json.dumps({"type": "result", "subtype": "error_during_execution", "is_error": True}))
    raise SystemExit(22)
log_env("provider")
index = json.loads(Path(INDEX_PATH).read_text(encoding="utf-8"))
prompt_index = index["prompt_sha256_to_task"]
solutions = index["solutions"]
retry_units = [list(unit) for unit in index["scripted_retry_units"]]

settings_path = sys.argv[sys.argv.index("--settings") + 1]
arm = "treatment" if "treatment" in Path(settings_path).name else "baseline"
# runs/<run_id>/session/<arm>.settings.json 스냅샷 경로에서 슬롯 신원을 복원한다.
run_id = Path(settings_path).parent.parent.name
slot = index.get("run_id_to_unit", {}).get(run_id)

prompt = ""
if "--" in sys.argv:
    tail = sys.argv[sys.argv.index("--") + 1:]
    if len(tail) == 1:
        prompt = tail[0]
if not prompt:
    prompt = sys.argv[-1]
task_id = prompt_index.get(hashlib.sha256(prompt.encode("utf-8")).hexdigest())
if task_id is None or slot is None or slot["task_id"] != task_id or slot["arm"] != arm:
    print(json.dumps({"type": "result", "subtype": "error_during_execution", "is_error": True}))
    raise SystemExit(21)

state_path = Path(STATE_PATH)
with open(state_path, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(
        {
            "task_id": task_id, "arm": arm, "run_id": run_id,
            "repetition": slot["repetition"], "attempt": slot["attempt"],
        },
        sort_keys=True,
    ) + "\\n")

# 스크립트된 재시도: 지정된 (task, arm, repetition) 의 attempt 0 만 유효 실패로 끝낸다.
should_fail = (
    [task_id, arm, slot["repetition"]] in retry_units and int(slot["attempt"]) == 0
)


def lifecycle(hook_id, hook_name, hook_event, progress=1):
    common = {
        "type": "system", "hook_id": hook_id, "hook_name": hook_name,
        "hook_event": hook_event, "session_id": "rehearsal-session",
    }
    records = [dict(common, subtype="hook_started", uuid=hook_id + "-start")]
    for offset in range(progress):
        records.append(dict(
            common, subtype="hook_progress", uuid=f"{hook_id}-progress-{offset}",
            stdout="bounded rehearsal output", stderr="", output="bounded rehearsal output",
        ))
    records.append(dict(
        common, subtype="hook_response", uuid=hook_id + "-response",
        stdout="bounded rehearsal output", stderr="", output="bounded rehearsal output",
        outcome="success", exit_code=0,
    ))
    return records


if arm == "treatment":
    for event in (
        lifecycle("hook-pre", "opaque-pre-name", "PreToolUse")
        + lifecycle("hook-post", "opaque-post-name", "PostToolUse")
        + lifecycle("hook-fail", "opaque-fail-name", "PostToolUseFailure", progress=0)
    ):
        print(json.dumps(event, separators=(",", ":")), flush=True)

if not should_fail:
    for rel, content in sorted(solutions[task_id].items()):
        target = Path.cwd() / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

# 스크립트된 fake usage. provider 측정값이 아니며 절감 근거로 쓰일 수 없다.
digest = int(hashlib.sha256(
    f"{task_id}|{arm}|{slot['repetition']}|{slot['attempt']}".encode("utf-8")
).hexdigest()[:8], 16)
base_input = 4_000 + digest % 400
treatment_reduction = 900 if arm == "treatment" else 0
usage = {
    "input_tokens": base_input - treatment_reduction,
    "cache_creation_input_tokens": 120 + digest % 40,
    "cache_read_input_tokens": 60 + digest % 20,
    "output_tokens": 300 + digest % 60,
}
print(json.dumps({
    "type": "result",
    "subtype": "success",
    "is_error": False,
    "usage": usage,
    "total_cost_usd": 0.0,
}, separators=(",", ":")), flush=True)
log_env("audit_clean" if not AUDIT_VIOLATIONS else "audit_violation")
raise SystemExit(0 if not AUDIT_VIOLATIONS else 24)
'''


def sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_runner_module():
    import importlib.util

    spec = importlib.util.spec_from_file_location("s003_runner", CANONICAL_RUNNER)
    if spec is None or spec.loader is None:
        raise SystemExit("benchmark runner is not importable")
    module = importlib.util.module_from_spec(spec)
    sys.modules["s003_runner"] = module
    spec.loader.exec_module(module)
    return module


def prepare_inputs(*, suite: Path, output_root: Path, runner) -> dict:
    inputs = output_root / "inputs"
    inputs.mkdir(mode=0o700, parents=True)
    artifacts = output_root / "artifacts"
    artifacts.mkdir(mode=0o700)
    candidate_hash = sha256_path(CANONICAL_RUNNER)
    if candidate_hash != sha256_path(PACKAGED_RUNNER):
        raise SystemExit("canonical and packaged benchmark runners differ")
    plan = json.loads((suite / "study-plan.json").read_text(encoding="utf-8"))
    template = (suite / "variants.template.json").read_text(encoding="utf-8")
    variants_text = (
        template.replace("{{CANDIDATE_HASH}}", candidate_hash)
        .replace("{{NAMESPACE}}", str(plan["namespace"]))
        .replace("{{ARTIFACT_ROOT}}", str(artifacts))
    )
    variants = json.loads(variants_text)
    for variant in variants:
        measurement = variant["measurement"]
        measurement["environment"]["allow"] = ["PATH", "LANG"]
        measurement["environment"]["overrides"] = {
            "CG_S003_STATE": str(output_root / "fake-provider-state.jsonl"),
            "CG_S003_INDEX": str(inputs / "rehearsal-index.json"),
            "CG_S003_ENV_LOG": str(output_root / "fake-provider-env.jsonl"),
        }
    (inputs / "variants.json").write_text(
        json.dumps(variants, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    for name in ("baseline", "treatment"):
        shutil.copyfile(
            suite / "settings" / f"{name}.settings.json", inputs / f"{name}.settings.json",
        )
    tasks = runner.parse_tasks(suite / "tasks.json")
    runner.load_task_fixture_trees(tasks, task_file_dir=suite)
    solutions = json.loads(
        (suite / "rehearsal" / "solutions.json").read_text(encoding="utf-8")
    )["solutions"]
    missing = sorted({task.id for task in tasks} - set(solutions))
    if missing:
        raise SystemExit(f"rehearsal solutions are missing tasks: {', '.join(missing)}")
    (inputs / "rehearsal-index.json").write_text(
        json.dumps(
            {
                "prompt_sha256_to_task": {
                    hashlib.sha256(task.prompt.encode("utf-8")).hexdigest(): task.id
                    for task in tasks
                },
                "solutions": solutions,
                "scripted_retry_units": [list(unit) for unit in SCRIPTED_RETRY_UNITS],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    bin_dir = output_root / "bin"
    bin_dir.mkdir(mode=0o700)
    fake_cli = bin_dir / "fake-claude"
    fake_cli.write_text(FAKE_CLI, encoding="utf-8")
    os.chmod(fake_cli, 0o700)
    return {
        "candidate_hash": candidate_hash,
        "fake_cli": fake_cli,
        "inputs": inputs,
        "artifacts": artifacts,
        "plan": plan,
        "tasks": tasks,
    }


def bind_slot_identities(*, index_path: Path, manifest_path: Path) -> None:
    """Bind run_id -> (task, arm, repetition, attempt) so retries are exactly scripted."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    index = json.loads(index_path.read_text(encoding="utf-8"))
    index["run_id_to_unit"] = {
        str(slot["run_id"]): {
            "task_id": str(slot["task_id"]),
            "arm": str(slot["arm"]),
            "repetition": int(slot["repetition"]),
            "attempt": int(slot["attempt"]),
        }
        for slot in manifest["slots"]
    }
    index_path.write_text(json.dumps(index, sort_keys=True), encoding="utf-8")


def run_study_action(
    *, action: str, suite: Path, inputs: Path, study_root: Path, fake_cli: Path,
) -> tuple[int, float]:
    argv = [
        sys.executable,
        str(CANONICAL_RUNNER),
        "--tasks", str(suite / "tasks.json"),
        "--variants", str(inputs / "variants.json"),
        "--measurement-study-plan", str(suite / "study-plan.json"),
        "--measurement-study-action", action,
        "--measurement-study-output-root", str(study_root),
        "--claude-bin", str(fake_cli),
        "--project-root", str(suite),
    ]
    started = time.monotonic()
    proc = subprocess.run(argv, capture_output=True, text=True)
    elapsed = time.monotonic() - started
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout[-4000:])
        sys.stderr.write(proc.stderr[-4000:])
        raise SystemExit(f"rehearsal study action {action} failed: {proc.returncode}")
    return proc.returncode, elapsed


def summarize_attempts(attempts_path: Path) -> dict:
    initial = 0
    retries = 0
    classifications: dict[str, int] = {}
    states: dict[str, int] = {}
    per_arm: dict[str, dict[str, int]] = {"baseline": {}, "treatment": {}}
    for line in attempts_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        states[event["state"]] = states.get(event["state"], 0) + 1
        if event["state"] != "terminal":
            continue
        if int(event["attempt"]) == 0:
            initial += 1
        else:
            retries += 1
        label = str(event.get("terminal_classification", "unknown"))
        classifications[label] = classifications.get(label, 0) + 1
        arm = str(event["arm"])
        per_arm.setdefault(arm, {})
        per_arm[arm][label] = per_arm[arm].get(label, 0) + 1
    return {
        "terminal_initial_attempts": initial,
        "terminal_retry_attempts": retries,
        "terminal_classifications": dict(sorted(classifications.items())),
        "attempt_states": dict(sorted(states.items())),
        "terminal_classifications_by_arm": {
            arm: dict(sorted(values.items())) for arm, values in sorted(per_arm.items())
        },
    }


def audit_fake_provider_log(env_log: Path) -> dict:
    """Summarize the fake provider's own runtime evidence."""
    observed: set[str] = set()
    kinds: dict[str, int] = {}
    if env_log.exists():
        for line in env_log.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            observed.update(record.get("env", {}))
            kind = str(record.get("kind", "unknown"))
            kinds[kind] = kinds.get(kind, 0) + 1
    return {
        "credential_env_names_observed": sorted(observed & set(FORBIDDEN_ENV_NAMES)),
        "invocation_kinds": dict(sorted(kinds.items())),
    }


def attempt_order_projection(attempts_path: Path) -> list[list]:
    """Path-free ordered projection of the recorded schedule and outcomes."""
    projection: list[list] = []
    for line in attempts_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        projection.append([
            str(event["state"]),
            str(event["task_id"]),
            str(event["arm"]),
            int(event["repetition"]),
            int(event["attempt"]),
            str(event.get("terminal_classification", "")),
            bool(event.get("successful", False)),
            event.get("token_buckets"),
            event.get("reason"),
        ])
    return projection


# 아래 필드들은 run-local 절대 경로에서 유도되므로 서로 다른 output root 사이에서
# 같을 수 없다. 교차 비교에서는 자리표시자로 바꾸고, 동일 경로 재실행의 byte 동일성으로
# 따로 증명한다.
PATH_DERIVED_ANALYSIS_FIELDS = (
    "manifest_sha256",
    "observability.artifact_index_sha256",
    "observability.attempt_index_sha256",
    "observability.manifest_input_hashes.variants",
)


def normalized_analysis(study_report: dict, *, output_root: Path) -> dict:
    """Analysis output with run-local path-derived identity replaced.

    Everything else is determined by the frozen suite, plan, and scripted
    outcomes, so this projection is comparable across output roots.
    """
    placeholder = "<path-derived>"

    def scrub(value, path: str):
        if path in PATH_DERIVED_ANALYSIS_FIELDS:
            if isinstance(value, list):
                return [placeholder for _ in value]
            return placeholder
        if isinstance(value, dict):
            return {
                key: scrub(item, f"{path}.{key}" if path else key)
                for key, item in sorted(value.items())
            }
        if isinstance(value, list):
            return [scrub(item, path) for item in value]
        if isinstance(value, str):
            return value.replace(str(output_root), "<output-root>")
        return value

    return scrub(study_report, "")


def artifact_completeness(*, artifacts_root: Path, attempts_path: Path) -> dict:
    """Receipt/index completeness for every terminal attempt."""
    receipts = sorted(artifacts_root.glob("runs/*/receipt.json"))
    index_path = artifacts_root / "artifact-index.ndjson"
    index_rows = 0
    if index_path.exists():
        index_rows = len([
            line for line in index_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ])
    terminal_runs = set()
    receipt_bound = 0
    for line in attempts_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if event["state"] != "terminal":
            continue
        terminal_runs.add(str(event["run_id"]))
        receipt = artifacts_root / "runs" / str(event["run_id"]) / "receipt.json"
        if event.get("receipt_sha256") and receipt.is_file():
            digest = hashlib.sha256(receipt.read_bytes()).hexdigest()
            if digest == event["receipt_sha256"]:
                receipt_bound += 1
    return {
        "receipt_files": len(receipts),
        "artifact_index_rows": index_rows,
        "terminal_runs": len(terminal_runs),
        "terminal_attempts_with_verified_receipt": receipt_bound,
    }


def build_report(*, suite: Path, prepared: dict, study_root: Path, runner) -> dict:
    manifest_raw = (study_root / "study-manifest.json").read_bytes()
    manifest = json.loads(manifest_raw.decode("utf-8"))
    task_bindings = []
    for task in prepared["tasks"]:
        entries = task.fixture_tree_entries or ()
        checker = next(
            (entry for entry in entries if entry.path == task.success_checker), None,
        )
        task_bindings.append({
            "task_id": task.id,
            "prompt_sha256": hashlib.sha256(task.prompt.encode("utf-8")).hexdigest(),
            "fixture_tree_root": task.fixture_tree,
            "fixture_tree_sha256": runner.fixture_tree_sha256(entries),
            "fixture_tree_file_count": len(entries),
            "success_command": task.success_command,
            "success_checker_path": task.success_checker,
            "success_checker_sha256": (
                hashlib.sha256(checker.data).hexdigest() if checker is not None else None
            ),
        })
    summary = summarize_attempts(study_root / "attempts.jsonl")
    study_report = json.loads((study_root / "study-report.json").read_text(encoding="utf-8"))
    provider_log = audit_fake_provider_log(
        Path(json.loads(
            (prepared["inputs"] / "variants.json").read_text(encoding="utf-8")
        )[0]["measurement"]["environment"]["overrides"]["CG_S003_ENV_LOG"])
    )
    output_root = prepared["inputs"].parent
    order = attempt_order_projection(study_root / "attempts.jsonl")
    analysis = normalized_analysis(study_report, output_root=output_root)
    completeness = artifact_completeness(
        artifacts_root=prepared["artifacts"], attempts_path=study_root / "attempts.jsonl",
    )
    return {
        "schema_version": REHEARSAL_REPORT_SCHEMA,
        "claim_boundary": CLAIM_BOUNDARY,
        "deterministic": {
            "suite": {
                "tasks_sha256": sha256_path(suite / "tasks.json"),
                "study_plan_sha256": sha256_path(suite / "study-plan.json"),
                "variants_template_sha256": sha256_path(suite / "variants.template.json"),
                "baseline_settings_sha256": sha256_path(
                    suite / "settings/baseline.settings.json"
                ),
                "treatment_settings_sha256": sha256_path(
                    suite / "settings/treatment.settings.json"
                ),
                "task_count": len(prepared["tasks"]),
                "task_bindings": task_bindings,
            },
            "candidate": {
                "canonical_runner_sha256": prepared["candidate_hash"],
                "packaged_runner_sha256": sha256_path(PACKAGED_RUNNER),
            },
            "schedule": {
                "schedule_sha256": manifest["schedule_sha256"],
                "planned_units": len(manifest["slots"]),
                "expected_initial_attempts": 72,
            },
            "attempts": summary,
            "attempt_order_sha256": hashlib.sha256(json.dumps(
                order, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")).hexdigest(),
            "analysis_sha256": hashlib.sha256(json.dumps(
                analysis, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")).hexdigest(),
            "analysis_normalized_fields": list(PATH_DERIVED_ANALYSIS_FIELDS),
            "artifact_completeness": completeness,
            "runtime_audit": {
                "fake_provider_invocation_kinds": provider_log["invocation_kinds"],
                "audit_hook": "fail_closed_blocked_network_and_process_events_v1",
            },
            "scripted_retry_units": [list(unit) for unit in SCRIPTED_RETRY_UNITS],
            "study_report_verdict": study_report.get("verdict"),
            "zero_cost_evidence": {
                "provider_calls": 0,
                "network_calls": 0,
                "usd_spent": 0.0,
                "credential_env_names_observed": provider_log["credential_env_names_observed"],
                "fake_provider": True,
            },
            "not_evidence_of": [
                "provider-measured token savings",
                "provider-measured cost savings",
                "public or release claim readiness",
            ],
        },
        "declared_timestamps": {
            "note": "Timestamps and durations are declared non-deterministic fields.",
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output-root", required=True, type=Path,
                        help="private rehearsal output directory (must be new or empty)")
    parser.add_argument("--suite", default=DEFAULT_SUITE, type=Path,
                        help="real 12-task suite directory")
    parser.add_argument("--json", action="store_true", help="print the report to stdout")
    args = parser.parse_args(argv)

    suite = args.suite.resolve()
    output_root = args.output_root.resolve()
    if output_root.exists() and (
        output_root.is_symlink() or not output_root.is_dir() or any(output_root.iterdir())
    ):
        raise SystemExit("rehearsal output root must be new or empty")
    output_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(output_root, 0o700)

    runner = load_runner_module()
    started_at = time.time()
    prepared = prepare_inputs(suite=suite, output_root=output_root, runner=runner)
    study_root = output_root / "study"
    ledger_rows = []
    for action in ("prepare", "run", "analyze"):
        if action == "run":
            bind_slot_identities(
                index_path=prepared["inputs"] / "rehearsal-index.json",
                manifest_path=study_root / "study-manifest.json",
            )
        _, elapsed = run_study_action(
            action=action,
            suite=suite,
            inputs=prepared["inputs"],
            study_root=study_root,
            fake_cli=prepared["fake_cli"],
        )
        ledger_rows.append({
            "schema_version": OVERHEAD_LEDGER_SCHEMA,
            "phase": f"study_{action}",
            "wall_time_seconds": round(elapsed, 3),
            "provider_calls": 0,
            "usd_spent": 0.0,
            "cost_class": "local_engineering_overhead",
        })

    report = build_report(
        suite=suite, prepared=prepared, study_root=study_root, runner=runner,
    )
    report["declared_timestamps"].update({
        "started_at_unix": round(started_at, 3),
        "completed_at_unix": round(time.time(), 3),
        "total_wall_time_seconds": round(
            sum(row["wall_time_seconds"] for row in ledger_rows), 3,
        ),
    })
    deterministic_bytes = json.dumps(
        report["deterministic"], ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    report["deterministic_sha256"] = hashlib.sha256(deterministic_bytes).hexdigest()

    report_path = output_root / "rehearsal-report.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(report_path, 0o600)
    ledger_path = output_root / "overhead-ledger.jsonl"
    ledger_path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
            for row in ledger_rows
        ),
        encoding="utf-8",
    )
    os.chmod(ledger_path, 0o600)

    attempts = report["deterministic"]["attempts"]
    problems = []
    if attempts["terminal_initial_attempts"] != 72:
        problems.append(
            f"expected 72 terminal initial attempts, got {attempts['terminal_initial_attempts']}"
        )
    if attempts["terminal_retry_attempts"] != len(SCRIPTED_RETRY_UNITS):
        problems.append(
            "expected "
            f"{len(SCRIPTED_RETRY_UNITS)} scripted retry attempts, got "
            f"{attempts['terminal_retry_attempts']}"
        )
    if report["deterministic"]["zero_cost_evidence"]["credential_env_names_observed"]:
        problems.append("credential-shaped environment names reached the fake provider")
    expected_terminal = 72 + len(SCRIPTED_RETRY_UNITS)
    kinds = report["deterministic"]["runtime_audit"]["fake_provider_invocation_kinds"]
    if kinds.get("audit_violation"):
        problems.append("fake provider recorded a blocked non-local operation")
    if kinds.get("audit_clean") != expected_terminal:
        problems.append(
            f"expected {expected_terminal} clean fake-provider audits, got "
            f"{kinds.get('audit_clean')}"
        )
    completeness = report["deterministic"]["artifact_completeness"]
    if completeness["terminal_runs"] != expected_terminal:
        problems.append(
            f"expected {expected_terminal} terminal runs, got {completeness['terminal_runs']}"
        )
    for key in ("receipt_files", "artifact_index_rows", "terminal_attempts_with_verified_receipt"):
        if completeness[key] != expected_terminal:
            problems.append(
                f"expected {expected_terminal} {key}, got {completeness[key]}"
            )
    if args.json:
        print(json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2))
    else:
        print(f"rehearsal report: {report_path}")
        print(f"overhead ledger: {ledger_path}")
        print(f"deterministic_sha256: {report['deterministic_sha256']}")
        print(
            "initial attempts: "
            f"{attempts['terminal_initial_attempts']}, retries: "
            f"{attempts['terminal_retry_attempts']}"
        )
    for problem in problems:
        sys.stderr.write(f"rehearsal problem: {problem}\n")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
