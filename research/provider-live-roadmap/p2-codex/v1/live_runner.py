"""One-use Codex subscription measurement over the frozen G5 schedule.

The runner reuses the already authenticated public pack/schedule machinery but
has a separate Codex JSONL observer. Direct mutable execution is unavailable.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import stat
import subprocess
import sys
import time
import types
from typing import Callable, Mapping


SCHEMA = "contextguard.p2-codex-subscription-live-contract/v1"
EVIDENCE_SCHEMA = "contextguard.p2-codex-subscription-live-evidence/v1"
MAX_CODEX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_CODEX_STDERR_BYTES = 64 * 1024
MAX_ANSWER_BYTES = 256
BASE_RUNNER_RELATIVE = Path("research/provider-live-roadmap/p2/v1/live_runner.py")
BASE_CONTRACT_RELATIVE = Path("research/provider-live-roadmap/p2/v1/contract.json")
EXPECTED_BASE = {
    "contract_sha256": "8c38cc3d61fd79003b56fc3357334fd22b0aea72739f3b66e41ad07b6d16a9c0",
    "runner_sha256": "ec201cb9f8cb931131875218aa02c606899e75aa15ebc9eac6b07398eb597e28",
}
EXPECTED_APPROVAL = {
    "module_sha256": "809405655f7b171f7b564f5ad381ae88237e325e1fe3a7e2bbb9f1442d20c6d0",
    "schema_sha256": "c535d464311d9f7dd5b326face7596e6b930da4fb3e0350a5d3e0942e735eb69",
}
EXPECTED_PROVIDER = {
    "auth_method": "chatgpt",
    "id": "openai-codex-subscription",
    "model_id": "gpt-5.6-luna",
    "reasoning_effort": "low",
}
EXPECTED_LIMITS = {
    "call_cap": 240,
    "timeout_seconds": 180,
    "unexpected_direct_spend_cap_usd": "0.01",
}
EXPECTED_USAGE_SEMANTICS = {
    "cache_write_input_is_subset_of_input": True,
    "cached_input_is_subset_of_input": True,
    "provider_total_formula": "input_tokens + output_tokens",
    "reasoning_output_is_subset_of_output": True,
    "subscription_quota_conversion": "unavailable",
}
DISABLED_FEATURES = [
    "apps",
    "auth_elicitation",
    "browser_use",
    "browser_use_external",
    "browser_use_full_cdp_access",
    "code_mode_host",
    "computer_use",
    "goals",
    "guardian_approval",
    "hooks",
    "image_generation",
    "in_app_browser",
    "multi_agent",
    "plugin_sharing",
    "plugins",
    "remote_plugin",
    "shell_snapshot",
    "shell_tool",
    "skill_mcp_dependency_install",
    "skill_search",
    "tool_call_mcp_elicitation",
    "tool_suggest",
    "unified_exec",
    "workspace_dependencies",
]
EXPECTED_RUNTIME = {
    "cli_version": "0.146.0",
    "disabled_features": DISABLED_FEATURES,
    "ephemeral": True,
    "ignore_rules": True,
    "ignore_user_config": True,
    "native_executable_sha256": "ae1d3ffe6d48aec6a4dc3f50e7eb8e0d11962485a6a9406c5a7012139383da02",
    "sandbox": "read-only",
    "tools": "prohibited_and_excluded_if_observed",
}
EXPECTED_DESTINATIONS = [
    {"host": "api.openai.com", "port": 443, "scheme": "https"},
    {"host": "auth.openai.com", "port": 443, "scheme": "https"},
    {"host": "chatgpt.com", "port": 443, "scheme": "https"},
]


class CodexLiveError(RuntimeError):
    """Value-free refusal from the Codex subscription runner."""


def refuse(code: str) -> None:
    raise CodexLiveError(code)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        refuse("noncanonical_value")


def duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            refuse("duplicate_json_key")
        result[key] = value
    return result


def parse_json(raw: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=duplicate_keys,
            parse_constant=lambda _value: refuse("nonfinite_json_value"),
        )
    except CodexLiveError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        refuse(f"invalid_{label}")
    if type(value) is not dict:
        refuse(f"invalid_{label}")
    return value


def _exact(value: object, keys: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        refuse(f"invalid_{label}")
    return value


def _read_bound(path: Path, expected_sha256: str, label: str) -> bytes:
    try:
        if path.is_symlink():
            refuse(f"changed_{label}")
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            refuse(f"changed_{label}")
        raw = path.read_bytes()
    except OSError:
        refuse(f"changed_{label}")
    if sha256(raw) != expected_sha256:
        refuse(f"changed_{label}")
    return raw


def _load_module(raw: bytes, expected_sha256: str, name: str) -> types.ModuleType:
    if sha256(raw) != expected_sha256:
        refuse("changed_module")
    module = types.ModuleType(name)
    module.__file__ = f"<captured-{name}>"
    sys.modules[name] = module
    exec(compile(raw, module.__file__, "exec"), module.__dict__, module.__dict__)
    return module


def load_base(contract: dict[str, object], *, repo_root: Path) -> types.ModuleType:
    declared = _exact(
        contract.get("base_measurement"),
        {"contract_sha256", "runner_sha256"},
        "base_measurement",
    )
    if declared != EXPECTED_BASE:
        refuse("invalid_base_measurement")
    runner_raw = _read_bound(
        repo_root / BASE_RUNNER_RELATIVE,
        declared["runner_sha256"],
        "base_runner",
    )
    base = _load_module(runner_raw, declared["runner_sha256"], "captured_codex_p2_base")
    contract_raw = _read_bound(
        repo_root / BASE_CONTRACT_RELATIVE,
        declared["contract_sha256"],
        "base_contract",
    )
    base_contract = base.parse_json(contract_raw, "base_contract")
    try:
        base.validate_contract(base_contract, repo_root=repo_root)
    except Exception:
        refuse("invalid_base_measurement")
    base.CAPTURED_CONTRACT_RAW = contract_raw
    base.CAPTURED_CONTRACT = base_contract
    return base


def validate_contract(contract: dict[str, object], *, repo_root: Path) -> None:
    top = _exact(
        contract,
        {
            "approval_boundary",
            "base_measurement",
            "claims",
            "destination_allowlist",
            "limits",
            "observer",
            "operation",
            "provider",
            "runtime",
            "safety",
            "schema_version",
            "source_candidate",
            "status",
            "usage_semantics",
        },
        "contract",
    )
    if top["schema_version"] != SCHEMA:
        refuse("invalid_contract")
    if top["approval_boundary"] != EXPECTED_APPROVAL:
        refuse("invalid_approval_boundary")
    if top["base_measurement"] != EXPECTED_BASE:
        refuse("invalid_base_measurement")
    if top["provider"] != EXPECTED_PROVIDER:
        refuse("invalid_provider")
    if top["limits"] != EXPECTED_LIMITS:
        refuse("invalid_limits")
    if top["usage_semantics"] != EXPECTED_USAGE_SEMANTICS:
        refuse("invalid_usage_semantics")
    if top["runtime"] != EXPECTED_RUNTIME:
        refuse("invalid_runtime")
    if top["destination_allowlist"] != EXPECTED_DESTINATIONS:
        refuse("invalid_destination")
    if top["observer"] != {
        "id": "codex-exec-jsonl-v1",
        "phase": "P2",
        "schema": "contextguard.g5-authoritative-observation/v1",
        "surface": "codex-exec-jsonl/v1",
    }:
        refuse("invalid_observer")
    if top["operation"] != {
        "receipt_schema": "contextguard.g5-authoritative-observation/v1",
        "surface": "p2-g5-fixed-schedule-codex-subscription-shadow",
        "version": "v1",
    }:
        refuse("invalid_operation")
    if top["claims"] != {
        "activation": False,
        "cross_provider_equivalence": False,
        "generalization": False,
        "production_readiness": False,
        "provider_cost_savings": False,
        "subscription_quota_savings": False,
        "token_savings": False,
    }:
        refuse("invalid_claims")
    if top["safety"] != {
        "network_redirects": False,
        "network_proxies": False,
        "output_mode": "owner_private",
        "raw_content_publication": False,
        "retention_seconds": 604800,
        "scorer_load_after_all_calls": True,
    }:
        refuse("invalid_safety")
    if top["source_candidate"] != {
        "artifact_ids": ["9163551917", "9163551685"],
        "checksums_sha256": "a20f2fc93bfa0e2774f8288eb9d31e9c83c962a816a65cfb829351610e7c5efb",
        "commit_sha": "540c6e02222f25346ca9c797197882cebbe5331d",
        "manifest_sha256": "149d26383663f57a5bac2f79f52acb53ed8b3f8a7675176557120dd3ec353050",
    }:
        refuse("invalid_source_candidate")
    if top["status"] != "prepared_requires_new_one_use_network_and_auth_approval":
        refuse("invalid_status")
    _read_bound(
        repo_root
        / "packages/context-guard-receipt/python/context_guard_receipt/external_approval.py",
        EXPECTED_APPROVAL["module_sha256"],
        "approval_module",
    )
    _read_bound(
        repo_root / "packages/context-guard-receipt/schemas/external-approval.schema.json",
        EXPECTED_APPROVAL["schema_sha256"],
        "approval_schema",
    )
    load_base(contract, repo_root=repo_root)


def _jsonl_object(raw: bytes) -> dict[str, object]:
    return parse_json(raw, "codex_event")


def parse_codex_jsonl(raw: bytes) -> dict[str, object]:
    if not raw or len(raw) > MAX_CODEX_OUTPUT_BYTES or not raw.endswith(b"\n"):
        refuse("provider_output_limit")
    events: list[dict[str, object]] = []
    for line in raw.splitlines():
        if not line or len(line) > MAX_CODEX_OUTPUT_BYTES:
            refuse("provider_result_unavailable")
        events.append(_jsonl_object(line))
    if len(events) < 4:
        refuse("provider_result_unavailable")

    thread_count = 0
    turn_started_count = 0
    turn_completed: dict[str, object] | None = None
    answers: list[str] = []
    for index, event in enumerate(events):
        event_type = event.get("type")
        if event_type == "thread.started":
            thread_count += 1
            if index != 0:
                refuse("provider_result_unavailable")
        elif event_type == "turn.started":
            turn_started_count += 1
            if index != 1:
                refuse("provider_result_unavailable")
        elif event_type in {"item.started", "item.completed"}:
            item = event.get("item")
            item_type = item.get("type") if type(item) is dict else None
            if item_type not in {"agent_message", "reasoning"}:
                refuse("tool_usage_observed")
            if event_type == "item.completed" and item_type == "agent_message":
                text = item.get("text")
                if not isinstance(text, str):
                    refuse("provider_result_unavailable")
                answers.append(text)
        elif event_type == "turn.completed":
            if turn_completed is not None or index != len(events) - 1:
                refuse("provider_result_unavailable")
            turn_completed = event
        else:
            refuse("provider_result_unavailable")
    if thread_count != 1 or turn_started_count != 1 or turn_completed is None:
        refuse("provider_result_unavailable")
    if len(answers) != 1:
        refuse("provider_result_unavailable")
    answer = answers[0].strip()
    if not answer or len(answer.encode("utf-8")) > MAX_ANSWER_BYTES:
        refuse("provider_result_unavailable")

    usage = _exact(
        turn_completed.get("usage"),
        {
            "cache_write_input_tokens",
            "cached_input_tokens",
            "input_tokens",
            "output_tokens",
            "reasoning_output_tokens",
        },
        "provider_usage",
    )
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in usage.values()
    ):
        refuse("provider_usage_unavailable")
    input_tokens = usage["input_tokens"]
    cached = usage["cached_input_tokens"]
    cache_write = usage["cache_write_input_tokens"]
    output_tokens = usage["output_tokens"]
    reasoning = usage["reasoning_output_tokens"]
    if cached + cache_write > input_tokens or reasoning > output_tokens:
        refuse("provider_usage_unavailable")
    return {
        "answer": answer,
        "usage": {
            "cache_write_input_tokens": cache_write,
            "cached_input_tokens": cached,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "provider_total_tokens": input_tokens + output_tokens,
            "reasoning_output_tokens": reasoning,
            "uncached_nonwrite_input_tokens": input_tokens - cached - cache_write,
        },
    }


def codex_argv(
    executable: Path, *, contract: dict[str, object], cwd: Path,
) -> list[str]:
    argv = [
        str(executable),
        "exec",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--strict-config",
        "--skip-git-repo-check",
        "--sandbox",
        "read-only",
        "--model",
        contract["provider"]["model_id"],
        "--json",
        "-c",
        'approval_policy="never"',
        "-c",
        f'model_reasoning_effort="{contract["provider"]["reasoning_effort"]}"',
        "-c",
        "shell_environment_policy.inherit=none",
        "-c",
        'web_search="disabled"',
    ]
    for feature in contract["runtime"]["disabled_features"]:
        argv.extend(("--disable", feature))
    argv.extend([
        "-C",
        str(cwd),
        "-",
    ])
    return argv


def build_codex_environment(
    tmpdir: Path, *, home: Path, codex_home: Path,
) -> dict[str, str]:
    if not all(path.is_absolute() for path in (tmpdir, home, codex_home)):
        refuse("runtime_environment_unavailable")
    return {
        "CODEX_HOME": str(codex_home),
        "HOME": str(home),
        "LANG": "C",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(tmpdir),
    }


def source_codex_auth_path() -> Path:
    configured = os.environ.get("CODEX_HOME")
    if configured:
        codex_home = Path(configured)
    else:
        inherited_home = os.environ.get("HOME", "")
        if not inherited_home:
            refuse("chatgpt_auth_unavailable")
        codex_home = Path(inherited_home) / ".codex"
    if not codex_home.is_absolute():
        refuse("chatgpt_auth_unavailable")
    return codex_home / "auth.json"


def _prepare_private_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, exist_ok=True)
        metadata = path.stat()
    except OSError:
        refuse("chatgpt_auth_unavailable")
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.geteuid()
    ):
        refuse("chatgpt_auth_unavailable")


def prepare_isolated_codex_home(
    *, source_auth: Path, home: Path, codex_home: Path,
) -> Path:
    """Link saved auth into an otherwise isolated CLI home without reading it."""

    if not all(path.is_absolute() for path in (source_auth, home, codex_home)):
        refuse("chatgpt_auth_unavailable")
    try:
        source_metadata = source_auth.lstat()
    except OSError:
        refuse("chatgpt_auth_unavailable")
    if (
        not stat.S_ISREG(source_metadata.st_mode)
        or source_metadata.st_nlink != 1
        or source_metadata.st_uid != os.geteuid()
        or not (source_metadata.st_mode & stat.S_IRUSR)
        or source_metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
    ):
        refuse("chatgpt_auth_unavailable")
    _prepare_private_directory(home)
    _prepare_private_directory(codex_home)
    auth_link = codex_home / "auth.json"
    try:
        os.symlink(str(source_auth), auth_link)
        link_metadata = auth_link.lstat()
    except OSError:
        refuse("chatgpt_auth_unavailable")
    if not stat.S_ISLNK(link_metadata.st_mode):
        refuse("chatgpt_auth_unavailable")
    return auth_link


def remove_isolated_auth_link(auth_link: Path) -> None:
    try:
        metadata = auth_link.lstat()
    except FileNotFoundError:
        return
    except OSError:
        refuse("auth_cleanup_unavailable")
    if not stat.S_ISLNK(metadata.st_mode):
        refuse("auth_cleanup_unavailable")
    try:
        auth_link.unlink()
    except OSError:
        refuse("auth_cleanup_unavailable")


def validate_login_status(*, returncode: int, stdout: bytes, stderr: bytes) -> None:
    if (
        returncode != 0
        or len(stdout) > 4096
        or len(stderr) > 4096
        or stdout
        or stderr != b"Logged in using ChatGPT\n"
    ):
        refuse("chatgpt_auth_unavailable")


def _native_from_launcher(launcher: Path) -> Path:
    resolved = launcher.resolve(strict=True)
    if resolved.name != "codex.js":
        return resolved
    if sys.platform != "darwin" or platform.machine() != "arm64":
        refuse("runtime_unavailable")
    return (
        resolved.parents[1]
        / "node_modules/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/bin/codex"
    )


def resolve_codex_runtime(
    contract: dict[str, object], *, environment: dict[str, str],
    executable: Path | None = None,
) -> tuple[Path, str]:
    candidate = executable
    if candidate is None:
        found = shutil.which("codex")
        if found is None:
            refuse("runtime_unavailable")
        candidate = Path(found)
    try:
        candidate = _native_from_launcher(candidate)
    except OSError:
        refuse("runtime_unavailable")
    try:
        candidate = candidate.resolve(strict=True)
        metadata = candidate.stat()
        if (
            candidate.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
        ):
            refuse("runtime_unavailable")
        digest = sha256(candidate.read_bytes())
    except OSError:
        refuse("runtime_unavailable")
    if digest != contract["runtime"]["native_executable_sha256"]:
        refuse("runtime_identity_mismatch")
    try:
        result = subprocess.run(
            [str(candidate), "--version"],
            cwd="/tmp",
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        refuse("runtime_unavailable")
    if (
        result.returncode != 0
        or result.stdout != f"codex-cli {contract['runtime']['cli_version']}\n".encode("ascii")
        or result.stderr
    ):
        refuse("runtime_version_mismatch")
    return candidate, digest


def capture_runtime_copy(
    source: Path, *, contract: dict[str, object], runtime_root: Path,
) -> Path:
    """Copy the verified native runtime into a private, single-link inode."""

    try:
        runtime_root.mkdir(mode=0o700)
        root_metadata = runtime_root.stat()
        if (
            runtime_root.is_symlink()
            or not stat.S_ISDIR(root_metadata.st_mode)
            or stat.S_IMODE(root_metadata.st_mode) != 0o700
            or root_metadata.st_uid != os.geteuid()
        ):
            refuse("runtime_capture_unavailable")
        source_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        source_fd = os.open(source, source_flags)
    except (OSError, CodexLiveError):
        refuse("runtime_capture_unavailable")
    captured = runtime_root / "codex"
    destination_fd: int | None = None
    digest = hashlib.sha256()
    try:
        source_metadata = os.fstat(source_fd)
        if not stat.S_ISREG(source_metadata.st_mode) or source_metadata.st_nlink != 1:
            refuse("runtime_capture_unavailable")
        destination_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
        )
        destination_fd = os.open(captured, destination_flags, 0o500)
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    refuse("runtime_capture_unavailable")
                view = view[written:]
        os.fchmod(destination_fd, 0o500)
        os.fsync(destination_fd)
    except (OSError, CodexLiveError):
        refuse("runtime_capture_unavailable")
    finally:
        os.close(source_fd)
        if destination_fd is not None:
            os.close(destination_fd)
    if digest.hexdigest() != contract["runtime"]["native_executable_sha256"]:
        refuse("runtime_identity_mismatch")
    try:
        directory_fd = os.open(runtime_root, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        metadata = captured.stat()
    except OSError:
        refuse("runtime_capture_unavailable")
    if (
        captured.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o500
        or metadata.st_uid != os.geteuid()
    ):
        refuse("runtime_capture_unavailable")
    return captured


def _approval_plan_sha256(
    *, base: types.ModuleType, contract: dict[str, object], executable: Path,
    workspace: Path, plan: list[dict[str, object]],
) -> str:
    projection = [
        {
            "argv": codex_argv(executable, contract=contract, cwd=workspace),
            "payload_sha256": item["payload_sha256"],
            "request_id": item["request_id"],
        }
        for item in plan
    ]
    return sha256(b"contextguard.p2-codex-subscription-argv-plan/v1\0" + base.canonical(projection))


def build_approval_scope(
    *, contract: dict[str, object], base: types.ModuleType, executable: Path,
    executable_sha256: str, environment: dict[str, str], output_root: Path,
    workspace: Path, plan: list[dict[str, object]],
) -> dict[str, object]:
    if not output_root.is_absolute() or not workspace.is_absolute():
        refuse("output_unavailable")
    return {
        "source_candidate": copy.deepcopy(contract["source_candidate"]),
        "provider": {
            "provider_id": contract["provider"]["id"],
            "model_id": contract["provider"]["model_id"],
        },
        "observer": {
            "observer_id": contract["observer"]["id"],
            "phase": contract["observer"]["phase"],
            "receipt_schema": contract["observer"]["schema"],
            "surface_id": contract["observer"]["surface"],
        },
        "operation": {
            "receipt_schema": contract["operation"]["receipt_schema"],
            "surface_id": contract["operation"]["surface"],
            "version": contract["operation"]["version"],
        },
        "runtime": {
            "argv_sha256": _approval_plan_sha256(
                base=base,
                contract=contract,
                executable=executable,
                workspace=workspace,
                plan=plan,
            ),
            "environment_sha256": sha256(canonical(environment)),
            "executable_sha256": executable_sha256,
            "identity": "codex-cli-native",
            "version": contract["runtime"]["cli_version"],
        },
        "credential": {
            "consumer_id": "codex-cli-chatgpt-session",
            "scope_allowlist": ["provider:model.invoke"],
        },
        "destinations": copy.deepcopy(contract["destination_allowlist"]),
        "network_policy": {"proxies_allowed": False, "redirects_allowed": False},
        "limits": {
            "call_cap": contract["limits"]["call_cap"],
            "currency": "USD",
            "spend_cap": contract["limits"]["unexpected_direct_spend_cap_usd"],
            "timeout_seconds": contract["limits"]["timeout_seconds"],
        },
        "output": {"mode": "owner_private", "root": str(output_root)},
        "retention": {"seconds": contract["safety"]["retention_seconds"]},
    }


def invoke_codex(
    item: dict[str, object], *, contract: dict[str, object], executable: Path,
    environment: dict[str, str], cwd: Path,
) -> bytes:
    argv = codex_argv(executable, contract=contract, cwd=cwd)
    prompt = item.get("prompt")
    if not isinstance(prompt, str):
        refuse("payload_unavailable")
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(
                input=prompt.encode("utf-8"),
                timeout=contract["limits"]["timeout_seconds"],
            )
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                process.kill()
            process.wait()
            refuse("timeout")
    except CodexLiveError:
        raise
    except OSError:
        refuse("transport_error")
    if len(stdout) > MAX_CODEX_OUTPUT_BYTES or len(stderr) > MAX_CODEX_STDERR_BYTES:
        refuse("transport_error")
    if process.returncode != 0:
        refuse("transport_error")
    return stdout


def _empty_token_usage() -> dict[str, int]:
    return {
        "cache_write_input_tokens": 0,
        "cached_input_tokens": 0,
        "completed_calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "provider_total_tokens": 0,
        "reasoning_output_tokens": 0,
        "uncached_nonwrite_input_tokens": 0,
    }


def execute_schedule(
    *, contract: dict[str, object], schedule: dict[str, object],
    observation_schema_bytes: bytes, tasks: Mapping[str, dict[str, object]],
    packs: Mapping[tuple[str, str], dict[str, object]], output_root: Path,
    invoke: Callable[[dict[str, object]], bytes], scorer_loader: Callable[[], object],
    repo_root: Path,
) -> dict[str, object]:
    base = load_base(contract, repo_root=repo_root)
    base._private_root(output_root)
    plan = base.build_request_plan(
        contract=contract, schedule=schedule, tasks=tasks, packs=packs
    )
    provisional: list[dict[str, object]] = []
    answers: list[str | None] = []
    sealed_runs: list[dict[str, object]] = []
    totals = _empty_token_usage()
    model_id = contract["provider"]["model_id"]

    for item in plan:
        pack_started = time.monotonic_ns()
        prompt = base._prompt(
            tasks[item["task_id"]], packs[(item["task_id"], item["arm"])]["rendered_pack"]
        )
        pack_finished = time.monotonic_ns()
        if sha256(prompt.encode("utf-8")) != item["payload_sha256"]:
            refuse("payload_identity_mismatch")
        live_item = dict(item, prompt=prompt)
        completed = True
        exclusion = "none"
        parsed: dict[str, object] | None = None
        raw = b""
        try:
            raw = invoke(live_item)
            parsed = parse_codex_jsonl(raw)
        except CodexLiveError as exc:
            completed = False
            code = exc.args[0] if exc.args else "transport_error"
            if code in {"timeout", "transport_error"}:
                exclusion = code
            elif code in {
                "tool_usage_observed",
                "provider_result_unavailable",
                "provider_usage_unavailable",
            }:
                exclusion = "malformed_required_field"
            else:
                exclusion = "transport_error"
        answer = parsed["answer"] if parsed is not None else None
        answers.append(answer)
        usage = parsed["usage"] if parsed is not None else None
        if usage is not None:
            totals["completed_calls"] += 1
            for key in totals:
                if key != "completed_calls":
                    totals[key] += usage[key]
        sealed_core = {
            "model_ids": [model_id] if parsed is not None else [],
            "payload_sha256": item["payload_sha256"],
            "request_id": item["request_id"],
            "response_bytes": len(raw),
            "response_sha256": sha256(raw),
            "scheduled_unit_id": item["scheduled_unit_id"],
            "usage": copy.deepcopy(usage),
        }
        sealed_runs.append(
            {**sealed_core, "seal_sha256": sha256(canonical(sealed_core))}
        )
        receipt_id = "receipt-" + sha256(
            canonical(
                {"request_id": item["request_id"], "response_sha256": sha256(raw)}
            )
        )
        provisional.append(
            {
                "schema_version": "contextguard.g5-authoritative-observation/v1",
                "observer_version": "contextguard.g5-minimized-observer/v1",
                **{
                    key: item[key]
                    for key in (
                        "scheduled_unit_id",
                        "block_id",
                        "task_id",
                        "lineage_id",
                        "partition",
                        "stratum",
                        "arm",
                        "assigned_order",
                        "repetition",
                        "assignment_id",
                        "payload_sha256",
                        "request_id",
                    )
                },
                "receipt_id": receipt_id,
                "model_identity": model_id,
                "unit_status": "completed" if completed else "excluded",
                "completion_event": "normal_completion" if completed else exclusion,
                "event_count": 1,
                "pack_start_monotonic_ns": pack_started,
                "pack_end_monotonic_ns": pack_finished,
                "correctness": {
                    "availability": "unavailable",
                    "outcome": "unavailable",
                    "unavailable_reason": "not_observed" if completed else "excluded_unit",
                },
                "input_usage": base._metric(
                    usage["input_tokens"] if usage else None, completed=completed
                ),
                "output_usage": base._metric(
                    usage["output_tokens"] if usage else None, completed=completed
                ),
                "correction_count": base._metric(0 if parsed else None, completed=completed),
                "correction_tokens": base._metric(0 if parsed else None, completed=completed),
                "retrieval_count": base._metric(0 if parsed else None, completed=completed),
                "retrieval_bytes": base._metric(0 if parsed else None, completed=completed),
                "retrieval_tokens": base._metric(0 if parsed else None, completed=completed),
                "billing_receipt": {
                    "authority": "unavailable",
                    "reference": None,
                    "status": "unavailable",
                },
                "cost_components": base._cost_components(completed=completed),
                "exclusion_reason": "none" if completed else exclusion,
                "audit_status": "eligible" if completed else "excluded",
            }
        )

    if len(sealed_runs) != 240:
        refuse("incomplete_schedule")
    scorer = scorer_loader()
    expected_answers = scorer.get("answers") if type(scorer) is dict and "answers" in scorer else scorer
    if type(expected_answers) is not dict or set(expected_answers) != set(tasks):
        refuse("invalid_scorer")
    for observation, answer in zip(provisional, answers, strict=True):
        if observation["unit_status"] != "completed":
            continue
        expected = expected_answers.get(observation["task_id"])
        if not isinstance(expected, str):
            refuse("invalid_scorer")
        observation["correctness"] = {
            "availability": "observed",
            "outcome": "correct" if answer == expected else "incorrect",
            "unavailable_reason": "not_applicable",
        }
    base_contract = base.CAPTURED_CONTRACT
    schedule_raw = _read_bound(
        repo_root / "research/provider-free-roadmap/g5/v1/schedule.json",
        base_contract["g5"]["schedule_sha256"],
        "g5_schedule",
    )
    summary = base.summarize_with_frozen_g5(
        provisional,
        schedule_bytes=schedule_raw,
        schema_bytes=observation_schema_bytes,
        repo_root=repo_root,
    )
    return {
        "observations": provisional,
        "request_plan_sha256": base.request_plan_sha256(plan),
        "sealed_runs": sealed_runs,
        "summary": summary,
        "token_usage": totals,
    }


_FORBIDDEN_PUBLIC_KEYS = frozenset(
    {
        "answer",
        "authorization",
        "credential",
        "environment",
        "headers",
        "home",
        "prompt",
        "raw",
        "response",
        "result",
        "session_id",
        "token",
        "url",
    }
)


def _recursive_keys(value: object) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            keys.add(str(key).lower())
            keys.update(_recursive_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.update(_recursive_keys(child))
    return keys


def build_public_evidence(
    *, contract_raw: bytes, execution: dict[str, object],
    phase_records: dict[str, dict[str, object]],
    phase_results: dict[str, dict[str, object]], executable_sha256: str,
) -> dict[str, object]:
    return {
        "schema_version": EVIDENCE_SCHEMA,
        "authority": {"activation": False, "claim": False, "runtime_mutation": False},
        "auth_method": "chatgpt",
        "base_measurement": copy.deepcopy(EXPECTED_BASE),
        "call_count": len(execution["sealed_runs"]),
        "contract_sha256": sha256(contract_raw),
        "executable_sha256": executable_sha256,
        "g5_summary": copy.deepcopy(execution["summary"]),
        "model_id": EXPECTED_PROVIDER["model_id"],
        "observations": copy.deepcopy(execution["observations"]),
        "p2_phase_records": copy.deepcopy(phase_records),
        "p2_phase_results": copy.deepcopy(phase_results),
        "provider_cost": {
            "availability": "unavailable",
            "currency": None,
            "reason": "chatgpt_subscription_has_no_per_request_billing_receipt",
            "value": None,
        },
        "request_plan_sha256": execution["request_plan_sha256"],
        "sealed_runs": copy.deepcopy(execution["sealed_runs"]),
        "token_usage": copy.deepcopy(execution["token_usage"]),
    }


def validate_public_evidence(
    evidence: dict[str, object], *, contract_raw: bytes, repo_root: Path,
) -> None:
    expected_keys = {
        "auth_method",
        "authority",
        "base_measurement",
        "call_count",
        "contract_sha256",
        "executable_sha256",
        "g5_summary",
        "model_id",
        "observations",
        "p2_phase_records",
        "p2_phase_results",
        "provider_cost",
        "request_plan_sha256",
        "schema_version",
        "sealed_runs",
        "token_usage",
    }
    if type(evidence) is not dict or set(evidence) != expected_keys:
        refuse("invalid_public_evidence")
    if _FORBIDDEN_PUBLIC_KEYS & _recursive_keys(evidence):
        refuse("private_surface_in_public_evidence")
    if (
        evidence["schema_version"] != EVIDENCE_SCHEMA
        or evidence["contract_sha256"] != sha256(contract_raw)
        or evidence["auth_method"] != "chatgpt"
        or evidence["base_measurement"] != EXPECTED_BASE
        or evidence["model_id"] != EXPECTED_PROVIDER["model_id"]
        or evidence["call_count"] != 240
        or evidence["authority"]
        != {"activation": False, "claim": False, "runtime_mutation": False}
        or evidence["provider_cost"]
        != {
            "availability": "unavailable",
            "currency": None,
            "reason": "chatgpt_subscription_has_no_per_request_billing_receipt",
            "value": None,
        }
    ):
        refuse("invalid_public_evidence")
    observations = evidence["observations"]
    sealed_runs = evidence["sealed_runs"]
    if (
        not isinstance(observations, list)
        or len(observations) != 240
        or not isinstance(sealed_runs, list)
        or len(sealed_runs) != 240
    ):
        refuse("invalid_public_evidence")
    observation_ids = [row.get("scheduled_unit_id") for row in observations]
    sealed_ids = [row.get("scheduled_unit_id") for row in sealed_runs]
    if observation_ids != sealed_ids or len(set(observation_ids)) != 240:
        refuse("public_evidence_identity_mismatch")
    totals = _empty_token_usage()
    for sealed in sealed_runs:
        if type(sealed) is not dict or set(sealed) != {
            "model_ids",
            "payload_sha256",
            "request_id",
            "response_bytes",
            "response_sha256",
            "scheduled_unit_id",
            "seal_sha256",
            "usage",
        }:
            refuse("invalid_public_evidence_seal")
        core = {key: value for key, value in sealed.items() if key != "seal_sha256"}
        if sealed["seal_sha256"] != sha256(canonical(core)):
            refuse("invalid_public_evidence_seal")
        usage = sealed["usage"]
        if usage is not None:
            if type(usage) is not dict or set(usage) != set(totals) - {"completed_calls"}:
                refuse("invalid_public_evidence_seal")
            totals["completed_calls"] += 1
            for key in usage:
                value = usage[key]
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    refuse("invalid_public_evidence_seal")
                totals[key] += value
    if evidence["token_usage"] != totals:
        refuse("public_evidence_usage_mismatch")
    contract = parse_json(contract_raw, "contract")
    validate_contract(contract, repo_root=repo_root)
    base = load_base(contract, repo_root=repo_root)
    base_contract = base.CAPTURED_CONTRACT
    schedule_raw = _read_bound(
        repo_root / "research/provider-free-roadmap/g5/v1/schedule.json",
        base_contract["g5"]["schedule_sha256"],
        "g5_schedule",
    )
    schema_raw = _read_bound(
        repo_root
        / "research/provider-free-roadmap/g5/v1/schemas/authoritative-observation.schema.json",
        base_contract["g5"]["observation_schema_sha256"],
        "g5_observation_schema",
    )
    recomputed = base.summarize_with_frozen_g5(
        observations,
        schedule_bytes=schedule_raw,
        schema_bytes=schema_raw,
        repo_root=repo_root,
    )
    if evidence["g5_summary"] != recomputed:
        refuse("public_evidence_summary_mismatch")
    phase_results = {
        name: base.evaluate_phase_record(record, repo_root=repo_root)
        for name, record in evidence["p2_phase_records"].items()
    }
    if evidence["p2_phase_results"] != phase_results:
        refuse("public_evidence_phase_mismatch")


def _probe_chatgpt_login(
    executable: Path, environment: dict[str, str], cwd: Path,
) -> None:
    try:
        result = subprocess.run(
            [str(executable), "login", "status"],
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        refuse("chatgpt_auth_unavailable")
    validate_login_status(
        returncode=result.returncode, stdout=result.stdout, stderr=result.stderr
    )


def resolve_external_approval(
    approval: object | Callable[[dict[str, object]], object],
    scope: dict[str, object],
) -> object:
    if not callable(approval):
        return approval
    try:
        return approval(copy.deepcopy(scope))
    except Exception:
        refuse("approval_unavailable")


def run_live_authorized(
    *, contract_path: Path, repo_root: Path, output_root: Path, state_root: Path,
    approval: object | Callable[[dict[str, object]], object],
    verification_key: bytes, registry_key: bytes,
    executable: Path | None = None,
) -> dict[str, object]:
    contract_raw = contract_path.read_bytes()
    contract = parse_json(contract_raw, "contract")
    validate_contract(contract, repo_root=repo_root)
    base = load_base(contract, repo_root=repo_root)
    base._private_root(output_root)
    base._private_root(state_root)
    workspace = output_root / "workspace"
    tmpdir = output_root / "tmp"
    home = output_root / "home"
    codex_home = output_root / "codex-home"
    source_auth = source_codex_auth_path()
    _prepare_private_directory(home)
    _prepare_private_directory(codex_home)
    environment = build_codex_environment(
        tmpdir, home=home, codex_home=codex_home,
    )
    source_codex, executable_digest = resolve_codex_runtime(
        contract, environment=environment, executable=executable
    )
    codex = capture_runtime_copy(
        source_codex,
        contract=contract,
        runtime_root=output_root / "runtime",
    )
    base_contract = base.CAPTURED_CONTRACT
    capture = base.capture_frozen_packs(contract=base_contract, repo_root=repo_root)
    schedule_raw = _read_bound(
        repo_root / "research/provider-free-roadmap/g5/v1/schedule.json",
        base_contract["g5"]["schedule_sha256"],
        "g5_schedule",
    )
    schedule = parse_json(schedule_raw, "g5_schedule")
    schema_raw = _read_bound(
        repo_root
        / "research/provider-free-roadmap/g5/v1/schemas/authoritative-observation.schema.json",
        base_contract["g5"]["observation_schema_sha256"],
        "g5_observation_schema",
    )
    plan = base.build_request_plan(
        contract=contract, schedule=schedule, tasks=capture.tasks, packs=capture.packs
    )
    scope = build_approval_scope(
        contract=contract,
        base=base,
        executable=codex,
        executable_sha256=executable_digest,
        environment=environment,
        output_root=output_root,
        workspace=workspace,
        plan=plan,
    )

    def materialize(_scope: dict[str, object]) -> dict[str, object]:
        try:
            workspace.mkdir(mode=0o700)
            tmpdir.mkdir(mode=0o700)
        except OSError:
            refuse("output_unavailable")
        auth_link = prepare_isolated_codex_home(
            source_auth=source_auth,
            home=home,
            codex_home=codex_home,
        )
        try:
            _probe_chatgpt_login(codex, environment, workspace)
            scorer_box: dict[str, object] = {}

            def load_scorer() -> object:
                scorer = capture.load_scorer()
                scorer_box.update(scorer)
                return scorer

            execution = execute_schedule(
                contract=contract,
                schedule=schedule,
                observation_schema_bytes=schema_raw,
                tasks=capture.tasks,
                packs=capture.packs,
                output_root=output_root,
                invoke=lambda item: invoke_codex(
                    item,
                    contract=contract,
                    executable=codex,
                    environment=environment,
                    cwd=workspace,
                ),
                scorer_loader=load_scorer,
                repo_root=repo_root,
            )
            if sha256(codex.read_bytes()) != executable_digest:
                refuse("runtime_identity_mismatch")
            phase_records = base.build_p2_phase_records(
                observed_at=int(time.time()),
                retention_seconds=contract["safety"]["retention_seconds"],
                tasks=capture.tasks,
                packs=capture.packs,
                oracle=scorer_box["oracle"],
            )
            phase_results = {
                name: base.evaluate_phase_record(record, repo_root=repo_root)
                for name, record in phase_records.items()
            }
            evidence = build_public_evidence(
                contract_raw=contract_raw,
                execution=execution,
                phase_records=phase_records,
                phase_results=phase_results,
                executable_sha256=executable_digest,
            )
            validate_public_evidence(
                evidence, contract_raw=contract_raw, repo_root=repo_root
            )
            evidence_raw = canonical(evidence)
        finally:
            remove_isolated_auth_link(auth_link)
        base._write_private(output_root / "p2-codex-subscription-evidence.json", evidence_raw)
        return {
            "call_count": 240,
            "evidence_sha256": sha256(evidence_raw),
            "status": "p2_codex_subscription_recorded",
        }

    resolved_approval = resolve_external_approval(approval, scope)
    result = base.consume_authorized(
        contract=contract,
        approval=resolved_approval,
        requested_scope=scope,
        verification_key=verification_key,
        registry_key=registry_key,
        state_root=state_root,
        materialize=materialize,
        repo_root=repo_root,
    )
    if type(result) is not dict:
        refuse("materialization_failed")
    return result


def main(argv: list[str] | None = None) -> int:
    del argv
    print(
        "direct mutable Codex subscription execution is unavailable; use a one-use external approval envelope",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
