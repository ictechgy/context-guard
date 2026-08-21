#!/usr/bin/env python3
"""Require a successful main-push CI run for an exact release commit."""
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any


MAX_RESPONSE_BYTES = 8 * 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{40}")
EXPECTED_WORKFLOW_PATH = ".github/workflows/ci.yml"


def duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def successful_main_ci(payload: object, commit_sha: str) -> bool:
    if type(payload) is not dict:
        return False
    runs = payload.get("workflow_runs")
    if type(runs) is not list:
        return False
    return any(
        type(run) is dict
        and run.get("conclusion") == "success"
        and run.get("event") == "push"
        and run.get("head_branch") == "main"
        and run.get("head_sha") == commit_sha
        and run.get("path") == EXPECTED_WORKFLOW_PATH
        and run.get("status") == "completed"
        for run in runs
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit-sha", required=True)
    args = parser.parse_args()
    if SHA256_RE.fullmatch(args.commit_sha) is None:
        raise SystemExit("commit SHA must be 40 lowercase hexadecimal characters")
    raw = sys.stdin.buffer.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise SystemExit("GitHub workflow response exceeds the verification limit")
    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise SystemExit("GitHub workflow response is invalid") from None
    if not successful_main_ci(payload, args.commit_sha):
        raise SystemExit("release commit lacks a successful main-push CI run")
    print("release commit CI verification: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
