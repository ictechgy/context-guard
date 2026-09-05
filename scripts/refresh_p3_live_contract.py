#!/usr/bin/env python3
"""P3 live-contract 캐스케이드(research/AGENTS.md 의 4단계)를 기계적으로 갱신한다.

왜 있는가: `context_pack.py` 나 `sanitize_output.py` 같은 canonical 산출물이 바뀌면
`live-contract.json` 과 `live_runner.py` 의 digest, 그 두 파일 자신의 digest
(`EXPECTED_CONTRACT_SHA256`, `EXPECTED_RUNNER_SHA256`), 그리고 그 커밋의 SHA
(`EXPECTED_CORE_COMMIT`)를 순서대로 고쳐야 한다. 4단계는 고정점이라 커밋 두 개가 필요하고
(research/AGENTS.md), 손으로 하면 순서를 틀리기 쉽다.

사용:
    python3 scripts/refresh_p3_live_contract.py --check
        artifact digest 드리프트와 contract/runner digest 불일치를 보고한다. exit 1 이면 드리프트.
    python3 scripts/refresh_p3_live_contract.py --write
        1~3단계: artifact digest 를 live-contract.json 과 live_runner.py 양쪽에 다시 쓰고,
        EXPECTED_CONTRACT_SHA256 (runner, launcher) 과 EXPECTED_RUNNER_SHA256 (launcher) 을 갱신한다.
        그 다음 커밋한다.
    python3 scripts/refresh_p3_live_contract.py --pin-core <40-hex commit>
        4단계: 1~3단계를 담은 커밋의 SHA 를 launcher 와 그 핀 테스트에 적는다. 두 번째 커밋.

무엇을 pinned artifact 로 볼지는 바꾸지 않는다. 항목 집합은 live-contract.json 이 정한다.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
P3 = ROOT / "research" / "provider-live-roadmap" / "p3-api" / "v4"
CONTRACT = P3 / "live-contract.json"
RUNNER = P3 / "live_runner.py"
LAUNCHER = P3 / "live_launcher.py"
CORE_PIN_TEST = ROOT / "tests" / "provider-live-roadmap" / "test_p3_anthropic_api_v4.py"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def contract_artifacts() -> dict[str, dict[str, str]]:
    data = json.loads(CONTRACT.read_text(encoding="utf-8"))
    artifacts = data.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        raise SystemExit("refresh-p3: live-contract.json has no artifacts map")
    return artifacts


def replace_constant(text: str, name: str, value: str, label: str) -> tuple[str, bool]:
    pattern = re.compile(rf'^{name} = "([0-9a-f]{{40,64}})"$', re.M)
    match = pattern.search(text)
    if match is None:
        raise SystemExit(f"refresh-p3: {name} not found in {label}")
    if match.group(1) == value:
        return text, False
    return text[: match.start(1)] + value + text[match.end(1):], True


def run_check_or_write(write: bool) -> int:
    drift: list[str] = []
    artifacts = contract_artifacts()
    contract_text = CONTRACT.read_text(encoding="utf-8")
    runner_text = RUNNER.read_text(encoding="utf-8")
    # 1) artifact digest — contract 와 runner 양쪽
    for key, entry in artifacts.items():
        path = entry.get("path")
        old = entry.get("sha256")
        if not isinstance(path, str) or not isinstance(old, str):
            raise SystemExit(f"refresh-p3: artifact {key!r} lacks path/sha256")
        target = ROOT / path
        if not target.is_file():
            raise SystemExit(f"refresh-p3: artifact path missing: {path}")
        new = sha256_of(target)
        if new != old:
            drift.append(f"artifact {key} ({path}): {old[:8]} -> {new[:8]}")
            contract_text = contract_text.replace(f'"sha256": "{old}"', f'"sha256": "{new}"')
        # runner 는 같은 (path, sha256) 쌍을 문자열로 갖는다. path 뒤에 오는 sha256 만 바꾼다.
        runner_pattern = re.compile(r'("path": "' + re.escape(path) + r'",\n\s*"sha256": ")([0-9a-f]{64})(")')
        runner_match = runner_pattern.search(runner_text)
        if runner_match is None:
            raise SystemExit(f"refresh-p3: runner has no digest entry for {path}")
        if runner_match.group(2) != new:
            if new == old:
                drift.append(f"runner digest for {path} disagrees with contract")
            runner_text = runner_text[: runner_match.start(2)] + new + runner_text[runner_match.end(2):]
    if write:
        CONTRACT.write_text(contract_text, encoding="utf-8")
        RUNNER.write_text(runner_text, encoding="utf-8")
    # 2) EXPECTED_CONTRACT_SHA256 — runner 와 launcher (write 시 갱신된 contract 로 계산)
    contract_digest = hashlib.sha256(contract_text.encode("utf-8")).hexdigest()
    runner_text, changed = replace_constant(runner_text, "EXPECTED_CONTRACT_SHA256", contract_digest, "live_runner.py")
    if changed:
        drift.append("EXPECTED_CONTRACT_SHA256 in live_runner.py")
    if write and changed:
        RUNNER.write_text(runner_text, encoding="utf-8")
    launcher_text = LAUNCHER.read_text(encoding="utf-8")
    launcher_text, changed = replace_constant(launcher_text, "EXPECTED_CONTRACT_SHA256", contract_digest, "live_launcher.py")
    if changed:
        drift.append("EXPECTED_CONTRACT_SHA256 in live_launcher.py")
    # 3) EXPECTED_RUNNER_SHA256 — launcher (write 시 갱신된 runner 로 계산)
    runner_digest = hashlib.sha256(runner_text.encode("utf-8")).hexdigest()
    launcher_text, changed_runner = replace_constant(launcher_text, "EXPECTED_RUNNER_SHA256", runner_digest, "live_launcher.py")
    if changed_runner:
        drift.append("EXPECTED_RUNNER_SHA256 in live_launcher.py")
    if write and (changed or changed_runner):
        LAUNCHER.write_text(launcher_text, encoding="utf-8")

    if not drift:
        print("refresh-p3: contract, runner, and launcher digests match the working tree")
        return 0
    verb = "updated" if write else "drift"
    for line in drift:
        print(f"refresh-p3: {verb}: {line}")
    if write:
        print("refresh-p3: commit these files, then run --pin-core <that commit sha> for step 4")
        return 0
    return 1


def pin_core(commit: str) -> int:
    """4단계: launcher 의 EXPECTED_CORE_COMMIT 과, 그 값을 리터럴로 박아 둔 핀 테스트를 갱신한다.

    핀 테스트는 상수 이름 없이 SHA 리터럴만 갖고 있으므로, launcher 에서 읽은 *이전* 값을
    새 값으로 치환한다.
    """
    if COMMIT_RE.fullmatch(commit) is None:
        raise SystemExit("refresh-p3: --pin-core needs a 40-character lowercase commit sha")
    import subprocess

    ancestor = subprocess.run(["git", "merge-base", "--is-ancestor", commit, "HEAD"], cwd=ROOT, capture_output=True)
    if ancestor.returncode != 0:
        raise SystemExit(f"refresh-p3: {commit[:10]} is not an ancestor of HEAD (or does not exist); commit steps 1-3 first")
    launcher_text = LAUNCHER.read_text(encoding="utf-8")
    match = re.search(r'^EXPECTED_CORE_COMMIT = "([0-9a-f]{40})"$', launcher_text, re.M)
    if match is None:
        raise SystemExit("refresh-p3: EXPECTED_CORE_COMMIT not found in live_launcher.py")
    previous = match.group(1)
    changed_any = False
    if previous != commit:
        LAUNCHER.write_text(launcher_text[: match.start(1)] + commit + launcher_text[match.end(1):], encoding="utf-8")
        changed_any = True
        print(f"refresh-p3: pinned EXPECTED_CORE_COMMIT in {LAUNCHER.relative_to(ROOT)}")
    test_text = CORE_PIN_TEST.read_text(encoding="utf-8")
    if previous in test_text and previous != commit:
        CORE_PIN_TEST.write_text(test_text.replace(previous, commit), encoding="utf-8")
        changed_any = True
        print(f"refresh-p3: pinned core commit literal in {CORE_PIN_TEST.relative_to(ROOT)}")
    elif commit not in test_text:
        raise SystemExit(
            f"refresh-p3: {CORE_PIN_TEST.relative_to(ROOT)} holds neither the previous nor the new core commit"
        )
    if not changed_any:
        print("refresh-p3: EXPECTED_CORE_COMMIT already pinned to that commit")
    print("refresh-p3: commit this as the second cascade commit; the pinned commit must stay an ancestor of main (merge commit, never squash)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--pin-core", metavar="COMMIT")
    args = parser.parse_args(argv)
    if args.pin_core:
        return pin_core(args.pin_core)
    return run_check_or_write(write=bool(args.write))


if __name__ == "__main__":
    sys.exit(main())
