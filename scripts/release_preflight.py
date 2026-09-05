#!/usr/bin/env python3
"""PR 시점에 릴리스 캐스케이드를 미리 알린다.

왜 있는가: 동결 경로, 보호 표면 핀, P3 live-contract 산출물을 건드린 사실은 지금까지
릴리스 게이트(prepublish, Gate-B proof, 후보 빌드)에서야 드러났다. 그때 발견하면 세대
작성이나 핀 갱신을 위해 브랜치를 다시 짜야 한다. 이 스크립트는 같은 사실을 PR 의 첫 CI
스텝에서 GitHub 경고 주석으로 낸다. 보증은 그대로이고, 발견 시점만 앞당긴다.

기본은 경고만 낸다(exit 0). `--strict` 는 드리프트가 남아 있으면 exit 1.

검사:
- 변경 경로 ∩ 활성 Gate-B 세대의 컴포넌트 경로 → "세대 작성 필요"
- 변경 경로 ∩ 보호 표면 맵 키 → `refresh_protected_pins.py --check` 결과
- 변경 경로 ∩ live-contract artifact 경로 → `refresh_p3_live_contract.py --check` 결과
"""
from __future__ import annotations

import argparse
import json
import re
import runpy
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout


def changed_paths(base: str) -> set[str]:
    merge_base = git("merge-base", base, "HEAD").strip()
    out = git("diff", "--name-only", "--no-renames", f"{merge_base}..HEAD")
    return {line for line in out.splitlines() if line}


def annotate(kind: str, message: str) -> None:
    print(f"::{kind}::{message}" if kind in {"warning", "error", "notice"} else message)


def run_helper(script: str) -> tuple[int, str]:
    proc = subprocess.run([sys.executable, str(SCRIPTS / script), "--check"], cwd=ROOT, capture_output=True, text=True)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base", default="origin/main", help="base ref for the changed-path set (default origin/main)")
    parser.add_argument("--strict", action="store_true", help="exit 1 when any cascade is stale")
    args = parser.parse_args(argv)

    changed = changed_paths(args.base)
    stale = False

    proof = runpy.run_path(str(SCRIPTS / "verify_gate_b_rollback.py"), run_name="gate_b_fingerprint")
    active = proof["GENERATIONS"][-1]
    # 세대의 reapply 커밋이 HEAD 이력에 있으면, 그 *이후* 에 동결 경로가 바뀐 것만 문제다.
    # (세대 안에서 바뀐 것은 정상.) 없으면 변경 경로와의 교집합 전체가 문제다.
    shared_commit = next(
        (line.split("\x00", 1)[0] for line in git("log", "--format=%H%x00%s", "HEAD").splitlines()
         if line.split("\x00", 1)[1] == active.shared_subject),
        None,
    )
    if shared_commit is not None:
        after = git("diff", "--name-only", "--no-renames", f"{shared_commit}..HEAD", "--", *sorted(active.all_component_paths))
        frozen_hits = sorted({line for line in after.splitlines() if line})
    else:
        frozen_hits = sorted(changed & set(active.all_component_paths))
    if frozen_hits:
        annotate(
            "warning",
            f"Gate-B frozen paths changed ({active.name}): {', '.join(frozen_hits)} — these edits must land "
            "inside a new generation's reapply commits (scripts/author_gate_b_generation.py); an ordinary commit "
            "here fails verify_gate_b_rollback.py",
        )

    protected_source = (ROOT / "tests" / "test_contextguard_stage2_protected_surfaces.py").read_text(encoding="utf-8")
    protected_keys = set(re.findall(r'"([^"]+)": "[0-9a-f]{64}"', protected_source))
    protected_hits = sorted(changed & protected_keys)
    code, output = run_helper("refresh_protected_pins.py")
    if protected_hits or code != 0:
        stale = stale or code != 0
        annotate(
            "warning" if code != 0 else "notice",
            f"protected surfaces changed: {', '.join(protected_hits) or '(none by path)'}; "
            f"refresh_protected_pins.py --check → {'stale, run --write and commit' if code != 0 else 'pins match'}",
        )

    contract = json.loads((ROOT / "research" / "provider-live-roadmap" / "p3-api" / "v4" / "live-contract.json").read_text(encoding="utf-8"))
    artifact_paths = {entry.get("path") for entry in contract.get("artifacts", {}).values() if isinstance(entry, dict)}
    artifact_hits = sorted(changed & artifact_paths)
    code, output = run_helper("refresh_p3_live_contract.py")
    if artifact_hits or code != 0:
        stale = stale or code != 0
        annotate(
            "warning" if code != 0 else "notice",
            f"P3 live-contract artifacts changed: {', '.join(artifact_hits) or '(none by path)'}; "
            f"refresh_p3_live_contract.py --check → {'stale, run --write, commit, then --pin-core' if code != 0 else 'digests match'}",
        )

    if not frozen_hits and not protected_hits and not artifact_hits and not stale:
        print("release-preflight: no frozen, protected, or live-contract paths changed")
    return 1 if (args.strict and stale) else 0


if __name__ == "__main__":
    sys.exit(main())
