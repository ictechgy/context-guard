#!/usr/bin/env python3
"""Gate-B 세대(bless + 3 reapply + record)를 기계적으로 만든다.

왜 있는가: 동결 파일을 한 줄 고칠 때마다 사람이 다섯 커밋을 손으로 짜야 했다. 순서와
경로 집합을 틀리면 proof 가 실패하고, 0.13.0 릴리스 기간에 이 작업이 네 번 반복됐다.
이 스크립트는 *기계적인* 부분만 맡는다: 잔여물 트리 복원, 경로 집합별 reapply 커밋,
지문 계산과 원장 append. 무엇을 축복(bless)할지 — 즉 레코드의 경로 집합·마커·잔여
편집 선언 — 는 여전히 사람이 `scripts/verify_gate_b_rollback.py` 에 적고 리뷰한다.
bless diff 의 리뷰(runbook "Re-blessing procedure" 5단계)도 자동화하지 않는다.

전제:
1. `GENERATIONS` 마지막에 새 `Generation` 레코드와 그 subject 상수를 이미 적어 두었고
   (지문은 아직 원장에 없어도 된다), 컴포넌트 경로의 최종 내용이 작업 트리에 있다.
2. 그 밖의 작업 트리 변경은 없다(스크립트가 거부한다). 비동결 변경은 먼저 커밋한다.

동작:
- 직전 세대의 bless 커밋을 subject 로 찾고, 새 세대의 모든 컴포넌트 경로를 그 트리의
  내용으로 되돌린다(잔여물에 없는 경로는 삭제). → bless 커밋.
- b1, b2, shared 경로 집합 순서로 작업 트리의 최종 내용을 복원해 커밋한다.
- 지문을 생산 canonicalizer 로 계산해 `GENERATION_RECORD_FINGERPRINTS` 끝에 붙이고,
  검증기 파일과 `--record-extra` 로 준 경로를 record 커밋으로 남긴다.
- 끝으로 `verify_gate_b_rollback.py` 를 실행한다(`--skip-proof` 로 생략 가능).

`--dry-run` 은 커밋 없이 계획(경로 집합, 삭제될 경로, 지문)만 출력한다.
"""
from __future__ import annotations

import argparse
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "scripts" / "verify_gate_b_rollback.py"
TRAILER = (
    "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>\n"
    "Claude-Session: https://claude.ai/code/session_01DE3AupXcyv64SEuQeTckSh"
)


def git(*args: str, check: bool = True) -> str:
    proc = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=False)
    if check and proc.returncode != 0:
        raise SystemExit(f"author-gate-b: git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def load_proof() -> dict:
    return runpy.run_path(str(VERIFIER), run_name="gate_b_fingerprint")


def find_commit_by_subject(subject: str) -> str:
    out = git("log", "--format=%H%x00%s", "HEAD")
    matches = [line.split("\x00", 1)[0] for line in out.splitlines() if line.split("\x00", 1)[1] == subject]
    if len(matches) != 1:
        raise SystemExit(f"author-gate-b: subject must resolve to exactly one commit, found {len(matches)}: {subject!r}")
    return matches[0]


def path_exists_in(commit: str, path: str) -> bool:
    return subprocess.run(["git", "cat-file", "-e", f"{commit}:{path}"], cwd=ROOT, capture_output=True).returncode == 0


def assert_clean_except(paths: set[str]) -> None:
    """컴포넌트 경로와 검증기 파일 외의 작업 트리 변경을 거부한다."""
    status = git("status", "--porcelain", "--untracked-files=all")
    dirty = []
    for line in status.splitlines():
        entry = line[3:]
        if " -> " in entry:
            entry = entry.split(" -> ", 1)[1]
        if entry not in paths and entry != str(VERIFIER.relative_to(ROOT)):
            dirty.append(entry)
    if dirty:
        raise SystemExit(
            "author-gate-b: commit or stash unrelated changes first; dirty paths outside the "
            f"component set: {sorted(dirty)}"
        )


def commit(message: str) -> str:
    git("commit", "--quiet", "-m", message)
    return git("rev-parse", "HEAD").strip()


def stage_paths(paths: list[str]) -> None:
    """존재하는 경로만 add 한다. 삭제는 `git rm` 이 이미 스테이징했고, 없는 경로를 add 에
    주면 git 이 pathspec 오류를 낸다."""
    existing = [path for path in paths if (ROOT / path).exists()]
    if existing:
        git("add", "-A", "--", *existing)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--body", default="", help="extra commit-message body for the bless and record commits")
    parser.add_argument("--record-extra", action="append", default=[], help="extra path to include in the record commit (e.g. tests/test_gate_b_rollback_proof.py)")
    parser.add_argument("--dry-run", action="store_true", help="print the plan and the fingerprint, commit nothing")
    parser.add_argument("--skip-proof", action="store_true", help="do not run verify_gate_b_rollback.py at the end")
    args = parser.parse_args(argv)

    proof = load_proof()
    generations = proof["GENERATIONS"]
    current, previous = generations[-1], generations[-2]
    proof["assert_generation_records_wellformed"](generations)
    proof["assert_shipped_generations_narrow_only"]()
    fingerprint = proof["generation_record_fingerprint"](current)
    ledger = proof["GENERATION_RECORD_FINGERPRINTS"]
    if len(ledger) == len(generations):
        raise SystemExit(f"author-gate-b: {current.name} already has a fingerprint in the ledger; nothing to author")
    if len(ledger) != len(generations) - 1:
        raise SystemExit("author-gate-b: ledger length must be one short of GENERATIONS")

    b1, b2, shared = sorted(current.b1_paths), sorted(current.b2_paths), sorted(current.shared_paths)
    all_paths = sorted(current.all_component_paths)
    prev_bless = find_commit_by_subject(previous.bless_subject)
    deletions = [path for path in all_paths if not path_exists_in(prev_bless, path)]
    print(f"author-gate-b: {current.name} after {previous.name} (bless {prev_bless[:10]})")
    print(f"  b1={len(b1)} b2={len(b2)} shared={len(shared)} deleted-in-residual={len(deletions)}")
    print(f"  fingerprint={fingerprint}")
    if args.dry_run:
        for path in all_paths:
            print(f"  {'delete ' if path in deletions else 'restore'} {path}")
        return 0

    assert_clean_except(set(all_paths))
    for subject in (current.bless_subject, current.b1_subject, current.b2_subject, current.shared_subject):
        if git("log", "--format=%s", "HEAD").count(subject):
            raise SystemExit(f"author-gate-b: subject already exists in history: {subject!r}")

    # 최종 내용을 임시 디렉터리에 보관한다.
    stash_dir = Path(tempfile.mkdtemp(prefix="gate-b-final-"))
    try:
        for path in all_paths:
            source = ROOT / path
            if source.exists():
                target = stash_dir / path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
        # bless: 잔여물 복원
        for path in all_paths:
            if path in deletions:
                if (ROOT / path).exists():
                    git("rm", "--quiet", "--", path)
            else:
                git("checkout", "--quiet", prev_bless, "--", path)
        stage_paths(all_paths)
        body = (args.body.strip() + "\n\n") if args.body.strip() else ""
        bless = commit(f"{current.bless_subject}\n\n{body}{TRAILER}")
        print(f"  bless  {bless[:10]}")

        def reapply(paths: list[str], subject: str) -> None:
            for path in paths:
                saved = stash_dir / path
                target = ROOT / path
                if saved.exists():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(saved, target)
                elif target.exists():
                    target.unlink()
            stage_paths(paths)
            changed = git("diff", "--cached", "--name-only").split()
            if sorted(changed) != sorted(paths):
                raise SystemExit(f"author-gate-b: reapply for {subject!r} would touch {changed}, expected {paths}")
            print(f"  {subject.split()[2]:<12} {commit(f'{subject}\n\n{TRAILER}')[:10]}")

        reapply(b1, current.b1_subject)
        reapply(b2, current.b2_subject)
        reapply(shared, current.shared_subject)
    finally:
        shutil.rmtree(stash_dir, ignore_errors=True)

    # 원장 append
    text = VERIFIER.read_text(encoding="utf-8")
    match = re.search(r"GENERATION_RECORD_FINGERPRINTS: tuple\[str, \.\.\.\] = \((.*?)\n\)", text, re.S)
    if match is None:
        raise SystemExit("author-gate-b: fingerprint ledger not found")
    if fingerprint in match.group(1):
        raise SystemExit("author-gate-b: fingerprint already present")
    updated = text[: match.end(1)] + f'\n    "{fingerprint}",' + text[match.end(1):]
    VERIFIER.write_text(updated, encoding="utf-8")
    record_paths = [str(VERIFIER.relative_to(ROOT)), *args.record_extra]
    stage_paths(record_paths)
    record = commit(
        f"proof: append Gate-B generation record {current.name} {current.bless_subject.split(current.name + ' ', 1)[1]}\n\n"
        f"{body}지문은 생산 canonicalizer 로 계산했고 기존 레코드와 지문은 건드리지 않았다.\n\n{TRAILER}"
    )
    print(f"  record {record[:10]}")
    if args.skip_proof:
        return 0
    result = subprocess.run([sys.executable, str(VERIFIER)], cwd=ROOT)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
