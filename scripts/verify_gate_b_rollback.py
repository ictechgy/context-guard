#!/usr/bin/env python3
"""Mechanically prove durable Gate-B component apply/revert behavior.

The proof consumes a reachable, path-separated reapplication sequence carried
by the PR itself.  Its parent is a Gate-B-free residual that retains unrelated
hook-safety and quiet-narration work.  This avoids depending on unpublished
objects and avoids deriving destructive whole-path patches from ``base..HEAD``.

Gate-B의 증명 앵커는 append-only ``GENERATIONS`` 목록이다. 세대 하나는 4개의
reapply 커밋(subject로 식별), 세 그룹의 컴포넌트 경로 집합, 이 세대의 bless가
지켜야 하는 무관 기능 마커, 이 세대가 정의하는 Gate-B 표면 마커, 그리고 직전
세대 대비 이 세대의 bless가 정당하게 바꾸는 잔여물 경로를 담는 불변 레코드다.
모든 세대(은퇴 포함)는 구조·서로소·잔여 계약을 영원히 검사받는다. 활성
세대(목록의 마지막 원소)만 HEAD에 대한 동결, 순서 있는 라이브 롤백, Gate-B
마커 존재/부재를 추가로 검사받는다. 재축복은 세대 하나를 append하는 명시적
리뷰 커밋이며, 기존 세대의 레코드는 절대 수정하지 않는다.

각 레코드의 정규 지문은 ``GENERATION_RECORD_FINGERPRINTS``의 같은 위치에
append된다. 검증기는 현재 레코드와 지문을 대조한 뒤, 도달 가능한 과거 버전의
지문 목록이 모두 현재 목록의 prefix인지 확인한다. 따라서 기존 레코드의 삭제나
경로 축소와 함께 현재 지문을 고쳐도 이미 커밋된 더 긴/다른 prefix가 이를 막는다.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE_COMMIT = "6aac7d8e10d3e2bc8e6cc94973af142a68e911ec"
SCHEMA_VERSION = "contextguard.gate-b-rollback-proof.v3"

BLESS_SUBJECT = "proof: establish Gate-B-free residual"
B1_SUBJECT = "proof: reapply Gate-B nudge component"
B2_SUBJECT = "proof: reapply Gate-B usage component"
SHARED_SUBJECT = "proof: reapply Gate-B integration component"

GEN2_BLESS_SUBJECT = "proof: establish Gate-B-free residual gen2 command identity"
GEN2_B1_SUBJECT = "proof: reapply Gate-B nudge component gen2 command identity"
GEN2_B2_SUBJECT = "proof: reapply Gate-B usage component gen2 command identity"
GEN2_SHARED_SUBJECT = "proof: reapply Gate-B integration component gen2 command identity"

GEN3_BLESS_SUBJECT = "proof: establish Gate-B-free residual gen3 login shell"
GEN3_B1_SUBJECT = "proof: reapply Gate-B nudge component gen3 login shell"
GEN3_B2_SUBJECT = "proof: reapply Gate-B usage component gen3 login shell"
GEN3_SHARED_SUBJECT = "proof: reapply Gate-B integration component gen3 login shell"

GEN4_BLESS_SUBJECT = "proof: establish Gate-B-free residual gen4 bash references"
GEN4_B1_SUBJECT = "proof: reapply Gate-B nudge component gen4 bash references"
GEN4_B2_SUBJECT = "proof: reapply Gate-B usage component gen4 bash references"
GEN4_SHARED_SUBJECT = "proof: reapply Gate-B integration component gen4 bash references"

GEN5_BLESS_SUBJECT = "proof: establish Gate-B-free residual gen5 release smoke CI marker"
GEN5_B1_SUBJECT = "proof: reapply Gate-B nudge component gen5 release smoke CI marker"
GEN5_B2_SUBJECT = "proof: reapply Gate-B usage component gen5 release smoke CI marker"
GEN5_SHARED_SUBJECT = "proof: reapply Gate-B integration component gen5 release smoke CI marker"

GEN6_BLESS_SUBJECT = "proof: establish Gate-B-free residual gen6 hook runtime hardening"
GEN6_B1_SUBJECT = "proof: reapply Gate-B nudge component gen6 hook runtime hardening"
GEN6_B2_SUBJECT = "proof: reapply Gate-B usage component gen6 hook runtime hardening"
GEN6_SHARED_SUBJECT = "proof: reapply Gate-B integration component gen6 hook runtime hardening"

GEN7_BLESS_SUBJECT = "proof: establish Gate-B-free residual gen7 hosted statusline tests"
GEN7_B1_SUBJECT = "proof: reapply Gate-B nudge component gen7 hosted statusline tests"
GEN7_B2_SUBJECT = "proof: reapply Gate-B usage component gen7 hosted statusline tests"
GEN7_SHARED_SUBJECT = "proof: reapply Gate-B integration component gen7 hosted statusline tests"

GEN8_BLESS_SUBJECT = "proof: establish Gate-B-free residual gen8 home settings safety"
GEN8_B1_SUBJECT = "proof: reapply Gate-B nudge component gen8 home settings safety"
GEN8_B2_SUBJECT = "proof: reapply Gate-B usage component gen8 home settings safety"
GEN8_SHARED_SUBJECT = "proof: reapply Gate-B integration component gen8 home settings safety"

B1_PATHS = frozenset(
    {
        "context-guard-kit/failed_attempt_nudge.py",
        "plugins/context-guard/bin/context-guard-failed-nudge",
        "tests/test_context_guard_nudge_protocol.py",
    }
)
B2_PATHS = frozenset(
    {
        "context-guard-kit/claude_transcript_cost_audit.py",
        "context-guard-kit/statusline.sh",
        "context-guard-kit/statusline_merged.sh",
        "context-guard-kit/transcript_usage_reducer.py",
        "plugins/context-guard/bin/context-guard-audit",
        "plugins/context-guard/bin/context-guard-statusline",
        "plugins/context-guard/bin/context-guard-statusline-merged",
        "plugins/context-guard/lib/transcript_usage_reducer.py",
        "tests/test_context_guard_usage_reducer_v2.py",
    }
)
SHARED_INTEGRATION_PATHS = frozenset(
    {
        "context-guard-kit/context_guard_commands.py",
        "context-guard-kit/setup_wizard.py",
        "plugins/context-guard/bin/context-guard-setup",
        "plugins/context-guard/lib/context_guard_commands.py",
        "scripts/release_smoke.py",
        "tests/test_context_guard_kit.py",
    }
)
ALL_COMPONENT_PATHS = B1_PATHS | B2_PATHS | SHARED_INTEGRATION_PATHS

# gen1 잔여물이 보존해야 하는 무관 기능 마커(존재 방향). 이 세대가 무엇을
# 축복했는지에 상대적이므로 세대 레코드에 박아 넣는다 — 나중에 무관 기능이
# 마커를 하나 더 추가해도 과거 세대의 bless는 소급으로 재검사되지 않는다.
GEN1_RESIDUAL_MARKERS: dict[str, tuple[str, ...]] = {
    "context-guard-kit/setup_wizard.py": (
        "NARRATION_MODE_CHOICES",
        "def parse_managed_bytes",
    ),
    "scripts/release_smoke.py": ("def run_quiet_narration_smoke",),
}


@dataclass(frozen=True)
class GateBMarker:
    """Gate-B 표면 리터럴 하나와, HEAD에서 그 리터럴을 소유하는 경로.

    존재 방향(활성 세대 HEAD)과 부재 방향(해당 세대 bless 트리) 두 검사가
    같은 레코드를 공유한다 — 두 검사가 서로 다른 리터럴을 보면 자기 무효화
    성질(개명 시 존재 검사가 먼저 큰 소리로 실패)이 깨진다.
    """

    literal: str
    owner_path: str


# gen1이 정의하는 Gate-B 표면 마커. 처음 3개는 조사에서 실측한 B1/B2 쪽 벡터이고
# 마지막 1개는 shared-integration 쪽 벡터로, `git diff 31d3f15 802dd49 --
# context-guard-kit/setup_wizard.py`가 추가한 라인에서 고른 고유 함수명이다
# (HEAD 존재, bless 부재를 실측 확인함).
GEN1_GATE_B_MARKERS: tuple[GateBMarker, ...] = (
    GateBMarker("CGW1_SHELL_ARGV", "context-guard-kit/failed_attempt_nudge.py"),
    GateBMarker("failures-v2.json", "context-guard-kit/failed_attempt_nudge.py"),
    GateBMarker(
        "transcript_usage_reducer", "context-guard-kit/claude_transcript_cost_audit.py"
    ),
    GateBMarker("ensure_post_tool_failure_hook", "context-guard-kit/setup_wizard.py"),
)


@dataclass(frozen=True)
class Generation:
    """되돌릴 수 있는 Gate-B 재축복 한 세대의 불변 레코드.

    append-only ``GENERATIONS`` 목록의 원소 하나를 표현한다. ``residual_edits``는
    직전 세대 대비 이 세대의 bless가 공유 컴포넌트 경로 중 정당하게 바꾸는
    경로를 선언한다(첫 세대는 비교 대상이 없으므로 항상 빈 집합).
    """

    name: str
    bless_subject: str
    b1_subject: str
    b2_subject: str
    shared_subject: str
    b1_paths: frozenset[str]
    b2_paths: frozenset[str]
    shared_paths: frozenset[str]
    residual_markers: dict[str, tuple[str, ...]]
    gate_b_markers: tuple[GateBMarker, ...]
    residual_edits: frozenset[str] = frozenset()

    @property
    def all_component_paths(self) -> frozenset[str]:
        """이 세대가 구속하는 컴포넌트 경로 전체(B1 ∪ B2 ∪ shared-integration)."""
        return self.b1_paths | self.b2_paths | self.shared_paths


GENERATIONS: tuple[Generation, ...] = (
    Generation(
        name="gen1",
        bless_subject=BLESS_SUBJECT,
        b1_subject=B1_SUBJECT,
        b2_subject=B2_SUBJECT,
        shared_subject=SHARED_SUBJECT,
        b1_paths=B1_PATHS,
        b2_paths=B2_PATHS,
        shared_paths=SHARED_INTEGRATION_PATHS,
        residual_markers=GEN1_RESIDUAL_MARKERS,
        gate_b_markers=GEN1_GATE_B_MARKERS,
        residual_edits=frozenset(),
    ),
    Generation(
        name="gen2",
        bless_subject=GEN2_BLESS_SUBJECT,
        b1_subject=GEN2_B1_SUBJECT,
        b2_subject=GEN2_B2_SUBJECT,
        shared_subject=GEN2_SHARED_SUBJECT,
        b1_paths=B1_PATHS,
        b2_paths=B2_PATHS,
        shared_paths=SHARED_INTEGRATION_PATHS,
        residual_markers=GEN1_RESIDUAL_MARKERS,
        gate_b_markers=GEN1_GATE_B_MARKERS,
        residual_edits=frozenset({"tests/test_context_guard_kit.py"}),
    ),
    Generation(
        name="gen3",
        bless_subject=GEN3_BLESS_SUBJECT,
        b1_subject=GEN3_B1_SUBJECT,
        b2_subject=GEN3_B2_SUBJECT,
        shared_subject=GEN3_SHARED_SUBJECT,
        b1_paths=B1_PATHS,
        b2_paths=B2_PATHS,
        shared_paths=SHARED_INTEGRATION_PATHS,
        residual_markers=GEN1_RESIDUAL_MARKERS,
        gate_b_markers=GEN1_GATE_B_MARKERS,
        residual_edits=frozenset({"tests/test_context_guard_kit.py"}),
    ),
    Generation(
        name="gen4",
        bless_subject=GEN4_BLESS_SUBJECT,
        b1_subject=GEN4_B1_SUBJECT,
        b2_subject=GEN4_B2_SUBJECT,
        shared_subject=GEN4_SHARED_SUBJECT,
        b1_paths=B1_PATHS,
        b2_paths=B2_PATHS,
        shared_paths=SHARED_INTEGRATION_PATHS,
        residual_markers=GEN1_RESIDUAL_MARKERS,
        gate_b_markers=GEN1_GATE_B_MARKERS,
        residual_edits=SHARED_INTEGRATION_PATHS,
    ),
    Generation(
        name="gen5",
        bless_subject=GEN5_BLESS_SUBJECT,
        b1_subject=GEN5_B1_SUBJECT,
        b2_subject=GEN5_B2_SUBJECT,
        shared_subject=GEN5_SHARED_SUBJECT,
        b1_paths=B1_PATHS,
        b2_paths=B2_PATHS,
        shared_paths=SHARED_INTEGRATION_PATHS,
        residual_markers=GEN1_RESIDUAL_MARKERS,
        gate_b_markers=GEN1_GATE_B_MARKERS,
        residual_edits=frozenset(
            {"scripts/release_smoke.py", "tests/test_context_guard_kit.py"}
        ),
    ),
    Generation(
        name="gen6",
        bless_subject=GEN6_BLESS_SUBJECT,
        b1_subject=GEN6_B1_SUBJECT,
        b2_subject=GEN6_B2_SUBJECT,
        shared_subject=GEN6_SHARED_SUBJECT,
        b1_paths=B1_PATHS,
        b2_paths=B2_PATHS,
        shared_paths=SHARED_INTEGRATION_PATHS,
        residual_markers=GEN1_RESIDUAL_MARKERS,
        gate_b_markers=GEN1_GATE_B_MARKERS,
        residual_edits=frozenset(
            {
                "context-guard-kit/failed_attempt_nudge.py",
                "context-guard-kit/setup_wizard.py",
                "context-guard-kit/statusline.sh",
                "context-guard-kit/statusline_merged.sh",
                "plugins/context-guard/bin/context-guard-failed-nudge",
                "plugins/context-guard/bin/context-guard-setup",
                "plugins/context-guard/bin/context-guard-statusline",
                "plugins/context-guard/bin/context-guard-statusline-merged",
                "tests/test_context_guard_kit.py",
            }
        ),
    ),
    Generation(
        name="gen7",
        bless_subject=GEN7_BLESS_SUBJECT,
        b1_subject=GEN7_B1_SUBJECT,
        b2_subject=GEN7_B2_SUBJECT,
        shared_subject=GEN7_SHARED_SUBJECT,
        b1_paths=B1_PATHS,
        b2_paths=B2_PATHS,
        shared_paths=SHARED_INTEGRATION_PATHS,
        residual_markers=GEN1_RESIDUAL_MARKERS,
        gate_b_markers=GEN1_GATE_B_MARKERS,
        residual_edits=frozenset({"tests/test_context_guard_kit.py"}),
    ),
    Generation(
        name="gen8",
        bless_subject=GEN8_BLESS_SUBJECT,
        b1_subject=GEN8_B1_SUBJECT,
        b2_subject=GEN8_B2_SUBJECT,
        shared_subject=GEN8_SHARED_SUBJECT,
        b1_paths=B1_PATHS,
        b2_paths=B2_PATHS,
        shared_paths=SHARED_INTEGRATION_PATHS,
        residual_markers=GEN1_RESIDUAL_MARKERS,
        gate_b_markers=GEN1_GATE_B_MARKERS,
        residual_edits=frozenset(
            {
                "context-guard-kit/setup_wizard.py",
                "plugins/context-guard/bin/context-guard-setup",
            }
        ),
    ),
)

# F-7 append-only anchor. Each digest binds one complete, canonical Generation
# record (subjects, owned path sets, residual contract, Gate-B markers, and
# declared residual edits). A routine re-bless appends both a Generation and its
# digest; editing or deleting an already shipped record makes the proof fail
# before it consults git history.
GENERATION_RECORD_FINGERPRINTS: tuple[str, ...] = (
    "b7cd908dcf516350ba0ac41f9db0043bc19ef5805550acb0a6667a51af6cd62b",
    "77f3117dff264c2fac25ea338af7d7cda6ff66c28e01aa479390e1109e9db7e2",
    "6a70a0217c89ed0c06767c95197449323fc62a1d22fda5c4639e83688e2da19f",
    "5cce305d7ed8b55f8f9300dc5a449fc36a555cb014516e5f81205ac950ddac33",
    "0d2009b33050312910525ec47d62d9bb12c0a625358dd6337b6b6b39c7dbab06",
    "e2dcb006bf5f30b4837c0b9716da2291a3ce8f753b02aec408fde9b9454a4ed2",
    "97ff6b1ea219c5aaf6d2a913e442fa50861365f237ab7a6cb80c7f0b1f6f3934",
    "f4891db1972aa5f423ad7942e58746371ff40b4ba3f9c73d8310b66b93ea6ae3",
)
GENERATION_FINGERPRINT_SOURCE_PATH = "scripts/verify_gate_b_rollback.py"


class ProofError(RuntimeError):
    """Raised when the Gate-B rollback contract no longer holds."""


class ProofHistoryUnavailable(ProofError):
    """Raised when a checkout cannot inspect the durable proof history."""


def proof_environment() -> dict[str, str]:
    env = os.environ.copy()
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        env.pop(key, None)
    env.update(
        {
            "GIT_AUTHOR_NAME": "ContextGuard rollback proof",
            "GIT_AUTHOR_EMAIL": "rollback-proof@example.invalid",
            "GIT_COMMITTER_NAME": "ContextGuard rollback proof",
            "GIT_COMMITTER_EMAIL": "rollback-proof@example.invalid",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            # 컴포넌트 경로 문자열은 여러 곳에서 git pathspec으로 넘어간다
            # (``path_exists_in_tree``의 ls-tree, ``prove_current_revert_order``의
            # diff). pathspec 문법에서 ``*``/``?``/``[``는 glob이고 선행 ``:``는
            # magic 접두사이므로, 그런 문자를 담은 경로는 '자기 자신'이 아니라
            # 패턴으로 해석된다 — ``:(exclude)...`` 형태면 오히려 다른 경로를
            # 검사 대상에서 빼버린다. 경로 집합은 세대마다 다시 선언되므로 오늘의
            # 18개가 순수 ASCII라는 사실에 기댈 수 없다. 모든 pathspec을 리터럴로
            # 강제한다 — 이 증명에서 glob이 의도된 곳은 한 군데도 없다.
            "GIT_LITERAL_PATHSPECS": "1",
        }
    )
    return env


def run_git(
    repo: Path,
    *args: str,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "-C",
            str(repo),
            *args,
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=proof_environment(),
        check=False,
    )
    if check and proc.returncode:
        detail = (proc.stderr or proc.stdout).strip()
        raise ProofError(f"git {' '.join(args)} failed: {detail}")
    return proc


def commit_paths(repo: Path, commit: str) -> frozenset[str]:
    proc = run_git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", commit)
    return frozenset(line for line in proc.stdout.splitlines() if line)


def path_exists_in_tree(repo: Path, commit: str, path: str) -> bool:
    """주어진 커밋의 트리에 경로가 존재하는지 확인한다 (D5 헬퍼).

    ``--name-status`` 기반 헬퍼는 쓰지 않는다 — 서로소·경로 집합 고정 체인에서는
    상태(M/D) 비교 자체가 laundering을 구별하는 정보를 주지 않기 때문이다
    (Decision D5 참고). 트리 존재 여부만 직접 묻는다.

    ``git cat-file -e <commit>:<path>``는 쓰지 않는다. 그 형태는 '트리에 경로
    없음'과 '잘못된 리비전·손상된 객체' 양쪽에 똑같이 128을 돌려주므로, 종료
    코드로 둘을 가를 수 없다(1은 나오지 않는다 — 실측 확인). 두 경우를 '부재'로
    합치면 인프라 실패가 곧 통과가 된다: D5는 before/after가 함께 비어 같아지고,
    C3-b는 실제 파일 내용을 검사 표면에서 빼 버린다 — 릴리스 게이트가
    fail-open 한다.

    ``git ls-tree``는 정확히 필요한 분리를 준다. 커밋이 유효하면 경로가 없어도
    종료 0에 빈 출력이고, 리비전 자체가 나쁘면 0이 아닌 종료로 실패한다. 따라서
    ``check=True``로 호출해 인프라 실패는 ``ProofError``로 큰 소리를 내게 하고,
    부재는 출력이 비었는지로만 판단한다.

    ``-z``는 선택이 아니라 필수다. 줄 단위 출력에서는 git이 ASCII 밖 경로를
    C 스타일로 따옴표 처리해(``"hangul_\\355\\225\\234..."``) 원래 경로 문자열과
    일치하지 않게 되고, 그러면 존재하는 경로가 '부재'로 읽혀 정확히 이 함수가
    막으려던 fail-open이 되살아난다. NUL 구분 출력은 따옴표 처리를 하지 않는다.

    ``--name-only`` 대신 전체 출력을 파싱해 객체 타입까지 본다. ``ls-tree``는
    ``-r`` 없이도 트리 엔트리를 그대로 보고하므로, 파일이 같은 이름의 디렉터리로
    바뀌어도 이름만 비교하면 '여전히 존재'로 읽힌다 — D5가 파일→디렉터리 교체를
    변화 없음으로 통과시킨다. 컴포넌트 경로는 언제나 blob이므로 blob만 존재로 센다.
    """
    proc = run_git(repo, "ls-tree", "-z", commit, "--", path)
    for entry in proc.stdout.split("\0"):
        if not entry:
            continue
        info, _, name = entry.partition("\t")
        fields = info.split()
        if name == path and len(fields) >= 2 and fields[1] == "blob":
            return True
    return False


def is_shallow_repository(repo: Path) -> bool:
    proc = run_git(repo, "rev-parse", "--is-shallow-repository", check=False)
    if proc.returncode:
        detail = (proc.stderr or proc.stdout).strip()
        raise ProofHistoryUnavailable(
            "full Gate-B proof history is unavailable: "
            f"could not inspect repository depth ({detail or f'exit {proc.returncode}'})"
        )
    return proc.stdout.strip() == "true"


def changed_paths(repo: Path, left: str, right: str) -> frozenset[str]:
    # --no-renames: 이름을 바꾼 동결 경로도 옛 이름 그대로 '변경됨'으로 보고되게
    # 강제한다. rename 탐지가 켜져 있으면 옛 경로는 diff에서 사라지고 새 경로만
    # 나타나는데, 새 경로는 컴포넌트 경로 집합에 없으므로 겹침 검사를 조용히
    # 통과시킨다 — 동결 회피 진단 공백(rename 구멍)이었다.
    proc = run_git(repo, "diff", "--no-renames", "--name-only", left, right)
    return frozenset(line for line in proc.stdout.splitlines() if line)


def find_unique_subject(
    repo: Path,
    source_head: str,
    subject: str,
    *,
    history_may_be_truncated: bool,
) -> str:
    proc = run_git(
        repo,
        "log",
        "--format=%H%x00%s",
        f"{BASE_COMMIT}..{source_head}",
        check=False,
    )
    if proc.returncode:
        # 이 `git log BASE_COMMIT..source_head` 호출은 실전 저장소 상태로는 실패로
        # 도달할 수 없다 — 호출 시점에 resolve_source_head가 이미
        # `merge-base --is-ancestor`를 exit 0으로 통과시켰고, **그 호출 자체가
        # BASE_COMMIT의 커밋 해석을 요구한다**. 따라서 두 인자 모두 유효하고
        # 정렬된 커밋이며, 객체 DB 손상이 아닌 한 `git log A..B`에는 실패 모드가
        # 없다. (이 자리에 예전에는 별도의 `commit_exists` 가드가 있었으나 같은
        # 커밋에서 삭제됐다 — ancestor 호출이 이미 같은 보증을 주고, 실패 시
        # exit 코드가 0도 1도 아닌 128이라 뒤따르는 ancestry 오류 분기가 잡는다.
        # 근거 실측은 아래 문서 참조.) 트루케이티드 분기(304-307번째 줄)도
        # 마찬가지로 이론상으로만 도달 가능하다(얕은 클론의 shallow boundary 커밋
        # 자체가 손상된 극단적 graft 케이스) — 둘 다 unreachable-by-construction으로
        # 문서화만 한다.
        # 근거: .omc/research/gate-b-guard-coverage-20260729.md, #3/#4 분류.
        detail = (proc.stderr or proc.stdout).strip()
        if history_may_be_truncated:
            raise ProofHistoryUnavailable(
                "full Gate-B proof history is unavailable: "
                f"could not inspect proof commits ({detail or f'exit {proc.returncode}'})"
            )
        raise ProofError(
            f"could not inspect Gate-B proof commits: {detail or f'exit {proc.returncode}'}"
        )
    matches = []
    for raw in proc.stdout.splitlines():
        commit, separator, actual_subject = raw.partition("\0")
        if separator and actual_subject == subject:
            matches.append(commit)
    if not matches and history_may_be_truncated:
        raise ProofHistoryUnavailable(
            "full Gate-B proof history is unavailable: "
            f"reachable commit {subject!r} was not found"
        )
    if len(matches) != 1:
        # 이 유일성 검사는 subject마다 독립적으로 호출되며, 모든 세대의 모든
        # subject가 같은 BASE_COMMIT..source_head 범위에서 찾아진다(D4). 따라서
        # 두 세대가 같은 subject 문자열을 재사용하면(세대 내부든 세대 간이든)
        # 이 호출이 그 subject에 대해 2개 이상을 찾아 여기서 발화한다 — subject
        # 전역 고유성을 위한 별도 코드가 필요하지 않다.
        raise ProofError(
            f"expected exactly one reachable commit named {subject!r}, found {len(matches)}"
        )
    return matches[0]


def file_at(repo: Path, commit: str, path: str) -> str:
    return run_git(repo, "show", f"{commit}:{path}").stdout


def assert_residual_contract(repo: Path, generation: Generation, bless: str) -> None:
    """이 세대의 bless 트리가 이 세대의 무관 기능 마커를 보존하는지 검사한다.

    모든 세대(은퇴 포함)에 대해 검사된다 — 불변 커밋만 읽으므로 첫 통과 이후
    항상 참인 상수로 영구히 남는다.
    """
    for path, markers in generation.residual_markers.items():
        content = file_at(repo, bless, path)
        for marker in markers:
            if marker not in content:
                raise ProofError(
                    f"generation {generation.name!r} Gate-B-free residual lost "
                    f"unrelated feature marker {marker!r} in {path}"
                )


def assert_disjoint_paths(generation: Generation) -> None:
    """세 컴포넌트 경로 집합이 서로소인지 검사한다 (I1, 신규 구현).

    ``python -O``에서도 소거되지 않도록 ``assert`` 문을 쓰지 않고 명시적으로
    ``raise``한다. 서로소가 깨지면 apply_then_revert가 어느 reapply 커밋의
    소유인지 모호한 경로를 만들어 트리 동등성 보증이 약화된다.
    """
    pairs = (
        ("b1", generation.b1_paths, "b2", generation.b2_paths),
        ("b1", generation.b1_paths, "shared-integration", generation.shared_paths),
        ("b2", generation.b2_paths, "shared-integration", generation.shared_paths),
    )
    for left_name, left_paths, right_name, right_paths in pairs:
        overlap = left_paths & right_paths
        if overlap:
            raise ProofError(
                f"generation {generation.name!r} component paths overlap between "
                f"{left_name} and {right_name}: {sorted(overlap)!r}"
            )


# 컴포넌트 경로가 사람의 셸·터미널에서 안전하게 리터럴로 남으려면 선행 ``:``
# 뿐 아니라 제어문자, 공백, 셸/glob 메타문자도 없어야 한다. 공백은
# `-- $(jq -r ...)` 같은 인용 없는
# 확장에서 워드 스플리팅으로 경로 하나를 여러 토큰으로 쪼개 사람의 리뷰 diff에서
# 조용히 사라지게 만든다(런북은 이제 인용된 배열 확장을 쓰지만, 레코드 자체를
# 안전하게 만들어 두면 인용을 놓친 미래의 실수에도 방어선이 남는다). glob
# 메타문자(``*?[``)는 git 자체를 속이지는 못한다고 측정으로 확인했지만(git은
# wildmatch보다 먼저 정확 일치를 시도한다), 셸 쪽 경로명 확장은 별개의 위험이라
# 함께 막는다. C0/DEL/C1 제어문자는 ``jq -r``가 원시 바이트로 내보낼 때 커서
# 이동·지움 같은 터미널 효과로 이웃 경로를 숨길 수 있으므로 전 범위를 거부한다.
# ``\s``는 비ASCII 공백류까지 계속 맡는다.
_UNSAFE_COMPONENT_PATH_CHARS = re.compile(
    r"[\x00-\x1f\x7f-\x9f\s*?\[\]{}$`\"'\\|;&<>()~!#]"
)


def generation_record_fingerprint(generation: Generation) -> str:
    """Return the domain-separated canonical SHA-256 for one generation record."""
    payload = {
        "name": generation.name,
        "subjects": {
            "bless": generation.bless_subject,
            "b1": generation.b1_subject,
            "b2": generation.b2_subject,
            "shared-integration": generation.shared_subject,
        },
        "paths": {
            "b1": sorted(generation.b1_paths),
            "b2": sorted(generation.b2_paths),
            "shared-integration": sorted(generation.shared_paths),
        },
        "residual_markers": {
            path: list(generation.residual_markers[path])
            for path in sorted(generation.residual_markers)
        },
        "gate_b_markers": [
            {"literal": marker.literal, "owner_path": marker.owner_path}
            for marker in generation.gate_b_markers
        ],
        "residual_edits": sorted(generation.residual_edits),
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(
        b"contextguard.gate-b-generation-record.v1\0" + encoded
    ).hexdigest()


def assert_generation_fingerprint_ledger_matches(
    generations: tuple[Generation, ...],
    fingerprints: tuple[str, ...],
) -> None:
    """Reject deletion or mutation of a record bound by the shipped ledger."""
    if len(generations) != len(fingerprints):
        raise ProofError(
            "generation fingerprint ledger length mismatch: "
            f"records={len(generations)} fingerprints={len(fingerprints)}"
        )
    for generation, expected in zip(generations, fingerprints):
        actual = generation_record_fingerprint(generation)
        if actual != expected:
            raise ProofError(
                "generation fingerprint ledger mismatch for "
                f"{generation.name!r}: actual={actual} expected={expected}"
            )


def generation_fingerprint_ledger_from_source(
    source: str,
    *,
    revision: str,
) -> tuple[str, ...] | None:
    """Read the literal fingerprint tuple from one historical verifier source."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise ProofError(
            f"could not parse historical Gate-B verifier at {revision}: {exc.msg}"
        ) from exc

    values: list[ast.expr] = []
    for node in tree.body:
        if isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and (
                node.target.id == "GENERATION_RECORD_FINGERPRINTS"
            ):
                if node.value is not None:
                    values.append(node.value)
        elif isinstance(node, ast.Assign):
            if any(
                isinstance(target, ast.Name)
                and target.id == "GENERATION_RECORD_FINGERPRINTS"
                for target in node.targets
            ):
                values.append(node.value)
    if not values:
        return None
    if len(values) != 1:
        raise ProofError(
            "historical Gate-B verifier declares "
            f"GENERATION_RECORD_FINGERPRINTS {len(values)} times at {revision}"
        )
    try:
        ledger = ast.literal_eval(values[0])
    except (TypeError, ValueError) as exc:
        raise ProofError(
            "historical GENERATION_RECORD_FINGERPRINTS is not a literal tuple at "
            f"{revision}"
        ) from exc
    if not isinstance(ledger, tuple) or any(
        not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
        for value in ledger
    ):
        raise ProofError(
            "historical GENERATION_RECORD_FINGERPRINTS is malformed at "
            f"{revision}"
        )
    return ledger


def assert_generation_fingerprint_history_append_only(
    repo: Path,
    source_head: str,
    current: tuple[str, ...],
    *,
    history_may_be_truncated: bool = False,
) -> None:
    """Require every committed fingerprint ledger to be a prefix of the current one."""
    if not path_exists_in_tree(repo, source_head, GENERATION_FINGERPRINT_SOURCE_PATH):
        raise ProofError(
            "generation fingerprint source path is missing at "
            f"{source_head}: {GENERATION_FINGERPRINT_SOURCE_PATH!r}"
        )
    history = run_git(
        repo,
        "log",
        "--format=%H",
        "--follow",
        source_head,
        "--",
        GENERATION_FINGERPRINT_SOURCE_PATH,
    ).stdout.splitlines()
    observed = 0
    for commit in history:
        shown = run_git(
            repo,
            "show",
            f"{commit}:{GENERATION_FINGERPRINT_SOURCE_PATH}",
            check=False,
        )
        if shown.returncode:
            continue
        historical = generation_fingerprint_ledger_from_source(
            shown.stdout,
            revision=commit,
        )
        if historical is None:
            continue
        observed += 1
        if len(historical) > len(current) or current[: len(historical)] != historical:
            raise ProofError(
                "historical generation fingerprint ledger is not a prefix of the "
                f"current ledger: revision={commit} historical={len(historical)} "
                f"current={len(current)}"
            )
    if not observed and not history_may_be_truncated:
        raise ProofError(
            "no committed generation fingerprint ledger was reachable from "
            f"{source_head}: the append-only history check would pass vacuously"
        )


def assert_generation_records_wellformed(generations: tuple[Generation, ...]) -> None:
    """git 없이 세대 레코드 자체의 자기 신고 구멍을 막는다 (D6, 신규 구현).

    ``python -O``에서도 소거되지 않도록 ``assert`` 문을 쓰지 않고 명시적으로
    ``raise``한다. 다섯 가지를 검사한다(아래 번호는 코드 순서와 다르다 — 기존
    순서를 그대로 두고 항목만 추가했다).

    1. ``name`` 전역 고유성. ``resolve_history``의 ``all_commits``는 ``name``을
       키로 쓰므로, 이름이 겹치면 앞 세대의 커밋이 조용히 덮어써지고 D3/D5가
       같은 bless를 자기 자신과 비교해 통째로 공허해진다 — 재축복 커밋 안의
       한 단어짜리 편집으로 이번 PR이 추가하는 두 방어선이 모두 꺼진다.
    2. ``gate_b_markers``/``residual_markers`` 비어 있지 않고, needle 목록과
       리터럴이 실제로 무언가를 구속함. 빈 컬렉션은 C3-a/C3-b/잔여 계약을 0회
       루프로 만들어 공허하게 통과시킨다. 컬렉션이 비었는지만 보면 바닥이 옮겨질
       뿐이라 ``{"p": ()}``와 ``{"p": ("",)}``도 함께 막는다.

    4. Gate-B 마커 전방 이월(forward carry). 세대 N은 세대 N-1의
       ``gate_b_markers``를 모두 포함해야 한다. 비어 있지 않기만 요구하면
       재축복자가 자기 bless를 구속할 리터럴 집합을 스스로 고르게 되어, nonce
       마커 하나를 선언하고(자기 b1 커밋이 HEAD에 그 nonce를 넣으면 C3-a 통과,
       bless는 그보다 앞서므로 C3-b 통과) 진짜 Gate-B 리터럴은 bless에 그대로
       남겨두는 세탁이 성립한다. 이월은 *소급*이 아니다 — 과거 bless를 새 마커로
       다시 검사하는 것이 아니라, 새 bless를 과거 마커로 검사할 뿐이다. 따라서
       세대별 비소급 성질(U-12)은 그대로 보존된다. 마커를 버리는 탈출 필드는
       두지 않는다: 그런 필드는 바로 그 세탁을 잡을 마커를 지목해 버리게 해준다.
       리터럴이 정말로 사라졌다면 C3-a가 HEAD에 대해 먼저 큰 소리로 실패하므로
       그 경우는 이미 자기 신고된다(P5).
    3. 마커 소유 경로가 그 세대의 컴포넌트 경로에 속함. C3-b는 bless의 모든
       컴포넌트 경로를 검사하지만, C3-a는 live HEAD의 선언된 소유 경로에서
       리터럴을 확인하고 전방 이월도 그 소유 관계를 기준으로 한다. 컴포넌트 밖
       경로를 소유자로 허용하면 그 두 보증이 세대의 동결 경계 밖을 가리킨다.
    5. 컴포넌트 경로가 리터럴이고 사람의 셸·터미널에서 안전함. 선행 ``:``는 git
       pathspec 매직이고, 제어문자·공백·셸/glob 메타문자는 런북이 지시하는
       사람의 리뷰 diff를 조작하거나 경로를 조용히 잃게 만든다 — 기계 게이트는
       ``GIT_LITERAL_PATHSPECS=1``로 전체 경로를 그대로 보므로 exit 0인 채
       사람 검토만 좁아지는 비대칭이 생긴다. 자세한 근거는 아래 검사부의
       주석을 참고한다.
    """
    if not generations:
        raise ProofError("GENERATIONS is empty: the proof has no anchor")
    names = [generation.name for generation in generations]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise ProofError(f"duplicate generation names: {duplicates!r}")
    for generation in generations:
        if not generation.gate_b_markers:
            raise ProofError(
                f"generation {generation.name!r} declares no Gate-B markers: "
                "the reverse anti-laundering check would pass vacuously"
            )
        if not generation.residual_markers:
            raise ProofError(
                f"generation {generation.name!r} declares no residual markers: "
                "the unrelated-feature preservation contract would pass vacuously"
            )
        components = generation.all_component_paths
        # 5. 컴포넌트 경로는 리터럴이고 셸에서 안전해야 한다. 기계 게이트 자체는
        #    이미 ``GIT_LITERAL_PATHSPECS=1``로 pathspec 매직을 무력화하지만,
        #    런북은 ``review_pathspec``을 **사람의 셸에 붙여넣으라**고 지시하고
        #    거기엔 그 환경변수가 없다. 따라서 ``:(exclude)…`` 꼴 경로는 기계
        #    검사에는 잡히면서 사람이 보는 리뷰 diff에서만 조용히 사라질 수
        #    있다. 공백도 같은 비대칭을 다른 방식으로 만든다: 인용 없는 셸
        #    확장은 공백에서 워드 스플리팅해 경로 하나를 여러 토큰으로 쪼개고,
        #    git은 그중 일부만(또는 전혀 매치하지 않는 조각을) 받아 사람의 diff가
        #    조용히 좁아진다. 런북 명령 자체는 인용된 배열 확장으로 고쳤지만,
        #    레코드 단계에서도 막아 두 겹의 방어선을 유지한다.
        for path in sorted(components):
            if path.startswith(":"):
                raise ProofError(
                    f"generation {generation.name!r} declares a non-literal component "
                    f"path {path!r}: a leading ':' is git pathspec magic and would hide "
                    "the path from the human review diff described in the runbook"
                )
            unsafe = _UNSAFE_COMPONENT_PATH_CHARS.search(path)
            if unsafe:
                raise ProofError(
                    f"generation {generation.name!r} declares a component path "
                    f"{path!r} containing unsafe character {unsafe.group()!r}: "
                    "control characters can alter terminal rendering, while "
                    "whitespace and shell/glob metacharacters can narrow or split "
                    "the path when a human reviews review_pathspec, hiding it from "
                    "the review diff"
                )
        for marker in generation.gate_b_markers:
            if not marker.literal.strip():
                raise ProofError(
                    f"generation {generation.name!r} declares an empty Gate-B marker "
                    f"literal for {marker.owner_path!r}"
                )
            if marker.owner_path not in components:
                raise ProofError(
                    f"generation {generation.name!r} Gate-B marker "
                    f"{marker.literal!r} owner path {marker.owner_path!r} is not a "
                    "component path of that generation"
                )
        # 컬렉션이 비어 있지 않은지만 보면 바닥이 옮겨질 뿐 막히지 않는다.
        # ``{"p": ()}``는 안쪽 루프가 0회라 아무 needle도 검사하지 않고,
        # ``{"p": ("",)}``는 ``"" in content``가 항상 참이라 어떤 내용이든 통과한다.
        # 둘 다 dict는 비어 있지 않으므로 위 검사를 그대로 빠져나간다.
        for path, needles in generation.residual_markers.items():
            if path not in components:
                raise ProofError(
                    f"generation {generation.name!r} residual marker path {path!r} is "
                    "not a component path of that generation"
                )
            if not needles:
                raise ProofError(
                    f"generation {generation.name!r} declares no residual marker "
                    f"needles for {path!r}: that path's contract would pass vacuously"
                )
            for needle in needles:
                if not needle.strip():
                    raise ProofError(
                        f"generation {generation.name!r} declares an empty residual "
                        f"marker needle for {path!r}: it matches any content"
                    )
    for previous, current in zip(generations, generations[1:]):
        # 이월 범위는 '현 세대가 여전히 소유한 경로의 마커'로 한정한다. 경로 자체를
        # 컴포넌트 집합에서 뺀 경우까지 이월을 강요하면 규칙 3(소유 경로는 컴포넌트
        # 경로)과 충돌해 구성 자체가 불가능해진다. 경로를 빼는 것은 별개의 알려진
        # 좁히기 벡터이고, 그쪽은 ``review_pathspec``이 전 세대 합집합이라 리뷰에
        # 계속 드러난다. 여기서 막는 것은 '경로는 그대로 들고 있으면서 그 경로를
        # 구속하던 마커만 조용히 버리는' 세탁이다.
        carried = {
            marker
            for marker in previous.gate_b_markers
            if marker.owner_path in current.all_component_paths
        }
        dropped = carried - set(current.gate_b_markers)
        if dropped:
            raise ProofError(
                f"generation {current.name!r} drops Gate-B markers declared by "
                f"{previous.name!r} for paths it still owns: "
                f"{sorted((marker.literal, marker.owner_path) for marker in dropped)!r}"
            )


def resolve_generation_commits(
    repo: Path,
    source_head: str,
    generation: Generation,
    *,
    history_may_be_truncated: bool,
) -> dict[str, str]:
    """세대 하나의 4개 subject를 각각 유일한 도달 가능 커밋으로 해석한다."""
    subjects = {
        "bless": generation.bless_subject,
        "b1": generation.b1_subject,
        "b2": generation.b2_subject,
        "shared-integration": generation.shared_subject,
    }
    return {
        role: find_unique_subject(
            repo,
            source_head,
            subject,
            history_may_be_truncated=history_may_be_truncated,
        )
        for role, subject in subjects.items()
    }


def assert_generation_structure(
    repo: Path,
    generation: Generation,
    commits: dict[str, str],
) -> None:
    """세대 하나의 부모 체인·경로 집합·서로소 불변을 검사한다 (모든 세대 공통).

    부모 체인과 경로 집합 동등은 PR #240부터 있던 보증의 형태 보존이고,
    서로소는 이번 변경이 최초로 구현하는 검사다(코드에 없었고 오늘은
    우연히 성립했을 뿐이다).
    """
    expected_parents = (
        (commits["b1"], commits["bless"]),
        (commits["b2"], commits["b1"]),
        (commits["shared-integration"], commits["b2"]),
    )
    for commit, expected_parent in expected_parents:
        parent = run_git(repo, "rev-parse", f"{commit}^").stdout.strip()
        if parent != expected_parent:
            raise ProofError(
                f"generation {generation.name!r} parent mismatch: {commit}^={parent}, "
                f"expected {expected_parent}"
            )
    expected_paths = {
        "bless": generation.all_component_paths,
        "b1": generation.b1_paths,
        "b2": generation.b2_paths,
        "shared-integration": generation.shared_paths,
    }
    for name, expected in expected_paths.items():
        actual = commit_paths(repo, commits[name])
        if actual != expected:
            raise ProofError(
                f"generation {generation.name!r} {name} path set changed: "
                f"actual={sorted(actual)!r} expected={sorted(expected)!r}"
            )
    assert_disjoint_paths(generation)


def assert_gate_b_markers_absent_from_bless(
    repo: Path,
    generation: Generation,
    bless: str,
) -> None:
    """활성 세대의 bless 트리가 활성 세대의 Gate-B 마커를 포함하지 않는지 검사한다
    (C3-b, 활성 세대 한정).

    선언된 소유 경로만 보면 re-blesser가 같은 리터럴을 다른 컴포넌트 파일로
    옮겨 C3-b를 우회할 수 있다. 따라서 bless 트리에 남아 있는 모든 컴포넌트
    파일의 내용을 읽고, 모든 마커를 그 전체 표면에 대해 검사한다. 개별 경로가
    bless에서 삭제된 경우는 구조 검사가 이미 구속하지만, 모든 컴포넌트 경로가
    사라지면 검사가 공허해지므로 명시적으로 실패한다.
    """
    component_contents = {
        path: file_at(repo, bless, path)
        for path in sorted(generation.all_component_paths)
        if path_exists_in_tree(repo, bless, path)
    }
    if not component_contents:
        raise ProofError(
            f"generation {generation.name!r} evaluated no Gate-B markers against "
            f"bless tree {bless}: every component path is absent there, so the "
            "reverse anti-laundering check would pass vacuously"
        )
    for marker in generation.gate_b_markers:
        for path, content in component_contents.items():
            if marker.literal in content:
                raise ProofError(
                    f"generation {generation.name!r} bless tree {bless} retains Gate-B "
                    f"marker {marker.literal!r} in {path} "
                    f"(declared owner {marker.owner_path})"
                )


def assert_gate_b_markers_present_at_head(
    repo: Path,
    source_head: str,
    generation: Generation,
) -> None:
    """활성 세대의 Gate-B 마커가 현재 HEAD에 실제로 존재하는지 검사한다
    (C3-a, 활성 세대 한정, HEAD 의존적이므로 자기 무효화).

    마커 리터럴이 개명 등으로 rot하면 이 검사가 먼저 큰 소리로 실패해,
    부재 검사(C3-b)가 공허하게 통과하는 것을 막는다(P5).
    """
    for marker in generation.gate_b_markers:
        # 소유 경로가 HEAD에서 통째로 사라진 경우를 먼저 걸러 낸다. 그냥 file_at을
        # 부르면 ``git show ... failed``라는 날것의 메시지가 올라와, 실제 원인
        # (마커가 가리키던 표면이 HEAD에 없다)이 진단에서 사라진다.
        if not path_exists_in_tree(repo, source_head, marker.owner_path):
            raise ProofError(
                f"generation {generation.name!r} Gate-B marker {marker.literal!r} "
                f"missing from {marker.owner_path} at HEAD {source_head}: "
                "the owner path itself does not exist there"
            )
        content = file_at(repo, source_head, marker.owner_path)
        if marker.literal not in content:
            raise ProofError(
                f"generation {generation.name!r} Gate-B marker {marker.literal!r} "
                f"missing from {marker.owner_path} at HEAD {source_head}"
            )


def assert_declared_residual_edits(
    repo: Path,
    previous: Generation,
    previous_commits: dict[str, str],
    current: Generation,
    current_commits: dict[str, str],
) -> None:
    """직전 세대 대비 잔여물 컴포넌트 경로 변경이 선언과 정확히 일치하는지
    검사한다 (D3).

    두 세대가 공유하는 컴포넌트 경로 중 실제로 bless 내용이 바뀐 경로가
    ``current.residual_edits``와 다르면 미선언 잔여물 편집으로 실패한다.
    선언 자체는 자기 신고이지만, 검사의 가치는 반대편에 있다 — 선언되지 않은
    경로 변경이 laundering의 가장 자연스러운 형태이고 이것이 그것을 잡는다.
    """
    shared_components = current.all_component_paths & previous.all_component_paths
    changed = changed_paths(repo, previous_commits["bless"], current_commits["bless"])
    actual_edits = changed & shared_components
    if actual_edits != current.residual_edits:
        raise ProofError(
            f"generation {current.name!r} residual edits undeclared: "
            f"actual={sorted(actual_edits)!r} declared={sorted(current.residual_edits)!r}"
        )


def assert_residual_existence_invariant(
    repo: Path,
    previous: Generation,
    previous_commits: dict[str, str],
    current: Generation,
    current_commits: dict[str, str],
) -> None:
    """세대 간 공유 컴포넌트 경로의 존재 여부 집합이 그대로 보존되는지 검사한다
    (D5, 필수).

    존재하던 경로가 사라지거나(진짜 삭제해야 할 것을 숨김) 부재하던 경로가
    나타나면(삭제 대신 수정해 세탁본을 남김) laundering일 수 있으므로 실패한다.
    ``residual_edits`` 선언으로는 우회되지 않는다 — D3는 *내용* 변화를,
    D5는 *존재* 여부를 다루는 직교하는 축이다. 개수가 아니라 집합을 비교한다 —
    개수 비교는 상쇄 쌍(하나 사라지고 하나 나타남)으로 우회할 수 있다.
    """
    shared_components = current.all_component_paths & previous.all_component_paths
    before = frozenset(
        path
        for path in shared_components
        if path_exists_in_tree(repo, previous_commits["bless"], path)
    )
    after = frozenset(
        path
        for path in shared_components
        if path_exists_in_tree(repo, current_commits["bless"], path)
    )
    if before != after:
        raise ProofError(
            f"generation {current.name!r} residual existence set changed: "
            f"resurrected={sorted(after - before)!r} vanished={sorted(before - after)!r}"
        )


def resolve_history(
    repo: Path,
    source_head: str,
    *,
    history_may_be_truncated: bool,
) -> dict[str, dict[str, str]]:
    """세대 목록 전체를 해석하고 세대별·세대 간 불변을 검사한다.

    모든 세대(은퇴 포함)는 구조·서로소·잔여 계약을 영원히 검사받는다.
    활성 세대만 HEAD에 대한 동결과 Gate-B 마커 존재/부재를 추가로 검사받는다.
    세대 간 잔여물 편집 선언(D3)과 존재 집합 불변(D5)은 연속한 두 세대마다
    검사한다 — 세대가 하나뿐인 PR-1에서는 이 루프가 비어 있어 완전히 불활성이다.
    """
    # git이 필요 없는 레코드 검사를 먼저 돌린다. 커밋 해석 뒤에 두면 얕은
    # 체크아웃에서 ProofHistoryUnavailable(종료 3)이 먼저 나서 순수 레코드
    # 불변이 아예 평가되지 않는다.
    assert_generation_records_wellformed(GENERATIONS)
    for generation in GENERATIONS:
        assert_disjoint_paths(generation)

    all_commits: dict[str, dict[str, str]] = {}
    for generation in GENERATIONS:
        commits = resolve_generation_commits(
            repo,
            source_head,
            generation,
            history_may_be_truncated=history_may_be_truncated,
        )
        assert_generation_structure(repo, generation, commits)
        assert_residual_contract(repo, generation, commits["bless"])
        all_commits[generation.name] = commits

    for previous, current in zip(GENERATIONS, GENERATIONS[1:]):
        previous_commits = all_commits[previous.name]
        current_commits = all_commits[current.name]
        assert_declared_residual_edits(
            repo, previous, previous_commits, current, current_commits
        )
        assert_residual_existence_invariant(
            repo, previous, previous_commits, current, current_commits
        )

    active = GENERATIONS[-1]
    active_commits = all_commits[active.name]
    post_component_changes = changed_paths(
        repo, active_commits["shared-integration"], source_head
    )
    overlap = post_component_changes & active.all_component_paths
    if overlap:
        raise ProofError(
            f"component paths changed after durable reapplication: {sorted(overlap)!r}"
        )
    # 순서가 의미를 가진다. C3-a(HEAD 존재)가 먼저다 — 마커 리터럴이 개명 등으로
    # rot하면 C3-b는 '어디에도 없으니 bless에도 없다'로 조용히 통과하므로, 그보다
    # 먼저 C3-a가 큰 소리로 실패해야 자기 무효화(P5)가 문서대로 작동한다. 뒤집으면
    # 최종 판정은 같아도 진단이 '잔여물이 마커를 품었다'가 아니라 침묵이 된다.
    assert_gate_b_markers_present_at_head(repo, source_head, active)
    assert_gate_b_markers_absent_from_bless(repo, active, active_commits["bless"])
    return all_commits


def checkout(repo: Path, commit: str) -> None:
    run_git(repo, "checkout", "--quiet", "--detach", commit)


def apply_then_revert(
    repo: Path,
    base: str,
    component: str,
) -> dict[str, str]:
    checkout(repo, base)
    base_tree = run_git(repo, "rev-parse", f"{base}^{{tree}}").stdout.strip()
    run_git(repo, "cherry-pick", component)
    applied_commit = run_git(repo, "rev-parse", "HEAD").stdout.strip()
    applied_tree = run_git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()
    run_git(repo, "revert", "--no-edit", applied_commit)
    reverted_tree = run_git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()
    # 이 분기는 unreachable by construction이다 — 두 겹으로 증명됨:
    # (1) cherry-pick/revert가 충돌하면 run_git의 check=True가 그보다 먼저
    #     ProofError를 던진다(이 함수까지 도달하지 않는다);
    # (2) 충돌 없이 성공하면 git의 3-way merge 항등성(ours == merge-base일 때
    #     결과는 항상 theirs)에 의해 reverted_tree == base_tree가 보장된다 —
    #     revert는 (base=tree(applied_commit), ours=tree(HEAD)=applied_tree,
    #     theirs=tree(parent(applied_commit))=base_tree)의 3-way merge이고
    #     parent(applied_commit)은 cherry-pick이 base 위에 만든 커밋이므로 base다.
    # 이 검사가 이 파일의 중심 주장(apply/revert가 트리를 복원한다)이면서도
    # mutation으로 죽지 않는 것은 결함이 아니라, 그 불변이 git 자신에 의해
    # 강제된다는 뜻이다. 근거: .omc/research/gate-b-guard-coverage-20260729.md, #30.
    if reverted_tree != base_tree:
        raise ProofError(
            f"apply/revert tree mismatch for {component}: {reverted_tree} != {base_tree}"
        )
    return {
        "source_commit": component,
        "applied_tree": applied_tree,
        "reverted_tree": reverted_tree,
    }


def prove_current_revert_order(
    repo: Path,
    source_head: str,
    commits: dict[str, str],
    generation: Generation,
) -> dict[str, str]:
    """활성 세대만 검사되는 순서 있는 라이브 롤백(B1 -> B2 -> shared)을 증명한다."""
    checkout(repo, source_head)
    run_git(repo, "revert", "--no-edit", commits["b1"])
    b1_only = run_git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()

    checkout(repo, source_head)
    run_git(repo, "revert", "--no-edit", commits["b2"])
    b2_only = run_git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()

    checkout(repo, source_head)
    run_git(repo, "revert", "--no-edit", commits["b1"])
    after_b1 = run_git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()
    run_git(repo, "revert", "--no-edit", commits["b2"])
    after_b2 = run_git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()
    run_git(repo, "revert", "--no-edit", commits["shared-integration"])
    after_shared_commit = run_git(repo, "rev-parse", "HEAD").stdout.strip()
    after_shared = run_git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()

    residual_delta = run_git(
        repo,
        "diff",
        "--name-only",
        commits["bless"],
        after_shared_commit,
        "--",
        *sorted(generation.all_component_paths),
    ).stdout.splitlines()
    if residual_delta:
        raise ProofError(
            f"ordered Gate-B rollback does not restore durable residual: {residual_delta!r}"
        )
    rollback_delta = changed_paths(repo, source_head, after_shared_commit)
    if rollback_delta != generation.all_component_paths:
        raise ProofError(
            f"ordered rollback changed paths outside exact Gate-B set: "
            f"actual={sorted(rollback_delta)!r} "
            f"expected={sorted(generation.all_component_paths)!r}"
        )
    assert_residual_contract(repo, generation, after_shared_commit)
    return {
        "b1_only_revert_tree": b1_only,
        "b2_only_revert_tree": b2_only,
        "after_b1_revert_tree": after_b1,
        "after_b2_revert_tree": after_b2,
        "after_shared_revert_tree": after_shared,
    }


def review_pathspec() -> list[str]:
    """모든 세대의 컴포넌트 경로 합집합을 정렬된 리뷰 pathspec으로 반환한다.

    활성 세대만으로 도출하면 경로 집합을 좁히는 세대가 리뷰 대상에서 경로를
    숨길 수 있고, 하드코딩된 리터럴 목록은 세대가 경로를 추가하면 stale해진다.
    반드시 전 세대의 합집합을 써서 두 방향 모두를 막는다.
    """
    union: frozenset[str] = frozenset()
    for generation in GENERATIONS:
        union |= generation.all_component_paths
    return sorted(union)


def build_generations_report(
    all_commits: dict[str, dict[str, str]]
) -> list[dict[str, object]]:
    """세대별 이름·subject 4개·커밋 4개·활성 여부를 JSON 직렬화 가능한 형태로
    만든다."""
    active_name = GENERATIONS[-1].name
    return [
        {
            "name": generation.name,
            "subjects": {
                "bless": generation.bless_subject,
                "b1": generation.b1_subject,
                "b2": generation.b2_subject,
                "shared-integration": generation.shared_subject,
            },
            "commits": all_commits[generation.name],
            "active": generation.name == active_name,
        }
        for generation in GENERATIONS
    ]


def resolve_source_head(repo: Path) -> tuple[str, bool]:
    """HEAD를 해석하고 ``BASE_COMMIT``이 그 조상인지 확인한다.

    반환값은 ``(source_head, history_may_be_truncated)``다. 얕은 클론이거나
    ``BASE_COMMIT``을 찾을 수 없으면 ``ProofHistoryUnavailable``을,
    ``BASE_COMMIT``이 조상이 아니면 ``ProofError``를 던진다.
    """
    head = run_git(repo, "rev-parse", "HEAD", check=False)
    if head.returncode:
        detail = (head.stderr or head.stdout).strip()
        raise ProofHistoryUnavailable(
            "full Gate-B proof history is unavailable: "
            f"could not resolve HEAD ({detail or f'exit {head.returncode}'})"
        )
    source_head = head.stdout.strip()
    history_may_be_truncated = is_shallow_repository(repo)
    # 별도의 "BASE_COMMIT이 없다" 검사는 두지 않는다. commit_exists(BASE_COMMIT)이
    # 거짓인 모든 경우, 바로 아래 merge-base --is-ancestor 호출도 BASE_COMMIT
    # 자신을 해석해야 하므로 exit 0/1이 아닌 다른 코드로 실패하고, 그 실패는 이미
    # ancestry.returncode != 1 분기(ProofHistoryUnavailable, "could not inspect
    # ancestry")가 잡는다 — 메시지만 다를 뿐 판정은 갈라지지 않는 진짜 중복 검사였다
    # (검증: .omc/research/gate-b-guard-coverage-20260729.md, #34 분류).
    ancestry = run_git(
        repo,
        "merge-base",
        "--is-ancestor",
        BASE_COMMIT,
        source_head,
        check=False,
    )
    if ancestry.returncode:
        if ancestry.returncode != 1:
            detail = (ancestry.stderr or ancestry.stdout).strip()
            raise ProofHistoryUnavailable(
                "full Gate-B proof history is unavailable: "
                f"could not inspect ancestry ({detail or f'exit {ancestry.returncode}'})"
            )
        raise ProofError(f"Gate-B base {BASE_COMMIT} is not an ancestor of {source_head}")
    return source_head, history_may_be_truncated


def apply_and_revert_all_generations(
    repo: Path, all_commits: dict[str, dict[str, str]]
) -> dict[str, dict[str, dict[str, str]]]:
    """모든 세대(은퇴 포함)에 대해 apply/revert 트리 동등성을 증명한다.

    불변 커밋만 읽으므로 은퇴 세대에서도 첫 통과 이후 계속 참인 상수 검사로
    영구히 남는다.
    """
    results: dict[str, dict[str, dict[str, str]]] = {}
    for generation in GENERATIONS:
        commits = all_commits[generation.name]
        results[generation.name] = {
            "b1": apply_then_revert(repo, commits["bless"], commits["b1"]),
            "b2": apply_then_revert(repo, commits["bless"], commits["b2"]),
        }
    return results


def run_proof(repo: Path = ROOT) -> dict[str, object]:
    repo = repo.resolve()
    # 레코드 검사는 git을 전혀 쓰지 않으므로 ``resolve_source_head``보다도 앞선다.
    # 뒤에 두면 얕은 체크아웃(fetch-depth: 1처럼 BASE_COMMIT이 없는 경우)에서
    # ProofHistoryUnavailable(종료 3)이 먼저 나서, 망가진 레코드가 '증명 불가'로
    # 보고된다. 레코드 결함은 체크아웃 모양과 무관한 소스 결함이므로 어떤
    # 체크아웃에서도 똑같이 실패(종료 1)해야 한다.
    assert_generation_records_wellformed(GENERATIONS)
    for generation in GENERATIONS:
        assert_disjoint_paths(generation)
    assert_generation_fingerprint_ledger_matches(
        GENERATIONS,
        GENERATION_RECORD_FINGERPRINTS,
    )
    source_head, history_may_be_truncated = resolve_source_head(repo)
    assert_generation_fingerprint_history_append_only(
        repo,
        source_head,
        GENERATION_RECORD_FINGERPRINTS,
        history_may_be_truncated=history_may_be_truncated,
    )
    all_commits = resolve_history(
        repo,
        source_head,
        history_may_be_truncated=history_may_be_truncated,
    )

    active = GENERATIONS[-1]
    with tempfile.TemporaryDirectory(prefix="context-guard-gate-b-proof-") as tmp:
        proof_repo = Path(tmp) / "repo"
        run_git(repo, "clone", "--quiet", "--no-hardlinks", str(repo), str(proof_repo))
        generation_apply_results = apply_and_revert_all_generations(proof_repo, all_commits)
        active_commits = all_commits[active.name]
        revert_order = prove_current_revert_order(
            proof_repo, source_head, active_commits, active
        )

    active_apply = generation_apply_results[active.name]
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "ok",
        "repo": str(repo),
        "source_head": source_head,
        "base_commit": BASE_COMMIT,
        "durable_commits": active_commits,
        "b1": active_apply["b1"],
        "b2": active_apply["b2"],
        "revert_order": ["b1", "b2", "shared-integration"],
        "generations": build_generations_report(all_commits),
        "review_pathspec": review_pathspec(),
        **revert_order,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="prove durable Gate-B component rollback")
    parser.add_argument("--json", action="store_true", help="emit machine-readable evidence")
    parser.add_argument(
        "--repo",
        type=Path,
        default=ROOT,
        help="repository checkout to inspect (defaults to the project root)",
    )
    args = parser.parse_args()
    try:
        result = run_proof(args.repo)
    except ProofHistoryUnavailable as exc:
        if args.json:
            print(
                json.dumps(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "status": "unavailable",
                        "error": str(exc),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        else:
            print(f"gate-b rollback proof: UNAVAILABLE: {exc}")
        return 3
    except ProofError as exc:
        if args.json:
            print(
                json.dumps(
                    {"schema_version": SCHEMA_VERSION, "status": "fail", "error": str(exc)},
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        else:
            print(f"gate-b rollback proof: FAIL: {exc}")
        return 1
    if args.json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        # Decision E / M-5: 평문 출력도 어느 저장소의 어느 HEAD를 증명했는지
        # 드러내야 한다. 워크트리에서 메인 체크아웃 스크립트를 절대경로로
        # 부르면 다른 저장소를 조용히 증명하는 발 걸림이 실제로 있었다.
        active_name = GENERATIONS[-1].name
        print(
            "gate-b rollback proof: OK "
            f"(repo={result['repo']} source_head={result['source_head']} "
            f"active_generation={active_name} generations={len(GENERATIONS)})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
