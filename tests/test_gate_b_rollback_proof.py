from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_gate_b_rollback.py"
SPEC = importlib.util.spec_from_file_location("verify_gate_b_rollback", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"unable to load rollback proof script: {SCRIPT}")
rollback_proof = importlib.util.module_from_spec(SPEC)
# dataclass 정의(Generation/GateBMarker)가 실행 중 sys.modules[cls.__module__]를
# 조회하므로, exec 전에 먼저 등록해 둔다.
sys.modules["verify_gate_b_rollback"] = rollback_proof
SPEC.loader.exec_module(rollback_proof)

HISTORICAL_FINGERPRINT_LEDGER_SOURCE = "GENERATION_RECORD_FINGERPRINTS = ()\n"


def commit_paths_for_test(repo: Path, contents: dict[str, str], subject: str) -> str:
    """주어진 경로들에 내용을 쓰고 한 커밋으로 묶어 SHA를 반환한다.

    두 테스트 클래스(``GateBRollbackProofTests``/``GateBGenerationsTests``)가
    함께 쓰므로 모듈 레벨 함수로 둔다 — TestCase를 상속해 공유하면 상속받은
    쪽에서 부모의 test_* 메서드가 중복 실행된다.
    """
    for path, content in contents.items():
        file_path = repo / path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8")
    rollback_proof.run_git(repo, "add", *contents)
    rollback_proof.run_git(repo, "commit", "--quiet", "-m", subject)
    return rollback_proof.run_git(repo, "rev-parse", "HEAD").stdout.strip()


class GateBRollbackProofTests(unittest.TestCase):
    def make_snapshot_repo(self, root: Path) -> Path:
        repo = root / "snapshot"
        repo.mkdir()
        rollback_proof.run_git(repo, "init", "--quiet")
        (repo / "README.md").write_text("snapshot\n", encoding="utf-8")
        verifier = repo / rollback_proof.GENERATION_FINGERPRINT_SOURCE_PATH
        verifier.parent.mkdir(parents=True, exist_ok=True)
        verifier.write_text(HISTORICAL_FINGERPRINT_LEDGER_SOURCE, encoding="utf-8")
        rollback_proof.run_git(
            repo,
            "add",
            "README.md",
            rollback_proof.GENERATION_FINGERPRINT_SOURCE_PATH,
        )
        rollback_proof.run_git(repo, "commit", "--quiet", "-m", "snapshot")
        return repo

    def make_gate_b_history_repo(self, root: Path) -> tuple[Path, dict[str, str]]:
        """활성 Gate-B 4-커밋 이력과 경로·subject가 동형인 합성 저장소를 만든다.

        활성 세대의 경로 집합·subject·``residual_markers``를 그대로 읽어 파일을
        배치하므로, 새 세대가 append되면 이 헬퍼도 자동으로 따라간다
        (``RESIDUAL_MARKERS``는 세대 레코드로 옮겨지며 사라진 이름이다). 반환값은
        ``{"base"/"bless"/"b1"/"b2"/"shared-integration": <sha>}``.
        """
        repo = root / "gate-b-history"
        repo.mkdir()
        rollback_proof.run_git(repo, "init", "--quiet")
        base = commit_paths_for_test(
            repo,
            {
                "README.md": "base\n",
                rollback_proof.GENERATION_FINGERPRINT_SOURCE_PATH:
                    HISTORICAL_FINGERPRINT_LEDGER_SOURCE,
            },
            "base",
        )
        active_commits: dict[str, str] | None = None
        for generation in rollback_proof.GENERATIONS:
            bless_contents = {
                path: (
                    f"# residual edit[{generation.name}]: {path}\n"
                    if path in generation.residual_edits
                    else f"# gate-b residual placeholder: {path}\n"
                )
                for path in generation.all_component_paths
            }
            for path, needles in generation.residual_markers.items():
                bless_contents[path] = "".join(
                    f"# {needle}\n" for needle in needles
                ) + bless_contents[path]
            bless = commit_paths_for_test(repo, bless_contents, generation.bless_subject)

            b1 = commit_paths_for_test(
                repo,
                {
                    path: f"# gate-b b1 component: {path}\n"
                    for path in generation.b1_paths
                },
                generation.b1_subject,
            )
            b2 = commit_paths_for_test(
                repo,
                {
                    path: f"# gate-b b2 component: {path}\n"
                    for path in generation.b2_paths
                },
                generation.b2_subject,
            )
            shared = commit_paths_for_test(
                repo,
                {
                    path: f"# gate-b shared integration: {path}\n"
                    for path in generation.shared_paths
                },
                generation.shared_subject,
            )
            active_commits = {
                "bless": bless,
                "b1": b1,
                "b2": b2,
                "shared-integration": shared,
            }

        if active_commits is None:
            raise RuntimeError("rollback proof must declare at least one generation")
        return repo, {"base": base, **active_commits}

    def test_b1_b2_apply_and_revert_independently_before_shared_integration(self) -> None:
        try:
            result = rollback_proof.run_proof(ROOT)
        except rollback_proof.ProofHistoryUnavailable as exc:
            self.skipTest(str(exc))

        self.assertEqual(result["status"], "ok")
        self.assertEqual(
            result["schema_version"],
            "contextguard.gate-b-rollback-proof.v3",
        )
        self.assertEqual(result["repo"], str(ROOT))
        self.assertEqual(
            set(result["durable_commits"]),
            {"bless", "b1", "b2", "shared-integration"},
        )
        self.assertEqual(
            result["revert_order"],
            ["b1", "b2", "shared-integration"],
        )
        self.assertEqual(
            result["b1"]["reverted_tree"],
            rollback_proof.run_git(
                ROOT,
                "rev-parse",
                f"{result['durable_commits']['bless']}^{{tree}}",
            ).stdout.strip(),
        )
        self.assertEqual(
            result["b2"]["reverted_tree"],
            result["b1"]["reverted_tree"],
        )
        self.assertNotEqual(
            result["b1_only_revert_tree"],
            result["b2_only_revert_tree"],
        )

    def test_partial_unapplication_of_active_generation_fails(self) -> None:
        """U-1 — 검토를 통과한 Gate-B hunk가 조용히 부분 미적용되면 실패해야 한다 (I5).

        ``resolve_history``의 유일한 부하 단언(:256-259 상당)을 고정한다. 이 단언이
        없으면 이 테스트가 실패(오탐 없음)하며, 있으면 통과한다.
        """
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-partial-") as tmp:
            repo, commits = self.make_gate_b_history_repo(Path(tmp))
            frozen_path = sorted(rollback_proof.SHARED_INTEGRATION_PATHS)[0]
            (repo / frozen_path).write_text(
                "# hunk surgery: partially unapplied\n", encoding="utf-8"
            )
            rollback_proof.run_git(repo, "add", frozen_path)
            rollback_proof.run_git(
                repo, "commit", "--quiet", "-m", "unrelated tweak that touches a frozen path"
            )
            with mock.patch.object(rollback_proof, "BASE_COMMIT", commits["base"]):
                with self.assertRaisesRegex(
                    rollback_proof.ProofError,
                    "component paths changed after durable reapplication",
                ):
                    rollback_proof.run_proof(repo)

    def test_ordered_rollback_must_restore_residual(self) -> None:
        """U-1b — ``residual_delta``(:313-325 상당)를 고정한다.

        ``prove_current_revert_order``를 직접 호출해 ``commits["bless"]``만 틀린
        커밋(실제 bless가 아닌 base)으로 바꾼다. b1/b2/shared 되돌리기 자체는
        구조적으로 정상 성공하지만, 되돌린 결과가 (잘못 지정된) bless와 다르므로
        잔여물 복원 검사가 발화해야 한다.
        """
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-residual-") as tmp:
            repo, commits = self.make_gate_b_history_repo(Path(tmp))
            wrong_commits = {**commits, "bless": commits["base"]}
            with self.assertRaisesRegex(
                rollback_proof.ProofError,
                "does not restore durable residual",
            ):
                rollback_proof.prove_current_revert_order(
                    repo,
                    commits["shared-integration"],
                    wrong_commits,
                    rollback_proof.GENERATIONS[-1],
                )

    def test_ordered_rollback_must_touch_exactly_component_paths(self) -> None:
        """U-1c — ``rollback_delta``(:326-331 상당)를 고정한다.

        b1 자리에 "B1_PATHS 변경 + 무관 경로 변경"을 함께 담은 커밋을 넣고,
        source_head에도 그 무관 경로가 존재하도록 만들어 되돌리기 자체는 충돌
        없이 성공하게 한다. 되돌린 뒤 남는 차이가 정확히 컴포넌트 경로 집합과
        일치하지 않으므로(무관 경로 1개 추가) 실패해야 한다.
        """
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-rollback-") as tmp:
            repo, commits = self.make_gate_b_history_repo(Path(tmp))
            unrelated_path = "unrelated/extra.txt"

            rollback_proof.checkout(repo, commits["bless"])
            b1_contents = {
                path: f"# gate-b b1 component: {path}\n" for path in rollback_proof.B1_PATHS
            }
            b1_contents[unrelated_path] = "extra\n"
            over_broad_b1 = commit_paths_for_test(
                repo, b1_contents, "over-broad b1 (test double)"
            )

            rollback_proof.checkout(repo, commits["shared-integration"])
            (repo / unrelated_path).parent.mkdir(parents=True, exist_ok=True)
            (repo / unrelated_path).write_text("extra\n", encoding="utf-8")
            rollback_proof.run_git(repo, "add", unrelated_path)
            rollback_proof.run_git(
                repo, "commit", "--quiet", "-m", "unrelated addition on top of shared"
            )
            extra_head = rollback_proof.run_git(repo, "rev-parse", "HEAD").stdout.strip()

            over_broad_commits = {**commits, "b1": over_broad_b1}
            with self.assertRaisesRegex(
                rollback_proof.ProofError,
                "outside exact Gate-B set",
            ):
                rollback_proof.prove_current_revert_order(
                    repo, extra_head, over_broad_commits, rollback_proof.GENERATIONS[-1]
                )

    def test_renamed_component_path_is_detected(self) -> None:
        """U-2 — 동결 경로를 이름만 바꿔 옮기는 회피를 탐지한다 (``--no-renames``).

        rename 탐지가 켜져 있으면(git 기본값) 옛 경로는 diff에서 사라지고 새
        경로만 나타나 겹침 검사가 조용히 통과한다. ``changed_paths``가
        ``--no-renames``를 쓰지 않으면 이 테스트가 실패한다.
        """
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-rename-") as tmp:
            repo, commits = self.make_gate_b_history_repo(Path(tmp))
            frozen_path = sorted(rollback_proof.SHARED_INTEGRATION_PATHS)[0]
            old_content = (repo / frozen_path).read_text(encoding="utf-8")
            renamed_path = frozen_path + ".renamed"
            rollback_proof.run_git(repo, "mv", frozen_path, renamed_path)
            (repo / renamed_path).write_text(old_content, encoding="utf-8")
            rollback_proof.run_git(repo, "add", renamed_path)
            rollback_proof.run_git(
                repo, "commit", "--quiet", "-m", "rename a frozen component path"
            )
            with mock.patch.object(rollback_proof, "BASE_COMMIT", commits["base"]):
                with self.assertRaisesRegex(
                    rollback_proof.ProofError,
                    "component paths changed after durable reapplication",
                ):
                    rollback_proof.run_proof(repo)

    def test_base_commit_not_an_ancestor_of_head_is_rejected(self) -> None:
        """#35 — ``BASE_COMMIT``이 실존하지만 HEAD의 조상이 아니면 거부된다.

        두 개의 서로소(disjoint) orphan 루트 커밋을 만든다 — 공통 조상이 전혀
        없는 두 이력이라, 어느 쪽에서 봐도 다른 쪽은 조상이 아니다.
        ``BASE_COMMIT``을 한쪽 orphan에 고정하고 다른 쪽 orphan을 HEAD로 두면
        ``BASE_COMMIT``은 저장소에 실존하는 커밋이므로(#34가 있었다면 발화하지
        않았을 사례 — 그 검사는 중복이라 삭제됐다) ``merge-base --is-ancestor``가
        곧장 호출되고, exit 1(조상 아님)을 돌려줘야 한다.
        """
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-not-ancestor-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            rollback_proof.run_git(repo, "init", "--quiet")
            rollback_proof.run_git(
                repo, "commit", "--quiet", "--allow-empty", "-m", "orphan root one"
            )
            branch_one = rollback_proof.run_git(repo, "rev-parse", "HEAD").stdout.strip()

            rollback_proof.run_git(
                repo, "checkout", "--quiet", "--orphan", "branch-two"
            )
            rollback_proof.run_git(
                repo, "commit", "--quiet", "--allow-empty", "-m", "orphan root two"
            )
            branch_two = rollback_proof.run_git(repo, "rev-parse", "HEAD").stdout.strip()
            self.assertNotEqual(branch_one, branch_two)

            with mock.patch.object(rollback_proof, "BASE_COMMIT", branch_one):
                with self.assertRaisesRegex(
                    rollback_proof.ProofError, "is not an ancestor of"
                ):
                    rollback_proof.resolve_source_head(repo)

    def test_shallow_clone_missing_subject_reports_unavailable(self) -> None:
        """#5 — 얕은 클론의 시야 밖에 있는 subject는 '증명 불가'로 보고해야 한다.

        전체 이력을 가진 합성 저장소를 ``git clone --depth 1``로 복제하면
        HEAD 커밋 단 하나만 보이는 얕은 클론이 된다. ``BASE_COMMIT``을 그
        하나뿐인 커밋(클론된 HEAD 자신, 조상 검사는 자기 자신을 조상으로
        인정하므로 통과한다)으로 고정하면, ``BASE_COMMIT..source_head``
        범위는 0개 커밋이므로 어떤 subject도 찾지 못한다(``ProofError``가
        아니라 ``ProofHistoryUnavailable``이어야 한다 — 증명이 못 봤다고
        스스로 신고하는 것이지, 봤는데 틀렸다고 말하는 게 아니다).
        """
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-shallow-") as tmp:
            root = Path(tmp)
            repo, commits = self.make_gate_b_history_repo(root)
            shallow = root / "shallow-clone"
            clone = subprocess.run(
                [
                    "git",
                    "clone",
                    "--quiet",
                    "--depth",
                    "1",
                    "--no-local",
                    "--no-hardlinks",
                    str(repo),
                    str(shallow),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                # 이 파일의 다른 모든 git 호출과 같은 격리 환경을 쓴다. 맨
                # subprocess로 두면 이 호출만 앰비언트 전역/시스템 git config를
                # 상속한다(예: `protocol.file.allow`) — 테스트가 실행 머신의
                # 설정에 따라 갈리게 되고, 그건 이 파일이 지키는 규율이 아니다.
                env=rollback_proof.proof_environment(),
            )
            self.assertEqual(clone.returncode, 0, clone.stderr)

            self.assertTrue(rollback_proof.is_shallow_repository(shallow))
            shallow_head = rollback_proof.run_git(shallow, "rev-parse", "HEAD").stdout.strip()
            self.assertEqual(shallow_head, commits["shared-integration"])
            # 얕은 클론이 정말로 목표 subject(bless)를 시야 밖으로 잘라냈는지
            # 직접 확인한다 — 이 확인이 없으면 이 테스트는 "얕은 클론을
            # 만들어봤다"만 증명할 뿐, "정말로 잘렸다"는 증명하지 못한다.
            visible = rollback_proof.run_git(
                shallow, "log", "--format=%H"
            ).stdout.splitlines()
            self.assertEqual(visible, [shallow_head])
            self.assertNotIn(commits["bless"], visible)

            with mock.patch.object(rollback_proof, "BASE_COMMIT", shallow_head):
                with self.assertRaisesRegex(
                    rollback_proof.ProofHistoryUnavailable,
                    "reachable commit .* was not found",
                ):
                    rollback_proof.run_proof(shallow)

    def test_is_shallow_repository_reports_unavailable_on_git_failure(self) -> None:
        """#2 — ``rev-parse --is-shallow-repository`` 호출 자체가 실패하면
        '증명 불가'로 보고해야 한다.

        이 가지는 실제 저장소 상태로는 도달할 수 없다(일단 유효한 저장소
        안이면 이 plumbing 명령은 항상 성공한다) — 의존성 주입으로만
        연습할 수 있다. ``run_git``을 통째로 실패시키는 와일드카드 패치는
        쓰지 않는다: 그러면 이 테스트가 통과해도 어떤 호출이 실패해서
        통과했는지 증명하지 못한다(이 조사 전체가 잡으려는 '범위가 고정되지
        않은 패치'와 같은 결함이 된다). 대신 ``args[:2] ==
        ("rev-parse", "--is-shallow-repository")``인 호출만 실패시키고
        나머지는 패치 전에 잡아둔 진짜 ``run_git``으로 위임한다.
        ``run_proof``를 앞에서부터 태워, HEAD 해석(``rev-parse HEAD``)은
        실제로 성공한 뒤 이 호출에서만 걸리는지까지 함께 고정한다.
        """
        real_run_git = rollback_proof.run_git

        def selectively_failing_run_git(
            repo: Path, *args: str, check: bool = True
        ) -> subprocess.CompletedProcess[str]:
            if args[:2] == ("rev-parse", "--is-shallow-repository"):
                return subprocess.CompletedProcess(
                    args=("git", *args),
                    returncode=1,
                    stdout="",
                    stderr="simulated is-shallow-repository failure (test double)",
                )
            return real_run_git(repo, *args, check=check)

        with tempfile.TemporaryDirectory(prefix="context-guard-proof-shallow-check-fail-") as tmp:
            repo = self.make_snapshot_repo(Path(tmp))
            with mock.patch.object(
                rollback_proof, "run_git", side_effect=selectively_failing_run_git
            ):
                with self.assertRaisesRegex(
                    rollback_proof.ProofHistoryUnavailable,
                    "could not inspect repository depth",
                ):
                    rollback_proof.run_proof(repo)

    def test_snapshot_repo_reports_history_unavailable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-snapshot-") as tmp:
            repo = self.make_snapshot_repo(Path(tmp))
            with self.assertRaisesRegex(
                rollback_proof.ProofHistoryUnavailable,
                "full Gate-B proof history is unavailable",
            ):
                rollback_proof.run_proof(repo)

    def test_run_proof_rejects_malformed_record_before_checking_history_availability(
        self,
    ) -> None:
        """``run_proof``의 *자기* ``assert_generation_records_wellformed`` 호출부를
        고정한다 (문서화된 순서: 레코드 결함은 체크아웃 모양과 무관하게 항상
        '실패'(``ProofError``)여야 하고, '증명 불가'(``ProofHistoryUnavailable``)로
        오분류되면 안 된다).

        ``resolve_history``도 같은 함수를 호출하지만(그 함수 첫머리의 git-free
        선행 호출), 그 호출부는 이미
        ``test_cli_reports_a_malformed_record_as_failure_not_unavailable``이
        ``component paths overlap``(``assert_disjoint_paths``)로 고정하고 있어
        ``run_proof``(``resolve_source_head`` 앞의 선행 호출) 자신의 호출부
        하나가 지워져도 그 테스트는 계속
        통과한다 — ``resolve_history``의 호출부가 대신 걸리기 때문이다. 여기서는
        ``assert_disjoint_paths``는 통과하지만(``b1``/``b2``/``shared`` 서로소)
        ``assert_generation_records_wellformed``만 걸리는 레코드(빈 Gate-B 마커)를
        쓰고, 저장소는 ``BASE_COMMIT``을 전혀 포함하지 않는 무관 이력으로 만든다.
        ``run_proof``의 사전 호출부가 지워지면 ``resolve_source_head``가 먼저
        돌아 ``ProofHistoryUnavailable``을 던지므로 이 테스트가 실패한다.
        """
        bad = rollback_proof.Generation(
            name="bad-no-markers",
            bless_subject="proof: establish bad-no-markers residual",
            b1_subject="proof: reapply bad-no-markers b1 component",
            b2_subject="proof: reapply bad-no-markers b2 component",
            shared_subject="proof: reapply bad-no-markers shared component",
            b1_paths=frozenset({"bad/b1.txt"}),
            b2_paths=frozenset({"bad/b2.txt"}),
            shared_paths=frozenset({"bad/shared.txt"}),
            residual_markers={"bad/shared.txt": ("N",)},
            gate_b_markers=(),
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-runproof-wired-") as tmp:
            repo = self.make_snapshot_repo(Path(tmp))
            with mock.patch.object(rollback_proof, "GENERATIONS", (bad,)):
                with self.assertRaisesRegex(
                    rollback_proof.ProofError, "declares no Gate-B markers"
                ) as raised:
                    rollback_proof.run_proof(repo)
            self.assertNotIsInstance(
                raised.exception, rollback_proof.ProofHistoryUnavailable
            )

    def test_complete_squashed_history_is_a_failed_proof(self) -> None:
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-squash-") as tmp:
            repo = self.make_snapshot_repo(Path(tmp))
            base_commit = rollback_proof.run_git(repo, "rev-parse", "HEAD").stdout.strip()
            (repo / "README.md").write_text("squashed feature tree\n", encoding="utf-8")
            rollback_proof.run_git(repo, "add", "README.md")
            rollback_proof.run_git(repo, "commit", "--quiet", "-m", "squashed change")
            with mock.patch.object(rollback_proof, "BASE_COMMIT", base_commit):
                with self.assertRaisesRegex(
                    rollback_proof.ProofError,
                    "expected exactly one reachable commit named "
                    "'proof: establish Gate-B-free residual', found 0",
                ) as raised:
                    rollback_proof.run_proof(repo)
            self.assertNotIsInstance(
                raised.exception,
                rollback_proof.ProofHistoryUnavailable,
            )

    def test_cli_distinguishes_unavailable_history_from_failed_proof(self) -> None:
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-cli-") as tmp:
            repo = self.make_snapshot_repo(Path(tmp))
            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--json",
                    "--repo",
                    str(repo),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

        self.assertEqual(proc.returncode, 3, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "unavailable")
        self.assertIn("full Gate-B proof history is unavailable", payload["error"])

    def test_cli_reports_unborn_repository_as_unavailable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-unborn-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            rollback_proof.run_git(repo, "init", "--quiet")
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), "--json", "--repo", str(repo)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

        self.assertEqual(proc.returncode, 3, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "unavailable")
        self.assertIn("could not resolve HEAD", payload["error"])


class SyntheticGenerationHelpers:
    """합성 세대/저장소 헬퍼. ``TestCase``가 아니라 믹스인이다.

    이 헬퍼를 쓰려고 한 테스트 클래스가 다른 테스트 클래스를 상속하면, 부모의
    ``test_*``가 자식 클래스 이름으로 한 번 더 실행된다 — 각 테스트가 실제 임시
    git 저장소를 만들기 때문에 이 파일에서 가장 느린 클래스의 벽시계 시간이
    두 배가 되고, 실패가 두 이름으로 보고돼 진단을 방해한다. 모듈 레벨
    ``commit_paths_for_test``가 이미 같은 이유로 밖으로 빠져 있다.
    """

    SHARED_MARKER_LITERAL = "shared:"
    RESIDUAL_MARKER_NEEDLE = "SYNTHETIC_RESIDUAL_MARKER"

    def make_generation(
        self,
        name: str,
        *,
        b1_paths: frozenset[str],
        b2_paths: frozenset[str],
        shared_paths: frozenset[str],
        residual_markers: dict[str, tuple[str, ...]] | None = None,
        gate_b_markers: tuple | None = None,
        residual_edits: frozenset[str] = frozenset(),
    ):
        """합성 세대 하나를 만든다.

        ``gate_b_markers``/``residual_markers``를 넘기지 않으면 합성 저장소와
        아귀가 맞는 유효한 기본값을 채운다 — 빈 컬렉션은 이제
        ``assert_generation_records_wellformed``가 거부하기 때문이다(D6). 기본
        마커의 소유 경로는 반드시 그 세대의 컴포넌트 경로여야 한다.
        """
        owner = sorted(shared_paths)[0]
        if gate_b_markers is None:
            gate_b_markers = (
                rollback_proof.GateBMarker(self.SHARED_MARKER_LITERAL, owner),
            )
        if residual_markers is None:
            residual_markers = {owner: (self.RESIDUAL_MARKER_NEEDLE,)}
        return rollback_proof.Generation(
            name=name,
            bless_subject=f"proof: establish {name} residual",
            b1_subject=f"proof: reapply {name} b1 component",
            b2_subject=f"proof: reapply {name} b2 component",
            shared_subject=f"proof: reapply {name} shared component",
            b1_paths=b1_paths,
            b2_paths=b2_paths,
            shared_paths=shared_paths,
            residual_markers=residual_markers,
            gate_b_markers=gate_b_markers,
            residual_edits=residual_edits,
        )

    def make_repo_for_generations(
        self,
        root: Path,
        generations: tuple,
        bless_deletions: dict[str, frozenset[str]] | None = None,
    ) -> tuple[Path, str, dict[str, dict[str, str]]]:
        """세대 목록을 base -> gen[0](bless/b1/b2/shared) -> gen[1](...) -> ...
        순으로 이어 붙인 합성 저장소를 만든다. 반환값은
        ``(repo, base_sha, {세대이름: {"bless"/"b1"/"b2"/"shared-integration": sha}})``.

        bless 내용에 세대 이름을 박아 넣는다 — 세대 간 컴포넌트 경로가 겹칠 때
        두 bless가 같은 내용이면 D3가 볼 변화가 없어 배선 테스트가 공허해진다.

        ``bless_deletions``는 세대 이름별로 그 세대의 bless가 (내용을 쓰는 대신)
        트리에서 지울 컴포넌트 경로를 지정한다 — D5의 존재 집합 축을
        ``resolve_history``까지 태워 검사하기 위한 것이다.
        """
        repo = root / "generations-history"
        repo.mkdir()
        rollback_proof.run_git(repo, "init", "--quiet")
        base = commit_paths_for_test(
            repo,
            {
                "README.md": "base\n",
                rollback_proof.GENERATION_FINGERPRINT_SOURCE_PATH:
                    HISTORICAL_FINGERPRINT_LEDGER_SOURCE,
            },
            "base",
        )

        deletions = bless_deletions or {}
        all_commits: dict[str, dict[str, str]] = {}
        for generation in generations:
            dropped = deletions.get(generation.name, frozenset())
            bless_contents = {
                path: f"# residual[{generation.name}]: {path}\n"
                for path in generation.all_component_paths
                if path not in dropped
            }
            for path, needles in generation.residual_markers.items():
                # 컴포넌트 밖 경로를 선언한 (거부되어야 할) 레코드도 여기서
                # KeyError로 죽지 않고 resolve_history의 사전 검사까지 도달해야
                # 한다 — 그 거부가 바로 검사 대상이기 때문이다.
                if path not in bless_contents:
                    continue
                bless_contents[path] = (
                    "".join(f"# {needle}\n" for needle in needles) + bless_contents[path]
                )
            if dropped:
                for path in sorted(dropped):
                    if (repo / path).exists():
                        rollback_proof.run_git(repo, "rm", "--quiet", path)
                for path, content in bless_contents.items():
                    file_path = repo / path
                    file_path.parent.mkdir(parents=True, exist_ok=True)
                    file_path.write_text(content, encoding="utf-8")
                rollback_proof.run_git(repo, "add", *bless_contents)
                rollback_proof.run_git(
                    repo, "commit", "--quiet", "-m", generation.bless_subject
                )
                bless = rollback_proof.run_git(repo, "rev-parse", "HEAD").stdout.strip()
            else:
                bless = commit_paths_for_test(
                    repo, bless_contents, generation.bless_subject
                )
            b1 = commit_paths_for_test(
                repo,
                {path: f"# b1: {path}\n" for path in generation.b1_paths},
                generation.b1_subject,
            )
            b2 = commit_paths_for_test(
                repo,
                {path: f"# b2: {path}\n" for path in generation.b2_paths},
                generation.b2_subject,
            )
            shared = commit_paths_for_test(
                repo,
                {path: f"# shared: {path}\n" for path in generation.shared_paths},
                generation.shared_subject,
            )
            all_commits[generation.name] = {
                "bless": bless,
                "b1": b1,
                "b2": b2,
                "shared-integration": shared,
            }
        return repo, base, all_commits



class GateBGenerationsTests(SyntheticGenerationHelpers, unittest.TestCase):
    """append-only ``GENERATIONS`` 목록 메커니즘 자체를 합성 저장소로 검증한다.

    실제 18개 경로 대신 작은 합성 경로 집합을 쓴다 — G-11 완화책(계획 Decision B)
    대로, 실제 이력 1건에 기대는 것보다 세대 메커니즘(구조 보존/해제/마커/D3/D5)을
    더 정확하게 검증한다. ``GateBRollbackProofTests``를 상속하지 않는 이유는
    상속하면 그 클래스의 test_* 메서드가 이 클래스 이름으로 중복 실행되기
    때문이다 — 공용 헬퍼는 모듈 레벨 ``commit_paths_for_test``로 뺐다.
    """

    # 합성 저장소가 실제로 쓰는 리터럴. bless 트리는 ``# residual[<gen>]: <path>``,
    # shared reapply 커밋은 ``# shared: <path>``를 쓰므로 ``SHARED_MARKER_LITERAL``은
    # HEAD에는 있고 bless에는 없다 — C3-a/C3-b가 요구하는 방향과 정확히 일치한다.
    def test_overlapping_component_path_sets_are_rejected(self) -> None:
        """U-3b — 서로소가 깨지면 거부된다 (I1, 신규 구현). git이 필요 없다 —
        ``assert_disjoint_paths``는 ``Generation`` 레코드만 본다.

        ``python -O`` 생존 성질은 여기서 간접 증명하지 않는다. 이 저장소의
        어떤 CI/prepublish 경로도 스위트를 ``-O``로 돌리지 않으므로 그런 주장은
        자동화된 보증이 아니다(실측 확인). 그 성질은
        ``test_record_invariants_survive_python_optimized_mode``가 ``-O`` 하위
        프로세스를 직접 띄워 고정한다. 호출부 배선은
        ``test_resolve_history_rejects_overlapping_component_paths``가 고정한다.
        """
        overlapping = self.make_generation(
            "gen-overlap",
            b1_paths=frozenset({"a/one.txt", "shared/dup.txt"}),
            b2_paths=frozenset({"shared/dup.txt"}),
            shared_paths=frozenset({"c/three.txt"}),
        )
        with self.assertRaisesRegex(rollback_proof.ProofError, "component paths overlap"):
            rollback_proof.assert_disjoint_paths(overlapping)

    def test_generation_subjects_are_globally_unique(self) -> None:
        """U-3 — subject 전역 고유성(D4)은 새 코드가 아니라 ``find_unique_subject``의
        기존 유일성 검사가 모든 세대의 모든 subject를 같은
        ``BASE_COMMIT..source_head`` 범위에서 찾는 구성(composition)만으로 이미
        보장한다. 별도 검사를 추가하지 않았다 — 추가했다면 공허한 중복이었을
        것이다.
        """
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-subject-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            rollback_proof.run_git(repo, "init", "--quiet")
            base = commit_paths_for_test(repo, {"README.md": "base\n"}, "base")
            dup_subject = "proof: duplicate subject across commits"
            commit_paths_for_test(repo, {"a.txt": "1\n"}, dup_subject)
            head = commit_paths_for_test(repo, {"b.txt": "2\n"}, dup_subject)
            with mock.patch.object(rollback_proof, "BASE_COMMIT", base):
                with self.assertRaisesRegex(rollback_proof.ProofError, "found 2"):
                    rollback_proof.find_unique_subject(
                        repo, head, dup_subject, history_may_be_truncated=False
                    )

    def test_retired_generation_still_structurally_verified(self) -> None:
        """U-4 — 은퇴 세대도 구조 검사(부모 체인/경로 집합/서로소)가 계속
        발화한다. 어느 하위 검사가 먼저 걸리는지는 중요하지 않다 — 부모 체인이
        경로 집합보다 먼저 검사되므로 이 시나리오는 부모 불일치로 걸린다.
        """
        gen_a = self.make_generation(
            "gen-a-retired",
            b1_paths=frozenset({"a/b1.txt"}),
            b2_paths=frozenset({"a/b2.txt"}),
            shared_paths=frozenset({"a/shared.txt"}),
        )
        gen_b = self.make_generation(
            "gen-b-active",
            b1_paths=frozenset({"b/b1.txt"}),
            b2_paths=frozenset({"b/b2.txt"}),
            shared_paths=frozenset({"b/shared.txt"}),
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-retired-structure-") as tmp:
            repo, base, all_commits = self.make_repo_for_generations(Path(tmp), (gen_a, gen_b))
            broken = {**all_commits["gen-a-retired"], "b1": all_commits["gen-b-active"]["b1"]}
            with self.assertRaisesRegex(rollback_proof.ProofError, "generation 'gen-a-retired'"):
                rollback_proof.assert_generation_structure(repo, gen_a, broken)

    def test_generation_parent_chain_mismatch_is_rejected(self) -> None:
        """#21 — 부모 체인 검사만 단독으로 발화시킨다 (경로 집합은 그대로 둔다).

        ``test_retired_generation_still_structurally_verified``는 부모와 경로
        집합이 *동시에* 어긋나는 커밋을 넣으므로, 부모 체인 검사(:565-569 상당)를
        중화해도 경로 집합 검사(:578-582 상당)가 대신 걸려 초록으로 남는다 —
        이 스위트가 실제로 만든 mutation-survive 사례다. 여기서는 bless 위에
        무관한 중간 커밋을 하나 끼워 넣고, 그 위에 정확히 b1_paths만 다시
        커밋한다: 부모는 bless가 아니게 되지만(체인 검사만 발화), b1 커밋
        자체가 바꾸는 경로 집합은 여전히 ``generation.b1_paths``와 정확히
        같다(경로 집합 검사는 통과해야 정상이다).
        """
        gen = self.make_generation(
            "gen-parent-mismatch",
            b1_paths=frozenset({"p/b1.txt"}),
            b2_paths=frozenset({"p/b2.txt"}),
            shared_paths=frozenset({"p/shared.txt"}),
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-parent-mismatch-") as tmp:
            repo, base, all_commits = self.make_repo_for_generations(Path(tmp), (gen,))
            commits = all_commits["gen-parent-mismatch"]
            rollback_proof.checkout(repo, commits["bless"])
            commit_paths_for_test(
                repo, {"scratch/intermediate.txt": "unrelated noise\n"},
                "unrelated intermediate commit (test double)",
            )
            new_b1 = commit_paths_for_test(
                repo,
                {path: f"# b1: {path}\n" for path in gen.b1_paths},
                gen.b1_subject + " (rebuilt on intermediate commit)",
            )
            broken = {**commits, "b1": new_b1}
            with self.assertRaisesRegex(rollback_proof.ProofError, "parent mismatch"):
                rollback_proof.assert_generation_structure(repo, gen, broken)

    def test_generation_component_path_set_mismatch_is_rejected(self) -> None:
        """#22 — 경로 집합 검사만 단독으로 발화시킨다 (부모 체인은 그대로 둔다).

        ``shared-integration`` 자리를 바꾼다 — 부모 체인 검사에서 이 역할은
        마지막 항(``(commits["shared-integration"], commits["b2"])``)이라 다른
        어떤 역할의 기대 부모도 이 커밋을 가리키지 않는다. 그래서 실제 b2 바로
        위에 다시 커밋하면(부모는 그대로 정상) 부모 체인 검사 전체가 깨끗이
        통과하고, ``shared_paths``에 없는 경로를 하나 더 얹은 경로 집합 검사
        (:578-582 상당)만 단독으로 걸린다. (b1을 바꾸면 그 부모가 바뀌어 b2의
        기대 부모까지 연쇄로 어긋나 버려 부모 체인 검사가 먼저 걸린다 — 실제로
        시도해서 확인했다.)
        """
        gen = self.make_generation(
            "gen-pathset-mismatch",
            b1_paths=frozenset({"q/b1.txt"}),
            b2_paths=frozenset({"q/b2.txt"}),
            shared_paths=frozenset({"q/shared.txt"}),
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-pathset-mismatch-") as tmp:
            repo, base, all_commits = self.make_repo_for_generations(Path(tmp), (gen,))
            commits = all_commits["gen-pathset-mismatch"]
            rollback_proof.checkout(repo, commits["b2"])
            over_broad_contents = {
                path: f"# shared: {path}\n" for path in gen.shared_paths
            }
            over_broad_contents["q/unexpected-extra.txt"] = "surprise\n"
            new_shared = commit_paths_for_test(
                repo,
                over_broad_contents,
                gen.shared_subject + " (over-broad, test double)",
            )
            broken = {**commits, "shared-integration": new_shared}
            with self.assertRaisesRegex(rollback_proof.ProofError, "path set changed"):
                rollback_proof.assert_generation_structure(repo, gen, broken)

    def test_retired_generation_is_not_frozen_against_head(self) -> None:
        """U-5 — 은퇴 세대가 소유한 경로가 HEAD에서 바뀌어도 통과한다 (해제가
        실제로 작동함 — 동결은 활성 세대만).
        """
        gen_a = self.make_generation(
            "gen-a-unfrozen",
            b1_paths=frozenset({"a/b1.txt"}),
            b2_paths=frozenset({"a/b2.txt"}),
            shared_paths=frozenset({"a/shared.txt"}),
        )
        gen_b = self.make_generation(
            "gen-b-unfrozen-active",
            b1_paths=frozenset({"b/b1.txt"}),
            b2_paths=frozenset({"b/b2.txt"}),
            shared_paths=frozenset({"b/shared.txt"}),
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-retired-unfrozen-") as tmp:
            repo, base, all_commits = self.make_repo_for_generations(Path(tmp), (gen_a, gen_b))
            touched = commit_paths_for_test(
                repo, {"a/shared.txt": "touched after HEAD moved on\n"}, "touch retired gen path"
            )
            with mock.patch.object(rollback_proof, "GENERATIONS", (gen_a, gen_b)):
                with mock.patch.object(rollback_proof, "BASE_COMMIT", base):
                    resolved = rollback_proof.resolve_history(
                        repo, touched, history_may_be_truncated=False
                    )
            self.assertIn("gen-a-unfrozen", resolved)
            self.assertIn("gen-b-unfrozen-active", resolved)

    def test_active_generation_is_frozen_against_head(self) -> None:
        """U-6 — 활성 세대가 소유한 경로가 HEAD에서 바뀌면 실패한다 (해제가
        과하지 않음).
        """
        gen_a = self.make_generation(
            "gen-a-frozen-control",
            b1_paths=frozenset({"a/b1.txt"}),
            b2_paths=frozenset({"a/b2.txt"}),
            shared_paths=frozenset({"a/shared.txt"}),
        )
        gen_b = self.make_generation(
            "gen-b-frozen-active",
            b1_paths=frozenset({"b/b1.txt"}),
            b2_paths=frozenset({"b/b2.txt"}),
            shared_paths=frozenset({"b/shared.txt"}),
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-active-frozen-") as tmp:
            repo, base, all_commits = self.make_repo_for_generations(Path(tmp), (gen_a, gen_b))
            touched = commit_paths_for_test(
                repo, {"b/shared.txt": "touched active gen path\n"}, "touch active gen path"
            )
            with mock.patch.object(rollback_proof, "GENERATIONS", (gen_a, gen_b)):
                with mock.patch.object(rollback_proof, "BASE_COMMIT", base):
                    with self.assertRaisesRegex(
                        rollback_proof.ProofError,
                        "component paths changed after durable reapplication",
                    ):
                        rollback_proof.resolve_history(
                            repo, touched, history_may_be_truncated=False
                        )

    def test_schema_version_stays_v3_and_reports_generations_and_review_pathspec(self) -> None:
        """U-7 — ``schema_version``은 v3로 유지되고(사용자 결정 A), ``generations``/
        ``review_pathspec``/``repo``는 추가 키로만 노출된다.
        """
        gen_a = self.make_generation(
            "gen-a-schema",
            b1_paths=frozenset({"a/b1.txt"}),
            b2_paths=frozenset({"a/b2.txt"}),
            shared_paths=frozenset({"a/shared.txt"}),
        )
        gen_b = self.make_generation(
            "gen-b-schema",
            b1_paths=frozenset({"b/b1.txt"}),
            b2_paths=frozenset({"b/b2.txt"}),
            shared_paths=frozenset({"b/shared.txt"}),
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-schema-") as tmp:
            repo, base, all_commits = self.make_repo_for_generations(Path(tmp), (gen_a, gen_b))
            with mock.patch.object(rollback_proof, "GENERATIONS", (gen_a, gen_b)):
                fingerprints = tuple(
                    rollback_proof.generation_record_fingerprint(generation)
                    for generation in (gen_a, gen_b)
                )
                with mock.patch.object(
                    rollback_proof,
                    "GENERATION_RECORD_FINGERPRINTS",
                    fingerprints,
                ):
                    with mock.patch.object(rollback_proof, "BASE_COMMIT", base):
                        result = rollback_proof.run_proof(repo)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["schema_version"], "contextguard.gate-b-rollback-proof.v3")
        self.assertEqual(result["repo"], str(repo.resolve()))
        self.assertEqual(len(result["generations"]), 2)
        self.assertFalse(result["generations"][0]["active"])
        self.assertTrue(result["generations"][1]["active"])
        self.assertEqual(
            result["review_pathspec"],
            sorted(gen_a.all_component_paths | gen_b.all_component_paths),
        )
        self.assertEqual(result["durable_commits"], all_commits["gen-b-schema"])

    def test_generation_residual_markers_are_per_generation(self) -> None:
        """U-12 — ``RESIDUAL_MARKERS``가 세대 레코드로 옮겨져, 이후 세대가 새
        마커를 추가해도 과거 세대의 bless는 소급으로 재검사되지 않는다
        (C-2, G-16).
        """
        gen_a = self.make_generation(
            "gen-a-marker-retro",
            b1_paths=frozenset({"a/b1.txt"}),
            b2_paths=frozenset({"a/b2.txt"}),
            shared_paths=frozenset({"shared.txt"}),
            residual_markers={"shared.txt": ("MARKER_A",)},
        )
        gen_b = self.make_generation(
            "gen-b-marker-retro",
            b1_paths=frozenset({"b/b1.txt"}),
            b2_paths=frozenset({"b/b2.txt"}),
            shared_paths=frozenset({"shared.txt"}),
            residual_markers={"shared.txt": ("MARKER_A", "MARKER_B")},
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-marker-retro-") as tmp:
            repo, base, all_commits = self.make_repo_for_generations(Path(tmp), (gen_a, gen_b))
            gen_a_bless = all_commits["gen-a-marker-retro"]["bless"]
            gen_b_bless = all_commits["gen-b-marker-retro"]["bless"]

            # 정상 짝: 각 세대는 자기 마커만 본다 — 둘 다 통과해야 한다.
            rollback_proof.assert_residual_contract(repo, gen_a, gen_a_bless)
            rollback_proof.assert_residual_contract(repo, gen_b, gen_b_bless)

            # 대조군: gen_b의 (더 넓은) 마커 목록을 gen_a의 bless에 적용하면
            # MARKER_B가 없어 실패한다 — 마커 목록이 실제로 유효함을 확인한다.
            with self.assertRaisesRegex(rollback_proof.ProofError, "MARKER_B"):
                rollback_proof.assert_residual_contract(repo, gen_b, gen_a_bless)

    def test_bless_tree_must_not_contain_generation_gate_b_markers(self) -> None:
        """U-8 — 세대의 bless 트리가 그 세대의 Gate-B 마커를 포함하면 거부된다
        (C3-b).
        """
        marker = rollback_proof.GateBMarker("SECRET_GATE_B_TOKEN", "owner.txt")
        generation = self.make_generation(
            "gen-marker-absent",
            b1_paths=frozenset({"g/b1.txt"}),
            b2_paths=frozenset({"g/b2.txt"}),
            shared_paths=frozenset({"owner.txt"}),
            gate_b_markers=(marker,),
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-marker-absent-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            rollback_proof.run_git(repo, "init", "--quiet")
            commit_paths_for_test(repo, {"README.md": "base\n"}, "base")

            clean_bless = commit_paths_for_test(
                repo, {"owner.txt": "clean residual\n"}, generation.bless_subject + " (clean)"
            )
            rollback_proof.assert_gate_b_markers_absent_from_bless(repo, generation, clean_bless)

            dirty_bless = commit_paths_for_test(
                repo,
                {"owner.txt": "clean residual\nSECRET_GATE_B_TOKEN leaked back in\n"},
                generation.bless_subject + " (dirty)",
            )
            with self.assertRaisesRegex(rollback_proof.ProofError, "retains Gate-B marker"):
                rollback_proof.assert_gate_b_markers_absent_from_bless(
                    repo, generation, dirty_bless
                )

    def test_bless_tree_must_not_move_gate_b_marker_to_another_component(self) -> None:
        """F-9 — C3-b scans every component path, not only the declared owner."""
        marker = rollback_proof.GateBMarker("SECRET_GATE_B_TOKEN", "owner.txt")
        moved_paths = ("g/moved-b1.txt", "g/moved-b2.txt")
        generation = self.make_generation(
            "gen-marker-moved",
            b1_paths=frozenset({moved_paths[0]}),
            b2_paths=frozenset({moved_paths[1]}),
            shared_paths=frozenset({"owner.txt"}),
            gate_b_markers=(marker,),
        )
        for moved_path in moved_paths:
            with self.subTest(moved_path=moved_path):
                with tempfile.TemporaryDirectory(
                    prefix="context-guard-proof-marker-moved-"
                ) as tmp:
                    repo = Path(tmp) / "repo"
                    repo.mkdir()
                    rollback_proof.run_git(repo, "init", "--quiet")
                    commit_paths_for_test(repo, {"README.md": "base\n"}, "base")
                    moved_bless = commit_paths_for_test(
                        repo,
                        {
                            "owner.txt": "declared owner is clean\n",
                            moved_path: "SECRET_GATE_B_TOKEN moved here\n",
                        },
                        generation.bless_subject,
                    )

                    with self.assertRaisesRegex(
                        rollback_proof.ProofError,
                        "retains Gate-B marker",
                    ) as raised:
                        rollback_proof.assert_gate_b_markers_absent_from_bless(
                            repo,
                            generation,
                            moved_bless,
                        )
                    self.assertIn(moved_path, str(raised.exception))

    def test_gate_b_markers_must_be_present_at_active_head(self) -> None:
        """U-9 — 활성 세대의 Gate-B 마커가 HEAD에 없으면 거부된다 (C3-a,
        자기 무효화 — 마커가 rot하면 부재 검사보다 먼저 큰 소리로 실패한다).
        """
        marker = rollback_proof.GateBMarker("SECRET_GATE_B_TOKEN", "owner.txt")
        generation = self.make_generation(
            "gen-marker-present",
            b1_paths=frozenset({"g/b1.txt"}),
            b2_paths=frozenset({"g/b2.txt"}),
            shared_paths=frozenset({"owner.txt"}),
            gate_b_markers=(marker,),
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-marker-present-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            rollback_proof.run_git(repo, "init", "--quiet")

            with_marker = commit_paths_for_test(
                repo, {"owner.txt": "still has SECRET_GATE_B_TOKEN\n"}, "head with marker"
            )
            rollback_proof.assert_gate_b_markers_present_at_head(repo, with_marker, generation)

            without_marker = commit_paths_for_test(
                repo, {"owner.txt": "marker got renamed away\n"}, "head without marker"
            )
            with self.assertRaisesRegex(rollback_proof.ProofError, "missing from"):
                rollback_proof.assert_gate_b_markers_present_at_head(
                    repo, without_marker, generation
                )

    def test_undeclared_residual_edit_is_rejected(self) -> None:
        """U-11 — 직전 세대 대비 미선언 잔여물 편집이 거부된다 (D3, AC-8b)."""
        gen1 = self.make_generation(
            "gen1-d3",
            b1_paths=frozenset({"g1/b1.txt"}),
            b2_paths=frozenset({"g1/b2.txt"}),
            shared_paths=frozenset({"shared/a.txt", "shared/b.txt"}),
        )
        gen2 = self.make_generation(
            "gen2-d3",
            b1_paths=frozenset({"g2/b1.txt"}),
            b2_paths=frozenset({"g2/b2.txt"}),
            shared_paths=frozenset({"shared/a.txt", "shared/b.txt"}),
            residual_edits=frozenset({"shared/a.txt"}),
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-d3-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            rollback_proof.run_git(repo, "init", "--quiet")
            commit_paths_for_test(repo, {"README.md": "base\n"}, "base")
            gen1_bless = commit_paths_for_test(
                repo, {"shared/a.txt": "v1-a\n", "shared/b.txt": "v1-b\n"}, gen1.bless_subject
            )

            # 선언대로 shared/a.txt만 바꾼 경우: 통과해야 한다.
            gen2_bless_declared = commit_paths_for_test(
                repo, {"shared/a.txt": "v2-a\n"}, gen2.bless_subject + " (declared)"
            )
            rollback_proof.assert_declared_residual_edits(
                repo, gen1, {"bless": gen1_bless}, gen2, {"bless": gen2_bless_declared}
            )

            # 선언에 없는 shared/b.txt까지 바꾼 경우: 거부해야 한다.
            gen2_bless_undeclared = commit_paths_for_test(
                repo,
                {"shared/a.txt": "v2-a\n", "shared/b.txt": "v2-b-tampered\n"},
                gen2.bless_subject + " (undeclared)",
            )
            with self.assertRaisesRegex(rollback_proof.ProofError, "residual edits undeclared"):
                rollback_proof.assert_declared_residual_edits(
                    repo, gen1, {"bless": gen1_bless}, gen2, {"bless": gen2_bless_undeclared}
                )

    def test_resurrected_component_path_in_residual_is_rejected(self) -> None:
        """U-13 — 세대 간 잔여물 존재 집합 불변이 깨지면 거부된다 (D5, 필수,
        AC-8c). ``residual_edits``에 선언해도 우회되지 않는다 — D3(내용)와
        D5(존재)는 직교하는 축이다.
        """
        gen1 = self.make_generation(
            "gen1-d5",
            b1_paths=frozenset({"g1/b1.txt"}),
            b2_paths=frozenset({"g1/b2.txt"}),
            shared_paths=frozenset({"shared/kept.txt", "shared/deleted.txt"}),
        )
        gen2 = self.make_generation(
            "gen2-d5",
            b1_paths=frozenset({"g2/b1.txt"}),
            b2_paths=frozenset({"g2/b2.txt"}),
            shared_paths=frozenset({"shared/kept.txt", "shared/deleted.txt"}),
            residual_edits=frozenset({"shared/deleted.txt"}),
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-d5-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            rollback_proof.run_git(repo, "init", "--quiet")
            commit_paths_for_test(repo, {"README.md": "base\n"}, "base")

            # gen1 bless: kept.txt는 시드 후 수정, deleted.txt는 시드 후 진짜로
            # 삭제되어야(rm) 트리에서 부재가 된다.
            commit_paths_for_test(
                repo,
                {"shared/kept.txt": "seed\n", "shared/deleted.txt": "will-be-removed\n"},
                "seed for gen1-d5",
            )
            rollback_proof.run_git(repo, "rm", "--quiet", "shared/deleted.txt")
            (repo / "shared/kept.txt").write_text("v1\n", encoding="utf-8")
            rollback_proof.run_git(repo, "add", "shared/kept.txt")
            rollback_proof.run_git(repo, "commit", "--quiet", "-m", gen1.bless_subject)
            gen1_bless = rollback_proof.run_git(repo, "rev-parse", "HEAD").stdout.strip()

            # 정당한 gen2: deleted.txt는 계속 부재, kept.txt만 내용이 바뀐다 —
            # 통과해야 한다.
            gen2_legit = commit_paths_for_test(
                repo, {"shared/kept.txt": "v2\n"}, gen2.bless_subject + " (legit)"
            )
            rollback_proof.assert_residual_existence_invariant(
                repo, gen1, {"bless": gen1_bless}, gen2, {"bless": gen2_legit}
            )

            # 세탁: deleted.txt를 삭제 대신 수정으로 되살린다. residual_edits에
            # 선언해도(D3와 직교) D5가 잡아야 한다.
            rollback_proof.checkout(repo, gen1_bless)
            gen2_laundered = commit_paths_for_test(
                repo,
                {"shared/kept.txt": "v2\n", "shared/deleted.txt": "laundered-back\n"},
                gen2.bless_subject + " (laundered)",
            )
            with self.assertRaisesRegex(
                rollback_proof.ProofError, "residual existence set changed"
            ):
                rollback_proof.assert_residual_existence_invariant(
                    repo, gen1, {"bless": gen1_bless}, gen2, {"bless": gen2_laundered}
                )


class GateBGenerationRecordTests(SyntheticGenerationHelpers, unittest.TestCase):
    """세대 레코드 자체의 자기 신고 구멍(D6)과, 신규 단언의 *배선*을 고정한다.

    앞선 클래스의 U-3b/U-11/U-13은 단언 함수를 직접 호출하므로, 호출부를
    ``resolve_history``에서 지워도 스위트가 초록으로 남는다(PR #243에서 발견된
    '임포트만 되고 호출되지 않는 헬퍼' 실패 모드와 같은 계열). 여기 테스트는
    전부 ``resolve_history``를 통해 발화시켜 배선을 함께 고정한다.

    헬퍼는 ``SyntheticGenerationHelpers`` 믹스인에서 가져온다 — 다른 TestCase를
    상속하면 그 클래스의 test_*가 이 클래스 이름으로 한 번 더 실행되기 때문이다.
    """

    def test_shipped_generations_pin_s006_gen2_and_s007_gen3(self) -> None:
        """운영 레코드는 S006 gen2와 S007 gen3를 순서대로 보존한다."""
        self.assertEqual(
            tuple(generation.name for generation in rollback_proof.GENERATIONS),
            ("gen1", "gen2", "gen3"),
        )
        gen1, gen2, gen3 = rollback_proof.GENERATIONS
        self.assertEqual(gen2.b1_paths, gen1.b1_paths)
        self.assertEqual(gen2.b2_paths, gen1.b2_paths)
        self.assertEqual(gen2.shared_paths, gen1.shared_paths)
        self.assertEqual(gen2.residual_markers, gen1.residual_markers)
        self.assertEqual(gen2.gate_b_markers, gen1.gate_b_markers)
        self.assertEqual(
            gen2.residual_edits,
            frozenset({"tests/test_context_guard_kit.py"}),
        )
        subjects = (
            rollback_proof.GEN2_BLESS_SUBJECT,
            rollback_proof.GEN2_B1_SUBJECT,
            rollback_proof.GEN2_B2_SUBJECT,
            rollback_proof.GEN2_SHARED_SUBJECT,
        )
        self.assertEqual(
            subjects,
            (
                "proof: establish Gate-B-free residual gen2 command identity",
                "proof: reapply Gate-B nudge component gen2 command identity",
                "proof: reapply Gate-B usage component gen2 command identity",
                "proof: reapply Gate-B integration component gen2 command identity",
            ),
        )
        self.assertEqual(
            (
                gen2.bless_subject,
                gen2.b1_subject,
                gen2.b2_subject,
                gen2.shared_subject,
            ),
            subjects,
        )

        self.assertEqual(gen3.b1_paths, gen2.b1_paths)
        self.assertEqual(gen3.b2_paths, gen2.b2_paths)
        self.assertEqual(gen3.shared_paths, gen2.shared_paths)
        self.assertEqual(gen3.residual_markers, gen2.residual_markers)
        self.assertEqual(gen3.gate_b_markers, gen2.gate_b_markers)
        self.assertEqual(
            gen3.residual_edits,
            frozenset({"tests/test_context_guard_kit.py"}),
        )
        gen3_subjects = (
            rollback_proof.GEN3_BLESS_SUBJECT,
            rollback_proof.GEN3_B1_SUBJECT,
            rollback_proof.GEN3_B2_SUBJECT,
            rollback_proof.GEN3_SHARED_SUBJECT,
        )
        self.assertEqual(
            gen3_subjects,
            (
                "proof: establish Gate-B-free residual gen3 login shell",
                "proof: reapply Gate-B nudge component gen3 login shell",
                "proof: reapply Gate-B usage component gen3 login shell",
                "proof: reapply Gate-B integration component gen3 login shell",
            ),
        )
        self.assertEqual(
            (
                gen3.bless_subject,
                gen3.b1_subject,
                gen3.b2_subject,
                gen3.shared_subject,
            ),
            gen3_subjects,
        )

    def test_run_proof_rejects_mutation_of_shipped_generation_record(self) -> None:
        """F-7: editing a retired record cannot silently narrow its proof scope."""
        generations = rollback_proof.GENERATIONS
        removed_path = "tests/test_context_guard_nudge_protocol.py"
        self.assertIn(removed_path, generations[0].b1_paths)
        narrowed_gen1 = replace(
            generations[0],
            b1_paths=generations[0].b1_paths - {removed_path},
        )

        with mock.patch.object(
            rollback_proof,
            "GENERATIONS",
            (narrowed_gen1, *generations[1:]),
        ):
            with self.assertRaisesRegex(
                rollback_proof.ProofError,
                "generation fingerprint ledger mismatch.*gen1",
            ):
                rollback_proof.run_proof(ROOT)

    def test_run_proof_rejects_removal_of_shipped_generation_record(self) -> None:
        """F-7: the generation registry itself is mechanically append-only."""
        with mock.patch.object(
            rollback_proof,
            "GENERATIONS",
            rollback_proof.GENERATIONS[:-1],
        ):
            with self.assertRaisesRegex(
                rollback_proof.ProofError,
                "generation fingerprint ledger length mismatch",
            ):
                rollback_proof.run_proof(ROOT)

    def test_run_proof_rejects_historical_fingerprint_ledger_truncation(self) -> None:
        """F-7: editing records and their local digests cannot erase prior history."""
        shortened_generations = rollback_proof.GENERATIONS[:-1]
        shortened_fingerprints = rollback_proof.GENERATION_RECORD_FINGERPRINTS[:-1]
        with mock.patch.object(
            rollback_proof,
            "GENERATIONS",
            shortened_generations,
        ):
            with mock.patch.object(
                rollback_proof,
                "GENERATION_RECORD_FINGERPRINTS",
                shortened_fingerprints,
            ):
                with self.assertRaisesRegex(
                    rollback_proof.ProofError,
                    "historical generation fingerprint ledger is not a prefix",
                ):
                    rollback_proof.run_proof(ROOT)

    def test_fingerprint_history_rejects_missing_source_path(self) -> None:
        """F-7: moving the verifier cannot make its append-only history vacuous."""
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-ledger-missing-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            rollback_proof.run_git(repo, "init", "--quiet")
            head = commit_paths_for_test(repo, {"README.md": "no verifier\n"}, "head")

            with self.assertRaisesRegex(
                rollback_proof.ProofError,
                "generation fingerprint source path is missing",
            ):
                rollback_proof.assert_generation_fingerprint_history_append_only(
                    repo,
                    head,
                    rollback_proof.GENERATION_RECORD_FINGERPRINTS,
                )

    def test_fingerprint_history_rejects_no_observed_ledger(self) -> None:
        """F-7: complete history must expose at least one committed ledger."""
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-ledger-empty-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            rollback_proof.run_git(repo, "init", "--quiet")
            head = commit_paths_for_test(
                repo,
                {
                    rollback_proof.GENERATION_FINGERPRINT_SOURCE_PATH:
                        "print('verifier without a fingerprint ledger')\n",
                },
                "verifier without ledger",
            )

            with self.assertRaisesRegex(
                rollback_proof.ProofError,
                "no committed generation fingerprint ledger",
            ):
                rollback_proof.assert_generation_fingerprint_history_append_only(
                    repo,
                    head,
                    rollback_proof.GENERATION_RECORD_FINGERPRINTS,
                )

    def test_fingerprint_history_allows_no_observed_ledger_when_truncated(self) -> None:
        """A truncated checkout may lack the historical ledger it cannot fetch."""
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-ledger-shallow-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            rollback_proof.run_git(repo, "init", "--quiet")
            head = commit_paths_for_test(
                repo,
                {
                    rollback_proof.GENERATION_FINGERPRINT_SOURCE_PATH:
                        "print('shallow verifier without visible ledger')\n",
                },
                "shallow verifier without visible ledger",
            )

            try:
                rollback_proof.assert_generation_fingerprint_history_append_only(
                    repo,
                    head,
                    rollback_proof.GENERATION_RECORD_FINGERPRINTS,
                    history_may_be_truncated=True,
                )
            except (TypeError, rollback_proof.ProofError) as exc:
                self.fail(f"truncated history did not permit an unobserved ledger: {exc}")

    def make_pair(self, *, residual_edits=frozenset()):
        """컴포넌트 경로가 *겹치는* 두 세대를 만든다.

        기존 U-5/U-6/U-7의 합성 세대는 경로가 서로소라 ``shared_components``가
        공집합이고, 그래서 D3/D5가 ``resolve_history``를 지나가도 공허하게
        통과했다. 겹치게 만들어야 두 검사가 실제로 평가된다.
        """
        shared = frozenset({"shared/keep.txt", "shared/vanish.txt"})
        gen1 = self.make_generation(
            "gen1-wired",
            b1_paths=frozenset({"g1/b1.txt"}),
            b2_paths=frozenset({"g1/b2.txt"}),
            shared_paths=shared,
        )
        gen2 = self.make_generation(
            "gen2-wired",
            b1_paths=frozenset({"g2/b1.txt"}),
            b2_paths=frozenset({"g2/b2.txt"}),
            shared_paths=shared,
            residual_edits=residual_edits,
        )
        return gen1, gen2

    def drive(self, tmp, generations, *, bless_deletions=None, drive_generations=None):
        """합성 저장소를 만들고 ``resolve_history``를 HEAD까지 태운다.

        ``drive_generations``를 주면 저장소는 ``generations``로 만들되
        ``resolve_history``는 그 기록으로 돌린다 — 저장소 내용과 어긋나는 기록을
        검사에 태울 때 쓴다(subject/경로는 같게 유지해야 커밋 해석이 성공한다).
        """
        repo, base, _ = self.make_repo_for_generations(
            Path(tmp), generations, bless_deletions=bless_deletions
        )
        head = rollback_proof.run_git(repo, "rev-parse", "HEAD").stdout.strip()
        generations = drive_generations or generations
        with mock.patch.object(rollback_proof, "GENERATIONS", generations):
            with mock.patch.object(rollback_proof, "BASE_COMMIT", base):
                return rollback_proof.resolve_history(
                    repo, head, history_may_be_truncated=False
                )

    def test_resolve_history_fires_d3_on_undeclared_residual_edit(self) -> None:
        """D3 배선 — ``resolve_history``의 호출부를 지우면 이 테스트가 실패한다."""
        gen1, gen2 = self.make_pair(residual_edits=frozenset())
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-d3-wired-") as tmp:
            with self.assertRaisesRegex(
                rollback_proof.ProofError, "residual edits undeclared"
            ):
                self.drive(tmp, (gen1, gen2))

    def test_resolve_history_accepts_declared_residual_edit(self) -> None:
        """대조군 — 정확히 선언하면 통과한다(오탐 없음)."""
        declared = frozenset({"shared/keep.txt", "shared/vanish.txt"})
        gen1, gen2 = self.make_pair(residual_edits=declared)
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-d3-ok-") as tmp:
            resolved = self.drive(tmp, (gen1, gen2))
        self.assertIn("gen1-wired", resolved)
        self.assertIn("gen2-wired", resolved)

    def test_resolve_history_fires_d5_on_vanished_residual_path(self) -> None:
        """D5 배선 — D3를 선언으로 만족시킨 뒤에도 존재 집합 변화는 잡힌다.

        D3(내용)와 D5(존재)가 직교한다는 성질을 ``resolve_history``까지 태워
        고정한다. D5 호출부를 지우면 이 테스트가 실패한다.
        """
        declared = frozenset({"shared/keep.txt", "shared/vanish.txt"})
        gen1, gen2 = self.make_pair(residual_edits=declared)
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-d5-wired-") as tmp:
            with self.assertRaisesRegex(
                rollback_proof.ProofError, "residual existence set changed"
            ):
                self.drive(
                    tmp,
                    (gen1, gen2),
                    bless_deletions={"gen2-wired": frozenset({"shared/vanish.txt"})},
                )

    def test_d5_rejects_compensating_pair_with_equal_counts(self) -> None:
        """D5가 개수가 아니라 *집합*을 비교함을 고정한다.

        U-13의 세탁 케이스는 존재 개수까지 달라지므로, 구현을
        ``len(before) != len(after)``로 독살해도 통과한다 — 즉 이 PR이 명시적으로
        내세운 '개수가 아니라 집합' 성질에 핀이 없었다. 여기서는 한 경로가
        사라지고 다른 경로가 되살아나 개수가 그대로인 상쇄 쌍을 만든다.
        """
        shared = frozenset({"shared/alive.txt", "shared/dead.txt"})
        gen1 = self.make_generation(
            "gen1-pair",
            b1_paths=frozenset({"p1/b1.txt"}),
            b2_paths=frozenset({"p1/b2.txt"}),
            shared_paths=shared,
        )
        gen2 = self.make_generation(
            "gen2-pair",
            b1_paths=frozenset({"p2/b1.txt"}),
            b2_paths=frozenset({"p2/b2.txt"}),
            shared_paths=shared,
            residual_edits=shared,
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-pair-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            rollback_proof.run_git(repo, "init", "--quiet")
            commit_paths_for_test(repo, {"README.md": "base\n"}, "base")
            # gen1 bless: alive.txt 존재, dead.txt 부재(정상적으로 삭제된 상태).
            commit_paths_for_test(
                repo,
                {"shared/alive.txt": "v1\n", "shared/dead.txt": "seed\n"},
                "seed for compensating pair",
            )
            rollback_proof.run_git(repo, "rm", "--quiet", "shared/dead.txt")
            rollback_proof.run_git(repo, "commit", "--quiet", "-m", gen1.bless_subject)
            gen1_bless = rollback_proof.run_git(repo, "rev-parse", "HEAD").stdout.strip()

            # gen2 bless: dead.txt를 되살리고(세탁) alive.txt를 지워 개수를 맞춘다.
            rollback_proof.run_git(repo, "rm", "--quiet", "shared/alive.txt")
            gen2_bless = commit_paths_for_test(
                repo,
                {"shared/dead.txt": "GATE_B_LAUNDERED_BACK\n"},
                gen2.bless_subject,
            )

            before = {
                path
                for path in shared
                if rollback_proof.path_exists_in_tree(repo, gen1_bless, path)
            }
            after = {
                path
                for path in shared
                if rollback_proof.path_exists_in_tree(repo, gen2_bless, path)
            }
            # 이것이 이 테스트의 핵심 전제다 — 개수가 같아야 개수 비교를 독살로
            # 검출할 수 있다.
            self.assertEqual(len(before), len(after))
            self.assertNotEqual(before, after)

            with self.assertRaisesRegex(
                rollback_proof.ProofError, "residual existence set changed"
            ):
                rollback_proof.assert_residual_existence_invariant(
                    repo, gen1, {"bless": gen1_bless}, gen2, {"bless": gen2_bless}
                )

    def test_d3_rejects_equal_count_declaration_mismatch(self) -> None:
        """D3도 개수가 아니라 집합을 비교함을 고정한다.

        U-11의 미선언 케이스는 개수까지 달라(2 대 1) ``len`` 비교 독살을
        통과시킨다. 여기서는 개수가 같고 원소만 어긋나는 선언을 쓴다.
        """
        gen1 = self.make_generation(
            "gen1-d3-count",
            b1_paths=frozenset({"c1/b1.txt"}),
            b2_paths=frozenset({"c1/b2.txt"}),
            shared_paths=frozenset({"shared/a.txt", "shared/b.txt"}),
        )
        gen2 = self.make_generation(
            "gen2-d3-count",
            b1_paths=frozenset({"c2/b1.txt"}),
            b2_paths=frozenset({"c2/b2.txt"}),
            shared_paths=frozenset({"shared/a.txt", "shared/b.txt"}),
            residual_edits=frozenset({"shared/a.txt"}),
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-d3-count-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            rollback_proof.run_git(repo, "init", "--quiet")
            commit_paths_for_test(repo, {"README.md": "base\n"}, "base")
            gen1_bless = commit_paths_for_test(
                repo,
                {"shared/a.txt": "v1-a\n", "shared/b.txt": "v1-b\n"},
                gen1.bless_subject,
            )
            # 선언은 {a}인데 실제로 바뀐 것은 {b} — 개수는 1로 같다.
            gen2_bless = commit_paths_for_test(
                repo, {"shared/b.txt": "v2-b\n"}, gen2.bless_subject
            )
            with self.assertRaisesRegex(
                rollback_proof.ProofError, "residual edits undeclared"
            ):
                rollback_proof.assert_declared_residual_edits(
                    repo, gen1, {"bless": gen1_bless}, gen2, {"bless": gen2_bless}
                )

    def test_assert_generation_records_wellformed_rejects_empty_generations(self) -> None:
        """D6-0 — ``GENERATIONS``가 비면 이 증명은 고정할 대상이 없다.

        직접 호출 단위 테스트다. git 픽스처가 필요 없다 — ``not generations``
        분기는 레코드 자체만 보고 저장소를 전혀 건드리지 않기 때문이다.
        """
        with self.assertRaisesRegex(
            rollback_proof.ProofError, "GENERATIONS is empty"
        ):
            rollback_proof.assert_generation_records_wellformed(())

    def test_resolve_history_rejects_duplicate_generation_names(self) -> None:
        """D6-1 — 이름이 겹치면 ``all_commits``에서 앞 세대가 덮어써져 D3/D5가
        같은 bless를 자기 자신과 비교하게 되고 둘 다 공허해진다. 재축복 커밋 안의
        한 단어짜리 편집으로 이번 변경이 세우는 두 방어선이 모두 꺼진다.
        """
        gen1, gen2 = self.make_pair()
        collided = rollback_proof.Generation(
            **{**gen2.__dict__, "name": gen1.name}
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-dupname-") as tmp:
            with self.assertRaisesRegex(
                rollback_proof.ProofError, "duplicate generation names"
            ):
                self.drive(tmp, (gen1, collided))

    def test_resolve_history_rejects_generation_without_gate_b_markers(self) -> None:
        """D6-2 — ``gate_b_markers=()``면 C3-a/C3-b가 0회 루프로 공허하게
        통과한다. I5 약화를 정당화하는 역방향 anti-laundering 방어선을 재축복자
        자신이 끌 수 있으면 안 된다.
        """
        gen1, _ = self.make_pair()
        blind = self.make_generation(
            "gen2-no-markers",
            b1_paths=frozenset({"g2/b1.txt"}),
            b2_paths=frozenset({"g2/b2.txt"}),
            shared_paths=frozenset({"shared/keep.txt", "shared/vanish.txt"}),
            gate_b_markers=(),
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-nomarker-") as tmp:
            with self.assertRaisesRegex(
                rollback_proof.ProofError, "declares no Gate-B markers"
            ):
                self.drive(tmp, (gen1, blind))

    def test_resolve_history_rejects_generation_without_residual_markers(self) -> None:
        """D6-2b — ``residual_markers={}``면 무관 기능 보존 계약이 공허해진다."""
        gen1, _ = self.make_pair()
        blind = self.make_generation(
            "gen2-no-residual-markers",
            b1_paths=frozenset({"g2/b1.txt"}),
            b2_paths=frozenset({"g2/b2.txt"}),
            shared_paths=frozenset({"shared/keep.txt", "shared/vanish.txt"}),
            residual_markers={},
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-noresid-") as tmp:
            with self.assertRaisesRegex(
                rollback_proof.ProofError, "declares no residual markers"
            ):
                self.drive(tmp, (gen1, blind))

    def test_resolve_history_rejects_vacuous_residual_marker_collections(self) -> None:
        """D6-2c — 컬렉션이 '비어 있지 않은지'만 보면 바닥이 옮겨질 뿐 막히지 않는다.

        ``residual_markers={"p": ()}``는 안쪽 루프가 0회라 아무 needle도 검사하지
        않고, ``{"p": ("",)}``는 ``"" in content``가 항상 참이라 어떤 내용이든
        통과시킨다. 둘 다 dict 자체는 비어 있지 않아 D6의 첫 검사를 그냥 지나간다.
        needle 목록의 비어 있음과 빈 문자열 needle을 모두 거부해야 한다.
        """
        gen1, _ = self.make_pair()
        shared = frozenset({"shared/keep.txt", "shared/vanish.txt"})
        cases = (
            ({"shared/keep.txt": ()}, "declares no residual marker needles"),
            ({"shared/keep.txt": ("",)}, "empty residual marker needle"),
            ({"shared/keep.txt": ("   ",)}, "empty residual marker needle"),
            ({"not/a/component.txt": ("N",)}, "is not a component path"),
        )
        for index, (markers, expected) in enumerate(cases):
            with self.subTest(residual_markers=markers):
                vacuous = self.make_generation(
                    f"gen2-vacuous-{index}",
                    b1_paths=frozenset({"g2/b1.txt"}),
                    b2_paths=frozenset({"g2/b2.txt"}),
                    shared_paths=shared,
                    residual_markers=markers,
                )
                prefix = "context-guard-proof-vacuous-"
                with tempfile.TemporaryDirectory(prefix=prefix) as tmp:
                    with self.assertRaisesRegex(rollback_proof.ProofError, expected):
                        self.drive(tmp, (gen1, vacuous))

    def test_resolve_history_rejects_empty_gate_b_marker_literal(self) -> None:
        """D6-2d — 빈 Gate-B 마커 리터럴을 거부한다.

        ``""``는 어떤 내용에도 포함되므로 존재 검사(C3-a)는 무조건 통과하고 부재
        검사(C3-b)는 무조건 실패해, 마커 레코드가 의미를 잃는다.
        """
        gen1, _ = self.make_pair()
        blank = self.make_generation(
            "gen2-blank-literal",
            b1_paths=frozenset({"g2/b1.txt"}),
            b2_paths=frozenset({"g2/b2.txt"}),
            shared_paths=frozenset({"shared/keep.txt", "shared/vanish.txt"}),
            gate_b_markers=(rollback_proof.GateBMarker("", "shared/keep.txt"),),
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-blank-") as tmp:
            with self.assertRaisesRegex(
                rollback_proof.ProofError, "empty Gate-B marker literal"
            ):
                self.drive(tmp, (gen1, blank))

    def test_resolve_history_rejects_marker_owner_outside_component_paths(self) -> None:
        """D6-3 — 선언된 소유 경로는 C3-a와 전방 이월의 기준이다.

        컴포넌트 밖 경로를 허용하면 그 보증들이 세대의 동결 경계 밖을 가리킨다.
        """
        gen1, _ = self.make_pair()
        foreign = self.make_generation(
            "gen2-foreign-owner",
            b1_paths=frozenset({"g2/b1.txt"}),
            b2_paths=frozenset({"g2/b2.txt"}),
            shared_paths=frozenset({"shared/keep.txt", "shared/vanish.txt"}),
            gate_b_markers=(
                rollback_proof.GateBMarker("shared:", "not/a/component/path.txt"),
            ),
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-owner-") as tmp:
            with self.assertRaisesRegex(
                rollback_proof.ProofError, "is not a\n?\\s*component path"
            ):
                self.drive(tmp, (gen1, foreign))

    def test_resolve_history_rejects_pathspec_magic_component_path(self) -> None:
        """D6-5 배선 — 컴포넌트 경로가 리터럴이 아니면 거부한다.

        기계 게이트는 모든 git 호출에 ``GIT_LITERAL_PATHSPECS=1``을 걸어 두므로
        pathspec 매직에 속지 않는다. 그러나 런북은 ``review_pathspec``을
        **사람의 셸에 붙여넣으라**고 지시하고 거기엔 그 환경변수가 없다. 따라서
        ``:(exclude)…`` 꼴 경로는 기계 검사에는 그대로 걸리면서 사람이 읽는
        리뷰 diff에서만 조용히 사라진다 — 사람 검토만 좁히는 비대칭이다.

        ``self.drive``로 몰아 호출부까지 고정한다. 함수를 직접 부르면 검사를
        호출하는 자리를 지워도 이 테스트가 통과해 버린다.
        """
        gen1, _ = self.make_pair()
        magic = self.make_generation(
            "gen2-pathspec-magic",
            b1_paths=frozenset({"g2/b1.txt"}),
            b2_paths=frozenset({"g2/b2.txt"}),
            shared_paths=frozenset({":(exclude)shared/keep.txt"}),
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-magic-") as tmp:
            with self.assertRaisesRegex(
                rollback_proof.ProofError, "non-literal component"
            ):
                self.drive(tmp, (gen1, magic))

    def test_resolve_history_rejects_pathspec_magic_component_path_in_b1_or_b2(
        self,
    ) -> None:
        """D6-5 배선(범위) — 리터럴 검사가 ``shared_paths``만이 아니라
        ``all_component_paths``(=``b1_paths | b2_paths | shared_paths``) 전체에
        적용됨을 고정한다.

        위 테스트와 ``test_shipped_component_paths_are_all_literal``은 둘 다 매직
        경로를 ``shared_paths``에만 넣으므로, 검사 범위를 ``all_component_paths``에서
        ``shared_paths``로 좁혀도(``b1_paths``/``b2_paths``를 빼먹어도) 스위트
        전체가 초록으로 남는다. 여기서는 매직 경로를 ``b1_paths``와 ``b2_paths``
        양쪽에 각각 따로 넣어 그 좁히기를 잡는다.
        """
        gen1, _ = self.make_pair()
        for slot in ("b1_paths", "b2_paths"):
            with self.subTest(slot=slot):
                kwargs = {
                    "b1_paths": frozenset({"g2/b1.txt"}),
                    "b2_paths": frozenset({"g2/b2.txt"}),
                    "shared_paths": frozenset({"shared/keep.txt"}),
                }
                kwargs[slot] = frozenset({":(exclude)component.txt"})
                magic = self.make_generation(f"gen2-pathspec-magic-{slot}", **kwargs)
                with tempfile.TemporaryDirectory(
                    prefix=f"context-guard-proof-magic-{slot}-"
                ) as tmp:
                    with self.assertRaisesRegex(
                        rollback_proof.ProofError, "non-literal component"
                    ):
                        self.drive(tmp, (gen1, magic))

    def test_resolve_history_rejects_other_pathspec_magic_spellings(self) -> None:
        """D6-5 배선(스펠링) — ``startswith(":")``가 ``":(...)"`` 한 철자만이
        아니라 모든 git pathspec 매직 서명(``:!``/``:^``/``:/`` 등, 전부 선행
        ``:``를 공유한다)을 잡음을 고정한다.

        구현을 ``startswith(":(")``로 약화해도 위 테스트들은 계속 초록이다 —
        전부 ``:(exclude)…`` 철자만 쓰기 때문이다. 프로덕션 술어 자체
        (``startswith(":")``)는 이미 완전하다(모든 git pathspec 매직은 선행
        ``:``를 요구한다); 부족했던 것은 이 커버리지뿐이다.
        """
        gen1, _ = self.make_pair()
        for magic_prefix in (":!", ":^", ":/"):
            with self.subTest(magic_prefix=magic_prefix):
                magic = self.make_generation(
                    f"gen2-pathspec-magic-{magic_prefix.strip(':')}",
                    b1_paths=frozenset({"g2/b1.txt"}),
                    b2_paths=frozenset({"g2/b2.txt"}),
                    shared_paths=frozenset({f"{magic_prefix}component.txt"}),
                )
                with tempfile.TemporaryDirectory(
                    prefix="context-guard-proof-magic-spelling-"
                ) as tmp:
                    with self.assertRaisesRegex(
                        rollback_proof.ProofError, "non-literal component"
                    ):
                        self.drive(tmp, (gen1, magic))

    def test_resolve_history_rejects_unsafe_shell_characters_in_component_path(
        self,
    ) -> None:
        """D6-5 확장 — 공백과 셸/glob 메타문자를 가진 컴포넌트 경로를 거부한다.

        ``GIT_LITERAL_PATHSPECS=1``은 이 문제를 풀지 못한다: 공백은 git이 아니라
        *사람의 셸*이 ``-- $(jq -r '.review_pathspec[]' ...)``를 인용 없이 확장할
        때 워드 스플리팅으로 경로 하나를 여러 토큰으로 쪼갠다. 그 결과 git은
        경로 일부만(또는 전혀 매치하지 않는 조각을) 받고, 기계 게이트는 여전히
        전체 경로를 리터럴로 보므로 exit 0 그대로다 — 사람 검토만 조용히
        좁아진다. ``self.drive``로 몰아 호출부까지 고정한다.

        각 불안전 문자를 **서로 다른 경로 슬롯**에 넣는다. 셋 다
        ``shared_paths``에만 넣으면 이 규칙의 적용 범위를 ``all_component_paths``
        에서 ``shared_paths``로 좁혀도(=``b1_paths``/``b2_paths``를 빼먹어도)
        스위트가 전부 초록으로 남는다 — 바로 위 매직 경로 테스트가 막으려던 것과
        똑같은 구멍이 새 규칙 쪽에 그대로 재발한 것이었다(변이 측정으로 확인).
        슬롯을 나눠 담으면 어느 슬롯 하나라도 검사에서 빠지는 순간 그 하위
        테스트가 실패하고, 동시에 공백/glob 문자 커버리지도 그대로 유지된다.
        """
        gen1, _ = self.make_pair()
        # (불안전 경로, 그 경로를 담을 슬롯) — 슬롯마다 하나씩 배치한다.
        cases = (
            ("g2/has space.txt", "b1_paths"),
            ("g2/glob[ab].txt", "b2_paths"),
            ("shared/star*.txt", "shared_paths"),
        )
        for unsafe_path, slot in cases:
            with self.subTest(unsafe_path=unsafe_path, slot=slot):
                kwargs = {
                    "b1_paths": frozenset({"g2/b1.txt"}),
                    "b2_paths": frozenset({"g2/b2.txt"}),
                    "shared_paths": frozenset({"shared/keep.txt"}),
                }
                kwargs[slot] = frozenset({unsafe_path})
                unsafe = self.make_generation("gen2-unsafe-chars", **kwargs)
                with tempfile.TemporaryDirectory(
                    prefix="context-guard-proof-unsafe-chars-"
                ) as tmp:
                    with self.assertRaisesRegex(
                        rollback_proof.ProofError, "unsafe character"
                    ):
                        self.drive(tmp, (gen1, unsafe))

    def test_every_unsafe_character_in_the_rule_is_individually_rejected(self) -> None:
        """D6-5 확장(문자 커버리지) — ``_UNSAFE_COMPONENT_PATH_CHARS``가 나열한
        문자 하나하나가 실제로 거부됨을 고정한다.

        바로 위 ``drive`` 테스트는 호출부와 적용 범위를 고정하지만 문자는 셋
        (공백/``[``/``*``)만 태운다. 그래서 규칙을 ``r"[\\s*?\\[]"``로 줄여
        나머지 15개 문자를 빼도 스위트 전체가 초록이었다(측정 확인) — 문자
        집합이 미핀 상태였다. 여기서 각 문자를 개별 하위 테스트로 태워, 어느
        문자를 지우든 그 하위 테스트가 실패하게 만든다.

        ``drive``(합성 저장소 생성)를 쓰지 않고 술어 함수를 직접 부른다. 문자
        하나마다 저장소를 만들면 느리고, 호출부 고정은 이미 위 테스트가 맡고
        있어 여기서 중복할 이유가 없다.

        **문자 × 슬롯 교차**를 전부 태운다. 문자 집합을 ``b1_paths``에만,
        슬롯을 문자 하나씩만 태우면 두 축이 직교로만 고정돼 교차가 빈다:
        그 상태에서는

            if unsafe and (path in generation.b1_paths
                           or unsafe.group() in {" ", "*", "["}):

        같은 단일 편집이 스위트를 초록으로 통과하면서 ``b2_paths``의
        ``x/has$dollar.txt``를 실제로 받아들인다(측정 확인). 교차를 전부
        고정하면 어느 슬롯의 어느 문자가 빠져도 그 하위 테스트가 실패한다.
        """
        unsafe_characters = (
            " ", "\t", "\n", "\r", "\v", "\f",
            # 비ASCII 공백류. bash의 IFS는 ASCII 공백만 쪼개므로 이들은 워드
            # 스플리팅 위험은 아니지만, `jq -r` 목록을 눈으로 읽는 사람에게는
            # 보통 공백과 구별되지 않는다 — 사람 검토 무결성이 곧 이 규칙의
            # 위협 모델이므로 함께 막는다. 이 항목들이 없으면 정규식에
            # ``re.ASCII``를 붙이는 단일 편집이 스위트를 초록으로 통과한다
            # (측정 확인).
            " ", " ", "　",
            "*", "?", "[", "]", "{", "}", "$", "`", '"', "'", "\\",
            "|", ";", "&", "<", ">", "(", ")", "~", "!", "#",
        )
        for slot in ("b1_paths", "b2_paths", "shared_paths"):
            for character in unsafe_characters:
                with self.subTest(slot=slot, character=character):
                    kwargs = {
                        "b1_paths": frozenset({"g/b1.txt"}),
                        "b2_paths": frozenset({"g/b2.txt"}),
                        # ``shared_paths``는 기본 마커의 소유 경로로 쓰이므로
                        # 불안전 경로를 넣을 때도 깨끗한 경로를 함께 남긴다.
                        "shared_paths": frozenset({"shared/keep.txt"}),
                    }
                    unsafe_path = f"g/a{character}b.txt"
                    kwargs[slot] = frozenset({unsafe_path}) | (
                        {"shared/keep.txt"} if slot == "shared_paths" else set()
                    )
                    generation = self.make_generation("gen-unsafe-char", **kwargs)
                    with self.assertRaisesRegex(
                        rollback_proof.ProofError, "unsafe character"
                    ):
                        rollback_proof.assert_generation_records_wellformed(
                            (generation,)
                        )

    def test_shipped_component_paths_are_all_literal(self) -> None:
        """출하 중인 ``GENERATIONS``가 실제로 이 규칙을 지키는지 확인한다.

        위 테스트들은 합성 레코드만 보므로, 규칙이 살아 있는 경로 목록에는
        적용되지 않는 상태로도 통과한다. 술어를 여기서 재구현하면(예:
        ``path.startswith(":")``만 다시 짜면) 규칙이 바뀔 때 재구현본이 조용히
        낡는다. 그래서 프로덕션 함수를 직접 호출한다 — 규칙이 바뀌어도 이
        테스트는 자동으로 따라간다.

        이 테스트가 고정하는 것과 고정하지 **못하는** 것을 분명히 해 둔다(실측):

        - 고정한다: 출하 중인 ``GENERATIONS``의 경로가 살아 있는 프로덕션 술어를
          통과한다는 것. 누군가 규칙을 어기는 경로를 출하 목록에 넣으면 실패한다.
        - 고정하지 못한다: **검사부의 존재**. 출하 경로는 전부 깨끗하므로
          ``assert_generation_records_wellformed``는 검사부가 있든 없든 정상
          반환한다. 실제로 ``:`` 검사나 unsafe 검사를 각각 무력화해도 이
          테스트는 초록으로 남는다(측정 확인). 검사부와 그 적용 범위를 고정하는
          것은 위의 합성 ``drive`` 테스트들이지 이 테스트가 아니다.

        이 구분을 적어 두는 이유는, '이 테스트가 호출부를 고정한다'는 잘못된
        믿음이 바로 이 PR 시리즈가 같은 결함을 네 번 반복한 전파 경로이기
        때문이다.
        """
        rollback_proof.assert_generation_records_wellformed(rollback_proof.GENERATIONS)

    def test_resolve_history_rejects_overlapping_component_paths(self) -> None:
        """I1 배선 — ``assert_disjoint_paths``의 호출부를 지우면 실패한다.

        U-3b는 함수를 직접 호출하므로 호출부 제거를 잡지 못했다.

        이 테스트는 ``resolve_history``를 직접 부르므로 ``resolve_source_head``를
        거치지 않는다 — 즉 CLI 수준의 이력 가용성 판정보다 레코드 검사가 앞선다는
        성질은 여기서 검증되지 않는다. 그 순서는
        ``test_cli_reports_a_malformed_record_as_failure_not_unavailable``이
        하위 프로세스로 고정한다.
        """
        overlapping = self.make_generation(
            "gen-overlap-wired",
            b1_paths=frozenset({"o/dup.txt", "o/b1.txt"}),
            b2_paths=frozenset({"o/dup.txt"}),
            shared_paths=frozenset({"o/shared.txt"}),
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-overlap-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            rollback_proof.run_git(repo, "init", "--quiet")
            base = commit_paths_for_test(repo, {"README.md": "base\n"}, "base")
            with mock.patch.object(rollback_proof, "GENERATIONS", (overlapping,)):
                with mock.patch.object(rollback_proof, "BASE_COMMIT", base):
                    with self.assertRaisesRegex(
                        rollback_proof.ProofError, "component paths overlap"
                    ):
                        rollback_proof.resolve_history(
                            repo, base, history_may_be_truncated=False
                        )

    def test_resolve_history_fires_c3b_when_bless_retains_a_gate_b_marker(self) -> None:
        """C3-b 배선 — U-8은 헬퍼를 직접 호출하므로 ``resolve_history``의 호출부를
        지워도 잡히지 않았다. 여기서는 활성 세대의 bless 트리가 실제로 그 세대의
        Gate-B 마커를 품게 만들어 호출부까지 고정한다.

        합성 bless는 ``# residual[<gen>]: <path>``를 쓰므로 리터럴 ``residual[``는
        bless에는 있고 shared reapply 커밋(``# shared: <path>``)에는 없다 —
        C3-b가 발화해야 하는 정확한 조건이다.
        """
        gen1, _ = self.make_pair()
        leaky = self.make_generation(
            "gen2-leaky-bless",
            b1_paths=frozenset({"g2/b1.txt"}),
            b2_paths=frozenset({"g2/b2.txt"}),
            shared_paths=frozenset({"shared/keep.txt", "shared/vanish.txt"}),
            # 직전 세대의 마커를 그대로 이월하면서(전방 이월 규칙) 누출을
            # 드러내는 리터럴을 하나 더 얹는다. 누출 리터럴은 HEAD에도 있어야
            # 한다 — C3-a가 C3-b보다 먼저 돌기 때문이다. 경로 이름 자체는 bless
            # (``# residual[...]: shared/keep.txt``)와 HEAD(``# shared:
            # shared/keep.txt``) 양쪽에 나타나므로 이 조건을 만족한다.
            gate_b_markers=(
                rollback_proof.GateBMarker(
                    self.SHARED_MARKER_LITERAL, "shared/keep.txt"
                ),
                rollback_proof.GateBMarker("shared/keep.txt", "shared/keep.txt"),
            ),
            residual_edits=frozenset({"shared/keep.txt", "shared/vanish.txt"}),
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-c3b-wired-") as tmp:
            with self.assertRaisesRegex(
                rollback_proof.ProofError, "retains Gate-B marker"
            ):
                self.drive(tmp, (gen1, leaky))

    def test_d3_rejects_over_declaration(self) -> None:
        """D3가 *정확히* 일치를 요구함을 고정한다 (과대선언 방향).

        U-11과 개수 테스트는 과소선언만 다루므로, 구현을
        ``if actual_edits - current.residual_edits``(부분집합 허용)로 독살해도
        통과했다. 실제로 바꾼 것보다 넓게 선언하는 것도 거부되어야 한다 —
        그렇지 않으면 '전부 선언'이 D3를 통째로 무력화하는 만능 키가 된다.
        """
        gen1 = self.make_generation(
            "gen1-over",
            b1_paths=frozenset({"o1/b1.txt"}),
            b2_paths=frozenset({"o1/b2.txt"}),
            shared_paths=frozenset({"shared/a.txt", "shared/b.txt"}),
        )
        gen2 = self.make_generation(
            "gen2-over",
            b1_paths=frozenset({"o2/b1.txt"}),
            b2_paths=frozenset({"o2/b2.txt"}),
            shared_paths=frozenset({"shared/a.txt", "shared/b.txt"}),
            residual_edits=frozenset({"shared/a.txt", "shared/b.txt"}),
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-d3-over-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            rollback_proof.run_git(repo, "init", "--quiet")
            commit_paths_for_test(repo, {"README.md": "base\n"}, "base")
            gen1_bless = commit_paths_for_test(
                repo,
                {"shared/a.txt": "v1-a\n", "shared/b.txt": "v1-b\n"},
                gen1.bless_subject,
            )
            # 선언은 {a, b}인데 실제로 바뀐 것은 {a}뿐이다.
            gen2_bless = commit_paths_for_test(
                repo, {"shared/a.txt": "v2-a\n"}, gen2.bless_subject
            )
            with self.assertRaisesRegex(
                rollback_proof.ProofError, "residual edits undeclared"
            ):
                rollback_proof.assert_declared_residual_edits(
                    repo, gen1, {"bless": gen1_bless}, gen2, {"bless": gen2_bless}
                )

    def test_resolve_history_rejects_silently_dropped_gate_b_marker(self) -> None:
        """D6-4 — 여전히 소유한 경로의 Gate-B 마커를 조용히 버리면 거부된다.

        마커가 '비어 있지 않기만' 하면 재축복자가 자기 bless를 구속할 리터럴
        집합을 스스로 고른다. nonce 마커 하나를 선언하고(자기 reapply 커밋이
        HEAD에 그 nonce를 넣으면 존재 검사 통과, bless는 그보다 앞서므로 부재
        검사 통과) 진짜 Gate-B 리터럴은 bless에 그대로 남기는 세탁이 성립한다.
        전방 이월은 그 선택권을 없앤다.

        이월은 소급이 아니다 — 과거 bless를 새 마커로 다시 검사하는 게 아니라
        새 bless를 과거 마커로 검사할 뿐이라, 세대별 비소급 성질은 보존된다
        (U-12가 계속 통과하는 것으로 확인된다).
        """
        gen1, _ = self.make_pair()
        shared = frozenset({"shared/keep.txt", "shared/vanish.txt"})
        nonce_only = self.make_generation(
            "gen2-nonce-only",
            b1_paths=frozenset({"g2/b1.txt"}),
            b2_paths=frozenset({"g2/b2.txt"}),
            shared_paths=shared,
            gate_b_markers=(
                rollback_proof.GateBMarker("GEN2_NONCE_TOKEN", "shared/keep.txt"),
            ),
            residual_edits=shared,
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-carry-") as tmp:
            with self.assertRaisesRegex(
                rollback_proof.ProofError, "drops Gate-B markers"
            ):
                self.drive(tmp, (gen1, nonce_only))

    def test_resolve_history_fires_c3a_when_head_lost_a_gate_b_marker(self) -> None:
        """C3-a 배선 — 존재 검사의 *호출부*를 고정한다.

        U-9는 헬퍼를 직접 부르므로 ``resolve_history``에서 호출 한 줄을 지워도
        스위트가 초록이었다(변이 배터리로 확인). 마커가 rot했는데 이 검사가
        빠지면 C3-b가 '어디에도 없으니 bless에도 없다'로 조용히 통과해 역방향
        방어선 전체가 소리 없이 사라진다.
        """
        gen1, _ = self.make_pair()
        rotted = self.make_generation(
            "gen2-rotted-marker",
            b1_paths=frozenset({"g2/b1.txt"}),
            b2_paths=frozenset({"g2/b2.txt"}),
            shared_paths=frozenset({"shared/keep.txt", "shared/vanish.txt"}),
            gate_b_markers=(
                rollback_proof.GateBMarker(
                    self.SHARED_MARKER_LITERAL, "shared/keep.txt"
                ),
                rollback_proof.GateBMarker("GONE_FROM_HEAD", "shared/keep.txt"),
            ),
            residual_edits=frozenset({"shared/keep.txt", "shared/vanish.txt"}),
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-c3a-wired-") as tmp:
            with self.assertRaisesRegex(rollback_proof.ProofError, "missing from"):
                self.drive(tmp, (gen1, rotted))

    def test_c3b_rejects_a_generation_that_evaluates_no_markers(self) -> None:
        """bless가 모든 컴포넌트 경로를 삭제해 C3-b가 0개 파일을 평가한 채
        성공하는 것을 막는다.

        ``commit_paths``는 ``diff-tree --name-only``라 상태를 보지 않으므로,
        bless가 삭제한 경로도 여전히 정당한 컴포넌트 경로다. 따라서 경로 집합
        구조 검사만으로는 이 공허화를 막지 못한다.
        """
        marker_owner = "shared/only.txt"
        generation = self.make_generation(
            "gen-evaluates-nothing",
            b1_paths=frozenset({"e/b1.txt"}),
            b2_paths=frozenset({"e/b2.txt"}),
            shared_paths=frozenset({marker_owner}),
            residual_markers={marker_owner: (self.RESIDUAL_MARKER_NEEDLE,)},
            gate_b_markers=(
                rollback_proof.GateBMarker("ANY_LITERAL", marker_owner),
            ),
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-noeval-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            rollback_proof.run_git(repo, "init", "--quiet")
            commit_paths_for_test(repo, {"README.md": "base\n"}, "base")
            # 컴포넌트 경로가 아예 없는 bless 트리 — 검사할 파일이 하나도 없다.
            empty_bless = commit_paths_for_test(
                repo, {"other.txt": "no marker owner here\n"}, "bless without owners"
            )
            with self.assertRaisesRegex(
                rollback_proof.ProofError, "evaluated no Gate-B markers"
            ):
                rollback_proof.assert_gate_b_markers_absent_from_bless(
                    repo, generation, empty_bless
                )

    def test_assert_generation_structure_rejects_overlapping_paths(self) -> None:
        """서로소 검사가 ``assert_generation_structure`` 안에서도 실제로 돈다.

        사전 검사(pre-pass)와 이 호출은 서로 다른 진입점을 방어한다. 사전 검사만
        고정돼 있으면 ``assert_generation_structure``를 직접 부르는 경로에서 검사가
        사라져도 아무 테스트가 실패하지 않는다(변이 배터리로 확인).
        """
        overlapping = self.make_generation(
            "gen-structure-overlap",
            b1_paths=frozenset({"s/dup.txt", "s/b1.txt"}),
            b2_paths=frozenset({"s/dup.txt"}),
            shared_paths=frozenset({"s/shared.txt"}),
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-structover-") as tmp:
            # 진짜 4-커밋 체인을 만든다. 겹치는 경로 집합은 부모 체인 검사도 경로
            # 집합 검사도 통과시킬 수 있으므로(b1 커밋이 {b1,dup}을, b2 커밋이
            # {dup}을 건드리면 둘 다 선언과 일치한다) 서로소 검사에 실제로 도달한다.
            _repo, _base, all_commits = self.make_repo_for_generations(
                Path(tmp), (overlapping,)
            )
            with self.assertRaisesRegex(
                rollback_proof.ProofError, "component paths overlap"
            ):
                rollback_proof.assert_generation_structure(
                    _repo, overlapping, all_commits[overlapping.name]
                )

    def test_apply_then_revert_restores_the_base_tree(self) -> None:
        """apply/revert 트리 동등성의 성공 방향만 고정한다.

        변이 배터리에서 이 단언(``reverted_tree != base_tree``)을 꺼도 스위트가
        초록으로 남는다. 그러나 실패 방향을 합성으로 만들 수 없다: ``git revert``가
        깨끗이 적용되면 결과 트리는 정의상 cherry-pick 직전 트리와 같고, 깨끗이
        적용되지 않으면 ``run_git``이 그 전에 cherry-pick/revert 실패로 발화한다.
        즉 이 단언은 git 의미론상 도달 불가능한 방어적 단언이며, 억지 픽스처로
        핀을 만드는 대신 그 사실을 여기 기록한다. 성공 방향은 회귀를 잡는다.
        """
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-applyrevert-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            rollback_proof.run_git(repo, "init", "--quiet")
            base = commit_paths_for_test(repo, {"f.txt": "v1\n"}, "base")
            component = commit_paths_for_test(repo, {"f.txt": "v2\n"}, "component")
            base_tree = rollback_proof.run_git(
                repo, "rev-parse", f"{base}^{{tree}}"
            ).stdout.strip()
            result = rollback_proof.apply_then_revert(repo, base, component)
            self.assertEqual(result["reverted_tree"], base_tree)
            self.assertNotEqual(result["applied_tree"], base_tree)

    def test_resolve_history_fires_residual_contract(self) -> None:
        """잔여 계약의 ``resolve_history`` 호출부를 고정한다.

        이 검사는 ``prove_current_revert_order``에서도 불리므로 호출부 하나를 지워도
        전체가 무력해지지는 않지만, 그렇다고 배선이 검증된 것은 아니다.

        저장소는 마커를 *쓰는* 세대 기록으로 만들고, ``resolve_history``에는 더 넓은
        마커를 요구하는 기록을 넘긴다 — U-12의 대조군과 같은 기법이다.
        """
        gen1, gen2 = self.make_pair(
            residual_edits=frozenset({"shared/keep.txt", "shared/vanish.txt"})
        )
        demanding = self.make_generation(
            gen2.name,
            b1_paths=gen2.b1_paths,
            b2_paths=gen2.b2_paths,
            shared_paths=gen2.shared_paths,
            residual_markers={"shared/keep.txt": ("MARKER_NEVER_WRITTEN",)},
            residual_edits=gen2.residual_edits,
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-residwire-") as tmp:
            with self.assertRaisesRegex(
                rollback_proof.ProofError, "unrelated feature marker"
            ):
                self.drive(tmp, (gen1, gen2), drive_generations=(gen1, demanding))

    def test_cli_reports_a_malformed_record_as_failure_not_unavailable(self) -> None:
        """레코드 결함은 체크아웃 모양과 무관하므로 어떤 클론에서도 '실패'(종료 1)여야
        한다.

        레코드 검사가 ``resolve_source_head`` 뒤에 있으면, ``BASE_COMMIT``이 없는
        얕은/무관 체크아웃에서 ``ProofHistoryUnavailable``(종료 3)이 먼저 나서
        망가진 레코드가 '증명 불가'로 보고된다. 그건 소스 결함을 환경 문제로
        오분류하는 것이다. 이 테스트는 레코드 사전 검사가 이력 가용성 판정보다도
        앞선다는 순서를 고정한다.
        """
        program = (
            "import importlib.util, sys;"
            f"spec = importlib.util.spec_from_file_location('vg', {str(SCRIPT)!r});"
            "m = importlib.util.module_from_spec(spec);"
            "sys.modules['vg'] = m;"
            "spec.loader.exec_module(m);"
            "bad = m.Generation(name='bad', bless_subject='b', b1_subject='1',"
            " b2_subject='2', shared_subject='s',"
            " b1_paths=frozenset({'x', 'dup'}), b2_paths=frozenset({'dup'}),"
            " shared_paths=frozenset({'y'}), residual_markers={'y': ('N',)},"
            " gate_b_markers=(m.GateBMarker('L', 'y'),));"
            "m.GENERATIONS = (bad,);"
            "sys.argv = ['vg', '--json', '--repo', sys.argv[1]];"
            "raise SystemExit(m.main())"
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-cli-record-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            rollback_proof.run_git(repo, "init", "--quiet")
            commit_paths_for_test(repo, {"README.md": "unrelated\n"}, "unrelated")
            proc = subprocess.run(
                [sys.executable, "-c", program, str(repo)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertEqual(proc.returncode, 1, proc.stderr or proc.stdout)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "fail")
        self.assertIn("component paths overlap", payload["error"])

    def test_record_invariants_survive_python_optimized_mode(self) -> None:
        """AC-2b — 레코드 불변이 ``python -O``에서도 살아 있음을 *기계적으로*
        고정한다.

        기존 독스트링은 '전체 스위트가 ``python -O``로도 실행되므로'라고 적었지만
        실측하면 ``scripts/prepublish_check.py``도 ``.github/workflows/``도 ``-O``를
        쓰지 않는다 — 자동화된 보증이 아니라 수동 실행에 기댄 주장이었다. 그래서
        여기서 직접 ``-O`` 하위 프로세스를 띄운다. 검사가 ``assert`` 문으로
        회귀하면 ``-O``가 그것을 소거해 이 테스트가 실패한다.
        """
        program = "\n".join(
            [
                "import importlib.util, sys",
                f"spec = importlib.util.spec_from_file_location('vg', {str(SCRIPT)!r})",
                "m = importlib.util.module_from_spec(spec)",
                "sys.modules['vg'] = m",
                "spec.loader.exec_module(m)",
                "",
                "def gen(name, **kw):",
                "    base = dict(name=name, bless_subject='b ' + name,",
                "                b1_subject='1 ' + name, b2_subject='2 ' + name,",
                "                shared_subject='s ' + name,",
                "                b1_paths=frozenset({name + '/x'}),",
                "                b2_paths=frozenset({name + '/z'}),",
                "                shared_paths=frozenset({name + '/y'}),",
                "                residual_markers={name + '/y': ('N',)},",
                "                gate_b_markers=(m.GateBMarker('L', name + '/y'),))",
                "    base.update(kw)",
                "    return m.Generation(**base)",
                "",
                "ok = gen('ok')",
                "overlap = gen('ov', b1_paths=frozenset({'ov/x', 'ov/dup'}),",
                "               b2_paths=frozenset({'ov/dup'}))",
                # 각 분기를 서로 다른 레코드로 따로 발화시킨다 — 한 레코드에 여러
                # 결함을 몰아넣으면 먼저 걸리는 분기 하나만 검증되고 나머지 분기는
                # -O에서 소거돼도 눈치채지 못한다.
                "cases = [",
                "    ('disjoint', lambda: m.assert_disjoint_paths(overlap)),",
                "    ('dupname', lambda: m.assert_generation_records_wellformed(",
                "        (ok, gen('ok', b1_paths=frozenset({'ok2/x'}),",
                "                 b2_paths=frozenset({'ok2/z'}),",
                "                 shared_paths=frozenset({'ok2/y'}),",
                "                 residual_markers={'ok2/y': ('N',)},",
                "                 gate_b_markers=(m.GateBMarker('L', 'ok2/y'),))))),",
                "    ('nomarkers', lambda: m.assert_generation_records_wellformed(",
                "        (gen('nm', gate_b_markers=()),))),",
                "    ('noresidual', lambda: m.assert_generation_records_wellformed(",
                "        (gen('nr', residual_markers={}),))),",
                "    ('emptyneedle', lambda: m.assert_generation_records_wellformed(",
                "        (gen('en', residual_markers={'en/y': ('',)}),))),",
                "    ('foreignowner', lambda: m.assert_generation_records_wellformed(",
                "        (gen('fo', gate_b_markers=(m.GateBMarker('L', 'nope'),)),))),",
                "    ('pathspecmagic', lambda: m.assert_generation_records_wellformed(",
                "        (gen('pm', shared_paths=frozenset({':(exclude)pm/y'}),",
                "             residual_markers={':(exclude)pm/y': ('N',)},",
                "             gate_b_markers=(m.GateBMarker('L', ':(exclude)pm/y'),)),))),",
                # 공백/메타문자 분기도 -O 행렬에 넣는다. 이 분기가 빠져 있으면
                # 검사가 ``assert not unsafe``로 회귀했을 때 이 테스트만 따로
                # 돌리면 초록으로 남는다(측정 확인) — AC-2b가 보장한다고 말하는
                # 범위에 새 분기가 빠진 상태였다. 불안전 경로는 ``b1_paths``에
                # 넣어 ``shared_paths``와 마커 기본값은 깨끗하게 둔다.
                "    ('unsafechars', lambda: m.assert_generation_records_wellformed(",
                "        (gen('uc', b1_paths=frozenset({'uc/has space'})),))),",
                "]",
                "missed = []",
                "for label, call in cases:",
                "    try:",
                "        call()",
                "    except m.ProofError:",
                "        continue",
                "    missed.append(label)",
                "print(','.join(missed) if missed else 'ALL_RAISED')",
            ]
        )
        proc = subprocess.run(
            [sys.executable, "-O", "-c", program],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            proc.stdout.strip(),
            "ALL_RAISED",
            "these record invariants were optimized away under python -O "
            "(they must raise explicitly, never use an assert statement)",
        )

    def test_path_exists_in_tree_fails_loudly_on_a_bad_revision(self) -> None:
        """부재와 인프라 실패를 가르는 성질을 고정한다.

        ``git cat-file -e <commit>:<path>``는 '트리에 경로 없음'과 '잘못된
        리비전' 양쪽에 128을 돌려주므로 종료 코드로 둘을 가를 수 없었다. 그
        구현에서는 인프라 실패가 곧 '부재'로 읽혀 D5가 before/after 모두 비어
        통과하고 C3-b가 실제 파일을 검사 표면에서 뺐다 — 릴리스 게이트의
        fail-open이다.
        """
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-badrev-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            rollback_proof.run_git(repo, "init", "--quiet")
            head = commit_paths_for_test(repo, {"real.txt": "x\n"}, "base")

            self.assertTrue(rollback_proof.path_exists_in_tree(repo, head, "real.txt"))
            # 유효한 커밋에서의 진짜 부재는 조용히 False여야 한다.
            self.assertFalse(rollback_proof.path_exists_in_tree(repo, head, "gone.txt"))
            # 잘못된 리비전은 부재가 아니라 ProofError여야 한다.
            with self.assertRaises(rollback_proof.ProofError):
                rollback_proof.path_exists_in_tree(repo, "0" * 40, "real.txt")

    def test_path_exists_in_tree_counts_only_blobs(self) -> None:
        """같은 이름의 디렉터리는 '존재'가 아니다.

        ``ls-tree``는 ``-r`` 없이도 트리 엔트리를 그대로 보고하므로 이름만
        비교하면 파일이 디렉터리로 바뀌어도 '여전히 존재'로 읽히고, D5가
        파일→디렉터리 교체를 변화 없음으로 통과시킨다. 컴포넌트 경로는 언제나
        blob이므로 blob만 센다.
        """
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-blob-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            rollback_proof.run_git(repo, "init", "--quiet")
            as_blob = commit_paths_for_test(repo, {"thing": "I am a file\n"}, "as blob")
            self.assertTrue(rollback_proof.path_exists_in_tree(repo, as_blob, "thing"))

            rollback_proof.run_git(repo, "rm", "--quiet", "thing")
            as_tree = commit_paths_for_test(
                repo, {"thing/inner.txt": "now a directory\n"}, "as tree"
            )
            self.assertFalse(
                rollback_proof.path_exists_in_tree(repo, as_tree, "thing"),
                "a directory must not be reported as an existing component path",
            )
            self.assertTrue(
                rollback_proof.path_exists_in_tree(repo, as_tree, "thing/inner.txt")
            )

    def test_path_exists_in_tree_treats_pathspec_magic_literally(self) -> None:
        """컴포넌트 경로는 패턴이 아니라 리터럴로 해석되어야 한다.

        경로 문자열은 여러 곳에서 git pathspec으로 넘어간다.
        ``proof_environment``의 ``GIT_LITERAL_PATHSPECS``가 이를 리터럴로 강제한다.
        경로 집합은 세대마다 다시 선언되므로 '오늘의 18개는 순수 ASCII'라는 사실에
        기댈 수 없다.

        실측한 두 방향(``git diff``에서만 드러난다 — ``ls-tree``는 애초에 glob하지
        않는다):

        * ``weird[a].txt``는 문자 클래스로 읽혀 ``weirda.txt``까지 함께 매칭한다
          (과다 매칭).
        * ``:(exclude)<path>``는 음수 pathspec이 되어 *다른* 경로를 검사 대상에서
          빼버린다 — ``prove_current_revert_order``의 ``residual_delta``가 바로 이
          형태로 컴포넌트 경로를 넘기므로 fail-open이 된다.
        """
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-pathspec-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            rollback_proof.run_git(repo, "init", "--quiet")
            left = commit_paths_for_test(
                repo, {"weird[a].txt": "v1\n", "weirda.txt": "v1\n"}, "left"
            )
            right = commit_paths_for_test(
                repo, {"weird[a].txt": "v2\n", "weirda.txt": "v2\n"}, "right"
            )

            # 과다 매칭 방향: 리터럴이면 자기 자신만 나온다.
            names = rollback_proof.run_git(
                repo, "diff", "--no-renames", "--name-only", left, right,
                "--", "weird[a].txt",
            ).stdout.split()
            self.assertEqual(
                names,
                ["weird[a].txt"],
                "pathspec magic made a component path match unrelated paths",
            )

            # 음수 pathspec 방향: 리터럴이면 아무것도 제외하지 못한다.
            excluded = rollback_proof.run_git(
                repo, "diff", "--no-renames", "--name-only", left, right,
                "--", ":(exclude)weirda.txt",
            ).stdout.split()
            self.assertEqual(
                excluded,
                [],
                "a component path spelled ':(exclude)...' still acted as a negative "
                "pathspec, so it could hide other paths from the proof",
            )

            # 존재 검사 자체도 리터럴이어야 한다.
            self.assertTrue(
                rollback_proof.path_exists_in_tree(repo, right, "weird[a].txt")
            )
            self.assertFalse(
                rollback_proof.path_exists_in_tree(repo, right, "weird[b].txt")
            )

    def test_c3a_reports_a_missing_owner_path_as_a_marker_failure(self) -> None:
        """소유 경로가 HEAD에서 통째로 사라지면 날것의 git 오류가 아니라 마커
        실패로 보고한다.

        가드가 없으면 ``file_at``이 ``git show ... failed``를 올려, 실제 원인
        (마커가 가리키던 표면이 HEAD에 없다)이 진단에서 사라진다.
        """
        generation = self.make_generation(
            "gen-owner-gone",
            b1_paths=frozenset({"o/b1.txt"}),
            b2_paths=frozenset({"o/b2.txt"}),
            shared_paths=frozenset({"o/owner.txt"}),
            gate_b_markers=(rollback_proof.GateBMarker("LIT", "o/owner.txt"),),
        )
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-ownergone-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            rollback_proof.run_git(repo, "init", "--quiet")
            head = commit_paths_for_test(repo, {"unrelated.txt": "x\n"}, "no owner path")
            with self.assertRaisesRegex(
                rollback_proof.ProofError, "owner path itself does not exist"
            ):
                rollback_proof.assert_gate_b_markers_present_at_head(
                    repo, head, generation
                )

    def test_path_exists_in_tree_handles_paths_git_would_quote(self) -> None:
        """존재하는 경로가 따옴표 처리 때문에 '부재'로 읽히지 않아야 한다.

        ``git ls-tree --name-only``는 줄 단위 출력에서 ASCII 밖 경로를 C 스타일로
        따옴표 처리한다(``"hangul_\\355\\225\\234..."``). 그 출력을 줄 단위로
        비교하면 실재하는 경로가 일치하지 않아 '부재'가 되고, 이 함수가 막으려던
        fail-open이 그대로 되살아난다 — D5는 before/after가 함께 줄어 통과하고
        C3-b는 실제 파일을 검사 표면에서 뺀다. ``-z``(NUL 구분)는 따옴표 처리를
        하지 않는다.

        오늘의 18개 컴포넌트 경로는 모두 ASCII라 잠재적이지만, 경로 집합은 세대마다
        재선언되므로 릴리스 게이트에 잠복시켜 둘 종류의 결함이 아니다.
        """
        tricky = {
            "ascii.txt": "a\n",
            "with space.txt": "b\n",
            "유니코드.txt": "c\n",
            "nested/디렉터리/파일.txt": "d\n",
        }
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-quote-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            rollback_proof.run_git(repo, "init", "--quiet")
            head = commit_paths_for_test(repo, tricky, "paths git would quote")
            for path in tricky:
                self.assertTrue(
                    rollback_proof.path_exists_in_tree(repo, head, path),
                    f"existing path {path!r} was misread as absent",
                )
            self.assertFalse(
                rollback_proof.path_exists_in_tree(repo, head, "유니코드-없음.txt")
            )


if __name__ == "__main__":
    unittest.main()
