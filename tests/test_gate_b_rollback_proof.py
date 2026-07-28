from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
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
        rollback_proof.run_git(repo, "add", "README.md")
        rollback_proof.run_git(repo, "commit", "--quiet", "-m", "snapshot")
        return repo

    def make_gate_b_history_repo(self, root: Path) -> tuple[Path, dict[str, str]]:
        """실제 Gate-B 4-커밋 이력과 경로·subject가 동형인 합성 저장소를 만든다.

        운영 코드의 ``B1_PATHS``/``B2_PATHS``/``SHARED_INTEGRATION_PATHS``/
        ``RESIDUAL_MARKERS``를 그대로 읽어 파일을 배치하므로, 프로덕션 상수가
        바뀌면 이 헬퍼도 자동으로 따라간다. 반환값은
        ``{"base"/"bless"/"b1"/"b2"/"shared-integration": <sha>}``.
        """
        repo = root / "gate-b-history"
        repo.mkdir()
        rollback_proof.run_git(repo, "init", "--quiet")
        base = commit_paths_for_test(repo, {"README.md": "base\n"}, "base")

        bless_contents = {
            path: f"# gate-b residual placeholder: {path}\n"
            for path in rollback_proof.ALL_COMPONENT_PATHS
        }
        for path, needles in rollback_proof.GENERATIONS[-1].residual_markers.items():
            bless_contents[path] = "".join(
                f"# {needle}\n" for needle in needles
            ) + f"# gate-b residual placeholder: {path}\n"
        bless = commit_paths_for_test(repo, bless_contents, rollback_proof.BLESS_SUBJECT)

        b1_contents = {
            path: f"# gate-b b1 component: {path}\n" for path in rollback_proof.B1_PATHS
        }
        b1 = commit_paths_for_test(repo, b1_contents, rollback_proof.B1_SUBJECT)

        b2_contents = {
            path: f"# gate-b b2 component: {path}\n" for path in rollback_proof.B2_PATHS
        }
        b2 = commit_paths_for_test(repo, b2_contents, rollback_proof.B2_SUBJECT)

        shared_contents = {
            path: f"# gate-b shared integration: {path}\n"
            for path in rollback_proof.SHARED_INTEGRATION_PATHS
        }
        shared = commit_paths_for_test(repo, shared_contents, rollback_proof.SHARED_SUBJECT)

        return repo, {
            "base": base,
            "bless": bless,
            "b1": b1,
            "b2": b2,
            "shared-integration": shared,
        }

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

    def test_snapshot_repo_reports_history_unavailable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="context-guard-proof-snapshot-") as tmp:
            repo = self.make_snapshot_repo(Path(tmp))
            with self.assertRaisesRegex(
                rollback_proof.ProofHistoryUnavailable,
                "full Gate-B proof history is unavailable",
            ):
                rollback_proof.run_proof(repo)

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


class GateBGenerationsTests(unittest.TestCase):
    """append-only ``GENERATIONS`` 목록 메커니즘 자체를 합성 저장소로 검증한다.

    실제 18개 경로 대신 작은 합성 경로 집합을 쓴다 — G-11 완화책(계획 Decision B)
    대로, 실제 이력 1건에 기대는 것보다 세대 메커니즘(구조 보존/해제/마커/D3/D5)을
    더 정확하게 검증한다. ``GateBRollbackProofTests``를 상속하지 않는 이유는
    상속하면 그 클래스의 test_* 메서드가 이 클래스 이름으로 중복 실행되기
    때문이다 — 공용 헬퍼는 모듈 레벨 ``commit_paths_for_test``로 뺐다.
    """

    def make_generation(
        self,
        name: str,
        *,
        b1_paths: frozenset[str],
        b2_paths: frozenset[str],
        shared_paths: frozenset[str],
        residual_markers: dict[str, tuple[str, ...]] | None = None,
        gate_b_markers: tuple = (),
        residual_edits: frozenset[str] = frozenset(),
    ):
        return rollback_proof.Generation(
            name=name,
            bless_subject=f"proof: establish {name} residual",
            b1_subject=f"proof: reapply {name} b1 component",
            b2_subject=f"proof: reapply {name} b2 component",
            shared_subject=f"proof: reapply {name} shared component",
            b1_paths=b1_paths,
            b2_paths=b2_paths,
            shared_paths=shared_paths,
            residual_markers=residual_markers or {},
            gate_b_markers=gate_b_markers,
            residual_edits=residual_edits,
        )

    def make_repo_for_generations(
        self, root: Path, generations: tuple
    ) -> tuple[Path, str, dict[str, dict[str, str]]]:
        """세대 목록을 base -> gen[0](bless/b1/b2/shared) -> gen[1](...) -> ...
        순으로 이어 붙인 합성 저장소를 만든다. 반환값은
        ``(repo, base_sha, {세대이름: {"bless"/"b1"/"b2"/"shared-integration": sha}})``.
        """
        repo = root / "generations-history"
        repo.mkdir()
        rollback_proof.run_git(repo, "init", "--quiet")
        base = commit_paths_for_test(repo, {"README.md": "base\n"}, "base")

        all_commits: dict[str, dict[str, str]] = {}
        for generation in generations:
            bless_contents = {
                path: f"# residual: {path}\n" for path in generation.all_component_paths
            }
            for path, needles in generation.residual_markers.items():
                bless_contents[path] = (
                    "".join(f"# {needle}\n" for needle in needles) + bless_contents[path]
                )
            bless = commit_paths_for_test(repo, bless_contents, generation.bless_subject)
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

    def test_overlapping_component_path_sets_are_rejected(self) -> None:
        """U-3b — 서로소가 깨지면 거부된다 (I1, 신규 구현). git이 필요 없다 —
        ``assert_disjoint_paths``는 ``Generation`` 레코드만 본다. 전체 스위트가
        ``python -O``로도 실행되므로(AC-2b) 이 검사가 ``assert`` 문이 아님을
        간접 증명한다.
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


if __name__ == "__main__":
    unittest.main()
