"""`context-guard-audit`의 tool_result 바이트 프로파일 절에 대한 계약 테스트.

이 절이 답하는 질문은 "컨텍스트 바이트가 어느 도구에서 왔는가"이다. provider의 usage
필드는 요청 단위 합계만 주므로 도구별 귀속이 불가능하고, 그래서 transcript의
tool_use/tool_result 블록을 직접 세는 경로가 필요하다.

여기서 고정하는 성질:

1. 바이트는 관측값이고 절감 주장이 아니다 (`claim_boundary`가 항상 붙는다).
2. 경로는 절대 새지 않는다 - 확장자만 집계한다.
3. tool_use 상관과 완전중복 판정은 세션(파일) 경계를 넘지 않는다.
4. 이미지/텍스트 분류가 확장자 없는 도구(Bash 등)를 unknown으로 과대 집계하지 않는다.
5. 범위 없는 파일 읽기가 범위 있는 것과 구분되어 집계된다.
6. 모든 누적 구조에 상한이 있어 적대적 transcript가 메모리를 무한히 쓰게 할 수 없다.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
KIT = REPO_ROOT / "context-guard-kit"
sys.path.insert(0, str(KIT))

import claude_transcript_cost_audit as audit  # noqa: E402


def user_row(*blocks: dict) -> dict:
    """tool_result 블록을 담은 사용자 레코드."""
    return {"type": "user", "message": {"role": "user", "content": list(blocks)}}


def assistant_row(*blocks: dict) -> dict:
    """tool_use 블록을 담은 어시스턴트 레코드."""
    return {"type": "assistant", "message": {"role": "assistant", "content": list(blocks)}}


def tool_use(use_id: str, name: str, **payload: object) -> dict:
    return {"type": "tool_use", "id": use_id, "name": name, "input": dict(payload)}


def tool_result(use_id: str, content: object) -> dict:
    return {"type": "tool_result", "tool_use_id": use_id, "content": content}


def write_transcript(directory: Path, name: str, rows: list[dict]) -> Path:
    path = directory / name
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    return path


def profile(rows_by_file: dict[str, list[dict]], top: int = 15) -> dict:
    """임시 디렉터리에 transcript를 쓰고 프로파일 절을 만들어 돌려준다."""
    with tempfile.TemporaryDirectory() as raw:
        directory = Path(raw)
        for name, rows in rows_by_file.items():
            write_transcript(directory, name, rows)
        summary = audit.scan([str(directory)])
        return audit.build_tool_result_bytes(summary, top)


def rows_for(label: str, byte_count: int) -> list[dict]:
    return [
        assistant_row(tool_use("u1", "Bash", command="echo hi")),
        user_row(tool_result("u1", label * byte_count)),
    ]


class ToolResultBytesProfileTests(unittest.TestCase):
    def test_reports_unavailable_without_tool_results(self) -> None:
        report = profile({"a.jsonl": [{"type": "user", "message": {"content": []}}]})
        self.assertEqual(report["status"], "unavailable")
        self.assertEqual(report["results"], 0)
        self.assertIn("reason", report)
        self.assertIn("not a savings claim", report["claim_boundary"])

    def test_attributes_bytes_to_the_tool_that_produced_them(self) -> None:
        report = profile(
            {
                "a.jsonl": [
                    assistant_row(tool_use("u1", "Read", file_path="/secret/dir/App.swift")),
                    user_row(tool_result("u1", "s" * 400)),
                    assistant_row(tool_use("u2", "Bash", command="ls")),
                    user_row(tool_result("u2", "b" * 100)),
                ]
            }
        )
        rows = {row["label"]: row for row in report["by_tool"]}
        self.assertEqual(rows["Read"]["bytes"], 400)
        self.assertEqual(rows["Bash"]["bytes"], 100)
        self.assertEqual(report["total_bytes"], 500)
        self.assertAlmostEqual(rows["Read"]["byte_share"], 0.8)

    def test_never_emits_transcript_paths_only_extensions(self) -> None:
        report = profile(
            {
                "a.jsonl": [
                    assistant_row(
                        tool_use("u1", "Read", file_path="/Users/someone/private/Secret.swift")
                    ),
                    user_row(tool_result("u1", "x" * 50)),
                ]
            }
        )
        serialized = json.dumps(report, ensure_ascii=False)
        self.assertNotIn("private", serialized)
        self.assertNotIn("Secret", serialized)
        self.assertNotIn("someone", serialized)
        extensions = {row["label"] for row in report["by_file_extension"]}
        self.assertEqual(extensions, {"swift"})

    def test_classifies_image_reads_apart_from_text(self) -> None:
        report = profile(
            {
                "a.jsonl": [
                    assistant_row(tool_use("u1", "Read", file_path="/tmp/shot.png")),
                    user_row(tool_result("u1", "p" * 900)),
                    assistant_row(tool_use("u2", "Read", file_path="/tmp/main.py")),
                    user_row(tool_result("u2", "t" * 100)),
                ]
            }
        )
        classes = {row["label"]: row["bytes"] for row in report["by_content_class"]}
        self.assertEqual(classes["image"], 900)
        self.assertEqual(classes["text"], 100)

    def test_image_payload_blocks_count_as_image_without_an_extension(self) -> None:
        block_content = [
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "Q" * 300}}
        ]
        report = profile(
            {
                "a.jsonl": [
                    assistant_row(tool_use("u1", "take_screenshot")),
                    user_row(tool_result("u1", block_content)),
                ]
            }
        )
        classes = {row["label"]: row["bytes"] for row in report["by_content_class"]}
        self.assertEqual(classes.get("image"), 300)
        self.assertNotIn("unknown", classes)

    def test_extensionless_text_results_are_text_not_unknown(self) -> None:
        report = profile({"a.jsonl": rows_for("z", 300)})
        classes = {row["label"] for row in report["by_content_class"]}
        self.assertEqual(classes, {"text"})

    def test_separates_bounded_from_unbounded_file_reads(self) -> None:
        report = profile(
            {
                "a.jsonl": [
                    assistant_row(tool_use("u1", "Read", file_path="/tmp/a.py", offset=1, limit=20)),
                    user_row(tool_result("u1", "a" * 100)),
                    assistant_row(tool_use("u2", "Read", file_path="/tmp/b.py")),
                    user_row(tool_result("u2", "b" * 900)),
                ]
            }
        )
        bounding = report["file_read_bounding"]
        self.assertEqual(bounding["bounded_results"], 1)
        self.assertEqual(bounding["bounded_bytes"], 100)
        self.assertEqual(bounding["unbounded_results"], 1)
        self.assertEqual(bounding["unbounded_bytes"], 900)
        self.assertAlmostEqual(bounding["unbounded_byte_share"], 0.9)

    def test_counts_byte_identical_repeats_as_duplicates(self) -> None:
        payload = "same-output"
        report = profile(
            {
                "a.jsonl": [
                    assistant_row(tool_use("u1", "Bash", command="ls")),
                    user_row(tool_result("u1", payload)),
                    assistant_row(tool_use("u2", "Bash", command="ls")),
                    user_row(tool_result("u2", payload)),
                    assistant_row(tool_use("u3", "Bash", command="ls")),
                    user_row(tool_result("u3", payload)),
                ]
            }
        )
        duplicates = report["exact_duplicates"]
        self.assertEqual(duplicates["results"], 2)
        self.assertEqual(duplicates["bytes"], len(payload) * 2)

    def test_duplicate_and_correlation_state_do_not_cross_sessions(self) -> None:
        payload = "identical"
        rows = [
            assistant_row(tool_use("shared-id", "Read", file_path="/tmp/a.py")),
            user_row(tool_result("shared-id", payload)),
        ]
        report = profile({"a.jsonl": list(rows), "b.jsonl": list(rows)})
        # 같은 내용이 서로 다른 세션에 한 번씩 있으면 세션 내 중복이 아니다.
        self.assertEqual(report["exact_duplicates"]["results"], 0)
        # 상관은 세션마다 새로 이루어지므로 둘 다 귀속되어야 한다.
        self.assertEqual(report["attribution"]["uncorrelated_results"], 0)
        rows_by_tool = {row["label"]: row for row in report["by_tool"]}
        self.assertEqual(rows_by_tool["Read"]["results"], 2)

    def test_result_without_a_matching_use_is_reported_as_unattributed(self) -> None:
        report = profile({"a.jsonl": [user_row(tool_result("missing", "x" * 60))]})
        labels = {row["label"] for row in report["by_tool"]}
        self.assertEqual(labels, {"unattributed"})
        self.assertEqual(report["attribution"]["uncorrelated_results"], 1)
        self.assertEqual(report["attribution"]["correlated_results"], 0)

    def test_concentration_reports_the_share_carried_by_large_results(self) -> None:
        big = audit.TOOL_RESULT_LARGE_BYTES + 10
        rows: list[dict] = []
        for index in range(9):
            rows.append(assistant_row(tool_use(f"s{index}", "Bash", command="ls")))
            rows.append(user_row(tool_result(f"s{index}", "s" * 10)))
        rows.append(assistant_row(tool_use("big", "Bash", command="ls")))
        rows.append(user_row(tool_result("big", "b" * big)))
        report = profile({"a.jsonl": rows})
        concentration = report["concentration"]
        self.assertEqual(concentration["large_results"], 1)
        self.assertAlmostEqual(concentration["large_result_share"], 0.1)
        self.assertGreater(concentration["large_byte_share"], 0.99)

    def test_percentiles_are_ordered_and_bounded_by_max(self) -> None:
        rows: list[dict] = []
        for index in range(50):
            rows.append(assistant_row(tool_use(f"u{index}", "Bash", command="ls")))
            rows.append(user_row(tool_result(f"u{index}", "x" * (index + 1) * 10)))
        report = profile({"a.jsonl": rows})
        percentiles = report["size_percentiles_bytes"]
        self.assertLessEqual(percentiles["p50"], percentiles["p90"])
        self.assertLessEqual(percentiles["p90"], percentiles["p99"])
        self.assertLessEqual(percentiles["p99"], percentiles["max"])
        self.assertEqual(percentiles["max"], 500)

    def test_measures_text_blocks_and_base64_payloads_by_utf8_length(self) -> None:
        self.assertEqual(audit._tool_result_byte_length("abc"), 3)
        self.assertEqual(audit._tool_result_byte_length("한글"), 6)
        self.assertEqual(
            audit._tool_result_byte_length([{"type": "text", "text": "abcd"}]), 4
        )
        self.assertEqual(
            audit._tool_result_byte_length(
                [{"type": "image", "source": {"type": "base64", "data": "AAAA"}}]
            ),
            4,
        )
        self.assertIsNone(audit._tool_result_byte_length(None))

    def test_pending_tool_use_map_is_bounded(self) -> None:
        accumulator = audit.ToolResultBytesAudit()
        accumulator.start_file(Path("a.jsonl"))
        overflow = audit.TOOL_RESULT_MAX_PENDING_USES + 50
        for index in range(overflow):
            accumulator.observe(assistant_row(tool_use(f"u{index}", "Bash", command="ls")))
        self.assertLessEqual(
            len(accumulator._pending_uses), audit.TOOL_RESULT_MAX_PENDING_USES
        )

    def test_duplicate_hash_set_is_bounded_and_flags_truncation(self) -> None:
        accumulator = audit.ToolResultBytesAudit()
        accumulator.start_file(Path("a.jsonl"))
        overflow = audit.TOOL_RESULT_MAX_DUP_HASHES + 5
        for index in range(overflow):
            accumulator.observe(user_row(tool_result(f"u{index}", f"payload-{index}")))
        self.assertLessEqual(
            len(accumulator._seen_hashes), audit.TOOL_RESULT_MAX_DUP_HASHES
        )
        self.assertTrue(accumulator.duplicate_tracking_truncated)

    def test_unserializable_content_does_not_abort_the_scan(self) -> None:
        recursive: list[object] = []
        recursive.append(recursive)
        accumulator = audit.ToolResultBytesAudit()
        accumulator.start_file(Path("a.jsonl"))
        accumulator.observe(user_row(tool_result("u1", {"weird": recursive})))
        self.assertEqual(accumulator.results, 1)
        self.assertGreater(accumulator.total_bytes, 0)

    def test_section_is_present_in_both_json_surfaces(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            write_transcript(directory, "a.jsonl", rows_for("q", 40))
            for flag in ("--json", "--feasibility-json"):
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(KIT / "claude_transcript_cost_audit.py"),
                        str(directory),
                        flag,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                    env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                payload = json.loads(completed.stdout)
                self.assertIn("tool_result_bytes", payload, flag)
                self.assertEqual(
                    payload["tool_result_bytes"]["schema_version"],
                    audit.TOOL_RESULT_BYTES_SCHEMA_VERSION,
                )

    def test_text_output_states_the_claim_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            write_transcript(directory, "a.jsonl", rows_for("q", 40))
            completed = subprocess.run(
                [
                    sys.executable,
                    str(KIT / "claude_transcript_cost_audit.py"),
                    str(directory),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("Context bytes carried by tool results", completed.stdout)
            self.assertIn("not a savings claim", completed.stdout)


if __name__ == "__main__":
    unittest.main()
