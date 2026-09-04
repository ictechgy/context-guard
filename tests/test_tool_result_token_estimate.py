"""`context-guard-audit`의 토큰 단위 회계에 대한 계약 테스트.

바이트 점유는 이미지에 대해 비용 신호가 아니다. 제공자는 이미지를 장변 상한으로
줄인 뒤 면적 기준으로 과금하므로 장당 토큰에 상한이 있고, 텍스트는 상한 없이
바이트에 비례한다. 그래서 같은 코퍼스가 바이트로는 이미지 우위로, 토큰으로는
텍스트 우위로 읽힌다. 이 절은 두 단위를 함께 보고해 그 오독을 막는다.

여기서 고정하는 성질:

1. 이미지 토큰은 파싱한 픽셀 크기에서 나오며, 장변 상한 위에서는 페이로드가
   커져도 토큰이 늘지 않는다 (상한의 존재).
2. 크기를 못 읽은 이미지는 추정에서 조용히 빠지지 않고 별도로 센다.
3. 헤더 파싱은 상한 안에서만 디코드하며, 잘린/깨진 페이로드는 None이다.
4. 텍스트와 이미지의 추정 방법이 서로 다르므로 각 행이 자기 method를 밝힌다.
5. 추정은 관측이 아니다 - claim_boundary가 항상 붙고 절감 주장을 하지 않는다.
6. 같은 세션에서 같은 내용을 다시 읽으면 재읽기로 잡힌다.
7. 턴당 신규 바이트(cache_creation)는 합계가 아니라 분포로 보고된다.
"""
from __future__ import annotations

import base64
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
KIT = REPO_ROOT / "context-guard-kit"
sys.path.insert(0, str(KIT))

import claude_transcript_cost_audit as audit  # noqa: E402


def png_bytes(width: int, height: int, *, trailing: int = 0) -> bytes:
    """IHDR까지만 유효한 최소 PNG. 크기 파싱은 헤더만 보므로 이걸로 충분하다."""
    header = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">I", 13) + b"IHDR" + struct.pack(">II", width, height)
    ihdr += bytes([8, 6, 0, 0, 0]) + b"\x00\x00\x00\x00"
    return header + ihdr + b"\x00" * trailing


def jpeg_bytes(width: int, height: int, *, pad_before_sof: int = 0) -> bytes:
    """SOF0에 크기를 담은 최소 JPEG. pad_before_sof로 SOF를 뒤로 밀 수 있다."""
    out = b"\xff\xd8"
    if pad_before_sof:
        # APP0 세그먼트 하나로 채운다: 마커 + 길이 + 본문.
        body = b"\x00" * pad_before_sof
        out += b"\xff\xe0" + struct.pack(">H", len(body) + 2) + body
    sof_body = bytes([8]) + struct.pack(">HH", height, width) + bytes([3]) + b"\x00" * 9
    out += b"\xff\xc0" + struct.pack(">H", len(sof_body) + 2) + sof_body
    return out


def image_block(raw: bytes, media_type: str) -> dict:
    return {
        "type": "image",
        "source": {
            "type": "base64",
            "media_type": media_type,
            "data": base64.b64encode(raw).decode("ascii"),
        },
    }


def user_row(*blocks: dict) -> dict:
    return {"type": "user", "message": {"role": "user", "content": list(blocks)}}


def assistant_row(*blocks: dict) -> dict:
    return {"type": "assistant", "message": {"role": "assistant", "content": list(blocks)}}


def tool_use(use_id: str, name: str, **payload: object) -> dict:
    return {"type": "tool_use", "id": use_id, "name": name, "input": dict(payload)}


def tool_result(use_id: str, content: object) -> dict:
    return {"type": "tool_result", "tool_use_id": use_id, "content": content}


def usage_row(cache_creation: int, ordinal: int = 0) -> dict:
    """usage 필드를 담은 어시스턴트 레코드.

    ordinal로 행을 서로 다르게 만든다. usage reducer는 id 없는 완전 동일 행을 중복으로
    접으므로, 값이 같은 턴 두 개를 세려면 다른 필드에서 구분되어야 한다.
    """
    return {
        "type": "assistant",
        "message": {
            "role": "assistant",
            "id": f"msg_{ordinal}",
            "model": "claude-test",
            "usage": {
                "input_tokens": 10,
                "output_tokens": 5,
                "cache_creation_input_tokens": cache_creation,
                "cache_read_input_tokens": 0,
            },
        },
    }


def profile(rows: list[dict]) -> dict:
    """감사를 돌려 tool_result_bytes 절을 돌려준다."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        with (root / "session.jsonl").open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        summary = audit.scan([str(root)])
        return audit.build_tool_result_bytes(summary, 15)


def full_report(rows: list[dict]) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        with (root / "session.jsonl").open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        return audit.summary_json(audit.scan([str(root)]), 15)


class ImageDimensionParsing(unittest.TestCase):
    def test_png_dimensions_come_from_the_ihdr_header(self) -> None:
        self.assertEqual(
            audit.image_pixel_dimensions("image/png", base64.b64encode(png_bytes(800, 600)).decode()),
            (800, 600),
        )

    def test_jpeg_dimensions_come_from_the_sof_segment(self) -> None:
        self.assertEqual(
            audit.image_pixel_dimensions("image/jpeg", base64.b64encode(jpeg_bytes(1024, 768)).decode()),
            (1024, 768),
        )

    def test_jpeg_sof_is_found_after_an_earlier_segment(self) -> None:
        raw = jpeg_bytes(320, 240, pad_before_sof=512)
        self.assertEqual(
            audit.image_pixel_dimensions("image/jpeg", base64.b64encode(raw).decode()),
            (320, 240),
        )

    def test_truncated_payload_yields_no_dimensions(self) -> None:
        raw = png_bytes(800, 600)[:12]
        self.assertIsNone(
            audit.image_pixel_dimensions("image/png", base64.b64encode(raw).decode())
        )

    def test_non_base64_payload_yields_no_dimensions(self) -> None:
        self.assertIsNone(audit.image_pixel_dimensions("image/png", "not base64 !!!"))

    def test_unsupported_media_type_yields_no_dimensions(self) -> None:
        raw = base64.b64encode(png_bytes(800, 600)).decode()
        self.assertIsNone(audit.image_pixel_dimensions("image/gif", raw))

    def test_only_a_bounded_prefix_is_decoded(self) -> None:
        """SOF가 상한 밖에 있으면 크기를 못 읽는다. 상한이 실재한다는 증거다."""
        raw = jpeg_bytes(640, 480, pad_before_sof=audit.IMAGE_HEADER_MAX_BYTES + 4096)
        self.assertIsNone(
            audit.image_pixel_dimensions("image/jpeg", base64.b64encode(raw).decode())
        )


class ImageTokenEstimate(unittest.TestCase):
    def test_small_image_is_area_over_the_divisor(self) -> None:
        # 1000x1000 은 장변 상한 아래라 축소가 없다. ceil(1_000_000/750) = 1334.
        self.assertEqual(audit.image_token_estimate(1000, 1000), 1334)

    def test_long_edge_over_the_cap_is_scaled_down_first(self) -> None:
        # 3136x1960 -> 1568x980. ceil(1_536_640/750) = 2049.
        self.assertEqual(audit.image_token_estimate(3136, 1960), 2049)

    def test_tokens_stop_growing_above_the_cap(self) -> None:
        """상한의 존재 - 페이로드 픽셀을 4배로 늘려도 토큰은 그대로다."""
        self.assertEqual(
            audit.image_token_estimate(3136, 1960),
            audit.image_token_estimate(6272, 3920),
        )

    def test_square_at_the_cap_is_the_ceiling(self) -> None:
        self.assertEqual(audit.image_token_estimate(1568, 1568), 3279)
        self.assertEqual(
            audit.image_token_estimate(10_000, 10_000),
            audit.image_token_estimate(1568, 1568),
        )

    def test_degenerate_dimensions_are_rejected(self) -> None:
        for width, height in ((0, 10), (10, 0), (-1, 10)):
            with self.subTest(width=width, height=height):
                self.assertIsNone(audit.image_token_estimate(width, height))


class TokenEstimateSection(unittest.TestCase):
    def test_image_tokens_are_reported_next_to_image_bytes(self) -> None:
        rows = [
            assistant_row(tool_use("u1", "Bash")),
            user_row(tool_result("u1", [image_block(png_bytes(1000, 1000), "image/png")])),
        ]
        section = profile(rows)["token_estimate"]
        images = section["images"]
        self.assertEqual(images["payloads"], 1)
        self.assertEqual(images["dimensions_parsed"], 1)
        self.assertEqual(images["dimensions_unavailable"], 0)
        self.assertEqual(images["tokens"], 1334)

    def test_image_without_parsable_dimensions_is_counted_not_dropped(self) -> None:
        rows = [
            assistant_row(tool_use("u1", "Bash")),
            user_row(tool_result("u1", [{"type": "image", "file": "screenshot"}])),
        ]
        images = profile(rows)["token_estimate"]["images"]
        self.assertEqual(images["payloads"], 1)
        self.assertEqual(images["dimensions_parsed"], 0)
        self.assertEqual(images["dimensions_unavailable"], 1)

    def test_downscaled_images_are_counted(self) -> None:
        rows = [
            assistant_row(tool_use("u1", "Bash")),
            user_row(tool_result("u1", [image_block(png_bytes(3136, 1960), "image/png")])),
        ]
        images = profile(rows)["token_estimate"]["images"]
        self.assertEqual(images["downscaled_to_cap"], 1)

    def test_each_class_row_states_its_own_method(self) -> None:
        rows = [
            assistant_row(tool_use("u1", "Bash")),
            user_row(tool_result("u1", "plain text result")),
            assistant_row(tool_use("u2", "Bash")),
            user_row(tool_result("u2", [image_block(png_bytes(800, 600), "image/png")])),
        ]
        rows_by_class = {
            row["label"]: row for row in profile(rows)["token_estimate"]["by_content_class"]
        }
        self.assertEqual(rows_by_class["text"]["method"], "bytes_div_4")
        self.assertEqual(rows_by_class["image"]["method"], "image_formula")

    def test_byte_share_and_token_share_disagree_for_images(self) -> None:
        """이 절이 존재하는 이유. 큰 이미지 하나가 바이트는 지배하고 토큰은 아니다."""
        rows = [
            assistant_row(tool_use("u1", "Bash")),
            user_row(tool_result("u1", [image_block(png_bytes(1600, 1000, trailing=400_000), "image/png")])),
            assistant_row(tool_use("u2", "Bash")),
            user_row(tool_result("u2", "x" * 40_000)),
        ]
        report = profile(rows)
        byte_share = {row["label"]: row["byte_share"] for row in report["by_content_class"]}
        token_share = {
            row["label"]: row["token_share"] for row in report["token_estimate"]["by_content_class"]
        }
        self.assertGreater(byte_share["image"], byte_share["text"])
        self.assertLess(token_share["image"], token_share["text"])

    def test_formula_is_stamped_with_a_version(self) -> None:
        section = profile([])["token_estimate"]
        formula = section["image_formula"]
        self.assertEqual(formula["long_edge_cap_px"], 1568)
        self.assertEqual(formula["area_divisor"], 750)
        self.assertTrue(formula["id"])

    def test_estimate_never_claims_savings(self) -> None:
        boundary = profile([])["token_estimate"]["claim_boundary"]
        self.assertFalse(boundary["provider_measured"])
        self.assertFalse(boundary["token_or_cost_savings_claim_allowed"])


class RepeatReads(unittest.TestCase):
    def test_reading_the_same_content_twice_counts_as_a_repeat(self) -> None:
        body = "line\n" * 200
        rows = [
            assistant_row(tool_use("u1", "Read", file_path="a.py")),
            user_row(tool_result("u1", body)),
            assistant_row(tool_use("u2", "Read", file_path="a.py")),
            user_row(tool_result("u2", body)),
        ]
        repeats = profile(rows)["repeat_reads"]
        self.assertEqual(repeats["results"], 1)
        self.assertEqual(repeats["bytes"], len(body.encode("utf-8")))

    def test_distinct_reads_are_not_repeats(self) -> None:
        rows = [
            assistant_row(tool_use("u1", "Read", file_path="a.py")),
            user_row(tool_result("u1", "alpha")),
            assistant_row(tool_use("u2", "Read", file_path="b.py")),
            user_row(tool_result("u2", "beta")),
        ]
        self.assertEqual(profile(rows)["repeat_reads"]["results"], 0)

    def test_a_repeated_non_read_tool_is_not_a_repeat_read(self) -> None:
        rows = [
            assistant_row(tool_use("u1", "Bash")),
            user_row(tool_result("u1", "same")),
            assistant_row(tool_use("u2", "Bash")),
            user_row(tool_result("u2", "same")),
        ]
        self.assertEqual(profile(rows)["repeat_reads"]["results"], 0)

    def test_repeats_do_not_cross_a_session_boundary(self) -> None:
        body = "shared\n" * 50
        rows_a = [
            assistant_row(tool_use("u1", "Read", file_path="a.py")),
            user_row(tool_result("u1", body)),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("one.jsonl", "two.jsonl"):
                with (root / name).open("w", encoding="utf-8") as handle:
                    for row in rows_a:
                        handle.write(json.dumps(row) + "\n")
            section = audit.build_tool_result_bytes(audit.scan([str(root)]), 15)
        self.assertEqual(section["repeat_reads"]["results"], 0)


class NewBytesPerTurn(unittest.TestCase):
    def test_cache_creation_is_reported_as_a_distribution(self) -> None:
        rows = [usage_row(n, i) for i, n in enumerate((100, 200, 300, 400))]
        section = full_report(rows)["new_tokens_per_turn"]
        self.assertEqual(section["turns"], 4)
        self.assertEqual(section["total_cache_creation_tokens"], 1000)
        self.assertEqual(section["percentiles"]["p50"], 300)
        self.assertEqual(section["max"], 400)

    def test_turns_without_cache_creation_are_excluded_from_the_distribution(self) -> None:
        rows = [usage_row(0, 1), usage_row(0, 2), usage_row(500, 3)]
        section = full_report(rows)["new_tokens_per_turn"]
        self.assertEqual(section["turns"], 1)
        self.assertEqual(section["zero_cache_creation_turns"], 2)

    def test_section_states_that_new_tokens_are_the_billable_quantity(self) -> None:
        boundary = full_report([usage_row(10, 1)])["new_tokens_per_turn"]["claim_boundary"]
        self.assertFalse(boundary["token_or_cost_savings_claim_allowed"])


if __name__ == "__main__":
    unittest.main()
