#!/usr/bin/env python3
"""Best-effort Claude Code transcript usage auditor.

Claude Code transcript schemas may change. Token totals use the deterministic
``row.message.usage`` contract; other bounded usage-like shapes mark results
partial instead of being silently counted. Cost and diagnostic metadata retain
their bounded schema-tolerant scans. Parse/read skips are reported so totals are
not mistaken for billing-authoritative data.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import datetime as _dt
import errno
import hashlib
import json
import math
import os
import re
import shlex
import stat
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Iterator

_SCRIPT_DIR = Path(__file__).resolve().parent
_REDUCER_DIR = _SCRIPT_DIR
if not (_REDUCER_DIR / "transcript_usage_reducer.py").is_file():
    _REDUCER_DIR = _SCRIPT_DIR.parent / "lib"
if str(_REDUCER_DIR) not in sys.path:
    sys.path.insert(0, str(_REDUCER_DIR))

from transcript_usage_reducer import (  # noqa: E402
    REDUCER_SCHEMA,
    UsageReducer,
    hash_file_identity,
)

TOKEN_KEY_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("input", ("input_tokens",)),
    ("output", ("output_tokens",)),
    ("cache_creation", ("cache_creation_input_tokens", "cacheCreation")),
    ("cache_read", ("cache_read_input_tokens", "cacheRead")),
)
KNOWN_TOKEN_BUCKETS = {bucket for bucket, _ in TOKEN_KEY_GROUPS}
TOKEN_TYPE_ALIASES = {
    "input": "input",
    "input_tokens": "input",
    "output": "output",
    "output_tokens": "output",
    "cacheRead": "cache_read",
    "cache_read": "cache_read",
    "cache_read_input_tokens": "cache_read",
    "cacheCreation": "cache_creation",
    "cache_creation": "cache_creation",
    "cache_creation_input_tokens": "cache_creation",
}
COST_KEYS = ("total_cost_usd", "cost_usd", "costUSD")
MODEL_KEYS = ("model", "model_id", "modelId")
QUERY_SOURCE_KEYS = ("query_source", "querySource")
TIMESTAMP_KEYS = ("timestamp", "created_at", "createdAt", "time", "ts")
FEASIBILITY_SCHEMA_VERSION = "contextguard.metric-feasibility.v1.3"
MAC_VISIBILITY_SCHEMA_VERSION = "contextguard.mac-visibility.v1"
FEASIBILITY_PRODUCER = "context-guard-audit"
CACHE_DIAGNOSTICS_SCHEMA_VERSION = "contextguard.cache-diagnostics.v1"
CACHE_LAYOUT_ADVICE_SCHEMA_VERSION = "contextguard.cache-layout-advice.v1"
MAX_ERROR_EXAMPLES = 20
JSON_PARSE_RECURSION_LIMIT = 10_000
READ_CHUNK_BYTES = 64 * 1024
DEFAULT_MAX_FILE_BYTES = 50 * 1024 * 1024
DEFAULT_MAX_LINE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_SCAN_FILES = 100_000
MAX_FILE_BYTES_LIMIT = 2 * 1024 * 1024 * 1024
MAX_LINE_BYTES_LIMIT = 128 * 1024 * 1024
MAX_SCAN_FILES_LIMIT = 1_000_000
SECRET_VALUE_RE = re.compile(
    r"(?i)(gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"xox[abprs]-[A-Za-z0-9-]{8,}|(?:AKIA|ASIA)[0-9A-Z]{8,}|"
    r"AIza[0-9A-Za-z_\-]{8,}|Bearer\s+[A-Za-z0-9._~+/=-]+|"
    r"Basic\s+[A-Za-z0-9._~+/=-]+|"
    r"sk-ant-[A-Za-z0-9_-]{12,}|sk-[A-Za-z0-9_-]{12,}|glpat-[A-Za-z0-9_-]{12,}|"
    r"npm_[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|"
    r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@|"
    r"(?:--password|-p)\s+\S+|(?:-u|--user)\s+\S+:\S+|"
    r"(api[_-]?key|token|secret|password)=\S+)"
)
REDACTED_PATH_COMPONENT = "[REDACTED-PATH-COMPONENT]"
COMMAND_KEYS = ("command", "cmd")
TOOL_NAME_KEYS = ("tool_name", "toolName", "tool")
PROMPT_AUDIT_MAX_RECORDS = 200
PROMPT_AUDIT_MAX_TEXT_BYTES = 32 * 1024
PROMPT_AUDIT_MAX_SEGMENTS_PER_RECORD = 32
PROMPT_AUDIT_PREFIX_SEGMENTS = 3
PROMPT_AUDIT_TAIL_SEGMENTS = 3
PROMPT_AUDIT_MIN_RECORDS = 3
PROMPT_PREFIX_VOLATILE_THRESHOLD = 0.66
PROMPT_PREFIX_TAIL_CHURN_DELTA = 0.34
PROMPT_AUDIT_MAX_FINDINGS = 5
PROMPT_SEGMENT_HASH_CHARS = 16
PROMPT_AUDIT_MAX_TEXT_VALUES = 64
PROMPT_AUDIT_MAX_ROOT_NODES = 4096
PROMPT_AUDIT_MAX_CONTENT_NODES = 2048
PROMPT_AUDIT_MAX_DEPTH = 64
USER_PROMPT_ROLES = {"user", "human"}
TEXT_BLOCK_TYPES = {"text", "input_text"}

TOOL_RESULT_BYTES_SCHEMA_VERSION = "contextguard.tool-result-bytes.v1"
TOOL_RESULT_TOKEN_ESTIMATE_SCHEMA_VERSION = "contextguard.tool-result-token-estimate.v1"
NEW_TOKENS_PER_TURN_SCHEMA_VERSION = "contextguard.new-tokens-per-turn.v1"
# 이미지 토큰 공식. 제공자가 공표한 계산식이며 관측값이 아니다.
#
# 바이트 점유는 이미지에 대해 비용 신호가 아니다. 제공자는 장변을 상한으로 줄인 뒤
# 면적으로 과금하므로 장당 토큰에 상한이 있고, 텍스트는 상한 없이 바이트에 비례한다.
# 두 클래스를 바이트로만 비교하면 이미지가 실제 토큰 비용의 여러 배로 보인다.
#
# 식별자에 버전을 박는다. 공식이 바뀌면 새 id를 쓰고 옛 리포트는 자기가 어떤 식으로
# 계산됐는지 계속 밝힐 수 있어야 한다. 만료 날짜는 두지 않는다 - 날짜로 만료하는
# 제공자 상수는 코드 변경 없이 빌드를 깨뜨린 전례가 있다.
IMAGE_TOKEN_FORMULA_ID = "anthropic.image-tokens.area-div-750.v1"
IMAGE_LONG_EDGE_CAP_PX = 1568
IMAGE_TOKEN_AREA_DIVISOR = 750
# 크기를 읽기 위해 디코드하는 최대 바이트. PNG는 헤더 24바이트면 충분하고 JPEG는
# SOF 세그먼트까지 훑어야 하므로 상한을 둔다. 상한 밖의 SOF는 못 읽은 것으로 센다.
IMAGE_HEADER_MAX_BYTES = 32_768
# 텍스트 토큰 추정 제수. 이미지 쪽 공식과 달리 이건 거친 대리값이다.
TEXT_TOKEN_PROXY_DIVISOR = 4
# 턴당 cache_creation 표본의 상한. 정수만 담으므로 내용은 남지 않는다.
NEW_TOKENS_MAX_SAMPLES = 200_000
NEW_TOKENS_BY_PRECEDING_TOOL_SCHEMA_VERSION = "contextguard.new-tokens-by-preceding-tool.v1"
TOKEN_CALIBRATION_SCHEMA_VERSION = "contextguard.token-calibration.v1"
GUARD_COVERAGE_SCHEMA_VERSION = "contextguard.guard-coverage.v1"
# 보정 표본: 직전 tool_result 의 텍스트 바이트가 이 값 이상인 턴만 쓴다. 작은 결과에서는
# 같은 턴에 들어온 어시스턴트 출력·사용자 입력이 cache_creation 을 지배해 비율이 무의미하다.
TOKEN_CALIBRATION_MIN_RESULT_BYTES = 4_000
TOKEN_CALIBRATION_MIN_SAMPLES = 30
TOKEN_CALIBRATION_MAX_SAMPLES = 50_000
TOKEN_PROXY_CHOICES = ("bytes_div_4", "calibrated")
# 큰 결과의 기준. 이 값 이상만 상위 목록과 집중도 분모에 쓴다.
TOOL_RESULT_LARGE_BYTES = 20_000
# 백분위 계산을 위해 보관하는 크기 표본의 상한. 크기(int)만 담으므로 내용은 남지 않는다.
TOOL_RESULT_MAX_SIZE_SAMPLES = 200_000
# 세션 하나에서 tool_use_id -> 도구 정보를 들고 있을 상한. 파일이 바뀌면 비운다.
TOOL_RESULT_MAX_PENDING_USES = 20_000
# 세션 하나에서 완전 중복 판정을 위해 유지하는 해시 상한.
TOOL_RESULT_MAX_DUP_HASHES = 100_000
# 확장자 라벨은 알려진 목록에 있는 것만 내보낸다.
#
# 모양 검사로는 "경로가 새지 않는다" 를 보장할 수 없다. 어떤 정규식을 쓰든
# `notes.clientAcme` 의 `clientAcme` 처럼 확장자 모양을 한 파일명 조각이 통과한다.
# 목록에 없는 접미사는 (not-an-extension) 으로 접는다. 흔치 않지만 실재하는
# 확장자가 함께 접히는 손실을 감수한다 - 바이트 총합과 도구별 귀속은 그대로이고
# 확장자 차원만 뭉개지는 반면, 통과시키면 고객명이 리포트로 나갈 수 있다.
KNOWN_FILE_EXTENSIONS = frozenset(
    {
        # 프로그래밍 언어
        "c", "cc", "cjs", "clj", "cljs", "cpp", "cs", "cxx", "dart", "el", "erl",
        "ex", "exs", "fs", "go", "groovy", "h", "hpp", "hs", "hxx", "java", "jl",
        "js", "jsx", "kt", "kts", "lua", "m", "mjs", "ml", "mm", "php", "pl", "pm",
        "py", "pyi", "pyx", "r", "rb", "rs", "sc", "scala", "sh", "swift", "tcl",
        "ts", "tsx", "v", "vb", "vue", "zig", "zsh", "bash", "fish", "ps1", "svelte",
        # 마크업/문서
        "adoc", "csv", "htm", "html", "log", "md", "mdx", "org", "pdf", "rst",
        "tex", "text", "tsv", "txt", "xhtml",
        # 설정/데이터
        "cfg", "conf", "env", "gradle", "ini", "json", "json5", "jsonc", "lock",
        "plist", "properties", "proto", "toml", "xml", "yaml", "yml", "graphql",
        "gql", "sql", "tf", "tfvars", "xcconfig", "entitlements", "storyboard",
        "xib", "pbxproj", "resolved", "sum", "mod",
        # 스타일
        "css", "less", "sass", "scss", "styl",
        # 이미지/미디어
        "avif", "bmp", "gif", "heic", "heif", "ico", "jpeg", "jpg", "mp3", "mp4",
        "png", "svg", "tif", "tiff", "wav", "webm", "webp",
        # 그 외 자주 보이는 것
        "diff", "dockerfile", "gitignore", "ipynb", "makefile", "patch", "snap",
        "tgz", "zip", "gz", "map", "d",
    }
)
TOOL_RESULT_MAX_EXTENSIONS = 200
TOOL_RESULT_MAX_TOOL_LABELS = 500
TOOL_RESULT_OVERFLOW_LABEL = "(other)"
# 확장자 모양이 아니어서 라벨로 내보내지 않은 경우. 넘침 버킷과 구분해야 리포트를
# 읽는 쪽이 "종류가 많아 접혔다" 와 "확장자가 아니다" 를 혼동하지 않는다.
TOOL_RESULT_NON_EXTENSION_LABEL = "(not-an-extension)"
TOOL_RESULT_NO_EXTENSION_LABEL = "(none)"
# 넘침 접기에서 면제되는 라벨. 이들이 (other) 로 접히면 구분 자체가 사라진다.
TOOL_RESULT_RESERVED_LABELS = frozenset(
    {TOOL_RESULT_OVERFLOW_LABEL, TOOL_RESULT_NON_EXTENSION_LABEL, TOOL_RESULT_NO_EXTENSION_LABEL}
)
# 헤더에서 크기를 읽을 수 있는 media type만 시도한다. GIF/WebP는 파서가 없으므로
# 크기 미상으로 세고, 추측하지 않는다.
IMAGE_DIMENSION_MEDIA_TYPES = frozenset({"image/png", "image/jpeg", "image/jpg"})

IMAGE_EXTENSIONS = frozenset(
    {
        "png", "jpg", "jpeg", "gif", "webp", "bmp", "tif", "tiff",
        "ico", "heic", "heif", "avif",
    }
)
# Read 계열로 취급할 도구 이름. 파일 경로 입력을 갖는 것들만 확장자 집계 대상이다.
FILE_READ_TOOL_NAMES = frozenset({"Read", "NotebookRead"})
TOOL_RESULT_FILE_PATH_KEYS = ("file_path", "filePath", "notebook_path")
TOOL_RESULT_RANGE_KEYS = ("offset", "limit", "pages", "line_range", "range")


def push_bounded(
    stack: list[tuple[Any, int]],
    items: Iterable[Any],
    depth: int,
    *,
    visited: int,
    max_nodes: int,
) -> bool:
    """Push traversal children without letting broad structures grow unbounded."""
    budget = max(0, max_nodes - visited - len(stack))
    if budget <= 0:
        return True
    pushed = 0
    capped = False
    for item in items:
        if pushed >= budget:
            capped = True
            break
        stack.append((item, depth))
        pushed += 1
    return capped


@dataclass(frozen=True)
class PromptSegmentSample:
    prefix_hashes: tuple[str, ...]
    tail_hashes: tuple[str, ...]
    segment_count: int
    bytes_sampled: int
    redactions: int


@dataclass
class RecordUsage:
    tokens: Counter[str] = field(default_factory=Counter)
    cost_usd: float = 0.0
    commands: set[str] = field(default_factory=set)
    tools: set[str] = field(default_factory=set)


@dataclass
class PromptCacheAudit:
    sampled_records: int = 0
    analyzed_prompt_records: int = 0
    capped_records: int = 0
    prompt_collection_capped_records: int = 0
    total_segments: int = 0
    total_bytes_sampled: int = 0
    redacted_segments: int = 0
    samples: list[PromptSegmentSample] = field(default_factory=list)

    def observe(self, root: Any) -> None:
        self.sampled_records += 1
        if len(self.samples) >= PROMPT_AUDIT_MAX_RECORDS:
            self.capped_records += 1
            return
        segments, bytes_sampled, redactions, collection_capped = prompt_segments_for_record(root)
        if collection_capped:
            self.prompt_collection_capped_records += 1
        if not segments:
            return
        self.analyzed_prompt_records += 1
        self.total_segments += len(segments)
        self.total_bytes_sampled += bytes_sampled
        self.redacted_segments += redactions
        self.samples.append(PromptSegmentSample(
            prefix_hashes=tuple(stable_hash(segment, PROMPT_SEGMENT_HASH_CHARS) for segment in segments[:PROMPT_AUDIT_PREFIX_SEGMENTS]),
            tail_hashes=tuple(stable_hash(segment, PROMPT_SEGMENT_HASH_CHARS) for segment in segments[-PROMPT_AUDIT_TAIL_SEGMENTS:]),
            segment_count=len(segments),
            bytes_sampled=bytes_sampled,
            redactions=redactions,
        ))


def json_compact(value: Any) -> str:
    """바이트 길이 측정을 위한 결정적 직렬화.

    깊게 중첩되거나 직렬화 불가능한 값이 와도 예외로 스캔을 멈추지 않아야 하므로,
    실패하면 repr로 물러난다. 여기서 나온 문자열은 길이/해시 계산에만 쓰이고 출력되지 않는다.
    """
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError):
        pass
    try:
        return repr(value)
    except BaseException:
        return f"<unrepresentable {type(value).__name__}>"


def _iter_content_blocks(root: Any) -> Iterable[dict[str, Any]]:
    """레코드의 message.content 배열에서 블록 딕셔너리를 순회한다.

    transcript 스키마는 message.content 아래에 블록을 두지만, 일부 행은 content를 최상위에
    두기도 한다. 두 모양만 받고 그 밖은 무시해 walk() 전체 순회 비용을 피한다.
    """
    if not isinstance(root, dict):
        return
    message = root.get("message")
    holder = message if isinstance(message, dict) else root
    content = holder.get("content")
    if not isinstance(content, list):
        return
    for block in content:
        if isinstance(block, dict):
            yield block


def _tool_input_extension(payload: dict[str, Any]) -> str | None:
    """도구 입력의 파일 경로에서 소문자 확장자만 뽑는다. 경로 자체는 버린다."""
    for key in TOOL_RESULT_FILE_PATH_KEYS:
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        normalized = value.replace("\\", "/")
        if normalized.endswith("/"):
            return None
        base = normalized.rsplit("/", 1)[-1]
        if "." not in base or base.startswith("."):
            return TOOL_RESULT_NO_EXTENSION_LABEL
        extension = base.rsplit(".", 1)[-1].lower()
        if extension in KNOWN_FILE_EXTENSIONS:
            return extension
        return TOOL_RESULT_NON_EXTENSION_LABEL
    return None


def _tool_result_byte_length(content: Any) -> int | None:
    """tool_result 내용의 UTF-8 바이트 길이. 측정할 수 없으면 None."""
    if isinstance(content, str):
        return len(content.encode("utf-8", errors="replace"))
    if isinstance(content, list):
        total = 0
        for block in content:
            if isinstance(block, dict):
                text = block.get("text")
                if isinstance(text, str):
                    total += len(text.encode("utf-8", errors="replace"))
                    continue
                source = block.get("source")
                if isinstance(source, dict):
                    data = source.get("data")
                    if isinstance(data, str):
                        total += len(data.encode("utf-8", errors="replace"))
                        continue
            total += len(json_compact(block).encode("utf-8", errors="replace"))
        return total
    if content is None:
        return None
    return len(json_compact(content).encode("utf-8", errors="replace"))


def _tool_result_has_image_block(content: Any) -> bool:
    """내용 블록에 이미지 페이로드가 들어 있는지 확인한다."""
    if not isinstance(content, list):
        return False
    for block in content:
        if not isinstance(block, dict):
            continue
        if block.get("type") == "image":
            return True
        source = block.get("source")
        if isinstance(source, dict):
            media = source.get("media_type")
            if isinstance(media, str) and media.startswith("image/"):
                return True
    return False


def _png_dimensions(raw: bytes) -> tuple[int, int] | None:
    """PNG 시그니처 뒤 IHDR에서 폭/높이를 읽는다.

    IHDR는 규격상 첫 청크이므로 앞 24바이트만 보면 된다. 시그니처와 청크 타입을 모두
    확인해 이미지가 아닌 바이트가 우연히 크기처럼 읽히는 일을 막는다.
    """
    if len(raw) < 24 or not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    if raw[12:16] != b"IHDR":
        return None
    width, height = struct.unpack(">II", raw[16:24])
    return width, height


def _jpeg_dimensions(raw: bytes) -> tuple[int, int] | None:
    """JPEG 세그먼트를 훑어 SOF에서 폭/높이를 읽는다.

    SOF 위치는 고정이 아니라 앞선 세그먼트 개수에 따라 달라지므로 마커 체인을 따라간다.
    상한(IMAGE_HEADER_MAX_BYTES) 안에서 SOF를 못 만나면 못 읽은 것으로 처리한다. 크기를
    추측하지 않는 편이, 추측한 값으로 토큰을 세는 것보다 낫다.
    """
    if len(raw) < 4 or not raw.startswith(b"\xff\xd8"):
        return None
    offset = 2
    limit = len(raw)
    while offset + 4 <= limit:
        if raw[offset] != 0xFF:
            return None
        marker = raw[offset + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            # 길이 필드가 없는 마커.
            offset += 2
            continue
        if marker == 0xD9 or marker == 0xDA:
            # 이미지 끝 또는 스캔 시작. 이 뒤에는 SOF가 없다.
            return None
        segment_length = struct.unpack(">H", raw[offset + 2 : offset + 4])[0]
        if segment_length < 2:
            return None
        # SOF0..SOF15 중 DHT(0xC4), JPG(0xC8), DAC(0xCC)는 크기 세그먼트가 아니다.
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            if offset + 9 > limit:
                return None
            height, width = struct.unpack(">HH", raw[offset + 5 : offset + 9])
            return width, height
        offset += 2 + segment_length
    return None


def image_pixel_dimensions(media_type: str | None, data: str | None) -> tuple[int, int] | None:
    """base64 이미지 페이로드의 픽셀 크기를 헤더에서만 읽는다.

    앞부분만 디코드한다. 전체를 디코드하면 스크린샷 하나에 수백 KB를 쓰게 되고, 크기는
    어차피 헤더에만 있다. 손상되었거나 상한 밖에 헤더가 있는 페이로드는 None이며,
    호출자는 이를 "없음"이 아니라 "못 읽음"으로 따로 세야 한다.
    """
    if not isinstance(media_type, str) or not isinstance(data, str):
        return None
    if media_type not in IMAGE_DIMENSION_MEDIA_TYPES:
        return None
    # base64 4문자가 3바이트가 되므로 필요한 바이트에 맞춰 문자 수를 자른다.
    prefix = data[: ((IMAGE_HEADER_MAX_BYTES + 2) // 3) * 4]
    # 잘린 조각이 4의 배수가 아니면 디코더가 거부하므로 경계에 맞춘다.
    prefix = prefix[: len(prefix) - (len(prefix) % 4)]
    if not prefix:
        return None
    try:
        raw = base64.b64decode(prefix, validate=True)
    except (binascii.Error, ValueError):
        return None
    if media_type == "image/png":
        return _png_dimensions(raw)
    return _jpeg_dimensions(raw)


def image_token_estimate(width: int, height: int) -> int | None:
    """제공자 공식으로 이미지 하나의 토큰을 추정한다.

    장변이 상한을 넘으면 제공자가 먼저 줄이므로, 그 위로는 픽셀을 더 실어도 토큰이 늘지
    않는다. 이 상한이 "바이트 점유는 이미지 비용 신호가 아니다"의 근거다.

    정수 연산만 쓴다. 부동소수점을 쓰면 같은 입력이 기계에 따라 다른 값을 낼 수 있어
    결정성이 깨진다. 올림을 쓰는 것은 추정을 낮게 잡아 절감처럼 보이게 하지 않기 위해서다.
    """
    if not isinstance(width, int) or not isinstance(height, int):
        return None
    if width <= 0 or height <= 0:
        return None
    long_edge = max(width, height)
    if long_edge > IMAGE_LONG_EDGE_CAP_PX:
        width = max(1, width * IMAGE_LONG_EDGE_CAP_PX // long_edge)
        height = max(1, height * IMAGE_LONG_EDGE_CAP_PX // long_edge)
    area = width * height
    return -(-area // IMAGE_TOKEN_AREA_DIVISOR)


def _iter_image_payloads(content: Any) -> Iterator[tuple[str | None, str | None]]:
    """내용 블록에서 이미지 페이로드의 (media_type, base64 data)를 뽑는다.

    페이로드가 없는 이미지 참조 블록(`{"type": "image", "file": ...}`)도 (None, None)으로
    내보낸다. 이런 블록을 건너뛰면 이미지 개수가 조용히 줄어, 크기를 못 읽은 이미지가
    추정에서 사라진 것을 독자가 알 수 없게 된다.
    """
    if not isinstance(content, list):
        return
    for block in content:
        if not isinstance(block, dict):
            continue
        source = block.get("source")
        if isinstance(source, dict):
            media = source.get("media_type")
            if isinstance(media, str) and media.startswith("image/"):
                data = source.get("data")
                yield media, data if isinstance(data, str) else None
                continue
        if block.get("type") == "image":
            yield None, None


def _tool_result_content_class(extension: str | None, content: Any) -> str:
    """결과 바이트를 image/text/unknown 중 하나로 분류한다.

    내용을 우선 본다. 이미지 페이로드 블록이 있으면 image, 본문이 평문이거나 텍스트
    블록뿐이면 text 이고, 확장자는 그 둘로 판정되지 않을 때만 쓰는 보조 신호다. 확장자를
    먼저 보면 읽기에 실패해 오류 문자열이 돌아온 결과가 이미지 바이트로 잡힌다.

    이미지 바이트는 줄 단위 트리밍으로 줄일 수 없어 텍스트와 성격이 다르므로 따로 센다.
    """
    if _tool_result_has_image_block(content):
        return "image"
    if isinstance(content, str) or _tool_result_is_all_text_blocks(content):
        # 이미지 확장자여도 본문이 평문이면 읽기가 실패해 오류 문자열이 돌아온 것이다.
        # 확장자를 먼저 보면 그런 결과가 이미지 바이트로 잡혀 독자를 오도한다.
        return "text"
    if extension in IMAGE_EXTENSIONS:
        return "image"
    if extension is not None:
        return "text"
    return "unknown"


def _tool_result_is_all_text_blocks(content: Any) -> bool:
    """내용이 텍스트 블록으로만 이루어졌는지 확인한다.

    Bash처럼 파일 경로가 없는 도구의 결과에는 확장자가 없다. 그렇다고 종류를 모르는 것은
    아니므로, 텍스트 블록만 있으면 text로 분류해 unknown이 과대 집계되지 않게 한다.
    """
    if not isinstance(content, list) or not content:
        return False
    for block in content:
        if isinstance(block, str):
            continue
        if isinstance(block, dict) and block.get("type") in TEXT_BLOCK_TYPES:
            continue
        return False
    return True


def _bounded_label(label: str, seen: Counter[str], limit: int) -> str:
    """라벨 카디널리티를 상한 안에 둔다.

    도구 이름과 확장자는 transcript가 정하는 값이므로 서로 다른 값이 무한히 올 수 있다.
    상한을 넘으면 넘침 버킷으로 접어 바이트 총합은 보존하되 Counter가 무한히 자라지 않게 한다.
    """
    if label in TOOL_RESULT_RESERVED_LABELS:
        # sentinel 은 넘침 대상이 아니다. 접히면 "종류가 많아 접혔다" 와
        # "확장자가 아니다" 가 구분되지 않아, 구분한다는 약속이 깨진다.
        return label
    if label in seen or len(seen) < limit:
        return label
    return TOOL_RESULT_OVERFLOW_LABEL


def _tool_result_class_bytes(
    extension: str | None, content: Any, total_size: int
) -> dict[str, int]:
    """결과 하나의 바이트를 내용 종류별로 나눈다.

    결과 전체를 한 클래스로 몰면, 스크린샷에 캡션이나 오류 텍스트가 함께 실릴 때 그
    텍스트까지 image 로 잡힌다. image 비중은 "이 바이트는 줄 단위 트리밍으로 줄일 수
    없다" 는 판단의 근거이므로, 부풀면 곧바로 잘못된 결론으로 이어진다.

    블록 목록이면 블록마다 재고, 합이 total_size 와 어긋나면 마지막 클래스에 차이를
    몰아 총합을 보존한다. 블록 목록이 아니면 기존처럼 결과 전체를 한 클래스로 센다.
    """
    if not isinstance(content, list) or not content:
        return {_tool_result_content_class(extension, content): total_size}

    per_class: dict[str, int] = {}
    measured = 0
    for raw_block in content:
        block_size = _tool_result_byte_length([raw_block]) or 0
        measured += block_size
        if isinstance(raw_block, dict) and _tool_result_has_image_block([raw_block]):
            block_class = "image"
        elif isinstance(raw_block, str) or (
            isinstance(raw_block, dict) and raw_block.get("type") in TEXT_BLOCK_TYPES
        ):
            block_class = "text"
        else:
            block_class = _tool_result_content_class(extension, [raw_block])
        per_class[block_class] = per_class.get(block_class, 0) + block_size
    if not per_class:
        return {_tool_result_content_class(extension, content): total_size}
    if measured != total_size:
        # 블록 합과 결과 크기가 어긋나도 총합은 보존해야 by_content_class 가
        # total_bytes 와 맞는다.
        last = next(reversed(per_class))
        per_class[last] += total_size - measured
    return per_class


def _tool_result_digest(content: Any) -> str | None:
    """완전 중복 판정을 위한 SHA-256. 내용은 저장하지 않고 해시만 남긴다."""
    if isinstance(content, str):
        raw = content.encode("utf-8", errors="replace")
    elif content is None:
        return None
    else:
        raw = json_compact(content).encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()


@dataclass
class ToolResultBytesAudit:
    """tool_result가 컨텍스트로 실어 나른 바이트를 도구/내용종류별로 집계한다.

    토큰 사용량 필드(usage)는 요청 전체의 합계만 알려주므로, 그 바이트가 어느 도구에서
    왔는지는 알 수 없다. 이 집계는 transcript의 tool_use/tool_result 블록을 직접 세어
    "어디로 바이트가 갔는가"를 답한다. 절감 주장을 하지 않고 관측된 분포만 보고한다.

    내용은 보관하지 않는다. 크기(int)와 SHA-256 해시만 들고 있으며, 파일 경로는 확장자로만
    환원한다. 중복 판정과 tool_use 상관은 세션(파일) 단위로 범위를 제한한다.
    """

    results: int = 0
    total_bytes: int = 0
    sizes: list[int] = field(default_factory=list)
    size_samples_truncated: bool = False
    by_tool_results: Counter[str] = field(default_factory=Counter)
    by_tool_bytes: Counter[str] = field(default_factory=Counter)
    by_extension_results: Counter[str] = field(default_factory=Counter)
    by_extension_bytes: Counter[str] = field(default_factory=Counter)
    by_class_results: Counter[str] = field(default_factory=Counter)
    by_class_bytes: Counter[str] = field(default_factory=Counter)
    duplicate_results: int = 0
    duplicate_bytes: int = 0
    duplicate_tracking_truncated: bool = False
    unbounded_read_results: int = 0
    unbounded_read_bytes: int = 0
    bounded_read_results: int = 0
    bounded_read_bytes: int = 0
    correlated_results: int = 0
    uncorrelated_results: int = 0
    attribution_truncated: bool = False
    image_payloads: int = 0
    image_dimensions_parsed: int = 0
    image_dimensions_unavailable: int = 0
    image_downscaled_to_cap: int = 0
    image_tokens: int = 0
    repeat_read_results: int = 0
    repeat_read_bytes: int = 0
    _current_file: Path | None = field(default=None, init=False, repr=False)
    _pending_uses: dict[str, tuple[str, bool, str | None]] = field(
        default_factory=dict, init=False, repr=False
    )
    _seen_hashes: set[str] = field(default_factory=set, init=False, repr=False)
    _seen_read_hashes: set[str] = field(default_factory=set, init=False, repr=False)
    # 현재 파일에서 가장 최근에 본 tool_result 의 (도구, 바이트). 다음 assistant 턴의
    # cache_creation 을 "직전에 들어온 도구 결과"에 귀속하는 데 쓴다.
    last_result: tuple[str, int] | None = field(default=None, init=False, repr=False)
    # 직전 usage 턴 이후 들어온 모든 tool_result 의 텍스트(비이미지) 바이트 합과 건수.
    # 병렬 tool_use 는 결과 여러 개가 한 턴에 들어오므로 마지막 하나만 보면 비율이 왜곡된다.
    # scan() 이 usage 행을 받을 때 읽고 0 으로 되돌린다.
    text_bytes_since_turn: int = field(default=0, init=False, repr=False)
    results_since_turn: int = field(default=0, init=False, repr=False)
    # 직전 usage 턴 이후의 어시스턴트 콘텐츠(thinking/text/tool_use) 바이트. 보정 분자에만
    # 더하고, "큰 결과" 표본 필터에는 쓰지 않는다.
    assistant_bytes_since_turn: int = field(default=0, init=False, repr=False)
    # TOOL_RESULT_LARGE_BYTES 를 넘는 결과를 도구별로 센다. Read 가드가 덮는 경로(Read)와
    # 덮지 않는 경로(Grep, Bash 등)로 큰 바이트가 얼마나 들어오는지가 가드 실효 범위다.
    large_results_by_tool: Counter[str] = field(default_factory=Counter)
    large_bytes_by_tool: Counter[str] = field(default_factory=Counter)

    def start_file(self, file: Path | None) -> None:
        """세션 하나가 시작됨을 알리고 상관/중복 상태를 비운다.

        tool_use_id와 완전중복은 한 세션 안에서만 의미가 있고, 파일을 넘겨 유지하면
        메모리도 무한히 자란다.

        경계는 추론하지 않고 scan()이 파일마다 정확히 한 번 알려준다. 예전에는 레코드
        마다 불리면서 경로가 직전과 같으면 건너뛰는 방식으로 경계를 추론했는데, 그러면
        같은 파일을 두 번 넘겼을 때 초기화를 건너뛰어 없는 중복을 만들어냈다. 호출자가
        경계를 아는데 굳이 추론할 이유가 없다.
        """
        self._current_file = file
        self._pending_uses.clear()
        self._seen_hashes.clear()
        self._seen_read_hashes.clear()
        self.last_result = None
        self.text_bytes_since_turn = 0
        self.results_since_turn = 0
        self.assistant_bytes_since_turn = 0

    def observe(self, root: Any) -> None:
        """레코드 하나에서 tool_use와 tool_result 블록을 찾아 집계한다."""
        for block in _iter_content_blocks(root):
            block_type = block.get("type")
            if block_type == "tool_use":
                self._observe_tool_use(block)
            elif block_type == "tool_result":
                self._observe_tool_result(block)

    def _observe_tool_use(self, block: dict[str, Any]) -> None:
        use_id = block.get("id")
        name = block.get("name")
        if not isinstance(use_id, str) or not isinstance(name, str):
            return
        if len(self._pending_uses) >= TOOL_RESULT_MAX_PENDING_USES:
            self.attribution_truncated = True
            return
        payload = block.get("input")
        payload = payload if isinstance(payload, dict) else {}
        bounded = any(payload.get(key) is not None for key in TOOL_RESULT_RANGE_KEYS)
        self._pending_uses[use_id] = (
            sanitize_label(name, 80),
            bounded,
            _tool_input_extension(payload),
        )

    def _observe_tool_result(self, block: dict[str, Any]) -> None:
        size = _tool_result_byte_length(block.get("content"))
        if size is None:
            return
        self.results += 1
        self.total_bytes += size
        if len(self.sizes) < TOOL_RESULT_MAX_SIZE_SAMPLES:
            self.sizes.append(size)
        else:
            self.size_samples_truncated = True

        use_id = block.get("tool_use_id")
        entry = self._pending_uses.pop(use_id, None) if isinstance(use_id, str) else None
        if entry is None:
            self.uncorrelated_results += 1
            tool_name, bounded, extension = "unattributed", False, None
        else:
            self.correlated_results += 1
            tool_name, bounded, extension = entry
        tool_name = _bounded_label(
            tool_name, self.by_tool_bytes, TOOL_RESULT_MAX_TOOL_LABELS
        )
        self.by_tool_results[tool_name] += 1
        self.by_tool_bytes[tool_name] += size
        self.last_result = (tool_name, size)
        if size > TOOL_RESULT_LARGE_BYTES:
            self.large_results_by_tool[tool_name] += 1
            self.large_bytes_by_tool[tool_name] += size

        if extension is not None:
            extension = _bounded_label(
                extension, self.by_extension_bytes, TOOL_RESULT_MAX_EXTENSIONS
            )
            self.by_extension_results[extension] += 1
            self.by_extension_bytes[extension] += size
        image_bytes_in_result = 0
        for content_class, class_bytes in _tool_result_class_bytes(
            extension, block.get("content"), size
        ).items():
            # 결과 하나가 이미지와 텍스트를 함께 담으면 두 클래스 모두에 계상된다.
            # 따라서 by_class_results 의 합은 results 보다 클 수 있다.
            self.by_class_results[content_class] += 1
            self.by_class_bytes[content_class] += class_bytes
            if content_class == "image":
                image_bytes_in_result += class_bytes
        self.text_bytes_since_turn += max(0, size - image_bytes_in_result)
        self.results_since_turn += 1

        if entry is not None and tool_name in FILE_READ_TOOL_NAMES:
            if bounded:
                self.bounded_read_results += 1
                self.bounded_read_bytes += size
            else:
                self.unbounded_read_results += 1
                self.unbounded_read_bytes += size
            self._observe_repeat_read(block.get("content"), size)

        self._observe_images(block.get("content"))
        self._observe_duplicate(block.get("content"), size)

    def _observe_images(self, content: Any) -> None:
        """이미지 페이로드마다 픽셀 크기와 추정 토큰을 센다.

        크기를 못 읽은 페이로드도 센다. 세지 않으면 추정 토큰이 "이 코퍼스의 이미지 비용"
        처럼 읽히지만 실제로는 읽을 수 있었던 일부만의 합이 된다.
        """
        for media_type, data in _iter_image_payloads(content):
            self.image_payloads += 1
            dimensions = image_pixel_dimensions(media_type, data)
            if dimensions is None:
                self.image_dimensions_unavailable += 1
                continue
            width, height = dimensions
            tokens = image_token_estimate(width, height)
            if tokens is None:
                self.image_dimensions_unavailable += 1
                continue
            self.image_dimensions_parsed += 1
            self.image_tokens += tokens
            if max(width, height) > IMAGE_LONG_EDGE_CAP_PX:
                self.image_downscaled_to_cap += 1

    def _observe_repeat_read(self, content: Any, size: int) -> None:
        """같은 세션에서 같은 내용을 다시 읽었는지 센다.

        완전중복(_observe_duplicate)은 모든 도구를 대상으로 하지만, 재읽기는 파일 읽기
        도구로 좁힌다. 이미 컨텍스트에 있는 파일을 다시 실어 나른 바이트가 얼마인지가
        묻고 싶은 질문이고, 같은 명령을 두 번 돌려 같은 출력이 나온 것은 다른 현상이다.
        """
        digest = _tool_result_digest(content)
        if digest is None:
            return
        if digest in self._seen_read_hashes:
            self.repeat_read_results += 1
            self.repeat_read_bytes += size
        elif len(self._seen_read_hashes) < TOOL_RESULT_MAX_DUP_HASHES:
            self._seen_read_hashes.add(digest)
        else:
            self.duplicate_tracking_truncated = True

    def _observe_duplicate(self, content: Any, size: int) -> None:
        digest = _tool_result_digest(content)
        if digest is None:
            return
        if digest in self._seen_hashes:
            self.duplicate_results += 1
            self.duplicate_bytes += size
        elif len(self._seen_hashes) >= TOOL_RESULT_MAX_DUP_HASHES:
            self.duplicate_tracking_truncated = True
        else:
            self._seen_hashes.add(digest)


@dataclass
class UsageSummary:
    files: int = 0
    records: int = 0
    skipped_files: int = 0
    unscanned_files_lower_bound: int = 0
    scan_truncated: bool = False
    skipped_records: int = 0
    parse_errors: list[str] = field(default_factory=list)
    tokens: Counter[str] = field(default_factory=Counter)
    cost_usd: float = 0.0
    by_model: dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))
    by_query_source: dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))
    by_file: Counter[str] = field(default_factory=Counter)
    cost_by_file: Counter[str] = field(default_factory=Counter)
    by_command: Counter[str] = field(default_factory=Counter)
    by_tool: Counter[str] = field(default_factory=Counter)
    token_field_presence: Counter[str] = field(default_factory=Counter)
    cost_field_count: int = 0
    cache_creation_per_turn: list[int] = field(default_factory=list)
    cache_creation_zero_turns: int = 0
    # 턴의 cache_creation 을 직전 tool_result 의 도구에 귀속한 합계와 턴 수.
    cache_creation_by_preceding_tool: Counter[str] = field(default_factory=Counter)
    cache_creation_turns_by_preceding_tool: Counter[str] = field(default_factory=Counter)
    cache_creation_samples_truncated: bool = False
    # (도구, 직전 턴 이후 새 바이트(결과 텍스트+어시스턴트 콘텐츠), 그 턴의 cache_creation).
    calibration_samples: list[tuple[str, int, int]] = field(default_factory=list)
    calibration_samples_truncated: bool = False
    # cache_read <= cache_creation 이라 캐시 재작성으로 보고 보정 표본에서 뺀 턴 수.
    calibration_excluded_cache_rewrites: int = 0
    # 직전 usage 턴 이후 tool_result 가 2개 이상이었던 턴 수(병렬 tool_use). 귀속은 마지막
    # 도구에만 하므로 이 수가 크면 by_preceding_tool 은 과소분배됐다.
    multi_result_turns: int = 0
    cache_record_timestamps: list[_dt.datetime] = field(default_factory=list)
    positive_cache_record_timestamps: list[_dt.datetime] = field(default_factory=list)
    prompt_cache_audit: PromptCacheAudit = field(default_factory=PromptCacheAudit)
    tool_result_bytes: ToolResultBytesAudit = field(default_factory=ToolResultBytesAudit)
    usage_reducer_schema: str = REDUCER_SCHEMA
    usage_reducer_counters: Counter[str] = field(default_factory=Counter)
    usage_reducer_partial: bool = False
    cache_friendliness_cache: dict[str, Any] | None = field(default=None, init=False, repr=False)
    cache_diagnostics_cache: dict[str, Any] | None = field(default=None, init=False, repr=False)
    cache_layout_advice_cache: dict[str, Any] | None = field(default=None, init=False, repr=False)

    @property
    def total_tokens(self) -> int:
        return sum(self.tokens.values())

    @property
    def cache_hit_rate(self) -> float:
        """cache_read의 입력 측 비중 = cache_read / (input + cache_read + cache_creation).

        cache_creation이 분모에 포함되므로 신규 prefix를 막 만든 세션에서는 비율이 낮게
        나타날 수 있다. 고전적 hit-rate(cache 가능 풀 대비 hit)가 아니라 입력 비용 절감
        지표로 해석해야 한다. denom == 0이면 0.0.
        """
        cr = self.tokens.get("cache_read", 0)
        cc = self.tokens.get("cache_creation", 0)
        inp = self.tokens.get("input", 0)
        denom = cr + cc + inp
        return (cr / denom) if denom > 0 else 0.0

    @property
    def cache_amortization(self) -> float:
        """cache_read / cache_creation. 토큰 단위로 본 평균 재사용 배수의 근사.

        cache_creation == 0인 경우 의미가 정의되지 않으므로 0.0을 반환한다 (정의되지 않음을
        표현하기 위해 cache_amortization_defined 플래그를 함께 노출한다). 같은 prefix가
        길이 변화 없이 N회 재사용되면 토큰 비도 약 N배가 되지만, prefix 길이가 변하는
        세션에서는 정확히 호출 횟수가 아닌 토큰 비율로 본 근사값임에 주의.
        """
        cc = self.tokens.get("cache_creation", 0)
        cr = self.tokens.get("cache_read", 0)
        return (cr / cc) if cc > 0 else 0.0

    @property
    def cache_amortization_defined(self) -> bool:
        """cache_amortization이 의미를 갖는지 여부. cache_creation > 0일 때만 True."""
        return self.tokens.get("cache_creation", 0) > 0

    def note_error(self, message: str) -> None:
        if len(self.parse_errors) < MAX_ERROR_EXAMPLES:
            self.parse_errors.append(message)


def iter_jsonl_files(paths: Iterable[str]) -> Iterable[Path]:
    seen: set[Path] = set()
    for raw in paths:
        path = Path(raw).expanduser()
        root = path.resolve()
        candidates: Iterable[Path]
        if path.is_file() and path.suffix in {".jsonl", ".json"}:
            candidates = [path]
        elif path.is_dir():
            candidates = sorted(path.rglob("*.jsonl"))
        else:
            continue
        for candidate in candidates:
            if candidate.is_symlink():
                # The scanner opens candidates with O_NOFOLLOW and will skip
                # this path.  Do not let a rejected link reserve its target's
                # dedupe key and suppress a later real transcript in scope.
                yield candidate
                continue
            resolved = candidate.resolve()
            try:
                resolved.relative_to(root if path.is_dir() else root.parent)
            except ValueError:
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            yield candidate


def walk(obj: Any) -> Iterable[dict[str, Any]]:
    stack = [obj]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            yield current
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)


def first_string(obj: dict[str, Any], keys: Iterable[str]) -> str | None:
    for key in keys:
        val = obj.get(key)
        if isinstance(val, str):
            return val
        if isinstance(val, dict):
            nested = val.get("id") or val.get("name")
            if isinstance(nested, str):
                return nested
    return None


MAX_METRIC_VALUE = 10**18


def finite_nonnegative_number(value: Any, *, clamp_negative: bool) -> int | float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        if value < 0 and not clamp_negative:
            return None
        return min(max(value, 0), MAX_METRIC_VALUE)
    if isinstance(value, float):
        if not math.isfinite(value) or (value < 0 and not clamp_negative):
            return None
        return min(max(value, 0.0), float(MAX_METRIC_VALUE))
    return None


def parse_timestamp_value(value: Any) -> _dt.datetime | None:
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            parsed = _dt.datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_dt.timezone.utc)
        return parsed.astimezone(_dt.timezone.utc)
    metric = finite_nonnegative_number(value, clamp_negative=False)
    if metric is None:
        return None
    seconds = float(metric) / 1000.0 if float(metric) > 10_000_000_000 else float(metric)
    try:
        return _dt.datetime.fromtimestamp(seconds, tz=_dt.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def record_timestamp(root: Any) -> _dt.datetime | None:
    candidates: list[Any] = []
    if isinstance(root, dict):
        for key in TIMESTAMP_KEYS:
            if key in root:
                candidates.append(root.get(key))
        message = root.get("message")
        if isinstance(message, dict):
            for key in TIMESTAMP_KEYS:
                if key in message:
                    candidates.append(message.get(key))
    for candidate in candidates:
        parsed = parse_timestamp_value(candidate)
        if parsed is not None:
            return parsed
    return None


def normalize_token_bucket(raw: str) -> str:
    return TOKEN_TYPE_ALIASES.get(raw, raw)


def stable_token_counter(tokens: Counter[str]) -> dict[str, int]:
    return {bucket: tokens[bucket] for bucket in sorted(KNOWN_TOKEN_BUCKETS) if tokens.get(bucket, 0) != 0}


def stable_token_presence(presence: Counter[str]) -> dict[str, int]:
    return {bucket: presence[bucket] for bucket in sorted(KNOWN_TOKEN_BUCKETS) if presence.get(bucket, 0) > 0}


def add_token_groups(local_tokens: Counter[str], d: dict[str, Any]) -> set[str]:
    present: set[str] = set()
    for bucket, keys in TOKEN_KEY_GROUPS:
        for raw_key in keys:
            val = d.get(raw_key)
            metric = finite_nonnegative_number(val, clamp_negative=True)
            if metric is not None:
                local_tokens[bucket] += int(metric)
                present.add(bucket)
                break
    return present


def sanitize_label(value: str, limit: int = 120) -> str:
    compact = " ".join(value.strip().split())
    compact = SECRET_VALUE_RE.sub("[REDACTED]", compact)
    if len(compact) > limit:
        compact = compact[: limit - 15].rstrip() + " ...[truncated]"
    return compact


def stable_hash(value: str, length: int = 12) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:length]


def truncate_utf8(text: str, max_bytes: int) -> tuple[str, bool]:
    raw = text.encode("utf-8", errors="replace")
    if len(raw) <= max_bytes:
        return text, False
    return raw[:max_bytes].decode("utf-8", errors="ignore"), True


def collect_content_text(value: Any, out: list[str]) -> bool:
    """Collect allowlisted text blocks without recursive descent.

    Returns True when collection hit a bounded traversal cap. Deep or very broad
    transcript shapes should downgrade cache-friendliness evidence instead of
    crashing the whole audit.
    """
    capped = False
    visited = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack and len(out) < PROMPT_AUDIT_MAX_TEXT_VALUES:
        current, depth = stack.pop()
        visited += 1
        if visited > PROMPT_AUDIT_MAX_CONTENT_NODES or depth > PROMPT_AUDIT_MAX_DEPTH:
            capped = True
            break
        if isinstance(current, str):
            if current.strip():
                out.append(current)
            continue
        if isinstance(current, list):
            if depth >= PROMPT_AUDIT_MAX_DEPTH:
                capped = True
                continue
            capped = push_bounded(
                stack,
                reversed(current),
                depth + 1,
                visited=visited,
                max_nodes=PROMPT_AUDIT_MAX_CONTENT_NODES,
            ) or capped
            continue
        if not isinstance(current, dict):
            continue
        block_type = current.get("type")
        if block_type in TEXT_BLOCK_TYPES and isinstance(current.get("text"), str):
            stack.append((current.get("text"), depth + 1))
            continue
        if depth >= PROMPT_AUDIT_MAX_DEPTH:
            capped = True
            continue
        if "content" in current:
            capped = push_bounded(
                stack,
                (current.get("content"),),
                depth + 1,
                visited=visited,
                max_nodes=PROMPT_AUDIT_MAX_CONTENT_NODES,
            ) or capped
        if isinstance(current.get("text"), str):
            capped = push_bounded(
                stack,
                (current.get("text"),),
                depth + 1,
                visited=visited,
                max_nodes=PROMPT_AUDIT_MAX_CONTENT_NODES,
            ) or capped
    if stack or len(out) >= PROMPT_AUDIT_MAX_TEXT_VALUES:
        capped = True
    return capped


def extract_prompt_texts(root: Any) -> tuple[list[str], bool]:
    """Best-effort prompt text extraction from allowlisted user/prompt shapes."""
    texts: list[str] = []
    capped = False
    visited = 0
    stack: list[tuple[Any, int]] = [(root, 0)]
    while stack and len(texts) < PROMPT_AUDIT_MAX_TEXT_VALUES:
        current, depth = stack.pop()
        visited += 1
        if visited > PROMPT_AUDIT_MAX_ROOT_NODES or depth > PROMPT_AUDIT_MAX_DEPTH:
            capped = True
            break
        if isinstance(current, dict):
            role = current.get("role")
            role_text = str(role).lower() if isinstance(role, str) else ""
            if role_text in USER_PROMPT_ROLES:
                if "content" in current:
                    capped = collect_content_text(current.get("content"), texts) or capped
                if isinstance(current.get("text"), str):
                    capped = collect_content_text(current.get("text"), texts) or capped
                if isinstance(current.get("prompt"), str):
                    capped = collect_content_text(current.get("prompt"), texts) or capped
                # Role-scoped content was handled above; do not re-walk it and
                # risk duplicating text blocks.
                continue
            prompt = current.get("prompt")
            if isinstance(prompt, str) and prompt.strip():
                texts.append(prompt)
            if depth >= PROMPT_AUDIT_MAX_DEPTH:
                capped = True
                continue
            capped = push_bounded(
                stack,
                current.values(),
                depth + 1,
                visited=visited,
                max_nodes=PROMPT_AUDIT_MAX_ROOT_NODES,
            ) or capped
        elif isinstance(current, list):
            if depth >= PROMPT_AUDIT_MAX_DEPTH:
                capped = True
                continue
            capped = push_bounded(
                stack,
                reversed(current),
                depth + 1,
                visited=visited,
                max_nodes=PROMPT_AUDIT_MAX_ROOT_NODES,
            ) or capped
    if stack or len(texts) >= PROMPT_AUDIT_MAX_TEXT_VALUES:
        capped = True
    return texts, capped


def prompt_segments_for_record(root: Any) -> tuple[list[str], int, int, bool]:
    texts, collection_capped = extract_prompt_texts(root)
    if not texts:
        return [], 0, 0, collection_capped
    budget = PROMPT_AUDIT_MAX_TEXT_BYTES
    segments: list[str] = []
    bytes_sampled = 0
    redactions = 0
    for text in texts:
        if budget <= 0 or len(segments) >= PROMPT_AUDIT_MAX_SEGMENTS_PER_RECORD:
            break
        clipped, _truncated = truncate_utf8(text, budget)
        sanitized, count = SECRET_VALUE_RE.subn("[REDACTED]", clipped)
        redactions += count
        bytes_sampled += len(sanitized.encode("utf-8", errors="replace"))
        budget = max(0, PROMPT_AUDIT_MAX_TEXT_BYTES - bytes_sampled)
        for raw_line in sanitized.splitlines():
            compact = " ".join(raw_line.strip().split())
            if not compact:
                continue
            segment, _ = truncate_utf8(compact, 512)
            segments.append(segment)
            if len(segments) >= PROMPT_AUDIT_MAX_SEGMENTS_PER_RECORD:
                break
        if not segments and sanitized.strip():
            segment, _ = truncate_utf8(" ".join(sanitized.strip().split()), 512)
            if segment:
                segments.append(segment)
    return segments, bytes_sampled, redactions, collection_capped


def safe_resolve(path: Path) -> Path:
    try:
        return path.resolve()
    except (OSError, RuntimeError):
        return path.absolute()


def path_component_contains_secret(component: str) -> bool:
    return bool(component and component not in {".", ".."} and SECRET_VALUE_RE.search(component))


def sanitize_path_component(component: str) -> str:
    if not component or component in {".", ".."}:
        return component
    if not path_component_contains_secret(component):
        return component
    return REDACTED_PATH_COMPONENT


def sanitize_path_text(path: str) -> str:
    return "/".join(sanitize_path_component(component) for component in path.replace(os.sep, "/").split("/"))


def display_path_hash(path: Path) -> str:
    return stable_hash(sanitize_path_text(str(safe_resolve(path))))


def path_label(path: Path, show_paths: bool = False) -> str:
    if show_paths:
        return sanitize_path_text(str(path))
    name = sanitize_label(sanitize_path_component(path.name or "transcript"), 80)
    return f"{name}#path:{display_path_hash(path)}"


def command_label(command: str, show_commands: bool = False) -> str:
    sanitized = sanitize_label(command)
    if show_commands:
        return sanitized
    try:
        argv = shlex.split(sanitized)
    except ValueError:
        argv = sanitized.split()
    if not argv:
        category = "command"
    elif len(argv) >= 3 and argv[0] in {"python", "python3"} and argv[1] == "-m":
        category = " ".join(argv[:3])
    elif len(argv) >= 2 and argv[0] in {"npm", "pnpm", "yarn", "bun"} and argv[1] in {"run", "run-script"}:
        category = " ".join(argv[:3]) if len(argv) >= 3 else " ".join(argv[:2])
    else:
        category = argv[0]
    return f"{category}#cmd:{stable_hash(sanitized)}"


def bounded_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return min(max(number, minimum), maximum)


def require_scan_limit(parser: argparse.ArgumentParser, option: str, value: int, maximum: int) -> int:
    if value < 1 or value > maximum:
        parser.error(f"{option} must be between 1 and {maximum}")
    return value


def os_error_summary(exc: OSError) -> str:
    """Return OSError metadata without embedding raw filenames from str(exc)."""
    parts = [exc.__class__.__name__]
    if exc.errno is not None:
        parts.append(f"errno={exc.errno}")
    message = sanitize_label(str(exc.strerror or ""), 160)
    if message:
        parts.append(message)
    return ": ".join(parts)


@dataclass(frozen=True)
class ScanLimits:
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES
    max_files: int = DEFAULT_MAX_SCAN_FILES


def open_regular_no_symlink(file: Path):
    """Open a transcript candidate only if it is still a regular non-symlink file."""
    before = file.lstat()
    if stat.S_ISLNK(before.st_mode):
        raise OSError(errno.ELOOP, "transcript file must not be a symlink", str(file))
    if not stat.S_ISREG(before.st_mode):
        raise OSError(errno.EINVAL, "transcript file must be a regular file", str(file))
    flags = os.O_RDONLY
    for optional_flag in ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"):
        flags |= getattr(os, optional_flag, 0)
    fd = os.open(file, flags)
    try:
        opened = os.fstat(fd)
        after = file.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or not os.path.samestat(before, opened)
            or not os.path.samestat(after, opened)
        ):
            raise OSError(errno.ELOOP, "transcript file changed while opening", str(file))
        return os.fdopen(fd, "rb")
    except Exception:
        os.close(fd)
        raise


def iter_bounded_lines(handle: BinaryIO, max_line_bytes: int) -> Iterable[tuple[int, str | None]]:
    """Yield decoded lines without retaining an oversized JSONL record in memory.

    `None` means the record exceeded `max_line_bytes` and was skipped after the
    iterator consumed bytes up to the next newline.  This keeps transcript audit
    robust when a corrupted trace contains one huge single-line payload.
    """
    line_no = 1
    buffer = bytearray()
    oversized = False
    while True:
        chunk = handle.read(READ_CHUNK_BYTES)
        if not chunk:
            if oversized:
                yield line_no, None
            elif buffer:
                yield line_no, buffer.decode("utf-8", errors="replace")
            break

        start = 0
        while start < len(chunk):
            newline = chunk.find(b"\n", start)
            end = len(chunk) if newline == -1 else newline + 1
            piece = chunk[start:end]

            if not oversized:
                if len(buffer) + len(piece) > max_line_bytes:
                    buffer.clear()
                    oversized = True
                else:
                    buffer.extend(piece)

            if newline == -1:
                break

            if oversized:
                yield line_no, None
            else:
                yield line_no, buffer.decode("utf-8", errors="replace")
                buffer.clear()
            line_no += 1
            oversized = False
            start = end


def collect_record_hints(root: Any, show_commands: bool = False) -> tuple[set[str], set[str]]:
    commands: set[str] = set()
    tools: set[str] = set()
    for d in walk(root):
        for key in COMMAND_KEYS:
            value = d.get(key)
            if isinstance(value, str) and value.strip():
                commands.add(command_label(value, show_commands=show_commands))
        for key in TOOL_NAME_KEYS:
            value = d.get(key)
            if isinstance(value, str) and value.strip():
                name = sanitize_label(value, 80)
                if name and len(name.split()) <= 4:
                    tools.add(name)
    return commands, tools


def add_usage(
    summary: UsageSummary,
    root: Any,
    file: Path | None = None,
    show_paths: bool = False,
    show_commands: bool = False,
) -> RecordUsage:
    record = RecordUsage()
    summary.prompt_cache_audit.observe(root)
    summary.tool_result_bytes.observe(root)
    for d in walk(root):
        for key in COST_KEYS:
            val = d.get(key)
            metric = finite_nonnegative_number(val, clamp_negative=False)
            if metric is not None:
                cost = float(metric)
                summary.cost_usd += cost
                record.cost_usd += cost
                summary.cost_field_count += 1
                break
    commands, tools = collect_record_hints(root, show_commands=show_commands)
    record.commands = commands
    record.tools = tools
    if file is not None and record.cost_usd:
        file_key = path_label(file, show_paths=show_paths)
        summary.cost_by_file[file_key] += record.cost_usd
    for command in commands:
        summary.by_command[command] += 1
    for tool in tools:
        summary.by_tool[tool] += 1
    return record


def parse_json_line(line: str) -> Any:
    # Python 3.11's json decoder can hit the interpreter recursion limit on
    # deeply nested transcript payloads before our iterative walker sees them.
    # Raise the process limit enough for realistic hostile fixtures, while still
    # treating too-deep input as a skipped parse record instead of crashing.
    if sys.getrecursionlimit() < JSON_PARSE_RECURSION_LIMIT:
        sys.setrecursionlimit(JSON_PARSE_RECURSION_LIMIT)
    return json.loads(line)


NO_PRECEDING_TOOL_LABEL = "no_tool_result"


def _apply_usage_reduction(
    summary: UsageSummary,
    reducer: UsageReducer,
    row_metadata: dict[int, tuple[Path, str]],
    *,
    show_paths: bool,
    row_preceding_result: dict[int, tuple[str, int] | None] | None = None,
    row_preceding_text_bytes: dict[int, int] | None = None,
    row_preceding_results: dict[int, int] | None = None,
    row_preceding_assistant_bytes: dict[int, int] | None = None,
) -> None:
    reduction = reducer.finalize()
    summary.usage_reducer_schema = reduction.schema
    summary.usage_reducer_counters.update(reduction.counters)
    summary.usage_reducer_partial = reduction.partial
    summary.tokens.update(reduction.tokens)
    for selection in reduction.selections:
        local_tokens = Counter(selection.tokens)
        for bucket in selection.present_buckets:
            summary.token_field_presence[bucket] += 1
        if local_tokens:
            model = sanitize_label(selection.model, 80)
            summary.by_model[model].update(local_tokens)
        metadata = row_metadata.get(selection.row_ordinal)
        if metadata is not None:
            file, query_source = metadata
            if local_tokens:
                summary.by_query_source[query_source].update(local_tokens)
                summary.by_file[path_label(file, show_paths=show_paths)] += sum(local_tokens.values())
        created = selection.tokens.get("cache_creation", 0)
        if isinstance(created, int) and created > 0:
            if len(summary.cache_creation_per_turn) < NEW_TOKENS_MAX_SAMPLES:
                summary.cache_creation_per_turn.append(created)
            else:
                summary.cache_creation_samples_truncated = True
            # 귀속은 "이 턴 직전에 컨텍스트에 들어온 도구 결과"에 한다. 사용자 프롬프트나
            # 시스템 변경으로 새 토큰이 생긴 턴은 no_tool_result 로 남겨 도구 탓을 하지 않는다.
            preceding = (row_preceding_result or {}).get(selection.row_ordinal)
            label = preceding[0] if preceding is not None else NO_PRECEDING_TOOL_LABEL
            summary.cache_creation_by_preceding_tool[label] += created
            summary.cache_creation_turns_by_preceding_tool[label] += 1
            if (row_preceding_results or {}).get(selection.row_ordinal, 0) > 1:
                # 결과 여러 개가 한 턴에 들어왔는데 마지막 도구에만 귀속했다. 과소분배가
                # 얼마나 되는지 독자가 볼 수 있게 턴 수를 따로 센다.
                summary.multi_result_turns += 1
            text_bytes = (row_preceding_text_bytes or {}).get(selection.row_ordinal, 0)
            if preceding is not None and text_bytes >= TOKEN_CALIBRATION_MIN_RESULT_BYTES:
                cache_read = selection.tokens.get("cache_read", 0)
                # 캐시가 만료된 턴은 cache_creation 이 컨텍스트 전체를 다시 쓴 값이라
                # 결과 크기와 무관하다. cache_read 가 creation 보다 큰 턴(접두사 대부분이
                # 캐시에서 읽힌 증분 턴)만 표본으로 쓰고, 나머지는 따로 센다.
                if isinstance(cache_read, int) and cache_read > created:
                    new_bytes = text_bytes + (row_preceding_assistant_bytes or {}).get(selection.row_ordinal, 0)
                    if len(summary.calibration_samples) < TOKEN_CALIBRATION_MAX_SAMPLES:
                        summary.calibration_samples.append((label, new_bytes, created))
                    else:
                        summary.calibration_samples_truncated = True
                else:
                    summary.calibration_excluded_cache_rewrites += 1
        elif "cache_creation" in selection.present_buckets:
            summary.cache_creation_zero_turns += 1
        cache_present = bool({"cache_read", "cache_creation"} & set(selection.present_buckets))
        positive_cache = (
            selection.tokens.get("cache_read", 0) > 0
            or selection.tokens.get("cache_creation", 0) > 0
        )
        if selection.timestamp is not None and cache_present:
            summary.cache_record_timestamps.append(selection.timestamp)
        if selection.timestamp is not None and positive_cache:
            summary.positive_cache_record_timestamps.append(selection.timestamp)


def _assistant_content_bytes(row: dict[str, Any]) -> int:
    """어시스턴트 행의 콘텐츠(thinking/text/tool_use)를 canonical JSON 으로 잰 바이트."""
    message = row.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if content is None:
        return 0
    try:
        return len(json.dumps(content, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError):
        return 0


def scan(
    paths: list[str],
    show_paths: bool = False,
    show_commands: bool = False,
    limits: ScanLimits | None = None,
) -> UsageSummary:
    limits = limits or ScanLimits()
    summary = UsageSummary()
    reducer = UsageReducer()
    row_metadata: dict[int, tuple[Path, str]] = {}
    row_preceding_result: dict[int, tuple[str, int] | None] = {}
    row_preceding_text_bytes: dict[int, int] = {}
    row_preceding_results: dict[int, int] = {}
    row_preceding_assistant_bytes: dict[int, int] = {}
    file_identities: dict[Path, str] = {}
    next_ordinal = 0

    def observe_row(file: Path, obj: Any, location: str) -> None:
        nonlocal next_ordinal
        if not isinstance(obj, dict):
            summary.skipped_records += 1
            reducer.note_invalid_row()
            summary.note_error(
                f"{path_label(file, show_paths=show_paths)}:{location}: "
                "skipped non-object transcript row"
            )
            return
        ordinal = next_ordinal
        next_ordinal += 1
        summary.records += 1
        query_source = sanitize_label(first_string(obj, QUERY_SOURCE_KEYS) or "unknown", 80)
        file_identity = file_identities.get(file)
        if file_identity is None:
            file_identity = hash_file_identity(file)
            file_identities[file] = file_identity
        accepted = reducer.observe(
            obj,
            file_identity=file_identity,
            row_ordinal=ordinal,
        )
        if accepted:
            row_metadata[ordinal] = (file, query_source)
            # usage 행(assistant)이 관측되기 *전*의 마지막 tool_result 가 이 턴의 선행 결과다.
            row_preceding_result[ordinal] = summary.tool_result_bytes.last_result
            audit_state = summary.tool_result_bytes
            row_preceding_text_bytes[ordinal] = audit_state.text_bytes_since_turn
            row_preceding_results[ordinal] = audit_state.results_since_turn
            row_preceding_assistant_bytes[ordinal] = audit_state.assistant_bytes_since_turn
            audit_state.text_bytes_since_turn = 0
            audit_state.results_since_turn = 0
            audit_state.assistant_bytes_since_turn = 0
        if obj.get("type") == "assistant":
            # 이 어시스턴트 메시지(thinking, 텍스트, tool_use)는 다음 턴에 입력으로 다시
            # 보내져 그 턴의 cache_creation 에 들어간다. 보정 분자에 함께 넣지 않으면
            # bytes/token 이 실제보다 훨씬 작게 나온다(thinking 이 긴 턴에서 특히).
            summary.tool_result_bytes.assistant_bytes_since_turn += _assistant_content_bytes(obj)
        add_usage(summary, obj, file, show_paths=show_paths, show_commands=show_commands)

    for file in iter_jsonl_files(paths):
        if summary.files >= limits.max_files:
            summary.skipped_files += 1
            summary.unscanned_files_lower_bound += 1
            summary.scan_truncated = True
            summary.note_error(
                f"transcript scan file limit reached ({limits.max_files}); "
                "rerun with narrower paths or --max-files if more evidence is required"
            )
            break
        summary.files += 1
        summary.tool_result_bytes.start_file(file)
        try:
            with open_regular_no_symlink(file) as handle:
                size = os.fstat(handle.fileno()).st_size
                if size > limits.max_file_bytes:
                    summary.skipped_files += 1
                    summary.note_error(
                        f"{path_label(file, show_paths=show_paths)}: skipped oversized transcript file "
                        f"({size} bytes > {limits.max_file_bytes})"
                    )
                    continue
                if file.suffix == ".json":
                    try:
                        raw = handle.read(size + 1)
                        parsed = parse_json_line(raw.decode("utf-8", errors="strict"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        summary.skipped_records += 1
                        reducer.note_invalid_row()
                        reason = "invalid UTF-8" if isinstance(exc, UnicodeDecodeError) else exc.msg
                        summary.note_error(
                            f"{path_label(file, show_paths=show_paths)}: JSON parse error: {reason}"
                        )
                        continue
                    except RecursionError:
                        summary.skipped_records += 1
                        reducer.note_invalid_row()
                        summary.note_error(
                            f"{path_label(file, show_paths=show_paths)}: "
                            "JSON parse error: nested JSON exceeds supported depth"
                        )
                        continue
                    rows = parsed if isinstance(parsed, list) else [parsed]
                    for index, obj in enumerate(rows):
                        observe_row(file, obj, f"item-{index}")
                    continue

                for line_no, line in iter_bounded_lines(handle, limits.max_line_bytes):
                    if line is None:
                        summary.skipped_records += 1
                        reducer.note_invalid_row()
                        summary.note_error(
                            f"{path_label(file, show_paths=show_paths)}:{line_no}: "
                            f"skipped oversized JSONL record (> {limits.max_line_bytes} bytes)"
                        )
                        continue
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = parse_json_line(line)
                    except json.JSONDecodeError as exc:
                        summary.skipped_records += 1
                        reducer.note_invalid_row()
                        summary.note_error(
                            f"{path_label(file, show_paths=show_paths)}:{line_no}: "
                            f"JSON parse error: {exc.msg}"
                        )
                        continue
                    except RecursionError:
                        summary.skipped_records += 1
                        reducer.note_invalid_row()
                        summary.note_error(
                            f"{path_label(file, show_paths=show_paths)}:{line_no}: "
                            "JSON parse error: nested JSON exceeds supported depth"
                        )
                        continue
                    observe_row(file, obj, f"line-{line_no}")
        except OSError as exc:
            summary.skipped_files += 1
            summary.note_error(f"{path_label(file, show_paths=show_paths)}: read error: {os_error_summary(exc)}")
            continue
    _apply_usage_reduction(
        summary,
        reducer,
        row_metadata,
        show_paths=show_paths,
        row_preceding_result=row_preceding_result,
        row_preceding_text_bytes=row_preceding_text_bytes,
        row_preceding_results=row_preceding_results,
        row_preceding_assistant_bytes=row_preceding_assistant_bytes,
    )
    return summary


def print_counter(title: str, counter: Counter[str], top: int) -> None:
    print(f"\n{title}")
    for key, val in counter.most_common(top):
        print(f"  {key:24s} {val:12d}")


def counter_json(counter: Counter[str], top: int) -> list[dict[str, Any]]:
    return [{"name": key, "value": val} for key, val in counter.most_common(top)]


def utc_now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def availability_status(*, present: bool, skipped: bool = False, partial: bool = False) -> str:
    if present and partial:
        return "partial"
    if present:
        return "available"
    if skipped:
        return "partial"
    return "missing"


# 측정 증거 3-상태 등급. status(available/partial/missing)와 직교하는 보조 축으로,
# 값이 "어떻게" 알려졌는지를 GUI/소비자에게 노출한다.
EVIDENCE_OBSERVED = "observed"
EVIDENCE_INFERRED = "inferred"
EVIDENCE_UNAVAILABLE = "unavailable"


def evidence_class(*, observed: bool, inferable: bool = False) -> str:
    """관측/추론/불가 3-상태 증거 등급을 반환한다.

    - observed: transcript 필드에서 직접 읽은 값.
    - inferred: 관측값에서 문서화된 공식으로 파생한 값(추정치).
    - unavailable: scan 데이터만으로는 판별할 수 없는 값.

    observed가 우선한다. 직접 관측이 없고 inferable한 경우에만 inferred로, 둘 다
    아니면 unavailable로 분류해 보수적 측정 원칙을 지킨다.
    """
    if observed:
        return EVIDENCE_OBSERVED
    if inferable:
        return EVIDENCE_INFERRED
    return EVIDENCE_UNAVAILABLE


def build_headroom_availability(summary: UsageSummary) -> dict[str, Any]:
    """Context-window headroom 가용성/증거 등급을 보수적으로 분류한다.

    transcript JSON에는 live `context_window`/잔여 토큰 정보가 없으므로 과거 scan
    만으로는 headroom을 관측하거나 추론할 수 없다. 따라서 status는 기존 context와
    동일하게 "missing", evidence는 "unavailable"로 둔다. live statusline snapshot을
    입력으로 받는 미래 surface에서는 observed로 승급될 수 있음을 contract로 남긴다.
    """
    return {
        "status": "missing",
        "evidence": EVIDENCE_UNAVAILABLE,
        "reason": (
            "Transcript scans do not carry live context-window or remaining-token data, "
            "so context headroom cannot be observed or conservatively inferred from history alone."
        ),
        "observable_via": "live_statusline_snapshot",
    }


def scan_integrity(summary: UsageSummary) -> dict[str, Any]:
    skipped = summary.skipped_files + summary.skipped_records
    complete = skipped == 0 and not summary.parse_errors and not summary.usage_reducer_partial
    return {
        "status": "complete" if complete else "partial",
        "files_scanned": summary.files,
        "records_scanned": summary.records,
        "skipped_files": summary.skipped_files,
        "unscanned_files_lower_bound": summary.unscanned_files_lower_bound,
        "scan_truncated": summary.scan_truncated,
        "skipped_records": summary.skipped_records,
        "parse_error_count": len(summary.parse_errors),
        "usage_reducer_schema": summary.usage_reducer_schema,
        "usage_reducer_partial": summary.usage_reducer_partial,
        "usage_conflict": summary.usage_reducer_counters.get("usage_conflict", 0),
        "numeric_overflow": summary.usage_reducer_counters.get("numeric_overflow", 0),
        "invalid_numeric": summary.usage_reducer_counters.get("invalid_numeric", 0),
        "no_id_fallback": summary.usage_reducer_counters.get("no_id_fallback", 0),
        "ineligible_usage_shape": summary.usage_reducer_counters.get(
            "ineligible_usage_shape", 0
        ),
        "complete": complete,
        "reason": (
            "All candidate transcript files/records were parsed within configured limits."
            if complete
            else "Some transcript files or records were skipped; downstream GUI surfaces should label totals as partial."
        ),
    }


def build_metric_availability(summary: UsageSummary) -> dict[str, Any]:
    token_presence = stable_token_presence(summary.token_field_presence)
    has_any_token = bool(token_presence)
    has_cache_read = summary.token_field_presence.get("cache_read", 0) > 0
    has_cache_creation = summary.token_field_presence.get("cache_creation", 0) > 0
    has_cache_any = has_cache_read or has_cache_creation
    cache_partial = has_cache_any and not (has_cache_read and has_cache_creation)
    skipped = bool(summary.skipped_files or summary.skipped_records or summary.parse_errors)
    has_input = summary.token_field_presence.get("input", 0) > 0
    has_output = summary.token_field_presence.get("output", 0) > 0
    return {
        "tokens": {
            "status": availability_status(present=has_any_token, skipped=skipped and not has_any_token, partial=skipped and has_any_token),
            "present_fields": token_presence,
            "evidence": evidence_class(observed=has_any_token),
        },
        "input": {
            "status": availability_status(present=has_input, partial=skipped and has_input),
            "present_count": summary.token_field_presence.get("input", 0),
            "evidence": evidence_class(observed=has_input),
        },
        "output": {
            "status": availability_status(present=has_output, partial=skipped and has_output),
            "present_count": summary.token_field_presence.get("output", 0),
            "evidence": evidence_class(observed=has_output),
        },
        "cache": {
            "status": availability_status(present=has_cache_any, partial=cache_partial or (skipped and has_cache_any)),
            "present_fields": {
                "cache_read": summary.token_field_presence.get("cache_read", 0),
                "cache_creation": summary.token_field_presence.get("cache_creation", 0),
            },
            "zero_values_observed": {
                "cache_read": has_cache_read and summary.tokens.get("cache_read", 0) == 0,
                "cache_creation": has_cache_creation and summary.tokens.get("cache_creation", 0) == 0,
            },
            # 원시 cache 토큰 수는 관측값(observed)이지만, share/reuse 비율은 관측값에서
            # 파생한 추정값(inferred)이므로 별도로 분류해 노출한다.
            "evidence": evidence_class(observed=has_cache_any),
            "derived": {
                "cache_read_share": {
                    "evidence": evidence_class(observed=False, inferable=has_cache_any),
                    "value": summary.cache_hit_rate if has_cache_any else None,
                },
                "cache_reuse_ratio": {
                    "evidence": evidence_class(observed=False, inferable=summary.cache_amortization_defined),
                    "value": summary.cache_amortization if summary.cache_amortization_defined else None,
                },
            },
        },
        "cost": {
            "status": availability_status(present=summary.cost_field_count > 0, partial=skipped and summary.cost_field_count > 0),
            "present_count": summary.cost_field_count,
            "observed_cost_usd": summary.cost_usd,
            "evidence": evidence_class(observed=summary.cost_field_count > 0),
        },
        "context": {
            "status": "missing",
            "evidence": EVIDENCE_UNAVAILABLE,
            "reason": (
                "Transcript scans do not include live Claude Code context_window data. "
                "Pass a live statusline snapshot in a future surface to populate context availability."
            ),
        },
        "headroom": build_headroom_availability(summary),
    }


def segment_stability(samples: list[PromptSegmentSample], attr: str, window: int) -> tuple[float, int, int]:
    stabilities: list[float] = []
    unique_total = 0
    observed_positions = 0
    for pos in range(window):
        values: list[str] = []
        for sample in samples:
            hashes = getattr(sample, attr)
            if len(hashes) > pos:
                values.append(hashes[pos])
        if not values:
            continue
        counts = Counter(values)
        observed_positions += 1
        unique_total += len(counts)
        stabilities.append(max(counts.values()) / len(values))
    if not stabilities:
        return 0.0, 0, 0
    return sum(stabilities) / len(stabilities), unique_total, observed_positions


def segment_position_stats(samples: list[PromptSegmentSample], attr: str, window: int) -> list[dict[str, Any]]:
    stats: list[dict[str, Any]] = []
    for pos in range(window):
        values: list[str] = []
        for sample in samples:
            hashes = getattr(sample, attr)
            if len(hashes) > pos:
                values.append(hashes[pos])
        if not values:
            continue
        counts = Counter(values)
        stability = max(counts.values()) / len(values)
        stats.append({
            "position": pos,
            "stability": stability,
            "volatile_share": 1.0 - stability,
            "unique_hashes": len(counts),
            "sample_count": len(values),
        })
    return stats


def prompt_window_overlap_counts(samples: list[PromptSegmentSample]) -> tuple[int, int]:
    """Return (non_overlapping, overlapping) prefix/tail evidence counts.

    Prefix and tail segment windows are independent evidence only when the
    sampled prompt has enough segments for the configured windows not to share
    positions. Short prompts are still useful, but prefix-vs-tail deltas from
    overlapping windows are lower-confidence diagnostics.
    """
    non_overlapping = 0
    overlapping = 0
    for sample in samples:
        if sample.segment_count >= PROMPT_AUDIT_PREFIX_SEGMENTS + PROMPT_AUDIT_TAIL_SEGMENTS:
            non_overlapping += 1
        else:
            overlapping += 1
    return non_overlapping, overlapping


def build_cache_friendliness(summary: UsageSummary) -> dict[str, Any]:
    audit = summary.prompt_cache_audit
    skipped = bool(
        summary.skipped_files
        or summary.skipped_records
        or summary.parse_errors
        or audit.capped_records
        or audit.prompt_collection_capped_records
    )
    samples = audit.samples
    if not samples:
        return {
            "status": "partial" if skipped else "missing",
            "confidence": "partial" if skipped else "unavailable",
            "evidence": EVIDENCE_UNAVAILABLE,
            "heuristic": True,
            "sampled_records": audit.sampled_records,
            "analyzed_prompt_records": 0,
            "non_overlapping_prompt_records": 0,
            "overlapping_prompt_records": 0,
            "prefix_tail_windows_overlap": False,
            "prompt_collection_capped_records": audit.prompt_collection_capped_records,
            "skipped_evidence": skipped,
            "segment_window": {"prefix_segments": PROMPT_AUDIT_PREFIX_SEGMENTS, "tail_segments": PROMPT_AUDIT_TAIL_SEGMENTS},
            "signals": {
                "stable_prefix_share": None,
                "volatile_prefix_share": None,
                "volatile_tail_share": None,
                "cache_reuse_ratio": summary.cache_amortization if summary.cache_amortization_defined else None,
                "cache_read_share": summary.cache_hit_rate,
            },
            "findings": [],
            "caveats": [
                "No allowlisted user prompt text was found in scanned transcript records; cache layout cannot be inferred.",
                "Deep or broad prompt content structures are bounded and skipped rather than recursively expanded.",
                "Provider cache token fields, when present, remain diagnostic telemetry rather than ContextGuard-caused token reduction.",
            ],
        }

    prefix_stability, prefix_unique, prefix_positions = segment_stability(samples, "prefix_hashes", PROMPT_AUDIT_PREFIX_SEGMENTS)
    tail_stability, tail_unique, tail_positions = segment_stability(samples, "tail_hashes", PROMPT_AUDIT_TAIL_SEGMENTS)
    prefix_position_stats = segment_position_stats(samples, "prefix_hashes", PROMPT_AUDIT_PREFIX_SEGMENTS)
    non_overlapping_prompt_records, overlapping_prompt_records = prompt_window_overlap_counts(samples)
    prefix_tail_windows_overlap = overlapping_prompt_records > 0
    volatile_prefix = 1.0 - prefix_stability
    volatile_tail = 1.0 - tail_stability
    most_volatile_prefix = max(prefix_position_stats, key=lambda item: item["volatile_share"], default=None)
    max_prefix_position_volatile = float(most_volatile_prefix["volatile_share"]) if most_volatile_prefix else 0.0
    analyzed = audit.analyzed_prompt_records
    status = "available"
    if skipped or analyzed < PROMPT_AUDIT_MIN_RECORDS or non_overlapping_prompt_records == 0:
        status = "partial"
    confidence = "partial" if status == "partial" or prefix_tail_windows_overlap else "observed"
    average_prefix_churn = (
        volatile_prefix >= PROMPT_PREFIX_VOLATILE_THRESHOLD
        and (volatile_prefix - volatile_tail) >= PROMPT_PREFIX_TAIL_CHURN_DELTA
    )
    early_prefix_churn = (
        max_prefix_position_volatile >= PROMPT_PREFIX_VOLATILE_THRESHOLD
        and (max_prefix_position_volatile - volatile_tail) >= PROMPT_PREFIX_TAIL_CHURN_DELTA
    )
    findings: list[dict[str, Any]] = []
    if analyzed >= PROMPT_AUDIT_MIN_RECORDS and (average_prefix_churn or early_prefix_churn):
        findings.append({
            "id": "volatile-content-near-prefix",
            "severity": "P1",
            "confidence": confidence,
            "title": "Volatile content appears near prompt prefix",
            "reason": (
                "Observed user prompt segment hashes churn much more near the prefix than in the tail window; "
                "provider cache telemetry is used only as corroborating diagnostic context."
            ),
            "action": "Move generated logs, diffs, file evidence, and run-specific context after stable instructions and reusable policy text.",
            "heuristic": True,
            "evidence": {
                "records": analyzed,
                "non_overlapping_prompt_records": non_overlapping_prompt_records,
                "overlapping_prompt_records": overlapping_prompt_records,
                "prefix_tail_windows_overlap": prefix_tail_windows_overlap,
                "confidence": confidence,
                "prefix_positions": prefix_positions,
                "tail_positions": tail_positions,
                "prefix_unique_hashes": prefix_unique,
                "tail_unique_hashes": tail_unique,
                "volatile_prefix_share": round(volatile_prefix, 4),
                "volatile_tail_share": round(volatile_tail, 4),
                "max_prefix_position_volatile_share": round(max_prefix_position_volatile, 4),
                "max_prefix_position": most_volatile_prefix["position"] if most_volatile_prefix else None,
                "trigger": "prefix_window_average" if average_prefix_churn else "early_prefix_position",
                "cache_creation": summary.tokens.get("cache_creation", 0),
                "cache_read": summary.tokens.get("cache_read", 0),
            },
        })
    findings = findings[:PROMPT_AUDIT_MAX_FINDINGS]
    return {
        "status": status,
        "confidence": confidence,
        "evidence": EVIDENCE_OBSERVED,
        "heuristic": True,
        "sampled_records": audit.sampled_records,
        "analyzed_prompt_records": analyzed,
        "non_overlapping_prompt_records": non_overlapping_prompt_records,
        "overlapping_prompt_records": overlapping_prompt_records,
        "prefix_tail_windows_overlap": prefix_tail_windows_overlap,
        "capped_records": audit.capped_records,
        "prompt_collection_capped_records": audit.prompt_collection_capped_records,
        "skipped_evidence": skipped,
        "total_segments": audit.total_segments,
        "total_bytes_sampled": audit.total_bytes_sampled,
        "redacted_segments": audit.redacted_segments,
        "segment_window": {"prefix_segments": PROMPT_AUDIT_PREFIX_SEGMENTS, "tail_segments": PROMPT_AUDIT_TAIL_SEGMENTS},
        "thresholds": {
            "min_records": PROMPT_AUDIT_MIN_RECORDS,
            "prefix_volatile_threshold": PROMPT_PREFIX_VOLATILE_THRESHOLD,
            "prefix_tail_churn_delta": PROMPT_PREFIX_TAIL_CHURN_DELTA,
        },
        "signals": {
            "stable_prefix_share": round(prefix_stability, 4),
            "volatile_prefix_share": round(volatile_prefix, 4),
            "volatile_tail_share": round(volatile_tail, 4),
            "max_prefix_position_volatile_share": round(max_prefix_position_volatile, 4),
            "cache_reuse_ratio": summary.cache_amortization if summary.cache_amortization_defined else None,
            "cache_read_share": summary.cache_hit_rate,
        },
        "findings": findings,
        "caveats": [
            "Prompt layout findings are heuristic and based on bounded redacted user-message segment hashes, not raw prompt text or exact provider cache-prefix state.",
            "When prefix and tail segment windows overlap in short prompts, cache-friendliness findings are partial-confidence diagnostics.",
            "Deep or broad prompt content structures are bounded and make cache-friendliness evidence partial.",
            "Provider cache read/write fields are diagnostic telemetry and do not prove ContextGuard-caused token reduction.",
            "Unknown transcript prompt schemas are skipped rather than inferred aggressively.",
        ],
    }


def cache_friendliness_for_summary(summary: UsageSummary) -> dict[str, Any]:
    if summary.cache_friendliness_cache is None:
        summary.cache_friendliness_cache = build_cache_friendliness(summary)
    return summary.cache_friendliness_cache


def _cache_diagnostic_confidence(*, skipped: bool, samples: bool, has_cache: bool) -> str:
    if skipped:
        return "partial"
    if samples or has_cache:
        return "hypothesis"
    return "unavailable"


def build_ttl_diagnostics(summary: UsageSummary, *, has_cache_any: bool, skipped: bool) -> dict[str, Any]:
    timestamped_cache_record_count = len(summary.cache_record_timestamps)
    timestamps = sorted(summary.positive_cache_record_timestamps)
    caveats = [
        "Timestamped cache telemetry records do not prove exact provider cache-prefix identity or provider cache TTL state.",
        "5-minute versus 1-hour TTL guidance is a local hypothesis unless corroborated with provider telemetry and repeated stable prefixes.",
    ]
    if len(timestamps) < 2:
        return {
            "status": "unavailable",
            "evidence": EVIDENCE_UNAVAILABLE,
            "confidence": "unavailable" if not skipped else "partial",
            "timestamped_cache_record_count": timestamped_cache_record_count,
            "positive_timestamped_cache_record_count": len(timestamps),
            "timestamped_cache_record_span_seconds": None,
            "candidate": None,
            "reason": (
                "Fewer than two positive timestamped cache telemetry records were observed, so TTL reuse intervals cannot be inferred."
            ),
            "interval_basis": "positive_timestamped_cache_records",
            "caveats": caveats,
        }
    interval = max(0, int((timestamps[-1] - timestamps[0]).total_seconds()))
    candidate = "within-5m" if interval <= 5 * 60 else ("between-5m-and-1h" if interval <= 60 * 60 else "beyond-1h")
    return {
        "status": "hypothesis" if has_cache_any else "unavailable",
        "evidence": EVIDENCE_INFERRED if has_cache_any else EVIDENCE_UNAVAILABLE,
        "confidence": "partial" if skipped else "hypothesis",
        "timestamped_cache_record_count": timestamped_cache_record_count,
        "positive_timestamped_cache_record_count": len(timestamps),
        "timestamped_cache_record_span_seconds": interval,
        "candidate": candidate,
        "reason": (
            "Positive timestamped cache telemetry records bound the local cache-observation span, but exact provider cache TTL reuse remains a hypothesis."
        ),
        "interval_basis": "positive_timestamped_cache_records",
        "caveats": caveats,
    }


def build_cache_diagnostics(summary: UsageSummary) -> dict[str, Any]:
    if summary.cache_diagnostics_cache is not None:
        return summary.cache_diagnostics_cache

    availability = build_metric_availability(summary)
    cache_availability = availability["cache"]
    cache_friendliness = cache_friendliness_for_summary(summary)
    skipped = bool(
        summary.skipped_files
        or summary.skipped_records
        or summary.parse_errors
        or cache_friendliness.get("skipped_evidence")
    )
    has_cache_read = summary.token_field_presence.get("cache_read", 0) > 0
    has_cache_creation = summary.token_field_presence.get("cache_creation", 0) > 0
    has_cache_any = has_cache_read or has_cache_creation
    cache_read = summary.tokens.get("cache_read", 0)
    cache_creation = summary.tokens.get("cache_creation", 0)
    samples = summary.prompt_cache_audit.samples
    prefix_stats = segment_position_stats(samples, "prefix_hashes", PROMPT_AUDIT_PREFIX_SEGMENTS) if samples else []
    confidence = _cache_diagnostic_confidence(skipped=skipped, samples=bool(samples), has_cache=has_cache_any)

    stable_prefix_candidates: list[dict[str, Any]] = []
    for stat_item in sorted(prefix_stats, key=lambda item: (-item["stability"], item["position"]))[:PROMPT_AUDIT_PREFIX_SEGMENTS]:
        if stat_item["stability"] < 0.66:
            continue
        stable_prefix_candidates.append({
            "position": stat_item["position"],
            "stability": round(float(stat_item["stability"]), 4),
            "volatile_share": round(float(stat_item["volatile_share"]), 4),
            "unique_hashes": stat_item["unique_hashes"],
            "sample_count": stat_item["sample_count"],
            "evidence": EVIDENCE_INFERRED,
            "confidence": "partial" if cache_friendliness.get("confidence") == "partial" else "hypothesis",
            "action": "Keep stable instructions, policies, and reusable context before run-specific evidence.",
        })

    dynamic_prefix_breakers: list[dict[str, Any]] = []
    breaker_trigger = "prefix_position"
    for finding in cache_friendliness.get("findings", []):
        if isinstance(finding, dict) and finding.get("id") == "volatile-content-near-prefix":
            evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
            breaker_trigger = str(evidence.get("trigger") or breaker_trigger)
            break
    for stat_item in sorted(prefix_stats, key=lambda item: (-item["volatile_share"], item["position"])):
        if stat_item["volatile_share"] < 0.34:
            continue
        dynamic_prefix_breakers.append({
            "position": stat_item["position"],
            "trigger": breaker_trigger,
            "volatile_share": round(float(stat_item["volatile_share"]), 4),
            "stability": round(float(stat_item["stability"]), 4),
            "unique_hashes": stat_item["unique_hashes"],
            "sample_count": stat_item["sample_count"],
            "evidence": EVIDENCE_INFERRED,
            "confidence": "partial" if cache_friendliness.get("confidence") == "partial" else "hypothesis",
            "heuristic": True,
            "action": "Move diffs, logs, timestamps, and command output after stable reusable prompt prefixes.",
        })
    dynamic_prefix_breakers = dynamic_prefix_breakers[:PROMPT_AUDIT_MAX_FINDINGS]

    hypotheses: list[dict[str, Any]] = []
    if not has_cache_any:
        hypotheses.append({
            "id": "cache-fields-missing",
            "evidence": EVIDENCE_UNAVAILABLE,
            "confidence": "unavailable" if not skipped else "partial",
            "reason": "No cache_read/cache_creation transcript fields were observed.",
            "action": "Hide cache-read UI or label cache telemetry as missing for this scan.",
        })
    if has_cache_creation and cache_creation > 0 and (not has_cache_read or cache_read == 0):
        hypotheses.append({
            "id": "cache-cold-or-prefix-changed",
            "evidence": EVIDENCE_INFERRED,
            "confidence": "hypothesis",
            "reason": "Cache creation tokens were observed without corresponding cache read tokens.",
            "action": "Check whether stable instructions changed or whether the session was cache-cold.",
        })
    if has_cache_creation and cache_creation >= 10_000 and cache_read > 0 and summary.cache_amortization < 0.5:
        hypotheses.append({
            "id": "cache-read-low-vs-write",
            "evidence": EVIDENCE_INFERRED,
            "confidence": "hypothesis",
            "reason": "Cache reads are small relative to observed cache writes.",
            "action": "Keep reusable prompt prefixes stable across turns before changing large context blocks.",
        })
    if dynamic_prefix_breakers:
        hypotheses.append({
            "id": "volatile-prefix-breakers",
            "evidence": EVIDENCE_INFERRED,
            "confidence": dynamic_prefix_breakers[0]["confidence"],
            "reason": "Redacted prompt segment hashes show volatile content near the prefix window.",
            "action": dynamic_prefix_breakers[0]["action"],
        })
    if skipped:
        hypotheses.append({
            "id": "partial-transcript-scan",
            "evidence": EVIDENCE_INFERRED,
            "confidence": "partial",
            "reason": "Some transcript files, records, or prompt structures were skipped/capped.",
            "action": "Rerun against narrower transcript paths or higher safe scan limits before making decisions.",
        })

    ttl = build_ttl_diagnostics(summary, has_cache_any=has_cache_any, skipped=skipped)
    headroom = build_headroom_availability(summary)
    headroom_diagnostics = {
        **headroom,
        "historical_total_tokens_are_not_headroom": True,
        "required_observation": "live_statusline_snapshot",
    }
    status = "missing"
    if has_cache_any or samples:
        status = "partial" if skipped or cache_friendliness.get("status") == "partial" else "available"
    elif skipped:
        status = "partial"

    diagnostics = {
        "schema_version": CACHE_DIAGNOSTICS_SCHEMA_VERSION,
        "status": status,
        "confidence": confidence,
        "evidence": EVIDENCE_INFERRED if (has_cache_any or samples) else EVIDENCE_UNAVAILABLE,
        "heuristic": True,
        "observations": {
            "cache_fields": cache_availability,
            "cache_read_tokens": cache_read,
            "cache_creation_tokens": cache_creation,
        },
        "derived_ratios": cache_availability["derived"],
        "stable_prefix_candidates": stable_prefix_candidates,
        "dynamic_prefix_breakers": dynamic_prefix_breakers,
        "cache_miss_hypotheses": hypotheses[:PROMPT_AUDIT_MAX_FINDINGS],
        "ttl_diagnostics": ttl,
        "headroom_diagnostics": headroom_diagnostics,
        "caveats": [
            "Cache diagnostics are local transcript heuristics and do not prove exact provider cache-prefix state.",
            "Provider cache read/write fields are diagnostic telemetry and do not prove ContextGuard-caused token reduction.",
            "Stable-prefix and breaker positions come from bounded redacted segment hashes, not raw prompt text.",
        ],
    }
    summary.cache_diagnostics_cache = diagnostics
    return diagnostics


def cache_diagnostics_for_summary(summary: UsageSummary) -> dict[str, Any]:
    return build_cache_diagnostics(summary)


def _dominant_transcript(summary: UsageSummary) -> dict[str, Any] | None:
    if summary.total_tokens <= 0 or not summary.by_file:
        return None
    _label, tokens = summary.by_file.most_common(1)[0]
    share = tokens / summary.total_tokens if summary.total_tokens else 0.0
    return {
        "tokens": tokens,
        "share": round(share, 4),
        "dominates": share >= 0.20 and tokens >= 1_000,
    }


def _first_dynamic_breaker(cache_diagnostics: dict[str, Any]) -> dict[str, Any] | None:
    breakers = cache_diagnostics.get("dynamic_prefix_breakers") or []
    if not breakers:
        return None
    first = breakers[0]
    return first if isinstance(first, dict) else None


def build_cache_layout_advice(summary: UsageSummary) -> dict[str, Any]:
    if summary.cache_layout_advice_cache is not None:
        return summary.cache_layout_advice_cache

    cache_friendliness = cache_friendliness_for_summary(summary)
    cache_diagnostics = cache_diagnostics_for_summary(summary)
    signals = cache_friendliness.get("signals") if isinstance(cache_friendliness.get("signals"), dict) else {}
    dynamic_breaker = _first_dynamic_breaker(cache_diagnostics)
    dominant = _dominant_transcript(summary)
    cache_creation = summary.tokens.get("cache_creation", 0)
    cache_read = summary.tokens.get("cache_read", 0)
    cache_fields = cache_diagnostics.get("observations", {}).get("cache_fields", {}) if isinstance(cache_diagnostics.get("observations"), dict) else {}
    cache_status = cache_fields.get("status") if isinstance(cache_fields, dict) else None
    stable_prefix_share = signals.get("stable_prefix_share")
    volatile_prefix_share = signals.get("volatile_prefix_share")
    volatile_tail_share = signals.get("volatile_tail_share")
    max_prefix_position = dynamic_breaker.get("position") if dynamic_breaker else None
    max_prefix_position_volatile_share = dynamic_breaker.get("volatile_share") if dynamic_breaker else signals.get("max_prefix_position_volatile_share")

    status = "missing"
    confidence = "unavailable"
    observed_issue = "unknown"
    priority = "P2"
    hypothesized_causes: list[dict[str, Any]] = []
    corroborated_causes: list[dict[str, Any]] = []
    next_checks: list[dict[str, Any]] = []
    recommended_experiments: list[dict[str, Any]] = []

    has_cache_any = bool(
        summary.token_field_presence.get("cache_read", 0)
        or summary.token_field_presence.get("cache_creation", 0)
    )
    has_prompt_samples = bool(summary.prompt_cache_audit.samples)
    if has_cache_any or has_prompt_samples:
        status = "partial" if (
            not has_prompt_samples
            or cache_friendliness.get("status") == "partial"
            or cache_diagnostics.get("status") == "partial"
            or summary.skipped_files
            or summary.skipped_records
            or summary.parse_errors
        ) else "available"
        confidence = "partial" if status == "partial" else "hypothesis"

    volatile_prefix_breaker = bool(
        dynamic_breaker
        and cache_creation > 0
        and (max_prefix_position in {0, 1} or (max_prefix_position_volatile_share or 0) >= PROMPT_PREFIX_VOLATILE_THRESHOLD)
    )
    long_session_dominates = bool(dominant and dominant.get("dominates"))

    if volatile_prefix_breaker:
        observed_issue = "volatile_prefix_breaker"
        priority = "P0" if cache_creation >= 50_000 and max_prefix_position in {0, 1} else "P1"
        hypothesized_causes.append({
            "id": "prefix-position-churn",
            "confidence": confidence,
            "evidence": EVIDENCE_INFERRED,
            "reason": (
                "A highly volatile redacted prompt segment appears in the early prefix window; "
                "this identifies a layout issue, not a confirmed source."
            ),
            "next_check": "Check whether startup context, generated evidence, or tool/MCP catalog changes are moving before stable policy.",
        })
        if cache_diagnostics.get("stable_prefix_candidates"):
            hypothesized_causes.append({
                "id": "evidence-before-policy",
                "confidence": confidence,
                "evidence": EVIDENCE_INFERRED,
                "reason": (
                    "Stable reusable segments appear elsewhere while the early prefix churns; "
                    "check whether logs, diffs, timestamps, or file evidence precede stable instructions."
                ),
                "next_check": "Keep stable policy/instructions first and move generated run evidence later.",
            })
        next_checks.append({
            "id": "inspect-startup-context-size",
            "confidence": "hypothesis",
            "command_templates": [
                "context-guard-diet scan <repo>",
                "context-guard-diet structural-waste <repo>",
            ],
            "evidence_required_for_corroboration": (
                "Large or duplicate CLAUDE.md/AGENTS.md/GEMINI.md findings from diet output."
            ),
        })
    elif long_session_dominates:
        observed_issue = "long_session_accumulation"
        priority = "P1"
    elif cache_creation >= 10_000 and cache_read > 0 and summary.cache_amortization < 0.5:
        observed_issue = "low_cache_reuse"
        priority = "P1"
    elif cache_status == "missing" or not has_cache_any:
        observed_issue = "missing_cache_fields"
        priority = "P2"

    if long_session_dominates:
        recommended_experiments.append({
            "id": "split-long-sessions",
            "order": len(recommended_experiments) + 1,
            "priority": "P1",
            "effort": "low",
            "action": "Use /clear between unrelated tasks and /compact focus on changed files, failing tests, and remaining TODO during long work.",
            "expected_signal": "Cache creation per comparable task decreases and one transcript no longer dominates observed tokens.",
            "verification": "Re-run context-guard-audit on a comparable window and compare cache_creation, cache_amortization, and top transcript share.",
            "evidence": dominant or {},
        })
    if volatile_prefix_breaker:
        recommended_experiments.append({
            "id": "stabilize-cache-prefix",
            "order": len(recommended_experiments) + 1,
            "priority": priority,
            "effort": "medium",
            "action": "Keep stable reusable instructions/policy before volatile logs, diffs, timestamps, and generated file evidence.",
            "expected_signal": "Stable prefix share rises and volatile prefix share falls on matched audit windows.",
            "verification": "Re-run context-guard-audit --json --recommend and compare cache_layout_advice plus cache_friendliness signals.",
            "evidence": {
                "dynamic_prefix_breaker_position": max_prefix_position,
                "dynamic_prefix_breaker_volatile_share": max_prefix_position_volatile_share,
            },
        })
        recommended_experiments.append({
            "id": "run-context-diet-checks",
            "order": len(recommended_experiments) + 1,
            "priority": "P1",
            "effort": "low",
            "action": "Run the generated diet command templates and treat any large/duplicate context-file findings as corroborating evidence before editing instructions.",
            "expected_signal": "Diet output identifies or rules out oversized/duplicated startup context as a contributor.",
            "verification": "Record diet JSON separately; do not convert prefix-position evidence alone into a confirmed startup-context cause.",
            "command_templates": [
                "context-guard-diet scan <repo> --json > diet.json",
                "context-guard-diet structural-waste <repo> --json > structural-waste.json",
            ],
        })
    if cache_creation >= 50_000 and summary.cache_amortization_defined and 1.0 <= summary.cache_amortization < 5.0:
        recommended_experiments.append({
            "id": "defer-longer-ttl-until-prefix-stable" if volatile_prefix_breaker else "evaluate-longer-ttl-after-stability-check",
            "order": len(recommended_experiments) + 1,
            "priority": "P2",
            "effort": "medium",
            "action": "Treat longer TTL as secondary; first corroborate stable prefix reuse and current provider TTL/pricing behavior.",
            "expected_signal": "TTL evaluation happens only after prefix volatility is reduced or ruled out.",
            "verification": "Use timestamped cache telemetry and provider-measured billing/cost evidence; historical token totals alone are insufficient.",
        })
    if not recommended_experiments and status == "partial":
        next_checks.append({
            "id": "rerun-narrower-audit",
            "confidence": "partial",
            "command_templates": ["context-guard-audit <transcript-or-project-dir> --json --recommend"],
            "evidence_required_for_corroboration": "Enough uncapped prompt/cache records to classify prefix layout.",
        })
    if not recommended_experiments and observed_issue == "missing_cache_fields":
        next_checks.append({
            "id": "collect-cache-telemetry",
            "confidence": "unavailable",
            "command_templates": ["context-guard-audit ~/.claude/projects --json --recommend"],
            "evidence_required_for_corroboration": "Transcript records with cache_read/cache_creation fields.",
        })

    advice = {
        "schema_version": CACHE_LAYOUT_ADVICE_SCHEMA_VERSION,
        "status": status,
        "confidence": confidence,
        "heuristic": True,
        "observed_issue": observed_issue,
        "priority": priority,
        "observed_summary": {
            "cache_creation_tokens": cache_creation,
            "cache_read_tokens": cache_read,
            "cache_amortization": round(summary.cache_amortization, 4) if summary.cache_amortization_defined else None,
            "stable_prefix_share": stable_prefix_share,
            "volatile_prefix_share": volatile_prefix_share,
            "volatile_tail_share": volatile_tail_share,
            "max_prefix_position": max_prefix_position,
            "max_prefix_position_volatile_share": max_prefix_position_volatile_share,
            "dominant_transcript_share": dominant.get("share") if dominant else None,
        },
        "hypothesized_causes": hypothesized_causes,
        "corroborated_causes": corroborated_causes,
        "next_checks": next_checks,
        "recommended_experiments": recommended_experiments,
        "caveats": [
            "Cache layout advice is a local transcript heuristic, not billing authority or provider-cache proof.",
            "Observed issues come from cache fields and redacted segment statistics; causes remain hypotheses until corroborated by diet/structural evidence.",
            "Generated command templates use placeholders and must not be treated as observed user commands or paths.",
            "Use matched before/after audits before making token or cost savings claims.",
        ],
    }
    summary.cache_layout_advice_cache = advice
    return advice


def cache_layout_advice_for_summary(summary: UsageSummary) -> dict[str, Any]:
    return build_cache_layout_advice(summary)


def build_metric_caveats(summary: UsageSummary) -> list[str]:
    caveats = [
        "Values are observed from local Claude Code transcript JSON/JSONL fields and are not official billing records.",
        "Claude Code transcript schemas may change; skipped files/records and parse errors reduce confidence.",
        "cache-read share is cache_read / (input + cache_read + cache_creation), not a provider billing hit-rate.",
        "reuse ratio is cache_read / cache_creation when cache_creation is non-zero; it is undefined for cache-cold sessions.",
        "each metric carries an evidence class: observed (read from transcript fields), inferred "
        "(derived via a documented formula), or unavailable (not determinable from a historical scan).",
        "context headroom is unavailable from transcript scans; it requires a live statusline snapshot to be observed.",
    ]
    if summary.cost_field_count == 0:
        caveats.append("No cost fields were observed; use Claude Console or official billing exports for invoice-grade cost.")
    if not (summary.token_field_presence.get("cache_read") or summary.token_field_presence.get("cache_creation")):
        caveats.append("No cache fields were observed; hide cache UI or label cache availability as missing.")
    if summary.skipped_files or summary.skipped_records:
        caveats.append("Some transcript files or records were skipped, so hotspot rankings may be incomplete.")
    return caveats


def _mac_card(
    card_id: str,
    title: str,
    status: str,
    binding_paths: list[str],
    *,
    required_observation: str | None = None,
) -> dict[str, Any]:
    card: dict[str, Any] = {
        "id": card_id,
        "title": title,
        "status": status,
        "binding_paths": binding_paths,
    }
    if required_observation:
        card["required_observation"] = required_observation
    return card


def build_mac_visibility_contract(
    *,
    availability: dict[str, Any],
    integrity: dict[str, Any],
    cache_layout_advice: dict[str, Any],
) -> dict[str, Any]:
    """Build the pre-GUI macOS visibility binding contract.

    This is intentionally a thin index over already-emitted stable feasibility
    fields. It does not recompute metrics, read diagnostic summary data, or infer
    live context/headroom from historical transcript totals.
    """
    token_status = str((availability.get("tokens") or {}).get("status", "missing"))
    scan_status = str(integrity.get("status", "partial"))
    if token_status == "available" and scan_status == "complete":
        readiness_status = "ready"
        readiness_reason = "Transcript token totals are available and the scan completed within configured limits."
    elif token_status in {"available", "partial"}:
        readiness_status = "partial"
        readiness_reason = "Some stable fields can be shown, but scan integrity or metric availability is partial."
    else:
        readiness_status = "missing"
        readiness_reason = "Token totals are missing from the transcript scan; show setup or unavailable state."

    context_status = str((availability.get("context") or {}).get("status", "missing"))
    headroom_status = str((availability.get("headroom") or {}).get("status", "missing"))
    cache_status = str((availability.get("cache") or {}).get("status", "missing"))
    cost_status = str((availability.get("cost") or {}).get("status", "missing"))
    advice_status = str(cache_layout_advice.get("status", "missing"))

    missing_live_observations: list[dict[str, Any]] = []
    if context_status == "missing":
        missing_live_observations.append({
            "id": "live_context_window",
            "required_observation": "live_statusline_snapshot",
            "affects": ["context_availability", "metric_availability.context"],
            "reason": "Historical transcript scans do not include live Claude Code context_window data.",
        })
    if headroom_status == "missing":
        missing_live_observations.append({
            "id": "live_headroom",
            "required_observation": "live_statusline_snapshot",
            "affects": ["headroom_availability", "cache_diagnostics.headroom_diagnostics"],
            "reason": "Historical transcript totals are not remaining-token or live headroom observations.",
        })

    return {
        "schema_version": MAC_VISIBILITY_SCHEMA_VERSION,
        "surface_kind": "local_macos_visibility_contract",
        "readiness": {
            "status": readiness_status,
            "reason": readiness_reason,
        },
        "bind_to_top_level_fields": [
            "source_kind",
            "source_freshness",
            "scan_integrity",
            "metric_availability",
            "metric_caveats",
            "redaction_mode",
            "context_availability",
            "headroom_availability",
            "cache_friendliness",
            "cache_diagnostics",
            "cache_layout_advice",
            "totals",
        ],
        "diagnostic_only_fields": ["summary"],
        "primary_cards": [
            _mac_card(
                "source_freshness",
                "Source freshness",
                "available",
                ["source_kind", "source_freshness.status", "source_freshness.generated_at"],
            ),
            _mac_card(
                "scan_integrity",
                "Scan integrity",
                scan_status,
                [
                    "scan_integrity.status",
                    "scan_integrity.files_scanned",
                    "scan_integrity.records_scanned",
                    "scan_integrity.skipped_files",
                    "scan_integrity.skipped_records",
                ],
            ),
            _mac_card(
                "token_totals",
                "Token totals",
                token_status,
                [
                    "totals.total_tokens",
                    "totals.tokens.input",
                    "totals.tokens.output",
                    "totals.tokens.cache_read",
                    "totals.tokens.cache_creation",
                ],
            ),
            _mac_card(
                "cache_reuse",
                "Cache-read share and reuse ratio",
                cache_status,
                ["totals.cache_read_share", "totals.cache_reuse_ratio", "metric_availability.cache"],
            ),
            _mac_card(
                "observed_cost",
                "Observed transcript cost",
                cost_status,
                ["totals.cost_usd_observed", "metric_availability.cost"],
            ),
            _mac_card(
                "context_availability",
                "Context availability",
                context_status,
                ["context_availability", "metric_availability.context"],
                required_observation="live_statusline_snapshot" if context_status == "missing" else None,
            ),
            _mac_card(
                "headroom_availability",
                "Headroom availability",
                headroom_status,
                ["headroom_availability", "cache_diagnostics.headroom_diagnostics"],
                required_observation="live_statusline_snapshot" if headroom_status == "missing" else None,
            ),
            _mac_card(
                "cache_layout_advice",
                "Cache layout advice",
                advice_status,
                ["cache_layout_advice", "cache_friendliness", "cache_diagnostics.dynamic_prefix_breakers"],
            ),
        ],
        "missing_live_observations": missing_live_observations,
        "claim_boundaries": [
            "Local transcript observations are not invoice-grade billing records.",
            "Provider cache fields are telemetry, not ContextGuard-caused token reduction and do not prove provider cache hits.",
            "Historical transcript totals do not infer live context headroom or remaining tokens.",
            "This contract does not guarantee token or cost savings.",
        ],
        "redaction_required": True,
    }


def feasibility_json(
    summary: UsageSummary,
    top: int = 15,
    include_recommendations: bool = False,
    limits: ScanLimits | None = None,
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    generated_at = generated_at or utc_now_iso()
    base = summary_json(summary, top, include_recommendations=include_recommendations, limits=limits)
    availability = build_metric_availability(summary)
    integrity = scan_integrity(summary)
    stable_tokens = stable_token_counter(summary.tokens)
    stable_total_tokens = sum(stable_tokens.values())
    cache_friendliness = cache_friendliness_for_summary(summary)
    cache_diagnostics = cache_diagnostics_for_summary(summary)
    cache_layout_advice = cache_layout_advice_for_summary(summary)
    mac_visibility = build_mac_visibility_contract(
        availability=availability,
        integrity=integrity,
        cache_layout_advice=cache_layout_advice,
    )
    return {
        "schema_version": FEASIBILITY_SCHEMA_VERSION,
        "producer": FEASIBILITY_PRODUCER,
        "generated_at": generated_at,
        "consumer_contract": {
            "stable_top_level_fields": [
                "schema_version",
                "producer",
                "generated_at",
                "source_kind",
                "source_freshness",
                "scan_integrity",
                "metric_availability",
                "metric_caveats",
                "redaction_mode",
                "context_availability",
                "headroom_availability",
                "cache_friendliness",
                "cache_diagnostics",
                "cache_layout_advice",
                "mac_visibility",
                "totals",
            ],
            "diagnostic_fields": ["summary"],
            "summary_contract": (
                "summary is the legacy audit JSON payload for diagnostics and backward compatibility; "
                "new GUI prototypes should bind to stable top-level feasibility fields first."
            ),
        },
        "source_kind": "historical_transcript_scan",
        "source_freshness": {
            "status": "snapshot_at_scan_time",
            "live": False,
            "generated_at": generated_at,
            "description": "Local transcript files were scanned when this report was generated; this is not a live statusline snapshot.",
        },
        "scan_integrity": integrity,
        "metric_availability": availability,
        "metric_caveats": build_metric_caveats(summary),
        "redaction_mode": {
            "paths": "basename_plus_stable_hash_by_default",
            "commands": "command_category_plus_stable_hash_by_default",
            "secret_like_values": "pattern_redacted",
            "raw_path_and_command_flags": ["--show-paths", "--show-commands"],
        },
        "context_availability": availability["context"],
        "headroom_availability": availability["headroom"],
        "cache_friendliness": cache_friendliness,
        "cache_diagnostics": cache_diagnostics,
        "cache_layout_advice": cache_layout_advice,
        "tool_result_bytes": build_tool_result_bytes(summary, top),
        "mac_visibility": mac_visibility,
        "totals": {
            "total_tokens": stable_total_tokens,
            "tokens": stable_tokens,
            "cost_usd_observed": summary.cost_usd,
            "cache_read_share": summary.cache_hit_rate,
            "cache_reuse_ratio": summary.cache_amortization if summary.cache_amortization_defined else None,
        },
        "summary": base,
    }


def _share(part: int, whole: int) -> float | None:
    """비중을 0~1 사이 값으로. 분모가 0이면 None(정의되지 않음)."""
    return (part / whole) if whole > 0 else None


def _counter_pair_rows(
    counts: Counter[str], byte_counts: Counter[str], total_bytes: int, limit: int
) -> list[dict[str, Any]]:
    """바이트 내림차순으로 (라벨, 건수, 바이트, 비중) 행을 만든다."""
    rows: list[dict[str, Any]] = []
    for label, measured in byte_counts.most_common(limit):
        rows.append(
            {
                "label": label,
                "results": counts.get(label, 0),
                "bytes": measured,
                "byte_share": _share(measured, total_bytes),
            }
        )
    return rows


def _rows_coverage(
    rows: list[dict[str, Any]], byte_counts: Counter[str], total_bytes: int
) -> dict[str, Any]:
    """표에 실제로 나온 행이 전체 라벨과 바이트 중 얼마를 덮는지 보고한다.

    행은 --top 으로 잘린다. 그 사실을 말하지 않으면 독자는 합이 100%에 못 미치는 표를
    보고 원인을 알 수 없다. 잘렸는지, 몇 개 중 몇 개인지, 보이는 행이 전체 바이트의
    얼마인지를 함께 낸다.
    """
    shown_bytes = sum(row["bytes"] for row in rows)
    return {
        "rows_shown": len(rows),
        "labels_total": len(byte_counts),
        "truncated": len(rows) < len(byte_counts),
        "shown_byte_share": _share(shown_bytes, total_bytes),
    }


def build_new_tokens_per_turn(summary: UsageSummary) -> dict[str, Any]:
    """턴당 신규 토큰(cache_creation)의 분포를 보고한다.

    prompt cache가 켜진 세션에서 청구 대상은 컨텍스트 총량이 아니라 그 턴에 새로 쓴
    부분이다. 합계만 보면 "매 턴 조금씩"과 "한 턴에 몰아서"가 구분되지 않는데, 두
    상황의 처방이 정반대이므로 분포로 보고한다.

    0인 턴은 분포에서 빼고 따로 센다. 섞으면 백분위가 0 쪽으로 끌려가 실제로 새 바이트를
    쓴 턴의 크기를 읽을 수 없다.
    """
    samples = sorted(summary.cache_creation_per_turn)
    report: dict[str, Any] = {
        "schema_version": NEW_TOKENS_PER_TURN_SCHEMA_VERSION,
        "turns": len(samples),
        "zero_cache_creation_turns": summary.cache_creation_zero_turns,
        "total_cache_creation_tokens": sum(samples),
        "samples_truncated": summary.cache_creation_samples_truncated,
        "note": (
            "Under prompt caching the billable input for a turn is roughly the newly written "
            "prefix plus discounted cached reads, so new tokens per turn — not total context — is "
            "the quantity that moves cost. Turns reporting zero cache_creation are counted "
            "separately rather than folded into the percentiles, which would drag them toward zero."
        ),
        "claim_boundary": {
            "provider_measured": True,
            "token_or_cost_savings_claim_allowed": False,
            "note": (
                "These are provider usage fields, so the token counts are observed rather than "
                "estimated. Observing where new tokens land is still not evidence that any change "
                "reduced them; that requires a matched before/after comparison."
            ),
        },
    }
    if samples:
        def percentile(fraction: float) -> int:
            index = min(len(samples) - 1, max(0, int(len(samples) * fraction)))
            return samples[index]

        report["percentiles"] = {
            "p50": percentile(0.50),
            "p75": percentile(0.75),
            "p90": percentile(0.90),
            "p95": percentile(0.95),
            "p99": percentile(0.99),
        }
        report["max"] = samples[-1]
    report["by_preceding_tool"] = build_new_tokens_by_preceding_tool(summary)
    return report


def build_new_tokens_by_preceding_tool(summary: UsageSummary) -> dict[str, Any]:
    """턴의 cache_creation 을 직전 tool_result 의 도구별로 합산해 보고한다.

    이것이 "어느 표면을 겨냥할지"를 말해주는 표다. tool_result 바이트 표는 결과가 얼마나
    큰지를 말하지만 청구 단위는 그 결과가 만든 새 토큰이므로, 둘은 다를 수 있다.
    귀속은 순서 기반 관측이지 인과 증명이 아니다 — 같은 턴에 사용자 입력이나 규칙 파일
    변경이 함께 들어왔을 수 있다. 그래서 claim_boundary 를 붙인다.
    """
    totals = summary.cache_creation_by_preceding_tool
    turns = summary.cache_creation_turns_by_preceding_tool
    grand_total = sum(totals.values())
    rows = [
        {
            "label": label,
            "turns": turns.get(label, 0),
            "cache_creation_tokens": tokens,
            "token_share": _share(tokens, grand_total),
            "tokens_per_turn": tokens // max(1, turns.get(label, 0)),
        }
        for label, tokens in totals.most_common()
    ]
    return {
        "schema_version": NEW_TOKENS_BY_PRECEDING_TOOL_SCHEMA_VERSION,
        "total_cache_creation_tokens": grand_total,
        # 이 표는 모든 턴을 합산하고, 위의 분포는 NEW_TOKENS_MAX_SAMPLES 로 표본을 자른다.
        # 표본이 잘리면 두 총계가 달라지며, 그 사실을 여기 적어 두 표를 나란히 읽게 한다.
        "covers_all_turns": True,
        "distribution_samples_truncated": summary.cache_creation_samples_truncated,
        "multi_result_turns": summary.multi_result_turns,
        "rows": rows,
        "note": (
            "Each turn's cache_creation is attributed to the most recent tool_result that entered the "
            f"context before it; turns with no preceding tool_result are labelled {NO_PRECEDING_TOOL_LABEL!r} "
            "(user prompts, rule-file or tool-catalog changes). Turns that received several results "
            "(parallel tool_use) are attributed to the last one only; multi_result_turns counts them. "
            "This is an ordering observation, not a causal proof."
        ),
        "claim_boundary": {
            "provider_measured": True,
            "token_or_cost_savings_claim_allowed": False,
        },
    }


def _percentile(sorted_values: list[float], fraction: float) -> float:
    index = min(len(sorted_values) - 1, max(0, int(len(sorted_values) * fraction)))
    return sorted_values[index]


def build_token_calibration(summary: UsageSummary) -> dict[str, Any]:
    """bytes/4 대리값을 관측된 provider usage 와 대조한다 (reconcile).

    표본은 "직전 tool_result 의 텍스트 바이트가 충분히 큰 턴"의 (새 바이트, cache_creation)
    쌍이다. 분자에는 사용자 입력과 하네스가 주입한 reminder 가 빠져 비율이 낮아지고, 반대로
    canonical JSON 이스케이프만큼 실제 입력보다 커져 비율이 높아진다. 두 오차가 공존하므로
    이 값은 상한도 하한도 아닌 관측 비율이다. 큰 결과로 표본을 제한해 빠진 텍스트의 몫을
    줄인다. 이 절은 보정 계수의 근거를 보여줄 뿐 어떤 절감도 주장하지 않는다.
    """
    samples = summary.calibration_samples
    report: dict[str, Any] = {
        "schema_version": TOKEN_CALIBRATION_SCHEMA_VERSION,
        "assumed_bytes_per_token": TEXT_TOKEN_PROXY_DIVISOR,
        "min_result_text_bytes": TOKEN_CALIBRATION_MIN_RESULT_BYTES,
        "min_samples": TOKEN_CALIBRATION_MIN_SAMPLES,
        "samples": len(samples),
        "samples_truncated": summary.calibration_samples_truncated,
        "excluded_cache_rewrite_turns": summary.calibration_excluded_cache_rewrites,
        "status": "insufficient_samples",
        "note": (
            "bytes_per_token = bytes of everything new since the previous usage turn (tool_result text "
            "plus the assistant's own thinking/text/tool_use content, canonical JSON) / that turn's "
            "cache_creation. The ratio is biased in both directions: user-typed text and harness-injected "
            "reminders are missing from the numerator (pushes it low), while canonical JSON escaping "
            "inflates the numerator over the decoded input (pushes it high). Treat it as an observed "
            "corpus ratio, not a bound. Restricting to turns with at least min_result_text_bytes of "
            "tool_result text keeps the omitted text small. Turns whose "
            "cache_read did not exceed cache_creation are "
            "treated as cache rewrites and excluded. Ordering-based observation, not a tokenizer "
            "measurement."
        ),
        "claim_boundary": {
            "provider_measured": True,
            "token_or_cost_savings_claim_allowed": False,
        },
    }
    if len(samples) < TOKEN_CALIBRATION_MIN_SAMPLES:
        return report
    ratios = sorted(text_bytes / created for _tool, text_bytes, created in samples if created > 0)
    if not ratios:
        return report
    p50 = _percentile(ratios, 0.50)
    report.update({
        "status": "observed",
        "bytes_per_token": {
            "p25": round(_percentile(ratios, 0.25), 2),
            "p50": round(p50, 2),
            "p75": round(_percentile(ratios, 0.75), 2),
        },
        "calibrated_divisor": round(p50, 2),
        "proxy_bias": {
            "assumed_over_observed": round(TEXT_TOKEN_PROXY_DIVISOR / p50, 3) if p50 > 0 else None,
            "note": (
                "assumed_over_observed > 1 means bytes/4 under-counts tokens for this corpus "
                "(dense code, identifiers); < 1 means it over-counts."
            ),
        },
    })
    by_tool: dict[str, list[float]] = {}
    for tool, text_bytes, created in samples:
        if created > 0:
            by_tool.setdefault(tool, []).append(text_bytes / created)
    report["by_tool"] = [
        {"label": tool, "samples": len(values), "bytes_per_token_p50": round(_percentile(sorted(values), 0.5), 2)}
        for tool, values in sorted(by_tool.items(), key=lambda item: (-len(item[1]), item[0]))
        if len(values) >= 5
    ]
    return report


def calibrated_text_divisor(summary: UsageSummary) -> tuple[float, str]:
    """`--token-proxy calibrated` 가 쓸 나눗수와 method 라벨. 표본이 부족하면 bytes/4 로 돌아간다."""
    calibration = build_token_calibration(summary)
    if calibration["status"] == "observed":
        divisor = float(calibration["calibrated_divisor"])
        if divisor > 0:
            return divisor, f"calibrated_bytes_div_{divisor:g}"
    return float(TEXT_TOKEN_PROXY_DIVISOR), "bytes_div_4_fallback"


def build_guard_coverage(audit: ToolResultBytesAudit) -> dict[str, Any]:
    """큰 tool_result 가 어느 도구로 들어왔는지, 그중 Read 가드가 덮는 비중을 보고한다.

    Read 가드는 Claude Read 만 막는다. 같은 바이트가 Grep 이나 Bash cat 으로 들어오면
    가드는 침묵한다(README 에 문서화된 한계). 우회를 막을 수는 없으니 측정으로 봉쇄한다:
    큰 결과 바이트 중 Read 경유 비율이 가드의 실효 커버리지다.
    """
    total_bytes = sum(audit.large_bytes_by_tool.values())
    read_bytes = sum(
        audit.large_bytes_by_tool[tool] for tool in audit.large_bytes_by_tool if tool in FILE_READ_TOOL_NAMES
    )
    rows = [
        {
            "label": tool,
            "results": audit.large_results_by_tool[tool],
            "bytes": byte_count,
            "byte_share": _share(byte_count, total_bytes),
            "covered_by_read_guard": tool in FILE_READ_TOOL_NAMES,
        }
        for tool, byte_count in audit.large_bytes_by_tool.most_common()
    ]
    return {
        "schema_version": GUARD_COVERAGE_SCHEMA_VERSION,
        "threshold_bytes": TOOL_RESULT_LARGE_BYTES,
        "large_results": sum(audit.large_results_by_tool.values()),
        "large_bytes": total_bytes,
        "read_guard_covered_share": _share(read_bytes, total_bytes),
        "bypass_share": _share(total_bytes - read_bytes, total_bytes),
        "read_guard_default_budget_bytes": 48_000,
        "rows": rows,
        "note": (
            "covered_by_read_guard means the result came through Read/NotebookRead, the only tools "
            "the large-Read guard can see; it does not mean the guard fired (the guard is opt-in and "
            "its default budget is 48,000B, above this table's 20,000B threshold). Results from other "
            "tools never reach the guard. The Bash escrow wrapper, when installed, stores Bash outputs "
            "over its line budget, so a long single-line Bash result can still bypass it. Grep and MCP "
            "tools are uncovered. Observation, not a savings claim."
        ),
    }


def _build_token_estimate(audit: ToolResultBytesAudit, *, text_divisor: float = TEXT_TOKEN_PROXY_DIVISOR, text_method: str = "bytes_div_4") -> dict[str, Any]:
    """바이트를 토큰 단위로 다시 세어 클래스별로 보고한다.

    두 클래스의 추정 방법이 다르므로 행마다 method를 밝힌다. 이미지는 제공자 공식을
    파싱한 픽셀 크기에 적용한 값이고, 텍스트는 바이트/4라는 거친 대리값이다. 둘을
    "토큰"이라는 같은 이름으로 부르되 근거가 다름을 숨기지 않는다.
    """
    class_tokens: dict[str, int] = {}
    class_method: dict[str, str] = {}
    for label, class_bytes in audit.by_class_bytes.items():
        if label == "image":
            class_tokens[label] = audit.image_tokens
            class_method[label] = "image_formula"
        else:
            class_tokens[label] = int(class_bytes / text_divisor)
            class_method[label] = text_method
    total_tokens = sum(class_tokens.values())
    rows = [
        {
            "label": label,
            "tokens": class_tokens[label],
            "token_share": _share(class_tokens[label], total_tokens),
            "method": class_method[label],
        }
        for label in sorted(class_tokens, key=lambda name: (-class_tokens[name], name))
    ]
    return {
        "schema_version": TOOL_RESULT_TOKEN_ESTIMATE_SCHEMA_VERSION,
        "total_tokens": total_tokens,
        "by_content_class": rows,
        "image_formula": {
            "id": IMAGE_TOKEN_FORMULA_ID,
            "long_edge_cap_px": IMAGE_LONG_EDGE_CAP_PX,
            "area_divisor": IMAGE_TOKEN_AREA_DIVISOR,
            "rounding": "ceil",
            "note": (
                "Images are resized to the long-edge cap before area pricing, so an image's token "
                "cost stops growing above the cap no matter how large the payload is. Text has no "
                "such cap. Comparing the two in bytes therefore overstates images."
            ),
        },
        "images": {
            "payloads": audit.image_payloads,
            "dimensions_parsed": audit.image_dimensions_parsed,
            "dimensions_unavailable": audit.image_dimensions_unavailable,
            "downscaled_to_cap": audit.image_downscaled_to_cap,
            "bytes": audit.by_class_bytes.get("image", 0),
            "tokens": audit.image_tokens,
            "note": (
                "dimensions_unavailable covers payloads whose header could not be read: a media "
                "type with no parser here (GIF, WebP), a reference block carrying no inline data, "
                "or a header past the decode bound. Their tokens are not estimated, so the image "
                "token total is a lower bound whenever this is non-zero."
            ),
        },
        "claim_boundary": {
            "provider_measured": False,
            "token_or_cost_savings_claim_allowed": False,
            "note": (
                "These are estimates, not billed amounts. The image figure applies a published "
                "provider formula to parsed pixel dimensions; the text figure is a bytes/4 proxy "
                "that under-counts dense source code. Use them to compare classes against each "
                "other, never as a measurement of what a provider charged."
            ),
        },
    }


def build_tool_result_bytes(summary: UsageSummary, top: int, *, token_proxy: str = "bytes_div_4") -> dict[str, Any]:
    """tool_result 바이트가 어디로 갔는지에 대한 관측 보고를 만든다.

    이 절은 절감을 주장하지 않는다. usage 토큰 필드는 요청 합계만 주므로 도구별 귀속이
    불가능한데, 여기서는 transcript 블록을 직접 세어 분포/집중도/중복률을 관측값으로만
    보고한다. 어떤 가드레일을 켤지는 이 분포를 보고 사용자가 정한다.
    """
    audit = summary.tool_result_bytes
    total = audit.total_bytes
    status = "observed" if audit.results else "unavailable"
    report: dict[str, Any] = {
        "schema_version": TOOL_RESULT_BYTES_SCHEMA_VERSION,
        "status": status,
        "claim_boundary": (
            "Observed distribution of bytes stored in transcript tool_result blocks, counted once "
            "per result. This is not a token count, not a cost estimate, and not a savings claim. "
            "Provider token accounting is per-request and does not attribute tokens to individual "
            "tools, and a stored result is re-sent on later requests, so stored bytes are a lower "
            "bound on context exposure rather than a measure of it. Sizes are measured on a "
            "canonical serialization, so they approximate rather than reproduce on-disk bytes."
        ),
        "results": audit.results,
        "total_bytes": total,
        "large_result_threshold_bytes": TOOL_RESULT_LARGE_BYTES,
        "attribution": {
            "correlated_results": audit.correlated_results,
            "uncorrelated_results": audit.uncorrelated_results,
            "truncated": audit.attribution_truncated,
            "note": (
                "Uncorrelated results had no matching tool_use block in the same transcript file "
                "and are reported under the 'unattributed' label. If truncated is true the "
                "correlation table filled up, so some results are unattributed for that reason "
                "rather than because their tool_use was absent."
            ),
        },
    }
    # 결과가 없어도 공식 스탬프는 남긴다. 소비자가 "이 리포트가 어떤 공식으로 말하는가"
    # 를 결과 유무와 무관하게 읽을 수 있어야 한다.
    if token_proxy == "calibrated":
        divisor, method = calibrated_text_divisor(summary)
        report["token_estimate"] = _build_token_estimate(audit, text_divisor=divisor, text_method=method)
    else:
        report["token_estimate"] = _build_token_estimate(audit)
    report["token_calibration"] = build_token_calibration(summary)
    report["guard_coverage"] = build_guard_coverage(audit)
    if not audit.results:
        report["reason"] = "no tool_result blocks were observed in the scanned transcripts"
        return report

    sizes = sorted(audit.sizes)
    if sizes:
        def percentile(fraction: float) -> int:
            index = min(len(sizes) - 1, max(0, int(len(sizes) * fraction)))
            return sizes[index]

        report["size_percentiles_bytes"] = {
            "p50": percentile(0.50),
            "p75": percentile(0.75),
            "p90": percentile(0.90),
            "p95": percentile(0.95),
            "p99": percentile(0.99),
            "max": sizes[-1],
        }
        report["size_samples"] = {
            "counted": len(sizes),
            "truncated": audit.size_samples_truncated,
        }
        large = [size for size in sizes if size >= TOOL_RESULT_LARGE_BYTES]
        sampled_total = sum(sizes)
        report["concentration"] = {
            "large_results": len(large),
            "large_result_share": _share(len(large), len(sizes)),
            "large_byte_share": _share(sum(large), sampled_total),
            "sample_results": len(sizes),
            "sample_bytes": sampled_total,
            "sample_truncated": audit.size_samples_truncated,
            "note": (
                "Shares here are over the size sample, not over total_bytes as every other share in "
                "this report is. A small count holding a large byte share means a few results "
                "dominate. If sample_truncated is true the sample is the results seen first rather "
                "than a random draw, so it may not represent the whole scan; the direction of the "
                "difference is not known."
            ),
        }

    report["by_tool"] = _counter_pair_rows(
        audit.by_tool_results, audit.by_tool_bytes, total, top
    )
    report["by_tool_coverage"] = _rows_coverage(
        report["by_tool"], audit.by_tool_bytes, total
    )
    report["by_content_class"] = _counter_pair_rows(
        audit.by_class_results, audit.by_class_bytes, total, len(audit.by_class_bytes)
    )
    report["repeat_reads"] = {
        "results": audit.repeat_read_results,
        "bytes": audit.repeat_read_bytes,
        "share_of_read_bytes": _share(
            audit.repeat_read_bytes,
            audit.bounded_read_bytes + audit.unbounded_read_bytes,
        ),
        "tracking_truncated": audit.duplicate_tracking_truncated,
        "note": (
            "A repeat read is a file-read result whose exact content was already seen in the "
            "same session. Scope is the session, so the same file read in two sessions is not a "
            "repeat here. Content-identical reads of different files also count, and a file that "
            "changed between reads does not."
        ),
    }
    report["by_content_class_note"] = (
        "Bytes are attributed per content block, so one result holding both an image and text "
        "counts into both classes and the result counts here can sum above the result total. "
        "Byte totals still sum to total_bytes."
    )
    if audit.by_extension_bytes:
        report["by_file_extension"] = _counter_pair_rows(
            audit.by_extension_results,
            audit.by_extension_bytes,
            total,
            min(top, TOOL_RESULT_MAX_EXTENSIONS),
        )
        report["by_file_extension_coverage"] = _rows_coverage(
            report["by_file_extension"], audit.by_extension_bytes, total
        )
        report["by_file_extension_note"] = (
            "File extensions only; transcript file paths are never emitted by this section. "
            "Shares here are of total_bytes, but rows exist only for results whose tool_use "
            "named a file to read, so they are not a partition of it: everything read by other "
            "tools, and every result with no matching tool_use, is outside these rows. See "
            "by_file_extension_coverage for how much of total_bytes the rows shown do cover."
        )
    report["exact_duplicates"] = {
        "results": audit.duplicate_results,
        "bytes": audit.duplicate_bytes,
        "byte_share": _share(audit.duplicate_bytes, total),
        "scope": "within a single transcript file",
        "tracking_truncated": audit.duplicate_tracking_truncated,
        "note": (
            "Repeats of an earlier result in the same session, matched on a canonical serialization "
            "rather than raw bytes, so this is an upper bound on byte-identical repeats. Repeats "
            "stored by the transcript itself are indistinguishable here from content the model saw "
            "twice. If tracking_truncated is true the share is understated."
        ),
    }
    read_bytes = audit.unbounded_read_bytes + audit.bounded_read_bytes
    report["file_read_bounding"] = {
        "status": "observed" if read_bytes else "unavailable",
        "unbounded_results": audit.unbounded_read_results,
        "unbounded_bytes": audit.unbounded_read_bytes,
        "unbounded_byte_share": _share(audit.unbounded_read_bytes, read_bytes),
        "bounded_results": audit.bounded_read_results,
        "bounded_bytes": audit.bounded_read_bytes,
        "note": (
            "Bounded means the request carried an explicit range argument (offset/limit/pages). "
            "This counts how reads were requested, not how much of each file exists: an unranged "
            "request may still be truncated by the host's own read limits. Only exact-match "
            "file-reading tool names are counted here, so MCP or custom readers are excluded."
        ),
    }
    return report


def recommendation(
    ident: str,
    title: str,
    reason: str,
    action: str,
    priority: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": ident,
        "priority": priority,
        "title": title,
        "reason": reason,
        "action": action,
        "evidence": evidence,
    }


AIM_MIN_SHARE = 0.4
AIM_MIN_TOKENS = 50_000
AIM_ACTIONS: dict[str, str] = {
    "Read": "Keep the large-Read guard on and prefer context-guard-read-symbol or offset/limit ranges before whole-file reads.",
    "Bash": "Keep the Bash escrow wrapper on so outputs over the line budget land in a local artifact instead of the context.",
    "Grep": "Narrow grep patterns and paths; large search results enter the context as new tokens each time.",
    "Glob": "Glob listings are cheap individually; if they dominate, the working tree is being listed repeatedly.",
    NO_PRECEDING_TOOL_LABEL: (
        "New tokens arrive without a preceding tool result: look at rule files (CLAUDE.md/AGENTS.md), "
        "MCP tool catalogs, and long user pastes rather than at hooks."
    ),
}


def _aim_at_new_token_source(summary: UsageSummary) -> dict[str, Any] | None:
    """cache_creation 이 한 선행 도구에 집중돼 있으면 그 표면을 가리키는 권고 하나를 만든다.

    임계값은 보수적이다: 전체의 40% 이상이고 절대량이 5만 토큰을 넘을 때만 낸다.
    그 아래에서는 분산돼 있어 한 표면을 지목해도 처방이 되지 않는다.
    """
    section = build_new_tokens_by_preceding_tool(summary)
    rows = section["rows"]
    if not rows or section["total_cache_creation_tokens"] < AIM_MIN_TOKENS:
        return None
    lead = rows[0]
    if lead["token_share"] < AIM_MIN_SHARE:
        return None
    label = lead["label"]
    action = AIM_ACTIONS.get(label, f"Inspect what the {label} tool returns; its results precede most new tokens.")
    return recommendation(
        "aim-at-new-token-source",
        f"Most new tokens per turn follow {label} results",
        (
            f"{_format_share(lead['token_share'])} of cache_creation tokens landed in turns whose "
            f"preceding tool_result came from {label} (~{lead['tokens_per_turn']:,} tokens per such turn). "
            "Under prompt caching this, not total context, is what is billed."
        ),
        action,
        "P1",
        {
            "label": label,
            "turns": lead["turns"],
            "cache_creation_tokens": lead["cache_creation_tokens"],
            "token_share": lead["token_share"],
            "attribution": "preceding tool_result ordering; observational, not causal",
        },
    )


BYPASS_MIN_SHARE = 0.5
BYPASS_MIN_BYTES = 1_000_000


def _large_results_bypass_guard(summary: UsageSummary) -> dict[str, Any] | None:
    """큰 결과의 절반 이상이 Read 가드 밖 도구로 들어오면 그 도구를 지목하는 권고 하나."""
    coverage = build_guard_coverage(summary.tool_result_bytes)
    share = coverage["bypass_share"]
    if share is None or share < BYPASS_MIN_SHARE or coverage["large_bytes"] < BYPASS_MIN_BYTES:
        return None
    unguarded = [row for row in coverage["rows"] if not row["covered_by_read_guard"]]
    if not unguarded:
        return None
    lead = unguarded[0]
    actions = {
        "Bash": "Keep the default Bash escrow wrapper installed; it stores outputs over the line budget as local artifacts.",
        "Grep": "Narrow Grep patterns and paths or cap matches; Grep results are not guarded and enter the context whole.",
    }
    action = actions.get(lead["label"], f"{lead['label']} results over {coverage['threshold_bytes']:,}B are not guarded; bound them at the source.")
    return recommendation(
        "large-results-bypass-read-guard",
        f"{_format_share(share)} of large tool results arrive outside the Read guard",
        (
            f"Large results (> {coverage['threshold_bytes']:,}B) total {coverage['large_bytes']:,}B; "
            f"{_format_share(coverage['read_guard_covered_share'])} came through Read, the rest through "
            f"{lead['label']} and other tools the guard never sees."
        ),
        action,
        "P1",
        {"lead_tool": lead["label"], "bypass_share": share, "large_bytes": coverage["large_bytes"]},
    )


def build_recommendations(summary: UsageSummary, top: int) -> list[dict[str, Any]]:
    recs: list[dict[str, Any]] = []
    total = max(0, summary.total_tokens)
    if total == 0:
        recs.append(recommendation(
            "no-usage-found",
            "No token usage found in scanned transcripts",
            "The scanner did not find recognizable Claude Code usage fields.",
            "Verify the transcript path or run again against ~/.claude/projects after more Claude Code activity.",
            "P2",
            {"files_scanned": summary.files, "records": summary.records},
        ))
        return recs

    aim = _aim_at_new_token_source(summary)
    if aim is not None:
        recs.append(aim)
    bypass = _large_results_bypass_guard(summary)
    if bypass is not None:
        recs.append(bypass)

    output_tokens = summary.tokens.get("output", 0)
    input_tokens = summary.tokens.get("input", 0)
    cache_creation = summary.tokens.get("cache_creation", 0)
    cache_read = summary.tokens.get("cache_read", 0)
    output_ratio = output_tokens / total
    input_ratio = input_tokens / total
    cache_friendliness = cache_friendliness_for_summary(summary)
    cache_diagnostics = cache_diagnostics_for_summary(summary)
    cache_layout_advice = cache_layout_advice_for_summary(summary)
    if cache_layout_advice.get("observed_issue") == "volatile_prefix_breaker":
        evidence = {
            "observed_issue": cache_layout_advice.get("observed_issue"),
            "priority": cache_layout_advice.get("priority"),
            "confidence": cache_layout_advice.get("confidence"),
            "cache_creation_tokens": cache_creation,
            "cache_read_tokens": cache_read,
        }
        observed_summary = cache_layout_advice.get("observed_summary")
        if isinstance(observed_summary, dict):
            for key in ("max_prefix_position", "max_prefix_position_volatile_share", "stable_prefix_share", "volatile_prefix_share"):
                evidence[key] = observed_summary.get(key)
        rec = recommendation(
            "prioritize-cache-prefix-stabilization",
            "Prioritize cache-prefix stabilization before TTL or output trimming",
            (
                "Cache creation remains material and redacted segment statistics show a volatile early prefix; "
                "this is an experiment-prioritization signal, not a confirmed root cause."
            ),
            (
                "If one transcript dominates, split unrelated work into shorter sessions; then check startup/context "
                "size and keep stable policy before volatile logs, diffs, timestamps, and generated evidence."
            ),
            str(cache_layout_advice.get("priority") or "P1"),
            evidence,
        )
        rec["heuristic"] = True
        rec["confidence"] = cache_layout_advice.get("confidence")
        recs.append(rec)
    for finding in cache_friendliness.get("findings", []):
        if isinstance(finding, dict) and finding.get("id") == "volatile-content-near-prefix":
            evidence = dict(finding.get("evidence") or {})
            evidence["heuristic"] = True
            if finding.get("confidence"):
                evidence["confidence"] = finding.get("confidence")
            rec = recommendation(
                "move-volatile-context-after-stable-prefix",
                "Volatile context appears before stable prompt prefix",
                str(finding.get("reason") or "Observed prompt prefix churn is higher than tail churn."),
                str(finding.get("action") or "Move run-specific context after stable instructions."),
                str(finding.get("severity") or "P1"),
                evidence,
            )
            rec["heuristic"] = True
            if finding.get("confidence"):
                rec["confidence"] = finding.get("confidence")
            recs.append(rec)
            break
    has_command_or_tool_evidence = bool(summary.by_command or summary.by_tool)
    if has_command_or_tool_evidence and (output_tokens >= 5_000 or output_ratio >= 0.35):
        recs.append(recommendation(
            "trim-output-heavy-sessions",
            "Output tokens are a major hotspot",
            f"Output accounts for {output_ratio:.0%} of observed tokens.",
            "Enable/keep Bash output trimming and add runner-aware failure extraction for repeated test/build commands.",
            "P0",
            {"output_tokens": output_tokens, "total_tokens": total},
        ))
    if input_tokens >= 5_000 or input_ratio >= 0.45:
        recs.append(recommendation(
            "reduce-large-reads",
            "Input tokens are a major hotspot",
            f"Input accounts for {input_ratio:.0%} of observed tokens.",
            "Prefer diff-first review, symbol-scoped reads, and large-file read guards before sending whole files to Claude.",
            "P0",
            {"input_tokens": input_tokens, "total_tokens": total},
        ))
    if (
        cache_creation >= 10_000
        and cache_read >= 1
        and summary.cache_amortization < 0.5
    ):
        recs.append(recommendation(
            "improve-prompt-cache-reuse",
            "Prompt cache reuse looks low",
            (
                f"Cache amortization is {summary.cache_amortization:.2f}x "
                f"(cache_read={cache_read}, cache_creation={cache_creation}); each cached prefix is barely re-served."
            ),
            "Keep stable instructions early, move volatile context later, and avoid editing large instruction files during active sessions.",
            "P1",
            {
                "cache_creation": cache_creation,
                "cache_read": cache_read,
                "cache_amortization": round(summary.cache_amortization, 4),
                "cache_hit_rate": round(summary.cache_hit_rate, 4),
            },
        ))
    if cache_creation >= 50_000 and 1.0 <= summary.cache_amortization < 5.0:
        ttl = cache_diagnostics.get("ttl_diagnostics") or {}
        ttl_status = str(ttl.get("status") or "unavailable")
        ttl_confidence = str(ttl.get("confidence") or "unavailable")
        ttl_candidate = ttl.get("candidate")
        ttl_span = ttl.get("timestamped_cache_record_span_seconds")
        if ttl_status == "hypothesis" and ttl_candidate in {"between-5m-and-1h", "beyond-1h"}:
            ttl_reason = (
                f"Heuristic only — cache amortization {summary.cache_amortization:.2f}x with "
                f"{cache_creation} write tokens; timestamped cache telemetry spans {ttl_span} seconds "
                f"({ttl_candidate})."
            )
            ttl_action = (
                "Evaluate a longer provider prompt-cache TTL only after confirming the same stable prefix "
                "pattern in representative sessions and rechecking current provider TTL/pricing documentation."
            )
        elif ttl_status == "hypothesis":
            ttl_reason = (
                f"Heuristic only — cache amortization {summary.cache_amortization:.2f}x with "
                f"{cache_creation} write tokens, but timestamped cache telemetry currently points to {ttl_candidate}."
            )
            ttl_action = (
                "Keep collecting timestamped cache read/write evidence; do not enable a longer TTL solely from this scan."
            )
        else:
            ttl_reason = (
                f"Heuristic only — cache amortization {summary.cache_amortization:.2f}x with "
                f"{cache_creation} write tokens, but TTL diagnostics are {ttl_status} because this scan lacks "
                "at least two timestamped cache telemetry records."
            )
            ttl_action = (
                "Collect or inspect timestamped cache read/write evidence before evaluating a longer provider "
                "prompt-cache TTL; historical token totals alone are not TTL evidence."
            )
        recs.append(recommendation(
            "evaluate-1h-ttl-cache",
            "Cache writes are large; validate TTL evidence before longer TTL",
            ttl_reason,
            ttl_action,
            "P2",
            {
                "cache_creation": cache_creation,
                "cache_read": cache_read,
                "cache_amortization": round(summary.cache_amortization, 4),
                "cache_hit_rate": round(summary.cache_hit_rate, 4),
                "ttl_status": ttl_status,
                "ttl_evidence": ttl.get("evidence") or EVIDENCE_UNAVAILABLE,
                "ttl_confidence": ttl_confidence,
                "ttl_candidate": ttl_candidate,
                "timestamped_cache_record_count": ttl.get("timestamped_cache_record_count"),
                "positive_timestamped_cache_record_count": ttl.get("positive_timestamped_cache_record_count"),
                "timestamped_cache_record_span_seconds": ttl_span,
                "heuristic": True,
            },
        ))
    if cache_read >= 10_000 and summary.cache_hit_rate >= 0.5:
        rec = recommendation(
            "separate-cache-discounts-from-token-reduction",
            "Provider cache reuse is visible, but it is not token reduction",
            (
                f"Cache read share is {summary.cache_hit_rate:.0%}; this can reduce provider input cost/latency, "
                "but the prompt content may still be sent logically and should not be counted as ContextGuard token reduction."
            ),
            (
                "Report cache_read/cache_creation separately from bytes avoided by local guards, and keep stable cached "
                "instructions before volatile evidence to preserve provider-cache eligibility."
            ),
            "P2",
            {
                "cache_read": cache_read,
                "cache_creation": cache_creation,
                "cache_hit_rate": round(summary.cache_hit_rate, 4),
                "cache_amortization": round(summary.cache_amortization, 4) if summary.cache_amortization_defined else None,
                "provider_cache_telemetry_only": True,
            },
        )
        rec["heuristic"] = True
        recs.append(rec)

    for command, record_count in summary.by_command.most_common(top):
        lowered = command.lower()
        if any(marker in lowered for marker in ("pytest", "jest", "vitest", "go test", "cargo test", "npm test", "pnpm test", "yarn test")):
            recs.append(recommendation(
                "runner-aware-test-summary",
                "Test command appears in transcript records",
                "A test command category was observed in transcript records; token totals are session-level, not precise per-command billing.",
                "Route this command through runner-aware failure extraction so Claude sees failing test names, file:line, assertion text, and rerun commands only.",
                "P0",
                {"command_hint": command, "record_count": record_count},
            ))
            break

    top_files = summary.by_file.most_common(3)
    if top_files:
        largest_file, largest_tokens = top_files[0]
        if largest_tokens >= max(1_000, total * 0.25):
            recs.append(recommendation(
                "inspect-costliest-transcript",
                "One transcript file dominates observed usage",
                "A single transcript file accounts for a large share of observed tokens.",
                "Inspect this session first, then use /clear between unrelated tasks or /compact during long-running work.",
                "P1",
                {"file": largest_file, "tokens": largest_tokens, "share": round(largest_tokens / total, 3)},
            ))

    if summary.by_model:
        model_totals = Counter({model: sum(tokens.values()) for model, tokens in summary.by_model.items()})
        model, model_tokens = model_totals.most_common(1)[0]
        if model != "unknown" and model_tokens >= max(2_000, total * 0.5):
            recs.append(recommendation(
                "route-heavy-work-by-model",
                "One model carries most observed token usage",
                "A single model dominates the observed transcript tokens.",
                "Use lower-cost/auxiliary models for broad search, logs, and first-pass summaries; reserve Claude for final reasoning and edits.",
                "P1",
                {"model": model, "tokens": model_tokens, "share": round(model_tokens / total, 3)},
            ))

    if summary.skipped_files or summary.skipped_records:
        recs.append(recommendation(
            "fix-transcript-scan-gaps",
            "Some transcript data was skipped",
            "Skipped records can hide token hotspots and make recommendations less reliable.",
            "Review parse warnings and rerun with a narrower path if malformed or unrelated JSON files are mixed in.",
            "P2",
            {"skipped_files": summary.skipped_files, "skipped_records": summary.skipped_records},
        ))
    return recs


def summary_json(
    summary: UsageSummary,
    top: int = 15,
    include_recommendations: bool = False,
    limits: ScanLimits | None = None,
    token_proxy: str = "bytes_div_4",
) -> dict[str, Any]:
    limits = limits or ScanLimits()
    data = {
        "files": summary.files,
        "records": summary.records,
        "skipped_files": summary.skipped_files,
        "unscanned_files_lower_bound": summary.unscanned_files_lower_bound,
        "scan_truncated": summary.scan_truncated,
        "skipped_records": summary.skipped_records,
        "parse_errors": summary.parse_errors,
        "scan_integrity": scan_integrity(summary),
        "scan_limits": {
            "max_file_bytes": limits.max_file_bytes,
            "max_line_bytes": limits.max_line_bytes,
            "max_files": limits.max_files,
        },
        "total_tokens": summary.total_tokens,
        "tokens": dict(summary.tokens),
        "usage_reducer": {
            "schema": summary.usage_reducer_schema,
            "partial": summary.usage_reducer_partial,
            **{
                key: summary.usage_reducer_counters.get(key, 0)
                for key in (
                    "observed_rows",
                    "eligible_candidates",
                    "selected_candidates",
                    "usage_conflict",
                    "numeric_overflow",
                    "invalid_numeric",
                    "invalid_row",
                    "no_id_fallback",
                    "ineligible_usage_shape",
                )
            },
        },
        "tool_result_bytes": build_tool_result_bytes(summary, top, token_proxy=token_proxy),
        "new_tokens_per_turn": build_new_tokens_per_turn(summary),
        "cache_metrics": {
            "cache_hit_rate": round(summary.cache_hit_rate, 4),
            "cache_amortization": round(summary.cache_amortization, 4),
            "cache_amortization_defined": summary.cache_amortization_defined,
            "cache_read_tokens": summary.tokens.get("cache_read", 0),
            "cache_creation_tokens": summary.tokens.get("cache_creation", 0),
            "input_tokens": summary.tokens.get("input", 0),
        },
        "cost_usd_observed": summary.cost_usd,
        "by_model": {k: dict(v) for k, v in summary.by_model.items()},
        "by_query_source": {k: dict(v) for k, v in summary.by_query_source.items()},
        "top_files": counter_json(summary.by_file, top),
        "top_commands": counter_json(summary.by_command, top),
        "top_tools": counter_json(summary.by_tool, top),
        "cache_friendliness": cache_friendliness_for_summary(summary),
        "cache_diagnostics": cache_diagnostics_for_summary(summary),
        "cache_layout_advice": cache_layout_advice_for_summary(summary),
    }
    if include_recommendations:
        data["recommendations"] = build_recommendations(summary, top)
    return data


def _format_share(share: float | None) -> str:
    """비중을 사람이 읽는 퍼센트로. 정의되지 않으면 '-'."""
    return "-" if share is None else f"{share * 100:.1f}%"


def print_new_tokens_per_turn(summary: UsageSummary, top: int) -> None:
    """턴당 신규 토큰 분포와 선행 도구별 귀속을 사람이 읽는 형태로 낸다."""
    report = build_new_tokens_per_turn(summary)
    print("\nNew tokens per turn (cache_creation; the quantity that moves cost under prompt caching)")
    if not report["turns"]:
        print("  no turns with cache_creation observed")
        return
    percentiles = report.get("percentiles", {})
    print(
        f"  turns={report['turns']:,} zero_turns={report['zero_cache_creation_turns']:,} "
        f"total={report['total_cache_creation_tokens']:,} tok "
        f"p50={percentiles.get('p50', 0):,} p90={percentiles.get('p90', 0):,} "
        f"p99={percentiles.get('p99', 0):,} max={report.get('max', 0):,}"
    )
    rows = report["by_preceding_tool"]["rows"]
    if rows:
        print("  by preceding tool_result (observed ordering, not causation):")
        for row in rows[:top]:
            print(
                f"    {row['label'][:44]:44s} {row['turns']:>7,} turns "
                f"{row['cache_creation_tokens']:>14,} tok {_format_share(row['token_share']):>7s} "
                f"~{row['tokens_per_turn']:,}/turn"
            )


def print_tool_result_bytes(summary: UsageSummary, top: int, token_proxy: str = "bytes_div_4") -> None:
    """tool_result 바이트 분포를 텍스트로 출력한다."""
    report = build_tool_result_bytes(summary, top, token_proxy=token_proxy)
    print("\nBytes stored in tool_result blocks")
    if report["status"] != "observed":
        print(f"  unavailable: {report.get('reason', 'no tool_result blocks observed')}")
        return
    print(f"  results={report['results']} total_bytes={report['total_bytes']:,}")
    percentiles = report.get("size_percentiles_bytes")
    if percentiles:
        print(
            "  size p50={p50:,}B p90={p90:,}B p99={p99:,}B max={max:,}B".format(**percentiles)
        )
    concentration = report.get("concentration")
    if concentration:
        basis = " (over the size sample, not total_bytes)"
        if concentration.get("sample_truncated"):
            basis += "; sample truncated to the results seen first, so it may not represent the scan"
        print(
            f"  results >= {report['large_result_threshold_bytes']:,}B: "
            f"{concentration['large_results']} "
            f"({_format_share(concentration['large_result_share'])} of results) "
            f"carrying {_format_share(concentration['large_byte_share'])} of bytes"
            f"{basis}"
        )
    for title, key in (
        ("by tool", "by_tool"),
        ("by content class", "by_content_class"),
        ("by file extension", "by_file_extension"),
    ):
        rows = report.get(key)
        if not rows:
            continue
        print(f"  {title}:")
        for row in rows[:top]:
            print(
                f"    {row['label'][:44]:44s} {row['results']:>7,} results "
                f"{row['bytes']:>14,}B {_format_share(row['byte_share']):>7s}"
            )
        coverage = report.get(f"{key}_coverage")
        if coverage and coverage["truncated"]:
            print(
                f"    ... {coverage['rows_shown']} of {coverage['labels_total']} labels shown, "
                f"covering {_format_share(coverage['shown_byte_share'])} of bytes"
            )
    estimate = report.get("token_estimate")
    if estimate and estimate["total_tokens"]:
        print("  by content class, in estimated tokens:")
        for row in estimate["by_content_class"][:top]:
            print(
                f"    {row['label'][:44]:44s} {row['tokens']:>14,} tok "
                f"{_format_share(row['token_share']):>7s} ({row['method']})"
            )
        images = estimate["images"]
        if images["payloads"]:
            unread = images["dimensions_unavailable"]
            unread_note = f", {unread} with unreadable dimensions" if unread else ""
            print(
                f"    images: {images['payloads']} payloads, "
                f"{images['downscaled_to_cap']} over the {estimate['image_formula']['long_edge_cap_px']}px "
                f"long-edge cap{unread_note}"
            )
        text_method = next(
            (row["method"] for row in estimate["by_content_class"] if row["label"] == "text"), "bytes_div_4"
        )
        text_note = (
            "text uses a divisor observed from this corpus's cache_creation (see token proxy reconcile; "
            "may over- or under-count)"
            if text_method.startswith("calibrated")
            else "text uses a bytes/4 proxy"
        )
        print(
            "    token shares are estimates, not billed amounts; images use a published provider "
            f"formula and {text_note}"
        )
    calibration = report.get("token_calibration")
    if calibration:
        if calibration["status"] == "observed":
            ratio = calibration["bytes_per_token"]
            print(
                f"  token proxy reconcile: observed ~{ratio['p50']} bytes/token "
                f"(p25 {ratio['p25']}, p75 {ratio['p75']}) over {calibration['samples']:,} large-result turns "
                f"vs assumed {calibration['assumed_bytes_per_token']}; corpus ratio with errors in both "
                "directions, not a tokenizer measurement"
            )
        else:
            print(
                f"  token proxy reconcile: {calibration['samples']} large-result turns "
                f"(< {calibration['min_samples']} needed); bytes/4 stays unverified for this corpus"
            )
    coverage = report.get("guard_coverage")
    if coverage and coverage["large_results"]:
        print(
            f"  large results (> {coverage['threshold_bytes']:,}B): {coverage['large_results']:,} results, "
            f"{coverage['large_bytes']:,}B; {_format_share(coverage['read_guard_covered_share'])} via Read "
            f"(the only tool the guard sees), {_format_share(coverage['bypass_share'])} via other tools"
        )
        for row in coverage["rows"][:top]:
            marker = "via Read (guard-visible)" if row["covered_by_read_guard"] else "outside the guard"
            print(
                f"    {row['label'][:44]:44s} {row['results']:>7,} results "
                f"{row['bytes']:>14,}B {_format_share(row['byte_share']):>7s} {marker}"
            )
    repeats = report.get("repeat_reads")
    if repeats and repeats["results"]:
        print(
            f"  repeat file reads within a session: {repeats['results']:,} results, "
            f"{repeats['bytes']:,}B ({_format_share(repeats['share_of_read_bytes'])} of read bytes)"
        )
    duplicates = report["exact_duplicates"]
    duplicate_note = " (understated: duplicate tracking truncated)" if duplicates["tracking_truncated"] else ""
    print(
        f"  duplicate results within a session: {duplicates['results']:,} results, "
        f"{_format_share(duplicates['byte_share'])} of bytes{duplicate_note}"
    )
    attribution = report["attribution"]
    if attribution["uncorrelated_results"]:
        reason = (
            "no matching tool_use in the same file, or the correlation table filled up"
            if attribution["truncated"]
            else "no matching tool_use in the same file"
        )
        print(
            f"  results counted as unattributed: {attribution['uncorrelated_results']:,} "
            f"({reason})"
        )
    bounding = report["file_read_bounding"]
    if bounding["status"] == "observed":
        print(
            f"  file reads that requested no explicit range: {bounding['unbounded_results']:,} "
            f"results, {_format_share(bounding['unbounded_byte_share'])} of read bytes "
            f"(exact-match file-reading tools only)"
        )
    print(f"  note: {report['claim_boundary']}")


def print_recommendations(summary: UsageSummary, top: int) -> None:
    print("\nRecommendations")
    for idx, rec in enumerate(build_recommendations(summary, top), 1):
        print(f"{idx}. [{rec['priority']}] {rec['title']}")
        print(f"   reason: {rec['reason']}")
        print(f"   action: {rec['action']}")
        if rec.get("evidence"):
            print(f"   evidence: {json.dumps(rec['evidence'], ensure_ascii=False, sort_keys=True)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", default=[os.path.expanduser("~/.claude/projects")])
    parser.add_argument("--top", type=int, default=15)
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--feasibility-json",
        action="store_true",
        help="emit a GUI-consumable local metric availability report with schema, freshness, caveats, and redaction metadata",
    )
    parser.add_argument("--recommend", action="store_true", help="Print concrete token-saving recommendations")
    parser.add_argument(
        "--token-proxy",
        choices=TOKEN_PROXY_CHOICES,
        default="bytes_div_4",
        help=(
            "text token proxy for the tool_result token estimate: bytes_div_4 (default) or "
            "calibrated (divisor observed from this corpus's cache_creation; falls back to bytes/4 "
            "when fewer than %d large-result samples exist)" % TOKEN_CALIBRATION_MIN_SAMPLES
        ),
    )
    parser.add_argument(
        "--show-paths",
        action="store_true",
        help="Show transcript paths instead of basename+hash labels; local debugging only; secret-shaped path components remain redacted",
    )
    parser.add_argument("--show-commands", action="store_true", help="Show redacted command strings instead of command category+hash labels")
    parser.add_argument(
        "--max-file-bytes",
        type=int,
        default=DEFAULT_MAX_FILE_BYTES,
        help="skip transcript files larger than this many bytes (default: 50 MiB)",
    )
    parser.add_argument(
        "--max-line-bytes",
        type=int,
        default=DEFAULT_MAX_LINE_BYTES,
        help="skip individual JSONL records larger than this many bytes (default: 2 MiB)",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=DEFAULT_MAX_SCAN_FILES,
        help=f"stop after this many transcript files (default: {DEFAULT_MAX_SCAN_FILES})",
    )
    args = parser.parse_args()
    limits = ScanLimits(
        max_file_bytes=require_scan_limit(parser, "--max-file-bytes", args.max_file_bytes, MAX_FILE_BYTES_LIMIT),
        max_line_bytes=require_scan_limit(parser, "--max-line-bytes", args.max_line_bytes, MAX_LINE_BYTES_LIMIT),
        max_files=require_scan_limit(parser, "--max-files", args.max_files, MAX_SCAN_FILES_LIMIT),
    )

    summary = scan(args.paths, show_paths=args.show_paths, show_commands=args.show_commands, limits=limits)

    if args.feasibility_json:
        print(json.dumps(
            feasibility_json(summary, args.top, include_recommendations=args.recommend, limits=limits),
            indent=2,
            sort_keys=True,
        ))
        return 0

    if args.json:
        print(json.dumps(
            summary_json(summary, args.top, include_recommendations=args.recommend, limits=limits, token_proxy=args.token_proxy),
            indent=2,
            sort_keys=True,
        ))
        return 0

    print("Claude Code transcript usage audit")
    print(
        f"files_scanned={summary.files} records={summary.records} "
        f"skipped_files={summary.skipped_files} skipped_records={summary.skipped_records} "
        f"scan_truncated={str(summary.scan_truncated).lower()} "
        f"unscanned_files_lower_bound={summary.unscanned_files_lower_bound}"
    )
    print(
        f"scan_limits=max_file_bytes:{limits.max_file_bytes} "
        f"max_line_bytes:{limits.max_line_bytes} max_files:{limits.max_files}"
    )
    print(
        f"usage_reducer={summary.usage_reducer_schema} "
        f"partial={str(summary.usage_reducer_partial).lower()} "
        f"conflicts={summary.usage_reducer_counters.get('usage_conflict', 0)} "
        f"overflows={summary.usage_reducer_counters.get('numeric_overflow', 0)} "
        f"no_id_fallback={summary.usage_reducer_counters.get('no_id_fallback', 0)} "
        f"ineligible_usage_shape={summary.usage_reducer_counters.get('ineligible_usage_shape', 0)}"
    )
    print(f"observed_total_tokens={summary.total_tokens}")
    if summary.cost_usd:
        print(f"observed_cost_usd={summary.cost_usd:.4f}")
    if summary.parse_errors:
        print("\nWarnings")
        for warning in summary.parse_errors:
            print(f"  - {warning}")
    print_counter("Token buckets", summary.tokens, args.top)

    print("\nCache reuse")
    print(f"  cache_hit_rate           {summary.cache_hit_rate:.2%}")
    if summary.cache_amortization_defined:
        print(f"  cache_amortization       {summary.cache_amortization:.2f}x")
    else:
        print("  cache_amortization       n/a (no cache writes observed)")
    print(f"  cache_read_tokens        {summary.tokens.get('cache_read', 0):12d}")
    print(f"  cache_creation_tokens    {summary.tokens.get('cache_creation', 0):12d}")
    cache_friendliness = cache_friendliness_for_summary(summary)
    if cache_friendliness.get("status") != "missing":
        signals = cache_friendliness.get("signals", {})
        print("\nCache friendliness")
        print(f"  status                  {cache_friendliness.get('status')}")
        print(f"  heuristic               {str(cache_friendliness.get('heuristic')).lower()}")
        print(f"  analyzed_prompt_records {cache_friendliness.get('analyzed_prompt_records', 0):12d}")
        stable_prefix = signals.get("stable_prefix_share")
        volatile_prefix = signals.get("volatile_prefix_share")
        volatile_tail = signals.get("volatile_tail_share")
        if stable_prefix is not None:
            print(f"  stable_prefix_share     {stable_prefix:.2%}")
        if volatile_prefix is not None:
            print(f"  volatile_prefix_share   {volatile_prefix:.2%}")
        if volatile_tail is not None:
            print(f"  volatile_tail_share     {volatile_tail:.2%}")
        for finding in cache_friendliness.get("findings", []):
            if isinstance(finding, dict):
                print(f"  finding                 [{finding.get('severity')}] {finding.get('id')}: {finding.get('title')}")

    cache_diagnostics = cache_diagnostics_for_summary(summary)
    print("\nCache diagnostics")
    print(f"  status                  {cache_diagnostics.get('status')}")
    print(f"  confidence              {cache_diagnostics.get('confidence')}")
    hypotheses = cache_diagnostics.get("cache_miss_hypotheses") or []
    if hypotheses:
        first = hypotheses[0]
        print(f"  top_hypothesis          {first.get('id')} ({first.get('confidence')})")
    stable_candidates = cache_diagnostics.get("stable_prefix_candidates") or []
    if stable_candidates:
        first = stable_candidates[0]
        print(f"  stable_prefix_candidate position={first.get('position')} stability={first.get('stability')}")
    breakers = cache_diagnostics.get("dynamic_prefix_breakers") or []
    if breakers:
        first = breakers[0]
        print(f"  dynamic_prefix_breaker  position={first.get('position')} volatile_share={first.get('volatile_share')}")
    ttl = cache_diagnostics.get("ttl_diagnostics") or {}
    print(f"  ttl_status              {ttl.get('status')} ({ttl.get('confidence')})")
    headroom = cache_diagnostics.get("headroom_diagnostics") or {}
    print(f"  headroom_status         {headroom.get('status')} ({headroom.get('evidence')})")

    cache_layout_advice = cache_layout_advice_for_summary(summary)
    if cache_layout_advice.get("status") != "missing" or cache_layout_advice.get("observed_issue") != "unknown":
        print("\nCache layout advice")
        print(f"  status                  {cache_layout_advice.get('status')}")
        print(f"  confidence              {cache_layout_advice.get('confidence')}")
        print(f"  observed_issue          {cache_layout_advice.get('observed_issue')}")
        print(f"  priority                {cache_layout_advice.get('priority')}")
        experiments = cache_layout_advice.get("recommended_experiments") or []
        if experiments:
            first = experiments[0]
            print(f"  first_experiment        {first.get('id')} ({first.get('priority')})")
            print(f"  experiment_action       {first.get('action')}")
        checks = cache_layout_advice.get("next_checks") or []
        if checks:
            first = checks[0]
            print(f"  next_check              {first.get('id')}")
            templates = first.get("command_templates") or []
            if templates:
                print(f"  command_template        {templates[0]}")

    model_totals = Counter({model: sum(tokens.values()) for model, tokens in summary.by_model.items()})
    print_counter("By model", model_totals, args.top)

    source_totals = Counter({src: sum(tokens.values()) for src, tokens in summary.by_query_source.items()})
    print_counter("By query_source", source_totals, args.top)
    print_counter("Top transcript files", summary.by_file, args.top)
    print_counter("Top command hints observed", summary.by_command, args.top)
    print_counter("Top tools observed", summary.by_tool, args.top)
    print_new_tokens_per_turn(summary, args.top)
    print_tool_result_bytes(summary, args.top, token_proxy=args.token_proxy)
    if args.recommend:
        print_recommendations(summary, args.top)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
