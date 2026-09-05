#!/usr/bin/env python3
"""보호 표면 SHA-256 맵 3벌과 Receipt companion 인벤토리를 현재 내용으로 다시 계산한다.

왜 있는가: `POST_STAGE2_PROTECTED_SHA256` 은 세 파일에 같은 내용으로 존재하고, 그중 두
Receipt 파일은 다시 `tests/test_contextguard_stage2_feasibility.py` 의 companion
인벤토리에 digest 로 박혀 있다(tests/AGENTS.md "The pin cascade"). 보호 파일 하나를
바꿀 때마다 이 다섯 곳을 손으로 고치는 일이 0.13.0 릴리스 동안 다섯 번 반복됐다.
이 스크립트는 그 다섯 곳을 한 번에 갱신하되, 어떤 경로를 보호할지는 바꾸지 않는다 —
맵의 *키* 는 그대로이고 *값* 만 현재 파일 내용에서 다시 계산한다. 캐스케이드 순서
(맵 3벌 → 인벤토리)도 그대로 지킨다.

사용:
    python3 scripts/refresh_protected_pins.py --check   # 드리프트만 보고, 있으면 exit 1
    python3 scripts/refresh_protected_pins.py --write   # 갱신하고 바뀐 항목을 출력

`--write` 뒤에는 커밋한 다음 다시 검사해야 한다. 인벤토리 identity 검사는 커밋된
상태를 읽기 때문이다(tests/AGENTS.md).
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# 세 맵 사본. 첫 번째가 canonical 이며 나머지는 같은 키 집합을 가져야 한다.
MAP_FILES = (
    ROOT / "tests" / "test_contextguard_stage2_protected_surfaces.py",
    ROOT / "packages" / "context-guard-receipt" / "scripts" / "verify_protected_surfaces.py",
    ROOT / "packages" / "context-guard-receipt" / "tests" / "contract" / "test_boundary.py",
)
# 인벤토리에 digest 로 박힌 Receipt 파일. 맵을 고친 *뒤* 계산해야 한다.
INVENTORY_FILE = ROOT / "tests" / "test_contextguard_stage2_feasibility.py"
INVENTORY_PINNED = (
    "packages/context-guard-receipt/scripts/verify_protected_surfaces.py",
    "packages/context-guard-receipt/tests/contract/test_boundary.py",
)
MAP_BLOCK_RE = re.compile(r"POST_STAGE2_PROTECTED_SHA256 = \{\n(.*?)\n\}", re.S)
ENTRY_RE = re.compile(r'"([^"]+)": "([0-9a-f]{64})"')


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_map_entries(text: str, label: str) -> list[tuple[str, str]]:
    """파일 본문에서 맵 항목 (경로, digest) 목록을 순서대로 뽑는다."""
    match = MAP_BLOCK_RE.search(text)
    if match is None:
        raise SystemExit(f"refresh-protected-pins: no POST_STAGE2_PROTECTED_SHA256 map in {label}")
    entries = ENTRY_RE.findall(match.group(1))
    if not entries:
        raise SystemExit(f"refresh-protected-pins: empty map in {label}")
    return entries


def rewrite_entries(text: str, expected: dict[str, str], label: str) -> tuple[str, list[str]]:
    """맵 안의 digest 값만 바꾼다. 키 집합이 canonical 과 다르면 멈춘다.

    세 사본의 문법이 다르다: 두 파일은 `NAME = {...}` 리터럴이고, Receipt 계약 테스트는
    `assertEqual(guard.NAME, {...})` 안에 같은 항목을 둔다. 그래서 블록을 찾지 않고 파일
    전체에서 `"경로": "digest"` 항목을 찾아 바꾼다. 같은 경로 항목이 두 번 나오면 둘 다
    같은 값으로 바뀌어야 하므로 그것도 확인한다.
    """
    present: dict[str, set[str]] = {}
    for path, digest in ENTRY_RE.findall(text):
        present.setdefault(path, set()).add(digest)
    if set(present) != set(expected):
        missing = sorted(set(expected) - set(present))
        extra = sorted(set(present) - set(expected))
        raise SystemExit(
            f"refresh-protected-pins: {label} map keys differ from canonical "
            f"(missing={missing} extra={extra}); align the keys by hand first"
        )
    changed: list[str] = []
    for path, digests in present.items():
        new = expected[path]
        if digests != {new}:
            for old in digests:
                text = text.replace(f'"{path}": "{old}"', f'"{path}": "{new}"')
            changed.append(path)
    return text, changed


def rewrite_inventory(text: str, path: str, digest: str) -> tuple[str, bool]:
    pattern = re.compile(r"('path': '" + re.escape(path) + r"',\n\s*'sha256': ')([0-9a-f]{64})(')")
    match = pattern.search(text)
    if match is None:
        raise SystemExit(f"refresh-protected-pins: inventory entry for {path} not found")
    if match.group(2) == digest:
        return text, False
    return text[: match.start(2)] + digest + text[match.end(2):], True


def run(write: bool) -> int:
    canonical_text = MAP_FILES[0].read_text(encoding="utf-8")
    entries = read_map_entries(canonical_text, str(MAP_FILES[0].relative_to(ROOT)))
    expected: dict[str, str] = {}
    for path, _old in entries:
        target = ROOT / path
        if not target.is_file():
            raise SystemExit(f"refresh-protected-pins: protected path is missing: {path}")
        expected[path] = sha256_of(target)

    drift: list[str] = []
    # 1) 맵 3벌
    for map_file in MAP_FILES:
        label = str(map_file.relative_to(ROOT))
        text = map_file.read_text(encoding="utf-8")
        new_text, changed = rewrite_entries(text, expected, label)
        for path in changed:
            drift.append(f"{label}: {path}")
        if write and changed:
            map_file.write_text(new_text, encoding="utf-8")
    # 2) 인벤토리 — 맵을 쓴 *뒤* 의 Receipt 파일 내용으로 계산한다.
    inventory_text = INVENTORY_FILE.read_text(encoding="utf-8")
    inventory_changed = False
    for path in INVENTORY_PINNED:
        digest = sha256_of(ROOT / path)
        inventory_text, changed = rewrite_inventory(inventory_text, path, digest)
        if changed:
            drift.append(f"{INVENTORY_FILE.relative_to(ROOT)}: inventory {path}")
            inventory_changed = True
    if write and inventory_changed:
        INVENTORY_FILE.write_text(inventory_text, encoding="utf-8")

    if not drift:
        print("refresh-protected-pins: all pins match the working tree")
        return 0
    verb = "updated" if write else "drift"
    for line in drift:
        print(f"refresh-protected-pins: {verb}: {line}")
    if write:
        print("refresh-protected-pins: commit, then re-run --check (inventory identity reads committed state)")
        return 0
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="report drift; exit 1 if any pin is stale")
    mode.add_argument("--write", action="store_true", help="rewrite stale pins in place")
    args = parser.parse_args(argv)
    return run(write=bool(args.write))


if __name__ == "__main__":
    sys.exit(main())
