"""Narrow canonical receipt serialization primitives used by the context packer."""
from __future__ import annotations

import json
from typing import Any


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
