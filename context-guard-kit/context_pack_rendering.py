"""Narrow byte-identity rendering primitives used by the context packer."""
from __future__ import annotations

import hashlib


def byte_len(text: str) -> int:
    return len(text.encode("utf-8", errors="replace"))


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
