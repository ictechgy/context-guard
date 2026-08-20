"""Narrow source-scanning primitives used by the context packer."""
from __future__ import annotations


def input_limit_exceeded(*, bytes_read: int, lines_read: int, max_bytes: int, max_lines: int) -> str | None:
    if bytes_read > max_bytes:
        return "source_input_bytes_exceeded"
    if lines_read > max_lines:
        return "source_input_lines_exceeded"
    return None
