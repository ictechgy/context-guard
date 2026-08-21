"""Narrow deterministic selection primitives used by the context packer."""
from __future__ import annotations


def priority_key(priority: int, input_index: int, path: str) -> tuple[int, int, str]:
    return (-priority, input_index, path)
