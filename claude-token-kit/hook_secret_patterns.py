#!/usr/bin/env python3
"""Shared high-confidence secret patterns for hook-visible text.

These patterns are intentionally narrower than the full output sanitizer: hooks
use them on user-controlled path labels and short diagnostics where false
positives should redact the whole label rather than rewrite large command
output. Keep alternatives bounded or structurally linear; hooks run before any
downstream sanitizer can protect their own stderr/JSON output.
"""
from __future__ import annotations

import re


SENSITIVE_HOOK_TEXT_RE = re.compile(
    r"(?i)("
    r"gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"glpat-[A-Za-z0-9_-]{12,}|(?:AKIA|ASIA)[0-9A-Z]{16}|"
    r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|"
    r"sk-(?:ant|proj)-[A-Za-z0-9_-]{8,}|xox[abprs]-[A-Za-z0-9-]{8,}|"
    r"npm_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{20,}|"
    r"SG\.[A-Za-z0-9_-]{16,256}\.[A-Za-z0-9_-]{16,512}|"
    r"eyJ[A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]*){2}|"
    r"\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{12,}|"
    r"[a-z][a-z0-9+.-]{0,31}:/+(?:[^/\s:@]{0,256}:[^/\s@]{0,2048}|[^/\s@]{1,2048})@|"
    r"(?<![A-Za-z0-9])(?:api[_-]?key|token|secret|password|client[_-]?secret)\s*(?:=|:|%3d)[^/\\\s]{4,})"
)


def hook_text_has_sensitive_evidence(value: str) -> bool:
    """Return True when hook-visible text contains a high-confidence secret."""
    return bool(SENSITIVE_HOOK_TEXT_RE.search(value))


def redact_sensitive_hook_text(value: str, replacement: str = "[redacted]") -> str:
    """Redact high-confidence secrets from hook-visible text."""
    return SENSITIVE_HOOK_TEXT_RE.sub(replacement, value)
