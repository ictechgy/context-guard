"""Narrow fail-closed Git environment boundary for context selection."""
from __future__ import annotations

import os


def sanitized_environment(_source: dict[str, str]) -> dict[str, str]:
    return {
        "GIT_ASKPASS": "/usr/bin/false",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "SSH_ASKPASS": "/usr/bin/false",
    }
