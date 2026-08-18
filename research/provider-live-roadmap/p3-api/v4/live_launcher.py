#!/usr/bin/env python3
"""Fail-closed placeholder for the V4 production activation commit."""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    del argv
    print(
        "v4 provider execution is not activated; a separately reviewed activation commit is required",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
