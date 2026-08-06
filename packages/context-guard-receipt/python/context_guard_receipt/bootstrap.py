"""Isolated bootstrap invoked only by the package's Node launcher."""

from __future__ import annotations

import json
import platform
import sys
from pathlib import Path


PACKAGE_PROTOCOL = "contextguard-receipt-launch/v1"


def probe() -> int:
    """Describe the interpreter in a deliberately closed launcher protocol."""
    result = {
        "implementation": platform.python_implementation(),
        "package_protocol": PACKAGE_PROTOCOL,
        "python_version": [sys.version_info.major, sys.version_info.minor],
    }
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return 0


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--launcher-probe":
        return probe()
    package_root = Path(__file__).resolve().parents[1]
    package_root_text = str(package_root)
    if package_root_text not in sys.path:
        sys.path.insert(0, package_root_text)
    from context_guard_receipt.cli import mcp_main, receipt_main

    if len(sys.argv) < 2:
        return receipt_main(())
    kind = sys.argv[1]
    if kind == "receipt":
        return receipt_main(sys.argv[2:])
    if kind == "mcp":
        return mcp_main(sys.argv[2:])
    return 70


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130) from None
