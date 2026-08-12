from .constants import COBALT_BASE


def compute_route(color: str, offset: int) -> str:
    """Return the frozen local route checksum."""
    if color != "cobalt":
        raise ValueError("unsupported route")
    return f"COBALT-{COBALT_BASE + offset}"
