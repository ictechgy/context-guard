from .routing.checksum import compute_route


def resolver_entrypoint() -> str:
    """Return the checksum chosen by the nested routing package."""
    return compute_route("cobalt", 19)
