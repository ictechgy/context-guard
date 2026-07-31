"""Budget helpers."""


def resolve_token_budget(limit, used):
    return max(0, limit - used)
