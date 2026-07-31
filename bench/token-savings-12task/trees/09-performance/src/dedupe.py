"""Deduplication helpers."""


def first_unique(rows):
    result = []
    for row in rows:
        seen = False
        for kept in result:
            if kept == row:
                seen = True
        if not seen:
            result.append(row)
    return result
