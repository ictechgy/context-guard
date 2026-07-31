"""Alpha report."""


def normalize_key(raw):
    return raw.strip().lower().replace(' ', '_')


def alpha_keys(rows):
    return [normalize_key(row) for row in rows]
