"""Beta report."""


def normalize_key(raw):
    return raw.strip().lower().replace(' ', '_')


def beta_keys(rows):
    return sorted(normalize_key(row) for row in rows)
