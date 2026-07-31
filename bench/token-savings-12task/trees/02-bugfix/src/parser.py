"""Request field parser."""


def parse_fields(raw):
    fields = {}
    for line in raw.splitlines():
        if not line.strip() or '=' not in line:
            continue
        key, value = line.split('=', 1)
        fields[key.strip()] = value.strip()
    return fields
