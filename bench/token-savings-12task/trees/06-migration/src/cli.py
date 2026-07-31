"""Tiny option parser."""


def parse_args(argv):
    options = {"value": None, "deprecated": []}
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "--old-flag":
            options["value"] = argv[index + 1]
            index += 2
            continue
        raise SystemExit("unknown option: " + token)
    return options
