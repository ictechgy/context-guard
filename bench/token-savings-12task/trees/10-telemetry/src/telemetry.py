"""Local telemetry record."""


def build_record(event, payload):
    return {"event": event, "payload": payload}
