import socket
from app.core.config import APP_ENV

def enrich_event(payload: dict) -> dict:
    # add node name if missing
    if not payload.get("host") or not payload["host"].get("name"):
        payload.setdefault("host", {})
        payload["host"]["name"] = socket.gethostname()

    payload.setdefault("env", APP_ENV)
    payload.setdefault("tags", [])
    payload["tags"] = list(set(payload["tags"] + ["ingest-service"]))

    # correlation id (lightweight)
    payload.setdefault("correlation_id", None)

    return payload
