from fastapi import APIRouter, Depends, Request, HTTPException
from datetime import datetime, timezone
from typing import Any, Dict

from app.core.security import require_api_key
from app.services.enricher import enrich_event
from app.services.redis_queue import enqueue, queue_len
from app.services.metrics_store import incr, set_gauge

router = APIRouter()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def extract_service_name(body: Dict[str, Any]) -> str:
    svc = body.get("service")
    if isinstance(svc, str) and svc.strip():
        return svc.strip()
    if isinstance(svc, dict):
        return str(svc.get("name") or svc.get("type") or "host-logs")

    host = body.get("host")
    if isinstance(host, dict) and host.get("name"):
        return str(host["name"])
    return "host-logs"


def extract_log_level(body: Dict[str, Any]) -> str:
    log_obj = body.get("log")
    if isinstance(log_obj, dict) and log_obj.get("level"):
        return str(log_obj["level"]).upper()
    if body.get("level"):
        return str(body["level"]).upper()
    return "INFO"


def extract_host(body: Dict[str, Any]) -> Dict[str, Any]:
    host = body.get("host")
    return host if isinstance(host, dict) else {}


def extract_source(body: Dict[str, Any]) -> str:
    src = body.get("source")
    if isinstance(src, list):
        for s in src:
            if isinstance(s, str) and s.strip():
                return s.strip()
        return "filebeat"
    if isinstance(src, str) and src.strip():
        return src.strip()
    return "filebeat"


def extract_message(body: Dict[str, Any]) -> str:
    msg = body.get("message")
    if isinstance(msg, str) and msg.strip():
        return msg

    event = body.get("event")
    if isinstance(event, dict):
        eo = event.get("original")
        if isinstance(eo, str) and eo.strip():
            return eo

    log_obj = body.get("log")
    if isinstance(log_obj, dict):
        lo = log_obj.get("original")
        if isinstance(lo, str) and lo.strip():
            return lo

    return str(body)[:5000]


@router.post("/logs", status_code=202)
async def ingest_logs(request: Request, _=Depends(require_api_key)):
    incr("requests_total", 1)
    incr("auth_ok_total", 1)

    try:
        raw = await request.json()
    except Exception:
        incr("bad_json_total", 1)
        raise HTTPException(status_code=400, detail="Invalid JSON")

    body: Dict[str, Any] = raw if isinstance(raw, dict) else {"message": str(raw)}

    payload: Dict[str, Any] = {
        "@timestamp": body.get("@timestamp") or now_iso(),
        "event": {"type": "log"},
        "log": {"level": extract_log_level(body)},
        "service": {"name": extract_service_name(body)},
        "message": extract_message(body),
        "env": body.get("env", "dev"),
        "host": extract_host(body),
        "source": extract_source(body),
        "extra": body,
    }

    payload = enrich_event(payload)

    # ✅ enqueue بالـ envelope الصحيح
    enqueue("/logs", payload)

    incr("accepted_total", 1)

    # ✅ gauge optional (مرة واحدة)
    try:
        set_gauge("queue_len", queue_len())
    except Exception:
        pass

    return {"status": "queued"}
