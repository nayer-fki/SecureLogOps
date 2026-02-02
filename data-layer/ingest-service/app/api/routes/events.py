from fastapi import APIRouter, Depends
from app.schemas.security_event import SecurityEvent
from app.core.security import require_api_key
from app.services.normalizer import normalize_security_event
from app.services.enricher import enrich_event
from app.services.redis_queue import enqueue
from app.services.metrics_store import incr

router = APIRouter()

@router.post("/events")
def ingest_events(event: SecurityEvent, _=Depends(require_api_key)):
    incr("requests_total", 1)
    incr("auth_ok_total", 1)

    payload = normalize_security_event(event)
    payload = enrich_event(payload)

    enqueue({"endpoint": "/events", "payload": payload})
    incr("accepted_total", 1)

    return {"status": "queued"}
