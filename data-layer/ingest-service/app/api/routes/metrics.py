from fastapi import APIRouter, Depends
from app.schemas.metric_event import MetricEvent
from app.core.security import require_api_key
from app.services.normalizer import normalize_metric
from app.services.enricher import enrich_event
from app.services.redis_queue import enqueue
from app.services.metrics_store import incr, snapshot

router = APIRouter()

@router.post("/metrics")
def ingest_metrics(event: MetricEvent, _=Depends(require_api_key)):
    incr("requests_total", 1)
    incr("auth_ok_total", 1)

    payload = normalize_metric(event)
    payload = enrich_event(payload)

    enqueue({"endpoint": "/metrics", "payload": payload})
    incr("accepted_total", 1)

    return {"status": "queued"}

@router.get("/metrics")
def get_metrics():
    return snapshot()
