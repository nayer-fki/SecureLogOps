import json
import redis
from typing import Any, Dict, List, Optional

from app.core.config import REDIS_URL, REDIS_QUEUE_KEY, REDIS_DLQ_KEY
from app.services.metrics_store import incr, set_gauge

# Singleton Redis client
_client: Optional[redis.Redis] = None


def get_redis() -> redis.Redis:
    """Return a singleton Redis client (sync)."""
    global _client
    if _client is None:
        _client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    return _client


def enqueue(endpoint: str, payload: Dict[str, Any]) -> None:
    """
    Push an envelope that the async worker expects:
    { "endpoint": "...", "payload": {...} }
    """
    r = get_redis()
    event = {"endpoint": endpoint, "payload": payload}
    r.rpush(REDIS_QUEUE_KEY, json.dumps(event))

    incr("queued_total", 1)
    set_gauge("queue_len", r.llen(REDIS_QUEUE_KEY))


def push_dlq(event: Dict[str, Any], error: str) -> None:
    """Push event to DLQ with error context."""
    r = get_redis()
    event["_error"] = error
    r.rpush(REDIS_DLQ_KEY, json.dumps(event))

    incr("dlq_total", 1)
    set_gauge("dlq_len", r.llen(REDIS_DLQ_KEY))


def queue_len() -> int:
    """Return current queue length (for API & health checks)."""
    r = get_redis()
    return int(r.llen(REDIS_QUEUE_KEY))


def dlq_len() -> int:
    """Return current DLQ length."""
    r = get_redis()
    return int(r.llen(REDIS_DLQ_KEY))


def dequeue_batch(max_items: int = 50) -> List[Dict[str, Any]]:
    """
    Pop a batch from Redis queue (sync utility).
    NOTE: Your async worker uses LPOP directly, so this is optional.
    """
    r = get_redis()
    items: List[Dict[str, Any]] = []

    for _ in range(max_items):
        raw = r.lpop(REDIS_QUEUE_KEY)
        if raw is None:
            break
        try:
            items.append(json.loads(raw))
        except Exception:
            # if corrupted item, drop it (or push to DLQ if you want)
            incr("bad_queue_item_total", 1)

    set_gauge("queue_len", r.llen(REDIS_QUEUE_KEY))
    incr("worker_processed_total", len(items))
    return items
