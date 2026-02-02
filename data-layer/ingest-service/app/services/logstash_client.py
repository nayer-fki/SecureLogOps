import requests
from app.core.config import LOGSTASH_BASE_URL, USE_REDIS_BUFFER
from app.services.redis_queue import enqueue

class LogstashError(RuntimeError):
    pass

def forward_to_logstash(payload: dict, endpoint: str = "/logs"):
    """
    Sends payload to Logstash HTTP input.
    If Logstash down and Redis buffer enabled => enqueue.
    """
    url = f"{LOGSTASH_BASE_URL.rstrip('/')}{endpoint}"
    try:
        resp = requests.post(url, json=payload, timeout=5)
        if resp.status_code >= 400:
            raise LogstashError(f"Logstash responded {resp.status_code}: {resp.text[:200]}")
    except Exception as ex:
        if USE_REDIS_BUFFER:
            # store for later (simple buffer)
            enqueue({"endpoint": endpoint, "payload": payload})
            return
        raise LogstashError(str(ex))
