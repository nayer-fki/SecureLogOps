import redis
from app.core.config import REDIS_URL

_client = None
PREFIX = "metrics:ingest"

def r():
    global _client
    if _client is None:
        _client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    return _client

def incr(name: str, n: int = 1):
    try:
        r().incrby(f"{PREFIX}:{name}", n)
    except Exception:
        pass

def set_gauge(name: str, value):
    try:
        r().set(f"{PREFIX}:{name}", value)
    except Exception:
        pass

def snapshot() -> dict:
    out = {}
    try:
        for k in r().scan_iter(f"{PREFIX}:*"):
            out[k.replace(f"{PREFIX}:", "")] = r().get(k)
    except Exception:
        pass
    return out
