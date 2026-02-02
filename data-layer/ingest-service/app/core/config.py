import os

def env_bool(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).lower() in ("1", "true", "yes", "on")

APP_ENV = os.getenv("APP_ENV", "dev")

API_KEY = os.getenv("INGEST_API_KEY", "ChangeMe_IngestKey")

LOGSTASH_BASE_URL = os.getenv("LOGSTASH_BASE_URL", "http://logstash:8080")

USE_REDIS_BUFFER = env_bool("USE_REDIS_BUFFER", "true")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

# Redis queue keys (List)
REDIS_QUEUE_KEY = os.getenv("REDIS_QUEUE_KEY", "ingest:queue")
REDIS_DLQ_KEY = os.getenv("REDIS_DLQ_KEY", "ingest:dlq")

# Worker settings (optional, used in main.py/worker.py)
WORKER_ENABLED = env_bool("WORKER_ENABLED", "true")
WORKER_CONCURRENCY = int(os.getenv("WORKER_CONCURRENCY", "1"))

MAX_RETRIES = int(os.getenv("MAX_RETRIES", "8"))
BASE_BACKOFF_MS = int(os.getenv("BASE_BACKOFF_MS", "250"))
