from datetime import datetime, timezone
from app.schemas.log_event import LogEvent
from app.schemas.metric_event import MetricEvent
from app.schemas.security_event import SecurityEvent

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def normalize_log(e: LogEvent) -> dict:
    return {
        "@timestamp": now_iso(),
        "event": {"type": "log"},
        "log": {"level": e.level.upper()},
        "service": {"name": e.service},
        "message": e.message,
        "env": e.env,
        "host": {"name": e.host} if e.host else {},
        "source": e.source,
        "extra": e.extra or {},
    }

def normalize_metric(e: MetricEvent) -> dict:
    return {
        "@timestamp": now_iso(),
        "event": {"type": "metric"},
        "service": {"name": e.service},
        "env": e.env,
        "host": {"name": e.host} if e.host else {},
        "metrics": e.metrics,
        "source": e.source,
    }

def normalize_security_event(e: SecurityEvent) -> dict:
    return {
        "@timestamp": now_iso(),
        "event": {"type": "security"},
        "service": {"name": e.service},
        "env": e.env,
        "host": {"name": e.host} if e.host else {},
        "security": {
            "severity": e.severity.upper(),
            "category": e.category.lower(),
            "src_ip": e.src_ip,
            "dst_ip": e.dst_ip,
        },
        "message": e.message,
        "extra": e.extra or {},
    }
