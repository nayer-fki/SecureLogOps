import os
import time
import re
import hashlib
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import requests
from pymongo import MongoClient, ASCENDING

# ===================== CONFIG =====================
ES_URL = os.getenv("ES_URL", "http://elasticsearch:9200")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASS = os.getenv("ES_PASS", "ChangeMe_Elastic123!")

MONGO_URI = os.getenv(
    "MONGO_URI",
    "mongodb://admin:ChangeMe_Mongo123!@mongodb:27017/?authSource=admin"
)
MONGO_DB = os.getenv("MONGO_DB", "securelogops")

INDEX_PATTERN = os.getenv("ES_INDEX", "logs-*")
WINDOW_MINUTES = int(os.getenv("WINDOW_MINUTES", "5"))
POLL_SECONDS = int(os.getenv("POLL_SECONDS", "10"))
AUTO_CLOSE_MINUTES = int(os.getenv("AUTO_CLOSE_MINUTES", "10"))

DEBUG = os.getenv("DEBUG", "true").lower() in ("1", "true", "yes")

# ---- SSH Bruteforce rule
FAILED_PHRASE = os.getenv("FAILED_PHRASE", "Failed password")
SSH_THRESHOLD = int(os.getenv("SSH_THRESHOLD", "10"))

# ---- Port-scan rule
PORTSCAN_THRESHOLD_PORTS = int(os.getenv("PORTSCAN_THRESHOLD_PORTS", "15"))

# ---- Wazuh integration
SECURITY_SERVICE_URL = os.getenv("SECURITY_SERVICE_URL", "http://security-service:8003").rstrip("/")
SECURITY_API_KEY = os.getenv("SECURITY_API_KEY", "ChangeMe_Security123!")
WAZUH_SUMMARY_PATH = os.getenv("WAZUH_SUMMARY_PATH", "/alerts/summary")

# ---- Enrichment (cache ok)
WAZUH_ENRICH = os.getenv("WAZUH_ENRICH", "true").lower() in ("1", "true", "yes")
WAZUH_ENRICH_TTL = int(os.getenv("WAZUH_ENRICH_TTL", "60"))  # seconds
WAZUH_ENRICH_BACKFILL = os.getenv("WAZUH_ENRICH_BACKFILL", "false").lower() in ("1", "true", "yes")
WAZUH_ENRICH_LOOKBACK_HOURS = int(os.getenv("WAZUH_ENRICH_LOOKBACK_HOURS", "24"))

# ---- Phase 3.3 Delta spike (PRO+)
WAZUH_DELTA_ENABLED = os.getenv("WAZUH_DELTA_ENABLED", "true").lower() in ("1", "true", "yes")
WAZUH_DELTA_MIN = int(os.getenv("WAZUH_DELTA_MIN", "20"))
WAZUH_DELTA_WINDOW_SECONDS = int(os.getenv("WAZUH_DELTA_WINDOW_SECONDS", "300"))
WAZUH_DELTA_SPAM_SECONDS = int(os.getenv("WAZUH_DELTA_SPAM_SECONDS", "30"))  # spam guard
WAZUH_DELTA_FORCE_FRESH = os.getenv("WAZUH_DELTA_FORCE_FRESH", "true").lower() in ("1", "true", "yes")

# ---- Scoring weights (0..100)
W_ATTEMPT = float(os.getenv("W_ATTEMPT", "3.0"))
W_DENSITY = float(os.getenv("W_DENSITY", "20.0"))
W_BONUS = float(os.getenv("W_BONUS", "10.0"))

S_LOW = int(os.getenv("S_LOW", "25"))
S_MED = int(os.getenv("S_MED", "50"))
S_HIGH = int(os.getenv("S_HIGH", "80"))

# ---- cooldown (spam guard for sending incidents)
INCIDENT_COOLDOWN_SECONDS = int(os.getenv("INCIDENT_COOLDOWN_SECONDS", "60"))

# ---- incident-service (Phase 4.1.1)
INCIDENT_URL = os.getenv("INCIDENT_URL", "http://incident-service:8000").rstrip("/")
INCIDENT_INTERNAL_KEY = os.getenv("INCIDENT_INTERNAL_KEY", "ChangeMe_Internal123!")
INCIDENT_TIMEOUT = int(os.getenv("INCIDENT_TIMEOUT", "5"))

IP_REGEXES = [
    re.compile(r"\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b"),
    re.compile(r"\brhost=(\d{1,3}(?:\.\d{1,3}){3})\b"),
    re.compile(r"\bSRC=(\d{1,3}(?:\.\d{1,3}){3})\b"),
]
PORT_REGEXES = [
    re.compile(r"\bport\s+(\d{1,5})\b"),
    re.compile(r"\bdpt=(\d{1,5})\b"),
]

# ===================== LOGGING =====================
def log(msg: str):
    print(msg, flush=True)

# ===================== MONGO INDEXES =====================
def ensure_indexes(db):
    # ✅ IMPORTANT: do NOT create dedup_key unique index anymore (it was removed)
    db.state.create_index([("updated_at", ASCENDING)])

# ===================== INCIDENT SERVICE CLIENT =====================
def incident_upsert(payload: dict) -> dict | None:
    try:
        r = requests.post(
            f"{INCIDENT_URL}/internal/incidents/upsert",
            json=payload,
            headers={"X-Internal-Api-Key": INCIDENT_INTERNAL_KEY},
            timeout=INCIDENT_TIMEOUT,
        )
        if r.status_code >= 400:
            log(f"[incident-api] upsert failed {r.status_code}: {r.text[:200]}")
            return None
        return r.json()
    except Exception as e:
        log(f"[incident-api] upsert exception: {e}")
        return None

def compute_fingerprint(type_: str, source_ip: str | None, title: str) -> str:
    base = f"{type_}|{source_ip or 'none'}|{title}".lower().strip()
    return hashlib.sha1(base.encode("utf-8")).hexdigest()

# ===================== ELASTIC =====================
def es_search(body: dict) -> dict:
    r = requests.get(
        f"{ES_URL}/{INDEX_PATTERN}/_search",
        auth=(ES_USER, ES_PASS),
        headers={"Content-Type": "application/json"},
        json=body,
        timeout=30,
    )
    if r.status_code >= 400:
        raise Exception(r.text)
    return r.json()

def pick_message(src: dict) -> str:
    # ✅ new normalized schema (logstash)
    msg = src.get("message")
    if isinstance(msg, str) and msg.strip():
        return msg

    # sometimes event.original exists
    ev = src.get("event", {}) or {}
    original = ev.get("original")
    if isinstance(original, str) and original.strip():
        return original

    # ✅ legacy schemas
    payload = src.get("payload") or {}
    syslog = src.get("syslog") or {}

    msg = payload.get("message") or syslog.get("msg")

    # sometimes payload.extra.message
    if not msg:
        extra = payload.get("extra") or {}
        msg = extra.get("message")

    return msg or ""

def extract_ip_from_src(src: dict, msg: str):
    # ✅ structured (preferred)
    source = src.get("source") or {}
    ip = source.get("ip")
    if isinstance(ip, str) and ip:
        return ip

    # fallback: parse from message
    for rgx in IP_REGEXES:
        m = rgx.search(msg)
        if m:
            return m.group(1)
    return None

def extract_port(msg: str):
    for rgx in PORT_REGEXES:
        m = rgx.search(msg)
        if m:
            return m.group(1)
    return None

def fetch_window_docs(now_utc: datetime):
    gte = (now_utc - timedelta(minutes=WINDOW_MINUTES)).isoformat()
    lte = now_utc.isoformat()
    body = {
        "size": 2000,
        "sort": [{"@timestamp": "desc"}],
        "_source": [
            "@timestamp",
            "message",
            "event.original",
            "payload",
            "syslog",
            "host",
            "service",
            "source",
            "user",
            "event.action",
            "event.outcome",
            "tags",
        ],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": gte, "lte": lte}}}
                ]
            }
        }
    }
    return es_search(body).get("hits", {}).get("hits", [])

# ===================== SCORING =====================
def clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))

def compute_score(attempts: int, window_minutes: int, bonus_threshold: int) -> int:
    density = attempts / max(1, window_minutes)
    score = 0.0
    score += attempts * W_ATTEMPT
    score += density * W_DENSITY
    if attempts >= bonus_threshold:
        score += W_BONUS
    return int(clamp(score, 0, 100))

def score_to_severity(score: int) -> str:
    if score >= S_HIGH: return "critical"
    if score >= S_MED:  return "high"
    if score >= S_LOW:  return "medium"
    return "low"

# ===================== WAZUH SUMMARY =====================
_wazuh_cache = {"ts": 0, "data": None}

def fetch_wazuh_summary() -> dict | None:
    url = f"{SECURITY_SERVICE_URL}{WAZUH_SUMMARY_PATH}"
    r = requests.get(url, headers={"x-api-key": SECURITY_API_KEY}, timeout=15)
    if r.status_code != 200:
        raise Exception(f"security-service {r.status_code}: {r.text[:200]}")
    data = r.json()
    return {
        "source_mode": data.get("source_mode"),
        "period": data.get("period"),
        "total_alerts": int(data.get("total_alerts", 0) or 0),
        "by_severity": data.get("by_severity", {}),
        "top_rules": data.get("top_rules", []),
        "top_agents": data.get("top_agents", []),
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }

def get_wazuh_summary_cached(force_fresh: bool = False):
    if not WAZUH_ENRICH and not WAZUH_DELTA_ENABLED:
        return None

    if force_fresh:
        try:
            return fetch_wazuh_summary()
        except Exception as e:
            if DEBUG:
                log(f"[wazuh] force fetch failed: {e}")
            return None

    now = int(time.time())
    if _wazuh_cache["data"] is not None and (now - _wazuh_cache["ts"]) < WAZUH_ENRICH_TTL:
        return _wazuh_cache["data"]

    try:
        ctx = fetch_wazuh_summary()
        _wazuh_cache["ts"] = now
        _wazuh_cache["data"] = ctx
        return ctx
    except Exception as e:
        if DEBUG:
            log(f"[wazuh] fetch failed: {e}")
        _wazuh_cache["ts"] = now
        _wazuh_cache["data"] = None
        return None

# ===================== COOLDOWN (state collection) =====================
def allow_upsert_now(db, fingerprint: str, now: datetime) -> bool:
    key = f"cooldown:{fingerprint}"
    doc = db.state.find_one({"_id": key}, {"last_sent_at": 1})
    if not doc or not doc.get("last_sent_at"):
        return True
    try:
        last = datetime.fromisoformat(doc["last_sent_at"].replace("Z", "+00:00"))
    except Exception:
        return True
    return (now - last).total_seconds() >= INCIDENT_COOLDOWN_SECONDS

def mark_sent(db, fingerprint: str, now: datetime):
    key = f"cooldown:{fingerprint}"
    db.state.update_one(
        {"_id": key},
        {"$set": {"last_sent_at": now.isoformat(), "updated_at": now.isoformat()}},
        upsert=True
    )

# ===================== RULES (LOG-BASED) =====================
def rule_ssh_bruteforce(now: datetime, docs: list, wazuh_ctx: dict | None, db):
    matched = []
    for h in docs:
        src = h.get("_source", {})
        msg = pick_message(src)
        if FAILED_PHRASE in msg:
            matched.append(h)

    if DEBUG:
        log(f"[rule:ssh_bruteforce] matched_docs={len(matched)}")

    counts = defaultdict(int)
    first_seen, last_seen, samples = {}, {}, {}

    for h in matched:
        src = h.get("_source", {})
        ts = src.get("@timestamp")
        msg = pick_message(src)
        ip = extract_ip_from_src(src, msg)
        if not ip:
            continue
        counts[ip] += 1
        first_seen.setdefault(ip, ts)
        last_seen[ip] = ts
        samples.setdefault(ip, msg[:300])

    if DEBUG:
        log(f"[rule:ssh_bruteforce] extracted_ips={len(counts)}")

    incidents = 0
    TITLE = "SSH brute force detected"

    for ip, cnt in counts.items():
        if cnt < SSH_THRESHOLD:
            continue

        score = compute_score(cnt, WINDOW_MINUTES, bonus_threshold=SSH_THRESHOLD * 2)
        severity = score_to_severity(score)

        fingerprint = compute_fingerprint("ssh_bruteforce", ip, TITLE)
        if not allow_upsert_now(db, fingerprint, now):
            continue

        payload = {
            "type": "ssh_bruteforce",
            "severity": severity,
            "title": TITLE,
            "description": f"Multiple failed logins from {ip} (count={cnt} in {WINDOW_MINUTES}m)",
            "source": {"ip": ip, "host": None, "user": None},
            "tags": ["ssh", "auth"],
            "fingerprint": fingerprint,
            "evidence": {
                "logs": [{
                    "sample_message": samples.get(ip),
                    "first_seen": first_seen.get(ip),
                    "last_seen": last_seen.get(ip),
                    "count": cnt,
                    "search_phrase": FAILED_PHRASE,
                    "index_pattern": INDEX_PATTERN,
                }],
                "wazuh": (wazuh_ctx or {}) if WAZUH_ENRICH else {},
                "metrics": {
                    "score": score,
                    "window_minutes": WINDOW_MINUTES,
                    "threshold": SSH_THRESHOLD,
                },
            },
        }

        out = incident_upsert(payload)
        if out and out.get("id"):
            mark_sent(db, fingerprint, now)
            incidents += 1
            log(f"[incident-api] upserted type=ssh_bruteforce ip={ip} id={out.get('id')} severity={severity} score={score}")

    if DEBUG:
        log(f"[rule:ssh_bruteforce] incidents={incidents}")

def rule_port_scan(now: datetime, docs: list, wazuh_ctx: dict | None, db):
    ports_by_ip = defaultdict(set)
    sample_by_ip = {}

    for h in docs:
        src = h.get("_source", {})
        msg = pick_message(src)
        ip = extract_ip_from_src(src, msg)
        port = extract_port(msg)
        if not ip or not port:
            continue
        ports_by_ip[ip].add(port)
        sample_by_ip.setdefault(ip, msg[:300])

    incidents = 0
    extracted = len(ports_by_ip)
    TITLE = "Port scan detected"

    for ip, ports in ports_by_ip.items():
        if len(ports) < PORTSCAN_THRESHOLD_PORTS:
            continue

        cnt = len(ports)
        score = compute_score(cnt, WINDOW_MINUTES, bonus_threshold=PORTSCAN_THRESHOLD_PORTS)
        severity = score_to_severity(score)

        fingerprint = compute_fingerprint("port_scan", ip, TITLE)
        if not allow_upsert_now(db, fingerprint, now):
            continue

        payload = {
            "type": "port_scan",
            "severity": severity,
            "title": TITLE,
            "description": f"Multiple unique ports scanned from {ip} (ports={cnt} in {WINDOW_MINUTES}m)",
            "source": {"ip": ip, "host": None, "user": None},
            "tags": ["scan", "network"],
            "fingerprint": fingerprint,
            "evidence": {
                "logs": [{
                    "unique_ports": sorted(list(ports), key=lambda x: int(x)),
                    "sample_message": sample_by_ip.get(ip),
                    "index_pattern": INDEX_PATTERN,
                    "window_minutes": WINDOW_MINUTES,
                    "threshold_ports": PORTSCAN_THRESHOLD_PORTS,
                }],
                "wazuh": (wazuh_ctx or {}) if WAZUH_ENRICH else {},
                "metrics": {
                    "score": score,
                    "ports_count": cnt,
                },
            },
        }

        out = incident_upsert(payload)
        if out and out.get("id"):
            mark_sent(db, fingerprint, now)
            incidents += 1
            log(f"[incident-api] upserted type=port_scan ip={ip} id={out.get('id')} severity={severity} score={score}")

    if DEBUG:
        log(f"[rule:port_scan] extracted_ips={extracted} incidents={incidents}")

# ===================== PHASE 3.3 PRO+ (DELTA SPIKE) =====================
def rule_wazuh_delta_spike(now: datetime, wazuh_ctx_fresh: dict | None, db):
    if not (WAZUH_DELTA_ENABLED and wazuh_ctx_fresh):
        return

    total_now = int(wazuh_ctx_fresh.get("total_alerts", 0))
    now_ts = int(time.time())

    state_id = "wazuh_summary_total"
    state = db.state.find_one({"_id": state_id}) or {}

    last_total = int(state.get("last_total", 0) or 0)
    last_ts = int(state.get("last_ts", 0) or 0)
    last_seen_spike_ts = int(state.get("last_seen_spike_ts", 0) or 0)

    # baseline on first run
    if last_ts == 0:
        db.state.update_one(
            {"_id": state_id},
            {"$set": {
                "last_total": total_now,
                "last_ts": now_ts,
                "last_seen_spike_ts": last_seen_spike_ts,
                "updated_at": now.isoformat(),
            }},
            upsert=True
        )
        if DEBUG:
            log(f"[wazuh:delta] baseline saved total={total_now}")
        return

    dt = now_ts - last_ts
    if dt <= 0:
        return

    delta = total_now - last_total

    # always update baseline
    db.state.update_one(
        {"_id": state_id},
        {"$set": {
            "last_total": total_now,
            "last_ts": now_ts,
            "updated_at": now.isoformat(),
        }},
        upsert=True
    )

    if dt > WAZUH_DELTA_WINDOW_SECONDS:
        if DEBUG:
            log(f"[wazuh:delta] skipped dt={dt}s > window={WAZUH_DELTA_WINDOW_SECONDS}s (delta={delta})")
        return

    if delta < WAZUH_DELTA_MIN:
        if DEBUG:
            log(f"[wazuh:delta] no spike delta={delta} < {WAZUH_DELTA_MIN} (dt={dt}s)")
        return

    if last_seen_spike_ts and (now_ts - last_seen_spike_ts) < WAZUH_DELTA_SPAM_SECONDS:
        if DEBUG:
            log(f"[wazuh:delta] spam-guard skip (since_last_spike={now_ts-last_seen_spike_ts}s < {WAZUH_DELTA_SPAM_SECONDS}s) delta={delta}")
        return

    db.state.update_one(
        {"_id": state_id},
        {"$set": {"last_seen_spike_ts": now_ts, "updated_at": now.isoformat()}},
        upsert=True
    )

    TITLE = "Wazuh alert delta spike"
    fingerprint = compute_fingerprint("wazuh_alert_delta_spike", None, TITLE)

    if not allow_upsert_now(db, fingerprint, now):
        return

    ratio = delta / max(1, WAZUH_DELTA_MIN)
    score = int(clamp(50 + ratio * 30, 0, 100))
    severity = score_to_severity(score)

    payload = {
        "type": "wazuh_alert_delta_spike",
        "severity": severity,
        "title": TITLE,
        "description": f"Delta spike detected: delta={delta} in dt={dt}s (total_now={total_now})",
        "source": {"ip": None, "host": "wazuh", "user": None},
        "tags": ["wazuh", "alerts", "spike"],
        "fingerprint": fingerprint,
        "evidence": {
            "logs": [{
                "delta": delta,
                "dt_seconds": dt,
                "total_now": total_now,
                "total_prev": last_total,
                "ts": now.isoformat(),
            }],
            "wazuh": wazuh_ctx_fresh,
            "metrics": {
                "score": score,
                "delta_min": WAZUH_DELTA_MIN,
                "delta_window_seconds": WAZUH_DELTA_WINDOW_SECONDS,
                "spam_guard_seconds": WAZUH_DELTA_SPAM_SECONDS,
            },
        },
    }

    out = incident_upsert(payload)
    if out and out.get("id"):
        mark_sent(db, fingerprint, now)
        log(f"[incident-api] upserted type=wazuh_alert_delta_spike id={out.get('id')} delta={delta} severity={severity} score={score}")

# ===================== MAIN =====================
def main():
    log("[correlation] booting ...")
    log(f"[correlation] INDEX={INDEX_PATTERN} WINDOW={WINDOW_MINUTES} POLL={POLL_SECONDS}s AUTO_CLOSE={AUTO_CLOSE_MINUTES}m")
    log(f"[correlation] ssh phrase='{FAILED_PHRASE}' ssh_threshold={SSH_THRESHOLD}")
    log(f"[correlation] portscan_threshold_ports={PORTSCAN_THRESHOLD_PORTS}")
    log(f"[correlation] security_service={SECURITY_SERVICE_URL} wazuh_summary={WAZUH_SUMMARY_PATH}")
    log(f"[correlation] enrich={WAZUH_ENRICH} ttl={WAZUH_ENRICH_TTL}s backfill={WAZUH_ENRICH_BACKFILL} lookback_h={WAZUH_ENRICH_LOOKBACK_HOURS}")
    log(f"[correlation] delta_enabled={WAZUH_DELTA_ENABLED} delta_min={WAZUH_DELTA_MIN} delta_window={WAZUH_DELTA_WINDOW_SECONDS}s spam_guard={WAZUH_DELTA_SPAM_SECONDS}s")
    log(f"[correlation] incident cooldown={INCIDENT_COOLDOWN_SECONDS}s")
    log(f"[correlation] incident_service={INCIDENT_URL}")

    mongo = MongoClient(MONGO_URI)
    db = mongo[MONGO_DB]
    ensure_indexes(db)
    log("[correlation] connected to Mongo ✅")

    while True:
        now = datetime.now(timezone.utc)
        try:
            docs = fetch_window_docs(now)
            if DEBUG:
                log(f"[correlation] window_docs={len(docs)}")

            wazuh_ctx_cached = get_wazuh_summary_cached(force_fresh=False)
            wazuh_ctx_fresh = get_wazuh_summary_cached(force_fresh=WAZUH_DELTA_FORCE_FRESH)

            rule_ssh_bruteforce(now, docs, wazuh_ctx_cached, db)
            rule_port_scan(now, docs, wazuh_ctx_cached, db)
            rule_wazuh_delta_spike(now, wazuh_ctx_fresh, db)

        except Exception as e:
            log(f"[correlation] error: {e}")

        time.sleep(POLL_SECONDS)

if __name__ == "__main__":
    main()
