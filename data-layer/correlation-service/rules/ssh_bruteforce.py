import re
import hashlib
from collections import defaultdict
from datetime import datetime, timedelta

IP_REGEXES = [
    re.compile(r"\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b"),
    re.compile(r"\brhost=(\d{1,3}(?:\.\d{1,3}){3})\b"),
    re.compile(r"\bSRC=(\d{1,3}(?:\.\d{1,3}){3})\b"),
]

def extract_ip(msg: str):
    for rgx in IP_REGEXES:
        m = rgx.search(msg)
        if m:
            return m.group(1)
    return None

def make_dedup_key(rule_id: str, ip: str, window_minutes: int):
    raw = f"{rule_id}|{ip}|{window_minutes}"
    return hashlib.sha256(raw.encode()).hexdigest()

def build_es_query(phrase: str, window_minutes: int, now_iso: str):
    # now_iso is ISO string of now UTC (timezone-aware)
    # use now-<window> minutes in python side
    return {
        "size": 2000,
        "sort": [{"@timestamp": "desc"}],
        "_source": ["@timestamp", "payload", "syslog"],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": now_iso["gte"], "lte": now_iso["lte"]}}}
                ],
                "should": [
                    {"match_phrase": {"payload.message": phrase}},
                    {"match_phrase": {"syslog.msg": phrase}},
                ],
                "minimum_should_match": 1,
            }
        },
    }

def pick_message(src: dict) -> str:
    payload = src.get("payload") or {}
    syslog = src.get("syslog") or {}
    return payload.get("message") or syslog.get("msg") or ""

def aggregate(hits, phrase: str, window_minutes: int, threshold: int):
    """
    returns list of incidents candidates:
      {ip, count, first_seen, last_seen, sample_message, dedup_key, type}
    """
    counts = defaultdict(int)
    first_seen, last_seen, samples = {}, {}, {}

    for h in hits:
        src = h.get("_source", {})
        ts = src.get("@timestamp")
        msg = pick_message(src)
        ip = extract_ip(msg)
        if not ip:
            continue

        counts[ip] += 1
        first_seen.setdefault(ip, ts)
        last_seen[ip] = ts
        samples.setdefault(ip, msg[:300])

    incidents = []
    for ip, cnt in counts.items():
        if cnt < threshold:
            continue

        incidents.append({
            "type": "ssh_bruteforce",
            "source_ip": ip,
            "count": cnt,
            "first_seen": first_seen[ip],
            "last_seen": last_seen[ip],
            "dedup_key": make_dedup_key("ssh_bruteforce", ip, window_minutes),
            "evidence": {
                "sample_message": samples[ip],
                "search_phrase": phrase,
                "window_minutes": window_minutes,
                "threshold": threshold,
            }
        })

    return incidents, len(counts)
