import re
import hashlib
from collections import defaultdict

IP_REGEXES = [
    re.compile(r"\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b", re.IGNORECASE),
    re.compile(r"\brhost=(\d{1,3}(?:\.\d{1,3}){3})\b", re.IGNORECASE),
    re.compile(r"\bSRC=(\d{1,3}(?:\.\d{1,3}){3})\b", re.IGNORECASE),
    re.compile(r"\bsource\s+ip[:=]\s*(\d{1,3}(?:\.\d{1,3}){3})\b", re.IGNORECASE),
]

PORT_REGEXES = [
    re.compile(r"\bport\s+(\d{1,5})\b", re.IGNORECASE),
    re.compile(r"\bDPT=(\d{1,5})\b", re.IGNORECASE),
    re.compile(r"\bdst\s+port\s+(\d{1,5})\b", re.IGNORECASE),
    re.compile(r"\bdestination\s+port[:=]\s*(\d{1,5})\b", re.IGNORECASE),
]

def extract_ip(msg: str):
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

def make_dedup_key(rule_id: str, ip: str, window_minutes: int):
    raw = f"{rule_id}|{ip}|{window_minutes}"
    return hashlib.sha256(raw.encode()).hexdigest()

def pick_message(src: dict) -> str:
    payload = src.get("payload") or {}
    syslog = src.get("syslog") or {}
    return payload.get("message") or syslog.get("msg") or ""

def aggregate(hits, window_minutes: int, threshold_ports: int):
    """
    Port scan heuristic:
    - same IP hits many different destination ports within window
    """
    ports_by_ip = defaultdict(set)
    last_seen, samples = {}, {}

    for h in hits:
        src = h.get("_source", {})
        ts = src.get("@timestamp")
        msg = pick_message(src)
        if not msg:
            continue

        ip = extract_ip(msg)
        if not ip:
            continue

        port = extract_port(msg)
        if port:
            ports_by_ip[ip].add(port)

        last_seen[ip] = ts
        samples.setdefault(ip, msg[:300])

    incidents = []
    for ip, ports in ports_by_ip.items():
        if len(ports) < threshold_ports:
            continue

        incidents.append({
            "type": "port_scan",
            "source_ip": ip,
            "count": len(ports),
            "first_seen": None,
            "last_seen": last_seen[ip],
            "dedup_key": make_dedup_key("port_scan", ip, window_minutes),
            "evidence": {
                "unique_ports": sorted(list(ports))[:40],
                "sample_message": samples[ip],
                "window_minutes": window_minutes,
                "threshold_ports": threshold_ports,
            }
        })

    return incidents, len(ports_by_ip)
