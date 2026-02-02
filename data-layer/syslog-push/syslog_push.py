import os
import time
import socket
import threading
import subprocess
from typing import List

import requests
import redis  # ✅ NEW

URL = os.getenv("INGEST_URL", "http://ingest-service:8000/logs")
KEY = os.getenv("INGEST_API_KEY", "ChangeMe_IngestKey_123")

APP_ENV = os.getenv("APP_ENV", "dev")
SLEEP_SEC = float(os.getenv("SLEEP_SEC", "0.2"))
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "3"))
START_FROM_END = os.getenv("START_FROM_END", "1") == "1"

LOG_PATHS_RAW = os.getenv("LOG_PATHS", "/host/var/log/syslog")
LOG_PATHS = [p.strip() for p in LOG_PATHS_RAW.split(",") if p.strip()]

ENABLE_JOURNALD = os.getenv("ENABLE_JOURNALD", "0") == "1"
HOSTNAME = os.getenv("HOSTNAME_OVERRIDE") or socket.gethostname()

HEADERS = {"X-API-Key": KEY}

session = requests.Session()
session.headers.update(HEADERS)

# =========================
# ✅ METRICS (Redis)
# =========================
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "0"))
METRICS_PREFIX = os.getenv("METRICS_PREFIX", "metrics:syslog-push")
SUMMARY_EVERY_S = int(os.getenv("SUMMARY_EVERY_S", "10"))

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)

def mkey(name: str) -> str:
    return f"{METRICS_PREFIX}:{name}"

def now_ts() -> int:
    return int(time.time())

def incr(name: str, val: int = 1) -> None:
    try:
        r.incrby(mkey(name), val)
    except Exception:
        # ما نحبوش metrics تطيّح الخدمة
        pass

def setv(name: str, val) -> None:
    try:
        r.set(mkey(name), val)
    except Exception:
        pass

def set_error(err: str) -> None:
    # نخزنو آخر error مختصر
    setv("last_error", (err or "")[:300])

def get_int(name: str) -> int:
    try:
        v = r.get(mkey(name))
        return int(v) if v and str(v).isdigit() else 0
    except Exception:
        return 0

def heartbeat_loop():
    while True:
        setv("last_heartbeat_ts", now_ts())
        time.sleep(5)

def summary_loop():
    prev = {
        "read": get_int("lines_read_total"),
        "sent": get_int("lines_sent_total"),
        "fail": get_int("lines_failed_total"),
    }
    while True:
        time.sleep(SUMMARY_EVERY_S)
        read_now = get_int("lines_read_total")
        sent_now = get_int("lines_sent_total")
        fail_now = get_int("lines_failed_total")

        d_read = read_now - prev["read"]
        d_sent = sent_now - prev["sent"]
        d_fail = fail_now - prev["fail"]

        prev["read"], prev["sent"], prev["fail"] = read_now, sent_now, fail_now

        print(
            f"[syslog-push][summary] +{d_read} read, +{d_sent} sent, +{d_fail} failed | "
            f"total read={read_now} sent={sent_now} failed={fail_now}",
            flush=True
        )

# =========================
# Core logic
# =========================
def post_log(message: str, source: str, level: str = "INFO", service: str = "host-logs") -> bool:
    payload = {
        "level": level,
        "service": service,
        "message": message,
        "env": APP_ENV,
        "host": HOSTNAME,
        "source_file": source,
    }

    try:
        resp = session.post(URL, json=payload, timeout=HTTP_TIMEOUT)

        if resp.status_code == 401:
            incr("auth_401_total", 1)
            incr("lines_failed_total", 1)
            set_error("401 Unauthorized (check INGEST_API_KEY)")
            print(f"[AUTH] 401 Unauthorized. Check INGEST_API_KEY. source={source}", flush=True)
            return False

        if 400 <= resp.status_code < 500:
            incr("http_4xx_total", 1)
            incr("lines_failed_total", 1)
            set_error(f"HTTP {resp.status_code} 4xx: {resp.text[:120]}")
            print(f"[HTTP] status={resp.status_code} source={source} body={resp.text[:120]}", flush=True)
            return False

        if resp.status_code >= 500:
            incr("http_5xx_total", 1)
            incr("lines_failed_total", 1)
            set_error(f"HTTP {resp.status_code} 5xx: {resp.text[:120]}")
            print(f"[HTTP] status={resp.status_code} source={source} body={resp.text[:120]}", flush=True)
            return False

        # ✅ success
        incr("lines_sent_total", 1)
        setv("last_send_ts", now_ts())
        return True

    except Exception as e:
        incr("post_exceptions_total", 1)
        incr("lines_failed_total", 1)
        set_error(repr(e))
        print(f"[ERR] post failed source={source} err={repr(e)}", flush=True)
        return False

def follow_file(path: str):
    # wait for file to appear
    waited = 0
    while not os.path.exists(path):
        if waited == 0:
            print(f"[WARN] file not found yet: {path} (waiting...)", flush=True)
            incr("file_waiting_total", 1)
        time.sleep(1)
        waited += 1
        if waited % 30 == 0:
            print(f"[WARN] still waiting for: {path}", flush=True)
            incr("file_waiting_total", 1)

    print(f"[OK] watching file: {path}", flush=True)
    incr("watched_files_up", 1)

    with open(path, "r", errors="ignore") as f:
        if START_FROM_END:
            f.seek(0, 2)
        else:
            f.seek(0)

        backoff = 0.2
        while True:
            line = f.readline()
            if not line:
                time.sleep(SLEEP_SEC)
                continue

            msg = line.strip()
            if not msg:
                continue

            # ✅ metrics read
            incr("lines_read_total", 1)
            setv("last_read_ts", now_ts())

            ok = post_log(msg, source=path, level="INFO", service="host-logs")
            if not ok:
                time.sleep(backoff)
                backoff = min(backoff * 2, 5.0)
            else:
                backoff = 0.2

def journald_available() -> bool:
    try:
        subprocess.run(["journalctl", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except Exception:
        return False

def follow_journald():
    if not journald_available():
        print("[WARN] ENABLE_JOURNALD=1 but journalctl not found inside container.", flush=True)
        print("[HINT] Install systemd/journalctl in Dockerfile OR keep ENABLE_JOURNALD=0.", flush=True)
        return

    print("[OK] watching journald: journalctl -f -o short-iso", flush=True)
    p = subprocess.Popen(
        ["journalctl", "-f", "-o", "short-iso"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        universal_newlines=True,
    )

    backoff = 0.2
    try:
        assert p.stdout is not None
        for line in p.stdout:
            msg = line.strip()
            if not msg:
                continue

            # ✅ metrics read (journald)
            incr("lines_read_total", 1)
            setv("last_read_ts", now_ts())

            ok = post_log(msg, source="journald", level="INFO", service="journald")
            if not ok:
                time.sleep(backoff)
                backoff = min(backoff * 2, 5.0)
            else:
                backoff = 0.2
    finally:
        try:
            p.terminate()
        except Exception:
            pass

def main():
    print("=== syslog-push starting ===", flush=True)
    print(f"INGEST_URL={URL}", flush=True)
    print(f"APP_ENV={APP_ENV}", flush=True)
    print(f"HOST={HOSTNAME}", flush=True)
    print(f"LOG_PATHS={LOG_PATHS}", flush=True)
    print(f"ENABLE_JOURNALD={ENABLE_JOURNALD}", flush=True)
    print(f"REDIS={REDIS_HOST}:{REDIS_PORT} DB={REDIS_DB}", flush=True)
    print(f"METRICS_PREFIX={METRICS_PREFIX}", flush=True)
    print("============================", flush=True)

    # init timestamps
    setv("last_read_ts", now_ts())
    setv("last_send_ts", now_ts())
    setv("last_heartbeat_ts", now_ts())

    # ✅ start metrics loops
    threading.Thread(target=heartbeat_loop, daemon=True).start()
    threading.Thread(target=summary_loop, daemon=True).start()

    threads: List[threading.Thread] = []

    for path in LOG_PATHS:
        t = threading.Thread(target=follow_file, args=(path,), daemon=True)
        t.start()
        threads.append(t)

    if ENABLE_JOURNALD:
        t = threading.Thread(target=follow_journald, daemon=True)
        t.start()
        threads.append(t)

    while True:
        time.sleep(5)

if __name__ == "__main__":
    main()
