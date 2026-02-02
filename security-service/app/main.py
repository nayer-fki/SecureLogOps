from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Optional
import os
import json
import httpx

# ---------------- CONFIG ----------------
API_KEY = os.getenv("API_KEY", "ChangeMe_Security123!")
WAZUH_URL = os.getenv("WAZUH_URL", "https://wazuh-manager:55000")

# fallback file mode
WAZUH_ALERTS_FILE = os.getenv("WAZUH_ALERTS_FILE", "/var/ossec/logs/alerts/alerts.json")
USE_WAZUH_FILE_FALLBACK = os.getenv("USE_WAZUH_FILE_FALLBACK", "true").lower() in ("1", "true", "yes")

# ✅ mock mode (for delta spike testing without touching /var/ossec)
MOCK_MODE = os.getenv("MOCK_MODE", "false").lower() in ("1", "true", "yes")

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="SecureLogOps – Security Service", version="1.2")
app.state.limiter = limiter

# ---------------- MOCK STORE ----------------
_mock_total = 0
_mock_by_sev = {"7": 0, "3": 0}
_mock_top_rules = {"99999": 0}
_mock_top_agents = {"wazuh-manager": 0}

# ---------------- RATE LIMIT HANDLER ----------------
@app.exception_handler(RateLimitExceeded)
def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})

# ---------------- API KEY SECURITY ----------------
def verify_api_key(request: Request):
    key = request.headers.get("x-api-key")
    if key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

# ---------------- HELPERS ----------------
def load_alerts_from_file(limit: int = 2000):
    """
    Read wazuh alerts.json (JSON lines file).
    Return latest alerts (best effort).
    """
    if not os.path.exists(WAZUH_ALERTS_FILE):
        raise Exception(f"alerts file not found: {WAZUH_ALERTS_FILE}")

    alerts = []
    with open(WAZUH_ALERTS_FILE, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            alerts.append(json.loads(line))
        except Exception:
            continue

    return alerts

async def try_wazuh_api_payload(since_dt: datetime, limit: int = 1000):
    """
    Best effort Wazuh API query.
    NOTE: Depending on Wazuh version, endpoint/auth differs.
    We keep it best-effort and rely on fallback file if it fails.
    """
    # Typical Wazuh API: GET /alerts?limit=...&sort=-timestamp&q=timestamp>...
    wazuh_endpoint = f"{WAZUH_URL}/alerts"
    params = {
        "limit": str(limit),
        "sort": "-timestamp",
        "q": f"timestamp>{since_dt.isoformat()}Z",
    }

    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        r = await client.get(wazuh_endpoint, params=params)
        if r.status_code != 200:
            raise Exception(f"wazuh api status={r.status_code} body={r.text[:200]}")
        return r.json()

def _parse_ts_best_effort(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        # accept Z
        if ts.endswith("Z"):
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        # if no timezone
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None

def _mock_summary_response():
    top_rules = sorted(_mock_top_rules.items(), key=lambda x: x[1], reverse=True)[:5]
    top_agents = sorted(_mock_top_agents.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "source_mode": "mock",
        "period": "last_24h",
        "total_alerts": int(_mock_total),
        "by_severity": dict(_mock_by_sev),
        "top_rules": top_rules,
        "top_agents": top_agents,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }

# ---------------- HEALTH ----------------
@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "security-service",
        "wazuh_url": WAZUH_URL,
        "file_fallback": USE_WAZUH_FILE_FALLBACK,
        "alerts_file": WAZUH_ALERTS_FILE,
        "mock_mode": MOCK_MODE,
    }

# ---------------- TEST ENDPOINTS (MOCK MODE) ----------------
@app.post("/test/increase")
@limiter.limit("30/minute")
def test_increase(
    request: Request,
    n: int = 25,
    sev: str = "7",
    rule_id: str = "99999",
    agent: str = "wazuh-manager",
    _: None = Depends(verify_api_key),
):
    """
    Increase mock alerts count to simulate spikes/deltas.
    Works ONLY when MOCK_MODE=true.
    """
    if not MOCK_MODE:
        raise HTTPException(status_code=400, detail="MOCK_MODE is disabled")

    global _mock_total, _mock_by_sev, _mock_top_rules, _mock_top_agents

    n = int(n)
    _mock_total += n

    _mock_by_sev[str(sev)] = int(_mock_by_sev.get(str(sev), 0)) + n
    _mock_top_rules[str(rule_id)] = int(_mock_top_rules.get(str(rule_id), 0)) + n
    _mock_top_agents[str(agent)] = int(_mock_top_agents.get(str(agent), 0)) + n

    return {"ok": True, "total_alerts": _mock_total}

@app.post("/test/reset")
@limiter.limit("10/minute")
def test_reset(request: Request, _: None = Depends(verify_api_key)):
    """
    Reset mock counters.
    """
    if not MOCK_MODE:
        raise HTTPException(status_code=400, detail="MOCK_MODE is disabled")

    global _mock_total, _mock_by_sev, _mock_top_rules, _mock_top_agents
    _mock_total = 0
    _mock_by_sev = {"7": 0, "3": 0}
    _mock_top_rules = {"99999": 0}
    _mock_top_agents = {"wazuh-manager": 0}

    return {"ok": True}

# ---------------- ALERTS SUMMARY (SOC KPIs) ----------------
@app.get("/alerts/summary")
@limiter.limit("10/minute")
async def alerts_summary(request: Request, _: None = Depends(verify_api_key)):
    """
    SOC KPIs – last 24 hours
    Priority:
      1) MOCK_MODE => return mock summary
      2) Try Wazuh API (best effort)
      3) If fails and fallback enabled -> read alerts.json (mounted read-only)
    """
    if MOCK_MODE:
        return _mock_summary_response()

    now = datetime.now(timezone.utc)
    since_dt = now - timedelta(hours=24)

    # 1) Try API (best effort)
    try:
        api_data = await try_wazuh_api_payload(since_dt=since_dt, limit=1000)

        alerts = api_data.get("data", [])
        if isinstance(alerts, dict) and "affected_items" in alerts:
            alerts = alerts.get("affected_items", [])
        if not isinstance(alerts, list):
            alerts = []

        source_mode = "wazuh_api"

    except Exception as e:
        if not USE_WAZUH_FILE_FALLBACK:
            raise HTTPException(status_code=502, detail=f"Error from Wazuh API: {e}")

        # 2) Fallback to file
        try:
            alerts = load_alerts_from_file(limit=3000)
            source_mode = "alerts_file"
        except Exception as fe:
            raise HTTPException(status_code=502, detail=f"Wazuh API failed ({e}) and file fallback failed ({fe})")

    # Filter last 24h (especially for file mode)
    filtered = []
    for a in alerts:
        ts = a.get("timestamp") or a.get("@timestamp")
        dt = _parse_ts_best_effort(str(ts)) if ts else None

        # if we can't parse => keep it (best effort)
        if not dt:
            filtered.append(a)
            continue

        if dt >= since_dt:
            filtered.append(a)

    total = len(filtered)

    severity_counter = Counter()
    rule_counter = Counter()
    agent_counter = Counter()

    for alert in filtered:
        rule = alert.get("rule", {}) or {}
        agent = alert.get("agent", {}) or {}

        severity = rule.get("level", "unknown")
        rule_id = rule.get("id", "unknown")
        agent_name = agent.get("name", "unknown")

        severity_counter[str(severity)] += 1
        rule_counter[str(rule_id)] += 1
        agent_counter[str(agent_name)] += 1

    return {
        "source_mode": source_mode,
        "period": "last_24h",
        "total_alerts": total,
        "by_severity": dict(severity_counter),
        "top_rules": rule_counter.most_common(5),
        "top_agents": agent_counter.most_common(5),
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
