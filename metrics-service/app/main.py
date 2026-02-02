import os
import time
import httpx
from fastapi import FastAPI, HTTPException

app = FastAPI(title="metrics-service", version="1.0.0")

PROM_URL = os.getenv("PROMETHEUS_URL", "http://prometheus:9090")
TIMEOUT = float(os.getenv("PROM_TIMEOUT", "5"))

async def prom_query(query: str):
    url = f"{PROM_URL}/api/v1/query"
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        r = await client.get(url, params={"query": query})
    if r.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Prometheus HTTP {r.status_code}")
    data = r.json()
    if data.get("status") != "success":
        raise HTTPException(status_code=502, detail="Prometheus query failed")
    return data

def vector_to_number(data) -> float:
    # expects resultType: vector with one sample
    try:
        result = data["data"]["result"]
        if not result:
            return 0.0
        v = result[0]["value"][1]
        return float(v)
    except Exception:
        return 0.0

@app.get("/health")
def health():
    return {"status": "ok", "service": "metrics-service", "ts": int(time.time())}

@app.get("/metrics/overview")
async def overview():
    # CPU usage % (node-exporter): 100 - idle%
    cpu_q = '100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[2m])) * 100)'
    # Memory usage % (node-exporter)
    mem_q = '(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100'
    # Running containers (cadvisor)
    containers_q = 'count(container_last_seen{container!=""})'

    cpu = vector_to_number(await prom_query(cpu_q))
    mem = vector_to_number(await prom_query(mem_q))
    containers = vector_to_number(await prom_query(containers_q))

    return {
        "cpu_usage_percent": round(cpu, 2),
        "memory_usage_percent": round(mem, 2),
        "running_containers": int(containers),
        "prometheus_url": PROM_URL,
    }

@app.get("/metrics/services")
async def services():
    # per-job up (basic)
    q = 'sum by(job) (up)'
    data = await prom_query(q)
    result = data["data"]["result"]
    services = []
    for item in result:
        job = item.get("metric", {}).get("job", "unknown")
        value = float(item.get("value", [0, "0"])[1])
        services.append({"job": job, "up_targets": value})
    services.sort(key=lambda x: x["job"])
    return {"services": services, "count": len(services)}
