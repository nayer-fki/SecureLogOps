# app/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from redis.asyncio import Redis
import asyncio
import os

from app.api.routes import logs, events, metrics, uploads
from app.worker import worker_loop
from app.upload_worker import upload_worker_loop

app = FastAPI(title="SecureLogOps Ingest Service")

# ✅ CORS (put it here مباشرة بعد FastAPI)
ALLOWED_ORIGINS = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:3000,http://localhost:5173"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in ALLOWED_ORIGINS if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

# existing pipeline worker (optional)
WORKER_ENABLED = os.getenv("WORKER_ENABLED", "true").lower() == "true"
WORKER_CONCURRENCY = int(os.getenv("WORKER_CONCURRENCY", "1"))

# upload worker (recommended)
UPLOAD_WORKER_ENABLED = os.getenv("UPLOAD_WORKER_ENABLED", "true").lower() == "true"
UPLOAD_WORKER_CONCURRENCY = int(os.getenv("UPLOAD_WORKER_CONCURRENCY", "1"))

redis: Redis | None = None

# ✅ routers
app.include_router(logs.router)
app.include_router(events.router)
app.include_router(metrics.router)
app.include_router(uploads.router)


@app.on_event("startup")
async def startup():
    global redis
    redis = Redis.from_url(REDIS_URL, decode_responses=True)
    await redis.ping()

    # ✅ make redis available in routes
    app.state.redis = redis

    # ✅ Upload worker(s)
    if UPLOAD_WORKER_ENABLED:
        for _ in range(UPLOAD_WORKER_CONCURRENCY):
            asyncio.create_task(upload_worker_loop(redis))

    # ✅ Legacy worker(s)
    if WORKER_ENABLED:
        for _ in range(WORKER_CONCURRENCY):
            asyncio.create_task(worker_loop(redis))


@app.on_event("shutdown")
async def shutdown():
    global redis
    if redis:
        try:
            await redis.close()
        except Exception:
            pass


@app.get("/health")
async def health():
    ok = True
    try:
        await redis.ping()  # type: ignore
    except Exception:
        ok = False
    return {"status": "ok" if ok else "degraded"}
 