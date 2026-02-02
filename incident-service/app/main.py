from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional

from .config import settings
from .schemas import IncidentOut, ActionBody, UpsertIncidentIn
from .crud import (
    InvalidObjectId,
    list_incidents,
    get_incident,
    ack_incident,
    close_incident,
    overview_stats,
    upsert_incident,
)
from .auth import require_roles, UserCtx

app = FastAPI(title="incident-service", version="1.2.0")

# ---------------- CORS (React dev server) ----------------
# If you later put Nginx / gateway, you can tighten this.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- Health ----------------
@app.get("/health")
def health():
    return {"ok": True, "service": settings.SERVICE_NAME}

# ---------------- Public (RBAC protected) ----------------

@app.get("/incidents", response_model=list[IncidentOut])
async def incidents(
    status: str | None = None,
    severity: str | None = None,
    limit: int = 50,
    skip: int = 0,
    _: UserCtx = Depends(require_roles("viewer", "analyst", "admin")),
):
    return await list_incidents(
        status=status,
        severity=severity,
        limit=min(max(limit, 1), 200),
        skip=max(skip, 0),
    )

@app.get("/incidents/{id}", response_model=IncidentOut)
async def incident_by_id(
    id: str,
    _: UserCtx = Depends(require_roles("viewer", "analyst", "admin")),
):
    try:
        doc = await get_incident(id)
    except InvalidObjectId:
        raise HTTPException(status_code=400, detail="Invalid incident id")

    if not doc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return doc

@app.post("/incidents/{id}/ack", response_model=IncidentOut)
async def ack(
    id: str,
    body: ActionBody,  # kept for future timeline notes
    user: UserCtx = Depends(require_roles("analyst", "admin")),
):
    try:
        doc = await ack_incident(id, user=user.username)
    except InvalidObjectId:
        raise HTTPException(status_code=400, detail="Invalid incident id")

    if not doc:
        raise HTTPException(status_code=404, detail="Incident not found or not ackable")
    return doc

@app.post("/incidents/{id}/close", response_model=IncidentOut)
async def close(
    id: str,
    body: ActionBody,  # kept for future timeline notes
    user: UserCtx = Depends(require_roles("admin")),
):
    try:
        doc = await close_incident(id, user=user.username)
    except InvalidObjectId:
        raise HTTPException(status_code=400, detail="Invalid incident id")

    if not doc:
        raise HTTPException(status_code=404, detail="Incident not found or not closable")
    return doc

@app.get("/stats/overview")
async def stats_overview(
    _: UserCtx = Depends(require_roles("viewer", "analyst", "admin")),
):
    return await overview_stats()

# ---------------- Internal (API Key protected) ----------------

def _require_internal_key(x_internal_api_key: Optional[str] = Header(default=None)):
    if x_internal_api_key != settings.INTERNAL_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized (internal)")

@app.post("/internal/incidents/upsert", response_model=IncidentOut)
async def internal_upsert(
    body: UpsertIncidentIn,
    _: None = Depends(_require_internal_key),
):
    return await upsert_incident(body.model_dump())
