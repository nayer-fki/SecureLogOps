from pydantic import BaseModel, Field
from typing import Optional, Any, Dict, List, Literal
from datetime import datetime

Severity = Literal["critical", "high", "medium", "low"]
Status = Literal["open", "ack", "closed"]


class Source(BaseModel):
    ip: Optional[str] = None
    host: Optional[str] = None
    user: Optional[str] = None


class Evidence(BaseModel):
    logs: List[Dict[str, Any]] = Field(default_factory=list)
    wazuh: Dict[str, Any] = Field(default_factory=dict)
    metrics: Dict[str, Any] = Field(default_factory=dict)


class IncidentOut(BaseModel):
    id: str
    status: Status
    severity: Severity
    type: str
    title: str  # ✅ keep required (we will generate if missing in crud)
    description: Optional[str] = None
    source: Source = Field(default_factory=Source)
    tags: List[str] = Field(default_factory=list)
    evidence: Evidence = Field(default_factory=Evidence)
    created_at: datetime
    updated_at: datetime
    acked_at: Optional[datetime] = None
    acked_by: Optional[str] = None
    closed_at: Optional[datetime] = None
    closed_by: Optional[str] = None


# ✅ RBAC: user comes from JWT, so body can be empty
class ActionBody(BaseModel):
    note: Optional[str] = None


# ✅ payload for correlation-service / internal upsert
class UpsertIncidentIn(BaseModel):
    type: str
    severity: Severity
    title: str
    description: Optional[str] = None
    source: Source = Field(default_factory=Source)
    tags: List[str] = Field(default_factory=list)
    evidence: Evidence = Field(default_factory=Evidence)
    fingerprint: Optional[str] = None
