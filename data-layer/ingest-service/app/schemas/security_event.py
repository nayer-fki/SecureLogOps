from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

class SecurityEvent(BaseModel):
    severity: str = Field(..., examples=["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    category: str = Field(..., examples=["ids", "auth", "malware", "firewall"])
    message: str
    service: str = Field(default="security")
    env: Optional[str] = Field(default="dev")
    host: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    extra: Optional[Dict[str, Any]] = None
