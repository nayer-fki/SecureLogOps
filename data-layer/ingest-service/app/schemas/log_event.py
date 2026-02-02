from pydantic import BaseModel, Field
from typing import Optional, Dict, Any


class LogEvent(BaseModel):
    level: str = Field(..., examples=["INFO", "WARN", "ERROR"])
    service: str = Field(..., examples=["ingest-service", "auth-service", "system"])
    message: str
    env: Optional[str] = Field(default="dev", examples=["dev", "prod"])
    host: Optional[str] = None
    source: Optional[str] = Field(default="app", examples=["app", "system", "collector"])
    extra: Optional[Dict[str, Any]] = None
