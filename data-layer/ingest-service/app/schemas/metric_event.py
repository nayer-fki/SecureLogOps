from pydantic import BaseModel, Field
from typing import Optional, Dict

class MetricEvent(BaseModel):
    service: str = Field(..., examples=["node-exporter", "collector-metrics", "system"])
    env: Optional[str] = Field(default="dev")
    host: Optional[str] = None
    metrics: Dict[str, float] = Field(..., examples=[{"cpu_pct": 41.2, "ram_pct": 62.5}])
    source: Optional[str] = Field(default="collector", examples=["collector", "agent"])
