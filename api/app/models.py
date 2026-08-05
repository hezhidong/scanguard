"""Pydantic models."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ReportIn(BaseModel):
    ip: str
    rule: str = "unknown"
    severity: str = "high"
    hit_count: int = 1
    evidence: list[str] = Field(default_factory=list)
    source: str = ""
    node_id: str = ""
    node_name: str = ""
    geo: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime | None = None


class IngestBatch(BaseModel):
    reports: list[ReportIn]
