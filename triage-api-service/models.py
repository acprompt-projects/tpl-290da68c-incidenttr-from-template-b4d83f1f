from __future__ import annotations
from enum import Enum
from datetime import datetime
from pydantic import BaseModel, Field

class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

class IncidentStatus(str, Enum):
    open = "open"
    triaging = "triaging"
    escalated = "escalated"
    resolved = "resolved"

class AlertSource(BaseModel):
    service: str
    host: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)

class IncidentSubmit(BaseModel):
    title: str
    description: str
    fingerprint: str = Field(..., description="Dedup key from rules engine")
    source: AlertSource
    raw_alert: dict = Field(default_factory=dict)

class TriageUpdate(BaseModel):
    severity: Severity | None = None
    status: IncidentStatus | None = None
    assignee: str | None = None
    notes: str | None = None

class CorrelatedAlert(BaseModel):
    fingerprint: str
    received_at: datetime

class IncidentRead(BaseModel):
    id: str
    title: str
    description: str
    fingerprint: str
    source: AlertSource
    severity: Severity
    status: IncidentStatus = IncidentStatus.open
    assignee: str | None = None
    notes: str | None = None
    correlated_alerts: list[CorrelatedAlert] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime