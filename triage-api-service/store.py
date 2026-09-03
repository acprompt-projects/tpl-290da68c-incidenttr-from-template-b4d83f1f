from __future__ import annotations
import uuid
from datetime import datetime, timezone
from models import IncidentSubmit, IncidentRead, TriageUpdate, Severity, IncidentStatus, CorrelatedAlert

class IncidentStore:
    def __init__(self):
        self._incidents: dict[str, dict] = {}
        self._fingerprint_index: dict[str, str] = {}

    async def init(self):
        self._incidents.clear()
        self._fingerprint_index.clear()

    async def find_duplicate(self, fingerprint: str) -> IncidentRead | None:
        incident_id = self._fingerprint_index.get(fingerprint)
        if incident_id and incident_id in self._incidents:
            return self._to_model(self._incidents[incident_id])
        return None

    async def create(self, payload: IncidentSubmit, severity: Severity) -> IncidentRead:
        now = datetime.now(timezone.utc)
        incident_id = str(uuid.uuid4())
        record = {
            "id": incident_id, "title": payload.title, "description": payload.description,
            "fingerprint": payload.fingerprint, "source": payload.source,
            "severity": severity, "status": IncidentStatus.open, "assignee": None,
            "notes": None, "correlated_alerts": [
                CorrelatedAlert(fingerprint=payload.fingerprint, received_at=now)
            ],
            "created_at": now, "updated_at": now,
        }
        self._incidents[incident_id] = record
        self._fingerprint_index[payload.fingerprint] = incident_id
        return self._to_model(record)

    async def get(self, incident_id: str) -> IncidentRead | None:
        rec = self._incidents.get(incident_id)
        return self._to_model(rec) if rec else None

    async def add_correlation(self, incident_id: str, payload: IncidentSubmit) -> None:
        rec = self._incidents[incident_id]
        now = datetime.now(timezone.utc)
        rec["correlated_alerts"].append(CorrelatedAlert(fingerprint=payload.fingerprint, received_at=now))
        rec["updated_at"] = now
        self._fingerprint_index[payload.fingerprint] = incident_id

    async def update_triage(self, incident_id: str, update: TriageUpdate) -> IncidentRead:
        rec = self._incidents[incident_id]
        if update.severity is not None:
            rec["severity"] = update.severity
        if update.status is not None:
            rec["status"] = update.status
        if update.assignee is not None:
            rec["assignee"] = update.assignee
        if update.notes is not None:
            rec["notes"] = update.notes
        rec["updated_at"] = datetime.now(timezone.utc)
        return self._to_model(rec)

    def _to_model(self, rec: dict) -> IncidentRead:
        return IncidentRead(**rec)