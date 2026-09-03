from fastapi import FastAPI, HTTPException
from contextlib import asynccontextmanager
from models import IncidentSubmit, IncidentRead, TriageUpdate, Severity
from store import IncidentStore
from classifier import classify_incident

store = IncidentStore()

@asynccontextmanager
async def lifespan(app: FastAPI):
    await store.init()
    yield

app = FastAPI(title="Incident Triage Service", version="1.0.0", lifespan=lifespan)

@app.post("/incidents", response_model=IncidentRead, status_code=201)
async def submit_incident(payload: IncidentSubmit):
    dedup = await store.find_duplicate(payload.fingerprint)
    if dedup:
        await store.add_correlation(dedup.id, payload)
        return await store.get(dedup.id)
    severity = classify_incident(payload)
    incident = await store.create(payload, severity)
    return incident

@app.get("/incidents/{incident_id}", response_model=IncidentRead)
async def get_incident(incident_id: str):
    incident = await store.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

@app.patch("/incidents/{incident_id}/triage", response_model=IncidentRead)
async def update_triage(incident_id: str, update: TriageUpdate):
    incident = await store.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return await store.update_triage(incident_id, update)